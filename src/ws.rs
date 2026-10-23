//! Minimal RFC 6455 WebSocket client on `std::net::TcpStream`.
//!
//! Reads Mihomo's `/connections?interval=` push (`mihomo::stream_connections`);
//! `/traffic`, `/memory` and `/logs` stay on chunked HTTP, which is no slower.
//! Plain `ws://` only: the controller is local, and remote HTTPS stays with
//! the system `curl`. No extensions or subprotocols are negotiated.
//!
//! Mihomo's controller only writes: it never answers pings or close frames
//! (`hub/route/common.go`), so callers must not wait for either.

use crate::subconv::encode_base64;
use std::{
    collections::hash_map::RandomState,
    hash::BuildHasher,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::Duration,
};

const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const MAX_HEADER: usize = 16 * 1024;
/// Bytes asked of the socket per read once the handshake is done.
const READ_CHUNK: usize = 64 * 1024;
/// Largest single frame accepted before any of its payload is buffered.
pub const DEFAULT_MAX_FRAME: usize = 16 << 20;
/// Largest reassembled message.
pub const DEFAULT_MAX_MESSAGE: usize = 32 << 20;

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Close(Option<CloseFrame>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CloseFrame {
    pub code: u16,
    pub reason: String,
}

#[derive(Debug, thiserror::Error)]
pub enum WsError {
    #[error("WebSocket I/O: {0}")]
    Io(#[from] io::Error),
    #[error("WebSocket handshake: {0}")]
    Handshake(String),
    #[error("WebSocket protocol: {0}")]
    Protocol(&'static str),
    #[error("WebSocket text is not UTF-8")]
    InvalidUtf8,
    #[error("WebSocket payload of {0} bytes exceeds the limit")]
    TooLarge(u64),
    #[error("WebSocket closed")]
    Closed,
}

impl WsError {
    /// Close code sent when this error fails the connection (RFC 6455 §7.4.1).
    fn close_code(&self) -> Option<u16> {
        match self {
            WsError::Protocol(_) => Some(1002),
            WsError::InvalidUtf8 => Some(1007),
            WsError::TooLarge(_) => Some(1009),
            _ => None,
        }
    }
}

/// `Sec-WebSocket-Accept` for a request key (RFC 6455 §4.2.2).
pub fn accept_key(key: &str) -> String {
    encode_base64(&sha1(format!("{key}{GUID}").as_bytes()))
}

/// SHA-1 (RFC 3174); used only for the handshake, never for security.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xEFCD_AB89,
        0x98BA_DCFE,
        0x1032_5476,
        0xC3D2_E1F0,
    ];
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&((data.len() as u64).wrapping_mul(8)).to_be_bytes());
    for block in msg.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (slot, word) in w.iter_mut().zip(block.as_chunks::<4>().0) {
            *slot = u32::from_be_bytes(*word);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (acc, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *acc = acc.wrapping_add(v);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, v) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *chunk = v.to_be_bytes();
    }
    out
}

/// Masking keys and nonces without a crate: SipHash under the per-process
/// random keys of `RandomState`, fed a counter.
struct Rng {
    state: RandomState,
    counter: u64,
}

impl Rng {
    fn new() -> Self {
        Self {
            state: RandomState::new(),
            counter: 0,
        }
    }
    fn next_u64(&mut self) -> u64 {
        self.counter = self.counter.wrapping_add(1);
        self.state.hash_one(self.counter)
    }
    fn mask(&mut self) -> [u8; 4] {
        let b = self.next_u64().to_le_bytes();
        [b[0], b[1], b[2], b[3]]
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Frame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
}

/// One client frame. Every client frame is masked (RFC 6455 §5.3).
fn encode_frame(fin: bool, opcode: u8, payload: &[u8], mask: [u8; 4]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 14);
    out.push(if fin { 0x80 } else { 0 } | opcode);
    let len = payload.len();
    if len < 126 {
        out.push(0x80 | len as u8);
    } else if len <= 0xFFFF {
        out.push(0x80 | 126);
        out.extend_from_slice(&(len as u16).to_be_bytes());
    } else {
        out.push(0x80 | 127);
        out.extend_from_slice(&(len as u64).to_be_bytes());
    }
    out.extend_from_slice(&mask);
    out.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
    out
}

/// Parse one server frame from the front of `buf`; `Ok(None)` asks for more
/// bytes. The length guard runs on the header alone, before payload arrives.
fn decode_frame(buf: &[u8], max_frame: usize) -> Result<Option<(Frame, usize)>, WsError> {
    let &[b0, b1, ..] = buf else {
        return Ok(None);
    };
    if b0 & 0x70 != 0 {
        return Err(WsError::Protocol("reserved bits set without an extension"));
    }
    if b1 & 0x80 != 0 {
        return Err(WsError::Protocol("server frames must not be masked"));
    }
    let fin = b0 & 0x80 != 0;
    let opcode = b0 & 0x0F;
    let (len, start) = match b1 & 0x7F {
        126 => match buf.get(2..4) {
            Some(b) => (u16::from_be_bytes([b[0], b[1]]) as u64, 4),
            None => return Ok(None),
        },
        127 => match buf.get(2..10) {
            Some(b) => {
                let mut be = [0u8; 8];
                be.copy_from_slice(b);
                let len = u64::from_be_bytes(be);
                if len >> 63 != 0 {
                    return Err(WsError::Protocol("64-bit length has its high bit set"));
                }
                (len, 10)
            }
            None => return Ok(None),
        },
        n => (n as u64, 2),
    };
    match opcode {
        OP_CLOSE | OP_PING | OP_PONG if !fin => {
            return Err(WsError::Protocol("fragmented control frame"))
        }
        OP_CLOSE | OP_PING | OP_PONG if len > 125 => {
            return Err(WsError::Protocol("control frame over 125 bytes"))
        }
        OP_CONT | OP_TEXT | OP_BINARY | OP_CLOSE | OP_PING | OP_PONG => {}
        _ => return Err(WsError::Protocol("unknown opcode")),
    }
    if len > max_frame as u64 {
        return Err(WsError::TooLarge(len));
    }
    let end = start + len as usize;
    let Some(payload) = buf.get(start..end) else {
        return Ok(None);
    };
    let frame = Frame {
        fin,
        opcode,
        payload: payload.to_vec(),
    };
    Ok(Some((frame, end)))
}

fn parse_close(payload: &[u8]) -> Result<Option<CloseFrame>, WsError> {
    match payload {
        [] => Ok(None),
        [_] => Err(WsError::Protocol("close payload of one byte")),
        [hi, lo, reason @ ..] => {
            let code = u16::from_be_bytes([*hi, *lo]);
            // 1004-1006 and 1015 are reserved and never sent on the wire.
            if !matches!(code, 1000..=1003 | 1007..=1014 | 3000..=4999) {
                return Err(WsError::Protocol("invalid close code"));
            }
            let reason = String::from_utf8(reason.to_vec()).map_err(|_| WsError::InvalidUtf8)?;
            Ok(Some(CloseFrame { code, reason }))
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Check a handshake response head (status line and headers). Header names
/// are matched case-insensitively: Go canonicalizes `Sec-Websocket-Accept`.
fn check_response(head: &str, key: &str) -> Result<(), WsError> {
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| WsError::Handshake("malformed status line".into()))?;
    if status != 101 {
        return Err(WsError::Handshake(format!("HTTP {status}")));
    }
    let headers: Vec<(&str, &str)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim(), v.trim()))
        .collect();
    let header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| *v)
    };
    if !header("Upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket")) {
        return Err(WsError::Handshake("missing Upgrade: websocket".into()));
    }
    if !header("Connection").is_some_and(|v| {
        v.split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("upgrade"))
    }) {
        return Err(WsError::Handshake("missing Connection: Upgrade".into()));
    }
    if header("Sec-WebSocket-Accept") != Some(accept_key(key).as_str()) {
        return Err(WsError::Handshake("Sec-WebSocket-Accept mismatch".into()));
    }
    if header("Sec-WebSocket-Extensions").is_some() || header("Sec-WebSocket-Protocol").is_some() {
        return Err(WsError::Handshake(
            "unrequested extension or subprotocol".into(),
        ));
    }
    Ok(())
}

pub struct Client<S> {
    stream: S,
    rbuf: Vec<u8>,
    partial: Option<(u8, Vec<u8>)>,
    max_frame: usize,
    max_message: usize,
    sent_close: bool,
    closed: bool,
    rng: Rng,
}

/// Connect to `ws://{addr}{path}`. For a Mihomo secret pass
/// `("Authorization", "Bearer …")`; `?token=` exists only for browsers.
pub fn connect(
    addr: SocketAddr,
    path: &str,
    headers: &[(&str, &str)],
    timeout: Duration,
) -> Result<Client<TcpStream>, WsError> {
    let stream = TcpStream::connect_timeout(&addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let _ = stream.set_nodelay(true);
    Client::handshake(stream, &addr.to_string(), path, headers)
}

impl<S: Read + Write> Client<S> {
    /// Run the opening handshake on an already connected stream.
    pub fn handshake(
        mut stream: S,
        host: &str,
        path: &str,
        headers: &[(&str, &str)],
    ) -> Result<Self, WsError> {
        let unsafe_text = |s: &str| s.contains(['\r', '\n']);
        if unsafe_text(host)
            || unsafe_text(path)
            || !path.starts_with('/')
            || headers
                .iter()
                .any(|(k, v)| unsafe_text(k) || unsafe_text(v) || k.contains(':'))
        {
            return Err(WsError::Handshake("invalid request line or header".into()));
        }
        let mut rng = Rng::new();
        let mut nonce = [0u8; 16];
        nonce[..8].copy_from_slice(&rng.next_u64().to_le_bytes());
        nonce[8..].copy_from_slice(&rng.next_u64().to_le_bytes());
        let key = encode_base64(&nonce);
        let mut req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n"
        );
        for (k, v) in headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        stream.write_all(req.as_bytes())?;
        stream.flush()?;

        let mut rbuf = Vec::new();
        let head_end = loop {
            if let Some(i) = find(&rbuf, b"\r\n\r\n") {
                break i + 4;
            }
            if rbuf.len() > MAX_HEADER {
                return Err(WsError::Handshake("response headers too large".into()));
            }
            let mut chunk = [0u8; 1024];
            match stream.read(&mut chunk) {
                Ok(0) => return Err(WsError::Handshake("connection closed".into())),
                Ok(n) => rbuf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        };
        check_response(&String::from_utf8_lossy(&rbuf[..head_end]), &key)?;
        // Frames sent right behind the 101 response are already buffered.
        rbuf.drain(..head_end);
        Ok(Self {
            stream,
            rbuf,
            partial: None,
            max_frame: DEFAULT_MAX_FRAME,
            max_message: DEFAULT_MAX_MESSAGE,
            sent_close: false,
            closed: false,
            rng,
        })
    }

    pub fn with_limits(mut self, max_frame: usize, max_message: usize) -> Self {
        self.max_frame = max_frame;
        self.max_message = max_message;
        self
    }

    pub fn get_ref(&self) -> &S {
        &self.stream
    }

    // Only tests ask; the app drops the client instead of reusing it.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn is_closed(&self) -> bool {
        self.closed
    }

    fn write_frame(&mut self, fin: bool, opcode: u8, payload: &[u8]) -> Result<(), WsError> {
        if self.sent_close {
            return Err(WsError::Closed);
        }
        let frame = encode_frame(fin, opcode, payload, self.rng.mask());
        self.stream.write_all(&frame)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Send one unfragmented message. Control payloads are capped at 125 bytes.
    // Mihomo never reads client frames, so the app sends none; kept for tests
    // and for controllers that do read.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn send(&mut self, msg: &Message) -> Result<(), WsError> {
        match msg {
            Message::Text(t) => self.write_frame(true, OP_TEXT, t.as_bytes()),
            Message::Binary(b) => self.write_frame(true, OP_BINARY, b),
            Message::Ping(p) | Message::Pong(p) if p.len() > 125 => {
                Err(WsError::Protocol("control frame over 125 bytes"))
            }
            Message::Ping(p) => self.write_frame(true, OP_PING, p),
            Message::Pong(p) => self.write_frame(true, OP_PONG, p),
            Message::Close(c) => match c {
                Some(c) => self.close(c.code, &c.reason),
                None => self.close_empty(),
            },
        }
    }

    /// Send a text or binary message split into frames of at most `size` bytes.
    #[cfg_attr(not(test), allow(dead_code))] // As `send`.
    pub fn send_fragmented(&mut self, msg: &Message, size: usize) -> Result<(), WsError> {
        let (opcode, data) = match msg {
            Message::Text(t) => (OP_TEXT, t.as_bytes()),
            Message::Binary(b) => (OP_BINARY, b.as_slice()),
            _ => return Err(WsError::Protocol("control frames cannot be fragmented")),
        };
        let size = size.max(1);
        if data.len() <= size {
            return self.write_frame(true, opcode, data);
        }
        let parts = data.len().div_ceil(size);
        for (i, part) in data.chunks(size).enumerate() {
            let op = if i == 0 { opcode } else { OP_CONT };
            self.write_frame(i + 1 == parts, op, part)?;
        }
        Ok(())
    }

    /// Start the closing handshake. The reason is cut to fit 123 bytes.
    pub fn close(&mut self, code: u16, reason: &str) -> Result<(), WsError> {
        let mut end = reason.len().min(123);
        while !reason.is_char_boundary(end) {
            end -= 1;
        }
        let mut payload = code.to_be_bytes().to_vec();
        payload.extend_from_slice(&reason.as_bytes()[..end]);
        self.write_frame(true, OP_CLOSE, &payload)?;
        self.sent_close = true;
        Ok(())
    }

    fn close_empty(&mut self) -> Result<(), WsError> {
        self.write_frame(true, OP_CLOSE, &[])?;
        self.sent_close = true;
        Ok(())
    }

    /// Read until one whole frame is buffered. A read timeout (`WouldBlock` /
    /// `TimedOut`) loses nothing: the next call resumes from the buffer.
    fn read_frame(&mut self) -> Result<Frame, WsError> {
        loop {
            if let Some((frame, used)) = decode_frame(&self.rbuf, self.max_frame)? {
                self.rbuf.drain(..used);
                return Ok(frame);
            }
            // Read straight into the buffer's tail: a 1.5 MB snapshot then
            // takes about 25 reads instead of about 200 through a stack chunk.
            let filled = self.rbuf.len();
            self.rbuf.resize(filled + READ_CHUNK, 0);
            let read = self.stream.read(&mut self.rbuf[filled..]);
            self.rbuf.truncate(filled + read.as_ref().map_or(0, |n| *n));
            match read {
                Ok(0) => {
                    self.closed = true;
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                }
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
        }
    }

    /// Next message. Pings are answered with a pong and still returned; a
    /// close frame is echoed once and ends the connection.
    pub fn read_message(&mut self) -> Result<Message, WsError> {
        if self.closed {
            return Err(WsError::Closed);
        }
        let result = self.next_message();
        if let Err(err) = &result {
            if let Some(code) = err.close_code() {
                if !self.sent_close {
                    let _ = self.close(code, "");
                }
                self.closed = true;
            }
        }
        result
    }

    fn next_message(&mut self) -> Result<Message, WsError> {
        loop {
            let Frame {
                fin,
                opcode,
                payload,
            } = self.read_frame()?;
            match opcode {
                OP_PING => {
                    if !self.sent_close {
                        self.write_frame(true, OP_PONG, &payload)?;
                    }
                    return Ok(Message::Ping(payload));
                }
                OP_PONG => return Ok(Message::Pong(payload)),
                OP_CLOSE => {
                    let close = parse_close(&payload)?;
                    if !self.sent_close {
                        // Echo the peer's code (RFC 6455 §5.5.1); errors are moot now.
                        let _ = match &close {
                            Some(c) => self.close(c.code, ""),
                            None => self.close_empty(),
                        };
                    }
                    self.closed = true;
                    return Ok(Message::Close(close));
                }
                OP_TEXT | OP_BINARY => {
                    if self.partial.is_some() {
                        return Err(WsError::Protocol("new message inside a fragmented one"));
                    }
                    if payload.len() > self.max_message {
                        return Err(WsError::TooLarge(payload.len() as u64));
                    }
                    if fin {
                        return finish(opcode, payload);
                    }
                    self.partial = Some((opcode, payload));
                }
                _ => {
                    let Some((first, mut data)) = self.partial.take() else {
                        return Err(WsError::Protocol("continuation without a message"));
                    };
                    let total = data.len() + payload.len();
                    if total > self.max_message {
                        return Err(WsError::TooLarge(total as u64));
                    }
                    data.extend_from_slice(&payload);
                    if fin {
                        return finish(first, data);
                    }
                    self.partial = Some((first, data));
                }
            }
        }
    }
}

fn finish(opcode: u8, data: Vec<u8>) -> Result<Message, WsError> {
    if opcode == OP_TEXT {
        String::from_utf8(data)
            .map(Message::Text)
            .map_err(|_| WsError::InvalidUtf8)
    } else {
        Ok(Message::Binary(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{BufRead, BufReader, Cursor},
        net::TcpListener,
        thread,
    };

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Server-side frame as Mihomo's `wsWriteServerMessage` writes it, but
    /// with FIN selectable.
    fn server_frame(fin: bool, opcode: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = vec![if fin { 0x80 } else { 0 } | opcode];
        match payload.len() {
            n if n < 126 => out.push(n as u8),
            n if n < 65536 => {
                out.push(126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        out.extend_from_slice(payload);
        out
    }

    /// Decode one client frame: (fin, opcode, unmasked payload).
    fn client_frame(buf: &[u8]) -> (bool, u8, Vec<u8>, usize) {
        assert_eq!(buf[1] & 0x80, 0x80, "client frames must be masked");
        let (len, mut pos) = match buf[1] & 0x7F {
            126 => (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4),
            127 => (
                u64::from_be_bytes(buf[2..10].try_into().unwrap()) as usize,
                10,
            ),
            n => (n as usize, 2),
        };
        let mask = [buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]];
        pos += 4;
        let payload = buf[pos..pos + len]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ mask[i % 4])
            .collect();
        (buf[0] & 0x80 != 0, buf[0] & 0x0F, payload, pos + len)
    }

    /// In-memory stream: hands out `input` in `step`-byte reads, optionally
    /// returning `WouldBlock` before each read to mimic a read timeout.
    struct Pipe {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
        step: usize,
        stall: bool,
        stalled: bool,
        reads: usize,
    }

    impl Pipe {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
                step: usize::MAX,
                stall: false,
                stalled: false,
                reads: 0,
            }
        }
    }

    impl Read for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.stall && !self.stalled {
                self.stalled = true;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.stalled = false;
            self.reads += 1;
            let n = buf.len().min(self.step);
            self.input.read(&mut buf[..n])
        }
    }

    impl Write for Pipe {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn client(input: Vec<u8>) -> Client<Pipe> {
        Client {
            stream: Pipe::new(input),
            rbuf: Vec::new(),
            partial: None,
            max_frame: DEFAULT_MAX_FRAME,
            max_message: DEFAULT_MAX_MESSAGE,
            sent_close: false,
            closed: false,
            rng: Rng::new(),
        }
    }

    #[test]
    fn sha1_and_accept_key_match_published_vectors() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(&sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hex(&sha1(&[b'a'; 1_000_000])),
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        );
        // A full 64-byte block forces padding into a second block.
        assert_eq!(
            hex(&sha1(&[b'a'; 64])),
            "0098ba824b5c16427bd7a1122a5a442a25ec644d"
        );
        // RFC 6455 §1.3 example.
        assert_eq!(
            accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
        for (raw, b64) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode_base64(raw.as_bytes()), b64);
        }
    }

    #[test]
    fn client_frames_are_masked_with_minimal_lengths() {
        let mask = [0x37, 0xfa, 0x21, 0x3d];
        // RFC 6455 §5.7: masked "Hello".
        assert_eq!(
            encode_frame(true, OP_TEXT, b"Hello", mask),
            [0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58]
        );
        for (len, header) in [(0, 2), (125, 2), (126, 4), (65535, 4), (65536, 10)] {
            let payload: Vec<u8> = (0..len).map(|i| i as u8).collect();
            let frame = encode_frame(false, OP_BINARY, &payload, mask);
            assert_eq!(frame.len(), header + 4 + len);
            let (fin, op, body, used) = client_frame(&frame);
            assert!(!fin);
            assert_eq!((op, used), (OP_BINARY, frame.len()));
            assert_eq!(body, payload);
        }
    }

    #[test]
    fn server_frames_decode_across_length_forms_and_partial_input() {
        for len in [0usize, 125, 126, 65535, 65536, 70_000] {
            let payload = vec![7u8; len];
            let frame = server_frame(true, OP_BINARY, &payload);
            let (got, used) = decode_frame(&frame, DEFAULT_MAX_FRAME).unwrap().unwrap();
            assert_eq!((got.payload.len(), used), (len, frame.len()));
        }
        let frame = server_frame(true, OP_TEXT, &[b'x'; 300]);
        for cut in 0..frame.len() {
            assert!(decode_frame(&frame[..cut], DEFAULT_MAX_FRAME)
                .unwrap()
                .is_none());
        }
        let mut two = server_frame(true, OP_TEXT, b"a");
        two.extend(server_frame(true, OP_TEXT, b"b"));
        let (first, used) = decode_frame(&two, 100).unwrap().unwrap();
        assert_eq!((first.payload, used), (b"a".to_vec(), 3));
    }

    #[test]
    fn decoder_rejects_protocol_violations_and_oversized_headers() {
        let bad = |bytes: &[u8]| decode_frame(bytes, 1024).unwrap_err();
        assert!(matches!(
            bad(&[0x81, 0x81, 0, 0, 0, 0, b'x']),
            WsError::Protocol(_)
        ));
        assert!(matches!(bad(&[0xC1, 0x00]), WsError::Protocol(_)));
        assert!(matches!(bad(&[0x83, 0x00]), WsError::Protocol(_)));
        assert!(matches!(bad(&[0x09, 0x00]), WsError::Protocol(_)));
        assert!(matches!(bad(&[0x89, 126, 0, 126]), WsError::Protocol(_)));
        let mut huge = vec![0x82, 127];
        huge.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(matches!(bad(&huge), WsError::Protocol(_)));
        // The guard fires from the header alone; no payload is buffered.
        let mut big = vec![0x82, 127];
        big.extend_from_slice(&(1u64 << 40).to_be_bytes());
        assert!(matches!(bad(&big), WsError::TooLarge(n) if n == 1 << 40));
        assert!(matches!(
            bad(&[0x82, 126, 0x04, 0x01]),
            WsError::TooLarge(1025)
        ));
    }

    #[test]
    fn fragments_reassemble_around_pings_and_survive_read_timeouts() {
        let mut input = server_frame(false, OP_TEXT, "{\"up\":".as_bytes());
        input.extend(server_frame(true, OP_PING, b"hb"));
        input.extend(server_frame(false, OP_CONT, "1,\"down\":".as_bytes()));
        input.extend(server_frame(true, OP_CONT, "2}\n".as_bytes()));
        input.extend(server_frame(true, OP_PONG, b""));
        let mut ws = client(input);
        ws.stream.step = 1;
        ws.stream.stall = true;
        let mut next = || loop {
            match ws.read_message() {
                Err(WsError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
                other => break other.unwrap(),
            }
        };
        assert_eq!(next(), Message::Ping(b"hb".to_vec()));
        assert_eq!(next(), Message::Text("{\"up\":1,\"down\":2}\n".into()));
        assert_eq!(next(), Message::Pong(Vec::new()));
        let (fin, op, body, _) = client_frame(&ws.stream.output);
        assert_eq!((fin, op, body), (true, OP_PONG, b"hb".to_vec()));
    }

    #[test]
    fn a_large_snapshot_takes_few_reads_and_keeps_what_follows() {
        let big = "x".repeat(300_000);
        let mut input = server_frame(true, OP_TEXT, big.as_bytes());
        input.extend(server_frame(true, OP_TEXT, b"next"));
        let mut ws = client(input);
        ws.stream.stall = true;
        let mut next = || loop {
            match ws.read_message() {
                Err(WsError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => continue,
                other => break other.unwrap(),
            }
        };
        assert_eq!(next(), Message::Text(big));
        assert_eq!(next(), Message::Text("next".into()));
        // 300 kB in 64 KiB reads; a timeout in between drops no byte.
        assert!(ws.stream.reads <= 6, "{}", ws.stream.reads);
        assert!(ws.rbuf.is_empty());
    }

    #[test]
    fn close_is_echoed_once_and_ends_the_session() {
        let mut payload = 1001u16.to_be_bytes().to_vec();
        payload.extend_from_slice("going away".as_bytes());
        let mut ws = client(server_frame(true, OP_CLOSE, &payload));
        assert_eq!(
            ws.read_message().unwrap(),
            Message::Close(Some(CloseFrame {
                code: 1001,
                reason: "going away".into()
            }))
        );
        let (_, op, body, _) = client_frame(&ws.stream.output);
        assert_eq!((op, body), (OP_CLOSE, 1001u16.to_be_bytes().to_vec()));
        assert!(ws.is_closed());
        assert!(matches!(ws.read_message(), Err(WsError::Closed)));
        assert!(matches!(
            ws.send(&Message::Text("late".into())),
            Err(WsError::Closed)
        ));
        assert_eq!(parse_close(&[]).unwrap(), None);
        assert!(parse_close(&[0x03]).is_err());
        assert!(parse_close(&1005u16.to_be_bytes()).is_err());
        assert!(parse_close(&999u16.to_be_bytes()).is_err());
    }

    #[test]
    fn violations_fail_the_connection_with_matching_close_codes() {
        let cases: [(Vec<u8>, u16); 4] = [
            (server_frame(true, OP_CONT, b"x"), 1002),
            (
                [
                    server_frame(false, OP_TEXT, b"a"),
                    server_frame(true, OP_TEXT, b"b"),
                ]
                .concat(),
                1002,
            ),
            (server_frame(true, OP_TEXT, &[0xff, 0xfe]), 1007),
            (
                [
                    server_frame(false, OP_BINARY, &[0; 6]),
                    server_frame(true, OP_CONT, &[0; 6]),
                ]
                .concat(),
                1009,
            ),
        ];
        for (input, code) in cases {
            let mut ws = client(input).with_limits(1024, 10);
            assert!(ws.read_message().is_err());
            let (_, op, body, _) = client_frame(&ws.stream.output);
            assert_eq!((op, body), (OP_CLOSE, code.to_be_bytes().to_vec()));
            assert!(matches!(ws.read_message(), Err(WsError::Closed)));
        }
        let mut eof = client(Vec::new());
        assert!(matches!(eof.read_message(), Err(WsError::Io(_))));
        assert!(eof.is_closed());
    }

    #[test]
    fn sends_fragmented_and_bounded_control_messages() {
        let mut ws = client(Vec::new());
        ws.send_fragmented(&Message::Text("abcdefg".into()), 3)
            .unwrap();
        let out = ws.stream.output.clone();
        let mut pos = 0;
        let mut frames = Vec::new();
        while pos < out.len() {
            let (fin, op, body, used) = client_frame(&out[pos..]);
            frames.push((fin, op, body));
            pos += used;
        }
        assert_eq!(
            frames,
            [
                (false, OP_TEXT, b"abc".to_vec()),
                (false, OP_CONT, b"def".to_vec()),
                (true, OP_CONT, b"g".to_vec()),
            ]
        );
        assert!(ws.send(&Message::Ping(vec![0; 126])).is_err());
        assert!(ws.send_fragmented(&Message::Ping(Vec::new()), 1).is_err());
        ws.stream.output.clear();
        ws.close(1000, &"é".repeat(70)).unwrap();
        let (_, op, body, _) = client_frame(&ws.stream.output);
        assert_eq!(op, OP_CLOSE);
        assert!(body.len() <= 125);
        assert!(std::str::from_utf8(&body[2..]).is_ok());
    }

    #[test]
    fn handshake_response_checks() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        // Go's http.Header.Write canonicalizes to Sec-Websocket-Accept.
        let ok = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\nSec-Websocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n";
        check_response(ok, key).unwrap();
        let err = |head: &str| check_response(head, key).unwrap_err().to_string();
        assert!(err("HTTP/1.1 401 Unauthorized\r\n\r\n").contains("401"));
        assert!(err(&ok.replace("s3pP", "AAAA")).contains("Accept"));
        assert!(err(&ok.replace("Upgrade: websocket\r\n", "")).contains("Upgrade"));
        assert!(err(&ok.replace("keep-alive, Upgrade", "keep-alive")).contains("Connection"));
        assert!(
            err(&ok.replace("\r\n\r\n", "\r\nSec-WebSocket-Extensions: x\r\n\r\n"))
                .contains("extension")
        );
        assert!(err("garbage").contains("status"));
        for (path, headers) in [
            ("/x\r\nEvil: 1", vec![]),
            ("x", vec![]),
            ("/x", vec![("A", "b\r\nEvil: 1")]),
            ("/x", vec![("A:B", "c")]),
        ] {
            assert!(Client::handshake(Pipe::new(Vec::new()), "h", path, &headers).is_err());
        }
    }

    /// Accept one connection and answer the upgrade the way Mihomo does,
    /// returning the request head for inspection.
    fn accept_upgrade(listener: &TcpListener) -> (TcpStream, String) {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut head = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            head.push_str(&line);
            if line == "\r\n" || line.is_empty() {
                break;
            }
        }
        (stream, head)
    }

    fn request_key(head: &str) -> String {
        head.lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap()
            .trim()
            .to_string()
    }

    #[test]
    fn talks_to_a_local_mock_controller() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let big = vec![b'z'; 70_000];
        let big_server = big.clone();
        let server = thread::spawn(move || {
            let (mut stream, head) = accept_upgrade(&listener);
            let key = request_key(&head);
            assert_eq!(key.len(), 24);
            assert_eq!(crate::subconv::decode_base64(&key).unwrap().len(), 16);
            // The 101 and the first frame share one write, as a fast server may.
            let mut reply = format!(
                "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-Websocket-Accept: {}\r\nUpgrade: websocket\r\n\r\n",
                accept_key(&key)
            )
            .into_bytes();
            reply.extend(server_frame(true, OP_TEXT, b"{\"up\":1,\"down\":2}\n"));
            reply.extend(server_frame(true, OP_BINARY, &[1; 300]));
            reply.extend(server_frame(true, OP_BINARY, &big_server));
            reply.extend(server_frame(false, OP_TEXT, "连".as_bytes()));
            reply.extend(server_frame(true, OP_CONT, "接".as_bytes()));
            reply.extend(server_frame(true, OP_PING, b"p"));
            stream.write_all(&reply).unwrap();

            let mut seen = Vec::new();
            let mut frames = Vec::new();
            let mut chunk = [0u8; 4096];
            while frames.len() < 3 {
                let n = stream.read(&mut chunk).unwrap();
                assert!(n > 0, "client hung up early");
                seen.extend_from_slice(&chunk[..n]);
                while seen.len() >= 2 {
                    let need = 2 + 4 + (seen[1] & 0x7F) as usize;
                    if seen.len() < need {
                        break;
                    }
                    let (fin, op, body, used) = client_frame(&seen);
                    frames.push((fin, op, body));
                    seen.drain(..used);
                }
            }
            // Like Mihomo, never answer the client's close.
            (head, frames)
        });

        let mut ws = connect(
            addr,
            "/traffic",
            &[("Authorization", "Bearer s3cret")],
            Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(
            ws.read_message().unwrap(),
            Message::Text("{\"up\":1,\"down\":2}\n".into())
        );
        assert_eq!(ws.read_message().unwrap(), Message::Binary(vec![1; 300]));
        assert_eq!(ws.read_message().unwrap(), Message::Binary(big));
        assert_eq!(ws.read_message().unwrap(), Message::Text("连接".into()));
        assert_eq!(ws.read_message().unwrap(), Message::Ping(b"p".to_vec()));
        ws.send(&Message::Text("hi".into())).unwrap();
        ws.close(1000, "bye").unwrap();

        let (head, frames) = server.join().unwrap();
        assert!(head.starts_with("GET /traffic HTTP/1.1\r\n"));
        assert!(head.contains(&format!("Host: {addr}\r\n")));
        assert!(head.contains("Upgrade: websocket\r\n"));
        assert!(head.contains("Sec-WebSocket-Version: 13\r\n"));
        assert!(head.contains("Authorization: Bearer s3cret\r\n"));
        assert_eq!(
            frames,
            [
                (true, OP_PONG, b"p".to_vec()),
                (true, OP_TEXT, b"hi".to_vec()),
                (
                    true,
                    OP_CLOSE,
                    [&1000u16.to_be_bytes()[..], b"bye"].concat()
                ),
            ]
        );
    }

    #[test]
    fn mock_controller_rejections_surface_as_handshake_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            for reply in [
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n".to_string(),
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n".to_string(),
            ] {
                let (mut stream, _) = accept_upgrade(&listener);
                stream.write_all(reply.as_bytes()).unwrap();
            }
        });
        let timeout = Duration::from_secs(5);
        let unauthorized = connect(addr, "/logs?level=info", &[], timeout)
            .err()
            .unwrap();
        assert!(unauthorized.to_string().contains("401"));
        let forged = connect(addr, "/memory", &[], timeout).err().unwrap();
        assert!(forged.to_string().contains("Accept"));
        server.join().unwrap();
    }
}
