use std::{
    collections::HashMap,
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::Sender,
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ops::{
    apply_general_json, bool_patch_body, parse_dns_message, parse_probe_target,
    parse_providers_json, parse_rules_json, parse_yaml_flags, rule_disable_body, DnsMessage,
    DnsStatus, ProbeTarget, ProviderInfo, RuleInfo, RuntimeFlags,
};

#[derive(Clone, Debug)]
pub enum BackendEvent {
    ActionDone {
        result: Result<String, String>,
        modules: Option<Vec<String>>,
        profile: Option<String>,
    },
    SnapshotDone(Box<CoreSnapshot>),
    Traffic {
        up: u64,
        down: u64,
    },
    Memory {
        inuse: u64,
    },
    Log {
        level: String,
        payload: String,
    },
    Snapshot(Box<CoreSnapshot>),
    /// A reload or TUN rebuild is about to be sent; closures in `scope` are
    /// blamed on it from now until the action finishes.
    Disrupting {
        cause: crate::conns::Cause,
        scope: crate::conns::Scope,
    },
    /// A `/connections` snapshot pushed over WebSocket.
    Connections {
        items: Vec<ConnectionItem>,
        upload_total: u64,
        download_total: u64,
    },
    DelayResult {
        group: String,
        node: String,
        delay: Option<u16>,
    },
    GroupTestDone {
        group: String,
    },
    BestTestDone {
        group: String,
        results: Vec<(String, Option<u16>)>,
    },
    StatusMessage {
        text: String,
        is_error: bool,
    },
    CoreDownloadDone {
        ok: bool,
    },
    DnsLookup {
        lines: Vec<String>,
        is_error: bool,
    },
    ProbeDone {
        lines: Vec<String>,
        is_error: bool,
    },
}

#[derive(Clone, Debug, Default)]
pub struct CoreSnapshot {
    pub running: bool,
    pub version: String,
    pub mode: String,
    pub http_port: u16,
    pub socks_port: u16,
    pub mixed_port: u16,
    pub allow_lan: bool,
    pub config_values: HashMap<String, String>,
    pub sysproxy_enabled: bool,
    pub network_service: String,
    pub groups: Vec<ProxyGroup>,
    pub nodes: HashMap<String, ProxyNode>,
    pub connections: Vec<ConnectionItem>,
    /// `/connections` answered with JSON; an empty list is then real, not a fetch failure.
    pub connections_ok: bool,
    pub upload_total: u64,
    pub download_total: u64,
    pub sub_info: Option<SubscriptionSummary>,
    pub core_bin_path: String,
    pub tun_enabled: bool,
    pub tun_stack: String,
    pub tun_device: String,
    pub sniffing: bool,
    pub ipv6: bool,
    pub tcp_concurrent: bool,
    pub find_process: String,
    pub dns: DnsStatus,
    pub rules: Vec<RuleInfo>,
    pub providers: Vec<ProviderInfo>,
}

#[derive(Clone, Debug, Default)]
pub struct SubscriptionSummary {
    pub traffic: String,
    pub reset: String,
    pub expire: String,
}

#[derive(Clone, Debug)]
pub struct ProxyGroup {
    pub name: String,
    pub kind: String,
    pub now: String,
    pub all: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct ProxyNode {
    pub name: String,
    pub kind: String,
    pub udp: bool,
    pub delay: Option<u16>,
    /// Owning proxy provider, used for the provider healthcheck delay route.
    pub provider: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ConnectionItem {
    pub id: String,
    pub host: String,
    pub network: String,
    pub rule: String,
    pub chains: String,
    pub upload: u64,
    pub download: u64,
    pub process: String,
    pub process_path: String,
    pub inbound: String,
    pub inbound_name: String,
    pub source: String,
    pub sniff_host: String,
    pub rule_payload: String,
    pub start: String,
    /// `start` as unix milliseconds, parsed on the worker thread.
    pub start_ms: Option<i64>,
    /// Non-empty `providerChains`, outermost first like `chains`.
    pub provider: String,
    pub dns_mode: String,
    pub dest_geo: String,
    pub dest_asn: String,
    /// Filled by `conns::Tracker` from id-keyed diffs between snapshots.
    pub up_rate: u64,
    pub down_rate: u64,
    pub ai: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControllerConfig {
    pub addr: String,
    pub secret: String,
    pub config_dir: String,
    pub subscription_url: String,
    pub test_url: String,
    pub timeout_ms: u64,
    #[serde(default)]
    pub profile_id: String,
}

impl Default for ControllerConfig {
    fn default() -> Self {
        Self {
            addr: "127.0.0.1:9090".to_string(),
            secret: String::new(),
            config_dir: default_config_dir(),
            subscription_url: String::new(),
            test_url: "http://www.gstatic.com/generate_204".to_string(),
            timeout_ms: 4000,
            profile_id: String::new(),
        }
    }
}

const HOMEBREW_CONFIG_DIR: &str = "/opt/homebrew/etc/mihomo";

fn default_config_dir() -> String {
    if Path::new(HOMEBREW_CONFIG_DIR).join("config.yaml").is_file() {
        return HOMEBREW_CONFIG_DIR.to_string();
    }
    std::env::var_os("HOME")
        .map(|home| {
            PathBuf::from(home)
                .join(".config/terc/mihomo")
                .display()
                .to_string()
        })
        .unwrap_or_else(|| HOMEBREW_CONFIG_DIR.to_string())
}

pub fn config_file_exists(cfg: &ControllerConfig) -> bool {
    Path::new(&cfg.config_dir).join("config.yaml").is_file()
}

pub fn normalize_subscription(raw: &str, controller_addr: &str) -> String {
    crate::ops::set_top_scalar(raw, "external-controller", controller_addr)
}
pub fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len() * 3);
    for b in input.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", b));
            }
        }
    }
    out
}

fn parse_socket_addr(addr: &str) -> SocketAddr {
    let clean = addr
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_end_matches('/');
    clean
        .parse()
        .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 9090)))
}

pub fn http_request(
    addr: &str,
    secret: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
    timeout: Duration,
) -> io::Result<(u16, String)> {
    let sock_addr = parse_socket_addr(addr);
    let mut stream = TcpStream::connect_timeout(&sock_addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;

    let payload = body.unwrap_or("");
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\nAccept: application/json\r\n"
    );
    if !secret.is_empty() {
        req.push_str(&format!("Authorization: Bearer {secret}\r\n"));
    }
    if body.is_some() {
        req.push_str("Content-Type: application/json\r\n");
        req.push_str(&format!("Content-Length: {}\r\n", payload.len()));
    }
    req.push_str("\r\n");
    if body.is_some() {
        req.push_str(payload);
    }

    stream.write_all(req.as_bytes())?;
    stream.flush()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;

    // Keep the body as bytes until the chunk framing is gone: a chunk boundary
    // may split a multibyte character, and lossy-decoding first shifts offsets.
    let (head, rest) = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(pos) => (&raw[..pos], &raw[pos + 4..]),
        None => (&raw[..], &[][..]),
    };
    let headers = String::from_utf8_lossy(head);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        // A dropped connection is not an answer from the controller.
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no HTTP response"))?;

    let body = if headers.lines().any(|l| {
        l.to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
    }) {
        decode_chunked(rest)
    } else {
        rest.to_vec()
    };

    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn decode_chunked(mut input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(line_end) = input.windows(2).position(|w| w == b"\r\n") {
        let len_line = String::from_utf8_lossy(&input[..line_end]);
        let Ok(chunk_len) = usize::from_str_radix(len_line.trim(), 16) else {
            break;
        };
        if chunk_len == 0 {
            break;
        }
        let after_len = &input[line_end + 2..];
        let take = chunk_len.min(after_len.len());
        out.extend_from_slice(&after_len[..take]);
        if take < chunk_len {
            break;
        }
        input = &after_len[take..];
        if let Some(stripped) = input.strip_prefix(b"\r\n") {
            input = stripped;
        }
    }
    out
}

pub fn spawn_stream_workers(
    addr: String,
    secret: String,
    tx: Sender<BackendEvent>,
    stop: Arc<AtomicBool>,
    conn_stream: Arc<ConnStream>,
) {
    let tx_conns = tx.clone();
    let addr_conns = addr.clone();
    let secret_conns = secret.clone();
    let stop_conns = stop.clone();
    thread::spawn(move || {
        stream_connections(
            &addr_conns,
            &secret_conns,
            &tx_conns,
            &stop_conns,
            &conn_stream,
        );
    });

    let tx_traffic = tx.clone();
    let addr_traffic = addr.clone();
    let secret_traffic = secret.clone();
    let stop_traffic = stop.clone();
    thread::spawn(move || {
        stream_json_lines(
            &addr_traffic,
            &secret_traffic,
            "/traffic",
            &stop_traffic,
            |val| {
                let up = val.get("up").and_then(Value::as_u64).unwrap_or(0);
                let down = val.get("down").and_then(Value::as_u64).unwrap_or(0);
                let _ = tx_traffic.send(BackendEvent::Traffic { up, down });
            },
        );
    });

    let tx_mem = tx.clone();
    let addr_mem = addr.clone();
    let secret_mem = secret.clone();
    let stop_mem = stop.clone();
    thread::spawn(move || {
        stream_json_lines(&addr_mem, &secret_mem, "/memory", &stop_mem, |val| {
            let inuse = val.get("inuse").and_then(Value::as_u64).unwrap_or(0);
            let _ = tx_mem.send(BackendEvent::Memory { inuse });
        });
    });

    let tx_logs = tx;
    thread::spawn(move || {
        stream_json_lines(&addr, &secret, "/logs?level=info", &stop, |val| {
            let level = val
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("info")
                .to_string();
            let payload = val
                .get("payload")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            if !payload.is_empty() {
                let _ = tx_logs.send(BackendEvent::Log { level, payload });
            }
        });
    });
}

fn stream_json_lines<F>(
    addr: &str,
    secret: &str,
    path: &str,
    stop: &Arc<AtomicBool>,
    mut on_json: F,
) where
    F: FnMut(Value),
{
    let sock_addr = parse_socket_addr(addr);
    while !stop.load(Ordering::Relaxed) {
        if let Ok(mut stream) = TcpStream::connect_timeout(&sock_addr, Duration::from_millis(800)) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
            let mut req =
                format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nAccept: application/json\r\n");
            if !secret.is_empty() {
                req.push_str(&format!("Authorization: Bearer {secret}\r\n"));
            }
            req.push_str("\r\n");
            if stream.write_all(req.as_bytes()).is_ok() {
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                while !stop.load(Ordering::Relaxed) {
                    line.clear();
                    match reader.read_line(&mut line) {
                        Ok(0) => break,
                        Ok(_) => {
                            let trimmed = line.trim();
                            if trimmed.starts_with('{') && trimmed.ends_with('}') {
                                if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
                                    on_json(val);
                                }
                            }
                        }
                        Err(err)
                            if err.kind() == io::ErrorKind::WouldBlock
                                || err.kind() == io::ErrorKind::TimedOut =>
                        {
                            continue;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        thread::sleep(Duration::from_millis(900));
    }
}

/// The settings switch for the `/connections` WebSocket worker, shared with it.
pub struct ConnStream {
    pub enabled: AtomicBool,
}

/// Push path. `interval` must be a positive integer: Mihomo answers a bad
/// value with 101 and then silence, and panics on `<= 0` (88dcbf7
/// `hub/route/connections.go:36`-`64`).
const CONNECTIONS_WS_PATH: &str = "/connections?interval=1000";

/// Waits and limits of the `/connections` worker; tests scale them to ms.
struct StreamTiming {
    connect: Duration,
    read: Duration,
    /// Consecutive read timeouts that end a session; Mihomo pushes every second.
    idle_reads: u32,
    /// Pause after a session that delivered snapshots.
    retry: Duration,
    /// Pauses after consecutive failed attempts; the last one repeats.
    backoff: [Duration; 5],
    /// Pause after an oversized frame; HTTP polling reads that core meanwhile.
    too_large: Duration,
    /// How often a switched-off worker looks at the switch again.
    disabled: Duration,
    /// Sleep step for noticing `stop` and the switch.
    slice: Duration,
    max_frame: usize,
    max_message: usize,
}

const STREAM_TIMING: StreamTiming = StreamTiming {
    connect: Duration::from_millis(1500),
    read: Duration::from_secs(2),
    idle_reads: 3,
    retry: Duration::from_secs(1),
    backoff: [
        Duration::from_secs(2),
        Duration::from_secs(4),
        Duration::from_secs(8),
        Duration::from_secs(16),
        Duration::from_secs(30),
    ],
    too_large: Duration::from_secs(300),
    disabled: Duration::from_millis(500),
    slice: Duration::from_millis(100),
    max_frame: crate::ws::DEFAULT_MAX_FRAME,
    max_message: crate::ws::DEFAULT_MAX_MESSAGE,
};

#[derive(Debug, PartialEq)]
enum SessionEnd {
    /// `stop` rose or the app hung up: the worker exits.
    Exit,
    /// The switch went off.
    Disabled,
    /// Snapshots arrived, then the stream broke.
    Dropped(String),
    /// Snapshots arrived, then the core closed the socket (EOF, reset or a
    /// close frame), as it does when it stops or restarts. Not logged: the
    /// next attempt is refused while it is down, and any other failure logs.
    Ended(String),
    /// The core refused the TCP connection. It is not running, so polling
    /// has nothing to fetch either and this is not worth a log line.
    Unreachable(String),
    /// No snapshot arrived: handshake rejected, silence or garbage.
    Failed(String),
    /// A frame or message exceeded the size limit.
    TooLarge(String),
}

/// Pause before the next attempt; `failures` counts consecutive failed ones.
fn retry_delay(end: &SessionEnd, failures: &mut usize, t: &StreamTiming) -> Duration {
    match end {
        SessionEnd::Dropped(_) | SessionEnd::Ended(_) => {
            *failures = 0;
            t.retry
        }
        SessionEnd::TooLarge(_) => t.too_large,
        SessionEnd::Failed(_) | SessionEnd::Unreachable(_) => {
            let wait = t.backoff[(*failures).min(t.backoff.len() - 1)];
            *failures += 1;
            wait
        }
        SessionEnd::Exit | SessionEnd::Disabled => Duration::ZERO,
    }
}

/// Sleep up to `total` in `slice` steps while `go()` holds.
fn nap(total: Duration, slice: Duration, go: impl Fn() -> bool) {
    let deadline = Instant::now() + total;
    while go() {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        thread::sleep(left.min(slice));
    }
}

/// Read `/connections` pushes and forward them as `BackendEvent::Connections`.
/// While this is down the app sees no pushes and polls over HTTP instead.
fn stream_connections(
    addr: &str,
    secret: &str,
    tx: &Sender<BackendEvent>,
    stop: &AtomicBool,
    conn_stream: &ConnStream,
) {
    stream_connections_with(addr, secret, tx, stop, conn_stream, &STREAM_TIMING);
}

fn stream_connections_with(
    addr: &str,
    secret: &str,
    tx: &Sender<BackendEvent>,
    stop: &AtomicBool,
    conn_stream: &ConnStream,
    t: &StreamTiming,
) {
    let sock_addr = parse_socket_addr(addr);
    // A header keeps the secret out of the URL; Mihomo accepts Bearer for WS.
    let auth = format!("Bearer {secret}");
    let headers: Vec<(&str, &str)> = if secret.is_empty() {
        Vec::new()
    } else {
        vec![("Authorization", auth.as_str())]
    };
    let live = || !stop.load(Ordering::Relaxed) && conn_stream.enabled.load(Ordering::Relaxed);
    // None until a WebSocket outcome is known; logs fire only on changes.
    let mut healthy = None;
    let mut failures = 0;
    while !stop.load(Ordering::Relaxed) {
        if !conn_stream.enabled.load(Ordering::Relaxed) {
            healthy = None;
            failures = 0;
            nap(t.disabled, t.slice, || !stop.load(Ordering::Relaxed));
            continue;
        }
        let end = stream_session(sock_addr, &headers, tx, stop, conn_stream, &mut healthy, t);
        match &end {
            SessionEnd::Exit => return,
            SessionEnd::Disabled => continue,
            SessionEnd::Unreachable(_) | SessionEnd::Ended(_) => {}
            SessionEnd::Dropped(err) | SessionEnd::Failed(err) | SessionEnd::TooLarge(err) => {
                if healthy != Some(false) {
                    healthy = Some(false);
                    let payload = format!(
                        "terc: /connections WebSocket 不可用，改用 HTTP 轮询 / unavailable, polling over HTTP: {err}"
                    );
                    let level = "warning".into();
                    if tx.send(BackendEvent::Log { level, payload }).is_err() {
                        return;
                    }
                }
            }
        }
        nap(retry_delay(&end, &mut failures, t), t.slice, live);
    }
}

/// One connection. The client is dropped, never closed: Mihomo does not
/// read after the handshake, so it would never answer a close frame.
fn stream_session(
    addr: SocketAddr,
    headers: &[(&str, &str)],
    tx: &Sender<BackendEvent>,
    stop: &AtomicBool,
    conn_stream: &ConnStream,
    healthy: &mut Option<bool>,
    t: &StreamTiming,
) -> SessionEnd {
    use crate::ws::{Message, WsError};
    let mut client = match crate::ws::connect(addr, CONNECTIONS_WS_PATH, headers, t.connect) {
        Ok(client) => client.with_limits(t.max_frame, t.max_message),
        Err(WsError::Io(e)) if e.kind() == io::ErrorKind::ConnectionRefused => {
            return SessionEnd::Unreachable(e.to_string())
        }
        Err(e) => return SessionEnd::Failed(e.to_string()),
    };
    if let Err(e) = client.get_ref().set_read_timeout(Some(t.read)) {
        return SessionEnd::Failed(e.to_string());
    }
    let mut delivered = 0usize;
    let mut idle = 0;
    let mut garbled = 0;
    let ended = |why: String, delivered: usize| {
        if delivered > 0 {
            SessionEnd::Dropped(why)
        } else {
            SessionEnd::Failed(why)
        }
    };
    loop {
        if stop.load(Ordering::Relaxed) {
            return SessionEnd::Exit;
        }
        if !conn_stream.enabled.load(Ordering::Relaxed) {
            return SessionEnd::Disabled;
        }
        match client.read_message() {
            Ok(Message::Text(text)) => {
                idle = 0;
                let snapshot = serde_json::from_str::<Value>(&text).ok().filter(|v| {
                    v.get("connections")
                        .is_some_and(|c| c.is_null() || c.is_array())
                });
                let Some(v) = snapshot else {
                    garbled += 1;
                    if garbled >= 3 {
                        return ended("3 unreadable snapshots in a row".into(), delivered);
                    }
                    continue;
                };
                garbled = 0;
                let (items, upload_total, download_total) = connections_from_snapshot_json(&v);
                let event = BackendEvent::Connections {
                    items,
                    upload_total,
                    download_total,
                };
                if tx.send(event).is_err() {
                    return SessionEnd::Exit;
                }
                delivered += 1;
                if delivered == 1 {
                    if *healthy == Some(false) {
                        let payload = "terc: /connections WebSocket 已连接 / connected".into();
                        let level = "info".into();
                        if tx.send(BackendEvent::Log { level, payload }).is_err() {
                            return SessionEnd::Exit;
                        }
                    }
                    *healthy = Some(true);
                }
            }
            Ok(Message::Close(_)) if delivered > 0 => {
                return SessionEnd::Ended("closed by the controller".into())
            }
            Ok(Message::Close(_)) => return SessionEnd::Failed("closed by the controller".into()),
            // ws.rs already answered pings; Mihomo sends none of these.
            Ok(Message::Binary(_) | Message::Ping(_) | Message::Pong(_)) => idle = 0,
            Err(WsError::Io(e))
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                idle += 1;
                if idle >= t.idle_reads {
                    let why = format!("no snapshot for {:?}", t.read * t.idle_reads);
                    return ended(why, delivered);
                }
            }
            Err(e @ WsError::TooLarge(_)) => return SessionEnd::TooLarge(e.to_string()),
            Err(WsError::Io(e))
                if delivered > 0
                    && matches!(
                        e.kind(),
                        io::ErrorKind::UnexpectedEof
                            | io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                    ) =>
            {
                return SessionEnd::Ended(e.to_string())
            }
            Err(e) => return ended(e.to_string(), delivered),
        }
    }
}

/// A `/connections` body, polled or pushed: items sorted by total bytes, then
/// the upload and download totals. `connections: null` means none.
pub fn connections_from_snapshot_json(v: &Value) -> (Vec<ConnectionItem>, u64, u64) {
    let upload_total = v.get("uploadTotal").and_then(Value::as_u64).unwrap_or(0);
    let download_total = v.get("downloadTotal").and_then(Value::as_u64).unwrap_or(0);
    let mut connections = Vec::new();
    for c in v
        .get("connections")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        // Id, rule, byte counters and the rest come from connection_from_value.
        let Some(mut item) = connection_from_value(c) else {
            continue;
        };
        let meta = c.get("metadata");
        let field = |key: &str| {
            meta.and_then(|m| m.get(key))
                .and_then(Value::as_str)
                .unwrap_or("")
        };
        let host = match field("host") {
            "" => field("destinationIP"),
            host => host,
        };
        item.host = format!("{host}:{}", field("destinationPort"));
        item.network = meta
            .and_then(|m| m.get("network"))
            .and_then(Value::as_str)
            .unwrap_or("tcp")
            .to_uppercase();
        item.chains = c
            .get("chains")
            .and_then(Value::as_array)
            .map(|ch| {
                ch.iter()
                    .rev()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(" › ")
            })
            .unwrap_or_default();
        connections.push(item);
    }
    connections.sort_by_key(|c| std::cmp::Reverse(c.download + c.upload));
    (connections, upload_total, download_total)
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    use serde_json::json;
    use std::{net::TcpListener, sync::mpsc};

    /// Production behaviour at millisecond scale.
    fn fast() -> StreamTiming {
        StreamTiming {
            connect: Duration::from_millis(500),
            read: Duration::from_millis(100),
            idle_reads: 3,
            retry: Duration::from_millis(20),
            backoff: [20, 40, 80, 160, 300].map(Duration::from_millis),
            too_large: Duration::from_secs(60),
            disabled: Duration::from_millis(20),
            slice: Duration::from_millis(10),
            ..STREAM_TIMING
        }
    }

    struct Worker {
        rx: mpsc::Receiver<BackendEvent>,
        stop: Arc<AtomicBool>,
        conn: Arc<ConnStream>,
        handle: thread::JoinHandle<()>,
    }

    fn start(listener: &TcpListener, timing: StreamTiming, enabled: bool) -> Worker {
        let addr = listener.local_addr().unwrap().to_string();
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let conn = Arc::new(ConnStream {
            enabled: AtomicBool::new(enabled),
        });
        let (s, c) = (stop.clone(), conn.clone());
        let handle = thread::spawn(move || {
            stream_connections_with(&addr, "s3cret", &tx, &s, &c, &timing);
        });
        Worker {
            rx,
            stop,
            conn,
            handle,
        }
    }

    impl Worker {
        fn next(&self) -> BackendEvent {
            self.rx
                .recv_timeout(Duration::from_secs(5))
                .expect("worker event")
        }

        /// Raise `stop`, insist the thread ends `within`, return unread events.
        fn finish(self, within: Duration) -> Vec<BackendEvent> {
            self.stop.store(true, Ordering::Relaxed);
            let deadline = Instant::now() + within;
            while !self.handle.is_finished() {
                assert!(Instant::now() < deadline, "worker ignored stop");
                thread::sleep(Duration::from_millis(5));
            }
            self.handle.join().unwrap();
            self.rx.try_iter().collect()
        }
    }

    fn accept_within(listener: &TcpListener, wait: Duration) -> Option<TcpStream> {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + wait;
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    return Some(stream);
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return None;
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                Err(e) => panic!("{e}"),
            }
        }
    }

    /// Accept one attempt and return it with its request head.
    fn accept_request(listener: &TcpListener) -> (TcpStream, String) {
        let stream = accept_within(listener, Duration::from_secs(5)).expect("connect attempt");
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            assert_eq!((&stream).read(&mut byte).unwrap(), 1, "request cut short");
            head.push(byte[0]);
        }
        (stream, String::from_utf8(head).unwrap())
    }

    /// Mihomo's 101, with Go's header casing.
    fn upgrade(head: &str) -> Vec<u8> {
        let key = head
            .lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap();
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-Websocket-Accept: {}\r\n\r\n",
            crate::ws::accept_key(key)
        )
        .into_bytes()
    }

    /// One unfragmented, unmasked text frame, as `wsWriteServerMessage` writes.
    fn text_frame(payload: &str) -> Vec<u8> {
        let mut out = vec![0x81];
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
        out.extend_from_slice(payload.as_bytes());
        out
    }

    fn snapshot_json(hosts: &[&str]) -> String {
        let conns: Vec<_> = hosts
            .iter()
            .enumerate()
            .map(|(i, host)| {
                json!({
                    "id": format!("c{i}"),
                    "metadata": {
                        "network": "tcp",
                        "host": host,
                        "destinationIP": "203.0.113.9",
                        "destinationPort": "443",
                        "sourcePort": "50123",
                    },
                    "upload": 10 * (i + 1),
                    "download": 100 * (i + 1),
                    "chains": ["HK-01", "AI"],
                })
            })
            .collect();
        format!(
            "{}\n",
            json!({"downloadTotal": 900, "uploadTotal": 90, "connections": conns, "memory": 1})
        )
    }

    fn logs(events: &[BackendEvent]) -> Vec<(String, String)> {
        events
            .iter()
            .filter_map(|e| match e {
                BackendEvent::Log { level, payload } => Some((level.clone(), payload.clone())),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn pushed_snapshots_become_connection_events() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let timing = StreamTiming {
            read: Duration::from_secs(1),
            ..fast()
        };
        let worker = start(&listener, timing, true);
        let (mut stream, head) = accept_request(&listener);
        assert!(
            head.starts_with("GET /connections?interval=1000 HTTP/1.1\r\n"),
            "{head}"
        );
        assert!(head.contains("\r\nUpgrade: websocket\r\n"), "{head}");
        assert!(
            head.contains("\r\nAuthorization: Bearer s3cret\r\n"),
            "{head}"
        );
        assert!(!head.contains("token="), "{head}");
        // Like Mihomo: the first snapshot rides with the 101.
        let mut reply = upgrade(&head);
        reply.extend(text_frame(&snapshot_json(&["api.openai.com", ""])));
        stream.write_all(&reply).unwrap();
        let BackendEvent::Connections {
            items,
            upload_total,
            download_total,
        } = worker.next()
        else {
            panic!("expected pushed connections");
        };
        let hosts: Vec<_> = items.iter().map(|c| c.host.as_str()).collect();
        assert_eq!(hosts, ["203.0.113.9:443", "api.openai.com:443"]);
        assert_eq!(items[1].source, "");
        assert_eq!(items[1].chains, "AI › HK-01");
        assert_eq!((upload_total, download_total), (90, 900));

        stream
            .write_all(&text_frame(
                "{\"downloadTotal\":901,\"uploadTotal\":91,\"connections\":null,\"memory\":1}\n",
            ))
            .unwrap();
        let BackendEvent::Connections {
            items,
            upload_total,
            download_total,
        } = worker.next()
        else {
            panic!("expected pushed connections");
        };
        assert!(items.is_empty());
        assert_eq!((upload_total, download_total), (91, 901));
        // The first success is not news; nothing was down before it.
        assert!(logs(&worker.finish(Duration::from_secs(3))).is_empty());
    }

    #[test]
    fn rejected_handshake_warns_once_and_keeps_retrying_with_backoff() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let worker = start(&listener, fast(), true);
        let mut attempts = Vec::new();
        for _ in 0..3 {
            let (mut stream, _) = accept_request(&listener);
            attempts.push(Instant::now());
            stream
                .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                .unwrap();
        }
        assert!(attempts[1] - attempts[0] >= Duration::from_millis(20));
        assert!(attempts[2] - attempts[1] >= Duration::from_millis(40));
        let events = worker.finish(Duration::from_secs(1));
        assert!(!events
            .iter()
            .any(|e| matches!(e, BackendEvent::Connections { .. })));
        let logs = logs(&events);
        assert_eq!(logs.len(), 1, "{logs:?}");
        assert_eq!(logs[0].0, "warning");
        assert!(logs[0].1.contains("polling over HTTP"), "{logs:?}");
        assert!(logs[0].1.contains("HTTP 404"), "{logs:?}");
    }

    #[test]
    fn oversized_frame_pauses_the_stream_until_toggled() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let timing = StreamTiming {
            max_frame: 64,
            ..fast()
        };
        let worker = start(&listener, timing, true);
        let (mut stream, head) = accept_request(&listener);
        let mut reply = upgrade(&head);
        // A header announcing 1024 bytes; the guard fires before the payload.
        reply.extend([0x81, 126, 0x04, 0x00]);
        reply.extend([b'{'; 16]);
        stream.write_all(&reply).unwrap();
        let BackendEvent::Log { level, payload } = worker.next() else {
            panic!("expected a warning");
        };
        assert_eq!(level, "warning");
        assert!(payload.contains("exceeds the limit"), "{payload}");
        // The short backoff would retry within 20 ms; the long pause holds.
        assert!(accept_within(&listener, Duration::from_millis(300)).is_none());
        // Switching it off and on again retries at once.
        worker.conn.enabled.store(false, Ordering::Relaxed);
        thread::sleep(Duration::from_millis(50));
        worker.conn.enabled.store(true, Ordering::Relaxed);
        let (_again, head) = accept_request(&listener);
        assert!(head.starts_with("GET /connections?interval=1000 "));
        worker.finish(Duration::from_secs(1));

        let mut failures = 0;
        let too_large = SessionEnd::TooLarge(String::new());
        assert_eq!(
            retry_delay(&too_large, &mut failures, &STREAM_TIMING),
            Duration::from_secs(300)
        );
    }

    #[test]
    fn silent_stream_ends_after_three_read_timeouts_and_reconnects() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let worker = start(&listener, fast(), true);
        let (mut first, head) = accept_request(&listener);
        let mut reply = upgrade(&head);
        reply.extend(text_frame(&snapshot_json(&["a.test"])));
        first.write_all(&reply).unwrap();
        let sent = Instant::now();
        assert!(matches!(worker.next(), BackendEvent::Connections { .. }));
        // `first` stays open and silent, as a wedged controller would.
        let (mut second, head) = accept_request(&listener);
        assert!(sent.elapsed() >= Duration::from_millis(300));
        let BackendEvent::Log { level, payload } = worker.next() else {
            panic!("expected a warning");
        };
        assert_eq!(level, "warning");
        assert!(payload.contains("no snapshot for 300ms"), "{payload}");
        let mut reply = upgrade(&head);
        reply.extend(text_frame(&snapshot_json(&["b.test"])));
        second.write_all(&reply).unwrap();
        assert!(matches!(worker.next(), BackendEvent::Connections { .. }));
        let BackendEvent::Log { level, payload } = worker.next() else {
            panic!("expected the recovery line");
        };
        assert_eq!(level, "info");
        assert!(
            payload.ends_with("WebSocket 已连接 / connected"),
            "{payload}"
        );
        worker.finish(Duration::from_secs(1));
        drop(first);
    }

    #[test]
    fn a_core_stop_and_restart_leave_no_log_lines() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let worker = start(&listener, fast(), true);
        let (mut stream, head) = accept_request(&listener);
        let mut reply = upgrade(&head);
        reply.extend(text_frame(&snapshot_json(&["a.test"])));
        stream.write_all(&reply).unwrap();
        assert!(matches!(worker.next(), BackendEvent::Connections { .. }));
        // The core stops: EOF, then refused connections for a while.
        drop(stream);
        drop(listener);
        thread::sleep(Duration::from_millis(150));
        // It comes back on the same address.
        let listener = TcpListener::bind(addr).unwrap();
        let (mut stream, head) = accept_request(&listener);
        let mut reply = upgrade(&head);
        reply.extend(text_frame(&snapshot_json(&["b.test"])));
        stream.write_all(&reply).unwrap();
        assert!(matches!(worker.next(), BackendEvent::Connections { .. }));
        let events = worker.finish(Duration::from_secs(1));
        assert!(logs(&events).is_empty(), "{:?}", logs(&events));
    }

    #[test]
    fn stop_and_the_switch_end_the_worker_promptly() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        // Switched off: no attempt at all, and stop still ends the thread.
        let idle = start(&listener, fast(), false);
        assert!(accept_within(&listener, Duration::from_millis(150)).is_none());
        assert!(idle.finish(Duration::from_millis(300)).is_empty());

        // Mid-session: stop ends a live stream within about one read timeout.
        let worker = start(&listener, fast(), false);
        worker.conn.enabled.store(true, Ordering::Relaxed);
        let (mut stream, head) = accept_request(&listener);
        let mut reply = upgrade(&head);
        reply.extend(text_frame(&snapshot_json(&["a.test"])));
        stream.write_all(&reply).unwrap();
        assert!(matches!(worker.next(), BackendEvent::Connections { .. }));
        worker.finish(Duration::from_millis(500));

        // A refused connection (core not running) backs off without a log line.
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let (tx, rx) = mpsc::channel();
        let stop = Arc::new(AtomicBool::new(false));
        let conn = ConnStream {
            enabled: AtomicBool::new(true),
        };
        let s = stop.clone();
        let stopper = thread::spawn(move || {
            thread::sleep(Duration::from_millis(200));
            s.store(true, Ordering::Relaxed);
        });
        stream_connections_with(&addr.to_string(), "", &tx, &stop, &conn, &fast());
        stopper.join().unwrap();
        assert!(rx.try_iter().next().is_none());
    }

    #[test]
    fn backoff_doubles_to_a_cap_and_resets_after_a_good_session() {
        let t = &STREAM_TIMING;
        let mut failures = 0;
        let failed = SessionEnd::Failed(String::new());
        let waits: Vec<_> = (0..6)
            .map(|_| retry_delay(&failed, &mut failures, t).as_secs())
            .collect();
        assert_eq!(waits, [2, 4, 8, 16, 30, 30]);
        let dropped = SessionEnd::Dropped(String::new());
        assert_eq!(retry_delay(&dropped, &mut failures, t).as_secs(), 1);
        assert_eq!(retry_delay(&failed, &mut failures, t).as_secs(), 2);
        // Six silent seconds at a one-second push interval end a session.
        assert_eq!(t.read * t.idle_reads, Duration::from_secs(6));
    }

    #[test]
    fn snapshot_parser_matches_the_polled_list() {
        // The shape Mihomo 88dcbf7 writes: ports as strings, chains leaf first.
        let v: Value = serde_json::from_str(
            r#"{"downloadTotal":5000,"uploadTotal":700,"memory":1,"connections":[
              {"id":"small","metadata":{"network":"udp","type":"Tun","sourceIP":"198.18.0.1",
               "destinationIP":"1.1.1.1","sourcePort":"53000","destinationPort":"53","host":"",
               "dnsMode":"normal","process":"mDNSResponder"},
               "upload":1,"download":2,"start":"2026-10-20T04:34:56.1234Z",
               "chains":["DIRECT"],"providerChains":[""],"rule":"Match","rulePayload":""},
              {"id":"big","metadata":{"network":"tcp","type":"Mixed","sourceIP":"127.0.0.1",
               "destinationIP":"104.18.33.45","sourcePort":"51234","destinationPort":"443",
               "host":"api.openai.com","sniffHost":"","processPath":"/usr/bin/codex"},
               "upload":300,"download":4000,"start":"2026-10-20T12:34:56.123456789+08:00",
               "chains":["HK-01","AI","PROXY"],"providerChains":["sub","",""],
               "rule":"DomainSuffix","rulePayload":"openai.com"},
              {"id":"bare","metadata":{"destinationIP":"203.0.113.7","destinationPort":"8443"},
               "upload":10,"download":10}
            ]}"#,
        )
        .unwrap();
        let (items, up, down) = connections_from_snapshot_json(&v);
        assert_eq!((up, down), (700, 5000));
        fn row(c: &ConnectionItem) -> (&str, &str, &str, &str, &str, u64, u64) {
            (
                c.id.as_str(),
                c.host.as_str(),
                c.network.as_str(),
                c.chains.as_str(),
                c.rule.as_str(),
                c.upload,
                c.download,
            )
        }
        assert_eq!(
            items.iter().map(row).collect::<Vec<_>>(),
            [
                (
                    "big",
                    "api.openai.com:443",
                    "TCP",
                    "PROXY › AI › HK-01",
                    "DomainSuffix",
                    300,
                    4000
                ),
                ("bare", "203.0.113.7:8443", "TCP", "", "", 10, 10),
                ("small", "1.1.1.1:53", "UDP", "DIRECT", "Match", 1, 2),
            ]
        );
        assert_eq!(items[0].source, "127.0.0.1:51234");
        assert_eq!(items[0].rule_payload, "openai.com");
        assert_eq!(items[0].provider, "sub");
        assert!(items[0].start_ms.is_some());
        assert!(items[2].start_ms.is_some());

        let empty = json!({"downloadTotal": 1, "uploadTotal": 2, "connections": null});
        assert_eq!(connections_from_snapshot_json(&empty).0.len(), 0);
        assert_eq!(connections_from_snapshot_json(&empty).1, 2);
    }
}

pub fn config_yaml_path(cfg: &ControllerConfig) -> PathBuf {
    Path::new(&cfg.config_dir).join("config.yaml")
}

pub fn read_config_text(cfg: &ControllerConfig) -> Result<String, String> {
    let path = config_yaml_path(cfg);
    fs::read_to_string(&path).map_err(|_| format!("config not found: {}", path.display()))
}

fn local_flags(cfg: &ControllerConfig) -> RuntimeFlags {
    fs::read_to_string(config_yaml_path(cfg))
        .map(|text| parse_yaml_flags(&text))
        .unwrap_or_default()
}

pub fn fetch_snapshot(cfg: &ControllerConfig) -> CoreSnapshot {
    fetch_snapshot_with(cfg, true)
}

/// `include_connections: false` skips the `/connections` GET (the WebSocket
/// push supplies it); the snapshot then has `connections_ok == false`.
pub fn fetch_snapshot_with(cfg: &ControllerConfig, include_connections: bool) -> CoreSnapshot {
    let mut snapshot = fetch_core_snapshot(cfg, include_connections);
    if let Ok(raw) = read_config_text(cfg) {
        for chunk in crate::ops::split_chunks(&raw) {
            if let Some(key) = chunk.key {
                if ![
                    "mode",
                    "port",
                    "socks-port",
                    "mixed-port",
                    "log-level",
                    "find-process-mode",
                    "allow-lan",
                    "tcp-concurrent",
                ]
                .contains(&key.as_str())
                {
                    continue;
                }
                if let Some((_, value)) = chunk.lines.first().and_then(|l| l.split_once(':')) {
                    let value = crate::ops::clean_scalar(value);
                    if !value.is_empty() {
                        snapshot.config_values.insert(key, value);
                    }
                }
            }
        }
    }
    if !snapshot.running {
        let port = |key: &str| {
            snapshot
                .config_values
                .get(key)
                .and_then(|v| v.parse::<u16>().ok())
                .unwrap_or(0)
        };
        snapshot.http_port = port("port");
        snapshot.socks_port = port("socks-port");
        snapshot.mixed_port = port("mixed-port");
        snapshot.allow_lan = snapshot
            .config_values
            .get("allow-lan")
            .is_some_and(|v| v == "true");
        snapshot.mode = snapshot
            .config_values
            .get("mode")
            .cloned()
            .unwrap_or_else(|| "rule".into());
    }
    snapshot
}

fn fetch_core_snapshot(cfg: &ControllerConfig, include_connections: bool) -> CoreSnapshot {
    let timeout = Duration::from_millis(700);
    let (net_service, sysproxy_enabled) = detect_sysproxy();
    let core_bin_path = discover_mihomo_binary()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "not found".to_string());
    let mut flags = local_flags(cfg);

    let Ok((200, ver_body)) =
        http_request(&cfg.addr, &cfg.secret, "GET", "/version", None, timeout)
    else {
        return snapshot_from_flags(
            false,
            String::new(),
            flags,
            sysproxy_enabled,
            net_service,
            core_bin_path,
        );
    };

    let version = serde_json::from_str::<Value>(&ver_body)
        .ok()
        .and_then(|v| v.get("version").and_then(Value::as_str).map(String::from))
        .unwrap_or_else(|| "unknown".to_string());

    let mut mode = "Rule".to_string();
    let mut http_port = 0;
    let mut socks_port = 0;
    let mut mixed_port = 0;
    let mut allow_lan = false;

    if let Ok((200, cfg_body)) =
        http_request(&cfg.addr, &cfg.secret, "GET", "/configs", None, timeout)
    {
        if let Ok(v) = serde_json::from_str::<Value>(&cfg_body) {
            if let Some(m) = v.get("mode").and_then(Value::as_str) {
                mode = m.to_string();
            }
            http_port = v.get("port").and_then(Value::as_u64).unwrap_or(0) as u16;
            socks_port = v.get("socks-port").and_then(Value::as_u64).unwrap_or(0) as u16;
            mixed_port = v.get("mixed-port").and_then(Value::as_u64).unwrap_or(0) as u16;
            allow_lan = v.get("allow-lan").and_then(Value::as_bool).unwrap_or(false);
            apply_general_json(&mut flags, &v);
        }
    }

    let mut groups = Vec::new();
    let mut nodes = HashMap::new();
    let mut sub_info: Option<SubscriptionSummary> = None;

    if let Ok((200, prox_body)) =
        http_request(&cfg.addr, &cfg.secret, "GET", "/proxies", None, timeout)
    {
        if let Ok(v) = serde_json::from_str::<Value>(&prox_body) {
            if let Some(proxies_obj) = v.get("proxies").and_then(Value::as_object) {
                // Determine ordering from GLOBAL.all if available
                let global_order: Vec<String> = proxies_obj
                    .get("GLOBAL")
                    .and_then(|g| g.get("all"))
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();

                for (name, item) in proxies_obj {
                    let kind = item
                        .get("type")
                        .and_then(Value::as_str)
                        .unwrap_or("Unknown")
                        .to_string();
                    let udp = item.get("udp").and_then(Value::as_bool).unwrap_or(false);
                    let delay = item
                        .get("history")
                        .and_then(Value::as_array)
                        .and_then(|arr| arr.last())
                        .and_then(|h| h.get("delay"))
                        .and_then(Value::as_u64)
                        .and_then(|d| if d > 0 { Some(d as u16) } else { None });

                    if let Some(all_arr) = item.get("all").and_then(Value::as_array) {
                        let all: Vec<String> = all_arr
                            .iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect();
                        if sub_info.is_none() {
                            sub_info = extract_subscription_summary(&all);
                        }
                        let now = item
                            .get("now")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        groups.push(ProxyGroup {
                            name: name.clone(),
                            kind: kind.clone(),
                            now,
                            all,
                        });
                    }

                    nodes.insert(
                        name.clone(),
                        ProxyNode {
                            name: name.clone(),
                            kind,
                            udp,
                            delay,
                            provider: None,
                        },
                    );
                }

                // Filter and sort groups cleanly
                groups.retain(|g| {
                    let k = g.kind.to_ascii_lowercase();
                    (k == "selector" || k == "urltest" || k == "fallback" || k == "loadbalance")
                        && (g.name != "GLOBAL" || mode.eq_ignore_ascii_case("global"))
                });

                groups.sort_by_key(|g| {
                    if g.name.eq_ignore_ascii_case("Proxies")
                        || g.name.eq_ignore_ascii_case("Proxy")
                        || g.name.contains("节点")
                    {
                        0usize
                    } else if let Some(pos) = global_order.iter().position(|n| n == &g.name) {
                        pos + 1
                    } else {
                        999
                    }
                });
            }
        }
    }

    let mut connections = Vec::new();
    let mut connections_ok = false;
    let mut upload_total = 0;
    let mut download_total = 0;

    if include_connections {
        if let Ok((200, conn_body)) =
            http_request(&cfg.addr, &cfg.secret, "GET", "/connections", None, timeout)
        {
            if let Ok(v) = serde_json::from_str::<Value>(&conn_body) {
                (connections, upload_total, download_total) = connections_from_snapshot_json(&v);
                connections_ok = true;
            }
        }
    }

    let mut rules = Vec::new();
    if let Ok((200, body)) = http_request(&cfg.addr, &cfg.secret, "GET", "/rules", None, timeout) {
        rules = parse_rules_json(&body);
    }
    let mut providers = Vec::new();
    if let Ok((200, body)) = http_request(
        &cfg.addr,
        &cfg.secret,
        "GET",
        "/providers/proxies",
        None,
        timeout,
    ) {
        providers.extend(parse_providers_json(&body, "proxy"));
        for found in crate::ops::parse_provider_nodes(&body) {
            let node = nodes.entry(found.name.clone()).or_insert(ProxyNode {
                name: found.name,
                kind: found.kind,
                udp: found.udp,
                delay: found.delay,
                provider: None,
            });
            node.provider.get_or_insert(found.provider);
        }
    }
    if let Ok((200, body)) = http_request(
        &cfg.addr,
        &cfg.secret,
        "GET",
        "/providers/rules",
        None,
        timeout,
    ) {
        providers.extend(parse_providers_json(&body, "rule"));
    }

    CoreSnapshot {
        running: true,
        version,
        mode,
        http_port,
        socks_port,
        mixed_port,
        allow_lan,
        config_values: HashMap::new(),
        sysproxy_enabled,
        network_service: net_service,
        groups,
        nodes,
        connections,
        connections_ok,
        upload_total,
        download_total,
        sub_info,
        core_bin_path,
        tun_enabled: flags.tun_enabled,
        tun_stack: flags.tun_stack,
        tun_device: flags.tun_device,
        sniffing: flags.sniffing,
        ipv6: flags.ipv6,
        tcp_concurrent: flags.tcp_concurrent,
        find_process: flags.find_process,
        dns: flags.dns,
        rules,
        providers,
    }
}

fn snapshot_from_flags(
    running: bool,
    version: String,
    flags: RuntimeFlags,
    sysproxy_enabled: bool,
    network_service: String,
    core_bin_path: String,
) -> CoreSnapshot {
    CoreSnapshot {
        running,
        version,
        sysproxy_enabled,
        network_service,
        core_bin_path,
        tun_enabled: flags.tun_enabled,
        tun_stack: flags.tun_stack,
        tun_device: flags.tun_device,
        sniffing: flags.sniffing,
        ipv6: flags.ipv6,
        tcp_concurrent: flags.tcp_concurrent,
        find_process: flags.find_process,
        dns: flags.dns,
        ..Default::default()
    }
}

pub fn connection_from_value(value: &Value) -> Option<ConnectionItem> {
    let meta = value.get("metadata");
    let text = |key: &str| {
        meta.and_then(|item| item.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let geo = |key: &str| {
        meta.and_then(|item| item.get(key))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default()
    };
    let source_ip = text("sourceIP");
    let source_port = text("sourcePort");
    let source = if source_ip.is_empty() {
        String::new()
    } else {
        format!("{source_ip}:{source_port}")
    };
    let start = value.get("start").and_then(Value::as_str).unwrap_or("");
    Some(ConnectionItem {
        id: value
            .get("id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        host: String::new(),
        network: text("network").to_uppercase(),
        rule: value
            .get("rule")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        chains: String::new(),
        upload: value.get("upload").and_then(Value::as_u64).unwrap_or(0),
        download: value.get("download").and_then(Value::as_u64).unwrap_or(0),
        process: text("process"),
        process_path: text("processPath"),
        inbound: text("type"),
        inbound_name: text("inboundName"),
        source,
        sniff_host: text("sniffHost"),
        rule_payload: value
            .get("rulePayload")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        start: start.to_string(),
        start_ms: crate::conns::parse_rfc3339_ms(start),
        provider: value
            .get("providerChains")
            .and_then(Value::as_array)
            .map(|chain| {
                chain
                    .iter()
                    .rev()
                    .filter_map(Value::as_str)
                    .filter(|name| !name.is_empty())
                    .collect::<Vec<_>>()
                    .join(" › ")
            })
            .unwrap_or_default(),
        dns_mode: text("dnsMode"),
        dest_geo: geo("destinationGeoIP"),
        dest_asn: text("destinationIPASN"),
        up_rate: 0,
        down_rate: 0,
        ai: false,
    })
}

fn extract_subscription_summary(nodes: &[String]) -> Option<SubscriptionSummary> {
    let mut traffic = String::new();
    let mut reset = String::new();
    let mut expire = String::new();

    for name in nodes.iter().take(8) {
        if name.contains("G |") || name.contains("GB") || name.contains("Traffic:") {
            traffic = name.clone();
        } else if name.to_ascii_lowercase().contains("reset") || name.contains("重置") {
            reset = name
                .split([':', '：'])
                .nth(1)
                .unwrap_or(name)
                .trim()
                .to_string();
        } else if name.to_ascii_lowercase().contains("expire") || name.contains("到期") {
            expire = name
                .split([':', '：'])
                .nth(1)
                .unwrap_or(name)
                .trim()
                .to_string();
        }
    }

    if traffic.is_empty() && expire.is_empty() {
        None
    } else {
        Some(SubscriptionSummary {
            traffic,
            reset,
            expire,
        })
    }
}

pub fn select_group_node(cfg: &ControllerConfig, group: &str, node: &str) -> io::Result<()> {
    let path = format!("/proxies/{}", percent_encode(group));
    let body = serde_json::json!({ "name": node }).to_string();
    let (status, _) = http_request(
        &cfg.addr,
        &cfg.secret,
        "PUT",
        &path,
        Some(&body),
        Duration::from_millis(1200),
    )?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(io::Error::other(format!("HTTP {status}")))
    }
}

pub fn switch_routing_mode(cfg: &ControllerConfig, new_mode: &str) -> io::Result<()> {
    let body = serde_json::json!({ "mode": new_mode }).to_string();
    let (status, _) = http_request(
        &cfg.addr,
        &cfg.secret,
        "PATCH",
        "/configs",
        Some(&body),
        Duration::from_millis(1200),
    )?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(io::Error::other(format!("HTTP {status}")))
    }
}

pub fn close_connection(cfg: &ControllerConfig, id: Option<&str>) -> io::Result<()> {
    let path = match id {
        Some(conn_id) => format!("/connections/{}", percent_encode(conn_id)),
        None => "/connections".to_string(),
    };
    let (status, _) = http_request(
        &cfg.addr,
        &cfg.secret,
        "DELETE",
        &path,
        None,
        Duration::from_millis(1200),
    )?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(io::Error::other(format!("HTTP {status}")))
    }
}

pub fn test_group_delays_async(
    cfg: ControllerConfig,
    group_name: String,
    nodes: Vec<String>,
    tx: Sender<BackendEvent>,
) {
    test_delays_async(cfg, group_name, nodes, tx, false);
}

pub fn test_best_delays_async(
    cfg: ControllerConfig,
    group_name: String,
    nodes: Vec<String>,
    tx: Sender<BackendEvent>,
) {
    test_delays_async(cfg, group_name, nodes, tx, true);
}

/// Concurrent delay probes per test run. Workers pull the next node as soon
/// as one finishes, so a slow node never holds back the rest of a batch.
const DELAY_WORKERS: usize = 8;

fn test_delays_async(
    cfg: ControllerConfig,
    group_name: String,
    nodes: Vec<String>,
    tx: Sender<BackendEvent>,
    best: bool,
) {
    thread::spawn(move || {
        let queue: Vec<String> = nodes
            .into_iter()
            .filter(|node| !is_info_pseudo_node(node))
            .collect();
        let next = std::sync::atomic::AtomicUsize::new(0);
        let providers = std::sync::OnceLock::new();
        let mut indexed: Vec<(usize, Option<u16>)> = thread::scope(|scope| {
            let workers: Vec<_> = (0..DELAY_WORKERS.min(queue.len()))
                .map(|_| {
                    let tx = tx.clone();
                    let (cfg, group_name, queue, next, providers) =
                        (&cfg, &group_name, &queue, &next, &providers);
                    scope.spawn(move || {
                        let mut done = Vec::new();
                        loop {
                            let index = next.fetch_add(1, Ordering::Relaxed);
                            let Some(node) = queue.get(index) else {
                                break;
                            };
                            let delay = node_delay_with(cfg, node, &cfg.test_url, providers)
                                .ok()
                                .flatten();
                            let _ = tx.send(BackendEvent::DelayResult {
                                group: group_name.clone(),
                                node: node.clone(),
                                delay,
                            });
                            done.push((index, delay));
                        }
                        done
                    })
                })
                .collect();
            workers
                .into_iter()
                .filter_map(|worker| worker.join().ok())
                .flatten()
                .collect()
        });
        // BestTestDone keeps the group order, as the batched version did.
        indexed.sort_by_key(|(index, _)| *index);
        let results = indexed
            .into_iter()
            .map(|(index, delay)| (queue[index].clone(), delay))
            .collect();
        let _ = tx.send(if best {
            BackendEvent::BestTestDone {
                group: group_name,
                results,
            }
        } else {
            BackendEvent::GroupTestDone { group: group_name }
        });
    });
}

pub fn is_info_pseudo_node(name: &str) -> bool {
    name.contains("G |")
        || name.starts_with("Traffic Reset")
        || name.starts_with("Expire Date")
        || name.contains("剩余流量")
        || name.contains("到期时间")
}

pub fn discover_mihomo_binary() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(home) = std::env::var_os("HOME") {
        candidates.push(PathBuf::from(home).join(".config/terc/core/mihomo"));
    }
    candidates.push(PathBuf::from("/opt/homebrew/bin/mihomo"));
    candidates.push(PathBuf::from("/usr/local/bin/mihomo"));

    for p in candidates {
        if p.is_file() {
            return Some(p);
        }
    }
    if let Ok(output) = Command::new("which").arg("mihomo").output() {
        if output.status.success() {
            let s = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !s.is_empty() {
                return Some(PathBuf::from(s));
            }
        }
    }
    None
}

pub fn validate_listener_ports(text: &str) -> Result<(), String> {
    let mut ports = HashMap::new();
    for chunk in crate::ops::split_chunks(text) {
        let Some(key) = chunk.key else {
            continue;
        };
        if !["port", "socks-port", "mixed-port"].contains(&key.as_str()) {
            continue;
        }
        let port = chunk
            .lines
            .first()
            .and_then(|l| l.split_once(':'))
            .and_then(|(_, v)| crate::ops::clean_scalar(v).parse::<u16>().ok())
            .unwrap_or(0);
        if port == 0 {
            continue;
        }
        if let Some(other) = ports.insert(port, key.clone()) {
            return Err(format!("代理端口冲突 / Proxy port conflict: {other} and {key} both use {port}. Set different ports or disable one listener with 0 under Settings → Proxy."));
        }
    }
    Ok(())
}

fn check_startup_ports(text: &str) -> Result<(), String> {
    for chunk in crate::ops::split_chunks(text) {
        let Some(key) = chunk.key else {
            continue;
        };
        if !["port", "socks-port", "mixed-port"].contains(&key.as_str()) {
            continue;
        }
        let port = chunk
            .lines
            .first()
            .and_then(|l| l.split_once(':'))
            .and_then(|(_, v)| crate::ops::clean_scalar(v).parse::<u16>().ok())
            .unwrap_or(0);
        if port != 0 {
            // The authorized core may bind privileged ports that the UI cannot.
            if let Err(e) = std::net::TcpListener::bind(("127.0.0.1", port)) {
                if e.kind() != io::ErrorKind::PermissionDenied {
                    return Err(format!("{key} :{port} 无法使用 / Port is occupied or unavailable: {e}. Close the other proxy or change this port under Settings → Proxy."));
                }
            }
        }
    }
    let dns = crate::ops::parse_dns_block(text);
    if dns.enable {
        if let Ok(address) = dns.listen.parse::<SocketAddr>() {
            if let Err(e) = std::net::TcpListener::bind(address) {
                if e.kind() != io::ErrorKind::PermissionDenied {
                    return Err(format!("DNS {} 已被占用 / DNS port is occupied or unavailable: {e}. Check for another Mihomo service. No additional core was started.",dns.listen));
                }
            }
            if let Err(e) = std::net::UdpSocket::bind(address) {
                if e.kind() != io::ErrorKind::PermissionDenied {
                    return Err(format!(
                        "DNS {} 已被占用 / DNS port is occupied or unavailable: {e}",
                        dns.listen
                    ));
                }
            }
        }
    }
    Ok(())
}

pub fn core_log_excerpt(cfg: &ControllerConfig) -> String {
    use std::io::{Seek, SeekFrom};
    let Ok(mut file) = fs::File::open(Path::new(&cfg.config_dir).join("terc-core.log")) else {
        return String::new();
    };
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);
    let _ = file.seek(SeekFrom::Start(size.saturating_sub(8192)));
    let mut tail = Vec::new();
    let _ = file.read_to_end(&mut tail);
    let text = String::from_utf8_lossy(&tail);
    let lines: Vec<_> = text.lines().collect();
    lines[lines.len().saturating_sub(24)..].join("\n")
}

pub fn start_core_service(cfg: &ControllerConfig) -> Result<String, String> {
    let bin = discover_mihomo_binary()
        .ok_or("mihomo binary not found  download the managed core first")?;
    let config_file = config_yaml_path(cfg);
    if !config_file.is_file() {
        return Err(format!("config not found: {}", config_file.display()));
    }
    if matches!(
        http_request(
            &cfg.addr,
            &cfg.secret,
            "GET",
            "/version",
            None,
            Duration::from_millis(500)
        ),
        Ok((200, _))
    ) {
        return Ok("Mihomo controller is already running".into());
    }
    if let Ok((pid, _)) = crate::privilege::managed_core(cfg) {
        return Err(format!("Mihomo (PID {pid}) is still running but its controller is not responding. Stop the existing core before restarting.\n{}", core_log_excerpt(cfg)));
    }
    if let Ok(address) = cfg.addr.parse::<SocketAddr>() {
        if TcpStream::connect_timeout(&address, Duration::from_millis(400)).is_ok() {
            return Err(format!("Controller {} is occupied but did not accept this client. Check the controller secret or existing Mihomo service. No additional core was started.", cfg.addr));
        }
    }
    let raw = read_config_text(cfg)?;
    validate_listener_ports(&raw)?;
    check_startup_ports(&raw)?;
    if cfg!(target_os = "macos") && local_flags(cfg).tun_enabled {
        return crate::privilege::start_core(cfg, None);
    }
    let log_path = Path::new(&cfg.config_dir).join("terc-core.log");
    if log_path.is_file() {
        fs::rename(&log_path, log_path.with_file_name("terc-core.previous.log"))
            .map_err(|e| e.to_string())?;
    }
    let log = fs::File::create(&log_path).map_err(|e| e.to_string())?;
    let mut child = Command::new(&bin)
        .arg("-d")
        .arg(&cfg.config_dir)
        .arg("-f")
        .arg(&config_file)
        .arg("-ext-ctl")
        .arg(&cfg.addr)
        .arg("-secret")
        .arg(&cfg.secret)
        .stdin(Stdio::null())
        .stdout(log.try_clone().map_err(|e| e.to_string())?)
        .stderr(log)
        .spawn()
        .map_err(|e| format!("failed to start mihomo: {e}"))?;
    let pid_path = Path::new(&cfg.config_dir).join("terc-core.pid");
    if let Err(err) = fs::write(&pid_path, child.id().to_string()) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(err.to_string());
    }
    // A first start may download GeoIP/GeoSite data before the controller
    // listens, so wait on a deadline while the process stays alive.
    let started = Instant::now();
    loop {
        let exited = child.try_wait().map_err(|e| e.to_string())?;
        let step = core_startup_step(
            exited.is_some(),
            || {
                classify_probe(&http_request(
                    &cfg.addr,
                    &cfg.secret,
                    "GET",
                    "/version",
                    None,
                    Duration::from_millis(200),
                ))
            },
            started.elapsed(),
            || log_suggests_download(&core_log_excerpt(cfg)),
        );
        let reason = match step {
            StartupStep::Wait => {
                thread::sleep(Duration::from_millis(200));
                continue;
            }
            StartupStep::Exited => {
                let _ = fs::remove_file(&pid_path);
                return Err(format!(
                    "Mihomo exited ({}): {}",
                    exited.map(|s| s.to_string()).unwrap_or_default(),
                    fs::read_to_string(&log_path).unwrap_or_default()
                ));
            }
            StartupStep::Ready | StartupStep::StillStarting => {
                thread::spawn(move || {
                    let _ = child.wait();
                });
                if step == StartupStep::Ready {
                    return Ok(format!("Started mihomo ({})", bin.display()));
                }
                // The PID record stays, so the managed-core guard blocks a second launch.
                return Ok(format!(
                    "Mihomo is still starting (downloading geodata?); the controller will come up when it finishes. Log: {}",
                    log_path.display()
                ));
            }
            StartupStep::Rejected(code) => {
                format!("Mihomo controller rejected the request (HTTP {code})")
            }
            StartupStep::TimedOut => format!(
                "Mihomo controller was not ready after {}s",
                CORE_START_DEADLINE.as_secs()
            ),
        };
        // A failed start must not leave an orphan that collides with the next attempt.
        let _ = child.kill();
        let _ = child.wait();
        let _ = fs::remove_file(&pid_path);
        return Err(format!(
            "{reason}; the failed startup was stopped. Log: {}\n{}",
            log_path.display(),
            core_log_excerpt(cfg)
        ));
    }
}

/// Overall window for a fresh core to bring up its controller.
const CORE_START_DEADLINE: Duration = Duration::from_secs(60);

#[derive(Debug, PartialEq, Eq)]
enum CoreProbe {
    Ready,
    Rejected(u16),
    Pending,
}

#[derive(Debug, PartialEq, Eq)]
enum StartupStep {
    Ready,
    Exited,
    Rejected(u16),
    Wait,
    StillStarting,
    TimedOut,
}

fn classify_probe(result: &io::Result<(u16, String)>) -> CoreProbe {
    match result {
        Ok((200, _)) => CoreProbe::Ready,
        Ok((code @ (401 | 403), _)) => CoreProbe::Rejected(*code),
        _ => CoreProbe::Pending,
    }
}

// The probe and the log are evaluated lazily: an exited core is not probed,
// and the log is only read once the deadline has passed.
fn core_startup_step(
    exited: bool,
    probe: impl FnOnce() -> CoreProbe,
    elapsed: Duration,
    downloading: impl FnOnce() -> bool,
) -> StartupStep {
    if exited {
        return StartupStep::Exited;
    }
    match probe() {
        CoreProbe::Ready => StartupStep::Ready,
        CoreProbe::Rejected(code) => StartupStep::Rejected(code),
        CoreProbe::Pending if elapsed < CORE_START_DEADLINE => StartupStep::Wait,
        CoreProbe::Pending if downloading() => StartupStep::StillStarting,
        CoreProbe::Pending => StartupStep::TimedOut,
    }
}

fn log_suggests_download(log: &str) -> bool {
    log.to_ascii_lowercase().contains("download")
}

pub fn stop_core_service(cfg: &ControllerConfig) -> Result<String, String> {
    let (pid, uid) = crate::privilege::managed_core(cfg)?;
    if cfg!(target_os = "macos") && uid == 0 {
        crate::privilege::stop_core(pid)?;
    } else {
        let output = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .output()
            .map_err(|e| e.to_string())?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned());
        }
        let mut stopped = false;
        for _ in 0..25 {
            if crate::privilege::managed_core(cfg).is_err() {
                stopped = true;
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        if !stopped {
            return Err("Stop requested, but managed Mihomo process has not exited".into());
        }
    }
    let _ = fs::remove_file(Path::new(&cfg.config_dir).join("terc-core.pid"));
    let (_, enabled) = detect_sysproxy();
    if enabled {
        set_sysproxy(false, 0, 0)?;
    }
    Ok("Stopped managed Mihomo core".into())
}

pub fn download_subscription(cfg: &ControllerConfig) -> Result<String, String> {
    if cfg.subscription_url.trim().is_empty() {
        return Err("Subscription URL is empty".into());
    }
    let output = Command::new("curl")
        .args([
            "-fsSL",
            "--connect-timeout",
            "10",
            "--max-time",
            "60",
            "-A",
            "clash.meta/1.19.32",
            "--url",
            cfg.subscription_url.trim(),
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err(format!(
            "Failed to download subscription: {}",
            brief(&String::from_utf8_lossy(&output.stderr))
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| e.to_string())
}

/// Download (when `refresh`) and compose subscription + own nodes + private
/// rules into `config.yaml`, validate it with `mihomo -t`, and hot-reload.
pub fn regenerate_config(
    cfg: &ControllerConfig,
    modules: &[crate::ops::ModuleSnippet],
    running: bool,
    refresh: bool,
    zh: bool,
) -> Result<String, String> {
    regenerate_routing(cfg, modules, running, refresh, zh, None)
}

pub fn regenerate_routing(
    cfg: &ControllerConfig,
    modules: &[crate::ops::ModuleSnippet],
    running: bool,
    refresh: bool,
    zh: bool,
    selection: Option<&str>,
) -> Result<String, String> {
    use crate::compose;
    let dir = compose::profile_dir(cfg);
    let old = read_config_text(cfg).ok();
    let route = selection
        .map(str::to_string)
        .unwrap_or_else(|| crate::routing::selected(cfg));
    // Preserve the outgoing configuration before the first explicit switch.
    // This snapshot never becomes the subscription cache.
    if selection.is_some() && !dir.join("routing-local.yaml").exists() {
        if let Some(doc) = &old {
            compose::write_private(&dir.join("routing-local.yaml"), doc)?;
        }
    }
    let has_url = !cfg.subscription_url.trim().is_empty();
    let need_download = refresh
        || (selection == Some("subscription")
            && has_url
            && fs::read_to_string(compose::cache_path(&dir))
                .ok()
                .as_deref()
                .is_none_or(compose::is_generated))
        || (has_url
            && !compose::cache_path(&dir).is_file()
            && old.as_deref().is_none_or(compose::is_generated));
    let fresh = if need_download && has_url {
        Some(download_subscription(cfg)?)
    } else {
        None
    };
    let source_config = if cfg.profile_id.is_empty() {
        old.as_deref()
    } else {
        None
    };
    // Keep imported source documents before any generated output replaces them.
    if !compose::cache_path(&dir).exists() {
        if let Some(doc) = source_config.filter(|doc| !compose::is_generated(doc)) {
            if crate::ops::has_subscription_source(doc) {
                crate::subconv::convert_subscription(doc)?;
                compose::write_private(&compose::cache_path(&dir), doc)?;
            }
        }
    }
    let sub = if compose::ProfileSource::load(&dir).kind == "proxy" {
        None
    } else if let Some(raw) = &fresh {
        Some(crate::subconv::convert_subscription(raw)?)
    } else {
        compose::load_subscription_source(&dir, None, source_config)?
    };
    if selection == Some("subscription")
        && sub.is_none()
        && compose::load_manual_nodes(&dir).is_empty()
    {
        return Err(
            "没有机场原始配置。请在当前订阅中填写订阅地址后重试 / Add a subscription URL first"
                .into(),
        );
    }
    let manual = compose::load_manual_nodes(&dir);
    // Custom rules and AI presets are paused. The source owns routing policy.
    let rules = compose::PrivateRules::default();
    let (base, report) = compose::compose_profile(&compose::ComposeInput {
        subscription: sub.as_ref(),
        manual: &manual,
        rules: &rules,
        controller_addr: &cfg.addr,
        secret: &cfg.secret,
        test_url: &cfg.test_url,
    })?;
    let base = crate::routing::apply(&base, &route, cfg)?;
    let (base, switches) = match old.as_deref() {
        Some(doc) => (
            compose::carry_runtime_state(&crate::ops::strip_marked_modules(doc), &base),
            crate::ops::saved_switches(doc),
        ),
        None => (base, Vec::new()),
    };
    let generated = crate::ops::apply_modules_with_switches(&base, modules, &switches)?;
    // A reload re-initialises proxy providers and drops their connections, so
    // an output identical to the active file is not reloaded at all.
    let candidate = if running {
        keep_runtime_mode(cfg, &generated)
    } else {
        generated.clone()
    };
    let reload = reload_needed(
        old.as_deref(),
        &candidate,
        running,
        RELOAD_UNCERTAIN.load(Ordering::SeqCst),
    );
    // A file kept after an unanswered reload may already be live, so record
    // the matching cache and routing before reporting the unknown outcome.
    let unknown = if !reload {
        None
    } else {
        match install_config_with(
            cfg,
            &generated,
            running,
            discover_mihomo_binary,
            &INSTALL_LIMITS,
        ) {
            Ok(()) => None,
            Err(failure) if failure.kept => Some(failure.message),
            Err(failure) => return Err(failure.message),
        }
    };
    if let Some(raw) = fresh {
        compose::write_private(&compose::cache_path(&dir), &raw)?;
    }
    if let Some(route) = selection {
        let mut source = compose::ProfileSource::load(&dir);
        source.routing = route.into();
        source.save(&dir)?;
    }
    if !cfg.profile_id.is_empty() {
        compose::write_private(
            &compose::terc_dir()
                .join("generated")
                .join(format!("{}.yaml", cfg.profile_id)),
            &generated,
        )?;
    }
    if let Some(message) = unknown {
        return Err(message);
    }
    let tail = match (reload, running, zh) {
        (false, true, true) => " — 配置未变化，未重载，现有连接不受影响",
        (false, true, false) => " — unchanged; not reloaded, existing connections kept",
        (false, false, true) => " — 配置未变化，内核未运行",
        (false, false, false) => " — unchanged; core stopped",
        (true, true, true) => " — 已校验并热重载",
        (true, true, false) => " — validated & hot-reloaded",
        (true, false, true) => " — 已校验保存，内核未运行",
        (true, false, false) => " — validated & saved; core stopped",
    };
    Ok(format!("{}{tail}{}", report.summary(zh), report.details()))
}

/// Validate before replacing the active file. Keep disk and runtime on the old
/// configuration if the controller rejects the candidate.
pub fn install_config(cfg: &ControllerConfig, text: &str, running: bool) -> Result<(), String> {
    install_config_with(cfg, text, running, discover_mihomo_binary, &INSTALL_LIMITS)
        .map_err(|failure| failure.message)
}

/// How long `mihomo -t` may run, how long once its output shows a geodata
/// download, and how long the controller may stay silent after an unanswered
/// reload before its outcome is reported as unknown.
struct InstallLimits {
    check: Duration,
    download: Duration,
    settle: Duration,
}

const INSTALL_LIMITS: InstallLimits = InstallLimits {
    check: Duration::from_secs(60),
    // A first check fetches missing GeoIP/GeoSite files before it can finish;
    // stopping it discards the partial file, so a slow link never gets past.
    download: Duration::from_secs(600),
    settle: Duration::from_secs(30),
};

struct InstallFailure {
    message: String,
    /// The new file stayed on disk because the reload outcome is unknown.
    kept: bool,
}

impl From<String> for InstallFailure {
    fn from(message: String) -> Self {
        Self {
            message,
            kept: false,
        }
    }
}

impl From<&str> for InstallFailure {
    fn from(message: &str) -> Self {
        message.to_string().into()
    }
}

fn install_config_with(
    cfg: &ControllerConfig,
    text: &str,
    running: bool,
    find_bin: impl FnOnce() -> Option<PathBuf>,
    limits: &InstallLimits,
) -> Result<(), InstallFailure> {
    validate_listener_ports(text)?;
    fs::create_dir_all(&cfg.config_dir).map_err(|e| e.to_string())?;
    // A force reload applies the file's `mode`, so keep a mode that was only
    // switched at runtime.
    let text = if running {
        keep_runtime_mode(cfg, text)
    } else {
        text.to_string()
    };
    let candidate = Path::new(&cfg.config_dir).join(".terc-candidate.yaml");
    write_private(&candidate, text.as_bytes()).map_err(|e| e.to_string())?;
    let result = (|| {
        let bin =
            find_bin().ok_or("Install the managed Mihomo core before saving a configuration")?;
        check_candidate(&bin, cfg, &candidate, limits)?;
        let path = config_yaml_path(cfg);
        let previous = match fs::read(&path) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(e.to_string().into()),
        };
        fs::rename(&candidate, &path).map_err(|e| e.to_string())?;
        if !running {
            return Ok(());
        }
        match reload_config(cfg) {
            Ok(()) => {
                RELOAD_UNCERTAIN.store(false, Ordering::SeqCst);
                Ok(())
            }
            Err(ReloadError::Rejected(err)) => {
                let restored = match previous {
                    Some(bytes) => write_private(&path, &bytes),
                    None => fs::remove_file(&path),
                };
                Err(match restored {
                    Ok(()) => format!("{err}; previous configuration restored"),
                    Err(restore) => {
                        format!("{err}; could not restore previous configuration: {restore}")
                    }
                }
                .into())
            }
            // Mihomo finishes applying a PUT after the client gives up, so the
            // new file may already be live. Never roll back on a lost reply.
            // Either way the running config may differ from the file, so the
            // next regeneration reloads even when its output is unchanged.
            Err(ReloadError::Unknown(_)) if controller_answers(cfg, limits.settle) => {
                RELOAD_UNCERTAIN.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(ReloadError::Unknown(err)) => {
                RELOAD_UNCERTAIN.store(true, Ordering::SeqCst);
                Err(InstallFailure {
                    message: format!(
                        "热重载结果未知，新配置已保留在磁盘上 / Reload outcome unknown ({err}); the new configuration was kept on disk"
                    ),
                    kept: true,
                })
            }
        }
    })();
    let _ = fs::remove_file(candidate);
    result
}

/// Run `mihomo -t` on the candidate, stopping a check that hangs.
fn check_candidate(
    bin: &Path,
    cfg: &ControllerConfig,
    candidate: &Path,
    limits: &InstallLimits,
) -> Result<(), String> {
    let mut child = Command::new(bin)
        .arg("-t")
        .arg("-d")
        .arg(&cfg.config_dir)
        .arg("-f")
        .arg(candidate)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| e.to_string())?;
    // Drain both pipes so a chatty check cannot block on a full buffer; the
    // output read so far shows whether the check is downloading geodata.
    fn drain(
        pipe: Option<impl Read + Send + 'static>,
        out: &Arc<Mutex<Vec<u8>>>,
    ) -> thread::JoinHandle<()> {
        let out = Arc::clone(out);
        thread::spawn(move || {
            let Some(mut pipe) = pipe else {
                return;
            };
            let mut buf = [0u8; 4096];
            while let Ok(n) = pipe.read(&mut buf) {
                if n == 0 {
                    break;
                }
                if let Ok(mut out) = out.lock() {
                    out.extend_from_slice(&buf[..n]);
                }
            }
        })
    }
    let (out, err) = (Arc::default(), Arc::default());
    let stdout = drain(child.stdout.take(), &out);
    let stderr = drain(child.stderr.take(), &err);
    let text = |buf: &Arc<Mutex<Vec<u8>>>| {
        buf.lock()
            .map(|b| String::from_utf8_lossy(&b).into_owned())
            .unwrap_or_default()
    };
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            break status;
        }
        let elapsed = started.elapsed();
        if elapsed >= limits.check
            && (elapsed >= limits.download
                || !log_suggests_download(&format!("{}{}", text(&out), text(&err))))
        {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "Configuration check did not finish within {}s and was stopped",
                elapsed.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(50));
    };
    if status.success() {
        return Ok(());
    }
    let _ = (stdout.join(), stderr.join());
    let (stdout, stderr) = (text(&out), text(&err));
    Err(format!(
        "Configuration rejected: {} {}",
        stdout.trim(),
        stderr.trim()
    ))
}

/// Poll the controller after a reload that got no reply.
fn controller_answers(cfg: &ControllerConfig, settle: Duration) -> bool {
    let started = Instant::now();
    loop {
        if matches!(
            http_request(
                &cfg.addr,
                &cfg.secret,
                "GET",
                "/version",
                None,
                Duration::from_millis(1000),
            ),
            Ok((200, _))
        ) {
            return true;
        }
        if started.elapsed() >= settle {
            return false;
        }
        thread::sleep(Duration::from_millis(250));
    }
}

fn keep_runtime_mode(cfg: &ControllerConfig, text: &str) -> String {
    let runtime = read_runtime_config(cfg).ok();
    match runtime
        .as_ref()
        .and_then(|v| v.get("mode"))
        .and_then(Value::as_str)
    {
        Some(mode) => with_mode(text, &mode.to_ascii_lowercase()),
        None => text.to_string(),
    }
}

/// Set the top-level `mode`. With modules applied, the base kept in the header
/// is updated too, so disabling a module does not bring the old mode back.
fn with_mode(doc: &str, mode: &str) -> String {
    use crate::ops::set_top_scalar;
    let literal = serde_json::to_string(mode).unwrap();
    // Header layout written by ops::apply_modules_with_switches.
    let mut parts = doc.splitn(3, '\n');
    if let (Some(head), Some(switches), Some(effective)) =
        (parts.next(), parts.next(), parts.next())
    {
        let base = head
            .strip_prefix("# terc-base: ")
            .and_then(|v| serde_json::from_str::<String>(v).ok());
        if let Some(base) = base.filter(|_| switches.starts_with("# terc-switches: ")) {
            return format!(
                "# terc-base: {}\n{switches}\n{}",
                serde_json::to_string(&set_top_scalar(&base, "mode", &literal)).unwrap(),
                set_top_scalar(effective, "mode", &literal)
            );
        }
    }
    set_top_scalar(doc, "mode", &literal)
}

/// Write a file only the user can read (configs hold node credentials and the
/// controller secret), replacing any existing file atomically.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = fs::remove_file(&tmp);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let written = options
        .open(&tmp)
        .and_then(|mut file| file.write_all(bytes))
        .and_then(|()| fs::rename(&tmp, path));
    if written.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    written
}

pub fn mihomo_asset_id_for(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("macos", "x86_64") => Some("darwin-amd64"),
        ("linux", "aarch64") => Some("linux-arm64"),
        ("linux", "x86_64") => Some("linux-amd64"),
        _ => None,
    }
}

pub fn mihomo_asset_id() -> Option<&'static str> {
    mihomo_asset_id_for(std::env::consts::OS, std::env::consts::ARCH)
}

pub fn mihomo_asset_label() -> String {
    match mihomo_asset_id() {
        Some(id) => format!("mihomo-{id}"),
        None => "unsupported".to_string(),
    }
}

pub fn mihomo_release_grep(asset: &str) -> String {
    format!(r#"https://[^"]*mihomo-{asset}-v[^"]*\.gz"#)
}

fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', r#"'\''"#))
}

pub fn managed_core_script(asset: &str, gz: &str, bin: &str) -> String {
    let pattern = mihomo_release_grep(asset);
    format!(
        r#"URL=$(curl -fsSL https://api.github.com/repos/MetaCubeX/mihomo/releases/latest | grep -o '{pattern}' | head -n 1); if [ -n "$URL" ]; then curl -fsSL "$URL" -o {gz} && gunzip -f {gz} && chmod +x {bin}; else exit 1; fi"#,
        pattern = pattern,
        gz = shell_quote(gz),
        bin = shell_quote(bin),
    )
}

fn install_managed_core(tx: &Sender<BackendEvent>) -> Result<String, String> {
    let asset = mihomo_asset_id().ok_or_else(|| {
        "No mihomo build for this OS/CPU (darwin-arm64, darwin-amd64, linux-arm64, linux-amd64)"
            .to_string()
    })?;
    let home = std::env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    let core_dir = PathBuf::from(home).join(".config/terc/core");
    fs::create_dir_all(&core_dir)
        .map_err(|err| format!("Cannot create {}: {err}", core_dir.display()))?;
    let bin_path = core_dir.join("mihomo");
    let gz_path = core_dir.join("mihomo.gz");
    let _ = tx.send(BackendEvent::StatusMessage {
        text: format!("Checking latest mihomo-{asset} release..."),
        is_error: false,
    });
    let script = managed_core_script(
        asset,
        &gz_path.display().to_string(),
        &bin_path.display().to_string(),
    );
    let ok = matches!(
        Command::new("sh")
            .arg("-c")
            .arg(&script)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status(),
        Ok(status) if status.success()
    );
    if ok {
        Ok(bin_path.display().to_string())
    } else {
        Err(format!("Failed to download mihomo-{asset} from GitHub"))
    }
}

pub fn download_managed_core_async(tx: Sender<BackendEvent>) {
    thread::spawn(move || {
        let (text, ok) = match install_managed_core(&tx) {
            Ok(path) => (format!("Managed core installed to {path}"), true),
            Err(err) => (err, false),
        };
        let _ = tx.send(BackendEvent::StatusMessage {
            text,
            is_error: !ok,
        });
        let _ = tx.send(BackendEvent::CoreDownloadDone { ok });
    });
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SysproxyBackend {
    Macos,
    Gnome,
    Unavailable,
}

pub fn sysproxy_backend_for(os: &str, gnome_ready: bool) -> SysproxyBackend {
    match os {
        "macos" => SysproxyBackend::Macos,
        "linux" if gnome_ready => SysproxyBackend::Gnome,
        _ => SysproxyBackend::Unavailable,
    }
}

/// GVariant text values for `gsettings set`. Strings keep their quotes; the port is an int.
pub fn gnome_proxy_commands(enable: bool, http_port: u16, socks_port: u16) -> Vec<Vec<String>> {
    let set = |schema: &str, key: &str, value: &str| {
        vec![
            "gsettings".to_string(),
            "set".to_string(),
            schema.to_string(),
            key.to_string(),
            value.to_string(),
        ]
    };
    if !enable {
        return vec![set("org.gnome.system.proxy", "mode", "'none'")];
    }
    let http = http_port.to_string();
    let socks = socks_port.to_string();
    vec![
        set("org.gnome.system.proxy.http", "host", "'127.0.0.1'"),
        set("org.gnome.system.proxy.http", "port", &http),
        set("org.gnome.system.proxy.https", "host", "'127.0.0.1'"),
        set("org.gnome.system.proxy.https", "port", &http),
        set(
            "org.gnome.system.proxy.socks",
            "host",
            if socks_port > 0 { "'127.0.0.1'" } else { "''" },
        ),
        set("org.gnome.system.proxy.socks", "port", &socks),
        set("org.gnome.system.proxy", "mode", "'manual'"),
    ]
}

fn detect_gnome_sysproxy() -> Option<(String, bool)> {
    let output = Command::new("gsettings")
        .args(["get", "org.gnome.system.proxy", "mode"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    Some(("GNOME".to_string(), text.contains("'manual'")))
}

fn gnome_proxy_ready() -> bool {
    detect_gnome_sysproxy().is_some()
}

pub fn detect_sysproxy() -> (String, bool) {
    // Unit tests drive real key paths whose workers fetch a snapshot; they must
    // never run networksetup or gsettings (AGENTS.md), not even to read.
    if cfg!(test) {
        return ("n/a".to_string(), false);
    }
    match std::env::consts::OS {
        "macos" => detect_macos_sysproxy(),
        "linux" => detect_gnome_sysproxy().unwrap_or_else(|| ("n/a".to_string(), false)),
        _ => ("n/a".to_string(), false),
    }
}

fn detect_macos_sysproxy() -> (String, bool) {
    let Some(service) = active_macos_network_service() else {
        return ("n/a".into(), false);
    };
    let output = Command::new("networksetup")
        .args(["-getwebproxy", &service])
        .output();
    if let Ok(out) = output {
        let text = String::from_utf8_lossy(&out.stdout);
        let enabled = text.lines().any(|l| l.trim() == "Enabled: Yes");
        return (service, enabled);
    }
    (service, false)
}

fn network_services(output: &str) -> Vec<(String, String)> {
    let mut services = Vec::new();
    let mut pending = None;
    for line in output.lines().map(str::trim) {
        if let Some(rest) = line.strip_prefix('(') {
            if let Some((number, name)) = rest.split_once(") ") {
                if number.parse::<usize>().is_ok() {
                    pending = (!name.starts_with('*')).then(|| name.to_string());
                    continue;
                }
            }
        }
        if let Some((_, device)) = line.split_once("Device: ") {
            let device = device.trim_end_matches(')').trim();
            if let Some(name) = pending.take() {
                if !device.is_empty() {
                    services.push((name, device.to_string()));
                }
            }
        }
    }
    services
}

fn active_nwi_interfaces(output: &str) -> Vec<String> {
    let mut interfaces = Vec::new();
    for line in output.lines().map(str::trim) {
        if let Some((name, flags)) = line.split_once(" : flags") {
            if flags.contains("IPv4") || flags.contains("IPv6") {
                let name = name.trim();
                if !interfaces.iter().any(|n| n == name) {
                    interfaces.push(name.to_string());
                }
            }
        }
    }
    interfaces
}

fn select_network_service(
    services: &[(String, String)],
    primary: Option<&str>,
    active: &[String],
) -> Option<String> {
    if let Some(primary) = primary {
        if let Some((name, _)) = services.iter().find(|(_, device)| device == primary) {
            return Some(name.clone());
        }
    }
    services
        .iter()
        .find(|(_, device)| active.contains(device))
        .map(|(name, _)| name.clone())
}

fn active_macos_network_service() -> Option<String> {
    let primary_interface = scutil_value("State:/Network/Global/IPv4", "PrimaryInterface")
        .or_else(|| scutil_value("State:/Network/Global/IPv6", "PrimaryInterface"));
    // A packet tunnel can be PrimaryService without a Setup/UserDefinedName.
    // Map the active underlying hardware interface to its actual service name.
    let output = Command::new("/usr/sbin/networksetup")
        .arg("-listnetworkserviceorder")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let services = network_services(&String::from_utf8_lossy(&output.stdout));
    if let Some(name) = select_network_service(&services, primary_interface.as_deref(), &[]) {
        return Some(name);
    }
    let output = Command::new("/usr/sbin/scutil")
        .arg("--nwi")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    select_network_service(
        &services,
        None,
        &active_nwi_interfaces(&String::from_utf8_lossy(&output.stdout)),
    )
}

pub(crate) fn macos_tun_route_conflict() -> Option<String> {
    let output = Command::new("/usr/sbin/scutil")
        .args(["--nc", "list"])
        .output()
        .ok()?;
    let connections = connected_vpns(&String::from_utf8_lossy(&output.stdout));
    if connections.is_empty() {
        return None;
    }
    let route = Command::new("/sbin/route")
        .args(["-n", "get", "1.0.0.1"])
        .output()
        .ok()?;
    if conflicting_tun_route(&String::from_utf8_lossy(&route.stdout)) {
        Some(format!("TUN 路由冲突：{} 已连接并占用 1.0.0.0/8 所在的虚拟网卡路由。请先在该 VPN 中断开，再开启 terc TUN；未删除任何路由 / Disconnect the other VPN before enabling terc TUN: {}", connections.join(", "), connections.join(", ")))
    } else {
        None
    }
}

fn connected_vpns(output: &str) -> Vec<String> {
    output
        .lines()
        .filter(|line| line.contains("(Connected)"))
        .filter_map(|line| {
            let (_, rest) = line.split_once('"')?;
            Some(rest.split_once('"')?.0.to_string())
        })
        .collect()
}

fn conflicting_tun_route(output: &str) -> bool {
    let field = |name| {
        output.lines().find_map(|line| {
            let (key, value) = line.trim().split_once(':')?;
            (key == name).then(|| value.trim())
        })
    };
    field("destination") == Some("1.0.0.0")
        && field("mask") == Some("255.0.0.0")
        && field("interface").is_some_and(|name| name.starts_with("utun"))
}

fn scutil_value(key: &str, field: &str) -> Option<String> {
    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    writeln!(child.stdin.take()?, "show {key}").ok()?;
    let output = child.wait_with_output().ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .find_map(|line| {
            let (name, value) = line.trim().split_once(" : ")?;
            (name == field).then(|| value.trim().to_string())
        })
}

pub fn patch_configs(cfg: &ControllerConfig, body: &str) -> io::Result<()> {
    let (status, text) = http_request(
        &cfg.addr,
        &cfg.secret,
        "PATCH",
        "/configs",
        Some(body),
        Duration::from_millis(1500),
    )?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(io::Error::other(format!("HTTP {status} {}", brief(&text))))
    }
}

pub(crate) fn read_runtime_config(cfg: &ControllerConfig) -> io::Result<Value> {
    let (status, body) = http_request(
        &cfg.addr,
        &cfg.secret,
        "GET",
        "/configs",
        None,
        Duration::from_millis(1500),
    )?;
    if status != 200 {
        return Err(io::Error::other(format!(
            "Read runtime config: HTTP {status}"
        )));
    }
    serde_json::from_str(&body).map_err(io::Error::other)
}

pub fn set_tun_enabled(cfg: &ControllerConfig, enable: bool) -> io::Result<()> {
    // Mihomo replaces nested TUN settings on PATCH; preserve the complete object.
    let current = read_runtime_config(cfg)?;
    let body = crate::ops::tun_patch_from_config(&current, enable).map_err(io::Error::other)?;
    let offset = fs::metadata(Path::new(&cfg.config_dir).join("terc-core.log"))
        .map(|m| m.len() as usize)
        .unwrap_or(0);
    announce_disruption(crate::conns::Cause::Tun, crate::conns::Scope::TunInbound);
    patch_configs(cfg, &body)?;
    let actual = read_runtime_config(cfg)?;
    if let Some(error) = crate::privilege::tun_log_error(cfg, offset) {
        return Err(io::Error::other(error));
    }
    if actual.pointer("/tun/enable").and_then(Value::as_bool) != Some(enable) {
        return Err(io::Error::other("Mihomo accepted the request but TUN did not reach the requested state. Check core logs and administrator permissions; external cores must be authorized by their service manager."));
    }
    Ok(())
}

pub fn set_bool_config(cfg: &ControllerConfig, field: &str, enable: bool) -> io::Result<()> {
    patch_configs(cfg, &bool_patch_body(field, enable))
}

pub fn set_rule_disabled(cfg: &ControllerConfig, index: usize, disabled: bool) -> io::Result<()> {
    let body = rule_disable_body(index, disabled);
    let (status, text) = http_request(
        &cfg.addr,
        &cfg.secret,
        "PATCH",
        "/rules/disable",
        Some(&body),
        Duration::from_millis(1500),
    )?;
    if (200..300).contains(&status) {
        Ok(())
    } else {
        Err(io::Error::other(format!("HTTP {status} {}", brief(&text))))
    }
}

/// Only an explicit rejection proves the core kept its previous configuration.
#[derive(Debug)]
pub enum ReloadError {
    /// The controller answered with an HTTP error.
    Rejected(String),
    /// No answer (I/O error or timeout); the core may still apply the file.
    Unknown(String),
}

impl std::fmt::Display for ReloadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(text) | Self::Unknown(text) => f.write_str(text),
        }
    }
}

pub fn reload_config(cfg: &ControllerConfig) -> Result<(), ReloadError> {
    let path = config_yaml_path(cfg);
    let body = serde_json::json!({
        "path": path.display().to_string(),
        "payload": ""
    })
    .to_string();
    // Mihomo re-initialises every proxy provider on reload (§2.2 of
    // docs/websocket-plan.md); top-level `proxies:` connections stay.
    announce_disruption(crate::conns::Cause::Reload, crate::conns::Scope::Providers);
    // The first fetch of new providers runs inside the request, so allow well
    // beyond Mihomo's own provider download timeout.
    match http_request(
        &cfg.addr,
        &cfg.secret,
        "PUT",
        "/configs?force=true",
        Some(&body),
        Duration::from_millis(cfg.timeout_ms.max(90_000)),
    ) {
        Ok((status, _)) if (200..300).contains(&status) => Ok(()),
        Ok((status, text)) => Err(ReloadError::Rejected(format!(
            "reload HTTP {status} {}",
            brief(&text)
        ))),
        Err(err) => Err(ReloadError::Unknown(err.to_string())),
    }
}

/// Set when a reload got no clear answer, so the core may not run the file.
pub(crate) static RELOAD_UNCERTAIN: AtomicBool = AtomicBool::new(false);

thread_local! {
    /// The UI channel of a `run_action` worker. Each worker runs one action,
    /// so a thread-local reaches the reload and TUN paths deep inside it.
    static DISRUPTION_TX: std::cell::RefCell<Option<Sender<BackendEvent>>> =
        const { std::cell::RefCell::new(None) };
}

/// Lets this thread's reloads and TUN rebuilds report themselves to the UI.
pub fn report_disruptions(tx: Sender<BackendEvent>) {
    DISRUPTION_TX.with(|cell| *cell.borrow_mut() = Some(tx));
}

/// Sent just before the request that cuts connections, so a skipped reload
/// (unchanged output) or an action that fails earlier blames nothing.
pub(crate) fn announce_disruption(cause: crate::conns::Cause, scope: crate::conns::Scope) {
    DISRUPTION_TX.with(|cell| {
        if let Some(tx) = cell.borrow().as_ref() {
            let _ = tx.send(BackendEvent::Disrupting { cause, scope });
        }
    });
}

/// Whether installing `candidate` needs `mihomo -t` and a reload.
fn reload_needed(old: Option<&str>, candidate: &str, running: bool, uncertain: bool) -> bool {
    old != Some(candidate) || (running && uncertain)
}

/// Validate and save `text` with the runtime mode kept, without a reload; the
/// caller applies the change live.
pub fn install_config_keep_mode(cfg: &ControllerConfig, text: &str) -> Result<(), String> {
    let text = keep_runtime_mode(cfg, text);
    install_config_with(cfg, &text, false, discover_mihomo_binary, &INSTALL_LIMITS)
        .map_err(|failure| failure.message)
}

/// `PATCH /configs` a key Mihomo applies live, then read it back. Listener rebuilds
/// close only the listening socket, so established connections continue.
/// An `Err` means the change may not be live and the caller should reload.
pub fn patch_config_value(cfg: &ControllerConfig, key: &str, value: &Value) -> Result<(), String> {
    let body = serde_json::json!({ key: value }).to_string();
    let (status, text) = http_request(
        &cfg.addr,
        &cfg.secret,
        "PATCH",
        "/configs",
        Some(&body),
        Duration::from_millis(1200),
    )
    .map_err(|e| e.to_string())?;
    if !(200..300).contains(&status) {
        return Err(format!("HTTP {status} {}", brief(&text)));
    }
    let runtime = read_runtime_config(cfg).map_err(|e| e.to_string())?;
    // An older core that does not report the key cannot be checked.
    let Some(actual) = runtime.get(key) else {
        return Ok(());
    };
    let matches = match key {
        "allow-lan" | "tcp-concurrent" => {
            actual.as_bool().is_some() && actual.as_bool() == value.as_bool()
        }
        "find-process-mode" | "log-level" => actual
            .as_str()
            .zip(value.as_str())
            .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b)),
        _ => actual.as_u64().is_some() && actual.as_u64() == value.as_u64(),
    };
    if matches {
        Ok(())
    } else {
        Err(format!("{key} reads back as {actual}"))
    }
}

pub fn persist_nested_bool(
    cfg: &ControllerConfig,
    path: &[&str],
    value: bool,
) -> Result<(), String> {
    let raw = read_config_text(cfg)?;
    let next = crate::ops::set_nested_bool(&raw, path, value);
    install_config(cfg, &next, false)
}

/// Record a mode switched at runtime so later reloads and restarts keep it.
/// The core already runs it, so this only writes the file.
pub fn persist_mode(cfg: &ControllerConfig, mode: &str) -> Result<(), String> {
    let raw = read_config_text(cfg)?;
    write_private(&config_yaml_path(cfg), with_mode(&raw, mode).as_bytes())
        .map_err(|e| e.to_string())
}

pub fn query_dns(cfg: &ControllerConfig, name: &str, qtype: &str) -> Result<DnsMessage, String> {
    let path = format!(
        "/dns/query?name={}&type={}",
        percent_encode(name),
        percent_encode(qtype)
    );
    match http_request(
        &cfg.addr,
        &cfg.secret,
        "GET",
        &path,
        None,
        Duration::from_millis(cfg.timeout_ms.max(1500)),
    ) {
        Ok((200, body)) => parse_dns_message(&body).map_err(|err| brief(&err)),
        Ok((status, body)) => Err(format!("HTTP {status} {}", brief(&body))),
        Err(err) => Err(err.to_string()),
    }
}

pub fn dns_query_async(
    cfg: ControllerConfig,
    name: String,
    qtype: String,
    tx: Sender<BackendEvent>,
) {
    thread::spawn(move || {
        let (lines, is_error) = match query_dns(&cfg, &name, &qtype) {
            Ok(msg) => (format_dns_lines(&name, &qtype, &msg), false),
            Err(err) => (vec![err], true),
        };
        let _ = tx.send(BackendEvent::DnsLookup { lines, is_error });
    });
}

fn format_dns_lines(name: &str, qtype: &str, msg: &DnsMessage) -> Vec<String> {
    let mut lines = vec![format!("{name}  {qtype}  rcode {}", msg.status)];
    if msg.answers.is_empty() {
        lines.push("no answer".to_string());
    } else {
        for answer in &msg.answers {
            lines.push(format!(
                "{:<6} {:<6} {}",
                answer.qtype,
                format!("{}s", answer.ttl),
                answer.data
            ));
        }
    }
    lines
}

pub fn flush_dns(cfg: &ControllerConfig) -> Result<String, String> {
    let mut done = Vec::new();
    let mut errors = Vec::new();
    for (label, path) in [
        ("dns", "/cache/dns/flush"),
        ("fake-ip", "/cache/fakeip/flush"),
    ] {
        match http_request(
            &cfg.addr,
            &cfg.secret,
            "POST",
            path,
            Some(""),
            Duration::from_millis(1500),
        ) {
            Ok((status, _)) if (200..300).contains(&status) => done.push(label),
            Ok((status, body)) => errors.push(format!("{label} HTTP {status} {}", brief(&body))),
            Err(err) => errors.push(format!("{label} {err}")),
        }
    }
    if done.is_empty() {
        Err(errors.join("  "))
    } else {
        Ok(format!("flushed {}", done.join(" + ")))
    }
}

pub fn flush_dns_async(cfg: ControllerConfig, tx: Sender<BackendEvent>) {
    thread::spawn(move || {
        let (text, is_error) = match flush_dns(&cfg) {
            Ok(text) => (text, false),
            Err(err) => (err, true),
        };
        let _ = tx.send(BackendEvent::StatusMessage { text, is_error });
    });
}

pub fn refresh_provider(cfg: &ControllerConfig, kind: &str, name: &str) -> Result<(), String> {
    let path = format!("/providers/{kind}/{}", percent_encode(name));
    match http_request(
        &cfg.addr,
        &cfg.secret,
        "PUT",
        &path,
        None,
        // Mihomo downloads and parses the provider before it answers.
        Duration::from_secs(30),
    ) {
        Ok((status, _)) if (200..300).contains(&status) => Ok(()),
        Ok((status, body)) => Err(format!("HTTP {status} {}", brief(&body))),
        Err(err) => Err(err.to_string()),
    }
}

pub fn provider_healthcheck(cfg: &ControllerConfig, name: &str) -> Result<(), String> {
    let path = format!("/providers/proxies/{}/healthcheck", percent_encode(name));
    match http_request(
        &cfg.addr,
        &cfg.secret,
        "GET",
        &path,
        None,
        Duration::from_millis(4000),
    ) {
        Ok((status, _)) if (200..300).contains(&status) => Ok(()),
        Ok((status, body)) => Err(format!("HTTP {status} {}", brief(&body))),
        Err(err) => Err(err.to_string()),
    }
}

pub fn refresh_provider_async(
    cfg: ControllerConfig,
    kind: String,
    name: String,
    tx: Sender<BackendEvent>,
) {
    thread::spawn(move || {
        let result = refresh_provider(&cfg, &kind, &name);
        let ok = result.is_ok();
        let text = match result {
            Ok(()) => format!("provider updated  {name}"),
            Err(err) => err,
        };
        if ok {
            let snap = fetch_snapshot(&cfg);
            let _ = tx.send(BackendEvent::Snapshot(Box::new(snap)));
        }
        let _ = tx.send(BackendEvent::StatusMessage {
            text,
            is_error: !ok,
        });
    });
}

pub fn refresh_all_providers_async(cfg: ControllerConfig, tx: Sender<BackendEvent>) {
    thread::spawn(move || {
        let snap = fetch_snapshot(&cfg);
        let mut ok = 0usize;
        let mut failed = 0usize;
        for provider in &snap.providers {
            if refresh_provider(&cfg, &provider.kind, &provider.name).is_ok() {
                ok += 1;
            } else {
                failed += 1;
            }
        }
        let fresh = fetch_snapshot(&cfg);
        let _ = tx.send(BackendEvent::Snapshot(Box::new(fresh)));
        let _ = tx.send(BackendEvent::StatusMessage {
            text: format!("providers {ok} updated  {failed} failed"),
            is_error: ok == 0 && failed > 0,
        });
    });
}

pub fn test_node_delay(
    cfg: &ControllerConfig,
    node: &str,
    url: &str,
) -> Result<Option<u16>, String> {
    node_delay_with(cfg, node, url, &std::sync::OnceLock::new())
}

/// GET /proxies/{name}/delay, falling back to the provider healthcheck route
/// on 404: since Mihomo v1.19.28 the former only resolves inline proxies.
/// `providers` maps node to provider and is fetched at most once per run.
fn node_delay_with(
    cfg: &ControllerConfig,
    node: &str,
    url: &str,
    providers: &std::sync::OnceLock<HashMap<String, String>>,
) -> Result<Option<u16>, String> {
    let query = format!("url={}&timeout={}", percent_encode(url), cfg.timeout_ms);
    let get = |path: &str| {
        http_request(
            &cfg.addr,
            &cfg.secret,
            "GET",
            path,
            None,
            Duration::from_millis(cfg.timeout_ms + 500),
        )
    };
    let mut response = get(&format!("/proxies/{}/delay?{query}", percent_encode(node)));
    if matches!(response, Ok((404, _))) {
        let providers = providers.get_or_init(|| {
            match get("/providers/proxies") {
                Ok((200, body)) => crate::ops::parse_provider_nodes(&body),
                _ => Vec::new(),
            }
            .into_iter()
            .map(|found| (found.name, found.provider))
            .collect()
        });
        if let Some(provider) = providers.get(node) {
            response = get(&format!(
                "/providers/proxies/{}/{}/healthcheck?{query}",
                percent_encode(provider),
                percent_encode(node)
            ));
        }
    }
    match response {
        Ok((200, body)) => Ok(serde_json::from_str::<Value>(&body)
            .ok()
            .and_then(|v| v.get("delay").and_then(Value::as_u64))
            .and_then(|d| if d > 0 { Some(d as u16) } else { None })),
        Ok((status, body)) => Err(format!("HTTP {status} {}", brief(&body))),
        Err(err) => Err(err.to_string()),
    }
}

pub fn test_node_async(cfg: ControllerConfig, node: String, tx: Sender<BackendEvent>) {
    thread::spawn(move || {
        let delay = test_node_delay(&cfg, &node, &cfg.test_url).ok().flatten();
        let _ = tx.send(BackendEvent::DelayResult {
            group: String::new(),
            node,
            delay,
        });
    });
}

#[derive(Clone, Debug)]
pub struct ProbeReport {
    pub lines: Vec<String>,
    pub is_error: bool,
}

pub fn run_probe(cfg: &ControllerConfig, node: &str, raw: &str) -> ProbeReport {
    let target: ProbeTarget = parse_probe_target(raw);
    if target.host.is_empty() && target.delay_url.is_empty() {
        return ProbeReport {
            lines: vec!["empty target".into()],
            is_error: true,
        };
    }
    let mut lines = vec![format!("target  {}", target.raw)];
    let mut dns_ok = false;
    if target.is_ip {
        lines.push(format!("ip  {}", target.host));
        dns_ok = true;
    } else if !target.host.is_empty() {
        for qtype in ["A", "AAAA"] {
            match query_dns(cfg, &target.host, qtype) {
                Ok(msg) => {
                    dns_ok = true;
                    if msg.answers.is_empty() {
                        lines.push(format!("dns {qtype}  no answer  rcode {}", msg.status));
                    }
                    for answer in msg.answers {
                        lines.push(format!("dns {qtype}  {}  {}s", answer.data, answer.ttl));
                    }
                }
                Err(err) => lines.push(format!("dns {qtype}  {err}")),
            }
        }
    }
    let mut delay_ok = false;
    if !target.delay_url.is_empty() {
        match test_node_delay(cfg, node, &target.delay_url) {
            Ok(Some(ms)) => {
                delay_ok = true;
                lines.push(format!("delay  {node}  {ms} ms"));
            }
            Ok(None) => lines.push(format!("delay  {node}  timeout")),
            Err(err) => lines.push(format!("delay  {node}  {err}")),
        }
    }
    ProbeReport {
        lines,
        is_error: !(dns_ok || delay_ok),
    }
}

pub fn probe_async(cfg: ControllerConfig, node: String, raw: String, tx: Sender<BackendEvent>) {
    thread::spawn(move || {
        let report = run_probe(&cfg, &node, &raw);
        let _ = tx.send(BackendEvent::ProbeDone {
            lines: report.lines,
            is_error: report.is_error,
        });
    });
}

fn brief(text: &str) -> String {
    let one = text.split_whitespace().collect::<Vec<_>>().join(" ");
    one.chars().take(80).collect()
}

fn run_gsettings(schema: &str, key: &str, value: &str) -> Result<(), String> {
    let status = Command::new("gsettings")
        .args(["set", schema, key, value])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("gsettings: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("gsettings set {schema} {key} failed"))
    }
}

fn set_gnome_sysproxy(enable: bool, http_port: u16, socks_port: u16) -> Result<String, String> {
    if !gnome_proxy_ready() {
        return Err("sysproxy_unavailable".to_string());
    }
    for cmd in gnome_proxy_commands(enable, http_port, socks_port) {
        // cmd is gsettings, set, schema, key, value
        run_gsettings(&cmd[2], &cmd[3], &cmd[4])?;
    }
    if enable {
        let port = if http_port > 0 { http_port } else { socks_port };
        Ok(format!("System proxy ON (GNOME -> 127.0.0.1:{port})"))
    } else {
        Ok("System proxy OFF (GNOME)".to_string())
    }
}

pub fn set_sysproxy(enable: bool, http_port: u16, socks_port: u16) -> Result<String, String> {
    match std::env::consts::OS {
        "macos" => set_macos_sysproxy(enable, http_port, socks_port),
        "linux" => set_gnome_sysproxy(enable, http_port, socks_port),
        _ => Err("sysproxy_unavailable".to_string()),
    }
}

pub fn proxy_ports(snapshot: &CoreSnapshot) -> Result<(u16, u16), String> {
    let http = if snapshot.http_port > 0 {
        snapshot.http_port
    } else {
        snapshot.mixed_port
    };
    let socks = if snapshot.socks_port > 0 {
        snapshot.socks_port
    } else {
        snapshot.mixed_port
    };
    if http == 0 {
        return Err("No HTTP or mixed proxy listener is enabled".into());
    }
    Ok((http, socks))
}

fn set_macos_sysproxy(enable: bool, http_port: u16, socks_port: u16) -> Result<String, String> {
    let service =
        active_macos_network_service().ok_or("Cannot identify the active macOS network service")?;
    let run = |args: &[&str]| -> Result<(), String> {
        let output = Command::new("networksetup")
            .args(args)
            .output()
            .map_err(|e| e.to_string())?;
        // networksetup may print an error while returning status 0.
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() || stdout.contains("Error") || stdout.contains("error") {
            return Err(format!(
                "networksetup: {} {}",
                stdout.trim(),
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        Ok(())
    };
    if enable {
        if http_port == 0 {
            return Err("No HTTP proxy listener is enabled".into());
        }
        let port = http_port.to_string();
        run(&["-setwebproxy", &service, "127.0.0.1", &port])?;
        run(&["-setsecurewebproxy", &service, "127.0.0.1", &port])?;
        run(&["-setwebproxystate", &service, "on"])?;
        run(&["-setsecurewebproxystate", &service, "on"])?;
        if socks_port > 0 {
            run(&[
                "-setsocksfirewallproxy",
                &service,
                "127.0.0.1",
                &socks_port.to_string(),
            ])?;
            run(&["-setsocksfirewallproxystate", &service, "on"])?;
        } else {
            run(&["-setsocksfirewallproxystate", &service, "off"])?;
        }
    } else {
        for key in [
            "-setwebproxystate",
            "-setsecurewebproxystate",
            "-setsocksfirewallproxystate",
        ] {
            run(&[key, &service, "off"])?;
        }
    }
    Ok(format!(
        "System Proxy {} ({service})",
        if enable { "ON" } else { "OFF" }
    ))
}

#[cfg(test)]
mod provider_tests {
    use super::*;
    use std::sync::{atomic::AtomicUsize, mpsc};

    /// Mock controller in the shape of Mihomo >= v1.19.28: /proxies/{name}/delay
    /// 404s for provider nodes, which answer on the provider healthcheck route.
    fn mock_controller(lookups: Arc<AtomicUsize>) -> ControllerConfig {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let lookups = lookups.clone();
                thread::spawn(move || {
                    let mut reader = BufReader::new(stream);
                    let mut first = String::new();
                    reader.read_line(&mut first).unwrap();
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                            break;
                        }
                    }
                    let path = first.split_whitespace().nth(1).unwrap_or("").to_string();
                    let (status, body) = if path == "/providers/proxies" {
                        lookups.fetch_add(1, Ordering::SeqCst);
                        (
                            200,
                            r#"{"providers":{"air":{"name":"air","proxies":[{"name":"JP 01","type":"Vmess"},{"name":"US 01","type":"Trojan"}]}}}"#,
                        )
                    } else if path.starts_with("/proxies/Inline/delay?") {
                        (200, r#"{"delay":15}"#)
                    } else if path.starts_with("/providers/proxies/air/JP%2001/healthcheck?url=")
                        && path.contains("&timeout=")
                    {
                        (200, r#"{"delay":42}"#)
                    } else if path.starts_with("/providers/proxies/air/US%2001/healthcheck?") {
                        (504, r#"{"message":"Timeout"}"#)
                    } else {
                        (404, r#"{"message":"resource not found"}"#)
                    };
                    let _ = write!(
                        reader.get_mut(),
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                });
            }
        });
        ControllerConfig {
            addr,
            timeout_ms: 500,
            ..ControllerConfig::default()
        }
    }

    #[test]
    fn delay_falls_back_to_provider_healthcheck_on_404() {
        let lookups = Arc::new(AtomicUsize::new(0));
        let cfg = mock_controller(lookups.clone());
        let url = "https://www.gstatic.com/generate_204";
        assert_eq!(test_node_delay(&cfg, "Inline", url), Ok(Some(15)));
        assert_eq!(lookups.load(Ordering::SeqCst), 0);
        assert_eq!(test_node_delay(&cfg, "JP 01", url), Ok(Some(42)));
        assert!(test_node_delay(&cfg, "US 01", url)
            .unwrap_err()
            .starts_with("HTTP 504"));
        assert!(test_node_delay(&cfg, "Gone", url)
            .unwrap_err()
            .starts_with("HTTP 404"));
    }

    #[test]
    fn group_test_streams_results_and_looks_up_providers_once() {
        let lookups = Arc::new(AtomicUsize::new(0));
        let cfg = mock_controller(lookups.clone());
        let (tx, rx) = mpsc::channel();
        let nodes = [
            "JP 01",
            "剩余流量：1 GB",
            "Inline",
            "US 01",
            "Gone",
            "JP 01",
        ];
        test_best_delays_async(
            cfg,
            "Main".into(),
            nodes.iter().map(|s| s.to_string()).collect(),
            tx,
        );
        let mut streamed = Vec::new();
        let results = loop {
            match rx.recv_timeout(Duration::from_secs(10)).unwrap() {
                BackendEvent::DelayResult { group, node, delay } => {
                    assert_eq!(group, "Main");
                    streamed.push((node, delay));
                }
                BackendEvent::BestTestDone { group, results } => {
                    assert_eq!(group, "Main");
                    break results;
                }
                _ => panic!("unexpected event"),
            }
        };
        let expected: Vec<(String, Option<u16>)> = [
            ("JP 01", Some(42)),
            ("Inline", Some(15)),
            ("US 01", None),
            ("Gone", None),
            ("JP 01", Some(42)),
        ]
        .iter()
        .map(|(n, d)| (n.to_string(), *d))
        .collect();
        assert_eq!(results, expected);
        streamed.sort();
        let mut sorted = expected.clone();
        sorted.sort();
        assert_eq!(streamed, sorted);
        assert_eq!(lookups.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_primary_interface_uses_connected_hardware_service() {
        let services = network_services("An asterisk (*) denotes that a network service is disabled.\n(1) Ethernet\n(Hardware Port: USB LAN, Device: en5)\n(2) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n(3) Shadowrocket\n(Hardware Port: com.liguangming.Shadowrocket, Device: )\n(4) *Disabled Ethernet\n(Hardware Port: USB LAN, Device: en8)\n");
        let active = active_nwi_interfaces("IPv4 network interface information\n   utun7 : flags      : 0x7 (IPv4,IPv6,DNS)\n     en0 : flags      : 0x7 (IPv4,IPv6,DNS)\nIPv6 network interface information\n   utun7 : flags      : 0x7 (IPv4,IPv6,DNS)\n     en0 : flags      : 0x7 (IPv4,IPv6,DNS)\n");
        assert_eq!(
            select_network_service(&services, Some("utun7"), &active).as_deref(),
            Some("Wi-Fi")
        );
        assert_eq!(
            select_network_service(&services, Some("en5"), &active).as_deref(),
            Some("Ethernet")
        );
        assert!(select_network_service(&services, None, &["en8".into()]).is_none());
    }

    #[test]
    fn tun_conflict_requires_an_existing_specific_tunnel_route() {
        assert_eq!(connected_vpns("* (Disconnected) UUID VPN (x) \"Tailscale\"\n* (Connected) UUID VPN (y) \"Shadowrocket\" [VPN:y]\n"), vec!["Shadowrocket"]);
        assert!(conflicting_tun_route(
            "destination: 1.0.0.0\nmask: 255.0.0.0\ninterface: utun7\n"
        ));
        assert!(!conflicting_tun_route(
            "destination: default\nmask: default\ninterface: en0\n"
        ));
        assert!(!conflicting_tun_route(
            "destination: 1.0.0.0\nmask: 255.0.0.0\ninterface: en0\n"
        ));
    }

    #[test]
    #[cfg(target_os = "macos")]
    #[ignore = "read-only diagnosis of active network service and conflicting VPN routes"]
    fn live_macos_network_service_and_tun_conflict_read_only() {
        let service = active_macos_network_service().expect("Connected hardware network service");
        eprintln!("Detected physical network service: {service}");
        if let Some(conflict) = macos_tun_route_conflict() {
            eprintln!("{conflict}");
        }
    }

    #[test]
    fn mixed_listener_supplies_both_system_proxy_protocols() {
        let mut snapshot = CoreSnapshot {
            mixed_port: 7897,
            ..CoreSnapshot::default()
        };
        assert_eq!(proxy_ports(&snapshot).unwrap(), (7897, 7897));
        snapshot.http_port = 8080;
        assert_eq!(proxy_ports(&snapshot).unwrap(), (8080, 7897));
        snapshot.mixed_port = 0;
        assert_eq!(proxy_ports(&snapshot).unwrap(), (8080, 0));
        snapshot.http_port = 0;
        assert!(proxy_ports(&snapshot).is_err());
        let commands = gnome_proxy_commands(true, 8080, 0);
        assert!(commands.iter().any(|c| c
            == &vec![
                "gsettings",
                "set",
                "org.gnome.system.proxy.socks",
                "host",
                "''"
            ]));
        assert_eq!(commands.last().unwrap()[3], "mode");
    }

    #[test]
    fn tun_patch_preserves_settings_and_checks_the_result() {
        use std::net::TcpListener;
        for actual in [false, true] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let cfg = ControllerConfig {
                addr: listener.local_addr().unwrap().to_string(),
                config_dir: "/terc-mock-tun".into(),
                ..ControllerConfig::default()
            };
            let server = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut requests = 0;
                let mut patch = String::new();
                while requests < 3 && Instant::now() < deadline {
                    let (stream, _) = match listener.accept() {
                        Ok(pair) => pair,
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(e) => panic!("{e}"),
                    };
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut reader = BufReader::new(stream);
                    let mut first = String::new();
                    reader.read_line(&mut first).unwrap();
                    let mut length = 0;
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" || line.is_empty() {
                            break;
                        }
                        if let Some(value) =
                            line.to_ascii_lowercase().strip_prefix("content-length:")
                        {
                            length = value.trim().parse().unwrap();
                        }
                    }
                    let mut bytes = vec![0; length];
                    reader.read_exact(&mut bytes).unwrap();
                    let (status, body) = if requests == 1 {
                        assert!(first.starts_with("PATCH /configs "));
                        patch = String::from_utf8(bytes).unwrap();
                        (204, String::new())
                    } else {
                        assert!(first.starts_with("GET /configs "));
                        (200, serde_json::json!({"tun": {"enable": requests == 2 && actual, "stack": "mixed", "auto-route": true, "mtu": 1400}}).to_string())
                    };
                    write!(reader.get_mut(), "HTTP/1.1 {status} OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                    requests += 1;
                }
                assert_eq!(requests, 3);
                let value: Value = serde_json::from_str(&patch).unwrap();
                assert_eq!(value["tun"]["enable"], true);
                assert_eq!(value["tun"]["mtu"], 1400);
                assert_eq!(value["tun"]["auto-route"], true);
            });
            let result = set_tun_enabled(&cfg, true);
            server.join().unwrap();
            assert_eq!(result.is_ok(), actual);
            if !actual {
                assert!(result.unwrap_err().to_string().contains("did not reach"));
            }
        }
    }

    #[test]
    fn stopping_an_external_core_does_not_attempt_system_changes() {
        let cfg = ControllerConfig {
            config_dir: "/terc-nonexistent-unmanaged-test".into(),
            ..ControllerConfig::default()
        };
        assert!(stop_core_service(&cfg)
            .unwrap_err()
            .contains("managed externally"));
    }

    #[test]
    #[ignore = "requires an installed Mihomo binary; only validates temporary configs and calls a mock controller"]
    fn real_core_validates_overlays_and_config_updates_restore_on_failure() {
        use std::net::TcpListener;
        let directory = std::env::temp_dir().join(format!(
            "terc-config-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&directory).unwrap();
        let mut cfg = ControllerConfig {
            config_dir: directory.display().to_string(),
            ..ControllerConfig::default()
        };
        let base = "mode: direct\nmixed-port: 7897\nproxies: []\nrules: []\ntun:\n  enable: false\n  mtu: 1400\ndns:\n  enable: false\n  listen: 127.0.0.1:1053\n  fallback-filter:\n    geoip: false\n";
        let generated =
            crate::ops::apply_enabled_modules(base, &crate::ops::builtin_modules()).unwrap();
        install_config(&cfg, &generated, false).unwrap();
        assert_eq!(read_config_text(&cfg).unwrap(), generated);
        let invalid = "dns: [\n";
        assert!(install_config(&cfg, invalid, false)
            .unwrap_err()
            .contains("rejected"));
        assert_eq!(read_config_text(&cfg).unwrap(), generated);
        persist_nested_bool(&cfg, &["tun", "enable"], false).unwrap();
        assert!(!crate::ops::parse_yaml_flags(&read_config_text(&cfg).unwrap()).tun_enabled);
        // A valid provider-only document does not need a top-level proxies key.
        let provider_only = "mode: direct\nproxy-providers: {}\nproxy-groups: []\nrules: []\n";
        install_config(&cfg, provider_only, false).unwrap();
        for status in [400, 204] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            cfg.addr = listener.local_addr().unwrap().to_string();
            let server = thread::spawn(move || loop {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut reader = BufReader::new(stream);
                let mut request = String::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" {
                        break;
                    }
                    if let Some(v) = line.strip_prefix("Content-Length: ") {
                        length = v.trim().parse::<usize>().unwrap();
                    }
                    request.push_str(&line);
                }
                let mut payload = vec![0; length];
                reader.read_exact(&mut payload).unwrap();
                // The runtime mode is read first; this mock has none to carry.
                if request.starts_with("GET /configs ") {
                    write!(
                        reader.get_mut(),
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .unwrap();
                    continue;
                }
                assert!(request.starts_with("PUT /configs?force=true "));
                write!(
                    reader.get_mut(),
                    "HTTP/1.1 {status} Result\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
                .unwrap();
                break;
            });
            let next = "mode: direct\nipv6: true\nproxies: []\nrules: []\n";
            let result = install_config(&cfg, next, true);
            server.join().unwrap();
            if status == 400 {
                assert!(result
                    .unwrap_err()
                    .contains("previous configuration restored"));
                assert_eq!(read_config_text(&cfg).unwrap(), provider_only);
            } else {
                result.unwrap();
                assert_eq!(read_config_text(&cfg).unwrap(), next);
            }
        }
        assert!(!directory.join(".terc-candidate.yaml").exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn normalize_subscription_binds_controller_to_loopback() {
        let raw = "external-controller: :9090\nproxies:\n  - name: a\n";
        let out = normalize_subscription(raw, "127.0.0.1:9090");
        assert!(out.starts_with("external-controller: 127.0.0.1:9090\n"));
        assert_eq!(out.matches("external-controller:").count(), 1);
    }

    #[test]
    fn normalize_subscription_adds_missing_controller() {
        let raw = "mixed-port: 7890\nproxies:\n  - name: a\n";
        let out = normalize_subscription(raw, "127.0.0.1:9090");
        assert!(out.contains("external-controller: 127.0.0.1:9090"));
        assert!(out.contains("mixed-port: 7890"));
    }

    #[test]
    fn connection_keeps_process_rule_and_inbound() {
        let raw = serde_json::json!({
            "id": "abc",
            "upload": 10,
            "download": 20,
            "start": "2026-01-02T03:04:05.1Z",
            "rule": "DomainSuffix",
            "rulePayload": "example.com",
            "metadata": {
                "network": "tcp",
                "type": "TUN",
                "inboundName": "tun0",
                "sourceIP": "10.0.0.8",
                "sourcePort": "51234",
                "host": "example.com",
                "destinationPort": "443",
                "process": "curl",
                "processPath": "/usr/bin/curl",
                "sniffHost": "example.com",
                "dnsMode": "fake-ip",
                "destinationGeoIP": ["US"],
                "destinationIPASN": "AS15169"
            }
        });
        let item = connection_from_value(&raw).unwrap();
        assert_eq!(item.process, "curl");
        assert_eq!(item.process_path, "/usr/bin/curl");
        assert_eq!(item.inbound, "TUN");
        assert_eq!(item.inbound_name, "tun0");
        assert_eq!(item.source, "10.0.0.8:51234");
        assert_eq!(item.sniff_host, "example.com");
        assert_eq!(item.rule_payload, "example.com");
        assert_eq!(item.dns_mode, "fake-ip");
        assert_eq!(item.dest_geo, "US");
        assert_eq!(item.dest_asn, "AS15169");
    }

    #[test]
    fn asset_id_follows_os_and_cpu() {
        assert_eq!(
            mihomo_asset_id_for("macos", "aarch64"),
            Some("darwin-arm64")
        );
        assert_eq!(mihomo_asset_id_for("macos", "x86_64"), Some("darwin-amd64"));
        assert_eq!(mihomo_asset_id_for("linux", "aarch64"), Some("linux-arm64"));
        assert_eq!(mihomo_asset_id_for("linux", "x86_64"), Some("linux-amd64"));
        assert_eq!(mihomo_asset_id_for("windows", "x86_64"), None);
        assert_eq!(mihomo_asset_id_for("linux", "arm"), None);
    }

    #[test]
    fn managed_core_script_selects_matching_asset() {
        let script = managed_core_script("linux-amd64", "/tmp/terc/mihomo.gz", "/tmp/terc/mihomo");
        assert!(script.contains(r#"mihomo-linux-amd64-v[^"]*\.gz"#));
        assert!(!script.contains("darwin-arm64"));
        assert!(!script.contains("networksetup"));
        assert!(script.contains("'/tmp/terc/mihomo'"));
    }

    #[test]
    fn linux_proxy_plan_uses_gsettings_and_not_networksetup() {
        assert_eq!(sysproxy_backend_for("linux", true), SysproxyBackend::Gnome);
        assert_eq!(
            sysproxy_backend_for("linux", false),
            SysproxyBackend::Unavailable
        );
        assert_eq!(sysproxy_backend_for("macos", false), SysproxyBackend::Macos);
        assert_eq!(
            sysproxy_backend_for("windows", true),
            SysproxyBackend::Unavailable
        );

        let on = gnome_proxy_commands(true, 7890, 7891);
        let flat = on
            .iter()
            .flat_map(|cmd| cmd.iter().cloned())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(flat.contains("gsettings"));
        assert!(flat.contains("org.gnome.system.proxy"));
        assert!(flat.contains("'manual'"));
        assert!(flat.contains("org.gnome.system.proxy.socks"));
        assert!(flat.contains("7891"));
        assert!(!flat.contains("networksetup"));

        let off = gnome_proxy_commands(false, 7890, 7891);
        assert_eq!(off.len(), 1);
        assert_eq!(off[0][4], "'none'");
    }

    #[test]
    #[ignore = "requires an installed Mihomo binary; run alone, it points HOME at a temp dir"]
    fn regenerate_pipeline_composes_validates_and_keeps_switches() {
        let bin = discover_mihomo_binary().expect("mihomo binary");
        let home = std::env::temp_dir().join(format!("terc-home-{}", std::process::id()));
        let terc = home.join(".config/terc");
        fs::create_dir_all(terc.join("mihomo")).unwrap();
        std::env::set_var("HOME", &home);
        std::env::set_var(
            "PATH",
            format!("{}:/usr/bin:/bin", bin.parent().unwrap().display()),
        );
        let cfg = ControllerConfig {
            config_dir: terc.join("mihomo").display().to_string(),
            ..ControllerConfig::default()
        };
        // No subscription, no nodes: a clear error, nothing written.
        assert!(regenerate_config(&cfg, &[], false, false, true).is_err());
        fs::write(
            terc.join("subscription.cache"),
            crate::subconv::encode_base64(b"trojan://fake@192.0.2.1:443#JP-1\nssr://x\n"),
        )
        .unwrap();
        crate::compose::add_manual_node(
            &terc,
            "US-Own = ss, 192.0.2.2, 8388, encrypt-method=aes-128-gcm, password=fake",
        )
        .unwrap();
        let msg = regenerate_config(&cfg, &[], false, false, true).unwrap();
        assert!(msg.contains("URI 1 节点"), "{msg}");
        assert!(msg.contains("跳过 1"), "{msg}");
        assert!(!terc.join("rules.conf").is_file());
        persist_nested_bool(&cfg, &["sniffer", "enable"], true).unwrap();
        let modules = crate::ops::builtin_modules();
        regenerate_config(&cfg, &modules[..1], false, false, false).unwrap();
        let text = read_config_text(&cfg).unwrap();
        assert!(crate::compose::is_generated(&text));
        assert!(crate::ops::parse_yaml_flags(&text).sniffing);
        assert!(text.contains("US-Own"));
        fs::remove_dir_all(home).unwrap();
    }
}

#[cfg(test)]
mod listener_tests {
    use super::*;
    #[test]
    fn duplicate_proxy_ports_are_rejected_and_disabled_ports_are_allowed() {
        let err =
            validate_listener_ports("port: 7890\nmixed-port: 7890\nsocks-port: 0\n").unwrap_err();
        assert!(err.contains("port and mixed-port"));
        validate_listener_ports("port: 0\nsocks-port: 0\nmixed-port: 7890\n").unwrap();
        validate_listener_ports("port: 7890\nsocks-port: 7891\nmixed-port: 7892\n").unwrap();
    }
    #[test]
    fn occupied_proxy_and_dns_ports_fail_before_launching_a_core() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        assert!(check_startup_ports(&format!("mixed-port: {port}\n"))
            .unwrap_err()
            .contains("occupied"));
        assert!(check_startup_ports(&format!(
            "dns:\n  enable: true\n  listen: 127.0.0.1:{port}\n"
        ))
        .unwrap_err()
        .contains("DNS"));
    }

    #[test]
    fn slow_core_start_waits_while_alive_and_returns_once_ready() {
        let early = Duration::from_secs(5);
        let never = || -> bool { panic!("log is only checked at the deadline") };
        assert_eq!(
            core_startup_step(false, || CoreProbe::Pending, early, never),
            StartupStep::Wait
        );
        assert_eq!(
            core_startup_step(false, || CoreProbe::Pending, Duration::from_secs(45), never),
            StartupStep::Wait
        );
        assert_eq!(
            core_startup_step(false, || CoreProbe::Ready, Duration::from_secs(30), never),
            StartupStep::Ready
        );
        assert_eq!(
            core_startup_step(true, || panic!("exited core is not probed"), early, never),
            StartupStep::Exited
        );
        assert_eq!(
            core_startup_step(false, || CoreProbe::Rejected(401), early, never),
            StartupStep::Rejected(401)
        );
    }

    #[test]
    fn core_past_the_deadline_is_kept_only_while_downloading_geodata() {
        let late = CORE_START_DEADLINE;
        assert_eq!(
            core_startup_step(false, || CoreProbe::Ready, late, || false),
            StartupStep::Ready
        );
        assert_eq!(
            core_startup_step(false, || CoreProbe::Pending, late, || true),
            StartupStep::StillStarting
        );
        assert_eq!(
            core_startup_step(false, || CoreProbe::Pending, late, || false),
            StartupStep::TimedOut
        );
        assert!(log_suggests_download(
            "INFO Can't find GeoSite.dat, start download\n"
        ));
        assert!(!log_suggests_download("INFO Start initial configuration\n"));
    }

    #[test]
    fn controller_probe_separates_ready_rejected_and_pending() {
        assert_eq!(classify_probe(&Ok((200, String::new()))), CoreProbe::Ready);
        assert_eq!(
            classify_probe(&Ok((401, String::new()))),
            CoreProbe::Rejected(401)
        );
        assert_eq!(
            classify_probe(&Ok((503, String::new()))),
            CoreProbe::Pending
        );
        let refused = Err(io::Error::from(io::ErrorKind::ConnectionRefused));
        assert_eq!(classify_probe(&refused), CoreProbe::Pending);
    }

    /// Answer one connection per canned response (empty closes without a
    /// reply) and return each request line followed by its body.
    fn serve(
        listener: std::net::TcpListener,
        responses: Vec<Vec<u8>>,
    ) -> thread::JoinHandle<Vec<String>> {
        thread::spawn(move || {
            let mut requests = Vec::new();
            for response in responses {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut reader = BufReader::new(stream);
                let mut request = String::new();
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    if let Some(v) = line.strip_prefix("Content-Length: ") {
                        length = v.trim().parse::<usize>().unwrap();
                    }
                    if request.is_empty() {
                        request = line;
                    }
                }
                let mut payload = vec![0; length];
                reader.read_exact(&mut payload).unwrap();
                reader.get_mut().write_all(&response).unwrap();
                requests.push(request + &String::from_utf8_lossy(&payload));
            }
            requests
        })
    }

    #[test]
    fn chunk_boundary_inside_a_character_decodes_to_the_character() {
        assert_eq!(
            decode_chunked(b"2\r\n\xE8\x8A\r\n1\r\n\x82\r\n0\r\n\r\n"),
            "节".as_bytes()
        );
        // A truncated final chunk keeps what arrived instead of slicing past it.
        assert_eq!(decode_chunked(b"5\r\nab"), b"ab");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = serve(
            listener,
            vec![
                b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n\
                   8\r\n{\"n\":\"\xE8\x8A\r\n3\r\n\x82\"}\r\n0\r\n\r\n"
                    .to_vec(),
            ],
        );
        let (status, body) =
            http_request(&addr, "", "GET", "/proxies", None, Duration::from_secs(3)).unwrap();
        assert!(server.join().unwrap()[0].starts_with("GET /proxies "));
        assert_eq!(status, 200);
        assert_eq!(body, "{\"n\":\"节\"}");
    }

    fn http(status: &str, body: &str) -> Vec<u8> {
        format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .into_bytes()
    }

    /// A temporary config dir with a stand-in for `mihomo -t` (never a real core).
    #[cfg(unix)]
    fn install_fixture(tag: &str, check: &str) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "terc-install-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("fake-mihomo");
        fs::write(&bin, format!("#!/bin/sh\n{check}\n")).unwrap();
        fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
        (dir, bin)
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).unwrap().permissions().mode()
    }

    const TEST_LIMITS: InstallLimits = InstallLimits {
        check: Duration::from_secs(10),
        download: Duration::from_secs(10),
        settle: Duration::from_millis(600),
    };

    #[test]
    #[cfg(unix)]
    fn rejected_reload_restores_previous_file_privately() {
        let (dir, bin) = install_fixture("rejected", "exit 0");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cfg = ControllerConfig {
            addr: listener.local_addr().unwrap().to_string(),
            config_dir: dir.display().to_string(),
            ..ControllerConfig::default()
        };
        let previous = "mode: rule\nproxies: []\n";
        fs::write(config_yaml_path(&cfg), previous).unwrap();
        let server = serve(
            listener,
            vec![http("200 OK", "{}"), http("400 Bad Request", "bad")],
        );
        let failure = install_config_with(
            &cfg,
            "mode: rule\nipv6: true\n",
            true,
            || Some(bin),
            &TEST_LIMITS,
        )
        .err()
        .unwrap();
        let requests = server.join().unwrap();
        assert!(requests[1].starts_with("PUT /configs?force=true "));
        assert!(!failure.kept);
        assert!(failure.message.contains("previous configuration restored"));
        assert_eq!(read_config_text(&cfg).unwrap(), previous);
        assert_eq!(mode_of(&config_yaml_path(&cfg)) & 0o077, 0);
        assert!(!dir.join(".terc-candidate.yaml").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn unanswered_reload_keeps_the_new_file() {
        let next = "mode: rule\nipv6: true\n";
        for answers in [true, false] {
            let (dir, bin) = install_fixture("unknown", "exit 0");
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let cfg = ControllerConfig {
                addr: listener.local_addr().unwrap().to_string(),
                config_dir: dir.display().to_string(),
                ..ControllerConfig::default()
            };
            fs::write(config_yaml_path(&cfg), "mode: rule\n").unwrap();
            // The PUT connection closes without a reply, as on a client timeout.
            let mut responses = vec![http("200 OK", "{}"), Vec::new()];
            if answers {
                responses.push(http("200 OK", "{\"version\":\"v1\"}"));
            }
            let server = serve(listener, responses);
            let result = install_config_with(&cfg, next, true, || Some(bin), &TEST_LIMITS);
            let requests = server.join().unwrap();
            if answers {
                assert!(result.is_ok());
                assert!(requests[2].starts_with("GET /version "));
            } else {
                let failure = result.err().unwrap();
                assert!(failure.kept);
                assert!(failure.message.contains("kept on disk"));
            }
            assert_eq!(read_config_text(&cfg).unwrap(), next);
            fs::remove_dir_all(dir).unwrap();
        }
    }

    #[test]
    #[cfg(unix)]
    fn hung_config_check_is_stopped_and_leaves_the_file() {
        let (dir, bin) = install_fixture("hung", "exec sleep 30");
        let cfg = ControllerConfig {
            config_dir: dir.display().to_string(),
            ..ControllerConfig::default()
        };
        fs::write(config_yaml_path(&cfg), "mode: rule\n").unwrap();
        let limits = InstallLimits {
            check: Duration::from_millis(300),
            ..TEST_LIMITS
        };
        let started = Instant::now();
        let failure = install_config_with(&cfg, "mode: global\n", false, || Some(bin), &limits)
            .err()
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(failure.message.contains("did not finish"));
        assert_eq!(read_config_text(&cfg).unwrap(), "mode: rule\n");
        assert!(!dir.join(".terc-candidate.yaml").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn config_check_downloading_geodata_gets_more_time() {
        let limits = InstallLimits {
            check: Duration::from_millis(200),
            download: Duration::from_secs(10),
            ..TEST_LIMITS
        };
        let script = "echo 'Can not find GeoSite.dat, start download'; sleep 1; exit 0";
        let (dir, bin) = install_fixture("download", script);
        let cfg = ControllerConfig {
            config_dir: dir.display().to_string(),
            ..ControllerConfig::default()
        };
        assert!(install_config_with(&cfg, "mode: global\n", false, || Some(bin), &limits).is_ok());
        assert_eq!(read_config_text(&cfg).unwrap(), "mode: global\n");
        fs::remove_dir_all(dir).unwrap();
        // The longer deadline still stops a download that never ends.
        let limits = InstallLimits {
            download: Duration::from_millis(600),
            ..limits
        };
        let (dir, bin) = install_fixture("download-hung", "echo downloading; exec sleep 30");
        let cfg = ControllerConfig {
            config_dir: dir.display().to_string(),
            ..ControllerConfig::default()
        };
        let started = Instant::now();
        let failure = install_config_with(&cfg, "mode: global\n", false, || Some(bin), &limits)
            .err()
            .unwrap();
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(failure.message.contains("did not finish"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn installed_config_is_private_even_over_a_public_file() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, bin) = install_fixture("private", "echo checked; exit 0");
        let cfg = ControllerConfig {
            config_dir: dir.display().to_string(),
            ..ControllerConfig::default()
        };
        let path = config_yaml_path(&cfg);
        fs::write(&path, "mode: rule\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let stale = dir.join(".terc-candidate.yaml");
        fs::write(&stale, "").unwrap();
        fs::set_permissions(&stale, fs::Permissions::from_mode(0o644)).unwrap();
        install_config_with(&cfg, "mode: global\n", false, || Some(bin), &TEST_LIMITS)
            .ok()
            .unwrap();
        assert_eq!(read_config_text(&cfg).unwrap(), "mode: global\n");
        assert_eq!(mode_of(&path) & 0o077, 0);
        let (dir_fail, bin_fail) = install_fixture("private-fail", "echo bad key >&2; exit 1");
        let cfg_fail = ControllerConfig {
            config_dir: dir_fail.display().to_string(),
            ..ControllerConfig::default()
        };
        let failure = install_config_with(
            &cfg_fail,
            "mode: global\n",
            false,
            || Some(bin_fail),
            &TEST_LIMITS,
        )
        .err()
        .unwrap();
        assert!(failure.message.contains("rejected") && failure.message.contains("bad key"));
        fs::remove_dir_all(dir).unwrap();
        fs::remove_dir_all(dir_fail).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn reload_keeps_a_mode_switched_at_runtime() {
        let (dir, bin) = install_fixture("mode", "exit 0");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cfg = ControllerConfig {
            addr: listener.local_addr().unwrap().to_string(),
            config_dir: dir.display().to_string(),
            ..ControllerConfig::default()
        };
        let server = serve(
            listener,
            vec![
                http("200 OK", r#"{"mode":"Direct","allow-lan":false}"#),
                http("204 No Content", ""),
            ],
        );
        let modules = vec![crate::ops::ModuleSnippet {
            id: "lan".into(),
            name: "LAN".into(),
            description: String::new(),
            body: "allow-lan: true\n".into(),
            builtin: false,
        }];
        let text = crate::ops::apply_modules_with_switches(
            "mode: rule\nallow-lan: false\nproxies: []\n",
            &modules,
            &[],
        )
        .unwrap();
        install_config_with(&cfg, &text, true, || Some(bin), &TEST_LIMITS)
            .ok()
            .unwrap();
        let requests = server.join().unwrap();
        assert!(requests[0].starts_with("GET /configs "));
        assert!(requests[1].starts_with("PUT /configs?force=true "));
        let installed = read_config_text(&cfg).unwrap();
        assert!(installed.contains("\nmode: \"direct\"\n"));
        assert!(installed.contains("allow-lan: true"));
        let base = crate::ops::strip_marked_modules(&installed);
        assert!(base.starts_with("mode: \"direct\"\n"));
        assert!(base.contains("allow-lan: false"));

        // Persisting a runtime switch writes the file without a reload.
        persist_mode(&cfg, "global").unwrap();
        let persisted = read_config_text(&cfg).unwrap();
        assert!(crate::ops::strip_marked_modules(&persisted).starts_with("mode: \"global\"\n"));
        assert!(persisted.contains("\nmode: \"global\"\n"));
        // Regenerating from it carries the mode into the new base.
        let carried = crate::compose::carry_runtime_state(
            &crate::ops::strip_marked_modules(&persisted),
            "mode: rule\nproxies: []\n",
        );
        assert!(carried.starts_with("mode: global\n"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reload_runs_only_for_a_changed_or_uncertain_config() {
        let doc = "mode: rule\n";
        assert!(!reload_needed(Some(doc), doc, true, false));
        assert!(!reload_needed(Some(doc), doc, false, false));
        // A stopped core loads the file at startup, so uncertainty is moot.
        assert!(!reload_needed(Some(doc), doc, false, true));
        assert!(reload_needed(Some(doc), doc, true, true));
        assert!(reload_needed(Some(doc), "mode: global\n", true, false));
        assert!(reload_needed(Some(doc), "mode: global\n", false, false));
        assert!(reload_needed(None, doc, false, false));
        assert!(reload_needed(None, doc, true, false));
    }

    #[test]
    fn live_patch_is_verified_by_reading_the_config_back() {
        for (runtime, ok) in [
            (r#"{"allow-lan":true,"mixed-port":7890}"#, true),
            (r#"{"mixed-port":7890}"#, true),
            (r#"{"allow-lan":false}"#, false),
        ] {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let cfg = ControllerConfig {
                addr: listener.local_addr().unwrap().to_string(),
                ..ControllerConfig::default()
            };
            let server = serve(
                listener,
                vec![http("204 No Content", ""), http("200 OK", runtime)],
            );
            let result = patch_config_value(&cfg, "allow-lan", &Value::Bool(true));
            let requests = server.join().unwrap();
            assert!(requests[0].starts_with("PATCH /configs "), "{requests:?}");
            assert!(
                requests[0].ends_with("\r\n{\"allow-lan\":true}"),
                "{requests:?}"
            );
            assert!(requests[1].starts_with("GET /configs "), "{requests:?}");
            assert_eq!(result.is_ok(), ok, "{runtime}: {result:?}");
            if !ok {
                assert!(result
                    .unwrap_err()
                    .contains("allow-lan reads back as false"));
            }
        }

        // Ports compare as integers and the enums ignore case.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cfg = ControllerConfig {
            addr: listener.local_addr().unwrap().to_string(),
            ..ControllerConfig::default()
        };
        let runtime = r#"{"mixed-port":7899,"log-level":"Warning"}"#;
        let server = serve(
            listener,
            vec![
                http("204 No Content", ""),
                http("200 OK", runtime),
                http("204 No Content", ""),
                http("200 OK", runtime),
                http("400 Bad Request", r#"{"message":"bad"}"#),
            ],
        );
        assert!(patch_config_value(&cfg, "mixed-port", &7899.into()).is_ok());
        assert!(patch_config_value(&cfg, "log-level", &"warning".into()).is_ok());
        let err = patch_config_value(&cfg, "mixed-port", &7900.into()).unwrap_err();
        assert!(err.starts_with("HTTP 400"), "{err}");
        let requests = server.join().unwrap();
        assert!(requests[0].ends_with("{\"mixed-port\":7899}"));
        assert!(requests[2].ends_with("{\"log-level\":\"warning\"}"));
    }

    #[test]
    #[cfg(unix)]
    #[ignore = "points HOME at a temp dir; run alone. Uses a stand-in for mihomo -t and a mock controller, never a real core"]
    fn unchanged_regeneration_skips_the_check_and_the_reload() {
        let (home, bin) =
            install_fixture("skip", "echo run >> \"$(dirname \"$0\")/checks\"; exit 0");
        std::env::set_var("HOME", &home);
        let core = home.join(".config/terc/core");
        fs::create_dir_all(&core).unwrap();
        fs::rename(&bin, core.join("mihomo")).unwrap();
        let checks = core.join("checks");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cfg = ControllerConfig {
            addr: listener.local_addr().unwrap().to_string(),
            config_dir: home.join("mihomo").display().to_string(),
            profile_id: "p1".into(),
            ..ControllerConfig::default()
        };
        let dir = crate::compose::profile_dir(&cfg);
        crate::compose::add_manual_node(
            &dir,
            "Own = ss, 192.0.2.2, 8388, encrypt-method=aes-128-gcm, password=fake",
        )
        .unwrap();
        // The second pass carries listener keys over from the first file, so
        // the output settles after two installs. Each runs the check and
        // reloads; `regenerate_routing` and `install_config_with` read the mode.
        let mode = || http("200 OK", r#"{"mode":"rule"}"#);
        for pass in 1..=2 {
            let server = serve(
                listener.try_clone().unwrap(),
                vec![mode(), mode(), http("204 No Content", "")],
            );
            let msg = regenerate_config(&cfg, &[], true, false, false).unwrap();
            assert!(server.join().unwrap()[2].starts_with("PUT /configs?force=true "));
            assert!(msg.contains("validated & hot-reloaded"), "{msg}");
            assert_eq!(fs::read_to_string(&checks).unwrap().lines().count(), pass);
        }
        let installed = read_config_text(&cfg).unwrap();
        let generated = compose_generated(&cfg);
        fs::remove_file(&generated).unwrap();

        // Running: only `GET /configs` for the runtime mode, no PUT.
        let server = serve(listener.try_clone().unwrap(), vec![mode()]);
        assert!(crate::compose::ProfileSource::load(&dir).routing.is_empty());
        let second =
            regenerate_routing(&cfg, &[], true, false, false, Some("subscription")).unwrap();
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET /configs "));
        assert!(
            second.contains(" — unchanged; not reloaded, existing connections kept"),
            "{second}"
        );
        assert_eq!(fs::read_to_string(&checks).unwrap().lines().count(), 2);
        assert_eq!(read_config_text(&cfg).unwrap(), installed);
        // The routing choice and the generated copy are still written.
        assert_eq!(
            crate::compose::ProfileSource::load(&dir).routing,
            "subscription"
        );
        assert!(generated.is_file());

        // An earlier reload with no answer forces the next one, which clears it.
        RELOAD_UNCERTAIN.store(true, Ordering::SeqCst);
        let server = serve(
            listener.try_clone().unwrap(),
            vec![mode(), mode(), http("204 No Content", "")],
        );
        let third = regenerate_config(&cfg, &[], true, false, true).unwrap();
        assert!(server.join().unwrap()[2].starts_with("PUT /configs?force=true "));
        assert!(third.contains("已校验并热重载"), "{third}");
        assert!(!RELOAD_UNCERTAIN.load(Ordering::SeqCst));
        assert_eq!(fs::read_to_string(&checks).unwrap().lines().count(), 3);
        fs::remove_dir_all(home).unwrap();
    }

    fn compose_generated(cfg: &ControllerConfig) -> PathBuf {
        crate::compose::terc_dir()
            .join("generated")
            .join(format!("{}.yaml", cfg.profile_id))
    }
}
