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
        /// The worker sends a snapshot next; false when the action panicked.
        snapshot_follows: bool,
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
    /// The optional endpoints this snapshot read; see `carry_skipped`.
    pub fetched: Fetch,
}

/// The optional endpoints a snapshot poll reads. `/version` (the liveness
/// probe), `/configs` and `/proxies` are read every time; the default reads
/// everything, as every snapshot after an action does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fetch {
    /// `/connections`; the WebSocket push supplies it while live.
    pub connections: bool,
    /// `/rules`, which only the Rules tab shows.
    pub rules: bool,
    /// `/providers/proxies` and `/providers/rules`: the Providers tab, plus
    /// provider nodes and their delays, which `/proxies` omits since v1.19.28.
    pub providers: bool,
    /// Reuse the system proxy and core binary lookups for up to `HOST_TTL`
    /// instead of looking again; see `host_state`.
    pub cached_host: bool,
}

impl Default for Fetch {
    fn default() -> Self {
        Self {
            connections: true,
            rules: true,
            providers: true,
            cached_host: false,
        }
    }
}

impl CoreSnapshot {
    /// Take what this poll skipped from `old`, the snapshot it replaces:
    /// rules, providers, and the provider nodes with their delays (`old` is
    /// left without them). Connections are the caller's business.
    pub fn carry_skipped(&mut self, old: &mut CoreSnapshot) {
        if !self.running || !old.running {
            return;
        }
        if !self.fetched.rules {
            self.rules = std::mem::take(&mut old.rules);
        }
        if !self.fetched.providers {
            self.providers = std::mem::take(&mut old.providers);
            use std::collections::hash_map::Entry;
            for (name, node) in old.nodes.drain() {
                if node.provider.is_none() {
                    continue;
                }
                match self.nodes.entry(name) {
                    // Older cores still list provider nodes in /proxies.
                    Entry::Occupied(mut fresh) => {
                        let fresh = fresh.get_mut();
                        if fresh.provider.is_none() {
                            fresh.provider = node.provider;
                        }
                    }
                    Entry::Vacant(slot) => {
                        slot.insert(node);
                    }
                }
            }
        }
    }
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
    /// Node pinned on a url-test/fallback group; Mihomo keeps using it while
    /// it is alive for the group's own test URL, so `now` can differ.
    pub fixed: String,
    pub all: Vec<String>,
    /// `testUrl`; Selectors omit it when it is Mihomo's default.
    pub test_url: String,
    /// `expectedStatus`, such as `204` or `200-299/302`; empty accepts any.
    pub expected_status: String,
}

impl ProxyGroup {
    /// The URL whose `extra` state the group ranks on. Only URLTest and
    /// Fallback rank, and only those tests run with the group's own URL.
    pub fn ranking_url(&self) -> Option<&str> {
        let ranks = ["urltest", "fallback"].contains(&self.kind.to_ascii_lowercase().as_str());
        Some(self.test_url.as_str()).filter(|url| ranks && !url.is_empty())
    }

    /// The delay the group ranks `node` on: its `extra` state for the
    /// group's URL, or the global history for every other group.
    pub fn member_delay(&self, node: &ProxyNode) -> Option<u16> {
        match self.ranking_url() {
            Some(url) => node.url_delays.get(url).copied().flatten(),
            None => node.delay,
        }
    }
}

impl ProxyGroup {
    /// Groups where a PUT pins a node instead of selecting it.
    pub fn pinnable(&self) -> bool {
        self.kind.eq_ignore_ascii_case("urltest") || self.kind.eq_ignore_ascii_case("fallback")
    }
}

#[derive(Clone, Debug)]
pub struct ProxyNode {
    pub name: String,
    pub kind: String,
    pub udp: bool,
    pub delay: Option<u16>,
    /// Owning proxy provider, used for the provider healthcheck delay route.
    pub provider: Option<String>,
    /// Per test URL, the last delay of `extra` while alive. Unlike `delay`,
    /// a test that missed the expected status leaves no number here.
    pub url_delays: HashMap<String, Option<u16>>,
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
            test_url: DEFAULT_TEST_URL.to_string(),
            timeout_ms: 4000,
            profile_id: String::new(),
        }
    }
}

/// Mihomo's own `DefaultTestURL`. Over plain HTTP a provider can answer
/// generate_204 at the entry relay and report a fake-low delay.
pub const DEFAULT_TEST_URL: &str = "https://www.gstatic.com/generate_204";
/// terc's default before it followed Mihomo; migrated on config load.
pub const OLD_DEFAULT_TEST_URL: &str = "http://www.gstatic.com/generate_204";
/// The delay routes parse `timeout` as int16, so larger values get HTTP 400.
pub const MAX_DELAY_TIMEOUT_MS: u64 = 32_767;
/// Mihomo's default group healthcheck timeout. A shorter terc test would
/// mark nodes dead in `extra` that the group itself keeps.
const GROUP_DELAY_TIMEOUT_MS: u64 = 5000;

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
    let (head_end, body_start) = match raw.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(pos) => (pos, pos + 4),
        None => (raw.len(), raw.len()),
    };
    let headers = String::from_utf8_lossy(&raw[..head_end]);
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        // A dropped connection is not an answer from the controller.
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "no HTTP response"))?;
    let chunked = headers.lines().any(|l| {
        l.to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
    });
    drop(headers);

    // A plain body moves to the front of `raw` instead of into a new buffer.
    let body = if chunked {
        decode_chunked(&raw[body_start..])
    } else {
        raw.drain(..body_start);
        raw
    };
    // Valid UTF-8, the normal case, becomes the String without a copy.
    let text = String::from_utf8(body)
        .unwrap_or_else(|err| String::from_utf8_lossy(err.as_bytes()).into_owned());
    Ok((status, text))
}

fn decode_chunked(mut input: &[u8]) -> Vec<u8> {
    // The framing only adds bytes, so the input length bounds the output.
    let mut out = Vec::with_capacity(input.len());
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
                let Some((items, upload_total, download_total)) = parse_connections(&text) else {
                    garbled += 1;
                    if garbled >= 3 {
                        return ended("3 unreadable snapshots in a row".into(), delivered);
                    }
                    continue;
                };
                garbled = 0;
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
/// the upload and download totals. `connections: null` means none; a body
/// without the key is not a snapshot and gives `None`.
pub fn parse_connections(text: &str) -> Option<(Vec<ConnectionItem>, u64, u64)> {
    let snap: conn_json::Snap = serde_json::from_str(text).ok()?;
    let mut connections: Vec<ConnectionItem> = snap
        .connections
        .into_iter()
        .map(conn_json::Conn::into_item)
        .collect();
    connections.sort_by_key(|c| std::cmp::Reverse(c.download + c.upload));
    Some((connections, snap.upload_total, snap.download_total))
}

/// Typed `/connections` JSON. Only the fields `ConnectionItem` shows are
/// declared; serde skips the rest without building a tree, and each string
/// moves into the item. Fields read as leniently as the old `Value` lookups
/// did: null, a missing key or an odd type gives the default.
mod conn_json {
    use super::ConnectionItem;
    use serde::{Deserialize, Deserializer};
    use serde_json::Value;

    fn text<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
        Ok(match Value::deserialize(d)? {
            Value::String(s) => s,
            _ => String::new(),
        })
    }

    fn opt_text<'de, D: Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
        Ok(match Value::deserialize(d)? {
            Value::String(s) => Some(s),
            _ => None,
        })
    }

    fn count<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        Ok(Value::deserialize(d)?.as_u64().unwrap_or(0))
    }

    /// String array entries; anything else is skipped.
    fn texts<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<String>, D::Error> {
        Ok(match Value::deserialize(d)? {
            Value::Array(items) => items
                .into_iter()
                .filter_map(|v| match v {
                    Value::String(s) => Some(s),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        })
    }

    fn nul<'de, D, T>(d: D) -> Result<T, D::Error>
    where
        D: Deserializer<'de>,
        T: Default + Deserialize<'de>,
    {
        Ok(Option::<T>::deserialize(d)?.unwrap_or_default())
    }

    #[derive(Deserialize)]
    pub(super) struct Snap {
        #[serde(rename = "uploadTotal", default, deserialize_with = "count")]
        pub upload_total: u64,
        #[serde(rename = "downloadTotal", default, deserialize_with = "count")]
        pub download_total: u64,
        // No `default`: the key must be present, as Mihomo always writes it.
        #[serde(deserialize_with = "nul")]
        pub connections: Vec<Conn>,
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    pub(super) struct Conn {
        #[serde(deserialize_with = "text")]
        id: String,
        #[serde(deserialize_with = "nul")]
        metadata: Meta,
        #[serde(deserialize_with = "count")]
        upload: u64,
        #[serde(deserialize_with = "count")]
        download: u64,
        #[serde(deserialize_with = "text")]
        start: String,
        #[serde(deserialize_with = "texts")]
        chains: Vec<String>,
        #[serde(rename = "providerChains", deserialize_with = "texts")]
        provider_chains: Vec<String>,
        #[serde(deserialize_with = "text")]
        rule: String,
        #[serde(rename = "rulePayload", deserialize_with = "text")]
        rule_payload: String,
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Meta {
        #[serde(deserialize_with = "opt_text")]
        network: Option<String>,
        #[serde(rename = "type", deserialize_with = "text")]
        inbound: String,
        #[serde(rename = "inboundName", deserialize_with = "text")]
        inbound_name: String,
        #[serde(rename = "sourceIP", deserialize_with = "text")]
        source_ip: String,
        #[serde(rename = "sourcePort", deserialize_with = "text")]
        source_port: String,
        #[serde(rename = "destinationIP", deserialize_with = "text")]
        destination_ip: String,
        #[serde(rename = "destinationPort", deserialize_with = "text")]
        destination_port: String,
        #[serde(deserialize_with = "text")]
        host: String,
        #[serde(rename = "sniffHost", deserialize_with = "text")]
        sniff_host: String,
        #[serde(rename = "dnsMode", deserialize_with = "text")]
        dns_mode: String,
        #[serde(deserialize_with = "text")]
        process: String,
        #[serde(rename = "processPath", deserialize_with = "text")]
        process_path: String,
        #[serde(rename = "destinationGeoIP", deserialize_with = "texts")]
        destination_geo_ip: Vec<String>,
        #[serde(rename = "destinationIPASN", deserialize_with = "text")]
        destination_ip_asn: String,
    }

    impl Conn {
        pub(super) fn into_item(self) -> ConnectionItem {
            let m = self.metadata;
            let host = if m.host.is_empty() {
                &m.destination_ip
            } else {
                &m.host
            };
            let source = if m.source_ip.is_empty() {
                String::new()
            } else {
                format!("{}:{}", m.source_ip, m.source_port)
            };
            let provider: Vec<&str> = self
                .provider_chains
                .iter()
                .rev()
                .map(String::as_str)
                .filter(|name| !name.is_empty())
                .collect();
            ConnectionItem {
                host: format!("{host}:{}", m.destination_port),
                network: m.network.as_deref().unwrap_or("tcp").to_uppercase(),
                chains: self
                    .chains
                    .iter()
                    .rev()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(" › "),
                upload: self.upload,
                download: self.download,
                process: m.process,
                process_path: m.process_path,
                inbound: m.inbound,
                inbound_name: m.inbound_name,
                source,
                sniff_host: m.sniff_host,
                start_ms: crate::conns::parse_rfc3339_ms(&self.start),
                start: self.start,
                provider: provider.join(" › "),
                dns_mode: m.dns_mode,
                dest_geo: m.destination_geo_ip.join(","),
                dest_asn: m.destination_ip_asn,
                id: self.id,
                rule: self.rule,
                rule_payload: self.rule_payload,
                up_rate: 0,
                down_rate: 0,
                ai: false,
            }
        }
    }
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
        let text = r#"{"downloadTotal":5000,"uploadTotal":700,"memory":1,"connections":[
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
            ]}"#;
        let (items, up, down) = parse_connections(text).unwrap();
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

        let empty = r#"{"downloadTotal": 1, "uploadTotal": 2, "connections": null}"#;
        let (items, up, down) = parse_connections(empty).unwrap();
        assert!(items.is_empty());
        assert_eq!((up, down), (2, 1));
    }

    #[test]
    fn snapshot_parser_reads_nulls_and_odd_types_as_defaults() {
        let text = r#"{"uploadTotal":null,"downloadTotal":-1,"connections":[
            {"id":"n","metadata":{"network":null,"type":"Tun","host":null,
             "destinationIP":"198.51.100.4","destinationPort":"80","sourceIP":"",
             "destinationGeoIP":null,"destinationIPASN":null,"process":7},
             "upload":1.5,"download":null,"chains":null,"providerChains":null,
             "rule":null,"rulePayload":null,"start":null},
            {"id":"m","metadata":null,"chains":["A",null,"B"],"providerChains":"x",
             "destinationGeoIP":["CN"],"upload":3,"download":4,"extra":{"deep":[1,2]}}
        ]}"#;
        let (items, up, down) = parse_connections(text).unwrap();
        assert_eq!((up, down), (0, 0));
        let m = &items[0];
        assert_eq!((m.id.as_str(), m.host.as_str()), ("m", ":"));
        assert_eq!((m.network.as_str(), m.chains.as_str()), ("TCP", "B › A"));
        assert_eq!((m.upload, m.download, m.provider.as_str()), (3, 4, ""));
        let n = &items[1];
        assert_eq!(n.host, "198.51.100.4:80");
        assert_eq!((n.network.as_str(), n.inbound.as_str()), ("TCP", "Tun"));
        assert_eq!((n.upload, n.download), (0, 0));
        assert_eq!((n.chains.as_str(), n.provider.as_str()), ("", ""));
        assert_eq!((n.dest_geo.as_str(), n.dest_asn.as_str()), ("", ""));
        assert_eq!((n.process.as_str(), n.source.as_str()), ("", ""));
        assert_eq!((n.rule.as_str(), n.start.as_str()), ("", ""));
        assert_eq!(n.start_ms, None);
    }

    #[test]
    fn snapshot_parser_rejects_bodies_without_a_connection_list() {
        for text in [
            "",
            "not json",
            "{}",
            r#"{"uploadTotal":1,"downloadTotal":2}"#,
            r#"{"connections":{}}"#,
            r#"{"connections":"none"}"#,
            r#"[{"connections":[]}]"#,
        ] {
            assert!(parse_connections(text).is_none(), "{text}");
        }
        assert!(parse_connections(r#"{"connections":[]}"#).is_some());
    }
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;

    /// A controller that answers each path from `routes` (404 otherwise) and
    /// records the paths it was asked for.
    fn controller(
        routes: Vec<(&'static str, String)>,
    ) -> (ControllerConfig, Arc<Mutex<Vec<String>>>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = seen.clone();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut reader = BufReader::new(stream);
                let mut first = String::new();
                if reader.read_line(&mut first).is_err() {
                    continue;
                }
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                let path = first.split_whitespace().nth(1).unwrap_or("").to_string();
                let (status, body) = match routes.iter().find(|(p, _)| *p == path) {
                    Some((_, body)) => (200, body.as_str()),
                    None => (404, r#"{"message":"resource not found"}"#),
                };
                log.lock().unwrap().push(path);
                let _ = write!(
                    reader.get_mut(),
                    "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
            }
        });
        let cfg = ControllerConfig {
            addr,
            config_dir: "/nonexistent/terc-snapshot-test".into(),
            ..ControllerConfig::default()
        };
        (cfg, seen)
    }

    #[test]
    fn polled_body_without_a_connection_list_is_not_an_empty_list() {
        let conns = r#"{"uploadTotal":5,"downloadTotal":6,"connections":[{"id":"a","metadata":{"host":"a.test","destinationPort":"443"},"upload":1,"download":2}]}"#;
        let (cfg, _) = controller(vec![
            ("/version", r#"{"version":"v1.19.28"}"#.into()),
            ("/connections", conns.into()),
        ]);
        let snap = fetch_snapshot(&cfg);
        assert!(snap.running && snap.connections_ok);
        assert_eq!(snap.connections[0].host, "a.test:443");
        assert_eq!((snap.upload_total, snap.download_total), (5, 6));

        for body in [r#"{"uploadTotal":5,"downloadTotal":6}"#, "{}", "oops"] {
            let (cfg, _) = controller(vec![
                ("/version", r#"{"version":"v1.19.28"}"#.into()),
                ("/connections", body.into()),
            ]);
            let snap = fetch_snapshot(&cfg);
            assert!(snap.running, "{body}");
            // App::accept_snapshot then keeps the previous list and totals.
            assert!(!snap.connections_ok, "{body}");
        }
    }

    const PROXIES: &str = r#"{"proxies":{
        "GLOBAL":{"type":"Selector","all":["PROXY"],"now":"PROXY"},
        "PROXY":{"type":"Selector","all":["Inline","JP 01"],"now":"JP 01"},
        "Inline":{"type":"Shadowsocks","udp":true,"history":[{"delay":30}]}}}"#;
    const PROVIDERS: &str = r#"{"providers":{
        "default":{"name":"default","vehicleType":"Compatible","proxies":[{"name":"Inline","type":"Shadowsocks"}]},
        "air":{"name":"air","vehicleType":"HTTP","proxies":[{"name":"JP 01","type":"Vmess","history":[{"delay":88}]}]}}}"#;

    fn routes() -> Vec<(&'static str, String)> {
        vec![
            ("/version", r#"{"version":"v1.19.28"}"#.into()),
            ("/configs", r#"{"mode":"rule","mixed-port":7890}"#.into()),
            ("/proxies", PROXIES.into()),
            ("/connections", r#"{"connections":[]}"#.into()),
            (
                "/rules",
                r#"{"rules":[{"type":"Match","payload":"","proxy":"PROXY"}]}"#.into(),
            ),
            ("/providers/proxies", PROVIDERS.into()),
            (
                "/providers/rules",
                r#"{"providers":{"ads":{"name":"ads","vehicleType":"HTTP","ruleCount":9}}}"#.into(),
            ),
        ]
    }

    #[test]
    fn a_tiered_poll_reads_only_what_it_was_asked_for() {
        let (cfg, seen) = controller(routes());
        let full = fetch_snapshot(&cfg);
        assert_eq!(
            *seen.lock().unwrap(),
            [
                "/version",
                "/configs",
                "/proxies",
                "/connections",
                "/rules",
                "/providers/proxies",
                "/providers/rules"
            ]
        );
        assert_eq!(full.fetched, Fetch::default());
        assert_eq!(full.rules.len(), 1);
        // The reserved `default` provider is not listed; `air` brings its node.
        let names: Vec<_> = full.providers.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["air", "ads"]);
        let jp = &full.nodes["JP 01"];
        assert_eq!((jp.delay, jp.provider.as_deref()), (Some(88), Some("air")));
        assert_eq!(full.nodes["Inline"].provider, None);

        seen.lock().unwrap().clear();
        let fetch = Fetch {
            connections: false,
            rules: false,
            providers: false,
            cached_host: true,
        };
        let lean = fetch_snapshot_with(&cfg, fetch);
        assert_eq!(*seen.lock().unwrap(), ["/version", "/configs", "/proxies"]);
        assert!(lean.running && !lean.connections_ok);
        assert_eq!(lean.fetched, fetch);
        assert_eq!(lean.mixed_port, 7890);
        assert_eq!(lean.groups.len(), 1);
        assert!(lean.rules.is_empty() && lean.providers.is_empty());
        assert!(!lean.nodes.contains_key("JP 01"));

        // A failed GET is not reported as read, so the last data carries over.
        let (cfg, _) = controller(
            routes()
                .into_iter()
                .filter(|(path, _)| !matches!(*path, "/rules" | "/providers/proxies"))
                .collect(),
        );
        let mut failed = fetch_snapshot(&cfg);
        assert!(failed.running);
        assert!(!failed.fetched.rules && !failed.fetched.providers);
        let mut old = full;
        failed.carry_skipped(&mut old);
        assert_eq!(failed.rules.len(), 1);
        assert_eq!(failed.providers.len(), 2);
        assert_eq!(failed.nodes["JP 01"].delay, Some(88));
    }

    #[test]
    fn url_test_and_fallback_groups_carry_their_pin() {
        let proxies = r#"{"proxies":{
            "PROXY":{"type":"Selector","all":["Auto","JP 01"],"now":"Auto"},
            "Auto":{"type":"URLTest","all":["JP 01","US 01"],"now":"US 01","fixed":"JP 01"},
            "Safe":{"type":"Fallback","all":["JP 01","US 01"],"now":"JP 01","fixed":""}}}"#;
        let (cfg, _) = controller(vec![
            ("/version", r#"{"version":"v1.19.28"}"#.into()),
            ("/proxies", proxies.into()),
        ]);
        let snap = fetch_snapshot(&cfg);
        let group = |name: &str| snap.groups.iter().find(|g| g.name == name).unwrap();
        let auto = group("Auto");
        assert_eq!((auto.fixed.as_str(), auto.now.as_str()), ("JP 01", "US 01"));
        assert!(auto.pinnable());
        assert!(group("Safe").fixed.is_empty() && group("Safe").pinnable());
        assert!(group("PROXY").fixed.is_empty() && !group("PROXY").pinnable());
    }

    #[test]
    fn unpin_deletes_the_group_pin() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cfg = ControllerConfig {
            addr: listener.local_addr().unwrap().to_string(),
            ..ControllerConfig::default()
        };
        let (tx, rx) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for status in [204, 400] {
                let (stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream);
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                }
                tx.send(first.trim_end().to_string()).unwrap();
                let _ = write!(
                    reader.get_mut(),
                    "HTTP/1.1 {status} X\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
            }
        });
        unpin_group(&cfg, "Auto 自动").unwrap();
        assert_eq!(
            rx.recv().unwrap(),
            "DELETE /proxies/Auto%20%E8%87%AA%E5%8A%A8 HTTP/1.1"
        );
        // A Selector answers 400: the error reaches the status line.
        assert!(unpin_group(&cfg, "PROXY").is_err());
        assert_eq!(rx.recv().unwrap(), "DELETE /proxies/PROXY HTTP/1.1");
    }

    #[test]
    fn skipped_parts_carry_over_with_provider_nodes_and_their_delays() {
        let (cfg, _) = controller(routes());
        let mut old = fetch_snapshot(&cfg);
        // A latency test since then updated the provider node locally.
        old.nodes.get_mut("JP 01").unwrap().delay = Some(61);
        let fetch = Fetch {
            rules: false,
            providers: false,
            ..Fetch::default()
        };
        let mut lean = fetch_snapshot_with(&cfg, fetch);
        lean.carry_skipped(&mut old);
        assert_eq!(lean.rules.len(), 1);
        assert_eq!(lean.providers.len(), 2);
        let jp = &lean.nodes["JP 01"];
        assert_eq!((jp.delay, jp.provider.as_deref()), (Some(61), Some("air")));
        assert_eq!(jp.kind, "Vmess");
        // Fresh /proxies data wins for the nodes it lists.
        assert_eq!(lean.nodes["Inline"].delay, Some(30));

        // An older core lists provider nodes in /proxies too: the provider
        // name still carries over, the fresh delay stays.
        let mut old = fetch_snapshot(&cfg);
        let mut lean = fetch_snapshot_with(&cfg, fetch);
        lean.nodes.insert(
            "JP 01".into(),
            ProxyNode {
                name: "JP 01".into(),
                kind: "Vmess".into(),
                udp: false,
                delay: Some(70),
                provider: None,
                url_delays: HashMap::new(),
            },
        );
        lean.carry_skipped(&mut old);
        let jp = &lean.nodes["JP 01"];
        assert_eq!((jp.delay, jp.provider.as_deref()), (Some(70), Some("air")));

        // What a poll did read is never replaced, and a stopped core gets nothing.
        let mut old = fetch_snapshot(&cfg);
        let mut full = fetch_snapshot(&cfg);
        full.rules.clear();
        full.carry_skipped(&mut old);
        assert!(full.rules.is_empty());
        let mut stopped = CoreSnapshot {
            fetched: fetch,
            ..CoreSnapshot::default()
        };
        stopped.carry_skipped(&mut old);
        assert!(stopped.rules.is_empty() && stopped.nodes.is_empty());
    }

    #[test]
    fn host_lookups_are_reused_for_polls_and_redone_after_actions() {
        let cache = Mutex::new(None);
        let dir = std::env::temp_dir().join(format!("terc-host-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let bin = dir.join("mihomo");
        fs::write(&bin, "").unwrap();
        let calls = std::cell::Cell::new(0);
        let found = |on: bool| {
            calls.set(calls.get() + 1);
            HostState {
                sysproxy: ("GNOME".into(), on),
                core_bin: Some(bin.clone()),
            }
        };
        let t0 = Instant::now();
        let at = |secs| t0 + Duration::from_secs(secs);
        assert!(
            !host_state_with(&cache, true, at(0), || found(false))
                .sysproxy
                .1
        );
        // Polls within the TTL reuse it, even though the proxy changed.
        assert!(
            !host_state_with(&cache, true, at(14), || found(true))
                .sysproxy
                .1
        );
        assert_eq!(calls.get(), 1);
        // After an action terc looks again, and later polls get that answer.
        assert!(
            host_state_with(&cache, false, at(15), || found(true))
                .sysproxy
                .1
        );
        assert!(
            host_state_with(&cache, true, at(16), || found(false))
                .sysproxy
                .1
        );
        assert_eq!(calls.get(), 2);
        // Expired: a poll looks again.
        assert!(
            !host_state_with(&cache, true, at(31), || found(false))
                .sysproxy
                .1
        );
        assert_eq!(calls.get(), 3);
        // A cached binary that is gone is looked up again at once.
        fs::remove_file(&bin).unwrap();
        let missing = || HostState {
            sysproxy: ("GNOME".into(), false),
            core_bin: None,
        };
        assert_eq!(
            host_state_with(&cache, true, at(32), missing).core_bin,
            None
        );
        // "Not found" is reused only until it expires, so an outside install shows.
        fs::write(&bin, "").unwrap();
        assert_eq!(
            host_state_with(&cache, true, at(40), || found(false)).core_bin,
            None
        );
        let later = host_state_with(&cache, true, at(48), || found(false));
        assert_eq!(later.core_bin.as_deref(), Some(bin.as_path()));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_core_binary_is_found_on_path_without_which() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("terc-path-{}", std::process::id()));
        let (plain, exec) = (root.join("plain"), root.join("exec"));
        fs::create_dir_all(&plain).unwrap();
        fs::create_dir_all(&exec).unwrap();
        // Not executable, then a directory of that name: both skipped.
        fs::write(plain.join("mihomo"), "").unwrap();
        fs::create_dir_all(root.join("dir/mihomo")).unwrap();
        fs::write(exec.join("mihomo"), "").unwrap();
        fs::set_permissions(exec.join("mihomo"), fs::Permissions::from_mode(0o755)).unwrap();
        let path = std::env::join_paths([
            PathBuf::from("relative"),
            plain.clone(),
            root.join("dir"),
            exec.clone(),
        ])
        .unwrap();
        assert_eq!(find_executable(&path, "mihomo"), Some(exec.join("mihomo")));
        assert_eq!(find_executable(&path, "absent"), None);
        assert_eq!(find_executable(std::ffi::OsStr::new(""), "mihomo"), None);
        fs::remove_dir_all(&root).unwrap();
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
    fetch_snapshot_with(cfg, Fetch::default())
}

/// A snapshot reading only the optional endpoints in `fetch`. Without
/// `connections` it has `connections_ok == false`; the other skipped parts
/// stay empty until `CoreSnapshot::carry_skipped` fills them.
pub fn fetch_snapshot_with(cfg: &ControllerConfig, fetch: Fetch) -> CoreSnapshot {
    // One read serves both the runtime flags and the configured values.
    let raw = read_config_text(cfg).ok();
    let mut snapshot = fetch_core_snapshot(cfg, fetch, raw.as_deref());
    if let Some(raw) = raw {
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

fn fetch_core_snapshot(cfg: &ControllerConfig, fetch: Fetch, raw: Option<&str>) -> CoreSnapshot {
    let timeout = Duration::from_millis(700);
    let HostState {
        sysproxy: (net_service, sysproxy_enabled),
        core_bin,
    } = host_state(fetch.cached_host);
    let core_bin_path = core_bin
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "not found".to_string());
    let mut flags = raw.map(parse_yaml_flags).unwrap_or_default();

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
                        let fixed = item
                            .get("fixed")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string();
                        groups.push(ProxyGroup {
                            name: name.clone(),
                            kind: kind.clone(),
                            now,
                            fixed,
                            all,
                            test_url: json_str(item, "testUrl"),
                            expected_status: json_str(item, "expectedStatus"),
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
                            url_delays: url_delays(item),
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

    if fetch.connections {
        if let Ok((200, conn_body)) =
            http_request(&cfg.addr, &cfg.secret, "GET", "/connections", None, timeout)
        {
            // A body without a connection list keeps the last one (`connections_ok`
            // stays false) instead of reporting every session as closed.
            if let Some(parsed) = parse_connections(&conn_body) {
                (connections, upload_total, download_total) = parsed;
                connections_ok = true;
            }
        }
    }

    // `fetched` reports only what was read: a failed GET carries the last
    // data over (`carry_skipped`) instead of emptying it until the next read.
    let mut fetched = fetch;
    let mut rules = Vec::new();
    if fetch.rules {
        match http_request(&cfg.addr, &cfg.secret, "GET", "/rules", None, timeout) {
            Ok((200, body)) => rules = parse_rules_json(&body),
            _ => fetched.rules = false,
        }
    }
    let mut providers = Vec::new();
    let get = |path: &str| match http_request(&cfg.addr, &cfg.secret, "GET", path, None, timeout) {
        Ok((200, body)) => serde_json::from_str::<Value>(&body).ok(),
        _ => None,
    };
    if fetch.providers {
        // One parse feeds both the provider list and the provider nodes.
        if let Some(v) = get("/providers/proxies") {
            providers.extend(crate::ops::providers_from_value(&v, "proxy"));
            let mut extras = provider_url_delays(&v);
            for found in crate::ops::provider_nodes_from_value(&v) {
                let url_delays = extras.remove(&found.name).unwrap_or_default();
                let node = nodes.entry(found.name.clone()).or_insert(ProxyNode {
                    name: found.name,
                    kind: found.kind,
                    udp: found.udp,
                    delay: found.delay,
                    provider: None,
                    url_delays,
                });
                node.provider.get_or_insert(found.provider);
            }
        } else {
            fetched.providers = false;
        }
        if let Some(v) = get("/providers/rules") {
            providers.extend(crate::ops::providers_from_value(&v, "rule"));
        } else {
            fetched.providers = false;
        }
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
        fetched,
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

/// Test helper: one connection's columns except `host` and `chains`, which
/// `parse_connections` fills.
#[cfg(test)]
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

/// Clears the pin a PUT left on a url-test/fallback group.
pub fn unpin_group(cfg: &ControllerConfig, group: &str) -> io::Result<()> {
    let path = format!("/proxies/{}", percent_encode(group));
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
        let group = fetch_group(&cfg, &group_name);
        let ranking_url = group.as_ref().and_then(ProxyGroup::ranking_url);
        let probe = match (&group, ranking_url) {
            (Some(group), Some(url)) => DelayProbe {
                url,
                expected: &group.expected_status,
                timeout_ms: cfg.timeout_ms.max(GROUP_DELAY_TIMEOUT_MS),
            },
            _ => DelayProbe::plain(&cfg, &cfg.test_url),
        };
        let next = std::sync::atomic::AtomicUsize::new(0);
        let providers = std::sync::OnceLock::new();
        let mut indexed: Vec<(usize, Option<u16>)> = thread::scope(|scope| {
            let workers: Vec<_> = (0..DELAY_WORKERS.min(queue.len()))
                .map(|_| {
                    let tx = tx.clone();
                    let (cfg, group_name, queue, next, providers, probe) =
                        (&cfg, &group_name, &queue, &next, &providers, &probe);
                    scope.spawn(move || {
                        let mut done = Vec::new();
                        loop {
                            let index = next.fetch_add(1, Ordering::Relaxed);
                            let Some(node) = queue.get(index) else {
                                break;
                            };
                            let delay = node_delay_with(cfg, node, probe, providers).ok().flatten();
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
        let mut results: Vec<(String, Option<u16>)> = indexed
            .into_iter()
            .map(|(index, delay)| (queue[index].clone(), delay))
            .collect();
        // The route answers 200 with a delay even when the status missed the
        // expected range; only `extra` records whether the group can use it.
        if let Some(url) = ranking_url {
            let fresh = fetch_snapshot(&cfg);
            for (node, delay) in &mut results {
                *delay = fresh
                    .nodes
                    .get(node)
                    .and_then(|n| n.url_delays.get(url).copied().flatten());
            }
            if fresh.running {
                let _ = tx.send(BackendEvent::Snapshot(Box::new(fresh)));
            }
        }
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

fn json_str(item: &Value, key: &str) -> String {
    item.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// A proxy's `extra`: per test URL, the last delay while the state is alive.
/// The global history records a delay even when the expected status missed.
fn url_delays(item: &Value) -> HashMap<String, Option<u16>> {
    item.get("extra")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(url, state)| {
            let alive = state.get("alive").and_then(Value::as_bool) == Some(true);
            let delay = state
                .get("history")
                .and_then(Value::as_array)
                .and_then(|arr| arr.last())
                .and_then(|h| h.get("delay"))
                .and_then(Value::as_u64)
                .and_then(|d| if alive && d > 0 { Some(d as u16) } else { None });
            (url.clone(), delay)
        })
        .collect()
}

/// `url_delays` of every node in a `/providers/proxies` body, by node name.
fn provider_url_delays(value: &Value) -> HashMap<String, HashMap<String, Option<u16>>> {
    value
        .get("providers")
        .and_then(Value::as_object)
        .into_iter()
        .flat_map(|obj| obj.values())
        .filter_map(|item| item.get("proxies").and_then(Value::as_array))
        .flatten()
        .map(|proxy| (json_str(proxy, "name"), url_delays(proxy)))
        .filter(|(name, extra)| !name.is_empty() && !extra.is_empty())
        .collect()
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
    // A newer build earlier on PATH wins over the distribution or AUR
    // package, which is only the fallback for a PATH without /usr/bin.
    std::env::var_os("PATH")
        .and_then(|path| find_executable(&path, "mihomo"))
        .or_else(|| Some(PathBuf::from("/usr/bin/mihomo")).filter(|p| p.is_file()))
}

/// What `which` does, without starting it: the first executable `name` in
/// the directories of `path`.
fn find_executable(path: &std::ffi::OsStr, name: &str) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    std::env::split_paths(path)
        .filter(|dir| dir.is_absolute())
        .map(|dir| dir.join(name))
        .find(|p| fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0))
}

/// The two lookups a snapshot makes outside the controller.
#[derive(Clone, Debug, PartialEq)]
struct HostState {
    sysproxy: (String, bool),
    core_bin: Option<PathBuf>,
}

/// How long a background poll reuses `HostState`. Reading the system proxy
/// starts gsettings on Linux and three to five scutil and networksetup
/// processes on macOS, which every 2.2 s poll used to do. A change made
/// outside terc shows up within this; terc's own actions are followed by a
/// full snapshot, which looks again.
const HOST_TTL: Duration = Duration::from_secs(15);

static HOST_CACHE: Mutex<Option<(Instant, HostState)>> = Mutex::new(None);

fn host_state(cached: bool) -> HostState {
    host_state_with(&HOST_CACHE, cached, Instant::now(), || HostState {
        sysproxy: detect_sysproxy(),
        core_bin: discover_mihomo_binary(),
    })
}

/// A fresh lookup, stored for later `cached` calls. A cached result is used
/// while younger than `HOST_TTL` and its binary is still there; a missing
/// binary expires like any other result, so an install made outside terc
/// shows up.
fn host_state_with(
    cache: &Mutex<Option<(Instant, HostState)>>,
    cached: bool,
    now: Instant,
    detect: impl FnOnce() -> HostState,
) -> HostState {
    // Held while detecting, so a poll and an action never both spawn.
    let mut slot = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some((at, state)) = slot.as_ref().filter(|_| cached) {
        let fresh = now.saturating_duration_since(*at) < HOST_TTL;
        if fresh && state.core_bin.as_ref().is_none_or(|bin| bin.is_file()) {
            return state.clone();
        }
    }
    let state = detect();
    *slot = Some((now, state.clone()));
    state
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

/// Airport CDNs often gzip and now and then answer 5xx or 429, which curl
/// retries. A panel or converter may build the file for half a minute before
/// its first byte, and curl's low-speed check counts that wait, so there is
/// none: one attempt keeps the former 60 s. Only a failure within 20 s is
/// retried, so a timed-out attempt is not repeated and the worst case stays
/// near 80 s.
const SUBSCRIPTION_CURL: &[&str] = &[
    "-fsSL",
    "--compressed",
    "--connect-timeout",
    "10",
    "--max-time",
    "60",
    "--retry",
    "2",
    "--retry-delay",
    "1",
    "--retry-max-time",
    "20",
    "-A",
    "clash.meta/1.19.32",
];

pub fn download_subscription(cfg: &ControllerConfig) -> Result<String, String> {
    if cfg.subscription_url.trim().is_empty() {
        return Err("Subscription URL is empty".into());
    }
    let output = curl()
        .args(SUBSCRIPTION_CURL)
        .args(["--url", cfg.subscription_url.trim()])
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
/// rules into `config.yaml`, validate it (the running core checks it on reload,
/// `mihomo -t` otherwise), and hot-reload.
pub fn regenerate_config(
    cfg: &ControllerConfig,
    modules: &[crate::ops::ModuleSnippet],
    running: bool,
    refresh: bool,
    zh: bool,
) -> Result<String, String> {
    regenerate_routing(cfg, modules, running, refresh, zh, None)
}

/// `u`: download the subscription and regenerate. The outer document of a
/// provider-style subscription rarely changes, and a reload would only
/// re-read the providers' cached files while dropping their connections, so
/// an unchanged result refreshes the HTTP proxy providers in place instead.
/// After a reload Mihomo already pulls any provider whose cache is stale.
pub fn update_subscription(
    cfg: &ControllerConfig,
    modules: &[crate::ops::ModuleSnippet],
    running: bool,
    zh: bool,
) -> Result<String, String> {
    let (message, reloaded) = regenerate_outcome(cfg, modules, running, true, zh, None)?;
    Ok(match refresh_after_regenerate(cfg, running, reloaded) {
        Some((ok, 0)) if zh => format!("{message}；已更新 {ok} 个订阅提供者"),
        Some((ok, failed)) if zh => {
            format!("{message}；订阅提供者更新 {ok} 个，失败 {failed} 个")
        }
        Some((ok, failed)) => format!("{message}; providers {ok} updated  {failed} failed"),
        None => message,
    })
}

/// Refresh the HTTP proxy providers the core lists, when regenerating left
/// the running config untouched. `None` when there was nothing to refresh.
fn refresh_after_regenerate(
    cfg: &ControllerConfig,
    running: bool,
    reloaded: bool,
) -> Option<(usize, usize)> {
    if !running || reloaded {
        return None;
    }
    let (status, body) = http_request(
        &cfg.addr,
        &cfg.secret,
        "GET",
        "/providers/proxies",
        None,
        Duration::from_millis(cfg.timeout_ms.max(1500)),
    )
    .ok()?;
    let list: Vec<(String, String)> = parse_providers_json(&body, "proxy")
        .into_iter()
        .filter(|p| status == 200 && refreshable_provider(p))
        .filter(|p| p.vehicle.eq_ignore_ascii_case("HTTP"))
        .map(|p| (p.kind, p.name))
        .collect();
    (!list.is_empty()).then(|| refresh_providers(cfg, &list))
}

pub fn regenerate_routing(
    cfg: &ControllerConfig,
    modules: &[crate::ops::ModuleSnippet],
    running: bool,
    refresh: bool,
    zh: bool,
    selection: Option<&str>,
) -> Result<String, String> {
    regenerate_outcome(cfg, modules, running, refresh, zh, selection).map(|(message, _)| message)
}

/// The status message and whether the core was reloaded.
fn regenerate_outcome(
    cfg: &ControllerConfig,
    modules: &[crate::ops::ModuleSnippet],
    running: bool,
    refresh: bool,
    zh: bool,
    selection: Option<&str>,
) -> Result<(String, bool), String> {
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
        // Normalise the first file the way the next run will (it zeroes the
        // listener keys a source leaves out), so that run finds it unchanged.
        None => (compose::carry_runtime_state(&base, &base), Vec::new()),
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
    Ok((
        format!("{}{tail}{}", report.summary(zh), report.details()),
        reload && running,
    ))
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
    let path = config_yaml_path(cfg);
    // A running core parses the payload with the same code as `mihomo -t` and
    // answers 400 before applying anything, so it validates for free. A
    // stopped core cannot, and missing geodata would be downloaded inside the
    // PUT handler, past the reload timeout; the check fetches it first with
    // its own budget.
    let mut find_bin = Some(find_bin);
    // `mihomo -t` on a candidate copy, which a stopped core's file becomes.
    let mut check = |install: bool| -> Result<(), String> {
        let candidate = Path::new(&cfg.config_dir).join(".terc-candidate.yaml");
        write_private(&candidate, text.as_bytes()).map_err(|e| e.to_string())?;
        let checked = (|| {
            let bin = find_bin
                .take()
                .and_then(|find| find())
                .ok_or("Install the managed Mihomo core before saving a configuration")?;
            check_candidate(&bin, cfg, &candidate, limits)?;
            if install {
                fs::rename(&candidate, &path).map_err(|e| e.to_string())
            } else {
                Ok(())
            }
        })();
        let _ = fs::remove_file(candidate);
        checked
    };
    let checked = !running || needs_missing_geodata(&text, Path::new(&cfg.config_dir));
    if checked {
        check(!running)?;
        if !running {
            return Ok(());
        }
    }
    let save = || write_private(&path, text.as_bytes()).map_err(|e| e.to_string());
    match reload_config_text(cfg, &text) {
        Ok(()) => {
            // The core runs the new config; until the file matches, the next
            // regeneration must reload even when its output is unchanged.
            let saved = save();
            RELOAD_UNCERTAIN.store(saved.is_err(), Ordering::SeqCst);
            saved.map_err(|err| {
                format!("新配置已生效，但保存失败 / Applied, but could not save config.yaml: {err}")
                    .into()
            })
        }
        // The core kept its configuration and the file was never touched.
        Err(ReloadError::Rejected(err)) => {
            Err(format!("{err}; previous configuration kept").into())
        }
        // Mihomo finishes applying a PUT after the client gives up, so the new
        // config may already be live; keep it on disk too. Either way the
        // running config may differ from the file, so the next regeneration
        // reloads even when its output is unchanged.
        //
        // A handler that dropped the connection without applying anything
        // looks the same, so the core's own parse never vouched for this
        // text: check it before it can outlive a core that then restarts.
        Err(ReloadError::Unknown(err)) => {
            RELOAD_UNCERTAIN.store(true, Ordering::SeqCst);
            if !checked {
                check(false).map_err(|e| {
                    format!(
                        "热重载结果未知，新配置未通过校验，未保存 / Reload outcome unknown ({err}); the new configuration failed validation and was not saved: {e}"
                    )
                })?;
            }
            save()?;
            if controller_answers(cfg, limits.settle) {
                return Ok(());
            }
            Err(InstallFailure {
                message: format!(
                    "热重载结果未知，新配置已保留在磁盘上 / Reload outcome unknown ({err}); the new configuration was kept on disk"
                ),
                kept: true,
            })
        }
    }
}

/// Whether `text` uses geodata that `dir` lacks. Mihomo looks the files up in
/// its home directory, case-insensitively; a false positive only costs a
/// `mihomo -t`.
fn needs_missing_geodata(text: &str, dir: &Path) -> bool {
    let (mut geoip, mut geosite, mut asn, mut geodata_mode) = (false, false, false, false);
    let mut section = String::new();
    for raw in text.lines() {
        let line = raw.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if raw.len() == line.len() {
            section = lower.split(':').next().unwrap_or("").to_string();
        }
        // Download URLs and loader settings name the files without using them.
        if section == "geox-url" || section.starts_with("geodata-") {
            geodata_mode |= lower.starts_with("geodata-mode:") && lower.contains("true");
            continue;
        }
        // A DNS `fallback` list filters with GEOIP,CN unless told otherwise.
        geoip |= lower.contains("geoip") || lower.starts_with("fallback:");
        geosite |= lower.contains("geosite");
        asn |= lower.contains("ip-asn");
    }
    if !(geoip || geosite || asn) {
        return false;
    }
    let names: Vec<String> = fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_ascii_lowercase())
                .collect()
        })
        .unwrap_or_default();
    let has = |wanted: &[&str]| wanted.iter().any(|w| names.iter().any(|n| n == w));
    let ip_files: &[&str] = if geodata_mode {
        &["geoip.dat"]
    } else {
        &["country.mmdb", "geoip.db", "geoip.metadb"]
    };
    (geoip && !has(ip_files)) || (geosite && !has(&["geosite.dat"])) || (asn && !has(&["asn.mmdb"]))
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

/// The plain `-amd64` asset is the GOAMD64=v3 build, which will not run on
/// CPUs or VMs without AVX2; `-amd64-v1` is the baseline build under the
/// name upstream keeps (`-compatible` is marked for removal in build.yml).
pub fn mihomo_asset_id_for(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("macos", "aarch64") => Some("darwin-arm64"),
        ("macos", "x86_64") => Some("darwin-amd64-v1"),
        ("linux", "aarch64") => Some("linux-arm64"),
        ("linux", "x86_64") => Some("linux-amd64-v1"),
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

const MIHOMO_RELEASES: &str = "https://github.com/MetaCubeX/mihomo/releases";

/// The system curl. Tests talk to loopback mock servers, which a proxy from
/// the environment must not capture.
fn curl() -> Command {
    let mut cmd = Command::new("curl");
    cmd.stdin(Stdio::null());
    if cfg!(test) {
        for key in [
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
        ] {
            cmd.env_remove(key);
        }
    }
    cmd
}

fn curl_error(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let last = stderr.lines().rev().find(|l| !l.trim().is_empty());
    match last {
        Some(line) => brief(line),
        None => format!("curl exited with {}", output.status),
    }
}

/// The running core's own listener, for fetching a core update through the
/// user's node. Not with TUN on: curl is captured by it already. Only this
/// curl uses it; the system proxy is never touched.
pub fn core_download_proxy(snapshot: &CoreSnapshot) -> Option<u16> {
    if !snapshot.running || snapshot.tun_enabled {
        return None;
    }
    [snapshot.mixed_port, snapshot.http_port]
        .into_iter()
        .find(|port| *port > 0)
}

/// Arguments for one attempt at the release asset. No throughput floor: a
/// 10-15 KB/s link must still finish. A stall of 60 s below 1 KB/s ends the
/// attempt, and `-C -` lets the next one resume the partial file.
pub fn core_curl_args(url: &str, out: &Path, proxy: Option<&str>) -> Vec<String> {
    let mut args: Vec<String> = [
        "-fsSL",
        "--connect-timeout",
        "10",
        "--speed-limit",
        "1024",
        "--speed-time",
        "60",
        "-C",
        "-",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if let Some(proxy) = proxy {
        args.extend(proxy_args(proxy).map(str::to_string));
    }
    args.extend(["-o".to_string(), out.display().to_string(), url.to_string()]);
    args
}

/// An empty `--noproxy` keeps a NO_PROXY from the environment from quietly
/// turning the explicit route into a direct one.
fn proxy_args(proxy: &str) -> [&str; 4] {
    ["-x", proxy, "--noproxy", ""]
}

/// Routes to try in order: the core's local listener when given, then direct.
fn core_routes(proxy_port: Option<u16>) -> Vec<Option<String>> {
    proxy_port
        .map(|port| Some(format!("http://127.0.0.1:{port}")))
        .into_iter()
        .chain([None])
        .collect()
}

/// The latest tag from version.txt, which every release carries, so the
/// asset name is exact and the 60-per-hour api.github.com limit is avoided.
/// Also returns the routes left from the first one that worked.
fn latest_core_version(
    base: &str,
    routes: Vec<Option<String>>,
) -> Result<(String, Vec<Option<String>>), String> {
    let url = format!("{base}/latest/download/version.txt");
    let mut last = String::new();
    for (i, route) in routes.iter().enumerate() {
        let mut cmd = curl();
        cmd.args(["-fsSL", "--connect-timeout", "10", "--max-time", "30"]);
        if let Some(proxy) = route {
            cmd.args(proxy_args(proxy));
        }
        let output = cmd.arg(&url).output().map_err(|e| format!("curl: {e}"))?;
        if !output.status.success() {
            last = curl_error(&output);
            continue;
        }
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let valid = version.starts_with('v')
            && version.len() <= 32
            && version[1..]
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
        if !valid {
            last = format!("unexpected version.txt: {}", brief(&version));
            continue;
        }
        return Ok((version, routes[i..].to_vec()));
    }
    Err(last)
}

/// Download `url` to `part`, resuming across attempts: two through the core,
/// then three direct.
fn fetch_core_asset(
    url: &str,
    part: &Path,
    routes: &[Option<String>],
    tx: &Sender<BackendEvent>,
) -> Result<(), String> {
    let pause = Duration::from_secs(if cfg!(test) { 0 } else { 2 });
    let mut last = String::new();
    for (n, route) in routes.iter().enumerate() {
        if n > 0 {
            let _ = tx.send(BackendEvent::StatusMessage {
                text: format!("Core proxy failed ({last}); downloading directly..."),
                is_error: false,
            });
        }
        for attempt in 0..if route.is_some() { 2 } else { 3 } {
            if attempt > 0 {
                thread::sleep(pause);
            }
            let output = curl()
                .args(core_curl_args(url, part, route.as_deref()))
                .output()
                .map_err(|e| format!("curl: {e}"))?;
            if output.status.success() {
                return Ok(());
            }
            last = curl_error(&output);
            // 416: the part is already whole (an earlier run stopped before
            // unpacking it); 33: the server cannot resume. Start over.
            let code = output.status.code();
            if (code == Some(22) && last.contains("error: 416")) || code == Some(33) {
                let _ = fs::remove_file(part);
            }
        }
    }
    Err(last)
}

fn install_core_from(
    base: &str,
    asset: &str,
    core_dir: &Path,
    proxy_port: Option<u16>,
    tx: &Sender<BackendEvent>,
) -> Result<PathBuf, String> {
    fs::create_dir_all(core_dir)
        .map_err(|err| format!("Cannot create {}: {err}", core_dir.display()))?;
    let _ = tx.send(BackendEvent::StatusMessage {
        text: format!("Checking latest mihomo-{asset} release..."),
        is_error: false,
    });
    let (version, routes) = latest_core_version(base, core_routes(proxy_port))
        .map_err(|err| format!("Cannot read the latest mihomo version: {err}"))?;
    let name = format!("mihomo-{asset}-{version}.gz");
    let part = core_dir.join(format!("{name}.part"));
    // Partial files of other versions, and the old script's mihomo.gz.
    if let Ok(entries) = fs::read_dir(core_dir) {
        for entry in entries.flatten() {
            let file = entry.file_name().to_string_lossy().to_string();
            let stale = file.ends_with(".gz.part") || file == "mihomo.gz";
            if stale && entry.path() != part {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    let via = match routes.first() {
        Some(Some(proxy)) => format!(" via {}", proxy.trim_start_matches("http://")),
        _ => String::new(),
    };
    let _ = tx.send(BackendEvent::StatusMessage {
        text: format!("Downloading {name}{via}..."),
        is_error: false,
    });
    let url = format!("{base}/download/{version}/{name}");
    fetch_core_asset(&url, &part, &routes, tx)
        .map_err(|err| format!("Failed to download {name}: {err}"))?;
    let bin = core_dir.join("mihomo");
    let fresh = core_dir.join("mihomo.new");
    let unpacked = fs::File::create(&fresh)
        .and_then(|file| {
            Command::new("gunzip")
                .arg("-c")
                .arg(&part)
                .stdin(Stdio::null())
                .stdout(file)
                .stderr(Stdio::piped())
                .output()
        })
        .map_err(|err| format!("gunzip: {err}"))?;
    if !unpacked.status.success() {
        let _ = fs::remove_file(&fresh);
        let _ = fs::remove_file(&part);
        return Err(format!(
            "Downloaded {name} is damaged ({}); press Ctrl+D to fetch it again",
            brief(&String::from_utf8_lossy(&unpacked.stderr))
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&fresh, fs::Permissions::from_mode(0o755))
            .map_err(|err| format!("chmod {}: {err}", fresh.display()))?;
    }
    fs::rename(&fresh, &bin).map_err(|err| format!("Cannot replace {}: {err}", bin.display()))?;
    let _ = fs::remove_file(&part);
    Ok(bin)
}

fn install_managed_core(
    tx: &Sender<BackendEvent>,
    proxy_port: Option<u16>,
) -> Result<String, String> {
    let asset = mihomo_asset_id().ok_or_else(|| {
        "No mihomo build for this OS/CPU (darwin-arm64, darwin-amd64, linux-arm64, linux-amd64)"
            .to_string()
    })?;
    let home = std::env::var_os("HOME").ok_or_else(|| "HOME is not set".to_string())?;
    let core_dir = PathBuf::from(home).join(".config/terc/core");
    install_core_from(MIHOMO_RELEASES, asset, &core_dir, proxy_port, tx)
        .map(|bin| bin.display().to_string())
}

/// `proxy_port` comes from `core_download_proxy`.
pub fn download_managed_core_async(tx: Sender<BackendEvent>, proxy_port: Option<u16>) {
    thread::spawn(move || {
        let (text, ok) = match install_managed_core(&tx, proxy_port) {
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
    /// The controller answered with an HTTP error or refused the connection.
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

/// Reload the core from `config.yaml`.
pub fn reload_config(cfg: &ControllerConfig) -> Result<(), ReloadError> {
    let path = config_yaml_path(cfg);
    put_config(
        cfg,
        &serde_json::json!({
            "path": path.display().to_string(),
            "payload": ""
        })
        .to_string(),
    )
}

/// Reload the core from `text` before it is written. Sending the content also
/// spares Mihomo's safe-path check on a core whose home is elsewhere.
fn reload_config_text(cfg: &ControllerConfig, text: &str) -> Result<(), ReloadError> {
    put_config(cfg, &serde_json::json!({ "payload": text }).to_string())
}

fn put_config(cfg: &ControllerConfig, body: &str) -> Result<(), ReloadError> {
    use crate::conns::{Cause, Scope};
    // Mihomo re-initialises every proxy provider on reload (§2.2 of
    // docs/websocket-plan.md); top-level `proxies:` connections stay.
    announce_disruption(Cause::Reload, Scope::Providers);
    // The first fetch of new providers runs inside the request, so allow well
    // beyond Mihomo's own provider download timeout.
    match http_request(
        &cfg.addr,
        &cfg.secret,
        "PUT",
        "/configs?force=true",
        Some(body),
        Duration::from_millis(cfg.timeout_ms.max(90_000)),
    ) {
        Ok((status, _)) if (200..300).contains(&status) => Ok(()),
        Ok((status, text)) => {
            // Mihomo answers 400 before applying anything, so nothing was cut:
            // replace the announcement with one that covers no connection.
            announce_disruption(Cause::Reload, Scope::Id(String::new()));
            Err(ReloadError::Rejected(format!(
                "reload HTTP {status} {}",
                brief(&text)
            )))
        }
        // Refused at connect: the core is gone and received nothing.
        Err(err) if err.kind() == io::ErrorKind::ConnectionRefused => {
            announce_disruption(Cause::Reload, Scope::Id(String::new()));
            Err(ReloadError::Rejected(format!("reload failed: {err}")))
        }
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

/// Save `text` without `mihomo -t` or a reload, when what it changes is
/// already known to hold: the running core accepted and read back each
/// changed key, or the effective config equals the active one. With the core
/// running, a mode switched at runtime is kept.
pub fn save_config_unchecked(
    cfg: &ControllerConfig,
    text: &str,
    running: bool,
) -> Result<(), String> {
    validate_listener_ports(text)?;
    let text = if running {
        keep_runtime_mode(cfg, text)
    } else {
        text.to_string()
    };
    let saved = fs::create_dir_all(&cfg.config_dir)
        .and_then(|()| write_private(&config_yaml_path(cfg), text.as_bytes()))
        .map_err(|e| e.to_string());
    // The core now runs a value the file lacks, so the next regeneration
    // must reload even when its output is unchanged.
    if saved.is_err() && running {
        RELOAD_UNCERTAIN.store(true, Ordering::SeqCst);
    }
    saved
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
    verify_runtime_value(cfg, key, value)
}

/// Read `key` back from `GET /configs` after a PATCH.
pub fn verify_runtime_value(
    cfg: &ControllerConfig,
    key: &str,
    value: &Value,
) -> Result<(), String> {
    let runtime = read_runtime_config(cfg).map_err(|e| e.to_string())?;
    // An older core that does not report the key cannot be checked.
    let Some(actual) = runtime.get(key) else {
        return Ok(());
    };
    let matches = match key {
        "allow-lan" | "tcp-concurrent" | "ipv6" | "sniffing" => {
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

/// Record a switch the running core already applied and read back; the edit
/// is one bool in a file that already validated, so no `mihomo -t`.
pub fn persist_live_bool(cfg: &ControllerConfig, path: &[&str], value: bool) -> Result<(), String> {
    let raw = read_config_text(cfg)?;
    save_config_unchecked(cfg, &crate::ops::set_nested_bool(&raw, path, value), true)
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

/// The controller route for a provider kind. `ProviderInfo.kind` keeps the
/// singular label the UI compares; Mihomo mounts only the plural routes.
fn provider_route(kind: &str) -> &str {
    match kind {
        "proxy" => "proxies",
        "rule" => "rules",
        other => other,
    }
}

/// Unlike a reload, this swaps the provider's content without closing the
/// connections through its nodes.
pub fn refresh_provider(cfg: &ControllerConfig, kind: &str, name: &str) -> Result<(), String> {
    let path = format!(
        "/providers/{}/{}",
        provider_route(kind),
        percent_encode(name)
    );
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

/// Mihomo's reserved `default` provider is its only `Compatible` one, and
/// updating it does nothing.
pub fn refreshable_provider(provider: &ProviderInfo) -> bool {
    !provider.vehicle.eq_ignore_ascii_case("Compatible")
        && !(provider.kind == "proxy" && provider.name == "default")
}

/// Each refresh is a download inside the core; a few run at once.
const PROVIDER_WORKERS: usize = 4;

/// Refresh `(kind, name)` pairs concurrently; returns (updated, failed).
fn refresh_providers(cfg: &ControllerConfig, providers: &[(String, String)]) -> (usize, usize) {
    use std::sync::atomic::AtomicUsize;
    let next = AtomicUsize::new(0);
    let ok = AtomicUsize::new(0);
    thread::scope(|scope| {
        for _ in 0..PROVIDER_WORKERS.min(providers.len()) {
            scope.spawn(|| {
                while let Some((kind, name)) = providers.get(next.fetch_add(1, Ordering::SeqCst)) {
                    if refresh_provider(cfg, kind, name).is_ok() {
                        ok.fetch_add(1, Ordering::SeqCst);
                    }
                }
            });
        }
    });
    let ok = ok.into_inner();
    (ok, providers.len() - ok)
}

#[derive(Debug, PartialEq, Eq)]
pub enum HealthCheck {
    Done,
    /// No answer within the cap. The core keeps checking and records the
    /// delays, which the next poll picks up.
    StillRunning,
    Failed(String),
}

/// Mihomo answers only after every node was tried, ten at a time and each up
/// to its own timeout, so a large provider takes well over a few seconds.
const HEALTHCHECK_TIMEOUT: Duration = Duration::from_secs(120);

pub fn provider_healthcheck(cfg: &ControllerConfig, name: &str) -> HealthCheck {
    provider_healthcheck_with(cfg, name, HEALTHCHECK_TIMEOUT)
}

fn provider_healthcheck_with(cfg: &ControllerConfig, name: &str, timeout: Duration) -> HealthCheck {
    let path = format!("/providers/proxies/{}/healthcheck", percent_encode(name));
    match http_request(&cfg.addr, &cfg.secret, "GET", &path, None, timeout) {
        Ok((status, _)) if (200..300).contains(&status) => HealthCheck::Done,
        Ok((status, body)) => HealthCheck::Failed(format!("HTTP {status} {}", brief(&body))),
        // A read timeout surfaces as WouldBlock on Unix.
        Err(err)
            if matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            HealthCheck::StillRunning
        }
        Err(err) => HealthCheck::Failed(err.to_string()),
    }
}

/// Health check outcomes in the UI language.
pub struct HealthTexts {
    pub done: String,
    pub still: String,
}

/// Runs beside the action queue, so polling continues and delays show up
/// while the core checks.
pub fn provider_healthcheck_async(
    cfg: ControllerConfig,
    name: String,
    texts: HealthTexts,
    tx: Sender<BackendEvent>,
) {
    thread::spawn(move || {
        let (text, is_error) = match provider_healthcheck(&cfg, &name) {
            HealthCheck::Done => {
                let snap = fetch_snapshot(&cfg);
                let _ = tx.send(BackendEvent::Snapshot(Box::new(snap)));
                (texts.done, false)
            }
            HealthCheck::StillRunning => (texts.still, false),
            HealthCheck::Failed(err) => (err, true),
        };
        let _ = tx.send(BackendEvent::StatusMessage { text, is_error });
    });
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

/// Refresh the providers the UI already lists, then take one snapshot for the
/// new nodes and rule counts.
pub fn refresh_all_providers_async(
    cfg: ControllerConfig,
    providers: Vec<ProviderInfo>,
    tx: Sender<BackendEvent>,
) {
    thread::spawn(move || {
        let list: Vec<(String, String)> = providers
            .into_iter()
            .filter(refreshable_provider)
            .map(|p| (p.kind, p.name))
            .collect();
        let (ok, failed) = refresh_providers(&cfg, &list);
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
    node_delay_with(
        cfg,
        node,
        &DelayProbe::plain(cfg, url),
        &std::sync::OnceLock::new(),
    )
}

/// The query of one delay test.
struct DelayProbe<'a> {
    url: &'a str,
    /// Mihomo's `expected=`; empty sends none and accepts any status.
    expected: &'a str,
    timeout_ms: u64,
}

impl<'a> DelayProbe<'a> {
    fn plain(cfg: &ControllerConfig, url: &'a str) -> Self {
        Self {
            url,
            expected: "",
            timeout_ms: cfg.timeout_ms,
        }
    }

    /// Capped for saved settings from before the cap, too.
    fn timeout_ms(&self) -> u64 {
        self.timeout_ms.min(MAX_DELAY_TIMEOUT_MS)
    }

    fn query(&self) -> String {
        let mut query = format!(
            "url={}&timeout={}",
            percent_encode(self.url),
            self.timeout_ms()
        );
        if !self.expected.is_empty() {
            query.push_str(&format!("&expected={}", percent_encode(self.expected)));
        }
        query
    }
}

/// GET /proxies/{group}: its type, `testUrl` and `expectedStatus`, read at
/// the start of each test so the round uses what the core ranks on now.
fn fetch_group(cfg: &ControllerConfig, name: &str) -> Option<ProxyGroup> {
    let path = format!("/proxies/{}", percent_encode(name));
    let timeout = Duration::from_millis(cfg.timeout_ms.max(1500));
    let Ok((200, body)) = http_request(&cfg.addr, &cfg.secret, "GET", &path, None, timeout) else {
        return None;
    };
    let item = serde_json::from_str::<Value>(&body).ok()?;
    Some(ProxyGroup {
        name: name.to_string(),
        kind: json_str(&item, "type"),
        now: json_str(&item, "now"),
        fixed: json_str(&item, "fixed"),
        all: Vec::new(),
        test_url: json_str(&item, "testUrl"),
        expected_status: json_str(&item, "expectedStatus"),
    })
}

/// GET /proxies/{name}/delay, falling back to the provider healthcheck route
/// on 404: since Mihomo v1.19.28 the former only resolves inline proxies.
/// `providers` maps node to provider and is fetched at most once per run.
fn node_delay_with(
    cfg: &ControllerConfig,
    node: &str,
    probe: &DelayProbe,
    providers: &std::sync::OnceLock<HashMap<String, String>>,
) -> Result<Option<u16>, String> {
    let query = probe.query();
    let get = |path: &str| {
        http_request(
            &cfg.addr,
            &cfg.secret,
            "GET",
            path,
            None,
            Duration::from_millis(probe.timeout_ms() + 500),
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

    #[test]
    fn delay_timeout_is_capped_to_what_mihomo_parses() {
        let mut mock = recorder(Duration::ZERO, |_| (200, r#"{"delay":9}"#));
        mock.cfg.timeout_ms = 60_000;
        let url = DEFAULT_TEST_URL;
        assert_eq!(test_node_delay(&mock.cfg, "A", url), Ok(Some(9)));
        let lines = mock.lines.lock().unwrap().clone();
        assert_eq!(
            lines,
            ["GET /proxies/A/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=32767 HTTP/1.1"]
        );
    }

    /// `Auto` ranks on its own URL and status; `Main` is a Selector whose
    /// non-default `testUrl` terc does not use. The delay route answers 200
    /// for both nodes, but `B` missed the expected status.
    fn group_reply(path: &str) -> (u16, &'static str) {
        match path {
            "/version" => (200, r#"{"version":"v1.19.28"}"#),
            "/configs" => (200, r#"{"mode":"rule"}"#),
            "/proxies/Auto" => (
                200,
                r#"{"name":"Auto","type":"URLTest","all":["A","B","P"],"testUrl":"https://ai.test/x","expectedStatus":"200/204"}"#,
            ),
            "/proxies/Main" => (
                200,
                r#"{"name":"Main","type":"Selector","all":["A","B"],"testUrl":"https://ai.test/x"}"#,
            ),
            "/proxies" => (
                200,
                r#"{"proxies":{
                "Auto":{"type":"URLTest","all":["A","B","P"],"now":"A","testUrl":"https://ai.test/x","expectedStatus":"200/204"},
                "Main":{"type":"Selector","all":["A","B"],"now":"A"},
                "A":{"type":"Vmess","history":[{"delay":35}],"extra":{"https://ai.test/x":{"alive":true,"history":[{"delay":40}]}}},
                "B":{"type":"Vmess","history":[{"delay":30}],"extra":{"https://ai.test/x":{"alive":false,"history":[{"delay":30}]}}}}}"#,
            ),
            "/providers/proxies" => (
                200,
                r#"{"providers":{"air":{"name":"air","vehicleType":"HTTP","proxies":[{"name":"P","type":"Trojan","history":[{"delay":12}],"extra":{"https://ai.test/x":{"alive":true,"history":[{"delay":50}]}}}]}}}"#,
            ),
            p if p.starts_with("/proxies/P/delay?") => (404, ""),
            p if p.starts_with("/proxies/") && p.contains("/delay?") => (200, r#"{"delay":30}"#),
            p if p.starts_with("/providers/proxies/air/P/healthcheck?") => (200, r#"{"delay":50}"#),
            _ => (404, r#"{"message":"resource not found"}"#),
        }
    }

    fn run_best(
        cfg: &ControllerConfig,
        group: &str,
        nodes: &[&str],
    ) -> (Vec<(String, Option<u16>)>, Option<CoreSnapshot>) {
        let (tx, rx) = mpsc::channel();
        test_best_delays_async(
            cfg.clone(),
            group.into(),
            nodes.iter().map(|s| s.to_string()).collect(),
            tx,
        );
        let mut snapshot = None;
        loop {
            match rx.recv_timeout(Duration::from_secs(10)).unwrap() {
                BackendEvent::DelayResult { .. } => {}
                BackendEvent::Snapshot(snap) => snapshot = Some(*snap),
                BackendEvent::BestTestDone { results, .. } => break (results, snapshot),
                _ => panic!("unexpected event"),
            }
        }
    }

    #[test]
    fn urltest_rounds_use_the_group_url_and_rank_on_extra() {
        let mock = recorder(Duration::ZERO, group_reply);
        let (results, snapshot) = run_best(&mock.cfg, "Auto", &["A", "B", "P"]);
        // B answered 200 with a delay, yet the group counts it as dead.
        let expected: Vec<(String, Option<u16>)> = vec![
            ("A".into(), Some(40)),
            ("B".into(), None),
            ("P".into(), Some(50)),
        ];
        assert_eq!(results, expected);
        let lines = mock.lines.lock().unwrap().clone();
        let query = "url=https%3A%2F%2Fai.test%2Fx&timeout=5000&expected=200%2F204 HTTP/1.1";
        for line in [
            format!("GET /proxies/A/delay?{query}"),
            format!("GET /proxies/B/delay?{query}"),
            format!("GET /providers/proxies/air/P/healthcheck?{query}"),
        ] {
            assert!(lines.contains(&line), "{line} not in {lines:?}");
        }
        // The fresh state goes to the UI, which shows what the group ranks on.
        let snap = snapshot.expect("a snapshot after the round");
        let auto = snap.groups.iter().find(|g| g.name == "Auto").unwrap();
        assert_eq!(auto.ranking_url(), Some("https://ai.test/x"));
        assert_eq!(auto.expected_status, "200/204");
        let delays: Vec<_> = ["A", "B", "P"]
            .iter()
            .map(|n| auto.member_delay(&snap.nodes[*n]))
            .collect();
        assert_eq!(delays, [Some(40), None, Some(50)]);
        let main = snap.groups.iter().find(|g| g.name == "Main").unwrap();
        assert_eq!(main.ranking_url(), None);
        assert_eq!(main.member_delay(&snap.nodes["B"]), Some(30));
    }

    #[test]
    fn selector_rounds_keep_the_configured_url_and_history() {
        let mock = recorder(Duration::ZERO, group_reply);
        let (results, snapshot) = run_best(&mock.cfg, "Main", &["A", "B"]);
        assert_eq!(results, [("A".into(), Some(30)), ("B".into(), Some(30))]);
        assert!(snapshot.is_none());
        let lines = mock.lines.lock().unwrap().clone();
        assert!(lines.contains(
            &"GET /proxies/A/delay?url=https%3A%2F%2Fwww.gstatic.com%2Fgenerate_204&timeout=500 HTTP/1.1"
                .to_string()
        ));
        assert!(lines
            .iter()
            .all(|l| !l.contains("expected=") && l != "GET /proxies HTTP/1.1"));
    }

    /// Mock controller that records each request line, answers `PUT`s after
    /// `delay` and tracks how many were in flight at once.
    struct Recorder {
        cfg: ControllerConfig,
        lines: Arc<Mutex<Vec<String>>>,
        peak: Arc<AtomicUsize>,
    }

    fn recorder(delay: Duration, reply: fn(&str) -> (u16, &'static str)) -> Recorder {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let lines: Arc<Mutex<Vec<String>>> = Arc::default();
        let peak: Arc<AtomicUsize> = Arc::default();
        let busy: Arc<AtomicUsize> = Arc::default();
        let (seen, high) = (lines.clone(), peak.clone());
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let (seen, high, busy) = (seen.clone(), high.clone(), busy.clone());
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
                    let line = first.trim_end().to_string();
                    seen.lock().unwrap().push(line.clone());
                    if line.starts_with("PUT ") {
                        let now = busy.fetch_add(1, Ordering::SeqCst) + 1;
                        high.fetch_max(now, Ordering::SeqCst);
                        thread::sleep(delay);
                        busy.fetch_sub(1, Ordering::SeqCst);
                    }
                    let path = line.split_whitespace().nth(1).unwrap_or("");
                    let (status, body) = reply(path);
                    let _ = write!(
                        reader.get_mut(),
                        "HTTP/1.1 {status} X\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                });
            }
        });
        Recorder {
            cfg: ControllerConfig {
                addr,
                timeout_ms: 500,
                ..ControllerConfig::default()
            },
            lines,
            peak,
        }
    }

    fn provider(kind: &str, name: &str, vehicle: &str) -> ProviderInfo {
        ProviderInfo {
            name: name.into(),
            kind: kind.into(),
            vehicle: vehicle.into(),
            behavior: String::new(),
            count: 0,
            updated_at: String::new(),
        }
    }

    #[test]
    fn provider_refresh_puts_to_the_plural_routes_mihomo_mounts() {
        let mock = recorder(Duration::ZERO, |path| {
            if path.starts_with("/providers/proxies/") || path.starts_with("/providers/rules/") {
                (204, "")
            } else {
                (404, r#"{"message":"resource not found"}"#)
            }
        });
        assert_eq!(refresh_provider(&mock.cfg, "proxy", "air port"), Ok(()));
        assert_eq!(refresh_provider(&mock.cfg, "rule", "reject"), Ok(()));
        let lines = mock.lines.lock().unwrap().clone();
        assert_eq!(
            lines,
            [
                "PUT /providers/proxies/air%20port HTTP/1.1",
                "PUT /providers/rules/reject HTTP/1.1"
            ]
        );
    }

    #[test]
    fn refresh_all_runs_four_at_once_and_skips_the_reserved_provider() {
        let mock = recorder(Duration::from_millis(250), |path| match path {
            "/providers/rules/broken" => (500, r#"{"message":"download failed"}"#),
            p if p.starts_with("/providers/") => (204, ""),
            _ => (404, ""),
        });
        let mut providers = vec![
            provider("proxy", "default", "Compatible"),
            provider("proxy", "air", "HTTP"),
            provider("rule", "broken", "HTTP"),
        ];
        for i in 0..6 {
            providers.push(provider("rule", &format!("r{i}"), "HTTP"));
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let started = Instant::now();
        refresh_all_providers_async(mock.cfg.clone(), providers, tx);
        let status = loop {
            match rx.recv_timeout(Duration::from_secs(10)).unwrap() {
                BackendEvent::StatusMessage { text, is_error } => break (text, is_error),
                BackendEvent::Snapshot(_) => {}
                _ => panic!("unexpected event"),
            }
        };
        // 8 PUTs of 250 ms, four at a time: two rounds, not eight.
        assert!(started.elapsed() < Duration::from_millis(1500));
        assert_eq!(status, ("providers 7 updated  1 failed".into(), false));
        assert_eq!(mock.peak.load(Ordering::SeqCst), PROVIDER_WORKERS);
        let lines = mock.lines.lock().unwrap().clone();
        let puts: Vec<_> = lines.iter().filter(|l| l.starts_with("PUT ")).collect();
        assert_eq!(puts.len(), 8);
        assert!(puts.iter().all(|l| !l.contains("default")));
        assert!(puts.contains(&&"PUT /providers/proxies/air HTTP/1.1".to_string()));
        // The list came from the UI, so no snapshot is fetched before the PUTs.
        assert!(lines[0].starts_with("PUT "), "{lines:?}");
    }

    #[test]
    fn unchanged_update_refreshes_only_http_proxy_providers() {
        let mock = recorder(Duration::ZERO, |path| match path {
            "/providers/proxies" => (
                200,
                r#"{"providers":{"default":{"name":"default","vehicleType":"Compatible","proxies":[]},"air":{"name":"air","vehicleType":"HTTP","proxies":[]},"own":{"name":"own","vehicleType":"File","proxies":[]}}}"#,
            ),
            _ => (204, ""),
        });
        // A stopped core or a reload (which pulls stale providers itself)
        // sends nothing.
        assert_eq!(refresh_after_regenerate(&mock.cfg, false, false), None);
        assert_eq!(refresh_after_regenerate(&mock.cfg, true, true), None);
        assert!(mock.lines.lock().unwrap().is_empty());
        assert_eq!(
            refresh_after_regenerate(&mock.cfg, true, false),
            Some((1, 0))
        );
        assert_eq!(
            mock.lines.lock().unwrap().clone(),
            [
                "GET /providers/proxies HTTP/1.1",
                "PUT /providers/proxies/air HTTP/1.1"
            ]
        );
        // Inline `proxies:` only: nothing to refresh.
        let inline = recorder(Duration::ZERO, |_| (200, r#"{"providers":{}}"#));
        assert_eq!(refresh_after_regenerate(&inline.cfg, true, false), None);
    }

    #[test]
    fn slow_health_check_reports_the_core_still_checking() {
        let mock = recorder(Duration::ZERO, |path| match path {
            "/providers/proxies/air/healthcheck" => (204, ""),
            _ => (404, r#"{"message":"resource not found"}"#),
        });
        assert_eq!(provider_healthcheck(&mock.cfg, "air"), HealthCheck::Done);
        assert!(matches!(
            provider_healthcheck(&mock.cfg, "gone"),
            HealthCheck::Failed(err) if err.starts_with("HTTP 404")
        ));
        // A controller that accepts but stays silent past the cap.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cfg = ControllerConfig {
            addr: listener.local_addr().unwrap().to_string(),
            ..ControllerConfig::default()
        };
        let hold = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(800));
            drop(stream);
        });
        assert_eq!(
            provider_healthcheck_with(&cfg, "air", Duration::from_millis(200)),
            HealthCheck::StillRunning
        );
        hold.join().unwrap();
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
    fn real_core_validates_overlays_and_config_updates_keep_the_file_on_failure() {
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
                assert!(result.unwrap_err().contains("previous configuration kept"));
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
        // The baseline amd64 build, never the AVX2-only plain `-amd64`.
        assert_eq!(
            mihomo_asset_id_for("macos", "x86_64"),
            Some("darwin-amd64-v1")
        );
        assert_eq!(mihomo_asset_id_for("linux", "aarch64"), Some("linux-arm64"));
        assert_eq!(
            mihomo_asset_id_for("linux", "x86_64"),
            Some("linux-amd64-v1")
        );
        assert_eq!(mihomo_asset_id_for("windows", "x86_64"), None);
        assert_eq!(mihomo_asset_id_for("linux", "arm"), None);
    }

    #[test]
    fn core_download_resumes_stalls_and_never_caps_total_time() {
        let out = Path::new("/tmp/terc/mihomo.gz.part");
        let direct = core_curl_args("https://example.org/m.gz", out, None);
        let joined = direct.join(" ");
        assert!(joined.contains("--speed-limit 1024 --speed-time 60"));
        assert!(joined.contains("-C -"));
        assert!(joined.ends_with("-o /tmp/terc/mihomo.gz.part https://example.org/m.gz"));
        // A slow link must be able to finish; curl's own --retry restarts at 0.
        assert!(!joined.contains("--max-time") && !joined.contains("--retry"));
        assert!(!direct.iter().any(|a| a == "-x"));
        let proxied = core_curl_args(
            "https://example.org/m.gz",
            out,
            Some("http://127.0.0.1:7890"),
        );
        assert!(proxied
            .join(" ")
            .contains("-x http://127.0.0.1:7890 --noproxy  -o"));
        for arg in direct.iter().chain(&proxied) {
            assert!(!arg.contains("networksetup") && !arg.contains("gsettings"));
        }
    }

    #[test]
    fn core_download_uses_the_core_listener_only_without_tun() {
        let mut snapshot = CoreSnapshot {
            running: true,
            mixed_port: 7890,
            http_port: 7891,
            ..CoreSnapshot::default()
        };
        assert_eq!(core_download_proxy(&snapshot), Some(7890));
        snapshot.mixed_port = 0;
        assert_eq!(core_download_proxy(&snapshot), Some(7891));
        snapshot.tun_enabled = true;
        assert_eq!(core_download_proxy(&snapshot), None);
        snapshot.tun_enabled = false;
        snapshot.running = false;
        assert_eq!(core_download_proxy(&snapshot), None);
        snapshot.running = true;
        snapshot.http_port = 0;
        assert_eq!(core_download_proxy(&snapshot), None);
        assert_eq!(core_routes(None), vec![None]);
        assert_eq!(
            core_routes(Some(7890)),
            vec![Some("http://127.0.0.1:7890".to_string()), None]
        );
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
    fn rejected_reload_leaves_the_file_and_withdraws_the_disruption() {
        use crate::conns::{Cause, Scope};
        let (dir, _) = install_fixture("rejected", "exit 0");
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
        let (tx, rx) = std::sync::mpsc::channel();
        report_disruptions(tx);
        // The running core validates; no `mihomo -t` is needed.
        let failure = install_config_with(
            &cfg,
            "mode: rule\nipv6: true\n",
            true,
            || panic!("no check while the core runs"),
            &TEST_LIMITS,
        )
        .err()
        .unwrap();
        let requests = server.join().unwrap();
        assert!(requests[1].starts_with("PUT /configs?force=true "));
        assert!(requests[1].ends_with(r#"{"payload":"mode: rule\nipv6: true\n"}"#));
        assert!(!failure.kept);
        assert!(failure.message.contains("previous configuration kept"));
        assert_eq!(read_config_text(&cfg).unwrap(), previous);
        assert!(!dir.join(".terc-candidate.yaml").exists());
        // Nothing was applied, so no closure may be blamed on this reload.
        let events: Vec<_> = rx.try_iter().collect();
        assert!(matches!(
            &events[..],
            [
                BackendEvent::Disrupting {
                    cause: Cause::Reload,
                    scope: Scope::Providers
                },
                BackendEvent::Disrupting {
                    cause: Cause::Reload,
                    scope: Scope::Id(id)
                }
            ] if id.is_empty()
        ));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    #[cfg(unix)]
    fn running_core_validates_the_payload_and_the_file_follows() {
        let (dir, bin) = install_fixture(
            "payload",
            "echo run >> \"$(dirname \"$0\")/checks\"; exit 0",
        );
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cfg = ControllerConfig {
            addr: listener.local_addr().unwrap().to_string(),
            config_dir: dir.display().to_string(),
            ..ControllerConfig::default()
        };
        let checks = dir.join("checks");
        let next = "mode: rule\nrules:\n  - GEOSITE,cn,DIRECT\n";
        let ok = || {
            vec![
                http("200 OK", r#"{"mode":"rule"}"#),
                http("204 No Content", ""),
            ]
        };
        // GeoSite.dat is missing: `mihomo -t` fetches it before the PUT.
        let server = serve(listener.try_clone().unwrap(), ok());
        install_config_with(&cfg, next, true, || Some(bin.clone()), &TEST_LIMITS)
            .ok()
            .unwrap();
        let requests = server.join().unwrap();
        assert!(requests[1].contains(r#"{"payload":"mode: \"rule\"\nrules:"#));
        assert_eq!(fs::read_to_string(&checks).unwrap().lines().count(), 1);
        assert!(read_config_text(&cfg)
            .unwrap()
            .contains("GEOSITE,cn,DIRECT"));
        assert_eq!(mode_of(&config_yaml_path(&cfg)) & 0o077, 0);
        // With the file present the PUT alone validates and applies.
        fs::write(dir.join("GeoSite.dat"), "").unwrap();
        let server = serve(listener, ok());
        let other = "mode: rule\nipv6: true\nrules:\n  - GEOSITE,cn,DIRECT\n";
        install_config_with(&cfg, other, true, || None, &TEST_LIMITS)
            .ok()
            .unwrap();
        server.join().unwrap();
        assert_eq!(fs::read_to_string(&checks).unwrap().lines().count(), 1);
        assert!(read_config_text(&cfg).unwrap().contains("ipv6: true"));
        assert!(!dir.join(".terc-candidate.yaml").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn geodata_need_follows_the_rules_dns_and_files_present() {
        let dir = std::env::temp_dir().join(format!("terc-geo-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let need = |text: &str| needs_missing_geodata(text, &dir);
        assert!(!need(
            "rules:\n  - DOMAIN-SUFFIX,example.com,DIRECT\n  - MATCH,DIRECT\n"
        ));
        assert!(!need("# GEOSITE,cn,DIRECT only in a comment\nrules: []\n"));
        assert!(!need(
            "geodata-mode: false\ngeox-url:\n  geoip: \"https://x/geoip.dat\"\n  geosite: \"https://x/geosite.dat\"\n  asn: \"https://x/GeoLite2-ASN.mmdb\"\nrules: []\n"
        ));
        assert!(need("rules:\n  - GEOIP,CN,DIRECT\n"));
        assert!(need(
            "rules:\n  - AND,((GEOSITE,cn),(NETWORK,UDP)),REJECT\n"
        ));
        assert!(need("rules:\n  - IP-ASN,13335,DIRECT\n"));
        assert!(need(
            "dns:\n  nameserver-policy:\n    'geosite:cn': 223.5.5.5\n"
        ));
        assert!(need("dns:\n  fallback:\n    - tls://1.1.1.1\n"));
        fs::write(dir.join("Country.mmdb"), "").unwrap();
        fs::write(dir.join("geosite.dat"), "").unwrap();
        assert!(!need(
            "rules:\n  - GEOIP,CN,DIRECT\n  - GEOSITE,cn,DIRECT\n"
        ));
        // geodata-mode reads GeoIP.dat instead of the mmdb.
        assert!(need("geodata-mode: true\nrules:\n  - GEOIP,CN,DIRECT\n"));
        assert!(need("rules:\n  - SRC-IP-ASN,13335,DIRECT\n"));
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
    fn reload_that_never_reached_the_core_saves_only_a_checked_file() {
        let previous = "mode: rule\n";
        let invalid = "mode: rule\nproxies:\n  - {name: x, type: nosuch}\n";
        // Refused: the core is gone and got nothing, so nothing is kept.
        let (dir, _) = install_fixture("refused", "exit 0");
        let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cfg = ControllerConfig {
            addr: closed.local_addr().unwrap().to_string(),
            config_dir: dir.display().to_string(),
            ..ControllerConfig::default()
        };
        drop(closed);
        fs::write(config_yaml_path(&cfg), previous).unwrap();
        let failure = install_config_with(
            &cfg,
            invalid,
            true,
            || panic!("a refused reload needs no check"),
            &TEST_LIMITS,
        )
        .err()
        .unwrap();
        assert!(!failure.kept);
        assert!(failure.message.contains("previous configuration kept"));
        assert_eq!(read_config_text(&cfg).unwrap(), previous);
        fs::remove_dir_all(dir).unwrap();
        // Dropped without a reply: `mihomo -t` decides whether the file is kept.
        for valid in [false, true] {
            let (dir, bin) = install_fixture(
                "dropped",
                if valid {
                    "exit 0"
                } else {
                    "echo 'unsupported type' >&2; exit 1"
                },
            );
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let cfg = ControllerConfig {
                addr: listener.local_addr().unwrap().to_string(),
                config_dir: dir.display().to_string(),
                ..ControllerConfig::default()
            };
            fs::write(config_yaml_path(&cfg), previous).unwrap();
            let mut responses = vec![http("200 OK", "{}"), Vec::new()];
            if valid {
                responses.push(http("200 OK", "{\"version\":\"v1\"}"));
            }
            let server = serve(listener, responses);
            let next = if valid {
                "mode: rule\nipv6: true\n"
            } else {
                invalid
            };
            let result = install_config_with(&cfg, next, true, || Some(bin), &TEST_LIMITS);
            server.join().unwrap();
            if valid {
                assert!(result.is_ok());
                assert_eq!(read_config_text(&cfg).unwrap(), next);
            } else {
                let failure = result.err().unwrap();
                assert!(!failure.kept);
                assert!(failure.message.contains("not saved"), "{}", failure.message);
                assert!(failure.message.contains("unsupported type"));
                assert_eq!(read_config_text(&cfg).unwrap(), previous);
            }
            assert!(!dir.join(".terc-candidate.yaml").exists());
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
    fn first_generation_is_a_fixed_point_of_the_carry() {
        use crate::compose::carry_runtime_state as carry;
        let base =
            "mixed-port: 7890\nallow-lan: false\nmode: rule\ntun:\n  enable: false\nproxies: []\n";
        // What regenerate writes when there is no previous file.
        let first = carry(base, base);
        assert!(first.contains("\nport: 0\n") && first.contains("\nsocks-port: 0\n"));
        // What the next run derives from that file and the same source.
        assert_eq!(carry(&first, base), first);
    }

    #[test]
    #[cfg(unix)]
    fn live_changes_are_saved_without_a_check_or_reload() {
        let (dir, _) = install_fixture("live", "exit 1");
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cfg = ControllerConfig {
            addr: listener.local_addr().unwrap().to_string(),
            config_dir: dir.display().to_string(),
            ..ControllerConfig::default()
        };
        fs::write(config_yaml_path(&cfg), "mode: rule\nipv6: false\n").unwrap();
        // Only the runtime mode is read: no PUT, and no `mihomo -t` to reject it.
        let mode = || http("200 OK", r#"{"mode":"Global","ipv6":true}"#);
        let server = serve(listener.try_clone().unwrap(), vec![mode(), mode()]);
        persist_live_bool(&cfg, &["ipv6"], true).unwrap();
        assert_eq!(
            read_config_text(&cfg).unwrap(),
            "mode: \"global\"\nipv6: true\n"
        );
        assert_eq!(mode_of(&config_yaml_path(&cfg)) & 0o077, 0);
        save_config_unchecked(&cfg, "mode: rule\nmixed-port: 7899\n", true).unwrap();
        let requests = server.join().unwrap();
        assert!(requests.iter().all(|r| r.starts_with("GET /configs ")));
        assert_eq!(
            read_config_text(&cfg).unwrap(),
            "mode: \"global\"\nmixed-port: 7899\n"
        );
        // Listener clashes are still refused, and a stopped core reads nothing.
        assert!(save_config_unchecked(&cfg, "port: 7899\nmixed-port: 7899\n", false).is_err());
        save_config_unchecked(&cfg, "mode: rule\n", false).unwrap();
        assert_eq!(read_config_text(&cfg).unwrap(), "mode: rule\n");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn switches_read_back_as_bools() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cfg = ControllerConfig {
            addr: listener.local_addr().unwrap().to_string(),
            ..ControllerConfig::default()
        };
        let runtime = r#"{"ipv6":true,"sniffing":false}"#;
        let server = serve(
            listener,
            vec![http("200 OK", runtime), http("200 OK", runtime)],
        );
        assert!(verify_runtime_value(&cfg, "ipv6", &true.into()).is_ok());
        let err = verify_runtime_value(&cfg, "sniffing", &true.into()).unwrap_err();
        assert!(err.contains("sniffing reads back as false"), "{err}");
        server.join().unwrap();
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
        let checks_run = || fs::read_to_string(&checks).map_or(0, |t| t.lines().count());
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
        // The first file is already a fixed point: the next pass carries the
        // listener keys over from it and finds nothing to change. The running
        // core validates the PUT itself, so no install runs the check;
        // `regenerate_routing` and `install_config_with` read the mode.
        let mode = || http("200 OK", r#"{"mode":"rule"}"#);
        let server = serve(
            listener.try_clone().unwrap(),
            vec![mode(), mode(), http("204 No Content", "")],
        );
        let msg = regenerate_config(&cfg, &[], true, false, false).unwrap();
        assert!(server.join().unwrap()[2].starts_with("PUT /configs?force=true "));
        assert!(msg.contains("validated & hot-reloaded"), "{msg}");
        assert_eq!(checks_run(), 0);
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
        assert_eq!(checks_run(), 0);
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
        assert_eq!(checks_run(), 0);
        fs::remove_dir_all(home).unwrap();
    }

    fn compose_generated(cfg: &ControllerConfig) -> PathBuf {
        crate::compose::terc_dir()
            .join("generated")
            .join(format!("{}.yaml", cfg.profile_id))
    }
}

#[cfg(test)]
mod download_tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;

    /// Answer `count` connections with `respond(request head)`; returns the heads.
    fn serve_heads(
        listener: TcpListener,
        count: usize,
        respond: impl Fn(&str) -> Vec<u8> + Send + 'static,
    ) -> thread::JoinHandle<Vec<String>> {
        thread::spawn(move || {
            let mut heads = Vec::new();
            for _ in 0..count {
                let (stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream);
                let mut head = String::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    head.push_str(&line);
                }
                let _ = reader.get_mut().write_all(&respond(&head));
                heads.push(head);
            }
            heads
        })
    }

    fn reply(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut child = Command::new("gzip")
            .arg("-c")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(data).unwrap();
        child.wait_with_output().unwrap().stdout
    }

    fn dead_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn scratch(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("terc-core-dl-{tag}-{}-{nanos}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    const BINARY: &[u8] = b"#!/bin/sh\necho mihomo\n";
    const ASSET: &str = "/download/v1.2.3/mihomo-linux-amd64-v1-v1.2.3.gz";

    fn release(head: &str, gz: &[u8]) -> Vec<u8> {
        if head.contains("/latest/download/version.txt ") {
            reply("200 OK", "", b"v1.2.3\n")
        } else if head.contains(ASSET) {
            reply("200 OK", "", gz)
        } else {
            reply("404 Not Found", "", b"")
        }
    }

    fn notes(rx: &mpsc::Receiver<BackendEvent>) -> Vec<String> {
        rx.try_iter()
            .filter_map(|e| match e {
                BackendEvent::StatusMessage { text, .. } => Some(text),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn core_install_reads_version_txt_and_falls_back_from_a_dead_core_proxy() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let gz = gzip(BINARY);
        let server = serve_heads(listener, 2, move |head| release(head, &gz));
        let dir = scratch("direct");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("mihomo-linux-amd64-v1-v1.0.0.gz.part"), b"old").unwrap();
        fs::write(dir.join("mihomo.gz"), b"old").unwrap();
        let (tx, rx) = mpsc::channel();
        let bin = install_core_from(&base, "linux-amd64-v1", &dir, Some(dead_port()), &tx).unwrap();
        let heads = server.join().unwrap();
        assert!(heads[0].starts_with("GET /latest/download/version.txt "));
        assert!(heads[1].starts_with(&format!("GET {ASSET} ")), "{heads:?}");
        assert_eq!(fs::read(&bin).unwrap(), BINARY);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&bin).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        let mut left: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        left.sort();
        assert_eq!(left, ["mihomo"]);
        assert!(notes(&rx)
            .iter()
            .any(|n| n == "Downloading mihomo-linux-amd64-v1-v1.2.3.gz..."));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn core_install_goes_through_the_core_listener_when_it_works() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy = listener.local_addr().unwrap().port();
        // Unreachable directly: only the proxy route can succeed.
        let base = format!("http://127.0.0.1:{}", dead_port());
        let gz = gzip(BINARY);
        let server = serve_heads(listener, 2, move |head| release(head, &gz));
        let dir = scratch("proxy");
        let (tx, rx) = mpsc::channel();
        let bin = install_core_from(&base, "linux-amd64-v1", &dir, Some(proxy), &tx).unwrap();
        let heads = server.join().unwrap();
        // Absolute-form request lines: curl spoke to the core as a proxy.
        assert!(
            heads.iter().all(|h| h.starts_with(&format!("GET {base}/"))),
            "{heads:?}"
        );
        assert_eq!(fs::read(&bin).unwrap(), BINARY);
        let via = format!(" via 127.0.0.1:{proxy}...");
        assert!(notes(&rx).iter().any(|n| n.ends_with(&via)));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn core_install_resumes_a_cut_transfer_and_reports_curl_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let gz = gzip(BINARY);
        let cut = gz.len() / 2;
        let served = Arc::new(Mutex::new(0));
        let server = serve_heads(listener, 3, move |head| {
            if head.contains("version.txt") {
                return reply("200 OK", "", b"v1.2.3");
            }
            let mut n = served.lock().unwrap();
            *n += 1;
            if *n == 1 {
                // Promise the whole file, send half, hang up.
                let mut out = reply("200 OK", "", &gz);
                out.truncate(out.len() - (gz.len() - cut));
                return out;
            }
            let range = format!(
                "Content-Range: bytes {cut}-{}/{}\r\n",
                gz.len() - 1,
                gz.len()
            );
            reply("206 Partial Content", &range, &gz[cut..])
        });
        let dir = scratch("resume");
        let (tx, _rx) = mpsc::channel();
        let bin = install_core_from(&base, "linux-amd64-v1", &dir, None, &tx).unwrap();
        let heads = server.join().unwrap();
        assert!(
            heads[2].contains(&format!("Range: bytes={cut}-")),
            "{heads:?}"
        );
        assert_eq!(fs::read(&bin).unwrap(), BINARY);
        fs::remove_dir_all(&dir).unwrap();

        // A missing asset: three direct attempts, curl's reason in the error.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = serve_heads(listener, 4, |head| release(head, b""));
        let err = install_core_from(&base, "darwin-arm64", &dir, None, &tx).unwrap_err();
        assert_eq!(server.join().unwrap().len(), 4);
        assert!(
            err.starts_with("Failed to download mihomo-darwin-arm64-v1.2.3.gz: "),
            "{err}"
        );
        assert!(err.contains("404"), "{err}");
        assert!(!dir.join("mihomo").exists());

        // Not gzip: refused, and the part is dropped so Ctrl+D starts clean.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = serve_heads(listener, 2, |head| release(head, b"<html>portal</html>"));
        let err = install_core_from(&base, "linux-amd64-v1", &dir, None, &tx).unwrap_err();
        server.join().unwrap();
        assert!(err.contains("damaged"), "{err}");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn subscription_download_waits_for_a_slow_first_byte() {
        let flag = |name: &str| {
            let at = SUBSCRIPTION_CURL.iter().position(|a| *a == name).unwrap();
            SUBSCRIPTION_CURL[at + 1].parse::<u64>().unwrap()
        };
        // A low-speed window would also time the wait before the first byte.
        assert!(!SUBSCRIPTION_CURL.contains(&"--speed-limit"));
        assert_eq!(flag("--max-time"), 60);
        // An attempt that ran out of time is past the retry window.
        assert!(flag("--retry-max-time") < flag("--max-time"));
    }

    #[test]
    fn subscription_download_asks_for_gzip_and_retries_a_503() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/sub?token=x", listener.local_addr().unwrap());
        let body = "proxies:\n  - {name: a, type: ss}\n".repeat(20);
        let packed = gzip(body.as_bytes());
        let first = Arc::new(Mutex::new(true));
        let server = serve_heads(listener, 2, move |_| {
            if std::mem::replace(&mut *first.lock().unwrap(), false) {
                return reply("503 Service Unavailable", "", b"");
            }
            reply("200 OK", "Content-Encoding: gzip\r\n", &packed)
        });
        let cfg = ControllerConfig {
            subscription_url: url,
            ..ControllerConfig::default()
        };
        assert_eq!(download_subscription(&cfg).unwrap(), body);
        let heads = server.join().unwrap();
        assert!(heads[1].starts_with("GET /sub?token=x "));
        let lower = heads[1].to_ascii_lowercase();
        assert!(
            lower.contains("accept-encoding: ") && lower.contains("gzip"),
            "{lower}"
        );
        assert!(heads[1].contains("User-Agent: clash.meta/1.19.32"));
    }
}
