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
        Arc,
    },
    thread,
    time::Duration,
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ops::{
    apply_general_json, bool_patch_body, parse_dns_message, parse_probe_target,
    parse_providers_json, parse_rules_json, parse_yaml_flags, rule_disable_body, tun_patch_body,
    DnsMessage, DnsStatus, ProbeTarget, ProviderInfo, RuleInfo, RuntimeFlags,
};

#[derive(Clone, Debug)]
pub enum BackendEvent {
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
    DelayResult {
        group: String,
        node: String,
        delay: Option<u16>,
    },
    GroupTestDone {
        group: String,
    },
    StatusMessage {
        text: String,
        is_error: bool,
    },
    SubscriptionDone {
        ok: bool,
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
    pub sysproxy_enabled: bool,
    pub network_service: String,
    pub groups: Vec<ProxyGroup>,
    pub nodes: HashMap<String, ProxyNode>,
    pub connections: Vec<ConnectionItem>,
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
    pub dns_mode: String,
    pub dest_geo: String,
    pub dest_asn: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ControllerConfig {
    pub addr: String,
    pub secret: String,
    pub config_dir: String,
    pub subscription_url: String,
    pub test_url: String,
    pub timeout_ms: u64,
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
    let normalized = raw.replace(
        "external-controller: :9090",
        "external-controller: 127.0.0.1:9090",
    );
    let has_controller = normalized
        .lines()
        .any(|line| line.starts_with("external-controller:"));
    if has_controller {
        normalized
    } else {
        format!("external-controller: {controller_addr}\n{normalized}")
    }
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
    let text = String::from_utf8_lossy(&raw);

    let (headers, rest) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = headers
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(500);

    let decoded_body = if headers.lines().any(|l| {
        l.to_ascii_lowercase()
            .contains("transfer-encoding: chunked")
    }) {
        decode_chunked(rest)
    } else {
        rest.to_string()
    };

    Ok((status, decoded_body))
}

fn decode_chunked(mut input: &str) -> String {
    let mut out = String::new();
    loop {
        let Some((len_line, after_len)) = input.split_once("\r\n") else {
            break;
        };
        let Ok(chunk_len) = usize::from_str_radix(len_line.trim(), 16) else {
            break;
        };
        if chunk_len == 0 {
            break;
        }
        if after_len.len() < chunk_len {
            out.push_str(after_len);
            break;
        }
        out.push_str(&after_len[..chunk_len]);
        input = &after_len[chunk_len..];
        if let Some(stripped) = input.strip_prefix("\r\n") {
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
) {
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

pub fn config_yaml_path(cfg: &ControllerConfig) -> PathBuf {
    Path::new(&cfg.config_dir).join("config.yaml")
}

pub fn read_config_text(cfg: &ControllerConfig) -> Result<String, String> {
    let path = config_yaml_path(cfg);
    fs::read_to_string(&path).map_err(|_| format!("config not found: {}", path.display()))
}

pub fn write_config_text(cfg: &ControllerConfig, text: &str) -> Result<(), String> {
    let path = config_yaml_path(cfg);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| err.to_string())?;
    }
    fs::write(&path, text).map_err(|err| format!("cannot write {}: {err}", path.display()))
}

fn local_flags(cfg: &ControllerConfig) -> RuntimeFlags {
    fs::read_to_string(config_yaml_path(cfg))
        .map(|text| parse_yaml_flags(&text))
        .unwrap_or_default()
}

pub fn fetch_snapshot(cfg: &ControllerConfig) -> CoreSnapshot {
    let timeout = Duration::from_millis(700);
    let (net_service, sysproxy_enabled) = detect_macos_sysproxy();
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
    let mut http_port = 7890;
    let mut socks_port = 7891;
    let mut mixed_port = 0;
    let mut allow_lan = false;

    if let Ok((200, cfg_body)) =
        http_request(&cfg.addr, &cfg.secret, "GET", "/configs", None, timeout)
    {
        if let Ok(v) = serde_json::from_str::<Value>(&cfg_body) {
            if let Some(m) = v.get("mode").and_then(Value::as_str) {
                mode = m.to_string();
            }
            http_port = v.get("port").and_then(Value::as_u64).unwrap_or(7890) as u16;
            socks_port = v.get("socks-port").and_then(Value::as_u64).unwrap_or(7891) as u16;
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
    let mut upload_total = 0;
    let mut download_total = 0;

    if let Ok((200, conn_body)) =
        http_request(&cfg.addr, &cfg.secret, "GET", "/connections", None, timeout)
    {
        if let Ok(v) = serde_json::from_str::<Value>(&conn_body) {
            upload_total = v.get("uploadTotal").and_then(Value::as_u64).unwrap_or(0);
            download_total = v.get("downloadTotal").and_then(Value::as_u64).unwrap_or(0);
            if let Some(arr) = v.get("connections").and_then(Value::as_array) {
                for c in arr {
                    let id = c
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let meta = c.get("metadata");
                    let host_str = meta
                        .and_then(|m| m.get("host"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let dst_ip = meta
                        .and_then(|m| m.get("destinationIP"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let dst_port = meta
                        .and_then(|m| m.get("destinationPort"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let target = if !host_str.is_empty() {
                        format!("{host_str}:{dst_port}")
                    } else {
                        format!("{dst_ip}:{dst_port}")
                    };
                    let network = meta
                        .and_then(|m| m.get("network"))
                        .and_then(Value::as_str)
                        .unwrap_or("tcp")
                        .to_uppercase();
                    let rule = c
                        .get("rule")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    let chains = c
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
                    let upload = c.get("upload").and_then(Value::as_u64).unwrap_or(0);
                    let download = c.get("download").and_then(Value::as_u64).unwrap_or(0);
                    if let Some(mut item) = connection_from_value(c) {
                        item.id = id;
                        item.host = target;
                        item.network = network;
                        item.rule = rule;
                        item.chains = chains;
                        item.upload = upload;
                        item.download = download;
                        connections.push(item);
                    }
                }
                connections.sort_by(|a, b| (b.download + b.upload).cmp(&(a.download + a.upload)));
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
        sysproxy_enabled,
        network_service: net_service,
        groups,
        nodes,
        connections,
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
        start: value
            .get("start")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        dns_mode: text("dnsMode"),
        dest_geo: geo("destinationGeoIP"),
        dest_asn: text("destinationIPASN"),
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
    thread::spawn(move || {
        let mut handles = Vec::new();
        let chunk_size = 8;
        for chunk in nodes.chunks(chunk_size) {
            for node in chunk.iter().cloned() {
                if is_info_pseudo_node(&node) {
                    continue;
                }
                let cfg_clone = cfg.clone();
                let group_clone = group_name.clone();
                let tx_clone = tx.clone();
                handles.push(thread::spawn(move || {
                    let path = format!(
                        "/proxies/{}/delay?url={}&timeout={}",
                        percent_encode(&node),
                        percent_encode(&cfg_clone.test_url),
                        cfg_clone.timeout_ms
                    );
                    let delay = http_request(
                        &cfg_clone.addr,
                        &cfg_clone.secret,
                        "GET",
                        &path,
                        None,
                        Duration::from_millis(cfg_clone.timeout_ms + 500),
                    )
                    .ok()
                    .and_then(|(status, body)| {
                        if status == 200 {
                            serde_json::from_str::<Value>(&body)
                                .ok()
                                .and_then(|v| v.get("delay").and_then(Value::as_u64))
                                .and_then(|d| if d > 0 { Some(d as u16) } else { None })
                        } else {
                            None
                        }
                    });
                    let _ = tx_clone.send(BackendEvent::DelayResult {
                        group: group_clone,
                        node,
                        delay,
                    });
                }));
            }
            for h in handles.drain(..) {
                let _ = h.join();
            }
        }
        let _ = tx.send(BackendEvent::GroupTestDone { group: group_name });
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

pub fn start_core_service(cfg: &ControllerConfig) -> Result<String, String> {
    let Some(bin) = discover_mihomo_binary() else {
        return Err("mihomo binary not found · Settings › Download Managed Core".to_string());
    };

    let config_file = Path::new(&cfg.config_dir).join("config.yaml");
    if !config_file.exists() {
        return Err(format!(
            "config not found: {} · add a subscription first (u)",
            config_file.display()
        ));
    }

    let child = Command::new(&bin)
        .arg("-d")
        .arg(&cfg.config_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("failed to start mihomo: {e}"))?;

    let _ = child.id();
    thread::sleep(Duration::from_millis(350));
    Ok(format!("Started mihomo ({})", bin.display()))
}

pub fn stop_core_service(cfg: &ControllerConfig) -> Result<String, String> {
    let (_, enabled) = detect_macos_sysproxy();
    if enabled {
        let _ = set_macos_sysproxy(false, 7890, 7891);
    }
    let _ = Command::new("/opt/homebrew/bin/brew")
        .args(["services", "stop", "mihomo"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("pkill")
        .args(["-f", &format!("mihomo -d {}", cfg.config_dir)])
        .status();
    let _ = Command::new("pkill").args(["-x", "mihomo"]).status();
    thread::sleep(Duration::from_millis(250));
    Ok("Stopped mihomo & restored system proxy".to_string())
}

pub fn update_subscription_async(cfg: ControllerConfig, tx: Sender<BackendEvent>) {
    thread::spawn(move || {
        let result = fetch_subscription(&cfg, &tx);
        let ok = result.is_ok();
        let (text, is_error) = match result {
            Ok(text) => (text, false),
            Err(text) => (text, true),
        };
        let _ = tx.send(BackendEvent::StatusMessage { text, is_error });
        let _ = tx.send(BackendEvent::SubscriptionDone { ok });
    });
}

fn fetch_subscription(cfg: &ControllerConfig, tx: &Sender<BackendEvent>) -> Result<String, String> {
    if cfg.subscription_url.trim().is_empty() {
        return Err("Subscription URL is empty".to_string());
    }
    let _ = tx.send(BackendEvent::StatusMessage {
        text: "Fetching subscription...".to_string(),
        is_error: false,
    });

    fs::create_dir_all(&cfg.config_dir)
        .map_err(|e| format!("Cannot create {}: {e}", cfg.config_dir))?;
    let tmp_path = Path::new(&cfg.config_dir).join("config.yaml.tmp");
    let final_path = Path::new(&cfg.config_dir).join("config.yaml");

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
            "-o",
        ])
        .arg(&tmp_path)
        .stdin(Stdio::null())
        .output();

    let raw = match output {
        Ok(out) if out.status.success() => fs::read_to_string(&tmp_path).unwrap_or_default(),
        _ => {
            let _ = fs::remove_file(&tmp_path);
            return Err("Failed to download subscription".to_string());
        }
    };
    let _ = fs::remove_file(&tmp_path);
    if !raw.contains("proxies:") {
        return Err("Subscription is not a Clash/Mihomo YAML (missing proxies:)".to_string());
    }

    fs::write(&final_path, normalize_subscription(&raw, &cfg.addr))
        .map_err(|e| format!("Cannot write {}: {e}", final_path.display()))?;

    let body = serde_json::json!({
        "path": final_path.display().to_string(),
        "payload": ""
    })
    .to_string();
    let reloaded = matches!(
        http_request(
            &cfg.addr,
            &cfg.secret,
            "PUT",
            "/configs?force=true",
            Some(&body),
            Duration::from_millis(2500),
        ),
        Ok((code, _)) if (200..300).contains(&code)
    );
    if reloaded {
        let snap = fetch_snapshot(cfg);
        let _ = tx.send(BackendEvent::Snapshot(Box::new(snap)));
        Ok("Subscription updated & hot-reloaded".to_string())
    } else {
        Ok(format!("Subscription saved to {}", final_path.display()))
    }
}

pub fn download_managed_core_async(tx: Sender<BackendEvent>) {
    thread::spawn(move || {
        let Some(home) = std::env::var_os("HOME") else {
            return;
        };
        let core_dir = PathBuf::from(home).join(".config/terc/core");
        let _ = fs::create_dir_all(&core_dir);
        let bin_path = core_dir.join("mihomo");
        let gz_path = core_dir.join("mihomo.gz");

        let _ = tx.send(BackendEvent::StatusMessage {
            text: "Checking latest mihomo darwin-arm64 release...".to_string(),
            is_error: false,
        });

        let script = format!(
            r#"URL=$(curl -fsSL https://api.github.com/repos/MetaCubeX/mihomo/releases/latest | grep -o 'https://[^"]*mihomo-darwin-arm64-v[^"]*\.gz' | head -n 1); \
            if [ -n "$URL" ]; then curl -fsSL "$URL" -o "{}" && gunzip -f "{}" && chmod +x "{}"; else exit 1; fi"#,
            gz_path.display(),
            gz_path.display(),
            bin_path.display()
        );

        let ok = matches!(
            Command::new("sh")
                .arg("-c")
                .arg(&script)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status(),
            Ok(st) if st.success()
        );
        let text = if ok {
            format!("Managed core installed to {}", bin_path.display())
        } else {
            "Failed to download mihomo from GitHub".to_string()
        };
        let _ = tx.send(BackendEvent::StatusMessage {
            text,
            is_error: !ok,
        });
        let _ = tx.send(BackendEvent::CoreDownloadDone { ok });
    });
}

pub fn detect_macos_sysproxy() -> (String, bool) {
    let service = active_macos_network_service().unwrap_or_else(|| "Wi-Fi".to_string());
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

fn active_macos_network_service() -> Option<String> {
    let out = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for candidate in [
        "Wi-Fi",
        "USB 10/100/1000 LAN",
        "Thunderbolt Ethernet",
        "Ethernet",
    ] {
        if text.lines().any(|l| l.trim() == candidate) {
            return Some(candidate.to_string());
        }
    }
    text.lines()
        .skip(1)
        .map(str::trim)
        .find(|l| !l.is_empty() && !l.starts_with('*'))
        .map(String::from)
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

pub fn set_tun_enabled(cfg: &ControllerConfig, enable: bool) -> io::Result<()> {
    patch_configs(cfg, &tun_patch_body(enable))
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

pub fn reload_config(cfg: &ControllerConfig) -> Result<(), String> {
    let path = config_yaml_path(cfg);
    let body = serde_json::json!({
        "path": path.display().to_string(),
        "payload": ""
    })
    .to_string();
    match http_request(
        &cfg.addr,
        &cfg.secret,
        "PUT",
        "/configs?force=true",
        Some(&body),
        Duration::from_millis(2500),
    ) {
        Ok((status, _)) if (200..300).contains(&status) => Ok(()),
        Ok((status, text)) => Err(format!("reload HTTP {status} {}", brief(&text))),
        Err(err) => Err(err.to_string()),
    }
}

pub fn reload_config_async(cfg: ControllerConfig, tx: Sender<BackendEvent>) {
    thread::spawn(move || {
        let result = reload_config(&cfg);
        let ok = result.is_ok();
        let text = match result {
            Ok(()) => "config reloaded".to_string(),
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

pub fn persist_nested_bool(
    cfg: &ControllerConfig,
    path: &[&str],
    value: bool,
) -> Result<(), String> {
    let raw = read_config_text(cfg)?;
    let next = crate::ops::set_nested_bool(&raw, path, value);
    write_config_text(cfg, &next)
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
        Err(errors.join(" · "))
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
        Duration::from_millis(4000),
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
            Ok(()) => format!("provider updated · {name}"),
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
            text: format!("providers {ok} updated · {failed} failed"),
            is_error: ok == 0 && failed > 0,
        });
    });
}

pub fn test_node_delay(
    cfg: &ControllerConfig,
    node: &str,
    url: &str,
) -> Result<Option<u16>, String> {
    let path = format!(
        "/proxies/{}/delay?url={}&timeout={}",
        percent_encode(node),
        percent_encode(url),
        cfg.timeout_ms
    );
    match http_request(
        &cfg.addr,
        &cfg.secret,
        "GET",
        &path,
        None,
        Duration::from_millis(cfg.timeout_ms + 500),
    ) {
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
                        lines.push(format!("dns {qtype}  no answer · rcode {}", msg.status));
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

pub fn set_macos_sysproxy(enable: bool, http_port: u16, socks_port: u16) -> Result<String, String> {
    let (service, _) = detect_macos_sysproxy();
    let http_p = http_port.to_string();
    let socks_p = if socks_port > 0 {
        socks_port.to_string()
    } else {
        http_p.clone()
    };

    if enable {
        let _ = Command::new("networksetup")
            .args(["-setwebproxy", &service, "127.0.0.1", &http_p])
            .status();
        let _ = Command::new("networksetup")
            .args(["-setsecurewebproxy", &service, "127.0.0.1", &http_p])
            .status();
        let _ = Command::new("networksetup")
            .args(["-setsocksfirewallproxy", &service, "127.0.0.1", &socks_p])
            .status();
        Ok(format!("System Proxy ON ({service} -> 127.0.0.1:{http_p})"))
    } else {
        let _ = Command::new("networksetup")
            .args(["-setwebproxystate", &service, "off"])
            .status();
        let _ = Command::new("networksetup")
            .args(["-setsecurewebproxystate", &service, "off"])
            .status();
        let _ = Command::new("networksetup")
            .args(["-setsocksfirewallproxystate", &service, "off"])
            .status();
        Ok(format!("System Proxy OFF ({service})"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(out.starts_with("external-controller: 127.0.0.1:9090\nmixed-port: 7890"));
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
}
