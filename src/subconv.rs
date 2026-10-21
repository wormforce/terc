//! Subscription and single-node conversion into Mihomo proxy objects.
//!
//! Detects Clash/Mihomo YAML, Surge profiles (`[Proxy]`, `[Proxy Group]`,
//! `[Rule]`) and URI lists (plain or base64). Anything Mihomo cannot express is
//! skipped and counted; skip notes carry names and types only, never secrets.

use std::collections::{HashMap, HashSet};

use serde_json::{json, Map, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubFormat {
    ClashYaml,
    Surge,
    UriList,
}

impl SubFormat {
    pub fn label(self) -> &'static str {
        match self {
            SubFormat::ClashYaml => "Clash YAML",
            SubFormat::Surge => "Surge",
            SubFormat::UriList => "URI",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Converted {
    pub format: Option<SubFormat>,
    /// Proxies converted from Surge or URI lines (Clash YAML keeps its raw text).
    pub proxies: Vec<Value>,
    /// Surge proxy groups mapped to Mihomo groups.
    pub groups: Vec<Value>,
    /// Surge rules mapped to Mihomo rule strings, in order.
    pub rules: Vec<String>,
    pub rule_providers: Vec<(String, Value)>,
    pub skipped: Vec<String>,
    /// Original document when the subscription is already Clash/Mihomo YAML.
    pub clash_doc: Option<String>,
}

pub fn detect_format(raw: &str) -> Option<SubFormat> {
    let text = raw.trim_start_matches('\u{feff}');
    let has_section = text.lines().any(|l| {
        let t = l.trim().to_ascii_lowercase();
        matches!(
            t.as_str(),
            "[proxy]" | "[proxy group]" | "[rule]" | "[general]"
        )
    });
    if has_section {
        return Some(SubFormat::Surge);
    }
    if crate::ops::has_subscription_source(text) {
        return Some(SubFormat::ClashYaml);
    }
    if uri_lines(text).next().is_some() {
        return Some(SubFormat::UriList);
    }
    if let Some(decoded) = decode_base64_text(text) {
        if uri_lines(&decoded).next().is_some() {
            return Some(SubFormat::UriList);
        }
    }
    if text.lines().any(|l| surge_proxy_like(l.trim())) {
        return Some(SubFormat::Surge);
    }
    None
}

fn uri_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|l| {
        let lower = l.to_ascii_lowercase();
        URI_SCHEMES.iter().any(|s| lower.starts_with(s))
    })
}

const URI_SCHEMES: &[&str] = &[
    "ss://",
    "ssr://",
    "vmess://",
    "vless://",
    "trojan://",
    "hysteria2://",
    "hy2://",
    "hysteria://",
    "tuic://",
    "anytls://",
    "socks5://",
    "socks://",
    "wireguard://",
    "wg://",
    "ssh://",
];

/// For Surge url-test / smart groups that set none. Mihomo's default is 0,
/// which moves new connections (and the exit IP) to whichever node won the
/// last health check by any margin.
const URL_TEST_TOLERANCE: u64 = 50;

/// For TUIC nodes that name no congestion controller. Mihomo matches no case
/// on an empty value, so quic-go keeps NewReno, which backs off hard on lossy
/// long-haul UDP. This only affects client-to-server sending.
const TUIC_CONGESTION: &str = "bbr";

const SURGE_PROXY_TYPES: &[&str] = &[
    "ss",
    "shadowsocks",
    "trojan",
    "vmess",
    "http",
    "https",
    "socks5",
    "socks5-tls",
    "snell",
    "hysteria2",
    "tuic",
    "tuic-v5",
    "anytls",
    "wireguard",
    "direct",
    "reject",
    "reject-tinygif",
    "reject-drop",
    "external",
    "ssh",
];

fn surge_proxy_like(line: &str) -> bool {
    let Some((_, rest)) = line.split_once('=') else {
        return false;
    };
    let kind = rest
        .split(',')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    SURGE_PROXY_TYPES.contains(&kind.as_str()) && rest.contains(',')
}

/// Convert a downloaded subscription body. Never panics on bad input.
pub fn convert_subscription(raw: &str) -> Result<Converted, String> {
    let text = raw.trim_start_matches('\u{feff}');
    match detect_format(text) {
        Some(SubFormat::ClashYaml) => Ok(Converted {
            format: Some(SubFormat::ClashYaml),
            clash_doc: Some(text.to_string()),
            ..Converted::default()
        }),
        Some(SubFormat::Surge) => Ok(convert_surge(text)),
        Some(SubFormat::UriList) => {
            let decoded;
            let body = if uri_lines(text).next().is_some() {
                text
            } else {
                decoded = decode_base64_text(text).unwrap_or_default();
                decoded.as_str()
            };
            let mut out = Converted {
                format: Some(SubFormat::UriList),
                ..Converted::default()
            };
            let mut names = HashSet::new();
            for line in uri_lines(body) {
                match parse_uri(line) {
                    Ok(mut node) => {
                        unique_name(&mut node, &mut names);
                        out.proxies.push(node);
                    }
                    Err(reason) => out.skipped.push(reason),
                }
            }
            Ok(out)
        }
        None => Err(
            "无法识别订阅格式（需要 Clash YAML、Surge 或节点链接）/ Unrecognized subscription format"
                .into(),
        ),
    }
}

/// Parse one user-pasted node: a Surge `Name = type, ...` line or a URI.
pub fn parse_node_line(line: &str) -> Result<Value, String> {
    let line = line.trim().trim_start_matches('\u{feff}');
    if line.starts_with('{') {
        let mut value: Value = serde_json::from_str(line).map_err(|e| e.to_string())?;
        if value["name"].as_str().is_none()
            || value["type"].as_str().is_none()
            || value["server"].as_str().is_none()
            || value["port"]
                .as_u64()
                .filter(|p| (1..=65535).contains(p))
                .is_none()
        {
            return Err("节点缺少名称、类型、服务器或有效端口 / Incomplete proxy".into());
        }
        normalize_ws_network(&mut value);
        return Ok(value);
    }

    if line.is_empty() {
        return Err("空行 / empty line".into());
    }
    let lower = line.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        if let Ok(node) = parse_uri(line) {
            return Ok(node);
        }
    }
    if line.contains("://") && !line.contains(" = ") {
        return parse_uri(line);
    }
    let Some((name, rest)) = line.split_once('=') else {
        return Err("需要 Surge 节点行或节点链接 / expected a Surge line or URI".into());
    };
    let mut alias = HashMap::new();
    match parse_surge_proxy(name.trim(), rest, &mut alias, &SurgeCtx::default())? {
        Some(node) => Ok(node),
        None => Err("DIRECT / REJECT 不是节点 / not a node".into()),
    }
}

fn unique_name(node: &mut Value, names: &mut HashSet<String>) {
    let base = node["name"].as_str().unwrap_or("node").to_string();
    let mut name = base.clone();
    let mut n = 2;
    while names.contains(&name) {
        name = format!("{base} {n}");
        n += 1;
    }
    names.insert(name.clone());
    node["name"] = Value::String(name);
}

// ---------------------------------------------------------------- Surge

fn convert_surge(text: &str) -> Converted {
    let mut out = Converted {
        format: Some(SubFormat::Surge),
        ..Converted::default()
    };
    let mut section = String::new();
    let mut proxy_lines = Vec::new();
    let mut group_lines = Vec::new();
    let mut rule_lines = Vec::new();
    let mut ctx = SurgeCtx::default();
    let mut wg_section: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with(';')
            || line.starts_with("//")
        {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let header = line[1..line.len() - 1].trim();
            section = header.to_ascii_lowercase();
            wg_section = section
                .strip_prefix("wireguard ")
                .map(|_| header["wireguard ".len()..].trim().to_string());
            if let Some(name) = &wg_section {
                ctx.wireguard.entry(name.clone()).or_default();
            }
            continue;
        }
        if let Some(wg) = &wg_section {
            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim().to_ascii_lowercase();
                let entry = ctx.wireguard.entry(wg.clone()).or_default();
                if key == "peer" {
                    entry.peers.extend(split_params(v.trim()));
                } else {
                    entry.kv.insert(key, unquote(v.trim()));
                }
            }
            continue;
        }
        match section.as_str() {
            "proxy" => proxy_lines.push(line.to_string()),
            "proxy group" => group_lines.push(line.to_string()),
            "rule" => rule_lines.push(line.to_string()),
            "keystore" => {
                if let Some((k, v)) = line.split_once('=') {
                    ctx.keystore.insert(unquote(k.trim()), v.trim().to_string());
                }
            }
            // Section-less Surge proxy lists (policy-path style).
            "" if surge_proxy_like(line) => proxy_lines.push(line.to_string()),
            _ => {}
        }
    }

    // Policy names that resolve to built-ins (e.g. `On = direct`).
    let mut alias: HashMap<String, String> = HashMap::new();
    let mut names = HashSet::new();
    for line in &proxy_lines {
        let Some((name, rest)) = line.split_once('=') else {
            out.skipped.push("Proxy: malformed line".into());
            continue;
        };
        let name = unquote(name.trim());
        match parse_surge_proxy(&name, rest, &mut alias, &ctx) {
            Ok(Some(mut node)) => {
                unique_name(&mut node, &mut names);
                out.proxies.push(node);
            }
            Ok(None) => {}
            Err(reason) => out.skipped.push(reason),
        }
    }

    // Groups: first collect, then resolve members once all names are known.
    struct RawGroup {
        name: String,
        kind: String,
        members: Vec<String>,
        params: HashMap<String, String>,
    }
    let mut raw_groups = Vec::new();
    for line in &group_lines {
        let Some((name, rest)) = line.split_once('=') else {
            out.skipped.push("Proxy Group: malformed line".into());
            continue;
        };
        let name = unquote(name.trim());
        let parts = split_params(rest);
        let Some(kind) = parts.first().map(|k| k.to_ascii_lowercase()) else {
            continue;
        };
        let mut members = Vec::new();
        let mut params = HashMap::new();
        for part in parts.iter().skip(1) {
            match part.split_once('=') {
                Some((k, v)) if is_param_key(k) => {
                    params.insert(k.trim().to_ascii_lowercase(), unquote(v.trim()));
                }
                _ => members.push(unquote(part)),
            }
        }
        let mapped = match kind.as_str() {
            "select" | "url-test" | "fallback" | "load-balance" => kind.clone(),
            "smart" => "url-test".into(),
            other => {
                out.skipped.push(format!("Proxy Group {name} = {other}"));
                continue;
            }
        };
        raw_groups.push(RawGroup {
            name,
            kind: mapped,
            members,
            params,
        });
    }
    let group_names: HashSet<String> = raw_groups.iter().map(|g| g.name.clone()).collect();
    let proxy_names: HashSet<String> = out
        .proxies
        .iter()
        .filter_map(|p| p["name"].as_str().map(str::to_string))
        .collect();
    let resolve = |name: &str| -> Option<String> {
        let upper = name.to_ascii_uppercase();
        match upper.as_str() {
            "DIRECT" => return Some("DIRECT".into()),
            "REJECT" | "REJECT-TINYGIF" | "REJECT-NO-DROP" => return Some("REJECT".into()),
            "REJECT-DROP" => return Some("REJECT-DROP".into()),
            _ => {}
        }
        if let Some(target) = alias.get(name) {
            return Some(target.clone());
        }
        if proxy_names.contains(name) || group_names.contains(name) {
            return Some(name.to_string());
        }
        None
    };
    for group in &raw_groups {
        let mut obj = Map::new();
        obj.insert("name".into(), json!(group.name));
        obj.insert("type".into(), json!(group.kind));
        let mut members = Vec::new();
        let mut dropped = 0;
        for m in &group.members {
            match resolve(m) {
                Some(r) if r != group.name && !members.contains(&r) => members.push(r),
                Some(_) => {}
                None => dropped += 1,
            }
        }
        if let Some(other) = group.params.get("include-other-group") {
            for m in split_params(other) {
                if let Some(r) = resolve(&m) {
                    if r != group.name && !members.contains(&r) {
                        members.push(r);
                    }
                }
            }
        }
        if dropped > 0 {
            out.skipped.push(format!(
                "Proxy Group {}: {dropped} unknown member(s)",
                group.name
            ));
        }
        let include_all = group
            .params
            .get("include-all-proxies")
            .is_some_and(|v| truthy(v));
        if include_all {
            obj.insert("include-all-proxies".into(), json!(true));
        }
        if let Some(filter) = group.params.get("policy-regex-filter") {
            obj.insert("filter".into(), json!(filter));
        }
        if group.params.contains_key("policy-path") {
            out.skipped
                .push(format!("Proxy Group {}: policy-path", group.name));
        }
        if members.is_empty() && !include_all {
            members.push("DIRECT".into());
        }
        if !members.is_empty() {
            obj.insert("proxies".into(), json!(members));
        }
        if group.kind != "select" {
            if let Some(url) = group.params.get("url") {
                obj.insert("url".into(), json!(url));
            }
            if let Some(v) = group
                .params
                .get("interval")
                .and_then(|v| v.parse::<u64>().ok())
            {
                obj.insert("interval".into(), json!(v));
            }
            let tolerance = group
                .params
                .get("tolerance")
                .and_then(|v| v.parse::<u64>().ok())
                .or((group.kind == "url-test").then_some(URL_TEST_TOLERANCE));
            if let Some(v) = tolerance {
                obj.insert("tolerance".into(), json!(v));
            }
            if let Some(v) = group
                .params
                .get("timeout")
                .and_then(|v| v.parse::<f64>().ok())
            {
                obj.insert("timeout".into(), json!((v * 1000.0) as u64));
            }
        }
        out.groups.push(Value::Object(obj));
    }

    for line in &rule_lines {
        match convert_surge_rule(line, &resolve, &out.rule_providers) {
            Ok((rule, provider)) => {
                if let Some(p) = provider {
                    out.rule_providers.push(p);
                }
                out.rules.push(rule);
            }
            Err(reason) => out.skipped.push(reason),
        }
    }
    out
}

fn is_param_key(key: &str) -> bool {
    let k = key.trim();
    !k.is_empty()
        && !k.contains(' ')
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

fn truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on"
    )
}

fn unquote(s: &str) -> String {
    let t = s.trim();
    if t.len() >= 2 && t.starts_with('"') && t.ends_with('"') {
        t[1..t.len() - 1].to_string()
    } else {
        t.to_string()
    }
}

/// Split on commas outside double quotes and parentheses.
fn split_params(s: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut depth = 0i32;
    for c in s.chars() {
        match c {
            '"' => {
                quoted = !quoted;
                cur.push(c);
            }
            '(' if !quoted => {
                depth += 1;
                cur.push(c);
            }
            ')' if !quoted => {
                depth -= 1;
                cur.push(c);
            }
            ',' if !quoted && depth <= 0 => {
                parts.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur.trim().to_string());
    }
    parts
}

const SS_CIPHERS: &[&str] = &[
    "none",
    "plain",
    "rc4-md5",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20",
    "chacha20-ietf",
    "xchacha20",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "chacha8-ietf-poly1305",
    "xchacha8-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
];

fn check_ss(name: &str, cipher: &str, password: &str) -> Result<(), String> {
    if !SS_CIPHERS.contains(&cipher) {
        return Err(format!("{name}: ss cipher {cipher} unsupported"));
    }
    let need = match cipher {
        "2022-blake3-aes-128-gcm" => 16,
        "2022-blake3-aes-256-gcm" | "2022-blake3-chacha20-poly1305" => 32,
        _ => return Ok(()),
    };
    for key in password.split(':') {
        match decode_base64(key) {
            Some(bytes) if bytes.len() == need => {}
            _ => return Err(format!("{name}: ss 2022 key must be {need}-byte base64")),
        }
    }
    Ok(())
}

fn parse_port(name: &str, v: &str) -> Result<u16, String> {
    v.trim()
        .parse::<u16>()
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| format!("{name}: invalid port"))
}

/// Sections a Surge proxy line may reference: `[WireGuard <name>]` and
/// `[Keystore]` (SSH private keys).
#[derive(Debug, Default)]
struct SurgeCtx {
    wireguard: HashMap<String, WgSection>,
    keystore: HashMap<String, String>,
}

#[derive(Debug, Default)]
struct WgSection {
    kv: HashMap<String, String>,
    /// Raw `(public-key = ..., endpoint = ...)` groups, in order.
    peers: Vec<String>,
}

/// A WireGuard key as Mihomo wants it (standard base64 of 32 bytes). Surge also
/// accepts 64-character hex.
fn wg_key(raw: &str) -> Option<String> {
    let t = raw.trim();
    if t.len() == 64 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        let bytes: Vec<u8> = (0..32)
            .map(|i| u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).unwrap_or(0))
            .collect();
        return Some(encode_base64(&bytes));
    }
    decode_base64(t)
        .filter(|b| b.len() == 32)
        .map(|b| encode_base64(&b))
}

/// Surge `client-id` / URI `reserved`: `83/12/235`, `83,12,235`, 6 hex chars
/// or 4-char base64 — all three bytes.
fn wg_reserved(raw: &str) -> Option<Vec<u8>> {
    let t = raw.trim().trim_matches(|c| c == '[' || c == ']');
    if t.is_empty() {
        return None;
    }
    let sep = if t.contains('/') { '/' } else { ',' };
    if t.contains(sep) {
        let v: Option<Vec<u8>> = t.split(sep).map(|p| p.trim().parse::<u8>().ok()).collect();
        return v.filter(|v| v.len() == 3);
    }
    if t.len() == 6 && t.chars().all(|c| c.is_ascii_hexdigit()) {
        return (0..3)
            .map(|i| u8::from_str_radix(&t[i * 2..i * 2 + 2], 16).ok())
            .collect();
    }
    decode_base64(t).filter(|b| b.len() == 3)
}

/// `host:port`, `[v6]:port`.
fn split_endpoint(raw: &str) -> Option<(String, u16)> {
    let t = raw.trim();
    let (host, port) = if let Some(rest) = t.strip_prefix('[') {
        let (h, after) = rest.split_once(']')?;
        (h, after.strip_prefix(':')?)
    } else {
        t.rsplit_once(':')?
    };
    let port = port.trim().parse::<u16>().ok().filter(|p| *p > 0)?;
    (!host.trim().is_empty()).then(|| (host.trim().to_string(), port))
}

fn list_values(raw: &str) -> Vec<String> {
    unquote(raw)
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Fill a Mihomo `wireguard` proxy from a Surge `[WireGuard <section>]`.
fn surge_wireguard(
    name: &str,
    kv: &HashMap<String, String>,
    ctx: &SurgeCtx,
    node: &mut Map<String, Value>,
) -> Result<(), String> {
    let section_name = kv
        .get("section-name")
        .ok_or_else(|| format!("{name}: wireguard missing section-name"))?;
    let sec = ctx
        .wireguard
        .get(section_name.as_str())
        .ok_or_else(|| format!("{name}: wireguard section [WireGuard {section_name}] not found"))?;
    let private_key = sec
        .kv
        .get("private-key")
        .and_then(|k| wg_key(k))
        .ok_or_else(|| format!("{name}: wireguard private-key missing or invalid"))?;
    let mut peers = Vec::new();
    for raw in &sec.peers {
        let inner = raw.trim().trim_start_matches('(').trim_end_matches(')');
        let mut p: HashMap<String, String> = HashMap::new();
        for part in split_params(inner) {
            if let Some((k, v)) = part.split_once('=') {
                p.insert(k.trim().to_ascii_lowercase(), unquote(v.trim()));
            }
        }
        peers.push(p);
    }
    if peers.is_empty() {
        return Err(format!("{name}: wireguard section has no peer"));
    }
    let mut out_peers = Vec::new();
    let mut keepalive = None;
    for (i, p) in peers.iter().enumerate() {
        let public_key = p
            .get("public-key")
            .and_then(|k| wg_key(k))
            .ok_or_else(|| format!("{name}: wireguard peer {} public-key invalid", i + 1))?;
        let (server, port) = p
            .get("endpoint")
            .and_then(|e| split_endpoint(e))
            .ok_or_else(|| {
                format!(
                    "{name}: wireguard peer {} needs endpoint (listen-port unsupported)",
                    i + 1
                )
            })?;
        let mut peer = Map::new();
        peer.insert("server".into(), json!(server));
        peer.insert("port".into(), json!(port));
        peer.insert("public-key".into(), json!(public_key));
        if let Some(psk) = p.get("preshared-key").and_then(|k| wg_key(k)) {
            peer.insert("pre-shared-key".into(), json!(psk));
        }
        let allowed = p
            .get("allowed-ips")
            .map(|v| list_values(v))
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| vec!["0.0.0.0/0".into(), "::/0".into()]);
        peer.insert("allowed-ips".into(), json!(allowed));
        if let Some(id) = p.get("client-id") {
            let r = wg_reserved(id)
                .ok_or_else(|| format!("{name}: wireguard client-id must be 3 bytes"))?;
            peer.insert("reserved".into(), json!(r));
        }
        if keepalive.is_none() {
            keepalive = p.get("keepalive").and_then(|v| v.parse::<u64>().ok());
        }
        out_peers.push(peer);
    }
    node.insert("type".into(), json!("wireguard"));
    node.insert("private-key".into(), json!(private_key));
    let ip = sec.kv.get("self-ip").filter(|v| !v.is_empty());
    let ipv6 = sec.kv.get("self-ip-v6").filter(|v| !v.is_empty());
    if ip.is_none() && ipv6.is_none() {
        return Err(format!("{name}: wireguard needs self-ip or self-ip-v6"));
    }
    if let Some(v) = ip {
        node.insert("ip".into(), json!(v));
    }
    if let Some(v) = ipv6 {
        node.insert("ipv6".into(), json!(v));
    }
    if let Some(m) = sec.kv.get("mtu").and_then(|v| v.parse::<u64>().ok()) {
        node.insert("mtu".into(), json!(m));
    }
    if let Some(k) = keepalive {
        node.insert("persistent-keepalive".into(), json!(k));
    }
    let dns: Vec<String> = sec
        .kv
        .get("dns-server")
        .map(|v| list_values(v))
        .unwrap_or_default()
        .into_iter()
        .filter(|d| !d.eq_ignore_ascii_case("system"))
        .collect();
    if !dns.is_empty() {
        node.insert("remote-dns-resolve".into(), json!(true));
        node.insert("dns".into(), json!(dns));
    }
    node.insert("udp".into(), json!(true));
    let first = out_peers[0].clone();
    // Top-level server/port always mirror the first peer (summaries, tests).
    node.insert("server".into(), first["server"].clone());
    node.insert("port".into(), first["port"].clone());
    if out_peers.len() == 1 {
        for (k, v) in first {
            node.insert(k, v);
        }
    } else {
        node.insert("peers".into(), json!(out_peers));
    }
    Ok(())
}

/// Resolve a Surge `[Keystore]` item (`type=openssh-private-key, base64=...`)
/// to the PEM text Mihomo accepts inline.
fn keystore_private_key(name: &str, item: &str, ctx: &SurgeCtx) -> Result<String, String> {
    let raw = ctx
        .keystore
        .get(item)
        .ok_or_else(|| format!("{name}: ssh private-key needs [Keystore] item {item}"))?;
    let b64 = split_params(raw)
        .into_iter()
        .find_map(|p| {
            p.split_once('=')
                .filter(|(k, _)| k.trim().eq_ignore_ascii_case("base64"))
                .map(|(_, v)| unquote(v.trim()))
        })
        .ok_or_else(|| format!("{name}: ssh keystore item has no base64"))?;
    let pem = decode_base64(&b64)
        .and_then(|b| String::from_utf8(b).ok())
        .filter(|t| t.contains("PRIVATE KEY"))
        .ok_or_else(|| format!("{name}: ssh keystore item is not a private key"))?;
    Ok(pem)
}

/// Ok(None) means the line defines a built-in policy alias (direct/reject).
fn parse_surge_proxy(
    name: &str,
    rest: &str,
    alias: &mut HashMap<String, String>,
    ctx: &SurgeCtx,
) -> Result<Option<Value>, String> {
    let name = unquote(name);
    if name.is_empty() {
        return Err("Proxy: empty name".into());
    }
    let parts = split_params(rest);
    let kind = parts
        .first()
        .map(|k| k.to_ascii_lowercase())
        .unwrap_or_default();
    match kind.as_str() {
        "direct" => {
            alias.insert(name, "DIRECT".into());
            return Ok(None);
        }
        "reject" | "reject-tinygif" | "reject-no-drop" => {
            alias.insert(name, "REJECT".into());
            return Ok(None);
        }
        "reject-drop" => {
            alias.insert(name, "REJECT-DROP".into());
            return Ok(None);
        }
        _ => {}
    }
    const SUPPORTED: &[&str] = &[
        "ss",
        "shadowsocks",
        "trojan",
        "vmess",
        "http",
        "https",
        "socks5",
        "socks5-tls",
        "snell",
        "hysteria2",
        "tuic",
        "tuic-v5",
        "anytls",
        "wireguard",
        "ssh",
    ];
    if !SUPPORTED.contains(&kind.as_str()) {
        return Err(format!("{name} = {kind}"));
    }
    let mut positional = Vec::new();
    let mut kv: HashMap<String, String> = HashMap::new();
    for part in parts.iter().skip(1) {
        match part.split_once('=') {
            Some((k, v)) if is_param_key(k) => {
                kv.insert(k.trim().to_ascii_lowercase(), unquote(v.trim()));
            }
            _ => positional.push(unquote(part)),
        }
    }
    let flag = |k: &str| kv.get(k).map(|v| truthy(v));
    let mut node = Map::new();
    node.insert("name".into(), json!(name));
    if kind == "wireguard" {
        surge_wireguard(&name, &kv, ctx, &mut node)?;
    } else {
        let server = positional
            .first()
            .cloned()
            .ok_or_else(|| format!("{name}: missing server"))?;
        let port = parse_port(&name, positional.get(1).map(String::as_str).unwrap_or(""))?;
        node.insert("server".into(), json!(server));
        node.insert("port".into(), json!(port));
    }
    let sni = kv.get("sni").cloned();
    let skip_verify = flag("skip-cert-verify");
    let ws = |node: &mut Map<String, Value>| {
        if flag("ws") == Some(true) {
            node.insert("network".into(), json!("ws"));
            let mut opts = Map::new();
            opts.insert(
                "path".into(),
                json!(kv.get("ws-path").cloned().unwrap_or_else(|| "/".into())),
            );
            if let Some(h) = kv.get("ws-headers") {
                let mut headers = Map::new();
                for pair in h.split('|') {
                    if let Some((k, v)) = pair.split_once(':') {
                        headers.insert(k.trim().to_string(), json!(v.trim()));
                    }
                }
                if !headers.is_empty() {
                    opts.insert("headers".into(), Value::Object(headers));
                }
            }
            node.insert("ws-opts".into(), Value::Object(opts));
        }
    };
    match kind.as_str() {
        "ss" | "shadowsocks" => {
            let cipher = kv
                .get("encrypt-method")
                .cloned()
                .ok_or_else(|| format!("{name}: ss missing encrypt-method"))?;
            let password = kv.get("password").cloned().unwrap_or_default();
            check_ss(&name, &cipher, &password)?;
            node.insert("type".into(), json!("ss"));
            node.insert("cipher".into(), json!(cipher));
            node.insert("password".into(), json!(password));
            if let Some(mode) = kv.get("obfs") {
                let mut opts = Map::new();
                opts.insert("mode".into(), json!(mode));
                if let Some(host) = kv.get("obfs-host") {
                    opts.insert("host".into(), json!(host));
                }
                node.insert("plugin".into(), json!("obfs"));
                node.insert("plugin-opts".into(), Value::Object(opts));
            } else if let Some(pw) = kv.get("shadow-tls-password") {
                node.insert("plugin".into(), json!("shadow-tls"));
                let version = kv
                    .get("shadow-tls-version")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(3);
                node.insert(
                    "plugin-opts".into(),
                    json!({
                        "host": kv.get("shadow-tls-sni").cloned().unwrap_or_default(),
                        "password": pw,
                        "version": version,
                    }),
                );
            }
        }
        "trojan" => {
            node.insert("type".into(), json!("trojan"));
            node.insert(
                "password".into(),
                json!(kv.get("password").cloned().unwrap_or_default()),
            );
            if let Some(s) = &sni {
                node.insert("sni".into(), json!(s));
            }
            ws(&mut node);
        }
        "vmess" => {
            node.insert("type".into(), json!("vmess"));
            let uuid = kv
                .get("username")
                .cloned()
                .ok_or_else(|| format!("{name}: vmess missing username"))?;
            node.insert("uuid".into(), json!(uuid));
            node.insert("alterId".into(), json!(0));
            node.insert("cipher".into(), json!("auto"));
            if flag("tls") == Some(true) {
                node.insert("tls".into(), json!(true));
            }
            if let Some(s) = &sni {
                node.insert("servername".into(), json!(s));
            }
            ws(&mut node);
        }
        "http" | "https" | "socks5" | "socks5-tls" => {
            let mihomo_type = if kind.starts_with("http") {
                "http"
            } else {
                "socks5"
            };
            node.insert("type".into(), json!(mihomo_type));
            let user = kv
                .get("username")
                .cloned()
                .or_else(|| positional.get(2).cloned());
            let pass = kv
                .get("password")
                .cloned()
                .or_else(|| positional.get(3).cloned());
            if let Some(u) = user.filter(|u| !u.is_empty()) {
                node.insert("username".into(), json!(u));
            }
            if let Some(p) = pass.filter(|p| !p.is_empty()) {
                node.insert("password".into(), json!(p));
            }
            if kind == "https" || kind == "socks5-tls" {
                node.insert("tls".into(), json!(true));
                if let Some(s) = &sni {
                    let key = if mihomo_type == "http" {
                        "sni"
                    } else {
                        "servername"
                    };
                    node.insert(key.into(), json!(s));
                }
            }
        }
        "snell" => {
            let version = kv
                .get("version")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(1);
            // Mihomo ≥ 1.19.26 speaks v1–v5 (v5 = v4 wire, no QUIC proxy
            // mode); v6 is not implemented by Mihomo.
            if !(1..=5).contains(&version) {
                return Err(format!("{name}: snell v{version} unsupported by Mihomo"));
            }
            node.insert("type".into(), json!("snell"));
            node.insert(
                "psk".into(),
                json!(kv.get("psk").cloned().unwrap_or_default()),
            );
            node.insert("version".into(), json!(version));
            if version >= 4 && flag("reuse") == Some(true) {
                node.insert("reuse".into(), json!(true));
            }
            if let Some(pw) = kv.get("shadow-tls-password") {
                let v = kv
                    .get("shadow-tls-version")
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(3);
                node.insert(
                    "obfs-opts".into(),
                    json!({
                        "mode": "shadow-tls",
                        "host": kv.get("shadow-tls-sni").cloned().unwrap_or_default(),
                        "password": pw,
                        "version": v,
                    }),
                );
            } else if let Some(mode) = kv.get("obfs") {
                let mut opts = Map::new();
                opts.insert("mode".into(), json!(mode));
                if let Some(host) = kv.get("obfs-host") {
                    opts.insert("host".into(), json!(host));
                }
                node.insert("obfs-opts".into(), Value::Object(opts));
            }
        }
        "hysteria2" => {
            node.insert("type".into(), json!("hysteria2"));
            node.insert(
                "password".into(),
                json!(kv.get("password").cloned().unwrap_or_default()),
            );
            if let Some(s) = &sni {
                node.insert("sni".into(), json!(s));
            }
            if let Some(d) = kv.get("download-bandwidth") {
                node.insert("down".into(), json!(format!("{} Mbps", d.trim())));
            }
            if let Some(p) = kv.get("salamander-password") {
                node.insert("obfs".into(), json!("salamander"));
                node.insert("obfs-password".into(), json!(p));
            }
            if let Some(p) = kv.get("port-hopping") {
                node.insert("ports".into(), json!(p.replace(';', ",")));
            }
        }
        "tuic" | "tuic-v5" => {
            node.insert("type".into(), json!("tuic"));
            if kind == "tuic-v5" || kv.contains_key("uuid") {
                node.insert(
                    "uuid".into(),
                    json!(kv.get("uuid").cloned().unwrap_or_default()),
                );
                node.insert(
                    "password".into(),
                    json!(kv.get("password").cloned().unwrap_or_default()),
                );
            } else {
                node.insert(
                    "token".into(),
                    json!(kv.get("token").cloned().unwrap_or_default()),
                );
            }
            if let Some(s) = &sni {
                node.insert("sni".into(), json!(s));
            }
            if let Some(a) = kv.get("alpn") {
                node.insert("alpn".into(), json!([a]));
            }
            // Surge has no key for it; an empty value leaves quic-go on NewReno.
            let cc = kv
                .get("congestion-controller")
                .cloned()
                .unwrap_or_else(|| TUIC_CONGESTION.into());
            node.insert("congestion-controller".into(), json!(cc));
        }
        "anytls" => {
            node.insert("type".into(), json!("anytls"));
            node.insert(
                "password".into(),
                json!(kv.get("password").cloned().unwrap_or_default()),
            );
            if let Some(s) = &sni {
                node.insert("sni".into(), json!(s));
            }
        }
        "wireguard" => {}
        "ssh" => {
            node.insert("type".into(), json!("ssh"));
            let user = kv
                .get("username")
                .cloned()
                .or_else(|| positional.get(2).cloned())
                .filter(|u| !u.is_empty())
                .ok_or_else(|| format!("{name}: ssh missing username"))?;
            node.insert("username".into(), json!(user));
            let password = kv
                .get("password")
                .cloned()
                .or_else(|| positional.get(3).cloned())
                .filter(|p| !p.is_empty());
            let key = kv.get("private-key").filter(|k| !k.is_empty());
            if password.is_none() && key.is_none() {
                return Err(format!("{name}: ssh needs password or private-key"));
            }
            if let Some(p) = password {
                node.insert("password".into(), json!(p));
            }
            if let Some(item) = key {
                node.insert(
                    "private-key".into(),
                    json!(keystore_private_key(&name, item, ctx)?),
                );
            }
            if let Some(fp) = kv.get("server-fingerprint") {
                let keys = list_values(fp);
                if !keys.is_empty() {
                    node.insert("host-key".into(), json!(keys));
                }
            }
        }
        other => return Err(format!("{name} = {other}")),
    }
    if let Some(v) = flag("udp-relay") {
        node.insert("udp".into(), json!(v));
    }
    if let Some(v) = flag("tfo") {
        node.insert("tfo".into(), json!(v));
    }
    if let Some(v) = skip_verify {
        if !matches!(
            kind.as_str(),
            "ss" | "shadowsocks" | "snell" | "wireguard" | "ssh"
        ) {
            node.insert("skip-cert-verify".into(), json!(v));
        }
    }
    if let Some(v) = kv.get("server-cert-fingerprint-sha256") {
        node.insert("fingerprint".into(), json!(v));
    }
    if let Some(v) = kv.get("underlying-proxy") {
        node.insert("dialer-proxy".into(), json!(v));
    }
    Ok(Some(Value::Object(node)))
}

const RULE_PASS: &[&str] = &[
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "DOMAIN-REGEX",
    "IP-CIDR",
    "IP-CIDR6",
    "IP-ASN",
    "GEOIP",
    "GEOSITE",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "DST-PORT",
    "SRC-PORT",
    "IN-PORT",
    "SRC-IP-CIDR",
];

/// A provider is returned only for a list that `providers` does not hold yet.
fn convert_surge_rule(
    line: &str,
    resolve: &dyn Fn(&str) -> Option<String>,
    providers: &[(String, Value)],
) -> Result<(String, Option<(String, Value)>), String> {
    let parts = split_params(line);
    let kind = parts
        .first()
        .map(|k| k.to_ascii_uppercase())
        .unwrap_or_default();
    let unsupported = || format!("Rule {kind}");
    let policy_at = |i: usize| -> Result<String, String> {
        let raw = parts.get(i).ok_or_else(unsupported)?;
        resolve(&unquote(raw)).ok_or_else(|| format!("Rule {kind}: unknown policy"))
    };
    match kind.as_str() {
        "FINAL" | "MATCH" => Ok((format!("MATCH,{}", policy_at(1)?), None)),
        "AND" | "OR" | "NOT" => {
            let body = parts.get(1).ok_or_else(unsupported)?;
            let upper = body.to_ascii_uppercase();
            if [
                "USER-AGENT",
                "URL-REGEX",
                "RULE-SET",
                "DOMAIN-SET",
                "PROTOCOL",
                "SUBNET",
            ]
            .iter()
            .any(|k| upper.contains(k))
            {
                return Err(unsupported());
            }
            let compact: String = body
                .replace(", ", ",")
                .replace(" ,", ",")
                .replace("( ", "(")
                .replace(" )", ")");
            Ok((format!("{kind},{compact},{}", policy_at(2)?), None))
        }
        "RULE-SET" | "DOMAIN-SET" => {
            let url = parts.get(1).map(|u| unquote(u)).ok_or_else(unsupported)?;
            if !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(format!("Rule {kind},{url}"));
            }
            let policy = policy_at(2)?;
            let behavior = if kind == "DOMAIN-SET" {
                "domain"
            } else {
                "classical"
            };
            // No `path`: Mihomo then caches the list under a hash of its URL.
            // A path from the running index let a reordered rule list reuse
            // another list's cached file for up to `interval`. A repeated URL
            // shares one provider rather than two racing on the same file.
            let seen = providers
                .iter()
                .find(|(_, p)| p["url"] == url.as_str() && p["behavior"] == behavior);
            let (name, provider) = match seen {
                Some((name, _)) => (name.clone(), None),
                None => {
                    let name = format!("surge-{}", providers.len() + 1);
                    let provider = json!({
                        "type": "http",
                        "behavior": behavior,
                        "format": "text",
                        "url": url,
                        "interval": 86400,
                    });
                    (name.clone(), Some((name, provider)))
                }
            };
            let mut rule = format!("RULE-SET,{name},{policy}");
            if parts
                .iter()
                .skip(3)
                .any(|p| p.eq_ignore_ascii_case("no-resolve"))
            {
                rule.push_str(",no-resolve");
            }
            Ok((rule, provider))
        }
        _ => {
            let mapped = match kind.as_str() {
                "SRC-IP" => "SRC-IP-CIDR".to_string(),
                "PROTOCOL" => "NETWORK".to_string(),
                k if RULE_PASS.contains(&k) => k.to_string(),
                _ => return Err(unsupported()),
            };
            let value = parts.get(1).map(|v| unquote(v)).ok_or_else(unsupported)?;
            let value = if mapped == "NETWORK" {
                let v = value.to_ascii_lowercase();
                if v != "tcp" && v != "udp" {
                    return Err(unsupported());
                }
                v
            } else {
                value
            };
            let policy = policy_at(2)?;
            let mut rule = format!("{mapped},{value},{policy}");
            if parts
                .iter()
                .skip(3)
                .any(|p| p.eq_ignore_ascii_case("no-resolve"))
            {
                rule.push_str(",no-resolve");
            }
            Ok((rule, None))
        }
    }
}

// ---------------------------------------------------------------- URIs

struct Url {
    user: Option<String>,
    host: String,
    port: Option<u16>,
    query: Vec<(String, String)>,
    fragment: String,
}

impl Url {
    fn q(&self, key: &str) -> Option<String> {
        self.query
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
    }
    fn qflag(&self, key: &str) -> bool {
        self.q(key).is_some_and(|v| truthy(&v))
    }
}

fn parse_url(raw: &str) -> Option<Url> {
    let (scheme, rest) = raw.split_once("://")?;
    let (rest, fragment) = match rest.split_once('#') {
        Some((a, b)) => (a, percent_decode(b)),
        None => (rest, String::new()),
    };
    let (rest, query) = match rest.split_once('?') {
        Some((a, b)) => (a, b),
        None => (rest, ""),
    };
    let rest = rest.trim_end_matches('/');
    let (user, hostport) = match rest.rsplit_once('@') {
        Some((u, h)) => (Some(u.to_string()), h),
        None => (None, rest),
    };
    let hostport = hostport.split('/').next().unwrap_or(hostport);
    let (host, port) = if let Some(stripped) = hostport.strip_prefix('[') {
        let (h, after) = stripped.split_once(']')?;
        (
            h.to_string(),
            after.strip_prefix(':').and_then(|p| p.parse().ok()),
        )
    } else {
        match hostport.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()),
            None => (hostport.to_string(), None),
        }
    };
    let query = query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .collect();
    let _ = scheme;
    Some(Url {
        user,
        host,
        port,
        query,
        fragment,
    })
}

pub fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let hex = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 3 <= bytes.len() {
            if let (Some(h), Some(l)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(h << 4 | l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn uri_name(url: &Url, kind: &str) -> String {
    let name = url.fragment.trim();
    if name.is_empty() {
        format!("{kind} {}:{}", url.host, url.port.unwrap_or(0))
    } else {
        name.to_string()
    }
}

fn transport(node: &mut Map<String, Value>, url: &Url, name: &str) -> Result<(), String> {
    let net = url
        .q("type")
        .unwrap_or_else(|| "tcp".into())
        .to_ascii_lowercase();
    match net.as_str() {
        "tcp" | "none" | "" => {}
        "ws" | "httpupgrade" => ws_transport(
            node,
            net == "httpupgrade",
            url.q("path").unwrap_or_default(),
            url.q("host"),
            url.q("ed"),
            url.q("eh"),
            name,
        )?,
        "grpc" => {
            node.insert("network".into(), json!("grpc"));
            node.insert(
                "grpc-opts".into(),
                json!({ "grpc-service-name": url.q("serviceName").unwrap_or_default() }),
            );
        }
        other => return Err(format!("{name}: transport {other} unsupported")),
    }
    Ok(())
}

/// WebSocket or V2Ray HTTPUpgrade share-link transport. Mihomo has no
/// `network: httpupgrade`; it is `network: ws` plus `v2ray-http-upgrade`.
/// `ed` / `eh` are v2rayN's early-data size and header name.
fn ws_transport(
    node: &mut Map<String, Value>,
    upgrade: bool,
    path: String,
    host: Option<String>,
    ed: Option<String>,
    eh: Option<String>,
    name: &str,
) -> Result<(), String> {
    node.insert("network".into(), json!("ws"));
    let mut opts = Map::new();
    let path = if path.is_empty() { "/".into() } else { path };
    opts.insert("path".into(), json!(path));
    if let Some(h) = host.filter(|h| !h.is_empty()) {
        opts.insert("headers".into(), json!({ "Host": h }));
    }
    if upgrade {
        opts.insert("v2ray-http-upgrade".into(), json!(true));
    }
    if let Some(ed) = ed.filter(|e| !e.is_empty()) {
        let size: u64 = ed
            .parse()
            .map_err(|_| format!("{name}: WebSocket early data {ed} invalid"))?;
        if upgrade {
            opts.insert("v2ray-http-upgrade-fast-open".into(), json!(true));
        } else if size > 0 {
            opts.insert("max-early-data".into(), json!(size));
            opts.insert(
                "early-data-header-name".into(),
                json!("Sec-WebSocket-Protocol"),
            );
        }
    }
    if let Some(eh) = eh.filter(|h| !upgrade && !h.is_empty()) {
        opts.insert("early-data-header-name".into(), json!(eh));
    }
    node.insert("ws-opts".into(), Value::Object(opts));
    Ok(())
}

/// Split a numeric `ed=` early-data hint out of a vmess JSON WebSocket path.
fn split_path_ed(path: &str) -> (String, Option<String>) {
    let Some((base, query)) = path.split_once('?') else {
        return (path.to_string(), None);
    };
    let mut ed = None;
    let mut rest = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        match pair.strip_prefix("ed=") {
            Some(v) if ed.is_none() && v.parse::<u64>().is_ok() => ed = Some(v.to_string()),
            _ => rest.push(pair),
        }
    }
    match (ed, rest.is_empty()) {
        (None, _) => (path.to_string(), None),
        (ed, true) => (base.to_string(), ed),
        (ed, false) => (format!("{base}?{}", rest.join("&")), ed),
    }
}

/// Rewrite a Clash `network: httpupgrade` node to Mihomo's form, `network: ws`
/// plus `ws-opts.v2ray-http-upgrade: true`. Mihomo's vmess / vless / trojan
/// adapters have no httpupgrade case and silently dial plain TCP for an unknown
/// `network`. A non-standard `httpupgrade-opts {path, host}` is folded into
/// `ws-opts`. Returns whether anything changed; a second run changes nothing.
pub fn normalize_ws_network(node: &mut Value) -> bool {
    let upgrade = node["network"]
        .as_str()
        .is_some_and(|n| n.eq_ignore_ascii_case("httpupgrade"));
    let Some(node) = node.as_object_mut().filter(|_| upgrade) else {
        return false;
    };
    node.insert("network".into(), json!("ws"));
    let legacy = node.remove("httpupgrade-opts");
    let opts = node.entry("ws-opts").or_insert_with(|| json!({}));
    if !opts.is_object() {
        *opts = json!({});
    }
    let opts = opts.as_object_mut().unwrap();
    // `network: httpupgrade` means HTTPUpgrade, even next to an explicit false.
    opts.insert("v2ray-http-upgrade".into(), json!(true));
    let legacy = legacy.as_ref().and_then(Value::as_object);
    if let Some(path) = legacy.and_then(|l| l.get("path")).filter(|p| p.is_string()) {
        opts.entry("path").or_insert_with(|| path.clone());
    }
    if let Some(host) = legacy.and_then(|l| l.get("host")).filter(|h| h.is_string()) {
        let headers = opts.entry("headers").or_insert_with(|| json!({}));
        if let Some(headers) = headers.as_object_mut() {
            if !headers.keys().any(|k| k.eq_ignore_ascii_case("host")) {
                headers.insert("Host".into(), host.clone());
            }
        }
    }
    true
}

pub fn parse_uri(raw: &str) -> Result<Value, String> {
    let raw = raw.trim();
    let scheme = raw
        .split_once("://")
        .map(|(s, _)| s.to_ascii_lowercase())
        .unwrap_or_default();
    if scheme == "vmess" {
        return parse_vmess(raw);
    }
    if scheme == "ss" {
        return parse_ss_uri(raw);
    }
    let url = parse_url(raw).ok_or_else(|| format!("{scheme}:// malformed"))?;
    let port = url
        .port
        .ok_or_else(|| format!("{scheme}:// missing port"))?;
    if url.host.is_empty() {
        return Err(format!("{scheme}:// missing host"));
    }
    let user = url.user.as_deref().map(percent_decode).unwrap_or_default();
    let mut node = Map::new();
    let kind_label = match scheme.as_str() {
        "hy2" => "hysteria2",
        "socks" => "socks5",
        "wg" => "wireguard",
        s => s,
    };
    let name = uri_name(&url, kind_label);
    node.insert("name".into(), json!(name));
    node.insert("server".into(), json!(url.host));
    node.insert("port".into(), json!(port));
    let sni = url.q("sni").or_else(|| url.q("peer"));
    let insecure =
        url.qflag("allowInsecure") || url.qflag("insecure") || url.qflag("allow_insecure");
    match scheme.as_str() {
        "trojan" => {
            node.insert("type".into(), json!("trojan"));
            node.insert("password".into(), json!(user));
            if let Some(s) = sni {
                node.insert("sni".into(), json!(s));
            }
            if let Some(fp) = url.q("fp") {
                node.insert("client-fingerprint".into(), json!(fp));
            }
            transport(&mut node, &url, &name)?;
            node.insert("udp".into(), json!(true));
        }
        "vless" => {
            node.insert("type".into(), json!("vless"));
            node.insert("uuid".into(), json!(user));
            node.insert("udp".into(), json!(true));
            if let Some(flow) = url.q("flow") {
                node.insert("flow".into(), json!(flow));
            }
            let security = url.q("security").unwrap_or_default().to_ascii_lowercase();
            if security == "tls" || security == "reality" {
                node.insert("tls".into(), json!(true));
                if let Some(s) = sni {
                    node.insert("servername".into(), json!(s));
                }
                let fp = url.q("fp");
                if security == "reality" {
                    let mut opts = Map::new();
                    opts.insert(
                        "public-key".into(),
                        json!(url
                            .q("pbk")
                            .ok_or_else(|| format!("{name}: reality missing pbk"))?),
                    );
                    if let Some(sid) = url.q("sid") {
                        opts.insert("short-id".into(), json!(sid));
                    }
                    node.insert("reality-opts".into(), Value::Object(opts));
                    node.insert(
                        "client-fingerprint".into(),
                        json!(fp.unwrap_or_else(|| "chrome".into())),
                    );
                } else if let Some(fp) = fp {
                    node.insert("client-fingerprint".into(), json!(fp));
                }
            }
            transport(&mut node, &url, &name)?;
        }
        "hysteria2" | "hy2" => {
            node.insert("type".into(), json!("hysteria2"));
            node.insert("password".into(), json!(user));
            if let Some(s) = sni {
                node.insert("sni".into(), json!(s));
            }
            if let Some(o) = url.q("obfs") {
                node.insert("obfs".into(), json!(o));
                if let Some(p) = url.q("obfs-password") {
                    node.insert("obfs-password".into(), json!(p));
                }
            }
            if let Some(p) = url.q("mport") {
                node.insert("ports".into(), json!(p));
            }
        }
        "tuic" => {
            node.insert("type".into(), json!("tuic"));
            let (uuid, password) = user.split_once(':').unwrap_or((&user, ""));
            node.insert("uuid".into(), json!(uuid));
            node.insert("password".into(), json!(password));
            if let Some(s) = sni {
                node.insert("sni".into(), json!(s));
            }
            if let Some(a) = url.q("alpn") {
                let list: Vec<String> = a.split(',').map(|s| s.trim().to_string()).collect();
                node.insert("alpn".into(), json!(list));
            }
            let cc = url
                .q("congestion_control")
                .unwrap_or_else(|| TUIC_CONGESTION.into());
            node.insert("congestion-controller".into(), json!(cc));
            if let Some(m) = url.q("udp_relay_mode") {
                node.insert("udp-relay-mode".into(), json!(m));
            }
        }
        "anytls" => {
            node.insert("type".into(), json!("anytls"));
            node.insert("password".into(), json!(user));
            if let Some(s) = sni {
                node.insert("sni".into(), json!(s));
            }
        }
        "socks5" | "socks" | "http" | "https" => {
            let kind = if scheme.starts_with("http") {
                "http"
            } else {
                "socks5"
            };
            node.insert("type".into(), json!(kind));
            if !user.is_empty() {
                let (u, p) = user.split_once(':').unwrap_or((&user, ""));
                node.insert("username".into(), json!(u));
                if !p.is_empty() {
                    node.insert("password".into(), json!(p));
                }
            }
            if scheme == "https" {
                node.insert("tls".into(), json!(true));
            }
        }
        "wireguard" | "wg" => {
            node.insert("type".into(), json!("wireguard"));
            let key =
                wg_key(&user).ok_or_else(|| format!("{name}: wireguard private key invalid"))?;
            node.insert("private-key".into(), json!(key));
            let public = url
                .q("publickey")
                .or_else(|| url.q("public-key"))
                .or_else(|| url.q("peer_public_key"))
                .and_then(|k| wg_key(&k))
                .ok_or_else(|| format!("{name}: wireguard publickey missing or invalid"))?;
            node.insert("public-key".into(), json!(public));
            if let Some(psk) = url
                .q("presharedkey")
                .or_else(|| url.q("pre-shared-key"))
                .or_else(|| url.q("psk"))
                .and_then(|k| wg_key(&k))
            {
                node.insert("pre-shared-key".into(), json!(psk));
            }
            let addrs = url
                .q("address")
                .or_else(|| url.q("ip"))
                .or_else(|| url.q("local_address"))
                .map(|v| list_values(&v))
                .unwrap_or_default();
            for a in &addrs {
                let key = if a.contains(':') { "ipv6" } else { "ip" };
                node.entry(key).or_insert_with(|| json!(a));
            }
            if !node.contains_key("ip") && !node.contains_key("ipv6") {
                return Err(format!("{name}: wireguard address missing"));
            }
            if let Some(r) = url.q("reserved") {
                let r = wg_reserved(&r)
                    .ok_or_else(|| format!("{name}: wireguard reserved must be 3 bytes"))?;
                node.insert("reserved".into(), json!(r));
            }
            if let Some(m) = url.q("mtu").and_then(|v| v.parse::<u64>().ok()) {
                node.insert("mtu".into(), json!(m));
            }
            if let Some(k) = url
                .q("keepalive")
                .or_else(|| url.q("persistent-keepalive"))
                .and_then(|v| v.parse::<u64>().ok())
            {
                node.insert("persistent-keepalive".into(), json!(k));
            }
            let allowed = url
                .q("allowedips")
                .or_else(|| url.q("allowed-ips"))
                .map(|v| list_values(&v))
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| vec!["0.0.0.0/0".into(), "::/0".into()]);
            node.insert("allowed-ips".into(), json!(allowed));
            let dns = url.q("dns").map(|v| list_values(&v)).unwrap_or_default();
            if !dns.is_empty() {
                node.insert("remote-dns-resolve".into(), json!(true));
                node.insert("dns".into(), json!(dns));
            }
            node.insert("udp".into(), json!(true));
        }
        "ssh" => {
            node.insert("type".into(), json!("ssh"));
            let (u, p) = user.split_once(':').unwrap_or((&user, ""));
            if u.is_empty() || p.is_empty() {
                return Err(format!("{name}: ssh:// needs user:password@"));
            }
            node.insert("username".into(), json!(u));
            node.insert("password".into(), json!(p));
            if let Some(hk) = url.q("host-key").or_else(|| url.q("hostkey")) {
                node.insert("host-key".into(), json!(list_values(&hk)));
            }
        }
        other => return Err(format!("{other}://")),
    }
    if insecure {
        node.insert("skip-cert-verify".into(), json!(true));
    }
    Ok(Value::Object(node))
}

fn parse_ss_uri(raw: &str) -> Result<Value, String> {
    let body = &raw[5..];
    let (body, fragment) = match body.split_once('#') {
        Some((a, b)) => (a, percent_decode(b)),
        None => (body, String::new()),
    };
    let (body, query) = match body.split_once('?') {
        Some((a, b)) => (a.trim_end_matches('/'), b),
        None => (body.trim_end_matches('/'), ""),
    };
    let (userinfo, hostport) = if let Some((u, h)) = body.rsplit_once('@') {
        let decoded = percent_decode(u);
        let info = if decoded.contains(':') {
            decoded
        } else {
            decode_base64(&decoded)
                .and_then(|b| String::from_utf8(b).ok())
                .ok_or("ss:// userinfo is not base64")?
        };
        (info, h.to_string())
    } else {
        let decoded = decode_base64(body)
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or("ss:// malformed")?;
        let (u, h) = decoded.rsplit_once('@').ok_or("ss:// malformed")?;
        (u.to_string(), h.to_string())
    };
    let (cipher, password) = userinfo.split_once(':').ok_or("ss:// missing cipher")?;
    let url = parse_url(&format!("ss://x@{hostport}?{query}")).ok_or("ss:// malformed")?;
    let port = url.port.ok_or("ss:// missing port")?;
    let name = if fragment.trim().is_empty() {
        format!("ss {}:{port}", url.host)
    } else {
        fragment.trim().to_string()
    };
    let cipher = cipher.to_ascii_lowercase();
    check_ss(&name, &cipher, password)?;
    let mut node = Map::new();
    node.insert("name".into(), json!(name));
    node.insert("type".into(), json!("ss"));
    node.insert("server".into(), json!(url.host));
    node.insert("port".into(), json!(port));
    node.insert("cipher".into(), json!(cipher));
    node.insert("password".into(), json!(password));
    node.insert("udp".into(), json!(true));
    if let Some(plugin) = url.q("plugin") {
        let mut fields = plugin.split(';');
        let pname = fields.next().unwrap_or("");
        let mut opts: HashMap<String, String> = HashMap::new();
        let mut tls = false;
        for f in fields {
            match f.split_once('=') {
                Some((k, v)) => {
                    opts.insert(k.to_string(), v.to_string());
                }
                None if f == "tls" => tls = true,
                None => {}
            }
        }
        match pname {
            "obfs-local" | "simple-obfs" | "obfs" => {
                node.insert("plugin".into(), json!("obfs"));
                node.insert(
                    "plugin-opts".into(),
                    json!({
                        "mode": opts.get("obfs").cloned().unwrap_or_else(|| "http".into()),
                        "host": opts.get("obfs-host").cloned().unwrap_or_default(),
                    }),
                );
            }
            "v2ray-plugin" => {
                node.insert("plugin".into(), json!("v2ray-plugin"));
                node.insert(
                    "plugin-opts".into(),
                    json!({
                        "mode": opts.get("mode").cloned().unwrap_or_else(|| "websocket".into()),
                        "host": opts.get("host").cloned().unwrap_or_default(),
                        "path": opts.get("path").cloned().unwrap_or_else(|| "/".into()),
                        "tls": tls,
                    }),
                );
            }
            other => return Err(format!("{name}: ss plugin {other} unsupported")),
        }
    }
    Ok(Value::Object(node))
}

fn parse_vmess(raw: &str) -> Result<Value, String> {
    let body = raw[8..].split('#').next().unwrap_or("");
    let json_text = decode_base64(body)
        .and_then(|b| String::from_utf8(b).ok())
        .ok_or("vmess:// is not base64 JSON")?;
    let v: Value = serde_json::from_str(&json_text).map_err(|_| "vmess:// invalid JSON")?;
    let s = |k: &str| match &v[k] {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => String::new(),
    };
    let server = s("add");
    let port: u16 = s("port").parse().map_err(|_| "vmess:// invalid port")?;
    let name = if s("ps").trim().is_empty() {
        format!("vmess {server}:{port}")
    } else {
        s("ps").trim().to_string()
    };
    let mut node = Map::new();
    node.insert("name".into(), json!(name));
    node.insert("type".into(), json!("vmess"));
    node.insert("server".into(), json!(server));
    node.insert("port".into(), json!(port));
    node.insert("uuid".into(), json!(s("id")));
    node.insert(
        "alterId".into(),
        json!(s("aid").parse::<u64>().unwrap_or(0)),
    );
    let cipher = s("scy");
    node.insert(
        "cipher".into(),
        json!(if cipher.is_empty() {
            "auto".into()
        } else {
            cipher
        }),
    );
    node.insert("udp".into(), json!(true));
    if s("tls") == "tls" {
        node.insert("tls".into(), json!(true));
        let sni = if s("sni").is_empty() {
            s("host")
        } else {
            s("sni")
        };
        if !sni.is_empty() {
            node.insert("servername".into(), json!(sni));
        }
    }
    match s("net").as_str() {
        "" | "tcp" => {}
        net @ ("ws" | "httpupgrade") => {
            let (path, ed) = split_path_ed(&s("path"));
            ws_transport(
                &mut node,
                net == "httpupgrade",
                path,
                Some(s("host")),
                ed,
                None,
                &name,
            )?;
        }
        "grpc" => {
            node.insert("network".into(), json!("grpc"));
            node.insert(
                "grpc-opts".into(),
                json!({ "grpc-service-name": s("path") }),
            );
        }
        "h2" => {
            node.insert("network".into(), json!("h2"));
            node.insert(
                "h2-opts".into(),
                json!({ "host": [s("host")], "path": if s("path").is_empty() { "/".into() } else { s("path") } }),
            );
        }
        other => return Err(format!("{name}: vmess transport {other} unsupported")),
    }
    Ok(Value::Object(node))
}

// ---------------------------------------------------------------- base64

pub fn decode_base64(input: &str) -> Option<Vec<u8>> {
    let mut buf = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::new();
    let mut seen = 0;
    for c in input.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            b' ' | b'\n' | b'\r' | b'\t' => continue,
            _ => return None,
        };
        seen += 1;
        buf = (buf << 6) | v as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    if seen == 0 || seen % 4 == 1 {
        return None;
    }
    Some(out)
}

fn decode_base64_text(text: &str) -> Option<String> {
    let compact: String = text.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() < 8 {
        return None;
    }
    decode_base64(&compact).and_then(|b| String::from_utf8(b).ok())
}

pub fn encode_base64(input: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (b[0] as u32) << 16 | (b[1] as u32) << 8 | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// One-line summary safe for UI and logs: never includes secrets.
pub fn node_summary(node: &Value) -> String {
    format!(
        "{}  {}:{}",
        node["type"].as_str().unwrap_or("?"),
        node["server"].as_str().unwrap_or("?"),
        node["port"].as_u64().unwrap_or(0)
    )
}

fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Serialize a single-peer Mihomo `wireguard` node as a `wireguard://` line,
/// the one-line form nodes.conf stores. Multi-peer setups are refused.
pub fn wireguard_uri(node: &Value) -> Result<String, String> {
    let name = node["name"].as_str().unwrap_or("WireGuard");
    if node.get("peers").is_some() {
        return Err(format!(
            "{name}: 多 peer WireGuard 请放在订阅里 / multi-peer WireGuard: use a subscription"
        ));
    }
    let s = |k: &str| node[k].as_str().map(str::to_string);
    let server = s("server").ok_or_else(|| format!("{name}: no endpoint"))?;
    let host = if server.contains(':') {
        format!("[{server}]")
    } else {
        server
    };
    let mut q = vec![format!(
        "publickey={}",
        percent_encode(&s("public-key").unwrap_or_default())
    )];
    let addrs: Vec<String> = [s("ip"), s("ipv6")].into_iter().flatten().collect();
    q.push(format!("address={}", percent_encode(&addrs.join(","))));
    if let Some(psk) = s("pre-shared-key") {
        q.push(format!("presharedkey={}", percent_encode(&psk)));
    }
    if let Some(r) = node["reserved"].as_array() {
        let r: Vec<String> = r.iter().map(|b| b.to_string()).collect();
        q.push(format!("reserved={}", percent_encode(&r.join(","))));
    }
    if let Some(m) = node["mtu"].as_u64() {
        q.push(format!("mtu={m}"));
    }
    if let Some(k) = node["persistent-keepalive"].as_u64() {
        q.push(format!("keepalive={k}"));
    }
    if let Some(a) = node["allowed-ips"].as_array() {
        let a: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
        q.push(format!("allowedips={}", percent_encode(&a.join(","))));
    }
    if let Some(d) = node["dns"].as_array() {
        let d: Vec<&str> = d.iter().filter_map(Value::as_str).collect();
        q.push(format!("dns={}", percent_encode(&d.join(","))));
    }
    Ok(format!(
        "wireguard://{}@{}:{}?{}#{}",
        percent_encode(&s("private-key").unwrap_or_default()),
        host,
        node["port"].as_u64().unwrap_or(0),
        q.join("&"),
        percent_encode(name)
    ))
}

/// Parse a standard wg-quick `.conf` (`[Interface]` + `[Peer]`).
fn wg_quick_node(text: &str) -> Result<Value, String> {
    let mut section = String::new();
    let mut iface: HashMap<String, String> = HashMap::new();
    let mut peers: Vec<HashMap<String, String>> = Vec::new();
    for raw in text.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line[1..line.len() - 1].trim().to_ascii_lowercase();
            if section == "peer" {
                peers.push(HashMap::new());
            }
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim().to_ascii_lowercase(), v.trim().to_string());
        match section.as_str() {
            "interface" => {
                iface.insert(k, v);
            }
            "peer" => {
                if let Some(p) = peers.last_mut() {
                    p.insert(k, v);
                }
            }
            _ => {}
        }
    }
    if peers.len() != 1 {
        return Err(format!(
            "wg-quick: 需要正好一个 [Peer]，实际 {} / exactly one [Peer] expected",
            peers.len()
        ));
    }
    let peer = &peers[0];
    let (server, port) = peer
        .get("endpoint")
        .and_then(|e| split_endpoint(e))
        .ok_or("wg-quick: [Peer] Endpoint missing")?;
    let mut node = Map::new();
    node.insert("name".into(), json!(format!("WG {server}")));
    node.insert("type".into(), json!("wireguard"));
    node.insert("server".into(), json!(server));
    node.insert("port".into(), json!(port));
    node.insert(
        "private-key".into(),
        json!(iface
            .get("privatekey")
            .and_then(|k| wg_key(k))
            .ok_or("wg-quick: PrivateKey missing or invalid")?),
    );
    node.insert(
        "public-key".into(),
        json!(peer
            .get("publickey")
            .and_then(|k| wg_key(k))
            .ok_or("wg-quick: PublicKey missing or invalid")?),
    );
    if let Some(psk) = peer.get("presharedkey").and_then(|k| wg_key(k)) {
        node.insert("pre-shared-key".into(), json!(psk));
    }
    for a in iface
        .get("address")
        .map(|v| list_values(v))
        .unwrap_or_default()
    {
        let key = if a.contains(':') { "ipv6" } else { "ip" };
        node.entry(key).or_insert_with(|| json!(a));
    }
    if !node.contains_key("ip") && !node.contains_key("ipv6") {
        return Err("wg-quick: Address missing".into());
    }
    if let Some(m) = iface.get("mtu").and_then(|v| v.parse::<u64>().ok()) {
        node.insert("mtu".into(), json!(m));
    }
    if let Some(k) = peer
        .get("persistentkeepalive")
        .and_then(|v| v.parse::<u64>().ok())
    {
        node.insert("persistent-keepalive".into(), json!(k));
    }
    let allowed = peer
        .get("allowedips")
        .map(|v| list_values(v))
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| vec!["0.0.0.0/0".into(), "::/0".into()]);
    node.insert("allowed-ips".into(), json!(allowed));
    // DNS entries may also be search domains; keep IP literals only.
    let dns: Vec<String> = iface
        .get("dns")
        .map(|v| list_values(v))
        .unwrap_or_default()
        .into_iter()
        .filter(|d| d.parse::<std::net::IpAddr>().is_ok())
        .collect();
    if !dns.is_empty() {
        node.insert("remote-dns-resolve".into(), json!(true));
        node.insert("dns".into(), json!(dns));
    }
    node.insert("udp".into(), json!(true));
    Ok(Value::Object(node))
}

/// Multi-line pastes that describe nodes no single line can: a wg-quick
/// `.conf`, or a Surge WireGuard policy line plus its `[WireGuard x]` section.
/// Returns `None` when the text is not such a block (handle it line by line).
/// On success yields one-line node strings for nodes.conf.
pub fn block_to_node_lines(text: &str) -> Option<Result<Vec<String>, String>> {
    let lower = text.to_ascii_lowercase();
    if lower.contains("[interface]") && lower.contains("[peer]") {
        return Some(
            wg_quick_node(text)
                .and_then(|n| wireguard_uri(&n))
                .map(|l| vec![l]),
        );
    }
    if !lower.contains("[wireguard ") {
        return None;
    }
    let out = convert_surge(text);
    let lines: Result<Vec<String>, String> = out
        .proxies
        .iter()
        .filter(|p| p["type"] == "wireguard")
        .map(wireguard_uri)
        .collect();
    Some(match lines {
        Ok(v) if v.is_empty() => Err(out
            .skipped
            .first()
            .cloned()
            .unwrap_or_else(|| "没有找到 WireGuard 节点 / no WireGuard policy found".into())),
        other => other,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const SURGE: &str = r#"[General]
loglevel = notify

[Proxy]
On = direct
Block = reject-tinygif
🇺🇸 US-SS = ss, 192.0.2.1, 8388, encrypt-method=2022-blake3-aes-128-gcm, password=AAAAAAAAAAAAAAAAAAAAAA==, udp-relay=true, tfo=true
🇯🇵 JP-Trojan = trojan, jp.example.com, 443, password=fake, sni=jp.example.com, skip-cert-verify=true, ws=true, ws-path=/ws, ws-headers=Host:jp.example.com
SG-VMess = vmess, 192.0.2.3, 443, username=00000000-0000-0000-0000-000000000000, tls=true, sni=sg.example.com, vmess-aead=true
TW-HY2 = hysteria2, 192.0.2.4, 8443, password=fake, sni=tw.example.com, download-bandwidth=100
TUIC = tuic-v5, 192.0.2.5, 443, uuid=00000000-0000-0000-0000-000000000001, password=fake, alpn=h3, sni=t.example.com
HTTP = https, 192.0.2.6, 443, user, pass
SOCKS = socks5, 192.0.2.7, 1080
Obfs-SS = ss, 192.0.2.8, 8388, encrypt-method=aes-256-gcm, password=fake, obfs=http, obfs-host=example.com
WG = wireguard, section-name=Home
Snell5 = snell, 192.0.2.9, 443, psk=fake, version=5, reuse=true
Snell6 = snell, 192.0.2.9, 444, psk=fake, version=6

[Proxy Group]
Proxy = select, 🇺🇸 US-SS, 🇯🇵 JP-Trojan, Auto, WG, On
Auto = url-test, 🇺🇸 US-SS, SG-VMess, url=http://www.gstatic.com/generate_204, interval=600, tolerance=80, timeout=5
Fail = fallback, TW-HY2, TUIC
LB = load-balance, HTTP, SOCKS
Smart = smart, 🇺🇸 US-SS, include-other-group="Auto, Fail"
SSID = ssid, default=Proxy
Remote = select, policy-path=https://example.com/list.txt

[Rule]
DOMAIN-SUFFIX,openai.com,Proxy
DOMAIN,api.example.com,Auto,extended-matching
DOMAIN-KEYWORD,google,Proxy
IP-CIDR,192.0.2.0/24,On,no-resolve
IP-CIDR6,2001:db8::/32,Proxy
GEOIP,CN,DIRECT
PROCESS-NAME,Telegram,Proxy
USER-AGENT,Instagram*,Proxy
URL-REGEX,^http://example,REJECT
RULE-SET,https://example.com/ai.list,Proxy
DOMAIN-SET,https://example.com/ads.txt,Block
RULE-SET,SYSTEM,DIRECT
AND,((DOMAIN-SUFFIX,example.net), (DST-PORT,443)),Fail
PROTOCOL,UDP,Block
DOMAIN,missing.example,NoSuchPolicy
FINAL,Proxy,dns-failed
"#;

    fn by_name<'a>(list: &'a [Value], name: &str) -> &'a Value {
        list.iter()
            .find(|v| v["name"] == name)
            .unwrap_or_else(|| panic!("missing {name}"))
    }

    #[test]
    fn detects_formats() {
        assert_eq!(detect_format(SURGE), Some(SubFormat::Surge));
        assert_eq!(
            detect_format("proxies:\n  - {name: a, type: ss}\n"),
            Some(SubFormat::ClashYaml)
        );
        assert_eq!(
            detect_format("proxy-providers:\n  a: {}\n"),
            Some(SubFormat::ClashYaml)
        );
        assert_eq!(
            detect_format("trojan://p@192.0.2.1:443#a\n"),
            Some(SubFormat::UriList)
        );
        let b64 = encode_base64(b"trojan://p@192.0.2.1:443#a\nvless://u@192.0.2.2:443#b\n");
        assert_eq!(detect_format(&b64), Some(SubFormat::UriList));
        assert_eq!(
            detect_format("A = ss, 192.0.2.1, 1, encrypt-method=aes-128-gcm, password=x\n"),
            Some(SubFormat::Surge)
        );
        assert_eq!(detect_format("<html>nope</html>"), None);
        assert!(convert_subscription("<html>nope</html>").is_err());
        assert!(convert_subscription("").is_err());
    }

    #[test]
    fn surge_proxies_map_to_mihomo() {
        let out = convert_subscription(SURGE).unwrap();
        let ss = by_name(&out.proxies, "🇺🇸 US-SS");
        assert_eq!(ss["type"], "ss");
        assert_eq!(ss["cipher"], "2022-blake3-aes-128-gcm");
        assert_eq!(ss["udp"], true);
        assert_eq!(ss["tfo"], true);
        assert_eq!(ss["port"], 8388);
        let tj = by_name(&out.proxies, "🇯🇵 JP-Trojan");
        assert_eq!(tj["network"], "ws");
        assert_eq!(tj["ws-opts"]["headers"]["Host"], "jp.example.com");
        assert_eq!(tj["skip-cert-verify"], true);
        let vm = by_name(&out.proxies, "SG-VMess");
        assert_eq!(vm["uuid"], "00000000-0000-0000-0000-000000000000");
        assert_eq!(vm["servername"], "sg.example.com");
        assert_eq!(by_name(&out.proxies, "TW-HY2")["down"], "100 Mbps");
        assert_eq!(by_name(&out.proxies, "TUIC")["alpn"][0], "h3");
        let http = by_name(&out.proxies, "HTTP");
        assert_eq!(http["tls"], true);
        assert_eq!(http["username"], "user");
        assert_eq!(by_name(&out.proxies, "SOCKS")["type"], "socks5");
        assert_eq!(
            by_name(&out.proxies, "Obfs-SS")["plugin-opts"]["mode"],
            "http"
        );
        let snell = by_name(&out.proxies, "Snell5");
        assert_eq!(snell["version"], 5);
        assert_eq!(snell["reuse"], true);
        assert_eq!(out.proxies.len(), 9);
        // WG references a section that does not exist; Snell v6 has no Mihomo support.
        assert!(out.skipped.iter().any(|s| s.contains("wireguard section")));
        assert!(out.skipped.iter().any(|s| s.contains("snell v6")));
        // Skip notes never echo secrets.
        assert!(out.skipped.iter().all(|s| !s.contains("fake")));
    }

    #[test]
    fn surge_groups_and_rules_map_where_possible() {
        let out = convert_subscription(SURGE).unwrap();
        let proxy = by_name(&out.groups, "Proxy");
        assert_eq!(proxy["type"], "select");
        assert_eq!(
            proxy["proxies"],
            json!(["🇺🇸 US-SS", "🇯🇵 JP-Trojan", "Auto", "DIRECT"])
        );
        let auto = by_name(&out.groups, "Auto");
        assert_eq!(auto["interval"], 600);
        assert_eq!(auto["timeout"], 5000);
        assert_eq!(auto["tolerance"], 80);
        // url-test and smart without one get a tolerance; other kinds never do.
        assert_eq!(by_name(&out.groups, "Smart")["tolerance"], 50);
        assert!(by_name(&out.groups, "Fail").get("tolerance").is_none());
        assert!(by_name(&out.groups, "LB").get("tolerance").is_none());
        assert_eq!(by_name(&out.groups, "Fail")["type"], "fallback");
        assert_eq!(by_name(&out.groups, "LB")["type"], "load-balance");
        let smart = by_name(&out.groups, "Smart");
        assert_eq!(smart["type"], "url-test");
        assert_eq!(smart["proxies"], json!(["🇺🇸 US-SS", "Auto", "Fail"]));
        assert_eq!(by_name(&out.groups, "Remote")["proxies"], json!(["DIRECT"]));
        assert!(out.groups.iter().all(|g| g["name"] != "SSID"));

        let rules = &out.rules;
        assert!(rules.contains(&"DOMAIN-SUFFIX,openai.com,Proxy".to_string()));
        assert!(rules.contains(&"DOMAIN,api.example.com,Auto".to_string()));
        assert!(rules.contains(&"IP-CIDR,192.0.2.0/24,DIRECT,no-resolve".to_string()));
        assert!(rules.contains(&"PROCESS-NAME,Telegram,Proxy".to_string()));
        assert!(rules.contains(&"RULE-SET,surge-1,Proxy".to_string()));
        assert!(rules.contains(&"RULE-SET,surge-2,REJECT".to_string()));
        assert!(
            rules.contains(&"AND,((DOMAIN-SUFFIX,example.net),(DST-PORT,443)),Fail".to_string())
        );
        assert!(rules.contains(&"NETWORK,udp,REJECT".to_string()));
        assert_eq!(rules.last().unwrap(), "MATCH,Proxy");
        assert_eq!(out.rule_providers.len(), 2);
        assert_eq!(out.rule_providers[1].1["behavior"], "domain");
        for kind in [
            "USER-AGENT",
            "URL-REGEX",
            "RULE-SET,SYSTEM",
            "unknown policy",
            "SSID",
            "policy-path",
        ] {
            assert!(
                out.skipped.iter().any(|s| s.contains(kind)),
                "expected skip note for {kind}: {:?}",
                out.skipped
            );
        }
    }

    #[test]
    fn surge_rule_sets_cache_by_url_and_share_repeated_lists() {
        let surge = |rules: &str| {
            convert_subscription(&format!(
                "[Proxy]\nA = ss, 192.0.2.1, 8388, encrypt-method=aes-128-gcm, password=fake\n\n[Proxy Group]\nP = select, A\n\n[Rule]\n{rules}FINAL,P\n"
            ))
            .unwrap()
        };
        let out = surge(
            "RULE-SET,https://example.com/ai.list,P\n\
             DOMAIN-SET,https://example.com/ads.txt,REJECT\n\
             RULE-SET,https://example.com/ai.list,DIRECT,no-resolve\n\
             DOMAIN-SET,https://example.com/ai.list,REJECT\n",
        );
        assert_eq!(
            out.rules,
            [
                "RULE-SET,surge-1,P",
                "RULE-SET,surge-2,REJECT",
                "RULE-SET,surge-1,DIRECT,no-resolve",
                "RULE-SET,surge-3,REJECT",
                "MATCH,P",
            ]
        );
        let names: Vec<_> = out.rule_providers.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, ["surge-1", "surge-2", "surge-3"]);
        assert_eq!(out.rule_providers[2].1["behavior"], "domain");
        assert_eq!(
            out.rule_providers[2].1["url"],
            "https://example.com/ai.list"
        );
        // Mihomo keys the cache file on the URL, so a reorder cannot hand one
        // policy another list's cached rules.
        assert!(out
            .rule_providers
            .iter()
            .all(|(_, p)| p.get("path").is_none()));
        let swapped = surge(
            "DOMAIN-SET,https://example.com/ads.txt,REJECT\n\
             RULE-SET,https://example.com/ai.list,P\n",
        );
        assert_eq!(
            swapped.rule_providers[0].1["url"],
            "https://example.com/ads.txt"
        );
        assert_eq!(swapped.rules[0], "RULE-SET,surge-1,REJECT");
    }

    #[test]
    fn uri_nodes_parse() {
        let ss_b64 = format!(
            "ss://{}@192.0.2.1:8388?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dexample.com#SS%20One",
            encode_base64(b"aes-128-gcm:fake")
        );
        let ss = parse_uri(&ss_b64).unwrap();
        assert_eq!(ss["name"], "SS One");
        assert_eq!(ss["cipher"], "aes-128-gcm");
        assert_eq!(ss["plugin-opts"]["mode"], "tls");
        let plain = parse_uri(
            "ss://2022-blake3-aes-128-gcm:AAAAAAAAAAAAAAAAAAAAAA%3D%3D@[2001:db8::1]:443#v6",
        )
        .unwrap();
        assert_eq!(plain["server"], "2001:db8::1");
        assert_eq!(plain["password"], "AAAAAAAAAAAAAAAAAAAAAA==");
        let legacy = format!(
            "ss://{}#Legacy",
            encode_base64(b"chacha20-ietf-poly1305:pw@192.0.2.2:1234")
        );
        assert_eq!(parse_uri(&legacy).unwrap()["port"], 1234);
        assert!(parse_uri("ss://2022-blake3-aes-128-gcm:short@192.0.2.1:1#bad").is_err());

        let tj = parse_uri("trojan://fake@192.0.2.3:443?sni=a.example&type=ws&path=%2Fws&host=a.example&allowInsecure=1#TJ").unwrap();
        assert_eq!(tj["ws-opts"]["path"], "/ws");
        assert_eq!(tj["skip-cert-verify"], true);
        let vl = parse_uri("vless://00000000-0000-0000-0000-000000000000@192.0.2.4:443?security=reality&sni=www.example.com&pbk=PUBKEY&sid=ab&flow=xtls-rprx-vision&type=tcp#VL").unwrap();
        assert_eq!(vl["reality-opts"]["public-key"], "PUBKEY");
        assert_eq!(vl["client-fingerprint"], "chrome");
        assert_eq!(vl["flow"], "xtls-rprx-vision");
        let vm_json = r#"{"v":"2","ps":"VM","add":"192.0.2.5","port":"443","id":"00000000-0000-0000-0000-000000000000","aid":"0","net":"ws","path":"/v","host":"v.example","tls":"tls"}"#;
        let vm = parse_uri(&format!("vmess://{}", encode_base64(vm_json.as_bytes()))).unwrap();
        assert_eq!(vm["ws-opts"]["headers"]["Host"], "v.example");
        assert_eq!(vm["servername"], "v.example");
        let hy = parse_uri(
            "hy2://fake@192.0.2.6:8443?sni=h.example&obfs=salamander&obfs-password=x&insecure=1#HY",
        )
        .unwrap();
        assert_eq!(hy["type"], "hysteria2");
        assert_eq!(hy["obfs"], "salamander");
        let tuic =
            parse_uri("tuic://uuid-x:fake@192.0.2.7:443?alpn=h3,h2&congestion_control=bbr#TU")
                .unwrap();
        assert_eq!(tuic["alpn"], json!(["h3", "h2"]));
        assert_eq!(tuic["uuid"], "uuid-x");
        assert!(parse_uri("ssr://abc").is_err());
        assert!(parse_uri("vless://u@192.0.2.8:443?type=kcp#K").is_err());
        assert!(parse_uri("trojan://p@nohost").is_err());
    }

    #[test]
    fn websocket_early_data_and_http_upgrade_links() {
        let vl = parse_uri("vless://00000000-0000-0000-0000-000000000000@192.0.2.4:443?security=tls&type=ws&path=%2Fws&host=w.example&ed=2048#WS").unwrap();
        assert_eq!(vl["network"], "ws");
        assert_eq!(vl["ws-opts"]["path"], "/ws");
        assert_eq!(vl["ws-opts"]["headers"]["Host"], "w.example");
        assert_eq!(vl["ws-opts"]["max-early-data"], 2048);
        assert_eq!(
            vl["ws-opts"]["early-data-header-name"],
            "Sec-WebSocket-Protocol"
        );
        let eh = parse_uri("vless://u@192.0.2.4:443?type=ws&ed=2048&eh=X-Early#EH").unwrap();
        assert_eq!(eh["ws-opts"]["early-data-header-name"], "X-Early");
        assert_eq!(eh["ws-opts"]["path"], "/");
        let plain = parse_uri("trojan://p@192.0.2.3:443?type=ws#P").unwrap();
        assert!(plain["ws-opts"].get("max-early-data").is_none());
        assert!(plain["ws-opts"].get("v2ray-http-upgrade").is_none());

        let up =
            parse_uri("trojan://p@192.0.2.3:443?type=httpupgrade&path=%2Fup&host=u.example#UP")
                .unwrap();
        assert_eq!(up["network"], "ws");
        assert_eq!(up["ws-opts"]["v2ray-http-upgrade"], true);
        assert_eq!(up["ws-opts"]["headers"]["Host"], "u.example");
        assert!(up["ws-opts"].get("v2ray-http-upgrade-fast-open").is_none());
        let fast = parse_uri("vless://u@192.0.2.4:443?type=HTTPUpgrade&ed=2048#F").unwrap();
        assert_eq!(fast["ws-opts"]["v2ray-http-upgrade-fast-open"], true);
        assert!(fast["ws-opts"].get("max-early-data").is_none());
        assert!(parse_uri("vless://u@192.0.2.4:443?type=ws&ed=lots#Bad").is_err());

        let vm = |net: &str, path: &str| {
            let body = format!(
                r#"{{"ps":"VM","add":"192.0.2.5","port":"443","id":"x","net":"{net}","path":"{path}","host":"v.example"}}"#
            );
            parse_uri(&format!("vmess://{}", encode_base64(body.as_bytes()))).unwrap()
        };
        let ws = vm("ws", "/v?ed=2048&x=1");
        assert_eq!(ws["ws-opts"]["path"], "/v?x=1");
        assert_eq!(ws["ws-opts"]["max-early-data"], 2048);
        let up = vm("httpupgrade", "/u?ed=2048");
        assert_eq!(up["network"], "ws");
        assert_eq!(up["ws-opts"]["path"], "/u");
        assert_eq!(up["ws-opts"]["v2ray-http-upgrade"], true);
        assert_eq!(up["ws-opts"]["v2ray-http-upgrade-fast-open"], true);
        assert_eq!(vm("ws", "/k?ed=big")["ws-opts"]["path"], "/k?ed=big");
        assert_eq!(vm("ws", "")["ws-opts"]["path"], "/");
    }

    #[test]
    fn base64_list_converts_and_counts_skips() {
        let list = "trojan://p@192.0.2.1:443#A\nssr://zzz\nvless://u@192.0.2.2:443#A\n";
        let out = convert_subscription(&encode_base64(list.as_bytes())).unwrap();
        assert_eq!(out.format, Some(SubFormat::UriList));
        assert_eq!(out.proxies.len(), 2);
        assert_eq!(out.proxies[1]["name"], "A 2");
        assert_eq!(out.skipped.len(), 1);
    }

    #[test]
    fn single_node_lines() {
        let n = parse_node_line(
            "🇺🇸Fake-SS2022 = ss, 192.0.2.10, 8443, encrypt-method=2022-blake3-aes-128-gcm, password=AAAAAAAAAAAAAAAAAAAAAA==, udp-relay=true, tfo=true",
        )
        .unwrap();
        assert_eq!(n["name"], "🇺🇸Fake-SS2022");
        assert_eq!(n["type"], "ss");
        assert_eq!(n["cipher"], "2022-blake3-aes-128-gcm");
        assert_eq!(n["password"], "AAAAAAAAAAAAAAAAAAAAAA==");
        assert_eq!(n["udp"], true);
        assert_eq!(n["tfo"], true);
        assert_eq!(node_summary(&n), "ss  192.0.2.10:8443");
        assert!(parse_node_line("Home = direct").is_err());
        assert!(parse_node_line("garbage").is_err());
        assert!(parse_node_line(
            "X = ss, 192.0.2.1, 99999, encrypt-method=aes-128-gcm, password=p"
        )
        .is_err());
        assert!(parse_node_line("X = ss, 192.0.2.1, 1, encrypt-method=rot13, password=p").is_err());
        assert_eq!(
            parse_node_line("socks5://u:p@192.0.2.1:1080#S").unwrap()["username"],
            "u"
        );
    }

    // Placeholder keys: 32 bytes of 0x01 / 0x02, and 0x03 as hex.
    const K1: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const K2: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    const K3_HEX: &str = "0303030303030303030303030303030303030303030303030303030303030303";

    pub(crate) fn surge_wg_profile() -> String {
        format!(
            r#"[Proxy]
Home WG = wireguard, section-name=home, underlying-proxy=Jump
Mesh = wireguard, section-name=mesh
Jump = ssh, 192.0.2.20, 22, username=root, password=fake, server-fingerprint="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBk2No6KBq2m9VTCcHXXJBX4/A3RNr+L+yDBl5+TF9qz"
KeyJump = ssh, 192.0.2.21, 2222, username=ops, private-key=key1
NoKey = ssh, 192.0.2.22, 22, username=ops, private-key=missing

[Keystore]
key1 = type=openssh-private-key, base64={pem}

[WireGuard home]
private-key = {K1}
self-ip = 10.8.0.2
self-ip-v6 = fd00::2
dns-server = 10.8.0.1, system
mtu = 1280
peer = (public-key = {K3_HEX}, allowed-ips = "0.0.0.0/0, ::/0", endpoint = vpn.example.com:51820, keepalive = 25, preshared-key = {K2}, client-id = 83/12/235)

[WireGuard mesh]
private-key = {K1}
self-ip = 10.9.0.2
peer = (public-key = {K2}, allowed-ips = 10.9.0.0/24, endpoint = [2001:db8::1]:51820, client-id = U4An)
peer = (public-key = {K1}, allowed-ips = 10.10.0.0/24, endpoint = 192.0.2.30:51821)
"#,
            pem = encode_base64(
                b"-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----\n"
            )
        )
    }

    #[test]
    fn surge_wireguard_and_ssh_map_to_mihomo() {
        let out = convert_subscription(&surge_wg_profile()).unwrap();
        let wg = by_name(&out.proxies, "Home WG");
        assert_eq!(wg["type"], "wireguard");
        assert_eq!(wg["server"], "vpn.example.com");
        assert_eq!(wg["port"], 51820);
        assert_eq!(wg["private-key"], K1);
        assert_eq!(wg["public-key"], encode_base64(&[3u8; 32]));
        assert_eq!(wg["pre-shared-key"], K2);
        assert_eq!(wg["ip"], "10.8.0.2");
        assert_eq!(wg["ipv6"], "fd00::2");
        assert_eq!(wg["mtu"], 1280);
        assert_eq!(wg["reserved"], json!([83, 12, 235]));
        assert_eq!(wg["allowed-ips"], json!(["0.0.0.0/0", "::/0"]));
        assert_eq!(wg["persistent-keepalive"], 25);
        assert_eq!(wg["remote-dns-resolve"], true);
        assert_eq!(wg["dns"], json!(["10.8.0.1"]));
        assert_eq!(wg["udp"], true);
        assert_eq!(wg["dialer-proxy"], "Jump");
        assert!(wg.get("peers").is_none());
        assert!(wg.get("skip-cert-verify").is_none());

        let mesh = by_name(&out.proxies, "Mesh");
        let peers = mesh["peers"].as_array().unwrap();
        assert_eq!(peers.len(), 2);
        assert_eq!(peers[0]["server"], "2001:db8::1");
        assert_eq!(peers[0]["reserved"], json!([83, 128, 39]));
        assert_eq!(peers[1]["allowed-ips"], json!(["10.10.0.0/24"]));
        assert_eq!(mesh["server"], "2001:db8::1");

        let jump = by_name(&out.proxies, "Jump");
        assert_eq!(jump["type"], "ssh");
        assert_eq!(jump["username"], "root");
        assert_eq!(jump["password"], "fake");
        assert!(jump["host-key"][0]
            .as_str()
            .unwrap()
            .starts_with("ssh-ed25519 "));
        let kj = by_name(&out.proxies, "KeyJump");
        assert!(kj["private-key"]
            .as_str()
            .unwrap()
            .contains("OPENSSH PRIVATE KEY"));
        assert!(out
            .skipped
            .iter()
            .any(|s| s.contains("NoKey") && s.contains("Keystore")));
        assert!(out.skipped.iter().all(|s| !s.contains("fake")));
    }

    #[test]
    fn wireguard_one_line_forms_round_trip() {
        let line = format!(
            "wireguard://{}@192.0.2.40:51820?publickey={}&address=172.16.0.2/32,fd01::2/128&reserved=1,2,3&mtu=1280&dns=1.1.1.1#WARP",
            percent_encode(K1),
            percent_encode(K2)
        );
        let n = parse_node_line(&line).unwrap();
        assert_eq!(n["type"], "wireguard");
        assert_eq!(n["name"], "WARP");
        assert_eq!(n["private-key"], K1);
        assert_eq!(n["public-key"], K2);
        assert_eq!(n["ip"], "172.16.0.2/32");
        assert_eq!(n["ipv6"], "fd01::2/128");
        assert_eq!(n["reserved"], json!([1, 2, 3]));
        assert_eq!(node_summary(&n), "wireguard  192.0.2.40:51820");
        // Serializing and re-parsing yields the same node.
        let again = parse_node_line(&wireguard_uri(&n).unwrap()).unwrap();
        assert_eq!(again, n);
        assert!(parse_node_line("wg://bad@192.0.2.1:1?publickey=x#X").is_err());

        let conf = format!(
            "[Interface]\nPrivateKey = {K1}\nAddress = 10.7.0.2/32, fd07::2/128\nDNS = 10.7.0.1, lan\nMTU = 1420\n\n[Peer]\nPublicKey = {K2}\nAllowedIPs = 0.0.0.0/0\nEndpoint = [2001:db8::7]:51820\nPersistentKeepalive = 15\n"
        );
        let lines = block_to_node_lines(&conf).unwrap().unwrap();
        assert_eq!(lines.len(), 1);
        let q = parse_node_line(&lines[0]).unwrap();
        assert_eq!(q["server"], "2001:db8::7");
        assert_eq!(q["dns"], json!(["10.7.0.1"]));
        assert_eq!(q["persistent-keepalive"], 15);
        assert_eq!(q["allowed-ips"], json!(["0.0.0.0/0"]));

        let surge_block = format!(
            "Lab = wireguard, section-name=lab\n[WireGuard lab]\nprivate-key = {K1}\nself-ip = 10.6.0.2\npeer = (public-key = {K2}, allowed-ips = 10.6.0.0/24, endpoint = lab.example.com:51820)\n"
        );
        let lines = block_to_node_lines(&surge_block).unwrap().unwrap();
        assert_eq!(parse_node_line(&lines[0]).unwrap()["name"], "Lab");
        assert!(block_to_node_lines(&surge_wg_profile()).unwrap().is_err());
        assert!(block_to_node_lines("trojan://p@192.0.2.1:443#a").is_none());

        let ssh = parse_node_line("ssh://root:fake@192.0.2.50:22#Box").unwrap();
        assert_eq!(ssh["type"], "ssh");
        assert_eq!(ssh["password"], "fake");
        assert!(parse_node_line("ssh://root@192.0.2.50:22#Box").is_err());
        assert_eq!(
            parse_node_line("S = ssh, 192.0.2.51, 22, username=u, password=fake").unwrap()["type"],
            "ssh"
        );
    }

    #[test]
    fn wg_helpers() {
        assert_eq!(wg_key(K3_HEX).unwrap(), encode_base64(&[3u8; 32]));
        assert!(wg_key("short").is_none());
        assert_eq!(wg_reserved("U4An").unwrap(), vec![83, 128, 39]);
        assert_eq!(wg_reserved("010203").unwrap(), vec![1, 2, 3]);
        assert_eq!(wg_reserved("[1, 2, 3]").unwrap(), vec![1, 2, 3]);
        assert!(wg_reserved("1/2").is_none());
        assert_eq!(
            split_endpoint("[::1]:51820").unwrap(),
            ("::1".into(), 51820)
        );
        assert!(split_endpoint("host").is_none());
    }

    #[test]
    fn base64_round_trip_and_rejects_noise() {
        for s in ["", "a", "ab", "abc", "abcd", "héllo"] {
            let enc = encode_base64(s.as_bytes());
            if s.is_empty() {
                continue;
            }
            assert_eq!(decode_base64(&enc).unwrap(), s.as_bytes());
            assert_eq!(
                decode_base64(enc.trim_end_matches('=')).unwrap(),
                s.as_bytes()
            );
        }
        assert!(decode_base64("not base64!").is_none());
        assert_eq!(percent_decode("a%2Fb%zz%"), "a/b%zz%");
    }

    #[test]
    fn httpupgrade_nodes_become_ws_with_v2ray_http_upgrade() {
        let pasted = parse_node_line(
            r#"{"name":"U","type":"vless","server":"192.0.2.4","port":443,"uuid":"u","network":"HTTPUpgrade","httpupgrade-opts":{"path":"/up","host":"u.example"}}"#,
        )
        .unwrap();
        assert_eq!(pasted["network"], "ws");
        assert!(pasted.get("httpupgrade-opts").is_none());
        assert_eq!(
            pasted["ws-opts"],
            json!({"path": "/up", "headers": {"Host": "u.example"}, "v2ray-http-upgrade": true})
        );
        // Existing ws-opts win over the legacy keys; a lowercase host counts.
        let mut node = json!({"network": "httpupgrade",
            "ws-opts": {"path": "/keep", "headers": {"host": "k.example"},
                "v2ray-http-upgrade-fast-open": true},
            "httpupgrade-opts": {"path": "/old", "host": "old.example"}});
        assert!(normalize_ws_network(&mut node));
        assert_eq!(
            node["ws-opts"],
            json!({"path": "/keep", "headers": {"host": "k.example"},
                "v2ray-http-upgrade": true, "v2ray-http-upgrade-fast-open": true})
        );
        let once = node.clone();
        assert!(!normalize_ws_network(&mut node));
        assert_eq!(node, once);
        // ws-opts that is not an object is replaced.
        let mut odd = json!({"network": "httpupgrade", "ws-opts": null});
        assert!(normalize_ws_network(&mut odd));
        assert_eq!(odd["ws-opts"], json!({"v2ray-http-upgrade": true}));
        // `network: httpupgrade` wins over a converter's default false.
        let mut off = json!({"network": "httpupgrade", "ws-opts": {"v2ray-http-upgrade": false}});
        assert!(normalize_ws_network(&mut off));
        assert_eq!(off["ws-opts"], json!({"v2ray-http-upgrade": true}));
        for other in [
            json!({"network": "ws", "ws-opts": {"path": "/?ed=2048"}}),
            json!({"network": "grpc", "grpc-opts": {"grpc-service-name": "s"}}),
            json!({"network": "tcp"}),
            json!({"type": "ss"}),
            json!("httpupgrade"),
        ] {
            let mut node = other.clone();
            assert!(!normalize_ws_network(&mut node));
            assert_eq!(node, other);
        }
    }

    #[test]
    fn tuic_defaults_to_bbr_but_keeps_explicit_controllers() {
        let out = convert_subscription(SURGE).unwrap();
        assert_eq!(
            by_name(&out.proxies, "TUIC")["congestion-controller"],
            "bbr"
        );
        let surge = convert_subscription(
            "[Proxy]\nT4 = tuic, 192.0.2.5, 443, token=fake\n\
             TC = tuic-v5, 192.0.2.5, 443, uuid=u, password=fake, congestion-controller=cubic\n",
        )
        .unwrap();
        assert_eq!(
            by_name(&surge.proxies, "T4")["congestion-controller"],
            "bbr"
        );
        assert_eq!(
            by_name(&surge.proxies, "TC")["congestion-controller"],
            "cubic"
        );
        let bare = parse_uri("tuic://uuid-x:fake@192.0.2.7:443?alpn=h3#TU").unwrap();
        assert_eq!(bare["congestion-controller"], "bbr");
        let cubic =
            parse_uri("tuic://uuid-x:fake@192.0.2.7:443?congestion_control=cubic#TU").unwrap();
        assert_eq!(cubic["congestion-controller"], "cubic");
        // Only TUIC nodes get it.
        assert!(by_name(&out.proxies, "TW-HY2")
            .get("congestion-controller")
            .is_none());
    }
}
