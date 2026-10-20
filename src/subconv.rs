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
];

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
    match parse_surge_proxy(name.trim(), rest, &mut alias)? {
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
            section = line[1..line.len() - 1].trim().to_ascii_lowercase();
            continue;
        }
        match section.as_str() {
            "proxy" => proxy_lines.push(line.to_string()),
            "proxy group" => group_lines.push(line.to_string()),
            "rule" => rule_lines.push(line.to_string()),
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
        match parse_surge_proxy(&name, rest, &mut alias) {
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
            if let Some(v) = group
                .params
                .get("tolerance")
                .and_then(|v| v.parse::<u64>().ok())
            {
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
        match convert_surge_rule(line, &resolve, out.rule_providers.len()) {
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

/// Ok(None) means the line defines a built-in policy alias (direct/reject).
fn parse_surge_proxy(
    name: &str,
    rest: &str,
    alias: &mut HashMap<String, String>,
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
    let server = positional
        .first()
        .cloned()
        .ok_or_else(|| format!("{name}: missing server"))?;
    let port = parse_port(&name, positional.get(1).map(String::as_str).unwrap_or(""))?;
    let flag = |k: &str| kv.get(k).map(|v| truthy(v));
    let mut node = Map::new();
    node.insert("name".into(), json!(name));
    node.insert("server".into(), json!(server));
    node.insert("port".into(), json!(port));
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
            if version > 3 {
                return Err(format!("{name}: snell v{version} unsupported by Mihomo"));
            }
            node.insert("type".into(), json!("snell"));
            node.insert(
                "psk".into(),
                json!(kv.get("psk").cloned().unwrap_or_default()),
            );
            node.insert("version".into(), json!(version));
            if let Some(mode) = kv.get("obfs") {
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
        other => return Err(format!("{name} = {other}")),
    }
    if let Some(v) = flag("udp-relay") {
        node.insert("udp".into(), json!(v));
    }
    if let Some(v) = flag("tfo") {
        node.insert("tfo".into(), json!(v));
    }
    if let Some(v) = skip_verify {
        if kind != "ss" && kind != "snell" {
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

fn convert_surge_rule(
    line: &str,
    resolve: &dyn Fn(&str) -> Option<String>,
    provider_index: usize,
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
            let name = format!("surge-{}", provider_index + 1);
            let behavior = if kind == "DOMAIN-SET" {
                "domain"
            } else {
                "classical"
            };
            let provider = json!({
                "type": "http",
                "behavior": behavior,
                "format": "text",
                "url": url,
                "path": format!("./rules/{name}.list"),
                "interval": 86400,
            });
            let mut rule = format!("RULE-SET,{name},{policy}");
            if parts
                .iter()
                .skip(3)
                .any(|p| p.eq_ignore_ascii_case("no-resolve"))
            {
                rule.push_str(",no-resolve");
            }
            Ok((rule, Some((name, provider))))
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
        "ws" => {
            node.insert("network".into(), json!("ws"));
            let mut opts = Map::new();
            opts.insert(
                "path".into(),
                json!(url.q("path").unwrap_or_else(|| "/".into())),
            );
            if let Some(h) = url.q("host") {
                opts.insert("headers".into(), json!({ "Host": h }));
            }
            node.insert("ws-opts".into(), Value::Object(opts));
        }
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
            if let Some(c) = url.q("congestion_control") {
                node.insert("congestion-controller".into(), json!(c));
            }
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
        "ws" => {
            node.insert("network".into(), json!("ws"));
            let mut opts = Map::new();
            let path = s("path");
            opts.insert(
                "path".into(),
                json!(if path.is_empty() { "/".into() } else { path }),
            );
            if !s("host").is_empty() {
                opts.insert("headers".into(), json!({ "Host": s("host") }));
            }
            node.insert("ws-opts".into(), Value::Object(opts));
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
Snell5 = snell, 192.0.2.9, 443, psk=fake, version=5

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
        assert_eq!(out.proxies.len(), 8);
        assert!(out.skipped.iter().any(|s| s.contains("wireguard")));
        assert!(out.skipped.iter().any(|s| s.contains("snell v5")));
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
}
