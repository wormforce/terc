//! Pure helpers for YAML overlays, rule explain, and controller payloads.
//!
//! Mihomo unmarshals YAML with yaml.v3, where a later duplicate key replaces
//! the earlier one. Module snippets are therefore appended, and removing the
//! marked block restores the original document.

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde_json::Value;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsStatus {
    pub present: bool,
    pub enable: bool,
    pub listen: String,
    pub enhanced_mode: String,
    pub fake_ip_range: String,
    pub nameservers: Vec<String>,
    pub fallback: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RuntimeFlags {
    pub tun_enabled: bool,
    pub tun_stack: String,
    pub tun_device: String,
    pub sniffing: bool,
    pub ipv6: bool,
    pub tcp_concurrent: bool,
    pub find_process: String,
    pub dns: DnsStatus,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuleInfo {
    pub index: usize,
    pub kind: String,
    pub payload: String,
    pub proxy: String,
    pub size: i64,
    pub disabled: bool,
    pub hit_count: u64,
    pub hit_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderInfo {
    pub name: String,
    pub kind: String,
    pub vehicle: String,
    pub behavior: String,
    pub count: usize,
    pub updated_at: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModuleSnippet {
    pub id: String,
    pub name: String,
    pub description: String,
    pub body: String,
    pub builtin: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProfileEntry {
    pub kind: String,
    pub name: String,
    pub label: String,
    pub path: String,
    pub active: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeTarget {
    pub raw: String,
    pub host: String,
    pub port: Option<u16>,
    pub network: Option<String>,
    pub process: Option<String>,
    pub is_ip: bool,
    pub delay_url: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExplainOutcome {
    Hit,
    Miss,
    Skip,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplainStep {
    pub index: usize,
    pub kind: String,
    pub payload: String,
    pub proxy: String,
    pub outcome: ExplainOutcome,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExplainReport {
    pub target: String,
    pub host: String,
    pub matched: Option<ExplainStep>,
    pub partial: bool,
    pub uncertain: Vec<ExplainStep>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsMessage {
    pub status: i64,
    pub answers: Vec<DnsAnswer>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsAnswer {
    pub qtype: String,
    pub ttl: u64,
    pub data: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct YamlChunk {
    pub(crate) key: Option<String>,
    pub(crate) lines: Vec<String>,
}

pub fn builtin_modules() -> Vec<ModuleSnippet> {
    vec![
        ModuleSnippet {
            id: "tun".into(),
            name: "TUN".into(),
            description: "Mixed TUN, auto-route, DNS hijack".into(),
            // GSO only on Linux: Darwin ignores it, but Mihomo compares it
            // and would rebuild TUN on a reload for nothing.
            body: format!(
                "\
tun:
  enable: true
  stack: mixed
{}  auto-route: true
  auto-detect-interface: true
  dns-hijack:
    - any:53
    - tcp://any:53",
                if cfg!(target_os = "linux") {
                    "  gso: true\n"
                } else {
                    ""
                }
            ),
            builtin: true,
        },
        ModuleSnippet {
            id: "sniffer".into(),
            name: "Sniffer".into(),
            description: "HTTP / TLS / QUIC sniff".into(),
            body: "\
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: false
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]"
                .into(),
            builtin: true,
        },
        // Matches the template's DNS block. Sequences replace the source's as a
        // unit, so `fallback: []` drops a source fallback that would race
        // every non-CN answer. The listener stays on loopback: Mihomo binds it
        // without checking allow-lan.
        ModuleSnippet {
            id: "dns-fakeip".into(),
            name: "DNS fake-ip".into(),
            description: "Fake-IP DNS with mainland DoH".into(),
            body: "\
dns:
  enable: true
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - \"*.lan\"
    - \"+.local\"
    - localhost
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  proxy-server-nameserver:
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback: []"
                .into(),
            builtin: true,
        },
        // The foreign resolvers are reached through the rules; node hostnames
        // still use mainland DoH so connecting never waits on a blocked one.
        ModuleSnippet {
            id: "dns-fakeip-global".into(),
            name: "DNS fake-ip (global)".into(),
            description: "Fake-IP DNS with Google / Cloudflare DoH".into(),
            body: "\
dns:
  enable: true
  listen: 127.0.0.1:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - \"*.lan\"
    - \"+.local\"
    - localhost
  respect-rules: true
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29
  nameserver:
    - https://dns.google/dns-query
    - https://cloudflare-dns.com/dns-query
  proxy-server-nameserver:
    - https://doh.pub/dns-query
    - https://dns.alidns.com/dns-query
  fallback: []"
                .into(),
            builtin: true,
        },
        ModuleSnippet {
            id: "find-process".into(),
            name: "Find process".into(),
            description: "Always attach process name to connections".into(),
            body: "find-process-mode: always".into(),
            builtin: true,
        },
        ModuleSnippet {
            id: "tcp-concurrent".into(),
            name: "TCP concurrent".into(),
            description: "Race TCP handshakes for faster connects".into(),
            body: "tcp-concurrent: true".into(),
            builtin: true,
        },
        ModuleSnippet {
            id: "ipv6".into(),
            name: "IPv6".into(),
            description: "Enable IPv6 name resolution".into(),
            body: "ipv6: true".into(),
            builtin: true,
        },
    ]
}

pub fn load_user_modules(dir: &Path) -> Vec<ModuleSnippet> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return out;
    };
    let builtins: Vec<String> = builtin_modules().into_iter().map(|m| m.id).collect();
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
            continue;
        };
        if !ext.eq_ignore_ascii_case("yaml") && !ext.eq_ignore_ascii_case("yml") {
            continue;
        }
        let Ok(body) = fs::read_to_string(&path) else {
            continue;
        };
        let mut id = stem.to_string();
        if builtins.iter().any(|b| b == &id) || id.starts_with('.') {
            id = format!("local-{stem}");
        }
        let (name, description, stripped) = module_header(&body, stem);
        out.push(ModuleSnippet {
            id,
            name,
            description,
            body: stripped,
            builtin: false,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

pub fn module_catalog(dir: &Path) -> Vec<ModuleSnippet> {
    let mut all = builtin_modules();
    all.extend(load_user_modules(dir));
    all
}

pub fn enabled_snippets(catalog: &[ModuleSnippet], enabled: &[String]) -> Vec<ModuleSnippet> {
    catalog
        .iter()
        .filter(|m| enabled.iter().any(|id| id == &m.id))
        .cloned()
        .collect()
}

fn module_header(body: &str, stem: &str) -> (String, String, String) {
    let mut name = stem.to_string();
    let mut description = String::new();
    let mut rest = Vec::new();
    for line in split_lines(body) {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("# name:") {
            name = value.trim().to_string();
            continue;
        }
        if let Some(value) = trimmed
            .strip_prefix("# description:")
            .or_else(|| trimmed.strip_prefix("# desc:"))
        {
            description = value.trim().to_string();
            continue;
        }
        rest.push(line);
    }
    while rest.first().is_some_and(|l| l.trim().is_empty()) {
        rest.remove(0);
    }
    while rest.last().is_some_and(|l| l.trim().is_empty()) {
        rest.pop();
    }
    (name, description, rest.join("\n"))
}

/// Keep the source in a YAML comment so disabling an overlay restores it exactly.
const BASE_PREFIX: &str = "# terc-base: ";

pub fn has_subscription_source(doc: &str) -> bool {
    split_chunks(doc)
        .iter()
        .any(|chunk| matches!(chunk.key.as_deref(), Some("proxies" | "proxy-providers")))
}

pub fn apply_enabled_modules(doc: &str, modules: &[ModuleSnippet]) -> Result<String, String> {
    apply_modules_with_switches(&strip_marked_modules(doc), modules, &saved_switches(doc))
}

/// Overlay modules on a fresh base while keeping switch states saved earlier.
pub fn apply_modules_with_switches(
    base: &str,
    modules: &[ModuleSnippet],
    switches: &[(Vec<String>, bool)],
) -> Result<String, String> {
    let base = base.to_string();
    if modules.is_empty() {
        return Ok(base);
    }
    let mut merged = base.clone();
    for module in modules {
        merged = merge_yaml_mapping(&merged, &module.body)?;
    }
    for (path, value) in switches {
        let refs: Vec<&str> = path.iter().map(String::as_str).collect();
        merged = set_nested_bool(&merged, &refs, *value);
    }
    Ok(format!(
        "{BASE_PREFIX}{}\n# terc-switches: {}\n{merged}",
        serde_json::to_string(&base).unwrap(),
        serde_json::to_string(switches).unwrap()
    ))
}

/// Merge block mappings recursively; sequences and scalars are replaced as a unit.
/// Unchanged YAML (including anchors and flow collections) stays verbatim.
fn merge_yaml_mapping(base: &str, overlay: &str) -> Result<String, String> {
    let mut chunks = split_chunks(base);
    for patch in split_chunks(overlay) {
        let Some(key) = patch.key.as_deref() else {
            continue;
        };
        if let Some(pos) = chunks.iter().position(|c| c.key.as_deref() == Some(key)) {
            let original = &chunks[pos];
            let block_body = |chunk: &YamlChunk| -> Option<String> {
                let (_, scalar) = chunk.lines.first()?.split_once(':')?;
                if !clean_scalar(scalar).is_empty() {
                    return None;
                }
                let indent = chunk
                    .lines
                    .iter()
                    .skip(1)
                    .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                    .map(|l| leading_spaces(l))
                    .min()?;
                let body = chunk
                    .lines
                    .iter()
                    .skip(1)
                    .map(|l| l.get(indent..).unwrap_or(""))
                    .collect::<Vec<_>>()
                    .join("\n");
                if body
                    .lines()
                    .find(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))?
                    .trim_start()
                    .starts_with('-')
                {
                    return None;
                }
                Some(body)
            };
            if let Some(patch_body) = block_body(&patch) {
                if let Some(original_body) = block_body(original) {
                    let body = merge_yaml_mapping(&original_body, &patch_body)?;
                    chunks[pos].lines = std::iter::once(format!("{key}:"))
                        .chain(body.lines().map(|l| format!("  {l}")))
                        .collect();
                    continue;
                }
                let scalar = original.lines[0]
                    .split_once(':')
                    .map(|(_, v)| clean_scalar(v))
                    .unwrap_or_default();
                if !scalar.is_empty() && scalar != "null" && scalar != "~" {
                    return Err(format!("Cannot overlay block {key} on inline YAML; expand this mapping to multiple lines first"));
                }
            }
            chunks[pos] = patch;
        } else {
            chunks.push(patch);
        }
    }
    Ok(join_chunks(&chunks))
}

pub fn strip_marked_modules(doc: &str) -> String {
    if let Some(base) = doc
        .lines()
        .next()
        .and_then(|l| l.strip_prefix(BASE_PREFIX))
        .and_then(|v| serde_json::from_str::<String>(v).ok())
    {
        return base;
    }
    let mut out = Vec::new();
    let mut skipping = false;
    for line in split_lines(doc) {
        let trimmed = line.trim();
        if trimmed.starts_with("# terc-module:begin") {
            skipping = true;
            continue;
        }
        if trimmed.starts_with("# terc-module:end") {
            skipping = false;
            continue;
        }
        if !skipping {
            out.push(line);
        }
    }
    while out.last().is_some_and(|l| l.trim().is_empty()) {
        out.pop();
    }
    join_lines(&out)
}

pub(crate) fn saved_switches(doc: &str) -> Vec<(Vec<String>, bool)> {
    doc.lines()
        .nth(1)
        .and_then(|l| l.strip_prefix("# terc-switches: "))
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default()
}

pub fn set_nested_bool(doc: &str, path: &[&str], value: bool) -> String {
    if doc.starts_with(BASE_PREFIX) {
        let base = set_nested_bool(&strip_marked_modules(doc), path, value);
        let mut switches = saved_switches(doc);
        switches.retain(|(p, _)| !p.iter().map(String::as_str).eq(path.iter().copied()));
        switches.push((path.iter().map(|s| s.to_string()).collect(), value));
        let effective = doc
            .lines()
            .filter(|l| !l.starts_with(BASE_PREFIX) && !l.starts_with("# terc-switches: "))
            .collect::<Vec<_>>()
            .join("\n");
        let updated = set_nested_bool(&effective, path, value);
        return format!(
            "{BASE_PREFIX}{}\n# terc-switches: {}\n{updated}",
            serde_json::to_string(&base).unwrap(),
            serde_json::to_string(&switches).unwrap()
        );
    }
    let literal = if value { "true" } else { "false" };
    match path {
        [key] => set_top_scalar(doc, key, literal),
        [block, key] => set_block_scalar(doc, block, key, literal),
        _ => {
            let mut owned = doc.to_string();
            if !owned.is_empty() && !owned.ends_with('\n') {
                owned.push('\n');
            }
            owned
        }
    }
}

pub fn parse_yaml_flags(doc: &str) -> RuntimeFlags {
    parse_yaml_flags_chunks(&split_chunks(doc))
}

/// `parse_yaml_flags` on a document already split, so one split serves
/// every key.
pub(crate) fn parse_yaml_flags_chunks(chunks: &[YamlChunk]) -> RuntimeFlags {
    let mut flags = RuntimeFlags {
        dns: last_chunk_lines(chunks, "dns")
            .map(dns_from_lines)
            .unwrap_or_default(),
        ..RuntimeFlags::default()
    };
    let scalar = |key: &str| {
        last_chunk_lines(chunks, key)
            .and_then(|lines| lines.first())
            .and_then(|line| line.split_once(':'))
            .map(|(_, value)| value)
    };
    if let Some(value) = scalar("ipv6") {
        flags.ipv6 = parse_yaml_bool(value).unwrap_or(false);
    }
    if let Some(value) = scalar("tcp-concurrent") {
        flags.tcp_concurrent = parse_yaml_bool(value).unwrap_or(false);
    }
    if let Some(value) = scalar("find-process-mode") {
        flags.find_process = clean_scalar(value);
    }
    if let Some(lines) = last_chunk_lines(chunks, "tun") {
        flags.tun_enabled = block_bool(lines, "enable").unwrap_or(false);
        flags.tun_stack = block_scalar(lines, "stack").unwrap_or_default();
        flags.tun_device = block_scalar(lines, "device").unwrap_or_default();
    }
    if let Some(lines) = last_chunk_lines(chunks, "sniffer") {
        flags.sniffing = block_bool(lines, "enable").unwrap_or(false);
    }
    flags
}

/// The lines of the last top-level chunk named `key`.
fn last_chunk_lines<'a>(chunks: &'a [YamlChunk], key: &str) -> Option<&'a [String]> {
    chunks
        .iter()
        .rev()
        .find(|chunk| chunk.key.as_deref() == Some(key))
        .map(|chunk| chunk.lines.as_slice())
}

pub fn apply_general_json(flags: &mut RuntimeFlags, value: &Value) {
    if let Some(tun) = value.get("tun") {
        if let Some(enabled) = tun.get("enable").and_then(Value::as_bool) {
            flags.tun_enabled = enabled;
        }
        if let Some(stack) = tun.get("stack").and_then(Value::as_str) {
            if !stack.is_empty() {
                flags.tun_stack = stack.to_string();
            }
        }
        if let Some(device) = tun.get("device").and_then(Value::as_str) {
            if !device.is_empty() {
                flags.tun_device = device.to_string();
            }
        }
    }
    if let Some(sniffing) = value.get("sniffing").and_then(Value::as_bool) {
        flags.sniffing = sniffing;
    }
    if let Some(ipv6) = value.get("ipv6").and_then(Value::as_bool) {
        flags.ipv6 = ipv6;
    }
    if let Some(concurrent) = value.get("tcp-concurrent").and_then(Value::as_bool) {
        flags.tcp_concurrent = concurrent;
    }
    if let Some(mode) = value.get("find-process-mode").and_then(Value::as_str) {
        if !mode.is_empty() {
            flags.find_process = mode.to_string();
        }
    }
}

pub fn parse_dns_block(doc: &str) -> DnsStatus {
    last_chunk_lines(&split_chunks(doc), "dns")
        .map(dns_from_lines)
        .unwrap_or_default()
}

fn dns_from_lines(lines: &[String]) -> DnsStatus {
    let mut status = DnsStatus {
        present: true,
        ..DnsStatus::default()
    };
    let mut index = 1usize;
    while index < lines.len() {
        let line = &lines[index];
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            index += 1;
            continue;
        }
        let indent = leading_spaces(line);
        let Some((key, value)) = split_kv(trimmed) else {
            index += 1;
            continue;
        };
        match key {
            "enable" => status.enable = parse_yaml_bool(value).unwrap_or(status.enable),
            "listen" => status.listen = clean_scalar(value),
            "enhanced-mode" => status.enhanced_mode = clean_scalar(value),
            "fake-ip-range" => status.fake_ip_range = clean_scalar(value),
            "nameserver" | "fallback" => {
                let bucket = key;
                index += 1;
                let mut items = Vec::new();
                while index < lines.len() {
                    let item = &lines[index];
                    if item.trim().is_empty() || item.trim().starts_with('#') {
                        index += 1;
                        continue;
                    }
                    if leading_spaces(item) <= indent {
                        break;
                    }
                    if let Some(rest) = item.trim().strip_prefix("- ") {
                        items.push(clean_scalar(rest));
                    }
                    index += 1;
                }
                if bucket == "nameserver" {
                    status.nameservers = items;
                } else {
                    status.fallback = items;
                }
                continue;
            }
            _ => {}
        }
        index += 1;
    }
    status
}

pub fn parse_rules_json(body: &str) -> Vec<RuleInfo> {
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return Vec::new();
    };
    let Some(arr) = value.get("rules").and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter()
        .enumerate()
        .map(|(position, rule)| {
            let index = rule
                .get("index")
                .and_then(Value::as_u64)
                .map(|n| n as usize)
                .unwrap_or(position);
            let extra = rule.get("extra");
            RuleInfo {
                index,
                kind: json_string(rule, "type"),
                payload: json_string(rule, "payload"),
                proxy: json_string(rule, "proxy"),
                size: rule.get("size").and_then(Value::as_i64).unwrap_or(-1),
                disabled: extra
                    .and_then(|e| e.get("disabled"))
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                hit_count: extra
                    .and_then(|e| e.get("hitCount"))
                    .and_then(Value::as_u64)
                    .unwrap_or(0),
                hit_at: extra
                    .and_then(|e| e.get("hitAt"))
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
            }
        })
        .collect()
}

pub fn parse_providers_json(body: &str, kind: &str) -> Vec<ProviderInfo> {
    serde_json::from_str::<Value>(body)
        .map(|value| providers_from_value(&value, kind))
        .unwrap_or_default()
}

/// The providers in a parsed `/providers/*` body. Mihomo's reserved
/// `default` proxy provider (vehicle `Compatible`, 88dcbf7
/// `config/config.go:973`) only mirrors inline proxies and cannot be
/// updated, so it is left out of the list.
pub fn providers_from_value(value: &Value, kind: &str) -> Vec<ProviderInfo> {
    let Some(obj) = value.get("providers").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out: Vec<ProviderInfo> = obj
        .iter()
        .filter(|(_, item)| !json_string(item, "vehicleType").eq_ignore_ascii_case("Compatible"))
        .map(|(key, item)| {
            let name = provider_name(key, &json_string(item, "name")).to_string();
            let count = item
                .get("ruleCount")
                .and_then(Value::as_u64)
                .map(|n| n as usize)
                .or_else(|| {
                    item.get("proxies")
                        .and_then(Value::as_array)
                        .map(|a| a.len())
                })
                .unwrap_or(0);
            ProviderInfo {
                name,
                kind: kind.to_string(),
                vehicle: json_string(item, "vehicleType"),
                behavior: json_string(item, "behavior"),
                count,
                updated_at: json_string(item, "updatedAt"),
            }
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderNode {
    pub name: String,
    pub kind: String,
    pub udp: bool,
    pub delay: Option<u16>,
    pub provider: String,
}

/// Since Mihomo v1.19.28, GET /proxies omits proxy-provider nodes, so they are
/// read from GET /providers/proxies. The reserved `default` provider only
/// mirrors inline proxies and groups, which /proxies already lists.
pub fn parse_provider_nodes(body: &str) -> Vec<ProviderNode> {
    serde_json::from_str::<Value>(body)
        .map(|value| provider_nodes_from_value(&value))
        .unwrap_or_default()
}

/// `parse_provider_nodes` on a body already parsed.
pub fn provider_nodes_from_value(value: &Value) -> Vec<ProviderNode> {
    let Some(obj) = value.get("providers").and_then(Value::as_object) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for (key, item) in obj {
        let provider = provider_name(key, &json_string(item, "name")).to_string();
        if provider == "default" {
            continue;
        }
        for proxy in item
            .get("proxies")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let name = json_string(proxy, "name");
            let kind = json_string(proxy, "type");
            if name.is_empty() || is_group_kind(&kind) {
                continue;
            }
            let delay = proxy
                .get("history")
                .and_then(Value::as_array)
                .and_then(|arr| arr.last())
                .and_then(|h| h.get("delay"))
                .and_then(Value::as_u64)
                .and_then(|d| if d > 0 { Some(d as u16) } else { None });
            out.push(ProviderNode {
                name,
                kind,
                udp: proxy.get("udp").and_then(Value::as_bool).unwrap_or(false),
                delay,
                provider: provider.clone(),
            });
        }
    }
    out
}

/// A provider's name: its `name`, or its key when that is empty.
pub(crate) fn provider_name<'a>(key: &'a str, named: &'a str) -> &'a str {
    if named.is_empty() {
        key
    } else {
        named
    }
}

/// Proxy types that are groups, not nodes, in a provider's `proxies`.
pub(crate) fn is_group_kind(kind: &str) -> bool {
    ["selector", "urltest", "fallback", "loadbalance", "relay"]
        .contains(&kind.to_ascii_lowercase().as_str())
}

pub fn parse_dns_message(body: &str) -> Result<DnsMessage, String> {
    let value: Value = serde_json::from_str(body).map_err(|err| err.to_string())?;
    let status = value
        .get("Status")
        .or_else(|| value.get("status"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let answers = value
        .get("Answer")
        .or_else(|| value.get("answer"))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| {
                    let data = item
                        .get("data")
                        .or_else(|| item.get("Data"))
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    if data.is_empty() {
                        return None;
                    }
                    let type_num = item
                        .get("type")
                        .or_else(|| item.get("Type"))
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    Some(DnsAnswer {
                        qtype: dns_type_name(type_num),
                        ttl: item
                            .get("TTL")
                            .or_else(|| item.get("ttl"))
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                        data,
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(DnsMessage { status, answers })
}

pub fn explain_rules(rules: &[RuleInfo], raw: &str) -> ExplainReport {
    let target = parse_probe_target(raw);
    let mut uncertain = Vec::new();
    let mut partial = false;
    for rule in rules {
        let step = judge_rule(rule, &target);
        match step.outcome {
            ExplainOutcome::Hit => {
                return ExplainReport {
                    target: target.raw,
                    host: target.host,
                    matched: Some(step),
                    partial,
                    uncertain,
                };
            }
            ExplainOutcome::Skip => {
                partial = true;
                if uncertain.len() < 8 {
                    uncertain.push(step);
                }
            }
            ExplainOutcome::Miss => {}
        }
    }
    ExplainReport {
        target: target.raw,
        host: target.host,
        matched: None,
        partial,
        uncertain,
    }
}

pub fn parse_probe_target(raw: &str) -> ProbeTarget {
    let raw_trim = raw.trim();
    if let Some(rest) = raw_trim
        .strip_prefix("process:")
        .or_else(|| raw_trim.strip_prefix("PROCESS:"))
    {
        return ProbeTarget {
            raw: raw_trim.to_string(),
            host: String::new(),
            port: None,
            network: None,
            process: Some(rest.trim().to_string()),
            is_ip: false,
            delay_url: String::new(),
        };
    }

    if let Some((scheme, rest)) = raw_trim.split_once("://") {
        let scheme = scheme.to_ascii_lowercase();
        if scheme == "http" || scheme == "https" {
            let hostport = rest.split(['/', '?', '#']).next().unwrap_or(rest);
            let default_port = if scheme == "https" {
                Some(443)
            } else {
                Some(80)
            };
            let (host, port) = split_host_port(hostport, default_port);
            return ProbeTarget {
                raw: raw_trim.to_string(),
                host: host.clone(),
                port,
                network: Some("tcp".into()),
                process: None,
                is_ip: is_ip_literal(&host),
                delay_url: raw_trim.to_string(),
            };
        }
        if scheme == "tcp" || scheme == "udp" {
            let hostport = rest.split(['/', '?', '#']).next().unwrap_or(rest);
            let (host, port) = split_host_port(hostport, None);
            let delay_url = match port {
                Some(port) if !host.is_empty() => format!("http://{host}:{port}"),
                _ if !host.is_empty() => format!("http://{host}"),
                _ => String::new(),
            };
            return ProbeTarget {
                raw: raw_trim.to_string(),
                host: host.clone(),
                port,
                network: Some(scheme),
                process: None,
                is_ip: is_ip_literal(&host),
                delay_url,
            };
        }
    }

    let hostport = raw_trim.split(['/', '?', '#']).next().unwrap_or(raw_trim);
    let (host, port) = split_host_port(hostport, None);
    let delay_url = match port {
        Some(port) if !host.is_empty() => format!("http://{host}:{port}"),
        _ if !host.is_empty() => format!("http://{host}"),
        _ => String::new(),
    };
    ProbeTarget {
        raw: raw_trim.to_string(),
        host: host.clone(),
        port,
        network: None,
        process: None,
        is_ip: is_ip_literal(&host),
        delay_url,
    }
}

pub fn list_profiles(config_dir: &Path, extra_dir: &Path, active_name: &str) -> Vec<ProfileEntry> {
    let mut found = Vec::new();
    for dir in [config_dir, extra_dir]
        .into_iter()
        .enumerate()
        .filter_map(|(i, d)| (i == 0 || d != config_dir).then_some(d))
    {
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if name.starts_with('.') || name.ends_with(".tmp") {
                continue;
            }
            let Some(ext) = path.extension().and_then(|s| s.to_str()) else {
                continue;
            };
            if !ext.eq_ignore_ascii_case("yaml") && !ext.eq_ignore_ascii_case("yml") {
                continue;
            }
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or(name)
                .to_string();
            let source = crate::compose::ProfileSource::load(&path.with_extension(""));
            let label = if source.name.is_empty() {
                stem.clone()
            } else {
                source.name
            };
            found.push(ProfileEntry {
                kind: "导入".into(),
                label,
                active: !active_name.is_empty() && stem == active_name,
                name: stem,
                path: path.display().to_string(),
            });
        }
    }
    found.sort_by(|a, b| b.active.cmp(&a.active).then(a.name.cmp(&b.name)));
    found
}

pub fn next_profile_filename(dir: &Path) -> String {
    for n in 1..1000 {
        let name = format!("profile-{n}.yaml");
        if !dir.join(&name).exists() {
            return name;
        }
    }
    "profile-1000.yaml".into()
}

pub fn normalize_rule_type(kind: &str) -> String {
    kind.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

pub fn is_runtime_tunnel(kind: &str) -> bool {
    let kind = kind.to_ascii_lowercase();
    kind.contains("wireguard") || kind == "wg" || kind.contains("tailscale")
}

pub fn short_stamp(value: &str) -> String {
    if value.is_empty() {
        return "—".into();
    }
    if let Some(time) = value.split('T').nth(1) {
        let time = time.trim_end_matches('Z');
        return time.chars().take(8).collect();
    }
    value.chars().take(16).collect()
}

pub fn ip_in_cidr(ip: &str, cidr: &str) -> Option<bool> {
    let (addr, prefix) = cidr.split_once('/')?;
    let prefix: u32 = prefix.trim().parse().ok()?;
    if ip.contains(':') || addr.contains(':') {
        let ip = parse_ipv6(ip)?;
        let net = parse_ipv6(addr.trim())?;
        if prefix > 128 {
            return None;
        }
        if prefix == 0 {
            return Some(true);
        }
        let mask = u128::MAX << (128 - prefix);
        return Some((ip & mask) == (net & mask));
    }
    let ip = parse_ipv4(ip)?;
    let net = parse_ipv4(addr.trim())?;
    if prefix > 32 {
        return None;
    }
    if prefix == 0 {
        return Some(true);
    }
    let mask = u32::MAX << (32 - prefix);
    Some((ip & mask) == (net & mask))
}

pub fn tun_patch_from_config(config: &serde_json::Value, enable: bool) -> Result<String, String> {
    let mut tun = config
        .get("tun")
        .and_then(serde_json::Value::as_object)
        .cloned()
        .ok_or("Mihomo did not return its TUN configuration")?;
    tun.insert("enable".into(), enable.into());
    Ok(serde_json::json!({"tun": tun}).to_string())
}

pub fn bool_patch_body(field: &str, enable: bool) -> String {
    format!(r#"{{"{field}":{enable}}}"#)
}

pub fn rule_disable_body(index: usize, disabled: bool) -> String {
    format!(r#"{{"{index}":{disabled}}}"#)
}

fn judge_rule(rule: &RuleInfo, target: &ProbeTarget) -> ExplainStep {
    let base = ExplainStep {
        index: rule.index,
        kind: rule.kind.clone(),
        payload: rule.payload.clone(),
        proxy: rule.proxy.clone(),
        outcome: ExplainOutcome::Miss,
        reason: String::new(),
    };
    if rule.disabled {
        return ExplainStep {
            outcome: ExplainOutcome::Miss,
            reason: "disabled".into(),
            ..base
        };
    }
    let kind = normalize_rule_type(&rule.kind);
    let payload = rule.payload.trim();
    let head = payload.split(',').next().unwrap_or(payload).trim();
    let host = target.host.to_ascii_lowercase();
    let (outcome, reason) = match kind.as_str() {
        "match" | "final" => (ExplainOutcome::Hit, "final".to_string()),
        "domain" => {
            if !target.is_ip && domain_eq(&host, head) {
                (ExplainOutcome::Hit, "domain".into())
            } else {
                (ExplainOutcome::Miss, String::new())
            }
        }
        "domainsuffix" => {
            if !target.is_ip && domain_suffix(&host, head) {
                (ExplainOutcome::Hit, "suffix".into())
            } else {
                (ExplainOutcome::Miss, String::new())
            }
        }
        "domainkeyword" => {
            if !target.is_ip && host.contains(&head.to_ascii_lowercase()) {
                (ExplainOutcome::Hit, "keyword".into())
            } else {
                (ExplainOutcome::Miss, String::new())
            }
        }
        "dstport" | "port" => match target.port {
            Some(port) if port_matches(port, head) => (ExplainOutcome::Hit, "port".into()),
            Some(_) => (ExplainOutcome::Miss, String::new()),
            None => (ExplainOutcome::Skip, "dst-port needs a port".into()),
        },
        "network" | "networktype" => match &target.network {
            Some(net) if net.eq_ignore_ascii_case(head) => (ExplainOutcome::Hit, "network".into()),
            Some(_) => (ExplainOutcome::Miss, String::new()),
            None => (ExplainOutcome::Skip, "network unknown".into()),
        },
        "ipcidr" | "ipcidr6" => judge_ip_cidr(target, payload, head),
        "srcipcidr" | "srcport" | "inport" | "srcgeoip" | "inboundport" => {
            (ExplainOutcome::Skip, "source not visible".into())
        }
        "geoip" => (ExplainOutcome::Skip, "geoip is evaluated in-core".into()),
        "geosite" => (ExplainOutcome::Skip, "geosite is evaluated in-core".into()),
        "ruleset" => (ExplainOutcome::Skip, "rule-set is evaluated in-core".into()),
        "domainregex" => (ExplainOutcome::Skip, "regex is evaluated in-core".into()),
        "processname" | "processpath" | "processnamereregex" => judge_process(target, &kind, head),
        "and" | "or" | "not" | "subrule" | "logic" => (
            ExplainOutcome::Skip,
            "logic rule is evaluated in-core".into(),
        ),
        _ => (ExplainOutcome::Skip, format!("{kind} is evaluated in-core")),
    };
    ExplainStep {
        outcome,
        reason,
        ..base
    }
}

fn judge_ip_cidr(target: &ProbeTarget, payload: &str, head: &str) -> (ExplainOutcome, String) {
    let no_resolve = payload.to_ascii_lowercase().contains("no-resolve");
    if target.is_ip {
        return match ip_in_cidr(&target.host, head) {
            Some(true) => (ExplainOutcome::Hit, "cidr".into()),
            Some(false) => (ExplainOutcome::Miss, String::new()),
            None => (ExplainOutcome::Skip, "cidr not parsed".into()),
        };
    }
    if no_resolve || target.host.is_empty() {
        (ExplainOutcome::Miss, String::new())
    } else {
        (
            ExplainOutcome::Skip,
            "ip-cidr needs a resolved address".into(),
        )
    }
}

fn judge_process(target: &ProbeTarget, kind: &str, head: &str) -> (ExplainOutcome, String) {
    let Some(process) = &target.process else {
        return (ExplainOutcome::Skip, "process not given".into());
    };
    let hit = if kind == "processpath" {
        process
            .to_ascii_lowercase()
            .contains(&head.to_ascii_lowercase())
    } else {
        process.eq_ignore_ascii_case(head)
    };
    if hit {
        (ExplainOutcome::Hit, "process".into())
    } else {
        (ExplainOutcome::Miss, String::new())
    }
}

fn domain_eq(host: &str, payload: &str) -> bool {
    normalize_domain(host) == normalize_domain(payload)
}

fn domain_suffix(host: &str, payload: &str) -> bool {
    let host = normalize_domain(host);
    let payload = normalize_domain(payload);
    host == payload || host.ends_with(&format!(".{payload}"))
}

fn normalize_domain(value: &str) -> String {
    value.trim().trim_matches('.').to_ascii_lowercase()
}

fn port_matches(port: u16, payload: &str) -> bool {
    payload.split([',', '/']).any(|part| {
        let part = part.trim();
        if let Some((start, end)) = part.split_once('-') {
            let Ok(start) = start.trim().parse::<u16>() else {
                return false;
            };
            let Ok(end) = end.trim().parse::<u16>() else {
                return false;
            };
            port >= start && port <= end
        } else {
            part.parse::<u16>().ok() == Some(port)
        }
    })
}

fn split_host_port(hostport: &str, default_port: Option<u16>) -> (String, Option<u16>) {
    if let Some(inner) = hostport.strip_prefix('[') {
        if let Some((host, rest)) = inner.split_once(']') {
            let port = rest
                .strip_prefix(':')
                .and_then(|value| value.parse().ok())
                .or(default_port);
            return (host.to_string(), port);
        }
    }
    if hostport.chars().filter(|c| *c == ':').count() > 1 {
        return (hostport.to_string(), default_port);
    }
    if let Some((host, port)) = hostport.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return (host.to_string(), Some(port));
        }
    }
    (hostport.to_string(), default_port)
}

fn is_ip_literal(host: &str) -> bool {
    parse_ipv4(host).is_some() || parse_ipv6(host).is_some()
}

fn parse_ipv4(value: &str) -> Option<u32> {
    let parts: Vec<&str> = value.trim().split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = 0u32;
    for part in parts {
        if part.is_empty() {
            return None;
        }
        let octet: u32 = part.parse().ok()?;
        if octet > 255 {
            return None;
        }
        out = (out << 8) | octet;
    }
    Some(out)
}

fn parse_ipv6(value: &str) -> Option<u128> {
    let value = value.trim().split('%').next().unwrap_or("").trim();
    if value.is_empty() {
        return None;
    }
    let (left, right, compressed) = if let Some((head, tail)) = value.split_once("::") {
        (head, tail, true)
    } else {
        (value, "", false)
    };
    let left = parse_v6_groups(left)?;
    let right = parse_v6_groups(right)?;
    let groups = if compressed {
        if left.len() + right.len() > 7 {
            return None;
        }
        let zeros = 8 - left.len() - right.len();
        let mut groups = left;
        groups.extend(std::iter::repeat(0u16).take(zeros));
        groups.extend(right);
        groups
    } else if left.len() == 8 {
        left
    } else {
        return None;
    };
    if groups.len() != 8 {
        return None;
    }
    let mut out = 0u128;
    for group in groups {
        out = (out << 16) | group as u128;
    }
    Some(out)
}

fn parse_v6_groups(part: &str) -> Option<Vec<u16>> {
    if part.is_empty() {
        return Some(Vec::new());
    }
    let bits: Vec<&str> = part.split(':').collect();
    let mut out = Vec::new();
    for (index, bit) in bits.iter().enumerate() {
        if bit.contains('.') {
            if index != bits.len() - 1 {
                return None;
            }
            let ip = parse_ipv4(bit)?;
            out.push((ip >> 16) as u16);
            out.push((ip & 0xffff) as u16);
        } else {
            if bit.is_empty() {
                return None;
            }
            out.push(u16::from_str_radix(bit, 16).ok()?);
        }
    }
    Some(out)
}

fn dns_type_name(value: u64) -> String {
    match value {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        other => other.to_string(),
    }
}

fn json_string(value: &Value, key: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

fn split_lines(doc: &str) -> Vec<String> {
    if doc.is_empty() {
        return Vec::new();
    }
    let mut lines: Vec<String> = doc
        .split('\n')
        .map(|line| line.trim_end_matches('\r').to_string())
        .collect();
    if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    lines
}

fn join_lines(lines: &[String]) -> String {
    if lines.is_empty() {
        return String::new();
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

pub(crate) fn split_chunks(doc: &str) -> Vec<YamlChunk> {
    let mut chunks = Vec::new();
    let mut current: Option<YamlChunk> = None;
    for line in split_lines(doc) {
        if let Some(key) = top_level_key(&line) {
            if let Some(chunk) = current.take() {
                chunks.push(chunk);
            }
            current = Some(YamlChunk {
                key: Some(key),
                lines: vec![line],
            });
        } else if let Some(chunk) = current.as_mut() {
            chunk.lines.push(line);
        } else {
            current = Some(YamlChunk {
                key: None,
                lines: vec![line],
            });
        }
    }
    if let Some(chunk) = current {
        chunks.push(chunk);
    }
    chunks
}

fn top_level_key(line: &str) -> Option<String> {
    if line.is_empty() || line.starts_with([' ', '\t', '#']) {
        return None;
    }
    let trimmed = line.trim();
    if trimmed == "---" || trimmed == "..." {
        return None;
    }
    let (key, _) = line.split_once(':')?;
    let key = key.trim();
    if key.is_empty() || key.contains(' ') || key.starts_with('-') {
        return None;
    }
    Some(key.to_string())
}

pub(crate) fn set_top_scalar(doc: &str, key: &str, literal: &str) -> String {
    let mut chunks = split_chunks(doc);
    if let Some(chunk) = chunks
        .iter_mut()
        .rev()
        .find(|chunk| chunk.key.as_deref().is_some_and(|name| name == key))
    {
        if let Some(line) = chunk.lines.first_mut() {
            *line = replace_scalar_line(line, literal);
        }
    } else {
        chunks.push(YamlChunk {
            key: Some(key.to_string()),
            lines: vec![format!("{key}: {literal}")],
        });
    }
    join_chunks(&chunks)
}

fn set_block_scalar(doc: &str, block: &str, key: &str, literal: &str) -> String {
    let mut chunks = split_chunks(doc);
    if let Some(chunk) = chunks
        .iter_mut()
        .rev()
        .find(|chunk| chunk.key.as_deref().is_some_and(|name| name == block))
    {
        // `dns: {enable: true, ...}`: a block line under it would be invalid.
        if let Some(line) = crate::compose::set_flow_scalar(&chunk.lines[0], key, literal) {
            chunk.lines[0] = line;
            return join_chunks(&chunks);
        }
        if let Some(pos) = chunk.lines.iter().rposition(|line| {
            line_key(line).is_some_and(|name| name == key)
                && leading_spaces(line)
                    == chunk
                        .lines
                        .iter()
                        .skip(1)
                        .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                        .map(|l| leading_spaces(l))
                        .min()
                        .unwrap_or(2)
        }) {
            chunk.lines[pos] = replace_scalar_line(&chunk.lines[pos], literal);
        } else {
            let indent = chunk
                .lines
                .iter()
                .skip(1)
                .find(|line| !line.trim().is_empty() && !line.trim().starts_with('#'))
                .map(|line| " ".repeat(leading_spaces(line).max(2)))
                .unwrap_or_else(|| "  ".into());
            chunk.lines.insert(1, format!("{indent}{key}: {literal}"));
        }
    } else {
        chunks.push(YamlChunk {
            key: Some(block.to_string()),
            lines: vec![format!("{block}:"), format!("  {key}: {literal}")],
        });
    }
    join_chunks(&chunks)
}

pub(crate) fn join_chunks(chunks: &[YamlChunk]) -> String {
    let mut lines = Vec::new();
    for chunk in chunks {
        lines.extend(chunk.lines.iter().cloned());
    }
    join_lines(&lines)
}

fn block_bool(lines: &[String], key: &str) -> Option<bool> {
    block_scalar(lines, key).and_then(|value| parse_yaml_bool(&value))
}

fn block_scalar(lines: &[String], key: &str) -> Option<String> {
    lines.iter().rev().find_map(|line| {
        if line_key(line).as_deref() == Some(key) {
            line.split_once(':').map(|(_, value)| clean_scalar(value))
        } else {
            None
        }
    })
}

fn line_key(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
        return None;
    }
    let (key, _) = trimmed.split_once(':')?;
    let key = key.trim();
    if key.is_empty() || key.contains(' ') {
        return None;
    }
    Some(key.to_string())
}

fn replace_scalar_line(line: &str, literal: &str) -> String {
    let Some((key, rest)) = line.split_once(':') else {
        return line.to_string();
    };
    let comment = rest
        .split_once('#')
        .map(|(_, comment)| format!(" #{comment}"))
        .unwrap_or_default();
    format!("{}: {literal}{comment}", key.trim_end())
}

fn split_kv(trimmed: &str) -> Option<(&str, &str)> {
    let (key, value) = trimmed.split_once(':')?;
    let key = key.trim();
    if key.is_empty() || key.starts_with('-') {
        return None;
    }
    Some((key, value.trim()))
}

pub(crate) fn clean_scalar(value: &str) -> String {
    let value = value.split('#').next().unwrap_or(value).trim();
    value
        .trim_matches('"')
        .trim_matches('\'')
        .trim()
        .to_string()
}

fn parse_yaml_bool(value: &str) -> Option<bool> {
    match clean_scalar(value).to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" => Some(true),
        "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

pub(crate) fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

pub fn modules_dir(home: &Path) -> PathBuf {
    home.join(".config/terc/modules")
}

pub fn profiles_dir(home: &Path) -> PathBuf {
    home.join(".config/terc/profiles")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subscription_accepts_providers_without_accepting_empty_or_commented_documents() {
        assert!(has_subscription_source("proxy-providers: {}\nrules: []\n"));
        assert!(has_subscription_source("proxies: []\n"));
        assert!(!has_subscription_source("# proxies: unavailable\n"));
        assert!(!has_subscription_source(""));
    }

    #[test]
    fn switches_edit_a_flow_style_block_in_place() {
        let doc =
            "dns: {enable: true, nameserver: [223.5.5.5]}\ntun: {}\nsniffer: {enable: false,}\n";
        let doc = set_nested_bool(doc, &["dns", "enable"], false);
        let doc = set_nested_bool(&doc, &["tun", "enable"], true);
        let doc = set_nested_bool(&doc, &["sniffer", "enable"], true);
        assert_eq!(
            doc,
            "dns: {enable: false, nameserver: [223.5.5.5]}\ntun: {enable: true}\nsniffer: {enable: true,}\n"
        );
        let doc = set_nested_bool(
            "dns: {nameserver: [223.5.5.5]} # x\n",
            &["dns", "enable"],
            true,
        );
        assert_eq!(doc, "dns: {nameserver: [223.5.5.5], enable: true} # x\n");
    }

    #[test]
    fn module_switches_survive_regeneration_and_disabling_restores_source() {
        let base = "tun:\n  enable: false\n  stack: system\n  mtu: 1400\ndns:\n  enable: false\n  nameserver:\n    - 1.1.1.1\n";
        let modules = builtin_modules();
        let applied = apply_enabled_modules(base, &modules).unwrap();
        assert_eq!(applied.lines().filter(|l| *l == "tun:").count(), 1);
        assert!(applied.contains("mtu: 1400"));
        let off = set_nested_bool(&applied, &["tun", "enable"], false);
        let regenerated = apply_enabled_modules(&off, &modules[..2]).unwrap();
        assert!(!parse_yaml_flags(&regenerated).tun_enabled);
        assert!(parse_yaml_flags(&regenerated).sniffing);
        let restored = apply_enabled_modules(&regenerated, &[]).unwrap();
        assert!(!restored.contains(BASE_PREFIX));
        assert!(restored.contains("stack: system"));
        assert!(restored.contains("mtu: 1400"));
        assert!(!parse_yaml_flags(&restored).tun_enabled);
    }

    #[test]
    fn dns_modules_stay_on_loopback_and_drop_a_source_fallback() {
        let source = "dns:\n  enable: false\n  listen: 0.0.0.0:53\n  ipv6: true\n  nameserver:\n    - 114.114.114.114\n  fallback:\n    - tls://8.8.8.8\nproxies: []\n";
        let catalog = builtin_modules();
        let pick = |id: &str| enabled_snippets(&catalog, &[id.to_string()]);
        for (id, nameserver) in [
            ("dns-fakeip", "https://doh.pub/dns-query"),
            ("dns-fakeip-global", "https://dns.google/dns-query"),
        ] {
            let applied = apply_enabled_modules(source, &pick(id)).unwrap();
            let dns = parse_dns_block(&applied);
            assert!(dns.enable, "{id}");
            assert_eq!(dns.listen, "127.0.0.1:1053", "{id}");
            assert_eq!(dns.enhanced_mode, "fake-ip", "{id}");
            assert_eq!(
                dns.nameservers.first().map(String::as_str),
                Some(nameserver)
            );
            assert!(dns.fallback.is_empty(), "{id}: {applied}");
            assert!(!applied.contains("tls://8.8.8.8\n"), "{id}");
            // Node hostnames never wait on foreign DoH.
            assert!(applied.contains(
                "proxy-server-nameserver:\n    - https://doh.pub/dns-query\n    - https://dns.alidns.com/dns-query\n"
            ));
            assert!(applied.contains("default-nameserver:\n    - 223.5.5.5\n"));
            assert!(applied.contains("    - \"+.local\"\n"));
            // Keys the module does not name are the source's.
            assert!(applied.contains("  ipv6: true\n"));
            assert_eq!(strip_marked_modules(&applied), source);
        }
        let global = apply_enabled_modules(source, &pick("dns-fakeip-global")).unwrap();
        assert!(global.contains("  respect-rules: true\n"));
        let mainland = apply_enabled_modules("proxies: []\n", &pick("dns-fakeip")).unwrap();
        assert!(!mainland.contains("respect-rules"));
        assert!(!mainland.contains("dns.google"));
    }

    #[test]
    fn nested_overlay_merges_maps_and_replaces_sequences() {
        let base = "sniffer:\n  enable: false\n  sniff:\n    TLS:\n      ports: [443]\n    HTTP:\n      ports: [80]\n";
        let overlay = ModuleSnippet {
            id: "custom".into(),
            name: "Custom".into(),
            description: String::new(),
            builtin: false,
            body: "sniffer:\n  enable: true\n  sniff:\n    HTTP:\n      ports: [8080]\n".into(),
        };
        let merged = apply_enabled_modules(base, &[overlay]).unwrap();
        let effective = merged.lines().skip(2).collect::<Vec<_>>().join("\n");
        assert!(effective.contains("ports: [443]"));
        assert!(effective.contains("ports: [8080]"));
        assert!(!effective.contains("ports: [80]"));
        assert_eq!(effective.lines().filter(|l| l.trim() == "HTTP:").count(), 1);
    }

    #[test]
    fn module_merge_and_strip_restores_original() {
        let base = "\
dns:
  enable: false
  listen: 127.0.0.1:1053
proxies: []
";
        let module = ModuleSnippet {
            id: "dns-fakeip".into(),
            name: "DNS".into(),
            description: String::new(),
            body: "\
dns:
  enable: true
  enhanced-mode: fake-ip"
                .into(),
            builtin: true,
        };
        let applied = apply_enabled_modules(base, &[module]).unwrap();
        assert!(applied.starts_with(BASE_PREFIX));
        assert_eq!(applied.lines().filter(|l| *l == "dns:").count(), 1);
        assert!(applied.contains("listen: 127.0.0.1:1053"));
        assert!(parse_dns_block(&applied).enable);
        assert_eq!(parse_dns_block(&applied).enhanced_mode, "fake-ip");

        let restored = apply_enabled_modules(&applied, &[]).unwrap();
        assert!(!restored.contains("terc-module"));
        assert!(!parse_dns_block(&restored).enable);
        assert!(restored.contains("proxies: []"));
    }

    #[test]
    fn nested_bool_updates_last_block_and_keeps_comment() {
        let doc = "\
ipv6: false # keep
tun:
  enable: false
  stack: system
# terc-module:begin tun
tun:
  enable: false
  stack: mixed
# terc-module:end tun
";
        let updated = set_nested_bool(doc, &["tun", "enable"], true);
        assert!(updated.contains("enable: true"));
        assert!(updated.contains("stack: system"));
        assert!(updated.contains("stack: mixed"));
        let flags = parse_yaml_flags(&updated);
        assert!(flags.tun_enabled);
        assert_eq!(flags.tun_stack, "mixed");

        let ipv6 = set_nested_bool(doc, &["ipv6"], true);
        assert!(ipv6.contains("ipv6: true # keep"));
    }

    #[test]
    fn general_json_overrides_yaml_flags_without_dropping_dns() {
        let mut flags = parse_yaml_flags(
            "\
tun:
  enable: false
  stack: system
sniffer:
  enable: false
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver:
    - tls://1.1.1.1
ipv6: false
",
        );
        let value = serde_json::json!({
            "tun": {"enable": true, "stack": "Mixed", "device": "utun7"},
            "sniffing": true,
            "ipv6": true,
            "tcp-concurrent": true,
            "find-process-mode": "always"
        });
        apply_general_json(&mut flags, &value);
        assert!(flags.tun_enabled);
        assert_eq!(flags.tun_stack, "Mixed");
        assert_eq!(flags.tun_device, "utun7");
        assert!(flags.sniffing && flags.ipv6 && flags.tcp_concurrent);
        assert_eq!(flags.find_process, "always");
        assert_eq!(flags.dns.nameservers, vec!["tls://1.1.1.1".to_string()]);
    }

    #[test]
    fn explain_stops_at_suffix_and_marks_earlier_geosite_partial() {
        let rules = vec![
            rule(0, "GEOSITE", "cn", "DIRECT", false),
            rule(1, "DOMAIN-SUFFIX", "Example.COM", "Proxy", false),
            rule(2, "MATCH", "", "DIRECT", false),
        ];
        let report = explain_rules(&rules, "a.example.com:443");
        let matched = report.matched.expect("suffix");
        assert_eq!(matched.index, 1);
        assert_eq!(matched.proxy, "Proxy");
        assert!(report.partial);
        assert_eq!(report.uncertain.len(), 1);
    }

    #[test]
    fn explain_skips_disabled_rule_and_matches_cidr() {
        let rules = vec![
            rule(3, "DOMAIN", "one.test", "Proxy", true),
            rule(4, "IP-CIDR", "10.0.0.0/8,no-resolve", "LAN", false),
            rule(5, "MATCH", "", "DIRECT", false),
        ];
        let domain = explain_rules(&rules, "one.test");
        assert_eq!(domain.matched.unwrap().index, 5);
        let ip = explain_rules(&rules, "10.1.2.3");
        assert_eq!(ip.matched.unwrap().proxy, "LAN");
        assert!(!ip.partial);
    }

    #[test]
    fn explain_matches_process_target() {
        let rules = vec![rule(0, "PROCESS-NAME", "curl", "DIRECT", false)];
        let report = explain_rules(&rules, "process:curl");
        assert_eq!(report.matched.unwrap().reason, "process");
    }

    #[test]
    fn ipv6_cidr_and_mapped_address() {
        assert_eq!(ip_in_cidr("2001:db8::1", "2001:db8::/32"), Some(true));
        assert_eq!(ip_in_cidr("2001:db9::1", "2001:db8::/32"), Some(false));
        assert_eq!(
            parse_ipv6("::ffff:192.0.2.1"),
            Some((0xffffu128 << 32) | parse_ipv4("192.0.2.1").unwrap() as u128)
        );
    }

    #[test]
    fn parses_rules_and_providers() {
        let rules = parse_rules_json(
            r#"{"rules":[{"index":2,"type":"DOMAIN-SUFFIX","payload":"a.test","proxy":"P","size":-1,"extra":{"disabled":true,"hitCount":9,"hitAt":"2026-01-02T03:04:05Z"}}]}"#,
        );
        assert_eq!(rules.len(), 1);
        assert!(rules[0].disabled);
        assert_eq!(rules[0].hit_count, 9);
        assert_eq!(short_stamp(&rules[0].hit_at), "03:04:05");

        let proxies = parse_providers_json(
            r#"{"providers":{"b":{"name":"","vehicleType":"File","proxies":[{},{}]},"a":{"name":"alpha","vehicleType":"HTTP","updatedAt":"t","proxies":[{}]},"default":{"name":"default","vehicleType":"Compatible","proxies":[{}]}}}"#,
            "proxy",
        );
        assert_eq!(proxies.len(), 2);
        assert_eq!(proxies[0].name, "alpha");
        assert_eq!(proxies[1].name, "b");
        assert_eq!(proxies[1].count, 2);
    }

    #[test]
    fn provider_nodes_skip_default_provider_and_groups() {
        let nodes = parse_provider_nodes(
            r#"{"providers":{
                "default":{"name":"default","vehicleType":"Compatible","proxies":[{"name":"inline","type":"Shadowsocks"},{"name":"Auto","type":"URLTest"}]},
                "air":{"name":"air","vehicleType":"HTTP","proxies":[
                    {"name":"JP 01","type":"Vmess","udp":true,"history":[{"delay":0},{"delay":88}]},
                    {"name":"US 01","type":"Trojan","history":[{"delay":120},{"delay":0}]},
                    {"name":"Inner","type":"Selector","all":["JP 01"]},
                    {"name":"Chain","type":"Relay"}
                ]}
            }}"#,
        );
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "JP 01");
        assert_eq!(nodes[0].kind, "Vmess");
        assert!(nodes[0].udp);
        assert_eq!(nodes[0].delay, Some(88));
        assert_eq!(nodes[0].provider, "air");
        assert_eq!(nodes[1].name, "US 01");
        assert!(!nodes[1].udp);
        assert_eq!(nodes[1].delay, None);
        assert!(parse_provider_nodes("not json").is_empty());
    }

    #[test]
    fn parses_dns_answers_case_insensitively() {
        let msg = parse_dns_message(
            r#"{"status":0,"answer":[{"name":"a.test.","type":1,"ttl":30,"Data":"1.2.3.4"}]}"#,
        )
        .unwrap();
        assert_eq!(msg.answers[0].qtype, "A");
        assert_eq!(msg.answers[0].data, "1.2.3.4");
        assert_eq!(msg.answers[0].ttl, 30);
    }

    #[test]
    fn probe_target_splits_url_host_and_port() {
        let url = parse_probe_target("https://Example.com/health");
        assert_eq!(url.host, "Example.com");
        assert_eq!(url.port, Some(443));
        assert_eq!(url.delay_url, "https://Example.com/health");

        let plain = parse_probe_target("one.test:8443");
        assert_eq!(plain.port, Some(8443));
        assert_eq!(plain.delay_url, "http://one.test:8443");
        assert!(!plain.is_ip);
    }

    #[test]
    fn profiles_and_user_modules_round_trip_on_disk() {
        let root = std::env::temp_dir().join(format!("terc-ops-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let config_dir = root.join("mihomo");
        let profiles = root.join("profiles");
        let modules = root.join("modules");
        fs::create_dir_all(&config_dir).unwrap();
        fs::create_dir_all(&profiles).unwrap();
        fs::create_dir_all(&modules).unwrap();
        fs::write(config_dir.join("config.yaml"), "proxies: []\n").unwrap();
        fs::write(config_dir.join("config.yaml.tmp"), "skip").unwrap();
        fs::write(profiles.join("work.yaml"), "mode: rule\n").unwrap();
        fs::write(profiles.join("notes.txt"), "no").unwrap();
        fs::write(
            modules.join("tun.yaml"),
            "# name: Local TUN\n# description: custom\ntun:\n  enable: true\n",
        )
        .unwrap();

        let listed = list_profiles(&config_dir, &profiles, "work");
        assert!(listed.iter().any(|p| p.name == "work" && p.active));
        assert!(listed.iter().any(|p| p.name == "config" && !p.active));
        assert!(!listed
            .iter()
            .any(|p| p.path.contains(".tmp") || p.name == "notes"));
        assert_eq!(next_profile_filename(&profiles), "profile-1.yaml");

        let user = load_user_modules(&modules);
        assert_eq!(user[0].id, "local-tun");
        assert_eq!(user[0].name, "Local TUN");
        assert_eq!(user[0].description, "custom");
        assert!(!user[0].body.contains("# name:"));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn patch_bodies_only_touch_the_requested_field() {
        let current = serde_json::json!({"tun": {"enable": false, "stack": "mixed", "mtu": 1400, "auto-route": true, "dns-hijack": ["any:53"]}, "mode": "direct"});
        let patch: serde_json::Value =
            serde_json::from_str(&tun_patch_from_config(&current, true).unwrap()).unwrap();
        let mut expected = current["tun"].clone();
        expected["enable"] = true.into();
        assert_eq!(patch, serde_json::json!({"tun": expected}));
        assert!(tun_patch_from_config(&serde_json::json!({}), true).is_err());
        assert_eq!(bool_patch_body("sniffing", false), r#"{"sniffing":false}"#);
        assert_eq!(rule_disable_body(4, true), r#"{"4":true}"#);
    }

    #[test]
    fn manifest_stays_free_of_heavy_net_deps() {
        let toml = include_str!("../Cargo.toml");
        assert!(!toml.contains("tokio"));
        assert!(!toml.contains("reqwest"));
        assert!(!toml.contains("openssl"));
    }

    fn rule(index: usize, kind: &str, payload: &str, proxy: &str, disabled: bool) -> RuleInfo {
        RuleInfo {
            index,
            kind: kind.into(),
            payload: payload.into(),
            proxy: proxy.into(),
            size: -1,
            disabled,
            hit_count: 0,
            hit_at: String::new(),
        }
    }
}
