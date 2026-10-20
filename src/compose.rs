//! terc-owned configuration: subscription nodes + the user's own nodes +
//! private rules + the built-in AI preset, composed into one Mihomo config.
//!
//! Files under `~/.config/terc/` (all hand-editable):
//! - `rules.conf`  private rules and AI routing settings
//! - `nodes.conf`  user-owned nodes, one Surge line or URI per line
//! - `subscription.cache`  last downloaded subscription body

use std::{
    collections::HashSet,
    fs,
    path::{Path, PathBuf},
};

use serde_json::{json, Value};

use crate::{
    ops::{clean_scalar, join_chunks, leading_spaces, split_chunks, YamlChunk},
    subconv::{convert_subscription, parse_node_line, Converted, SubFormat},
};

pub const GENERATED_MARK: &str =
    "# terc-generated: edit ~/.config/terc/rules.conf and nodes.conf instead of this file";

pub const DEFAULT_AI_FILTER: &str = "(?i)(🇺🇸|🇯🇵|🇸🇬|🇹🇼|美国|美國|日本|新加坡|狮城|獅城|台湾|台灣|\\b(US|USA|JP|SG|TW|SEA|LAX|SJC|NRT|HND|SIN|TPE)\\b|United States|Japan|Tokyo|Osaka|Singapore|Taiwan|Taipei|Seattle|Los Angeles|San Jose|Silicon Valley|New York|Chicago|Dallas|Ashburn)";
pub const DEFAULT_AI_EXCLUDE: &str =
    "(?i)(🇭🇰|港|\\bHK\\b|Hong ?Kong|🇨🇳|中国|回国|剩余|到期|流量|过期|官网|套餐|expire|traffic)";
const INFO_EXCLUDE: &str = "(?i)(剩余|到期|流量|过期|官网|套餐|expire|traffic)";

/// AI services routed to the AI group. Kept as data so the UI and docs agree.
pub const AI_PRESET: &[(&str, &[&str])] = &[
    (
        "OpenAI / ChatGPT / Sora",
        &[
            "DOMAIN-SUFFIX,openai.com",
            "DOMAIN-SUFFIX,chatgpt.com",
            "DOMAIN-SUFFIX,chat.com",
            "DOMAIN-SUFFIX,oaistatic.com",
            "DOMAIN-SUFFIX,oaiusercontent.com",
            "DOMAIN-SUFFIX,sora.com",
            "DOMAIN-SUFFIX,chatgpt.livekit.cloud",
            "DOMAIN-SUFFIX,openaiapi-site.azureedge.net",
            "DOMAIN-KEYWORD,openai",
        ],
    ),
    (
        "Anthropic / Claude",
        &[
            "DOMAIN-SUFFIX,anthropic.com",
            "DOMAIN-SUFFIX,claude.ai",
            "DOMAIN-SUFFIX,claude.com",
            "DOMAIN-SUFFIX,claudeusercontent.com",
        ],
    ),
    (
        "Google Gemini / AI Studio / NotebookLM",
        &[
            "DOMAIN-SUFFIX,gemini.google.com",
            "DOMAIN-SUFFIX,gemini.google",
            "DOMAIN-SUFFIX,bard.google.com",
            "DOMAIN-SUFFIX,aistudio.google.com",
            "DOMAIN-SUFFIX,ai.google.dev",
            "DOMAIN-SUFFIX,makersuite.google.com",
            "DOMAIN-SUFFIX,generativelanguage.googleapis.com",
            "DOMAIN-SUFFIX,alkalimakersuite-pa.clients6.google.com",
            "DOMAIN-SUFFIX,notebooklm.google",
            "DOMAIN-SUFFIX,notebooklm.google.com",
            "DOMAIN-SUFFIX,labs.google",
            "DOMAIN-SUFFIX,deepmind.com",
            "DOMAIN-SUFFIX,deepmind.google",
        ],
    ),
    (
        "xAI / Grok",
        &["DOMAIN-SUFFIX,x.ai", "DOMAIN-SUFFIX,grok.com"],
    ),
    (
        "Perplexity",
        &["DOMAIN-SUFFIX,perplexity.ai", "DOMAIN-SUFFIX,pplx.ai"],
    ),
    (
        "Cursor",
        &[
            "DOMAIN-SUFFIX,cursor.com",
            "DOMAIN-SUFFIX,cursor.sh",
            "DOMAIN-SUFFIX,cursorapi.com",
            "DOMAIN-SUFFIX,cursor-cdn.com",
        ],
    ),
    (
        "GitHub Copilot",
        &[
            "DOMAIN-SUFFIX,githubcopilot.com",
            "DOMAIN,copilot-proxy.githubusercontent.com",
            "DOMAIN,origin-tracker.githubusercontent.com",
            "DOMAIN,copilot-telemetry.githubusercontent.com",
        ],
    ),
    (
        "Microsoft Copilot / Bing",
        &[
            "DOMAIN-SUFFIX,copilot.microsoft.com",
            "DOMAIN-SUFFIX,copilot.cloud.microsoft",
            "DOMAIN-SUFFIX,bing.com",
            "DOMAIN-SUFFIX,bingapis.com",
        ],
    ),
    ("Midjourney", &["DOMAIN-SUFFIX,midjourney.com"]),
    (
        "Hugging Face",
        &[
            "DOMAIN-SUFFIX,huggingface.co",
            "DOMAIN-SUFFIX,hf.co",
            "DOMAIN-SUFFIX,hf.space",
        ],
    ),
    (
        "Poe",
        &["DOMAIN-SUFFIX,poe.com", "DOMAIN-SUFFIX,poecdn.net"],
    ),
    (
        "Meta AI / Mistral / Cohere / Groq",
        &[
            "DOMAIN-SUFFIX,meta.ai",
            "DOMAIN-SUFFIX,mistral.ai",
            "DOMAIN-SUFFIX,cohere.com",
            "DOMAIN-SUFFIX,cohere.ai",
            "DOMAIN-SUFFIX,groq.com",
        ],
    ),
    (
        "OpenRouter / Together / Replicate",
        &[
            "DOMAIN-SUFFIX,openrouter.ai",
            "DOMAIN-SUFFIX,together.ai",
            "DOMAIN-SUFFIX,replicate.com",
        ],
    ),
    (
        "Windsurf / Codeium / v0",
        &[
            "DOMAIN-SUFFIX,windsurf.com",
            "DOMAIN-SUFFIX,codeium.com",
            "DOMAIN-SUFFIX,v0.dev",
        ],
    ),
    (
        "Character.AI / Suno / ElevenLabs / Runway",
        &[
            "DOMAIN-SUFFIX,character.ai",
            "DOMAIN-SUFFIX,suno.com",
            "DOMAIN-SUFFIX,suno.ai",
            "DOMAIN-SUFFIX,elevenlabs.io",
            "DOMAIN-SUFFIX,runwayml.com",
        ],
    ),
];

const LAN_RULES: &[&str] = &[
    "DOMAIN-SUFFIX,local",
    "DOMAIN-SUFFIX,lan",
    "DOMAIN,localhost",
    "IP-CIDR,127.0.0.0/8,no-resolve",
    "IP-CIDR,10.0.0.0/8,no-resolve",
    "IP-CIDR,172.16.0.0/12,no-resolve",
    "IP-CIDR,192.168.0.0/16,no-resolve",
    "IP-CIDR,100.64.0.0/10,no-resolve",
    "IP-CIDR,169.254.0.0/16,no-resolve",
    "IP-CIDR6,::1/128,no-resolve",
    "IP-CIDR6,fc00::/7,no-resolve",
    "IP-CIDR6,fe80::/10,no-resolve",
];

const CN_RULES: &[&str] = &["DOMAIN-SUFFIX,cn", "GEOIP,CN"];

/// Rule types the TUI editor accepts; hand edits may use any Mihomo type.
pub const SIMPLE_RULE_TYPES: &[&str] = &[
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN",
    "IP-CIDR",
    "IP-CIDR6",
    "GEOIP",
    "PROCESS-NAME",
];

pub const POLICY_TARGETS: &[&str] = &["PROXY", "AI", "AUTO", "DIRECT", "REJECT"];

pub fn terc_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("terc")
}

pub fn rules_path(dir: &Path) -> PathBuf {
    dir.join("rules.conf")
}

pub fn nodes_path(dir: &Path) -> PathBuf {
    dir.join("nodes.conf")
}

pub fn cache_path(dir: &Path) -> PathBuf {
    dir.join("subscription.cache")
}

/// Write a file readable only by the user (nodes and subscriptions hold secrets).
pub fn write_private(path: &Path, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, text).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600));
    }
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

// ------------------------------------------------------------ rules.conf

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AiSettings {
    pub enabled: bool,
    /// `url-test` or `fallback`.
    pub kind: String,
    /// Explicit node / group names; empty means "pick by filter".
    pub members: Vec<String>,
    pub filter: String,
    pub exclude: String,
}

impl Default for AiSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            kind: "url-test".into(),
            members: Vec::new(),
            filter: DEFAULT_AI_FILTER.into(),
            exclude: DEFAULT_AI_EXCLUDE.into(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateRules {
    pub ai: AiSettings,
    pub subscription_rules: bool,
    pub cn_direct: bool,
    pub rules: Vec<String>,
}

impl Default for PrivateRules {
    fn default() -> Self {
        Self {
            ai: AiSettings::default(),
            subscription_rules: false,
            cn_direct: true,
            rules: Vec::new(),
        }
    }
}

impl PrivateRules {
    pub fn parse(text: &str) -> Self {
        let mut out = Self::default();
        let mut section = String::from("rules");
        for raw in text.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                section = line[1..line.len() - 1].trim().to_ascii_lowercase();
                continue;
            }
            if section == "rules" {
                out.rules.push(line.to_string());
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim().to_ascii_lowercase();
            // Allow trailing "  # comment" on setting lines.
            let value = match value.find(" #").or_else(|| value.find("\t#")) {
                Some(at) => value[..at].trim(),
                None => value.trim(),
            };
            let flag = matches!(
                value.to_ascii_lowercase().as_str(),
                "true" | "1" | "yes" | "on"
            );
            match (section.as_str(), key.as_str()) {
                ("ai", "enabled") => out.ai.enabled = flag,
                ("ai", "type") => {
                    out.ai.kind = if value.eq_ignore_ascii_case("fallback") {
                        "fallback".into()
                    } else {
                        "url-test".into()
                    }
                }
                ("ai", "members") => {
                    out.ai.members = value
                        .split('|')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                }
                ("ai", "filter") => out.ai.filter = value.to_string(),
                ("ai", "exclude") => out.ai.exclude = value.to_string(),
                ("options", "subscription-rules") => out.subscription_rules = flag,
                ("options", "cn-direct") => out.cn_direct = flag,
                _ => {}
            }
        }
        out
    }

    pub fn render(&self) -> String {
        let b = |v: bool| if v { "true" } else { "false" };
        let mut text = String::from(
            "# terc 私有规则 / private rules\n\
             # 在 terc 里按 R 管理，也可以直接编辑本文件，保存后在 terc 里按 R 再按 Enter 应用。\n\
             # Edit in terc with R, or by hand; then press R, Enter in terc to apply.\n\
             #\n\
             # [rules] 每行一条 TYPE,VALUE,TARGET[,no-resolve]，从上到下优先匹配。\n\
             # TARGET: PROXY（主选择组） AI（AI 组） AUTO（自动测速） DIRECT REJECT，或任意节点名/策略组名。\n\
             # [ai] members 用 | 分隔节点或策略组名；留空 = 按 filter 自动挑选（默认美/日/新/台，排除香港）。\n\n",
        );
        text.push_str("[ai]\n");
        text.push_str(&format!("enabled = {}\n", b(self.ai.enabled)));
        text.push_str(&format!("type = {}\n", self.ai.kind));
        text.push_str(&format!("members = {}\n", self.ai.members.join(" | ")));
        text.push_str(&format!("filter = {}\n", self.ai.filter));
        text.push_str(&format!("exclude = {}\n\n", self.ai.exclude));
        text.push_str("[options]\n");
        text.push_str(
            "# subscription-rules: 追加机场自带的策略组和规则（在私有规则与 AI 预设之后）\n",
        );
        text.push_str(&format!(
            "subscription-rules = {}\n",
            b(self.subscription_rules)
        ));
        text.push_str("# cn-direct: 国内域名与 GEOIP,CN 直连\n");
        text.push_str(&format!("cn-direct = {}\n\n", b(self.cn_direct)));
        text.push_str("[rules]\n");
        for rule in &self.rules {
            text.push_str(rule);
            text.push('\n');
        }
        text
    }

    pub fn load(dir: &Path) -> Self {
        match fs::read_to_string(rules_path(dir)) {
            Ok(text) => Self::parse(&text),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        write_private(&rules_path(dir), &self.render())
    }
}

/// Parse TUI rule input. Accepts `TYPE,VALUE,TARGET[,no-resolve]`,
/// `VALUE,TARGET`, or just `VALUE` (domain → DOMAIN-SUFFIX, CIDR → IP-CIDR).
pub fn parse_rule_input(input: &str) -> Result<String, String> {
    let parts: Vec<String> = input
        .split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    let alias = |k: &str| -> Option<&'static str> {
        let upper = k.to_ascii_uppercase();
        let canon = match upper.as_str() {
            "SUFFIX" | "DOMAIN-SUFFIX" | "HOST-SUFFIX" => "DOMAIN-SUFFIX",
            "KEYWORD" | "DOMAIN-KEYWORD" | "HOST-KEYWORD" => "DOMAIN-KEYWORD",
            "DOMAIN" | "HOST" => "DOMAIN",
            "IP" | "IP-CIDR" => "IP-CIDR",
            "IP6" | "IP-CIDR6" => "IP-CIDR6",
            "GEOIP" => "GEOIP",
            "PROCESS" | "PROCESS-NAME" => "PROCESS-NAME",
            _ => return None,
        };
        Some(canon)
    };
    let (kind, value, rest) = match parts.as_slice() {
        [] => return Err("规则为空 / empty rule".into()),
        [first, rest @ ..] if alias(first).is_some() && !rest.is_empty() => (
            alias(first).unwrap().to_string(),
            rest[0].clone(),
            rest[1..].to_vec(),
        ),
        [value, rest @ ..] => (guess_type(value).to_string(), value.clone(), rest.to_vec()),
    };
    if value.is_empty() {
        return Err("缺少匹配内容 / missing value".into());
    }
    let target = rest.first().cloned().unwrap_or_else(|| "PROXY".into());
    let target = match target.to_ascii_uppercase().as_str() {
        t @ ("PROXY" | "AI" | "AUTO" | "DIRECT" | "REJECT") => t.to_string(),
        _ => target,
    };
    let value = if kind == "GEOIP" {
        value.to_ascii_uppercase()
    } else {
        value
    };
    if kind.starts_with("IP-CIDR") && !value.contains('/') {
        return Err("IP-CIDR 需要网段，如 1.2.3.0/24 / IP-CIDR needs a prefix".into());
    }
    let mut rule = format!("{kind},{value},{target}");
    let no_resolve = rest
        .iter()
        .skip(1)
        .any(|p| p.eq_ignore_ascii_case("no-resolve"));
    if no_resolve || kind.starts_with("IP-CIDR") {
        rule.push_str(",no-resolve");
    }
    Ok(rule)
}

fn guess_type(value: &str) -> &'static str {
    if value.contains(':') && value.contains('/') {
        "IP-CIDR6"
    } else if value.contains('/')
        && value
            .chars()
            .all(|c| c.is_ascii_digit() || c == '.' || c == '/')
    {
        "IP-CIDR"
    } else {
        "DOMAIN-SUFFIX"
    }
}

/// Replace a rule's target (second field from the end, before `no-resolve`).
pub fn set_rule_target(rule: &str, target: &str) -> String {
    let mut parts: Vec<String> = rule.split(',').map(str::to_string).collect();
    let options = parts
        .iter()
        .rev()
        .take_while(|p| p.eq_ignore_ascii_case("no-resolve") || p.eq_ignore_ascii_case("src"))
        .count();
    let idx = parts.len().saturating_sub(options + 1);
    if parts.len() >= 3 {
        parts[idx] = target.to_string();
    }
    parts.join(",")
}

pub fn rule_target(rule: &str) -> String {
    let parts: Vec<&str> = rule.split(',').collect();
    let options = parts
        .iter()
        .rev()
        .take_while(|p| p.eq_ignore_ascii_case("no-resolve") || p.eq_ignore_ascii_case("src"))
        .count();
    parts
        .get(parts.len().saturating_sub(options + 1))
        .map(|s| s.to_string())
        .unwrap_or_default()
}

// ------------------------------------------------------------ nodes.conf

#[derive(Clone, Debug)]
pub struct ManualNode {
    pub line: String,
    pub parsed: Result<Value, String>,
}

impl ManualNode {
    pub fn name(&self) -> String {
        match &self.parsed {
            Ok(v) => v["name"].as_str().unwrap_or("?").to_string(),
            Err(_) => self
                .line
                .split_once('=')
                .filter(|_| !self.line.contains("://"))
                .map(|(n, _)| n.trim().to_string())
                .unwrap_or_else(|| "?".into()),
        }
    }
}

const NODES_HEADER: &str = "# terc 自有节点 / own nodes — 一行一个：Surge 节点行或 ss:// trojan:// vless:// vmess:// hysteria2:// tuic:// 链接\n# 只保存在本机，不会上传。Local only.\n";

pub fn load_manual_nodes(dir: &Path) -> Vec<ManualNode> {
    let text = fs::read_to_string(nodes_path(dir)).unwrap_or_default();
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        .map(|line| ManualNode {
            line: line.to_string(),
            parsed: parse_node_line(line),
        })
        .collect()
}

pub fn add_manual_node(dir: &Path, line: &str) -> Result<String, String> {
    let line = line.trim();
    let node = parse_node_line(line)?;
    let name = node["name"].as_str().unwrap_or("?").to_string();
    if load_manual_nodes(dir).iter().any(|n| n.name() == name) {
        return Err(format!("已有同名节点 / duplicate node name: {name}"));
    }
    let path = nodes_path(dir);
    let mut text = fs::read_to_string(&path).unwrap_or_else(|_| NODES_HEADER.to_string());
    if !text.is_empty() && !text.ends_with('\n') {
        text.push('\n');
    }
    text.push_str(line);
    text.push('\n');
    write_private(&path, &text)?;
    Ok(name)
}

/// Remove the n-th node line, keeping comments and other lines verbatim.
pub fn remove_manual_node(dir: &Path, index: usize) -> Result<String, String> {
    let path = nodes_path(dir);
    let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let mut seen = 0usize;
    let mut removed = None;
    let mut kept = Vec::new();
    for raw in text.lines() {
        let t = raw.trim();
        let is_node = !t.is_empty() && !t.starts_with('#') && !t.starts_with("//");
        if is_node {
            if seen == index {
                removed = Some(
                    ManualNode {
                        line: t.to_string(),
                        parsed: parse_node_line(t),
                    }
                    .name(),
                );
                seen += 1;
                continue;
            }
            seen += 1;
        }
        kept.push(raw.to_string());
    }
    let name = removed.ok_or("没有这个节点 / no such node")?;
    let mut out = kept.join("\n");
    out.push('\n');
    write_private(&path, &out)?;
    Ok(name)
}

// ------------------------------------------------------------ compose

#[derive(Clone, Debug, Default)]
pub struct ComposeReport {
    pub format: Option<SubFormat>,
    pub sub_nodes: usize,
    pub sub_skipped: Vec<String>,
    pub manual_nodes: usize,
    pub manual_skipped: Vec<String>,
    pub rule_skipped: Vec<String>,
    pub private_rules: usize,
    pub ai_enabled: bool,
    pub ai_group: String,
}

impl ComposeReport {
    pub fn skipped_total(&self) -> usize {
        self.sub_skipped.len() + self.manual_skipped.len() + self.rule_skipped.len()
    }

    pub fn summary(&self, zh: bool) -> String {
        let fmt = self.format.map(SubFormat::label).unwrap_or("-");
        let mut text = if zh {
            format!(
                "订阅 {fmt} {} 节点 · 自有 {} · 私有规则 {} · AI 预设{}",
                self.sub_nodes,
                self.manual_nodes,
                self.private_rules,
                if self.ai_enabled { "开" } else { "关" }
            )
        } else {
            format!(
                "{fmt} {} nodes · own {} · rules {} · AI preset {}",
                self.sub_nodes,
                self.manual_nodes,
                self.private_rules,
                if self.ai_enabled { "on" } else { "off" }
            )
        };
        let skipped = self.skipped_total();
        if skipped > 0 {
            text.push_str(&if zh {
                format!(" · 跳过 {skipped} 项（按 ! 看详情）")
            } else {
                format!(" · {skipped} skipped (press ! for details)")
            });
        }
        text
    }

    /// Skipped entries, one per line (names and types only, never secrets).
    pub fn details(&self) -> String {
        let all: Vec<&String> = self
            .sub_skipped
            .iter()
            .chain(&self.manual_skipped)
            .chain(&self.rule_skipped)
            .collect();
        let mut text = String::new();
        for item in all.iter().take(60) {
            text.push_str("\n  - ");
            text.push_str(item);
        }
        if all.len() > 60 {
            text.push_str(&format!("\n  … +{}", all.len() - 60));
        }
        text
    }
}

pub struct ComposeInput<'a> {
    pub subscription: Option<&'a Converted>,
    pub manual: &'a [ManualNode],
    pub rules: &'a PrivateRules,
    pub controller_addr: &'a str,
    pub secret: &'a str,
    pub test_url: &'a str,
}

fn template_base(addr: &str, secret: &str) -> String {
    let mut text = format!(
        "mixed-port: 7890\n\
allow-lan: false\n\
mode: rule\n\
log-level: info\n\
ipv6: false\n\
unified-delay: true\n\
tcp-concurrent: true\n\
find-process-mode: strict\n\
external-controller: {addr}\n"
    );
    if !secret.is_empty() {
        text.push_str(&format!("secret: {}\n", json!(secret)));
    }
    text.push_str(
        "geodata-mode: false\n\
geox-url:\n  mmdb: \"https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb\"\n\
profile:\n  store-selected: true\n\
sniffer:\n  enable: false\n  sniff:\n    HTTP:\n      ports: [80, 8080-8880]\n      override-destination: true\n    TLS:\n      ports: [443, 8443]\n    QUIC:\n      ports: [443, 8443]\n\
tun:\n  enable: false\n  stack: mixed\n  auto-route: true\n  auto-detect-interface: true\n  dns-hijack: [\"any:53\"]\n\
dns:\n  enable: true\n  ipv6: false\n  listen: 127.0.0.1:1053\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  fake-ip-filter: [\"*.lan\", \"+.local\", \"localhost\"]\n  default-nameserver: [223.5.5.5, 119.29.29.29]\n  nameserver: [\"https://doh.pub/dns-query\", \"https://dns.alidns.com/dns-query\"]\n",
    );
    text
}

fn yaml_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

/// Extract `name:` values of list items in a Clash YAML block (best effort).
pub(crate) fn clash_item_names(chunk: &YamlChunk) -> Vec<String> {
    let mut names = Vec::new();
    let item_indent = chunk
        .lines
        .iter()
        .skip(1)
        .find(|l| l.trim_start().starts_with('-'))
        .map(|l| leading_spaces(l));
    let Some(item_indent) = item_indent else {
        return names;
    };
    let mut pending = false;
    for line in chunk.lines.iter().skip(1) {
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let indent = leading_spaces(line);
        let body = if indent == item_indent && trimmed.starts_with('-') {
            pending = true;
            trimmed[1..].trim_start()
        } else if indent > item_indent && pending {
            trimmed
        } else {
            continue;
        };
        if let Some(inner) = body.strip_prefix('{') {
            if let Some(name) = flow_value(inner, "name") {
                names.push(name);
                pending = false;
            }
        } else if let Some(v) = body.strip_prefix("name:") {
            let v = v.split(" #").next().unwrap_or(v);
            names.push(clean_scalar(v));
            pending = false;
        }
    }
    names
}

fn flow_value(inner: &str, key: &str) -> Option<String> {
    let mut rest = inner;
    loop {
        let pos = rest.find(key)?;
        let before = rest[..pos].trim_end();
        let after = rest[pos + key.len()..].trim_start();
        let at_key = before.is_empty() || before.ends_with(',') || before.ends_with('{');
        if at_key {
            if let Some(v) = after.strip_prefix(':') {
                let v = v.trim_start();
                if let Some(q) = v.chars().next().filter(|c| *c == '"' || *c == '\'') {
                    let body = &v[1..];
                    let end = body.find(q)?;
                    return Some(body[..end].to_string());
                }
                let end = v.find([',', '}']).unwrap_or(v.len());
                return Some(v[..end].trim().to_string());
            }
        }
        rest = &rest[pos + key.len()..];
    }
}

fn clash_rule_items(chunk: &YamlChunk) -> Vec<String> {
    chunk
        .lines
        .iter()
        .skip(1)
        .filter_map(|l| {
            let t = l.trim_start();
            let v = t.strip_prefix('-')?.trim();
            if v.is_empty() || v.starts_with('#') {
                return None;
            }
            Some(clean_scalar(v))
        })
        .collect()
}

/// Append JSON flow items to a YAML list chunk, matching its item indent.
fn append_items(chunk: &mut YamlChunk, items: &[String]) -> Result<(), String> {
    let key = chunk.key.clone().unwrap_or_default();
    let inline = chunk.lines[0]
        .split_once(':')
        .map(|(_, v)| clean_scalar(v.split(" #").next().unwrap_or(v)))
        .unwrap_or_default();
    if !inline.is_empty() && inline != "[]" && inline != "null" && inline != "~" {
        return Err(format!("inline {key} list"));
    }
    if !inline.is_empty() {
        chunk.lines = vec![format!("{key}:")];
    }
    let indent = chunk
        .lines
        .iter()
        .skip(1)
        .find(|l| l.trim_start().starts_with('-'))
        .map(|l| " ".repeat(leading_spaces(l)))
        .unwrap_or_else(|| "  ".into());
    // Insert after the last non-blank line of the chunk.
    let mut at = chunk.lines.len();
    while at > 1 && chunk.lines[at - 1].trim().is_empty() {
        at -= 1;
    }
    for (i, item) in items.iter().enumerate() {
        chunk.lines.insert(at + i, format!("{indent}- {item}"));
    }
    Ok(())
}

fn pick_name(base: &str, taken: &HashSet<String>) -> String {
    if !taken.contains(base) {
        return base.to_string();
    }
    let mut name = format!("terc-{base}");
    let mut n = 2;
    while taken.contains(&name) {
        name = format!("terc-{base}-{n}");
        n += 1;
    }
    name
}

pub fn compose(input: &ComposeInput) -> Result<(String, ComposeReport), String> {
    let mut report = ComposeReport {
        ai_enabled: input.rules.ai.enabled,
        ..ComposeReport::default()
    };
    let sub = input.subscription;
    report.format = sub.and_then(|s| s.format);
    let keep_sub = input.rules.subscription_rules;

    // Base document and pre-existing names.
    let mut chunks = match sub.and_then(|s| s.clash_doc.as_deref()) {
        Some(doc) => split_chunks(doc),
        None => split_chunks(&template_base(input.controller_addr, input.secret)),
    };
    let drop_keys: &[&str] = if keep_sub {
        &["sub-rules"]
    } else {
        &["proxy-groups", "rules", "rule-providers", "sub-rules"]
    };
    chunks.retain(|c| {
        !c.key.as_deref().is_some_and(|k| drop_keys.contains(&k))
            && !(c.key.is_none()
                && c.lines
                    .iter()
                    .all(|l| l.trim().is_empty() || l.starts_with("# terc-generated")))
    });
    let has_providers = chunks
        .iter()
        .any(|c| c.key.as_deref() == Some("proxy-providers"));

    let mut node_names: HashSet<String> = HashSet::new();
    let mut sub_group_names: Vec<String> = Vec::new();
    let mut sub_rules: Vec<String> = Vec::new();
    if let Some(c) = chunks.iter().find(|c| c.key.as_deref() == Some("proxies")) {
        node_names.extend(clash_item_names(c));
    }
    if keep_sub {
        if let Some(c) = chunks
            .iter()
            .find(|c| c.key.as_deref() == Some("proxy-groups"))
        {
            sub_group_names = clash_item_names(c);
        }
        if let Some(pos) = chunks
            .iter()
            .position(|c| c.key.as_deref() == Some("rules"))
        {
            sub_rules = clash_rule_items(&chunks[pos]);
            chunks.remove(pos);
        }
    }
    let mut new_proxies: Vec<Value> = Vec::new();
    let mut new_groups: Vec<Value> = Vec::new();
    let mut providers: Vec<(String, Value)> = Vec::new();
    if let Some(s) = sub {
        report.sub_skipped = s.skipped.clone();
        if s.clash_doc.is_none() {
            for p in &s.proxies {
                if let Some(n) = p["name"].as_str() {
                    node_names.insert(n.to_string());
                }
                new_proxies.push(p.clone());
            }
            if keep_sub {
                for g in &s.groups {
                    if let Some(n) = g["name"].as_str() {
                        sub_group_names.push(n.to_string());
                    }
                    new_groups.push(g.clone());
                }
                sub_rules = s.rules.clone();
                providers = s.rule_providers.clone();
            }
        }
    }
    report.sub_nodes = node_names.len();

    // User-owned nodes join the proxy list (renamed on collision).
    let mut manual_names = Vec::new();
    for m in input.manual {
        match &m.parsed {
            Ok(v) => {
                let mut v = v.clone();
                let base = v["name"].as_str().unwrap_or("node").to_string();
                let mut name = base.clone();
                let mut n = 2;
                while node_names.contains(&name) || sub_group_names.contains(&name) {
                    name = format!("{base} ({n})");
                    n += 1;
                }
                v["name"] = json!(name);
                node_names.insert(name.clone());
                manual_names.push(name);
                new_proxies.push(v);
            }
            Err(reason) => report.manual_skipped.push(format!("nodes.conf: {reason}")),
        }
    }
    report.manual_nodes = manual_names.len();
    if node_names.is_empty() && !has_providers {
        return Err("没有可用节点：请添加订阅（u）或自有节点（N）/ No nodes: add a subscription or own node".into());
    }

    let mut taken: HashSet<String> = node_names.clone();
    taken.extend(sub_group_names.iter().cloned());
    let proxy_name = pick_name("PROXY", &taken);
    taken.insert(proxy_name.clone());
    let auto_name = pick_name("AUTO", &taken);
    taken.insert(auto_name.clone());
    let ai_name = pick_name("AI", &taken);
    taken.insert(ai_name.clone());
    report.ai_group = ai_name.clone();

    let test_url = if input.test_url.is_empty() {
        "https://www.gstatic.com/generate_204"
    } else {
        input.test_url
    };
    let ai = &input.rules.ai;
    let mut ai_group = json!({
        "name": ai_name,
        "type": ai.kind,
        "url": test_url,
        "interval": 300,
    });
    if ai.kind == "url-test" {
        ai_group["tolerance"] = json!(50);
    }
    let known_members: Vec<String> = ai
        .members
        .iter()
        .filter(|m| node_names.contains(*m) || sub_group_names.contains(m) || *m == &auto_name)
        .cloned()
        .collect();
    if !ai.members.is_empty() && known_members.len() < ai.members.len() {
        report.rule_skipped.push(format!(
            "AI members: {} not found",
            ai.members.len() - known_members.len()
        ));
    }
    if known_members.is_empty() {
        ai_group["include-all"] = json!(true);
        if !ai.filter.trim().is_empty() {
            ai_group["filter"] = json!(ai.filter);
        }
        let exclude = if ai.exclude.trim().is_empty() {
            INFO_EXCLUDE.to_string()
        } else {
            ai.exclude.clone()
        };
        ai_group["exclude-filter"] = json!(exclude);
    } else {
        ai_group["proxies"] = json!(known_members);
    }
    let mut proxy_members = vec![auto_name.clone(), ai_name.clone()];
    proxy_members.extend(sub_group_names.iter().cloned());
    proxy_members.push("DIRECT".into());
    let mut groups = vec![
        json!({
            "name": proxy_name,
            "type": "select",
            "proxies": proxy_members,
            "include-all": true,
            "exclude-filter": INFO_EXCLUDE,
        }),
        json!({
            "name": auto_name,
            "type": "url-test",
            "include-all": true,
            "exclude-filter": INFO_EXCLUDE,
            "url": test_url,
            "interval": 300,
            "tolerance": 50,
        }),
        ai_group,
    ];
    groups.extend(new_groups);

    // Rules, in priority order.
    let alias = |t: &str| -> String {
        match t.to_ascii_uppercase().as_str() {
            "PROXY" => proxy_name.clone(),
            "AI" => ai_name.clone(),
            "AUTO" => auto_name.clone(),
            "DIRECT" => "DIRECT".into(),
            "REJECT" => "REJECT".into(),
            "REJECT-DROP" => "REJECT-DROP".into(),
            _ => t.to_string(),
        }
    };
    let builtin = ["DIRECT", "REJECT", "REJECT-DROP", "PASS", "COMPATIBLE"];
    let mut rules: Vec<String> = Vec::new();
    for rule in &input.rules.rules {
        let target = rule_target(rule);
        let mapped = alias(&target);
        let known =
            builtin.contains(&mapped.as_str()) || taken.contains(&mapped) || mapped == proxy_name;
        if rule.split(',').count() < 3 || !known {
            report
                .rule_skipped
                .push(format!("rules.conf: {rule} (unknown target {target})"));
            continue;
        }
        if rule.to_ascii_uppercase().starts_with("MATCH,") {
            report
                .rule_skipped
                .push(format!("rules.conf: {rule} (MATCH is added by terc)"));
            continue;
        }
        rules.push(set_rule_target(rule, &mapped));
    }
    report.private_rules = rules.len();
    let with_target = |r: &str, target: &str| -> String {
        match r.strip_suffix(",no-resolve") {
            Some(head) => format!("{head},{target},no-resolve"),
            None => format!("{r},{target}"),
        }
    };
    if ai.enabled {
        for (_, list) in AI_PRESET {
            for r in *list {
                rules.push(with_target(r, &ai_name));
            }
        }
    }
    for r in LAN_RULES {
        rules.push(with_target(r, "DIRECT"));
    }
    for r in sub_rules {
        let upper = r.to_ascii_uppercase();
        if upper.starts_with("MATCH,") || upper.starts_with("FINAL,") {
            continue;
        }
        rules.push(r);
    }
    if input.rules.cn_direct {
        for r in CN_RULES {
            rules.push(with_target(r, "DIRECT"));
        }
    }
    rules.push(format!("MATCH,{proxy_name}"));

    // Assemble.
    let proxy_items: Vec<String> = new_proxies.iter().map(|v| v.to_string()).collect();
    match chunks
        .iter_mut()
        .find(|c| c.key.as_deref() == Some("proxies"))
    {
        Some(chunk) => {
            if !proxy_items.is_empty() {
                if let Err(e) = append_items(chunk, &proxy_items) {
                    return Err(format!(
                        "订阅使用了单行 proxies 列表，无法合并自有节点 / {e}"
                    ));
                }
            }
        }
        None => {
            let mut lines = vec!["proxies:".to_string()];
            lines.extend(proxy_items.iter().map(|i| format!("  - {i}")));
            if proxy_items.is_empty() {
                lines = vec!["proxies: []".into()];
            }
            chunks.push(YamlChunk {
                key: Some("proxies".into()),
                lines,
            });
        }
    }
    let group_items: Vec<String> = groups.iter().map(|v| v.to_string()).collect();
    match chunks
        .iter_mut()
        .find(|c| c.key.as_deref() == Some("proxy-groups"))
    {
        Some(chunk) => {
            // terc groups first so PROXY is the first group in every client.
            let indent = chunk
                .lines
                .iter()
                .skip(1)
                .find(|l| l.trim_start().starts_with('-'))
                .map(|l| " ".repeat(leading_spaces(l)))
                .unwrap_or_else(|| "  ".into());
            let inline = chunk.lines[0]
                .split_once(':')
                .map(|(_, v)| clean_scalar(v))
                .unwrap_or_default();
            if !inline.is_empty() && inline != "[]" && inline != "null" && inline != "~" {
                return Err("订阅使用了单行 proxy-groups，无法保留 / inline proxy-groups".into());
            }
            let mut lines = vec!["proxy-groups:".to_string()];
            lines.extend(group_items.iter().map(|i| format!("{indent}- {i}")));
            lines.extend(chunk.lines.iter().skip(1).cloned());
            chunk.lines = lines;
        }
        None => {
            let mut lines = vec!["proxy-groups:".to_string()];
            lines.extend(group_items.iter().map(|i| format!("  - {i}")));
            chunks.push(YamlChunk {
                key: Some("proxy-groups".into()),
                lines,
            });
        }
    }
    if !providers.is_empty() {
        let mut lines = vec!["rule-providers:".to_string()];
        for (name, v) in &providers {
            lines.push(format!("  {}: {}", yaml_str(name), v));
        }
        chunks.push(YamlChunk {
            key: Some("rule-providers".into()),
            lines,
        });
    }
    let mut lines = vec!["rules:".to_string()];
    lines.extend(rules.iter().map(|r| format!("  - {}", yaml_str(r))));
    chunks.push(YamlChunk {
        key: Some("rules".into()),
        lines,
    });
    let body = join_chunks(&chunks);
    let body = crate::mihomo::normalize_subscription(&body, input.controller_addr);
    Ok((format!("{GENERATED_MARK}\n{body}"), report))
}

/// Keep TUN / sniffer / DNS / IPv6 switch states from the previous config.
pub fn carry_runtime_state(old_base: &str, new_base: &str) -> String {
    let old = split_chunks(old_base);
    let mut doc = new_base.to_string();
    let flags = crate::ops::parse_yaml_flags(old_base);
    let find = |key: &str| old.iter().find(|c| c.key.as_deref() == Some(key)).cloned();
    for (block, value) in [
        ("tun", flags.tun_enabled),
        ("sniffer", flags.sniffing),
        ("dns", flags.dns.enable),
    ] {
        let Some(old_chunk) = find(block) else {
            continue;
        };
        let mut chunks = split_chunks(&doc);
        if chunks.iter().any(|c| c.key.as_deref() == Some(block)) {
            doc = crate::ops::set_nested_bool(&doc, &[block, "enable"], value);
        } else {
            let pos = chunks
                .iter()
                .position(|c| c.key.as_deref() == Some("proxies"))
                .unwrap_or(chunks.len());
            chunks.insert(pos, old_chunk);
            doc = join_chunks(&chunks);
        }
    }
    if find("ipv6").is_some() {
        doc = crate::ops::set_nested_bool(&doc, &["ipv6"], flags.ipv6);
    }
    doc
}

pub fn is_generated(doc: &str) -> bool {
    crate::ops::strip_marked_modules(doc).starts_with("# terc-generated")
}

/// Where the subscription nodes come from on this regeneration.
pub fn load_subscription_source(
    dir: &Path,
    fresh: Option<String>,
    existing_config: Option<&str>,
) -> Result<Option<Converted>, String> {
    let raw = match fresh {
        Some(raw) => {
            // Validate before caching so a broken download never replaces a good cache.
            let converted = convert_subscription(&raw)?;
            write_private(&cache_path(dir), &raw)?;
            return Ok(Some(converted));
        }
        None => fs::read_to_string(cache_path(dir)).ok(),
    };
    if let Some(raw) = raw {
        return convert_subscription(&raw).map(Some);
    }
    // No cache yet: an existing hand-written / airport config is the source.
    if let Some(doc) = existing_config.filter(|d| !is_generated(d)) {
        let base = crate::ops::strip_marked_modules(doc);
        if crate::ops::has_subscription_source(&base) {
            return convert_subscription(&base).map(Some);
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manual(lines: &[&str]) -> Vec<ManualNode> {
        lines
            .iter()
            .map(|l| ManualNode {
                line: l.to_string(),
                parsed: parse_node_line(l),
            })
            .collect()
    }

    fn input<'a>(
        sub: Option<&'a Converted>,
        nodes: &'a [ManualNode],
        rules: &'a PrivateRules,
    ) -> ComposeInput<'a> {
        ComposeInput {
            subscription: sub,
            manual: nodes,
            rules,
            controller_addr: "127.0.0.1:9090",
            secret: "",
            test_url: "http://www.gstatic.com/generate_204",
        }
    }

    #[test]
    fn rules_conf_round_trips_and_tolerates_hand_edits() {
        let mut rules = PrivateRules::default();
        rules.rules.push("DOMAIN-SUFFIX,example.com,AI".into());
        rules.ai.members = vec!["Node A".into(), "Group B".into()];
        rules.ai.kind = "fallback".into();
        let text = rules.render();
        assert_eq!(PrivateRules::parse(&text), rules);
        let hand = "[rules]\n# note\nIP-CIDR,1.2.3.0/24,DIRECT,no-resolve\n[ai]\nenabled = off\nmembers =        # empty = auto\ntype = fallback  # or url-test\n";
        let parsed = PrivateRules::parse(hand);
        assert!(parsed.ai.members.is_empty());
        assert_eq!(parsed.ai.kind, "fallback");
        assert_eq!(parsed.rules, vec!["IP-CIDR,1.2.3.0/24,DIRECT,no-resolve"]);
        assert!(!parsed.ai.enabled);
        assert_eq!(parsed.ai.filter, DEFAULT_AI_FILTER);
    }

    #[test]
    fn rule_input_shorthand_and_targets() {
        assert_eq!(
            parse_rule_input("example.com").unwrap(),
            "DOMAIN-SUFFIX,example.com,PROXY"
        );
        assert_eq!(
            parse_rule_input("keyword, foo, ai").unwrap(),
            "DOMAIN-KEYWORD,foo,AI"
        );
        assert_eq!(
            parse_rule_input("10.1.0.0/16,DIRECT").unwrap(),
            "IP-CIDR,10.1.0.0/16,DIRECT,no-resolve"
        );
        assert_eq!(parse_rule_input("geoip,jp,AUTO").unwrap(), "GEOIP,JP,AUTO");
        assert_eq!(
            parse_rule_input("PROCESS-NAME,Cursor,AI").unwrap(),
            "PROCESS-NAME,Cursor,AI"
        );
        assert!(parse_rule_input("ip,1.2.3.4,DIRECT").is_err());
        assert_eq!(
            set_rule_target("IP-CIDR,10.0.0.0/8,PROXY,no-resolve", "AI"),
            "IP-CIDR,10.0.0.0/8,AI,no-resolve"
        );
        assert_eq!(rule_target("DOMAIN,a.com,DIRECT"), "DIRECT");
    }

    #[test]
    fn manual_nodes_file_add_remove_keeps_comments() {
        let dir = std::env::temp_dir().join(format!("terc-nodes-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let line = "Test-SS = ss, 192.0.2.10, 8388, encrypt-method=aes-128-gcm, password=fake-pass";
        assert_eq!(add_manual_node(&dir, line).unwrap(), "Test-SS");
        assert!(add_manual_node(&dir, line).is_err());
        add_manual_node(&dir, "trojan://fake@192.0.2.11:443?sni=example.com#T2").unwrap();
        let nodes = load_manual_nodes(&dir);
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[1].name(), "T2");
        assert_eq!(remove_manual_node(&dir, 0).unwrap(), "Test-SS");
        let text = fs::read_to_string(nodes_path(&dir)).unwrap();
        assert!(text.starts_with("# terc"));
        assert_eq!(load_manual_nodes(&dir).len(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(nodes_path(&dir)).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0);
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn manual_only_config_has_terc_groups_and_ai_rules() {
        let nodes = manual(&[
            "🇺🇸 Fake-US = ss, 192.0.2.1, 8388, encrypt-method=2022-blake3-aes-128-gcm, password=AAAAAAAAAAAAAAAAAAAAAA==, udp-relay=true, tfo=true",
            "🇭🇰 Fake-HK = trojan, 192.0.2.2, 443, password=fake",
        ]);
        let mut rules = PrivateRules::default();
        rules.rules.push("DOMAIN-SUFFIX,example.org,DIRECT".into());
        rules.rules.push("DOMAIN,x.example,NoSuchGroup".into());
        let (yaml, report) = compose(&input(None, &nodes, &rules)).unwrap();
        assert!(yaml.starts_with(GENERATED_MARK));
        assert!(yaml.contains("external-controller: 127.0.0.1:9090"));
        assert!(yaml.contains("\"cipher\":\"2022-blake3-aes-128-gcm\""));
        assert!(yaml.contains("\"name\":\"AI\""));
        assert!(yaml.contains("\"exclude-filter\""));
        let pos = |s: &str| yaml.find(s).unwrap_or_else(|| panic!("missing {s}"));
        assert!(pos("DOMAIN-SUFFIX,example.org,DIRECT") < pos("DOMAIN-SUFFIX,openai.com,AI"));
        assert!(
            pos("DOMAIN-SUFFIX,claude.ai,AI") < pos("IP-CIDR,192.168.0.0/16,DIRECT,no-resolve")
        );
        assert!(pos("IP-CIDR,192.168.0.0/16") < pos("GEOIP,CN,DIRECT"));
        assert!(yaml.trim_end().ends_with("- \"MATCH,PROXY\""));
        assert_eq!(report.manual_nodes, 2);
        assert_eq!(report.private_rules, 1);
        assert_eq!(report.rule_skipped.len(), 1);
        assert!(!report.summary(true).contains("fake"));
    }

    #[test]
    fn clash_subscription_keeps_settings_drops_airport_rules_and_merges_nodes() {
        let doc = "mixed-port: 7897\ndns:\n  enable: true\nproxies:\n  - {name: \"HK 01\", type: ss, server: 192.0.2.5, port: 1, cipher: aes-128-gcm, password: x}\n  - name: JP 02\n    type: trojan\n    server: 192.0.2.6\n    port: 443\n    password: y\nproxy-groups:\n  - name: Airport\n    type: select\n    proxies: [HK 01, JP 02]\nrules:\n  - DOMAIN-SUFFIX,google.com,Airport\n  - MATCH,Airport\n";
        let sub = convert_subscription(doc).unwrap();
        let nodes = manual(&["JP 02 = http, 192.0.2.9, 8080"]);
        let rules = PrivateRules::default();
        let (yaml, report) = compose(&input(Some(&sub), &nodes, &rules)).unwrap();
        assert_eq!(report.format, Some(SubFormat::ClashYaml));
        assert_eq!(report.sub_nodes, 2);
        assert!(yaml.contains("mixed-port: 7897"));
        assert!(!yaml.contains("Airport"));
        assert!(yaml.contains("\"name\":\"JP 02 (2)\""));
        assert_eq!(yaml.matches("proxies:\n").count(), 1);

        let keep = PrivateRules {
            subscription_rules: true,
            ..PrivateRules::default()
        };
        let (yaml, _) = compose(&input(Some(&sub), &nodes, &keep)).unwrap();
        assert!(yaml.contains("- name: Airport"));
        assert!(yaml.contains("\"DOMAIN-SUFFIX,google.com,Airport\""));
        assert!(!yaml.contains("MATCH,Airport"));
        assert!(yaml.find("\"name\":\"PROXY\"").unwrap() < yaml.find("- name: Airport").unwrap());
    }

    #[test]
    fn ai_members_and_name_collisions() {
        let nodes = manual(&[
            "PROXY = http, 192.0.2.9, 8080",
            "SG = http, 192.0.2.8, 8080",
        ]);
        let mut rules = PrivateRules::default();
        rules.ai.members = vec!["SG".into(), "Gone".into()];
        rules.rules.push("DOMAIN,a.example,PROXY".into());
        let (yaml, report) = compose(&input(None, &nodes, &rules)).unwrap();
        assert!(yaml.contains("\"name\":\"terc-PROXY\""));
        assert!(yaml.contains("DOMAIN,a.example,terc-PROXY"));
        assert!(yaml.contains("\"proxies\":[\"SG\"]"));
        assert!(yaml.contains("MATCH,terc-PROXY"));
        assert_eq!(report.rule_skipped.len(), 1);
    }

    #[test]
    fn empty_sources_are_an_error_not_a_crash() {
        let rules = PrivateRules::default();
        assert!(compose(&input(None, &[], &rules)).is_err());
    }

    #[test]
    fn runtime_state_is_carried_into_new_base() {
        let old = "tun:\n  enable: true\n  stack: system\nsniffer:\n  enable: true\nipv6: true\n";
        let new = "ipv6: false\nsniffer:\n  enable: false\nproxies: []\n";
        let out = carry_runtime_state(old, new);
        let flags = crate::ops::parse_yaml_flags(&out);
        assert!(flags.tun_enabled && flags.sniffing && flags.ipv6);
        assert_eq!(flags.tun_stack, "system");
    }

    #[test]
    #[ignore = "requires an installed Mihomo binary; validates generated configs with mihomo -t"]
    fn real_core_accepts_composed_configs() {
        let bin = crate::mihomo::discover_mihomo_binary().expect("mihomo binary");
        let dir = std::env::temp_dir().join(format!("terc-compose-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let nodes = manual(&[
            "🇺🇸 Own-SS = ss, 192.0.2.1, 8388, encrypt-method=2022-blake3-aes-128-gcm, password=AAAAAAAAAAAAAAAAAAAAAA==, udp-relay=true, tfo=true",
            "vless://00000000-0000-0000-0000-000000000000@192.0.2.4:443?security=reality&sni=www.example.com&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=ab&type=tcp#Own-VL",
        ]);
        let clash = "mixed-port: 7897\nproxies:\n  - {name: \"HK 01\", type: ss, server: 192.0.2.5, port: 1, cipher: aes-128-gcm, password: x}\nproxy-groups:\n  - name: Airport\n    type: select\n    proxies: [HK 01]\nrules:\n  - DOMAIN-SUFFIX,google.com,Airport\n  - MATCH,Airport\n";
        let surge = convert_subscription(crate::subconv::tests::SURGE).unwrap();
        let clash = convert_subscription(clash).unwrap();
        let mut rules = PrivateRules::default();
        rules.rules.push("DOMAIN-SUFFIX,example.org,AI".into());
        rules.rules.push("PROCESS-NAME,curl,DIRECT".into());
        for sub in [None, Some(&surge), Some(&clash)] {
            for keep in [false, true] {
                rules.subscription_rules = keep;
                let (yaml, _) = compose(&input(sub, &nodes, &rules)).unwrap();
                let path = dir.join("config.yaml");
                fs::write(&path, &yaml).unwrap();
                let out = std::process::Command::new(&bin)
                    .args(["-t", "-d"])
                    .arg(&dir)
                    .arg("-f")
                    .arg(&path)
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "keep={keep} {}\n{}\n{yaml}",
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
            }
        }
        fs::remove_dir_all(dir).unwrap();
    }

    /// Debug helper: compose a config for one node given in `TERC_LIVE_NODE`
    /// and write it to `TERC_LIVE_OUT`. Nothing secret lives in the source.
    #[test]
    #[ignore = "manual live-node helper; needs TERC_LIVE_NODE and TERC_LIVE_OUT"]
    fn live_node_compose() {
        let line = std::env::var("TERC_LIVE_NODE").expect("TERC_LIVE_NODE");
        let out = std::env::var("TERC_LIVE_OUT").expect("TERC_LIVE_OUT");
        let nodes = manual(&[line.as_str()]);
        let node = nodes[0].parsed.as_ref().expect("node parses");
        assert_eq!(node["type"], "ss");
        let rules = PrivateRules::default();
        let (yaml, _) = compose(&input(None, &nodes, &rules)).unwrap();
        fs::write(out, yaml).unwrap();
    }
}
