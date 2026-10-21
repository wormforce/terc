//! terc-owned configuration: subscription nodes + the user's own nodes +
//! private rules + the built-in AI preset, composed into one Mihomo config.
//!
//! Files under `~/.config/terc/` (all hand-editable):
//! - `rules.conf`  private rules and AI routing settings
//! - `source.json`  named source, structured nodes and routing assignment
//! - `subscription.yaml`  original subscription body (cached separately)

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use serde_json::{json, Value};

use crate::{
    ops::{clean_scalar, join_chunks, leading_spaces, split_chunks, YamlChunk},
    subconv::{convert_subscription, parse_node_line, Converted, SubFormat},
};

pub const GENERATED_MARK: &str =
    "# terc-generated: managed by Settings; nodes and routing are composed separately";

pub const DEFAULT_AI_FILTER: &str = "(?i)(🇺🇸|🇯🇵|🇸🇬|🇹🇼|美国|美國|日本|新加坡|狮城|獅城|台湾|台灣|\\b(US|USA|JP|SG|TW|SEA|LAX|SJC|NRT|HND|SIN|TPE)\\b|United States|Japan|Tokyo|Osaka|Singapore|Taiwan|Taipei|Seattle|Los Angeles|San Jose|Silicon Valley|New York|Chicago|Dallas|Ashburn)";
pub const DEFAULT_AI_EXCLUDE: &str =
    "(?i)(🇭🇰|港|\\bHK\\b|Hong ?Kong|🇨🇳|中国|回国|剩余|到期|流量|过期|官网|套餐|expire|traffic)";
pub(crate) const INFO_EXCLUDE: &str = "(?i)(剩余|到期|流量|过期|官网|套餐|expire|traffic)";

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

/// Existing installations keep their current sources until a profile is saved.
pub fn profile_dir(cfg: &crate::mihomo::ControllerConfig) -> PathBuf {
    if cfg.profile_id.is_empty() {
        terc_dir()
    } else {
        terc_dir().join("sources").join(&cfg.profile_id)
    }
}

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ProfileSource {
    pub name: String,
    pub subscription_url: String,
    #[serde(default)]
    pub nodes: Vec<Value>,
    #[serde(default)]
    pub kind: String,
    #[serde(default = "default_routing")]
    pub routing: String,
}
fn default_routing() -> String {
    "subscription".into()
}
impl ProfileSource {
    pub fn load(dir: &Path) -> Self {
        fs::read_to_string(dir.join("source.json"))
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }
    pub fn save(&self, dir: &Path) -> Result<(), String> {
        write_private(
            &dir.join("source.json"),
            &serde_json::to_string_pretty(self).map_err(|e| e.to_string())?,
        )
    }
}

pub fn local_routing(dir: &Path) -> bool {
    ProfileSource::load(dir).routing == "local"
}

pub fn rules_path(dir: &Path) -> PathBuf {
    dir.join("rules.conf")
}

pub fn nodes_path(dir: &Path) -> PathBuf {
    dir.join("source.json")
}

pub fn cache_path(dir: &Path) -> PathBuf {
    dir.join("subscription.yaml")
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

pub fn load_manual_nodes(dir: &Path) -> Vec<ManualNode> {
    ProfileSource::load(dir)
        .nodes
        .into_iter()
        .map(|node| ManualNode {
            line: node.to_string(),
            parsed: Ok(node),
        })
        .collect()
}
pub fn add_manual_node(dir: &Path, line: &str) -> Result<String, String> {
    let node = parse_node_line(line.trim())?;
    let name = node["name"].as_str().unwrap_or("Proxy").to_string();
    let mut source = ProfileSource::load(dir);
    if source
        .nodes
        .iter()
        .any(|n| n["name"].as_str() == Some(&name))
    {
        return Err(format!("已有同名节点 / Duplicate node: {name}"));
    }
    source.nodes.push(node);
    source.save(dir)?;
    Ok(name)
}
pub fn remove_manual_node(dir: &Path, index: usize) -> Result<String, String> {
    let mut source = ProfileSource::load(dir);
    if index >= source.nodes.len() {
        return Err("没有这个节点 / No such node".into());
    }
    let node = source.nodes.remove(index);
    source.save(dir)?;
    Ok(node["name"].as_str().unwrap_or("Proxy").into())
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
    /// Nodes rewritten from `network: httpupgrade` to Mihomo's ws form.
    pub normalized: Vec<String>,
    /// Warnings about the final config (DNS, rule order), "zh / en".
    pub notes: Vec<String>,
    /// Nodes whose type defaults `udp` to false and that do not set it.
    pub no_udp: Vec<String>,
}

impl ComposeReport {
    pub fn skipped_total(&self) -> usize {
        self.sub_skipped.len() + self.manual_skipped.len() + self.rule_skipped.len()
    }

    pub fn summary(&self, zh: bool) -> String {
        let fmt = self.format.map(SubFormat::label).unwrap_or("-");
        let mut text = if zh {
            format!(
                "来源 {fmt} {} 节点  手动 {}  保留来源分流",
                self.sub_nodes, self.manual_nodes
            )
        } else {
            format!(
                "{fmt} {} nodes  Manual {}  Source routing preserved",
                self.sub_nodes, self.manual_nodes
            )
        };
        // Mihomo moves a UDP flow whose target lacks UDP on to later rules
        // and finally DIRECT (tunnel.go), from TUN or SOCKS5 UDP alike.
        let n = self.no_udp.len();
        if n > 0 {
            text.push_str(&if zh {
                format!("  {n} 个节点未开启 udp，其 UDP 流量（TUN / SOCKS5）会改走后续规则或直连")
            } else {
                format!("  {n} node(s) without udp: their UDP traffic (TUN / SOCKS5) falls through to later rules or DIRECT")
            });
        }
        let n = self.notes.len();
        if n > 0 {
            text.push_str(&if zh {
                format!("  {n} 条配置提示（! 详情）")
            } else {
                format!("  {n} config note(s) (! details)")
            });
        }
        if self.skipped_total() > 0 {
            text.push_str(&format!(
                "  {} skipped / 跳过（! 详情）",
                self.skipped_total()
            ));
        }
        let n = self.normalized.len();
        if n > 0 {
            text.push_str(&if zh {
                format!("  {n} 个 httpupgrade 节点已改为 ws + v2ray-http-upgrade")
            } else {
                format!("  {n} httpupgrade node(s) rewritten to ws + v2ray-http-upgrade")
            });
        }
        text
    }

    /// Replace the compose-time UDP list with what the running core reports,
    /// which also covers proxy-provider nodes and smux (which carries UDP).
    pub fn apply_runtime_udp(&mut self, nodes: &[crate::ops::ProviderNode]) {
        for node in nodes {
            let listed = self.no_udp.iter().position(|n| *n == node.name);
            match (node.udp, listed) {
                (true, Some(i)) => {
                    self.no_udp.remove(i);
                }
                (false, None) if udp_optional(&runtime_type(&node.kind)) => {
                    self.no_udp.push(node.name.clone());
                }
                _ => {}
            }
        }
    }

    /// Config notes, nodes without udp, skipped, then rewritten entries, one per line (names and types only,
    /// never secrets).
    pub fn details(&self) -> String {
        let normalized: Vec<String> = self
            .normalized
            .iter()
            .map(|name| format!("httpupgrade → ws: {name}"))
            .collect();
        let mut no_udp = Vec::new();
        if !self.no_udp.is_empty() {
            let mut names = self
                .no_udp
                .iter()
                .take(8)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            if self.no_udp.len() > 8 {
                names.push_str(&format!(" … +{}", self.no_udp.len() - 8));
            }
            no_udp.push(format!("未开启 udp / no udp: {names}"));
        }
        let all: Vec<&String> = self
            .notes
            .iter()
            .chain(&no_udp)
            .chain(&self.sub_skipped)
            .chain(&self.manual_skipped)
            .chain(&self.rule_skipped)
            .chain(&normalized)
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

// ------------------------------------------------------------ report checks

/// Proxy types whose `udp` defaults to false in Mihomo (`proxy:"udp,omitempty"`).
/// Hysteria2 and TUIC are always UDP; http never is.
const UDP_OPTIONAL: &[&str] = &[
    "ss",
    "ssr",
    "vmess",
    "vless",
    "trojan",
    "anytls",
    "wireguard",
    "snell",
    "mieru",
    "socks5",
];

fn udp_optional(kind: &str) -> bool {
    UDP_OPTIONAL.contains(&kind.to_ascii_lowercase().as_str())
}

/// Config `type` for an adapter type name from the controller (`Shadowsocks`).
fn runtime_type(kind: &str) -> String {
    match kind.to_ascii_lowercase().as_str() {
        "shadowsocks" => "ss".into(),
        "shadowsocksr" => "ssr".into(),
        other => other.into(),
    }
}

/// Resolvers outside the mainland that are often reset or blackholed from it.
const FOREIGN_DNS: &[&str] = &[
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
    "185.222.222.222",
    "45.11.45.11",
    "101.101.101.101",
    "dns.google",
    "cloudflare-dns.com",
    "one.one.one.one",
    "quad9.net",
    "opendns.com",
    "adguard.com",
    "adguard-dns.com",
    "nextdns.io",
    "dns.sb",
    "mullvad.net",
    "dns.twnic.tw",
];

/// Whether a DNS server URL dials a known foreign resolver DIRECT, i.e. not
/// through a `#proxy` given in the URL.
fn foreign_direct(server: &str) -> bool {
    let (addr, params) = server.split_once('#').unwrap_or((server, ""));
    let via = params
        .split('&')
        .find(|p| !p.is_empty() && !p.contains('='));
    if via.is_some_and(|p| !p.eq_ignore_ascii_case("DIRECT")) {
        return false;
    }
    let host = addr.split_once("://").map_or(addr, |(_, rest)| rest);
    let host = host.split('/').next().unwrap_or("");
    let host = match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(""),
        None if host.matches(':').count() == 1 => host.split(':').next().unwrap_or(""),
        None => host,
    };
    let host = host.to_ascii_lowercase();
    FOREIGN_DNS
        .iter()
        .any(|f| host == *f || host.ends_with(&format!(".{f}")))
}

/// Split a YAML flow collection body (without its brackets) at top-level
/// commas, returning trimmed raw parts.
fn flow_split(inner: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let (mut from, mut depth) = (0, 0usize);
    for (i, c) in flow_unquoted(inner) {
        match c {
            '[' | '{' | '(' => depth += 1,
            ']' | '}' | ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(inner[from..i].trim());
                from = i + 1;
            }
            _ => {}
        }
    }
    parts.push(inner[from..].trim());
    parts.retain(|p| !p.is_empty());
    parts
}

/// `key` and the rest after `key:` in a mapping line (quoted keys may hold
/// colons; a plain key ends at `: ` or a final `:`).
fn entry_key(text: &str) -> Option<(String, &str)> {
    if let Some(q) = text.chars().next().filter(|c| *c == '"' || *c == '\'') {
        let close = text[1..].find(q)? + 1;
        let rest = text[close + 1..].trim_start().strip_prefix(':')?;
        return Some((text[1..close].to_string(), rest));
    }
    let end = text
        .find(": ")
        .or_else(|| text.find(":\t"))
        .or_else(|| text.strip_suffix(':').map(str::len))?;
    let key = text[..end].trim();
    (!key.is_empty() && !key.starts_with('-')).then(|| (key.to_string(), &text[end + 1..]))
}

/// Entries of the block mapping in `lines[from..to]`: key, first line, end.
fn block_entries(lines: &[String], from: usize, to: usize) -> Vec<(String, usize, usize)> {
    let skip = |l: &String| l.trim().is_empty() || l.trim_start().starts_with('#');
    let Some(indent) = lines[from..to]
        .iter()
        .find(|l| !skip(l))
        .map(|l| leading_spaces(l))
    else {
        return Vec::new();
    };
    let starts: Vec<(String, usize)> = (from..to)
        .filter(|&i| !skip(&lines[i]) && leading_spaces(&lines[i]) == indent)
        .filter_map(|i| Some((entry_key(lines[i].trim_start())?.0, i)))
        .collect();
    let mut out = Vec::new();
    for (k, (key, start)) in starts.iter().enumerate() {
        let mut end = starts.get(k + 1).map_or(to, |s| s.1);
        // Lines below the entry indent end the mapping.
        if let Some(stop) =
            (start + 1..end).find(|&i| !skip(&lines[i]) && leading_spaces(&lines[i]) < indent)
        {
            end = stop;
        }
        out.push((key.clone(), *start, end));
    }
    out
}

/// The inline value of an entry line, without a trailing comment.
fn inline_value(line: &str) -> String {
    let rest = entry_key(line.trim_start()).map_or("", |(_, r)| r).trim();
    if rest.starts_with('#') {
        return String::new();
    }
    match rest.chars().next() {
        Some('[' | '{') => matching_close(rest, 0)
            .map_or(rest, |c| &rest[..=c])
            .to_string(),
        _ => rest.split(" #").next().unwrap_or(rest).trim().to_string(),
    }
}

/// A scalar without quotes or a ` #` comment; unlike `clean_scalar` it keeps
/// a `#` inside the value (a DNS server's `#proxy`).
fn plain_scalar(v: &str) -> String {
    let v = v.split(" #").next().unwrap_or(v).trim();
    ['"', '\'']
        .iter()
        .find_map(|q| v.strip_prefix(*q)?.strip_suffix(*q))
        .unwrap_or(v)
        .to_string()
}

/// Scalar items of the list or scalar value of the entry in `lines[s..e]`.
fn entry_items(lines: &[String], s: usize, e: usize) -> Vec<String> {
    let inline = inline_value(&lines[s]);
    if let Some(inner) = inline.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
        return flow_split(inner).into_iter().map(plain_scalar).collect();
    }
    if !inline.is_empty() {
        return vec![plain_scalar(&inline)];
    }
    lines[s + 1..e]
        .iter()
        .filter_map(|l| l.trim_start().strip_prefix('-'))
        .map(plain_scalar)
        .filter(|v| !v.is_empty())
        .collect()
}

/// The `dns` chunk when it is a block mapping (a flow `dns: {...}` is not read).
fn dns_chunk(chunks: &[YamlChunk]) -> Option<usize> {
    let i = chunks
        .iter()
        .rposition(|c| c.key.as_deref() == Some("dns"))?;
    inline_value(&chunks[i].lines[0]).is_empty().then_some(i)
}

/// Warn about DNS servers that stall lookups from the mainland: a foreign
/// fallback, or a nameserver-policy entry, dialed DIRECT. Mihomo waits on the
/// fallback for every non-CN answer and does not cache a failed lookup.
fn dns_notes(chunks: &[YamlChunk]) -> Vec<String> {
    let mut notes = Vec::new();
    let Some(at) = dns_chunk(chunks) else {
        return notes;
    };
    let lines = &chunks[at].lines;
    let entries = block_entries(lines, 1, lines.len());
    let value = |key: &str| entries.iter().rev().find(|e| e.0 == key);
    let flag =
        |key: &str| value(key).is_some_and(|e| clean_scalar(&inline_value(&lines[e.1])) == "true");
    // With respect-rules the servers are dialed by the rules, not DIRECT.
    if value("enable").is_some_and(|e| clean_scalar(&inline_value(&lines[e.1])) == "false")
        || flag("respect-rules")
    {
        return notes;
    }
    if let Some(&(_, s, e)) = value("fallback") {
        let foreign: Vec<_> = entry_items(lines, s, e)
            .into_iter()
            .filter(|v| foreign_direct(v))
            .collect();
        if !foreign.is_empty() {
            notes.push(format!(
                "dns.fallback 直连境外 DNS（{}）：大陆网络下每个境外域名都会等它，失败时卡到 5 秒且不缓存，建议清空 fallback / dns.fallback dials foreign DNS DIRECT ({}): from the mainland every foreign lookup waits on it, up to 5 s uncached when blocked; consider clearing fallback",
                foreign.join(", "),
                foreign.join(", ")
            ));
        }
    }
    if let Some(&(_, s, e)) = value("nameserver-policy") {
        for (key, ks, ke) in block_entries(lines, s + 1, e) {
            let foreign: Vec<_> = entry_items(lines, ks, ke)
                .into_iter()
                .filter(|v| foreign_direct(v))
                .collect();
            if !foreign.is_empty() {
                notes.push(format!(
                    "dns.nameserver-policy {key} 直连境外 DNS（{}），大陆网络下同样会卡顿 / dns.nameserver-policy {key} dials foreign DNS DIRECT ({}) and stalls the same way from the mainland",
                    foreign.join(", "),
                    foreign.join(", ")
                ));
            }
        }
    }
    notes
}

/// Names of the entries of the `rule-providers` chunk.
fn rule_provider_names(chunks: &[YamlChunk]) -> HashSet<String> {
    let Some(c) = chunks
        .iter()
        .rfind(|c| c.key.as_deref() == Some("rule-providers"))
    else {
        return HashSet::new();
    };
    let inline = inline_value(&c.lines[0]);
    if let Some(inner) = inline.strip_prefix('{').and_then(|v| v.strip_suffix('}')) {
        return flow_split(inner)
            .into_iter()
            .filter_map(|p| entry_key(p).map(|(k, _)| k))
            .collect();
    }
    block_entries(&c.lines, 1, c.lines.len())
        .into_iter()
        .map(|e| e.0)
        .collect()
}

/// Rule-set names that a DNS policy key or fake-ip-filter item references:
/// `rule-set:a,b`, or `RULE-SET,a,…` under `fake-ip-filter-mode: rule`.
fn referenced_rule_sets(item: &str) -> Vec<String> {
    if let Some(names) = item.strip_prefix("rule-set:") {
        return names.split(',').map(|n| n.trim().to_string()).collect();
    }
    let mut fields = item.splitn(3, ',');
    match (fields.next(), fields.next()) {
        (Some(kind), Some(name)) if kind.trim().eq_ignore_ascii_case("RULE-SET") => {
            vec![name.trim().to_string()]
        }
        _ => Vec::new(),
    }
}

/// Remove DNS references to rule-providers the config does not define: a
/// `nameserver-policy` or `proxy-server-nameserver-policy` entry keyed by one,
/// and `fake-ip-filter` items naming one. Mihomo refuses such a config with
/// "not found rule-set", e.g. after the providers were dropped with the
/// source's routing. Returns one note per removed reference.
pub(crate) fn strip_dangling_rule_sets(chunks: &mut [YamlChunk]) -> Vec<String> {
    let Some(at) = dns_chunk(chunks) else {
        return Vec::new();
    };
    let known = rule_provider_names(chunks);
    let dangling = |item: &str| {
        let names = referenced_rule_sets(item);
        names
            .iter()
            .any(|n| !known.contains(n))
            .then(|| names.join(","))
    };
    let lines = &mut chunks[at].lines;
    let entries = block_entries(lines, 1, lines.len());
    // Back to front, so removed lines do not shift earlier entries.
    let mut removed_by_entry = Vec::new();
    for (key, s, e) in entries.into_iter().rev() {
        let policy = matches!(
            key.as_str(),
            "nameserver-policy" | "proxy-server-nameserver-policy"
        );
        if !policy && key != "fake-ip-filter" {
            continue;
        }
        let mut removed = Vec::new();
        let inline = inline_value(&lines[s]);
        let pad = " ".repeat(leading_spaces(&lines[s]));
        let (open, close) = if policy { ('{', '}') } else { ('[', ']') };
        if let Some(inner) = inline
            .strip_prefix(open)
            .and_then(|v| v.strip_suffix(close))
        {
            let kept: Vec<&str> = flow_split(inner)
                .into_iter()
                .filter(|part| {
                    let item = if policy {
                        entry_key(part).map(|(k, _)| k).unwrap_or_default()
                    } else {
                        clean_scalar(part)
                    };
                    let gone = dangling(&item).is_some();
                    if gone {
                        removed.push(item);
                    }
                    !gone
                })
                .collect();
            if !removed.is_empty() {
                lines[s] = format!("{pad}{key}: {open}{}{close}", kept.join(", "));
            }
        } else if inline.is_empty() {
            let drop: Vec<(usize, usize, String)> = if policy {
                block_entries(lines, s + 1, e)
                    .into_iter()
                    .filter(|(k, _, _)| dangling(k).is_some())
                    .map(|(k, ks, ke)| (ks, ke, k))
                    .collect()
            } else {
                (s + 1..e)
                    .filter_map(|i| {
                        let v = lines[i].trim_start().strip_prefix('-')?;
                        let item = clean_scalar(v.split(" #").next().unwrap_or(v));
                        dangling(&item).map(|_| (i, i + 1, item))
                    })
                    .collect()
            };
            let mut end = e;
            for (ds, de, item) in drop.into_iter().rev() {
                lines.drain(ds..de);
                end -= de - ds;
                removed.insert(0, item);
            }
            let left = lines[s + 1..end]
                .iter()
                .any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'));
            // An emptied block becomes an empty collection rather than null.
            if !removed.is_empty() && !left {
                lines[s] = format!("{pad}{key}: {open}{close}");
            }
        }
        removed_by_entry.push((key, removed));
    }
    removed_by_entry
        .into_iter()
        .rev()
        .flat_map(|(key, removed)| {
            removed.into_iter().map(move |item| format!(
                "已移除 dns.{key} 中的 {item}：配置里没有这个规则集（否则 Mihomo 报 not found rule-set）/ Removed {item} from dns.{key}: no such rule-provider in the config (Mihomo would fail with 'not found rule-set')"
            ))
        })
        .collect()
}

/// Behavior and inline payload of each entry of the `rule-providers` chunk.
fn rule_provider_kinds(chunks: &[YamlChunk]) -> HashMap<String, (String, Vec<String>)> {
    let mut out = HashMap::new();
    let Some(c) = chunks
        .iter()
        .rfind(|c| c.key.as_deref() == Some("rule-providers"))
    else {
        return out;
    };
    for (name, s, e) in block_entries(&c.lines, 1, c.lines.len()) {
        let inline = inline_value(&c.lines[s]);
        if let Ok(value) = serde_json::from_str::<Value>(&inline) {
            let payload = value["payload"]
                .as_array()
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            let behavior = value["behavior"].as_str().unwrap_or("").to_string();
            out.insert(name, (behavior, payload));
        } else if let Some(inner) = inline.strip_prefix('{') {
            let behavior = flow_value(inner, "behavior").unwrap_or_default();
            let payload = flow_key_list(&inline, "payload")
                .map(|(o, c)| {
                    flow_split(&inline[o + 1..c])
                        .into_iter()
                        .map(clean_scalar)
                        .collect()
                })
                .unwrap_or_default();
            out.insert(name, (behavior, payload));
        } else {
            let fields = block_entries(&c.lines, s + 1, e);
            let field = |key: &str| fields.iter().find(|f| f.0 == key);
            let behavior = field("behavior")
                .map(|f| clean_scalar(&inline_value(&c.lines[f.1])))
                .unwrap_or_default();
            let payload = field("payload")
                .map(|&(_, ps, pe)| entry_items(&c.lines, ps, pe))
                .unwrap_or_default();
            out.insert(name, (behavior, payload));
        }
    }
    out
}

/// Whether Mihomo resolves the host locally to match `rule`: an IP rule
/// without `no-resolve` (GEOIP,LAN included), a RULE-SET of an ipcidr
/// provider or of a classical one whose inline payload holds such a rule,
/// or a logic rule wrapping one. SRC-* rules never resolve. Remote classical
/// payloads are not visible here and are not flagged.
fn rule_resolves(rule: &str, providers: &HashMap<String, (String, Vec<String>)>) -> bool {
    let fields = flow_split(rule);
    let Some(kind) = fields.first().map(|k| k.to_ascii_uppercase()) else {
        return false;
    };
    let no_resolve = fields
        .iter()
        .skip(2)
        .any(|f| f.eq_ignore_ascii_case("no-resolve"));
    match kind.as_str() {
        "IP-CIDR" | "IP-CIDR6" | "IP-SUFFIX" | "IP-ASN" | "GEOIP" => !no_resolve,
        "RULE-SET" => {
            !no_resolve
                && fields.get(1).and_then(|n| providers.get(*n)).is_some_and(
                    |(behavior, payload)| {
                        behavior.eq_ignore_ascii_case("ipcidr")
                            || (behavior.eq_ignore_ascii_case("classical")
                                && payload.iter().any(|r| rule_resolves(r, providers)))
                    },
                )
        }
        "AND" | "OR" | "NOT" => fields.get(1).is_some_and(|inner| {
            let inner = inner.trim();
            let inner = inner
                .strip_prefix('(')
                .and_then(|v| v.strip_suffix(')'))
                .unwrap_or(inner);
            flow_split(inner).into_iter().any(|r| {
                let r = r
                    .strip_prefix('(')
                    .and_then(|v| v.strip_suffix(')'))
                    .unwrap_or(r);
                rule_resolves(r, providers)
            })
        }),
        _ => false,
    }
}

/// Note the first of the source's `rules` that makes Mihomo resolve the host
/// locally: every connection that reaches it unmatched pays a DNS lookup.
fn resolving_rule_note(rules: &[String], chunks: &[YamlChunk]) -> Option<String> {
    let providers = rule_provider_kinds(chunks);
    let n = rules.iter().position(|r| rule_resolves(r, &providers))?;
    let rule: String = rules[n].chars().take(60).collect();
    let n = n + 1;
    Some(format!(
        "订阅规则第 {n} 条（{rule}）起，前面规则未命中的每个连接都要先做一次本地 DNS 解析 / From subscription rule {n} ({rule}) on, every connection no earlier rule matched pays a local DNS lookup"
    ))
}

/// Names of the `proxies` items whose type defaults `udp` to false and that
/// set no `udp` key.
fn missing_udp(chunks: &[YamlChunk]) -> Vec<String> {
    let mut out = Vec::new();
    let Some(c) = chunks.iter().find(|c| c.key.as_deref() == Some("proxies")) else {
        return out;
    };
    let lines = &c.lines;
    let Some(item_indent) = lines
        .iter()
        .skip(1)
        .find(|l| l.trim_start().starts_with('-'))
        .map(|l| leading_spaces(l))
    else {
        return out;
    };
    let starts: Vec<usize> = (1..lines.len())
        .filter(|&i| {
            leading_spaces(&lines[i]) == item_indent && lines[i].trim_start().starts_with('-')
        })
        .collect();
    for (k, &start) in starts.iter().enumerate() {
        let end = starts.get(k + 1).copied().unwrap_or(lines.len());
        let first = lines[start].trim_start()[1..].trim_start();
        let (name, kind, has_udp) = if let Ok(v) = serde_json::from_str::<Value>(first) {
            (
                v["name"].as_str().unwrap_or("?").to_string(),
                v["type"].as_str().unwrap_or("").to_string(),
                v.get("udp").is_some(),
            )
        } else if first.starts_with('{') {
            let flow = matching_close(first, 0).map_or(first, |c| &first[..=c]);
            (
                flow_value(&flow[1..], "name").unwrap_or_else(|| "?".into()),
                flow_value(&flow[1..], "type").unwrap_or_default(),
                flow_key_value(flow, "udp").is_some(),
            )
        } else {
            // A block item: its first key shares the `- ` line.
            let at = lines[start].len() - first.len();
            let mut item: Vec<String> = vec![format!("{}{first}", " ".repeat(at))];
            item.extend(lines[start + 1..end].iter().cloned());
            let fields = block_entries(&item, 0, item.len());
            let field = |key: &str| {
                fields
                    .iter()
                    .find(|f| f.0 == key)
                    .map(|f| plain_scalar(&inline_value(&item[f.1])))
            };
            (
                field("name").unwrap_or_else(|| "?".into()),
                field("type").unwrap_or_default(),
                field("udp").is_some(),
            )
        };
        if !has_udp && udp_optional(&kind) {
            out.push(name);
        }
    }
    out
}

impl ComposeReport {
    /// Checks on the final config. `sub_rules` are the source's rules when
    /// they reach the config (subscription-rules on), else empty.
    fn inspect(&mut self, chunks: &mut [YamlChunk], sub_rules: &[String]) {
        self.notes.extend(strip_dangling_rule_sets(chunks));
        self.notes.extend(dns_notes(chunks));
        self.notes.extend(resolving_rule_note(sub_rules, chunks));
        self.no_udp = missing_udp(chunks);
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
log-level: warning\n\
ipv6: false\n\
unified-delay: true\n\
tcp-concurrent: true\n\
find-process-mode: strict\n\
external-controller: {addr}\n"
    );
    if !secret.is_empty() {
        text.push_str(&format!("secret: {}\n", json!(secret)));
    }
    text.push_str("geodata-mode: false\n");
    for line in geox_url_chunk().lines {
        text.push_str(&line);
        text.push('\n');
    }
    text.push_str(
        "profile:\n  store-selected: true\n\
sniffer:\n  enable: false\n  sniff:\n    HTTP:\n      ports: [80, 8080-8880]\n      override-destination: true\n    TLS:\n      ports: [443, 8443]\n    QUIC:\n      ports: [443, 8443]\n\
tun:\n  enable: false\n  stack: mixed\n  auto-route: true\n  auto-detect-interface: true\n  dns-hijack: [\"any:53\"]\n\
dns:\n  enable: true\n  ipv6: false\n  listen: 127.0.0.1:1053\n  enhanced-mode: fake-ip\n  fake-ip-range: 198.18.0.1/16\n  fake-ip-filter: [\"*.lan\", \"+.local\", \"localhost\"]\n  default-nameserver: [223.5.5.5, 119.29.29.29]\n  nameserver: [\"https://doh.pub/dns-query\", \"https://dns.alidns.com/dns-query\"]\n",
    );
    text
}

/// jsDelivr mirror of the meta-rules-dat `release` branch. Mihomo's defaults
/// are GitHub release downloads with 90 s per file, and a failed download
/// fails `mihomo -t`, so a first run on a slow link would not start.
const GEOX_MIRROR: &str = "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/";

/// All four keys: one left out falls back to Mihomo's GitHub default.
fn geox_url_chunk() -> YamlChunk {
    let files = [
        ("geoip", "geoip.dat"),
        ("geosite", "geosite.dat"),
        ("mmdb", "country.mmdb"),
        ("asn", "GeoLite2-ASN.mmdb"),
    ];
    YamlChunk {
        key: Some("geox-url".into()),
        lines: std::iter::once("geox-url:".to_string())
            .chain(files.iter().map(|(key, file)| {
                format!("  {key}: {}", yaml_str(&format!("{GEOX_MIRROR}{file}")))
            }))
            .collect(),
    }
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
            if let Ok(value) = serde_json::from_str::<Value>(body) {
                if let Some(name) = value["name"].as_str() {
                    names.push(name.to_string());
                    pending = false;
                }
                continue;
            }
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

/// Rewrite `network: httpupgrade` items of a Clash `proxies` chunk to Mihomo's
/// `network: ws` + `ws-opts.v2ray-http-upgrade: true` (see
/// `subconv::normalize_ws_network`), keeping all other text and comments.
/// Handles one-line flow items and block items; an item whose `ws-opts` cannot
/// be read stays as it is. Returns the names of the rewritten items.
pub(crate) fn normalize_httpupgrade_items(chunk: &mut YamlChunk) -> Vec<String> {
    let mut names = Vec::new();
    if chunk.key.as_deref() != Some("proxies") {
        return names;
    }
    let item_indent = chunk
        .lines
        .iter()
        .skip(1)
        .find(|l| l.trim_start().starts_with('-'))
        .map(|l| leading_spaces(l));
    let Some(item_indent) = item_indent else {
        return names;
    };
    let starts: Vec<usize> = (1..chunk.lines.len())
        .filter(|&i| {
            leading_spaces(&chunk.lines[i]) == item_indent
                && chunk.lines[i].trim_start().starts_with('-')
        })
        .collect();
    // Back to front, so lines inserted into one item do not shift the next.
    for (k, &start) in starts.iter().enumerate().rev() {
        let end = starts.get(k + 1).copied().unwrap_or(chunk.lines.len());
        let name = if chunk.lines[start].trim_start()[1..]
            .trim_start()
            .starts_with('{')
        {
            normalize_flow_item(&mut chunk.lines[start])
        } else {
            normalize_block_item(&mut chunk.lines, start, end)
        };
        names.extend(name);
    }
    names.reverse();
    names
}

fn is_httpupgrade(token: &str) -> bool {
    let t = token.trim();
    let t = ['"', '\'']
        .iter()
        .find_map(|q| t.strip_prefix(*q)?.strip_suffix(*q))
        .unwrap_or(t);
    t.eq_ignore_ascii_case("httpupgrade")
}

/// A YAML null: `~`, `null` or nothing.
fn is_null(token: &str) -> bool {
    matches!(token.trim(), "" | "~" | "null" | "Null" | "NULL")
}

/// The value that sets a key whose value spans `start..end`; an empty span
/// sits right after the colon.
fn true_value(start: usize, end: usize) -> &'static str {
    if start == end {
        " true"
    } else {
        "true"
    }
}

/// The edit (byte range in `map`, replacement) that makes the flow map `map`
/// set `v2ray-http-upgrade: true`; None when `map` is no flow map.
/// `network: httpupgrade` means HTTPUpgrade, so an explicit `false` becomes true.
fn upgrade_flag_edit(map: &str) -> Option<(usize, usize, &'static str)> {
    if !(map.starts_with('{') && map.ends_with('}')) {
        return None;
    }
    if let Some((s, e)) = flow_key_value(map, "v2ray-http-upgrade") {
        return Some((s, e, true_value(s, e)));
    }
    let empty = map[1..map.len() - 1].trim().is_empty();
    Some((
        1,
        1,
        if empty {
            "v2ray-http-upgrade: true"
        } else {
            "v2ray-http-upgrade: true, "
        },
    ))
}

/// A one-line flow item `- {...}`; JSON-style items go through serde_json.
fn normalize_flow_item(line: &mut String) -> Option<String> {
    let open = line.find('{')?;
    if let Ok(mut node) = serde_json::from_str::<Value>(&line[open..]) {
        if !crate::subconv::normalize_ws_network(&mut node) {
            return None;
        }
        *line = format!("{}{node}", &line[..open]);
        return Some(node["name"].as_str().unwrap_or("?").to_string());
    }
    let close = matching_close(line, open)?;
    let flow = &line[open..=close];
    let (vs, ve) = flow_key_value(flow, "network")?;
    if !is_httpupgrade(&flow[vs..ve]) {
        return None;
    }
    let (at, end, text) = match flow_key_value(flow, "ws-opts") {
        Some((os, oe)) if is_null(&flow[os..oe]) => (os, oe, "{v2ray-http-upgrade: true}"),
        Some((os, oe)) => {
            let (s, e, text) = upgrade_flag_edit(&flow[os..oe])?;
            (os + s, os + e, text)
        }
        None => {
            // A trailing comma is valid in a flow map; `,,` is not.
            let body = flow[..flow.len() - 1].trim_end();
            let text = if body.ends_with(',') {
                " ws-opts: {v2ray-http-upgrade: true}"
            } else {
                ", ws-opts: {v2ray-http-upgrade: true}"
            };
            (body.len(), body.len(), text)
        }
    };
    let name = flow_value(&flow[1..], "name").unwrap_or_else(|| "?".into());
    // The later edit first, so the earlier offsets stay valid.
    let mut edits = [(open + vs, open + ve, "ws"), (open + at, open + end, text)];
    edits.sort_by_key(|e| std::cmp::Reverse(e.0));
    for (s, e, text) in edits {
        line.replace_range(s..e, text);
    }
    Some(name)
}

/// A block item in `lines[start..end]`.
fn normalize_block_item(lines: &mut Vec<String>, start: usize, end: usize) -> Option<String> {
    let skip = |l: &String| l.trim().is_empty() || l.trim_start().starts_with('#');
    let first = &lines[start];
    let first_key = first.len() - first.trim_start()[1..].trim_start().len();
    let inline_key = first_key < first.len() && !first[first_key..].starts_with('#');
    let key_indent = if inline_key {
        first_key
    } else {
        leading_spaces(lines[start + 1..end].iter().find(|l| !skip(l))?)
    };
    // (line, byte offset of the key) for each of the item's own keys.
    let keys: Vec<(usize, usize)> = std::iter::once((start, first_key))
        .filter(|_| inline_key)
        .chain(
            (start + 1..end)
                .filter(|&i| !skip(&lines[i]) && leading_spaces(&lines[i]) == key_indent)
                .map(|i| (i, key_indent)),
        )
        .collect();
    let find = |lines: &[String], key: &str| {
        keys.iter()
            .find_map(|&(i, at)| Some((i, block_value(&lines[i], at, key)?)))
    };
    let (net, (vs, ve)) = find(lines, "network")?;
    if !is_httpupgrade(&lines[net][vs..ve]) {
        return None;
    }
    let name = find(lines, "name")
        .map(|(i, (s, e))| clean_scalar(&lines[i][s..e]))
        .unwrap_or_else(|| "?".into());
    // Plan the ws-opts edit before changing anything.
    let mut inline = None;
    let mut insert = None;
    match find(lines, "ws-opts") {
        Some((i, (s, e))) if s == e => {
            let children: Vec<usize> = (i + 1..end)
                .take_while(|&j| skip(&lines[j]) || leading_spaces(&lines[j]) > key_indent)
                .filter(|&j| !skip(&lines[j]))
                .collect();
            let indent = children
                .first()
                .map_or(key_indent + 2, |&j| leading_spaces(&lines[j]));
            let flag = children.iter().find_map(|&j| {
                let value = block_value(&lines[j], indent, "v2ray-http-upgrade")?;
                (leading_spaces(&lines[j]) == indent).then_some((j, value))
            });
            match flag {
                Some((j, (fs, fe))) => inline = Some((j, fs, fe, true_value(fs, fe))),
                None => {
                    let line = format!("{}v2ray-http-upgrade: true", " ".repeat(indent));
                    insert = Some((i + 1, vec![line]));
                }
            }
        }
        Some((i, (s, e))) if is_null(&lines[i][s..e]) => {
            inline = Some((i, s, e, "{v2ray-http-upgrade: true}"));
        }
        Some((i, (s, e))) => {
            let (a, b, text) = upgrade_flag_edit(&lines[i][s..e])?;
            inline = Some((i, s + a, s + b, text));
        }
        None => {
            let pad = " ".repeat(key_indent);
            insert = Some((
                net + 1,
                vec![
                    format!("{pad}ws-opts:"),
                    format!("{pad}  v2ray-http-upgrade: true"),
                ],
            ));
        }
    }
    lines[net].replace_range(vs..ve, "ws");
    if let Some((i, s, e, text)) = inline {
        lines[i].replace_range(s..e, text);
    }
    if let Some((at, new)) = insert {
        lines.splice(at..at, new);
    }
    Some(name)
}

/// Byte span of the value of `key:` at byte `at` of a block line, without a
/// trailing comment. Empty for `key:` alone; a flow map spans to its `}`.
fn block_value(line: &str, at: usize, key: &str) -> Option<(usize, usize)> {
    let after = line[at..]
        .strip_prefix(key)?
        .trim_start_matches(' ')
        .strip_prefix(':')?;
    if !(after.is_empty() || after.starts_with([' ', '\t'])) {
        return None;
    }
    let start = line.len() - after.trim_start().len();
    let v = &line[start..];
    let len = if v.starts_with('#') {
        0
    } else if v.starts_with('{') {
        matching_close(v, 0).map_or(v.trim_end().len(), |c| c + 1)
    } else {
        v.find(" #").map_or(v, |e| &v[..e]).trim_end().len()
    };
    Some((start, start + len))
}

/// Byte span of the value of a top-level `key` in a one-line YAML flow map.
fn flow_key_value(flow: &str, key: &str) -> Option<(usize, usize)> {
    let mut depth = 0usize;
    let mut at_key = false;
    for (i, c) in flow_unquoted(flow) {
        if depth == 1 && at_key && !c.is_whitespace() {
            at_key = false;
            let value = flow[i..]
                .strip_prefix(key)
                .map(str::trim_start)
                .and_then(|a| a.strip_prefix(':'));
            if let Some(value) = value {
                let start = flow.len() - value.trim_start().len();
                let v = &flow[start..];
                let end = match v.chars().next()? {
                    '{' | '[' => matching_close(flow, start)? + 1,
                    q @ ('"' | '\'') => start + 1 + v[1..].find(q)? + 1,
                    _ => start + v.find([',', '}']).map_or(v, |e| &v[..e]).trim_end().len(),
                };
                return Some((start, end));
            }
        }
        match c {
            '[' | '{' => {
                depth += 1;
                at_key = depth == 1;
            }
            ']' | '}' => depth = depth.saturating_sub(1),
            ',' => at_key = depth == 1,
            _ => {}
        }
    }
    None
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

pub(crate) fn pick_name(base: &str, taken: &HashSet<String>) -> String {
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
            Err(reason) => report.manual_skipped.push(format!("source.json: {reason}")),
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
    for r in sub_rules.iter().cloned() {
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
    // sub_rules is empty unless subscription-rules is on.
    report.inspect(&mut chunks, &sub_rules);
    let body = join_chunks(&chunks);
    let body = crate::mihomo::normalize_subscription(&body, input.controller_addr);
    Ok((format!("{GENERATED_MARK}\n{body}"), report))
}

/// Keep TUN / sniffer / DNS / IPv6 switch states and the routing mode from the
/// previous config.
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
    if ["mixed-port", "port", "socks-port"]
        .iter()
        .any(|k| find(k).is_some())
    {
        for key in ["mixed-port", "port", "socks-port"] {
            if find(key).is_none() {
                doc = crate::ops::set_top_scalar(&doc, key, "0");
            }
        }
    }
    for key in [
        "mixed-port",
        "port",
        "socks-port",
        "allow-lan",
        "log-level",
        "find-process-mode",
        "tcp-concurrent",
        "mode",
    ] {
        if let Some(chunk) = find(key) {
            if let Some((_, value)) = chunk.lines.first().and_then(|l| l.split_once(':')) {
                doc = crate::ops::set_top_scalar(&doc, key, &clean_scalar(value));
            }
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

/// The subscription part of a terc-generated config: the copies it inlined
/// from `manual` are dropped, and None means no other node or provider is left.
/// Manual nodes were appended after the subscription's, so the last proxy named
/// like each one (or its ` (n)` rename) is the manual copy.
pub(crate) fn generated_subscription(doc: &str, manual: &[String]) -> Option<String> {
    let doc = crate::ops::strip_marked_modules(doc);
    let body: Vec<&str> = doc
        .lines()
        .skip_while(|l| l.starts_with("# terc-generated"))
        .collect();
    let mut chunks = split_chunks(&body.join("\n"));
    let has_providers = chunks
        .iter()
        .any(|c| c.key.as_deref() == Some("proxy-providers"));
    let proxies = chunks
        .iter_mut()
        .find(|c| c.key.as_deref() == Some("proxies"))?;
    let indent = proxies
        .lines
        .iter()
        .skip(1)
        .find(|l| l.trim_start().starts_with('-'))
        .map(|l| leading_spaces(l));
    let starts: Vec<_> = (1..proxies.lines.len())
        .filter(|&i| {
            let line = &proxies.lines[i];
            Some(leading_spaces(line)) == indent && line.trim_start().starts_with('-')
        })
        .collect();
    let items: Vec<_> = starts
        .iter()
        .enumerate()
        .map(|(n, &start)| {
            let end = starts.get(n + 1).copied().unwrap_or(proxies.lines.len());
            let chunk = YamlChunk {
                key: Some("proxies".into()),
                lines: std::iter::once("proxies:".to_string())
                    .chain(proxies.lines[start..end].iter().cloned())
                    .collect(),
            };
            (
                start..end,
                clash_item_names(&chunk).pop().unwrap_or_default(),
            )
        })
        .collect();
    let mut dropped = HashSet::new();
    for base in manual {
        let renamed = |name: &str| {
            name == base
                || name
                    .strip_prefix(base.as_str())
                    .and_then(|r| r.strip_prefix(" ("))
                    .and_then(|r| r.strip_suffix(')'))
                    .is_some_and(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
        };
        if let Some(i) = (0..items.len())
            .rev()
            .find(|i| !dropped.contains(i) && renamed(&items[*i].1))
        {
            dropped.insert(i);
        }
    }
    let kept = items.len() - dropped.len();
    for i in (0..items.len()).rev().filter(|i| dropped.contains(i)) {
        proxies.lines.drain(items[i].0.clone());
    }
    (kept > 0 || has_providers).then(|| join_chunks(&chunks))
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
    fn manual_nodes_json_add_remove_preserves_source() {
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
        assert!(serde_json::from_str::<ProfileSource>(&text).is_ok());
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
            "wireguard://AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE%3D@192.0.2.40:51820?publickey=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI%3D&address=172.16.0.2%2F32&reserved=1%2C2%2C3&mtu=1280#Own-WG",
            "Own-SSH = ssh, 192.0.2.50, 22, username=root, password=fake",
        ]);
        let clash = "mixed-port: 7897\nproxies:\n  - {name: \"HK 01\", type: ss, server: 192.0.2.5, port: 1, cipher: aes-128-gcm, password: x}\nproxy-groups:\n  - name: Airport\n    type: select\n    proxies: [HK 01]\nrules:\n  - DOMAIN-SUFFIX,google.com,Airport\n  - MATCH,Airport\n";
        let surge = convert_subscription(crate::subconv::tests::SURGE).unwrap();
        let clash = convert_subscription(clash).unwrap();
        // The fake PEM in the fixture would (rightly) fail Mihomo's key parser.
        let wg_profile = crate::subconv::tests::surge_wg_profile()
            .lines()
            .filter(|l| !l.starts_with("KeyJump"))
            .collect::<Vec<_>>()
            .join("\n");
        let wg = convert_subscription(&wg_profile).unwrap();
        assert!(wg.proxies.iter().any(|p| p["name"] == "Mesh"));
        let mut rules = PrivateRules::default();
        rules.rules.push("DOMAIN-SUFFIX,example.org,AI".into());
        rules.rules.push("PROCESS-NAME,curl,DIRECT".into());
        for sub in [None, Some(&surge), Some(&clash), Some(&wg)] {
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

    fn normalized(lines: &[&str]) -> (Vec<String>, Vec<String>) {
        let mut chunk = YamlChunk {
            key: Some("proxies".into()),
            lines: std::iter::once("proxies:")
                .chain(lines.iter().copied())
                .map(String::from)
                .collect(),
        };
        let names = normalize_httpupgrade_items(&mut chunk);
        (names, chunk.lines[1..].to_vec())
    }

    #[test]
    fn httpupgrade_block_items_are_rewritten_in_place() {
        let (names, out) = normalized(&[
            "  - name: Nested",
            "    type: vless",
            "    network: httpupgrade  # from a converter",
            "    ws-opts:",
            "      path: /up",
            "      headers:",
            "        Host: u.example",
            "  # a comment between items",
            "  - name: Bare",
            "    type: trojan",
            "    network: \"HTTPUpgrade\"",
            "    sni: b.example",
            "  - name: Inline",
            "    network: 'httpupgrade'",
            "    ws-opts: {path: /x}",
            "  - name: Set",
            "    network: httpupgrade",
            "    ws-opts:",
            "      path: /s",
            "      v2ray-http-upgrade: true",
            "  - network: httpupgrade",
            "    name: First",
            "  - name: Plain",
            "    network: ws",
            "    ws-opts:",
            "      path: /ws",
            "  - name: Null",
            "    network: httpupgrade",
            "    ws-opts: ~",
            "  - name: Off",
            "    network: httpupgrade",
            "    ws-opts:",
            "      v2ray-http-upgrade: false  # converter default",
            "  - name: Odd",
            "    network: httpupgrade",
            "    ws-opts: [1]",
        ]);
        assert_eq!(
            names,
            ["Nested", "Bare", "Inline", "Set", "First", "Null", "Off"]
        );
        assert_eq!(
            out,
            [
                "  - name: Nested",
                "    type: vless",
                "    network: ws  # from a converter",
                "    ws-opts:",
                "      v2ray-http-upgrade: true",
                "      path: /up",
                "      headers:",
                "        Host: u.example",
                "  # a comment between items",
                "  - name: Bare",
                "    type: trojan",
                "    network: ws",
                "    ws-opts:",
                "      v2ray-http-upgrade: true",
                "    sni: b.example",
                "  - name: Inline",
                "    network: ws",
                "    ws-opts: {v2ray-http-upgrade: true, path: /x}",
                "  - name: Set",
                "    network: ws",
                "    ws-opts:",
                "      path: /s",
                "      v2ray-http-upgrade: true",
                "  - network: ws",
                "    ws-opts:",
                "      v2ray-http-upgrade: true",
                "    name: First",
                "  - name: Plain",
                "    network: ws",
                "    ws-opts:",
                "      path: /ws",
                // A null ws-opts becomes the flag, as in `normalize_ws_network`.
                "  - name: Null",
                "    network: ws",
                "    ws-opts: {v2ray-http-upgrade: true}",
                // `network: httpupgrade` wins over an explicit false.
                "  - name: Off",
                "    network: ws",
                "    ws-opts:",
                "      v2ray-http-upgrade: true  # converter default",
                // ws-opts it cannot read: left alone rather than half rewritten.
                "  - name: Odd",
                "    network: httpupgrade",
                "    ws-opts: [1]",
            ]
        );
        // Other chunks are never touched.
        let mut other = YamlChunk {
            key: Some("x-templates".into()),
            lines: vec![
                "x-templates:".into(),
                "  - {name: T, network: httpupgrade}".into(),
            ],
        };
        let before = other.clone();
        assert!(normalize_httpupgrade_items(&mut other).is_empty());
        assert_eq!(other, before);
    }

    #[test]
    fn httpupgrade_flow_items_are_rewritten_in_place() {
        let (names, out) = normalized(&[
            "  - {name: F1, type: vmess, network: httpupgrade, ws-opts: {path: /f}}",
            "  - {name: F2, type: vmess, network: \"httpupgrade\" }  # kept",
            "  - {name: F3, network: HttpUpgrade, ws-opts: {}}",
            "  - {name: F4, network: httpupgrade, ws-opts: {v2ray-http-upgrade: true, path: /p}}",
            "  - {name: F5, network: ws, ws-opts: {path: /w}}",
            "  - {name: 'a, network: httpupgrade', network: grpc}",
            "  - {name: N, ws-opts: {headers: {network: httpupgrade}}, network: tcp}",
            r#"  - {"name":"J","type":"vless","network":"httpupgrade","ws-opts":{"path":"/j"}}"#,
            "  - {name: T, network: httpupgrade, }",
            "  - {name: U, network: httpupgrade, ws-opts: null}",
            "  - {name: V, network: httpupgrade, ws-opts: {v2ray-http-upgrade: false}}",
        ]);
        assert_eq!(names, ["F1", "F2", "F3", "F4", "J", "T", "U", "V"]);
        assert_eq!(
            out[8..],
            [
                // A trailing comma stays valid YAML (no `,,`).
                "  - {name: T, network: ws, ws-opts: {v2ray-http-upgrade: true} }",
                "  - {name: U, network: ws, ws-opts: {v2ray-http-upgrade: true}}",
                "  - {name: V, network: ws, ws-opts: {v2ray-http-upgrade: true}}",
            ]
        );
        assert_eq!(
            out[..7],
            [
                "  - {name: F1, type: vmess, network: ws, ws-opts: {v2ray-http-upgrade: true, path: /f}}",
                "  - {name: F2, type: vmess, network: ws, ws-opts: {v2ray-http-upgrade: true} }  # kept",
                "  - {name: F3, network: ws, ws-opts: {v2ray-http-upgrade: true}}",
                "  - {name: F4, network: ws, ws-opts: {v2ray-http-upgrade: true, path: /p}}",
                "  - {name: F5, network: ws, ws-opts: {path: /w}}",
                "  - {name: 'a, network: httpupgrade', network: grpc}",
                "  - {name: N, ws-opts: {headers: {network: httpupgrade}}, network: tcp}",
            ]
        );
        assert!(out[7].starts_with("  - {"));
        let json: Value = serde_json::from_str(&out[7][4..]).unwrap();
        assert_eq!(json["network"], "ws");
        assert_eq!(
            json["ws-opts"],
            json!({"path": "/j", "v2ray-http-upgrade": true})
        );
    }

    #[test]
    fn compose_rewrites_httpupgrade_proxies_and_names_them() {
        let doc = "proxies:\r\n  - name: Up\r\n    type: vless\r\n    server: 192.0.2.4\r\n    port: 443\r\n    uuid: 12345678-1234-1234-1234-123456789abc\r\n    network: httpupgrade\r\n  # network: httpupgrade in a comment\r\n  - {name: Ws, type: vless, server: 192.0.2.5, port: 443, uuid: 12345678-1234-1234-1234-123456789abc, network: ws}\r\nx-templates:\r\n  - name: Tpl\r\n    network: httpupgrade\r\nproxy-groups:\r\n  - {name: G, type: select, proxies: [Up, Ws]}\r\nrules:\r\n  - MATCH,G\r\n";
        let sub = convert_subscription(doc).unwrap();
        // A node saved before normalisation existed, loaded as is.
        let nodes = vec![ManualNode {
            line: String::new(),
            parsed: Ok(
                json!({"name": "Own", "type": "trojan", "server": "192.0.2.6",
                "port": 443, "password": "fake", "network": "httpupgrade"}),
            ),
        }];
        let rules = PrivateRules::default();
        let (yaml, report) = compose_profile(&input(Some(&sub), &nodes, &rules)).unwrap();
        assert_eq!(report.normalized, ["Up", "Own"]);
        assert!(
            yaml.contains("    network: ws\n    ws-opts:\n      v2ray-http-upgrade: true\n  # network: httpupgrade in a comment\n"),
            "{yaml}"
        );
        assert!(yaml.contains("network: ws}"));
        assert!(yaml.contains("x-templates:\n  - name: Tpl\n    network: httpupgrade\n"));
        let own = yaml.lines().find(|l| l.contains("\"Own\"")).unwrap();
        let own: Value = serde_json::from_str(own.trim_start()[1..].trim()).unwrap();
        assert_eq!(own["network"], "ws");
        assert_eq!(own["ws-opts"]["v2ray-http-upgrade"], true);
        // The raw source is not rewritten.
        assert!(sub
            .clash_doc
            .as_deref()
            .unwrap()
            .contains("    network: httpupgrade\r\n"));
        assert!(report
            .summary(true)
            .ends_with("  2 个 httpupgrade 节点已改为 ws + v2ray-http-upgrade"));
        assert!(report
            .summary(false)
            .ends_with("  2 httpupgrade node(s) rewritten to ws + v2ray-http-upgrade"));
        assert_eq!(
            report.details(),
            "\n  - 未开启 udp / no udp: Up, Ws, Own\n  - httpupgrade → ws: Up\n  - httpupgrade → ws: Own"
        );
        // Node-list subscriptions are normalised too.
        let list = Converted {
            format: Some(SubFormat::UriList),
            proxies: vec![json!({"name": "L", "type": "vless", "server": "192.0.2.7",
                "port": 443, "uuid": "12345678-1234-1234-1234-123456789abc",
                "network": "httpupgrade"})],
            ..Converted::default()
        };
        let (yaml, report) = compose_profile(&input(Some(&list), &[], &rules)).unwrap();
        assert_eq!(report.normalized, ["L"]);
        assert!(!yaml.contains("httpupgrade\""), "{yaml}");
        assert!(yaml.contains("\"v2ray-http-upgrade\":true"));
        assert!(compose_profile(&input(
            None,
            &manual(&["P = ss, 192.0.2.8, 8388, encrypt-method=aes-128-gcm, password=fake"]),
            &rules
        ))
        .unwrap()
        .1
        .normalized
        .is_empty());
    }

    const DNS_DOC: &str = "dns:\n  enable: true\n  enhanced-mode: fake-ip\n  fake-ip-filter: ['*.lan', 'rule-set:private']\n  nameserver: [223.5.5.5]\n  fallback:\n    - tls://1.1.1.1\n    - https://dns.google/dns-query#Airport\n    - 119.29.29.29\n  nameserver-policy:\n    'rule-set:proxy':\n      - https://cloudflare-dns.com/dns-query\n    geosite:geolocation-!cn: [\"https://dns.google/dns-query\", tls://8.8.8.8#DIRECT]\n    geosite:cn: https://doh.pub/dns-query\nproxies:\n  - {name: HK, type: ss, server: 192.0.2.5, port: 1, cipher: aes-128-gcm, password: x}\n  - name: JP\n    type: vmess\n    server: 192.0.2.6\n    port: 443\n    udp: false\n  - {\"name\":\"SG\",\"type\":\"trojan\",\"server\":\"192.0.2.7\",\"port\":443,\"udp\":true}\n  - {name: US, type: hysteria2, server: 192.0.2.8, port: 443}\n  - name: TW\n    type: vless\n    server: 192.0.2.9\nproxy-groups:\n  - name: Airport\n    type: select\n    proxies: [HK, JP, SG, US, TW]\nrule-providers:\n  private:\n    type: http\n    behavior: domain\n    url: https://example.org/private.yaml\n  proxy:\n    type: http\n    behavior: domain\n    url: https://example.org/proxy.yaml\n  cncidr: {type: http, behavior: ipcidr, url: https://example.org/cncidr.yaml}\nrules:\n  - DOMAIN-SUFFIX,example.org,DIRECT\n  - SRC-IP-CIDR,192.168.1.0/24,DIRECT\n  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve\n  - RULE-SET,proxy,Airport\n  - RULE-SET,cncidr,DIRECT\n  - GEOIP,CN,DIRECT\n  - MATCH,Airport\n";

    #[test]
    fn subscription_rules_off_strips_dns_rule_set_references() {
        let sub = convert_subscription(DNS_DOC).unwrap();
        let (yaml, report) = compose(&input(Some(&sub), &[], &PrivateRules::default())).unwrap();
        assert!(
            !yaml.contains("rule-providers") && !yaml.contains("rule-set:"),
            "{yaml}"
        );
        assert!(yaml.contains("  fake-ip-filter: ['*.lan']\n"), "{yaml}");
        assert!(yaml.contains("  nameserver-policy:\n    geosite:geolocation-!cn:"));
        let removed: Vec<_> = report
            .notes
            .iter()
            .filter(|n| n.contains("not found rule-set"))
            .collect();
        assert_eq!(removed.len(), 2, "{:?}", report.notes);
        // Airport rules are dropped, so the resolution note has nothing to say.
        assert!(!report.notes.iter().any(|n| n.contains("subscription rule")));

        let keep = PrivateRules {
            subscription_rules: true,
            ..PrivateRules::default()
        };
        let (yaml, report) = compose(&input(Some(&sub), &[], &keep)).unwrap();
        assert!(yaml.contains("'rule-set:private'") && yaml.contains("'rule-set:proxy':"));
        assert!(!report
            .notes
            .iter()
            .any(|n| n.contains("not found rule-set")));
        let rule = report
            .notes
            .iter()
            .find(|n| n.contains("subscription rule"))
            .unwrap();
        assert!(rule.contains("rule 5 (RULE-SET,cncidr,DIRECT)"), "{rule}");
    }

    #[test]
    fn report_flags_foreign_direct_dns_and_nodes_without_udp() {
        let sub = convert_subscription(DNS_DOC).unwrap();
        let (_, report) =
            compose_profile(&input(Some(&sub), &[], &PrivateRules::default())).unwrap();
        let notes = report.notes.join("\n");
        assert!(
            notes.contains("dns.fallback dials foreign DNS DIRECT (tls://1.1.1.1)"),
            "{notes}"
        );
        assert!(notes.contains("nameserver-policy rule-set:proxy dials foreign DNS DIRECT (https://cloudflare-dns.com/dns-query)"));
        assert!(notes.contains("geosite:geolocation-!cn dials foreign DNS DIRECT (https://dns.google/dns-query, tls://8.8.8.8#DIRECT)"));
        assert!(!notes.contains("geosite:cn ") && !notes.contains("#Airport"));
        assert!(notes.contains("From subscription rule 5 (RULE-SET,cncidr,DIRECT)"));
        assert_eq!(report.notes.len(), 4, "{notes}");
        assert_eq!(report.no_udp, ["HK", "TW"]);
        assert!(report.summary(true).contains("2 个节点未开启 udp"));
        assert!(report.summary(false).contains("4 config note(s)"));
        assert!(report
            .details()
            .contains("\n  - 未开启 udp / no udp: HK, TW"));

        let quiet = DNS_DOC.replace(
            "  enable: true\n",
            "  enable: true\n  respect-rules: true\n",
        );
        let sub = convert_subscription(&quiet).unwrap();
        let (_, report) =
            compose_profile(&input(Some(&sub), &[], &PrivateRules::default())).unwrap();
        assert!(!report.notes.iter().any(|n| n.contains("foreign DNS")));
    }

    #[test]
    fn runtime_udp_replaces_compose_time_guess() {
        let mut report = ComposeReport {
            no_udp: vec!["HK".into(), "TW".into()],
            ..ComposeReport::default()
        };
        let node = |name: &str, kind: &str, udp| crate::ops::ProviderNode {
            name: name.into(),
            kind: kind.into(),
            udp,
            delay: None,
            provider: "p".into(),
        };
        report.apply_runtime_udp(&[
            node("HK", "Shadowsocks", true),
            node("P1", "Vmess", false),
            node("P2", "Hysteria2", false),
            node("P3", "Http", false),
        ]);
        assert_eq!(report.no_udp, ["TW", "P1"]);
    }

    #[test]
    fn rule_resolution_checks_logic_and_inline_classical_sets() {
        let providers = HashMap::from([
            ("dom".to_string(), ("domain".to_string(), vec![])),
            (
                "mixed".to_string(),
                (
                    "classical".to_string(),
                    vec![
                        "DOMAIN,a.example".to_string(),
                        "IP-CIDR,192.0.2.0/24".to_string(),
                    ],
                ),
            ),
            (
                "safe".to_string(),
                (
                    "classical".to_string(),
                    vec!["IP-CIDR,192.0.2.0/24,no-resolve".to_string()],
                ),
            ),
        ]);
        let resolves = |r: &str| rule_resolves(r, &providers);
        assert!(resolves("GEOIP,LAN,DIRECT"));
        assert!(resolves("IP-ASN,13335,PROXY"));
        assert!(!resolves("GEOIP,CN,DIRECT,no-resolve"));
        assert!(!resolves("SRC-GEOIP,CN,DIRECT"));
        assert!(resolves("RULE-SET,mixed,PROXY"));
        assert!(!resolves("RULE-SET,mixed,PROXY,no-resolve"));
        assert!(!resolves("RULE-SET,safe,PROXY"));
        assert!(!resolves("RULE-SET,dom,PROXY"));
        assert!(resolves(
            "AND,((DOMAIN,a.example),(IP-CIDR,192.0.2.0/24)),PROXY"
        ));
        assert!(!resolves(
            "OR,((DOMAIN,a.example),(IP-CIDR,192.0.2.0/24,no-resolve)),PROXY"
        ));
        assert!(!resolves("MATCH,PROXY"));
    }

    #[test]
    fn emptied_dns_blocks_become_empty_collections() {
        let mut chunks = split_chunks("dns:\n  fake-ip-filter:\n    - rule-set:gone # x\n  nameserver-policy: {'rule-set:gone': 1.1.1.1, '+.lan': system}\n  proxy-server-nameserver-policy:\n    rule-set:gone:\n      - 223.5.5.5\nrule-providers: {kept: {type: http, behavior: domain}}\n");
        let notes = strip_dangling_rule_sets(&mut chunks);
        assert_eq!(notes.len(), 3, "{notes:?}");
        assert_eq!(
            join_chunks(&chunks),
            "dns:\n  fake-ip-filter: []\n  nameserver-policy: {'+.lan': system}\n  proxy-server-nameserver-policy: {}\nrule-providers: {kept: {type: http, behavior: domain}}\n"
        );
        let doc = "dns:\n  fake-ip-filter: ['rule-set:kept', 'RULE-SET,kept,fake-ip']\nrule-providers: {kept: {type: http, behavior: domain}}\n";
        let mut chunks = split_chunks(doc);
        assert!(strip_dangling_rule_sets(&mut chunks).is_empty());
        assert_eq!(join_chunks(&chunks), doc);
    }
}

/// Preserve the source's routing policy. Node-only sources get one simple selector.
/// This is the only composition path exposed while custom routing is paused.
pub fn compose_profile(input: &ComposeInput) -> Result<(String, ComposeReport), String> {
    compose_profile_reserving(input, &HashSet::new())
}

/// compose_profile, with `reserved` group names (from the routing scheme that
/// will replace the source's) kept free of manual node names.
pub fn compose_profile_reserving(
    input: &ComposeInput,
    reserved: &HashSet<String>,
) -> Result<(String, ComposeReport), String> {
    let mut report = ComposeReport::default();
    let mut chunks = match input.subscription.and_then(|s| s.clash_doc.as_deref()) {
        Some(doc) => split_chunks(doc),
        None => split_chunks(&template_base(input.controller_addr, input.secret)),
    };
    // Only the generated config is rewritten; the raw subscription cache is not.
    if input.subscription.is_some_and(|s| s.clash_doc.is_some()) {
        if let Some(c) = chunks
            .iter_mut()
            .find(|c| c.key.as_deref() == Some("proxies"))
        {
            report.normalized = normalize_httpupgrade_items(c);
        }
    }
    // Source sub-rules stay: its SUB-RULE rules reference them.
    let mut names = HashSet::new();
    if let Some(c) = chunks.iter().find(|c| c.key.as_deref() == Some("proxies")) {
        names.extend(clash_item_names(c));
    }
    let mut new_nodes = Vec::new();
    if let Some(sub) = input.subscription {
        report.format = sub.format;
        report.sub_skipped = sub.skipped.clone();
        if sub.clash_doc.is_none() {
            for node in &sub.proxies {
                if let Some(name) = node["name"].as_str() {
                    names.insert(name.to_string());
                }
                let mut node = node.clone();
                if crate::subconv::normalize_ws_network(&mut node) {
                    let name = node["name"].as_str().unwrap_or("?");
                    report.normalized.push(name.to_string());
                }
                new_nodes.push(node);
            }
            if !sub.groups.is_empty() {
                chunks.push(YamlChunk {
                    key: Some("proxy-groups".into()),
                    lines: std::iter::once("proxy-groups:".into())
                        .chain(sub.groups.iter().map(|g| format!("  - {g}")))
                        .collect(),
                });
            }
            if !sub.rules.is_empty() {
                chunks.push(YamlChunk {
                    key: Some("rules".into()),
                    lines: std::iter::once("rules:".into())
                        .chain(sub.rules.iter().map(|r| format!("  - {}", yaml_str(r))))
                        .collect(),
                });
            }
            if !sub.rule_providers.is_empty() {
                chunks.push(YamlChunk {
                    key: Some("rule-providers".into()),
                    lines: std::iter::once("rule-providers:".into())
                        .chain(
                            sub.rule_providers
                                .iter()
                                .map(|(k, v)| format!("  {}: {v}", yaml_str(k))),
                        )
                        .collect(),
                });
            }
        }
    }
    report.sub_nodes = names.len();
    // Manual nodes must not reuse a proxy or group name.
    let mut taken = names.clone();
    taken.extend(reserved.iter().cloned());
    if let Some(c) = chunks
        .iter()
        .find(|c| c.key.as_deref() == Some("proxy-groups"))
    {
        taken.extend(clash_item_names(c));
    }
    let mut manual_names = Vec::new();
    for node in input.manual {
        match &node.parsed {
            Ok(node) => {
                let mut node = node.clone();
                let base = node["name"].as_str().unwrap_or("node").to_string();
                let mut name = base.clone();
                let mut n = 2;
                while taken.contains(&name) {
                    name = format!("{base} ({n})");
                    n += 1;
                }
                taken.insert(name.clone());
                names.insert(name.clone());
                manual_names.push(name.clone());
                node["name"] = json!(name);
                if crate::subconv::normalize_ws_network(&mut node) {
                    report.normalized.push(name);
                }
                new_nodes.push(node);
            }
            Err(reason) => report.manual_skipped.push(reason.clone()),
        }
    }
    report.manual_nodes = manual_names.len();
    let has_providers = chunks
        .iter()
        .any(|c| c.key.as_deref() == Some("proxy-providers"));
    if names.is_empty() && !has_providers {
        return Err("没有可用节点，请在设置 → 代理订阅导入订阅或节点 / Import nodes under Settings → Proxy subscriptions".into());
    }
    let items: Vec<_> = new_nodes.iter().map(Value::to_string).collect();
    if let Some(c) = chunks
        .iter_mut()
        .find(|c| c.key.as_deref() == Some("proxies"))
    {
        if !items.is_empty() {
            append_items(c, &items)?;
        }
    } else {
        chunks.push(YamlChunk {
            key: Some("proxies".into()),
            lines: std::iter::once("proxies:".into())
                .chain(items.iter().map(|i| format!("  - {i}")))
                .collect(),
        });
    }
    let group_names = chunks
        .iter()
        .find(|c| c.key.as_deref() == Some("proxy-groups"))
        .map(clash_item_names)
        .unwrap_or_default();
    let fallback = if let Some(name) = group_names.first() {
        name.clone()
    } else {
        let name = pick_name("PROXY", &taken);
        chunks.retain(|c| c.key.as_deref() != Some("proxy-groups"));
        let group =
            json!({"name":name,"type":"select","include-all":true,"exclude-filter":INFO_EXCLUDE});
        chunks.push(YamlChunk {
            key: Some("proxy-groups".into()),
            lines: vec!["proxy-groups:".into(), format!("  - {group}")],
        });
        name
    };
    if !manual_names.is_empty() {
        if let Some(c) = chunks
            .iter_mut()
            .find(|c| c.key.as_deref() == Some("proxy-groups"))
        {
            append_manual_members(c, &manual_names);
        }
    }
    let has_rules = chunks
        .iter()
        .find(|c| c.key.as_deref() == Some("rules"))
        .is_some_and(|c| {
            c.lines.iter().any(|l| l.trim_start().starts_with('-'))
                || c.lines.first().is_some_and(|l| {
                    !clean_scalar(l.split_once(':').map(|(_, v)| v).unwrap_or("")).is_empty()
                        && !l.trim_end().ends_with("[]")
                })
        });
    if !has_rules {
        chunks.retain(|c| c.key.as_deref() != Some("rules"));
        chunks.push(YamlChunk {
            key: Some("rules".into()),
            lines: vec![
                "rules:".into(),
                format!("  - {}", yaml_str(&format!("MATCH,{fallback}"))),
            ],
        });
    }
    // The source's routing is kept here, as with subscription-rules on.
    let sub_rules = chunks
        .iter()
        .rfind(|c| c.key.as_deref() == Some("rules"))
        .map(clash_rule_items)
        .unwrap_or_default();
    report.inspect(&mut chunks, &sub_rules);
    // A source's own geox-url, even a partial one, is left as it is.
    if !chunks.iter().any(|c| c.key.as_deref() == Some("geox-url")) {
        let pos = chunks
            .iter()
            .position(|c| c.key.as_deref() == Some("proxies"))
            .unwrap_or(chunks.len());
        chunks.insert(pos, geox_url_chunk());
    }
    let body = crate::mihomo::normalize_subscription(&join_chunks(&chunks), input.controller_addr);
    let body = crate::ops::set_top_scalar(&body, "secret", &json!(input.secret).to_string());
    Ok((format!("{GENERATED_MARK}\n{body}"), report))
}

fn append_manual_members(groups: &mut YamlChunk, names: &[String]) {
    let Some(indent) = groups
        .lines
        .iter()
        .skip(1)
        .filter(|l| l.trim_start().starts_with('-'))
        .map(|l| leading_spaces(l))
        .min()
    else {
        return;
    };
    let starts: Vec<_> = groups
        .lines
        .iter()
        .enumerate()
        .filter(|(_, l)| leading_spaces(l) == indent && l.trim_start().starts_with('-'))
        .map(|(i, _)| i)
        .collect();
    for (n, start) in starts.iter().enumerate().rev() {
        let end = starts.get(n + 1).copied().unwrap_or(groups.lines.len());
        let block = &groups.lines[*start..end];
        // A group that already lists a node (a migrated snapshot) keeps one entry.
        let listed = group_members(block);
        let names: Vec<_> = names.iter().filter(|n| !listed.contains(*n)).collect();
        if names.is_empty() {
            continue;
        }
        // JSON flow groups are emitted by terc's Surge converter.
        if let Ok(mut value) =
            serde_json::from_str::<Value>(block[0].trim_start().trim_start_matches('-').trim())
        {
            if value["type"] == "select"
                && value["include-all"] != true
                && value["include-all-proxies"] != true
            {
                if let Some(members) = value["proxies"].as_array_mut() {
                    members.extend(names.iter().map(|n| json!(n)));
                    groups.lines[*start] = format!("{}- {value}", " ".repeat(indent));
                }
            }
            continue;
        }
        let members = names
            .iter()
            .map(|n| yaml_str(n))
            .collect::<Vec<_>>()
            .join(", ");
        let flow = block[0].trim_start().trim_start_matches('-').trim();
        if flow.starts_with('{') {
            let inner = flow.trim_start_matches('{');
            if flow_value(inner, "type").as_deref() == Some("select")
                && ["include-all", "include-all-proxies"]
                    .iter()
                    .all(|k| flow_value(inner, k).as_deref() != Some("true"))
            {
                let pad = " ".repeat(indent);
                if let Some((open, close)) = flow_key_list(flow, "proxies") {
                    let sep = if flow[open + 1..close].trim().is_empty() {
                        ""
                    } else {
                        ", "
                    };
                    groups.lines[*start] =
                        format!("{pad}- {}{sep}{members}{}", &flow[..close], &flow[close..]);
                } else if let Some(close) = matching_close(flow, 0) {
                    let sep = if flow[1..close].trim().is_empty() {
                        ""
                    } else {
                        ", "
                    };
                    groups.lines[*start] = format!(
                        "{pad}- {}{sep}proxies: [{members}]{}",
                        flow[..close].trim_end(),
                        &flow[close..]
                    );
                }
            }
            continue;
        }
        if !block.iter().any(|l| l.trim() == "type: select")
            || block.iter().any(|l| {
                let t = l.trim().trim_start_matches('-').trim_start();
                t == "include-all: true" || t == "include-all-proxies: true"
            })
        {
            continue;
        }
        // The first field may share the item's `- ` line.
        let Some(pos) = block.iter().enumerate().position(|(i, l)| {
            let t = l.trim_start();
            let t = if i == 0 {
                t.trim_start_matches('-').trim_start()
            } else {
                t
            };
            t.starts_with("proxies:")
        }) else {
            groups.lines.insert(
                end,
                format!("{}proxies: [{members}]", " ".repeat(indent + 2)),
            );
            continue;
        };
        let at = *start + pos;
        let line = &groups.lines[at];
        let key = line.find("proxies:").unwrap_or(0) + "proxies:".len();
        let span = line[key..]
            .find(|c: char| !c.is_whitespace())
            .map(|i| key + i)
            .filter(|&i| line[i..].starts_with('['))
            .and_then(|open| matching_close(line, open).map(|close| (open, close)));
        if let Some((open, close)) = span {
            let sep = if line[open + 1..close].trim().is_empty() {
                ""
            } else {
                ", "
            };
            groups.lines[at] = format!("{}{sep}{members}{}", &line[..close], &line[close..]);
        } else {
            let field_indent = leading_spaces(line);
            let insert = groups.lines[at + 1..end]
                .iter()
                .position(|l| {
                    !l.trim().is_empty()
                        && leading_spaces(l) <= field_indent
                        && !l.trim_start().starts_with('-')
                })
                .map(|p| at + 1 + p)
                .unwrap_or(end);
            let item_indent = groups.lines[at + 1..end]
                .iter()
                .find(|l| l.trim_start().starts_with('-'))
                .map(|l| leading_spaces(l))
                .unwrap_or(field_indent + 2);
            groups.lines.splice(
                insert..insert,
                names
                    .iter()
                    .map(|n| format!("{}- {}", " ".repeat(item_indent), yaml_str(n))),
            );
        }
    }
}

/// Names in the `proxies` list of one proxy-groups item (best effort).
fn group_members(block: &[String]) -> Vec<String> {
    let split = |text: &str, open: usize| {
        let Some(close) = matching_close(text, open) else {
            return Vec::new();
        };
        let inner = &text[open + 1..close];
        let mut parts = Vec::new();
        let (mut from, mut depth) = (0, 0usize);
        for (i, c) in flow_unquoted(inner) {
            match c {
                '[' | '{' => depth += 1,
                ']' | '}' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    parts.push(clean_scalar(&inner[from..i]));
                    from = i + 1;
                }
                _ => {}
            }
        }
        parts.push(clean_scalar(&inner[from..]));
        parts.retain(|p| !p.is_empty());
        parts
    };
    let first = block[0].trim_start().trim_start_matches('-').trim();
    if first.starts_with('{') {
        return flow_key_list(first, "proxies")
            .map(|(open, _)| split(first, open))
            .unwrap_or_default();
    }
    let Some(pos) = block.iter().enumerate().position(|(i, l)| {
        let t = l.trim_start();
        let t = if i == 0 {
            t.trim_start_matches('-').trim_start()
        } else {
            t
        };
        t.starts_with("proxies:")
    }) else {
        return Vec::new();
    };
    let line = &block[pos];
    let value = line[line.find("proxies:").unwrap_or(0) + "proxies:".len()..].trim_start();
    if value.starts_with('[') {
        return split(value, 0);
    }
    let field_indent = leading_spaces(line);
    block[pos + 1..]
        .iter()
        .take_while(|l| {
            l.trim().is_empty()
                || leading_spaces(l) > field_indent
                || l.trim_start().starts_with('-')
        })
        .filter_map(|l| l.trim().strip_prefix('-').map(clean_scalar))
        .collect()
}

/// Characters of YAML flow text outside quoted scalars, with their byte index.
fn flow_unquoted(text: &str) -> Vec<(usize, char)> {
    let mut out = Vec::new();
    let mut quote = None;
    let mut escaped = false;
    let mut prev = '{';
    for (i, c) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if c == '\\' && q == '"' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        // A quote only opens a scalar where a value can start, not mid-word.
        if (c == '"' || c == '\'') && matches!(prev, '{' | '[' | ',' | ':') {
            quote = Some(c);
            continue;
        }
        if !c.is_whitespace() {
            prev = c;
        }
        out.push((i, c));
    }
    out
}

/// Byte index of the bracket closing the `[` or `{` at `open`.
fn matching_close(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in flow_unquoted(&text[open..]) {
        match c {
            '[' | '{' => depth += 1,
            ']' | '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(open + i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Byte span of the `[...]` value of a top-level `key` in a YAML flow mapping.
fn flow_key_list(flow: &str, key: &str) -> Option<(usize, usize)> {
    let mut depth = 0usize;
    let mut at_key = false;
    for (i, c) in flow_unquoted(flow) {
        if depth == 1 && at_key && !c.is_whitespace() {
            at_key = false;
            let value = flow[i..]
                .strip_prefix(key)
                .map(str::trim_start)
                .and_then(|a| a.strip_prefix(':'));
            if let Some(value) = value {
                let value = value.trim_start();
                let open = flow.len() - value.len();
                return value
                    .starts_with('[')
                    .then(|| matching_close(flow, open).map(|close| (open, close)))
                    .flatten();
            }
        }
        match c {
            '[' | '{' => {
                depth += 1;
                at_key = depth == 1;
            }
            ']' | '}' => depth = depth.saturating_sub(1),
            ',' => at_key = depth == 1,
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod profile_tests {
    use super::*;

    const CLASH: &str = "mixed-port: 7897\nproxies:\n  - {name: HK, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: fake}\nproxy-groups:\n  - name: Airport\n    type: select\n    proxies: [HK]\nrules:\n  - DOMAIN-SUFFIX,example.org,DIRECT\n  - MATCH,Airport\n";
    fn build(sub: Option<&Converted>, nodes: &[ManualNode]) -> String {
        let mut rules = PrivateRules::default();
        rules.rules.push("DOMAIN-SUFFIX,custom.invalid,AI".into());
        compose_profile(&ComposeInput {
            subscription: sub,
            manual: nodes,
            rules: &rules,
            controller_addr: "127.0.0.1:9090",
            secret: "local-secret",
            test_url: "https://example.org",
        })
        .unwrap()
        .0
    }
    fn manual() -> Vec<ManualNode> {
        let line = "Own = ss, 192.0.2.2, 8388, encrypt-method=aes-128-gcm, password=fake";
        vec![ManualNode {
            line: line.into(),
            parsed: parse_node_line(line),
        }]
    }

    #[test]
    fn profile_preserves_source_rules_groups_and_includes_manual_nodes() {
        let sub = convert_subscription(CLASH).unwrap();
        let yaml = build(Some(&sub), &manual());
        assert!(yaml.contains("DOMAIN-SUFFIX,example.org,DIRECT"));
        assert!(yaml.contains("MATCH,Airport"));
        assert!(yaml.contains("proxies: [HK, \"Own\"]"));
        assert!(!yaml.contains("custom.invalid"));
        let chunks = split_chunks(&yaml);
        let groups = chunks
            .iter()
            .find(|c| c.key.as_deref() == Some("proxy-groups"))
            .unwrap();
        assert_eq!(clash_item_names(groups), vec!["Airport"]);
        assert!(yaml.contains("secret: \"local-secret\""));
        let flow = CLASH.replace(
            "  - name: Airport\n    type: select\n    proxies: [HK]",
            "  - {name: Airport, type: select, proxies: [HK]}",
        );
        let yaml = build(Some(&convert_subscription(&flow).unwrap()), &manual());
        assert!(yaml.contains("proxies: [HK, \"Own\"]"));
    }

    #[test]
    fn geodata_mirror_fills_only_an_absent_geox_url() {
        let geox = |yaml: &str| {
            split_chunks(yaml)
                .into_iter()
                .filter(|c| c.key.as_deref() == Some("geox-url"))
                .map(|c| c.lines.join("\n"))
                .collect::<Vec<_>>()
        };
        let mirror = |file: &str| format!("\"{GEOX_MIRROR}{file}\"");
        let clash = build(Some(&convert_subscription(CLASH).unwrap()), &manual());
        let found = geox(&clash);
        assert_eq!(found.len(), 1, "{clash}");
        for (key, file) in [
            ("geoip", "geoip.dat"),
            ("geosite", "geosite.dat"),
            ("mmdb", "country.mmdb"),
            ("asn", "GeoLite2-ASN.mmdb"),
        ] {
            assert!(
                found[0].contains(&format!("  {key}: {}", mirror(file))),
                "{clash}"
            );
        }
        // Placed ahead of the node list, and recomposing keeps one copy.
        assert!(clash.find("geox-url:").unwrap() < clash.find("proxies:").unwrap());
        let again = build(Some(&convert_subscription(&clash).unwrap()), &manual());
        assert_eq!(geox(&again), found);
        // A source's own geox-url, even with one key, is left alone.
        let own = format!("geox-url:\n  geosite: \"https://example.org/gs.dat\"\n{CLASH}");
        let kept = build(Some(&convert_subscription(&own).unwrap()), &manual());
        assert_eq!(
            geox(&kept),
            vec!["geox-url:\n  geosite: \"https://example.org/gs.dat\"".to_string()]
        );
        assert!(!kept.contains(GEOX_MIRROR));
        // The template carries all four keys and a quiet core log.
        let template = build(None, &manual());
        assert_eq!(geox(&template), found);
        assert!(template.contains("\nlog-level: warning\n"));
        let source_level = format!("log-level: debug\n{CLASH}");
        let source_level = build(Some(&convert_subscription(&source_level).unwrap()), &[]);
        assert!(source_level.contains("log-level: debug\n"));
        assert!(!source_level.contains("log-level: warning"));
    }

    #[test]
    fn generated_snapshot_keeps_subscription_nodes_without_manual_copies() {
        let proxy_names = |yaml: &str| {
            split_chunks(yaml)
                .iter()
                .find(|c| c.key.as_deref() == Some("proxies"))
                .map(clash_item_names)
                .unwrap_or_default()
        };
        let own = vec!["Own".to_string()];
        let generated = build(Some(&convert_subscription(CLASH).unwrap()), &manual());
        let snapshot = generated_subscription(&generated, &own).unwrap();
        assert!(!snapshot.contains(GENERATED_MARK));
        assert_eq!(proxy_names(&snapshot), vec!["HK"]);
        // Recomposing lists the manual node once, in the proxies and the group.
        let yaml = build(Some(&convert_subscription(&snapshot).unwrap()), &manual());
        assert_eq!(proxy_names(&yaml), vec!["HK", "Own"]);
        assert!(yaml.contains("proxies: [HK, \"Own\"]"), "{yaml}");
        // A renamed manual copy goes; the subscription node it collided with stays.
        let clash = CLASH
            .replace("name: HK,", "name: Own,")
            .replace("[HK]", "[Own]");
        let generated = build(Some(&convert_subscription(&clash).unwrap()), &manual());
        assert_eq!(proxy_names(&generated), vec!["Own", "Own (2)"]);
        let snapshot = generated_subscription(&generated, &own).unwrap();
        assert_eq!(proxy_names(&snapshot), vec!["Own"]);
        assert!(snapshot.contains("192.0.2.1"));
        // Nothing but manual nodes: no subscription is left.
        assert!(generated_subscription(&build(None, &manual()), &own).is_none());
    }

    fn proxy_group_line(yaml: &str, name: &str) -> String {
        yaml.lines()
            .find(|l| l.contains(&format!("name: {name},")))
            .unwrap()
            .to_string()
    }

    #[test]
    fn manual_nodes_join_flow_group_proxies_not_providers() {
        let flow = CLASH.replace(
            "  - name: Airport\n    type: select\n    proxies: [HK]",
            "  - {name: Airport, type: select, include-all-proxies: false, proxies: [HK], use: [prov]}\n  - {name: Pool, type: select, use: [prov]}",
        ) + "proxy-providers:\n  prov: {type: file, path: ./prov.yaml}\n";
        let yaml = build(Some(&convert_subscription(&flow).unwrap()), &manual());
        assert_eq!(
            proxy_group_line(&yaml, "Airport").trim(),
            "- {name: Airport, type: select, include-all-proxies: false, proxies: [HK, \"Own\"], use: [prov]}"
        );
        assert_eq!(
            proxy_group_line(&yaml, "Pool").trim(),
            "- {name: Pool, type: select, use: [prov], proxies: [\"Own\"]}"
        );
        let block = CLASH.replace(
            "    proxies: [HK]",
            "    proxies: [HK] # [note]\n    use: [prov]",
        ) + "proxy-providers:\n  prov: {type: file, path: ./prov.yaml}\n";
        let yaml = build(Some(&convert_subscription(&block).unwrap()), &manual());
        assert!(yaml.contains("    proxies: [HK, \"Own\"] # [note]\n    use: [prov]\n"));
        let flow = CLASH.replace(
            "  - name: Airport\n    type: select\n    proxies: [HK]",
            "  - {name: Airport, type: select, proxies: [HK], use: [P]}\n  - {name: All, type: select, include-all-proxies: true, use: [P]}\n  - name: Block\n    type: select\n    include-all-proxies: true\n    use: [P]\n  - {\"name\":\"Json\",\"type\":\"select\",\"include-all-proxies\":true,\"proxies\":[\"HK\"]}",
        ) + "proxy-providers:\n  P: {type: file, path: ./p.yaml}\n";
        let yaml = build(Some(&convert_subscription(&flow).unwrap()), &manual());
        assert!(yaml.contains("- {name: Airport, type: select, proxies: [HK, \"Own\"], use: [P]}"));
        assert!(yaml.contains("- {name: All, type: select, include-all-proxies: true, use: [P]}"));
        assert!(yaml.contains("    include-all-proxies: true\n    use: [P]\n"));
        assert!(!yaml.contains("[\"HK\",\"Own\"]"));
        assert_eq!(yaml.matches("\"Own\"").count(), 2, "{yaml}");
        let tricky = "{name: \"a, proxies: [x]\", note: it's, proxies: [\"]\", HK], use: [p]}";
        let (open, close) = flow_key_list(tricky, "proxies").unwrap();
        assert_eq!(&tricky[open..=close], "[\"]\", HK]");
    }

    #[test]
    fn manual_node_named_like_a_group_is_renamed() {
        let line = "Airport = ss, 192.0.2.2, 8388, encrypt-method=aes-128-gcm, password=fake";
        let nodes = vec![ManualNode {
            line: line.into(),
            parsed: parse_node_line(line),
        }];
        let yaml = build(Some(&convert_subscription(CLASH).unwrap()), &nodes);
        assert!(yaml.contains("\"name\":\"Airport (2)\""));
        assert!(yaml.contains("proxies: [HK, \"Airport (2)\"]"));
        let surge = "[Proxy]\nJP = trojan, 192.0.2.3, 443, password=fake\n[Proxy Group]\nAirport = select, JP\n[Rule]\nFINAL,Airport\n";
        let yaml = build(Some(&convert_subscription(surge).unwrap()), &nodes);
        assert!(yaml.contains("\"name\":\"Airport (2)\""));
        assert!(!yaml.contains("\"name\":\"Airport\",\"server\""));
        let (yaml, _) = compose_profile_reserving(
            &ComposeInput {
                subscription: None,
                manual: &manual(),
                rules: &PrivateRules::default(),
                controller_addr: "127.0.0.1:9090",
                secret: "",
                test_url: "https://example.org",
            },
            &HashSet::from(["Own".to_string(), "Own (2)".to_string()]),
        )
        .unwrap();
        assert!(yaml.contains("\"name\":\"Own (3)\""), "{yaml}");
    }

    #[test]
    fn profile_keeps_source_sub_rules() {
        let doc = CLASH.replace(
            "  - MATCH,Airport\n",
            "  - SUB-RULE,(NETWORK,tcp),s1\n  - MATCH,Airport\nsub-rules:\n  s1:\n    - DOMAIN-SUFFIX,example.net,Airport\n    - MATCH,DIRECT\n",
        );
        let yaml = build(Some(&convert_subscription(&doc).unwrap()), &manual());
        assert!(yaml.contains("SUB-RULE,(NETWORK,tcp),s1"));
        assert!(yaml.contains("sub-rules:\n  s1:\n    - DOMAIN-SUFFIX,example.net,Airport\n"));
    }

    #[test]
    fn node_only_profiles_have_one_selector_and_no_custom_presets() {
        let yaml = build(None, &manual());
        let chunks = split_chunks(&yaml);
        let groups = chunks
            .iter()
            .find(|c| c.key.as_deref() == Some("proxy-groups"))
            .unwrap();
        assert_eq!(clash_item_names(groups), vec!["PROXY"]);
        assert!(yaml.contains("MATCH,PROXY"));
        assert!(!yaml.contains("custom.invalid"));
        assert!(!yaml.contains("GEOIP,CN"));
        let copied = carry_runtime_state("port: 7890\nsocks-port: 7891\n", &yaml);
        assert!(copied.contains("mixed-port: 0"));
        crate::mihomo::validate_listener_ports(&copied).unwrap();
    }

    #[test]
    #[ignore = "requires an installed Mihomo; validates temporary configs only"]
    fn real_core_accepts_profile_sources() {
        let bin = crate::mihomo::discover_mihomo_binary().unwrap();
        let dir =
            std::env::temp_dir().join(format!("terc-profile-validation-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let surge="[Proxy]\nJP = trojan, 192.0.2.3, 443, password=fake\n[Proxy Group]\nAirport = select, JP\n[Rule]\nDOMAIN-SUFFIX,example.org,DIRECT\nFINAL,Airport\n";
        for source in [None, Some(CLASH), Some(surge)] {
            let converted = source.map(|s| convert_subscription(s).unwrap());
            let yaml = build(converted.as_ref(), &manual());
            crate::mihomo::validate_listener_ports(&yaml).unwrap();
            let path = dir.join("config.yaml");
            fs::write(&path, &yaml).unwrap();
            let out = std::process::Command::new(&bin)
                .arg("-t")
                .arg("-d")
                .arg(&dir)
                .arg("-f")
                .arg(&path)
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{} {}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
