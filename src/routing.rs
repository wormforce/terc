//! Routing templates contain policy only. Proxy credentials and providers belong
//! to the selected subscription, and are never imported from a routing plan.
use crate::ops::{clean_scalar, join_chunks, split_chunks, YamlChunk};
use serde_json::json;
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::PathBuf,
};

#[derive(Clone, Debug)]
pub struct Entry {
    pub id: String,
    pub label: String,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct Plan {
    name: String,
    yaml: String,
}
fn directory() -> PathBuf {
    crate::compose::terc_dir().join("routing")
}
pub fn selected(cfg: &crate::mihomo::ControllerConfig) -> String {
    let source = crate::compose::ProfileSource::load(&crate::compose::profile_dir(cfg));
    if source.routing.is_empty() {
        "subscription".into()
    } else {
        source.routing
    }
}
pub fn entries(cfg: &crate::mihomo::ControllerConfig, zh: bool) -> Vec<Entry> {
    let mut entries = vec![
        Entry {
            id: "subscription".into(),
            label: if zh {
                "跟随订阅分流"
            } else {
                "Subscription routing"
            }
            .into(),
        },
        Entry {
            id: "all".into(),
            label: if zh { "全部代理" } else { "Proxy all" }.into(),
        },
    ];
    if crate::compose::profile_dir(cfg)
        .join("routing-local.yaml")
        .is_file()
    {
        entries.push(Entry {
            id: "local".into(),
            label: if zh {
                "原本地分流（保留）"
            } else {
                "Previous local routing"
            }
            .into(),
        });
    }
    for source in crate::storage::list(&cfg.profile_id) {
        if std::path::Path::new(&source.path)
            .join("subscription.yaml")
            .is_file()
        {
            entries.push(Entry {
                id: format!("source:{}", source.name),
                label: if zh {
                    format!("{} 的分流", source.label)
                } else {
                    format!("{} routing", source.label)
                },
            });
        }
    }
    if let Ok(files) = fs::read_dir(directory()) {
        let mut saved: Vec<_> = files
            .flatten()
            .filter_map(|f| {
                if f.path().extension()?.to_str()? != "json" {
                    return None;
                }
                let plan: Plan = serde_json::from_str(&fs::read_to_string(f.path()).ok()?).ok()?;
                Some(Entry {
                    id: f.path().file_stem()?.to_str()?.into(),
                    label: plan.name,
                })
            })
            .collect();
        saved.sort_by(|a, b| a.id.cmp(&b.id));
        entries.extend(saved);
    }
    entries
}
pub fn save(name: &str, raw: &str) -> Result<String, String> {
    let yaml = template(raw)?;
    let dir = directory();
    let mut n = 1;
    while dir.join(format!("plan-{n}.json")).exists() {
        n += 1;
    }
    let id = format!("plan-{n}");
    crate::compose::write_private(
        &dir.join(format!("{id}.json")),
        &serde_json::to_string_pretty(&Plan {
            name: name.into(),
            yaml,
        })
        .map_err(|e| e.to_string())?,
    )?;
    Ok(id)
}
fn policy_key(key: Option<&str>) -> bool {
    matches!(
        key,
        Some("proxy-groups" | "rules" | "rule-providers" | "sub-rules")
    )
}
pub fn apply(
    base: &str,
    id: &str,
    cfg: &crate::mihomo::ControllerConfig,
) -> Result<String, String> {
    apply_noting(base, id, cfg).map(|(doc, _)| doc)
}
/// `apply`, also returning a note for each DNS reference to a rule-provider
/// that the replacement plan no longer defines (and that was removed).
pub fn apply_noting(
    base: &str,
    id: &str,
    cfg: &crate::mihomo::ControllerConfig,
) -> Result<(String, Vec<String>), String> {
    if id == "subscription" {
        return Ok((base.into(), Vec::new()));
    }
    let chunks = split_chunks(base);
    let proxies = node_names(&chunks);
    let yaml = if id == "all" {
        let name = crate::compose::pick_name("PROXY", &proxies);
        let group = json!({"name":name,"type":"select","include-all":true,"exclude-filter":crate::compose::INFO_EXCLUDE});
        format!(
            "proxy-groups:\n  - {group}\nrules:\n  - {}\n",
            json!(format!("MATCH,{name}"))
        )
    } else if id == "local" {
        template(
            &fs::read_to_string(crate::compose::profile_dir(cfg).join("routing-local.yaml"))
                .map_err(|e| e.to_string())?,
        )?
    } else if let Some(source_id) = id.strip_prefix("source:") {
        let entry = crate::storage::list(&cfg.profile_id)
            .into_iter()
            .find(|s| s.name == source_id)
            .ok_or("原始分流来源不存在 / Routing source missing")?;
        let raw = fs::read_to_string(std::path::Path::new(&entry.path).join("subscription.yaml"))
            .map_err(|e| e.to_string())?;
        let converted = crate::subconv::convert_subscription(&raw)?;
        let (doc, _) = crate::compose::compose_profile(&crate::compose::ComposeInput {
            subscription: Some(&converted),
            manual: &[],
            rules: &crate::compose::PrivateRules::default(),
            controller_addr: &cfg.addr,
            secret: &cfg.secret,
            test_url: &cfg.test_url,
        })?;
        template(&doc)?
    } else {
        // IDs are generated by save() and selected from the catalog.
        if !id.starts_with("plan-") || !id[5..].chars().all(|c| c.is_ascii_digit()) {
            return Err("未知分流方案 / Unknown routing plan".into());
        }
        let plan: Plan = serde_json::from_str(
            &fs::read_to_string(directory().join(format!("{id}.json")))
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        plan.yaml
    };
    install_policy(chunks, &yaml, &proxies)
}

fn node_names(chunks: &[YamlChunk]) -> HashSet<String> {
    chunks
        .iter()
        .find(|c| c.key.as_deref() == Some("proxies"))
        .map(crate::compose::clash_item_names)
        .unwrap_or_default()
        .into_iter()
        .collect()
}

/// Puts the policy of a routing plan over `base`, whose nodes it draws on.
#[cfg(test)]
fn merge_plan(base: &str, yaml: &str) -> Result<String, String> {
    let chunks = split_chunks(base);
    let proxies = node_names(&chunks);
    install_policy(chunks, yaml, &proxies).map(|(doc, _)| doc)
}

/// Replace the policy chunks of `chunks` with those of the plan `yaml`.
fn install_policy(
    mut chunks: Vec<YamlChunk>,
    yaml: &str,
    proxies: &HashSet<String>,
) -> Result<(String, Vec<String>), String> {
    // Provider nodes are only known after the reload, so with providers a
    // region filter is kept; matching nothing then fails closed through the
    // `empty-fallback: REJECT` written beside it.
    let mut notes = Vec::new();
    let yaml = if has_providers(&chunks) {
        let regions = region_groups(yaml)?;
        if !regions.is_empty() {
            let names = regions.join("、");
            notes.push(format!(
                "地区组 {names} 只用订阅提供者里匹配的节点，没有匹配时拒绝连接；select 组把它排在第一位时默认也会拒绝 / Region group(s) {} use only matching provider nodes and reject connections when none match; a select group that lists one first defaults to it",
                regions.join(", ")
            ));
        }
        yaml.to_string()
    } else {
        let mut dropped = Vec::new();
        let yaml = drop_unmatched_regions(yaml, proxies, &mut dropped)?;
        if !dropped.is_empty() {
            notes.push(format!(
                "地区组 {} 在此来源没有匹配节点，已去掉地区筛选，组内为全部节点 / Region group(s) {} match no node of this source; the region filter was dropped, so they hold every node",
                dropped.join("、"),
                dropped.join(", ")
            ));
        }
        yaml
    };
    let yaml = avoid_names(&yaml, proxies)?;
    chunks.retain(|c| !policy_key(c.key.as_deref()));
    chunks.extend(
        split_chunks(&yaml)
            .into_iter()
            .filter(|c| policy_key(c.key.as_deref())),
    );
    // Plans and templates get the same url-test default as a composed source.
    if let Some(groups) = chunks
        .iter_mut()
        .find(|c| c.key.as_deref() == Some("proxy-groups"))
    {
        crate::compose::default_url_test_tolerance(groups);
    }
    // The source's rule-providers are gone; its DNS block may still name them.
    notes.extend(crate::compose::strip_dangling_rule_sets(&mut chunks));
    Ok((join_chunks(&chunks), notes))
}

// Split flow YAML only at top-level separators, keeping quoted names and nested
// lists intact. Unchanged field values remain YAML, rather than being retyped.
fn flow_parts(text: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0i32;
    let mut quote = None;
    let mut escaped = false;
    for (i, c) in text.char_indices() {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
                continue;
            }
            if c == '\\' && q == '"' {
                escaped = true;
            } else if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '\'' | '"' => quote = Some(c),
            '[' | '{' => depth += 1,
            ']' | '}' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(text[start..i].trim().into());
                start = i + 1;
            }
            _ => {}
        }
    }
    if !text[start..].trim().is_empty() {
        parts.push(text[start..].trim().into());
    }
    parts
}
/// Splits `&name rest` into the anchor name and the rest.
fn strip_anchor(text: &str) -> (Option<&str>, &str) {
    match text.strip_prefix('&') {
        Some(rest) => {
            let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
            (Some(&rest[..end]), rest[end..].trim_start())
        }
        None => (None, text),
    }
}

/// The fields of one group list item. An anchor on the item (`- &g {…}`)
/// is returned so later groups can merge it.
fn group_fields(lines: &[String]) -> Result<(Option<String>, Vec<YamlChunk>), String> {
    let (anchor, first) = strip_anchor(lines[0].trim_start().trim_start_matches('-').trim());
    let anchor = anchor.map(str::to_string);
    if first.starts_with('{') {
        let body = std::iter::once(first)
            .chain(lines.iter().skip(1).map(|s| s.trim()))
            .collect::<Vec<_>>()
            .join(" ");
        Ok((anchor, flow_fields(&body)?))
    } else {
        let indent = lines[0].len() - lines[0].trim_start().len() + 2;
        let rest = lines
            .iter()
            .skip(1)
            .map(|l| l.get(indent..).unwrap_or("").to_string());
        let normalized: Vec<String> = std::iter::once(first.to_string())
            .filter(|l| !l.is_empty())
            .chain(rest)
            .collect();
        Ok((anchor, split_chunks(&normalized.join("\n"))))
    }
}
/// The fields of a flow mapping `{key: value, …}`.
fn flow_fields(body: &str) -> Result<Vec<YamlChunk>, String> {
    let inner = body
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or("策略组格式不完整 / Incomplete group map")?;
    flow_parts(inner)
        .into_iter()
        .map(|field| {
            let (key, value) = field
                .split_once(':')
                .ok_or("策略组字段无效 / Invalid group field")?;
            let key = clean_scalar(key);
            Ok(YamlChunk {
                key: Some(key.clone()),
                lines: vec![format!("{key}: {}", value.trim())],
            })
        })
        .collect()
}
/// Mappings anchored at the top level, such as `p: &p {type: url-test, …}`
/// or `fb: &fb` over a block. A template keeps only policy keys, so groups
/// that merge them with `<<: *p` are expanded instead of left dangling.
fn top_anchors(chunks: &[YamlChunk]) -> HashMap<String, Vec<YamlChunk>> {
    let mut anchors = HashMap::new();
    for chunk in chunks {
        let Some(value) = chunk.lines[0].split_once(':').map(|(_, v)| v.trim()) else {
            continue;
        };
        let (Some(name), rest) = strip_anchor(value) else {
            continue;
        };
        let rest = rest.split(" #").next().unwrap_or(rest).trim();
        let fields = if rest.starts_with('{') {
            let body = std::iter::once(rest)
                .chain(chunk.lines.iter().skip(1).map(|s| s.trim()))
                .collect::<Vec<_>>()
                .join(" ");
            match flow_fields(&body) {
                Ok(fields) => fields,
                Err(_) => continue,
            }
        } else if rest.is_empty() {
            let body: Vec<_> = chunk.lines.iter().skip(1).collect();
            let indent = body
                .iter()
                .filter(|l| !l.trim().is_empty())
                .map(|l| crate::ops::leading_spaces(l))
                .min()
                .unwrap_or(0);
            let lines: Vec<_> = body.iter().map(|l| l.get(indent..).unwrap_or("")).collect();
            split_chunks(&lines.join("\n"))
        } else {
            continue;
        };
        let mut fields: Vec<_> = fields.into_iter().filter(|f| f.key.is_some()).collect();
        if expand_merges(&mut fields, &anchors).is_ok() {
            anchors.insert(name.to_string(), fields);
        }
    }
    anchors
}
/// Replaces `<<: *a` (or `<<: [*a, *b]`) with the anchored fields the group
/// does not set itself, as YAML merge keys do; earlier merges win.
fn expand_merges(
    fields: &mut Vec<YamlChunk>,
    anchors: &HashMap<String, Vec<YamlChunk>>,
) -> Result<(), String> {
    while let Some(i) = fields.iter().position(|f| f.key.as_deref() == Some("<<")) {
        let value = fields[i].lines[0]
            .split_once(':')
            .map(|(_, v)| v.split(" #").next().unwrap_or(v).trim())
            .unwrap_or("");
        let aliases = match value.strip_prefix('[').and_then(|v| v.strip_suffix(']')) {
            Some(inner) => flow_parts(inner),
            None => vec![value.to_string()],
        };
        let mut merged: Vec<YamlChunk> = Vec::new();
        for alias in aliases {
            let source = alias
                .strip_prefix('*')
                .and_then(|name| anchors.get(name))
                .ok_or_else(|| format!("策略组引用了未知锚点 / Unknown YAML anchor {alias}"))?;
            for field in source {
                let taken = |f: &YamlChunk| f.key == field.key;
                if !fields.iter().any(taken) && !merged.iter().any(taken) {
                    merged.push(field.clone());
                }
            }
        }
        fields.splice(i..=i, merged);
    }
    Ok(())
}
fn members(field: &YamlChunk) -> Result<Vec<String>, String> {
    let value = field.lines[0]
        .split_once(':')
        .map(|(_, v)| v.trim())
        .unwrap_or("");
    if let Some(inner) = value.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        Ok(flow_parts(inner).iter().map(|s| clean_scalar(s)).collect())
    } else if value.is_empty() {
        Ok(field
            .lines
            .iter()
            .skip(1)
            .filter_map(|l| l.trim().strip_prefix('-').map(clean_scalar))
            .collect())
    } else {
        Err(
            "保存分流方案需要显式节点列表 / Routing templates require an explicit member list"
                .into(),
        )
    }
}
fn field_value(field: &YamlChunk) -> String {
    let value = field.lines[0]
        .split_once(':')
        .map(|(_, v)| v.trim())
        .unwrap_or("");
    // Regex values may hold `#`, which clean_scalar would cut as a comment.
    if value.starts_with('"') {
        if let Ok(text) = serde_json::from_str::<String>(value) {
            return text;
        }
    } else if let Some(text) = value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) {
        return text.replace("''", "'");
    } else if !value.starts_with('\'') {
        return value.split(" #").next().unwrap_or(value).trim().to_string();
    }
    clean_scalar(value)
}
// Rewrite each group of a proxy-groups chunk as fields, keeping template layout.
// Merge keys are expanded first, from `anchors` and from earlier groups.
fn map_groups(
    groups: &YamlChunk,
    anchors: &HashMap<String, Vec<YamlChunk>>,
    mut edit: impl FnMut(&mut Vec<YamlChunk>) -> Result<(), String>,
) -> Result<Vec<String>, String> {
    let mut anchors = anchors.clone();
    let indent = groups
        .lines
        .iter()
        .skip(1)
        .find(|l| l.trim_start().starts_with('-'))
        .map(|l| l.len() - l.trim_start().len())
        .unwrap_or(2);
    let starts: Vec<_> = groups
        .lines
        .iter()
        .enumerate()
        .skip(1)
        .filter(|(_, l)| {
            l.len() - l.trim_start().len() == indent && l.trim_start().starts_with('-')
        })
        .map(|(i, _)| i)
        .collect();
    let mut output = vec!["proxy-groups:".into()];
    for (i, start) in starts.iter().enumerate() {
        let end = starts.get(i + 1).copied().unwrap_or(groups.lines.len());
        let (anchor, mut fields) = group_fields(&groups.lines[*start..end])?;
        expand_merges(&mut fields, &anchors)?;
        if let Some(anchor) = anchor {
            anchors.insert(anchor, fields.clone());
        }
        edit(&mut fields)?;
        let lines = join_chunks(&fields);
        for (j, line) in lines.lines().enumerate() {
            output.push(format!("{}{}", if j == 0 { "  - " } else { "    " }, line));
        }
    }
    Ok(output)
}
pub fn template(raw: &str) -> Result<String, String> {
    let mut chunks = split_chunks(&crate::ops::strip_marked_modules(raw));
    let groups = chunks
        .iter()
        .find(|c| c.key.as_deref() == Some("proxy-groups"))
        .ok_or("当前配置没有策略组 / No policy groups")?;
    let names = crate::compose::clash_item_names(groups);
    if names.is_empty() {
        return Err("当前策略组无法保存为分流方案 / Cannot read policy groups".into());
    }
    let is_policy = |name: &str| {
        names.iter().any(|n| n == name)
            || matches!(
                name,
                "DIRECT" | "REJECT" | "REJECT-DROP" | "PASS" | "COMPATIBLE" | "GLOBAL"
            )
    };
    let anchors = top_anchors(&chunks);
    let output = map_groups(groups, &anchors, |fields| {
        let set = |fields: &Vec<YamlChunk>, keys: &[&str]| {
            fields.iter().any(|f| {
                f.key.as_deref().is_some_and(|k| keys.contains(&k))
                    && !f.lines[0].ends_with("false")
            })
        };
        let all = set(fields, &["include-all", "include-all-proxies"]);
        let providers = set(fields, &["use", "include-all-providers"]);
        let value = |fields: &Vec<YamlChunk>, key: &str| {
            fields
                .iter()
                .find(|f| f.key.as_deref() == Some(key))
                .map(field_value)
        };
        let (name, kind) = (value(fields, "name"), value(fields, "type"));
        let filtered = value(fields, "filter").is_some_and(|f| !f.is_empty());
        let mut removed = Vec::new();
        if let Some(field) = fields
            .iter_mut()
            .find(|f| f.key.as_deref() == Some("proxies"))
        {
            let (kept, nodes): (Vec<_>, Vec<_>) =
                members(field)?.into_iter().partition(|n| is_policy(n));
            removed = nodes;
            field.lines = vec![format!(
                "proxies: {}",
                serde_json::to_string(&kept).unwrap()
            )];
        }
        fields.retain(|f| {
            !matches!(
                f.key.as_deref(),
                Some("use" | "include-all" | "include-all-proxies" | "include-all-providers")
            )
        });
        if !(all || providers || !removed.is_empty()) {
            return Ok(());
        }
        fields.push(YamlChunk {
            key: Some("include-all".into()),
            lines: vec!["include-all: true".into()],
        });
        if all {
            return Ok(());
        }
        // A regional group would otherwise rank every country's nodes. The
        // listed nodes say nothing about what providers added to the group.
        if let Some(code) = (!filtered && !providers)
            .then(|| region(name.as_deref().unwrap_or(""), kind.as_deref(), &removed))
            .flatten()
        {
            fields.retain(|f| !matches!(f.key.as_deref(), Some("filter" | "empty-fallback")));
            fields.push(YamlChunk {
                key: Some("filter".into()),
                lines: vec![format!("filter: {}", json!(country_filter(&code)))],
            });
            // With no match Mihomo would use COMPATIBLE, a DIRECT dialer.
            fields.push(YamlChunk {
                key: Some("empty-fallback".into()),
                lines: vec!["empty-fallback: REJECT".into()],
            });
        }
        // The group now draws on every node of whichever source the scheme is
        // applied to, so no node names are kept; info pseudo-nodes stay out.
        let info = crate::compose::INFO_EXCLUDE;
        let old = fields
            .iter()
            .position(|f| f.key.as_deref() == Some("exclude-filter"));
        let merged = match old.map(|i| field_value(&fields[i])) {
            Some(old) if old.contains(info) => old,
            Some(old) if old.contains('`') => format!("{old}`{info}"),
            Some(old) if !old.is_empty() => format!("(?:{old})|(?:{info})"),
            _ => info.to_string(),
        };
        let field = YamlChunk {
            key: Some("exclude-filter".into()),
            lines: vec![format!("exclude-filter: {}", json!(merged))],
        };
        match old {
            Some(i) => fields[i] = field,
            None => fields.push(field),
        }
        Ok(())
    })?;
    chunks.retain(|c| policy_key(c.key.as_deref()));
    for chunk in &mut chunks {
        if chunk.key.as_deref() == Some("proxy-groups") {
            chunk.lines = output.clone();
        }
    }
    Ok(join_chunks(&chunks))
}

/// The one country shared by a group's listed nodes, when the group stands
/// for that country. A select group must also name it, so that a source with
/// a single country does not narrow its main dropdown.
fn region(name: &str, kind: Option<&str>, nodes: &[String]) -> Option<String> {
    let select = match kind {
        Some("url-test" | "fallback" | "load-balance") => false,
        Some("select") => true,
        _ => return None,
    };
    let nodes: Vec<_> = nodes
        .iter()
        .filter(|n| !crate::mihomo::is_info_pseudo_node(n))
        .collect();
    let code = crate::best::country_hint(nodes.first()?)?;
    if nodes
        .iter()
        .any(|n| crate::best::country_hint(n).as_deref() != Some(code.as_str()))
    {
        return None;
    }
    match crate::best::country_hint(name) {
        Some(named) => (named == code).then_some(code),
        None => (!select).then_some(code),
    }
}

/// Each group's `timeout:` in a config split into chunks, merge keys
/// included. Mihomo's group JSON leaves it out.
pub(crate) fn group_timeouts(chunks: &[YamlChunk]) -> HashMap<String, u64> {
    let mut timeouts = HashMap::new();
    let Some(groups) = chunks
        .iter()
        .find(|c| c.key.as_deref() == Some("proxy-groups"))
    else {
        return timeouts;
    };
    let _ = map_groups(groups, &top_anchors(chunks), |fields| {
        let value = |key: &str| {
            fields
                .iter()
                .find(|f| f.key.as_deref() == Some(key))
                .map(field_value)
        };
        if let (Some(name), Some(ms)) = (value("name"), value("timeout")) {
            if let Ok(ms) = ms.parse::<u64>() {
                timeouts.insert(name, ms);
            }
        }
        Ok(())
    });
    timeouts
}

/// Lookbehind for a flag that starts a pair of regional indicators, so
/// 🇦🇺🇸🇬 matches AU and SG but not the 🇺🇸 inside it.
const FLAG_START: &str = "(?<=(?:^|[^🇦-🇿])(?:[🇦-🇿]{2})*)";

/// A Mihomo (regexp2) filter for the labels country_hint reads as `code`.
/// ASCII aliases are whole tokens between non-letters, so `US01` matches
/// where `\bUS\b` would not. A bare code is matched as US or us, not as the
/// word "Us", and GB after a number is a traffic size. Codes outside the
/// alias table come from flags.
fn country_filter(code: &str) -> String {
    let token = |word: String| format!("(?<![a-z]){word}(?![a-z])");
    let flag: String = code
        .bytes()
        .filter_map(|b| char::from_u32(0x1f1e6 + u32::from(b.wrapping_sub(b'A'))))
        .collect();
    let mut parts = vec![format!("{FLAG_START}{flag}")];
    if let Some((_, aliases)) = crate::best::COUNTRIES.iter().find(|(c, _)| *c == code) {
        parts.extend(aliases.iter().map(|alias| {
            if alias.is_ascii() {
                token(alias.split_whitespace().collect::<Vec<_>>().join("[^a-z]+"))
            } else if code == "IN" {
                format!("{alias}(?!尼西)")
            } else {
                alias.to_string()
            }
        }));
        let size = if code == "GB" { "(?<![0-9]\\s*)" } else { "" };
        parts.push(token(format!("{size}(?-i:{code}|{})", code.to_lowercase())));
    }
    format!("(?i)({})", parts.join("|"))
}

fn has_providers(chunks: &[YamlChunk]) -> bool {
    chunks.iter().any(|c| {
        c.key.as_deref() == Some("proxy-providers")
            && c.lines.iter().skip(1).any(|l| !l.trim().is_empty())
    })
}

/// A region filter matching no node leaves its group with only REJECT, so it
/// is dropped and the group draws on every node again. Only filters written
/// by template() are judged, and only against nodes in the YAML that the
/// info part of the exclude-filter keeps; a group whose own exclude-filter
/// drops the rest still fails closed.
/// The position of a group's region `filter` and its country, for filters
/// written by template() only.
fn template_region(fields: &[YamlChunk]) -> Option<(usize, String)> {
    let i = fields
        .iter()
        .position(|f| f.key.as_deref() == Some("filter"))?;
    let value = field_value(&fields[i]);
    // The flag leads every filter country_filter writes.
    let code: String = value
        .strip_prefix("(?i)(")
        .and_then(|v| v.strip_prefix(FLAG_START))
        .unwrap_or("")
        .chars()
        .take(2)
        .filter_map(|c| char::from_u32((c as u32).wrapping_sub(0x1f1e6 - u32::from(b'A'))))
        .collect();
    (code.len() == 2 && country_filter(&code) == value).then_some((i, code))
}

fn group_name(fields: &[YamlChunk]) -> String {
    fields
        .iter()
        .find(|f| f.key.as_deref() == Some("name"))
        .map(field_value)
        .unwrap_or_default()
}

/// Groups of a plan whose template region filter fails closed through
/// `empty-fallback: REJECT`.
fn region_groups(yaml: &str) -> Result<Vec<String>, String> {
    let chunks = split_chunks(yaml);
    let Some(groups) = chunks
        .iter()
        .find(|c| c.key.as_deref() == Some("proxy-groups"))
    else {
        return Ok(Vec::new());
    };
    let mut names = Vec::new();
    map_groups(groups, &HashMap::new(), |fields| {
        let rejects = fields
            .iter()
            .any(|f| f.key.as_deref() == Some("empty-fallback") && field_value(f) == "REJECT");
        if rejects && template_region(fields).is_some() {
            names.push(group_name(fields));
        }
        Ok(())
    })?;
    Ok(names)
}

fn drop_unmatched_regions(
    yaml: &str,
    proxies: &HashSet<String>,
    dropped: &mut Vec<String>,
) -> Result<String, String> {
    let mut chunks = split_chunks(yaml);
    let Some(groups) = chunks
        .iter()
        .find(|c| c.key.as_deref() == Some("proxy-groups"))
    else {
        return Ok(yaml.into());
    };
    let mut changed = false;
    let output = map_groups(groups, &HashMap::new(), |fields| {
        let Some((i, code)) = template_region(fields) else {
            return Ok(());
        };
        if !proxies
            .iter()
            .any(|n| !crate::compose::info_entry(n) && crate::best::country_hits(n).contains(&code))
        {
            fields.remove(i);
            dropped.push(group_name(fields));
            changed = true;
        }
        Ok(())
    })?;
    if !changed {
        return Ok(yaml.into());
    }
    for chunk in &mut chunks {
        if chunk.key.as_deref() == Some("proxy-groups") {
            chunk.lines = output.clone();
        }
    }
    Ok(join_chunks(&chunks))
}

// Point a rule at renamed groups. Only the target and later fields can name a
// group; a SUB-RULE target names a sub-rule set instead.
fn rename_rule(rule: &str, renames: &HashMap<String, String>) -> Option<String> {
    let mut parts = Vec::new();
    let (mut start, mut depth) = (0, 0i32);
    for (i, c) in rule.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            ',' if depth == 0 => {
                parts.push(&rule[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&rule[start..]);
    let kind = parts[0].trim();
    if kind == "SUB-RULE" {
        return None;
    }
    let first = if kind == "MATCH" { 1 } else { 2 };
    let mut changed = false;
    let parts: Vec<String> = parts
        .iter()
        .enumerate()
        .map(|(i, part)| match renames.get(part.trim()) {
            Some(new) if i >= first => {
                changed = true;
                new.clone()
            }
            _ => part.to_string(),
        })
        .collect();
    changed.then(|| parts.join(","))
}

/// A template group may share its name with a node of the selected source.
/// Such groups are renamed, with rules and other groups following them.
fn avoid_names(yaml: &str, proxies: &HashSet<String>) -> Result<String, String> {
    let mut chunks = split_chunks(yaml);
    let Some(groups) = chunks
        .iter()
        .find(|c| c.key.as_deref() == Some("proxy-groups"))
    else {
        return Ok(yaml.into());
    };
    let names = crate::compose::clash_item_names(groups);
    let mut taken: HashSet<String> = proxies.iter().chain(&names).cloned().collect();
    let mut renames = HashMap::new();
    for name in names.iter().filter(|n| proxies.contains(*n)) {
        let new = crate::compose::pick_name(name, &taken);
        taken.insert(new.clone());
        renames.insert(name.clone(), new);
    }
    if renames.is_empty() {
        return Ok(yaml.into());
    }
    let output = map_groups(groups, &HashMap::new(), |fields| {
        for field in fields.iter_mut() {
            match field.key.as_deref() {
                Some("name") => {
                    if let Some(new) = renames.get(&field_value(field)) {
                        field.lines = vec![format!("name: {}", json!(new))];
                    }
                }
                Some("proxies") => {
                    let list: Vec<_> = members(field)?
                        .into_iter()
                        .map(|n| renames.get(&n).cloned().unwrap_or(n))
                        .collect();
                    field.lines = vec![format!("proxies: {}", json!(list))];
                }
                _ => {}
            }
        }
        Ok(())
    })?;
    for chunk in &mut chunks {
        match chunk.key.as_deref() {
            Some("proxy-groups") => chunk.lines = output.clone(),
            Some("rules" | "sub-rules") => {
                for line in chunk.lines.iter_mut().skip(1) {
                    let Some(item) = line.trim_start().strip_prefix('-') else {
                        continue;
                    };
                    let item = item.trim();
                    let rule = if item.starts_with('"') {
                        serde_json::from_str::<String>(item).unwrap_or_else(|_| clean_scalar(item))
                    } else {
                        clean_scalar(item)
                    };
                    if let Some(rule) = rename_rule(&rule, &renames) {
                        let indent = crate::ops::leading_spaces(line);
                        *line = format!("{}- {}", " ".repeat(indent), json!(rule));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(join_chunks(&chunks))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn drop_unmatched_regions_for(yaml: &str, proxies: &HashSet<String>) -> Result<String, String> {
        drop_unmatched_regions(yaml, proxies, &mut Vec::new())
    }
    #[test]
    fn dropped_and_fail_closed_region_filters_are_reported() {
        let doc = "proxies:\n  - {name: US01, type: ss}\nproxy-groups:\n  - {name: 🇺🇸 美国, type: url-test, proxies: [US01]}\n  - {name: Sel, type: select, proxies: [🇺🇸 美国]}\nrules:\n  - MATCH,Sel\n";
        let plan = template(doc).unwrap();
        let notes = |base: &str| {
            let chunks = split_chunks(base);
            let proxies = node_names(&chunks);
            install_policy(chunks, &plan, &proxies).unwrap().1
        };
        let plain = "proxies:\n  - {name: HK01, type: ss}\nrules:\n  - MATCH,DIRECT\n";
        let dropped = notes(plain);
        assert!(
            dropped
                .iter()
                .any(|n| n.contains("🇺🇸 美国") && n.contains("filter was dropped")),
            "{dropped:?}"
        );
        let providers = "proxies:\n  - {name: HK01, type: ss}\nproxy-providers:\n  Air:\n    type: http\n    url: https://airport.test/sub\nrules:\n  - MATCH,DIRECT\n";
        let closed = notes(providers);
        assert!(
            closed
                .iter()
                .any(|n| n.contains("🇺🇸 美国") && n.contains("reject connections")),
            "{closed:?}"
        );
        // A matching node: nothing to say.
        let matched = notes(&plain.replace("HK01", "US 01"));
        assert!(!matched.iter().any(|n| n.contains("美国")), "{matched:?}");
    }
    #[test]
    fn templates_keep_policy_and_filters_but_never_source_nodes() {
        for groups in [
            "  - {name: Auto, type: url-test, proxies: ['HK, 01'], url: 'https://example.test', interval: 300, filter: HK}\n  - {name: Choice, type: select, proxies: [Auto, DIRECT, 'HK, 01']}\n",
            "  - name: Auto\n    type: url-test\n    proxies:\n      - 'HK, 01'\n    url: https://example.test\n    interval: 300\n    filter: HK\n  - name: Choice\n    type: select\n    proxies: [Auto, DIRECT, 'HK, 01']\n",
            "  - {\"name\":\"Auto\",\"type\":\"url-test\",\"use\":[\"AirportProvider\"],\"url\":\"https://example.test\",\"interval\":300,\"filter\":\"HK\"}\n  - {\"name\":\"Choice\",\"type\":\"select\",\"proxies\":[\"Auto\",\"DIRECT\"]}\n",
        ] {
            let doc = format!("proxies:\n  - {{name: 'HK, 01', type: ss, server: 192.0.2.1, password: SECRET}}\nproxy-providers:\n  AirportProvider:\n    type: http\n    url: https://airport.test/SECRET\nproxy-groups:\n{groups}rules:\n  - DOMAIN-SUFFIX,example.test,DIRECT\n  - MATCH,Choice\n");
            let route = template(&doc).unwrap();
            assert!(!route.contains("SECRET"));
            assert!(!route.contains("AirportProvider"));
            assert!(!route.contains("HK, 01"));
            assert!(route.contains("include-all: true"));
            assert!(route.contains("[\"Auto\",\"DIRECT\"]"));
            assert!(route.contains("filter:"));
            assert!(route.contains("MATCH,Choice"));
        }
    }

    fn group<'a>(yaml: &'a str, name: &str) -> &'a str {
        let at = yaml.find(&format!("- name: {name}\n")).unwrap();
        let rest = &yaml[at + 2..];
        &rest[..rest.find("\n  - ").or(rest.find("\nrules:")).unwrap()]
    }

    #[test]
    fn templates_widen_listed_nodes_without_info_nodes() {
        let doc = "proxies:\n  - {name: 剩余流量：100GB, type: ss}\n  - {name: HK1, type: ss}\n  - {name: 'HK.2', type: ss}\n  - {name: US1, type: ss}\nproxy-groups:\n  - {name: 香港, type: url-test, proxies: [剩余流量：100GB, HK1, 'HK.2'], exclude-filter: 'x#y'}\n  - {name: Netflix, type: select, proxies: [香港, HK1, US1]}\n  - {name: Mixed, type: select, proxies: [HK1], use: [P], exclude-filter: \"a`b\"}\n  - {name: Kept, type: select, include-all-proxies: true, proxies: [HK1]}\nrules:\n  - MATCH,Netflix\n";
        let route = template(doc).unwrap();
        let info = serde_json::to_string(crate::compose::INFO_EXCLUDE).unwrap();
        let hk = group(&route, "香港");
        assert!(hk.contains("proxies: []"), "{hk}");
        assert!(hk.contains("include-all: true"));
        assert!(!hk.contains("HK1"), "{hk}");
        // The region is kept as a filter, never as node names.
        let region = json!(country_filter("HK"));
        assert!(hk.contains(&format!("    filter: {region}")), "{hk}");
        let merged = format!("(?:x#y)|(?:{})", crate::compose::INFO_EXCLUDE);
        assert!(
            hk.contains(&format!("exclude-filter: {}", json!(merged))),
            "{hk}"
        );
        let netflix = group(&route, "Netflix");
        assert!(netflix.contains("proxies: [\"香港\"]"));
        assert!(!netflix.contains("    filter:"), "{netflix}");
        assert!(netflix.contains(&format!("exclude-filter: {info}")));
        let mixed = group(&route, "Mixed");
        assert!(!mixed.contains("\nfilter:") && !mixed.contains("    filter:"));
        let joined = format!("a`b`{}", crate::compose::INFO_EXCLUDE);
        assert!(
            mixed.contains(&format!("exclude-filter: {}", json!(joined))),
            "{mixed}"
        );
        let kept = group(&route, "Kept");
        assert!(kept.contains("include-all: true") && !kept.contains("filter"));
        assert!(!route.contains("剩余流量"));
    }

    #[test]
    fn region_filters_mirror_country_hint_tokens() {
        // Checked against regexp2 1.12, as Mihomo uses it: matches US01,
        // us-02, United States 2 and HK-US relay; not Us Home, LAXUS-01,
        // Russia, Plus or the 🇺🇸 inside 🇦🇺🇸🇬.
        assert_eq!(
            country_filter("US"),
            "(?i)((?<=(?:^|[^🇦-🇿])(?:[🇦-🇿]{2})*)🇺🇸|美国|美國|(?<![a-z])united[^a-z]+states(?![a-z])|(?<![a-z])usa(?![a-z])|(?<![a-z])(?-i:US|us)(?![a-z]))"
        );
        assert!(country_filter("IN").contains("|印度(?!尼西)|"));
        // GB right after a number is a traffic size, as in "100 GB".
        assert!(country_filter("GB").ends_with("|(?<![a-z])(?<![0-9]\\s*)(?-i:GB|gb)(?![a-z]))"));
        assert_eq!(country_filter("IT"), format!("(?i)({FLAG_START}🇮🇹)"));
    }

    #[test]
    fn templates_keep_the_country_of_regional_groups() {
        let doc = "proxies:\n  - {name: 剩余流量：100GB, type: ss}\n  - {name: US01, type: ss}\n  - {name: 'United States 2', type: ss}\n  - {name: HK1, type: ss}\n  - {name: Node, type: ss}\nproxy-groups:\n  - {name: 🇺🇸 美国自动, type: url-test, proxies: [剩余流量：100GB, US01, 'United States 2']}\n  - {name: Backup, type: fallback, proxies: [US01]}\n  - {name: 美国, type: select, proxies: [US01, DIRECT]}\n  - {name: Pick, type: select, proxies: [US01]}\n  - {name: Mixed, type: url-test, proxies: [US01, HK1]}\n  - {name: Unknown, type: load-balance, proxies: [US01, Node]}\n  - {name: 香港, type: url-test, proxies: [US01]}\n  - {name: Own, type: url-test, proxies: [US01], filter: 'US|JP'}\nrules:\n  - MATCH,Pick\n";
        let route = template(doc).unwrap();
        let us = format!("    filter: {}", json!(country_filter("US")));
        for name in ["🇺🇸 美国自动", "Backup", "美国"] {
            let g = group(&route, name);
            assert!(g.contains(&us) && g.contains("include-all: true"), "{g}");
        }
        // A select group narrows only when its own name names the region.
        for name in ["Pick", "Mixed", "Unknown", "香港"] {
            let g = group(&route, name);
            assert!(!g.contains("    filter:"), "{g}");
        }
        let own = group(&route, "Own");
        assert!(
            own.contains("filter: 'US|JP'") && !own.contains("美國"),
            "{own}"
        );
        assert!(!route.contains("US01") && !route.contains("United States 2"));
    }

    #[test]
    fn region_filters_matching_no_target_node_are_dropped() {
        let doc = "proxies:\n  - {name: US01, type: ss}\nproxy-groups:\n  - {name: US, type: url-test, proxies: [US01]}\n  - {name: Own, type: url-test, proxies: [US01], filter: 'US'}\nrules:\n  - MATCH,US\n";
        let route = template(doc).unwrap();
        let region = format!("    filter: {}", json!(country_filter("US")));
        let nodes =
            |names: &[&str]| -> HashSet<String> { names.iter().map(|n| n.to_string()).collect() };
        let kept =
            drop_unmatched_regions_for(&route, &nodes(&["剩余流量：1GB", "🇺🇸 洛杉矶"])).unwrap();
        assert_eq!(kept, route);
        let out = drop_unmatched_regions_for(&route, &nodes(&["剩余流量：US 1GB", "HK1"])).unwrap();
        let us = group(&out, "US");
        assert!(
            !us.contains(&region) && us.contains("include-all: true"),
            "{us}"
        );
        assert!(group(&out, "Own").contains("filter: 'US'"), "{out}");
        let flag = "proxies:\n  - {name: 🇮🇹 Milan, type: ss}\nproxy-groups:\n  - {name: Italy, type: fallback, proxies: [🇮🇹 Milan]}\nrules:\n  - MATCH,Italy\n";
        let route = template(flag).unwrap();
        assert!(
            route.contains(&format!("filter: {}", json!(country_filter("IT")))),
            "{route}"
        );
        let out = drop_unmatched_regions_for(&route, &nodes(&["US01"])).unwrap();
        assert!(!out.contains("    filter:"), "{out}");
        // Provider nodes are not in the YAML, so their filter is never judged.
        let base = "proxies:\n  - {name: HK1, type: ss}\nproxy-providers:\n  P:\n    type: http\n    url: https://airport.test/sub\nproxy-groups:\n  - {name: G, type: select, proxies: [HK1]}\nrules:\n  - MATCH,G\n";
        let mut chunks = split_chunks(base);
        assert!(has_providers(&chunks));
        chunks.retain(|c| c.key.as_deref() != Some("proxy-providers"));
        assert!(!has_providers(&chunks));
        // The only US-labelled node is one the info exclude-filter drops.
        let route = template(doc).unwrap();
        let out = drop_unmatched_regions_for(&route, &nodes(&["官网 example.us", "HK1"])).unwrap();
        assert!(!group(&out, "US").contains(&region), "{out}");
    }

    #[test]
    fn region_groups_fail_closed_when_a_provider_target_has_no_match() {
        // Saved from a source whose US group listed US nodes.
        let doc = "proxies:\n  - {name: US01, type: ss}\n  - {name: HK01, type: ss}\nproxy-groups:\n  - {name: 🇺🇸 美国, type: url-test, proxies: [US01]}\n  - {name: Sel, type: select, proxies: [🇺🇸 美国, HK01]}\nrules:\n  - MATCH,Sel\n";
        let plan = template(doc).unwrap();
        let region = format!("    filter: {}", json!(country_filter("US")));
        // Applied to a provider source whose US nodes are named by city:
        // the filter stays, and Mihomo's empty fallback is REJECT, not the
        // COMPATIBLE dialer that would send AI traffic out directly.
        let providers = "proxies:\n  - {name: 洛杉矶 01, type: ss}\nproxy-providers:\n  Air:\n    type: http\n    url: https://airport.test/sub\nproxy-groups:\n  - {name: G, type: select, proxies: [洛杉矶 01]}\nrules:\n  - MATCH,G\n";
        let out = merge_plan(providers, &plan).unwrap();
        let us = group(&out, "🇺🇸 美国");
        assert!(
            us.contains(&region) && us.contains("empty-fallback: REJECT"),
            "{us}"
        );
        assert!(
            out.contains("proxy-providers:") && !out.contains("name: G"),
            "{out}"
        );
        // Without providers the same filter is judged against the nodes.
        let plain = "proxies:\n  - {name: 洛杉矶 01, type: ss}\nproxy-groups:\n  - {name: G, type: select, proxies: [洛杉矶 01]}\nrules:\n  - MATCH,G\n";
        let out = merge_plan(plain, &plan).unwrap();
        assert!(!group(&out, "🇺🇸 美国").contains(&region), "{out}");
        let plain = plain.replace("洛杉矶 01", "US 洛杉矶 01");
        let out = merge_plan(&plain, &plan).unwrap();
        assert!(group(&out, "🇺🇸 美国").contains(&region), "{out}");
    }

    #[test]
    fn groups_that_drew_on_providers_keep_every_country() {
        let doc = "proxies:\n  - {name: US 自建, type: ss}\nproxy-providers:\n  Air:\n    type: http\n    url: https://airport.test/sub\nproxy-groups:\n  - {name: ♻️ 自动选择, type: url-test, use: [Air], proxies: [US 自建]}\n  - name: Auto2\n    type: url-test\n    include-all-providers: true\n    proxies: [US 自建]\nrules:\n  - MATCH,♻️ 自动选择\n";
        let route = template(doc).unwrap();
        for name in ["♻️ 自动选择", "Auto2"] {
            let g = group(&route, name);
            assert!(
                g.contains("include-all: true") && !g.contains("    filter:"),
                "{g}"
            );
        }
    }

    #[test]
    fn templates_expand_merge_keys_from_anchors() {
        let doc = "p: &p {type: url-test, url: 'https://cp.test/204', interval: 300, timeout: 2000}\nfb: &fb\n  type: fallback\n  interval: 600\nproxies:\n  - {name: 🇭🇰 香港 01, type: ss}\n  - {name: 🇭🇰 香港 02, type: ss}\n  - {name: 🇺🇸 美国 01, type: ss}\nproxy-groups:\n  - {name: 🇭🇰 香港节点, <<: *p, proxies: [🇭🇰 香港 01, 🇭🇰 香港 02]}\n  - name: 🇺🇸 美国节点\n    <<: *fb\n    interval: 120\n    proxies:\n      - 🇺🇸 美国 01\n  - &sel {name: Sel, type: select, proxies: [🇭🇰 香港节点, 🇺🇸 美国节点]}\n  - {name: Sel2, <<: *sel}\nrules:\n  - MATCH,Sel\n";
        let route = template(doc).unwrap();
        for anchor in ["<<", "*p", "*fb", "*sel", "&sel"] {
            assert!(!route.contains(anchor), "{route}");
        }
        let hk = group(&route, "🇭🇰 香港节点");
        assert!(
            hk.contains("type: url-test") && hk.contains("timeout: 2000"),
            "{hk}"
        );
        assert!(
            hk.contains(&format!("    filter: {}", json!(country_filter("HK")))),
            "{hk}"
        );
        let us = group(&route, "🇺🇸 美国节点");
        // The group's own key wins over the merged one.
        assert!(
            us.contains("type: fallback") && us.contains("interval: 120"),
            "{us}"
        );
        assert!(!us.contains("interval: 600"), "{us}");
        assert!(
            us.contains(&format!("    filter: {}", json!(country_filter("US")))),
            "{us}"
        );
        let sel2 = group(&route, "Sel2");
        assert!(
            sel2.contains("type: select") && sel2.contains("[\"🇭🇰 香港节点\",\"🇺🇸 美国节点\"]"),
            "{sel2}"
        );
        // Applied to another source, the plan no longer names the anchors.
        let other = "proxies:\n  - {name: HK9, type: ss}\nproxy-groups:\n  - {name: G, type: select, proxies: [HK9]}\nrules:\n  - MATCH,G\n";
        let out = merge_plan(other, &route).unwrap();
        assert!(!out.contains("*p") && !out.contains("*fb"), "{out}");
        assert_eq!(
            group_timeouts(&split_chunks(doc)),
            HashMap::from([("🇭🇰 香港节点".to_string(), 2000)])
        );
        assert!(
            template("proxy-groups:\n  - {name: A, <<: *missing}\nrules:\n  - MATCH,A\n")
                .unwrap_err()
                .contains("missing")
        );
    }

    #[test]
    fn templates_draw_on_the_nodes_of_the_source_they_are_applied_to() {
        let other = "proxies:\n  - {name: AirportNode, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: secret}\nproxy-groups:\n  - {name: Airport, type: select, proxies: [AirportNode]}\nrules:\n  - MATCH,Airport\n";
        let route = template(other).unwrap();
        assert!(!route.contains("AirportNode"), "{route}");
        let base = "proxies:\n  - {name: OwnNode, type: ss, server: 192.0.2.3, port: 8388, cipher: aes-128-gcm, password: fake}\nproxy-groups:\n  - {name: PROXY, type: select, proxies: [OwnNode]}\nrules:\n  - MATCH,PROXY\n";
        let mut chunks = split_chunks(base);
        chunks.retain(|c| !policy_key(c.key.as_deref()));
        chunks.extend(split_chunks(&route));
        let out = join_chunks(&chunks);
        let airport = group(&out, "Airport");
        assert!(airport.contains("include-all: true"), "{airport}");
        // A name filter from the template's own source would match nothing here.
        assert!(!airport.contains("    filter:"), "{airport}");
        assert!(out.contains("MATCH,Airport") && !out.contains("AirportNode"));
    }

    #[test]
    fn proxy_all_avoids_node_names_and_info_defaults() {
        let base = "proxies:\n  - {name: 剩余流量：100GB, type: ss}\n  - {\"name\":\"PROXY\",\"type\":\"ss\"}\nproxy-groups:\n  - {name: Airport, type: select, proxies: [PROXY]}\nrules:\n  - SUB-RULE,(NETWORK,tcp),s1\n  - MATCH,Airport\nsub-rules:\n  s1:\n    - MATCH,Airport\n";
        let cfg = crate::mihomo::ControllerConfig::default();
        let out = apply(base, "all", &cfg).unwrap();
        let group = json!({"name":"terc-PROXY","type":"select","include-all":true,"exclude-filter":crate::compose::INFO_EXCLUDE});
        assert!(
            out.contains(&format!("proxy-groups:\n  - {group}\n")),
            "{out}"
        );
        assert!(out.contains("rules:\n  - \"MATCH,terc-PROXY\"\n"));
        assert!(!out.contains("sub-rules") && !out.contains("SUB-RULE"));
        let plain = base.replace("\"PROXY\"", "\"Own\"");
        let out = apply(&plain, "all", &cfg).unwrap();
        assert!(out.contains("\"name\":\"PROXY\"") && out.contains("MATCH,PROXY"));
        assert_eq!(apply(base, "subscription", &cfg).unwrap(), base);
    }

    #[test]
    fn template_groups_named_like_nodes_are_renamed_with_their_rules() {
        let yaml = "proxy-groups:\n  - name: HK\n    type: select\n    proxies: [\"DIRECT\"]\n    include-all: true\n  - name: Choice\n    type: select\n    proxies: [\"HK\",\"DIRECT\"]\nrules:\n  - DOMAIN-SUFFIX,hk.example,HK\n  - AND,((DOMAIN,HK),(NETWORK,tcp)),HK,no-resolve\n  - SUB-RULE,(NETWORK,udp),HK\n  - \"MATCH,Choice\"\nsub-rules:\n  HK:\n    - IP-CIDR,192.0.2.0/24,HK,no-resolve\n";
        let proxies = HashSet::from(["HK".to_string(), "US".to_string()]);
        let out = avoid_names(yaml, &proxies).unwrap();
        assert!(out.contains("  - name: \"terc-HK\"\n"), "{out}");
        assert!(out.contains("proxies: [\"terc-HK\",\"DIRECT\"]"));
        assert!(out.contains("  - \"DOMAIN-SUFFIX,hk.example,terc-HK\"\n"));
        assert!(out.contains("  - \"AND,((DOMAIN,HK),(NETWORK,tcp)),terc-HK,no-resolve\"\n"));
        assert!(out.contains("  - SUB-RULE,(NETWORK,udp),HK\n"));
        assert!(out.contains("  HK:\n    - \"IP-CIDR,192.0.2.0/24,terc-HK,no-resolve\"\n"));
        assert!(out.contains("  - \"MATCH,Choice\"\n"));
        let untouched = HashSet::from(["US".to_string()]);
        assert_eq!(avoid_names(yaml, &untouched).unwrap(), yaml);
    }

    #[test]
    fn subscription_sub_rules_survive_compose_and_follow_routing() {
        let doc = "proxies:\n  - {name: HK, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: fake}\nproxy-groups:\n  - name: Airport\n    type: select\n    proxies: [HK]\nrules:\n  - SUB-RULE,(NETWORK,tcp),s1\n  - MATCH,Airport\nsub-rules:\n  s1:\n    - DOMAIN-SUFFIX,example.net,Airport\n    - MATCH,DIRECT\n";
        let converted = crate::subconv::convert_subscription(doc).unwrap();
        let (base, _) = crate::compose::compose_profile(&crate::compose::ComposeInput {
            subscription: Some(&converted),
            manual: &[],
            rules: &crate::compose::PrivateRules::default(),
            controller_addr: "127.0.0.1:9090",
            secret: "",
            test_url: "https://example.org",
        })
        .unwrap();
        let cfg = crate::mihomo::ControllerConfig::default();
        let out = apply(&base, "subscription", &cfg).unwrap();
        assert!(out.contains("  - SUB-RULE,(NETWORK,tcp),s1\n"));
        assert!(out.contains("sub-rules:\n  s1:\n    - DOMAIN-SUFFIX,example.net,Airport\n"));
        // A routing template carries sub-rules as policy.
        let route = template(&base).unwrap();
        assert!(route.contains("SUB-RULE,(NETWORK,tcp),s1") && route.contains("sub-rules:\n  s1:"));
    }

    #[test]
    fn plan_url_test_groups_get_the_default_tolerance() {
        let base = split_chunks("proxies:\n  - {name: HK, type: ss}\nproxy-groups:\n  - {name: Old, type: select, proxies: [HK]}\nrules:\n  - MATCH,Old\n");
        let plan = "proxy-groups:\n  - {name: Auto, type: url-test, include-all: true}\n  - {name: Kept, type: url-test, include-all: true, tolerance: 0}\n  - {name: Pick, type: select, proxies: [Auto, Kept]}\nrules:\n  - MATCH,Pick\n";
        let names = HashSet::from(["HK".to_string()]);
        let (out, notes) = install_policy(base, plan, &names).unwrap();
        assert!(notes.is_empty());
        assert!(
            out.contains("{name: Auto, type: url-test, include-all: true, tolerance: 50}"),
            "{out}"
        );
        assert!(out.contains("tolerance: 0}") && out.matches("tolerance").count() == 2);
    }

    #[test]
    fn dropped_rule_providers_take_their_dns_references_along() {
        let base = "dns:\n  enable: true\n  fake-ip-filter:\n    - '+.lan'\n    - rule-set:private\n  nameserver-policy:\n    'rule-set:cn,private':\n      - https://doh.pub/dns-query\n    geosite:cn: https://doh.pub/dns-query\nproxies:\n  - {name: HK, type: ss}\nproxy-groups:\n  - {name: Airport, type: select, proxies: [HK]}\nrule-providers:\n  cn: {type: http, behavior: domain, url: https://example.org/cn.yaml}\n  private: {type: http, behavior: domain, url: https://example.org/p.yaml}\nrules:\n  - RULE-SET,cn,DIRECT\n  - MATCH,Airport\n";
        let cfg = crate::mihomo::ControllerConfig::default();
        let (out, notes) = apply_noting(base, "all", &cfg).unwrap();
        assert!(
            !out.contains("rule-set:") && !out.contains("rule-providers"),
            "{out}"
        );
        assert!(out.contains("  fake-ip-filter:\n    - '+.lan'\n  nameserver-policy:\n    geosite:cn: https://doh.pub/dns-query\n"), "{out}");
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert!(notes[0].contains("rule-set:private") && notes[0].contains("fake-ip-filter"));
        assert!(notes[1].contains("rule-set:cn,private") && notes[1].contains("nameserver-policy"));
        assert_eq!(apply(base, "all", &cfg).unwrap(), out);
        // The subscription's own routing keeps its providers and references.
        assert_eq!(
            apply_noting(base, "subscription", &cfg).unwrap(),
            (base.into(), Vec::new())
        );
    }
}
