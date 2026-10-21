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
    if id == "subscription" {
        return Ok(base.into());
    }
    let mut chunks = split_chunks(base);
    let proxies: HashSet<String> = chunks
        .iter()
        .find(|c| c.key.as_deref() == Some("proxies"))
        .map(crate::compose::clash_item_names)
        .unwrap_or_default()
        .into_iter()
        .collect();
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
    // Provider nodes are only known after the reload, so with providers a
    // region filter is kept; matching nothing then fails closed.
    let yaml = if has_providers(&chunks) {
        yaml
    } else {
        drop_unmatched_regions(&yaml, &proxies)?
    };
    let yaml = avoid_names(&yaml, &proxies)?;
    chunks.retain(|c| !policy_key(c.key.as_deref()));
    chunks.extend(
        split_chunks(&yaml)
            .into_iter()
            .filter(|c| policy_key(c.key.as_deref())),
    );
    Ok(join_chunks(&chunks))
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
fn group_fields(lines: &[String]) -> Result<Vec<YamlChunk>, String> {
    let first = lines[0].trim_start().trim_start_matches('-').trim();
    if first.starts_with('{') {
        let body = lines.iter().map(|s| s.trim()).collect::<Vec<_>>().join(" ");
        let body = body.trim_start_matches('-').trim();
        let inner = body
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .ok_or("策略组格式不完整 / Incomplete group map")?;
        return Ok(flow_parts(inner)
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
            .collect::<Result<Vec<_>, String>>()?);
    }
    let indent = lines[0].len() - lines[0].trim_start().len() + 2;
    let mut normalized = vec![first.to_string()];
    normalized.extend(
        lines
            .iter()
            .skip(1)
            .map(|l| l.get(indent..).unwrap_or("").to_string()),
    );
    Ok(split_chunks(&normalized.join("\n")))
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
fn map_groups(
    groups: &YamlChunk,
    mut edit: impl FnMut(&mut Vec<YamlChunk>) -> Result<(), String>,
) -> Result<Vec<String>, String> {
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
        let mut fields = group_fields(&groups.lines[*start..end])?;
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
    let output = map_groups(groups, |fields| {
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
        // A regional group would otherwise rank every country's nodes.
        if let Some(code) = (!filtered)
            .then(|| region(name.as_deref().unwrap_or(""), kind.as_deref(), &removed))
            .flatten()
        {
            fields.retain(|f| f.key.as_deref() != Some("filter"));
            fields.push(YamlChunk {
                key: Some("filter".into()),
                lines: vec![format!("filter: {}", json!(country_filter(&code)))],
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

/// A Mihomo (regexp2) filter for the labels country_hint reads as `code`.
/// ASCII aliases are whole tokens between non-letters, so `US01` matches
/// where `\bUS\b` would not. Codes outside the alias table come from flags.
fn country_filter(code: &str) -> String {
    let token = |word: String| format!("(?<![a-z]){word}(?![a-z])");
    let mut parts = vec![code
        .bytes()
        .filter_map(|b| char::from_u32(0x1f1e6 + u32::from(b.wrapping_sub(b'A'))))
        .collect::<String>()];
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
        parts.push(token(code.to_lowercase()));
    }
    format!("(?i)({})", parts.join("|"))
}

fn has_providers(chunks: &[YamlChunk]) -> bool {
    chunks.iter().any(|c| {
        c.key.as_deref() == Some("proxy-providers")
            && c.lines.iter().skip(1).any(|l| !l.trim().is_empty())
    })
}

/// A region filter matching no node leaves its group with only COMPATIBLE,
/// so it is dropped and the group draws on every node again. Only filters
/// written by template() are judged, and only against nodes in the YAML.
fn drop_unmatched_regions(yaml: &str, proxies: &HashSet<String>) -> Result<String, String> {
    let mut chunks = split_chunks(yaml);
    let Some(groups) = chunks
        .iter()
        .find(|c| c.key.as_deref() == Some("proxy-groups"))
    else {
        return Ok(yaml.into());
    };
    let mut changed = false;
    let output = map_groups(groups, |fields| {
        let Some(i) = fields
            .iter()
            .position(|f| f.key.as_deref() == Some("filter"))
        else {
            return Ok(());
        };
        let value = field_value(&fields[i]);
        // The flag leads every filter country_filter writes.
        let code: String = value
            .strip_prefix("(?i)(")
            .unwrap_or("")
            .chars()
            .take(2)
            .filter_map(|c| char::from_u32((c as u32).wrapping_sub(0x1f1e6 - u32::from(b'A'))))
            .collect();
        let code = (code.len() == 2 && country_filter(&code) == value).then_some(code);
        let Some(code) = code else {
            return Ok(());
        };
        if !proxies.iter().any(|n| {
            !crate::mihomo::is_info_pseudo_node(n) && crate::best::country_hits(n).contains(&code)
        }) {
            fields.remove(i);
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
    let output = map_groups(groups, |fields| {
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
        assert_eq!(
            country_filter("US"),
            "(?i)(🇺🇸|美国|美國|(?<![a-z])united[^a-z]+states(?![a-z])|(?<![a-z])usa(?![a-z])|(?<![a-z])us(?![a-z]))"
        );
        assert!(country_filter("IN").contains("|印度(?!尼西)|"));
        assert_eq!(country_filter("IT"), "(?i)(🇮🇹)");
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
        let kept = drop_unmatched_regions(&route, &nodes(&["剩余流量：1GB", "🇺🇸 洛杉矶"])).unwrap();
        assert_eq!(kept, route);
        let out = drop_unmatched_regions(&route, &nodes(&["剩余流量：US 1GB", "HK1"])).unwrap();
        let us = group(&out, "US");
        assert!(
            !us.contains(&region) && us.contains("include-all: true"),
            "{us}"
        );
        assert!(group(&out, "Own").contains("filter: 'US'"), "{out}");
        let flag = "proxies:\n  - {name: 🇮🇹 Milan, type: ss}\nproxy-groups:\n  - {name: Italy, type: fallback, proxies: [🇮🇹 Milan]}\nrules:\n  - MATCH,Italy\n";
        let route = template(flag).unwrap();
        assert!(
            route.contains(&format!("filter: {}", json!("(?i)(🇮🇹)"))),
            "{route}"
        );
        let out = drop_unmatched_regions(&route, &nodes(&["US01"])).unwrap();
        assert!(!out.contains("    filter:"), "{out}");
        // Provider nodes are not in the YAML, so their filter is never judged.
        let base = "proxies:\n  - {name: HK1, type: ss}\nproxy-providers:\n  P:\n    type: http\n    url: https://airport.test/sub\nproxy-groups:\n  - {name: G, type: select, proxies: [HK1]}\nrules:\n  - MATCH,G\n";
        let mut chunks = split_chunks(base);
        assert!(has_providers(&chunks));
        chunks.retain(|c| c.key.as_deref() != Some("proxy-providers"));
        assert!(!has_providers(&chunks));
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
}
