//! Country hints from subscription node labels, not IP geolocation.
use crate::mihomo::{is_info_pseudo_node, CoreSnapshot};

pub fn country_hint(name: &str) -> Option<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut found = Vec::new();
    for pair in chars.windows(2) {
        if pair.iter().all(|c| ('\u{1f1e6}'..='\u{1f1ff}').contains(c)) {
            found.push(
                pair.iter()
                    .map(|c| (b'A' + (*c as u32 - 0x1f1e6) as u8) as char)
                    .collect::<String>(),
            );
        }
    }
    let lower = name.to_lowercase();
    let tokens: Vec<_> = lower
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|s| !s.is_empty())
        .collect();
    for (code, aliases) in [
        ("US", &["美国", "美國", "united states", "usa"][..]),
        ("JP", &["日本", "japan"][..]),
        ("SG", &["新加坡", "singapore"][..]),
        ("HK", &["香港", "hong kong"][..]),
        ("TW", &["台湾", "台灣", "taiwan"][..]),
        ("KR", &["韩国", "韓國", "south korea", "korea"][..]),
        ("GB", &["英国", "英國", "united kingdom", "uk"][..]),
        ("DE", &["德国", "德國", "germany"][..]),
        ("FR", &["法国", "法國", "france"][..]),
        ("CA", &["加拿大", "canada"][..]),
        ("AU", &["澳大利亚", "澳大利亞", "australia"][..]),
        ("NL", &["荷兰", "荷蘭", "netherlands"][..]),
        ("IN", &["印度", "india"][..]),
        ("RU", &["俄罗斯", "俄羅斯", "russia"][..]),
        ("TR", &["土耳其", "turkey"][..]),
        ("MY", &["马来西亚", "馬來西亞", "malaysia"][..]),
        ("TH", &["泰国", "泰國", "thailand"][..]),
        ("VN", &["越南", "vietnam"][..]),
        ("PH", &["菲律宾", "菲律賓", "philippines"][..]),
        ("ID", &["印度尼西亚", "印度尼西亞", "indonesia"][..]),
        ("BR", &["巴西", "brazil"][..]),
        ("CH", &["瑞士", "switzerland"][..]),
        ("SE", &["瑞典", "sweden"][..]),
        ("FI", &["芬兰", "芬蘭", "finland"][..]),
    ] {
        let token_code = code.to_lowercase();
        let matches_alias = aliases.iter().any(|alias| {
            if alias.is_ascii() {
                let words: Vec<_> = alias.split_whitespace().collect();
                tokens.windows(words.len()).any(|w| w == words)
            } else {
                // "印度" is also a prefix of "印度尼西亚".
                lower.contains(alias) && !(code == "IN" && lower.contains("印度尼西"))
            }
        });
        if tokens.contains(&token_code.as_str()) || matches_alias {
            found.push(code.to_string());
        }
    }
    found.sort();
    found.dedup();
    if found.len() == 1 {
        found.pop()
    } else {
        None
    }
}

pub fn active_country(snapshot: &CoreSnapshot, group_index: usize) -> Option<String> {
    let mut name = snapshot.groups.get(group_index)?.now.as_str();
    let mut visited = Vec::new();
    while let Some(group) = snapshot.groups.iter().find(|g| g.name == name) {
        if visited.contains(&name) {
            return None;
        }
        visited.push(name);
        if group.kind.eq_ignore_ascii_case("loadbalance") {
            return None;
        }
        name = &group.now;
    }
    country_hint(name)
}

pub fn candidates(
    snapshot: &CoreSnapshot,
    group_index: usize,
    country: Option<&str>,
) -> Vec<(usize, String)> {
    let Some(group) = snapshot.groups.get(group_index) else {
        return Vec::new();
    };
    group
        .all
        .iter()
        .enumerate()
        .filter(|(_, name)| {
            if is_info_pseudo_node(name) {
                return false;
            }
            let Some(node) = snapshot.nodes.get(*name) else {
                return false;
            };
            if [
                "direct",
                "reject",
                "rejectdrop",
                "selector",
                "urltest",
                "fallback",
                "loadbalance",
                "pass",
                "compatible",
            ]
            .contains(&node.kind.to_lowercase().as_str())
            {
                return false;
            }
            country.is_none_or(|code| country_hint(name).as_deref() == Some(code))
        })
        .map(|(i, n)| (i, n.clone()))
        .collect()
}

pub fn fastest(candidates: &[(usize, String)], results: &[(String, Option<u16>)]) -> Option<usize> {
    candidates
        .iter()
        .filter_map(|(index, name)| {
            results
                .iter()
                .find(|(node, _)| node == name)
                .and_then(|(_, delay)| *delay)
                .filter(|delay| *delay > 0)
                .map(|delay| (*index, delay))
        })
        .min_by_key(|(_, delay)| *delay)
        .map(|(index, _)| index)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scope_uses_connected_node_and_fresh_results_only() {
        use crate::mihomo::{ProxyGroup, ProxyNode};
        let mut snapshot = CoreSnapshot::default();
        let names = ["JP 01", "US 01", "JP 02", "DIRECT"];
        snapshot.groups.push(ProxyGroup {
            name: "Main".into(),
            kind: "Selector".into(),
            now: "JP 01".into(),
            fixed: String::new(),
            all: names.iter().map(|s| s.to_string()).collect(),
        });
        for name in names {
            snapshot.nodes.insert(
                name.into(),
                ProxyNode {
                    name: name.into(),
                    kind: if name == "DIRECT" {
                        "Direct"
                    } else {
                        "Shadowsocks"
                    }
                    .into(),
                    udp: true,
                    delay: Some(1),
                    provider: None,
                },
            );
        }
        assert_eq!(active_country(&snapshot, 0).as_deref(), Some("JP"));
        let local = candidates(&snapshot, 0, Some("JP"));
        assert_eq!(local.len(), 2);
        let all = candidates(&snapshot, 0, None);
        assert_eq!(all.len(), 3);
        let results = vec![
            ("US 01".into(), Some(5)),
            ("JP 01".into(), None),
            ("JP 02".into(), Some(20)),
        ];
        assert_eq!(fastest(&local, &results), Some(2));
        assert_eq!(fastest(&all, &results), Some(1));
        assert_eq!(fastest(&local, &[]), None);
        snapshot.groups.push(ProxyGroup {
            name: "Nested".into(),
            kind: "Selector".into(),
            now: "US 01".into(),
            fixed: String::new(),
            all: vec!["US 01".into()],
        });
        snapshot.groups[0].now = "Nested".into();
        assert_eq!(active_country(&snapshot, 0).as_deref(), Some("US"));
    }

    #[test]
    fn subscription_country_labels_are_unambiguous() {
        for (name, code) in [
            ("🇯🇵 Tokyo 01", "JP"),
            ("日本 02", "JP"),
            ("US-03", "US"),
            ("Hong Kong 2", "HK"),
            ("🇨🇿 Prague", "CZ"),
            ("印度尼西亚01", "ID"),
        ] {
            assert_eq!(country_hint(name).as_deref(), Some(code));
        }
        assert_eq!(country_hint("Premium Auto"), None);
        assert_eq!(country_hint("RUSH-01"), None);
        assert_eq!(country_hint("🇺🇸 US → JP"), None);
    }
}
