//! Country hints from subscription node labels, not IP geolocation.
use crate::mihomo::{is_info_pseudo_node, CoreSnapshot};

/// Country codes with the label aliases that name them.
pub const COUNTRIES: [(&str, &[&str]); 24] = [
    ("US", &["美国", "美國", "united states", "usa"]),
    ("JP", &["日本", "japan"]),
    ("SG", &["新加坡", "singapore"]),
    ("HK", &["香港", "hong kong"]),
    ("TW", &["台湾", "台灣", "taiwan"]),
    ("KR", &["韩国", "韓國", "south korea", "korea"]),
    ("GB", &["英国", "英國", "united kingdom", "uk"]),
    ("DE", &["德国", "德國", "germany"]),
    ("FR", &["法国", "法國", "france"]),
    ("CA", &["加拿大", "canada"]),
    ("AU", &["澳大利亚", "澳大利亞", "australia"]),
    ("NL", &["荷兰", "荷蘭", "netherlands"]),
    ("IN", &["印度", "india"]),
    ("RU", &["俄罗斯", "俄羅斯", "russia"]),
    ("TR", &["土耳其", "turkey"]),
    ("MY", &["马来西亚", "馬來西亞", "malaysia"]),
    ("TH", &["泰国", "泰國", "thailand"]),
    ("VN", &["越南", "vietnam"]),
    ("PH", &["菲律宾", "菲律賓", "philippines"]),
    ("ID", &["印度尼西亚", "印度尼西亞", "indonesia"]),
    ("BR", &["巴西", "brazil"]),
    ("CH", &["瑞士", "switzerland"]),
    ("SE", &["瑞典", "sweden"]),
    ("FI", &["芬兰", "芬蘭", "finland"]),
];

pub fn country_hint(name: &str) -> Option<String> {
    let mut found = country_hits(name);
    if found.len() == 1 {
        found.pop()
    } else {
        None
    }
}

/// Every country a label names, sorted and deduplicated.
pub fn country_hits(name: &str) -> Vec<String> {
    let chars: Vec<char> = name.chars().collect();
    let mut found = Vec::new();
    // Flags pair up from the start of a run, so 🇦🇺🇸🇬 is AU and SG, not US.
    let flag = |c: &char| ('\u{1f1e6}'..='\u{1f1ff}').contains(c);
    let mut i = 0;
    while i + 1 < chars.len() {
        if flag(&chars[i]) && flag(&chars[i + 1]) {
            found.push(
                chars[i..i + 2]
                    .iter()
                    .map(|c| (b'A' + (*c as u32 - 0x1f1e6) as u8) as char)
                    .collect::<String>(),
            );
            i += 2;
        } else {
            i += 1;
        }
    }
    let lower = name.to_lowercase();
    // Runs of ASCII letters, with where each starts.
    let mut words: Vec<(usize, &str)> = Vec::new();
    let mut start = None;
    for (at, c) in name.char_indices().chain([(name.len(), ' ')]) {
        match (c.is_ascii_alphabetic(), start) {
            (true, None) => start = Some(at),
            (false, Some(from)) => {
                words.push((from, &name[from..at]));
                start = None;
            }
            _ => {}
        }
    }
    let tokens: Vec<String> = words.iter().map(|(_, w)| w.to_lowercase()).collect();
    for (code, aliases) in COUNTRIES {
        // A bare code is written US or us; "My" and "In" are words, and a
        // GB right after a number is a traffic size.
        let names_code = words.iter().any(|(at, word)| {
            word.eq_ignore_ascii_case(code)
                && (*word == code || *word == code.to_lowercase())
                && !(code == "GB"
                    && name[..*at]
                        .trim_end()
                        .ends_with(|c: char| c.is_ascii_digit()))
        });
        let matches_alias = aliases.iter().any(|alias| {
            if alias.is_ascii() {
                let words: Vec<_> = alias.split_whitespace().collect();
                tokens.windows(words.len()).any(|w| w == words)
            } else {
                // "印度" is also a prefix of "印度尼西亚".
                lower.contains(alias) && !(code == "IN" && lower.contains("印度尼西"))
            }
        });
        if names_code || matches_alias {
            found.push(code.to_string());
        }
    }
    found.sort();
    found.dedup();
    found
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

/// Nodes re-tested after the first best-pick round.
const RETEST_TOP: usize = 5;
/// Samples per finalist: the first round and two re-tests, so the median
/// discards a single timeout or spike rather than averaging it in.
pub const ROUNDS: usize = 3;

fn delay_of(results: &[(String, Option<u16>)], name: &str) -> Option<u16> {
    results
        .iter()
        .find(|(node, _)| node == name)
        .and_then(|(_, delay)| *delay)
        .filter(|delay| *delay > 0)
}

/// The five fastest of the first round, plus the current node when it
/// answered, so the hysteresis compares medians with medians.
pub fn retest(
    candidates: &[(usize, String)],
    results: &[(String, Option<u16>)],
    current: &str,
) -> Vec<String> {
    let mut reachable: Vec<_> = candidates
        .iter()
        .filter_map(|(_, name)| delay_of(results, name).map(|delay| (delay, name)))
        .collect();
    reachable.sort_by_key(|(delay, _)| *delay);
    let mut names: Vec<String> = reachable
        .iter()
        .take(RETEST_TOP)
        .map(|(_, name)| name.to_string())
        .collect();
    if !names.iter().any(|name| name == current)
        && reachable.iter().any(|(_, name)| *name == current)
    {
        names.push(current.to_string());
    }
    names
}

/// Median with failures sorted last: of three samples, one failure is
/// outvoted, two drop the node.
pub fn median(samples: &[Option<u16>]) -> Option<u16> {
    let mut sorted: Vec<u32> = samples
        .iter()
        .map(|s| s.filter(|d| *d > 0).map_or(u32::MAX, u32::from))
        .collect();
    if sorted.is_empty() {
        return None;
    }
    sorted.sort_unstable();
    let (lo, hi) = (sorted[(sorted.len() - 1) / 2], sorted[sorted.len() / 2]);
    (hi != u32::MAX).then(|| ((lo + hi) / 2) as u16)
}

#[derive(Debug, PartialEq, Eq)]
pub enum Pick {
    /// Group index of the node to switch to.
    Switch(usize),
    /// The current node is the best or close enough to it.
    Keep {
        best: usize,
        current_ms: u16,
        best_ms: u16,
    },
    None,
}

/// Ranks the nodes of the last round by the median of their samples across
/// all rounds. Nodes the last round skipped had one lucky chance at most.
pub fn pick(
    candidates: &[(usize, String)],
    rounds: &[&[(String, Option<u16>)]],
    current: &str,
) -> Pick {
    let Some(last) = rounds.last() else {
        return Pick::None;
    };
    let medians: Vec<(usize, &str, u16)> = candidates
        .iter()
        .filter(|(_, name)| last.iter().any(|(node, _)| node == name))
        .filter_map(|(index, name)| {
            let samples: Vec<_> = rounds
                .iter()
                .filter(|round| round.iter().any(|(node, _)| node == name))
                .map(|round| delay_of(round, name))
                .collect();
            median(&samples).map(|ms| (*index, name.as_str(), ms))
        })
        .collect();
    let Some(&(best, _, best_ms)) = medians.iter().min_by_key(|(_, _, ms)| *ms) else {
        return Pick::None;
    };
    let margin = (u32::from(best_ms) * 15 / 100).max(30);
    match medians.iter().find(|(_, name, _)| *name == current) {
        Some(&(_, _, current_ms)) if u32::from(current_ms) <= u32::from(best_ms) + margin => {
            Pick::Keep {
                best,
                current_ms,
                best_ms,
            }
        }
        _ => Pick::Switch(best),
    }
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
            test_url: String::new(),
            expected_status: String::new(),
            timeout_ms: 0,
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
                    url_delays: Default::default(),
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
        assert_eq!(pick(&local, &[&results], "US 01"), Pick::Switch(2));
        assert_eq!(pick(&all, &[&results], "JP 01"), Pick::Switch(1));
        assert_eq!(pick(&local, &[&[]], "JP 01"), Pick::None);
        snapshot.groups.push(ProxyGroup {
            name: "Nested".into(),
            kind: "Selector".into(),
            now: "US 01".into(),
            fixed: String::new(),
            all: vec!["US 01".into()],
            test_url: String::new(),
            expected_status: String::new(),
            timeout_ms: 0,
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
        // Flag pairs, words and traffic sizes that only look like codes.
        assert_eq!(country_hits("🇦🇺🇸🇬 relay"), ["AU", "SG"]);
        assert_eq!(country_hint("🇬🇧🇺🇸"), None);
        assert_eq!(country_hint("Node 100GB"), None);
        assert_eq!(country_hint("Node 100 GB"), None);
        assert_eq!(country_hint("GB-London 1").as_deref(), Some("GB"));
        assert_eq!(country_hint("My Home"), None);
        assert_eq!(country_hint("my-01").as_deref(), Some("MY"));
        assert_eq!(country_hint("Made In Taiwan").as_deref(), Some("TW"));
    }

    fn named(pairs: &[(&str, Option<u16>)]) -> Vec<(String, Option<u16>)> {
        pairs.iter().map(|(n, d)| (n.to_string(), *d)).collect()
    }

    #[test]
    fn median_drops_nodes_whose_middle_sample_failed() {
        assert_eq!(median(&[]), None);
        assert_eq!(median(&[Some(40)]), Some(40));
        assert_eq!(median(&[Some(40), Some(60)]), Some(50));
        assert_eq!(median(&[Some(40), None]), None);
        assert_eq!(median(&[Some(40), Some(0)]), None);
        assert_eq!(median(&[Some(90), None, Some(40)]), Some(90));
        assert_eq!(median(&[None, None, Some(40)]), None);
    }

    #[test]
    fn retest_takes_top_five_and_the_reachable_current_node() {
        let candidates: Vec<_> = (0..8).map(|i| (i, format!("N{i}"))).collect();
        let first = named(&[
            ("N0", Some(70)),
            ("N1", Some(10)),
            ("N2", None),
            ("N3", Some(30)),
            ("N4", Some(20)),
            ("N5", Some(50)),
            ("N6", Some(40)),
            ("N7", Some(90)),
        ]);
        assert_eq!(
            retest(&candidates, &first, "N7"),
            ["N1", "N4", "N3", "N6", "N5", "N7"]
        );
        assert_eq!(retest(&candidates, &first, "N4").len(), 5);
        assert_eq!(retest(&candidates, &first, "N2").len(), 5);
        assert!(retest(&candidates, &[], "N0").is_empty());
    }

    #[test]
    fn pick_uses_medians_and_keeps_a_close_current_node() {
        let candidates: Vec<_> = (0..4).map(|i| (i, format!("N{i}"))).collect();
        // N3 was lucky once; only re-tested nodes compete.
        let first = named(&[
            ("N0", Some(100)),
            ("N1", Some(10)),
            ("N2", Some(120)),
            ("N3", Some(5)),
        ]);
        let second = named(&[("N0", Some(100)), ("N1", Some(300)), ("N2", Some(120))]);
        assert_eq!(pick(&candidates, &[&first, &second], "N3"), Pick::Switch(0));
        // A median of 120 is within max(30 ms, 15%) of 100.
        assert_eq!(
            pick(&candidates, &[&first, &second], "N2"),
            Pick::Keep {
                best: 0,
                current_ms: 120,
                best_ms: 100
            }
        );
        let second = named(&[("N0", Some(100)), ("N1", Some(300)), ("N2", Some(150))]);
        assert_eq!(pick(&candidates, &[&first, &second], "N2"), Pick::Switch(0));
        // 15% beats 30 ms for slow nodes: 400 + 60.
        let first = named(&[("N0", Some(400)), ("N1", Some(460))]);
        let second = named(&[("N0", Some(400)), ("N1", Some(460))]);
        assert!(matches!(
            pick(&candidates, &[&first, &second], "N1"),
            Pick::Keep { best: 0, .. }
        ));
        let second = named(&[("N0", Some(400)), ("N1", Some(480))]);
        assert_eq!(pick(&candidates, &[&first, &second], "N1"), Pick::Switch(0));
        // A current node that failed the re-test is not kept.
        let second = named(&[("N0", Some(400)), ("N1", None)]);
        assert_eq!(pick(&candidates, &[&first, &second], "N1"), Pick::Switch(0));
        // The best node is the current one.
        assert!(matches!(
            pick(&candidates, &[&first, &second], "N0"),
            Pick::Keep { best: 0, .. }
        ));
    }

    #[test]
    fn three_samples_outvote_one_timeout_or_spike() {
        let candidates: Vec<_> = (0..2).map(|i| (i, format!("N{i}"))).collect();
        // The current N1 times out once on a lossy link: 70 / - / 72.
        let rounds = [
            named(&[("N0", Some(75)), ("N1", Some(70))]),
            named(&[("N0", Some(80)), ("N1", None)]),
            named(&[("N0", Some(78)), ("N1", Some(72))]),
        ];
        let rounds: Vec<&[_]> = rounds.iter().map(Vec::as_slice).collect();
        assert!(matches!(
            pick(&candidates, &rounds, "N1"),
            Pick::Keep {
                best: 1,
                current_ms: 72,
                ..
            }
        ));
        // One 900 ms spike does not hand the win to the slower N1.
        let rounds = [
            named(&[("N0", Some(40)), ("N1", Some(60))]),
            named(&[("N0", Some(900)), ("N1", Some(65))]),
            named(&[("N0", Some(42)), ("N1", Some(62))]),
        ];
        let rounds: Vec<&[_]> = rounds.iter().map(Vec::as_slice).collect();
        assert_eq!(pick(&candidates, &rounds, "N9"), Pick::Switch(0));
    }
}
