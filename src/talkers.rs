//! Aggregate the live connection list into "who is using the proxy" rows.
//! Surge calls this traffic analytics; here it is one keyboard-first overlay
//! over the data `/connections` already carries.

use std::collections::HashMap;

use crate::mihomo::ConnectionItem;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    Domain,
    Process,
    Policy,
}

impl Group {
    pub fn next(self) -> Self {
        match self {
            Self::Domain => Self::Process,
            Self::Process => Self::Policy,
            Self::Policy => Self::Domain,
        }
    }

    pub fn label(self, zh: bool) -> &'static str {
        match (self, zh) {
            (Self::Domain, true) => "域名",
            (Self::Domain, false) => "Domain",
            (Self::Process, true) => "进程",
            (Self::Process, false) => "Process",
            (Self::Policy, true) => "策略",
            (Self::Policy, false) => "Policy",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sort {
    Bytes,
    Rate,
}

impl Sort {
    pub fn next(self) -> Self {
        match self {
            Self::Bytes => Self::Rate,
            Self::Rate => Self::Bytes,
        }
    }

    pub fn label(self, zh: bool) -> &'static str {
        match (self, zh) {
            (Self::Bytes, true) => "总量",
            (Self::Bytes, false) => "Total",
            (Self::Rate, true) => "速率",
            (Self::Rate, false) => "Rate",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Talker {
    pub name: String,
    pub count: usize,
    pub up: u64,
    pub down: u64,
    pub up_rate: u64,
    pub down_rate: u64,
}

impl Talker {
    pub fn total(&self) -> u64 {
        self.up.saturating_add(self.down)
    }

    pub fn total_rate(&self) -> u64 {
        self.up_rate.saturating_add(self.down_rate)
    }
}

fn domain(item: &ConnectionItem) -> String {
    let host = if item.sniff_host.is_empty() {
        &item.host
    } else {
        &item.sniff_host
    };
    if host.is_empty() {
        "—".into()
    } else if let Some((h, _)) = host.rsplit_once(':') {
        if !h.contains(':') {
            h.into()
        } else {
            host.clone()
        }
    } else {
        host.clone()
    }
}

fn process(item: &ConnectionItem) -> String {
    if !item.process.is_empty() {
        return item.process.clone();
    }
    if !item.process_path.is_empty() {
        return item
            .process_path
            .rsplit('/')
            .next()
            .unwrap_or(&item.process_path)
            .to_string();
    }
    "—".into()
}

fn policy(item: &ConnectionItem) -> String {
    item.chains
        .split(" › ")
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("—")
        .to_string()
}

pub fn aggregate(conns: &[ConnectionItem], group: Group, sort: Sort) -> Vec<Talker> {
    let mut map: HashMap<String, Talker> = HashMap::new();
    for item in conns {
        let name = match group {
            Group::Domain => domain(item),
            Group::Process => process(item),
            Group::Policy => policy(item),
        };
        let entry = map.entry(name.clone()).or_insert_with(|| Talker {
            name,
            count: 0,
            up: 0,
            down: 0,
            up_rate: 0,
            down_rate: 0,
        });
        entry.count += 1;
        entry.up = entry.up.saturating_add(item.upload);
        entry.down = entry.down.saturating_add(item.download);
        entry.up_rate = entry.up_rate.saturating_add(item.up_rate);
        entry.down_rate = entry.down_rate.saturating_add(item.down_rate);
    }
    let mut rows: Vec<Talker> = map.into_values().collect();
    match sort {
        Sort::Bytes => rows.sort_by(|a, b| b.total().cmp(&a.total()).then(a.name.cmp(&b.name))),
        Sort::Rate => rows.sort_by(|a, b| {
            b.total_rate()
                .cmp(&a.total_rate())
                .then(a.name.cmp(&b.name))
        }),
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(host: &str, process: &str, chains: &str, up: u64, down: u64) -> ConnectionItem {
        ConnectionItem {
            id: String::new(),
            host: host.into(),
            network: "tcp".into(),
            rule: "Match".into(),
            chains: chains.into(),
            upload: up,
            download: down,
            process: process.into(),
            process_path: String::new(),
            inbound: String::new(),
            inbound_name: String::new(),
            source: String::new(),
            sniff_host: String::new(),
            rule_payload: String::new(),
            start: String::new(),
            start_ms: None,
            provider: String::new(),
            dns_mode: String::new(),
            dest_geo: String::new(),
            dest_asn: String::new(),
            up_rate: 0,
            down_rate: 0,
            ai: false,
        }
    }

    #[test]
    fn groups_by_domain_and_sorts_by_total() {
        let conns = vec![
            item("a.com:443", "Safari", "PROXY › HK", 10, 90),
            item("a.com:443", "Safari", "PROXY › HK", 10, 10),
            item("b.com:443", "curl", "DIRECT", 500, 0),
        ];
        let rows = aggregate(&conns, Group::Domain, Sort::Bytes);
        assert_eq!(rows[0].name, "b.com");
        assert_eq!(rows[0].total(), 500);
        assert_eq!(rows[1].name, "a.com");
        assert_eq!(rows[1].count, 2);
        assert_eq!(rows[1].total(), 120);
    }

    #[test]
    fn groups_by_process_and_policy() {
        let conns = vec![
            item("a.com", "Safari", "AUTO › HK", 1, 2),
            item("b.com", "Safari", "AUTO › JP", 3, 4),
            item("c.com", "curl", "DIRECT", 5, 6),
        ];
        let by_proc = aggregate(&conns, Group::Process, Sort::Bytes);
        let safari = by_proc.iter().find(|t| t.name == "Safari").unwrap();
        assert_eq!(safari.count, 2);
        assert_eq!(safari.total(), 10);
        let by_policy = aggregate(&conns, Group::Policy, Sort::Bytes);
        assert_eq!(by_policy[0].name, "DIRECT");
        assert_eq!(by_policy[1].name, "AUTO");
        assert_eq!(by_policy[1].count, 2);
    }
}
