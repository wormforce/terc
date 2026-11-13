//! Read-only drift detection: what the running core config is missing compared
//! with the config terc generated for the active profile.
//!
//! This is the cheap guard against the failure mode where a config swap keeps
//! the core happy but silently drops module output such as the `tailscale-dns`
//! nameserver policy and its DIRECT rule.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use crate::mihomo::ControllerConfig;

#[derive(Debug, Default)]
pub struct Drift {
    pub expected: Option<PathBuf>,
    pub running: PathBuf,
    pub generated_missing: bool,
    pub missing_rules: Vec<String>,
    pub missing_dns_policy: Vec<String>,
}

impl Drift {
    pub fn is_clean(&self) -> bool {
        !self.generated_missing
            && self.missing_rules.is_empty()
            && self.missing_dns_policy.is_empty()
    }
}

pub fn check(cfg: &ControllerConfig) -> Result<Drift, String> {
    let running = Path::new(&cfg.config_dir).join("config.yaml");
    let running_doc = std::fs::read_to_string(&running)
        .map_err(|e| format!("cannot read {}: {e}", running.display()))?;
    let expected = generated_path(cfg);
    let mut drift = Drift {
        expected: expected.clone(),
        running,
        ..Drift::default()
    };
    let Some(expected_path) = expected else {
        return Ok(drift);
    };
    let Ok(expected_doc) = std::fs::read_to_string(&expected_path) else {
        drift.generated_missing = true;
        return Ok(drift);
    };
    let running_rules: HashSet<String> = items(&running_doc, "rules").into_iter().collect();
    drift.missing_rules = items(&expected_doc, "rules")
        .into_iter()
        .filter(|rule| !running_rules.contains(rule))
        .collect();
    let running_policy: HashSet<String> = items(&running_doc, "nameserver-policy")
        .into_iter()
        .collect();
    drift.missing_dns_policy = items(&expected_doc, "nameserver-policy")
        .into_iter()
        .filter(|entry| !running_policy.contains(entry))
        .collect();
    Ok(drift)
}

fn generated_path(cfg: &ControllerConfig) -> Option<PathBuf> {
    if cfg.profile_id.is_empty() {
        return None;
    }
    Some(
        crate::compose::terc_dir()
            .join("generated")
            .join(format!("{}.yaml", cfg.profile_id)),
    )
}

/// Items of the block starting at `key:`, up to the next line at the same or a
/// shallower indent. Blank lines and comments are skipped.
fn items(doc: &str, key: &str) -> Vec<String> {
    let mut items = Vec::new();
    let mut inside = false;
    let mut indent = 0;
    let head = format!("{key}:");
    for line in doc.lines() {
        let trimmed = line.trim_end();
        let body = trimmed.trim_start();
        let depth = trimmed.len() - body.len();
        if !inside {
            if body.starts_with(&head) {
                inside = true;
                indent = depth;
            }
            continue;
        }
        if body.is_empty() || body.starts_with('#') {
            continue;
        }
        if depth <= indent {
            break;
        }
        items.push(body.trim_start_matches('-').trim().to_string());
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_reads_only_the_block_under_the_key() {
        let doc =
            "port: 7890\nrules:\n  - MATCH,DIRECT\n  - DOMAIN,x,Proxy\nproxies:\n  - name: a\n";
        assert_eq!(items(doc, "rules"), vec!["MATCH,DIRECT", "DOMAIN,x,Proxy"]);
    }

    #[test]
    fn items_reads_nested_blocks_and_ignores_comments() {
        let doc = "dns:\n  nameserver-policy:\n    # note\n    \"+.ts.net\": 100.100.100.100\n  nameserver:\n    - 1.1.1.1\n";
        assert_eq!(
            items(doc, "nameserver-policy"),
            vec!["\"+.ts.net\": 100.100.100.100"]
        );
    }

    #[test]
    fn drift_is_clean_only_without_missing_pieces() {
        let mut drift = Drift::default();
        assert!(drift.is_clean());
        drift.missing_rules.push("MATCH,DIRECT".into());
        assert!(!drift.is_clean());
    }
}
