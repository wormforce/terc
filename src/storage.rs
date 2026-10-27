//! Source records are authoritative; cached subscriptions and generated core
//! configurations are separate files. Legacy originals are never removed.
use crate::{
    compose::{self, ProfileSource},
    ops::ProfileEntry,
    Config,
};
use std::{
    fs,
    path::{Path, PathBuf},
};
pub fn root() -> PathBuf {
    compose::terc_dir().join("sources")
}
pub fn next_id() -> String {
    let mut n = 1;
    while root().join(format!("proxy-{n:03}")).exists() {
        n += 1;
    }
    format!("proxy-{n:03}")
}
pub fn label(name: &str, url: &str, id: &str) -> String {
    if !name.trim().is_empty() && !matches!(name, "当前配置 / Current" | "当前配置" | "Current")
    {
        return name.into();
    }
    if !url.is_empty() {
        let host = url
            .split("://")
            .nth(1)
            .unwrap_or(url)
            .split(['/', '?', '#'])
            .next()
            .unwrap_or("")
            .rsplit('@')
            .next()
            .unwrap_or("");
        if !host.is_empty() {
            return host.into();
        }
    }
    // A v0.1.0 profile keeps the name the user gave its file.
    match id.strip_prefix("proxy-") {
        Some(n) => format!("代理 {n}"),
        None => id.into(),
    }
}
/// `name:`s of the `proxies:` list of a Clash document.
fn proxy_names(doc: &str) -> std::collections::HashSet<String> {
    crate::ops::split_chunks(doc)
        .iter()
        .find(|c| c.key.as_deref() == Some("proxies"))
        .map(compose::clash_item_names)
        .unwrap_or_default()
        .into_iter()
        .collect()
}
/// What a source holds, as data the list shows in the UI language:
/// `subscription`, one node's type, or `nodes:<n>`. An imported v0.1.0
/// profile keeps its nodes in `subscription.yaml`, not in `source.json`.
fn source_kind(source: &ProfileSource, dir: &Path) -> String {
    if !source.subscription_url.is_empty() {
        return "subscription".into();
    }
    let cached = fs::read_to_string(dir.join("subscription.yaml"))
        .map(|doc| proxy_names(&doc).len())
        .unwrap_or(0);
    match (source.nodes.as_slice(), cached) {
        ([node], 0) => node["type"].as_str().unwrap_or("proxy").to_uppercase(),
        (nodes, cached) => format!("nodes:{}", nodes.len() + cached),
    }
}
/// v0.1.0 marked the saved profile it last switched to in `active_profile`.
/// It is the active source after migration while the running config still
/// has that profile's nodes; an edit or update since then had replaced the
/// running config, and the name was left behind.
fn legacy_active_profile(name: &str, running: Option<&str>) -> Option<String> {
    if name.is_empty() || name.starts_with('.') || name.contains(['/', '\\']) {
        return None;
    }
    if !root().join(name).join("source.json").is_file() {
        return None;
    }
    let Some(running) = running else {
        return Some(name.into());
    };
    let saved = fs::read_to_string(
        compose::terc_dir()
            .join("profiles")
            .join(format!("{name}.yaml")),
    )
    .ok()?;
    let nodes = proxy_names(running);
    (!nodes.is_empty() && nodes == proxy_names(&saved)).then(|| name.into())
}
pub fn list(active: &str) -> Vec<ProfileEntry> {
    let mut result: Vec<_> = fs::read_dir(root())
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|f| {
            let path = f.path();
            if !path.join("source.json").is_file() {
                return None;
            }
            let id = path.file_name()?.to_str()?.to_string();
            let source = ProfileSource::load(&path);
            Some(ProfileEntry {
                kind: source_kind(&source, &path),
                label: label(&source.name, &source.subscription_url, &id),
                active: id == active,
                name: id,
                path: path.display().to_string(),
            })
        })
        .collect();
    result.sort_by(|a, b| a.name.cmp(&b.name));
    result
}

/// Permanently removes an inactive source and its cached data.
pub fn remove(id: &str, active: &str) -> Result<(), String> {
    if id == active {
        return Err("Switch to another proxy before deleting the active profile".into());
    }
    let mut components = Path::new(id).components();
    if !matches!(components.next(), Some(std::path::Component::Normal(_)))
        || components.next().is_some()
    {
        return Err("Invalid profile ID".into());
    }
    let dir = root().join(id);
    if !dir.join("source.json").is_file() {
        return Err("Profile no longer exists".into());
    }
    fs::remove_dir_all(dir).map_err(|e| format!("Could not delete profile: {e}"))
}
/// Returns the legacy node lines that could not be parsed; they stay on disk.
fn import_old(
    old: &Path,
    id: &str,
    snapshot: Option<&str>,
    url: &str,
) -> Result<Vec<String>, String> {
    let target = root().join(id);
    let mut skipped = Vec::new();
    if target.join("source.json").is_file() {
        return Ok(skipped);
    }
    let mut source = ProfileSource::load(old);
    if source.subscription_url.is_empty() {
        source.subscription_url = url.into();
    }
    source.name = label(&source.name, &source.subscription_url, id);
    let nodes_conf = old.join("nodes.conf");
    if let Ok(nodes) = fs::read_to_string(&nodes_conf) {
        for line in nodes
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#') && !l.starts_with("//"))
        {
            // Old versions skipped bad lines too; one typo must not block startup.
            let mut dropped = Vec::new();
            match crate::subconv::parse_node_line_noting(line, &mut dropped) {
                Ok(node) => {
                    source.nodes.push(node);
                    skipped.extend(
                        dropped
                            .into_iter()
                            .map(|what| format!("{}: {what}", nodes_conf.display())),
                    );
                }
                Err(reason) => skipped.push(format!("{}: {reason}", nodes_conf.display())),
            }
        }
    }
    if let Ok(mode) = fs::read_to_string(old.join("routing-mode")) {
        source.routing = mode.trim().into();
    }
    if source.routing.is_empty() {
        source.routing = "subscription".into();
    }
    for (from, to) in [
        ("subscription.cache", "subscription.yaml"),
        ("subscription.yaml", "subscription.yaml"),
        ("routing-local.yaml", "routing-local.yaml"),
    ] {
        if let Ok(text) = fs::read_to_string(old.join(from)) {
            compose::write_private(&target.join(to), &text)?;
        }
    }
    // A terc-generated snapshot already holds the manual nodes; keeping them
    // in the subscription would duplicate them with stale credentials. Its
    // other nodes may exist nowhere else, as in old saved profile copies.
    if !target.join("subscription.yaml").exists() {
        let doc = snapshot.and_then(|raw| {
            if !compose::is_generated(raw) {
                return Some(crate::ops::strip_marked_modules(raw));
            }
            let manual: Vec<String> = source
                .nodes
                .iter()
                .filter_map(|n| n["name"].as_str().map(str::to_string))
                .collect();
            compose::generated_subscription(raw, &manual)
        });
        if let Some(doc) = doc.filter(|d| crate::ops::has_subscription_source(d)) {
            compose::write_private(&target.join("subscription.yaml"), &doc)?;
        }
    }
    source.kind = if !source.subscription_url.is_empty() {
        "subscription"
    } else if target.join("subscription.yaml").exists() {
        "imported"
    } else {
        "proxy"
    }
    .into();
    // Record is written last: partial imports are retried without losing originals.
    source.save(&target)?;
    Ok(skipped)
}
/// Returns notes about skipped lines and profiles; a broken legacy profile is
/// reported and left in place rather than blocking the others or startup.
pub fn migrate(cfg: &mut Config) -> Result<Vec<String>, String> {
    // A newly selected core must not inherit the legacy imported-001 source
    // of a different core. Give it its own source based on its own file.
    if !cfg.core_instances.is_empty() && cfg.controller.profile_id.is_empty() {
        let name = cfg
            .core_instances
            .iter()
            .find(|e| {
                e.controller.addr == cfg.controller.addr
                    && e.controller.config_dir == cfg.controller.config_dir
                    && e.controller.secret == cfg.controller.secret
            })
            .map(|e| e.name.as_str())
            .unwrap_or("Core");
        bind_core_source(&root(), &mut cfg.controller, name)?;
        cfg.active_profile = cfg.controller.profile_id.clone();
        cfg.active_profile_label = name.to_string();
        cfg.save()?;
        return Ok(Vec::new());
    }
    let mut notes = Vec::new();
    let mut note = |id: &str, result: Result<Vec<String>, String>| match result {
        Ok(skipped) => notes.extend(skipped),
        Err(err) => notes.push(format!("{id}: {err}")),
    };
    let legacy = compose::terc_dir().join("profiles");
    if let Ok(files) = fs::read_dir(&legacy) {
        for file in files.flatten() {
            let path = file.path();
            if path.is_dir() && path.join("source.json").is_file() {
                let Some(id) = path.file_name().and_then(|s| s.to_str()) else {
                    continue;
                };
                let raw = fs::read_to_string(legacy.join(format!("{id}.yaml"))).ok();
                note(
                    id,
                    import_old(
                        &path,
                        id,
                        raw.as_deref(),
                        if cfg.controller.profile_id == id {
                            &cfg.controller.subscription_url
                        } else {
                            ""
                        },
                    ),
                );
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) != Some("yaml") {
                continue;
            }
            let Some(id) = path.file_stem().and_then(|s| s.to_str()) else {
                continue;
            };
            let result = fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|raw| {
                    import_old(
                        &legacy.join(id),
                        id,
                        Some(&raw),
                        if cfg.controller.profile_id == id {
                            &cfg.controller.subscription_url
                        } else {
                            ""
                        },
                    )
                });
            note(id, result);
        }
    }
    if cfg.controller.profile_id.is_empty() {
        let raw = crate::mihomo::read_config_text(&cfg.controller).ok();
        let active = legacy_active_profile(&cfg.active_profile, raw.as_deref());
        // The running config is that profile's copy then; it is imported
        // already, so it is not imported a second time here.
        let snapshot = raw.as_deref().filter(|_| active.is_none());
        if snapshot.is_some()
            || !cfg.controller.subscription_url.is_empty()
            || compose::terc_dir().join("nodes.conf").exists()
        {
            // Stable ID makes retrying a migration safe after an interrupted save.
            let id = "imported-001";
            let result = import_old(
                &compose::terc_dir(),
                id,
                snapshot,
                &cfg.controller.subscription_url,
            );
            if result.is_ok() && active.is_none() {
                cfg.controller.profile_id = id.into();
            }
            note(id, result);
        }
        if let Some(id) = active {
            cfg.controller.profile_id = id;
        }
    }
    if !cfg.controller.profile_id.is_empty() {
        let source = ProfileSource::load(&compose::profile_dir(&cfg.controller));
        cfg.active_profile = cfg.controller.profile_id.clone();
        cfg.active_profile_label =
            label(&source.name, &source.subscription_url, &cfg.active_profile);
        cfg.controller.subscription_url = source.subscription_url;
        cfg.save()?;
    }
    Ok(notes)
}

fn bind_core_source(
    root: &Path,
    controller: &mut crate::mihomo::ControllerConfig,
    name: &str,
) -> Result<(), String> {
    let mut n = 1;
    while root.join(format!("proxy-{n:03}")).exists() {
        n += 1;
    }
    let id = format!("proxy-{n:03}");
    let target = root.join(&id);
    let doc = crate::mihomo::read_config_text(controller)
        .ok()
        .map(|text| crate::ops::strip_marked_modules(&text))
        .filter(|text| crate::ops::has_subscription_source(text));
    if let Some(text) = &doc {
        compose::write_private(&target.join("subscription.yaml"), text)?;
    }
    let source = ProfileSource {
        name: name.to_string(),
        subscription_url: controller.subscription_url.clone(),
        kind: if doc.is_some() { "imported" } else { "proxy" }.into(),
        ..ProfileSource::default()
    };
    source.save(&target)?;
    controller.profile_id = id;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn selected_cores_import_their_own_source_without_touching_existing_data() {
        let temp = std::env::temp_dir().join(format!("terc-core-source-{}", std::process::id()));
        let root = temp.join("sources");
        let core = temp.join("core");
        fs::create_dir_all(root.join("proxy-001")).unwrap();
        fs::create_dir_all(&core).unwrap();
        fs::write(root.join("proxy-001/subscription.yaml"), "old source").unwrap();
        let yaml = "proxies:\n  - {name: xkp, type: direct}\nrules:\n  - MATCH,DIRECT\n";
        fs::write(core.join("config.yaml"), yaml).unwrap();
        let mut cfg = crate::mihomo::ControllerConfig {
            config_dir: core.display().to_string(),
            ..Default::default()
        };
        bind_core_source(&root, &mut cfg, "xkp").unwrap();
        assert_eq!(cfg.profile_id, "proxy-002");
        assert_eq!(
            fs::read_to_string(root.join("proxy-001/subscription.yaml")).unwrap(),
            "old source"
        );
        assert_eq!(fs::read_to_string(core.join("config.yaml")).unwrap(), yaml);
        assert!(fs::read_to_string(root.join("proxy-002/subscription.yaml"))
            .unwrap()
            .contains("name: xkp"));
        assert_eq!(ProfileSource::load(&root.join("proxy-002")).name, "xkp");
        fs::remove_dir_all(temp).unwrap();
    }
    #[test]
    fn display_names_only_replace_legacy_placeholders() {
        assert_eq!(
            label("Current VPN", "https://airport.test/sub", "proxy-001"),
            "Current VPN"
        );
        assert_eq!(
            label(
                "当前配置 / Current",
                "https://airport.test/sub?token=hidden",
                "proxy-001"
            ),
            "airport.test"
        );
        assert_eq!(label("", "", "proxy-001"), "代理 001");
        assert_eq!(label("", "", "work"), "work");
    }
    #[test]
    #[ignore = "changes HOME; run alone with temporary data; never starts a core"]
    fn migration_keeps_the_v010_profile_that_was_running() {
        let temp = temp_home("store-active");
        let home = "proxies:\n  - {name: HomeNode, type: ss, server: 192.0.2.7, port: 8388, cipher: aes-128-gcm, password: fake}\n  - {name: HomeNode2, type: ss, server: 192.0.2.8, port: 8388, cipher: aes-128-gcm, password: fake}\nproxy-groups:\n  - {name: Home, type: select, proxies: [HomeNode, HomeNode2]}\nrules:\n  - MATCH,Home\n";
        let airport = "proxies:\n  - {name: Remote, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: secret}\nrules:\n  - MATCH,DIRECT\n";
        let profiles = compose::terc_dir().join("profiles");
        compose::write_private(&profiles.join("home.yaml"), home).unwrap();
        compose::write_private(&profiles.join("work.yaml"), airport).unwrap();
        compose::write_private(&compose::terc_dir().join("subscription.cache"), airport).unwrap();
        let core = temp.join("core");
        compose::write_private(&core.join("config.yaml"), home).unwrap();
        let v010 = |active: &str| {
            let mut cfg = Config::default();
            cfg.controller.config_dir = core.display().to_string();
            cfg.controller.subscription_url = "https://sub.test/s?token=x".into();
            cfg.active_profile = active.into();
            cfg
        };
        let mut cfg = v010("home");
        migrate(&mut cfg).unwrap();
        assert_eq!(cfg.controller.profile_id, "home");
        assert!(cfg.controller.subscription_url.is_empty());
        // The airport source is still imported, inactive.
        let imported = ProfileSource::load(&root().join("imported-001"));
        assert_eq!(imported.subscription_url, "https://sub.test/s?token=x");
        let listed = list(&cfg.controller.profile_id);
        let entry = |id: &str| listed.iter().find(|e| e.name == id).unwrap().clone();
        assert!(entry("home").active && !entry("imported-001").active);
        assert_eq!(entry("home").label, "home");
        assert_eq!(entry("home").kind, "nodes:2");
        assert_eq!(entry("work").kind, "nodes:1");
        assert_eq!(entry("imported-001").kind, "subscription");

        // A name left behind after the running config was replaced.
        fs::remove_dir_all(compose::terc_dir().join("sources")).unwrap();
        let mut cfg = v010("work");
        compose::write_private(&core.join("config.yaml"), home).unwrap();
        migrate(&mut cfg).unwrap();
        assert_eq!(cfg.controller.profile_id, "imported-001");
        fs::remove_dir_all(temp).unwrap();
    }
    #[test]
    #[ignore = "changes HOME; run alone with temporary data; never starts a core"]
    fn migration_preserves_sources_nodes_and_assignments() {
        let temp = std::env::temp_dir().join(format!("terc-store-{}", std::process::id()));
        fs::create_dir_all(&temp).unwrap();
        std::env::set_var("HOME", &temp);
        let old = compose::terc_dir().join("profiles/old-1");
        let raw="proxies:\n  - {name: Remote, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: secret}\nproxy-groups:\n  - {name: Airport, type: select, proxies: [Remote]}\nrules:\n  - MATCH,Airport\n";
        compose::write_private(
            &old.join("source.json"),
            r#"{"name":"我的机场","subscription_url":"https://airport.test/sub?token=secret"}"#,
        )
        .unwrap();
        compose::write_private(&old.join("nodes.conf"),"# original comments\nLocal = ss, 192.0.2.2, 8388, encrypt-method=aes-128-gcm, password=fake\n").unwrap();
        compose::write_private(&old.join("subscription.cache"), raw).unwrap();
        compose::write_private(&old.join("routing-mode"), "all").unwrap();
        compose::write_private(&old.with_extension("yaml"), raw).unwrap();
        let mut cfg = Config::default();
        cfg.controller.profile_id = "old-1".into();
        migrate(&mut cfg).unwrap();
        let source = ProfileSource::load(&root().join("old-1"));
        assert_eq!(source.name, "我的机场");
        assert_eq!(source.routing, "all");
        assert_eq!(source.nodes.len(), 1);
        assert!(crate::routing::entries(&cfg.controller, true)
            .iter()
            .any(|p| p.label == "我的机场 的分流"));
        assert_eq!(source.nodes[0]["name"], "Local");
        assert!(old.join("nodes.conf").is_file());
        assert!(old.join("subscription.cache").is_file());
        assert_eq!(
            fs::read_to_string(root().join("old-1/subscription.yaml")).unwrap(),
            raw
        );
        migrate(&mut cfg).unwrap();
        assert_eq!(list("old-1").len(), 1);
        assert_eq!(ProfileSource::load(&root().join("old-1")).nodes.len(), 1);
        let mut cfg = Config::default();
        cfg.controller.config_dir = temp.join("core").display().to_string();
        compose::write_private(
            &Path::new(&cfg.controller.config_dir).join("config.yaml"),
            raw,
        )
        .unwrap();
        cfg.controller.subscription_url = "https://example.test/sub?token=secret".into();
        migrate(&mut cfg).unwrap();
        assert_eq!(cfg.active_profile_label, "example.test");
        assert!(!cfg.active_profile_label.contains("secret"));
        assert!(!cfg.controller.profile_id.is_empty());
        fs::remove_dir_all(temp).unwrap();
    }
    fn temp_home(name: &str) -> PathBuf {
        let temp = std::env::temp_dir().join(format!("terc-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(&temp).unwrap();
        std::env::set_var("HOME", &temp);
        temp
    }
    const OWN_NODE: &str =
        "OwnNode = ss, 192.0.2.3, 8388, encrypt-method=aes-128-gcm, password=fake";
    fn generated_config(cfg: &mut Config, temp: &Path) {
        cfg.controller.config_dir = temp.join("core").display().to_string();
        let doc = format!("{}\nproxies:\n  - {{name: OwnNode, type: ss, server: 192.0.2.3, port: 8388, cipher: aes-128-gcm, password: fake}}\nrules:\n  - MATCH,DIRECT\n", compose::GENERATED_MARK);
        compose::write_private(
            &Path::new(&cfg.controller.config_dir).join("config.yaml"),
            &doc,
        )
        .unwrap();
    }
    #[test]
    #[ignore = "changes HOME; run alone with temporary data; never starts a core"]
    fn migration_skips_unparseable_legacy_node_lines() {
        let temp = temp_home("store-bad-line");
        let old = compose::terc_dir().join("profiles/profile-3");
        compose::write_private(
            &old.join("source.json"),
            r#"{"name":"Mine","subscription_url":""}"#,
        )
        .unwrap();
        let nodes = format!("{OWN_NODE}\nTypo = ss 192.0.2.9\n");
        compose::write_private(&old.join("nodes.conf"), &nodes).unwrap();
        let mut cfg = Config::default();
        let notes = migrate(&mut cfg).unwrap();
        let source = ProfileSource::load(&root().join("profile-3"));
        assert_eq!(source.nodes.len(), 1);
        assert_eq!(source.nodes[0]["name"], "OwnNode");
        assert!(notes.iter().any(|n| n.contains("Typo = ss 192.0.2.9")));
        assert_eq!(fs::read_to_string(old.join("nodes.conf")).unwrap(), nodes);
        fs::remove_dir_all(temp).unwrap();
    }
    #[test]
    #[ignore = "changes HOME; run alone with temporary data; never starts a core"]
    fn migration_ignores_generated_snapshot_for_node_only_source() {
        let temp = temp_home("store-generated");
        compose::add_manual_node(&compose::terc_dir(), OWN_NODE).unwrap();
        let mut cfg = Config::default();
        generated_config(&mut cfg, &temp);
        migrate(&mut cfg).unwrap();
        assert_eq!(cfg.controller.profile_id, "imported-001");
        let source = ProfileSource::load(&root().join("imported-001"));
        assert_eq!(source.kind, "proxy");
        assert!(!root().join("imported-001/subscription.yaml").exists());
        assert_eq!(source.nodes.len(), 1);
        fs::remove_dir_all(temp).unwrap();
    }
    #[test]
    #[ignore = "changes HOME; run alone with temporary data; never starts a core"]
    fn migration_keeps_subscription_nodes_of_generated_snapshots() {
        let temp = temp_home("store-generated-sub");
        let remote = "  - {name: Remote, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: secret}\n";
        let own = "  - {\"name\":\"OwnNode\",\"type\":\"ss\",\"server\":\"192.0.2.3\",\"port\":8388,\"cipher\":\"aes-128-gcm\",\"password\":\"fake\"}\n";
        // An old saved copy of the generated config is its profile's only data.
        compose::write_private(
            &compose::terc_dir().join("profiles/profile-1.yaml"),
            &format!(
                "{}\nproxies:\n{remote}rules:\n  - MATCH,DIRECT\n",
                compose::GENERATED_MARK
            ),
        )
        .unwrap();
        // A config composed from a hand-written one without caching it.
        compose::write_private(&compose::terc_dir().join("nodes.conf"), OWN_NODE).unwrap();
        let mut cfg = Config::default();
        cfg.controller.config_dir = temp.join("core").display().to_string();
        compose::write_private(
            &Path::new(&cfg.controller.config_dir).join("config.yaml"),
            &format!(
                "{}\nproxies:\n{remote}{own}rules:\n  - MATCH,DIRECT\n",
                compose::GENERATED_MARK
            ),
        )
        .unwrap();
        migrate(&mut cfg).unwrap();
        for (id, nodes) in [("profile-1", 0), ("imported-001", 1)] {
            let source = ProfileSource::load(&root().join(id));
            assert_eq!(source.kind, "imported", "{id}");
            assert_eq!(source.nodes.len(), nodes, "{id}");
            let sub = fs::read_to_string(root().join(id).join("subscription.yaml")).unwrap();
            assert!(sub.contains("name: Remote"), "{id}");
            assert!(!sub.contains("OwnNode"), "{id}");
        }
        fs::remove_dir_all(temp).unwrap();
    }
    #[test]
    #[ignore = "changes HOME; run alone with temporary data; never starts a core"]
    fn migration_keeps_cached_subscription_download() {
        let temp = temp_home("store-cache");
        let raw = "proxies:\n  - {name: Remote, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: secret}\nrules:\n  - MATCH,DIRECT\n";
        compose::write_private(&compose::terc_dir().join("subscription.yaml"), raw).unwrap();
        let mut cfg = Config::default();
        generated_config(&mut cfg, &temp);
        migrate(&mut cfg).unwrap();
        assert_eq!(
            fs::read_to_string(root().join("imported-001/subscription.yaml")).unwrap(),
            raw
        );
        assert_eq!(
            ProfileSource::load(&root().join("imported-001")).kind,
            "imported"
        );
        fs::remove_dir_all(temp).unwrap();
    }
}
