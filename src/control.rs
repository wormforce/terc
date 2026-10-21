//! Dashboard actions that sit on top of the Mihomo controller.
//!
//! Runtime switches use PATCH so they land immediately. DNS and module
//! changes rewrite `config.yaml` and hot-reload, because those fields are
//! not partial-update keys. Nothing here touches the macOS system proxy.

use std::{fs, path::PathBuf};

use crate::{
    mihomo::{
        dns_query_async, flush_dns_async, is_info_pseudo_node, persist_live_bool,
        persist_nested_bool, probe_async, provider_healthcheck_async, read_config_text,
        refresh_all_providers_async, refresh_provider_async, refreshable_provider, set_bool_config,
        set_rule_disabled, test_group_delays_async, test_node_async, verify_runtime_value,
        HealthTexts, ProxyNode,
    },
    ops::{
        apply_enabled_modules, enabled_snippets, explain_rules, is_runtime_tunnel, module_catalog,
        modules_dir, parse_dns_block, ModuleSnippet, ProfileEntry,
    },
    App, Overlay,
};

const DNS_QTYPES: &[&str] = &["A", "AAAA", "CNAME", "TXT", "MX"];

impl App {
    pub fn clamp_aux(&mut self) {
        self.clamp_node_index();
        self.rule_index = clamp_to(self.rule_index, self.filtered_rule_indexes().len());
        self.provider_index = clamp_to(self.provider_index, self.snapshot.providers.len());
        self.module_index = clamp_to(self.module_index, self.catalog.len());
        self.profile_index = clamp_to(self.profile_index, self.profiles.len());
        self.tunnel_index = clamp_to(self.tunnel_index, self.wireguard_peers().len());
    }

    pub fn wireguard_peers(&self) -> Vec<ProxyNode> {
        let mut peers: Vec<_> = self
            .snapshot
            .nodes
            .values()
            .filter(|node| is_runtime_tunnel(&node.kind))
            .cloned()
            .collect();
        peers.sort_by(|a, b| a.name.cmp(&b.name));
        peers
    }

    pub fn selected_proxy_name(&self) -> String {
        self.snapshot
            .groups
            .get(self.group_index)
            .and_then(|group| group.all.get(self.node_index))
            .filter(|name| !is_info_pseudo_node(name))
            .cloned()
            .unwrap_or_else(|| "DIRECT".to_string())
    }

    pub fn dns_qtype(&self) -> &'static str {
        DNS_QTYPES
            .get(self.dns_qtype_idx % DNS_QTYPES.len())
            .copied()
            .unwrap_or("A")
    }

    pub fn cycle_dns_qtype(&mut self, dir: i32) {
        let len = DNS_QTYPES.len() as i32;
        let next = (self.dns_qtype_idx as i32 + dir).rem_euclid(len) as usize;
        self.dns_qtype_idx = next;
    }

    pub fn filtered_rule_indexes(&self) -> Vec<usize> {
        let query = self.rule_query.text.trim().to_ascii_lowercase();
        self.snapshot
            .rules
            .iter()
            .enumerate()
            .filter(|(_, rule)| {
                if query.is_empty() {
                    return true;
                }
                rule.kind.to_ascii_lowercase().contains(&query)
                    || rule.payload.to_ascii_lowercase().contains(&query)
                    || rule.proxy.to_ascii_lowercase().contains(&query)
            })
            .map(|(index, _)| index)
            .collect()
    }

    pub fn toggle_tun(&mut self) {
        let next = !self.snapshot.tun_enabled;
        let running = self.snapshot.running;
        // Enabling only patches TUN in, except that a non-root core on macOS is
        // restarted; the uid check needs the core's pid, so assume a restart.
        let disrupt = if !next {
            Some(crate::guard::Disrupt::TunOff)
        } else if cfg!(target_os = "macos") && running {
            Some(crate::guard::Disrupt::TunOnRestart)
        } else {
            None
        };
        if disrupt.is_some_and(|what| !self.confirm_disruption(what)) {
            return;
        }
        self.run_action(
            "正在设置 TUN，macOS 可能请求管理员授权 / Applying TUN…",
            None,
            None,
            move |cfg| crate::privilege::set_tun(&cfg, next, running),
        );
    }

    pub fn toggle_sniffing(&mut self) {
        self.runtime_switch(&["sniffer", "enable"], "sniffing", !self.snapshot.sniffing);
    }

    pub fn toggle_ipv6(&mut self) {
        self.runtime_switch(&["ipv6"], "ipv6", !self.snapshot.ipv6);
    }

    fn runtime_switch(&mut self, path: &[&str], field: &str, next: bool) {
        let path: Vec<String> = path.iter().map(|p| p.to_string()).collect();
        let field = field.to_string();
        let running = self.snapshot.running;
        self.run_action("Applying runtime switch…", None, None, move |cfg| {
            let refs: Vec<&str> = path.iter().map(String::as_str).collect();
            if running {
                // The core accepted and reports the value, so saving it skips
                // `mihomo -t`. A value that does not read back is not saved.
                set_bool_config(&cfg, &field, next)
                    .map_err(|e| e.to_string())
                    .and_then(|()| verify_runtime_value(&cfg, &field, &next.into()))
                    .map_err(|err| format!("Runtime change rejected: {err}"))?;
                persist_live_bool(&cfg, &refs, next)
                    .map_err(|err| format!("Runtime changed, but could not save: {err}"))?;
            } else {
                persist_nested_bool(&cfg, &refs, next)?;
            }
            Ok(if running {
                "Runtime changed and saved"
            } else {
                "Saved; core stopped"
            }
            .into())
        });
    }

    pub fn toggle_dns(&mut self) {
        if !self.confirm_disruption(crate::guard::Disrupt::Reload) {
            return;
        }
        let running = self.snapshot.running;
        self.run_action("Updating DNS configuration…", None, None, move |cfg| {
            let raw = read_config_text(&cfg)?;
            let dns = parse_dns_block(&raw);
            if !dns.present {
                return Err("No DNS block is configured".into());
            }
            let updated = crate::ops::set_nested_bool(&raw, &["dns", "enable"], !dns.enable);
            crate::mihomo::install_config(&cfg, &updated, running)?;
            Ok(if running {
                "DNS configuration applied"
            } else {
                "DNS saved; core stopped"
            }
            .into())
        });
    }

    pub fn submit_dns_query(&mut self) {
        let name = self.dns_editor.trimmed();
        if name.is_empty() {
            self.set_status(self.t("st_dns_empty"), true);
            return;
        }
        self.dns_editing = false;
        self.dns_lines = vec![self.t("st_dns_lookup").to_string()];
        self.dns_error = false;
        dns_query_async(
            self.config.controller.clone(),
            name,
            self.dns_qtype().to_string(),
            self.tx.clone(),
        );
    }

    pub fn flush_dns_cache(&mut self) {
        if !self.snapshot.running {
            self.set_status(self.t("st_core_down"), true);
            return;
        }
        self.set_status(self.t("st_dns_flushing"), false);
        flush_dns_async(self.config.controller.clone(), self.tx.clone());
    }

    pub fn explain_target(&mut self, raw: &str) {
        let raw = raw.trim();
        if raw.is_empty() {
            return;
        }
        self.explain = Some(explain_rules(&self.snapshot.rules, raw));
    }

    pub fn explain_selected_rule(&mut self) {
        let query = self.rule_query.trimmed();
        if !query.is_empty() {
            self.explain_target(&query);
            return;
        }
        let Some(rule) = self.selected_rule().cloned() else {
            return;
        };
        let target = if rule.payload.is_empty() {
            rule.kind.clone()
        } else {
            rule.payload.clone()
        };
        self.explain = Some(explain_rules(&self.snapshot.rules, &target));
    }

    pub fn toggle_selected_rule(&mut self) {
        let Some(rule) = self.selected_rule().cloned() else {
            return;
        };
        if !self.snapshot.running {
            self.set_status(self.t("st_core_down"), true);
            return;
        }
        let disabled = !rule.disabled;
        self.run_action("Updating rule…", None, None, move |cfg| {
            set_rule_disabled(&cfg, rule.index, disabled).map_err(|e| e.to_string())?;
            Ok(if disabled {
                "Rule disabled"
            } else {
                "Rule enabled"
            }
            .into())
        });
    }

    pub fn refresh_selected_provider(&mut self) {
        let Some(provider) = self.snapshot.providers.get(self.provider_index).cloned() else {
            self.set_status(self.t("st_no_provider"), true);
            return;
        };
        self.set_status(
            &format!("{} {}", self.t("st_provider_busy"), provider.name),
            false,
        );
        refresh_provider_async(
            self.config.controller.clone(),
            provider.kind,
            provider.name,
            self.tx.clone(),
        );
    }

    pub fn healthcheck_selected_provider(&mut self) {
        let Some(provider) = self.snapshot.providers.get(self.provider_index).cloned() else {
            return;
        };
        if provider.kind != "proxy" {
            self.set_status(self.t("st_provider_rule"), false);
            return;
        }
        let name = provider.name;
        let texts = match self.lang() {
            crate::Lang::Zh => HealthTexts {
                done: format!("健康检查完成  {name}"),
                still: format!("内核仍在检测 {name}，延迟会陆续更新"),
            },
            crate::Lang::En => HealthTexts {
                done: format!("Health check finished  {name}"),
                still: format!("The core is still checking {name}; delays update as they come in"),
            },
            crate::Lang::Ja => HealthTexts {
                done: format!("ヘルスチェック完了  {name}"),
                still: format!("コアが {name} を検査中。遅延は順次更新されます"),
            },
        };
        self.set_status(&format!("{}  {name}", self.t("st_provider_health")), false);
        provider_healthcheck_async(self.config.controller.clone(), name, texts, self.tx.clone());
    }

    pub fn refresh_all_providers(&mut self) {
        let providers: Vec<_> = self
            .snapshot
            .providers
            .iter()
            .filter(|p| refreshable_provider(p))
            .cloned()
            .collect();
        if providers.is_empty() {
            self.set_status(self.t("st_no_provider"), true);
            return;
        }
        self.set_status(self.t("st_provider_all"), false);
        refresh_all_providers_async(self.config.controller.clone(), providers, self.tx.clone());
    }

    pub fn open_modules(&mut self) {
        self.catalog = module_catalog(&modules_dir(&home_dir()));
        self.module_index = clamp_to(self.module_index, self.catalog.len());
        self.overlay = Overlay::Modules;
    }

    pub fn close_overlay(&mut self) {
        self.overlay = Overlay::None;
    }

    pub fn module_enabled(&self, id: &str) -> bool {
        self.config.enabled_modules.iter().any(|item| item == id)
    }

    pub fn toggle_selected_module(&mut self) {
        let Some(module) = self.catalog.get(self.module_index).cloned() else {
            return;
        };
        let raw = match read_config_text(&self.config.controller) {
            Ok(text) => text,
            Err(err) => {
                self.set_status(&err, true);
                return;
            }
        };
        let enabling = !self.module_enabled(&module.id);
        let mut ids = self.config.enabled_modules.clone();
        if enabling {
            ids.push(module.id.clone());
        } else {
            ids.retain(|id| id != &module.id);
        }
        let snippets = enabled_snippets(&self.catalog, &ids);
        if !self.confirm_disruption(crate::guard::Disrupt::Reload) {
            return;
        }
        let running = self.snapshot.running;
        self.run_action(
            "Applying module configuration…",
            Some(ids),
            None,
            move |cfg| {
                let next = apply_enabled_modules(&raw, &snippets)?;
                crate::mihomo::install_config(&cfg, &next, running)?;
                Ok(if enabling {
                    "Module enabled"
                } else {
                    "Module disabled"
                }
                .into())
            },
        );
    }

    pub fn open_profiles(&mut self) {
        self.routing_mode = crate::routing::selected(&self.config.controller);
        self.routing_plans =
            crate::routing::entries(&self.config.controller, self.lang() == crate::Lang::Zh);
        self.routing_index = self
            .routing_plans
            .iter()
            .position(|p| p.id == self.routing_mode)
            .unwrap_or(0);
        self.profiles = self.profile_list();
        self.profile_index = clamp_to(self.profile_index, self.profiles.len());
        self.own_nodes = crate::compose::load_manual_nodes(&crate::compose::profile_dir(
            &self.config.controller,
        ));
        self.screen = crate::Screen::Settings;
        self.overlay = Overlay::None;
        self.settings_management = true;
    }

    pub fn switch_selected_profile(&mut self) {
        let Some(profile) = self.profiles.get(self.profile_index).cloned() else {
            return;
        };
        if self.action_busy || !self.confirm_disruption(crate::guard::Disrupt::Reload) {
            return;
        }
        let modules = enabled_snippets(
            &module_catalog(&modules_dir(&home_dir())),
            &self.config.enabled_modules,
        );
        let running = self.snapshot.running;
        let target_id = profile.name.clone();
        self.run_action(
            "Applying configuration profile…",
            None,
            Some(profile.name),
            move |mut cfg| {
                cfg.profile_id = target_id;
                let source_dir = crate::compose::profile_dir(&cfg);
                cfg.subscription_url =
                    crate::compose::ProfileSource::load(&source_dir).subscription_url;
                crate::mihomo::regenerate_config(&cfg, &modules, running, false, true)
            },
        );
    }

    pub fn save_profile_copy(&mut self) {
        if self.action_busy {
            return;
        }
        let raw = match read_config_text(&self.config.controller) {
            Ok(text) => text,
            Err(err) => {
                self.set_status(&err, true);
                return;
            }
        };
        let id = crate::storage::next_id();
        let source_dir = crate::compose::profile_dir(&self.config.controller);
        let target_dir = crate::storage::root().join(&id);
        let result = (|| -> Result<(), String> {
            let mut source = crate::compose::ProfileSource::load(&source_dir);
            source.name = if self.config.active_profile_label.is_empty() {
                crate::storage::label("", &self.config.controller.subscription_url, &id)
            } else {
                format!("{} 副本", self.config.active_profile_label)
            };
            source.subscription_url = self.config.controller.subscription_url.clone();
            for filename in ["subscription.yaml", "routing-local.yaml"] {
                if let Ok(text) = fs::read_to_string(source_dir.join(filename)) {
                    crate::compose::write_private(&target_dir.join(filename), &text)?;
                }
            }
            if !target_dir.join("subscription.yaml").exists() && source.nodes.is_empty() {
                crate::compose::write_private(
                    &target_dir.join("subscription.yaml"),
                    &crate::ops::strip_marked_modules(&raw),
                )?;
            }
            source.save(&target_dir)
        })();
        if let Err(err) = result {
            self.set_status(&err, true);
            return;
        }
        self.config.controller.profile_id = id.clone();
        self.config.active_profile = id;
        self.config.active_profile_label = crate::compose::ProfileSource::load(&target_dir).name;
        self.save_preferences();
        self.open_profiles();
        self.set_status("代理副本已保存", false);
    }

    pub fn reload_profile(&mut self) {
        if !self.snapshot.running {
            self.set_status(self.t("st_core_down"), true);
            return;
        }
        if !self.confirm_disruption(crate::guard::Disrupt::Reload) {
            return;
        }
        self.set_status(self.t("st_reloading"), false);
        self.run_action(
            "Validating and reloading configuration…",
            None,
            None,
            |cfg| {
                let raw = read_config_text(&cfg)?;
                crate::mihomo::install_config(&cfg, &raw, true)?;
                Ok("Configuration reloaded".into())
            },
        );
    }

    pub fn open_probe(&mut self) {
        if self.probe_editor.text.is_empty() {
            self.probe_editor.load("example.com");
        }
        self.overlay = Overlay::Probe;
    }

    pub fn submit_probe(&mut self) {
        let raw = self.probe_editor.trimmed();
        if raw.is_empty() {
            self.set_status(self.t("st_probe_empty"), true);
            return;
        }
        if !self.snapshot.running {
            self.set_status(self.t("st_core_down"), true);
            return;
        }
        let node = self.selected_proxy_name();
        self.probe_lines = vec![format!("{} {raw}", self.t("st_probe_busy"))];
        self.probe_error = false;
        probe_async(self.config.controller.clone(), node, raw, self.tx.clone());
    }

    pub fn open_runtime(&mut self) {
        self.tunnel_index = clamp_to(self.tunnel_index, self.wireguard_peers().len());
        self.overlay = Overlay::Runtime;
    }

    pub fn test_selected_tunnel(&mut self) {
        let Some(peer) = self.wireguard_peers().get(self.tunnel_index).cloned() else {
            self.set_status(self.t("st_no_wg"), false);
            return;
        };
        self.set_status(&format!("{} {}", self.t("st_probe_busy"), peer.name), false);
        test_node_async(self.config.controller.clone(), peer.name, self.tx.clone());
    }

    pub fn test_all_tunnels(&mut self) {
        let names: Vec<String> = self
            .wireguard_peers()
            .into_iter()
            .map(|peer| peer.name)
            .collect();
        if names.is_empty() {
            self.set_status(self.t("st_no_wg"), false);
            return;
        }
        self.set_status(self.t("st_wg_test"), false);
        test_group_delays_async(
            self.config.controller.clone(),
            "WireGuard".into(),
            names,
            self.tx.clone(),
        );
    }

    pub fn selected_module(&self) -> Option<&ModuleSnippet> {
        self.catalog.get(self.module_index)
    }

    pub fn selected_profile(&self) -> Option<&ProfileEntry> {
        self.profiles.get(self.profile_index)
    }

    fn selected_rule(&self) -> Option<&crate::ops::RuleInfo> {
        let indexes = self.filtered_rule_indexes();
        let raw = *indexes.get(self.rule_index)?;
        self.snapshot.rules.get(raw)
    }

    fn profile_list(&self) -> Vec<ProfileEntry> {
        crate::storage::list(&self.config.controller.profile_id)
    }
}

fn clamp_to(index: usize, len: usize) -> usize {
    if len == 0 {
        0
    } else {
        index.min(len - 1)
    }
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

impl App {
    pub fn profile_display_name(&self) -> String {
        if self.config.controller.profile_id.is_empty() {
            return "尚未添加代理".into();
        }
        crate::storage::label(
            &self.config.active_profile_label,
            &self.config.controller.subscription_url,
            &self.config.controller.profile_id,
        )
    }

    pub fn save_profile_source(&mut self) {
        let dir = crate::compose::profile_dir(&self.config.controller);
        let mut source = crate::compose::ProfileSource::load(&dir);
        source.subscription_url = self.config.controller.subscription_url.clone();
        if let Err(err) = source.save(&dir) {
            self.set_status(&err, true);
        }
    }

    pub fn import_profile(&mut self, text: &str) {
        let is_url = text.starts_with("https://") || text.starts_with("http://");
        let mut record = crate::compose::ProfileSource::default();
        record.routing = "subscription".into();
        record.kind = if is_url { "subscription" } else { "proxy" }.into();
        if is_url {
            record.subscription_url = text.trim().into();
            record.name = crate::storage::label("", text, "new");
        } else {
            let lines = match crate::subconv::block_to_node_lines(text).transpose() {
                Ok(lines) => lines.unwrap_or_else(|| text.lines().map(str::to_string).collect()),
                Err(err) => {
                    self.set_status(&err, true);
                    return;
                }
            };
            for line in lines.iter().map(|s| s.trim()).filter(|s| !s.is_empty()) {
                match crate::subconv::parse_node_line(line) {
                    Ok(node) => record.nodes.push(node),
                    Err(err) => {
                        self.set_status(&err, true);
                        return;
                    }
                }
            }
            record.name = record
                .nodes
                .first()
                .and_then(|n| n["name"].as_str())
                .unwrap_or("导入代理")
                .into();
        }
        self.save_source_record(record, None);
    }

    pub fn save_source_record(
        &mut self,
        record: crate::compose::ProfileSource,
        edit_id: Option<String>,
    ) {
        if self.action_busy {
            return;
        }
        if self.config.controller.profile_id.is_empty()
            && crate::mihomo::config_file_exists(&self.config.controller)
        {
            self.save_profile_copy();
            if self.config.controller.profile_id.is_empty() {
                return;
            }
        }
        let id = edit_id.unwrap_or_else(crate::storage::next_id);
        let running = self.snapshot.running;
        let modules = enabled_snippets(
            &module_catalog(&modules_dir(&home_dir())),
            &self.config.enabled_modules,
        );
        self.manage_input = None;
        self.run_action(
            "正在保存代理…",
            None,
            Some(id.clone()),
            move |mut cfg| {
                cfg.profile_id = id;
                cfg.subscription_url = record.subscription_url.clone();
                let dir = crate::compose::profile_dir(&cfg);
                let old = fs::read_to_string(dir.join("source.json")).ok();
                let refresh = old
                    .as_ref()
                    .and_then(|s| serde_json::from_str::<crate::compose::ProfileSource>(s).ok())
                    .is_none_or(|s| s.subscription_url != record.subscription_url)
                    && !record.subscription_url.is_empty();
                record.save(&dir)?;
                let result =
                    crate::mihomo::regenerate_config(&cfg, &modules, running, refresh, true);
                if result.is_err() {
                    if let Some(raw) = old {
                        crate::compose::write_private(&dir.join("source.json"), &raw)?;
                    } else {
                        let _ = fs::remove_dir_all(&dir);
                    }
                }
                result
            },
        );
    }

    pub fn load_core_log(&mut self) {
        let text = crate::mihomo::core_log_excerpt(&self.config.controller);
        for line in text.lines() {
            let level = if line.contains("level=error") || line.contains("level=fatal") {
                "error"
            } else if line.contains("level=warning") {
                "warn"
            } else {
                "info"
            };
            let entry = (level.to_string(), line.to_string());
            if !self.logs.contains(&entry) {
                self.logs.push(entry);
            }
        }
        if self.logs.len() > 300 {
            self.logs.drain(..self.logs.len() - 300);
        }
    }
}

#[cfg(test)]
mod profile_integration_tests {
    use super::*;
    use std::{
        thread,
        time::{Duration, Instant},
    };
    fn finish(app: &mut App) {
        let start = Instant::now();
        while app.action_busy && start.elapsed() < Duration::from_secs(15) {
            thread::sleep(Duration::from_millis(10));
            app.drain_events();
        }
        assert!(!app.action_busy, "operation did not finish");
        assert!(!app.status_is_error, "{}", app.status_message);
        app.drain_events();
        // The worker sends ActionDone before its snapshot; refresh synchronously
        // so assertions inspect the applied file rather than a queued old view.
        let snapshot = crate::mihomo::fetch_snapshot(&app.config.controller);
        app.accept_snapshot(snapshot);
    }
    #[test]
    #[ignore = "requires Mihomo; run alone with temporary HOME; never starts core"]
    fn routing_switches_preserve_sources_and_failed_selection() {
        let home = std::env::temp_dir().join(format!("terc-routing-switch-{}", std::process::id()));
        fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);
        let cfg = crate::mihomo::ControllerConfig {
            config_dir: home.join("core").display().to_string(),
            addr: "127.0.0.1:1".into(),
            ..Default::default()
        };
        let source = "mixed-port: 7897\nproxies:\n  - {name: Node, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: fake}\nproxy-groups:\n  - {name: Airport, type: select, proxies: [Node]}\nrules:\n  - MATCH,Airport\n";
        let local = source.replace("Airport", "MyLocal");
        let dir = crate::compose::profile_dir(&cfg);
        crate::compose::write_private(&crate::compose::cache_path(&dir), source).unwrap();
        crate::mihomo::install_config(&cfg, &local, false).unwrap();
        for selected in [false, true, false, true] {
            crate::mihomo::regenerate_routing(
                &cfg,
                &[],
                false,
                false,
                true,
                Some(if selected { "local" } else { "subscription" }),
            )
            .unwrap();
            let text = read_config_text(&cfg).unwrap();
            assert!(text.contains(if selected { "MyLocal" } else { "Airport" }));
            assert!(!text.contains(if selected { "Airport" } else { "MyLocal" }));
            assert_eq!(
                fs::read_to_string(crate::compose::cache_path(&dir)).unwrap(),
                source
            );
            assert_eq!(
                fs::read_to_string(dir.join("routing-local.yaml")).unwrap(),
                local
            );
        }
        crate::mihomo::regenerate_config(&cfg, &[], false, false, true).unwrap();
        assert!(read_config_text(&cfg).unwrap().contains("MyLocal"));
        let previous = read_config_text(&cfg).unwrap();
        // A missing source must not silently replace airport routing with defaults.
        fs::remove_file(crate::compose::cache_path(&dir)).unwrap();
        assert!(crate::mihomo::regenerate_routing(
            &cfg,
            &[],
            false,
            false,
            true,
            Some("subscription")
        )
        .is_err());
        assert_eq!(read_config_text(&cfg).unwrap(), previous);
        assert!(crate::compose::local_routing(&dir));
        // A validly parsed document with a nonexistent target must fail core validation.
        crate::compose::write_private(
            &crate::compose::cache_path(&dir),
            &source.replace("MATCH,Airport", "MATCH,Missing"),
        )
        .unwrap();
        assert!(crate::mihomo::regenerate_routing(
            &cfg,
            &[],
            false,
            false,
            true,
            Some("subscription")
        )
        .is_err());
        assert_eq!(read_config_text(&cfg).unwrap(), previous);
        assert!(crate::compose::local_routing(&dir));
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    #[ignore = "requires Mihomo; run alone with temporary HOME, never starts a core or changes routing"]
    fn profile_switching_keeps_sources_separate() {
        let home = std::env::temp_dir().join(format!("terc-profile-switch-{}", std::process::id()));
        fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);
        let cfg = crate::mihomo::ControllerConfig {
            config_dir: home.join("core").display().to_string(),
            addr: "127.0.0.1:1".into(),
            subscription_url: "https://source.example.test/sub".into(),
            ..Default::default()
        };
        let source="mixed-port: 7897\nproxies:\n  - {name: AirportNode, type: ss, server: 192.0.2.1, port: 8388, cipher: aes-128-gcm, password: fake}\nproxy-groups:\n  - {name: Airport, type: select, proxies: [AirportNode]}\nrules:\n  - MATCH,Airport\n";
        let shared_route = crate::routing::save("共享分流", source).unwrap();
        crate::mihomo::install_config(&cfg, source, false).unwrap();
        let mut app = App::from_snapshot(
            crate::Config {
                controller: cfg,
                ..Default::default()
            },
            Default::default(),
        );
        app.save_profile_copy();
        let original = app.config.controller.profile_id.clone();
        assert!(!original.is_empty());
        app.apply_core_setting("allow-lan", true.into());
        finish(&mut app);
        assert!(app.snapshot.allow_lan);
        app.apply_core_setting("allow-lan", false.into());
        finish(&mut app);
        assert!(!app.snapshot.allow_lan);
        app.import_profile(
            "OwnNode = ss, 192.0.2.2, 8388, encrypt-method=aes-128-gcm, password=fake",
        );
        finish(&mut app);
        let manual = app.config.controller.profile_id.clone();
        assert_ne!(manual, original);
        assert!(app.config.controller.subscription_url.is_empty());
        let text = read_config_text(&app.config.controller).unwrap();
        assert!(text.contains("OwnNode"));
        assert!(!text.contains("AirportNode"));
        crate::mihomo::regenerate_routing(
            &app.config.controller,
            &[],
            false,
            false,
            true,
            Some(&shared_route),
        )
        .unwrap();
        let text = read_config_text(&app.config.controller).unwrap();
        assert!(text.contains("MATCH,Airport"));
        assert!(text.contains("OwnNode"));
        assert!(!text.contains("AirportNode"));
        // Editing the node source must keep its assigned policy and use new nodes.
        crate::compose::add_manual_node(
            &crate::compose::profile_dir(&app.config.controller),
            "NewNode = ss, 192.0.2.3, 8388, encrypt-method=aes-128-gcm, password=fake",
        )
        .unwrap();
        app.apply_composed();
        finish(&mut app);
        let text = read_config_text(&app.config.controller).unwrap();
        assert!(text.contains("NewNode"));
        assert!(text.contains("MATCH,Airport"));
        for id in [&original, &manual, &original, &manual] {
            app.profile_index = app.profiles.iter().position(|p| &p.name == id).unwrap();
            app.switch_selected_profile();
            finish(&mut app);
            app.apply_composed();
            finish(&mut app);
            let text = read_config_text(&app.config.controller).unwrap();
            if id == &original {
                assert!(text.contains("AirportNode"));
                assert!(!text.contains("OwnNode"));
                assert_eq!(
                    crate::routing::selected(&app.config.controller),
                    "subscription"
                );
                assert_eq!(
                    app.config.controller.subscription_url,
                    "https://source.example.test/sub"
                );
            } else {
                assert!(text.contains("OwnNode"));
                assert!(!text.contains("AirportNode"));
                assert!(text.contains("NewNode"));
                assert!(text.contains("MATCH,Airport"));
                assert_eq!(
                    crate::routing::selected(&app.config.controller),
                    shared_route
                );
                assert!(app.config.controller.subscription_url.is_empty());
            }
        }
        let dir = crate::compose::profile_dir(&app.config.controller);
        // A stale subscription cache cannot reintroduce nodes after switching to a manual source.
        crate::compose::write_private(&dir.join("subscription.yaml"), source).unwrap();
        app.apply_composed();
        finish(&mut app);
        assert!(!read_config_text(&app.config.controller)
            .unwrap()
            .contains("AirportNode"));
        let before = fs::read_to_string(dir.join("source.json")).unwrap();
        let previous_config = read_config_text(&app.config.controller).unwrap();
        let mut invalid = crate::compose::ProfileSource::load(&dir);
        invalid.nodes[0]["type"] = serde_json::json!("unsupported-protocol");
        app.save_source_record(invalid, Some(manual.clone()));
        let deadline = Instant::now();
        while app.action_busy && deadline.elapsed() < Duration::from_secs(15) {
            thread::sleep(Duration::from_millis(10));
            app.drain_events();
        }
        assert!(!app.action_busy);
        assert!(app.status_is_error);
        assert_eq!(fs::read_to_string(dir.join("source.json")).unwrap(), before);
        assert_eq!(
            read_config_text(&app.config.controller).unwrap(),
            previous_config
        );
        fs::remove_dir_all(home).unwrap();
    }
}
