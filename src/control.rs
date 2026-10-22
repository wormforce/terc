//! Dashboard actions that sit on top of the Mihomo controller.
//!
//! Runtime switches use PATCH so they land immediately. DNS and module
//! changes rewrite `config.yaml` and hot-reload, because those fields are
//! not partial-update keys. Nothing here touches the macOS system proxy.

use std::{fs, path::PathBuf};

use crate::{
    mihomo::{
        dns_query_async, flush_dns_async, is_info_pseudo_node, patch_config_value,
        persist_live_bool, persist_nested_bool, probe_async, provider_healthcheck_async,
        read_config_text, refresh_all_providers_async, refresh_provider_async,
        refreshable_provider, save_config_unchecked, set_bool_config, set_rule_disabled,
        test_group_delays_async, test_node_async, verify_runtime_value, HealthTexts, ProxyNode,
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
                // The core accepted the value, so saving it skips `mihomo -t`.
                set_bool_config(&cfg, &field, next)
                    .map_err(|err| format!("Runtime change rejected: {err}"))?;
                let live = verify_runtime_value(&cfg, &field, &next.into());
                persist_live_bool(&cfg, &refs, next)
                    .map_err(|err| format!("Runtime changed, but could not save: {err}"))?;
                // Mihomo ignores `sniffing` while the sniffer was off at load.
                // The file now differs from the core, so the next
                // regeneration reloads even when its output is unchanged.
                if let Err(err) = live {
                    crate::mihomo::RELOAD_UNCERTAIN
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    return Ok(format!(
                        "已保存，重载配置或重启内核后生效 / Saved; the core did not apply it live ({err}), so it takes effect after the next reload or core restart"
                    ));
                }
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
        let next = match apply_enabled_modules(&raw, &enabled_snippets(&self.catalog, &ids)) {
            Ok(text) => text,
            Err(err) => {
                self.set_status(&err, true);
                return;
            }
        };
        let running = self.snapshot.running;
        // After an unanswered reload the core may not run the file, so only a
        // reload makes them match.
        let uncertain =
            running && crate::mihomo::RELOAD_UNCERTAIN.load(std::sync::atomic::Ordering::SeqCst);
        let change = match module_change(&raw, &next) {
            ModuleChange::Live(_) if !running => ModuleChange::Reload,
            _ if uncertain => ModuleChange::Reload,
            change => change,
        };
        // Only a reload re-initialises providers, so only it asks first.
        if change == ModuleChange::Reload && !self.confirm_disruption(crate::guard::Disrupt::Reload)
        {
            return;
        }
        let done = self.t(if enabling {
            "st_module_on"
        } else {
            "st_module_off"
        });
        let (same, live, failed) = match self.lang() {
            crate::Lang::Zh => (
                "生效配置未变化，未重载",
                "已实时生效，未重载",
                "实时修改未生效，未重载；再次切换将确认后重载",
            ),
            crate::Lang::En => (
                "effective config unchanged; not reloaded",
                "applied live; no reload",
                "live change failed; nothing reloaded. Toggle again to reload",
            ),
            crate::Lang::Ja => (
                "有効な設定は変わらず、リロードなし",
                "ライブ適用、リロードなし",
                "ライブ適用に失敗、リロードなし。もう一度切り替えるとリロード",
            ),
        };
        self.run_action(
            "Applying module configuration…",
            Some(ids),
            None,
            move |cfg| match change {
                ModuleChange::Same => {
                    save_config_unchecked(&cfg, &next, running)?;
                    Ok(format!("{done} — {same}"))
                }
                ModuleChange::Live(keys) => {
                    for (key, value) in &keys {
                        if let Err(err) = patch_config_value(&cfg, key, value) {
                            // A reload would cut provider connections without
                            // the prompt a reload toggle shows. Keys may be
                            // half-applied, so the next toggle reloads, and
                            // asks first.
                            crate::mihomo::RELOAD_UNCERTAIN
                                .store(true, std::sync::atomic::Ordering::SeqCst);
                            return Err(format!("{failed} ({err})"));
                        }
                    }
                    save_config_unchecked(&cfg, &next, true)?;
                    Ok(format!("{done} — {live}"))
                }
                ModuleChange::Reload => {
                    crate::mihomo::install_config(&cfg, &next, running)?;
                    Ok(done.into())
                }
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
        test_node_async(
            self.config.controller.clone(),
            peer.name,
            self.snapshot.groups.clone(),
            self.tx.clone(),
        );
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
        self.group_tests += 1;
        test_group_delays_async(
            self.config.controller.clone(),
            "WireGuard".into(),
            names,
            self.snapshot.groups.clone(),
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

/// What a module toggle changes in the config the core runs.
#[derive(Debug, PartialEq)]
enum ModuleChange {
    /// Only the module bookkeeping in the header differs.
    Same,
    /// Only top-level keys `PATCH /configs` applies, with their new values.
    Live(Vec<(String, serde_json::Value)>),
    Reload,
}

/// Top-level keys a module may set that the core applies without a reload.
const LIVE_MODULE_KEYS: &[&str] = &[
    "allow-lan",
    "tcp-concurrent",
    "ipv6",
    "find-process-mode",
    "log-level",
];

/// The top-level chunks of `doc` without the `# terc-base` and
/// `# terc-switches` header that `apply_modules_with_switches` writes.
fn effective_chunks(doc: &str) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut parts = doc.splitn(3, '\n');
    let body = match (parts.next(), parts.next(), parts.next()) {
        (Some(head), Some(switches), Some(rest))
            if head.starts_with("# terc-base: ") && switches.starts_with("# terc-switches: ") =>
        {
            rest
        }
        _ => doc,
    };
    // A later duplicate key wins, as in Mihomo's YAML decoder.
    crate::ops::split_chunks(body)
        .into_iter()
        .filter_map(|chunk| {
            let mut lines = chunk.lines;
            while lines.last().is_some_and(|l| {
                let t = l.trim();
                t.is_empty() || t.starts_with('#')
            }) {
                lines.pop();
            }
            Some((chunk.key?, lines))
        })
        .collect()
}

/// Whether the effective configs differ in no top-level key but `key`. A
/// regenerated file also carries every module's current text, which a live
/// PATCH of one key does not bring to the core.
pub(crate) fn differs_only_in(old: &str, next: &str, key: &str) -> bool {
    let (mut old, mut next) = (effective_chunks(old), effective_chunks(next));
    old.remove(key);
    next.remove(key);
    old == next
}

/// Compare the effective configs.
fn module_change(old: &str, next: &str) -> ModuleChange {
    let (old, next) = (effective_chunks(old), effective_chunks(next));
    let mut keys: Vec<&String> = old.keys().chain(next.keys()).collect();
    keys.sort();
    keys.dedup();
    let mut live = Vec::new();
    for key in keys {
        let new_lines = next.get(key);
        if old.get(key) == new_lines {
            continue;
        }
        // A removed key falls back to a default the core cannot be told.
        let value = new_lines
            .filter(|lines| lines.len() == 1 && LIVE_MODULE_KEYS.contains(&key.as_str()))
            .and_then(|lines| lines[0].split_once(':'))
            .map(|(_, v)| crate::ops::clean_scalar(v))
            .and_then(|v| match key.as_str() {
                "allow-lan" | "tcp-concurrent" | "ipv6" => {
                    v.to_ascii_lowercase().parse::<bool>().ok().map(Into::into)
                }
                _ => (!v.is_empty()).then(|| v.into()),
            });
        match value {
            Some(value) => live.push((key.clone(), value)),
            None => return ModuleChange::Reload,
        }
    }
    if live.is_empty() {
        ModuleChange::Same
    } else {
        ModuleChange::Live(live)
    }
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

    /// Saves `record` (a new source, or `edit_id`), makes it active and
    /// reloads. Like every other reload it asks first when sessions would
    /// drop; the form or input stays open, so the same key confirms. `false`
    /// when nothing was started.
    pub fn save_source_record(
        &mut self,
        record: crate::compose::ProfileSource,
        edit_id: Option<String>,
    ) -> bool {
        if self.action_busy || !self.confirm_disruption(crate::guard::Disrupt::Reload) {
            return false;
        }
        if self.config.controller.profile_id.is_empty()
            && crate::mihomo::config_file_exists(&self.config.controller)
        {
            self.save_profile_copy();
            if self.config.controller.profile_id.is_empty() {
                return false;
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
        true
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

    #[test]
    #[ignore = "changes HOME; run alone with temporary data; never starts a core"]
    fn setup_on_a_fresh_install_creates_a_listed_source() {
        let settle = |app: &mut App| {
            let start = Instant::now();
            while app.action_busy && start.elapsed() < Duration::from_secs(15) {
                thread::sleep(Duration::from_millis(10));
                app.drain_events();
            }
        };
        let home = std::env::temp_dir().join(format!("terc-setup-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        std::env::set_var("HOME", &home);
        let cfg = crate::mihomo::ControllerConfig {
            config_dir: home.join("core").display().to_string(),
            addr: "127.0.0.1:1".into(),
            ..Default::default()
        };
        let snapshot = crate::mihomo::CoreSnapshot {
            core_bin_path: "/nonexistent/mihomo".into(),
            ..Default::default()
        };
        let mut app = App::from_snapshot(
            crate::Config {
                controller: cfg.clone(),
                ..Default::default()
            },
            snapshot.clone(),
        );
        app.setup_editor
            .load("SetupNode = ss, 192.0.2.2, 8388, encrypt-method=aes-128-gcm, password=fake");
        app.submit_setup();
        // Generating fails without a Mihomo on PATH, and with one the start
        // is refused under test; either way the source is written first.
        settle(&mut app);
        assert_eq!(app.config.controller.profile_id, "proxy-001");
        let dir = crate::storage::root().join("proxy-001");
        let source = crate::compose::ProfileSource::load(&dir);
        assert_eq!(source.name, "SetupNode");
        assert_eq!(source.kind, "proxy");
        assert_eq!(source.nodes.len(), 1);
        let terc = crate::compose::terc_dir();
        assert!(!terc.join("source.json").exists(), "not the pre-0.2 spot");
        let saved: crate::Config =
            serde_json::from_str(&fs::read_to_string(terc.join("config.json")).unwrap()).unwrap();
        assert_eq!(saved.controller.profile_id, "proxy-001");

        // A subscription link goes to its own new source the same way.
        let mut app = App::from_snapshot(
            crate::Config {
                controller: cfg,
                ..Default::default()
            },
            snapshot,
        );
        app.setup_editor
            .load("https://airport.example.test/sub?token=x");
        app.submit_setup();
        settle(&mut app);
        assert_eq!(app.config.controller.profile_id, "proxy-002");
        let source = crate::compose::ProfileSource::load(&crate::storage::root().join("proxy-002"));
        assert_eq!(
            source.subscription_url,
            "https://airport.example.test/sub?token=x"
        );
        assert_eq!(source.name, "airport.example.test");
        assert_eq!(source.kind, "subscription");
        assert!(!terc.join("source.json").exists());
        fs::remove_dir_all(home).unwrap();
    }
}

#[cfg(test)]
mod module_tests {
    use super::*;
    use crate::ops::builtin_modules;

    const BASE: &str = "mixed-port: 7890\nmode: rule\nipv6: false\ntcp-concurrent: true\nfind-process-mode: strict\nproxies: []\nrules:\n  - MATCH,DIRECT\n";

    fn with(base: &str, ids: &[&str]) -> String {
        let ids: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
        apply_enabled_modules(base, &enabled_snippets(&builtin_modules(), &ids)).unwrap()
    }

    #[test]
    fn failed_live_module_toggle_does_not_reload_unasked() {
        use std::io::{BufRead, BufReader, Read, Write};
        let dir = std::env::temp_dir().join(format!("terc-live-toggle-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let cfg = crate::mihomo::ControllerConfig {
            addr: listener.local_addr().unwrap().to_string(),
            config_dir: dir.display().to_string(),
            ..Default::default()
        };
        let path = dir.join("config.yaml");
        fs::write(&path, BASE).unwrap();
        // Answer the PATCH with 400; a reload would be a second request.
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let (mut head, mut length) = (String::new(), 0);
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if let Some(v) = line.strip_prefix("Content-Length: ") {
                    length = v.trim().parse().unwrap();
                }
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                head.push_str(&line);
            }
            reader.read_exact(&mut vec![0; length]).unwrap();
            let body = "bad value";
            write!(
                reader.get_mut(),
                "HTTP/1.1 400 Bad Request\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
            head
        });
        let mut app = App::from_snapshot(
            crate::Config {
                controller: cfg,
                ..Default::default()
            },
            crate::mihomo::CoreSnapshot {
                running: true,
                ..Default::default()
            },
        );
        app.catalog = builtin_modules();
        app.module_index = app.catalog.iter().position(|m| m.id == "ipv6").unwrap();
        app.toggle_selected_module();
        let start = std::time::Instant::now();
        while app.action_busy && start.elapsed() < std::time::Duration::from_secs(10) {
            std::thread::sleep(std::time::Duration::from_millis(10));
            app.drain_events();
        }
        assert!(server.join().unwrap().starts_with("PATCH /configs "));
        assert!(app.status_is_error);
        assert!(
            app.status_message.contains("bad value"),
            "{}",
            app.status_message
        );
        assert!(app.config.enabled_modules.is_empty());
        assert_eq!(fs::read_to_string(&path).unwrap(), BASE);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn module_toggles_reload_only_when_the_core_cannot_take_the_change_live() {
        // The template already races TCP handshakes: nothing to apply.
        let tcp = with(BASE, &["tcp-concurrent"]);
        assert_eq!(module_change(BASE, &tcp), ModuleChange::Same);
        assert_eq!(module_change(&tcp, BASE), ModuleChange::Same);
        assert_eq!(
            module_change(&tcp, &with(BASE, &["tcp-concurrent", "ipv6"])),
            ModuleChange::Live(vec![("ipv6".into(), true.into())])
        );
        assert_eq!(
            module_change(BASE, &with(BASE, &["find-process", "ipv6"])),
            ModuleChange::Live(vec![
                ("find-process-mode".into(), "always".into()),
                ("ipv6".into(), true.into()),
            ])
        );
        // Turning the module off restores the base value, also live.
        assert_eq!(
            module_change(&with(BASE, &["find-process"]), BASE),
            ModuleChange::Live(vec![("find-process-mode".into(), "strict".into())])
        );
        // Blocks and keys outside the PATCH set need a reload.
        for id in ["sniffer", "dns-fakeip", "tun"] {
            assert_eq!(
                module_change(BASE, &with(BASE, &[id])),
                ModuleChange::Reload,
                "{id}"
            );
        }
        assert_eq!(
            module_change(BASE, &with(BASE, &["find-process", "sniffer"])),
            ModuleChange::Reload
        );
        // A key the base lacks has no value to PATCH back once removed.
        let bare = "mode: rule\nproxies: []\n";
        let on = with(bare, &["find-process"]);
        assert!(matches!(module_change(bare, &on), ModuleChange::Live(_)));
        assert_eq!(module_change(&on, bare), ModuleChange::Reload);
        // A live setting may save only what differs in its own key.
        let dns = with(BASE, &["dns-fakeip"]);
        let lan = crate::ops::set_top_scalar(&dns, "allow-lan", "true");
        assert!(differs_only_in(&dns, &lan, "allow-lan"));
        assert!(!differs_only_in(&dns, &lan, "log-level"));
        let edited = lan.replace("127.0.0.1:1053", "0.0.0.0:1053");
        assert_ne!(edited, lan);
        assert!(!differs_only_in(&dns, &edited, "allow-lan"));
        assert!(differs_only_in(BASE, &dns, "dns"));
        assert!(differs_only_in(BASE, &with(BASE, &["tcp-concurrent"]), "x"));
        // Trailing comments and blank lines do not count as a change.
        assert_eq!(
            module_change(
                "ipv6: false\n\n# note\nmode: rule\n",
                "ipv6: false\nmode: rule\n"
            ),
            ModuleChange::Same
        );
    }
}
