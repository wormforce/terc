//! Dashboard actions that sit on top of the Mihomo controller.
//!
//! Runtime switches use PATCH so they land immediately. DNS and module
//! changes rewrite `config.yaml` and hot-reload, because those fields are
//! not partial-update keys. Nothing here touches the macOS system proxy.

use std::{fs, path::PathBuf};

use crate::{
    mihomo::{
        dns_query_async, flush_dns_async, is_info_pseudo_node, normalize_subscription,
        persist_nested_bool, probe_async, provider_healthcheck, read_config_text,
        refresh_all_providers_async, refresh_provider_async, reload_config_async, set_bool_config,
        set_rule_disabled, set_tun_enabled, test_group_delays_async, test_node_async,
        write_config_text, ProxyNode,
    },
    ops::{
        apply_enabled_modules, enabled_snippets, explain_rules, is_runtime_tunnel, list_profiles,
        module_catalog, modules_dir, next_profile_filename, parse_dns_block, profiles_dir,
        ModuleSnippet, ProfileEntry,
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
        if self.apply_runtime_switch(
            self.snapshot.running.then(|| {
                set_tun_enabled(&self.config.controller, next).map_err(|err| err.to_string())
            }),
            &["tun", "enable"],
            next,
            if next { "st_tun_on" } else { "st_tun_off" },
        ) {
            self.snapshot.tun_enabled = next;
        }
    }

    pub fn toggle_sniffing(&mut self) {
        let next = !self.snapshot.sniffing;
        if self.apply_runtime_switch(
            self.snapshot.running.then(|| {
                set_bool_config(&self.config.controller, "sniffing", next)
                    .map_err(|err| err.to_string())
            }),
            &["sniffer", "enable"],
            next,
            if next { "st_sniff_on" } else { "st_sniff_off" },
        ) {
            self.snapshot.sniffing = next;
        }
    }

    pub fn toggle_ipv6(&mut self) {
        let next = !self.snapshot.ipv6;
        if self.apply_runtime_switch(
            self.snapshot.running.then(|| {
                set_bool_config(&self.config.controller, "ipv6", next)
                    .map_err(|err| err.to_string())
            }),
            &["ipv6"],
            next,
            if next { "st_ipv6_on" } else { "st_ipv6_off" },
        ) {
            self.snapshot.ipv6 = next;
        }
    }

    pub fn toggle_dns(&mut self) {
        let raw = match read_config_text(&self.config.controller) {
            Ok(text) => text,
            Err(err) => {
                self.set_status(&err, true);
                return;
            }
        };
        let dns = parse_dns_block(&raw);
        if !dns.present {
            self.set_status(self.t("st_dns_missing"), true);
            return;
        }
        let next = !dns.enable;
        let updated = crate::ops::set_nested_bool(&raw, &["dns", "enable"], next);
        if let Err(err) = write_config_text(&self.config.controller, &updated) {
            self.set_status(&err, true);
            return;
        }
        self.snapshot.dns.enable = next;
        self.snapshot.dns.present = true;
        self.reload_or_save(if next { "st_dns_on" } else { "st_dns_off" });
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
        match set_rule_disabled(&self.config.controller, rule.index, disabled) {
            Ok(()) => {
                if let Some(slot) = self
                    .snapshot
                    .rules
                    .iter_mut()
                    .find(|item| item.index == rule.index)
                {
                    slot.disabled = disabled;
                }
                self.set_status(
                    self.t(if disabled {
                        "st_rule_off"
                    } else {
                        "st_rule_on"
                    }),
                    false,
                );
                self.refresh_snapshot_now();
                self.clamp_aux();
            }
            Err(err) => self.set_status(&format!("{} · {err}", self.t("st_rule_fail")), true),
        }
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
        match provider_healthcheck(&self.config.controller, &provider.name) {
            Ok(()) => self.set_status(
                &format!("{} {}", self.t("st_provider_health"), provider.name),
                false,
            ),
            Err(err) => self.set_status(&err, true),
        }
    }

    pub fn refresh_all_providers(&mut self) {
        if self.snapshot.providers.is_empty() {
            self.set_status(self.t("st_no_provider"), true);
            return;
        }
        self.set_status(self.t("st_provider_all"), false);
        refresh_all_providers_async(self.config.controller.clone(), self.tx.clone());
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
        let next = apply_enabled_modules(&raw, &snippets);
        if let Err(err) = write_config_text(&self.config.controller, &next) {
            self.set_status(&err, true);
            return;
        }
        self.config.enabled_modules = ids;
        self.config.save();
        self.reload_or_save(if enabling {
            "st_module_on"
        } else {
            "st_module_off"
        });
    }

    pub fn open_profiles(&mut self) {
        self.profiles = self.profile_list();
        self.profile_index = clamp_to(self.profile_index, self.profiles.len());
        self.overlay = Overlay::Profiles;
    }

    pub fn switch_selected_profile(&mut self) {
        let Some(profile) = self.profiles.get(self.profile_index).cloned() else {
            return;
        };
        let raw = match fs::read_to_string(&profile.path) {
            Ok(text) => text,
            Err(err) => {
                self.set_status(&err.to_string(), true);
                return;
            }
        };
        let normalized = normalize_subscription(&raw, &self.config.controller.addr);
        if let Err(err) = write_config_text(&self.config.controller, &normalized) {
            self.set_status(&err, true);
            return;
        }
        self.config.active_profile = profile.name.clone();
        self.config.save();
        self.profiles = self.profile_list();
        self.reload_or_save("st_profile");
    }

    pub fn save_profile_copy(&mut self) {
        let raw = match read_config_text(&self.config.controller) {
            Ok(text) => text,
            Err(err) => {
                self.set_status(&err, true);
                return;
            }
        };
        let dir = profiles_dir(&home_dir());
        if let Err(err) = fs::create_dir_all(&dir) {
            self.set_status(&err.to_string(), true);
            return;
        }
        let name = next_profile_filename(&dir);
        let path = dir.join(&name);
        if let Err(err) = fs::write(&path, raw) {
            self.set_status(&err.to_string(), true);
            return;
        }
        self.config.active_profile = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or("profile")
            .to_string();
        self.config.save();
        self.profiles = self.profile_list();
        self.profile_index = self
            .profiles
            .iter()
            .position(|item| item.active)
            .unwrap_or(0);
        self.set_status(&format!("{} {}", self.t("st_profile_saved"), name), false);
    }

    pub fn reload_profile(&mut self) {
        if !self.snapshot.running {
            self.set_status(self.t("st_core_down"), true);
            return;
        }
        self.set_status(self.t("st_reloading"), false);
        reload_config_async(self.config.controller.clone(), self.tx.clone());
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

    fn apply_runtime_switch(
        &mut self,
        api: Option<Result<(), String>>,
        yaml_path: &[&str],
        next: bool,
        ok_key: &'static str,
    ) -> bool {
        let file_ok = persist_nested_bool(&self.config.controller, yaml_path, next).is_ok();
        match api {
            Some(Ok(())) => {
                self.set_status(self.t(ok_key), false);
                true
            }
            Some(Err(err)) => {
                if file_ok {
                    self.set_status(self.t("st_saved_core_down"), false);
                } else {
                    self.set_status(&err, true);
                }
                file_ok
            }
            None => {
                if file_ok {
                    self.set_status(self.t("st_saved_core_down"), false);
                } else {
                    self.set_status(self.t("st_core_down"), true);
                }
                file_ok
            }
        }
    }

    fn reload_or_save(&mut self, ok_key: &'static str) {
        if self.snapshot.running {
            self.set_status(self.t("st_reloading"), false);
            reload_config_async(self.config.controller.clone(), self.tx.clone());
        } else {
            self.set_status(
                &format!("{} · {}", self.t(ok_key), self.t("st_saved_core_down")),
                false,
            );
        }
    }

    fn profile_list(&self) -> Vec<ProfileEntry> {
        let config_dir = PathBuf::from(&self.config.controller.config_dir);
        list_profiles(
            &config_dir,
            &profiles_dir(&home_dir()),
            &self.config.active_profile,
        )
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
