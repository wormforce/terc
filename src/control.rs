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
        refresh_all_providers_async, refresh_provider_async, set_bool_config, set_rule_disabled,
        set_tun_enabled, test_group_delays_async, test_node_async, ProxyNode,
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
        self.runtime_switch(&["tun", "enable"], "tun", !self.snapshot.tun_enabled);
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
            if running {
                if field == "tun" {
                    set_tun_enabled(&cfg, next)
                } else {
                    set_bool_config(&cfg, &field, next)
                }
                .map_err(|err| format!("Runtime change rejected: {err}"))?;
            }
            let refs: Vec<&str> = path.iter().map(String::as_str).collect();
            persist_nested_bool(&cfg, &refs, next).map_err(|err| {
                if running {
                    format!("Runtime changed, but could not save: {err}")
                } else {
                    err
                }
            })?;
            Ok(if running {
                "Runtime changed and saved"
            } else {
                "Saved; core stopped"
            }
            .into())
        });
    }

    pub fn toggle_dns(&mut self) {
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
        self.run_action("Running provider health check…", None, None, move |cfg| {
            provider_healthcheck(&cfg, &provider.name)?;
            Ok(format!("Health check requested: {}", provider.name))
        });
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
        let modules = enabled_snippets(
            &module_catalog(&modules_dir(&home_dir())),
            &self.config.enabled_modules,
        );
        let running = self.snapshot.running;
        self.run_action(
            "Applying configuration profile…",
            None,
            Some(profile.name),
            move |cfg| {
                let base = crate::ops::strip_marked_modules(&raw);
                let normalized = normalize_subscription(&base, &cfg.addr);
                let generated = apply_enabled_modules(&normalized, &modules)?;
                crate::mihomo::install_config(&cfg, &generated, running)?;
                Ok("Profile applied".into())
            },
        );
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
        self.save_preferences();
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
