//! Common connection controls and advanced tools live in the settings board.
use crate::{App, Lang, Screen, SettingCategory as C, SettingRow, WaveRenderer};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingId {
    Core,
    SystemProxy,
    Mode,
    Download,
    Theme,
    Renderer,
    Refresh,
    GraphInterval,
    Language,
    Profiles,
    Routing,
    DnsTools,
    MixedPort,
    HttpPort,
    SocksPort,
    Lan,
    Tun,
    Dns,
    Ipv6,
    Sniff,
    Tcp,
    Process,
    LogLevel,
    TestUrl,
    Timeout,
    Traffic,
    Toolbar,
    ConnStream,
    Modules,
    Probe,
    Runtime,
    Rules,
    Providers,
    Logs,
}
impl App {
    pub fn settings_rows(&self) -> Vec<SettingRow> {
        use SettingId::*;
        let mut rows = Vec::new();
        let mut add =
            |id, category, zh: &str, en: &str, value: String, desc_zh: &str, desc_en: &str| {
                let zh_lang = self.lang() == Lang::Zh;
                rows.push(SettingRow {
                    id,
                    category,
                    label: if zh_lang { zh } else { en }.into(),
                    value,
                    description: if zh_lang { desc_zh } else { desc_en }.into(),
                });
            };
        let on = |v| if v { "ON" } else { "OFF" }.to_string();
        let action = "Enter →".to_string();
        add(
            Core,
            C::Core,
            "内核服务",
            "Core service",
            on(self.snapshot.running),
            "启动或停止当前内核。启动失败时请查看设置 → 排查 → 日志。",
            "Start or stop the core. Startup errors appear under Diagnostics → Logs.",
        );
        add(
            SystemProxy,
            C::Core,
            "系统代理",
            "System proxy",
            on(self.snapshot.sysproxy_enabled),
            self.t("desc_sysproxy"),
            self.t("desc_sysproxy"),
        );
        add(
            Mode,
            C::Core,
            "分流模式",
            "Routing mode",
            self.snapshot.mode.clone(),
            self.t("desc_mode"),
            self.t("desc_mode"),
        );
        add(
            Download,
            C::Diagnostics,
            "下载 / 更新内核",
            "Download / update core",
            action.clone(),
            "从 Mihomo 官方发行版下载适配当前系统的内核。",
            "Download the official Mihomo binary for this platform.",
        );
        add(
            Theme,
            C::Appearance,
            "配色主题",
            "Palette",
            format!("{:?}", self.config.settings.theme),
            self.t("desc_theme"),
            self.t("desc_theme"),
        );
        add(
            Renderer,
            C::Appearance,
            "速率图样式",
            "Graph style",
            format!("{:?}", self.config.settings.renderer),
            self.t("desc_renderer"),
            self.t("desc_renderer"),
        );
        add(
            Refresh,
            C::Appearance,
            "界面刷新率",
            "UI refresh rate",
            format!("{} Hz", self.config.settings.refresh_hz),
            self.t("desc_refresh"),
            self.t("desc_refresh"),
        );
        add(
            GraphInterval,
            C::Appearance,
            "图表更新间隔",
            "Graph interval",
            format!("{} ms", self.config.settings.graph_interval_ms()),
            self.t("desc_graph_interval"),
            self.t("desc_graph_interval"),
        );
        add(
            Language,
            C::Appearance,
            "语言",
            "Language",
            match self.lang() {
                Lang::Zh => "中文",
                Lang::En => "English",
                Lang::Ja => "日本語",
            }
            .into(),
            self.t("desc_lang"),
            self.t("desc_lang"),
        );
        add(Profiles, C::Subscription, "代理订阅", "Proxy subscriptions", self.profile_display_name(), "管理机场订阅、自建和手动节点。选择来源后，可在分流方案中指定它使用的分流。", "Manage subscriptions and manual nodes. Assign an independent routing plan to each source.");
        add(Routing, C::Subscription, "分流方案", "Routing plans", self.routing_plans.iter().find(|p| p.id == self.routing_mode).map(|p| p.label.clone()).unwrap_or_else(|| "跟随订阅 / Follow source".into()), "选择当前代理订阅使用的分流方案。保存的方案可以被多个订阅复用，节点始终来自当前订阅。", "Choose routing for the active subscription. Saved plans can be shared; nodes always come from the active source.");
        add(
            DnsTools,
            C::Diagnostics,
            "DNS 查询",
            "DNS lookup",
            action.clone(),
            "查询解析结果与清理缓存。",
            "Inspect DNS results and clear the cache.",
        );
        let port_desc="Enter 输入端口（0–65535），0 表示关闭此监听。混合端口同时支持 HTTP 和 SOCKS。保存后校验并重载。系统代理开启时请先关闭，再调整端口。";
        let port_en="Enter a port (0–65535); 0 disables this listener. Mixed supports HTTP and SOCKS. Validate and reload on save. Turn off system proxy before changing ports.";
        add(
            MixedPort,
            C::Core,
            "混合代理端口",
            "Mixed proxy port",
            self.core_setting("mixed-port", "0"),
            port_desc,
            port_en,
        );
        add(
            HttpPort,
            C::Core,
            "HTTP 代理端口",
            "HTTP proxy port",
            self.core_setting("port", "0"),
            port_desc,
            port_en,
        );
        add(
            SocksPort,
            C::Core,
            "SOCKS 代理端口",
            "SOCKS proxy port",
            self.core_setting("socks-port", "0"),
            port_desc,
            port_en,
        );
        add(
            Lan,
            C::Core,
            "允许局域网连接",
            "Allow LAN",
            on(self.snapshot.allow_lan),
            "允许局域网设备使用本机代理端口。",
            "Allow LAN devices to connect to the local proxy listeners.",
        );
        add(
            Tun,
            C::Core,
            "TUN 虚拟网卡",
            "TUN",
            on(self.snapshot.tun_enabled),
            "接管系统流量；macOS 可能弹出管理员授权。",
            "Route system traffic through TUN. macOS may request administrator authorization.",
        );
        add(
            Dns,
            C::Core,
            "内置 DNS",
            "Built-in DNS",
            on(self.snapshot.dns.enable),
            "开启或关闭配置中的 DNS 服务。",
            "Enable or disable the configured DNS service.",
        );
        add(
            Ipv6,
            C::Core,
            "IPv6",
            "IPv6",
            on(self.snapshot.ipv6),
            self.t("help_ipv6"),
            self.t("help_ipv6"),
        );
        add(
            Sniff,
            C::Core,
            "域名嗅探",
            "Domain sniffing",
            on(self.snapshot.sniffing),
            self.t("help_sniff"),
            self.t("help_sniff"),
        );
        add(
            Tcp,
            C::Core,
            "TCP 并发连接",
            "Concurrent TCP",
            on(self.snapshot.tcp_concurrent),
            "并发尝试目标 IP，加快建立连接。",
            "Try destination IPs concurrently to establish connections faster.",
        );
        add(
            Process,
            C::Core,
            "进程识别",
            "Process matching",
            self.core_setting("find-process-mode", "strict"),
            "strict 只在规则走到进程规则时识别；always 每个新连接都识别；off 关闭。识别在拨号前同步进行，Linux 上每次约 1–15 ms。",
            "strict: only when matching reaches a process rule; always: every new connection; off: never. The lookup runs before dialling, about 1–15 ms each on Linux.",
        );
        add(
            LogLevel,
            C::Diagnostics,
            "内核日志级别",
            "Core log level",
            self.core_setting("log-level", "info"),
            "内核自己写出的日志（terc 启动时为 terc-core.log）。新生成的配置默认 warning；日志页始终按 info 订阅，不受影响。排查时可临时切换 debug。",
            "What the core writes itself (terc-core.log when terc starts it). New configs use warning; the Logs view always subscribes at info. Switch to debug while investigating.",
        );
        add(
            TestUrl,
            C::Core,
            "节点测速地址",
            "Latency test URL",
            self.config.controller.test_url.clone(),
            "Enter 编辑 HTTP / HTTPS 测速地址，用于手动节点测速与优选。默认 https://www.gstatic.com/generate_204；走 Cloudflare 边缘的路径（如 OpenAI）可用 https://cp.cloudflare.com/generate_204。URLTest / Fallback 组按组内 url 测速。",
            "Enter an HTTP / HTTPS URL for manual latency tests and best-node selection. Default https://www.gstatic.com/generate_204; https://cp.cloudflare.com/generate_204 tests the Cloudflare edge, as OpenAI-like paths use. URLTest / Fallback groups test with their own url.",
        );
        add(
            Timeout,
            C::Core,
            "测速 / 查询超时",
            "Test / query timeout",
            format!("{} ms", self.config.controller.timeout_ms),
            "Enter 输入 500–32767 毫秒（Mihomo 测速接口的上限）。URLTest / Fallback 组按组自己的 timeout（默认 5000）测速；测速地址与某个这类组相同时，也按该组的超时与期望状态码，免得把组仍在用的节点记成失效。",
            "Enter a timeout from 500 to 32767 milliseconds, the limit of Mihomo's delay route. URLTest / Fallback groups test with their own timeout (5000 by default); when the test URL is one such a group checks, tests use that group's timeout and expected status, so they never mark dead a node the group still uses.",
        );
        add(
            Traffic,
            C::Appearance,
            "实时速率面板",
            "Traffic panels",
            on(self.config.settings.show_traffic),
            "显示或隐藏主界面上方的速率与状态面板。",
            "Show or hide traffic and overview panels.",
        );
        add(
            Toolbar,
            C::Appearance,
            "底栏快捷键",
            "Shortcut footer",
            on(self.config.settings.show_toolbar),
            "显示一行常用快捷键。",
            "Show the single-line shortcut footer.",
        );
        let stream = if !self.config.settings.connections_stream {
            "OFF"
        } else if self.stream_live() {
            "ON · WebSocket"
        } else {
            "ON · HTTP"
        };
        add(
            ConnStream,
            C::Diagnostics,
            "连接实时推送",
            "Live connection stream",
            stream.into(),
            self.t("desc_conn_stream"),
            self.t("desc_conn_stream"),
        );
        for (id, zh, en) in [
            (Modules, "配置片段", "Config snippets"),
            (Probe, "连接探测", "Connection probe"),
            (Runtime, "运行详情", "Runtime details"),
            (Rules, "规则浏览", "Rule browser"),
            (Providers, "远程资源", "Providers"),
            (Logs, "日志", "Logs"),
        ] {
            add(id,C::Diagnostics,zh,en,action.clone(),"Enter 打开。自有规则编辑已暂停；规则浏览以当前内核实际生效的顺序为准。","Enter to open. Custom rule editing is paused; rule browsing follows the core's effective order.");
        }
        if let Some(input) = &self.setting_input {
            if let Some(row) = rows.get_mut(self.setting_index) {
                row.value = format!("{input}▏");
            }
        }
        rows
    }

    fn core_setting(&self, key: &str, default: &str) -> String {
        self.snapshot
            .config_values
            .get(key)
            .cloned()
            .unwrap_or_else(|| default.into())
    }

    pub fn adjust_setting(&mut self, dir: i32) {
        use SettingId::*;
        let id = self.settings_rows()[self.setting_index].id;
        match id {
            Core => self.toggle_core_service(),
            SystemProxy => self.toggle_sysproxy(),
            Mode => self.cycle_routing_mode(),
            Download => self.download_core(),
            Theme => {
                let i = crate::THEMES
                    .iter()
                    .position(|x| *x == self.config.settings.theme)
                    .unwrap_or(0);
                self.config.settings.theme = crate::THEMES[(i as i32 + dir).rem_euclid(3) as usize];
                self.save_preferences();
            }
            Renderer => {
                self.config.settings.renderer =
                    if self.config.settings.renderer == WaveRenderer::Braille {
                        WaveRenderer::Blocks
                    } else {
                        WaveRenderer::Braille
                    };
                self.save_preferences();
            }
            Refresh => {
                let i = crate::REFRESH_RATES
                    .iter()
                    .position(|x| *x == self.config.settings.refresh_hz)
                    .unwrap_or(2);
                self.config.settings.refresh_hz =
                    crate::REFRESH_RATES[(i as i32 + dir).rem_euclid(4) as usize];
                self.save_preferences();
            }
            GraphInterval => {
                self.set_graph_interval(
                    (self.config.settings.graph_interval_ms() as i64 + dir as i64 * 100)
                        .clamp(1000, 86_400_000) as u64,
                );
                self.save_preferences();
            }
            Language => {
                let langs = [Lang::Zh, Lang::En, Lang::Ja];
                let i = langs.iter().position(|x| *x == self.lang()).unwrap_or(0);
                self.config.settings.lang = langs[(i as i32 + dir).rem_euclid(3) as usize];
                self.save_preferences();
            }
            Profiles => {
                self.profile_page = 0;
                self.open_profiles();
            }
            Routing => {
                self.profile_page = 3;
                self.open_profiles();
            }
            DnsTools => {
                self.screen = Screen::Dashboard;
                self.main_tab = crate::MainTab::Dns;
            }
            MixedPort | HttpPort | SocksPort | TestUrl | Timeout => {
                self.setting_input = Some(String::new());
            }
            Tun => self.toggle_tun(),
            Dns => self.toggle_dns(),
            Ipv6 => self.toggle_ipv6(),
            Sniff => self.toggle_sniffing(),
            Lan => self.apply_core_setting("allow-lan", (!self.snapshot.allow_lan).into()),
            Tcp => {
                self.apply_core_setting("tcp-concurrent", (!self.snapshot.tcp_concurrent).into())
            }
            Process | LogLevel => {
                let (key, values): (&str, &[&str]) = if id == Process {
                    ("find-process-mode", &["strict", "always", "off"])
                } else {
                    (
                        "log-level",
                        &["info", "warning", "error", "debug", "silent"],
                    )
                };
                let current = self.core_setting(key, values[0]);
                let i = values.iter().position(|s| *s == current).unwrap_or(0);
                self.apply_core_setting(
                    key,
                    values[(i as i32 + dir).rem_euclid(values.len() as i32) as usize].into(),
                );
            }
            Traffic => {
                self.config.settings.show_traffic = !self.config.settings.show_traffic;
                self.save_preferences();
            }
            Toolbar => {
                self.config.settings.show_toolbar = !self.config.settings.show_toolbar;
                self.save_preferences();
            }
            ConnStream => {
                let on = !self.config.settings.connections_stream;
                self.config.settings.connections_stream = on;
                self.conn_stream
                    .enabled
                    .store(on, std::sync::atomic::Ordering::Relaxed);
                if !on {
                    self.conn_stream_at = None;
                }
                self.save_preferences();
            }
            Modules => self.open_modules(),
            Probe => self.open_probe(),
            Runtime => self.open_runtime(),
            Rules => {
                self.screen = Screen::Dashboard;
                self.main_tab = crate::MainTab::Rules;
            }
            Providers => {
                self.screen = Screen::Dashboard;
                self.main_tab = crate::MainTab::Providers;
            }
            Logs => {
                self.load_core_log();
                self.screen = Screen::Dashboard;
                self.main_tab = crate::MainTab::Logs;
            }
        }
    }

    pub fn apply_core_setting(&mut self, key: &str, value: serde_json::Value) {
        if matches!(key, "port" | "socks-port" | "mixed-port") && self.snapshot.sysproxy_enabled {
            self.set_status(
                "请先关闭系统代理再修改端口 / Turn off system proxy before changing ports",
                true,
            );
            return;
        }
        let key = key.to_string();
        let running = self.snapshot.running;
        let modules = crate::ops::enabled_snippets(
            &crate::ops::module_catalog(&crate::ops::modules_dir(&std::path::PathBuf::from(
                std::env::var_os("HOME").unwrap_or_default(),
            ))),
            &self.config.enabled_modules,
        );
        self.run_action(
            "正在保存并校验设置 / Saving and validating settings…",
            None,
            None,
            move |cfg| {
                let raw = crate::mihomo::read_config_text(&cfg)?;
                let base = crate::ops::strip_marked_modules(&raw);
                if matches!(key.as_str(), "port" | "socks-port" | "mixed-port") {
                    // The shown state may be a cached lookup up to 15 s old.
                    if crate::mihomo::detect_sysproxy().1 {
                        return Err(
                            "请先关闭系统代理再修改端口 / Turn off system proxy before changing ports"
                                .into(),
                        );
                    }
                    let old = crate::ops::split_chunks(&base)
                        .into_iter()
                        .find(|c| c.key.as_deref() == Some(&key))
                        .and_then(|c| {
                            c.lines
                                .first()
                                .and_then(|l| l.split_once(':'))
                                .map(|(_, v)| crate::ops::clean_scalar(v))
                        })
                        .unwrap_or_else(|| "0".into());
                    // Compare as text, as the file holds it: a String never
                    // equals a JSON number such as a port.
                    let new = value.to_string();
                    if old == new {
                        return Ok("端口未改变 / Port unchanged".into());
                    }
                    if let Some(port) = value.as_u64().filter(|p| *p > 0) {
                        if let Err(e) = std::net::TcpListener::bind(("127.0.0.1", port as u16)) {
                            if e.kind() != std::io::ErrorKind::PermissionDenied {
                                return Err(format!(
                                    "端口 {port} 无法使用 / Port occupied or unavailable: {e}"
                                ));
                            }
                        }
                    }
                }
                // The user's value replaces one terc filled in.
                let base = crate::compose::drop_default_mark(
                    &crate::ops::set_top_scalar(&base, &key, &value.to_string()),
                    &key,
                );
                let generated = crate::ops::apply_modules_with_switches(
                    &base,
                    &modules,
                    &crate::ops::saved_switches(&raw),
                )?;
                if !running
                    || !live_patchable(&raw, &generated, &key, &value)
                    || crate::mihomo::reload_uncertain(&cfg)
                {
                    crate::mihomo::install_config(&cfg, &generated, running)?;
                    return Ok("设置已保存 / Settings saved".into());
                }
                // A reload would drop proxy-provider connections; PATCH only
                // rebuilds the listener or switch that changed. The core checks
                // the value and it is read back, so the file that differs from
                // the active one only by this key is saved without `mihomo -t`.
                crate::mihomo::validate_listener_ports(&generated)?;
                match crate::mihomo::patch_config_value(&cfg, &key, &value) {
                    Ok(()) => {
                        crate::mihomo::save_config_unchecked(&cfg, &generated, true).map_err(
                            |err| format!("设置已实时生效，但保存失败 / Applied live, but could not save: {err}"),
                        )?;
                        Ok("设置已实时生效，未重载 / Applied live; no reload".into())
                    }
                    // The reload validates through the core and saves the file.
                    Err(err) => match crate::mihomo::install_config(&cfg, &generated, true) {
                        Ok(()) => Ok(format!(
                            "实时修改未生效，已重载配置 / Live change failed ({err}); configuration reloaded"
                        )),
                        Err(e) => {
                            // The PATCH may have half-applied; the next
                            // regeneration must reload even when its output is
                            // unchanged.
                            crate::mihomo::set_reload_uncertain(&cfg, true);
                            Err(format!(
                                "实时修改失败，重载也失败 / Live change failed ({err}); reload failed: {e}"
                            ))
                        }
                    },
                }
            },
        );
    }
}

/// Whether `PATCH /configs` alone brings the core in line with `generated`,
/// the active file `raw` regenerated with `key` set to `value`.
fn live_patchable(raw: &str, generated: &str, key: &str, value: &serde_json::Value) -> bool {
    // `PATCH /configs` applies these without suspending the tunnel or
    // re-initialising providers.
    const LIVE: &[&str] = &[
        "allow-lan",
        "port",
        "socks-port",
        "mixed-port",
        "tcp-concurrent",
        "find-process-mode",
        "log-level",
    ];
    // A module may override the key; then only a reload makes the core match
    // the file.
    let effective = crate::ops::split_chunks(generated)
        .into_iter()
        .rev()
        .find(|c| c.key.as_deref() == Some(key))
        .and_then(|c| {
            c.lines
                .first()
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| crate::ops::clean_scalar(v))
        });
    let wanted = value
        .as_str()
        .map_or_else(|| value.to_string(), str::to_string);
    // The regenerated file also carries each module's current text; when that
    // differs from the active file (an edited or upgraded module), only a
    // reload, which the core validates, brings it live.
    LIVE.contains(&key)
        && effective.as_deref() == Some(wanted.as_str())
        && crate::control::differs_only_in(raw, generated, key)
}

pub fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    use SettingId::*;
    let rows = app.settings_rows();
    let id = rows[app.setting_index].id;
    if let Some(input) = &mut app.setting_input {
        match key.code {
            KeyCode::Esc => app.setting_input = None,
            KeyCode::Backspace => {
                input.pop();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => input.clear(),
            KeyCode::Char(c)
                if !c.is_control()
                    && input.len() < 2048
                    && (id == TestUrl || c.is_ascii_digit()) =>
            {
                input.push(c)
            }
            KeyCode::Enter => {
                let text = input.trim().to_string();
                let n = text.parse::<u64>().ok();
                let valid = match id {
                    GraphInterval => n.is_some_and(|n| (1000..=86_400_000).contains(&n)),
                    MixedPort | HttpPort | SocksPort => n.is_some_and(|n| n <= 65535),
                    Timeout => {
                        n.is_some_and(|n| (500..=crate::mihomo::MAX_DELAY_TIMEOUT_MS).contains(&n))
                    }
                    TestUrl => text.starts_with("http://") || text.starts_with("https://"),
                    _ => false,
                };
                if !valid {
                    app.set_status(
                        "输入不在允许范围内 / Invalid value; see setting details",
                        true,
                    );
                    return false;
                }
                app.setting_input = None;
                match id {
                    GraphInterval => {
                        app.set_graph_interval(n.unwrap());
                        app.save_preferences();
                    }
                    Timeout => {
                        app.config.controller.timeout_ms = n.unwrap();
                        app.save_preferences();
                    }
                    TestUrl => {
                        app.config.controller.test_url = text;
                        app.save_preferences();
                    }
                    MixedPort | HttpPort | SocksPort => app.apply_core_setting(
                        match id {
                            MixedPort => "mixed-port",
                            HttpPort => "port",
                            _ => "socks-port",
                        },
                        n.unwrap().into(),
                    ),
                    _ => {}
                }
            }
            _ => {}
        }
        return false;
    }
    let category = rows[app.setting_index].category;
    let indexes: Vec<_> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.category == category)
        .map(|(i, _)| i)
        .collect();
    let pos = indexes
        .iter()
        .position(|i| *i == app.setting_index)
        .unwrap_or(0);
    match key.code {
        KeyCode::Esc | KeyCode::Char('q' | 's' | 'S') => app.screen = Screen::Dashboard,
        KeyCode::Up | KeyCode::Char('k') => {
            app.setting_index = indexes[(pos + indexes.len() - 1) % indexes.len()]
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.setting_index = indexes[(pos + 1) % indexes.len()]
        }
        KeyCode::Left | KeyCode::Char('h') => app.adjust_setting(-1),
        KeyCode::Right | KeyCode::Char('l') => app.adjust_setting(1),
        KeyCode::Enter
            if matches!(
                id,
                GraphInterval | MixedPort | HttpPort | SocksPort | TestUrl | Timeout
            ) =>
        {
            app.setting_input = Some(String::new())
        }
        KeyCode::Enter => app.adjust_setting(1),
        KeyCode::Tab | KeyCode::BackTab | KeyCode::Char('1'..='4') => {
            let categories = [C::Core, C::Appearance, C::Subscription, C::Diagnostics];
            let current = categories.iter().position(|c| *c == category).unwrap_or(0);
            let next = match key.code {
                KeyCode::Char(c) => (c as u8 - b'1') as usize,
                KeyCode::BackTab => (current + 3) % 4,
                _ => (current + 1) % 4,
            };
            app.setting_index = rows
                .iter()
                .position(|r| r.category == categories[next])
                .unwrap();
            if categories[next] == C::Subscription {
                app.profile_page = 0;
                app.open_profiles();
            }
        }
        _ => {}
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ops::{apply_enabled_modules, builtin_modules, enabled_snippets};

    /// The active file regenerated with `key` set, as `apply_core_setting` does.
    fn regenerate(raw: &str, key: &str, literal: &str, ids: &[&str]) -> String {
        let ids: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
        let base = crate::ops::set_top_scalar(&crate::ops::strip_marked_modules(raw), key, literal);
        crate::ops::apply_modules_with_switches(
            &base,
            &enabled_snippets(&builtin_modules(), &ids),
            &crate::ops::saved_switches(raw),
        )
        .unwrap()
    }

    #[test]
    fn live_setting_patches_only_when_nothing_else_changed() {
        let base = "mixed-port: 7890\nallow-lan: false\nlog-level: warning\nproxies: []\n";
        let ids = ["dns-fakeip"];
        let raw = apply_enabled_modules(
            base,
            &enabled_snippets(&builtin_modules(), &ids.map(String::from)),
        )
        .unwrap();
        let next = regenerate(&raw, "allow-lan", "true", &ids);
        assert!(live_patchable(&raw, &next, "allow-lan", &true.into()));
        // A key outside the PATCH set reloads.
        let next = regenerate(&raw, "ipv6", "true", &ids);
        assert!(!live_patchable(&raw, &next, "ipv6", &true.into()));
        // The active file still holds an older DNS module body: a PATCH of
        // `allow-lan` would save the new body without bringing it live.
        let old_body = raw.replace("listen: 127.0.0.1:1053", "listen: 0.0.0.0:1053");
        assert_ne!(old_body, raw);
        let next = regenerate(&old_body, "log-level", "info", &ids);
        assert!(next.contains("listen: 127.0.0.1:1053"));
        assert!(!live_patchable(
            &old_body,
            &next,
            "log-level",
            &"info".into()
        ));
        // A module that overrides the key keeps the old value live.
        let raw = apply_enabled_modules(
            base,
            &enabled_snippets(&builtin_modules(), &["find-process".to_string()]),
        )
        .unwrap();
        let next = regenerate(&raw, "find-process-mode", "off", &["find-process"]);
        assert!(!live_patchable(
            &raw,
            &next,
            "find-process-mode",
            &"off".into()
        ));
    }
}
