use std::{
    env, fs, io,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, Sender},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

pub mod control;
pub mod mihomo;
pub mod ops;
pub mod panels;
pub mod ui;

use crossterm::{
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event as CEvent, KeyCode, KeyEvent,
        KeyModifiers,
    },
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, BeginSynchronizedUpdate, EndSynchronizedUpdate,
        EnterAlternateScreen, LeaveAlternateScreen,
    },
};
use mihomo::{
    close_connection, config_file_exists, download_managed_core_async, fetch_snapshot,
    is_info_pseudo_node, mihomo_asset_label, select_group_node, set_sysproxy, spawn_stream_workers,
    start_core_service, stop_core_service, switch_routing_mode, test_group_delays_async,
    update_subscription_async, BackendEvent, ControllerConfig, CoreSnapshot,
};
use ratatui::prelude::{CrosstermBackend, Terminal};
use serde::{Deserialize, Serialize};
use ui::{draw, theme, Theme, ThemeId, WaveRenderer, THEMES, WAVE_RENDERERS};

const REFRESH_RATES: &[u16] = &[15, 30, 60, 120];
const ROUTING_MODES: &[&str] = &["Rule", "Global", "Direct"];
const HISTORY_LEN: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lang {
    Zh,
    En,
    Ja,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Settings,
    Help,
    Setup,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetupPhase {
    Editing,
    Fetching,
    Starting,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MainTab {
    Proxies,
    Connections,
    Logs,
    Dns,
    Rules,
    Providers,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overlay {
    None,
    Modules,
    Profiles,
    Probe,
    Runtime,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FocusPane {
    Groups,
    Nodes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingCategory {
    Core,
    Appearance,
    Subscription,
}

#[derive(Clone, Debug)]
pub struct SettingRow {
    pub category: SettingCategory,
    pub label: String,
    pub value: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Settings {
    pub lang: Lang,
    pub theme: ThemeId,
    pub renderer: WaveRenderer,
    pub refresh_hz: u16,
    pub show_traffic: bool,
    pub show_toolbar: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lang: Lang::Zh,
            theme: ThemeId::Spring,
            renderer: WaveRenderer::Braille,
            refresh_hz: 60,
            show_traffic: true,
            show_toolbar: true,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub settings: Settings,
    pub controller: ControllerConfig,
    #[serde(default)]
    pub enabled_modules: Vec<String>,
    #[serde(default)]
    pub active_profile: String,
}

impl Config {
    pub fn path() -> PathBuf {
        let base = env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."));
        base.join(".config").join("terc").join("config.json")
    }

    pub fn load() -> Self {
        let path = Self::path();
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str::<Self>(&raw) {
                return cfg;
            }
        }
        let cfg = Self::default();
        cfg.save();
        cfg
    }

    pub fn save(&self) {
        let path = Self::path();
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = fs::write(path, json);
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct LineEditor {
    pub text: String,
    pub cursor: usize,
}

impl LineEditor {
    fn byte_index(&self, char_index: usize) -> usize {
        self.text
            .char_indices()
            .nth(char_index)
            .map(|(i, _)| i)
            .unwrap_or(self.text.len())
    }

    pub fn load(&mut self, text: &str) {
        self.text = text.to_string();
        self.cursor = self.text.chars().count();
    }

    pub fn len(&self) -> usize {
        self.text.chars().count()
    }

    pub fn insert(&mut self, input: &str) -> bool {
        let clean: String = input
            .chars()
            .filter(|c| !c.is_control() && !c.is_whitespace())
            .collect();
        if clean.is_empty() {
            return false;
        }
        let at = self.byte_index(self.cursor);
        self.text.insert_str(at, &clean);
        self.cursor += clean.chars().count();
        true
    }

    pub fn backspace(&mut self) -> bool {
        if self.cursor == 0 {
            return false;
        }
        let at = self.byte_index(self.cursor - 1);
        self.text.remove(at);
        self.cursor -= 1;
        true
    }

    pub fn delete(&mut self) -> bool {
        if self.cursor >= self.len() {
            return false;
        }
        let at = self.byte_index(self.cursor);
        self.text.remove(at);
        true
    }

    pub fn clear(&mut self) {
        self.text.clear();
        self.cursor = 0;
    }

    pub fn move_left(&mut self) {
        self.cursor = self.cursor.saturating_sub(1);
    }

    pub fn move_right(&mut self) {
        if self.cursor < self.len() {
            self.cursor += 1;
        }
    }

    pub fn move_home(&mut self) {
        self.cursor = 0;
    }

    pub fn move_end(&mut self) {
        self.cursor = self.len();
    }

    pub fn chars(&self) -> Vec<char> {
        self.text.chars().collect()
    }

    pub fn trimmed(&self) -> String {
        self.text.trim().to_string()
    }
}

pub struct App {
    pub config: Config,
    pub screen: Screen,
    pub main_tab: MainTab,
    pub focus: FocusPane,
    pub group_index: usize,
    pub node_index: usize,
    pub conn_index: usize,
    pub setting_index: usize,
    pub rule_index: usize,
    pub provider_index: usize,
    pub module_index: usize,
    pub profile_index: usize,
    pub tunnel_index: usize,
    pub overlay: Overlay,
    pub catalog: Vec<crate::ops::ModuleSnippet>,
    pub profiles: Vec<crate::ops::ProfileEntry>,
    pub dns_editor: LineEditor,
    pub dns_editing: bool,
    pub dns_qtype_idx: usize,
    pub dns_lines: Vec<String>,
    pub dns_error: bool,
    pub rule_query: LineEditor,
    pub rule_editing: bool,
    pub explain: Option<crate::ops::ExplainReport>,
    pub probe_editor: LineEditor,
    pub probe_lines: Vec<String>,
    pub probe_error: bool,
    pub snapshot: CoreSnapshot,
    pub up_rate: u64,
    pub down_rate: u64,
    pub memory_inuse: u64,
    pub up_history: Vec<f32>,
    pub down_history: Vec<f32>,
    pub pulse_phase: f32,
    pub logs: Vec<(String, String)>,
    pub status_message: String,
    pub status_is_error: bool,
    pub tx: Sender<BackendEvent>,
    pub rx: Receiver<BackendEvent>,
    pub stop_flag: Arc<AtomicBool>,
    pub last_snapshot_poll: Instant,
    pub setup_origin: Screen,
    pub setup_editor: LineEditor,
    pub setup_phase: SetupPhase,
    pub setup_start_at: Instant,
    pub core_downloading: bool,
}

impl App {
    pub fn new(config: Config) -> Self {
        let (tx, rx) = mpsc::channel();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let initial_snapshot = fetch_snapshot(&config.controller);

        spawn_stream_workers(
            config.controller.addr.clone(),
            config.controller.secret.clone(),
            tx.clone(),
            stop_flag.clone(),
        );

        let screen = launch_screen(
            &config.controller.subscription_url,
            initial_snapshot.running,
            config_file_exists(&config.controller),
        );
        let mut app = Self {
            config,
            screen,
            main_tab: MainTab::Proxies,
            focus: FocusPane::Groups,
            group_index: 0,
            node_index: 0,
            conn_index: 0,
            setting_index: 0,
            rule_index: 0,
            provider_index: 0,
            module_index: 0,
            profile_index: 0,
            tunnel_index: 0,
            overlay: Overlay::None,
            catalog: Vec::new(),
            profiles: Vec::new(),
            dns_editor: LineEditor::default(),
            dns_editing: false,
            dns_qtype_idx: 0,
            dns_lines: Vec::new(),
            dns_error: false,
            rule_query: LineEditor::default(),
            rule_editing: false,
            explain: None,
            probe_editor: LineEditor::default(),
            probe_lines: Vec::new(),
            probe_error: false,
            snapshot: initial_snapshot,
            up_rate: 0,
            down_rate: 0,
            memory_inuse: 0,
            up_history: vec![0.0; HISTORY_LEN],
            down_history: vec![0.0; HISTORY_LEN],
            pulse_phase: 0.0,
            logs: Vec::new(),
            status_message: String::new(),
            status_is_error: false,
            tx,
            rx,
            stop_flag,
            last_snapshot_poll: Instant::now(),
            setup_origin: Screen::Dashboard,
            setup_editor: LineEditor::default(),
            setup_phase: SetupPhase::Editing,
            setup_start_at: Instant::now(),
            core_downloading: false,
        };
        app.dns_editor.load("example.com");
        app.sync_node_cursor_to_active();
        if app.screen == Screen::Setup {
            app.open_setup(Screen::Dashboard);
        }
        app
    }

    pub fn needs_setup(&self) -> bool {
        needs_setup_state(
            &self.config.controller.subscription_url,
            self.snapshot.running,
            config_file_exists(&self.config.controller),
        )
    }

    pub fn core_binary_found(&self) -> bool {
        !self.snapshot.core_bin_path.is_empty() && self.snapshot.core_bin_path != "not found"
    }

    pub fn open_setup(&mut self, origin: Screen) {
        self.setup_origin = origin;
        self.setup_editor
            .load(self.config.controller.subscription_url.trim());
        self.setup_phase = SetupPhase::Editing;
        self.clear_status();
        self.screen = Screen::Setup;
    }

    pub fn close_setup(&mut self) {
        self.setup_phase = SetupPhase::Editing;
        self.screen = self.setup_origin;
    }

    pub fn submit_setup(&mut self) {
        if self.setup_phase != SetupPhase::Editing {
            return;
        }
        let url = self.setup_editor.trimmed();
        if url.is_empty() {
            self.set_status(self.t("setup_err_empty"), true);
            return;
        }
        let lower = url.to_ascii_lowercase();
        if !lower.starts_with("https://") && !lower.starts_with("http://") {
            self.set_status(self.t("setup_err_scheme"), true);
            return;
        }
        self.config.controller.subscription_url = url;
        self.config.save();
        self.setup_phase = SetupPhase::Fetching;
        update_subscription_async(self.config.controller.clone(), self.tx.clone());
    }

    pub fn set_status(&mut self, text: &str, is_error: bool) {
        self.status_message = text.to_string();
        self.status_is_error = is_error;
    }

    pub fn clear_status(&mut self) {
        self.status_message.clear();
        self.status_is_error = false;
    }

    pub fn download_core(&mut self) {
        if self.core_downloading {
            return;
        }
        self.clear_status();
        self.core_downloading = true;
        download_managed_core_async(self.tx.clone());
    }

    fn finish_setup_fetch(&mut self, ok: bool) {
        if !ok {
            self.setup_phase = SetupPhase::Editing;
            return;
        }
        self.clear_status();
        if self.snapshot.running {
            self.close_setup();
            return;
        }
        if !self.core_binary_found() {
            self.setup_phase = SetupPhase::Editing;
            self.set_status(self.t("setup_msg_saved"), false);
            return;
        }
        match start_core_service(&self.config.controller) {
            Ok(_) => {
                self.setup_phase = SetupPhase::Starting;
                self.setup_start_at = Instant::now();
                self.set_status(self.t("setup_msg_starting"), false);
            }
            Err(e) => {
                self.setup_phase = SetupPhase::Editing;
                self.set_status(
                    &format!("{}: {}", self.t("setup_msg_start_failed"), e),
                    true,
                );
            }
        }
    }

    pub fn theme(&self) -> Theme {
        theme(self.config.settings.theme)
    }

    pub fn lang(&self) -> Lang {
        self.config.settings.lang
    }

    pub fn frame_duration(&self) -> Duration {
        let hz = self.config.settings.refresh_hz.clamp(15, 120) as u64;
        Duration::from_micros(1_000_000 / hz)
    }

    pub fn drain_events(&mut self) {
        while let Ok(ev) = self.rx.try_recv() {
            match ev {
                BackendEvent::Traffic { up, down } => {
                    self.up_rate = up;
                    self.down_rate = down;
                    self.snapshot.running = true;
                    self.up_history.remove(0);
                    self.up_history.push(up as f32);
                    self.down_history.remove(0);
                    self.down_history.push(down as f32);
                }
                BackendEvent::Memory { inuse } => {
                    self.memory_inuse = inuse;
                }
                BackendEvent::Log { level, payload } => {
                    self.logs.push((level, payload));
                    if self.logs.len() > 300 {
                        self.logs.remove(0);
                    }
                }
                BackendEvent::Snapshot(snap) => {
                    self.snapshot = *snap;
                    if self.group_index >= self.snapshot.groups.len() {
                        self.group_index = self.snapshot.groups.len().saturating_sub(1);
                    }
                    self.clamp_aux();
                }
                BackendEvent::DnsLookup { lines, is_error } => {
                    self.dns_error = is_error;
                    self.dns_lines = lines;
                }
                BackendEvent::ProbeDone { lines, is_error } => {
                    self.probe_error = is_error;
                    self.probe_lines = lines;
                }
                BackendEvent::DelayResult {
                    group: _,
                    node,
                    delay,
                } => {
                    if let Some(n) = self.snapshot.nodes.get_mut(&node) {
                        n.delay = delay;
                    }
                }
                BackendEvent::GroupTestDone { group } => {
                    self.status_message = format!("Latency test complete: {group}");
                    self.status_is_error = false;
                }
                BackendEvent::StatusMessage { text, is_error } => {
                    self.status_message = text;
                    self.status_is_error = is_error;
                }
                BackendEvent::SubscriptionDone { ok } => {
                    if matches!(self.screen, Screen::Setup)
                        || self.setup_phase == SetupPhase::Fetching
                    {
                        self.finish_setup_fetch(ok);
                    }
                }
                BackendEvent::CoreDownloadDone { ok } => {
                    self.core_downloading = false;
                    if ok {
                        self.refresh_snapshot_now();
                    }
                }
            }
        }
    }

    pub fn tick(&mut self, elapsed: Duration) {
        let dt = elapsed.as_secs_f32();
        self.pulse_phase = (self.pulse_phase + dt * 0.9) % 1.0;

        if self.screen == Screen::Setup
            && self.setup_phase == SetupPhase::Starting
            && self.setup_start_at.elapsed() >= Duration::from_secs(10)
        {
            self.setup_phase = SetupPhase::Editing;
            self.set_status(self.t("setup_msg_still_starting"), false);
        }

        if self.last_snapshot_poll.elapsed() >= Duration::from_millis(2200) {
            self.last_snapshot_poll = Instant::now();
            let cfg = self.config.controller.clone();
            let tx = self.tx.clone();
            thread::spawn(move || {
                let snap = fetch_snapshot(&cfg);
                let _ = tx.send(BackendEvent::Snapshot(Box::new(snap)));
            });
        }
    }

    pub fn refresh_snapshot_now(&mut self) {
        self.snapshot = fetch_snapshot(&self.config.controller);
        self.clamp_node_index();
    }

    pub fn sync_node_cursor_to_active(&mut self) {
        if let Some(group) = self.snapshot.groups.get(self.group_index) {
            if let Some(pos) = group.all.iter().position(|n| n == &group.now) {
                self.node_index = pos;
                return;
            }
        }
        self.node_index = 0;
    }

    pub fn clamp_node_index(&mut self) {
        if let Some(group) = self.snapshot.groups.get(self.group_index) {
            if self.node_index >= group.all.len() {
                self.node_index = group.all.len().saturating_sub(1);
            }
        } else {
            self.node_index = 0;
        }
    }

    pub fn activate_selected_node(&mut self) {
        let Some(group) = self.snapshot.groups.get(self.group_index) else {
            return;
        };
        let Some(node) = group.all.get(self.node_index) else {
            return;
        };
        if is_info_pseudo_node(node) {
            return;
        }
        let group_name = group.name.clone();
        let node_name = node.clone();
        match select_group_node(&self.config.controller, &group_name, &node_name) {
            Ok(()) => {
                if let Some(g) = self.snapshot.groups.get_mut(self.group_index) {
                    g.now = node_name.clone();
                }
                self.status_message = format!("{group_name} › {node_name}");
                self.status_is_error = false;
            }
            Err(e) => {
                self.status_message = format!("Switch failed: {e}");
                self.status_is_error = true;
            }
        }
    }

    pub fn test_current_group(&mut self) {
        let Some(group) = self.snapshot.groups.get(self.group_index) else {
            return;
        };
        self.status_message = format!("Testing {} ({})...", group.name, group.all.len());
        self.status_is_error = false;
        test_group_delays_async(
            self.config.controller.clone(),
            group.name.clone(),
            group.all.clone(),
            self.tx.clone(),
        );
    }

    pub fn select_best_node_in_group(&mut self) {
        let Some(group) = self.snapshot.groups.get(self.group_index) else {
            return;
        };
        let mut best: Option<(usize, String, u16)> = None;
        for (idx, name) in group.all.iter().enumerate() {
            if is_info_pseudo_node(name) {
                continue;
            }
            if let Some(delay) = self.snapshot.nodes.get(name).and_then(|n| n.delay) {
                if delay > 0 && best.as_ref().map(|b| delay < b.2).unwrap_or(true) {
                    best = Some((idx, name.clone(), delay));
                }
            }
        }
        if let Some((idx, _, _)) = best {
            self.node_index = idx;
            self.activate_selected_node();
        } else {
            self.test_current_group();
        }
    }

    pub fn toggle_sysproxy(&mut self) {
        let target = !self.snapshot.sysproxy_enabled;
        match set_sysproxy(target, self.snapshot.http_port, self.snapshot.socks_port) {
            Ok(msg) => {
                self.snapshot.sysproxy_enabled = target;
                self.status_message = msg;
                self.status_is_error = false;
            }
            Err(err) => {
                self.status_message = if err == "sysproxy_unavailable" {
                    self.t("sysproxy_unavailable").to_string()
                } else {
                    err
                };
                self.status_is_error = true;
            }
        }
    }

    pub fn cycle_routing_mode(&mut self) {
        let cur_idx = ROUTING_MODES
            .iter()
            .position(|m| m.eq_ignore_ascii_case(&self.snapshot.mode))
            .unwrap_or(0);
        let next_mode = ROUTING_MODES[(cur_idx + 1) % ROUTING_MODES.len()];
        if switch_routing_mode(&self.config.controller, next_mode).is_ok() {
            self.snapshot.mode = next_mode.to_string();
            self.status_message = format!("Routing mode › {next_mode}");
            self.status_is_error = false;
            self.refresh_snapshot_now();
        }
    }

    pub fn toggle_core_service(&mut self) {
        if self.snapshot.running {
            match stop_core_service(&self.config.controller) {
                Ok(msg) => {
                    self.status_message = msg;
                    self.status_is_error = false;
                    self.refresh_snapshot_now();
                }
                Err(e) => {
                    self.status_message = e;
                    self.status_is_error = true;
                }
            }
        } else {
            match start_core_service(&self.config.controller) {
                Ok(msg) => {
                    self.status_message = msg;
                    self.status_is_error = false;
                    self.refresh_snapshot_now();
                }
                Err(e) => {
                    self.status_message = e;
                    self.status_is_error = true;
                }
            }
        }
    }

    pub fn settings_rows(&self) -> Vec<SettingRow> {
        let theme_label = match self.config.settings.theme {
            ThemeId::Spring => "Spring",
            ThemeId::Vintage => "Vintage",
            ThemeId::Mono => "Mono",
        };
        let renderer_label = match self.config.settings.renderer {
            WaveRenderer::Braille => "Braille",
            WaveRenderer::Blocks => "Blocks",
        };
        let lang_label = match self.config.settings.lang {
            Lang::Zh => "中文",
            Lang::En => "English",
            Lang::Ja => "日本語",
        };

        vec![
            SettingRow {
                category: SettingCategory::Core,
                label: self.t("set_core_state").to_string(),
                value: if self.snapshot.running {
                    format!("Running ({})", self.snapshot.version)
                } else {
                    "Stopped".to_string()
                },
                description: format!(
                    "{}\nBinary: {}\nConfig: {}/config.yaml",
                    self.t("desc_core_state"),
                    self.snapshot.core_bin_path,
                    self.config.controller.config_dir
                ),
            },
            SettingRow {
                category: SettingCategory::Core,
                label: self.t("set_sysproxy").to_string(),
                value: if self.snapshot.sysproxy_enabled {
                    format!("ON ({})", self.snapshot.network_service)
                } else {
                    format!("OFF ({})", self.snapshot.network_service)
                },
                description: self.t("desc_sysproxy").to_string(),
            },
            SettingRow {
                category: SettingCategory::Core,
                label: self.t("set_mode").to_string(),
                value: self.snapshot.mode.clone(),
                description: self.t("desc_mode").to_string(),
            },
            SettingRow {
                category: SettingCategory::Core,
                label: self.t("set_download_core").to_string(),
                value: "Enter / →".to_string(),
                description: format!("{}\n{}", self.t("desc_download_core"), mihomo_asset_label()),
            },
            SettingRow {
                category: SettingCategory::Appearance,
                label: self.t("set_theme").to_string(),
                value: theme_label.to_string(),
                description: self.t("desc_theme").to_string(),
            },
            SettingRow {
                category: SettingCategory::Appearance,
                label: self.t("set_renderer").to_string(),
                value: renderer_label.to_string(),
                description: self.t("desc_renderer").to_string(),
            },
            SettingRow {
                category: SettingCategory::Appearance,
                label: self.t("set_refresh").to_string(),
                value: format!("{} Hz", self.config.settings.refresh_hz),
                description: self.t("desc_refresh").to_string(),
            },
            SettingRow {
                category: SettingCategory::Appearance,
                label: self.t("set_lang").to_string(),
                value: lang_label.to_string(),
                description: self.t("desc_lang").to_string(),
            },
            SettingRow {
                category: SettingCategory::Subscription,
                label: self.t("set_sub_url").to_string(),
                value: if self.config.controller.subscription_url.trim().is_empty() {
                    self.t("sub_not_set").to_string()
                } else {
                    mask_url(&self.config.controller.subscription_url)
                },
                description: self.t("desc_sub_url").to_string(),
            },
            SettingRow {
                category: SettingCategory::Subscription,
                label: self.t("set_sub_update").to_string(),
                value: "Enter / →".to_string(),
                description: format!(
                    "{}\nURL: {}",
                    self.t("desc_sub_update"),
                    mask_url(&self.config.controller.subscription_url)
                ),
            },
        ]
    }

    pub fn adjust_setting(&mut self, dir: i32) {
        match self.setting_index {
            0 => self.toggle_core_service(),
            1 => self.toggle_sysproxy(),
            2 => self.cycle_routing_mode(),
            3 => download_managed_core_async(self.tx.clone()),
            4 => {
                let pos = THEMES
                    .iter()
                    .position(|t| *t == self.config.settings.theme)
                    .unwrap_or(0);
                let next = (pos as i32 + dir).rem_euclid(THEMES.len() as i32) as usize;
                self.config.settings.theme = THEMES[next];
                self.config.save();
            }
            5 => {
                let pos = WAVE_RENDERERS
                    .iter()
                    .position(|r| *r == self.config.settings.renderer)
                    .unwrap_or(0);
                let next = (pos as i32 + dir).rem_euclid(WAVE_RENDERERS.len() as i32) as usize;
                self.config.settings.renderer = WAVE_RENDERERS[next];
                self.config.save();
            }
            6 => {
                let pos = REFRESH_RATES
                    .iter()
                    .position(|r| *r == self.config.settings.refresh_hz)
                    .unwrap_or(2);
                let next = (pos as i32 + dir).rem_euclid(REFRESH_RATES.len() as i32) as usize;
                self.config.settings.refresh_hz = REFRESH_RATES[next];
                self.config.save();
            }
            7 => {
                let langs = [Lang::Zh, Lang::En, Lang::Ja];
                let pos = langs
                    .iter()
                    .position(|l| *l == self.config.settings.lang)
                    .unwrap_or(0);
                let next = (pos as i32 + dir).rem_euclid(langs.len() as i32) as usize;
                self.config.settings.lang = langs[next];
                self.config.save();
            }
            8 => {
                self.open_setup(Screen::Settings);
            }
            9 => {
                if self.config.controller.subscription_url.trim().is_empty() {
                    self.open_setup(Screen::Settings);
                } else {
                    update_subscription_async(self.config.controller.clone(), self.tx.clone());
                }
            }
            _ => {}
        }
    }

    pub fn t(&self, key: &str) -> &'static str {
        match (self.config.settings.lang, key) {
            (_, "too_small") => "Terminal window too small",
            (Lang::Zh, "traffic") => "实时速率",
            (Lang::En, "traffic") => "Traffic",
            (Lang::Ja, "traffic") => "トラフィック",
            (Lang::Zh, "overview") => "内核状态",
            (Lang::En, "overview") => "Overview",
            (Lang::Ja, "overview") => "ステータス",
            (Lang::Zh, "groups") => "策略组",
            (Lang::En, "groups") => "Groups",
            (Lang::Ja, "groups") => "グループ",
            (Lang::Zh, "nodes") => "节点",
            (Lang::En, "nodes") => "Nodes",
            (Lang::Ja, "nodes") => "ノード",
            (Lang::Zh, "connections") => "连接",
            (Lang::En, "connections") => "Connections",
            (Lang::Ja, "connections") => "接続",
            (Lang::Zh, "logs") => "日志",
            (Lang::En, "logs") => "Logs",
            (Lang::Ja, "logs") => "ログ",
            (Lang::Zh, "settings") => "设置",
            (Lang::En, "settings") => "Settings",
            (Lang::Ja, "settings") => "設定",
            (Lang::Zh, "help") => "帮助",
            (Lang::En, "help") => "Help",
            (Lang::Ja, "help") => "ヘルプ",
            (Lang::Zh, "stopped") => "未运行 (按 K 启动)",
            (Lang::En, "stopped") => "Stopped (Press K)",
            (Lang::Ja, "stopped") => "停止中 (Kで起動)",
            (Lang::Zh, "no_groups") => "暂无策略组",
            (Lang::En, "no_groups") => "No proxy groups",
            (Lang::Ja, "no_groups") => "グループなし",
            (Lang::Zh, "core_stopped_hint") => "Mihomo 内核未运行 · 按 K 启动内核，按 u 更新订阅（首次使用请按提示添加订阅）",
            (Lang::En, "core_stopped_hint") => "Mihomo core is stopped · K starts it, u updates the subscription (first run: add one below)",
            (Lang::Ja, "core_stopped_hint") => "Mihomo停止中 · Kで起動、uでサブスク更新（初回は登録を追加）",
            (Lang::Zh, "no_connections") => "当前没有活跃连接",
            (Lang::En, "no_connections") => "No active connections",
            (Lang::Ja, "no_connections") => "アクティブな接続はありません",
            (Lang::Zh, "no_logs") => "等待实时日志流...",
            (Lang::En, "no_logs") => "Waiting for live logs...",
            (Lang::Ja, "no_logs") => "ログ待機中...",
            (Lang::Zh, "sysproxy_on") => "开启系统代理",
            (Lang::En, "sysproxy_on") => "Enable SysProxy",
            (Lang::Ja, "sysproxy_on") => "システムプロキシON",
            (Lang::Zh, "sysproxy_off") => "关闭系统代理",
            (Lang::En, "sysproxy_off") => "Disable SysProxy",
            (Lang::Ja, "sysproxy_off") => "システムプロキシOFF",
            (Lang::Zh, "test_delay") => "测速",
            (Lang::En, "test_delay") => "Test",
            (Lang::Ja, "test_delay") => "遅延測定",
            (Lang::Zh, "auto_best") => "优选",
            (Lang::En, "auto_best") => "Best",
            (Lang::Ja, "auto_best") => "最適選択",
            (Lang::Zh, "mode") => "模式",
            (Lang::En, "mode") => "Mode",
            (Lang::Ja, "mode") => "モード",
            (Lang::Zh, "sub_update") => "更新订阅",
            (Lang::En, "sub_update") => "Update Sub",
            (Lang::Ja, "sub_update") => "購読更新",
            (Lang::Zh, "cat_core") => "内核与代理",
            (Lang::En, "cat_core") => "Core & Proxy",
            (Lang::Ja, "cat_core") => "コア・プロキシ",
            (Lang::Zh, "cat_appearance") => "视觉与主题",
            (Lang::En, "cat_appearance") => "Appearance",
            (Lang::Ja, "cat_appearance") => "外観・テーマ",
            (Lang::Zh, "cat_sub") => "订阅管理",
            (Lang::En, "cat_sub") => "Subscription",
            (Lang::Ja, "cat_sub") => "サブスクリプション",
            (Lang::Zh, "settings_parameters") => "配置项",
            (Lang::En, "settings_parameters") => "Parameters",
            (Lang::Ja, "settings_parameters") => "項目",
            (Lang::Zh, "settings_details") => "详细说明",
            (Lang::En, "settings_details") => "Details",
            (Lang::Ja, "settings_details") => "詳細",
            (Lang::Zh, "setting_adjust") => "切换/执行",
            (Lang::En, "setting_adjust") => "Adjust",
            (Lang::Ja, "setting_adjust") => "変更",
            (Lang::Zh, "setting_select") => "选择",
            (Lang::En, "setting_select") => "Select",
            (Lang::Ja, "setting_select") => "選択",
            (Lang::Zh, "current_value") => "当前状态",
            (Lang::En, "current_value") => "Current",
            (Lang::Ja, "current_value") => "現在値",
            (Lang::Zh, "set_core_state") => "Mihomo 内核服务",
            (Lang::En, "set_core_state") => "Mihomo Core Service",
            (Lang::Ja, "set_core_state") => "Mihomo コアサービス",
            (Lang::Zh, "desc_core_state") => "一键启动或停止后台 Mihomo 进程。即使退出 terc，后台内核依然稳定保持运行。",
            (Lang::En, "desc_core_state") => "Start or stop background Mihomo daemon. Continues running after quitting terc.",
            (Lang::Ja, "desc_core_state") => "バックグラウンドのMihomoを起動・停止します。",
            (Lang::Zh, "set_sysproxy") => "系统代理",
            (Lang::En, "set_sysproxy") => "System Proxy",
            (Lang::Ja, "set_sysproxy") => "システムプロキシ",
            (Lang::Zh, "desc_sysproxy") => "macOS 用 networksetup 接管当前网卡的 HTTP/HTTPS/SOCKS。Linux 在有 GNOME 时用 gsettings（org.gnome.system.proxy）；没有则保持原样并提示。不会自动打开。",
            (Lang::En, "desc_sysproxy") => "macOS uses networksetup for the active service. Linux uses GNOME gsettings (org.gnome.system.proxy) when it is present, and otherwise leaves the proxy unchanged. Never enabled automatically.",
            (Lang::Ja, "desc_sysproxy") => "macOS は networksetup。Linux は GNOME の gsettings（org.gnome.system.proxy）があるときだけ変更し、なければそのままにして知らせます。",
            (Lang::Zh, "sysproxy_unavailable") => "此 Linux 环境没有 GNOME gsettings（org.gnome.system.proxy），系统代理未改动。",
            (Lang::En, "sysproxy_unavailable") => "System proxy unchanged: GNOME gsettings (org.gnome.system.proxy) is not available.",
            (Lang::Ja, "sysproxy_unavailable") => "システムプロキシは未変更です。GNOME の gsettings（org.gnome.system.proxy）がありません。",
            (Lang::Zh, "set_mode") => "路由分流模式",
            (Lang::En, "set_mode") => "Routing Mode",
            (Lang::Ja, "set_mode") => "ルーティングモード",
            (Lang::Zh, "desc_mode") => "在 Rule（规则分流）、Global（全局代理）、Direct（全局直连）之间无缝切换。",
            (Lang::En, "desc_mode") => "Switch between Rule, Global, and Direct routing modes.",
            (Lang::Ja, "desc_mode") => "Rule / Global / Direct モードを切り替えます。",
            (Lang::Zh, "set_download_core") => "下载/升级内置内核",
            (Lang::En, "set_download_core") => "Download Managed Core",
            (Lang::Ja, "set_download_core") => "コアのダウンロード",
            (Lang::Zh, "desc_download_core") => "从 GitHub 官方 MetaCubeX/mihomo 拉取与本机系统、架构匹配的包，解压到 ~/.config/terc/core/mihomo。",
            (Lang::En, "desc_download_core") => "Fetch the MetaCubeX/mihomo release that matches this OS and CPU into ~/.config/terc/core/mihomo.",
            (Lang::Ja, "desc_download_core") => "この OS と CPU に合う MetaCubeX/mihomo を ~/.config/terc/core/mihomo に入れます。",
            (Lang::Zh, "set_theme") => "色彩主题",
            (Lang::En, "set_theme") => "Palette Theme",
            (Lang::Ja, "set_theme") => "カラーテーマ",
            (Lang::Zh, "desc_theme") => "与 terb 同款的克制低饱和配色：Spring（浅青珊瑚）、Vintage（苔绿陶土）、Mono（极简黑白）。",
            (Lang::En, "desc_theme") => "Restrained palettes matching terb: Spring, Vintage, and Mono.",
            (Lang::Ja, "desc_theme") => "terbと同じ配色テーマ（Spring / Vintage / Mono）。",
            (Lang::Zh, "set_renderer") => "速率图样式",
            (Lang::En, "set_renderer") => "Rate Graph Style",
            (Lang::Ja, "set_renderer") => "グラフスタイル",
            (Lang::Zh, "desc_renderer") => "切换顶栏速率图样式：Braille（盲文点阵）或 Blocks（实心块），上下行以不同颜色分开展示。",
            (Lang::En, "desc_renderer") => "Switch traffic rate graph style: Braille or Blocks, with up/down drawn in separate colors.",
            (Lang::Ja, "desc_renderer") => "トラフィックグラフの描画スタイルを切り替えます。",
            (Lang::Zh, "set_refresh") => "界面刷新率",
            (Lang::En, "set_refresh") => "Refresh Rate",
            (Lang::Ja, "set_refresh") => "リフレッシュレート",
            (Lang::Zh, "desc_refresh") => "控制界面刷新率（15 / 30 / 60 / 120 Hz）。",
            (Lang::En, "desc_refresh") => "Target UI refresh rate (15 / 30 / 60 / 120 Hz).",
            (Lang::Ja, "desc_refresh") => "フレームレートを設定します。",
            (Lang::Zh, "set_lang") => "界面语言",
            (Lang::En, "set_lang") => "Language",
            (Lang::Ja, "set_lang") => "言語",
            (Lang::Zh, "desc_lang") => "切换中文、English 与 日本語。",
            (Lang::En, "desc_lang") => "Switch UI language between Chinese, English, and Japanese.",
            (Lang::Ja, "desc_lang") => "表示言語を切り替えます。",
            (Lang::Zh, "set_sub_update") => "立即更新机场订阅",
            (Lang::En, "set_sub_update") => "Update Subscription Now",
            (Lang::Ja, "set_sub_update") => "購読を今すぐ更新",
            (Lang::Zh, "desc_sub_update") => "拉取最新订阅配置并执行零停机热重载 (PUT /configs?force=true)。",
            (Lang::En, "desc_sub_update") => "Download latest subscription YAML and hot-reload Mihomo core.",
            (Lang::Ja, "desc_sub_update") => "最新のサブスクリプションを取得してリロードします。",
            (Lang::Zh, "set_sub_url") => "机场订阅链接",
            (Lang::En, "set_sub_url") => "Subscription URL",
            (Lang::Ja, "set_sub_url") => "サブスクリプションリンク",
            (Lang::Zh, "desc_sub_url") => "按 Enter 打开订阅编辑器；链接只保存在本机 ~/.config/terc/config.json。",
            (Lang::En, "desc_sub_url") => "Press Enter to edit. The link is stored only in ~/.config/terc/config.json.",
            (Lang::Ja, "desc_sub_url") => "Enterで編集。リンクは ~/.config/terc/config.json にのみ保存されます。",
            (Lang::Zh, "sub_not_set") => "未设置",
            (Lang::En, "sub_not_set") => "not set",
            (Lang::Ja, "sub_not_set") => "未設定",
            (Lang::Zh, "setup_title") => "初始设置",
            (Lang::En, "setup_title") => "First-run Setup",
            (Lang::Ja, "setup_title") => "初回セットアップ",
            (Lang::Zh, "setup_intro") => "terc 是 Mihomo (Clash.Meta) 的终端控制器与流量监视器。首次使用请完成以下三步。",
            (Lang::En, "setup_intro") => "terc is a terminal Mihomo (Clash.Meta) controller and traffic monitor. Three steps to get running.",
            (Lang::Ja, "setup_intro") => "terc はターミナルの Mihomo コントローラーです。3ステップで起動できます。",
            (Lang::Zh, "setup_step_sub") => "订阅链接",
            (Lang::En, "setup_step_sub") => "Subscription link",
            (Lang::Ja, "setup_step_sub") => "サブスクリンク",
            (Lang::Zh, "setup_step_core") => "内核二进制",
            (Lang::En, "setup_step_core") => "Core binary",
            (Lang::Ja, "setup_step_core") => "コアバイナリ",
            (Lang::Zh, "setup_step_run") => "运行内核",
            (Lang::En, "setup_step_run") => "Run core",
            (Lang::Ja, "setup_step_run") => "コア起動",
            (Lang::Zh, "setup_found") => "已找到",
            (Lang::En, "setup_found") => "found",
            (Lang::Ja, "setup_found") => "見つかりました",
            (Lang::Zh, "setup_missing") => "未找到",
            (Lang::En, "setup_missing") => "missing",
            (Lang::Ja, "setup_missing") => "見つかりません",
            (Lang::Zh, "setup_config_ok") => "已就绪",
            (Lang::En, "setup_config_ok") => "ready",
            (Lang::Ja, "setup_config_ok") => "準備完了",
            (Lang::Zh, "setup_waiting") => "等待订阅",
            (Lang::En, "setup_waiting") => "waiting",
            (Lang::Ja, "setup_waiting") => "待機中",
            (Lang::Zh, "setup_running") => "运行中",
            (Lang::En, "setup_running") => "running",
            (Lang::Ja, "setup_running") => "稼働中",
            (Lang::Zh, "setup_stopped") => "未运行",
            (Lang::En, "setup_stopped") => "stopped",
            (Lang::Ja, "setup_stopped") => "停止中",
            (Lang::Zh, "setup_dl_hint") => "未安装内核：按 Ctrl+D 从 GitHub 下载官方 mihomo",
            (Lang::En, "setup_dl_hint") => "No core binary: press Ctrl+D to download official mihomo",
            (Lang::Ja, "setup_dl_hint") => "コア未導入：Ctrl+D で GitHub からダウンロード",
            (Lang::Zh, "setup_dl_busy") => "正在下载 mihomo 内核…",
            (Lang::En, "setup_dl_busy") => "Downloading mihomo core…",
            (Lang::Ja, "setup_dl_busy") => "mihomo をダウンロード中…",
            (Lang::Zh, "setup_input") => "订阅链接",
            (Lang::En, "setup_input") => "Subscription URL",
            (Lang::Ja, "setup_input") => "サブスクリンク",
            (Lang::Zh, "setup_paste_hint") => "可直接粘贴机场订阅链接（Ctrl+U 清空，Ctrl+D 下载内核）",
            (Lang::En, "setup_paste_hint") => "Paste your subscription link (Ctrl+U clears, Ctrl+D downloads the core)",
            (Lang::Ja, "setup_paste_hint") => "リンクを貼り付け可能（Ctrl+U クリア、Ctrl+D でコア導入）",
            (Lang::Zh, "setup_keys") => "Enter 保存并启动内核 · Esc 稍后再说",
            (Lang::En, "setup_keys") => "Enter saves & starts the core · Esc for later",
            (Lang::Ja, "setup_keys") => "Enter で保存して起動 · Esc で後で",
            (Lang::Zh, "setup_sysproxy_note") => "提示：系统代理不会自动开启，确认网络正常后按 Space 手动接管。",
            (Lang::En, "setup_sysproxy_note") => "Note: the system proxy is never enabled automatically — press Space when you are ready.",
            (Lang::Ja, "setup_sysproxy_note") => "注意：システムプロキシは自動で有効になりません。準備できたら Space を押してください。",
            (Lang::Zh, "setup_fetching") => "正在拉取订阅…",
            (Lang::En, "setup_fetching") => "Fetching subscription…",
            (Lang::Ja, "setup_fetching") => "サブスクを取得中…",
            (Lang::Zh, "setup_starting") => "正在启动内核…",
            (Lang::En, "setup_starting") => "Starting core…",
            (Lang::Ja, "setup_starting") => "コアを起動中…",
            (Lang::Zh, "setup_err_empty") => "请输入订阅链接后再按 Enter",
            (Lang::En, "setup_err_empty") => "Paste your subscription link first",
            (Lang::Ja, "setup_err_empty") => "まずリンクを入力してください",
            (Lang::Zh, "setup_err_scheme") => "订阅链接必须以 http:// 或 https:// 开头",
            (Lang::En, "setup_err_scheme") => "The link must start with http:// or https://",
            (Lang::Ja, "setup_err_scheme") => "リンクは http:// または https:// で始めてください",
            (Lang::Zh, "setup_msg_saved") => "订阅已保存 · 内核未安装：按 Ctrl+D 下载，启动后按 K",
            (Lang::En, "setup_msg_saved") => "Subscription saved · no core binary: press Ctrl+D, then K to start",
            (Lang::Ja, "setup_msg_saved") => "サブスク保存済み · コア未導入：Ctrl+D で導入、K で起動",
            (Lang::Zh, "setup_msg_starting") => "内核启动中，就绪后自动关闭本窗口…",
            (Lang::En, "setup_msg_starting") => "Starting core; this window closes once it answers…",
            (Lang::Ja, "setup_msg_starting") => "コア起動中。応答するとこの窓は閉じます…",
            (Lang::Zh, "setup_msg_start_failed") => "内核启动失败",
            (Lang::En, "setup_msg_start_failed") => "Core failed to start",
            (Lang::Ja, "setup_msg_start_failed") => "コア起動に失敗",
            (Lang::Zh, "setup_msg_still_starting") => "内核仍未响应 · 按 Ctrl+D 重新下载内核，或 Esc 查看日志",
            (Lang::En, "setup_msg_still_starting") => "Core still not answering · Ctrl+D re-downloads it, Esc shows the logs",
            (Lang::Ja, "setup_msg_still_starting") => "コアが応答しません · Ctrl+D で再導入、Esc でログ",
            (Lang::Zh, "help_space") => "开关系统代理。macOS 用 networksetup，Linux 用 GNOME gsettings",
            (Lang::En, "help_space") => "Toggle the system proxy (networksetup, or GNOME gsettings)",
            (Lang::Ja, "help_space") => "システムプロキシを切替（networksetup または GNOME gsettings）",
            (_, "help_hl") => "Switch focus between Groups [1] and Nodes [2]",
            (_, "help_jk") => "Navigate up / down in current list",
            (_, "help_enter") => "Activate highlighted node in current group",
            (_, "help_r") => "Concurrent URL latency test for current group",
            (_, "help_a") => "Auto-select lowest latency node in current group",
            (_, "help_m") => "Cycle routing mode (Rule / Global / Direct)",
            (_, "help_u") => "Fetch subscription & hot-reload (u opens the setup window when unset)",
            (_, "help_tabs") => "Switch view: [p] Proxies  [c] Connections  [L] Logs",
            (_, "help_t") => "Toggle top Traffic & Overview panels",
            (_, "help_s") => "Open Settings board (Core / Theme / Subscription)",
            (Lang::Zh, "help_q") => "退出 terc（后台内核继续运行）",
            (Lang::En, "help_q") => "Quit terc (background core stays running)",
            (Lang::Ja, "help_q") => "終了（バックグラウンドのコアは継続）",
            (Lang::Zh, "help_esc") => "子页面回节点页，再按退出；设置与帮助回面板",
            (Lang::En, "help_esc") => "Back to proxies, then quit. Settings and Help return here",
            (Lang::Ja, "help_esc") => "プロキシへ戻って終了。設定とヘルプはパネルへ",
            (Lang::Zh, "controls") => "开关",
            (Lang::En, "controls") => "Controls",
            (Lang::Ja, "controls") => "スイッチ",
            (Lang::Zh, "tun") => "TUN",
            (Lang::En, "tun") => "TUN",
            (Lang::Ja, "tun") => "TUN",
            (Lang::Zh, "sniff") => "嗅探",
            (Lang::En, "sniff") => "Sniff",
            (Lang::Ja, "sniff") => "スニフ",
            (Lang::Zh, "dns") => "DNS",
            (Lang::En, "dns") => "DNS",
            (Lang::Ja, "dns") => "DNS",
            (Lang::Zh, "rules") => "规则",
            (Lang::En, "rules") => "Rules",
            (Lang::Ja, "rules") => "ルール",
            (Lang::Zh, "providers") => "订阅源",
            (Lang::En, "providers") => "Providers",
            (Lang::Ja, "providers") => "プロバイダ",
            (Lang::Zh, "modules") => "片段",
            (Lang::En, "modules") => "Snippets",
            (Lang::Ja, "modules") => "スニペット",
            (Lang::Zh, "profiles") => "配置",
            (Lang::En, "profiles") => "Profiles",
            (Lang::Ja, "profiles") => "プロファイル",
            (Lang::Zh, "probe") => "探测",
            (Lang::En, "probe") => "Probe",
            (Lang::Ja, "probe") => "プローブ",
            (Lang::Zh, "runtime") => "运行时",
            (Lang::En, "runtime") => "Runtime",
            (Lang::Ja, "runtime") => "ランタイム",
            (Lang::Zh, "ipv6") => "IPv6",
            (Lang::En, "ipv6") => "IPv6",
            (Lang::Ja, "ipv6") => "IPv6",
            (Lang::Zh, "st_tun_on") => "TUN 已开启",
            (Lang::En, "st_tun_on") => "TUN on",
            (Lang::Ja, "st_tun_on") => "TUN オン",
            (Lang::Zh, "st_tun_off") => "TUN 已关闭",
            (Lang::En, "st_tun_off") => "TUN off",
            (Lang::Ja, "st_tun_off") => "TUN オフ",
            (Lang::Zh, "st_sniff_on") => "嗅探已开启",
            (Lang::En, "st_sniff_on") => "Sniffer on",
            (Lang::Ja, "st_sniff_on") => "スニファ オン",
            (Lang::Zh, "st_sniff_off") => "嗅探已关闭",
            (Lang::En, "st_sniff_off") => "Sniffer off",
            (Lang::Ja, "st_sniff_off") => "スニファ オフ",
            (Lang::Zh, "st_ipv6_on") => "IPv6 解析已开启",
            (Lang::En, "st_ipv6_on") => "IPv6 resolution on",
            (Lang::Ja, "st_ipv6_on") => "IPv6 解決オン",
            (Lang::Zh, "st_ipv6_off") => "IPv6 解析已关闭",
            (Lang::En, "st_ipv6_off") => "IPv6 resolution off",
            (Lang::Ja, "st_ipv6_off") => "IPv6 解決オフ",
            (Lang::Zh, "st_dns_on") => "DNS 已开启",
            (Lang::En, "st_dns_on") => "DNS on",
            (Lang::Ja, "st_dns_on") => "DNS オン",
            (Lang::Zh, "st_dns_off") => "DNS 已关闭",
            (Lang::En, "st_dns_off") => "DNS off",
            (Lang::Ja, "st_dns_off") => "DNS オフ",
            (Lang::Zh, "st_dns_missing") => "配置里没有 dns 块 · 按 o 打开片段库",
            (Lang::En, "st_dns_missing") => "No dns block · o opens snippets",
            (Lang::Ja, "st_dns_missing") => "dns ブロックがありません · o でスニペット",
            (Lang::Zh, "st_dns_empty") => "先输入要查询的域名",
            (Lang::En, "st_dns_empty") => "Type a name to look up",
            (Lang::Ja, "st_dns_empty") => "検索する名前を入力してください",
            (Lang::Zh, "st_dns_lookup") => "正在查询 DNS…",
            (Lang::En, "st_dns_lookup") => "Looking up DNS…",
            (Lang::Ja, "st_dns_lookup") => "DNS 照会中…",
            (Lang::Zh, "st_dns_flushing") => "正在清空 DNS / Fake-IP 缓存…",
            (Lang::En, "st_dns_flushing") => "Flushing DNS / Fake-IP cache…",
            (Lang::Ja, "st_dns_flushing") => "DNS / Fake-IP キャッシュを消去中…",
            (Lang::Zh, "st_core_down") => "内核未运行 · 按 K 启动",
            (Lang::En, "st_core_down") => "Core is stopped · press K",
            (Lang::Ja, "st_core_down") => "コア停止中 · K で起動",
            (Lang::Zh, "st_saved_core_down") => "已写入配置 · 内核未运行，启动后生效",
            (Lang::En, "st_saved_core_down") => "Saved · applies when the core is running",
            (Lang::Ja, "st_saved_core_down") => "保存済み · コア起動後に反映",
            (Lang::Zh, "st_reloading") => "正在热重载配置…",
            (Lang::En, "st_reloading") => "Hot-reloading config…",
            (Lang::Ja, "st_reloading") => "設定を再読み込み中…",
            (Lang::Zh, "st_rule_off") => "规则已禁用",
            (Lang::En, "st_rule_off") => "Rule disabled",
            (Lang::Ja, "st_rule_off") => "ルールを無効化",
            (Lang::Zh, "st_rule_on") => "规则已恢复",
            (Lang::En, "st_rule_on") => "Rule enabled",
            (Lang::Ja, "st_rule_on") => "ルールを有効化",
            (Lang::Zh, "st_rule_fail") => "规则切换失败",
            (Lang::En, "st_rule_fail") => "Rule toggle failed",
            (Lang::Ja, "st_rule_fail") => "ルール切替に失敗",
            (Lang::Zh, "st_no_provider") => "没有可刷新的 Provider",
            (Lang::En, "st_no_provider") => "No providers to refresh",
            (Lang::Ja, "st_no_provider") => "更新するプロバイダがありません",
            (Lang::Zh, "st_provider_busy") => "正在更新",
            (Lang::En, "st_provider_busy") => "Updating",
            (Lang::Ja, "st_provider_busy") => "更新中",
            (Lang::Zh, "st_provider_all") => "正在更新全部 Provider…",
            (Lang::En, "st_provider_all") => "Updating every provider…",
            (Lang::Ja, "st_provider_all") => "全プロバイダを更新中…",
            (Lang::Zh, "st_provider_health") => "已发起健康检查",
            (Lang::En, "st_provider_health") => "Health check started",
            (Lang::Ja, "st_provider_health") => "ヘルスチェック開始",
            (Lang::Zh, "st_provider_rule") => "规则 Provider 没有延迟健康检查",
            (Lang::En, "st_provider_rule") => "Rule providers have no latency check",
            (Lang::Ja, "st_provider_rule") => "ルールプロバイダに遅延検査はありません",
            (Lang::Zh, "st_module_on") => "片段已叠加",
            (Lang::En, "st_module_on") => "Snippet applied",
            (Lang::Ja, "st_module_on") => "スニペットを適用",
            (Lang::Zh, "st_module_off") => "片段已移除",
            (Lang::En, "st_module_off") => "Snippet removed",
            (Lang::Ja, "st_module_off") => "スニペットを解除",
            (Lang::Zh, "st_profile") => "配置已切换",
            (Lang::En, "st_profile") => "Profile switched",
            (Lang::Ja, "st_profile") => "プロファイルを切替",
            (Lang::Zh, "st_profile_saved") => "已保存配置副本",
            (Lang::En, "st_profile_saved") => "Saved profile copy",
            (Lang::Ja, "st_profile_saved") => "プロファイルを保存",
            (Lang::Zh, "st_probe_empty") => "输入域名或 URL 后再探测",
            (Lang::En, "st_probe_empty") => "Type a host or URL first",
            (Lang::Ja, "st_probe_empty") => "ホストか URL を入力してください",
            (Lang::Zh, "st_probe_busy") => "正在探测",
            (Lang::En, "st_probe_busy") => "Probing",
            (Lang::Ja, "st_probe_busy") => "計測中",
            (Lang::Zh, "st_no_wg") => "当前配置没有 WireGuard / Tailscale 出站",
            (Lang::En, "st_no_wg") => "No WireGuard or Tailscale outbound",
            (Lang::Ja, "st_no_wg") => "WireGuard / Tailscale の出口がありません",
            (Lang::Zh, "st_wg_test") => "正在测试 WireGuard 出站…",
            (Lang::En, "st_wg_test") => "Testing WireGuard outbounds…",
            (Lang::Ja, "st_wg_test") => "WireGuard 出口を計測中…",
            (Lang::Zh, "mod_tun") => "TUN 路由",
            (Lang::En, "mod_tun") => "TUN route",
            (Lang::Ja, "mod_tun") => "TUN ルート",
            (Lang::Zh, "mod_tun_desc") => "mixed 栈、自动路由、劫持 53 端口",
            (Lang::En, "mod_tun_desc") => "Mixed stack, auto-route, hijack port 53",
            (Lang::Ja, "mod_tun_desc") => "mixed スタック、自動ルート、53 番を劫持",
            (Lang::Zh, "mod_sniffer") => "流量嗅探",
            (Lang::En, "mod_sniffer") => "Sniffer",
            (Lang::Ja, "mod_sniffer") => "スニファ",
            (Lang::Zh, "mod_sniffer_desc") => "解析 HTTP / TLS / QUIC 里的域名",
            (Lang::En, "mod_sniffer_desc") => "Recover hosts from HTTP, TLS, and QUIC",
            (Lang::Ja, "mod_sniffer_desc") => "HTTP / TLS / QUIC からホストを復元",
            (Lang::Zh, "mod_dns_fakeip") => "Fake-IP DNS",
            (Lang::En, "mod_dns_fakeip") => "Fake-IP DNS",
            (Lang::Ja, "mod_dns_fakeip") => "Fake-IP DNS",
            (Lang::Zh, "mod_dns_fakeip_desc") => "开启 DNS，使用 Fake-IP 与 DoH",
            (Lang::En, "mod_dns_fakeip_desc") => "Enable DNS with Fake-IP and DoH",
            (Lang::Ja, "mod_dns_fakeip_desc") => "Fake-IP と DoH で DNS を有効化",
            (Lang::Zh, "mod_find_process") => "进程名",
            (Lang::En, "mod_find_process") => "Process name",
            (Lang::Ja, "mod_find_process") => "プロセス名",
            (Lang::Zh, "mod_find_process_desc") => "连接上始终带上进程名",
            (Lang::En, "mod_find_process_desc") => "Attach a process name to every connection",
            (Lang::Ja, "mod_find_process_desc") => "接続にプロセス名を付与",
            (Lang::Zh, "mod_tcp_concurrent") => "并发连接",
            (Lang::En, "mod_tcp_concurrent") => "TCP concurrent",
            (Lang::Ja, "mod_tcp_concurrent") => "TCP 同時接続",
            (Lang::Zh, "mod_tcp_concurrent_desc") => "同时握手，取最快的一条",
            (Lang::En, "mod_tcp_concurrent_desc") => "Race TCP handshakes and keep the fastest",
            (Lang::Ja, "mod_tcp_concurrent_desc") => "TCP ハンドシェイクを競合させる",
            (Lang::Zh, "mod_ipv6") => "IPv6",
            (Lang::En, "mod_ipv6") => "IPv6",
            (Lang::Ja, "mod_ipv6") => "IPv6",
            (Lang::Zh, "mod_ipv6_desc") => "允许解析 AAAA",
            (Lang::En, "mod_ipv6_desc") => "Allow AAAA answers",
            (Lang::Ja, "mod_ipv6_desc") => "AAAA の解決を許可",
            (Lang::Zh, "help_tun") => "开关 TUN / 嗅探 / IPv6，立即生效并写回配置",
            (Lang::En, "help_tun") => "Toggle TUN, the sniffer, and IPv6",
            (Lang::Ja, "help_tun") => "TUN / スニファ / IPv6 を切替",
            (Lang::Zh, "help_sniff") => "开关嗅探",
            (Lang::En, "help_sniff") => "Toggle the sniffer",
            (Lang::Ja, "help_sniff") => "スニファを切替",
            (Lang::Zh, "help_ipv6") => "开关 IPv6 解析",
            (Lang::En, "help_ipv6") => "Toggle IPv6 resolution",
            (Lang::Ja, "help_ipv6") => "IPv6 解決を切替",
            (Lang::Zh, "help_dns_key") => "开关配置中的 DNS，并热重载",
            (Lang::En, "help_dns_key") => "Toggle dns.enable and hot-reload",
            (Lang::Ja, "help_dns_key") => "dns.enable を切替して再読込",
            (Lang::Zh, "help_views") => "DNS / 规则 / Provider / 片段 / 配置 / 探测 / 运行时",
            (Lang::En, "help_views") => "DNS / rules / providers / snippets / profiles / probe / runtime",
            (Lang::Ja, "help_views") => "DNS / ルール / プロバイダ / スニペット / プロファイル / 計測 / 状態",
            (Lang::Zh, "help_rule_x") => "禁用或恢复当前规则（连接页仍是断开连接）",
            (Lang::En, "help_rule_x") => "Disable or restore the selected rule",
            (Lang::Ja, "help_rule_x") => "選択中のルールを無効化 / 復帰",
            (Lang::Zh, "help_flush") => "DNS 清空缓存；规则与 Provider 页刷新",
            (Lang::En, "help_flush") => "Flush DNS, or refresh rules and providers",
            (Lang::Ja, "help_flush") => "DNS 消去、またはルールとプロバイダを更新",
            (Lang::Zh, "help_explain") => "输入目标，解释会命中哪条规则",
            (Lang::En, "help_explain") => "Type a target and explain which rule hits",
            (Lang::Ja, "help_explain") => "対象を入力して一致ルールを説明",
            (Lang::Zh, "ov_modules") => "片段会追加到配置末尾，关闭后恢复原文",
            (Lang::En, "ov_modules") => "Snippets append to the config and restore it when removed",
            (Lang::Ja, "ov_modules") => "スニペットは末尾に追加され、外すと元に戻ります",
            (Lang::Zh, "ov_profiles") => "Enter 切换并热重载 · c 保存当前副本 · r 重载",
            (Lang::En, "ov_profiles") => "Enter switches and reloads · c saves a copy · r reloads",
            (Lang::Ja, "ov_profiles") => "Enter で切替 · c で複製 · r で再読込",
            (Lang::Zh, "ov_probe") => "对当前节点做 DNS 查询和延迟测试",
            (Lang::En, "ov_probe") => "DNS lookup plus a latency test of the selected node",
            (Lang::Ja, "ov_probe") => "選択中ノードの DNS と遅延を計測",
            (Lang::Zh, "ov_runtime") => "TUN、进程查找，以及 WireGuard 出站",
            (Lang::En, "ov_runtime") => "TUN, process lookup, and WireGuard outbounds",
            (Lang::Ja, "ov_runtime") => "TUN、プロセス検索、WireGuard 出口",
            (Lang::Zh, "no_rules") => "还没有规则 · 内核运行后按 F 刷新",
            (Lang::En, "no_rules") => "No rules yet · F refreshes once the core is up",
            (Lang::Ja, "no_rules") => "ルールがありません · コア起動後に F で更新",
            (Lang::Zh, "no_providers") => "没有 Provider",
            (Lang::En, "no_providers") => "No providers",
            (Lang::Ja, "no_providers") => "プロバイダがありません",
            (Lang::Zh, "explain_match") => "命中",
            (Lang::En, "explain_match") => "MATCH",
            (Lang::Ja, "explain_match") => "一致",
            (Lang::Zh, "explain_partial") => "内核仍会先判断未展开的 GEOSITE / 规则集",
            (Lang::En, "explain_partial") => "Core still evaluates GEOSITE / rule-set before this",
            (Lang::Ja, "explain_partial") => "コアは GEOSITE / ルールセットを先に評価します",
            (Lang::Zh, "explain_none") => "没有命中",
            (Lang::En, "explain_none") => "No match",
            (Lang::Ja, "explain_none") => "一致なし",
            (Lang::Zh, "dns_query") => "查询",
            (Lang::En, "dns_query") => "Query",
            (Lang::Ja, "dns_query") => "照会",
            (Lang::Zh, "dns_status") => "解析状态",
            (Lang::En, "dns_status") => "Resolver",
            (Lang::Ja, "dns_status") => "リゾルバ",
            _ => "",
        }
    }
}

fn mask_url(url: &str) -> String {
    let without_scheme = url.split_once("://").map(|(_, rest)| rest).unwrap_or(url);
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(without_scheme);
    let host: String = host
        .chars()
        .filter(|c| !c.is_control() && !c.is_whitespace())
        .collect();
    if host.chars().count() > 34 {
        format!("{}…", host.chars().take(34).collect::<String>())
    } else if host.is_empty() {
        "set".to_string()
    } else {
        host
    }
}

fn main() -> io::Result<()> {
    if matches!(env::args().nth(1).as_deref(), Some("--version" | "-V")) {
        println!("terc {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let config = Config::load();
    let mut app = App::new(config);
    run(&mut app)
}

fn run(app: &mut App) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableBracketedPaste)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run_app(&mut terminal, app);
    app.stop_flag.store(true, Ordering::Relaxed);
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableBracketedPaste,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    result
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> io::Result<()> {
    let mut last_tick = Instant::now();

    loop {
        app.drain_events();
        execute!(terminal.backend_mut(), BeginSynchronizedUpdate)?;
        let draw_res = terminal.draw(|frame| draw(frame, app)).map(|_| ());
        let sync_res = execute!(terminal.backend_mut(), EndSynchronizedUpdate);
        draw_res?;
        sync_res?;

        let tick_rate = app.frame_duration();
        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_millis(0));

        if event::poll(timeout)? {
            match event::read()? {
                CEvent::Key(key) => {
                    if handle_key(app, key) {
                        return Ok(());
                    }
                }
                CEvent::Paste(text) => {
                    if app.screen == Screen::Setup && app.setup_phase == SetupPhase::Editing {
                        app.setup_editor.insert(&text);
                    } else if app.screen == Screen::Dashboard && app.overlay == Overlay::Probe {
                        app.probe_editor.insert(&text);
                    } else if app.screen == Screen::Dashboard
                        && app.main_tab == MainTab::Dns
                        && app.dns_editing
                    {
                        app.dns_editor.insert(&text);
                    } else if app.screen == Screen::Dashboard
                        && app.main_tab == MainTab::Rules
                        && app.rule_editing
                    {
                        app.rule_query.insert(&text);
                        app.rule_index = 0;
                    }
                }
                _ => {}
            }
        }

        let elapsed = last_tick.elapsed();
        if elapsed >= tick_rate {
            app.tick(elapsed);
            last_tick = Instant::now();
        }
    }
}

fn needs_setup_state(subscription_url: &str, core_running: bool, config_exists: bool) -> bool {
    subscription_url.trim().is_empty() && !core_running && !config_exists
}

/// Existing config opens the dashboard. First run (no subscription, core, or
/// config file) still opens Setup. There is no startup menu.
pub fn launch_screen(subscription_url: &str, core_running: bool, config_exists: bool) -> Screen {
    if needs_setup_state(subscription_url, core_running, config_exists) {
        Screen::Setup
    } else {
        Screen::Dashboard
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum EscStep {
    Quit,
    ClearQuery,
    Proxies,
}

fn dashboard_esc(tab: MainTab, rule_query_empty: bool) -> EscStep {
    if tab == MainTab::Rules && !rule_query_empty {
        EscStep::ClearQuery
    } else if tab != MainTab::Proxies {
        EscStep::Proxies
    } else {
        EscStep::Quit
    }
}

fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    match app.screen {
        Screen::Dashboard => handle_dashboard_key(app, key),
        Screen::Settings => handle_settings_key(app, key),
        Screen::Help => handle_help_key(app, key),
        Screen::Setup => handle_setup_key(app, key),
    }
}

fn handle_dashboard_key(app: &mut App, key: KeyEvent) -> bool {
    if app.overlay != Overlay::None {
        return handle_overlay_key(app, key);
    }
    if app.main_tab == MainTab::Dns && app.dns_editing {
        return handle_dns_edit_key(app, key);
    }
    if app.main_tab == MainTab::Rules && app.rule_editing {
        return handle_rule_edit_key(app, key);
    }
    match key.code {
        KeyCode::Char('q') => return true,
        KeyCode::Esc => match dashboard_esc(app.main_tab, app.rule_query.text.is_empty()) {
            EscStep::ClearQuery => {
                app.rule_query.clear();
                app.rule_index = 0;
            }
            EscStep::Proxies => app.main_tab = MainTab::Proxies,
            EscStep::Quit => return true,
        },
        KeyCode::Char(' ') => app.toggle_sysproxy(),
        KeyCode::Char('T') => app.toggle_tun(),
        KeyCode::Char('n') => app.toggle_sniffing(),
        KeyCode::Char('i') => app.toggle_ipv6(),
        KeyCode::Char('D') => app.toggle_dns(),
        KeyCode::Char('d') => app.main_tab = MainTab::Dns,
        KeyCode::Char('g') => app.main_tab = MainTab::Rules,
        KeyCode::Char('v') => app.main_tab = MainTab::Providers,
        KeyCode::Char('o') => app.open_modules(),
        KeyCode::Char('f') => app.open_profiles(),
        KeyCode::Char('b') => app.open_probe(),
        KeyCode::Char('w') => app.open_runtime(),
        KeyCode::Char('e') if app.main_tab == MainTab::Dns => app.dns_editing = true,
        KeyCode::Char('e') | KeyCode::Char('/') if app.main_tab == MainTab::Rules => {
            app.rule_editing = true;
        }
        KeyCode::Char('[') if app.main_tab == MainTab::Dns => app.cycle_dns_qtype(-1),
        KeyCode::Char(']') if app.main_tab == MainTab::Dns => app.cycle_dns_qtype(1),
        KeyCode::Char('F') => match app.main_tab {
            MainTab::Dns => app.flush_dns_cache(),
            MainTab::Rules => {
                app.refresh_snapshot_now();
                app.clamp_aux();
            }
            MainTab::Providers => app.refresh_all_providers(),
            _ => {}
        },
        KeyCode::Char('H') if app.main_tab == MainTab::Providers => {
            app.healthcheck_selected_provider()
        }
        KeyCode::Char('K') => app.toggle_core_service(),
        KeyCode::Char('m') => app.cycle_routing_mode(),
        KeyCode::Char('r') => app.test_current_group(),
        KeyCode::Char('a') => app.select_best_node_in_group(),
        KeyCode::Char('u') => {
            if app.config.controller.subscription_url.trim().is_empty() {
                app.open_setup(Screen::Dashboard);
            } else {
                update_subscription_async(app.config.controller.clone(), app.tx.clone());
            }
        }
        KeyCode::Char('t') => {
            app.config.settings.show_traffic = !app.config.settings.show_traffic;
            app.config.save();
        }
        KeyCode::Char('p') => app.main_tab = MainTab::Proxies,
        KeyCode::Char('c') => {
            app.main_tab = if app.main_tab == MainTab::Connections {
                MainTab::Proxies
            } else {
                MainTab::Connections
            };
        }
        KeyCode::Char('L') => {
            app.main_tab = if app.main_tab == MainTab::Logs {
                MainTab::Proxies
            } else {
                MainTab::Logs
            };
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            app.screen = Screen::Settings;
        }
        KeyCode::Char('?') => app.screen = Screen::Help,
        KeyCode::Char('1') => {
            app.main_tab = MainTab::Proxies;
            app.focus = FocusPane::Groups;
        }
        KeyCode::Char('2') => {
            app.main_tab = MainTab::Proxies;
            app.focus = FocusPane::Nodes;
        }
        KeyCode::Tab | KeyCode::Left | KeyCode::Right | KeyCode::Char('h') | KeyCode::Char('l')
            if app.main_tab == MainTab::Proxies =>
        {
            app.focus = match app.focus {
                FocusPane::Groups => FocusPane::Nodes,
                FocusPane::Nodes => FocusPane::Groups,
            };
        }
        KeyCode::Up | KeyCode::Char('k') => match app.main_tab {
            MainTab::Proxies => match app.focus {
                FocusPane::Groups => {
                    if !app.snapshot.groups.is_empty() {
                        app.group_index = app
                            .group_index
                            .checked_sub(1)
                            .unwrap_or(app.snapshot.groups.len() - 1);
                        app.sync_node_cursor_to_active();
                    }
                }
                FocusPane::Nodes => {
                    if let Some(g) = app.snapshot.groups.get(app.group_index) {
                        if !g.all.is_empty() {
                            app.node_index =
                                app.node_index.checked_sub(1).unwrap_or(g.all.len() - 1);
                        }
                    }
                }
            },
            MainTab::Connections => {
                if !app.snapshot.connections.is_empty() {
                    app.conn_index = app
                        .conn_index
                        .checked_sub(1)
                        .unwrap_or(app.snapshot.connections.len() - 1);
                }
            }
            MainTab::Logs | MainTab::Dns => {}
            MainTab::Rules => {
                let len = app.filtered_rule_indexes().len();
                if len > 0 {
                    app.rule_index = app.rule_index.checked_sub(1).unwrap_or(len - 1);
                }
            }
            MainTab::Providers => {
                if !app.snapshot.providers.is_empty() {
                    app.provider_index = app
                        .provider_index
                        .checked_sub(1)
                        .unwrap_or(app.snapshot.providers.len() - 1);
                }
            }
        },
        KeyCode::Down | KeyCode::Char('j') => match app.main_tab {
            MainTab::Proxies => match app.focus {
                FocusPane::Groups => {
                    if !app.snapshot.groups.is_empty() {
                        app.group_index = (app.group_index + 1) % app.snapshot.groups.len();
                        app.sync_node_cursor_to_active();
                    }
                }
                FocusPane::Nodes => {
                    if let Some(g) = app.snapshot.groups.get(app.group_index) {
                        if !g.all.is_empty() {
                            app.node_index = (app.node_index + 1) % g.all.len();
                        }
                    }
                }
            },
            MainTab::Connections => {
                if !app.snapshot.connections.is_empty() {
                    app.conn_index = (app.conn_index + 1) % app.snapshot.connections.len();
                }
            }
            MainTab::Logs | MainTab::Dns => {}
            MainTab::Rules => {
                let len = app.filtered_rule_indexes().len();
                if len > 0 {
                    app.rule_index = (app.rule_index + 1) % len;
                }
            }
            MainTab::Providers => {
                if !app.snapshot.providers.is_empty() {
                    app.provider_index = (app.provider_index + 1) % app.snapshot.providers.len();
                }
            }
        },
        KeyCode::Enter => match app.main_tab {
            MainTab::Proxies => match app.focus {
                FocusPane::Groups => app.focus = FocusPane::Nodes,
                FocusPane::Nodes => app.activate_selected_node(),
            },
            MainTab::Dns => app.submit_dns_query(),
            MainTab::Rules => app.explain_selected_rule(),
            MainTab::Providers => app.refresh_selected_provider(),
            MainTab::Connections | MainTab::Logs => {}
        },
        KeyCode::Char('x') if app.main_tab == MainTab::Rules => app.toggle_selected_rule(),
        KeyCode::Char('x') if app.main_tab == MainTab::Connections => {
            if let Some(c) = app.snapshot.connections.get(app.conn_index) {
                let id = c.id.clone();
                if close_connection(&app.config.controller, Some(&id)).is_ok() {
                    app.refresh_snapshot_now();
                }
            }
        }
        KeyCode::Char('X') if app.main_tab == MainTab::Connections => {
            if close_connection(&app.config.controller, None).is_ok() {
                app.refresh_snapshot_now();
            }
        }
        _ => {}
    }
    false
}

fn handle_overlay_key(app: &mut App, key: KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
        return true;
    }
    match app.overlay {
        Overlay::None => {}
        Overlay::Modules => match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('o') => app.close_overlay(),
            KeyCode::Up | KeyCode::Char('k') => {
                app.module_index = app
                    .module_index
                    .checked_sub(1)
                    .unwrap_or(app.catalog.len().saturating_sub(1));
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !app.catalog.is_empty() {
                    app.module_index = (app.module_index + 1) % app.catalog.len();
                }
            }
            KeyCode::Enter | KeyCode::Char(' ') => app.toggle_selected_module(),
            _ => {}
        },
        Overlay::Profiles => match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('f') => app.close_overlay(),
            KeyCode::Up | KeyCode::Char('k') => {
                app.profile_index = app
                    .profile_index
                    .checked_sub(1)
                    .unwrap_or(app.profiles.len().saturating_sub(1));
            }
            KeyCode::Down | KeyCode::Char('j') => {
                if !app.profiles.is_empty() {
                    app.profile_index = (app.profile_index + 1) % app.profiles.len();
                }
            }
            KeyCode::Enter => app.switch_selected_profile(),
            KeyCode::Char('c') => app.save_profile_copy(),
            KeyCode::Char('r') => app.reload_profile(),
            _ => {}
        },
        Overlay::Probe => {
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('u') | KeyCode::Char('w'))
            {
                app.probe_editor.clear();
                return false;
            }
            match key.code {
                KeyCode::Esc | KeyCode::Char('q') => app.close_overlay(),
                KeyCode::Enter => app.submit_probe(),
                KeyCode::Backspace => {
                    app.probe_editor.backspace();
                }
                KeyCode::Delete => {
                    app.probe_editor.delete();
                }
                KeyCode::Left => app.probe_editor.move_left(),
                KeyCode::Right => app.probe_editor.move_right(),
                KeyCode::Home => app.probe_editor.move_home(),
                KeyCode::End => app.probe_editor.move_end(),
                KeyCode::Char(ch) => {
                    app.probe_editor.insert(&ch.to_string());
                }
                _ => {}
            }
        }
        Overlay::Runtime => match key.code {
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('w') => app.close_overlay(),
            KeyCode::Up | KeyCode::Char('k') => {
                let len = app.wireguard_peers().len();
                if len > 0 {
                    app.tunnel_index = app.tunnel_index.checked_sub(1).unwrap_or(len - 1);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => {
                let len = app.wireguard_peers().len();
                if len > 0 {
                    app.tunnel_index = (app.tunnel_index + 1) % len;
                }
            }
            KeyCode::Enter | KeyCode::Char('r') => app.test_selected_tunnel(),
            KeyCode::Char('a') => app.test_all_tunnels(),
            _ => {}
        },
    }
    false
}

fn handle_dns_edit_key(app: &mut App, key: KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
        return true;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('u') | KeyCode::Char('w'))
    {
        app.dns_editor.clear();
        return false;
    }
    match key.code {
        KeyCode::Esc => app.dns_editing = false,
        KeyCode::Enter => app.submit_dns_query(),
        KeyCode::Char('F') => app.flush_dns_cache(),
        KeyCode::Char('[') => app.cycle_dns_qtype(-1),
        KeyCode::Char(']') => app.cycle_dns_qtype(1),
        KeyCode::Backspace => {
            app.dns_editor.backspace();
        }
        KeyCode::Delete => {
            app.dns_editor.delete();
        }
        KeyCode::Left => app.dns_editor.move_left(),
        KeyCode::Right => app.dns_editor.move_right(),
        KeyCode::Home => app.dns_editor.move_home(),
        KeyCode::End => app.dns_editor.move_end(),
        KeyCode::Char(ch) => {
            app.dns_editor.insert(&ch.to_string());
        }
        _ => {}
    }
    false
}

fn handle_rule_edit_key(app: &mut App, key: KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('c')) {
        return true;
    }
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('u') | KeyCode::Char('w'))
    {
        app.rule_query.clear();
        app.rule_index = 0;
        return false;
    }
    match key.code {
        KeyCode::Esc => app.rule_editing = false,
        KeyCode::Enter => {
            app.rule_editing = false;
            app.rule_index = 0;
            app.explain_selected_rule();
        }
        KeyCode::Backspace => {
            app.rule_query.backspace();
            app.rule_index = 0;
        }
        KeyCode::Delete => {
            app.rule_query.delete();
            app.rule_index = 0;
        }
        KeyCode::Left => app.rule_query.move_left(),
        KeyCode::Right => app.rule_query.move_right(),
        KeyCode::Home => app.rule_query.move_home(),
        KeyCode::End => app.rule_query.move_end(),
        KeyCode::Char(ch) => {
            app.rule_query.insert(&ch.to_string());
            app.rule_index = 0;
        }
        _ => {}
    }
    false
}

fn handle_settings_key(app: &mut App, key: KeyEvent) -> bool {
    let len = app.settings_rows().len();
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('s') | KeyCode::Char('S') => {
            app.screen = Screen::Dashboard;
        }
        KeyCode::Up | KeyCode::Char('k') => {
            app.setting_index = app.setting_index.checked_sub(1).unwrap_or(len - 1);
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.setting_index = (app.setting_index + 1) % len;
        }
        KeyCode::Left | KeyCode::Char('h') => app.adjust_setting(-1),
        KeyCode::Right | KeyCode::Char('l') | KeyCode::Enter => app.adjust_setting(1),
        KeyCode::Tab => {
            let rows = app.settings_rows();
            let cur_cat = rows
                .get(app.setting_index)
                .map(|r| r.category)
                .unwrap_or(SettingCategory::Core);
            let next_cat = match cur_cat {
                SettingCategory::Core => SettingCategory::Appearance,
                SettingCategory::Appearance => SettingCategory::Subscription,
                SettingCategory::Subscription => SettingCategory::Core,
            };
            if let Some(pos) = rows.iter().position(|r| r.category == next_cat) {
                app.setting_index = pos;
            }
        }
        _ => {}
    }
    false
}

fn handle_setup_key(app: &mut App, key: KeyEvent) -> bool {
    let editable = app.setup_phase == SetupPhase::Editing;
    if key.modifiers.contains(KeyModifiers::CONTROL) {
        match key.code {
            KeyCode::Char('c') | KeyCode::Char('q') => return true,
            KeyCode::Char('u') | KeyCode::Char('w') | KeyCode::Backspace if editable => {
                app.setup_editor.clear();
            }
            KeyCode::Char('d') => app.download_core(),
            _ => {}
        }
        return false;
    }

    match key.code {
        KeyCode::Esc => app.close_setup(),
        KeyCode::Enter if editable => app.submit_setup(),
        KeyCode::Backspace if editable => {
            app.setup_editor.backspace();
        }
        KeyCode::Delete if editable => {
            app.setup_editor.delete();
        }
        KeyCode::Left => app.setup_editor.move_left(),
        KeyCode::Right => app.setup_editor.move_right(),
        KeyCode::Home => app.setup_editor.move_home(),
        KeyCode::End => app.setup_editor.move_end(),
        KeyCode::Char(c) if editable => {
            app.setup_editor.insert(&c.to_string());
        }
        _ => {}
    }
    false
}

fn handle_help_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') | KeyCode::Enter => {
            app.screen = Screen::Dashboard;
        }
        _ => {}
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::{buffer::Buffer, layout::Rect, text::Line, widgets::Widget};
    use ui::Panel;

    #[test]
    fn panel_renders_rounded_btop_style_title_cutout() {
        let th = theme(ThemeId::Spring);
        let area = Rect::new(0, 0, 24, 5);
        let mut buf = Buffer::empty(area);
        Panel::new(Some(Line::from("Groups")), th, false).render(area, &mut buf);

        assert_eq!(buf[(0, 0)].symbol(), "╭");
        assert_eq!(buf[(23, 0)].symbol(), "╮");
        assert_eq!(buf[(0, 4)].symbol(), "╰");
        assert_eq!(buf[(23, 4)].symbol(), "╯");
        assert_eq!(buf[(2, 0)].symbol(), "┐");
        assert_eq!(buf[(9, 0)].symbol(), "┌");
    }

    #[test]
    fn themes_match_terb_palettes() {
        let spring = theme(ThemeId::Spring);
        assert_eq!(spring.border, ratatui::style::Color::Rgb(186, 223, 219));
        assert_eq!(spring.accent, ratatui::style::Color::Rgb(255, 164, 164));

        let vintage = theme(ThemeId::Vintage);
        assert_eq!(vintage.border, ratatui::style::Color::Rgb(96, 116, 86));
    }

    #[test]
    fn line_editor_edits_by_char_not_byte() {
        let mut ed = LineEditor::default();
        ed.insert("https://例子.test/feed");
        assert_eq!(ed.cursor, 20);
        for _ in 0..5 {
            ed.move_left();
        }
        assert_eq!(ed.cursor, 15);
        ed.insert("X");
        assert_eq!(ed.text, "https://例子.testX/feed");
        assert!(ed.backspace());
        assert_eq!(ed.text, "https://例子.test/feed");
        ed.move_home();
        assert!(ed.delete());
        assert_eq!(ed.text, "ttps://例子.test/feed");
    }

    #[test]
    fn line_editor_strips_whitespace_and_control_from_paste() {
        let mut ed = LineEditor::default();
        assert!(!ed.insert(" \n\t"));
        ed.insert("https://a.test/feed\r\n");
        assert_eq!(ed.text, "https://a.test/feed");
        ed.clear();
        assert!(ed.text.is_empty() && ed.cursor == 0);
    }

    #[test]
    fn line_editor_clamps_cursor_at_both_ends() {
        let mut ed = LineEditor::default();
        ed.insert("abc");
        ed.move_end();
        ed.move_right();
        assert_eq!(ed.cursor, 3);
        ed.move_home();
        ed.move_left();
        assert_eq!(ed.cursor, 0);
        assert!(!ed.backspace());
    }

    #[test]
    fn mask_url_hides_token_query() {
        assert_eq!(
            mask_url("https://sub.example.com:8443/link/SECRET-TOKEN?x=1"),
            "sub.example.com:8443"
        );
        assert_eq!(mask_url("http://a.test/feed"), "a.test");
        assert_eq!(mask_url(""), "set");
    }

    #[test]
    fn default_config_ships_no_subscription() {
        let cfg = Config::default();
        assert!(cfg.controller.subscription_url.is_empty());
        assert_eq!(cfg.controller.addr, "127.0.0.1:9090");
        assert!(cfg.enabled_modules.is_empty());
    }

    #[test]
    fn older_config_json_still_loads() {
        let raw = r#"{
            "settings": {
                "lang": "en",
                "theme": "mono",
                "renderer": "blocks",
                "refresh_hz": 30,
                "show_traffic": false,
                "show_toolbar": true
            },
            "controller": {
                "addr": "127.0.0.1:9090",
                "secret": "",
                "config_dir": "/tmp/terc",
                "subscription_url": "https://example.com/sub",
                "test_url": "http://www.gstatic.com/generate_204",
                "timeout_ms": 4000
            }
        }"#;
        let cfg: Config = serde_json::from_str(raw).unwrap();
        assert_eq!(cfg.controller.subscription_url, "https://example.com/sub");
        assert!(cfg.enabled_modules.is_empty());
        assert!(cfg.active_profile.is_empty());
        assert_eq!(cfg.settings.theme, ThemeId::Mono);
    }

    #[test]
    fn existing_config_lands_on_dashboard() {
        assert_eq!(
            launch_screen("https://example.com/sub", false, true),
            Screen::Dashboard
        );
        assert_eq!(launch_screen("", false, true), Screen::Dashboard);
        assert_eq!(launch_screen("", true, false), Screen::Dashboard);
        assert_eq!(launch_screen("  ", false, false), Screen::Setup);
    }

    #[test]
    fn dashboard_esc_quits_from_proxies_and_steps_back_elsewhere() {
        assert_eq!(dashboard_esc(MainTab::Proxies, true), EscStep::Quit);
        assert_eq!(dashboard_esc(MainTab::Rules, false), EscStep::ClearQuery);
        assert_eq!(dashboard_esc(MainTab::Rules, true), EscStep::Proxies);
        assert_eq!(dashboard_esc(MainTab::Providers, true), EscStep::Proxies);
        assert_eq!(dashboard_esc(MainTab::Dns, true), EscStep::Proxies);
    }
}
