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

pub mod best;
pub mod compose;
mod conns;
pub mod control;
mod guard;
pub mod manage;
pub mod mihomo;
pub mod ops;
pub mod panels;
mod privilege;
pub mod proxy_form;
pub mod routing;
mod settings;
pub mod storage;
pub mod subconv;
pub mod ui;
mod ws;

use crossterm::{
    event::{
        self, DisableBracketedPaste, DisableMouseCapture, EnableBracketedPaste, Event as CEvent,
        KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{
        disable_raw_mode, enable_raw_mode, BeginSynchronizedUpdate, EndSynchronizedUpdate,
        EnterAlternateScreen, LeaveAlternateScreen,
    },
};
use mihomo::{
    close_connection, config_file_exists, download_managed_core_async, fetch_snapshot,
    is_info_pseudo_node, select_group_node, set_sysproxy, spawn_stream_workers, start_core_service,
    stop_core_service, switch_routing_mode, test_group_delays_async, BackendEvent,
    ControllerConfig, CoreSnapshot,
};
use ratatui::prelude::{CrosstermBackend, Terminal};
use serde::{Deserialize, Serialize};
use ui::{draw, theme, Theme, ThemeId, WaveRenderer, THEMES};

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
    Probe,
    Runtime,
    Best,
    OwnNodes,
    PrivateRules,
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
    Diagnostics,
}

#[derive(Clone, Debug)]
pub struct SettingRow {
    pub id: settings::SettingId,
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
    #[serde(default = "default_graph_interval")]
    // Retain the previous seconds value when loading and re-saving an existing config.
    pub graph_interval_secs: u64,
    #[serde(default)]
    pub graph_interval_ms: Option<u64>,
    pub show_traffic: bool,
    pub show_toolbar: bool,
    /// Without a serde default an older config.json would fail to load and be
    /// replaced by `Config::default()` on the next save.
    #[serde(default = "default_true")]
    pub connections_stream: bool,
}

fn default_graph_interval() -> u64 {
    1
}

fn default_true() -> bool {
    true
}

impl Settings {
    pub fn graph_interval_ms(&self) -> u64 {
        self.graph_interval_ms
            .unwrap_or_else(|| self.graph_interval_secs.saturating_mul(1000))
            .clamp(1000, 86_400_000)
    }
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            lang: Lang::Zh,
            theme: ThemeId::Spring,
            renderer: WaveRenderer::Braille,
            refresh_hz: 60,
            graph_interval_secs: 1,
            graph_interval_ms: Some(1000),
            show_traffic: true,
            show_toolbar: true,
            connections_stream: true,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Config {
    pub settings: Settings,
    pub controller: ControllerConfig,
    #[serde(default)]
    pub enabled_modules: Vec<String>,
    #[serde(default, skip_serializing)]
    pub active_profile: String,
    #[serde(default, skip_serializing)]
    pub active_profile_label: String,
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
        if let Err(err) = cfg.save() {
            eprintln!("Cannot save preferences: {err}");
        }
        cfg
    }

    pub fn save(&self) -> Result<(), String> {
        self.save_to(&Self::path())
    }

    /// The file holds the controller secret and subscription URL, so only the
    /// user may read it.
    fn save_to(&self, path: &std::path::Path) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        crate::mihomo::write_private(path, json.as_bytes()).map_err(|e| e.to_string())
    }
}

/// Deliver a worker's completion event even when the worker panics, so
/// `snapshot_pending` and `action_busy` are always cleared.
struct SendOnDrop {
    tx: Sender<BackendEvent>,
    event: Option<BackendEvent>,
}

impl SendOnDrop {
    fn new(tx: Sender<BackendEvent>, fallback: BackendEvent) -> Self {
        Self {
            tx,
            event: Some(fallback),
        }
    }

    fn set(&mut self, event: BackendEvent) {
        self.event = Some(event);
    }
}

impl Drop for SendOnDrop {
    fn drop(&mut self) {
        if let Some(event) = self.event.take() {
            let _ = self.tx.send(event);
        }
    }
}

#[cfg(test)]
mod io_tests {
    use super::*;

    #[test]
    #[cfg(unix)]
    fn saved_preferences_are_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = env::temp_dir().join(format!("terc-prefs-{}", std::process::id()));
        let path = dir.join("config.json");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&path, "{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let mut cfg = Config::default();
        cfg.controller.secret = "s3cret".into();
        cfg.save_to(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0);
        assert!(fs::read_to_string(&path).unwrap().contains("s3cret"));
        assert!(!dir.join("config.json.tmp").exists());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn panicking_worker_still_reports_completion() {
        let (tx, rx) = mpsc::channel();
        let worker = thread::spawn(move || {
            let mut done = SendOnDrop::new(tx, BackendEvent::SnapshotDone(Box::default()));
            if done.event.is_some() {
                panic!("fetch failed");
            }
            done.set(BackendEvent::StatusMessage {
                text: String::new(),
                is_error: false,
            });
        });
        assert!(worker.join().is_err());
        assert!(matches!(rx.try_recv(), Ok(BackendEvent::SnapshotDone(_))));

        let (tx, rx) = mpsc::channel();
        let mut done = SendOnDrop::new(tx, BackendEvent::SnapshotDone(Box::default()));
        done.set(BackendEvent::StatusMessage {
            text: "ok".into(),
            is_error: false,
        });
        drop(done);
        assert!(matches!(
            rx.try_recv(),
            Ok(BackendEvent::StatusMessage { .. })
        ));
        assert!(rx.try_recv().is_err());
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
        self.insert_text(&clean)
    }

    pub fn insert_text(&mut self, input: &str) -> bool {
        let clean: String = input.chars().filter(|c| !c.is_control()).collect();
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
    pub group_scroll: usize,
    pub node_scroll: usize,
    pub conn_index: usize,
    pub connection_detail: bool,
    pub detail_scroll: u16,
    pub conns: conns::Tracker,
    /// Indices into `snapshot.connections` in display order; `conn_index` points here.
    pub conn_view: Vec<usize>,
    pub conn_sort: conns::SortKey,
    pub conn_filter: bool,
    pub conn_closed_view: bool,
    pub closed_index: usize,
    pub session_toast_at: Option<Instant>,
    pub help_scroll: u16,
    pub logs_paused: bool,
    pub frozen_logs: Vec<(String, String)>,
    pub status_detail: bool,
    pub log_query: LineEditor,
    pub log_editing: bool,
    pub log_detail: bool,
    pub log_index: usize,
    pub pending_best_group: Option<(String, Option<String>)>,
    pub best_scope_index: usize,
    pub action_busy: bool,
    pub snapshot_pending: bool,
    pub setting_index: usize,
    pub setting_input: Option<String>,
    pub rule_index: usize,
    pub provider_index: usize,
    pub module_index: usize,
    pub profile_index: usize,
    pub profile_page: usize,
    pub routing_index: usize,
    pub routing_mode: String,
    pub routing_plans: Vec<routing::Entry>,
    pub settings_management: bool,
    pub proxy_form: Option<proxy_form::Form>,
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
    pub rule_explaining: bool,
    pub rule_target_editor: LineEditor,
    pub rule_detail: bool,
    pub explain: Option<crate::ops::ExplainReport>,
    pub probe_editor: LineEditor,
    pub probe_lines: Vec<String>,
    pub probe_error: bool,
    pub snapshot: CoreSnapshot,
    pub up_rate: u64,
    pub down_rate: u64,
    pub memory_inuse: u64,
    pub graph_elapsed: Duration,
    pub graph_samples: (f64, f64, u64),
    pub up_history: Vec<f32>,
    pub down_history: Vec<f32>,
    /// Bumped on every graph shift, so `run_app` sees one that repeats a value.
    pub graph_gen: u64,
    pub logs: Vec<(String, String)>,
    pub toast_started: Option<Instant>,
    pub toast_area: Option<ratatui::layout::Rect>,
    pub proxy_hits: Vec<(ratatui::layout::Rect, FocusPane, usize, usize)>,
    pub status_message: String,
    pub status_is_error: bool,
    pub tx: Sender<BackendEvent>,
    pub rx: Receiver<BackendEvent>,
    pub stop_flag: Arc<AtomicBool>,
    /// Switch shared with the `/connections` WebSocket worker.
    pub conn_stream: Arc<mihomo::ConnStream>,
    /// When the last pushed `/connections` snapshot arrived.
    pub conn_stream_at: Option<Instant>,
    /// Polls in a row that found the core not running.
    pub down_polls: u8,
    pub last_snapshot_poll: Instant,
    pub setup_origin: Screen,
    pub setup_editor: LineEditor,
    pub setup_phase: SetupPhase,
    pub setup_start_at: Instant,
    pub core_downloading: bool,
    pub own_nodes: Vec<crate::compose::ManualNode>,
    pub own_node_index: usize,
    pub private_rules: crate::compose::PrivateRules,
    pub private_rule_index: usize,
    pub manage_input: Option<crate::manage::ManageInput>,
    pub manage_editor: LineEditor,
    pub ai_picker: bool,
    pub ai_picker_index: usize,
    pub ai_picker_selected: Vec<String>,
    pub pending_regen: bool,
    /// An action that would cut sessions and was pressed once (`guard`).
    pub pending_confirm: Option<(guard::Disrupt, Instant)>,
}

impl App {
    pub fn new(config: Config) -> Self {
        let snapshot = fetch_snapshot(&config.controller);
        let mut app = Self::from_snapshot(config, snapshot);
        app.load_core_log();
        spawn_stream_workers(
            app.config.controller.addr.clone(),
            app.config.controller.secret.clone(),
            app.tx.clone(),
            app.stop_flag.clone(),
            app.conn_stream.clone(),
        );
        app
    }

    fn from_snapshot(config: Config, initial_snapshot: CoreSnapshot) -> Self {
        let (tx, rx) = mpsc::channel();
        let stop_flag = Arc::new(AtomicBool::new(false));
        let conn_stream = Arc::new(mihomo::ConnStream {
            enabled: AtomicBool::new(config.settings.connections_stream),
        });
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
            group_scroll: 0,
            node_scroll: 0,
            conn_index: 0,
            connection_detail: false,
            detail_scroll: 0,
            conns: conns::Tracker::default(),
            conn_view: (0..initial_snapshot.connections.len()).collect(),
            conn_sort: conns::SortKey::default(),
            conn_filter: false,
            conn_closed_view: false,
            closed_index: 0,
            session_toast_at: None,
            help_scroll: 0,
            logs_paused: false,
            frozen_logs: Vec::new(),
            status_detail: false,
            log_query: LineEditor::default(),
            log_editing: false,
            log_detail: false,
            log_index: 0,
            pending_best_group: None,
            best_scope_index: 0,
            action_busy: false,
            snapshot_pending: false,
            setting_index: 0,
            setting_input: None,
            rule_index: 0,
            provider_index: 0,
            module_index: 0,
            profile_index: 0,
            profile_page: 0,
            routing_index: 0,
            routing_mode: String::new(),
            routing_plans: Vec::new(),
            settings_management: false,
            proxy_form: None,
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
            rule_explaining: false,
            rule_target_editor: LineEditor::default(),
            rule_detail: false,
            explain: None,
            probe_editor: LineEditor::default(),
            probe_lines: Vec::new(),
            probe_error: false,
            snapshot: initial_snapshot,
            up_rate: 0,
            down_rate: 0,
            memory_inuse: 0,
            graph_elapsed: Duration::ZERO,
            graph_samples: (0.0, 0.0, 0),
            up_history: vec![0.0; HISTORY_LEN],
            down_history: vec![0.0; HISTORY_LEN],
            graph_gen: 0,
            logs: Vec::new(),
            toast_started: None,
            toast_area: None,
            proxy_hits: Vec::new(),
            status_message: String::new(),
            status_is_error: false,
            tx,
            rx,
            stop_flag,
            conn_stream,
            conn_stream_at: None,
            down_polls: 0,
            last_snapshot_poll: Instant::now(),
            setup_origin: Screen::Dashboard,
            setup_editor: LineEditor::default(),
            setup_phase: SetupPhase::Editing,
            setup_start_at: Instant::now(),
            core_downloading: false,
            own_nodes: Vec::new(),
            own_node_index: 0,
            private_rules: crate::compose::PrivateRules::default(),
            private_rule_index: 0,
            manage_input: None,
            manage_editor: LineEditor::default(),
            ai_picker: false,
            ai_picker_index: 0,
            ai_picker_selected: Vec::new(),
            pending_regen: false,
            pending_confirm: None,
        };
        app.routing_mode = routing::selected(&app.config.controller);
        app.routing_plans = routing::entries(&app.config.controller, app.lang() == Lang::Zh);
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
        if self.setup_phase != SetupPhase::Editing || self.action_busy || self.core_downloading {
            return;
        }
        if !self.core_binary_found() {
            self.set_status(self.t("setup_dl_hint"), true);
            return;
        }
        let url = self.setup_editor.trimmed();
        if url.is_empty() {
            self.set_status(self.t("setup_err_empty"), true);
            return;
        }
        let lower = url.to_ascii_lowercase();
        if !lower.starts_with("https://") && !lower.starts_with("http://") {
            // Not a subscription link: accept a pasted node (Surge line or URI).
            if crate::subconv::parse_node_line(url.lines().next().unwrap_or("")).is_err() {
                self.set_status(self.t("setup_err_scheme"), true);
                return;
            }
            let dir = crate::compose::profile_dir(&self.config.controller);
            let mut added = 0;
            let mut last_err = String::new();
            for line in url.lines().map(str::trim).filter(|l| !l.is_empty()) {
                match crate::compose::add_manual_node(&dir, line) {
                    Ok(_) => added += 1,
                    Err(err) => last_err = err,
                }
            }
            if added == 0 {
                self.set_status(&last_err, true);
                return;
            }
            self.setup_phase = SetupPhase::Fetching;
            self.setup_editor.clear();
            self.apply_composed();
            return;
        }
        let url = url.split_whitespace().next().unwrap_or("").to_string();
        self.config.controller.subscription_url = url;
        self.save_profile_source();
        self.save_preferences();
        self.setup_phase = SetupPhase::Fetching;
        self.update_subscription();
    }

    pub fn set_status(&mut self, text: &str, is_error: bool) {
        self.toast_started = Some(Instant::now());
        self.status_message = text.to_string();
        self.status_is_error = is_error;
    }

    pub fn save_preferences(&mut self) {
        if let Err(err) = self.config.save() {
            self.set_status(&format!("Could not save preferences: {err}"), true);
        }
    }

    pub fn toast_visible(&self) -> bool {
        !self.status_message.is_empty()
            && self.toast_started.is_some_and(|at| {
                at.elapsed() < Duration::from_secs(if self.status_is_error { 8 } else { 4 })
            })
    }

    pub fn clear_status(&mut self) {
        self.toast_started = None;
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
        self.setup_phase = SetupPhase::Starting;
        self.setup_start_at = Instant::now();
        self.run_action("Starting Mihomo…", None, None, |cfg| {
            start_core_service(&cfg)
        });
    }

    pub fn filtered_logs(&self) -> Vec<&(String, String)> {
        let source = if self.logs_paused {
            &self.frozen_logs
        } else {
            &self.logs
        };
        let query = self.log_query.text.to_lowercase();
        source
            .iter()
            .filter(|(level, text)| {
                query.is_empty()
                    || level.to_lowercase().contains(&query)
                    || text.to_lowercase().contains(&query)
            })
            .collect()
    }

    pub fn pause_logs(&mut self) {
        if !self.logs_paused {
            self.frozen_logs = self.logs.clone();
            self.logs_paused = true;
            self.log_index = self.filtered_logs().len().saturating_sub(1);
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

    /// Applies queued backend events. Returns whether any of them can change
    /// the screen: `/logs` sends a line per new connection, but only the live
    /// Logs tab shows them (a TUN failure still raises a toast).
    pub fn drain_events(&mut self) -> bool {
        let mut visible = false;
        while let Ok(ev) = self.rx.try_recv() {
            visible |= !matches!(ev, BackendEvent::Log { .. })
                || (self.screen == Screen::Dashboard
                    && self.main_tab == MainTab::Logs
                    && !self.logs_paused);
            match ev {
                BackendEvent::Traffic { up, down } => {
                    self.up_rate = up;
                    self.down_rate = down;
                    self.snapshot.running = true;
                    self.graph_samples.0 += up as f64;
                    self.graph_samples.1 += down as f64;
                    self.graph_samples.2 += 1;
                }
                BackendEvent::Memory { inuse } => {
                    self.memory_inuse = inuse;
                }
                BackendEvent::Log { level, payload } => {
                    if level.eq_ignore_ascii_case("error")
                        && payload.contains("Start TUN listening error")
                    {
                        self.set_status(
                            &format!("TUN 启动失败 / TUN startup failed: {payload}"),
                            true,
                        );
                    }
                    self.logs.push((level, payload));
                    if self.logs.len() > 300 {
                        self.logs.remove(0);
                    }
                }
                BackendEvent::ActionDone {
                    result,
                    modules,
                    profile,
                } => {
                    self.action_busy = false;
                    // The action thread fetches a snapshot next; skip the poll.
                    self.last_snapshot_poll = Instant::now();
                    self.conns.action_finished(Instant::now());
                    let ok = result.is_ok();
                    match &result {
                        Ok(text) => self.set_status(text, false),
                        Err(err) => {
                            self.set_status(err, true);
                            self.logs.push(("error".into(), err.clone()));
                            self.load_core_log();
                        }
                    }
                    if self.proxy_form.as_ref().is_some_and(|f| f.submitting) {
                        if ok {
                            self.proxy_form = None;
                        } else if let Some(f) = self.proxy_form.as_mut() {
                            f.submitting = false;
                        }
                    }
                    if ok {
                        if let Some(ids) = modules {
                            self.config.enabled_modules = ids;
                            self.save_preferences();
                        }
                        if let Some(name) = profile {
                            self.config.controller.profile_id = name.clone();
                            let source = crate::compose::ProfileSource::load(
                                &crate::compose::profile_dir(&self.config.controller),
                            );
                            self.config.controller.subscription_url = source.subscription_url;
                            self.config.active_profile_label = source.name;
                            self.config.active_profile = name;
                            self.group_index = 0;
                            self.node_index = 0;
                            self.group_scroll = 0;
                            self.node_scroll = 0;
                            self.save_preferences();
                            self.open_profiles();
                        }
                    }
                    self.routing_plans =
                        routing::entries(&self.config.controller, self.lang() == Lang::Zh);
                    self.routing_mode = routing::selected(&self.config.controller);
                    if self.settings_management || self.overlay == Overlay::OwnNodes {
                        self.own_nodes = crate::compose::load_manual_nodes(
                            &crate::compose::profile_dir(&self.config.controller),
                        );
                    }
                    if self.pending_regen {
                        self.pending_regen = false;
                        self.apply_composed();
                    }
                    if self.setup_phase == SetupPhase::Fetching {
                        self.finish_setup_fetch(ok);
                    } else if self.screen == Screen::Setup
                        && self.setup_phase == SetupPhase::Starting
                    {
                        if ok {
                            self.close_setup();
                        } else {
                            self.setup_phase = SetupPhase::Editing;
                        }
                    }
                }
                BackendEvent::Disrupting { cause, scope } => self.conns.note(cause, scope),
                // Live data: accepted even while an action runs.
                BackendEvent::Connections {
                    items,
                    upload_total,
                    download_total,
                } => {
                    self.conn_stream_at = Some(Instant::now());
                    self.snapshot.upload_total = upload_total;
                    self.snapshot.download_total = download_total;
                    self.install_connections(items, true);
                }
                BackendEvent::SnapshotDone(snap) => {
                    self.snapshot_pending = false;
                    if !self.action_busy {
                        self.accept_snapshot(*snap);
                    }
                }
                BackendEvent::Snapshot(snap) => {
                    self.accept_snapshot(*snap);
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
                    self.set_status(&format!("Latency test complete: {group}"), false);
                }
                BackendEvent::BestTestDone { group, results } => {
                    if self
                        .pending_best_group
                        .as_ref()
                        .is_some_and(|(name, _)| name == &group)
                    {
                        let (_, country) = self.pending_best_group.take().unwrap();
                        if let Some(index) =
                            self.snapshot.groups.iter().position(|g| g.name == group)
                        {
                            let previous_group = self.group_index;
                            let previous_node = self.node_index;
                            self.group_index = index;
                            self.select_best_node_in_group_after_test(country.as_deref(), &results);
                            if previous_group != index {
                                self.group_index = previous_group;
                                self.node_index = previous_node;
                            }
                        }
                    }
                }
                BackendEvent::StatusMessage { text, is_error } => {
                    self.set_status(&text, is_error);
                }
                BackendEvent::CoreDownloadDone { ok } => {
                    self.core_downloading = false;
                    if ok {
                        self.refresh_snapshot_now();
                    }
                }
            }
        }
        visible
    }

    pub fn advance_graph(&mut self, elapsed: Duration) {
        self.graph_elapsed += elapsed;
        if self.graph_elapsed < Duration::from_millis(self.config.settings.graph_interval_ms()) {
            return;
        }
        self.graph_elapsed = Duration::ZERO;
        let (up, down, count) = self.graph_samples;
        if count > 0 {
            self.up_history.remove(0);
            self.up_history.push((up / count as f64) as f32);
            self.down_history.remove(0);
            self.down_history.push((down / count as f64) as f32);
            self.graph_samples = (0.0, 0.0, 0);
            self.graph_gen = self.graph_gen.wrapping_add(1);
        }
    }

    pub fn tick(&mut self, elapsed: Duration) {
        self.advance_graph(elapsed);

        if self.screen == Screen::Setup
            && self.setup_phase == SetupPhase::Starting
            && self.setup_start_at.elapsed() >= Duration::from_secs(10)
        {
            self.setup_phase = SetupPhase::Editing;
            self.set_status(self.t("setup_msg_still_starting"), false);
        }

        if !self.action_busy
            && !self.snapshot_pending
            && self.last_snapshot_poll.elapsed() >= Duration::from_millis(2200)
        {
            self.snapshot_pending = true;
            self.last_snapshot_poll = Instant::now();
            let cfg = self.config.controller.clone();
            let tx = self.tx.clone();
            // Pushed snapshots already cover /connections; skip that GET.
            let include_connections = !self.stream_live();
            thread::spawn(move || {
                let mut done = SendOnDrop::new(tx, BackendEvent::SnapshotDone(Box::default()));
                let snap = mihomo::fetch_snapshot_with(&cfg, include_connections);
                done.set(BackendEvent::SnapshotDone(Box::new(snap)));
            });
        }
    }

    /// `/connections` pushes are arriving; a gap of 3 s (three missed pushes)
    /// hands the list back to HTTP polling.
    pub fn stream_live(&self) -> bool {
        self.conn_stream.enabled.load(Ordering::Relaxed)
            && self
                .conn_stream_at
                .is_some_and(|at| at.elapsed() < Duration::from_secs(3))
    }

    pub fn accept_snapshot(&mut self, mut snapshot: CoreSnapshot) {
        if self.snapshot.running && !snapshot.running {
            self.load_core_log();
        }
        // A poll may have started before the latest push: never let it replace
        // fresher pushed data or report sessions as closed.
        if self.stream_live() {
            snapshot.connections_ok = false;
        }
        let fresh = std::mem::take(&mut snapshot.connections);
        snapshot.connections = std::mem::take(&mut self.snapshot.connections);
        // A transient /connections failure while the core runs keeps the last
        // list, so its sessions are not reported as closed. One slow or failed
        // /version (load, a GC pause, waking from sleep) also reads as a stopped
        // core, so only a second such poll in a row, with no live push, ends it.
        self.down_polls = if snapshot.running {
            0
        } else {
            self.down_polls.saturating_add(1)
        };
        let doubtful_stop = !snapshot.running && (self.down_polls < 2 || self.stream_live());
        let keep = (snapshot.running && !snapshot.connections_ok) || doubtful_stop;
        if keep {
            snapshot.upload_total = self.snapshot.upload_total;
            snapshot.download_total = self.snapshot.download_total;
        }
        self.snapshot = snapshot;
        if !keep {
            self.install_connections(fresh, self.snapshot.running);
        }
        self.group_index = self
            .group_index
            .min(self.snapshot.groups.len().saturating_sub(1));
        self.clamp_aux();
    }

    fn install_connections(&mut self, mut list: Vec<mihomo::ConnectionItem>, running: bool) {
        let selected = self.selected_connection().map(|c| c.id.clone());
        let was_empty = self.conn_view.is_empty();
        let now_ms = conns::now_ms();
        let had_closed = !self.conns.closed().is_empty();
        if running {
            let (up, down) = (self.snapshot.upload_total, self.snapshot.download_total);
            self.conns.note_totals(up, down);
        }
        let closed = self
            .conns
            .observe(&mut list, running, Instant::now(), now_ms);
        self.snapshot.connections = list;
        self.rebuild_conn_view();
        // An expired selection stays empty until the user navigates again.
        self.reselect_connection(selected, was_empty);
        if closed.is_empty() {
            return;
        }
        // New entries go in front; keep the closed-view cursor on its entry.
        if had_closed {
            self.closed_index =
                (self.closed_index + closed.len()).min(self.conns.closed().len().saturating_sub(1));
        }
        let lang = self.lang();
        let age = |c: &conns::ClosedConn| c.lifetime_secs.map_or("—".into(), conns::fmt_age);
        if closed.len() > 5 {
            let level = if closed.iter().any(|c| c.ai) {
                "warning"
            } else {
                "info"
            };
            let payload = format!(
                "terc: {} long-lived/AI connections closed ({})",
                closed.len(),
                closed[0].describe(lang)
            );
            self.logs.push((level.into(), payload));
        } else {
            for c in &closed {
                let payload = format!(
                    "terc: closed {} after {} ↑{} ↓{} via {} ({})",
                    c.host,
                    age(c),
                    ui::format_bytes(c.upload),
                    ui::format_bytes(c.download),
                    if c.chains.is_empty() {
                        "—"
                    } else {
                        &c.chains
                    },
                    c.describe(lang)
                );
                let level = if c.ai { "warning" } else { "info" };
                self.logs.push((level.into(), payload));
            }
        }
        if self.logs.len() > 300 {
            self.logs.drain(..self.logs.len() - 300);
        }
        let quiet =
            |at: Option<Instant>| at.is_none_or(|at| at.elapsed() >= Duration::from_secs(30));
        if !self.action_busy && quiet(self.session_toast_at) && !self.toast_visible() {
            if let Some(c) = closed.iter().find(|c| c.ai && c.cause.is_none()) {
                let text = format!(
                    "{}: {} ({})",
                    self.t("conn_toast_ai_closed"),
                    conns::host_only(&c.host),
                    age(c)
                );
                self.set_status(&text, false);
                self.session_toast_at = Some(Instant::now());
            }
        }
    }

    pub fn rebuild_conn_view(&mut self) {
        let now_ms = conns::now_ms();
        let list = &self.snapshot.connections;
        let filter = self.conn_filter;
        self.conn_view.clear();
        self.conn_view
            .extend((0..list.len()).filter(|&i| !filter || conns::is_session(&list[i], now_ms)));
        match self.conn_sort {
            // mihomo.rs already sorts by total bytes.
            conns::SortKey::Bytes => {}
            conns::SortKey::Age => self
                .conn_view
                .sort_by_key(|&i| list[i].start_ms.filter(|&ms| ms > 0).unwrap_or(i64::MAX)),
            conns::SortKey::Rate => self.conn_view.sort_by_key(|&i| {
                std::cmp::Reverse(list[i].up_rate.saturating_add(list[i].down_rate))
            }),
        }
    }

    pub fn selected_connection(&self) -> Option<&mihomo::ConnectionItem> {
        self.conn_view
            .get(self.conn_index)
            .and_then(|&i| self.snapshot.connections.get(i))
    }

    /// Points `conn_index` back at `id`; a vanished or hidden one leaves no selection.
    fn reselect_connection(&mut self, id: Option<String>, was_empty: bool) {
        let list = &self.snapshot.connections;
        self.conn_index = id
            .and_then(|id| self.conn_view.iter().position(|&i| list[i].id == id))
            .unwrap_or(if was_empty { 0 } else { self.conn_view.len() });
    }

    pub fn refresh_snapshot_now(&mut self) {
        if self.snapshot_pending {
            return;
        }
        self.snapshot_pending = true;
        let cfg = self.config.controller.clone();
        let tx = self.tx.clone();
        thread::spawn(move || {
            let mut done = SendOnDrop::new(tx, BackendEvent::SnapshotDone(Box::default()));
            done.set(BackendEvent::SnapshotDone(Box::new(fetch_snapshot(&cfg))));
        });
    }

    pub fn run_action<F>(
        &mut self,
        label: &str,
        modules: Option<Vec<String>>,
        profile: Option<String>,
        action: F,
    ) where
        F: FnOnce(ControllerConfig) -> Result<String, String> + Send + 'static,
    {
        if self.action_busy {
            self.set_status("Another operation is still running", true);
            return;
        }
        self.action_busy = true;
        self.set_status(label, false);
        let cfg = self.config.controller.clone();
        let tx = self.tx.clone();
        thread::spawn(move || {
            mihomo::report_disruptions(tx.clone());
            let mut done = SendOnDrop::new(
                tx.clone(),
                BackendEvent::ActionDone {
                    result: Err("Operation failed unexpectedly".into()),
                    modules: None,
                    profile: None,
                },
            );
            let result = action(cfg.clone());
            done.set(BackendEvent::ActionDone {
                result,
                modules,
                profile,
            });
            drop(done);
            let _ = tx.send(BackendEvent::Snapshot(Box::new(fetch_snapshot(&cfg))));
        });
    }

    pub fn update_subscription(&mut self) {
        if self.screen != Screen::Setup && !self.confirm_disruption(guard::Disrupt::Reload) {
            return;
        }
        let catalog = crate::ops::module_catalog(&crate::ops::modules_dir(&PathBuf::from(
            env::var_os("HOME").unwrap_or_default(),
        )));
        let modules = crate::ops::enabled_snippets(&catalog, &self.config.enabled_modules);
        let running = self.snapshot.running;
        let zh = self.lang() == Lang::Zh;
        self.run_action(
            "Fetching and validating subscription…",
            None,
            None,
            move |cfg| mihomo::regenerate_config(&cfg, &modules, running, true, zh),
        );
    }

    pub fn sync_node_cursor_to_active(&mut self) {
        self.node_scroll = 0;
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
        self.run_action("Switching node…", None, None, move |cfg| {
            select_group_node(&cfg, &group_name, &node_name).map_err(|e| e.to_string())?;
            Ok(format!("{group_name} › {node_name}"))
        });
    }

    pub fn test_current_group(&mut self) {
        if self.pending_best_group.is_some() {
            self.set_status("优选测速进行中 / Best-node test is running", true);
            return;
        }
        let Some(group) = self.snapshot.groups.get(self.group_index).cloned() else {
            return;
        };
        self.set_status(
            &format!("Testing {} ({})...", group.name, group.all.len()),
            false,
        );
        test_group_delays_async(
            self.config.controller.clone(),
            group.name.clone(),
            group.all.clone(),
            self.tx.clone(),
        );
    }

    pub fn select_best_node_in_group(&mut self) {
        if self.pending_best_group.is_some() {
            self.set_status("优选测速进行中 / Best-node test is running", true);
            return;
        }
        self.overlay = Overlay::Best;
    }

    pub fn start_best_selection(&mut self) {
        let Some(group) = self.snapshot.groups.get(self.group_index) else {
            return;
        };
        if !group.kind.eq_ignore_ascii_case("selector") {
            self.set_status(
                "请选择可手动切换的策略组 / Select a manual Selector group",
                true,
            );
            return;
        }
        let country = if self.best_scope_index == 1 {
            match best::active_country(&self.snapshot, self.group_index) {
                Some(code) => Some(code),
                None => {
                    self.set_status("无法识别已连接节点的国家，请检查节点名称 / Cannot identify the active node's country", true);
                    return;
                }
            }
        } else {
            None
        };
        let candidates = best::candidates(&self.snapshot, self.group_index, country.as_deref());
        if candidates.is_empty() {
            self.set_status(
                "范围内没有可选代理节点 / No selectable proxy nodes in this scope",
                true,
            );
            return;
        }
        let group_name = group.name.clone();
        self.pending_best_group = Some((group_name.clone(), country));
        self.overlay = Overlay::None;
        self.set_status("正在测速并优选 / Testing candidates…", false);
        mihomo::test_best_delays_async(
            self.config.controller.clone(),
            group_name,
            candidates.into_iter().map(|(_, name)| name).collect(),
            self.tx.clone(),
        );
    }

    fn select_best_node_in_group_after_test(
        &mut self,
        country: Option<&str>,
        results: &[(String, Option<u16>)],
    ) {
        let candidates = best::candidates(&self.snapshot, self.group_index, country);
        let selected = best::fastest(&candidates, results);
        if let Some(index) = selected {
            self.node_index = index;
            self.activate_selected_node();
        } else {
            self.set_status("范围内没有可达节点 / No reachable node in this scope", true);
        }
    }

    pub fn toggle_sysproxy(&mut self) {
        let target = !self.snapshot.sysproxy_enabled;
        let ports = if target {
            if !self.snapshot.running {
                self.set_status("Start the core before enabling system proxy", true);
                return;
            }
            match mihomo::proxy_ports(&self.snapshot) {
                Ok(p) => p,
                Err(e) => {
                    self.set_status(&e, true);
                    return;
                }
            }
        } else {
            (0, 0)
        };
        self.run_action("Updating system proxy…", None, None, move |_| {
            set_sysproxy(target, ports.0, ports.1)
        });
    }

    pub fn cycle_routing_mode(&mut self) {
        let index = ROUTING_MODES
            .iter()
            .position(|m| m.eq_ignore_ascii_case(&self.snapshot.mode))
            .unwrap_or(0);
        let mode = ROUTING_MODES[(index + 1) % ROUTING_MODES.len()];
        if !self.snapshot.running {
            self.apply_core_setting("mode", mode.to_ascii_lowercase().into());
            return;
        }
        self.run_action("Switching routing mode…", None, None, move |cfg| {
            switch_routing_mode(&cfg, mode).map_err(|e| e.to_string())?;
            // A later reload applies the file's mode, so record the switch there.
            if config_file_exists(&cfg) {
                crate::mihomo::persist_mode(&cfg, &mode.to_ascii_lowercase())
                    .map_err(|e| format!("Routing mode › {mode}; not saved to config.yaml: {e}"))?;
            }
            Ok(format!("Routing mode › {mode}"))
        });
    }

    pub fn toggle_core_service(&mut self) {
        if self.snapshot.running && !self.confirm_disruption(guard::Disrupt::CoreStop) {
            return;
        }
        let running = self.snapshot.running
            || crate::privilege::managed_core(&self.config.controller).is_ok();
        self.run_action("Updating core service…", None, None, move |cfg| {
            if running {
                stop_core_service(&cfg)
            } else {
                start_core_service(&cfg)
            }
        });
    }

    pub fn set_graph_interval(&mut self, ms: u64) {
        self.config.settings.graph_interval_ms = Some(ms.clamp(1000, 86_400_000));
        self.graph_elapsed = Duration::ZERO;
        self.graph_samples = (0.0, 0.0, 0);
        self.up_history.fill(0.0);
        self.down_history.fill(0.0);
    }

    pub fn t(&self, key: &str) -> &'static str {
        match (self.config.settings.lang, key) {
            (Lang::Zh, "cat_diagnostics") => "排查工具",
            (_, "cat_diagnostics") => "Diagnostics",
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
            (Lang::Zh, "stopped") => "未运行 (s → 内核服务)",
            (Lang::En, "stopped") => "Stopped (s → Core service)",
            (Lang::Ja, "stopped") => "停止中 (s → Core service)",
            (Lang::Zh, "no_groups") => "暂无策略组",
            (Lang::En, "no_groups") => "No proxy groups",
            (Lang::Ja, "no_groups") => "グループなし",
            (Lang::Zh, "core_stopped_hint") => "Mihomo 内核未运行\n\n启动：设置 → 内核与代理 → 内核服务\n更新订阅 (u)：设置 → 订阅与分流 → 代理订阅\n（首次使用请按提示添加订阅）",
            (Lang::En, "core_stopped_hint") => "Mihomo core is stopped\n\nStart: Settings → Core & Proxy → Core service\nUpdate (u): Settings → Sources & Routing → Proxy subscriptions\n(first run: add a subscription there)",
            (Lang::Ja, "core_stopped_hint") => "Mihomo停止中\n\n起動：設定 → コア・プロキシ → Core service\n更新 (u)：設定 → サブスクリプション → Proxy subscriptions\n（初回は登録を追加）",
            (Lang::Zh, "no_connections") => "当前没有活跃连接",
            (Lang::En, "no_connections") => "No active connections",
            (Lang::Ja, "no_connections") => "アクティブな接続はありません",
            (Lang::Zh, "conn_sort_bytes") => "按流量",
            (Lang::En, "conn_sort_bytes") => "by bytes",
            (Lang::Ja, "conn_sort_bytes") => "転送量順",
            (Lang::Zh, "conn_sort_age") => "按时长",
            (Lang::En, "conn_sort_age") => "by age",
            (Lang::Ja, "conn_sort_age") => "経過時間順",
            (Lang::Zh, "conn_sort_rate") => "按速率",
            (Lang::En, "conn_sort_rate") => "by rate",
            (Lang::Ja, "conn_sort_rate") => "速度順",
            (Lang::Zh, "conn_filter_sessions") => "仅长连接/AI",
            (Lang::En, "conn_filter_sessions") => "long & AI only",
            (Lang::Ja, "conn_filter_sessions") => "長時間/AI のみ",
            (Lang::Zh, "conn_closed_title") => "最近断开的长连接/AI 连接",
            (Lang::En, "conn_closed_title") => "Recently closed long-lived & AI connections",
            (Lang::Ja, "conn_closed_title") => "最近切断された長時間/AI 接続",
            (Lang::Zh, "conn_closed_empty") => "还没有长连接或 AI 连接断开",
            (Lang::En, "conn_closed_empty") => "No long-lived or AI connection has closed yet",
            (Lang::Ja, "conn_closed_empty") => "長時間/AI 接続の切断はまだありません",
            (Lang::Zh, "conn_none_filtered") => "没有存活 60 秒以上或访问 AI 服务的连接（f 显示全部）",
            (Lang::En, "conn_none_filtered") => "No connection older than 60 s or to an AI service (f shows all)",
            (Lang::Ja, "conn_none_filtered") => "60 秒以上または AI サービスへの接続はありません（f で全表示）",
            (Lang::Zh, "conn_closed_note") => "Mihomo 不提供断开原因；原因由 terc 根据自己的操作推断",
            (Lang::En, "conn_closed_note") => "Mihomo reports no close reason; terc infers it from its own actions",
            (Lang::Ja, "conn_closed_note") => "Mihomo は切断理由を返しません。terc が自身の操作から推定します",
            (Lang::Zh, "conn_toast_ai_closed") => "AI 长连接已断开",
            (Lang::En, "conn_toast_ai_closed") => "AI session closed",
            (Lang::Ja, "conn_toast_ai_closed") => "AI 長時間接続が切断されました",
            (Lang::Zh, "conn_long_lived") => "长连接",
            (Lang::En, "conn_long_lived") => "long-lived",
            (Lang::Ja, "conn_long_lived") => "長時間接続",
            (Lang::Zh, "conn_ago") => "前",
            (Lang::En, "conn_ago") => "ago",
            (Lang::Ja, "conn_ago") => "前",
            (Lang::Zh, "help_conn_keys") => "连接：o 排序（流量/时长/速率）  f 仅长连接/AI  d 最近断开",
            (Lang::En, "help_conn_keys") => "Connections: o sort (bytes/age/rate)  f long & AI only  d recently closed",
            (Lang::Ja, "help_conn_keys") => "接続：o 並べ替え（転送量/経過時間/速度）  f 長時間/AI のみ  d 最近の切断",
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
            (Lang::Zh, "cat_sub") => "订阅与分流",
            (Lang::En, "cat_sub") => "Sources & Routing",
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
            (Lang::Zh, "desc_conn_stream") => "用 WebSocket 接收 Mihomo 每秒推送的连接列表，单连接速率更准；握手失败、数据过大或中断时自动改回 HTTP 轮询。",
            (Lang::En, "desc_conn_stream") => "Receive Mihomo's per-second connection list over WebSocket for more accurate per-connection rates; falls back to HTTP polling on handshake failure, oversized data or drops.",
            (Lang::Ja, "desc_conn_stream") => "Mihomo が毎秒送る接続一覧を WebSocket で受信し、接続ごとの速度をより正確にします。ハンドシェイク失敗・サイズ超過・切断時は自動で HTTP ポーリングに戻ります。",
            (Lang::Zh, "set_renderer") => "速率图样式",
            (Lang::En, "set_renderer") => "Rate Graph Style",
            (Lang::Ja, "set_renderer") => "グラフスタイル",
            (Lang::Zh, "desc_renderer") => "切换顶栏速率图样式：Braille（盲文点阵）或 Blocks（实心块），上下行以不同颜色分开展示。",
            (Lang::En, "desc_renderer") => "Switch traffic rate graph style: Braille or Blocks, with up/down drawn in separate colors.",
            (Lang::Ja, "desc_renderer") => "トラフィックグラフの描画スタイルを切り替えます。",
            (Lang::Zh, "set_graph_interval") => "图表更新间隔",
            (Lang::Ja, "set_graph_interval") => "グラフ更新間隔",
            (_, "set_graph_interval") => "Graph interval",
            (Lang::Zh, "desc_graph_interval") => "单位：毫秒。← → 每次调整 100 ms；Enter 输入任意整数，Enter 保存，Esc 取消。范围 1000–86400000 ms。Mihomo 流量数据通常每秒一份，更快重绘不会增加采样精度。图表取期间平均速率，修改后清空旧图。",
            (Lang::Ja, "desc_graph_interval") => "単位 ms。← →: 100 ms 刻み、Enter: 入力、Esc: キャンセル。1000–86400000 ms。Mihomo のサンプルは通常 1 秒ごとです。変更時に履歴を消去します。",
            (_, "desc_graph_interval") => "Milliseconds. Arrows adjust by 100 ms; Enter edits an integer, Enter saves, Esc cancels. Range: 1000–86400000 ms. Mihomo normally supplies one traffic sample per second. The graph averages incoming samples; changes clear history.",
            (Lang::Zh, "set_refresh") => "界面刷新率",
            (Lang::En, "set_refresh") => "Refresh Rate",
            (Lang::Ja, "set_refresh") => "リフレッシュレート",
            (Lang::Zh, "desc_refresh") => {
                "界面最高重绘频率（15 / 30 / 60 / 120 Hz）。画面无变化时不重绘。"
            }
            (Lang::En, "desc_refresh") => {
                "Maximum UI redraw rate (15 / 30 / 60 / 120 Hz). Nothing redraws while the screen is unchanged."
            }
            (Lang::Ja, "desc_refresh") => {
                "画面の最大再描画レート（15 / 30 / 60 / 120 Hz）。変化がないときは再描画しません。"
            }
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
            (Lang::Zh, "setup_step_sub") => "订阅或自有节点",
            (Lang::En, "setup_step_sub") => "Subscription or own node",
            (Lang::Ja, "setup_step_sub") => "サブスクまたは自前ノード",
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
            (Lang::Zh, "setup_input") => "订阅链接 / 节点",
            (Lang::En, "setup_input") => "Subscription URL / node",
            (Lang::Ja, "setup_input") => "サブスクリンク",
            (Lang::Zh, "setup_paste_hint") => "粘贴机场订阅链接（Clash / Surge / 节点列表都能识别），或直接粘贴一条自有节点：Surge 节点行或 ss:// 等链接（Ctrl+U 清空，Ctrl+D 下载内核）",
            (Lang::En, "setup_paste_hint") => "Paste a subscription link (Clash / Surge / URI lists all work) or one own node: a Surge proxy line or ss:// etc. (Ctrl+U clears, Ctrl+D downloads the core)",
            (Lang::Ja, "setup_paste_hint") => "リンクを貼り付け可能（Ctrl+U クリア、Ctrl+D でコア導入）",
            (Lang::Zh, "setup_keys") => "Enter 保存并启动内核  Esc 稍后再说",
            (Lang::En, "setup_keys") => "Enter saves & starts the core  Esc for later",
            (Lang::Ja, "setup_keys") => "Enter で保存して起動  Esc で後で",
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
            (Lang::Zh, "setup_err_scheme") => "需要 http(s) 订阅链接，或一条 Surge 节点行 / ss:// 等节点链接",
            (Lang::En, "setup_err_scheme") => "Enter an http(s) subscription link, or a Surge proxy line / ss:// style node link",
            (Lang::Ja, "setup_err_scheme") => "リンクは http:// または https:// で始めてください",
            (Lang::Zh, "setup_msg_saved") => "订阅已保存  内核未安装：按 Ctrl+D 下载，再按 Esc 返回，在 设置 → 内核与代理 → 内核服务 启动",
            (Lang::En, "setup_msg_saved") => "Subscription saved  no core binary: press Ctrl+D to download, then Esc and start it in Settings → Core & Proxy → Core service",
            (Lang::Ja, "setup_msg_saved") => "サブスク保存済み  コア未導入：Ctrl+D で導入後、Esc で戻り 設定 → コア・プロキシ → Core service で起動",
            (Lang::Zh, "setup_msg_starting") => "内核启动中，就绪后自动关闭本窗口…",
            (Lang::En, "setup_msg_starting") => "Starting core; this window closes once it answers…",
            (Lang::Ja, "setup_msg_starting") => "コア起動中。応答するとこの窓は閉じます…",
            (Lang::Zh, "setup_msg_start_failed") => "内核启动失败",
            (Lang::En, "setup_msg_start_failed") => "Core failed to start",
            (Lang::Ja, "setup_msg_start_failed") => "コア起動に失敗",
            (Lang::Zh, "setup_msg_still_starting") => "内核仍未响应  按 Ctrl+D 重新下载内核，或 Esc 查看日志",
            (Lang::En, "setup_msg_still_starting") => "Core still not answering  Ctrl+D re-downloads it, Esc shows the logs",
            (Lang::Ja, "setup_msg_still_starting") => "コアが応答しません  Ctrl+D で再導入、Esc でログ",
            (Lang::Zh, "help_space") => "开关系统代理。macOS 用 networksetup，Linux 用 GNOME gsettings",
            (Lang::En, "help_space") => "Toggle the system proxy (networksetup, or GNOME gsettings)",
            (Lang::Ja, "help_space") => "システムプロキシを切替（networksetup または GNOME gsettings）",
            (_, "help_hl") => "Switch focus between Groups [1] and Nodes [2]",
            (_, "help_jk") => "Navigate up / down in current list",
            (_, "help_enter") => "Activate highlighted node in current group",
            (_, "help_r") => "Concurrent URL latency test for current group",
            (Lang::Zh, "help_a") => "选择全球或当前国家范围，测速后优选",
            (_, "help_a") => "Choose all countries or current country, test and select fastest",
            (_, "help_m") => "Cycle routing mode (Rule / Global / Direct)",
            (Lang::Zh, "help_u") => "更新当前方案的订阅，保留来源规则与策略组，校验后重载",
            (_, "help_u") => "Update the active profile subscription; preserve source rules and groups, validate and reload",
            (_, "help_tabs") => "Switch view: [p] Proxies  [c] Connections  [L] Logs",
            (_, "help_t") => "Toggle top Traffic & Overview panels",
            (_, "help_s") => "Open Settings board (Core / Theme / Subscription)",
            (Lang::Zh, "help_q") => "退出 terc（后台内核继续运行）",
            (Lang::En, "help_q") => "Quit terc (background core stays running)",
            (Lang::Ja, "help_q") => "終了（バックグラウンドのコアは継続）",
            (Lang::Zh, "help_esc") => "返回节点页；退出请按 q。设置与帮助回面板",
            (Lang::En, "help_esc") => "Back to proxies; q quits. Settings and Help return here",
            (Lang::Ja, "help_esc") => "プロキシへ戻る。終了は q。設定とヘルプはパネルへ",
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
            (Lang::Zh, "st_dns_missing") => "配置里没有 dns 块  按 o 打开片段库",
            (Lang::En, "st_dns_missing") => "No dns block  o opens snippets",
            (Lang::Ja, "st_dns_missing") => "dns ブロックがありません  o でスニペット",
            (Lang::Zh, "st_dns_empty") => "先输入要查询的域名",
            (Lang::En, "st_dns_empty") => "Type a name to look up",
            (Lang::Ja, "st_dns_empty") => "検索する名前を入力してください",
            (Lang::Zh, "st_dns_lookup") => "正在查询 DNS…",
            (Lang::En, "st_dns_lookup") => "Looking up DNS…",
            (Lang::Ja, "st_dns_lookup") => "DNS 照会中…",
            (Lang::Zh, "st_dns_flushing") => "正在清空 DNS / Fake-IP 缓存…",
            (Lang::En, "st_dns_flushing") => "Flushing DNS / Fake-IP cache…",
            (Lang::Ja, "st_dns_flushing") => "DNS / Fake-IP キャッシュを消去中…",
            (Lang::Zh, "st_core_down") => "内核未运行  在 设置 → 内核与代理 → 内核服务 启动",
            (Lang::En, "st_core_down") => "Core is stopped  start it in Settings → Core & Proxy → Core service",
            (Lang::Ja, "st_core_down") => "コア停止中  設定 → コア・プロキシ → Core service で起動",
            (Lang::Zh, "st_saved_core_down") => "已写入配置  内核未运行，启动后生效",
            (Lang::En, "st_saved_core_down") => "Saved  applies when the core is running",
            (Lang::Ja, "st_saved_core_down") => "保存済み  コア起動後に反映",
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
            (Lang::Zh, "ov_profiles") => "Enter 切换并热重载  c 保存当前副本  r 重载",
            (Lang::En, "ov_profiles") => "Enter switches and reloads  c saves a copy  r reloads",
            (Lang::Ja, "ov_profiles") => "Enter で切替  c で複製  r で再読込",
            (Lang::Zh, "ov_probe") => "对当前节点做 DNS 查询和延迟测试",
            (Lang::En, "ov_probe") => "DNS lookup plus a latency test of the selected node",
            (Lang::Ja, "ov_probe") => "選択中ノードの DNS と遅延を計測",
            (Lang::Zh, "ov_runtime") => "TUN、进程查找，以及 WireGuard 出站",
            (Lang::En, "ov_runtime") => "TUN, process lookup, and WireGuard outbounds",
            (Lang::Ja, "ov_runtime") => "TUN、プロセス検索、WireGuard 出口",
            (Lang::Zh, "no_rules") => "还没有规则  内核运行后按 F 刷新",
            (Lang::En, "no_rules") => "No rules yet  F refreshes once the core is up",
            (Lang::Ja, "no_rules") => "ルールがありません  コア起動後に F で更新",
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
    let mut config = Config::load();
    // Migration problems are shown in the UI; legacy files stay untouched.
    let migration = storage::migrate(&mut config);
    let mut app = App::new(config);
    match migration {
        Ok(notes) if !notes.is_empty() => app.set_status(
            &format!(
                "迁移跳过 / Migration skipped / 移行スキップ: {}",
                notes.join("; ")
            ),
            true,
        ),
        Ok(_) => {}
        Err(err) => app.set_status(
            &format!("迁移失败 / Migration failed / 移行失敗: {err}"),
            true,
        ),
    }
    run(&mut app)
}

/// Click and wheel reports only (1000, in SGR 1006 encoding). crossterm's
/// `EnableMouseCapture` also asks for drag (1002) and any-motion (1003)
/// reports, which terc never handles and which woke the loop on every mouse
/// move. `DisableMouseCapture` on exit still clears all of them.
struct ClickMouse;

impl crossterm::Command for ClickMouse {
    fn write_ansi(&self, f: &mut impl std::fmt::Write) -> std::fmt::Result {
        f.write_str("\x1b[?1000h\x1b[?1006h")
    }
}

fn run(app: &mut App) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(
        stdout,
        EnterAlternateScreen,
        EnableBracketedPaste,
        ClickMouse
    )?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    let result = run_app(&mut terminal, app);
    app.stop_flag.store(true, Ordering::Relaxed);
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        DisableBracketedPaste,
        DisableMouseCapture,
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;
    result
}

/// Longest the loop blocks on input before it drains backend events again.
const IDLE_WAKE: Duration = Duration::from_millis(50);
/// Data repaints (pushes, polls, toasts) run at most this often; Mihomo
/// pushes once a second anyway.
const DATA_FRAME: Duration = Duration::from_millis(100);
/// Ages, "ago" columns and the Setup screen's config check change with time
/// alone.
const HEARTBEAT: Duration = Duration::from_secs(1);
/// Key repeats and pastes applied before one repaint.
const INPUT_BURST: usize = 64;

/// When `run_app` repaints: input at once (capped by `refresh_hz`), data at
/// most every `DATA_FRAME`, and nothing while the screen cannot have changed.
struct Redraw {
    input: bool,
    data: bool,
    last: Instant,
    toast: (bool, Option<Instant>),
    graph: u64,
}

impl Redraw {
    fn new(now: Instant) -> Self {
        Self {
            input: true,
            data: false,
            // Long enough ago that the first frame draws at once.
            last: now.checked_sub(HEARTBEAT).unwrap_or(now),
            toast: (false, None),
            graph: 0,
        }
    }

    fn pending(&self) -> bool {
        self.input || self.data
    }

    fn toast_of(app: &App) -> (bool, Option<Instant>) {
        (app.toast_visible(), app.toast_started)
    }

    /// Notes changes no event reports: a toast shown, replaced or expired, a
    /// graph shift, and the heartbeat.
    fn observe(&mut self, app: &App, now: Instant) {
        self.data |= Self::toast_of(app) != self.toast
            || app.graph_gen != self.graph
            || now.saturating_duration_since(self.last) >= HEARTBEAT;
    }

    /// Time since the last frame the pending change has to wait for.
    fn gap(&self, frame: Duration) -> Option<Duration> {
        if self.input {
            Some(frame)
        } else if self.data {
            Some(frame.max(DATA_FRAME))
        } else {
            None
        }
    }

    fn due(&self, now: Instant, frame: Duration) -> bool {
        self.gap(frame)
            .is_some_and(|gap| now.saturating_duration_since(self.last) >= gap)
    }

    /// How long the loop may wait for input before it has to look again.
    fn wait(&self, now: Instant, frame: Duration) -> Duration {
        let since = now.saturating_duration_since(self.last);
        self.gap(frame)
            .unwrap_or(HEARTBEAT)
            .saturating_sub(since)
            .min(IDLE_WAKE)
    }

    fn drawn(&mut self, app: &App, now: Instant) {
        self.input = false;
        self.data = false;
        self.last = now;
        self.toast = Self::toast_of(app);
        self.graph = app.graph_gen;
    }
}

fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut App) -> io::Result<()> {
    let mut last_tick = Instant::now();
    let mut redraw = Redraw::new(last_tick);
    // A mouse event read behind undrawn changes waits for the next frame: its
    // hit areas (proxy_hits, list scroll) come from the last draw.
    let mut held: Option<CEvent> = None;

    loop {
        redraw.data |= app.drain_events();
        let now = Instant::now();
        redraw.observe(app, now);
        let frame = app.frame_duration();
        if redraw.due(now, frame) || (held.is_some() && redraw.pending()) {
            execute!(terminal.backend_mut(), BeginSynchronizedUpdate)?;
            let draw_res = terminal.draw(|frame| draw(frame, app)).map(|_| ());
            let sync_res = execute!(terminal.backend_mut(), EndSynchronizedUpdate);
            draw_res?;
            sync_res?;
            redraw.drawn(app, Instant::now());
        }

        let mut next = match held.take() {
            Some(ev) => Some(ev),
            None if event::poll(redraw.wait(Instant::now(), frame))? => Some(event::read()?),
            None => None,
        };
        let mut applied = 0;
        while let Some(ev) = next.take() {
            if matches!(&ev, CEvent::Mouse(m) if mouse_acts(m.kind)) && redraw.pending() {
                held = Some(ev);
                break;
            }
            let burst = matches!(ev, CEvent::Key(_) | CEvent::Paste(_));
            match handle_event(app, ev) {
                Handled::Quit => return Ok(()),
                Handled::Changed => redraw.input = true,
                Handled::Unchanged => {}
            }
            applied += 1;
            // Key repeat and pastes coalesce into one frame; mouse events do
            // not, since each hit-tests against the frame before it.
            if burst && applied < INPUT_BURST && event::poll(Duration::ZERO)? {
                next = Some(event::read()?);
            }
        }

        let shown = (app.screen, app.setup_phase);
        app.tick(last_tick.elapsed());
        last_tick = Instant::now();
        redraw.data |= shown != (app.screen, app.setup_phase);
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Handled {
    Quit,
    Changed,
    Unchanged,
}

/// Mouse events terc acts on; release, drag and motion change nothing.
fn mouse_acts(kind: MouseEventKind) -> bool {
    matches!(
        kind,
        MouseEventKind::Down(_) | MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
    )
}

fn handle_event(app: &mut App, ev: CEvent) -> Handled {
    match ev {
        CEvent::Key(key) => {
            if handle_key(app, key) {
                return Handled::Quit;
            }
        }
        CEvent::Mouse(mouse) => {
            if !mouse_acts(mouse.kind) {
                return Handled::Unchanged;
            }
            if proxy_mouse_action(app, mouse) {
                app.activate_selected_node();
            }
        }
        CEvent::Paste(text) => handle_paste(app, &text),
        // The next draw picks up the new size.
        CEvent::Resize(..) => {}
        CEvent::FocusGained | CEvent::FocusLost => return Handled::Unchanged,
    }
    Handled::Changed
}

fn handle_paste(app: &mut App, text: &str) {
    if let Some(form) = app.proxy_form.as_mut() {
        form.paste(text);
    } else if app.screen == Screen::Settings && app.setting_input.is_some() {
        let text = text.trim();
        let id = app.settings_rows()[app.setting_index].id;
        if id == crate::settings::SettingId::TestUrl
            || (text.len() <= 8 && text.chars().all(|c| c.is_ascii_digit()))
        {
            app.setting_input = Some(text.trim().to_string());
        }
    } else if app.screen == Screen::Setup && app.setup_phase == SetupPhase::Editing {
        if text.trim().lines().count() > 1 {
            app.setup_editor.load(text.trim());
        } else {
            app.setup_editor.insert_text(text.trim());
        }
    } else if matches!(app.screen, Screen::Dashboard | Screen::Settings)
        && (app.settings_management
            || matches!(app.overlay, Overlay::OwnNodes | Overlay::PrivateRules))
    {
        crate::manage::handle_manage_paste(app, text);
    } else if app.screen == Screen::Dashboard && app.overlay == Overlay::Probe {
        app.probe_editor.insert(text);
    } else if app.screen == Screen::Dashboard && app.main_tab == MainTab::Dns && app.dns_editing {
        app.dns_editor.insert(text);
    } else if app.screen == Screen::Dashboard && app.main_tab == MainTab::Rules && app.rule_editing
    {
        if app.rule_explaining {
            app.rule_target_editor.insert_text(text);
        } else {
            app.rule_query.insert_text(text);
            app.rule_index = 0;
        }
    } else if app.screen == Screen::Dashboard && app.main_tab == MainTab::Logs && app.log_editing {
        app.log_query.insert_text(text);
        app.log_index = 0;
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
    ClearQuery,
    Proxies,
}

fn dashboard_esc(tab: MainTab, rule_query_empty: bool) -> EscStep {
    if tab == MainTab::Rules && !rule_query_empty {
        EscStep::ClearQuery
    } else {
        EscStep::Proxies
    }
}

fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return true;
    }
    if app.status_detail {
        match key.code {
            KeyCode::Esc | KeyCode::Char('!') => app.status_detail = false,
            KeyCode::Up | KeyCode::Char('k') => {
                app.detail_scroll = app.detail_scroll.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.detail_scroll = app.detail_scroll.saturating_add(1)
            }
            _ => {}
        }
        return false;
    }
    if key.code == KeyCode::Char('!')
        && app.setting_input.is_none()
        && app.manage_input.is_none()
        && app.proxy_form.is_none()
        && !app.dns_editing
        && !app.rule_editing
        && !app.log_editing
        && app.overlay == Overlay::None
        && app.screen != Screen::Setup
    {
        app.status_detail = true;
        app.detail_scroll = 0;
        return false;
    }
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
    if app.main_tab == MainTab::Logs && app.log_editing {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('u') | KeyCode::Char('w'))
        {
            app.log_query.clear();
            return false;
        }
        match key.code {
            KeyCode::Esc | KeyCode::Enter => app.log_editing = false,
            KeyCode::Backspace => {
                app.log_query.backspace();
            }
            KeyCode::Delete => {
                app.log_query.delete();
            }
            KeyCode::Left => app.log_query.move_left(),
            KeyCode::Right => app.log_query.move_right(),
            KeyCode::Home => app.log_query.move_home(),
            KeyCode::End => app.log_query.move_end(),
            KeyCode::Char(ch) => {
                app.log_query.insert_text(&ch.to_string());
            }
            _ => {}
        }
        app.log_index = 0;
        return false;
    }
    if (app.main_tab == MainTab::Connections && app.connection_detail)
        || (app.main_tab == MainTab::Logs && app.log_detail)
        || (app.main_tab == MainTab::Rules && app.rule_detail)
    {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                app.connection_detail = false;
                app.log_detail = false;
                app.rule_detail = false;
            }
            KeyCode::Up | KeyCode::Char('k') => {
                app.detail_scroll = app.detail_scroll.saturating_sub(1)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                app.detail_scroll = app.detail_scroll.saturating_add(1)
            }
            _ => {}
        }
        return false;
    }
    match key.code {
        KeyCode::Char('q') => return true,
        KeyCode::Backspace => app.clear_status(),
        KeyCode::Esc => match dashboard_esc(app.main_tab, app.rule_query.text.is_empty()) {
            EscStep::ClearQuery => {
                app.rule_query.clear();
                app.rule_index = 0;
            }
            EscStep::Proxies => app.main_tab = MainTab::Proxies,
        },
        KeyCode::Char(' ') => app.toggle_sysproxy(),
        KeyCode::Char('e') if app.main_tab == MainTab::Dns => app.dns_editing = true,
        KeyCode::Char('e') | KeyCode::Char('/') if app.main_tab == MainTab::Rules => {
            app.rule_explaining = key.code == KeyCode::Char('e');
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
        KeyCode::Char('m') => app.cycle_routing_mode(),
        KeyCode::Char('r') if app.main_tab == MainTab::Proxies => app.test_current_group(),
        KeyCode::Char('a') if app.main_tab == MainTab::Proxies => app.select_best_node_in_group(),
        KeyCode::Char('/') if app.main_tab == MainTab::Logs => {
            app.pause_logs();
            app.log_editing = true;
        }
        KeyCode::Char('P') if app.main_tab == MainTab::Logs => {
            if app.logs_paused {
                app.logs_paused = false;
                app.log_detail = false;
                app.rule_detail = false;
            } else {
                app.pause_logs();
            }
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
            MainTab::Connections if app.conn_closed_view => {
                let len = app.conns.closed().len();
                if len > 0 {
                    app.closed_index = app.closed_index.checked_sub(1).unwrap_or(len - 1);
                }
            }
            MainTab::Connections => {
                if !app.conn_view.is_empty() {
                    app.conn_index = app
                        .conn_index
                        .checked_sub(1)
                        .unwrap_or(app.conn_view.len() - 1);
                }
            }
            MainTab::Logs => {
                app.pause_logs();
                app.log_index = app.log_index.saturating_sub(1);
            }
            MainTab::Dns => {}
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
            MainTab::Connections if app.conn_closed_view => {
                let len = app.conns.closed().len();
                if len > 0 {
                    app.closed_index = (app.closed_index + 1) % len;
                }
            }
            MainTab::Connections => {
                if !app.conn_view.is_empty() {
                    app.conn_index = if app.conn_index >= app.conn_view.len() {
                        0
                    } else {
                        (app.conn_index + 1) % app.conn_view.len()
                    };
                }
            }
            MainTab::Logs => {
                app.pause_logs();
                app.log_index =
                    (app.log_index + 1).min(app.filtered_logs().len().saturating_sub(1));
            }
            MainTab::Dns => {}
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
            MainTab::Rules => {
                app.rule_detail = true;
                app.detail_scroll = 0;
            }
            MainTab::Providers => app.refresh_selected_provider(),
            // In the closed view this shows the entry, its cause and the note
            // full-width, which narrow windows have no right pane for.
            MainTab::Connections if app.conn_closed_view && app.conns.closed().is_empty() => {}
            MainTab::Connections => {
                app.connection_detail = true;
                app.detail_scroll = 0;
            }
            MainTab::Logs => {
                app.pause_logs();
                app.log_detail = true;
                app.detail_scroll = 0;
            }
        },
        KeyCode::Char('o') if app.main_tab == MainTab::Connections => {
            let id = app.selected_connection().map(|c| c.id.clone());
            let was_empty = app.conn_view.is_empty();
            app.conn_sort = app.conn_sort.next();
            app.rebuild_conn_view();
            app.reselect_connection(id, was_empty);
        }
        KeyCode::Char('f') if app.main_tab == MainTab::Connections => {
            let id = app.selected_connection().map(|c| c.id.clone());
            let was_empty = app.conn_view.is_empty();
            app.conn_filter = !app.conn_filter;
            app.rebuild_conn_view();
            app.reselect_connection(id, was_empty);
        }
        KeyCode::Char('d') if app.main_tab == MainTab::Connections => {
            app.conn_closed_view = !app.conn_closed_view;
            app.closed_index = 0;
            app.connection_detail = false;
        }
        KeyCode::Char('x') if app.main_tab == MainTab::Rules => app.toggle_selected_rule(),
        KeyCode::Char('x') if app.main_tab == MainTab::Connections && !app.conn_closed_view => {
            if let Some(c) = app.selected_connection() {
                let id = c.id.clone();
                if !app.action_busy {
                    app.conns
                        .note(conns::Cause::UserClose, conns::Scope::Id(id.clone()));
                }
                app.run_action("Closing connection…", None, None, move |cfg| {
                    close_connection(&cfg, Some(&id)).map_err(|e| e.to_string())?;
                    Ok("Connection closed".into())
                });
            }
        }
        KeyCode::Char('X') if app.main_tab == MainTab::Connections && !app.conn_closed_view => {
            if !app.confirm_disruption(guard::Disrupt::CloseAll) {
                return false;
            }
            if !app.action_busy {
                app.conns.note(conns::Cause::CloseAll, conns::Scope::All);
            }
            app.run_action("Closing all connections…", None, None, |cfg| {
                close_connection(&cfg, None).map_err(|e| e.to_string())?;
                Ok("All connections closed".into())
            });
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
        Overlay::OwnNodes => crate::manage::handle_own_nodes_key(app, key),
        Overlay::PrivateRules => crate::manage::handle_private_rules_key(app, key),
        Overlay::Best => match key.code {
            KeyCode::Esc | KeyCode::Char('q') => app.close_overlay(),
            KeyCode::Up | KeyCode::Down | KeyCode::Tab | KeyCode::Char('j' | 'k') => {
                app.best_scope_index = 1 - app.best_scope_index
            }
            KeyCode::Char('1') => app.best_scope_index = 0,
            KeyCode::Char('2') => app.best_scope_index = 1,
            KeyCode::Enter => app.start_best_selection(),
            _ => {}
        },
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
        Overlay::Probe => {
            if key.modifiers.contains(KeyModifiers::CONTROL)
                && matches!(key.code, KeyCode::Char('u') | KeyCode::Char('w'))
            {
                app.probe_editor.clear();
                return false;
            }
            match key.code {
                KeyCode::Esc => app.close_overlay(),
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
    let editor = if app.rule_explaining {
        &mut app.rule_target_editor
    } else {
        &mut app.rule_query
    };
    if key.modifiers.contains(KeyModifiers::CONTROL) && matches!(key.code, KeyCode::Char('u' | 'w'))
    {
        editor.clear();
    } else {
        match key.code {
            KeyCode::Esc => app.rule_editing = false,
            KeyCode::Enter => {
                app.rule_editing = false;
                if app.rule_explaining {
                    let target = app.rule_target_editor.trimmed();
                    app.explain_target(&target);
                }
            }
            KeyCode::Backspace => {
                editor.backspace();
            }
            KeyCode::Delete => {
                editor.delete();
            }
            KeyCode::Left => editor.move_left(),
            KeyCode::Right => editor.move_right(),
            KeyCode::Home => editor.move_home(),
            KeyCode::End => editor.move_end(),
            KeyCode::Char(ch) => {
                editor.insert_text(&ch.to_string());
            }
            _ => {}
        }
    }
    if !app.rule_explaining {
        app.rule_index = 0;
    }
    false
}

// Hit regions come from the rendered list, including its scroll offset.
// Return true only when a node row was clicked; the caller performs activation.
fn proxy_mouse_action(app: &mut App, mouse: MouseEvent) -> bool {
    if app.screen != Screen::Dashboard
        || app.main_tab != MainTab::Proxies
        || app.overlay != Overlay::None
        || app.status_detail
    {
        return false;
    }
    let point = ratatui::layout::Position::new(mouse.column, mouse.row);
    if app.toast_visible() && app.toast_area.is_some_and(|r| r.contains(point)) {
        return false;
    }
    let Some((area, focus, start, len)) = app
        .proxy_hits
        .iter()
        .copied()
        .find(|(r, _, _, _)| r.contains(point))
    else {
        return false;
    };
    if len == 0 {
        return false;
    }
    match mouse.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            let index = start + (mouse.row - area.y) as usize;
            if index >= len {
                return false;
            }
            app.focus = focus;
            match focus {
                FocusPane::Groups => {
                    app.group_index = index;
                    app.sync_node_cursor_to_active();
                }
                FocusPane::Nodes => {
                    app.node_index = index;
                    return true;
                }
            }
        }
        MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
            app.focus = focus;
            let current = match focus {
                FocusPane::Groups => app.group_index,
                FocusPane::Nodes => app.node_index,
            };
            let next = if mouse.kind == MouseEventKind::ScrollUp {
                current.saturating_sub(1)
            } else {
                (current + 1).min(len - 1)
            };
            match focus {
                FocusPane::Groups => {
                    app.group_index = next;
                    app.sync_node_cursor_to_active();
                }
                FocusPane::Nodes => app.node_index = next,
            }
        }
        _ => {}
    }
    false
}

fn handle_settings_key(app: &mut App, key: KeyEvent) -> bool {
    if app.overlay != Overlay::None {
        return handle_overlay_key(app, key);
    }
    if app.settings_management {
        crate::manage::handle_profiles_key(app, key);
        return false;
    }
    crate::settings::handle_key(app, key)
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
            app.setup_editor.insert_text(&c.to_string());
        }
        _ => {}
    }
    false
}

fn handle_help_key(app: &mut App, key: KeyEvent) -> bool {
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => app.help_scroll = app.help_scroll.saturating_sub(1),
        KeyCode::Down | KeyCode::Char('j') => app.help_scroll = app.help_scroll.saturating_add(1),
        KeyCode::PageDown => app.help_scroll = app.help_scroll.saturating_add(8),
        KeyCode::PageUp => app.help_scroll = app.help_scroll.saturating_sub(8),
        KeyCode::Home => app.help_scroll = 0,

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

    fn offline_app() -> App {
        let mut app = App::from_snapshot(Config::default(), CoreSnapshot::default());
        app.screen = Screen::Dashboard;
        app
    }

    fn press(app: &mut App, key: KeyCode) -> bool {
        handle_key(app, KeyEvent::new(key, KeyModifiers::NONE))
    }

    fn render_text(app: &mut App, width: u16, height: u16) -> String {
        let mut term = Terminal::new(ratatui::backend::TestBackend::new(width, height)).unwrap();
        term.draw(|frame| ui::draw(frame, app)).unwrap();
        term.backend()
            .buffer()
            .content
            .chunks(width as usize)
            .map(|row| {
                row.iter()
                    .filter(|c| c.symbol() != " ")
                    .map(|c| c.symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn input_keeps_q_and_uppercase_f_and_escape_never_quits_dashboard() {
        let mut app = offline_app();
        app.overlay = Overlay::Probe;
        for ch in "qq.com".chars() {
            assert!(!press(&mut app, KeyCode::Char(ch)));
        }
        assert_eq!(app.probe_editor.text, "qq.com");
        assert_eq!(app.overlay, Overlay::Probe);
        press(&mut app, KeyCode::Esc);
        app.main_tab = MainTab::Dns;
        app.dns_editing = true;
        app.dns_editor.clear();
        for ch in "Foo.test".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        assert_eq!(app.dns_editor.text, "Foo.test");
        press(&mut app, KeyCode::Esc);
        for _ in 0..3 {
            assert!(!press(&mut app, KeyCode::Esc));
        }
        assert_eq!(app.main_tab, MainTab::Proxies);
        assert!(press(&mut app, KeyCode::Char('q')));
    }

    #[test]
    fn connection_selection_follows_id_and_does_not_replace_expired_target() {
        let mut app = offline_app();
        let connection = |id: &str| {
            mihomo::connection_from_value(&serde_json::json!({"id": id, "metadata": {"host": id}}))
                .unwrap()
        };
        let snapshot = |ids: &[&str]| CoreSnapshot {
            running: true,
            connections_ok: true,
            connections: ids.iter().map(|id| connection(id)).collect(),
            ..Default::default()
        };
        app.accept_snapshot(snapshot(&["a", "b"]));
        assert_eq!(app.conn_index, 0);
        app.conn_index = 1;
        app.accept_snapshot(snapshot(&["b", "a"]));
        assert_eq!(app.selected_connection().unwrap().id, "b");
        assert_eq!(app.conn_index, 0);
        app.accept_snapshot(snapshot(&["a"]));
        assert!(app.selected_connection().is_none());
        app.main_tab = MainTab::Connections;
        press(&mut app, KeyCode::Down);
        assert_eq!(app.selected_connection().unwrap().id, "a");
    }

    #[test]
    fn paused_logs_keep_reading_position_while_capture_continues() {
        let mut app = offline_app();
        app.main_tab = MainTab::Logs;
        app.logs = vec![
            ("info".into(), "first".into()),
            ("error".into(), "second".into()),
        ];
        press(&mut app, KeyCode::Char('P'));
        app.tx
            .send(BackendEvent::Log {
                level: "info".into(),
                payload: "third".into(),
            })
            .unwrap();
        app.drain_events();
        assert_eq!(app.filtered_logs().len(), 2);
        assert_eq!(app.logs.len(), 3);
        press(&mut app, KeyCode::Char('/'));
        for ch in "error".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.filtered_logs().len(), 1);
        press(&mut app, KeyCode::Enter);
        assert!(app.log_detail);
        assert!(render_text(&mut app, 60, 18).contains("second"));
    }

    #[test]
    fn stopped_core_hint_names_both_settings_paths_at_common_widths() {
        let mut app = offline_app();
        for lang in [Lang::Zh, Lang::En, Lang::Ja] {
            app.config.settings.lang = lang;
            for (width, height) in [(120, 36), (160, 40)] {
                let view = render_text(&mut app, width, height);
                let (core, update) = match lang {
                    Lang::Zh => ("内核服务", "更新订阅(u)"),
                    Lang::En => ("service", "Update(u)"),
                    Lang::Ja => ("service", "更新(u)"),
                };
                assert!(view.contains(core), "{lang:?} {width}\n{view}");
                assert!(view.contains(update), "{lang:?} {width}\n{view}");
            }
        }
    }

    #[test]
    fn settings_tabs_filter_rows_and_navigation_stays_in_category() {
        let mut app = offline_app();
        app.screen = Screen::Settings;
        for (width, height) in [(42, 12), (80, 24), (120, 30)] {
            app.setting_index = 0;
            press(&mut app, KeyCode::Tab);
            assert_eq!(app.setting_index, 4);
            let view = render_text(&mut app, width, height);
            assert!(!view.contains(app.t("set_download_core")));
            press(&mut app, KeyCode::Up);
            assert_eq!(
                app.settings_rows()[app.setting_index].id,
                crate::settings::SettingId::Toolbar
            );
            press(&mut app, KeyCode::Down);
            assert_eq!(app.setting_index, 4);
            press(&mut app, KeyCode::BackTab);
            assert_eq!(app.setting_index, 0);
            press(&mut app, KeyCode::Char('3'));
            assert_eq!(app.setting_index, 9);
            let view = render_text(&mut app, width, height);
            assert!(!view.contains(app.t("set_theme")));
            press(&mut app, KeyCode::Char('4'));
            assert_eq!(
                app.settings_rows()[app.setting_index].category,
                SettingCategory::Diagnostics
            );
        }
    }

    #[test]
    fn settings_ports_reject_invalid_input_and_profiles_work_inside_settings() {
        let mut app = offline_app();
        app.screen = Screen::Settings;
        app.setting_index = app
            .settings_rows()
            .iter()
            .position(|r| r.id == crate::settings::SettingId::MixedPort)
            .unwrap();
        press(&mut app, KeyCode::Enter);
        for ch in "65536".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        press(&mut app, KeyCode::Enter);
        assert!(!app.action_busy);
        assert!(app.setting_input.is_some());
        press(&mut app, KeyCode::Esc);
        app.clear_status();
        for (w, h) in [(42, 12), (80, 24), (120, 30)] {
            app.setting_index = app
                .settings_rows()
                .iter()
                .position(|r| r.id == crate::settings::SettingId::Profiles)
                .unwrap();
            press(&mut app, KeyCode::Enter);
            assert!(app.settings_management);
            assert_eq!(app.overlay, Overlay::None);
            assert!(render_text(&mut app, w, h).contains("代理列表"));
            press(&mut app, KeyCode::Char('v'));
            assert_eq!(app.profile_page, 2);
            render_text(&mut app, w, h);
            press(&mut app, KeyCode::Esc);
            assert_eq!(app.profile_page, 0);
            press(&mut app, KeyCode::Esc);
            assert!(!app.settings_management);
            app.setting_index = app
                .settings_rows()
                .iter()
                .position(|r| r.id == crate::settings::SettingId::Routing)
                .unwrap();
            press(&mut app, KeyCode::Enter);
            assert!(render_text(&mut app, w, h).contains("分流方案"));
            assert_eq!(app.overlay, Overlay::None);
            app.routing_index = 0;
            press(&mut app, KeyCode::Down);
            assert_eq!(app.routing_index, 1);
            press(&mut app, KeyCode::Char('c'));
            press(&mut app, KeyCode::Char('q'));
            assert_eq!(app.manage_editor.text, "q");
            press(&mut app, KeyCode::Esc);
            assert!(app.settings_management);
            press(&mut app, KeyCode::Esc);
        }
        assert_eq!(app.screen, Screen::Settings);
        assert_eq!(app.overlay, Overlay::None);
        let rows = app.settings_rows();
        let management: Vec<_> = rows
            .iter()
            .filter(|r| r.category == SettingCategory::Subscription)
            .map(|r| r.label.as_str())
            .collect();
        assert_eq!(management, vec!["代理订阅", "分流方案"]);
    }

    #[test]
    fn manager_has_named_rows_and_inline_masked_form() {
        let mut app = offline_app();
        app.screen = Screen::Settings;
        app.settings_management = true;
        app.setting_index = app
            .settings_rows()
            .iter()
            .position(|r| r.id == crate::settings::SettingId::Profiles)
            .unwrap();
        app.profiles = vec![crate::ops::ProfileEntry {
            name: "proxy-001".into(),
            label: "机场 Alpha".into(),
            kind: "订阅".into(),
            path: String::new(),
            active: true,
        }];
        app.config.controller.profile_id = "proxy-001".into();
        app.config.active_profile_label = "机场 Alpha".into();
        let view = render_text(&mut app, 100, 30);
        assert!(view.contains("机场Alpha"));
        assert!(view.contains("proxy-001"));
        assert!(!view.contains("Current"));
        press(&mut app, KeyCode::Char('a'));
        assert!(app.proxy_form.is_some());
        assert_eq!(app.overlay, Overlay::None);
        let form = app.proxy_form.as_mut().unwrap();
        form.kind = 1;
        form.secret.load("hidden-secret");
        form.index = form
            .fields()
            .iter()
            .position(|f| *f == crate::proxy_form::Field::Secret)
            .unwrap();
        form.editing = true;
        for (w, h) in [(42, 12), (80, 24), (120, 30)] {
            let view = render_text(&mut app, w, h);
            assert!(view.contains("添加代理"));
            assert!(!view.contains("hidden-secret"));
            assert!(view.contains("***"));
        }
        press(&mut app, KeyCode::Esc);
        assert!(app.proxy_form.is_some());
        press(&mut app, KeyCode::Esc);
        assert!(app.proxy_form.is_none());
        assert!(app.settings_management);
    }

    #[test]
    fn rule_search_and_target_tests_are_separate_and_details_fit_small_terminals() {
        let mut app = offline_app();
        app.main_tab = MainTab::Rules;
        app.snapshot.rules = crate::ops::parse_rules_json(
            r#"{"rules":[{"type":"DomainSuffix","payload":"example.org","proxy":"DIRECT"},{"type":"Match","payload":"","proxy":"PROXY"}]}"#,
        );
        press(&mut app, KeyCode::Char('/'));
        for c in "DIRECT".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.filtered_rule_indexes().len(), 1);
        assert!(app.explain.is_none());
        press(&mut app, KeyCode::Char('e'));
        for c in "api.example.org".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        press(&mut app, KeyCode::Enter);
        assert_eq!(app.rule_query.text, "DIRECT");
        assert_eq!(
            app.explain
                .as_ref()
                .unwrap()
                .matched
                .as_ref()
                .unwrap()
                .proxy,
            "DIRECT"
        );
        for (w, h) in [(42, 12), (80, 24), (120, 30)] {
            render_text(&mut app, w, h);
            press(&mut app, KeyCode::Enter);
            let text = render_text(&mut app, w, h);
            assert!(text.contains("规则详情"));
            press(&mut app, KeyCode::Esc);
            assert!(!app.rule_detail);
        }
    }

    #[test]
    fn millisecond_setting_edits_cancel_and_preserves_existing_config() {
        let mut app = offline_app();
        app.screen = Screen::Settings;
        app.setting_index = 7;
        press(&mut app, KeyCode::Enter);
        for c in "1250".chars() {
            press(&mut app, KeyCode::Char(c));
        }
        assert_eq!(app.setting_input.as_deref(), Some("1250"));
        press(&mut app, KeyCode::Esc);
        assert!(app.setting_input.is_none());
        assert_eq!(app.screen, Screen::Settings);
        assert_eq!(app.config.settings.graph_interval_ms(), 1000);
        app.set_graph_interval(1250);
        app.graph_samples = (125.0, 250.0, 1);
        app.advance_graph(Duration::from_millis(1249));
        assert_eq!(*app.up_history.last().unwrap(), 0.0);
        app.advance_graph(Duration::from_millis(1));
        assert_eq!(*app.up_history.last().unwrap(), 125.0);
        let mut old = serde_json::to_value(Settings::default()).unwrap();
        old.as_object_mut().unwrap().remove("graph_interval_ms");
        old["graph_interval_secs"] = 5.into();
        let loaded: Settings = serde_json::from_value(old).unwrap();
        let saved: Settings =
            serde_json::from_str(&serde_json::to_string(&loaded).unwrap()).unwrap();
        assert_eq!(saved.graph_interval_ms(), 5000);
    }

    #[test]
    fn graph_interval_averages_samples_without_delaying_live_rates() {
        let mut app = offline_app();
        app.config.settings.graph_interval_ms = Some(2000);
        app.tx
            .send(BackendEvent::Traffic { up: 100, down: 400 })
            .unwrap();
        app.drain_events();
        app.advance_graph(Duration::from_secs(1));
        assert_eq!(app.up_rate, 100);
        assert_eq!(*app.up_history.last().unwrap(), 0.0);
        app.tx
            .send(BackendEvent::Traffic { up: 300, down: 800 })
            .unwrap();
        app.drain_events();
        app.advance_graph(Duration::from_secs(1));
        assert_eq!(app.up_rate, 300);
        assert_eq!(*app.up_history.last().unwrap(), 200.0);
        assert_eq!(*app.down_history.last().unwrap(), 600.0);
        // No incoming samples must not duplicate a stale rate.
        let previous = app.up_history.clone();
        app.advance_graph(Duration::from_secs(2));
        assert_eq!(app.up_history, previous);
    }

    #[test]
    fn best_scope_popup_uses_active_country_and_rejects_unknown_country() {
        let mut app = offline_app();
        app.snapshot.groups.push(mihomo::ProxyGroup {
            name: "Main".into(),
            kind: "Selector".into(),
            now: "Unknown".into(),
            all: vec!["US 01".into()],
        });
        for (width, height) in [(42, 12), (80, 24)] {
            press(&mut app, KeyCode::Char('a'));
            assert_eq!(app.overlay, Overlay::Best);
            let view = render_text(&mut app, width, height);
            assert!(view.contains("Enter"));
            press(&mut app, KeyCode::Char('2'));
            press(&mut app, KeyCode::Enter);
            assert!(app.pending_best_group.is_none());
            assert!(!app.action_busy);
            assert!(app.status_is_error);
            press(&mut app, KeyCode::Esc);
            assert_eq!(app.overlay, Overlay::None);
            app.clear_status();
        }
    }

    #[test]
    fn toast_expires_without_moving_lists_and_keeps_full_result() {
        let mut app = offline_app();
        app.snapshot.groups.push(mihomo::ProxyGroup {
            name: "Group".into(),
            kind: "Selector".into(),
            now: "node".into(),
            all: vec!["node".into()],
        });
        render_text(&mut app, 80, 24);
        let before = app.proxy_hits.clone();
        app.set_status("TOAST_SENTINEL", false);
        render_text(&mut app, 80, 24);
        assert_eq!(before, app.proxy_hits);
        assert!(app.toast_area.is_some());
        app.toast_started = Some(Instant::now() - Duration::from_secs(5));
        assert!(!render_text(&mut app, 80, 24).contains("TOAST_SENTINEL"));
        assert!(app.toast_area.is_none());
        press(&mut app, KeyCode::Char('!'));
        assert!(render_text(&mut app, 80, 24).contains("TOAST_SENTINEL"));
        press(&mut app, KeyCode::Esc);
        app.set_status("ERROR_SENTINEL", true);
        app.toast_started = Some(Instant::now() - Duration::from_secs(5));
        assert!(app.toast_visible());
        app.toast_started = Some(Instant::now() - Duration::from_secs(9));
        assert!(!app.toast_visible());
    }

    #[test]
    fn mouse_selects_rendered_rows_scrolls_and_respects_overlays() {
        let mut app = offline_app();
        app.snapshot.groups = (0..2)
            .map(|i| mihomo::ProxyGroup {
                name: format!("Group{i}"),
                kind: "Selector".into(),
                now: "Node0".into(),
                all: (0..40).map(|n| format!("Node{n}")).collect(),
            })
            .collect();
        for (width, height) in [(42, 12), (80, 24), (120, 30)] {
            app.node_index = 30;
            render_text(&mut app, width, height);
            let (area, _, start, _) = app
                .proxy_hits
                .iter()
                .copied()
                .find(|(_, f, _, _)| *f == FocusPane::Nodes)
                .unwrap();
            assert!(start > 0);
            let mut event = MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: area.x + 1,
                row: area.y,
                modifiers: KeyModifiers::NONE,
            };
            assert!(proxy_mouse_action(&mut app, event));
            assert_eq!(app.node_index, start);
            assert_eq!(app.focus, FocusPane::Nodes);
            render_text(&mut app, width, height);
            assert!(app
                .proxy_hits
                .contains(&(area, FocusPane::Nodes, start, 40)));
            app.accept_snapshot(app.snapshot.clone());
            render_text(&mut app, width, height);
            assert!(app
                .proxy_hits
                .contains(&(area, FocusPane::Nodes, start, 40)));
            event.kind = MouseEventKind::ScrollDown;
            assert!(!proxy_mouse_action(&mut app, event));
            assert_eq!(app.node_index, start + 1);
            app.overlay = Overlay::Probe;
            event.kind = MouseEventKind::Down(MouseButton::Left);
            assert!(!proxy_mouse_action(&mut app, event));
            app.overlay = Overlay::None;
            app.set_status("Notice", false);
            render_text(&mut app, width, height);
            let toast = app.toast_area.unwrap();
            event.column = toast.x + 1;
            event.row = toast.y + 1;
            assert!(!proxy_mouse_action(&mut app, event));
            app.clear_status();
            render_text(&mut app, width, height);
            let (group_area, _, _, _) = app
                .proxy_hits
                .iter()
                .copied()
                .find(|(_, f, _, _)| *f == FocusPane::Groups)
                .unwrap();
            event.column = group_area.x + 1;
            event.row = group_area.y + 1;
            assert!(!proxy_mouse_action(&mut app, event));
            assert_eq!(app.group_index, 1);
            assert_eq!(app.node_index, 0);
            assert_eq!(app.focus, FocusPane::Groups);
            event.row = group_area.y + 2;
            assert!(!proxy_mouse_action(&mut app, event));
            assert_eq!(app.group_index, 1);
        }
    }

    #[test]
    fn notification_leaves_one_footer_and_can_be_dismissed() {
        let mut app = offline_app();
        app.set_status("TEST_RESULT", false);
        for (width, height) in [(42, 12), (80, 24), (120, 30)] {
            let text = render_text(&mut app, width, height);
            assert!(text.contains("TEST_RESULT"));
            let footer = text.lines().last().unwrap();
            assert!(footer.contains("q"));
            assert!(!footer.contains("TEST_RESULT"));
            press(&mut app, KeyCode::Char('!'));
            assert!(app.status_detail);
            press(&mut app, KeyCode::Esc);
        }
        press(&mut app, KeyCode::Backspace);
        assert!(app.status_message.is_empty());
    }

    #[test]
    fn status_help_and_connection_detail_remain_accessible_in_small_windows() {
        let mut app = offline_app();
        app.config.settings.show_traffic = false;
        app.set_status("REVIEW_ERROR_SENTINEL", true);
        for (width, height) in [(60, 18), (80, 24), (120, 30)] {
            assert!(render_text(&mut app, width, height).contains("REVIEW_ERROR_SENTINEL"));
            app.screen = Screen::Help;
            app.help_scroll = u16::MAX;
            let help = render_text(&mut app, width, height);
            assert!(help.contains("q"));
            assert!(app.help_scroll < u16::MAX);
            let previous = app.help_scroll;
            press(&mut app, KeyCode::Up);
            assert_eq!(app.help_scroll, previous.saturating_sub(1));
            app.screen = Screen::Dashboard;
        }
        let mut conn = mihomo::connection_from_value(
            &serde_json::json!({"id":"a", "metadata":{"host":"visible.test", "process":"curl"}}),
        )
        .unwrap();
        conn.host = "visible.test".into();
        app.accept_snapshot(live_snapshot(vec![conn]));
        app.main_tab = MainTab::Connections;
        app.conn_index = 0;
        press(&mut app, KeyCode::Enter);
        assert!(render_text(&mut app, 60, 18).contains("visible.test"));
        press(&mut app, KeyCode::Esc);
        assert!(!app.connection_detail);
    }

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
        assert_eq!(cfg.settings.graph_interval_secs, 1);
        assert!(cfg.settings.connections_stream);
    }

    #[test]
    fn pushed_connections_are_not_overwritten_by_an_older_poll() {
        let mut app = offline_app();
        app.accept_snapshot(live_snapshot(sample_connections()));
        let ids = |app: &App| {
            app.conn_view
                .iter()
                .map(|&i| app.snapshot.connections[i].id.clone())
                .collect::<Vec<_>>()
        };
        assert!(!app.stream_live());
        // Pushes are live data and land even while an action runs.
        app.action_busy = true;
        app.tx
            .send(BackendEvent::Connections {
                items: vec![
                    live_conn("ai", "api.openai.com:443", Some(2), 800),
                    live_conn("new", "chatgpt.com:443", Some(1), 50),
                ],
                upload_total: 5,
                download_total: 9,
            })
            .unwrap();
        app.drain_events();
        app.action_busy = false;
        assert!(app.stream_live());
        assert_eq!(ids(&app), ["ai", "new"]);
        assert_eq!(
            (app.snapshot.upload_total, app.snapshot.download_total),
            (5, 9)
        );
        // `long` was a long-lived session the push no longer lists.
        let closed = app.conns.closed().len();
        assert_eq!(app.conns.closed()[0].host, "ws.example.com:443");

        // A poll that started before the push carries the older list.
        app.snapshot_pending = true;
        let mut stale = live_snapshot(sample_connections());
        stale.mode = "Global".into();
        stale.upload_total = 1;
        app.tx
            .send(BackendEvent::SnapshotDone(Box::new(stale)))
            .unwrap();
        app.drain_events();
        assert!(!app.snapshot_pending);
        assert_eq!(app.snapshot.mode, "Global");
        assert_eq!(ids(&app), ["ai", "new"]);
        assert_eq!(app.snapshot.upload_total, 5);
        assert_eq!(app.conns.closed().len(), closed);

        // Three seconds without a push hand the list back to polling.
        app.conn_stream_at = Instant::now().checked_sub(Duration::from_secs(4));
        assert!(!app.stream_live());
        app.accept_snapshot(live_snapshot(sample_connections()));
        assert_eq!(ids(&app), ["big", "ai", "long"]);
        // Switched off, a fresh push does not count as live.
        app.conn_stream_at = Some(Instant::now());
        app.config.settings.connections_stream = false;
        app.conn_stream.enabled.store(false, Ordering::Relaxed);
        assert!(!app.stream_live());
    }

    #[test]
    fn polls_skip_the_connections_get_only_while_pushes_arrive() {
        use std::{io::Read as _, io::Write as _, net::TcpListener};
        // A controller on 127.0.0.1:0 that answers `{}` and records each path.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let (paths_tx, paths) = std::sync::mpsc::channel();
        thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut head = Vec::new();
                let mut byte = [0u8; 1];
                while !head.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head).to_string();
                let path = head.split_whitespace().nth(1).unwrap_or("").to_string();
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                );
                if paths_tx.send(path).is_err() {
                    return;
                }
            }
        });
        let mut app = offline_app();
        app.config.controller.addr = addr;
        app.config.controller.config_dir = "/nonexistent/terc-test".into();
        let poll = |app: &mut App| {
            app.last_snapshot_poll = Instant::now() - Duration::from_secs(3);
            app.tick(Duration::from_millis(10));
            assert!(app.snapshot_pending);
            let deadline = Instant::now() + Duration::from_secs(5);
            while app.snapshot_pending {
                assert!(Instant::now() < deadline, "poll never finished");
                app.drain_events();
                thread::sleep(Duration::from_millis(5));
            }
            paths.try_iter().collect::<Vec<String>>()
        };
        app.conn_stream_at = Some(Instant::now());
        assert!(app.stream_live());
        let pushed = poll(&mut app);
        assert!(pushed.iter().any(|p| p == "/version"), "{pushed:?}");
        assert!(!pushed.iter().any(|p| p == "/connections"), "{pushed:?}");
        app.conn_stream_at = None;
        let polled = poll(&mut app);
        assert!(polled.iter().any(|p| p == "/connections"), "{polled:?}");
    }

    #[test]
    fn live_connection_stream_row_shows_its_transport() {
        for lang in [Lang::Zh, Lang::En, Lang::Ja] {
            for (width, height) in [(80, 24), (160, 40)] {
                let mut app = offline_app();
                app.config.settings.lang = lang;
                app.screen = Screen::Settings;
                app.setting_index = app
                    .settings_rows()
                    .iter()
                    .position(|r| r.id == crate::settings::SettingId::ConnStream)
                    .unwrap();
                assert_eq!(
                    app.settings_rows()[app.setting_index].category,
                    SettingCategory::Diagnostics
                );
                let label = match lang {
                    Lang::Zh => "连接实时推送",
                    _ => "Liveconnectionstream",
                };
                let desc = prefix(&app.t("desc_conn_stream").replace(' ', ""), 8);
                // The list may put the value under the label; the detail pane
                // states it on one line.
                let shows = |app: &mut App, value: &str| {
                    let text = render_text(app, width, height);
                    let state = format!("{}:{value}", app.t("current_value"));
                    assert!(text.contains(label), "{lang:?} {width}\n{text}");
                    assert!(text.contains(&state), "{lang:?} {width} {value}\n{text}");
                    assert!(text.contains(&desc), "{lang:?} {width}\n{text}");
                };
                shows(&mut app, "ON·HTTP");
                app.conn_stream_at = Some(Instant::now());
                shows(&mut app, "ON·WebSocket");
                app.config.settings.connections_stream = false;
                app.conn_stream.enabled.store(false, Ordering::Relaxed);
                shows(&mut app, "OFF");
            }
        }
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
    fn dashboard_esc_steps_back_without_quitting() {
        assert_eq!(dashboard_esc(MainTab::Proxies, true), EscStep::Proxies);
        assert_eq!(dashboard_esc(MainTab::Rules, false), EscStep::ClearQuery);
        assert_eq!(dashboard_esc(MainTab::Rules, true), EscStep::Proxies);
        assert_eq!(dashboard_esc(MainTab::Providers, true), EscStep::Proxies);
        assert_eq!(dashboard_esc(MainTab::Dns, true), EscStep::Proxies);
    }

    #[test]
    fn own_nodes_and_private_rules_overlays_render_without_secrets() {
        let mut app = offline_app();
        let line =
            "Fake-Own = ss, 192.0.2.10, 8388, encrypt-method=aes-128-gcm, password=SuperSecretPw";
        app.own_nodes = vec![
            crate::compose::ManualNode {
                line: line.into(),
                parsed: crate::subconv::parse_node_line(line),
            },
            crate::compose::ManualNode {
                line: "broken".into(),
                parsed: crate::subconv::parse_node_line("broken"),
            },
        ];
        app.overlay = Overlay::OwnNodes;
        for (w, h) in [(120, 36), (60, 18)] {
            let text = render_text(&mut app, w, h);
            assert!(!text.contains("SuperSecret"), "{text}");
        }
        let text = render_text(&mut app, 140, 40);
        assert!(text.contains("Fake-Own"));
        assert!(text.contains("192.0.2.10:8388"));
        assert!(text.contains("手动节点"));
        // Typing in the add box keeps spaces (Surge lines need them).
        press(&mut app, KeyCode::Char('a'));
        for ch in "A = ss".chars() {
            press(&mut app, KeyCode::Char(ch));
        }
        assert_eq!(app.manage_editor.text, "A = ss");
        press(&mut app, KeyCode::Esc);
        assert!(app.manage_input.is_none());
        assert_eq!(app.overlay, Overlay::OwnNodes);
        press(&mut app, KeyCode::Esc);
        assert_eq!(app.overlay, Overlay::None);

        app.private_rules.rules = vec!["DOMAIN-SUFFIX,example.com,AI".into()];
        app.overlay = Overlay::PrivateRules;
        let text = render_text(&mut app, 140, 40);
        assert!(text.contains("example.com"));
        assert!(text.contains("→AI"));
        assert!(text.contains("AI预设"));
        app.ai_picker = true;
        app.snapshot.groups.push(crate::mihomo::ProxyGroup {
            name: "AUTO".into(),
            kind: "URLTest".into(),
            now: String::new(),
            all: vec![],
        });
        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.ai_picker_selected, vec!["AUTO".to_string()]);
        let text = render_text(&mut app, 140, 40);
        assert!(text.contains("●AUTO"));
        press(&mut app, KeyCode::Char('c'));
        assert!(app.ai_picker_selected.is_empty());
        press(&mut app, KeyCode::Esc);
        assert!(!app.ai_picker);
        assert_eq!(app.overlay, Overlay::PrivateRules);
    }

    fn live_conn(
        id: &str,
        host: &str,
        age_secs: Option<i64>,
        bytes: u64,
    ) -> mihomo::ConnectionItem {
        let mut conn =
            mihomo::connection_from_value(&serde_json::json!({ "id": id, "rule": "Match" }))
                .unwrap();
        conn.host = host.into();
        conn.chains = "PROXY › HK-01".into();
        conn.start_ms = age_secs.map(|secs| conns::now_ms() - secs * 1000);
        conn.download = bytes;
        conn
    }

    fn live_snapshot(conns: Vec<mihomo::ConnectionItem>) -> CoreSnapshot {
        CoreSnapshot {
            running: true,
            connections_ok: true,
            connections: conns,
            ..Default::default()
        }
    }

    fn sample_connections() -> Vec<mihomo::ConnectionItem> {
        vec![
            live_conn("big", "cdn.example.com:443", Some(5), 9000),
            live_conn("ai", "api.openai.com:443", Some(20), 500),
            live_conn("long", "ws.example.com:443", Some(90), 100),
        ]
    }

    #[test]
    fn sort_key_cycles_and_keeps_the_selected_connection() {
        let mut app = offline_app();
        app.main_tab = MainTab::Connections;
        app.accept_snapshot(live_snapshot(sample_connections()));
        let order = |app: &App| {
            app.conn_view
                .iter()
                .map(|&i| app.snapshot.connections[i].id.as_str())
                .collect::<Vec<_>>()
                .join(",")
        };
        assert_eq!(order(&app), "big,ai,long");
        press(&mut app, KeyCode::Down);
        assert_eq!(app.selected_connection().unwrap().id, "ai");
        press(&mut app, KeyCode::Char('o'));
        assert_eq!(app.conn_sort, conns::SortKey::Age);
        assert_eq!(order(&app), "long,ai,big");
        assert_eq!(app.selected_connection().unwrap().id, "ai");
        press(&mut app, KeyCode::Char('o'));
        assert_eq!(app.conn_sort, conns::SortKey::Rate);
        assert_eq!(app.selected_connection().unwrap().id, "ai");
        press(&mut app, KeyCode::Char('o'));
        assert_eq!(app.conn_sort, conns::SortKey::Bytes);
        assert_eq!(order(&app), "big,ai,long");
        assert_eq!(app.selected_connection().unwrap().id, "ai");
    }

    #[test]
    fn session_filter_hides_short_rows_and_close_targets_the_visible_row() {
        let mut app = offline_app();
        app.main_tab = MainTab::Connections;
        app.accept_snapshot(live_snapshot(sample_connections()));
        assert_eq!(app.selected_connection().unwrap().id, "big");
        press(&mut app, KeyCode::Char('f'));
        assert_eq!(app.conn_view.len(), 2);
        // The selected row was hidden, so nothing is selected until the user moves.
        assert!(app.selected_connection().is_none());
        press(&mut app, KeyCode::Down);
        assert_eq!(app.selected_connection().unwrap().id, "ai");
        press(&mut app, KeyCode::Down);
        assert_eq!(app.selected_connection().unwrap().id, "long");
        let text = render_text(&mut app, 100, 30);
        assert!(!text.contains("cdn.example.com"), "{text}");
        assert!(text.contains("(2/3)"), "{text}");

        // `x` reads the same row; a busy app refuses it without noting a cause,
        // so this does not reach the controller.
        app.action_busy = true;
        press(&mut app, KeyCode::Char('x'));
        assert_eq!(app.status_message, "Another operation is still running");
        app.action_busy = false;
        app.accept_snapshot(live_snapshot(vec![live_conn(
            "ai",
            "api.openai.com:443",
            Some(2),
            500,
        )]));
        assert_eq!(app.conns.closed()[0].host, "ws.example.com:443");
        assert_eq!(app.conns.closed()[0].cause, None);

        press(&mut app, KeyCode::Char('f'));
        assert!(!app.conn_filter);
        assert_eq!(app.conn_view.len(), 1);
        app.accept_snapshot(live_snapshot(vec![live_conn(
            "s",
            "a.test:443",
            Some(1),
            1,
        )]));
        press(&mut app, KeyCode::Char('f'));
        assert!(app.conn_view.is_empty());
        let text = render_text(&mut app, 100, 30);
        assert!(text.contains("没有存活60秒以上"), "{text}");
    }

    #[test]
    fn x_closes_and_blames_the_highlighted_row() {
        let mut app = offline_app();
        // Nothing listens here, so the close request cannot reach a real core.
        app.config.controller.addr = "127.0.0.1:1".into();
        app.main_tab = MainTab::Connections;
        app.accept_snapshot(live_snapshot(sample_connections()));
        press(&mut app, KeyCode::Char('f'));
        press(&mut app, KeyCode::Char('o'));
        // Filtered and by age: row 0 is `long`, which is row 2 of the snapshot.
        while app.selected_connection().is_none_or(|c| c.id != "long") {
            press(&mut app, KeyCode::Down);
        }
        assert_eq!(app.conn_index, 0);
        assert_eq!(app.snapshot.connections[2].id, "long");
        press(&mut app, KeyCode::Char('x'));
        assert!(app.action_busy);
        let mut closed: Vec<_> = sample_connections();
        closed.retain(|c| c.id == "big");
        let gone = app
            .conns
            .observe(&mut closed, true, Instant::now(), conns::now_ms());
        let cause = |host: &str| gone.iter().find(|c| c.host == host).map(|c| c.cause);
        assert_eq!(
            cause("ws.example.com:443"),
            Some(Some(conns::Cause::UserClose))
        );
        assert_eq!(cause("api.openai.com:443"), Some(None));
    }

    #[test]
    fn failed_connection_fetch_keeps_the_list_and_reports_no_closures() {
        let mut app = offline_app();
        let mut snapshot = live_snapshot(sample_connections());
        snapshot.upload_total = 77;
        app.accept_snapshot(snapshot);
        let logs = app.logs.len();
        app.accept_snapshot(CoreSnapshot {
            running: true,
            mode: "Rule".into(),
            ..Default::default()
        });
        assert_eq!(app.snapshot.connections.len(), 3);
        assert_eq!(app.snapshot.upload_total, 77);
        assert_eq!(app.snapshot.mode, "Rule");
        assert_eq!(app.conn_view.len(), 3);
        assert!(app.conns.closed().is_empty());
        assert_eq!(app.logs.len(), logs);

        // A real empty list closes them; the long-lived and AI ones are kept.
        app.accept_snapshot(live_snapshot(Vec::new()));
        assert!(app.snapshot.connections.is_empty());
        assert_eq!(app.conns.closed().len(), 2);
        let lines: Vec<_> = app.logs[logs..].iter().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines.iter().any(|(level, text)| level == "warning"
            && text.starts_with("terc: closed api.openai.com:443 after 20s")));
        assert!(lines.iter().any(|(level, text)| level == "info"
            && text.contains("ws.example.com:443 after 1m3")
            && text.contains("via PROXY › HK-01")));
        // The AI session closed for no known reason: one quiet toast.
        assert!(app
            .status_message
            .starts_with("AI 长连接已断开: api.openai.com"));
        assert!(!app.status_is_error);

        // A second one inside 30 s does not toast again, and a stop is attributed.
        app.clear_status();
        app.accept_snapshot(live_snapshot(sample_connections()));
        app.accept_snapshot(live_snapshot(Vec::new()));
        assert!(app.status_message.is_empty());
        assert_eq!(app.conns.closed()[0].cause, None);
        app.accept_snapshot(live_snapshot(sample_connections()));
        app.accept_snapshot(CoreSnapshot::default());
        app.accept_snapshot(CoreSnapshot::default());
        assert!(app.status_message.is_empty());
        assert_eq!(app.conns.closed()[0].cause, Some(conns::Cause::CoreStopped));
    }

    #[test]
    fn one_failed_poll_is_not_a_core_stop() {
        let mut app = offline_app();
        app.accept_snapshot(live_snapshot(sample_connections()));
        let logs = app.logs.len();
        // A slow /version and `SendOnDrop`'s fallback both read as not running.
        app.accept_snapshot(CoreSnapshot::default());
        assert!(!app.snapshot.running);
        assert_eq!(app.snapshot.connections.len(), 3);
        app.accept_snapshot(live_snapshot(sample_connections()));
        assert!(app.conns.closed().is_empty());
        assert_eq!(app.logs.len(), logs);
        // The session closes once, for no known reason, and is recorded once.
        app.accept_snapshot(live_snapshot(Vec::new()));
        let ws = |app: &App| {
            app.conns
                .closed()
                .iter()
                .filter(|c| c.host == "ws.example.com:443")
                .map(|c| c.cause)
                .collect::<Vec<_>>()
        };
        assert_eq!(ws(&app), [None]);

        // Two in a row are a stop.
        app.accept_snapshot(live_snapshot(sample_connections()));
        app.accept_snapshot(CoreSnapshot::default());
        assert_eq!(app.snapshot.connections.len(), 3);
        app.accept_snapshot(CoreSnapshot::default());
        assert!(app.snapshot.connections.is_empty());
        assert_eq!(ws(&app), [Some(conns::Cause::CoreStopped), None]);

        // While pushes arrive the core is plainly up, whatever polls say.
        app.tx
            .send(BackendEvent::Connections {
                items: sample_connections(),
                upload_total: 1,
                download_total: 1,
            })
            .unwrap();
        app.drain_events();
        for _ in 0..3 {
            app.accept_snapshot(CoreSnapshot::default());
        }
        assert_eq!(app.snapshot.connections.len(), 3);
        assert_eq!(ws(&app).len(), 2);
    }

    #[test]
    fn short_ai_requests_closing_normally_stay_quiet() {
        let mut app = offline_app();
        let short = |id: &str, host: &str| live_conn(id, host, Some(1), 10);
        app.accept_snapshot(live_snapshot(vec![
            short("page", "chatgpt.com:443"),
            short("ab", "ab.chatgpt.com:443"),
            short("cdn", "cdn.oaistatic.com:443"),
        ]));
        assert!(app.snapshot.connections.iter().all(|c| c.ai));
        let logs = app.logs.len();
        app.accept_snapshot(live_snapshot(Vec::new()));
        assert!(app.conns.closed().is_empty());
        assert_eq!(app.logs.len(), logs);
        assert!(app.status_message.is_empty());
    }

    #[test]
    fn closing_many_sessions_logs_one_summary_line() {
        let mut app = offline_app();
        let many = (0..7)
            .map(|i| live_conn(&i.to_string(), &format!("h{i}.test:443"), Some(120), 1))
            .collect();
        app.accept_snapshot(live_snapshot(many));
        let logs = app.logs.len();
        app.accept_snapshot(live_snapshot(Vec::new()));
        assert_eq!(app.logs.len(), logs + 1);
        let (level, text) = app.logs.last().unwrap();
        assert_eq!(level, "info");
        assert!(
            text.starts_with("terc: 7 long-lived/AI connections closed (同时断开 7 条"),
            "{text}"
        );
        assert_eq!(app.conns.closed().len(), 7);
        assert!(app.conns.closed().iter().all(|c| c.bulk == 7));
    }

    #[test]
    fn connections_view_shows_ai_tags_ages_and_closed_sessions() {
        for lang in [Lang::Zh, Lang::En, Lang::Ja] {
            for (width, height) in [(80, 24), (100, 30), (160, 40)] {
                let mut app = offline_app();
                app.config.settings.lang = lang;
                app.config.settings.show_traffic = false;
                app.main_tab = MainTab::Connections;
                app.accept_snapshot(live_snapshot(sample_connections()));
                let text = render_text(&mut app, width, height);
                let row = |needle: &str| {
                    text.lines()
                        .find(|line| line.contains(needle))
                        .unwrap_or_else(|| panic!("{lang:?} {width}: {needle}\n{text}"))
                        .to_string()
                };
                assert!(row("api.openai.com").contains("AIapi.openai.com"), "{text}");
                assert!(!row("ws.example.com").contains("AIws"), "{text}");
                assert!(row("ws.example.com").contains("1m3"), "{text}");
                assert!(row("cdn.example.com").contains("5s"), "{text}");
                assert!(text.contains("(3/3)"), "{lang:?} {width}\n{text}");
                let sort = app.t("conn_sort_bytes").replace(' ', "");
                assert!(text.contains(&sort), "{lang:?} {width}\n{text}");
                let sel = text.lines().find(|l| l.contains("›")).unwrap();
                assert!(sel.contains("cdn.example.com"), "{text}");

                press(&mut app, KeyCode::Char('o'));
                press(&mut app, KeyCode::Char('o'));
                let text = render_text(&mut app, width, height);
                let sort = app.t("conn_sort_rate").replace(' ', "");
                assert!(text.contains(&sort), "{lang:?} {width}\n{text}");
                if width >= 100 {
                    assert!(text.contains("0B/s"), "{lang:?} {width}\n{text}");
                }

                app.accept_snapshot(live_snapshot(vec![live_conn(
                    "big",
                    "cdn.example.com:443",
                    Some(5),
                    9000,
                )]));
                app.clear_status();
                press(&mut app, KeyCode::Char('d'));
                assert!(app.conn_closed_view);
                let text = render_text(&mut app, width, height);
                assert!(text.contains("ws.example.com"), "{lang:?} {width}\n{text}");
                assert!(
                    !text.contains("cdn.example.com"),
                    "{lang:?} {width}\n{text}"
                );
                assert!(row_has(&text, "api.openai.com", "AI"), "{text}");
                let ago = app.t("conn_ago");
                assert!(
                    text.contains(&format!("0s{ago}")),
                    "{lang:?} {width}\n{text}"
                );
                // The note wraps inside the right pane.
                assert!(text.contains("Mihomo"), "{lang:?} {width}\n{text}");
                let footer = text.lines().last().unwrap();
                assert!(footer.starts_with("↑↓"), "{lang:?} {width}\n{text}");

                press(&mut app, KeyCode::Down);
                assert_eq!(app.closed_index, 1);
                press(&mut app, KeyCode::Enter);
                assert!(app.connection_detail);
                let text = render_text(&mut app, width, height);
                assert!(
                    text.contains("cause"),
                    "{lang:?} {width}
{text}"
                );
                press(&mut app, KeyCode::Enter);
                assert!(!app.connection_detail);
                press(&mut app, KeyCode::Char('x'));
                assert!(!app.action_busy);
                press(&mut app, KeyCode::Char('d'));
                assert!(!app.conn_closed_view);
                assert_eq!(app.closed_index, 0);
            }
        }
    }

    #[test]
    fn connection_rows_fill_the_width_by_priority() {
        let mut app = offline_app();
        app.config.settings.lang = Lang::En;
        app.config.settings.show_traffic = false;
        app.main_tab = MainTab::Connections;
        let mut conn = live_conn("c", "cdn.example.com:443", Some(5), 3 << 20);
        conn.process = "Cursor Helper".into();
        conn.rule = "DomainSuffix".into();
        conn.inbound = "Mixed".into();
        conn.upload = 1 << 20;
        app.accept_snapshot(live_snapshot(vec![conn]));
        let row = |app: &mut App, width: u16| {
            let text = render_text(app, width, 30);
            let line = text
                .lines()
                .find(|l| l.contains("cdn.example.com"))
                .unwrap();
            // Only the list pane, not the detail pane on the right.
            line.split('│').nth(1).unwrap().to_string()
        };
        // At 80 columns the sort metric shows as one total.
        let narrow = row(&mut app, 80);
        assert!(narrow.contains("4.0MB"), "{narrow}");
        assert!(!narrow.contains("CursorHelp"), "{narrow}");
        let mid = row(&mut app, 120);
        for part in ["CursorHelp", "DomainSuffix", "5s", "4.0MB"] {
            assert!(mid.contains(part), "{part}: {mid}");
        }
        let wide = row(&mut app, 160);
        for part in ["CursorHelp", "DomainSuffix", "↑1.0MB", "↓3.0MB", "Mixed"] {
            assert!(wide.contains(part), "{part}: {wide}");
        }
        press(&mut app, KeyCode::Char('o'));
        press(&mut app, KeyCode::Char('o'));
        assert!(row(&mut app, 80).contains("0B/s"));
    }

    #[test]
    fn narrow_closed_view_shows_the_cause_and_keeps_its_cursor() {
        let mut app = offline_app();
        app.config.settings.lang = Lang::En;
        app.config.settings.show_traffic = false;
        app.main_tab = MainTab::Connections;
        let long = |id: &str| live_conn(id, &format!("{id}.test:443"), Some(90), 1);
        app.accept_snapshot(live_snapshot(vec![long("a"), long("b"), long("c")]));
        app.accept_snapshot(live_snapshot(vec![long("c")]));
        press(&mut app, KeyCode::Char('d'));
        let text = render_text(&mut app, 70, 24);
        assert!(row_has(&text, "a.test", "closedbytheapp"), "{text}");
        assert!(
            text.contains("Enterdetail") && !text.contains("Xall"),
            "{text}"
        );
        press(&mut app, KeyCode::Down);
        let host = |app: &App| app.conns.closed()[app.closed_index].host.clone();
        let picked = host(&app);
        app.accept_snapshot(live_snapshot(Vec::new()));
        assert_eq!(app.conns.closed().len(), 3);
        assert_eq!(host(&app), picked);
        press(&mut app, KeyCode::Enter);
        let text = render_text(&mut app, 70, 24);
        assert!(text.contains("Mihomo"), "{text}");
    }

    fn prefix(text: &str, chars: usize) -> String {
        text.chars().take(chars).collect()
    }

    fn row_has(text: &str, needle: &str, other: &str) -> bool {
        text.lines()
            .any(|line| line.contains(needle) && line.contains(other))
    }

    #[test]
    fn connection_detail_shows_age_rate_provider_and_ai() {
        let mut app = offline_app();
        app.main_tab = MainTab::Connections;
        let mut conn = live_conn("ai", "api.openai.com:443", Some(75), 10);
        conn.provider = "sub".into();
        app.accept_snapshot(live_snapshot(vec![conn]));
        for lang in [Lang::Zh, Lang::En, Lang::Ja] {
            app.config.settings.lang = lang;
            press(&mut app, KeyCode::Enter);
            let text = render_text(&mut app, 80, 30);
            let long = app.t("conn_long_lived").replace(' ', "");
            assert!(text.contains(&format!("({long})")), "{text}");
            assert!(text.contains("age1m1"), "{text}");
            assert!(text.contains("rate↑0B/s↓0B/s"), "{text}");
            assert!(text.contains("provsub"), "{text}");
            assert!(text.contains("aiyes"), "{text}");
            press(&mut app, KeyCode::Esc);
        }
        app.screen = Screen::Help;
        for lang in [Lang::Zh, Lang::En, Lang::Ja] {
            app.config.settings.lang = lang;
            let help = app.t("help_conn_keys").replace(' ', "");
            assert!(
                render_text(&mut app, 160, 60).contains(&prefix(&help, 9)),
                "{lang:?}"
            );
        }
    }

    #[test]
    fn action_done_restarts_the_poll_timer() {
        let mut app = offline_app();
        app.config.controller.config_dir = "/nonexistent/terc-test".into();
        app.action_busy = true;
        app.last_snapshot_poll = Instant::now() - Duration::from_secs(10);
        app.tx
            .send(BackendEvent::ActionDone {
                result: Ok("done".into()),
                modules: None,
                profile: None,
            })
            .unwrap();
        assert!(app.drain_events());
        assert!(!app.action_busy);
        // The action thread's own snapshot is on its way; no second poll now.
        app.tick(Duration::from_millis(10));
        assert!(!app.snapshot_pending);
    }

    fn log(level: &str, payload: &str) -> BackendEvent {
        BackendEvent::Log {
            level: level.into(),
            payload: payload.into(),
        }
    }

    #[test]
    fn drain_reports_only_changes_the_screen_shows() {
        let mut app = offline_app();
        assert!(!app.drain_events());
        // /logs carries a line per new connection; off the Logs tab it is kept, not drawn.
        app.tx.send(log("info", "[TCP] a --> b match x")).unwrap();
        assert!(!app.drain_events());
        assert_eq!(app.logs.len(), 1);
        app.main_tab = MainTab::Logs;
        app.tx.send(log("info", "[TCP] c --> d match x")).unwrap();
        assert!(app.drain_events());
        app.pause_logs();
        app.tx.send(log("info", "[TCP] e --> f match x")).unwrap();
        assert!(!app.drain_events());
        // A TUN failure still reaches the screen through the toast.
        app.main_tab = MainTab::Proxies;
        app.tx
            .send(log("error", "Start TUN listening error: denied"))
            .unwrap();
        assert!(!app.drain_events());
        assert!(app.toast_visible());
        app.tx
            .send(BackendEvent::Traffic { up: 1, down: 2 })
            .unwrap();
        app.tx.send(log("info", "[TCP] g --> h match x")).unwrap();
        assert!(app.drain_events());
        assert_eq!(app.logs.len(), 5);
    }

    #[test]
    fn graph_generation_counts_shifts_even_of_equal_samples() {
        let mut app = offline_app();
        let gen = app.graph_gen;
        app.advance_graph(Duration::from_secs(1));
        assert_eq!(app.graph_gen, gen, "no samples, no shift");
        for round in 1..=2 {
            app.graph_samples = (100.0, 100.0, 1);
            app.advance_graph(Duration::from_secs(1));
            assert_eq!(app.graph_gen, gen + round);
        }
        assert_eq!(app.up_history[HISTORY_LEN - 2..], [100.0, 100.0]);
    }

    #[test]
    fn redraw_draws_input_at_once_and_caps_data_and_heartbeat() {
        let app = offline_app();
        let frame = Duration::from_millis(16);
        let t0 = Instant::now();
        let at = |ms| t0 + Duration::from_millis(ms);
        let mut redraw = Redraw::new(t0);
        assert!(redraw.due(t0, frame), "first frame at once");
        redraw.drawn(&app, t0);
        redraw.observe(&app, at(10));
        assert!(!redraw.pending());
        assert_eq!(redraw.wait(at(10), frame), IDLE_WAKE);
        // Data waits for the 100 ms frame, input only for refresh_hz.
        redraw.data = true;
        assert!(!redraw.due(at(40), frame));
        assert_eq!(redraw.wait(at(70), frame), Duration::from_millis(30));
        assert!(redraw.due(at(100), frame));
        redraw.input = true;
        assert!(redraw.due(at(16), frame));
        assert!(!redraw.due(at(16), Duration::from_millis(66)), "15 Hz cap");
        redraw.drawn(&app, at(100));
        // Nothing changed: one heartbeat a second for ages and "ago" columns.
        redraw.observe(&app, at(1099));
        assert!(!redraw.pending());
        redraw.observe(&app, at(1100));
        assert!(redraw.due(at(1100), frame));
    }

    #[test]
    fn redraw_sees_toast_edges_and_graph_shifts() {
        let mut app = offline_app();
        let frame = Duration::from_millis(16);
        let t0 = Instant::now();
        let mut redraw = Redraw::new(t0);
        redraw.drawn(&app, t0);
        app.set_status("first", false);
        redraw.observe(&app, t0);
        assert!(redraw.pending(), "toast shown");
        redraw.drawn(&app, t0);
        // A new message while one is still up replaces it.
        app.toast_started = Some(Instant::now() + Duration::from_millis(1));
        redraw.observe(&app, t0);
        assert!(redraw.pending(), "toast replaced");
        redraw.drawn(&app, t0);
        app.toast_started = Some(Instant::now() - Duration::from_secs(5));
        redraw.observe(&app, t0);
        assert!(redraw.pending(), "toast expired");
        redraw.drawn(&app, t0);
        app.graph_gen += 1;
        redraw.observe(&app, t0);
        assert!(redraw.pending(), "graph shifted");
        redraw.drawn(&app, t0);
        redraw.observe(&app, t0);
        assert!(!redraw.due(t0 + Duration::from_millis(500), frame));
    }

    #[test]
    fn terminal_events_mark_only_what_can_change_the_screen() {
        let mut app = offline_app();
        let mouse = |kind| {
            CEvent::Mouse(MouseEvent {
                kind,
                column: 1,
                row: 1,
                modifiers: KeyModifiers::NONE,
            })
        };
        let key = |code| CEvent::Key(KeyEvent::new(code, KeyModifiers::NONE));
        assert_eq!(handle_event(&mut app, key(KeyCode::Down)), Handled::Changed);
        assert_eq!(
            handle_event(&mut app, CEvent::Resize(80, 24)),
            Handled::Changed
        );
        for kind in [
            MouseEventKind::Moved,
            MouseEventKind::Up(MouseButton::Left),
            MouseEventKind::Drag(MouseButton::Left),
        ] {
            assert!(!mouse_acts(kind));
            assert_eq!(handle_event(&mut app, mouse(kind)), Handled::Unchanged);
        }
        for kind in [
            MouseEventKind::Down(MouseButton::Left),
            MouseEventKind::ScrollUp,
            MouseEventKind::ScrollDown,
        ] {
            assert!(mouse_acts(kind));
            assert_eq!(handle_event(&mut app, mouse(kind)), Handled::Changed);
        }
        assert_eq!(
            handle_event(&mut app, CEvent::FocusGained),
            Handled::Unchanged
        );
        assert_eq!(
            handle_event(&mut app, key(KeyCode::Char('q'))),
            Handled::Quit
        );
    }

    #[test]
    fn mouse_mode_asks_for_clicks_and_wheel_only() {
        let mut out = String::new();
        crossterm::Command::write_ansi(&ClickMouse, &mut out).unwrap();
        // 1000 click/wheel + 1006 SGR; never 1002 (drag) or 1003 (any motion).
        assert_eq!(out, "\x1b[?1000h\x1b[?1006h");
    }
}
