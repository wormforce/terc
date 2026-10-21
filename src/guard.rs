//! Asks before an action that will cut long-lived or AI sessions.
//!
//! There is no confirm dialog: the first press shows a toast with the counts
//! and the same action pressed again within `CONFIRM_WINDOW` proceeds.

use std::time::{Duration, Instant};

use crate::{
    conns::{self, Cause},
    App, Lang, Screen,
};

const CONFIRM_WINDOW: Duration = Duration::from_secs(6);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Disrupt {
    CloseAll,
    TunOff,
    /// macOS: a non-root core rewrites the config and restarts to enable TUN.
    TunOnRestart,
    CoreStop,
    /// Mihomo re-initialises every `proxy-providers:` entry on reload and
    /// closes the connections through its nodes; top-level `proxies:` stay.
    Reload,
}

impl Disrupt {
    fn label(self, lang: Lang) -> &'static str {
        match (self, lang) {
            (Self::CloseAll, Lang::Zh) => "全部断开",
            (Self::CloseAll, Lang::En) => "Closing all",
            (Self::CloseAll, Lang::Ja) => "全切断",
            (Self::TunOff, Lang::Zh) => "关闭 TUN",
            (Self::TunOff, Lang::En) => "Turning TUN off",
            (Self::TunOff, Lang::Ja) => "TUN の無効化",
            (Self::TunOnRestart, Lang::Zh) => "开启 TUN（将重启内核）",
            (Self::TunOnRestart, Lang::En) => "Enabling TUN (restarts the core)",
            (Self::TunOnRestart, Lang::Ja) => "TUN の有効化（コア再起動）",
            (Self::CoreStop, Lang::Zh) => "停止内核",
            (Self::CoreStop, Lang::En) => "Stopping the core",
            (Self::CoreStop, Lang::Ja) => "コア停止",
            (Self::Reload, Lang::Zh) => "重载配置（订阅提供者节点会重连）",
            (Self::Reload, Lang::En) => "Reloading the config (proxy-provider nodes reconnect)",
            (Self::Reload, Lang::Ja) => "設定リロード（プロバイダーノード再接続）",
        }
    }

    /// A reload that also rebuilds TUN cuts its connections too.
    fn tun_label(lang: Lang) -> &'static str {
        match lang {
            Lang::Zh => "重载配置（订阅提供者节点会重连，TUN 将重建）",
            Lang::En => "Reloading the config (proxy-provider nodes reconnect, TUN is rebuilt)",
            Lang::Ja => "設定リロード（プロバイダーノード再接続、TUN 再構築）",
        }
    }

    /// The closed-history cause noted on confirmation. `CloseAll` is noted by
    /// the `X` key itself; reloads and TUN changes are announced by the worker
    /// just before it sends them (`mihomo::announce_disruption`), since an
    /// unchanged config is not reloaded and a failed check reloads nothing.
    fn cause(self) -> Option<Cause> {
        match self {
            Self::CoreStop => Some(Cause::CoreStopped),
            Self::CloseAll | Self::TunOff | Self::TunOnRestart | Self::Reload => None,
        }
    }
}

fn prompt(what: Disrupt, hit: conns::Affected, lang: Lang, tun_rebuild: bool) -> String {
    let label = if tun_rebuild {
        Disrupt::tun_label(lang)
    } else {
        what.label(lang)
    };
    let (n, a) = (hit.sessions, hit.ai);
    // A regenerated config identical to the running one is not reloaded.
    let may = what == Disrupt::Reload;
    match lang {
        Lang::Zh => {
            let verb = if may { "可能断开" } else { "将断开" };
            format!("{label}{verb} {n} 条长连接/AI 连接（其中 AI {a} 条）。再按一次确认")
        }
        Lang::En => {
            let verb = if may { "may" } else { "will" };
            format!(
                "{label} {verb} drop {n} long-lived/AI connection(s) ({a} AI). Press again to confirm"
            )
        }
        Lang::Ja => {
            let verb = if may {
                "切断される場合があります"
            } else {
                "切断されます"
            };
            format!("{label}で長時間/AI 接続 {n} 件（AI {a} 件）が{verb}。再度押して確定")
        }
    }
}

impl App {
    /// Sessions in the current snapshot that `what` would cut.
    pub fn affected(&self, what: Disrupt) -> conns::Affected {
        let now = conns::now_ms();
        let all = self.snapshot.connections.iter();
        match what {
            Disrupt::CloseAll | Disrupt::CoreStop | Disrupt::TunOnRestart => {
                conns::count_sessions(all, now)
            }
            Disrupt::TunOff => {
                conns::count_sessions(all.filter(|c| c.inbound.eq_ignore_ascii_case("tun")), now)
            }
            Disrupt::Reload => {
                let tun = self.reload_rebuilds_tun();
                conns::count_sessions(
                    all.filter(|c| {
                        !c.provider.is_empty() || (tun && c.inbound.eq_ignore_ascii_case("tun"))
                    }),
                    now,
                )
            }
        }
    }

    /// Linux: the first regeneration after terc started writing `tun.gso`
    /// changes a running TUN's settings, and Mihomo rebuilds TUN for it.
    fn reload_rebuilds_tun(&self) -> bool {
        self.snapshot.tun_enabled
            && crate::mihomo::read_config_text(&self.config.controller)
                .is_ok_and(|doc| crate::compose::reload_adds_tun_gso(&doc))
    }

    /// `true` when the caller may go ahead. The first press of an action that
    /// would cut sessions only shows the counts and returns `false`.
    pub fn confirm_disruption(&mut self, what: Disrupt) -> bool {
        // `run_action` refuses while busy; keep that refusal visible and do not
        // let this press arm or consume a confirmation.
        if self.action_busy || !self.snapshot.running {
            return true;
        }
        let hit = self.affected(what);
        let tun_rebuild = what == Disrupt::Reload && self.reload_rebuilds_tun();
        let again = self
            .pending_confirm
            .is_some_and(|(pending, at)| pending == what && at.elapsed() < CONFIRM_WINDOW);
        if hit.sessions > 0 && !again && self.screen != Screen::Setup {
            self.pending_confirm = Some((what, Instant::now()));
            self.set_status(&prompt(what, hit, self.lang(), tun_rebuild), false);
            return false;
        }
        self.pending_confirm = None;
        if let Some(cause) = what.cause() {
            self.conns.note(cause, conns::Scope::All);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{mihomo::ConnectionItem, Config};
    use ratatui::{backend::TestBackend, Terminal};

    fn conn(id: &str, age_secs: i64, ai: bool, provider: &str, inbound: &str) -> ConnectionItem {
        let mut item =
            crate::mihomo::connection_from_value(&serde_json::json!({ "id": id })).unwrap();
        item.host = format!("{id}.test:443");
        item.start_ms = Some(conns::now_ms() - age_secs * 1000);
        item.ai = ai;
        item.provider = provider.into();
        item.inbound = inbound.into();
        item
    }

    fn app_with(connections: Vec<ConnectionItem>) -> App {
        let mut app = App::from_snapshot(Config::default(), Default::default());
        app.screen = Screen::Dashboard;
        app.snapshot.running = true;
        app.snapshot.connections_ok = true;
        app.snapshot.connections = connections;
        app
    }

    /// One provider session over TUN, one AI session, one short connection.
    fn mixed() -> App {
        app_with(vec![
            conn("sub", 120, false, "airport", "Tun"),
            conn("ai", 3, true, "", "Mixed"),
            conn("short", 3, false, "airport", "Tun"),
        ])
    }

    /// The cause the tracker gives a long-lived top-level, Mixed-inbound
    /// session closing now.
    fn cause(app: &mut App) -> Option<Cause> {
        cause_for(app, conn("probe", 120, false, "", "Mixed"))
    }

    fn cause_for(app: &mut App, probe: ConnectionItem) -> Option<Cause> {
        let mut conns = vec![probe];
        app.conns
            .observe(&mut conns, true, Instant::now(), conns::now_ms());
        let closed = app
            .conns
            .observe(&mut [], true, Instant::now(), conns::now_ms());
        closed.first().and_then(|c| c.cause)
    }

    #[test]
    fn no_sessions_or_stopped_core_proceed_without_a_prompt() {
        let mut app = app_with(vec![conn("short", 3, false, "airport", "Tun")]);
        for what in [
            Disrupt::CloseAll,
            Disrupt::TunOff,
            Disrupt::TunOnRestart,
            Disrupt::CoreStop,
            Disrupt::Reload,
        ] {
            assert!(app.confirm_disruption(what), "{what:?}");
        }
        assert!(app.status_message.is_empty());
        assert!(app.pending_confirm.is_none());

        let mut app = mixed();
        app.snapshot.running = false;
        assert!(app.confirm_disruption(Disrupt::CoreStop));
        assert!(app.status_message.is_empty());
    }

    #[test]
    fn second_press_within_the_window_confirms() {
        let mut app = mixed();
        assert!(!app.confirm_disruption(Disrupt::CloseAll));
        assert_eq!(
            app.status_message,
            "全部断开将断开 2 条长连接/AI 连接（其中 AI 1 条）。再按一次确认"
        );
        assert!(!app.status_is_error);
        assert!(app.confirm_disruption(Disrupt::CloseAll));
        assert!(app.pending_confirm.is_none());
        // CloseAll notes its own cause in the `X` arm.
        assert_eq!(cause(&mut app), None);

        // A stale confirmation asks again.
        assert!(!app.confirm_disruption(Disrupt::CloseAll));
        app.pending_confirm = Some((Disrupt::CloseAll, Instant::now() - CONFIRM_WINDOW));
        assert!(!app.confirm_disruption(Disrupt::CloseAll));
        assert!(app.confirm_disruption(Disrupt::CloseAll));
    }

    #[test]
    fn a_different_action_replaces_the_pending_one() {
        let mut app = mixed();
        assert!(!app.confirm_disruption(Disrupt::CoreStop));
        assert!(!app.confirm_disruption(Disrupt::Reload));
        assert_eq!(app.pending_confirm.map(|p| p.0), Some(Disrupt::Reload));
        assert!(!app.confirm_disruption(Disrupt::CoreStop));
        assert!(app.confirm_disruption(Disrupt::CoreStop));
        assert_eq!(cause(&mut app), Some(Cause::CoreStopped));
    }

    #[test]
    fn tun_off_counts_tun_inbound_and_reload_counts_provider_nodes() {
        let mut app = mixed();
        let one = conns::Affected { sessions: 1, ai: 0 };
        assert_eq!(app.affected(Disrupt::TunOff), one);
        assert_eq!(app.affected(Disrupt::Reload), one);
        let all = conns::Affected { sessions: 2, ai: 1 };
        for what in [Disrupt::CloseAll, Disrupt::CoreStop, Disrupt::TunOnRestart] {
            assert_eq!(app.affected(what), all, "{what:?}");
        }

        app.config.settings.lang = Lang::En;
        assert!(!app.confirm_disruption(Disrupt::Reload));
        assert_eq!(
            app.status_message,
            "Reloading the config (proxy-provider nodes reconnect) may drop 1 \
             long-lived/AI connection(s) (0 AI). Press again to confirm"
        );
        assert!(app.confirm_disruption(Disrupt::Reload));
        // Confirming blames nothing: an unchanged config is never reloaded.
        assert_eq!(cause(&mut app), None);

        // Without TUN or provider sessions neither prompts.
        let mut app = app_with(vec![conn("ai", 3, true, "", "Mixed")]);
        assert!(app.confirm_disruption(Disrupt::TunOff));
        assert_eq!(cause(&mut app), None);
        assert!(app.confirm_disruption(Disrupt::Reload));
        assert!(app.status_message.is_empty());
    }

    #[test]
    fn announced_reloads_and_tun_rebuilds_blame_only_what_they_cut() {
        use crate::{conns::Scope, mihomo::BackendEvent};
        let mut app = mixed();
        let announce = |app: &mut App, cause, scope| {
            app.tx
                .send(BackendEvent::Disrupting { cause, scope })
                .unwrap();
            app.drain_events();
        };
        announce(&mut app, Cause::Reload, Scope::Providers);
        assert_eq!(cause(&mut app), None);
        let provider = conn("p", 120, false, "airport", "Mixed");
        assert_eq!(cause_for(&mut app, provider), Some(Cause::Reload));

        announce(&mut app, Cause::Tun, Scope::TunInbound);
        assert_eq!(cause(&mut app), None);
        let tun = conn("t", 120, false, "", "Tun");
        assert_eq!(cause_for(&mut app, tun), Some(Cause::Tun));

        // A worker announces only through the channel it was given.
        let (tx, rx) = std::sync::mpsc::channel();
        let cfg = crate::mihomo::ControllerConfig {
            addr: "127.0.0.1:1".into(),
            ..Default::default()
        };
        std::thread::spawn(move || {
            let _ = crate::mihomo::reload_config(&cfg);
            crate::mihomo::report_disruptions(tx);
            let _ = crate::mihomo::reload_config(&cfg);
        })
        .join()
        .unwrap();
        // The refused PUT cut nothing, so its announcement is withdrawn.
        let events: Vec<_> = rx.try_iter().collect();
        assert!(matches!(
            &events[..],
            [
                BackendEvent::Disrupting {
                    cause: Cause::Reload,
                    scope: Scope::Providers
                },
                BackendEvent::Disrupting {
                    cause: Cause::Reload,
                    scope: Scope::Id(id)
                }
            ] if id.is_empty()
        ));
    }

    #[test]
    fn a_reload_that_adds_tun_gso_counts_tun_sessions() {
        let dir = std::env::temp_dir().join(format!("terc-guard-gso-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // Top-level node and DIRECT sessions through TUN, no provider.
        let mut app = app_with(vec![
            conn("ai", 120, true, "", "Tun"),
            conn("direct", 120, false, "", "Tun"),
            conn("mixed", 120, false, "", "Mixed"),
        ]);
        app.config.controller.config_dir = dir.display().to_string();
        app.config.settings.lang = Lang::En;
        app.snapshot.tun_enabled = true;
        let write = |tun: &str| {
            std::fs::write(dir.join("config.yaml"), format!("mixed-port: 7890\n{tun}")).unwrap()
        };
        write("tun:\n  enable: true\n  stack: mixed\n");
        let linux = cfg!(target_os = "linux");
        let hit = app.affected(Disrupt::Reload);
        assert_eq!(hit.sessions, if linux { 2 } else { 0 });
        if linux {
            assert!(!app.confirm_disruption(Disrupt::Reload));
            assert!(
                app.status_message.starts_with(
                    "Reloading the config (proxy-provider nodes reconnect, TUN is rebuilt) may drop 2"
                ),
                "{}",
                app.status_message
            );
            assert!(app.confirm_disruption(Disrupt::Reload));
        }
        // Once the file has gso (or sets it either way) a reload keeps TUN.
        for kept in [
            "tun:\n  enable: true\n  gso: true\n",
            "tun:\n  enable: true\n  gso: false\n",
            "tun: {enable: true}\n",
        ] {
            write(kept);
            assert_eq!(app.affected(Disrupt::Reload).sessions, 0, "{kept}");
        }
        // TUN off: no TUN session to count, and the file is not read.
        write("tun:\n  enable: false\n");
        app.snapshot.tun_enabled = false;
        assert!(app.confirm_disruption(Disrupt::Reload));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_reload_that_rebuilds_tun_blames_tun_connections_too() {
        use crate::{conns::Scope, mihomo::BackendEvent};
        let mut app = mixed();
        // A worker composing a changed `tun:` block, then sending the reload.
        let (tx, worker_tx) = (app.tx.clone(), app.tx.clone());
        std::thread::spawn(move || {
            crate::mihomo::report_disruptions(worker_tx);
            crate::compose::carry_runtime_state(
                "tun:\n  enable: true\n  stack: mixed\n",
                "tun:\n  enable: true\n  stack: mixed\n  gso: true\n",
            );
        })
        .join()
        .unwrap();
        tx.send(BackendEvent::Disrupting {
            cause: Cause::Reload,
            scope: Scope::Providers,
        })
        .unwrap();
        app.drain_events();
        assert_eq!(
            cause_for(&mut app, conn("t", 120, false, "", "Tun")),
            Some(Cause::Tun)
        );
        let provider = conn("p", 120, false, "airport", "Tun");
        assert_eq!(cause_for(&mut app, provider), Some(Cause::Reload));
        assert_eq!(cause(&mut app), None);
    }

    #[test]
    fn busy_app_and_setup_never_arm_a_confirmation() {
        let mut app = mixed();
        app.action_busy = true;
        assert!(app.confirm_disruption(Disrupt::CloseAll));
        assert!(app.pending_confirm.is_none());
        assert!(app.status_message.is_empty());
        app.action_busy = false;
        app.screen = Screen::Setup;
        assert!(app.confirm_disruption(Disrupt::Reload));
        assert!(app.status_message.is_empty());
    }

    #[test]
    fn call_sites_ask_first_and_x_is_inert_in_the_closed_history() {
        use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
        let mut app = mixed();
        // Nothing listens here, so a confirmed action cannot reach a real core.
        app.config.controller.addr = "127.0.0.1:1".into();
        app.main_tab = crate::MainTab::Connections;
        app.snapshot.tun_enabled = true;
        fn press(app: &mut App) {
            crate::handle_key(app, KeyEvent::new(KeyCode::Char('X'), KeyModifiers::NONE));
        }
        app.conn_closed_view = true;
        press(&mut app);
        assert!(app.status_message.is_empty() && app.pending_confirm.is_none());
        app.conn_closed_view = false;

        let first = [
            (Disrupt::TunOff, App::toggle_tun as fn(&mut App)),
            (Disrupt::CoreStop, App::toggle_core_service),
            (Disrupt::Reload, App::reload_profile),
            (Disrupt::Reload, App::toggle_dns),
            (Disrupt::Reload, App::update_subscription),
            (Disrupt::Reload, |app: &mut App| {
                app.start_manage_input(crate::manage::ManageInput::EditSubscription);
                app.manage_editor.load("https://sub.example/new");
                app.submit_manage_input();
                // Still open, so Enter again confirms.
                assert!(app.manage_input.is_some());
            }),
            (Disrupt::CloseAll, press),
        ];
        for (what, action) in first {
            app.clear_status();
            app.pending_confirm = None;
            action(&mut app);
            assert_eq!(app.pending_confirm.map(|p| p.0), Some(what), "{what:?}");
            assert!(app.status_message.contains("再按一次确认"), "{what:?}");
            assert!(!app.action_busy, "{what:?}");
        }
        press(&mut app);
        assert!(app.action_busy);
        assert!(app.pending_confirm.is_none());
    }

    #[test]
    fn prompt_renders_in_the_toast_at_every_width_and_language() {
        for lang in [Lang::Zh, Lang::En, Lang::Ja] {
            for what in [Disrupt::Reload, Disrupt::TunOnRestart] {
                for (width, height) in [(42, 12), (80, 24), (160, 40)] {
                    // Two-digit counts, as in a busy agent session.
                    let mut app = app_with(
                        (0..12)
                            .map(|i| conn(&i.to_string(), 120, i < 10, "airport", "Tun"))
                            .collect(),
                    );
                    app.config.settings.lang = lang;
                    assert!(!app.confirm_disruption(what));
                    let mut term = Terminal::new(TestBackend::new(width, height)).unwrap();
                    term.draw(|frame| crate::ui::draw(frame, &mut app)).unwrap();
                    let area = app.toast_area.expect("toast shown");
                    let buffer = term.backend().buffer();
                    let mut text = String::new();
                    for y in area.y + 1..area.bottom() - 1 {
                        for x in area.x + 1..area.right() - 1 {
                            text.push_str(buffer[(x, y)].symbol());
                        }
                    }
                    let strip = |s: &str| s.replace(' ', "");
                    assert_eq!(
                        strip(&text),
                        strip(&app.status_message),
                        "{lang:?} {what:?} {width}"
                    );
                }
            }
        }
    }
}
