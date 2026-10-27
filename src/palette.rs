//! Keyboard command palette. One searchable list over the actions that are
//! otherwise spread across tabs, settings and shortcuts.

use crate::{App, Lang, MainTab, Screen};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    Proxies,
    Connections,
    Logs,
    Dns,
    Rules,
    Providers,
    Settings,
    Help,
    Sysproxy,
    Mode,
    Tun,
    TestGroup,
    BestNode,
    Refresh,
    Talkers,
    Quit,
}

pub struct Item {
    pub command: Command,
    pub label: String,
    /// Extra English tokens so both languages match.
    pub keywords: &'static str,
    pub hint: &'static str,
}

fn label(app: &App, zh: &'static str, en: &'static str) -> String {
    if app.lang() == Lang::Zh {
        zh.into()
    } else {
        en.into()
    }
}

pub fn items(app: &App) -> Vec<Item> {
    vec![
        Item {
            command: Command::Proxies,
            label: label(app, "节点面板", "Proxies"),
            keywords: "proxy node group 节点",
            hint: "p",
        },
        Item {
            command: Command::Connections,
            label: label(app, "连接监控", "Connections"),
            keywords: "connection traffic 连接",
            hint: "c",
        },
        Item {
            command: Command::Logs,
            label: label(app, "实时日志", "Live logs"),
            keywords: "log 日志",
            hint: "L",
        },
        Item {
            command: Command::Dns,
            label: label(app, "DNS", "DNS"),
            keywords: "dns query 解析",
            hint: "",
        },
        Item {
            command: Command::Rules,
            label: label(app, "规则", "Rules"),
            keywords: "rule 规则",
            hint: "",
        },
        Item {
            command: Command::Providers,
            label: label(app, "远程资源", "Providers"),
            keywords: "provider rule-set 订阅",
            hint: "",
        },
        Item {
            command: Command::Settings,
            label: label(app, "设置", "Settings"),
            keywords: "setting preference 设置",
            hint: "s",
        },
        Item {
            command: Command::Help,
            label: label(app, "快捷键帮助", "Keyboard help"),
            keywords: "help key 帮助",
            hint: "?",
        },
        Item {
            command: Command::Sysproxy,
            label: label(app, "切换系统代理", "Toggle system proxy"),
            keywords: "system proxy sysproxy 系统代理",
            hint: "Space",
        },
        Item {
            command: Command::Mode,
            label: label(app, "切换分流模式", "Cycle routing mode"),
            keywords: "mode rule global direct 分流",
            hint: "m",
        },
        Item {
            command: Command::Tun,
            label: label(app, "切换 TUN", "Toggle TUN"),
            keywords: "tun vpn 虚拟网卡",
            hint: "",
        },
        Item {
            command: Command::TestGroup,
            label: label(app, "测速当前策略组", "Test current group"),
            keywords: "test delay speed 测速",
            hint: "r",
        },
        Item {
            command: Command::BestNode,
            label: label(app, "优选节点", "Pick best node"),
            keywords: "best auto pick 优选",
            hint: "a",
        },
        Item {
            command: Command::Refresh,
            label: label(app, "立即刷新", "Refresh now"),
            keywords: "refresh reload 刷新",
            hint: "F",
        },
        Item {
            command: Command::Quit,
            label: label(app, "退出 terc", "Quit terc"),
            keywords: "quit exit 退出",
            hint: "q",
        },
    ]
}

pub fn filtered(app: &App) -> Vec<Item> {
    let query = app.palette_query.text.trim().to_lowercase();
    let all = items(app);
    if query.is_empty() {
        return all;
    }
    all.into_iter()
        .filter(|item| {
            item.label.to_lowercase().contains(&query)
                || item.keywords.to_lowercase().contains(&query)
                || item.hint.contains(&query)
        })
        .collect()
}

/// Returns true when the command asks terc to quit.
pub fn execute(app: &mut App, command: Command) -> bool {
    app.close_overlay();
    match command {
        Command::Proxies => {
            app.screen = Screen::Dashboard;
            app.main_tab = MainTab::Proxies;
        }
        Command::Connections => {
            app.screen = Screen::Dashboard;
            app.main_tab = MainTab::Connections;
        }
        Command::Logs => {
            app.load_core_log();
            app.screen = Screen::Dashboard;
            app.main_tab = MainTab::Logs;
        }
        Command::Dns => {
            app.screen = Screen::Dashboard;
            app.main_tab = MainTab::Dns;
        }
        Command::Rules => {
            app.screen = Screen::Dashboard;
            app.main_tab = MainTab::Rules;
        }
        Command::Providers => {
            app.screen = Screen::Dashboard;
            app.main_tab = MainTab::Providers;
        }
        Command::Settings => {
            app.screen = Screen::Settings;
            app.setting_index = 0;
        }
        Command::Help => app.screen = Screen::Help,
        Command::Sysproxy => app.toggle_sysproxy(),
        Command::Mode => app.cycle_routing_mode(),
        Command::Tun => app.toggle_tun(),
        Command::TestGroup => app.test_current_group(),
        Command::BestNode => app.select_best_node_in_group(),
        Command::Refresh => app.refresh_snapshot_now(),
        Command::Talkers => {
            app.overlay = crate::Overlay::Talkers;
            app.talker_index = 0;
        }
        Command::Quit => return true,
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mihomo::CoreSnapshot;
    use crate::{Config, Overlay};

    fn app() -> App {
        App::from_snapshot(Config::default(), CoreSnapshot::default())
    }

    #[test]
    fn filters_by_label_and_keyword() {
        let mut a = app();
        a.palette_query.load("tun");
        let hits = filtered(&a);
        assert!(hits.iter().any(|i| i.command == Command::Tun));

        a.palette_query.load("连接");
        let hits = filtered(&a);
        assert!(hits.iter().any(|i| i.command == Command::Connections));

        a.palette_query.load("zzz-no-such-command");
        assert!(filtered(&a).is_empty());
    }

    #[test]
    fn executes_and_closes_the_overlay() {
        let mut a = app();
        a.overlay = Overlay::Palette;
        a.main_tab = MainTab::Proxies;
        assert!(!execute(&mut a, Command::Connections));
        assert_eq!(a.main_tab, MainTab::Connections);
        assert_eq!(a.overlay, Overlay::None);
    }
}
