//! User-selected controller instances. Addresses on loopback are machine-wide.
use std::{path::Path, time::Duration};

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    prelude::Frame,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, List, ListItem, Paragraph, Wrap},
};
use serde::{Deserialize, Serialize};

use crate::{
    mihomo,
    ui::{centered_rect, draw_panel, panel_title, visible_list_start},
    App, Lang, LineEditor, Overlay,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CoreInstance {
    pub name: String,
    pub controller: mihomo::ControllerConfig,
}

#[derive(Default)]
pub struct State {
    entries: Vec<CoreInstance>,
    selected: usize,
    form: Option<Form>,
    report: String,
    pending_delete: Option<usize>,
}

struct Form {
    index: Option<usize>,
    fields: [LineEditor; 4],
    focus: usize,
}

fn same(a: &mihomo::ControllerConfig, b: &mihomo::ControllerConfig) -> bool {
    a.addr == b.addr && a.config_dir == b.config_dir && a.secret == b.secret
}

fn selected_config(
    config: &crate::Config,
    entries: &[CoreInstance],
    selected: usize,
) -> crate::Config {
    let mut next = config.clone();
    let mut entries = entries.to_vec();
    if let Some(current) = entries
        .iter_mut()
        .find(|e| same(&e.controller, &config.controller))
    {
        current.controller = config.controller.clone();
    } else {
        entries.push(CoreInstance {
            name: "Current instance".into(),
            controller: config.controller.clone(),
        });
    }
    next.controller = entries[selected].controller.clone();
    next.core_instances = entries;
    next
}

pub fn open(app: &mut App) {
    let mut entries = app.config.core_instances.clone();
    let selected = entries
        .iter()
        .position(|e| same(&e.controller, &app.config.controller))
        .unwrap_or_else(|| {
            entries.push(CoreInstance {
                name: if app.lang() == Lang::Zh {
                    "当前实例"
                } else {
                    "Current instance"
                }
                .into(),
                controller: app.config.controller.clone(),
            });
            entries.len() - 1
        });
    app.core_instances_ui = State {
        entries,
        selected,
        form: None,
        report: String::new(),
        pending_delete: None,
    };
    app.overlay = Overlay::CoreInstances;
}

fn start_form(app: &mut App, edit: bool) {
    let state = &mut app.core_instances_ui;
    let index = edit.then_some(state.selected);
    let mut fields: [LineEditor; 4] = std::array::from_fn(|_| LineEditor::default());
    if let Some(entry) = index.and_then(|i| state.entries.get(i)) {
        for (field, value) in fields.iter_mut().zip([
            &entry.name,
            &entry.controller.addr,
            &entry.controller.config_dir,
            &entry.controller.secret,
        ]) {
            field.load(value);
        }
    }
    state.form = Some(Form {
        index,
        fields,
        focus: 0,
    });
    state.report.clear();
}

fn save_entries(app: &mut App, entries: Vec<CoreInstance>) -> Result<(), String> {
    let mut next = app.config.clone();
    next.core_instances = entries;
    next.save()?;
    app.config.core_instances = next.core_instances;
    Ok(())
}

fn save_form(app: &mut App) {
    let Some(form) = app.core_instances_ui.form.as_ref() else {
        return;
    };
    let values: Vec<_> = form.fields.iter().map(|f| f.trimmed()).collect();
    if values[0].is_empty() || values[1].is_empty() || values[2].is_empty() {
        app.core_instances_ui.report =
            "名称、控制器地址和配置目录不能为空 / Name, address and directory are required".into();
        return;
    }
    if let Err(err) = mihomo::controller_socket_addr(&values[1]) {
        app.core_instances_ui.report = format!("控制器地址无效 / Invalid controller: {err}");
        return;
    }
    let mut cfg = form
        .index
        .and_then(|i| app.core_instances_ui.entries.get(i))
        .map(|e| e.controller.clone())
        .unwrap_or_default();
    cfg.addr = values[1].clone();
    cfg.config_dir = values[2].clone();
    cfg.secret = values[3].clone();
    let entry = CoreInstance {
        name: values[0].clone(),
        controller: cfg,
    };
    let mut entries = app.core_instances_ui.entries.clone();
    let selected = if let Some(index) = form.index {
        entries[index] = entry;
        index
    } else {
        entries.push(entry);
        entries.len() - 1
    };
    match save_entries(app, entries.clone()) {
        Ok(()) => {
            app.core_instances_ui.entries = entries;
            app.core_instances_ui.selected = selected;
            app.core_instances_ui.form = None;
            app.core_instances_ui.report =
                "已保存；Enter 选择，c 检查 / Saved; Enter selects, c checks".into();
        }
        Err(err) => app.core_instances_ui.report = format!("保存失败 / Save failed: {err}"),
    }
}

/// This check is read-only. A successful response cannot identify the process
/// owner or prove that the selected directory belongs to that process.
pub fn check(cfg: &mihomo::ControllerConfig) -> String {
    let request = |path| {
        mihomo::http_request(
            &cfg.addr,
            &cfg.secret,
            "GET",
            path,
            None,
            Duration::from_secs(3),
        )
    };
    let controller = match request("/version") {
        Ok((401 | 403, _)) => "控制器认证失败：检查地址和该实例的 secret / Authentication failed: check address and secret".to_string(),
        Ok((200, body)) if serde_json::from_str::<serde_json::Value>(&body).ok().and_then(|v| v.get("version").and_then(|v| v.as_str()).map(str::to_owned)).is_some() => {
            match request("/configs") {
                Ok((200, _)) => "控制器可访问；实例归属尚未确认 / Controller reachable; instance identity unconfirmed".into(),
                Ok((401 | 403, _)) => "控制器认证失败：检查地址和 secret / Authentication failed: check address and secret".into(),
                Ok((status, _)) => format!("/configs 返回 HTTP {status}；请检查控制器 / Check controller"),
                Err(err) => format!("/configs 不可达 / Unreachable: {err}"),
            }
        }
        Ok((status, _)) => format!("/version 返回 HTTP {status} 或响应无效 / Unexpected response"),
        Err(err) => format!("控制器不可达 / Controller unreachable: {err}"),
    };
    let dir = Path::new(&cfg.config_dir);
    let directory = if !dir.exists() {
        "配置目录不存在，请核对路径 / Configuration directory does not exist"
    } else if !dir.is_dir() {
        "配置路径不是目录 / Configuration path is not a directory"
    } else if !dir.join("config.yaml").is_file() {
        "目录中没有 config.yaml，请核对路径 / No config.yaml in directory"
    } else {
        "配置目录存在；请核对它属于所选内核 / Directory exists; verify it belongs to this core"
    };
    let file = std::fs::read_to_string(dir.join("config.yaml")).ok();
    let declared = file
        .as_deref()
        .and_then(|raw| {
            crate::ops::split_chunks(raw)
                .into_iter()
                .find(|c| c.key.as_deref() == Some("external-controller"))
        })
        .and_then(|c| {
            c.lines
                .first()
                .and_then(|l| l.split_once(':'))
                .map(|(_, v)| crate::ops::clean_scalar(v))
        });
    let mismatch = declared.filter(|v| !v.is_empty() && v != &cfg.addr).map(|v| format!("\n文件中的控制器为 {v}；启动参数可能覆盖文件，请核对 / File declares {v}; launch arguments may override it")).unwrap_or_default();
    format!("{controller}\n{directory}{mismatch}\n未测试代理出站 / Proxy outbound not tested")
}

pub fn paste(app: &mut App, text: &str) {
    if let Some(form) = app.core_instances_ui.form.as_mut() {
        form.fields[form.focus].insert_text(text.trim());
    }
}

pub fn handle_key(app: &mut App, key: KeyEvent) -> bool {
    if let Some(form) = app.core_instances_ui.form.as_mut() {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('u' | 'w'))
        {
            form.fields[form.focus].clear();
            return false;
        }
        match key.code {
            KeyCode::Esc => app.core_instances_ui.form = None,
            KeyCode::Tab | KeyCode::Down => form.focus = (form.focus + 1) % 4,
            KeyCode::BackTab | KeyCode::Up => form.focus = (form.focus + 3) % 4,
            KeyCode::Enter => save_form(app),
            KeyCode::Backspace => {
                form.fields[form.focus].backspace();
            }
            KeyCode::Delete => {
                form.fields[form.focus].delete();
            }
            KeyCode::Left => form.fields[form.focus].move_left(),
            KeyCode::Right => form.fields[form.focus].move_right(),
            KeyCode::Home => form.fields[form.focus].move_home(),
            KeyCode::End => form.fields[form.focus].move_end(),
            KeyCode::Char(c) if !c.is_control() => {
                form.fields[form.focus].insert_text(&c.to_string());
            }
            _ => {}
        }
        return false;
    }
    let state = &mut app.core_instances_ui;
    if !matches!(key.code, KeyCode::Char('d') | KeyCode::Delete) {
        state.pending_delete = None;
    }
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') => app.close_overlay(),
        KeyCode::Up | KeyCode::Char('k') => {
            state.selected = state
                .selected
                .checked_sub(1)
                .unwrap_or(state.entries.len().saturating_sub(1))
        }
        KeyCode::Down | KeyCode::Char('j') => {
            if !state.entries.is_empty() {
                state.selected = (state.selected + 1) % state.entries.len();
            }
        }
        KeyCode::Char('a') => start_form(app, false),
        KeyCode::Char('e') => start_form(app, true),
        KeyCode::Char('c') => {
            let cfg = state.entries[state.selected].controller.clone();
            state.report = check(&cfg);
        }
        KeyCode::Char('d') | KeyCode::Delete => {
            if same(
                &state.entries[state.selected].controller,
                &app.config.controller,
            ) {
                state.report = "当前实例不能删除 / Cannot delete the active instance".into();
            } else if state.pending_delete != Some(state.selected) {
                state.pending_delete = Some(state.selected);
                state.report = "再按一次 d 删除所选实例 / Press d again to delete".into();
            } else {
                let mut entries = state.entries.clone();
                entries.remove(state.selected);
                match save_entries(app, entries.clone()) {
                    Ok(()) => {
                        app.core_instances_ui.entries = entries;
                        app.core_instances_ui.selected = app
                            .core_instances_ui
                            .selected
                            .min(app.core_instances_ui.entries.len().saturating_sub(1));
                        app.core_instances_ui.pending_delete = None;
                        app.core_instances_ui.report = "实例已删除 / Instance deleted".into();
                    }
                    Err(err) => app.core_instances_ui.report = err,
                }
            }
        }
        KeyCode::Enter => {
            if app.action_busy
                || app.snapshot_pending
                || app.group_tests > 0
                || app.replies_owed > 0
            {
                state.report = "请等待当前操作完成 / Wait for ongoing actions".into();
                return false;
            }
            let selected = state.entries[state.selected].controller.clone();
            if same(&selected, &app.config.controller) {
                state.report = "这已经是当前实例 / Already active".into();
                return false;
            }
            let next = selected_config(&app.config, &state.entries, state.selected);
            match next.save() {
                Ok(()) => {
                    app.restart_for_core = true;
                    return true;
                }
                Err(err) => app.core_instances_ui.report = format!("保存失败 / Save failed: {err}"),
            }
        }
        _ => {}
    }
    false
}

pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let popup = centered_rect(90, 84, area);
    frame.render_widget(Clear, popup);
    let inner = draw_panel(
        frame,
        popup,
        theme,
        Some(panel_title(
            if app.lang() == Lang::Zh {
                "内核实例"
            } else {
                "Core instances"
            }
            .into(),
            theme,
        )),
        true,
    );
    let state = &app.core_instances_ui;
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(2),
            Constraint::Length(if state.form.is_some() { 7 } else { 0 }),
            Constraint::Length(3),
            Constraint::Length(5),
            Constraint::Length(2),
        ])
        .split(inner);
    let visible = chunks[0].height as usize;
    let start = visible_list_start(state.selected, state.entries.len(), visible);
    let items: Vec<_> = state
        .entries
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(i, e)| {
            let selected = i == state.selected;
            let active = same(&e.controller, &app.config.controller);
            let text = format!(
                "{} {}  {}  {}  {}",
                if selected { "›" } else { " " },
                if active { "●" } else { "○" },
                e.name,
                e.controller.addr,
                e.controller.config_dir
            );
            ListItem::new(text).style(if selected {
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD | Modifier::REVERSED)
            } else {
                Style::default().fg(theme.text)
            })
        })
        .collect();
    frame.render_widget(List::new(items), chunks[0]);
    if let Some(form) = &state.form {
        let labels = if app.lang() == Lang::Zh {
            ["名称", "控制器地址", "配置目录", "密钥（空为无认证）"]
        } else {
            [
                "Name",
                "Controller address",
                "Config directory",
                "Secret (empty = no auth)",
            ]
        };
        let lines: Vec<_> = labels
            .iter()
            .enumerate()
            .map(|(i, label)| {
                let mut value = if i == 3 {
                    "•".repeat(form.fields[i].text.chars().count())
                } else {
                    form.fields[i].text.clone()
                };
                if i == form.focus {
                    let at = value
                        .char_indices()
                        .nth(form.fields[i].cursor)
                        .map(|(at, _)| at)
                        .unwrap_or(value.len());
                    value.insert(at, '▏');
                }
                Line::from(vec![
                    Span::styled(
                        if i == form.focus { "› " } else { "  " },
                        Style::default().fg(theme.accent),
                    ),
                    Span::raw(format!("{label}: {value}")),
                ])
            })
            .collect();
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: false }), chunks[1]);
    }
    if let Some(entry) = state.entries.get(state.selected) {
        frame.render_widget(
            Paragraph::new(format!(
                "控制器 / Controller: {}\n配置目录 / Directory: {}",
                entry.controller.addr, entry.controller.config_dir
            ))
            .style(Style::default().fg(theme.text))
            .wrap(Wrap { trim: true }),
            chunks[2],
        );
    }
    frame.render_widget(
        Paragraph::new(state.report.as_str())
            .style(Style::default().fg(theme.text))
            .wrap(Wrap { trim: true }),
        chunks[3],
    );
    let hint = if state.form.is_some() {
        "Tab / ↑↓ 切换字段  Enter 保存  Esc 取消 / Save / Cancel"
    } else {
        "↑↓ 选择  a 添加  e 编辑  d 删除（再按确认）  c 检查  Enter 选择并退出  Esc 返回"
    };
    frame.render_widget(
        Paragraph::new(hint)
            .style(Style::default().fg(theme.muted))
            .wrap(Wrap { trim: true }),
        chunks[4],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        thread,
    };

    fn mock(status: u16) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = thread::spawn(move || {
            let count = if status == 200 { 2 } else { 1 };
            for _ in 0..count {
                let (mut stream, _) = listener.accept().unwrap();
                let mut bytes = [0; 4096];
                let n = stream.read(&mut bytes).unwrap();
                let request = String::from_utf8_lossy(&bytes[..n]);
                let body = if status == 200 && request.starts_with("GET /version ") {
                    r#"{"version":"v1.19.0"}"#
                } else {
                    "{}"
                };
                write!(stream, "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        (addr, server)
    }

    #[test]
    fn check_distinguishes_auth_failure_unreachable_and_directory_mismatch() {
        let dir = std::env::temp_dir().join(format!("terc-instance-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("config.yaml"),
            "external-controller: 127.0.0.1:38890\nsecret: do-not-print\n",
        )
        .unwrap();
        let (addr, server) = mock(200);
        let cfg = mihomo::ControllerConfig {
            addr,
            secret: "do-not-print".into(),
            config_dir: dir.display().to_string(),
            ..Default::default()
        };
        let result = check(&cfg);
        server.join().unwrap();
        assert!(
            result.contains("Controller reachable") && result.contains("identity unconfirmed"),
            "{result}"
        );
        assert!(
            result.contains("127.0.0.1:38890") && result.contains("may override"),
            "{result}"
        );
        assert!(result.contains("Proxy outbound not tested"));
        assert!(!result.contains("do-not-print"));
        let (addr, server) = mock(401);
        let cfg = mihomo::ControllerConfig {
            addr,
            config_dir: dir.join("missing").display().to_string(),
            ..cfg
        };
        let result = check(&cfg);
        server.join().unwrap();
        assert!(
            result.contains("Authentication failed") && result.contains("directory does not exist"),
            "{result}"
        );
        assert!(!result.contains("do-not-print"));
        let result = check(&cfg);
        assert!(result.contains("Controller unreachable"), "{result}");
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn selection_preserves_each_instance_and_empty_secret_through_save() {
        let dir = std::env::temp_dir().join(format!("terc-instances-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.json");
        let mut cfg = crate::Config::default();
        cfg.controller.secret = "old-secret".into();
        cfg.controller.profile_id = "old-profile".into();
        let first = CoreInstance {
            name: "old".into(),
            controller: cfg.controller.clone(),
        };
        let second = CoreInstance {
            name: "xkp".into(),
            controller: mihomo::ControllerConfig {
                addr: "127.0.0.1:38890".into(),
                config_dir: "/home/xkp/.local/better-server/config".into(),
                secret: String::new(),
                profile_id: "xkp-profile".into(),
                ..Default::default()
            },
        };
        let next = selected_config(&cfg, &[first, second], 1);
        next.save_to(&path).unwrap();
        let (loaded, issue) = crate::Config::load_from(&path, 0);
        assert!(issue.is_none());
        assert_eq!(loaded.controller.addr, "127.0.0.1:38890");
        assert_eq!(loaded.controller.profile_id, "xkp-profile");
        assert!(loaded.controller.secret.is_empty());
        assert_eq!(loaded.core_instances[0].controller.secret, "old-secret");
        assert_eq!(
            loaded.core_instances[0].controller.profile_id,
            "old-profile"
        );
        assert_eq!(
            selected_config(&loaded, &loaded.core_instances, 0)
                .controller
                .addr,
            cfg.controller.addr
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn instance_screen_shows_controller_and_directory_without_revealing_secret() {
        use ratatui::{backend::TestBackend, Terminal};
        let mut cfg = crate::Config::default();
        cfg.controller.addr = "127.0.0.1:38890".into();
        cfg.controller.config_dir = "/home/xkp/.local/better-server/config".into();
        cfg.controller.secret = "hidden-secret".into();
        let mut app = App::from_snapshot(cfg, mihomo::CoreSnapshot::default());
        open(&mut app);
        handle_key(&mut app, KeyEvent::from(KeyCode::Char('e')));
        let mut terminal = Terminal::new(TestBackend::new(120, 36)).unwrap();
        terminal
            .draw(|frame| draw(frame, &app, frame.area()))
            .unwrap();
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        assert!(text.contains("127.0.0.1:38890"), "{text}");
        assert!(
            text.contains("/home/xkp/.local/better-server/config"),
            "{text}"
        );
        assert!(!text.contains("hidden-secret"), "{text}");
        assert!(text.contains('•'), "{text}");
        handle_key(&mut app, KeyEvent::from(KeyCode::Esc));
        assert!(app.core_instances_ui.form.is_none());
        let mut other = app.core_instances_ui.entries[0].clone();
        other.controller.addr = "127.0.0.1:9090".into();
        app.core_instances_ui.entries.push(other);
        app.core_instances_ui.selected = 1;
        handle_key(&mut app, KeyEvent::from(KeyCode::Char('d')));
        assert_eq!(app.core_instances_ui.entries.len(), 2);
        assert!(app.core_instances_ui.report.contains("再按一次"));
    }
}
