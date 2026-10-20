//! Unified profiles and manual-node management. Legacy private-rule tools are not exposed.
//!
//! Every change is written to `~/.config/terc/` first, then the config is
//! regenerated, validated with `mihomo -t`, and hot-reloaded in the background.
//! Node secrets never reach the screen: rows show name, type and server only.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    prelude::Frame,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, List, ListItem, Paragraph, Wrap},
};

use crate::{
    compose::{
        add_manual_node, load_manual_nodes, parse_rule_input, remove_manual_node, rule_target,
        set_rule_target, PrivateRules, AI_PRESET, POLICY_TARGETS,
    },
    mihomo::{is_info_pseudo_node, test_node_async},
    subconv::node_summary,
    ui::{
        centered_rect, delay_color, draw_panel, editor_cursor_cell, editor_line_spans, panel_title,
        truncate_str, visible_list_start,
    },
    App, Lang, Overlay,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManageInput {
    AddNode,
    AddRule,
    AddProfile,
    RenameProfile,
}

/// Pick the Chinese, English or Japanese string for the current language.
pub fn l3(app: &App, zh: &'static str, en: &'static str, ja: &'static str) -> &'static str {
    match app.lang() {
        Lang::Zh => zh,
        Lang::En => en,
        Lang::Ja => ja,
    }
}

const BUILTIN_POLICIES: &[&str] = &[
    "DIRECT",
    "REJECT",
    "REJECT-DROP",
    "PASS",
    "COMPATIBLE",
    "GLOBAL",
];

impl App {
    pub fn open_own_nodes(&mut self) {
        self.own_nodes = load_manual_nodes(&crate::compose::profile_dir(&self.config.controller));
        self.own_node_index = self
            .own_node_index
            .min(self.own_nodes.len().saturating_sub(1));
        self.manage_input = None;
        self.overlay = Overlay::OwnNodes;
    }

    pub fn open_private_rules(&mut self) {
        self.private_rules =
            PrivateRules::load(&crate::compose::profile_dir(&self.config.controller));
        self.private_rule_index = self
            .private_rule_index
            .min(self.private_rules.rules.len().saturating_sub(1));
        self.manage_input = None;
        self.ai_picker = false;
        self.overlay = Overlay::PrivateRules;
    }

    /// Regenerate config.yaml from the cached subscription + manual nodes + rules.
    pub fn apply_composed(&mut self) {
        if self.action_busy {
            self.pending_regen = true;
            return;
        }
        let catalog = crate::ops::module_catalog(&crate::ops::modules_dir(
            &std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()),
        ));
        let modules = crate::ops::enabled_snippets(&catalog, &self.config.enabled_modules);
        let running = self.snapshot.running;
        let zh = self.lang() == Lang::Zh;
        let label = l3(
            self,
            "正在生成并校验配置…",
            "Generating and validating config…",
            "設定を生成・検証中…",
        );
        self.run_action(label, None, None, move |cfg| {
            crate::mihomo::regenerate_config(&cfg, &modules, running, false, zh)
        });
    }

    pub fn start_manage_input(&mut self, kind: ManageInput) {
        self.manage_editor.clear();
        self.manage_input = Some(kind);
    }

    pub fn submit_manage_input(&mut self) {
        let Some(kind) = self.manage_input else {
            return;
        };
        let text = self.manage_editor.trimmed();
        if text.is_empty() {
            self.manage_input = None;
            return;
        }
        match kind {
            ManageInput::AddProfile => self.import_profile(&text),
            ManageInput::RenameProfile => {
                if let Some(profile) = self.profiles.get(self.profile_index).cloned() {
                    let dir = std::path::Path::new(&profile.path).with_extension("");
                    let mut source = crate::compose::ProfileSource::load(&dir);
                    source.name = text;
                    match source.save(&dir) {
                        Ok(()) => {
                            if profile.active {
                                self.config.active_profile_label = source.name;
                                self.save_preferences();
                            }
                            self.manage_input = None;
                            self.open_profiles();
                        }
                        Err(err) => self.set_status(&err, true),
                    }
                }
            }
            ManageInput::AddNode => self.add_own_nodes(&text),
            ManageInput::AddRule => match parse_rule_input(&text) {
                Ok(rule) => {
                    let at = if self.private_rules.rules.is_empty() {
                        0
                    } else {
                        (self.private_rule_index + 1).min(self.private_rules.rules.len())
                    };
                    self.private_rules.rules.insert(at, rule);
                    self.private_rule_index = at;
                    self.manage_input = None;
                    self.save_rules_and_apply();
                }
                Err(err) => self.set_status(&err, true),
            },
        }
    }

    /// Add one or more pasted nodes (one per line). Never echoes the line.
    pub fn add_own_nodes(&mut self, text: &str) {
        if self.action_busy {
            self.set_status("请等待当前操作完成 / Wait for the current operation", true);
            return;
        }
        let dir = crate::compose::profile_dir(&self.config.controller);
        let mut added = Vec::new();
        let mut errors = Vec::new();
        // wg-quick .conf or Surge `[WireGuard x]` blocks become wireguard:// lines.
        let block_lines;
        let lines: Vec<&str> = match crate::subconv::block_to_node_lines(text) {
            Some(Ok(v)) => {
                block_lines = v;
                block_lines.iter().map(String::as_str).collect()
            }
            Some(Err(err)) => {
                errors.push(err);
                Vec::new()
            }
            None => text.lines().collect(),
        };
        for line in lines.into_iter().map(str::trim).filter(|l| !l.is_empty()) {
            match add_manual_node(&dir, line) {
                Ok(name) => added.push(name),
                Err(err) => errors.push(err),
            }
        }
        self.own_nodes = load_manual_nodes(&dir);
        if added.is_empty() {
            let err = errors.first().cloned().unwrap_or_default();
            self.set_status(
                &format!(
                    "{}: {err}",
                    l3(
                        self,
                        "无法添加节点",
                        "Cannot add node",
                        "ノードを追加できません"
                    )
                ),
                true,
            );
            return;
        }
        self.manage_input = None;
        self.own_node_index = self.own_nodes.len().saturating_sub(1);
        self.apply_composed();
    }

    pub fn remove_selected_own_node(&mut self) {
        if self.action_busy {
            self.set_status("请等待当前操作完成 / Wait for the current operation", true);
            return;
        }
        if self.own_nodes.is_empty() {
            return;
        }
        match remove_manual_node(
            &crate::compose::profile_dir(&self.config.controller),
            self.own_node_index,
        ) {
            Ok(_) => {
                self.own_nodes =
                    load_manual_nodes(&crate::compose::profile_dir(&self.config.controller));
                self.own_node_index = self
                    .own_node_index
                    .min(self.own_nodes.len().saturating_sub(1));
                self.apply_composed();
            }
            Err(err) => self.set_status(&err, true),
        }
    }

    pub fn test_own_nodes(&mut self, all: bool) {
        if !self.snapshot.running {
            self.set_status(
                l3(
                    self,
                    "内核未运行：按 K 启动后再测速",
                    "Core stopped: press K first",
                    "コア停止中：K で起動",
                ),
                true,
            );
            return;
        }
        let names: Vec<String> = if all {
            self.own_nodes.iter().map(|n| n.name()).collect()
        } else {
            self.own_nodes
                .get(self.own_node_index)
                .map(|n| vec![n.name()])
                .unwrap_or_default()
        };
        for name in names {
            test_node_async(self.config.controller.clone(), name, self.tx.clone());
        }
        self.set_status(l3(self, "测速中…", "Testing latency…", "測定中…"), false);
    }

    fn save_rules_and_apply(&mut self) {
        if let Err(err) = self
            .private_rules
            .save(&crate::compose::profile_dir(&self.config.controller))
        {
            self.set_status(&err, true);
            return;
        }
        self.apply_composed();
    }

    pub fn remove_selected_rule(&mut self) {
        if self.private_rule_index < self.private_rules.rules.len() {
            self.private_rules.rules.remove(self.private_rule_index);
            self.private_rule_index = self
                .private_rule_index
                .min(self.private_rules.rules.len().saturating_sub(1));
            self.save_rules_and_apply();
        }
    }

    pub fn move_selected_rule(&mut self, up: bool) {
        let len = self.private_rules.rules.len();
        let i = self.private_rule_index;
        if len < 2 || i >= len || (up && i == 0) || (!up && i + 1 >= len) {
            return;
        }
        let j = if up { i - 1 } else { i + 1 };
        self.private_rules.rules.swap(i, j);
        self.private_rule_index = j;
        self.save_rules_and_apply();
    }

    pub fn cycle_selected_rule_target(&mut self) {
        let Some(rule) = self
            .private_rules
            .rules
            .get(self.private_rule_index)
            .cloned()
        else {
            return;
        };
        let current = rule_target(&rule).to_ascii_uppercase();
        let next = POLICY_TARGETS
            .iter()
            .position(|t| *t == current)
            .map(|i| POLICY_TARGETS[(i + 1) % POLICY_TARGETS.len()])
            .unwrap_or(POLICY_TARGETS[0]);
        self.private_rules.rules[self.private_rule_index] = set_rule_target(&rule, next);
        self.save_rules_and_apply();
    }

    pub fn toggle_ai_preset(&mut self) {
        self.private_rules.ai.enabled = !self.private_rules.ai.enabled;
        self.save_rules_and_apply();
    }

    pub fn toggle_ai_kind(&mut self) {
        self.private_rules.ai.kind = if self.private_rules.ai.kind == "url-test" {
            "fallback".into()
        } else {
            "url-test".into()
        };
        self.save_rules_and_apply();
    }

    pub fn toggle_subscription_rules(&mut self) {
        self.private_rules.subscription_rules = !self.private_rules.subscription_rules;
        self.save_rules_and_apply();
    }

    pub fn toggle_cn_direct(&mut self) {
        self.private_rules.cn_direct = !self.private_rules.cn_direct;
        self.save_rules_and_apply();
    }

    /// Nodes and groups the user can feed into the AI group.
    pub fn ai_candidates(&self) -> Vec<String> {
        let ai = "AI";
        let group_names: Vec<String> = self
            .snapshot
            .groups
            .iter()
            .map(|g| g.name.clone())
            .filter(|n| n != ai && n != "terc-AI" && n != "PROXY" && n != "GLOBAL")
            .collect();
        let mut nodes: Vec<String> = self
            .snapshot
            .nodes
            .keys()
            .filter(|n| {
                !BUILTIN_POLICIES.contains(&n.as_str())
                    && !is_info_pseudo_node(n)
                    && !self.snapshot.groups.iter().any(|g| &g.name == *n)
            })
            .cloned()
            .collect();
        for own in &self.own_nodes {
            let name = own.name();
            if own.parsed.is_ok() && !nodes.contains(&name) {
                nodes.push(name);
            }
        }
        nodes.sort();
        let mut out = group_names;
        out.extend(nodes);
        for m in &self.private_rules.ai.members {
            if !out.contains(m) {
                out.push(m.clone());
            }
        }
        out
    }

    pub fn open_ai_picker(&mut self) {
        if self.own_nodes.is_empty() {
            self.own_nodes =
                load_manual_nodes(&crate::compose::profile_dir(&self.config.controller));
        }
        self.ai_picker_selected = self.private_rules.ai.members.clone();
        self.ai_picker_index = 0;
        self.ai_picker = true;
    }

    pub fn toggle_ai_candidate(&mut self) {
        let Some(name) = self.ai_candidates().get(self.ai_picker_index).cloned() else {
            return;
        };
        if let Some(pos) = self.ai_picker_selected.iter().position(|m| m == &name) {
            self.ai_picker_selected.remove(pos);
        } else {
            self.ai_picker_selected.push(name);
        }
    }

    pub fn save_ai_picker(&mut self) {
        self.private_rules.ai.members = self.ai_picker_selected.clone();
        self.ai_picker = false;
        self.save_rules_and_apply();
    }
}

fn move_cursor(index: &mut usize, len: usize, down: bool) {
    if len == 0 {
        *index = 0;
    } else if down {
        *index = (*index + 1) % len;
    } else {
        *index = index.checked_sub(1).unwrap_or(len - 1);
    }
}

fn handle_editor_key(app: &mut App, key: KeyEvent) {
    if key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char('u') | KeyCode::Char('w'))
    {
        app.manage_editor.clear();
        return;
    }
    match key.code {
        KeyCode::Esc => app.manage_input = None,
        KeyCode::Enter => app.submit_manage_input(),
        KeyCode::Backspace => {
            app.manage_editor.backspace();
        }
        KeyCode::Delete => {
            app.manage_editor.delete();
        }
        KeyCode::Left => app.manage_editor.move_left(),
        KeyCode::Right => app.manage_editor.move_right(),
        KeyCode::Home => app.manage_editor.move_home(),
        KeyCode::End => app.manage_editor.move_end(),
        KeyCode::Char(ch) => {
            app.manage_editor.insert_text(&ch.to_string());
        }
        _ => {}
    }
}

/// Paste into the add box. Several pasted node lines are added at once.
pub fn handle_manage_paste(app: &mut App, text: &str) {
    match app.manage_input {
        Some(ManageInput::AddNode) if text.trim().lines().count() > 1 => app.add_own_nodes(text),
        Some(ManageInput::AddProfile) if text.trim().lines().count() > 1 => {
            app.import_profile(text)
        }
        Some(_) => {
            app.manage_editor.insert_text(text.trim());
        }
        None => {}
    }
}

pub fn handle_own_nodes_key(app: &mut App, key: KeyEvent) {
    if app.manage_input.is_some() {
        handle_editor_key(app, key);
        return;
    }
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('N') => app.close_overlay(),
        KeyCode::Up | KeyCode::Char('k') => {
            move_cursor(&mut app.own_node_index, app.own_nodes.len(), false)
        }
        KeyCode::Down | KeyCode::Char('j') => {
            move_cursor(&mut app.own_node_index, app.own_nodes.len(), true)
        }
        KeyCode::Char('a') => app.start_manage_input(ManageInput::AddNode),
        KeyCode::Char('d') | KeyCode::Delete => app.remove_selected_own_node(),
        KeyCode::Char('r') | KeyCode::Enter => app.test_own_nodes(false),
        KeyCode::Char('A') => app.test_own_nodes(true),
        _ => {}
    }
}

pub fn handle_private_rules_key(app: &mut App, key: KeyEvent) {
    if app.manage_input.is_some() {
        handle_editor_key(app, key);
        return;
    }
    if app.ai_picker {
        let len = app.ai_candidates().len();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => app.ai_picker = false,
            KeyCode::Up | KeyCode::Char('k') => move_cursor(&mut app.ai_picker_index, len, false),
            KeyCode::Down | KeyCode::Char('j') => move_cursor(&mut app.ai_picker_index, len, true),
            KeyCode::Char(' ') => app.toggle_ai_candidate(),
            KeyCode::Char('c') => app.ai_picker_selected.clear(),
            KeyCode::Enter => app.save_ai_picker(),
            _ => {}
        }
        return;
    }
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);
    let len = app.private_rules.rules.len();
    match key.code {
        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('R') => app.close_overlay(),
        KeyCode::Up if shift => app.move_selected_rule(true),
        KeyCode::Down if shift => app.move_selected_rule(false),
        KeyCode::Char('K') => app.move_selected_rule(true),
        KeyCode::Char('J') => app.move_selected_rule(false),
        KeyCode::Up | KeyCode::Char('k') => move_cursor(&mut app.private_rule_index, len, false),
        KeyCode::Down | KeyCode::Char('j') => move_cursor(&mut app.private_rule_index, len, true),
        KeyCode::Char('a') => app.start_manage_input(ManageInput::AddRule),
        KeyCode::Char('d') | KeyCode::Delete => app.remove_selected_rule(),
        KeyCode::Char('t') => app.cycle_selected_rule_target(),
        KeyCode::Char('p') => app.toggle_ai_preset(),
        KeyCode::Char('y') => app.toggle_ai_kind(),
        KeyCode::Char('m') => app.open_ai_picker(),
        KeyCode::Char('b') => app.toggle_subscription_rules(),
        KeyCode::Char('c') => app.toggle_cn_direct(),
        KeyCode::Enter => {
            app.private_rules =
                PrivateRules::load(&crate::compose::profile_dir(&app.config.controller));
            app.apply_composed();
        }
        _ => {}
    }
}

// ------------------------------------------------------------ drawing

fn selected_style(app: &App, selected: bool) -> Style {
    let theme = app.theme();
    if selected {
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.text)
    }
}

fn draw_input(frame: &mut Frame, app: &App, area: Rect, title: &str) {
    let theme = app.theme();
    let input = draw_panel(
        frame,
        area,
        theme,
        Some(panel_title(title.to_string(), theme)),
        true,
    );
    let text_area = Rect::new(input.x + 1, input.y, input.width.saturating_sub(2), 1);
    let chars = app.manage_editor.chars();
    if text_area.width > 0 {
        frame.render_widget(
            Paragraph::new(Line::from(editor_line_spans(
                &chars,
                app.manage_editor.cursor,
                theme,
                text_area.width as usize,
            ))),
            text_area,
        );
        if let Some(cell) = editor_cursor_cell(&chars, app.manage_editor.cursor, text_area) {
            frame.set_cursor_position(cell);
        }
    }
}

fn hint(frame: &mut Frame, app: &App, area: Rect, text: &str) {
    frame.render_widget(
        Paragraph::new(Line::styled(
            text.to_string(),
            Style::default().fg(app.theme().muted),
        ))
        .wrap(Wrap { trim: true }),
        area,
    );
}

pub fn draw_own_nodes(frame: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(84, 72, area);
    frame.render_widget(Clear, popup);
    let inner = draw_panel(
        frame,
        popup,
        app.theme(),
        Some(panel_title("手动节点 / Manual nodes".into(), app.theme())),
        true,
    );
    draw_manual_nodes_content(frame, app, inner);
}

fn draw_manual_nodes_content(frame: &mut Frame, app: &App, inner: Rect) {
    let theme = app.theme();
    let adding = app.manage_input == Some(ManageInput::AddNode);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(3),
            Constraint::Length(if adding { 3 } else { 0 }),
            Constraint::Length(2),
        ])
        .split(inner);
    if app.own_nodes.is_empty() {
        let lines = vec![
            Line::styled(
                l3(
                    app,
                    "还没有手动节点。按 a 粘贴一条 Surge 节点行，或 ss:// trojan:// vless:// vmess:// hysteria2:// tuic:// wireguard:// ssh:// 链接；WireGuard 也可直接粘贴整段 wg-quick .conf。",
                    "No manual nodes yet. Press a and paste a Surge proxy line or an ss:// trojan:// vless:// vmess:// hysteria2:// tuic:// wireguard:// ssh:// link; for WireGuard you can also paste a whole wg-quick .conf.",
                    "自前ノードなし。a で Surge 行または ss:// などのリンクを貼り付け。",
                ),
                Style::default().fg(theme.text),
            ),
            Line::default(),
            Line::styled(
                l3(
                    app,
                    "节点单独保存在当前配置方案中；修改后校验并应用。",
                    "Manual nodes belong to the active profile. Changes are validated before applying.",
                    "~/.config/terc/nodes.conf を直接編集しても構いません。",
                ),
                Style::default().fg(theme.muted),
            ),
        ];
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), rows[0]);
    } else {
        let visible = rows[0].height as usize;
        let start = visible_list_start(app.own_node_index, app.own_nodes.len(), visible);
        let name_w = (rows[0].width as usize / 2).clamp(12, 40);
        let items: Vec<ListItem> = app
            .own_nodes
            .iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(index, node)| {
                let selected = index == app.own_node_index;
                let name = node.name();
                let mut spans = vec![Span::styled(
                    format!(
                        "{}{} {:<w$}",
                        if selected { "› " } else { "  " },
                        if node.parsed.is_ok() { "●" } else { "✕" },
                        truncate_str(&name, name_w),
                        w = name_w
                    ),
                    selected_style(app, selected),
                )];
                match &node.parsed {
                    Ok(v) => {
                        spans.push(Span::styled(
                            format!("  {}", node_summary(v)),
                            Style::default().fg(theme.muted),
                        ));
                        let delay = app.snapshot.nodes.get(&name).and_then(|n| n.delay);
                        if app.snapshot.nodes.contains_key(&name) {
                            spans.push(Span::styled(
                                match delay {
                                    Some(ms) => format!("  {ms}ms"),
                                    None => "  --".into(),
                                },
                                Style::default().fg(delay_color(theme, delay)),
                            ));
                        }
                    }
                    Err(err) => spans.push(Span::styled(
                        format!("  {}", truncate_str(err, 48)),
                        Style::default().fg(theme.accent),
                    )),
                }
                ListItem::new(Line::from(spans))
            })
            .collect();
        frame.render_widget(List::new(items), rows[0]);
    }
    if adding {
        draw_input(
            frame,
            app,
            rows[1],
            l3(
                app,
                "粘贴节点（Surge 行 / 链接）",
                "Paste node (Surge line / URI)",
                "ノードを貼り付け",
            ),
        );
    }
    hint(
        frame,
        app,
        rows[2],
        if adding {
            l3(
                app,
                "Enter 添加  Esc 取消  Ctrl+U 清空  可一次粘贴多行",
                "Enter add  Esc cancel  Ctrl+U clear  multi-line paste ok",
                "Enter 追加  Esc 取消",
            )
        } else {
            l3(
                app,
                "a 添加  d 删除  r/Enter 测速  A 全部测速  Esc 关闭  密码只存本机、不显示",
                "a add  d delete  r/Enter test  A test all  Esc close  secrets stay local, never shown",
                "a 追加  d 削除  r 測定  A 全測定  Esc 閉じる",
            )
        },
    );
}

pub fn draw_private_rules(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let popup = centered_rect(90, 84, area);
    frame.render_widget(Clear, popup);
    let inner = draw_panel(
        frame,
        popup,
        theme,
        Some(panel_title(
            l3(
                app,
                "私有规则与 AI 分流",
                "Private rules & AI routing",
                "プライベートルールと AI",
            )
            .to_string(),
            theme,
        )),
        true,
    );
    let adding = app.manage_input == Some(ManageInput::AddRule);
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(3),
            Constraint::Length(if adding { 3 } else { 0 }),
            Constraint::Length(2),
        ])
        .split(inner);
    let rules = &app.private_rules;
    let on = |v: bool| if v { "●" } else { "○" };
    let members = if rules.ai.members.is_empty() {
        l3(
            app,
            "自动：美/日/新/台，排除香港",
            "auto: US/JP/SG/TW, no HK",
            "自動：米/日/星/台、香港除外",
        )
        .to_string()
    } else {
        truncate_str(&rules.ai.members.join(" | "), 48)
    };
    let services = AI_PRESET.len();
    let domains: usize = AI_PRESET.iter().map(|(_, l)| l.len()).sum();
    let key = |k: &str| Span::styled(format!("[{k}] "), Style::default().fg(theme.accent));
    let text = |t: String| Span::styled(t, Style::default().fg(theme.text));
    let muted = |t: String| Span::styled(t, Style::default().fg(theme.muted));
    let settings = vec![
        Line::from(vec![
            key("p"),
            text(format!(
                "{} {}  {services} {} / {domains} {}",
                on(rules.ai.enabled),
                l3(app, "AI 预设", "AI preset", "AI プリセット"),
                l3(app, "类服务", "services", "サービス"),
                l3(app, "条", "rules", "件"),
            )),
            muted("   ".into()),
            key("y"),
            text(format!(
                "{} {}",
                l3(app, "AI 组", "AI group", "AI グループ"),
                rules.ai.kind
            )),
        ]),
        Line::from(vec![
            key("m"),
            text(format!(
                "{}  {members}",
                l3(app, "AI 成员", "AI members", "AI メンバー")
            )),
        ]),
        Line::from(vec![
            key("b"),
            text(format!(
                "{} {}",
                on(rules.subscription_rules),
                l3(
                    app,
                    "追加机场规则",
                    "Append airport rules",
                    "サブスクのルール"
                )
            )),
            muted("   ".into()),
            key("c"),
            text(format!(
                "{} {}",
                on(rules.cn_direct),
                l3(app, "国内直连", "China direct", "中国直結")
            )),
        ]),
        Line::from(muted(
            l3(
                app,
                "顺序：私有规则 → AI 预设 → 局域网直连 → 机场规则 → 国内直连 → MATCH,PROXY",
                "Order: private → AI preset → LAN direct → airport → China direct → MATCH,PROXY",
                "順序：プライベート → AI → LAN → サブスク → 中国 → MATCH",
            )
            .to_string(),
        )),
        Line::from(muted("~/.config/terc/rules.conf".into())),
    ];
    frame.render_widget(Paragraph::new(settings), rows[0]);

    if app.ai_picker {
        let candidates = app.ai_candidates();
        let list_inner = draw_panel(
            frame,
            rows[1],
            theme,
            Some(panel_title(
                format!(
                    "{}  {}",
                    l3(app, "选择 AI 成员", "Pick AI members", "AI メンバー選択"),
                    app.ai_picker_selected.len()
                ),
                theme,
            )),
            true,
        );
        if candidates.is_empty() {
            hint(
                frame,
                app,
                list_inner,
                l3(
                    app,
                    "没有候选：先启动内核（K）或添加手动节点（N）",
                    "No candidates: start the core (K) or add manual nodes (N)",
                    "候補なし",
                ),
            );
        } else {
            let visible = list_inner.height as usize;
            let start = visible_list_start(app.ai_picker_index, candidates.len(), visible);
            let items: Vec<ListItem> = candidates
                .iter()
                .enumerate()
                .skip(start)
                .take(visible)
                .map(|(i, name)| {
                    let selected = i == app.ai_picker_index;
                    let picked = app.ai_picker_selected.contains(name);
                    let is_group = app.snapshot.groups.iter().any(|g| &g.name == name);
                    ListItem::new(Line::from(vec![
                        Span::styled(
                            format!(
                                "{}{} {}",
                                if selected { "› " } else { "  " },
                                if picked { "●" } else { "○" },
                                name
                            ),
                            selected_style(app, selected),
                        ),
                        Span::styled(
                            if is_group {
                                format!("  {}", l3(app, "策略组", "group", "グループ"))
                            } else {
                                String::new()
                            },
                            Style::default().fg(theme.muted),
                        ),
                    ]))
                })
                .collect();
            frame.render_widget(List::new(items), list_inner);
        }
    } else {
        let list_inner = draw_panel(
            frame,
            rows[1],
            theme,
            Some(panel_title(
                format!(
                    "{}  {}",
                    l3(app, "私有规则", "Private rules", "プライベートルール"),
                    rules.rules.len()
                ),
                theme,
            )),
            true,
        );
        if rules.rules.is_empty() {
            hint(
                frame,
                app,
                list_inner,
                l3(
                    app,
                    "还没有私有规则。按 a 添加，例如 example.com,AI　或　DOMAIN-KEYWORD,steam,DIRECT　或　PROCESS-NAME,Cursor,AI",
                    "No private rules. Press a, e.g. example.com,AI  or  DOMAIN-KEYWORD,steam,DIRECT  or  PROCESS-NAME,Cursor,AI",
                    "a で追加。例：example.com,AI",
                ),
            );
        } else {
            let visible = list_inner.height as usize;
            let start = visible_list_start(app.private_rule_index, rules.rules.len(), visible);
            let items: Vec<ListItem> = rules
                .rules
                .iter()
                .enumerate()
                .skip(start)
                .take(visible)
                .map(|(i, rule)| {
                    let selected = i == app.private_rule_index;
                    let target = rule_target(rule);
                    let parts: Vec<&str> = rule.splitn(3, ',').collect();
                    let kind = parts.first().copied().unwrap_or("");
                    let value = parts.get(1).copied().unwrap_or("");
                    ListItem::new(Line::from(vec![
                        Span::styled(
                            format!(
                                "{}{:>3}  {:<15} {}",
                                if selected { "› " } else { "  " },
                                i + 1,
                                kind,
                                truncate_str(value, 40)
                            ),
                            selected_style(app, selected),
                        ),
                        Span::styled(format!("  → {target}"), Style::default().fg(theme.accent)),
                    ]))
                })
                .collect();
            frame.render_widget(List::new(items), list_inner);
        }
    }
    if adding {
        draw_input(
            frame,
            app,
            rows[2],
            l3(
                app,
                "新规则 TYPE,VALUE,TARGET",
                "New rule TYPE,VALUE,TARGET",
                "新ルール",
            ),
        );
    }
    hint(
        frame,
        app,
        rows[3],
        if adding {
            l3(
                app,
                "类型：DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN / IP-CIDR / GEOIP / PROCESS-NAME；目标：PROXY AI AUTO DIRECT REJECT。Enter 添加  Esc 取消",
                "Types: DOMAIN-SUFFIX / DOMAIN-KEYWORD / DOMAIN / IP-CIDR / GEOIP / PROCESS-NAME; targets: PROXY AI AUTO DIRECT REJECT. Enter add  Esc cancel",
                "Enter 追加  Esc 取消",
            )
        } else if app.ai_picker {
            l3(
                app,
                "Space 选/取消  c 清空（=自动挑选）  Enter 保存  Esc 取消",
                "Space toggle  c clear (= auto)  Enter save  Esc cancel",
                "Space 切替  c クリア  Enter 保存  Esc 取消",
            )
        } else {
            l3(
                app,
                "a 添加  d 删除  J/K 或 Shift+↑↓ 调整顺序  t 换目标  Enter 重新应用  Esc 关闭",
                "a add  d delete  J/K or Shift+↑↓ reorder  t target  Enter re-apply  Esc close",
                "a 追加  d 削除  J/K 並べ替え  t 宛先  Enter 再適用  Esc 閉じる",
            )
        },
    );
}

pub fn handle_profiles_key(app: &mut App, key: KeyEvent) {
    if app.manage_input.is_some() {
        handle_editor_key(app, key);
        return;
    }
    match key.code {
        KeyCode::Tab | KeyCode::BackTab => {
            app.profile_page =
                (app.profile_page + if key.code == KeyCode::Tab { 1 } else { 2 }) % 3;
        }
        KeyCode::Char('1'..='3') => {
            if let KeyCode::Char(c) = key.code {
                app.profile_page = (c as u8 - b'1') as usize;
            }
        }
        KeyCode::Esc | KeyCode::Char('q' | 'f') => app.close_overlay(),
        _ => match app.profile_page {
            0 => match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    app.profile_index = app
                        .profile_index
                        .checked_sub(1)
                        .unwrap_or(app.profiles.len().saturating_sub(1))
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if !app.profiles.is_empty() {
                        app.profile_index = (app.profile_index + 1) % app.profiles.len();
                    }
                }
                KeyCode::Enter => app.switch_selected_profile(),
                KeyCode::Char('a') => app.start_manage_input(ManageInput::AddProfile),
                KeyCode::Char('n') => {
                    if let Some(profile) = app.profiles.get(app.profile_index).cloned() {
                        app.start_manage_input(ManageInput::RenameProfile);
                        app.manage_editor.load(&profile.label);
                    }
                }
                KeyCode::Char('c') => {
                    if !app.action_busy {
                        app.save_profile_copy();
                        app.open_profiles();
                    }
                }
                _ => {}
            },
            1 => match key.code {
                KeyCode::Char('e') => app.open_setup(app.screen),
                KeyCode::Char('u') => app.update_subscription(),
                _ => {}
            },
            _ => handle_own_nodes_key(app, key),
        },
    }
}

pub fn draw_profile_hub(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let popup = if area.width < 75 || area.height < 22 {
        area
    } else {
        centered_rect(90, 86, area)
    };
    frame.render_widget(Clear, popup);
    let inner = draw_panel(
        frame,
        popup,
        theme,
        Some(panel_title(
            l3(app, "配置方案", "Profiles", "プロファイル").into(),
            theme,
        )),
        true,
    );
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(1),
        ])
        .split(inner);
    let tabs = if app.lang() == Lang::Zh {
        ["方案列表", "当前订阅", "手动节点"]
    } else {
        ["Profiles", "Subscription", "Manual nodes"]
    };
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 3); 3])
        .split(rows[0]);
    for (i, name) in tabs.iter().enumerate() {
        frame.render_widget(
            Paragraph::new(format!(
                "{} {} {}",
                if app.profile_page == i { "▶" } else { " " },
                i + 1,
                name
            ))
            .style(selected_style(app, app.profile_page == i)),
            cols[i],
        );
    }
    match app.profile_page {
        0 => {
            let adding = matches!(
                app.manage_input,
                Some(ManageInput::AddProfile | ManageInput::RenameProfile)
            );
            let body = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(2),
                    Constraint::Min(0),
                    Constraint::Length(if adding { 4 } else { 2 }),
                    Constraint::Length(1),
                ])
                .split(rows[1]);
            frame.render_widget(
                Paragraph::new(format!(
                    "{} {}",
                    l3(app, "当前方案", "Active profile", "使用中"),
                    app.profile_display_name()
                ))
                .style(Style::default().fg(theme.peak)),
                body[0],
            );
            if app.profiles.is_empty() {
                frame.render_widget(Paragraph::new(l3(app,"还没有保存的方案。c 保存当前配置；a 导入订阅或节点。","No saved profiles. c saves the current configuration; a imports a subscription or nodes.","c で保存、a で追加")).wrap(Wrap{trim:true}),body[1]);
            } else {
                let visible = body[1].height as usize;
                let start = visible_list_start(app.profile_index, app.profiles.len(), visible);
                let items: Vec<_> = app
                    .profiles
                    .iter()
                    .enumerate()
                    .skip(start)
                    .take(visible)
                    .map(|(i, p)| {
                        ListItem::new(Line::styled(
                            format!(
                                "{} {} {}",
                                if i == app.profile_index { "▶" } else { " " },
                                if p.active { "●" } else { "○" },
                                p.label
                            ),
                            selected_style(app, i == app.profile_index),
                        ))
                    })
                    .collect();
                frame.render_widget(List::new(items), body[1]);
            }
            if adding {
                draw_input(
                    frame,
                    app,
                    body[2],
                    if app.manage_input == Some(ManageInput::RenameProfile) {
                        l3(app, "方案名称", "Profile name", "プロファイル名")
                    } else {
                        l3(
                            app,
                            "粘贴订阅地址或节点（支持多行 / WireGuard 配置）",
                            "Paste subscription URL or nodes (multi-line / WireGuard supported)",
                            "URL / ノードを貼り付け",
                        )
                    },
                );
            } else {
                frame.render_widget(Paragraph::new(l3(app,"每个方案独立保存订阅来源和手动节点。自有规则编辑暂缓，优先使用来源分流。","Each profile keeps its subscription and manual nodes separately. Source routing is preserved; custom rule editing is paused.","プロファイルごとにソースを保存")).style(Style::default().fg(theme.muted)).wrap(Wrap{trim:true}),body[2]);
            }
            frame.render_widget(
                Paragraph::new(if adding {
                    "Enter 确认 / Confirm   Esc 取消 / Cancel"
                } else {
                    l3(
                        app,
                        "a 导入  c 副本  n 改名  Enter 应用",
                        "a Import  c Copy  n Rename  Enter Apply",
                        "a 追加  c コピー  Enter 適用",
                    )
                }),
                body[3],
            );
        }
        1 => {
            let url = if app.config.controller.subscription_url.is_empty() {
                "—".into()
            } else {
                crate::mask_url(&app.config.controller.subscription_url)
            };
            let lines=vec![Line::from(app.profile_display_name()),Line::default(),Line::styled(l3(app,"订阅地址","Subscription URL","URL"),Style::default().fg(theme.muted)),Line::from(url),Line::default(),Line::from(l3(app,"e 编辑当前来源   u 更新订阅","e Edit source   u Update subscription","e 編集  u 更新")),Line::default(),Line::styled(l3(app,"切换订阅请在方案列表按 a 导入新方案。来源自带的规则与策略组将保留。","Use a on the Profiles tab to import another source. Its rules and groups are preserved.","a で新しいソースを追加"),Style::default().fg(theme.muted))];
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), rows[1]);
        }
        _ => draw_manual_nodes_content(frame, app, rows[1]),
    }
    frame.render_widget(
        Paragraph::new(l3(
            app,
            "Tab 切换   1/2/3 分类   Esc 返回",
            "Tab Switch   1/2/3 Tabs   Esc Back",
            "Tab 切替  Esc 戻る",
        ))
        .style(Style::default().fg(theme.muted)),
        rows[2],
    );
}
