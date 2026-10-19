//! Extra dashboard panes: toggles, DNS, rules, providers, and overlays.
//!
//! Every region goes through the shared rounded `Panel` so the new views stay
//! on the same transparent btop canvas as the proxy list.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    prelude::Frame,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, List, ListItem, Paragraph, Wrap},
};
use unicode_width::UnicodeWidthStr;

use crate::{
    ops::{short_stamp, ModuleSnippet},
    ui::{
        centered_rect, delay_color, draw_panel, editor_cursor_cell, editor_line_spans,
        format_bytes, module_title_line, panel_title, truncate_str, visible_list_start, Theme,
    },
    App, Overlay,
};

pub fn draw_toggle_strip(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 3); 3])
        .split(area);
    let proxy = if area.width < 72 {
        if app.lang() == crate::Lang::Zh {
            "␣ 代理"
        } else {
            "␣ Proxy"
        }
    } else if app.lang() == crate::Lang::Zh {
        "Space 系统代理"
    } else {
        "Space Proxy"
    };
    let mode = if area.width < 72 && app.lang() == crate::Lang::Zh {
        "m 模式"
    } else if app.lang() == crate::Lang::Zh {
        "m 分流模式"
    } else {
        "m Mode"
    };
    for (i, (label, value, enabled)) in [
        (
            proxy,
            if app.snapshot.sysproxy_enabled {
                "ON"
            } else {
                "OFF"
            },
            app.snapshot.sysproxy_enabled,
        ),
        (mode, app.snapshot.mode.as_str(), true),
        (
            "T TUN",
            if app.snapshot.tun_enabled {
                "ON"
            } else {
                "OFF"
            },
            app.snapshot.tun_enabled,
        ),
    ]
    .iter()
    .enumerate()
    {
        let inner = draw_panel(
            frame,
            cols[i],
            theme,
            Some(panel_title(label.to_string(), theme)),
            false,
        );
        frame.render_widget(
            Paragraph::new(*value)
                .alignment(ratatui::layout::Alignment::Center)
                .style(
                    Style::default()
                        .fg(if *enabled { theme.peak } else { theme.muted })
                        .add_modifier(Modifier::BOLD),
                ),
            inner,
        );
    }
}

pub fn draw_dns(frame: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(area);
    draw_dns_status(frame, app, cols[0]);
    draw_dns_query(frame, app, cols[1]);
}

pub fn draw_rules(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let title = module_title_line(theme, app.lang(), 'g', "Rules", app.t("rules"));
    let inner = draw_panel(frame, area, theme, Some(title), true);
    if inner.width < 12 || inner.height < 2 {
        return;
    }
    let explain_h = if app.explain.is_some() { 2 } else { 0 };
    let list_top = inner.y + 1;
    let list_h = inner.height.saturating_sub(1 + explain_h);
    let query_area = Rect::new(inner.x + 1, inner.y, inner.width.saturating_sub(2), 1);
    draw_rule_query(frame, app, query_area);

    let indexes = app.filtered_rule_indexes();
    if indexes.is_empty() {
        frame.render_widget(
            Paragraph::new(app.t("no_rules")).style(Style::default().fg(theme.muted)),
            Rect::new(
                inner.x + 1,
                list_top,
                inner.width.saturating_sub(2),
                list_h.max(1),
            ),
        );
    } else if list_h > 0 {
        let start = visible_list_start(app.rule_index, indexes.len(), list_h as usize);
        let max_w = inner.width.saturating_sub(2) as usize;
        let items: Vec<ListItem> = indexes
            .iter()
            .enumerate()
            .skip(start)
            .take(list_h as usize)
            .filter_map(|(view_index, raw)| {
                let rule = app.snapshot.rules.get(*raw)?;
                let selected = view_index == app.rule_index;
                let prefix = if rule.disabled {
                    "× "
                } else if selected {
                    "› "
                } else {
                    "  "
                };
                let hits = if rule.hit_count == 0 {
                    "   ".to_string()
                } else {
                    format!("{:>3}×", rule.hit_count.min(999))
                };
                let style = if rule.disabled {
                    Style::default().fg(theme.muted)
                } else if selected {
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.text)
                };
                let left = format!("{prefix}{hits} {:<14}", truncate_str(&rule.kind, 14));
                let proxy = truncate_str(&rule.proxy, 16);
                let payload_budget = max_w.saturating_sub(left.width() + proxy.width() + 2);
                let payload = truncate_str(&rule.payload, payload_budget);
                let pad = max_w.saturating_sub(left.width() + payload.width() + proxy.width());
                Some(ListItem::new(Line::from(vec![
                    Span::styled(left, style),
                    Span::styled(payload, style),
                    Span::raw(" ".repeat(pad)),
                    Span::styled(
                        proxy,
                        Style::default().fg(if selected { theme.peak } else { theme.muted }),
                    ),
                ])))
            })
            .collect();
        frame.render_widget(
            List::new(items),
            Rect::new(inner.x + 1, list_top, inner.width.saturating_sub(2), list_h),
        );
    }
    if let Some(report) = &app.explain {
        let y = inner.y + inner.height.saturating_sub(explain_h);
        frame.render_widget(
            Paragraph::new(explain_lines(app, report)),
            Rect::new(inner.x + 1, y, inner.width.saturating_sub(2), explain_h),
        );
    }
}

pub fn draw_providers(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let title = module_title_line(theme, app.lang(), 'v', "Providers", app.t("providers"));
    let inner = draw_panel(frame, area, theme, Some(title), true);
    if inner.width < 10 || inner.height < 1 {
        return;
    }
    if app.snapshot.providers.is_empty() {
        frame.render_widget(
            Paragraph::new(app.t("no_providers")).style(Style::default().fg(theme.muted)),
            inner,
        );
        return;
    }
    let visible = inner.height as usize;
    let start = visible_list_start(app.provider_index, app.snapshot.providers.len(), visible);
    let max_w = inner.width.saturating_sub(2) as usize;
    let items: Vec<ListItem> = app
        .snapshot
        .providers
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(index, provider)| {
            let selected = index == app.provider_index;
            let style = if selected {
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.text)
            };
            let prefix = if selected { "› " } else { "  " };
            let kind = format!("{:<5}", provider.kind);
            let count = format!("{:>4}", provider.count);
            let when = short_stamp(&provider.updated_at);
            let left = format!(
                "{prefix}{kind} {}  {}",
                provider.name,
                if provider.behavior.is_empty() {
                    provider.vehicle.clone()
                } else {
                    format!("{} {}", provider.vehicle, provider.behavior)
                }
            );
            let right = format!("{count}  {when}");
            let pad = max_w.saturating_sub(left.width() + right.width()).max(1);
            ListItem::new(Line::from(vec![
                Span::styled(
                    truncate_str(&left, max_w.saturating_sub(right.width() + 1)),
                    style,
                ),
                Span::raw(" ".repeat(pad)),
                Span::styled(right, Style::default().fg(theme.muted)),
            ]))
        })
        .collect();
    frame.render_widget(
        List::new(items),
        Rect::new(
            inner.x + 1,
            inner.y,
            inner.width.saturating_sub(2),
            inner.height,
        ),
    );
}

pub fn draw_connections(frame: &mut Frame, app: &mut App, area: Rect) {
    let theme = app.theme();
    if app.connection_detail {
        draw_connection_detail(frame, app, area);
        return;
    }
    let split = area.width >= 78;
    let (list_area, detail_area) = if split {
        let cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(58), Constraint::Percentage(42)])
            .split(area);
        (cols[0], Some(cols[1]))
    } else {
        (area, None)
    };
    let title = format!(
        "{} ({})  x  X",
        app.t("connections"),
        app.snapshot.connections.len()
    );
    let inner = draw_panel(
        frame,
        list_area,
        theme,
        Some(module_title_line(
            theme,
            app.lang(),
            'c',
            "Connections",
            &title,
        )),
        true,
    );
    if app.snapshot.connections.is_empty() {
        frame.render_widget(
            Paragraph::new(app.t("no_connections")).style(Style::default().fg(theme.muted)),
            inner,
        );
    } else if inner.width > 4 && inner.height > 0 {
        let visible = inner.height as usize;
        let start = visible_list_start(app.conn_index, app.snapshot.connections.len(), visible);
        let max_w = inner.width.saturating_sub(2) as usize;
        let items: Vec<ListItem> = app
            .snapshot
            .connections
            .iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(index, conn)| {
                let selected = index == app.conn_index;
                let style = if selected {
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.text)
                };
                let process = if conn.process.is_empty() {
                    String::new()
                } else {
                    format!("{} ", truncate_str(&conn.process, 12))
                };
                let inbound = if conn.inbound.is_empty() {
                    conn.network.clone()
                } else {
                    conn.inbound.clone()
                };
                let traffic = format!(
                    "↑{} ↓{}",
                    format_bytes(conn.upload),
                    format_bytes(conn.download)
                );
                let mid = format!(
                    "{}{} {} {}",
                    if selected { "› " } else { "  " },
                    process,
                    truncate_str(&conn.host, 28),
                    truncate_str(&inbound, 8)
                );
                let rule = truncate_str(&conn.rule, 14);
                let used = mid.width() + rule.width() + traffic.width() + 2;
                let pad = max_w.saturating_sub(used).max(1);
                ListItem::new(Line::from(vec![
                    Span::styled(mid, style),
                    Span::raw(" ".repeat(pad)),
                    Span::styled(rule, Style::default().fg(theme.peak)),
                    Span::raw(" "),
                    Span::styled(traffic, Style::default().fg(theme.muted)),
                ]))
            })
            .collect();
        frame.render_widget(
            List::new(items),
            Rect::new(
                inner.x + 1,
                inner.y,
                inner.width.saturating_sub(2),
                inner.height,
            ),
        );
    }
    if let Some(detail) = detail_area {
        draw_connection_detail(frame, app, detail);
    }
}

pub fn draw_overlay(frame: &mut Frame, app: &App, area: Rect) {
    match app.overlay {
        Overlay::None => {}
        Overlay::Modules => draw_modules(frame, app, area),
        Overlay::Profiles => draw_profiles(frame, app, area),
        Overlay::Probe => draw_probe(frame, app, area),
        Overlay::Runtime => draw_runtime(frame, app, area),
    }
}

fn draw_dns_status(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let inner = draw_panel(
        frame,
        area,
        theme,
        Some(panel_title(app.t("dns_status").to_string(), theme)),
        false,
    );
    let dns = &app.snapshot.dns;
    let on = |value: bool| if value { "on" } else { "off" };
    let mode = if dns.enhanced_mode.is_empty() {
        "—"
    } else {
        dns.enhanced_mode.as_str()
    };
    let listen = if dns.listen.is_empty() {
        "—"
    } else {
        dns.listen.as_str()
    };
    let mut lines = vec![
        kv(theme, "enable", on(dns.enable && dns.present)),
        kv(theme, "mode", mode),
        kv(theme, "listen", listen),
        kv(
            theme,
            "fake-ip",
            if dns.fake_ip_range.is_empty() {
                "—"
            } else {
                dns.fake_ip_range.as_str()
            },
        ),
        kv(theme, "ipv6", on(app.snapshot.ipv6)),
        kv(theme, "sniff", on(app.snapshot.sniffing)),
    ];
    if !dns.nameservers.is_empty() {
        lines.push(kv(theme, "ns", &dns.nameservers.join("  ")));
    }
    if !dns.fallback.is_empty() {
        lines.push(kv(theme, "fallback", &dns.fallback.join("  ")));
    }
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn draw_dns_query(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let title = format!("{} {}", app.t("dns_query"), app.dns_qtype());
    let inner = draw_panel(
        frame,
        area,
        theme,
        Some(module_title_line(theme, app.lang(), 'd', "DNS", &title)),
        true,
    );
    if inner.height < 1 {
        return;
    }
    let input = Rect::new(inner.x, inner.y, inner.width, 1);
    let chars = app.dns_editor.chars();
    frame.render_widget(
        Paragraph::new(Line::from(editor_line_spans(
            &chars,
            app.dns_editor.cursor,
            theme,
            input.width as usize,
        ))),
        input,
    );
    if app.dns_editing {
        if let Some(cell) = editor_cursor_cell(&chars, app.dns_editor.cursor, input) {
            frame.set_cursor_position(cell);
        }
    }
    if inner.height > 1 {
        let style = Style::default().fg(if app.dns_error {
            theme.accent
        } else {
            theme.text
        });
        let lines: Vec<Line> = if app.dns_lines.is_empty() {
            vec![Line::styled(
                "e    Enter    F    [ ]",
                Style::default().fg(theme.muted),
            )]
        } else {
            app.dns_lines
                .iter()
                .cloned()
                .map(|line| Line::styled(line, style))
                .collect()
        };
        frame.render_widget(
            Paragraph::new(lines),
            Rect::new(
                inner.x,
                inner.y + 1,
                inner.width,
                inner.height.saturating_sub(1),
            ),
        );
    }
}

fn draw_rule_query(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    if area.width == 0 {
        return;
    }
    if app.rule_editing || !app.rule_query.text.is_empty() {
        let chars = app.rule_query.chars();
        frame.render_widget(
            Paragraph::new(Line::from(editor_line_spans(
                &chars,
                app.rule_query.cursor,
                theme,
                area.width as usize,
            ))),
            area,
        );
        if app.rule_editing {
            if let Some(cell) = editor_cursor_cell(&chars, app.rule_query.cursor, area) {
                frame.set_cursor_position(cell);
            }
        }
    } else {
        frame.render_widget(
            Paragraph::new(Line::styled(
                "/  filter    e  explain    x  disable    F  refresh",
                Style::default().fg(theme.muted),
            )),
            area,
        );
    }
}

fn draw_connection_detail(frame: &mut Frame, app: &mut App, area: Rect) {
    let theme = app.theme();
    let inner = draw_panel(
        frame,
        area,
        theme,
        Some(panel_title(
            format!("{}  Enter/Esc 返回  ↑↓ scroll", app.t("connections")),
            theme,
        )),
        false,
    );
    let Some(conn) = app.snapshot.connections.get(app.conn_index) else {
        return;
    };
    let process = if conn.process.is_empty() {
        "—".to_string()
    } else {
        conn.process.clone()
    };
    let path = if conn.process_path.is_empty() {
        "—".to_string()
    } else {
        conn.process_path.clone()
    };
    let inbound = match (conn.inbound.as_str(), conn.inbound_name.as_str()) {
        ("", "") => conn.network.clone(),
        ("", name) => name.to_string(),
        (kind, "") => kind.to_string(),
        (kind, name) => format!("{kind} {name}"),
    };
    let rule = if conn.rule_payload.is_empty() {
        conn.rule.clone()
    } else {
        format!("{} {}", conn.rule, conn.rule_payload)
    };
    let mut lines = vec![
        kv(theme, "proc", &process),
        kv(theme, "path", &path),
        kv(theme, "in", &inbound),
        kv(
            theme,
            "from",
            if conn.source.is_empty() {
                "—"
            } else {
                &conn.source
            },
        ),
        kv(theme, "host", &conn.host),
        kv(
            theme,
            "sniff",
            if conn.sniff_host.is_empty() {
                "—"
            } else {
                &conn.sniff_host
            },
        ),
        kv(theme, "rule", if rule.is_empty() { "—" } else { &rule }),
        kv(
            theme,
            "chain",
            if conn.chains.is_empty() {
                "—"
            } else {
                &conn.chains
            },
        ),
        kv(
            theme,
            "xfer",
            &format!(
                "↑{}  ↓{}",
                format_bytes(conn.upload),
                format_bytes(conn.download)
            ),
        ),
    ];
    if !conn.dest_geo.is_empty() || !conn.dest_asn.is_empty() {
        lines.push(kv(
            theme,
            "dst",
            &format!("{} {}", conn.dest_geo, conn.dest_asn)
                .trim()
                .to_string(),
        ));
    }
    if !conn.dns_mode.is_empty() {
        lines.push(kv(theme, "dns", &conn.dns_mode));
    }
    if !conn.start.is_empty() {
        lines.push(kv(theme, "start", &short_stamp(&conn.start)));
    }
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true });
    let max = paragraph
        .line_count(inner.width)
        .saturating_sub(inner.height as usize);
    app.detail_scroll = app.detail_scroll.min(max as u16);
    frame.render_widget(
        paragraph.scroll((
            if app.connection_detail {
                app.detail_scroll
            } else {
                0
            },
            0,
        )),
        inner,
    );
}

fn draw_modules(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let popup = centered_rect(88, 80, area);
    frame.render_widget(Clear, popup);
    let inner = draw_panel(
        frame,
        popup,
        theme,
        Some(panel_title(app.t("modules").to_string(), theme)),
        true,
    );
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(4), Constraint::Length(2)])
        .split(inner);
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(rows[0]);
    let list_inner = draw_panel(
        frame,
        cols[0],
        theme,
        Some(panel_title(app.t("modules").to_string(), theme)),
        true,
    );
    let preview = draw_panel(
        frame,
        cols[1],
        theme,
        Some(panel_title(app.t("settings_details").to_string(), theme)),
        false,
    );
    let visible = list_inner.height as usize;
    let start = visible_list_start(app.module_index, app.catalog.len(), visible);
    let items: Vec<ListItem> = app
        .catalog
        .iter()
        .enumerate()
        .skip(start)
        .take(visible)
        .map(|(index, module)| {
            let selected = index == app.module_index;
            let mark = if app.module_enabled(&module.id) {
                "● "
            } else {
                "○ "
            };
            let style = if selected {
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.text)
            };
            ListItem::new(Line::styled(
                format!(
                    "{}{mark}{}",
                    if selected { "› " } else { "  " },
                    module_name(app, module)
                ),
                style,
            ))
        })
        .collect();
    frame.render_widget(List::new(items), list_inner);
    if let Some(module) = app.catalog.get(app.module_index) {
        let mut lines = vec![
            Line::styled(
                module_name(app, module),
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Line::styled(module_desc(app, module), Style::default().fg(theme.muted)),
            Line::default(),
        ];
        for line in module
            .body
            .lines()
            .take(preview.height.saturating_sub(3) as usize)
        {
            lines.push(Line::styled(
                line.to_string(),
                Style::default().fg(theme.text),
            ));
        }
        frame.render_widget(Paragraph::new(lines), preview);
    }
    frame.render_widget(
        Paragraph::new(Line::styled(
            app.t("ov_modules"),
            Style::default().fg(theme.muted),
        )),
        rows[1],
    );
}

fn draw_profiles(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let popup = centered_rect(78, 70, area);
    frame.render_widget(Clear, popup);
    let inner = draw_panel(
        frame,
        popup,
        theme,
        Some(panel_title(app.t("profiles").to_string(), theme)),
        true,
    );
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(3), Constraint::Length(2)])
        .split(inner);
    if app.profiles.is_empty() {
        frame.render_widget(
            Paragraph::new("c  save").style(Style::default().fg(theme.muted)),
            rows[0],
        );
    } else {
        let visible = rows[0].height as usize;
        let start = visible_list_start(app.profile_index, app.profiles.len(), visible);
        let items: Vec<ListItem> = app
            .profiles
            .iter()
            .enumerate()
            .skip(start)
            .take(visible)
            .map(|(index, profile)| {
                let selected = index == app.profile_index;
                let style = if selected {
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.text)
                };
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!(
                            "{}{} {}",
                            if selected { "› " } else { "  " },
                            if profile.active { "●" } else { "○" },
                            profile.name
                        ),
                        style,
                    ),
                    Span::styled(
                        format!("  {}", truncate_str(&profile.path, 42)),
                        Style::default().fg(theme.muted),
                    ),
                ]))
            })
            .collect();
        frame.render_widget(List::new(items), rows[0]);
    }
    frame.render_widget(
        Paragraph::new(Line::styled(
            app.t("ov_profiles"),
            Style::default().fg(theme.muted),
        )),
        rows[1],
    );
}

fn draw_probe(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let popup = centered_rect(72, 58, area);
    frame.render_widget(Clear, popup);
    let inner = draw_panel(
        frame,
        popup,
        theme,
        Some(panel_title(app.t("probe").to_string(), theme)),
        true,
    );
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(3),
            Constraint::Min(3),
        ])
        .split(inner);
    frame.render_widget(
        Paragraph::new(Line::styled(
            format!("{}  {}", app.t("ov_probe"), app.selected_proxy_name()),
            Style::default().fg(theme.muted),
        )),
        rows[0],
    );
    let input = draw_panel(
        frame,
        rows[1],
        theme,
        Some(panel_title(app.t("dns_query").to_string(), theme)),
        true,
    );
    let text_area = Rect::new(input.x + 1, input.y, input.width.saturating_sub(2), 1);
    let chars = app.probe_editor.chars();
    if text_area.width > 0 {
        frame.render_widget(
            Paragraph::new(Line::from(editor_line_spans(
                &chars,
                app.probe_editor.cursor,
                theme,
                text_area.width as usize,
            ))),
            text_area,
        );
        if let Some(cell) = editor_cursor_cell(&chars, app.probe_editor.cursor, text_area) {
            frame.set_cursor_position(cell);
        }
    }
    let style = Style::default().fg(if app.probe_error {
        theme.accent
    } else {
        theme.text
    });
    let lines: Vec<Line> = if app.probe_lines.is_empty() {
        vec![Line::styled("Enter", Style::default().fg(theme.muted))]
    } else {
        app.probe_lines
            .iter()
            .cloned()
            .map(|line| Line::styled(line, style))
            .collect()
    };
    frame.render_widget(Paragraph::new(lines), rows[2]);
}

fn draw_runtime(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let popup = centered_rect(78, 76, area);
    frame.render_widget(Clear, popup);
    let inner = draw_panel(
        frame,
        popup,
        theme,
        Some(panel_title(app.t("runtime").to_string(), theme)),
        true,
    );
    let peers = app.wireguard_peers();
    let tun = if app.snapshot.tun_enabled {
        "on"
    } else {
        "off"
    };
    let stack = if app.snapshot.tun_stack.is_empty() {
        "—"
    } else {
        app.snapshot.tun_stack.as_str()
    };
    let device = if app.snapshot.tun_device.is_empty() {
        "—"
    } else {
        app.snapshot.tun_device.as_str()
    };
    let proc = if app.snapshot.find_process.is_empty() {
        "—"
    } else {
        app.snapshot.find_process.as_str()
    };
    let mut lines = vec![
        kv(theme, "core", &format!("Mihomo {}", app.snapshot.version)),
        kv(theme, "mode", &app.snapshot.mode),
        kv(theme, "tun", &format!("{tun}  {stack}  {device}")),
        kv(
            theme,
            "sniff",
            if app.snapshot.sniffing { "on" } else { "off" },
        ),
        kv(theme, "ipv6", if app.snapshot.ipv6 { "on" } else { "off" }),
        kv(theme, "proc", proc),
        kv(
            theme,
            "tcp",
            if app.snapshot.tcp_concurrent {
                "concurrent"
            } else {
                "off"
            },
        ),
        kv(
            theme,
            "port",
            &format!(
                "http :{}  socks :{}  mixed :{}",
                app.snapshot.http_port, app.snapshot.socks_port, app.snapshot.mixed_port
            ),
        ),
        Line::default(),
        Line::styled(
            "WireGuard",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if peers.is_empty() {
        lines.push(Line::styled(
            app.t("st_no_wg"),
            Style::default().fg(theme.muted),
        ));
    } else {
        for (index, peer) in peers.iter().enumerate() {
            let selected = index == app.tunnel_index;
            let delay = match peer.delay {
                Some(ms) => format!("{ms} ms"),
                None => "—".into(),
            };
            lines.push(Line::styled(
                format!(
                    "{}{}  {}  {}",
                    if selected { "› " } else { "  " },
                    peer.name,
                    delay,
                    if peer.udp { "udp" } else { "tcp" }
                ),
                if selected {
                    Style::default()
                        .fg(delay_color(theme, peer.delay))
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.text)
                },
            ));
        }
    }
    lines.push(Line::default());
    lines.push(Line::styled(
        app.t("ov_runtime"),
        Style::default().fg(theme.muted),
    ));
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner);
}

fn explain_lines(app: &App, report: &crate::ops::ExplainReport) -> Vec<Line<'static>> {
    let theme = app.theme();
    let mut lines = Vec::new();
    if let Some(hit) = &report.matched {
        lines.push(Line::styled(
            format!(
                "{}  #{}  {}  {}  →  {}",
                app.t("explain_match"),
                hit.index,
                hit.kind,
                truncate_str(&hit.payload, 32),
                hit.proxy
            ),
            Style::default().fg(theme.peak).add_modifier(Modifier::BOLD),
        ));
        if report.partial {
            lines.push(Line::styled(
                app.t("explain_partial"),
                Style::default().fg(theme.accent),
            ));
        } else if let Some(note) = report.uncertain.first() {
            lines.push(Line::styled(
                format!("{} {}", note.kind, note.reason),
                Style::default().fg(theme.muted),
            ));
        }
    } else {
        lines.push(Line::styled(
            format!("{}  {}", app.t("explain_none"), report.target),
            Style::default().fg(theme.accent),
        ));
        if report.partial {
            lines.push(Line::styled(
                app.t("explain_partial"),
                Style::default().fg(theme.muted),
            ));
        }
    }
    lines
}

fn kv(theme: Theme, key: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{key:<8}"), Style::default().fg(theme.muted)),
        Span::styled(value.to_string(), Style::default().fg(theme.text)),
    ])
}

fn module_name(app: &App, module: &ModuleSnippet) -> String {
    translated(app, &module.id, false).unwrap_or_else(|| module.name.clone())
}

fn module_desc(app: &App, module: &ModuleSnippet) -> String {
    translated(app, &module.id, true).unwrap_or_else(|| module.description.clone())
}

fn translated(app: &App, id: &str, desc: bool) -> Option<String> {
    let key = match (id, desc) {
        ("tun", false) => "mod_tun",
        ("tun", true) => "mod_tun_desc",
        ("sniffer", false) => "mod_sniffer",
        ("sniffer", true) => "mod_sniffer_desc",
        ("dns-fakeip", false) => "mod_dns_fakeip",
        ("dns-fakeip", true) => "mod_dns_fakeip_desc",
        ("find-process", false) => "mod_find_process",
        ("find-process", true) => "mod_find_process_desc",
        ("tcp-concurrent", false) => "mod_tcp_concurrent",
        ("tcp-concurrent", true) => "mod_tcp_concurrent_desc",
        ("ipv6", false) => "mod_ipv6",
        ("ipv6", true) => "mod_ipv6_desc",
        _ => return None,
    };
    let text = app.t(key);
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}
