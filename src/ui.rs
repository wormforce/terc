use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    prelude::Frame,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, List, ListItem, Paragraph, Widget, Wrap},
};
use serde::{Deserialize, Serialize};
use unicode_width::UnicodeWidthStr;

use crate::{
    mihomo::{is_info_pseudo_node, ProxyGroup},
    App, FocusPane, Lang, MainTab, Screen, SettingCategory, SettingRow,
};

pub const THEMES: &[ThemeId] = &[ThemeId::Spring, ThemeId::Vintage, ThemeId::Mono];
pub const WAVE_RENDERERS: &[WaveRenderer] = &[WaveRenderer::Braille, WaveRenderer::Blocks];

const BRAILLE_DOT_BITS: [[u8; 4]; 2] = [[0x01, 0x02, 0x04, 0x40], [0x08, 0x10, 0x20, 0x80]];
const EIGHTH_BLOCKS: [&str; 9] = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

pub const TITLE_ART: &[&str] = &[
    " _                ",
    "| |_ ___ _ __ ___ ",
    "| __/ _ \\ '__/ __|",
    "| ||  __/ | | (__ ",
    " \\__\\___|_|  \\___|",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeId {
    Spring,
    Vintage,
    Mono,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaveRenderer {
    Braille,
    #[serde(other)]
    Blocks,
}

#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub title_key: &'static str,
    pub accent: Color,
    pub text: Color,
    pub muted: Color,
    pub border: Color,
    pub low: Color,
    pub mid: Color,
    pub high: Color,
    pub peak: Color,
}

pub fn theme(id: ThemeId) -> Theme {
    match id {
        ThemeId::Spring => Theme {
            title_key: "theme_spring",
            accent: Color::Rgb(255, 164, 164),
            text: Color::Rgb(252, 249, 234),
            muted: Color::Rgb(186, 223, 219),
            border: Color::Rgb(186, 223, 219),
            low: Color::Rgb(255, 164, 164),
            mid: Color::Rgb(255, 189, 189),
            high: Color::Rgb(252, 249, 234),
            peak: Color::Rgb(186, 223, 219),
        },
        ThemeId::Vintage => Theme {
            title_key: "theme_vintage",
            accent: Color::Rgb(186, 106, 76),
            text: Color::Rgb(238, 224, 204),
            muted: Color::Rgb(96, 116, 86),
            border: Color::Rgb(96, 116, 86),
            low: Color::Rgb(123, 37, 37),
            mid: Color::Rgb(186, 106, 76),
            high: Color::Rgb(238, 224, 204),
            peak: Color::Rgb(96, 116, 86),
        },
        ThemeId::Mono => Theme {
            title_key: "theme_mono",
            accent: Color::White,
            text: Color::Gray,
            muted: Color::DarkGray,
            border: Color::DarkGray,
            low: Color::Gray,
            mid: Color::Gray,
            high: Color::White,
            peak: Color::White,
        },
    }
}

pub fn blend_color(a: Color, b: Color, t: f32) -> Color {
    let (ar, ag, ab) = color_to_rgb(a);
    let (br, bg, bb) = color_to_rgb(b);
    let t = t.clamp(0.0, 1.0);
    let lerp = |x: u8, y: u8| -> u8 { (x as f32 + (y as f32 - x as f32) * t).round() as u8 };
    Color::Rgb(lerp(ar, br), lerp(ag, bg), lerp(ab, bb))
}

pub fn color_to_rgb(color: Color) -> (u8, u8, u8) {
    match color {
        Color::Rgb(r, g, b) => (r, g, b),
        Color::White => (245, 245, 245),
        Color::Gray => (176, 176, 176),
        Color::DarkGray => (108, 108, 108),
        _ => (210, 210, 210),
    }
}

pub fn delay_color(theme: Theme, delay: Option<u16>) -> Color {
    match delay {
        Some(ms) if ms <= 100 => theme.peak,
        Some(ms) if ms <= 260 => theme.high,
        Some(_) => theme.accent,
        None => theme.muted,
    }
}

pub struct Panel {
    title: Option<Line<'static>>,
    theme: Theme,
    focused: bool,
}

impl Panel {
    pub fn new(title: Option<Line<'static>>, theme: Theme, focused: bool) -> Self {
        Self {
            title,
            theme,
            focused,
        }
    }

    pub fn inner(area: Rect) -> Rect {
        Rect {
            x: area.x.saturating_add(1),
            y: area.y.saturating_add(1),
            width: area.width.saturating_sub(2),
            height: area.height.saturating_sub(2),
        }
    }

    fn set_cell(buf: &mut Buffer, x: u16, y: u16, symbol: &str, style: Style) {
        buf[(x, y)].set_symbol(symbol).set_style(style);
    }

    fn border_style(&self) -> Style {
        let color = if self.focused {
            blend_color(self.theme.border, self.theme.accent, 0.36)
        } else {
            self.theme.border
        };
        Style::default().fg(color)
    }

    fn render_title(&self, area: Rect, buf: &mut Buffer, title: &Line<'_>) {
        if area.width < 7 || title.width() == 0 {
            return;
        }
        let border_style = self.border_style();
        let text_start = area.x + 3;
        let max_width = area.width.saturating_sub(5);
        let right_limit = area.right().saturating_sub(1);

        Self::set_cell(buf, area.x + 2, area.y, "┐", border_style);
        let (end_x, _) = buf.set_line(text_start, area.y, title, max_width);
        if end_x < right_limit {
            Self::set_cell(buf, end_x, area.y, "┌", border_style);
        }
    }
}

impl Widget for Panel {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width == 0 || area.height == 0 {
            return;
        }
        let content_style = Style::default().fg(self.theme.text).bg(Color::Reset);
        let border_style = self.border_style();
        buf.set_style(area, content_style);

        if area.width < 2 || area.height < 2 {
            return;
        }

        let x0 = area.left();
        let y0 = area.top();
        let x1 = area.right() - 1;
        let y1 = area.bottom() - 1;

        for y in y0 + 1..y1 {
            for x in x0 + 1..x1 {
                Self::set_cell(buf, x, y, " ", content_style);
            }
        }
        for x in x0 + 1..x1 {
            Self::set_cell(buf, x, y0, "─", border_style);
            Self::set_cell(buf, x, y1, "─", border_style);
        }
        for y in y0 + 1..y1 {
            Self::set_cell(buf, x0, y, "│", border_style);
            Self::set_cell(buf, x1, y, "│", border_style);
        }

        Self::set_cell(buf, x0, y0, "╭", border_style);
        Self::set_cell(buf, x1, y0, "╮", border_style);
        Self::set_cell(buf, x0, y1, "╰", border_style);
        Self::set_cell(buf, x1, y1, "╯", border_style);

        if let Some(title) = &self.title {
            self.render_title(area, buf, title);
        }
    }
}

pub fn draw_panel(
    frame: &mut Frame,
    area: Rect,
    theme: Theme,
    title: Option<Line<'static>>,
    focused: bool,
) -> Rect {
    let inner = Panel::inner(area);
    frame.render_widget(Panel::new(title, theme, focused), area);
    inner
}

pub fn panel_title(title: String, theme: Theme) -> Line<'static> {
    Line::from(Span::styled(
        title,
        Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
    ))
}

pub fn module_title_line(
    theme: Theme,
    lang: Lang,
    shortcut: char,
    en_title: &'static str,
    local_title: &str,
) -> Line<'static> {
    let hk_style = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);
    let title_style = Style::default().fg(theme.text).add_modifier(Modifier::BOLD);

    if lang == Lang::En {
        let lower_sc = shortcut.to_ascii_lowercase();
        if let Some(idx) = en_title.to_ascii_lowercase().find(lower_sc) {
            let before = en_title[..idx].to_string();
            let ch = en_title[idx..idx + 1].to_string();
            let after = en_title[idx + 1..].to_string();
            let mut spans = Vec::new();
            if !before.is_empty() {
                spans.push(Span::styled(before, title_style));
            }
            spans.push(Span::styled(ch, hk_style));
            if !after.is_empty() {
                spans.push(Span::styled(after, title_style));
            }
            return Line::from(spans);
        }
    }
    Line::from(vec![
        Span::styled(format!("[{shortcut}]"), hk_style),
        Span::raw(" "),
        Span::styled(local_title.to_string(), title_style),
    ])
}

pub fn format_bytes(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GB", b / GB)
    } else if b >= MB {
        format!("{:.1} MB", b / MB)
    } else if b >= KB {
        format!("{:.1} KB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

pub fn format_rate(bytes_per_sec: u64) -> String {
    format!("{}/s", format_bytes(bytes_per_sec))
}

pub fn draw(frame: &mut Frame, app: &App) {
    let size = frame.area();
    let theme = app.theme();
    frame
        .buffer_mut()
        .set_style(size, Style::default().fg(theme.text).bg(Color::Reset));

    if size.width < 42 || size.height < 12 {
        let text = Paragraph::new(app.t("too_small"))
            .alignment(Alignment::Center)
            .style(Style::default().fg(theme.muted));
        frame.render_widget(text, size);
        return;
    }

    match app.screen {
        Screen::Menu => draw_menu(frame, app, size),
        Screen::Dashboard => draw_dashboard(frame, app, size),
        Screen::Settings => {
            draw_dashboard(frame, app, size);
            draw_settings(frame, app, size);
        }
        Screen::Help => {
            draw_dashboard(frame, app, size);
            draw_help(frame, app, size);
        }
    }
}

fn draw_menu(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let mut lines = Vec::new();
    let title_style = Style::default()
        .fg(theme.accent)
        .add_modifier(Modifier::BOLD);
    if area.height >= 16 {
        lines.extend(
            TITLE_ART
                .iter()
                .map(|line| Line::styled(*line, title_style)),
        );
    } else {
        lines.push(Line::styled("terc", title_style));
    }
    lines.push(Line::default());

    let items = ["menu_dashboard", "menu_settings", "menu_help", "menu_quit"];
    for (index, key) in items.iter().enumerate() {
        let selected = index == app.menu_index;
        lines.push(Line::styled(
            format!("{}{}", if selected { "› " } else { "  " }, app.t(key)),
            if selected {
                title_style
            } else {
                Style::default().fg(theme.text)
            },
        ));
    }
    if area.height >= lines.len() as u16 + 3 {
        lines.push(Line::default());
        lines.push(Line::styled(
            "↑↓  Enter  ·  Space",
            Style::default().fg(theme.muted),
        ));
    }
    let height = (lines.len() as u16).min(area.height);
    let content = Rect::new(
        area.x,
        area.y + (area.height - height) / 2,
        area.width,
        height,
    );
    frame.render_widget(Paragraph::new(lines).alignment(Alignment::Center), content);
}

fn draw_dashboard(frame: &mut Frame, app: &App, area: Rect) {
    let toolbar_h = if app.config.settings.show_toolbar { 1 } else { 0 };
    let top_h = if app.config.settings.show_traffic && area.height >= 18 {
        7
    } else if app.config.settings.show_traffic {
        5
    } else {
        0
    };

    let v_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(top_h),
            Constraint::Min(6),
            Constraint::Length(toolbar_h),
        ])
        .split(area);

    if top_h > 0 {
        let top_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
            .split(v_chunks[0]);
        draw_traffic_panel(frame, app, top_cols[0]);
        draw_overview_panel(frame, app, top_cols[1]);
    }

    match app.main_tab {
        MainTab::Proxies => draw_proxies_main(frame, app, v_chunks[1]),
        MainTab::Connections => draw_connections_main(frame, app, v_chunks[1]),
        MainTab::Logs => draw_logs_main(frame, app, v_chunks[1]),
    }

    if toolbar_h > 0 {
        frame.render_widget(
            Paragraph::new(toolbar_line(app, v_chunks[2].width)),
            v_chunks[2],
        );
    }
}

fn draw_traffic_panel(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let title = module_title_line(theme, app.lang(), 't', "Traffic", app.t("traffic"));
    let inner = draw_panel(frame, area, theme, Some(title), false);
    if inner.width < 10 || inner.height < 2 {
        return;
    }

    let stats_line = Line::from(vec![
        Span::styled(" ▲ ", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("{:<10}", format_rate(app.up_rate)),
            Style::default().fg(theme.text),
        ),
        Span::styled(" ▼ ", Style::default().fg(theme.peak).add_modifier(Modifier::BOLD)),
        Span::styled(
            format!("{:<10}", format_rate(app.down_rate)),
            Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!(
                "  Σ ↑{} ↓{}",
                format_bytes(app.snapshot.upload_total),
                format_bytes(app.snapshot.download_total)
            ),
            Style::default().fg(theme.muted),
        ),
    ]);

    frame.render_widget(
        Paragraph::new(stats_line),
        Rect::new(inner.x, inner.y, inner.width, 1),
    );

    if inner.height >= 2 {
        let graph_area = Rect::new(
            inner.x,
            inner.y + 1,
            inner.width,
            inner.height.saturating_sub(1),
        );
        draw_traffic_graph(frame, app, graph_area);
    }
}

fn draw_traffic_graph(frame: &mut Frame, app: &App, area: Rect) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    let theme = app.theme();
    let hist_len = app.up_history.len();
    let cols = area.width as usize;
    // Braille packs two samples per column.
    let positions = match app.config.settings.renderer {
        WaveRenderer::Blocks => cols,
        WaveRenderer::Braille => cols * 2,
    };
    let start = hist_len.saturating_sub(positions);
    let axis_max = nice_rate_max(
        app.up_history[start..]
            .iter()
            .chain(app.down_history[start..].iter())
            .copied()
            .fold(0.0f32, f32::max),
    );

    let buf = frame.buffer_mut();
    match app.config.settings.renderer {
        WaveRenderer::Blocks => draw_rate_blocks(
            buf,
            &app.down_history,
            &app.up_history,
            area,
            axis_max,
            theme,
        ),
        WaveRenderer::Braille => draw_rate_braille(
            buf,
            &app.down_history,
            &app.up_history,
            area,
            axis_max,
            theme,
        ),
    }

    let label = format!("max {}", format_rate(axis_max as u64));
    frame.render_widget(
        Paragraph::new(Span::styled(label, Style::default().fg(theme.muted))),
        Rect::new(area.x, area.y, area.width, 1),
    );
}

// Round up to the next 1/2/4/8 x 1024^n step so the axis label always renders
// as a clean KiB/s or MiB/s value alongside the 1024-based format_bytes.
fn nice_rate_max(v: f32) -> f32 {
    const FLOOR: f32 = 1024.0;
    if v <= FLOOR {
        return FLOOR;
    }
    let exp = (v / FLOOR).log2().ceil();
    FLOOR * 2f32.powf(exp)
}

// Map graph position -> history sample. With more positions than samples
// (very wide terminal) stretch the full history across the columns instead of
// clamping to the newest sample, which would draw a flat plateau on the right.
fn sample_index(pos: usize, positions: usize, hist_len: usize) -> usize {
    if positions >= hist_len {
        pos * hist_len / positions
    } else {
        hist_len - positions + pos
    }
}

fn draw_rate_blocks(
    buf: &mut Buffer,
    down: &[f32],
    up: &[f32],
    area: Rect,
    axis_max: f32,
    theme: Theme,
) {
    let hist_len = down.len();
    let cols = area.width as usize;
    let height_eighths = area.height as usize * 8;

    for col in 0..cols {
        let idx = sample_index(col, cols, hist_len);
        let d = (down[idx] / axis_max * height_eighths as f32).round() as usize;
        let u = (up[idx] / axis_max * height_eighths as f32).round() as usize;
        for row in 0..area.height as usize {
            let row_from_bottom = area.height as usize - 1 - row;
            let e_d = d.saturating_sub(row_from_bottom * 8).min(8);
            let e_u = u.saturating_sub(row_from_bottom * 8).min(8);
            if e_d == 0 && e_u == 0 {
                continue;
            }
            // Up overlays down from the baseline, mirroring the ▲/▼ legend colors.
            let (eighths, color) = if e_u > 0 {
                (e_u, theme.accent)
            } else {
                (e_d, theme.peak)
            };
            let x = area.x + col as u16;
            let y = area.y + row as u16;
            buf[(x, y)]
                .set_symbol(EIGHTH_BLOCKS[eighths])
                .set_style(Style::default().fg(color));
        }
    }
}

fn draw_rate_braille(
    buf: &mut Buffer,
    down: &[f32],
    up: &[f32],
    area: Rect,
    axis_max: f32,
    theme: Theme,
) {
    let hist_len = down.len();
    let cols = area.width as usize;
    let positions = cols * 2;
    let dot_rows = area.height as usize * 4;

    for col in 0..cols {
        let idx_l = sample_index(col * 2, positions, hist_len);
        let idx_r = sample_index(col * 2 + 1, positions, hist_len);
        let d_l = (down[idx_l] / axis_max * dot_rows as f32).round() as usize;
        let d_r = (down[idx_r] / axis_max * dot_rows as f32).round() as usize;
        let u_l = (up[idx_l] / axis_max * dot_rows as f32).round() as usize;
        let u_r = (up[idx_r] / axis_max * dot_rows as f32).round() as usize;

        for row in 0..area.height as usize {
            let row_from_bottom = area.height as usize - 1 - row;
            let mut down_bits = 0u8;
            let mut up_bits = 0u8;
            for sub in 0..4 {
                let dot_idx = row_from_bottom * 4 + (3 - sub);
                if dot_idx < d_l {
                    down_bits |= BRAILLE_DOT_BITS[0][sub];
                }
                if dot_idx < d_r {
                    down_bits |= BRAILLE_DOT_BITS[1][sub];
                }
                if dot_idx < u_l {
                    up_bits |= BRAILLE_DOT_BITS[0][sub];
                }
                if dot_idx < u_r {
                    up_bits |= BRAILLE_DOT_BITS[1][sub];
                }
            }
            let bits = down_bits | up_bits;
            if bits != 0 {
                let ch = char::from_u32(0x2800 + bits as u32).unwrap_or(' ');
                let color = if up_bits != 0 {
                    theme.accent
                } else {
                    theme.peak
                };
                let x = area.x + col as u16;
                let y = area.y + row as u16;
                let mut s = [0u8; 4];
                buf[(x, y)]
                    .set_symbol(ch.encode_utf8(&mut s))
                    .set_style(Style::default().fg(color));
            }
        }
    }
}

fn draw_overview_panel(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let title = module_title_line(theme, app.lang(), 'm', "Overview", app.t("overview"));
    let inner = draw_panel(frame, area, theme, Some(title), false);
    if inner.width < 10 || inner.height < 1 {
        return;
    }

    let pulse_sym = if !app.snapshot.running {
        "○"
    } else if app.pulse_phase > 0.55 {
        "●"
    } else {
        "◉"
    };
    let core_style = if app.snapshot.running {
        Style::default().fg(theme.peak).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)
    };

    let sys_badge = if app.snapshot.sysproxy_enabled {
        Span::styled(
            " ON ",
            Style::default()
                .fg(Color::Black)
                .bg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" OFF ", Style::default().fg(theme.muted))
    };

    let mut lines = Vec::new();
    lines.push(Line::from(vec![
        Span::styled(" Core ", Style::default().fg(theme.muted)),
        Span::styled(format!("{pulse_sym} "), core_style),
        Span::styled(
            if app.snapshot.running {
                format!("Mihomo {}", app.snapshot.version)
            } else {
                app.t("stopped").to_string()
            },
            Style::default().fg(theme.text),
        ),
        Span::styled("  SysProxy ", Style::default().fg(theme.muted)),
        sys_badge,
    ]));

    lines.push(Line::from(vec![
        Span::styled(" Mode ", Style::default().fg(theme.muted)),
        Span::styled(
            format!("{:<7}", app.snapshot.mode),
            Style::default().fg(theme.accent).add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Mem ", Style::default().fg(theme.muted)),
        Span::styled(
            format!("{:<8}", format_bytes(app.memory_inuse)),
            Style::default().fg(theme.text),
        ),
        Span::styled(" Conns ", Style::default().fg(theme.muted)),
        Span::styled(
            format!("{}", app.snapshot.connections.len()),
            Style::default().fg(theme.text),
        ),
    ]));

    if inner.height >= 3 {
        if let Some(sub) = &app.snapshot.sub_info {
            let summary = if !sub.traffic.is_empty() && !sub.expire.is_empty() {
                format!(" Sub  {} · {}", sub.traffic, sub.expire)
            } else if !sub.traffic.is_empty() {
                format!(" Sub  {}", sub.traffic)
            } else {
                format!(" Sub  {}", sub.expire)
            };
            lines.push(Line::from(Span::styled(
                summary,
                Style::default().fg(theme.muted),
            )));
        } else {
            lines.push(Line::from(vec![
                Span::styled(" Port ", Style::default().fg(theme.muted)),
                Span::styled(
                    format!(
                        "HTTP :{}  SOCKS :{}",
                        app.snapshot.http_port, app.snapshot.socks_port
                    ),
                    Style::default().fg(theme.text),
                ),
            ]));
        }
    }

    if inner.height >= 4 && !app.status_message.is_empty() {
        let msg_color = if app.status_is_error {
            theme.accent
        } else {
            theme.peak
        };
        lines.push(Line::from(Span::styled(
            format!(" › {}", app.status_message),
            Style::default().fg(msg_color),
        )));
    }

    frame.render_widget(Paragraph::new(lines), inner);
}

fn draw_proxies_main(frame: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(36), Constraint::Percentage(64)])
        .split(area);

    draw_groups_panel(frame, app, cols[0]);
    draw_nodes_panel(frame, app, cols[1]);
}

fn draw_groups_panel(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let focused = app.focus == FocusPane::Groups;
    let title = module_title_line(theme, app.lang(), '1', "Groups", app.t("groups"));
    let inner = draw_panel(frame, area, theme, Some(title), focused);
    if inner.width < 6 || inner.height < 1 {
        return;
    }

    if app.snapshot.groups.is_empty() {
        let hint = if app.snapshot.running {
            app.t("no_groups")
        } else {
            app.t("core_stopped_hint")
        };
        frame.render_widget(
            Paragraph::new(hint)
                .style(Style::default().fg(theme.muted))
                .alignment(Alignment::Center),
            inner,
        );
        return;
    }

    let visible_h = inner.height as usize;
    let start = visible_list_start(app.group_index, app.snapshot.groups.len(), visible_h);
    let max_w = inner.width.saturating_sub(2) as usize;

    let items: Vec<ListItem> = app
        .snapshot
        .groups
        .iter()
        .enumerate()
        .skip(start)
        .take(visible_h)
        .map(|(idx, g)| {
            let selected = idx == app.group_index;
            let prefix = if selected { "› " } else { "  " };
            let name_style = if selected {
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.text)
            };
            let now_style = if selected {
                Style::default().fg(theme.text)
            } else {
                Style::default().fg(theme.muted)
            };

            let left = format!("{prefix}{}", g.name);
            let right = g.now.clone();
            let left_w = left.width();
            let right_w = right.width();
            let gap = max_w.saturating_sub(left_w + right_w).max(1);

            ListItem::new(Line::from(vec![
                Span::styled(left, name_style),
                Span::raw(" ".repeat(gap)),
                Span::styled(right, now_style),
            ]))
        })
        .collect();

    frame.render_widget(
        List::new(items),
        Rect::new(inner.x + 1, inner.y, inner.width.saturating_sub(2), inner.height),
    );
}

fn draw_nodes_panel(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let focused = app.focus == FocusPane::Nodes;
    let current_group: Option<&ProxyGroup> = app.snapshot.groups.get(app.group_index);

    let title_str = match current_group {
        Some(g) => format!("{} · {} ({})", app.t("nodes"), g.name, g.all.len()),
        None => app.t("nodes").to_string(),
    };
    let title = Line::from(vec![
        Span::styled(
            "[2] ",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            title_str,
            Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
        ),
    ]);

    let inner = draw_panel(frame, area, theme, Some(title), focused);
    if inner.width < 8 || inner.height < 1 {
        return;
    }

    let Some(group) = current_group else {
        return;
    };

    let visible_h = inner.height as usize;
    let start = visible_list_start(app.node_index, group.all.len(), visible_h);
    let max_w = inner.width.saturating_sub(2) as usize;

    let items: Vec<ListItem> = group
        .all
        .iter()
        .enumerate()
        .skip(start)
        .take(visible_h)
        .map(|(idx, node_name)| {
            let selected = idx == app.node_index;
            let is_active = &group.now == node_name;
            let is_info = is_info_pseudo_node(node_name);

            let cursor = if selected && focused {
                "› "
            } else if selected {
                "· "
            } else {
                "  "
            };
            let radio = if is_info {
                "ℹ "
            } else if is_active {
                "● "
            } else {
                "○ "
            };

            let node_meta = app.snapshot.nodes.get(node_name);
            let proto = node_meta
                .map(|n| n.kind.as_str())
                .unwrap_or("")
                .to_string();
            let delay = node_meta.and_then(|n| n.delay);

            let delay_str = match delay {
                Some(ms) => format!("{ms:>4} ms"),
                None if is_info => String::new(),
                None => "   -   ".to_string(),
            };

            let name_style = if selected && focused {
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else if is_active {
                Style::default()
                    .fg(theme.peak)
                    .add_modifier(Modifier::BOLD)
            } else if is_info {
                Style::default().fg(theme.muted)
            } else {
                Style::default().fg(theme.text)
            };

            let radio_style = if is_active {
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.muted)
            };

            let left_text = format!("{cursor}{radio}{node_name}");
            let proto_tag = if !proto.is_empty() && !is_info {
                format!(" {proto}  ")
            } else {
                String::new()
            };

            let used_w = left_text.width() + proto_tag.width() + delay_str.width();
            let pad = max_w.saturating_sub(used_w).max(1);

            ListItem::new(Line::from(vec![
                Span::styled(cursor, name_style),
                Span::styled(radio, radio_style),
                Span::styled(node_name.clone(), name_style),
                Span::raw(" ".repeat(pad)),
                Span::styled(proto_tag, Style::default().fg(theme.muted)),
                Span::styled(delay_str, Style::default().fg(delay_color(theme, delay))),
            ]))
        })
        .collect();

    frame.render_widget(
        List::new(items),
        Rect::new(inner.x + 1, inner.y, inner.width.saturating_sub(2), inner.height),
    );
}

fn draw_connections_main(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let title_str = format!(
        "{} ({}) · [x] Close  [X] Close All",
        app.t("connections"),
        app.snapshot.connections.len()
    );
    let title = module_title_line(theme, app.lang(), 'c', "Connections", &title_str);
    let inner = draw_panel(frame, area, theme, Some(title), true);
    if inner.width < 10 || inner.height < 2 {
        return;
    }

    if app.snapshot.connections.is_empty() {
        frame.render_widget(
            Paragraph::new(app.t("no_connections"))
                .alignment(Alignment::Center)
                .style(Style::default().fg(theme.muted)),
            inner,
        );
        return;
    }

    let visible_h = inner.height as usize;
    let start = visible_list_start(app.conn_index, app.snapshot.connections.len(), visible_h);
    let max_w = inner.width.saturating_sub(2) as usize;

    let items: Vec<ListItem> = app
        .snapshot
        .connections
        .iter()
        .enumerate()
        .skip(start)
        .take(visible_h)
        .map(|(idx, c)| {
            let selected = idx == app.conn_index;
            let prefix = if selected { "› " } else { "  " };
            let style = if selected {
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.text)
            };

            let host_part = format!("{prefix}[{:<3}] {:<30}", c.network, truncate_str(&c.host, 30));
            let chain_part = format!(" {} ", truncate_str(&c.chains, 28));
            let traffic_part = format!("↑{} ↓{}", format_bytes(c.upload), format_bytes(c.download));
            let used = host_part.width() + chain_part.width() + traffic_part.width();
            let pad = max_w.saturating_sub(used).max(1);

            ListItem::new(Line::from(vec![
                Span::styled(host_part, style),
                Span::styled(chain_part, Style::default().fg(theme.peak)),
                Span::raw(" ".repeat(pad)),
                Span::styled(traffic_part, Style::default().fg(theme.muted)),
            ]))
        })
        .collect();

    frame.render_widget(
        List::new(items),
        Rect::new(inner.x + 1, inner.y, inner.width.saturating_sub(2), inner.height),
    );
}

fn draw_logs_main(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let title = module_title_line(theme, app.lang(), 'l', "Logs", app.t("logs"));
    let inner = draw_panel(frame, area, theme, Some(title), true);
    if inner.width < 10 || inner.height < 2 {
        return;
    }

    if app.logs.is_empty() {
        frame.render_widget(
            Paragraph::new(app.t("no_logs"))
                .alignment(Alignment::Center)
                .style(Style::default().fg(theme.muted)),
            inner,
        );
        return;
    }

    let visible_h = inner.height as usize;
    let skip = app.logs.len().saturating_sub(visible_h);
    let items: Vec<ListItem> = app
        .logs
        .iter()
        .skip(skip)
        .map(|(lvl, msg)| {
            let lvl_color = match lvl.as_str() {
                "error" | "err" => theme.accent,
                "warning" | "warn" => theme.mid,
                _ => theme.peak,
            };
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!(" {:<5} ", lvl.to_uppercase()),
                    Style::default().fg(lvl_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    truncate_str(msg, inner.width.saturating_sub(9) as usize),
                    Style::default().fg(theme.text),
                ),
            ]))
        })
        .collect();

    frame.render_widget(List::new(items), inner);
}

fn toolbar_line(app: &App, width: u16) -> Line<'static> {
    let theme = app.theme();
    let mut spans = vec![
        Span::styled("Space ", Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
        Span::styled(
            if app.snapshot.sysproxy_enabled {
                app.t("sysproxy_off").to_string()
            } else {
                app.t("sysproxy_on").to_string()
            },
            Style::default().fg(theme.text),
        ),
    ];

    let hints = format!(
        "  r {}  a {}  m {}  u {}  c {}  L {}  s {}  ? {}",
        app.t("test_delay"),
        app.t("auto_best"),
        app.t("mode"),
        app.t("sub_update"),
        app.t("connections"),
        app.t("logs"),
        app.t("settings"),
        app.t("help")
    );

    if spans.iter().map(|s| s.width()).sum::<usize>() + hints.width() <= width as usize {
        spans.push(Span::styled(hints, Style::default().fg(theme.muted)));
    } else {
        spans.push(Span::styled(
            "  r  a  m  u  c  L  s  ?".to_string(),
            Style::default().fg(theme.muted),
        ));
    }

    Line::from(spans)
}

fn draw_settings(frame: &mut Frame, app: &App, area: Rect) {
    let dashboard = if area.width < 82 || area.height < 22 {
        area
    } else {
        centered_rect(92, 88, area)
    };
    frame.render_widget(Clear, dashboard);
    let theme = app.theme();
    let inner = draw_panel(
        frame,
        dashboard,
        theme,
        Some(panel_title(app.t("settings").to_string(), theme)),
        true,
    );
    if inner.width >= 56 && inner.height >= 10 {
        draw_settings_board(frame, app, inner);
    } else {
        draw_settings_compact(frame, app, inner);
    }
}

fn draw_settings_board(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let rows = app.settings_rows();
    let selected_row = rows.get(app.setting_index);

    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(8),
            Constraint::Length(2),
        ])
        .split(area);

    let active_cat = selected_row
        .map(|r| r.category)
        .unwrap_or(SettingCategory::Core);
    let mut cat_spans = vec![Span::raw("  ")];
    for cat in [
        SettingCategory::Core,
        SettingCategory::Appearance,
        SettingCategory::Subscription,
    ] {
        let is_sel = cat == active_cat;
        let label = match cat {
            SettingCategory::Core => app.t("cat_core"),
            SettingCategory::Appearance => app.t("cat_appearance"),
            SettingCategory::Subscription => app.t("cat_sub"),
        };
        cat_spans.push(Span::styled(
            format!(" {label} "),
            if is_sel {
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            } else {
                Style::default().fg(theme.muted)
            },
        ));
        cat_spans.push(Span::raw(" "));
    }
    frame.render_widget(Paragraph::new(Line::from(cat_spans)), sections[0]);

    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
        .split(sections[1]);

    let list_inner = draw_panel(
        frame,
        columns[0],
        theme,
        Some(panel_title(app.t("settings_parameters").to_string(), theme)),
        true,
    );
    let detail_inner = draw_panel(
        frame,
        columns[1],
        theme,
        Some(panel_title(app.t("settings_details").to_string(), theme)),
        false,
    );

    draw_settings_rows(frame, app, inset_rect(list_inner, 1, 0), &rows);
    draw_settings_detail(frame, app, inset_rect(detail_inner, 1, 0), selected_row);

    let footer = Line::from(vec![
        Span::styled("←", Style::default().fg(theme.accent)),
        Span::styled(" / ", Style::default().fg(theme.muted)),
        Span::styled("→", Style::default().fg(theme.accent)),
        Span::styled(
            format!(" {}  ", app.t("setting_adjust")),
            Style::default().fg(theme.muted),
        ),
        Span::styled("↑", Style::default().fg(theme.accent)),
        Span::styled(" / ", Style::default().fg(theme.muted)),
        Span::styled("↓", Style::default().fg(theme.accent)),
        Span::styled(
            format!(" {}  ", app.t("setting_select")),
            Style::default().fg(theme.muted),
        ),
        Span::styled("Tab", Style::default().fg(theme.accent)),
        Span::styled(" Category", Style::default().fg(theme.muted)),
    ]);
    frame.render_widget(Paragraph::new(footer), sections[2]);
}

fn draw_settings_rows(frame: &mut Frame, app: &App, area: Rect, rows: &[SettingRow]) {
    let theme = app.theme();
    let visible_h = area.height as usize;
    let start = visible_list_start(app.setting_index, rows.len(), visible_h);
    let max_w = area.width as usize;

    let items: Vec<ListItem> = rows
        .iter()
        .enumerate()
        .skip(start)
        .take(visible_h)
        .map(|(idx, row)| {
            let selected = idx == app.setting_index;
            let prefix = if selected { "› " } else { "  " };
            let style = if selected {
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.text)
            };
            let val_style = if selected {
                Style::default().fg(theme.peak).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(theme.muted)
            };
            let left = format!("{prefix}{}", row.label);
            let right = row.value.clone();
            let gap = max_w.saturating_sub(left.width() + right.width()).max(1);
            ListItem::new(Line::from(vec![
                Span::styled(left, style),
                Span::raw(" ".repeat(gap)),
                Span::styled(right, val_style),
            ]))
        })
        .collect();

    frame.render_widget(List::new(items), area);
}

fn draw_settings_detail(
    frame: &mut Frame,
    app: &App,
    area: Rect,
    selected: Option<&SettingRow>,
) {
    let theme = app.theme();
    let Some(row) = selected else {
        return;
    };
    let lines = vec![
        Line::from(Span::styled(
            row.label.clone(),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        )),
        Line::default(),
        Line::from(Span::styled(
            format!("{}: {}", app.t("current_value"), row.value),
            Style::default().fg(theme.peak),
        )),
        Line::default(),
        Line::from(Span::styled(
            row.description.clone(),
            Style::default().fg(theme.text),
        )),
    ];
    frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
}

fn draw_settings_compact(frame: &mut Frame, app: &App, area: Rect) {
    let rows = app.settings_rows();
    draw_settings_rows(frame, app, inset_rect(area, 1, 0), &rows);
}

fn draw_help(frame: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(76, 78, area);
    frame.render_widget(Clear, popup);
    let theme = app.theme();
    let inner = draw_panel(
        frame,
        popup,
        theme,
        Some(panel_title(app.t("help").to_string(), theme)),
        true,
    );

    let shortcuts = [
        ("Space", app.t("help_space")),
        ("← / → (h / l)", app.t("help_hl")),
        ("↑ / ↓ (j / k)", app.t("help_jk")),
        ("Enter", app.t("help_enter")),
        ("r", app.t("help_r")),
        ("a", app.t("help_a")),
        ("m", app.t("help_m")),
        ("u", app.t("help_u")),
        ("c / L / p", app.t("help_tabs")),
        ("t", app.t("help_t")),
        ("s", app.t("help_s")),
        ("q / Esc", app.t("help_q")),
    ];

    let mut lines = Vec::new();
    lines.push(Line::default());
    for (k, desc) in shortcuts {
        lines.push(Line::from(vec![
            Span::styled(
                format!("  {k:<18}"),
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(desc.to_string(), Style::default().fg(theme.text)),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

pub fn visible_list_start(selected: usize, len: usize, visible_height: usize) -> usize {
    if visible_height == 0 || len <= visible_height {
        return 0;
    }
    let max_start = len - visible_height;
    selected
        .saturating_add(1)
        .saturating_sub(visible_height)
        .min(max_start)
}

pub fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

pub fn inset_rect(area: Rect, dx: u16, dy: u16) -> Rect {
    Rect {
        x: area.x.saturating_add(dx),
        y: area.y.saturating_add(dy),
        width: area.width.saturating_sub(dx * 2),
        height: area.height.saturating_sub(dy * 2),
    }
}

pub fn truncate_str(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max_chars.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nice_rate_max_rounds_to_clean_binary_steps() {
        assert_eq!(nice_rate_max(0.0), 1024.0);
        assert_eq!(nice_rate_max(1024.0), 1024.0);
        assert_eq!(nice_rate_max(1500.0), 2048.0);
        assert_eq!(nice_rate_max(900.0 * 1024.0), 1024.0 * 1024.0);
        assert_eq!(nice_rate_max(6_000_000.0), 8.0 * 1024.0 * 1024.0);
    }

    #[test]
    fn braille_graph_draws_down_and_up_series() {
        let area = Rect::new(0, 0, 20, 4);
        let mut buf = Buffer::empty(area);
        let down = vec![2_000_000.0; 64];
        let up = vec![500_000.0; 64];
        let axis = nice_rate_max(2_000_000.0);
        let th = theme(ThemeId::Spring);

        draw_rate_braille(&mut buf, &down, &up, area, axis, th);

        // Down dominates: top rows carry only the peak (down) color.
        assert_eq!(buf[(10, 0)].fg, th.peak);
        assert_eq!(buf[(10, 1)].fg, th.peak);
        // Up overlaps the baseline: bottom row carries the accent (up) color.
        assert_eq!(buf[(10, 3)].fg, th.accent);
        // Both cells contain braille dots.
        assert_ne!(buf[(10, 0)].symbol(), " ");
        assert_ne!(buf[(10, 3)].symbol(), " ");
    }

    #[test]
    fn blocks_graph_draws_down_and_up_series() {
        let area = Rect::new(0, 0, 20, 2);
        let mut buf = Buffer::empty(area);
        let down = vec![1_835_008.0; 64]; // 14/16 of axis
        let up = vec![655_360.0; 64]; // 5/16 of axis
        let axis = 2_097_152.0;
        let th = theme(ThemeId::Spring);

        draw_rate_blocks(&mut buf, &down, &up, area, axis, th);

        // Bottom row: up overlays down -> accent; top row: down only -> peak.
        assert_eq!(buf[(10, 1)].fg, th.accent);
        assert_eq!(buf[(10, 0)].fg, th.peak);
        assert_eq!(buf[(10, 1)].symbol(), "▅");
        assert_eq!(buf[(10, 0)].symbol(), "▆");
    }

    #[test]
    fn sample_index_maps_window_one_to_one_and_stretches_when_wide() {
        // Windowed: the newest samples map 1:1 onto graph positions.
        assert_eq!(sample_index(0, 40, 64), 24);
        assert_eq!(sample_index(39, 40, 64), 63);
        // Stretched: the full history spreads across more positions than samples.
        assert_eq!(sample_index(0, 96, 64), 0);
        assert_eq!(sample_index(95, 96, 64), 63);
        // No flat plateau: neighbouring far-right positions differ.
        assert_ne!(sample_index(94, 96, 64), sample_index(95, 96, 64));
    }

    #[test]
    fn blocks_graph_stretches_history_instead_of_flat_right_edge() {
        // 96 columns over 64 samples: positions exceed the history length.
        let area = Rect::new(0, 0, 96, 1);
        let mut buf = Buffer::empty(area);
        let mut down = vec![6_000_000.0; 64];
        down[63] = 0.0; // newest sample drops to idle
        let up = vec![0.0; 64];
        let axis = 8_388_608.0;
        let th = theme(ThemeId::Spring);

        draw_rate_blocks(&mut buf, &down, &up, area, axis, th);

        // Column 80 maps to an older high sample, not the clamped idle newest.
        assert_eq!(buf[(80, 0)].symbol(), "▆");
        // Only the last column reflects the idle newest sample.
        assert_eq!(buf[(95, 0)].symbol(), " ");
    }
}
