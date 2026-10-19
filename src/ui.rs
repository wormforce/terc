use ratatui::{
    buffer::Buffer,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    prelude::Frame,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Clear, List, ListItem, Paragraph, Widget, Wrap},
};
use serde::{Deserialize, Serialize};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use crate::{
    mihomo::{config_file_exists, is_info_pseudo_node, ProxyGroup},
    App, FocusPane, Lang, MainTab, Screen, SettingCategory, SettingRow, SetupPhase,
};

pub const THEMES: &[ThemeId] = &[ThemeId::Spring, ThemeId::Vintage, ThemeId::Mono];
pub const WAVE_RENDERERS: &[WaveRenderer] = &[WaveRenderer::Braille, WaveRenderer::Blocks];

const BRAILLE_DOT_BITS: [[u8; 4]; 2] = [[0x01, 0x02, 0x04, 0x40], [0x08, 0x10, 0x20, 0x80]];
const EIGHTH_BLOCKS: [&str; 9] = [" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"];

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
            self.theme.accent
        } else {
            self.theme.border
        };
        Style::default().fg(color).add_modifier(if self.focused {
            Modifier::BOLD
        } else {
            Modifier::empty()
        })
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

pub fn draw(frame: &mut Frame, app: &mut App) {
    let size = frame.area();
    app.proxy_hits.clear();
    app.toast_area = None;
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

    let content = size;
    match app.screen {
        Screen::Dashboard => {
            draw_dashboard(frame, app, content);
            crate::panels::draw_overlay(frame, app, content);
        }
        Screen::Settings => {
            draw_dashboard(frame, app, content);
            draw_settings(frame, app, content);
        }
        Screen::Help => {
            draw_dashboard(frame, app, content);
            draw_help(frame, app, content);
        }
        Screen::Setup => {
            if app.setup_origin == Screen::Settings {
                draw_dashboard(frame, app, content);
                draw_settings(frame, app, content);
            } else {
                draw_dashboard(frame, app, content);
            }
            draw_setup(frame, app, content);
        }
    }
    if app.toast_visible() && !app.status_detail {
        let width = size.width.saturating_sub(4).min(64);
        let message = Paragraph::new(app.status_message.clone()).wrap(Wrap { trim: true });
        let height = (message.line_count(width.saturating_sub(2)) as u16 + 2)
            .clamp(3, 6)
            .min(size.height.saturating_sub(2));
        let popup = Rect::new(size.right() - width - 1, size.y + 1, width, height);
        app.toast_area = Some(popup);
        frame.render_widget(Clear, popup);
        let title = if app.lang() == Lang::Zh {
            "通知  ! 全文  Backspace 收起"
        } else {
            "Notice  ! details  Backspace dismiss"
        };
        let inner = draw_panel(
            frame,
            popup,
            theme,
            Some(panel_title(title.into(), theme)),
            true,
        );
        frame.render_widget(
            message.style(Style::default().fg(if app.status_is_error {
                theme.accent
            } else {
                theme.text
            })),
            inner,
        );
    }
    if app.status_detail {
        let popup = centered_rect(92, 84, content);
        frame.render_widget(Clear, popup);
        let inner = draw_panel(
            frame,
            popup,
            theme,
            Some(panel_title("Status  ↑↓ scroll  Esc".into(), theme)),
            true,
        );
        let paragraph = Paragraph::new(app.status_message.clone()).wrap(Wrap { trim: false });
        let max = paragraph
            .line_count(inner.width)
            .saturating_sub(inner.height as usize);
        app.detail_scroll = app.detail_scroll.min(max as u16);
        frame.render_widget(paragraph.scroll((app.detail_scroll, 0)), inner);
    }
}

pub fn setup_cursor_cell(app: &App, area: Rect) -> Option<(u16, u16)> {
    editor_cursor_cell(&app.setup_editor.chars(), app.setup_editor.cursor, area)
}

pub fn editor_cursor_cell(chars: &[char], cursor: usize, area: Rect) -> Option<(u16, u16)> {
    if area.width == 0 || area.height == 0 {
        return None;
    }
    let col = input_viewport(chars, cursor.min(chars.len()), area.width as usize).1;
    Some((area.x + col.min(area.width as usize - 1) as u16, area.y))
}

fn draw_dashboard(frame: &mut Frame, app: &mut App, area: Rect) {
    let toolbar_h = if app.config.settings.show_toolbar {
        1
    } else {
        0
    };
    let top_h = if app.config.settings.show_traffic && area.height >= 22 {
        7
    } else if app.config.settings.show_traffic && area.height >= 16 {
        5
    } else {
        0
    };
    let toggle_h = if area.height >= 20 { 3 } else { 0 };

    let v_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(top_h),
            Constraint::Length(toggle_h),
            Constraint::Min(3),
            Constraint::Length(toolbar_h),
        ])
        .split(area);

    if top_h > 0 {
        let top_cols = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(v_chunks[0]);
        draw_traffic_panel(frame, app, top_cols[0]);
        draw_overview_panel(frame, app, top_cols[1]);
    }

    if toggle_h > 0 {
        crate::panels::draw_toggle_strip(frame, app, v_chunks[1]);
    }

    let main = v_chunks[2];
    match app.main_tab {
        MainTab::Proxies => draw_proxies_main(frame, app, main),
        MainTab::Connections => crate::panels::draw_connections(frame, app, main),
        MainTab::Logs => draw_logs_main(frame, app, main),
        MainTab::Dns => crate::panels::draw_dns(frame, app, main),
        MainTab::Rules => crate::panels::draw_rules(frame, app, main),
        MainTab::Providers => crate::panels::draw_providers(frame, app, main),
    }

    if toolbar_h > 0 {
        frame.render_widget(
            Paragraph::new(toolbar_line(app, v_chunks[3].width)),
            v_chunks[3],
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
        Span::styled(
            " ▲ ",
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{:<10}", format_rate(app.up_rate)),
            Style::default().fg(theme.text),
        ),
        Span::styled(
            " ▼ ",
            Style::default().fg(theme.peak).add_modifier(Modifier::BOLD),
        ),
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

    let label = format!(
        "max {}  {}ms",
        format_rate(axis_max as u64),
        app.config.settings.graph_interval_ms()
    );
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

    let zh = app.lang() == Lang::Zh;
    let labels = if zh {
        ["内核", "模式", "代理", "TUN", "内存", "连接"]
    } else {
        ["Core", "Mode", "Proxy", "TUN", "Mem", "Conns"]
    };
    let values = [
        if app.snapshot.running {
            "● Mihomo".to_string()
        } else {
            app.t("stopped").into()
        },
        app.snapshot.mode.clone(),
        if app.snapshot.sysproxy_enabled {
            "ON"
        } else {
            "OFF"
        }
        .into(),
        if app.snapshot.tun_enabled {
            "ON"
        } else {
            "OFF"
        }
        .into(),
        format_bytes(app.memory_inuse),
        app.snapshot.connections.len().to_string(),
    ];
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(inner);
    for i in 0..6 {
        let compact = inner.width < 34;
        let col = if compact { inner } else { cols[i % 2] };
        let row = if compact { i as u16 } else { (i / 2) as u16 };
        if row >= inner.height {
            break;
        }
        let label = labels[i];
        let line = Line::from(vec![
            Span::styled(
                format!(
                    " {label}{}",
                    " ".repeat(6usize.saturating_sub(label.width()))
                ),
                Style::default().fg(theme.muted),
            ),
            Span::styled(
                values[i].clone(),
                Style::default()
                    .fg(if i < 2 { theme.peak } else { theme.text })
                    .add_modifier(Modifier::BOLD),
            ),
        ]);
        frame.render_widget(
            Paragraph::new(line),
            Rect::new(col.x, inner.y + row, col.width, 1),
        );
    }
    if inner.height >= 4 && inner.width >= 34 {
        let port = if app.snapshot.mixed_port > 0 {
            app.snapshot.mixed_port
        } else {
            app.snapshot.http_port
        };
        frame.render_widget(
            Paragraph::new(format!(" {} :{port}", if zh { "代理端口" } else { "Port" }))
                .style(Style::default().fg(theme.muted)),
            Rect::new(inner.x, inner.y + 3, inner.width, 1),
        );
    }
    if inner.height >= 5 && inner.width >= 34 {
        if let Some(sub) = &app.snapshot.sub_info {
            frame.render_widget(
                Paragraph::new(format!(" {}  {}", sub.traffic, sub.expire))
                    .style(Style::default().fg(theme.muted)),
                Rect::new(inner.x, inner.y + 4, inner.width, 1),
            );
        }
    }
}

fn draw_proxies_main(frame: &mut Frame, app: &mut App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(36), Constraint::Percentage(64)])
        .split(area);

    draw_groups_panel(frame, app, cols[0]);
    draw_nodes_panel(frame, app, cols[1]);
}

fn draw_groups_panel(frame: &mut Frame, app: &mut App, area: Rect) {
    let theme = app.theme();
    let focused = app.focus == FocusPane::Groups;
    let mut title = module_title_line(theme, app.lang(), '1', "Groups", app.t("groups"));
    if focused {
        title.spans.insert(
            0,
            Span::styled(
                "▶ ",
                Style::default()
                    .fg(theme.accent)
                    .add_modifier(Modifier::BOLD),
            ),
        );
    }
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
    app.proxy_hits
        .push((inner, FocusPane::Groups, start, app.snapshot.groups.len()));
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
            let prefix = if selected && focused {
                "▶ "
            } else if selected {
                "› "
            } else {
                "  "
            };
            let name_style = if selected && focused {
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
            .style(if selected && focused {
                Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            } else {
                Style::default()
            })
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

fn draw_nodes_panel(frame: &mut Frame, app: &mut App, area: Rect) {
    let theme = app.theme();
    let focused = app.focus == FocusPane::Nodes;
    let current_group: Option<&ProxyGroup> = app.snapshot.groups.get(app.group_index);

    let title_str = match current_group {
        Some(g) => format!("{}  {} ({})", app.t("nodes"), g.name, g.all.len()),
        None => app.t("nodes").to_string(),
    };
    let title = Line::from(vec![
        Span::styled(
            if focused { "▶ [2] " } else { "[2] " },
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
    app.proxy_hits
        .push((inner, FocusPane::Nodes, start, group.all.len()));
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
                "▶ "
            } else if selected {
                "› "
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
            let proto = node_meta.map(|n| n.kind.as_str()).unwrap_or("").to_string();
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
                Style::default().fg(theme.peak).add_modifier(Modifier::BOLD)
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
            .style(if selected && focused {
                Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED)
            } else {
                Style::default()
            })
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

fn draw_logs_main(frame: &mut Frame, app: &mut App, area: Rect) {
    let theme = app.theme();
    let mode = if app.logs_paused { "Paused" } else { "Live" };
    let inner = draw_panel(
        frame,
        area,
        theme,
        Some(panel_title(
            format!("{}  {mode}  P pause  / search  Enter detail", app.t("logs")),
            theme,
        )),
        true,
    );
    let logs = app.filtered_logs();
    if app.log_detail {
        if let Some((level, text)) = logs.get(app.log_index) {
            let paragraph = Paragraph::new(format!("{level}  Esc back  ↑↓ scroll\n\n{text}"))
                .wrap(Wrap { trim: false });
            let max = paragraph
                .line_count(inner.width)
                .saturating_sub(inner.height as usize);
            app.detail_scroll = app.detail_scroll.min(max as u16);
            frame.render_widget(paragraph.scroll((app.detail_scroll, 0)), inner);
        }
        return;
    }
    let query = Rect::new(inner.x, inner.y, inner.width, inner.height.min(1));
    frame.render_widget(
        Paragraph::new(format!(
            "/ {}{}",
            app.log_query.text,
            if app.log_editing { "▌" } else { "" }
        ))
        .style(Style::default().fg(theme.accent)),
        query,
    );
    let body = Rect::new(
        inner.x,
        inner.y + 1,
        inner.width,
        inner.height.saturating_sub(1),
    );
    if logs.is_empty() {
        frame.render_widget(Paragraph::new(app.t("no_logs")), body);
        return;
    }
    let selected = if app.logs_paused {
        app.log_index.min(logs.len() - 1)
    } else {
        logs.len() - 1
    };
    let start = visible_list_start(selected, logs.len(), body.height as usize);
    let items: Vec<ListItem> = logs
        .iter()
        .enumerate()
        .skip(start)
        .take(body.height as usize)
        .map(|(index, (level, text))| {
            let color = match level.as_str() {
                "error" | "err" => theme.accent,
                "warning" | "warn" => theme.mid,
                _ => theme.text,
            };
            ListItem::new(Line::styled(
                format!(
                    "{} {:<5} {}",
                    if app.logs_paused && index == selected {
                        "›"
                    } else {
                        " "
                    },
                    level.to_uppercase(),
                    text
                ),
                Style::default().fg(color),
            ))
        })
        .collect();
    frame.render_widget(List::new(items), body);
}

fn toolbar_line(app: &App, width: u16) -> Line<'static> {
    let theme = app.theme();
    let context = match app.main_tab {
        MainTab::Connections => Some("↑↓ 选择  Enter 详情  x 断开  X 全部断开  Esc 返回"),
        MainTab::Logs => Some("↑↓ 阅读  P 暂停/继续  / 搜索  Enter 全文  Esc 返回"),
        MainTab::Dns => Some("e 编辑  Enter 查询  [ ] 类型  F 清缓存  Esc 返回"),
        MainTab::Rules => Some("/ 过滤与解释  Enter 解释  x 禁用/恢复  F 刷新  Esc 返回"),
        MainTab::Providers => Some("Enter 刷新当前  F 全部刷新  H 健康检查  Esc 返回"),
        MainTab::Proxies => None,
    };
    if let Some(text) = context {
        return Line::styled(text, Style::default().fg(theme.muted));
    }
    let hints = if app.lang() == Lang::Zh {
        [
            "Space 代理",
            "↵ 选节点",
            "r 测速",
            "m 模式",
            "a 自动优选",
            "u 更新订阅",
            "s 设置",
            "? 更多",
            "q 退出",
        ]
    } else {
        [
            "Space Proxy",
            "↵ Select",
            "r Test",
            "m Mode",
            "a Best",
            "u Update",
            "s Settings",
            "? More",
            "q Quit",
        ]
    };
    let mut text = String::new();
    // Reserve help and quit so narrow windows still offer a way to discover controls.
    let tail = format!("  {}  {}", hints[7], hints[8]);
    for hint in &hints[..7] {
        let candidate = if text.is_empty() {
            hint.to_string()
        } else {
            format!("{text}  {hint}")
        };
        if candidate.width() + tail.width() <= width as usize {
            text = candidate;
        }
    }
    text.push_str(&tail);
    Line::styled(text, Style::default().fg(theme.muted))
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

fn settings_hint(app: &App) -> &'static str {
    match (app.lang(), app.setting_input.is_some()) {
        (Lang::Zh, true) => "Enter 保存  Esc 取消  Ctrl+U 清空",
        (_, true) => "Enter Save  Esc Cancel  Ctrl+U Clear",
        (Lang::Zh, false) => "Tab 分类  ↑↓ 选择  ←→ 调整  ↵ 编辑  Esc",
        (_, false) => "Tab Tabs  ↑↓ Select  ←→ Adjust  ↵ Edit  Esc",
    }
}

fn draw_settings_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let rows = app.settings_rows();
    let active = rows[app.setting_index].category;
    let theme = app.theme();
    let columns = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 3); 3])
        .split(area);
    for (i, (category, key)) in [
        (SettingCategory::Core, "cat_core"),
        (SettingCategory::Appearance, "cat_appearance"),
        (SettingCategory::Subscription, "cat_sub"),
    ]
    .iter()
    .enumerate()
    {
        let name = if area.width < 60 {
            if app.lang() == Lang::Zh {
                ["代理", "外观", "订阅"][i]
            } else {
                ["Core", "UI", "Subs"][i]
            }
        } else {
            app.t(key)
        };
        let label = if *category == active {
            format!("[{} {}]", i + 1, name)
        } else {
            format!("{} {}", i + 1, name)
        };
        frame.render_widget(
            Paragraph::new(label)
                .alignment(Alignment::Center)
                .style(if *category == active {
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(theme.muted)
                }),
            columns[i],
        );
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

    draw_settings_tabs(frame, app, sections[0]);

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

    frame.render_widget(
        Paragraph::new(settings_hint(app)).style(Style::default().fg(theme.muted)),
        sections[2],
    );
}

fn draw_settings_rows(frame: &mut Frame, app: &App, area: Rect, rows: &[SettingRow]) {
    let theme = app.theme();
    let category = rows[app.setting_index].category;
    let filtered: Vec<_> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| r.category == category)
        .collect();
    let selected = filtered
        .iter()
        .position(|(i, _)| *i == app.setting_index)
        .unwrap_or(0);
    let visible = (area.height as usize / 2).max(1);
    let start = visible_list_start(selected, filtered.len(), visible);
    let mut lines = Vec::new();
    for (index, row) in filtered.iter().skip(start).take(visible) {
        let active = *index == app.setting_index;
        let style = if active {
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(theme.text)
        };
        lines.push(Line::styled(
            format!("{}{}", if active { "› " } else { "  " }, row.label),
            style,
        ));
        lines.push(Line::styled(
            format!("  {}{}", row.value, if active { "  ← →" } else { "" }),
            Style::default().fg(if active { theme.peak } else { theme.muted }),
        ));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

fn draw_settings_detail(frame: &mut Frame, app: &App, area: Rect, selected: Option<&SettingRow>) {
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
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(2),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);
    draw_settings_tabs(frame, app, sections[0]);
    draw_settings_rows(frame, app, inset_rect(sections[1], 1, 0), &rows);
    frame.render_widget(
        Paragraph::new(rows[app.setting_index].description.clone())
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(app.theme().muted)),
        sections[2],
    );
    frame.render_widget(Paragraph::new(settings_hint(app)), sections[3]);
}

fn draw_help(frame: &mut Frame, app: &mut App, area: Rect) {
    let popup = centered_rect(94, 92, area);
    frame.render_widget(Clear, popup);
    let theme = app.theme();
    let inner = draw_panel(
        frame,
        popup,
        theme,
        Some(panel_title(
            format!("{}  ↑↓ / PgUp PgDn", app.t("help")),
            theme,
        )),
        true,
    );

    let shortcuts = [
        ("Space", app.t("help_space")),
        ("m", app.t("help_m")),
        ("r", app.t("help_r")),
        ("a", app.t("help_a")),
        ("u", app.t("help_u")),
        ("Enter", app.t("help_enter")),
        ("↑↓ jk", app.t("help_jk")),
        ("c / L / p", app.t("help_tabs")),
        ("t / s", app.t("help_t")),
        ("K", "启动/停止 terc 管理的内核  Start/stop managed core"),
        ("", "进阶与排查 / Advanced & diagnostics"),
        ("T / n / i", app.t("help_tun")),
        ("D", app.t("help_dns_key")),
        ("d g v o f b w", app.t("help_views")),
        ("e  /", app.t("help_explain")),
        ("x", app.t("help_rule_x")),
        ("F", app.t("help_flush")),
        (
            "Logs: P / Enter",
            "日志：暂停、搜索、全文  Logs: pause, search, full text",
        ),
        (
            "! / Backspace",
            "操作结果：全文 / 收起  Result: details / dismiss",
        ),
        ("q", app.t("help_q")),
        ("Esc", app.t("help_esc")),
    ];

    let lines: Vec<Line> = shortcuts
        .into_iter()
        .map(|(key, desc)| {
            Line::from(vec![
                Span::styled(
                    format!("{key}  "),
                    Style::default()
                        .fg(theme.accent)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(desc.to_string(), Style::default().fg(theme.text)),
            ])
        })
        .collect();
    let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true });
    let max = paragraph
        .line_count(inner.width)
        .saturating_sub(inner.height as usize);
    app.help_scroll = app.help_scroll.min(max as u16);
    frame.render_widget(paragraph.scroll((app.help_scroll, 0)), inner);
}

/// Single-line input windowing: returns (first visible char, cursor column).
/// One cell is reserved for the cursor block and one for the leading ellipsis.
pub fn input_viewport(chars: &[char], cursor: usize, body_w: usize) -> (usize, usize) {
    let cursor = cursor.min(chars.len());
    let mut head = cursor;
    let mut text = 0usize;
    while head > 0 {
        let w = chars[head - 1].width().unwrap_or(1);
        let next = text + w;
        let ellipsis = usize::from(head - 1 > 0);
        if ellipsis + next + 1 > body_w {
            break;
        }
        head -= 1;
        text = next;
    }
    (head, usize::from(head > 0) + text)
}

fn setup_line_spans(app: &App, theme: Theme, body_w: usize) -> Vec<Span<'static>> {
    editor_line_spans(
        &app.setup_editor.chars(),
        app.setup_editor.cursor,
        theme,
        body_w,
    )
}

pub fn editor_line_spans(
    chars: &[char],
    cursor: usize,
    theme: Theme,
    body_w: usize,
) -> Vec<Span<'static>> {
    let cursor = cursor.min(chars.len());
    let head = input_viewport(chars, cursor, body_w).0;

    let mut spans = Vec::new();
    let mut used = 0usize;
    if head > 0 {
        spans.push(Span::styled("…", Style::default().fg(theme.muted)));
        used += 1;
    }
    for c in &chars[head..cursor] {
        spans.push(Span::styled(c.to_string(), Style::default().fg(theme.text)));
        used += c.width().unwrap_or(1);
    }
    spans.push(Span::styled(
        " ",
        Style::default()
            .fg(theme.accent)
            .add_modifier(Modifier::BOLD),
    ));
    used += 1;
    for c in &chars[cursor..] {
        let w = c.width().unwrap_or(1);
        if used + w > body_w {
            break;
        }
        spans.push(Span::styled(c.to_string(), Style::default().fg(theme.text)));
        used += w;
    }
    spans
}

fn setup_step_line(theme: Theme, index: usize, text: String, done: bool) -> Line<'static> {
    let mark = if done { "✓" } else { "○" };
    let mark_color = if done { theme.peak } else { theme.accent };
    Line::from(vec![
        Span::styled(
            format!("  {mark} "),
            Style::default().fg(mark_color).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("{index}. "),
            Style::default().fg(theme.text).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            text,
            Style::default().fg(if done { theme.text } else { theme.muted }),
        ),
    ])
}

fn draw_setup(frame: &mut Frame, app: &App, area: Rect) {
    let theme = app.theme();
    let popup = centered_rect(86, 74, area);
    frame.render_widget(Clear, popup);
    let inner = draw_panel(
        frame,
        popup,
        theme,
        Some(panel_title(app.t("setup_title").to_string(), theme)),
        true,
    );

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Length(5),
            Constraint::Length(3),
            Constraint::Min(3),
        ])
        .split(inner);

    let intro = Paragraph::new(app.t("setup_intro"))
        .style(Style::default().fg(theme.muted))
        .wrap(Wrap { trim: true });
    frame.render_widget(intro, rows[0]);

    let sub_state = if config_file_exists(&app.config.controller) {
        app.t("setup_config_ok")
    } else if app.setup_phase == SetupPhase::Fetching {
        app.t("setup_fetching")
    } else {
        app.t("setup_waiting")
    };
    let core_state = if app.core_downloading {
        app.t("setup_dl_busy")
    } else if app.core_binary_found() {
        app.t("setup_found")
    } else {
        app.t("setup_missing")
    };
    let run_state = if app.snapshot.running {
        app.t("setup_running")
    } else if app.setup_phase == SetupPhase::Starting {
        app.t("setup_starting")
    } else {
        app.t("setup_stopped")
    };

    let has_config = config_file_exists(&app.config.controller);
    let mut step_lines = vec![
        setup_step_line(
            theme,
            1,
            format!("{}  {}", app.t("setup_step_sub"), sub_state),
            has_config,
        ),
        setup_step_line(
            theme,
            2,
            format!(
                "{}  {}  {}",
                app.t("setup_step_core"),
                core_state,
                truncate_str(&app.snapshot.core_bin_path, 28)
            ),
            app.core_binary_found(),
        ),
        setup_step_line(
            theme,
            3,
            format!("{}  {}", app.t("setup_step_run"), run_state),
            app.snapshot.running,
        ),
    ];
    if !app.core_binary_found() && !app.core_downloading {
        step_lines.push(Line::from(Span::styled(
            format!("      {}", app.t("setup_dl_hint")),
            Style::default().fg(theme.accent),
        )));
    }
    frame.render_widget(Paragraph::new(step_lines), rows[1]);

    let input_area = draw_panel(
        frame,
        rows[2],
        theme,
        Some(panel_title(app.t("setup_input").to_string(), theme)),
        app.setup_phase == SetupPhase::Editing,
    );
    let text_area = Rect::new(
        input_area.x + 1,
        input_area.y,
        input_area.width.saturating_sub(2),
        1,
    );
    let body_w = text_area.width as usize;
    if body_w > 0 {
        let spans = setup_line_spans(app, theme, body_w);
        frame.render_widget(Paragraph::new(Line::from(spans)), text_area);
        if app.setup_phase == SetupPhase::Editing {
            if let Some(cell) = setup_cursor_cell(app, text_area) {
                frame.set_cursor_position(cell);
            }
        }
    }

    let busy = app.setup_phase != SetupPhase::Editing || app.core_downloading;
    let mut foot = vec![
        Line::from(Span::styled(
            app.t("setup_paste_hint"),
            Style::default().fg(theme.muted),
        )),
        Line::styled(
            app.t("setup_keys"),
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if !app.status_message.is_empty() {
        foot.push(Line::from(Span::styled(
            truncate_str(&app.status_message, inner.width.saturating_sub(4) as usize),
            Style::default().fg(if app.status_is_error {
                theme.accent
            } else {
                theme.text
            }),
        )));
    }
    if !busy {
        foot.push(Line::from(Span::styled(
            app.t("setup_sysproxy_note"),
            Style::default().fg(theme.muted),
        )));
    }
    frame.render_widget(Paragraph::new(foot).wrap(Wrap { trim: true }), rows[3]);
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
    fn input_viewport_keeps_cursor_visible_when_scrolled() {
        let chars: Vec<char> = "https://sub.example.com/link/abcdefghij".chars().collect();
        // Short field: cursor at the end must stay inside the field, with a leading ellipsis.
        let (head, col) = input_viewport(&chars, chars.len(), 12);
        assert!(head > 0);
        assert!(col < 12, "cursor column {col} escaped the 12 cell field");

        // Wide field: no scrolling needed, cursor sits right after the text.
        let (head, col) = input_viewport(&chars, chars.len(), chars.len() + 4);
        assert_eq!(head, 0);
        assert_eq!(col, chars.len());

        // Empty input at zero width stays clamped.
        assert_eq!(input_viewport(&[], 0, 1), (0, 0));
    }

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
