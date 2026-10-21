//! One add/edit form for subscriptions, individual proxies and pasted links.
use crate::{compose::ProfileSource, manage::l3, App, LineEditor};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    prelude::Frame,
    style::{Modifier, Style},
    widgets::{Paragraph, Wrap},
};
use serde_json::{json, Map, Value};
const TYPES: &[&str] = &[
    "ss",
    "trojan",
    "vmess",
    "vless",
    "socks5",
    "http",
    "hysteria2",
    "tuic",
];
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Kind,
    Name,
    Protocol,
    Url,
    Server,
    Port,
    User,
    Secret,
    Password,
    Cipher,
    Tls,
    Sni,
    Transport,
    Path,
    WsHost,
    EarlyData,
    FastOpen,
    Flow,
    Save,
}
#[derive(Clone, Debug)]
pub struct Form {
    pub edit_id: Option<String>,
    pub original: ProfileSource,
    pub kind: usize,
    pub protocol: usize,
    pub index: usize,
    pub editing: bool,
    pub submitting: bool,
    pub name: LineEditor,
    pub url: LineEditor,
    pub server: LineEditor,
    pub port: LineEditor,
    pub user: LineEditor,
    pub secret: LineEditor,
    pub password: LineEditor,
    pub cipher: LineEditor,
    pub sni: LineEditor,
    pub path: LineEditor,
    pub ws_host: LineEditor,
    pub early_data: LineEditor,
    pub flow: LineEditor,
    pub tls: bool,
    pub ws: bool,
    /// V2Ray HTTPUpgrade: `network: ws` + `ws-opts.v2ray-http-upgrade`.
    pub upgrade: bool,
    pub fast_open: bool,
}
impl Default for Form {
    fn default() -> Self {
        let mut f = Self {
            edit_id: None,
            original: ProfileSource::default(),
            kind: 0,
            protocol: 0,
            index: 0,
            editing: false,
            submitting: false,
            name: Default::default(),
            url: Default::default(),
            server: Default::default(),
            port: Default::default(),
            user: Default::default(),
            secret: Default::default(),
            password: Default::default(),
            cipher: Default::default(),
            sni: Default::default(),
            path: Default::default(),
            ws_host: Default::default(),
            early_data: Default::default(),
            flow: Default::default(),
            tls: false,
            ws: false,
            upgrade: false,
            fast_open: false,
        };
        f.port.load("443");
        f.cipher.load("aes-128-gcm");
        f.path.load("/");
        f
    }
}
impl Form {
    pub fn from_record(id: String, source: ProfileSource) -> Self {
        let mut f = Self::default();
        f.edit_id = Some(id);
        f.name.load(&source.name);
        f.url.load(&source.subscription_url);
        if source.subscription_url.is_empty() {
            // Legacy `network: httpupgrade` nodes open as HTTPUpgrade.
            let mut node = source.nodes.first().cloned().unwrap_or_default();
            crate::subconv::normalize_ws_network(&mut node);
            if source.nodes.len() == 1 && fits_form(&node) {
                f.kind = 1;
                let n = &node;
                f.protocol = TYPES
                    .iter()
                    .position(|t| Some(*t) == n["type"].as_str())
                    .unwrap_or(0);
                f.server.load(n["server"].as_str().unwrap_or(""));
                f.port.load(&n["port"].to_string());
                f.user.load(n["username"].as_str().unwrap_or(""));
                f.secret
                    .load(n["uuid"].as_str().or(n["password"].as_str()).unwrap_or(""));
                f.password.load(n["password"].as_str().unwrap_or(""));
                f.cipher.load(n["cipher"].as_str().unwrap_or("aes-128-gcm"));
                f.sni
                    .load(n["servername"].as_str().or(n["sni"].as_str()).unwrap_or(""));
                f.tls = n["tls"].as_bool().unwrap_or(false);
                f.ws = n["network"].as_str() == Some("ws");
                let opts = &n["ws-opts"];
                f.upgrade = opts["v2ray-http-upgrade"].as_bool() == Some(true);
                f.fast_open = opts["v2ray-http-upgrade-fast-open"].as_bool() == Some(true);
                f.path.load(opts["path"].as_str().unwrap_or("/"));
                let host = opts["headers"]
                    .as_object()
                    .and_then(|h| h.iter().find(|(k, _)| k.eq_ignore_ascii_case("host")))
                    .and_then(|(_, v)| v.as_str());
                f.ws_host.load(host.unwrap_or(""));
                let early = opts["max-early-data"].as_u64().filter(|n| *n > 0);
                f.early_data
                    .load(&early.map(|n| n.to_string()).unwrap_or_default());
                f.flow.load(n["flow"].as_str().unwrap_or(""));
            } else {
                f.kind = 2;
                f.url.load(
                    &source
                        .nodes
                        .iter()
                        .map(Value::to_string)
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
            }
        }
        f.original = source;
        f
    }
    pub fn fields(&self) -> Vec<Field> {
        use Field::*;
        let mut fields = vec![Kind, Name];
        if self.kind != 1 {
            fields.push(Url);
        } else {
            fields.extend([Protocol, Server, Port]);
            let p = TYPES[self.protocol];
            if matches!(p, "socks5" | "http") {
                fields.push(User);
            }
            fields.push(Secret);
            if p == "tuic" {
                fields.push(Password);
            }
            if p == "ss" {
                fields.push(Cipher);
            }
            if matches!(p, "vmess" | "vless" | "http") {
                fields.push(Tls);
            }
            if matches!(p, "trojan" | "hysteria2" | "tuic") || self.tls {
                fields.push(Sni);
            }
            if matches!(p, "vmess" | "vless" | "trojan") {
                fields.push(Transport);
                if self.ws {
                    fields.extend([Path, WsHost]);
                    fields.push(if self.upgrade { FastOpen } else { EarlyData });
                }
            }
            if p == "vless" {
                fields.push(Flow);
            }
        }
        fields.push(Save);
        fields
    }
    fn editor(&mut self, field: Field) -> Option<&mut LineEditor> {
        use Field::*;
        Some(match field {
            Name => &mut self.name,
            Url => &mut self.url,
            Server => &mut self.server,
            Port => &mut self.port,
            User => &mut self.user,
            Secret => &mut self.secret,
            Password => &mut self.password,
            Cipher => &mut self.cipher,
            Sni => &mut self.sni,
            Path => &mut self.path,
            WsHost => &mut self.ws_host,
            EarlyData => &mut self.early_data,
            Flow => &mut self.flow,
            _ => return None,
        })
    }
    fn editor_ref(&self, field: Field) -> Option<&LineEditor> {
        use Field::*;
        Some(match field {
            Name => &self.name,
            Url => &self.url,
            Server => &self.server,
            Port => &self.port,
            User => &self.user,
            Secret => &self.secret,
            Password => &self.password,
            Cipher => &self.cipher,
            Sni => &self.sni,
            Path => &self.path,
            WsHost => &self.ws_host,
            EarlyData => &self.early_data,
            Flow => &self.flow,
            _ => return None,
        })
    }
    /// 0 TCP, 1 WebSocket, 2 HTTPUpgrade.
    fn transport(&self) -> usize {
        match (self.ws, self.upgrade) {
            (false, _) => 0,
            (true, false) => 1,
            (true, true) => 2,
        }
    }
    pub fn paste(&mut self, text: &str) {
        let field = self.fields()[self.index];
        if let Some(e) = self.editor(field) {
            e.load(text.trim());
            self.editing = true;
        }
    }
    pub fn record(&self) -> Result<ProfileSource, String> {
        if self.name.trimmed().is_empty() {
            return Err("请给代理起个名字".into());
        }
        let mut result = self.original.clone();
        result.name = self.name.trimmed();
        result.subscription_url.clear();
        // Migrated configs keep subscription.yaml; form nodes become its manual extras.
        let imported = self.kind != 0 && self.original.kind == "imported";
        if !imported {
            result.kind = if self.kind == 0 {
                "subscription"
            } else {
                "proxy"
            }
            .into();
        }
        if result.routing.is_empty() {
            result.routing = "subscription".into();
        }
        if self.kind == 0 {
            let url = self.url.trimmed();
            if !(url.starts_with("https://") || url.starts_with("http://"))
                || url
                    .split("://")
                    .nth(1)
                    .unwrap_or("")
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .is_empty()
            {
                return Err("请输入有效的订阅 URL".into());
            }
            result.subscription_url = url;
            // Keep manually attached nodes while editing an existing subscription,
            // or giving an imported one a URL; there they are extras, not the form's.
            if self.original.subscription_url.is_empty() && self.original.kind != "imported" {
                result.nodes.clear();
            }
        } else if self.kind == 2 {
            let raw = self.url.trimmed();
            let lines = crate::subconv::block_to_node_lines(&raw)
                .transpose()?
                .unwrap_or_else(|| raw.lines().map(str::to_string).collect());
            result.nodes = lines
                .iter()
                .filter(|l| !l.trim().is_empty())
                .map(|l| crate::subconv::parse_node_line(l))
                .collect::<Result<_, _>>()?;
            if result.nodes.is_empty() && !imported {
                return Err("请粘贴节点链接或配置".into());
            }
        } else {
            let p = TYPES[self.protocol];
            let port = self
                .port
                .trimmed()
                .parse::<u16>()
                .ok()
                .filter(|p| *p > 0)
                .ok_or("端口范围为 1–65535")?;
            if self.server.trimmed().is_empty() {
                return Err("请填写服务器地址".into());
            }
            if !matches!(p, "socks5" | "http") && self.secret.text.is_empty() {
                return Err("请填写密码或 UUID".into());
            }
            if matches!(p, "vmess" | "vless" | "tuic") && !valid_uuid(&self.secret.trimmed()) {
                return Err("UUID 格式不正确".into());
            }
            let mut base = self.original.nodes.first().cloned().unwrap_or_default();
            crate::subconv::normalize_ws_network(&mut base);
            let mut n = if base["type"].as_str() == Some(p) {
                base.clone()
            } else {
                json!({})
            };
            // Switching between vmess / vless / trojan keeps the WebSocket options.
            if self.ws
                && matches!(p, "vmess" | "vless" | "trojan")
                && base["ws-opts"].is_object()
                && n.get("ws-opts").is_none()
            {
                n["ws-opts"] = base["ws-opts"].clone();
            }
            n["name"] = json!(result.name);
            n["type"] = json!(p);
            if matches!(p, "ss" | "trojan" | "vmess" | "vless" | "socks5") && n.get("udp").is_none()
            {
                n["udp"] = json!(true);
            }
            n["server"] = json!(self.server.trimmed());
            n["port"] = json!(port);
            if matches!(p, "vmess" | "vless" | "tuic") {
                n["uuid"] = json!(self.secret.trimmed());
            } else {
                n["password"] = json!(self.secret.text);
            }
            if p == "tuic" {
                if self.password.text.is_empty() {
                    return Err("请填写 TUIC 密码".into());
                }
                n["password"] = json!(self.password.text);
                // A stored node keeps its explicit controller on edit.
                if n.get("congestion-controller")
                    .and_then(Value::as_str)
                    .is_none_or(|c| c.trim().is_empty())
                {
                    n["congestion-controller"] = json!("bbr");
                }
                n.as_object_mut().unwrap().remove("token");
            }
            if matches!(p, "http" | "socks5") {
                n["username"] = json!(self.user.text);
            }
            if p == "ss" {
                if self.cipher.trimmed().is_empty() {
                    return Err("请选择加密方式".into());
                }
                n["cipher"] = json!(self.cipher.trimmed());
            }
            if p == "vmess" {
                n["alterId"] = json!(0);
                n["cipher"] = json!("auto");
            }
            if matches!(p, "vmess" | "vless" | "http") {
                n["tls"] = json!(self.tls);
            }
            let sni_key = if matches!(p, "vmess" | "vless") {
                "servername"
            } else {
                "sni"
            };
            n.as_object_mut().unwrap().remove(sni_key);
            if !self.sni.trimmed().is_empty() {
                n[sni_key] = json!(self.sni.trimmed());
            }
            // Leave grpc/h2 alone unless the user switches Transport to WebSocket.
            if matches!(p, "vmess" | "vless" | "trojan")
                && (self.ws || matches!(n["network"].as_str(), None | Some("tcp" | "ws")))
            {
                n["network"] = json!(if self.ws { "ws" } else { "tcp" });
                if self.ws {
                    n["ws-opts"] = Value::Object(self.ws_opts(&n["ws-opts"])?);
                } else {
                    n.as_object_mut().unwrap().remove("ws-opts");
                }
            }
            if p == "vless" {
                n.as_object_mut().unwrap().remove("flow");
                if !self.flow.trimmed().is_empty() {
                    n["flow"] = json!(self.flow.trimmed());
                }
            }
            result.nodes = vec![n];
        }
        Ok(result)
    }
    /// `old` ws-opts with the form's keys applied; keys the form does not
    /// manage (custom headers, unknown options) stay as they are.
    fn ws_opts(&self, old: &Value) -> Result<Map<String, Value>, String> {
        let mut opts = old.as_object().cloned().unwrap_or_default();
        let path = self.path.trimmed();
        opts.insert(
            "path".into(),
            json!(if path.is_empty() { "/" } else { &path }),
        );
        let host = self.ws_host.trimmed();
        match opts.get_mut("headers").and_then(Value::as_object_mut) {
            Some(headers) => {
                let was_empty = headers.is_empty();
                let key = headers
                    .keys()
                    .find(|k| k.eq_ignore_ascii_case("host"))
                    .cloned();
                if !host.is_empty() {
                    headers.insert(key.unwrap_or_else(|| "Host".into()), json!(host));
                } else if let Some(key) = key {
                    headers.remove(&key);
                    if headers.is_empty() && !was_empty {
                        opts.remove("headers");
                    }
                }
            }
            None if !host.is_empty() => {
                opts.insert("headers".into(), json!({ "Host": host }));
            }
            None => {}
        }
        if self.upgrade {
            opts.insert("v2ray-http-upgrade".into(), json!(true));
            if self.fast_open {
                opts.insert("v2ray-http-upgrade-fast-open".into(), json!(true));
            } else {
                opts.remove("v2ray-http-upgrade-fast-open");
            }
            // Same as subconv::ws_transport: HTTPUpgrade has no WebSocket early data.
            opts.remove("max-early-data");
            opts.remove("early-data-header-name");
        } else {
            opts.remove("v2ray-http-upgrade");
            opts.remove("v2ray-http-upgrade-fast-open");
            let early = self.early_data.trimmed();
            let size = if early.is_empty() {
                0
            } else {
                early
                    .parse::<u64>()
                    .map_err(|_| "早期数据须为整数 / Early data must be a whole number")?
            };
            if size > 0 {
                // Without a header name Mihomo appends early data to the path;
                // an untouched value keeps that mode, a new one gets the header.
                let changed = opts.get("max-early-data").and_then(Value::as_u64) != Some(size);
                opts.insert("max-early-data".into(), json!(size));
                if changed {
                    opts.entry("early-data-header-name")
                        .or_insert_with(|| json!("Sec-WebSocket-Protocol"));
                }
            } else {
                opts.remove("max-early-data");
                opts.remove("early-data-header-name");
            }
        }
        Ok(opts)
    }
}
fn valid_uuid(uuid: &str) -> bool {
    uuid.len() == 36
        && uuid.chars().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}
/// Whether the structured form can show and save `n` without losing settings.
fn fits_form(n: &Value) -> bool {
    let p = n["type"].as_str().unwrap_or("");
    TYPES.contains(&p)
        && matches!(n["network"].as_str(), None | Some("tcp" | "ws"))
        && match p {
            "tuic" => n["uuid"].is_string() && n.get("token").is_none(),
            "vmess" | "vless" => n["uuid"].as_str().is_some_and(valid_uuid),
            _ => true,
        }
}
pub fn handle(app: &mut App, key: KeyEvent) {
    let Some(form) = app.proxy_form.as_mut() else {
        return;
    };
    if form.submitting {
        return;
    }
    let fields = form.fields();
    let field = fields[form.index];
    if key.code == KeyCode::Char('s') && key.modifiers.contains(KeyModifiers::CONTROL)
        || key.code == KeyCode::Enter && field == Field::Save
    {
        match form.record() {
            Ok(record) => {
                let id = form.edit_id.clone();
                if app.action_busy {
                    return;
                }
                form.submitting = true;
                app.save_source_record(record, id);
            }
            Err(e) => app.set_status(&e, true),
        };
        return;
    }
    if key.code == KeyCode::Esc {
        if form.editing {
            form.editing = false;
        } else {
            app.proxy_form = None;
        }
        return;
    }
    if matches!(key.code, KeyCode::Tab | KeyCode::BackTab)
        || !form.editing && matches!(key.code, KeyCode::Up | KeyCode::Down)
    {
        let back = matches!(key.code, KeyCode::BackTab | KeyCode::Up);
        form.index = (form.index + if back { fields.len() - 1 } else { 1 }) % fields.len();
        form.editing = false;
        return;
    }
    if form.editing {
        if key.code == KeyCode::Enter {
            form.editing = false;
            return;
        }
        if let Some(e) = form.editor(field) {
            match key.code {
                KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => e.clear(),
                KeyCode::Char(c) => {
                    e.insert_text(&c.to_string());
                }
                KeyCode::Backspace => {
                    e.backspace();
                }
                KeyCode::Delete => {
                    e.delete();
                }
                KeyCode::Left => e.move_left(),
                KeyCode::Right => e.move_right(),
                KeyCode::Home => e.move_home(),
                KeyCode::End => e.move_end(),
                _ => {}
            }
        }
        return;
    }
    if matches!(
        key.code,
        KeyCode::Enter | KeyCode::Left | KeyCode::Right | KeyCode::Char(' ')
    ) {
        let back = key.code == KeyCode::Left;
        match field {
            Field::Kind => form.kind = (form.kind + if back { 2 } else { 1 }) % 3,
            Field::Protocol => {
                form.protocol =
                    (form.protocol + if back { TYPES.len() - 1 } else { 1 }) % TYPES.len();
            }
            Field::Tls => form.tls = !form.tls,
            Field::FastOpen => form.fast_open = !form.fast_open,
            // TCP → WebSocket → HTTPUpgrade → TCP.
            Field::Transport => {
                let t = (form.transport() + if back { 2 } else { 1 }) % 3;
                form.ws = t != 0;
                form.upgrade = t == 2;
            }
            _ => form.editing = true,
        }
    }
}
pub fn draw(frame: &mut Frame, app: &App, area: Rect) {
    let Some(f) = &app.proxy_form else {
        return;
    };
    let theme = app.theme();
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .split(area);
    frame.render_widget(
        Paragraph::new(if f.edit_id.is_some() {
            "编辑代理"
        } else {
            "添加代理"
        })
        .style(
            Style::default()
                .fg(theme.accent)
                .add_modifier(Modifier::BOLD),
        ),
        rows[0],
    );
    let fields = f.fields();
    let visible = (rows[1].height as usize / 2).max(1);
    let start = crate::ui::visible_list_start(f.index, fields.len(), visible);
    for (i, field) in fields.iter().enumerate().skip(start).take(visible) {
        use Field::*;
        let (label, value) = match field {
            Kind => (
                "添加方式",
                ["订阅", "单个代理", "导入链接 / 配置"][f.kind].into(),
            ),
            Name => ("名称", f.name.text.clone()),
            Protocol => ("协议", TYPES[f.protocol].to_uppercase()),
            Url => (
                if f.kind == 0 {
                    "订阅 URL"
                } else {
                    "节点链接 / 配置"
                },
                if f.editing && i == f.index {
                    f.url.text.replace('\n', " ")
                } else if f.url.text.is_empty() {
                    String::new()
                } else if f.kind == 0 {
                    crate::mask_url(&f.url.text)
                } else {
                    "已填写".into()
                },
            ),
            Server => ("服务器", f.server.text.clone()),
            Port => ("端口", f.port.text.clone()),
            User => ("用户名（可选）", f.user.text.clone()),
            Secret => (
                if matches!(TYPES[f.protocol], "vmess" | "vless" | "tuic") {
                    "UUID"
                } else {
                    "密码"
                },
                "*".repeat(f.secret.text.chars().count().min(24)),
            ),
            Password => ("密码", "*".repeat(f.password.text.chars().count().min(24))),
            Cipher => ("加密方式", f.cipher.text.clone()),
            Tls => ("TLS", if f.tls { "开启" } else { "关闭" }.into()),
            Sni => ("SNI（可选）", f.sni.text.clone()),
            Transport => (
                l3(app, "传输", "Transport", "トランスポート"),
                ["TCP", "WebSocket", "HTTPUpgrade"][f.transport()].into(),
            ),
            Path => (l3(app, "路径", "Path", "パス"), f.path.text.clone()),
            WsHost => (
                l3(app, "Host 头（可选）", "Host header", "Host ヘッダー"),
                f.ws_host.text.clone(),
            ),
            EarlyData => (
                l3(app, "早期数据（可选）", "Early data", "アーリーデータ"),
                f.early_data.text.clone(),
            ),
            FastOpen => (
                l3(app, "快速打开", "Fast open", "ファストオープン"),
                if f.fast_open {
                    l3(app, "开启", "On", "オン")
                } else {
                    l3(app, "关闭", "Off", "オフ")
                }
                .into(),
            ),
            Flow => ("Flow（可选）", f.flow.text.clone()),
            Save => ("保存并使用", String::new()),
        };
        let selected = i == f.index;
        let style = if selected {
            Style::default()
                .fg(theme.peak)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            Style::default().fg(theme.text)
        };
        let row = Rect::new(
            rows[1].x,
            rows[1].y + ((i - start) * 2) as u16,
            rows[1].width,
            1,
        );
        frame.render_widget(
            Paragraph::new(" ".repeat(row.width as usize)).style(style),
            row,
        );
        let label_width = 20.min(row.width.saturating_sub(8));
        frame.render_widget(
            Paragraph::new(format!("{} {}", if selected { "▶" } else { " " }, label)).style(style),
            Rect::new(row.x, row.y, label_width, 1),
        );
        let value_area = Rect::new(
            row.x + label_width,
            row.y,
            row.width.saturating_sub(label_width),
            1,
        );
        if selected && f.editing {
            if let Some(editor) = f.editor_ref(*field) {
                let chars: Vec<_> = editor
                    .text
                    .chars()
                    .map(|c| {
                        if matches!(field, Secret | Password) {
                            '*'
                        } else if c == '\n' {
                            ' '
                        } else {
                            c
                        }
                    })
                    .collect();
                frame.render_widget(
                    Paragraph::new(ratatui::text::Line::from(crate::ui::editor_line_spans(
                        &chars,
                        editor.cursor,
                        theme,
                        value_area.width as usize,
                    )))
                    .style(style),
                    value_area,
                );
                if let Some(pos) = crate::ui::editor_cursor_cell(&chars, editor.cursor, value_area)
                {
                    frame.set_cursor_position(pos);
                }
            }
        } else {
            let value = if selected && matches!(field, Kind | Protocol | Tls | Transport | FastOpen)
            {
                format!("← {value} →")
            } else {
                value
            };
            frame.render_widget(Paragraph::new(value).style(style), value_area);
        }
    }
    frame.render_widget(
        Paragraph::new(if app.action_busy {
            "正在校验并保存…"
        } else if fields.get(f.index) == Some(&Field::WsHost) && TYPES[f.protocol] == "trojan" {
            // Mihomo's trojan falls back to the server address for SNI, never to Host.
            l3(
                app,
                "节点地址是 IP 或经 CDN 时填写域名；trojan 不会把 Host 用作 SNI，请同时填写 SNI",
                "Fill in the domain when the server is an IP or behind a CDN; trojan never uses Host as SNI, so fill in SNI too",
                "サーバーが IP や CDN 経由の場合はドメインを入力。trojan は Host を SNI に使わないため SNI も入力してください",
            )
        } else if fields.get(f.index) == Some(&Field::WsHost) {
            l3(
                app,
                "节点地址是 IP 或经 CDN 时填写域名；开启 TLS 且未填 SNI 时也用作 SNI",
                "Fill in the domain when the server is an IP or behind a CDN; also used as SNI with TLS and no SNI",
                "サーバーが IP や CDN 経由の場合はドメインを入力。TLS で SNI 未設定なら SNI にも使われます",
            )
        } else {
            "↑↓ / Tab 选择字段   ←→ 切换选项   Enter 编辑\nCtrl+S 保存并使用   Esc 返回"
        })
        .style(Style::default().fg(theme.muted))
        .wrap(Wrap { trim: true }),
        rows[2],
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    fn filled(protocol: usize) -> Form {
        let mut f = Form::default();
        f.kind = 1;
        f.protocol = protocol;
        f.name.load("我的代理");
        f.server.load("192.0.2.1");
        f.secret
            .load(if matches!(TYPES[protocol], "vmess" | "vless" | "tuic") {
                "12345678-1234-1234-1234-123456789abc"
            } else {
                "secret"
            });
        f.password.load("secret");
        f
    }
    #[test]
    fn form_records_validate_and_edit_without_losing_protocol_options() {
        for i in 0..TYPES.len() {
            let f = filled(i);
            let mut record = f.record().unwrap();
            assert_eq!(record.nodes[0]["type"], TYPES[i]);
            record.nodes[0]["udp"] = json!(true);
            let edited = Form::from_record("proxy-001".into(), record.clone())
                .record()
                .unwrap();
            assert_eq!(edited.nodes[0]["udp"], true);
            assert_eq!(edited.nodes[0]["server"], "192.0.2.1");
        }
        let mut f = filled(0);
        f.port.load("65536");
        assert!(f.record().is_err());
        f.port.load("443");
        f.name.clear();
        assert!(f.record().is_err());
        let mut f = filled(2);
        f.secret.load("invalid uuid");
        assert!(f.record().is_err());
        let mut f = Form::default();
        f.name.load("机场 A");
        f.url.load("https://airport.test/sub?token=secret");
        assert_eq!(f.record().unwrap().subscription_url, f.url.text);
    }
    fn pasted(line: &str) -> ProfileSource {
        let mut f = Form {
            kind: 2,
            ..Default::default()
        };
        f.name.load("导入");
        f.url.load(line);
        f.record().unwrap()
    }
    #[test]
    fn imported_sources_keep_their_kind_when_edited() {
        for nodes in [vec![], filled(4).record().unwrap().nodes] {
            let source = ProfileSource {
                name: "原配置".into(),
                kind: "imported".into(),
                nodes: nodes.clone(),
                ..Default::default()
            };
            let mut f = Form::from_record("imported-001".into(), source);
            f.name.load("改名");
            let saved = f.record().unwrap();
            assert_eq!(saved.kind, "imported");
            assert_eq!(saved.name, "改名");
            assert_eq!(saved.nodes.len(), nodes.len());
            // Adding the airport URL makes it refreshable without losing extras.
            f.kind = 0;
            f.url.load("https://airport.test/sub");
            let saved = f.record().unwrap();
            assert_eq!(saved.kind, "subscription");
            assert_eq!(saved.subscription_url, "https://airport.test/sub");
            assert_eq!(saved.nodes, nodes);
        }
    }
    #[test]
    fn edit_keeps_transports_the_form_cannot_show() {
        let record = pasted(
            "vless://12345678-1234-1234-1234-123456789abc@example.com:443\
             ?security=reality&pbk=PK&sid=ab&type=grpc&serviceName=svc#R",
        );
        assert_eq!(record.nodes[0]["network"], "grpc");
        let edited = Form::from_record("proxy-001".into(), record.clone())
            .record()
            .unwrap();
        assert_eq!(edited.nodes[0]["network"], "grpc");
        assert_eq!(edited.nodes[0]["grpc-opts"], record.nodes[0]["grpc-opts"]);
    }
    #[test]
    fn edit_saves_nodes_outside_the_structured_form() {
        for line in [
            "T = tuic, 192.0.2.5, 443, token=abc",
            "vless://not-a-uuid@example.com:443?security=tls#X",
        ] {
            let record = pasted(line);
            let edited = Form::from_record("proxy-001".into(), record.clone())
                .record()
                .unwrap_or_else(|e| panic!("{line}: {e}"));
            assert_eq!(edited.nodes, record.nodes);
        }
        let mut f = Form::from_record(
            "proxy-001".into(),
            ProfileSource {
                name: "T".into(),
                nodes: vec![json!({"name": "T", "type": "tuic", "server": "192.0.2.5",
                    "port": 443, "uuid": "12345678-1234-1234-1234-123456789abc",
                    "password": "pw"})],
                ..Default::default()
            },
        );
        assert_eq!(f.kind, 1);
        f.original.nodes[0]["token"] = json!("stale");
        assert!(f.record().unwrap().nodes[0].get("token").is_none());
    }
    #[test]
    fn edit_keeps_an_explicit_tuic_congestion_controller() {
        let record = pasted(
            "tuic://12345678-1234-1234-1234-123456789abc:pw@192.0.2.5:443?congestion_control=cubic#T",
        );
        assert_eq!(record.nodes[0]["congestion-controller"], "cubic");
        let mut f = Form::from_record("proxy-001".into(), record);
        assert_eq!(f.kind, 1);
        f.name.load("T2");
        let saved = f.record().unwrap();
        assert_eq!(saved.nodes[0]["name"], "T2");
        assert_eq!(saved.nodes[0]["congestion-controller"], "cubic");
        // New or empty values get bbr.
        assert_eq!(
            filled(TYPES.iter().position(|p| *p == "tuic").unwrap())
                .record()
                .unwrap()
                .nodes[0]["congestion-controller"],
            "bbr"
        );
    }
    #[test]
    fn new_nodes_enable_udp_where_mihomo_needs_it() {
        for (i, p) in TYPES.iter().enumerate() {
            let node = &filled(i).record().unwrap().nodes[0];
            match *p {
                "ss" | "trojan" | "vmess" | "vless" | "socks5" => assert_eq!(node["udp"], true),
                "http" => assert!(node.get("udp").is_none()),
                _ => {}
            }
        }
    }
    #[test]
    #[ignore = "requires Mihomo; only validates temporary config files"]
    fn form_protocols_pass_core_validation() {
        let dir = std::env::temp_dir().join(format!("terc-form-{}", std::process::id()));
        let cfg = crate::mihomo::ControllerConfig {
            config_dir: dir.display().to_string(),
            addr: "127.0.0.1:1".into(),
            ..Default::default()
        };
        // vless with WebSocket + Host + early data, and with HTTPUpgrade.
        let mut ws = filled(3);
        ws.ws = true;
        ws.tls = true;
        ws.path.load("/ws");
        ws.ws_host.load("cdn.example");
        ws.early_data.load("2048");
        let mut upgrade = ws.clone();
        upgrade.upgrade = true;
        upgrade.fast_open = true;
        let forms = (0..TYPES.len()).map(filled).chain([ws, upgrade]);
        for (i, form) in forms.enumerate() {
            let record = form.record().unwrap();
            let node = &record.nodes[0];
            let doc=format!("mixed-port: 0\nproxies:\n  - {node}\nproxy-groups:\n  - {{name: PROXY, type: select, include-all: true}}\nrules:\n  - MATCH,PROXY\n");
            crate::mihomo::install_config(&cfg, &doc, false)
                .unwrap_or_else(|e| panic!("{i} {}: {e}", node["type"]));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
    const UUID: &str = "12345678-1234-1234-1234-123456789abc";
    fn ws_record(opts: Value) -> ProfileSource {
        ProfileSource {
            name: "W".into(),
            kind: "proxy".into(),
            nodes: vec![json!({"name": "W", "type": "vmess", "server": "192.0.2.9",
                "port": 443, "uuid": UUID, "alterId": 0, "cipher": "auto", "udp": true,
                "tls": true, "network": "ws", "ws-opts": opts})],
            ..Default::default()
        }
    }
    fn saved_opts(f: &Form) -> Value {
        f.record().unwrap().nodes[0]["ws-opts"].clone()
    }
    #[test]
    fn ws_form_edits_only_the_keys_it_manages() {
        let opts = json!({"path": "/p", "headers": {"Host": "h.example", "User-Agent": "UA"},
            "max-early-data": 2048, "early-data-header-name": "X-Ed", "foo": 1});
        let record = ws_record(opts.clone());
        let mut f = Form::from_record("proxy-001".into(), record.clone());
        assert_eq!(f.kind, 1);
        assert!(f.ws && !f.upgrade && !f.fast_open);
        assert_eq!(f.path.text, "/p");
        assert_eq!(f.ws_host.text, "h.example");
        assert_eq!(f.early_data.text, "2048");
        let fields = f.fields();
        assert!(fields.contains(&Field::EarlyData) && !fields.contains(&Field::FastOpen));
        assert_eq!(f.record().unwrap().nodes, record.nodes);
        f.ws_host.load("new.example");
        let mut want = opts.clone();
        want["headers"]["Host"] = json!("new.example");
        assert_eq!(saved_opts(&f), want);
        f.early_data.clear();
        let mut want = json!({"path": "/p", "foo": 1,
            "headers": {"Host": "new.example", "User-Agent": "UA"}});
        assert_eq!(saved_opts(&f), want);
        f.early_data.load("0");
        assert_eq!(saved_opts(&f), want);
        f.ws_host.clear();
        want["headers"] = json!({"User-Agent": "UA"});
        assert_eq!(saved_opts(&f), want);
        f.path.clear();
        assert_eq!(saved_opts(&f)["path"], "/");

        // A lowercase host key keeps its spelling; clearing it drops `headers`.
        let mut f = Form::from_record(
            "proxy-001".into(),
            ws_record(json!({"path": "/?ed=2048", "headers": {"host": "l.example"}})),
        );
        assert_eq!(f.ws_host.text, "l.example");
        assert!(f.early_data.text.is_empty());
        f.ws_host.load("m.example");
        assert_eq!(
            saved_opts(&f),
            json!({"path": "/?ed=2048", "headers": {"host": "m.example"}})
        );
        f.ws_host.clear();
        f.early_data.load("1024");
        assert_eq!(
            saved_opts(&f),
            json!({"path": "/?ed=2048", "max-early-data": 1024,
                "early-data-header-name": "Sec-WebSocket-Protocol"})
        );
        // ws-opts that is not an object starts over; empty headers stay empty.
        let mut f = Form::from_record("proxy-001".into(), ws_record(json!("odd")));
        assert_eq!(f.path.text, "/");
        f.ws_host.load("n.example");
        assert_eq!(
            saved_opts(&f),
            json!({"path": "/", "headers": {"Host": "n.example"}})
        );
        let f = Form::from_record("proxy-001".into(), ws_record(json!({"headers": {}})));
        assert_eq!(saved_opts(&f), json!({"path": "/", "headers": {}}));

        // Path-based early data (no header name) survives an unrelated edit;
        // a changed size switches to the header.
        let opts = json!({"path": "/ws", "max-early-data": 2048});
        let mut f = Form::from_record("proxy-001".into(), ws_record(opts.clone()));
        f.port.load("8443");
        assert_eq!(saved_opts(&f), opts);
        f.early_data.load("4096");
        assert_eq!(
            saved_opts(&f),
            json!({"path": "/ws", "max-early-data": 4096,
                "early-data-header-name": "Sec-WebSocket-Protocol"})
        );
    }
    #[test]
    fn http_upgrade_mode_saves_mihomo_keys() {
        let opts = json!({"path": "/p", "headers": {"Host": "h.example", "User-Agent": "UA"},
            "max-early-data": 2048, "early-data-header-name": "X-Ed", "foo": 1});
        let mut f = Form::from_record("proxy-001".into(), ws_record(opts));
        f.upgrade = true;
        f.fast_open = true;
        let fields = f.fields();
        assert!(fields.contains(&Field::FastOpen) && !fields.contains(&Field::EarlyData));
        let saved = f.record().unwrap();
        assert_eq!(saved.nodes[0]["network"], "ws");
        assert_eq!(
            saved.nodes[0]["ws-opts"],
            json!({"path": "/p", "headers": {"Host": "h.example", "User-Agent": "UA"},
                "foo": 1, "v2ray-http-upgrade": true, "v2ray-http-upgrade-fast-open": true})
        );
        let mut f = Form::from_record("proxy-001".into(), saved);
        assert!(f.ws && f.upgrade && f.fast_open);
        f.fast_open = false;
        assert!(saved_opts(&f).get("v2ray-http-upgrade-fast-open").is_none());
        f.upgrade = false;
        let opts = saved_opts(&f);
        assert!(opts.get("v2ray-http-upgrade").is_none());
        assert_eq!(opts["foo"], 1);
    }
    #[test]
    fn legacy_httpupgrade_nodes_open_in_the_structured_form() {
        let record = ProfileSource {
            name: "U".into(),
            nodes: vec![json!({"name": "U", "type": "vless", "server": "192.0.2.4",
                "port": 443, "uuid": UUID, "network": "httpupgrade",
                "httpupgrade-opts": {"path": "/up", "host": "u.example"}})],
            ..Default::default()
        };
        let f = Form::from_record("proxy-001".into(), record);
        assert_eq!(f.kind, 1);
        assert!(f.ws && f.upgrade && !f.fast_open);
        assert_eq!(f.path.text, "/up");
        assert_eq!(f.ws_host.text, "u.example");
        let node = &f.record().unwrap().nodes[0];
        assert_eq!(node["network"], "ws");
        assert!(node.get("httpupgrade-opts").is_none());
        assert_eq!(
            node["ws-opts"],
            json!({"path": "/up", "headers": {"Host": "u.example"}, "v2ray-http-upgrade": true})
        );
    }
    #[test]
    fn protocol_switch_keeps_ws_options_and_bad_early_data_fails() {
        let opts = json!({"path": "/p", "headers": {"Host": "h.example", "User-Agent": "UA"},
            "foo": 1});
        let mut f = Form::from_record("proxy-001".into(), ws_record(opts.clone()));
        f.protocol = 3;
        let node = &f.record().unwrap().nodes[0];
        assert_eq!(node["type"], "vless");
        assert_eq!(node["network"], "ws");
        assert_eq!(node["ws-opts"], opts);
        f.protocol = 0;
        assert!(f.record().unwrap().nodes[0].get("ws-opts").is_none());
        f.protocol = 1;
        for bad in ["lots", "-1", "1.5"] {
            f.early_data.load(bad);
            assert!(f.record().unwrap_err().contains("Early data"));
        }
        f.ws = false;
        let node = &f.record().unwrap().nodes[0];
        assert_eq!(node["network"], "tcp");
        assert!(node.get("ws-opts").is_none());
    }
    fn render(app: &crate::App, width: u16) -> String {
        let mut term =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(width, 40)).unwrap();
        term.draw(|frame| draw(frame, app, frame.area())).unwrap();
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
    fn select(app: &mut crate::App, field: Field) {
        let f = app.proxy_form.as_mut().unwrap();
        f.index = f.fields().iter().position(|x| *x == field).unwrap();
    }
    #[test]
    fn transport_rows_render_and_cycle_in_every_language() {
        let mut app = crate::App::from_snapshot(Default::default(), Default::default());
        let opts = json!({"path": "/p", "headers": {"Host": "h.example"}});
        let labels = [
            (
                crate::Lang::Zh,
                [
                    "传输",
                    "路径",
                    "Host头（可选）",
                    "早期数据（可选）",
                    "快速打开",
                    "关闭",
                ],
            ),
            (
                crate::Lang::En,
                [
                    "Transport",
                    "Path",
                    "Hostheader",
                    "Earlydata",
                    "Fastopen",
                    "Off",
                ],
            ),
            (
                crate::Lang::Ja,
                [
                    "トランスポート",
                    "パス",
                    "Hostヘッダー",
                    "アーリーデータ",
                    "ファストオープン",
                    "オフ",
                ],
            ),
        ];
        let hints = [
            "节点地址是IP或经CDN时填写域名",
            "Fillinthedomain",
            "サーバーがIPやCDN経由",
        ];
        for ((lang, [transport, path, host, early, fast, off]), hint) in
            labels.into_iter().zip(hints)
        {
            app.config.settings.lang = lang;
            for width in [80, 120] {
                app.proxy_form = Some(Form::from_record(
                    "proxy-001".into(),
                    ws_record(opts.clone()),
                ));
                select(&mut app, Field::WsHost);
                let view = render(&app, width);
                for text in [
                    transport,
                    path,
                    host,
                    early,
                    "WebSocket",
                    "/p",
                    "h.example",
                    hint,
                ] {
                    assert!(view.contains(text), "{lang:?} {width}: {text}\n{view}");
                }
                assert!(!view.contains(fast));
                // WebSocket → HTTPUpgrade swaps early data for fast open.
                select(&mut app, Field::Transport);
                handle(&mut app, KeyEvent::from(KeyCode::Right));
                let view = render(&app, width);
                for text in [fast, off, "←HTTPUpgrade→"] {
                    assert!(view.contains(text), "{lang:?} {width}: {text}\n{view}");
                }
                assert!(!view.contains(early) && !view.contains(hint));
                select(&mut app, Field::FastOpen);
                handle(&mut app, KeyEvent::from(KeyCode::Enter));
                assert!(app.proxy_form.as_ref().unwrap().fast_open);
                // HTTPUpgrade → TCP → (Left) HTTPUpgrade → WebSocket.
                select(&mut app, Field::Transport);
                handle(&mut app, KeyEvent::from(KeyCode::Right));
                let f = app.proxy_form.as_ref().unwrap();
                assert!(!f.ws && !f.upgrade && !f.fields().contains(&Field::Path));
                handle(&mut app, KeyEvent::from(KeyCode::Left));
                let f = app.proxy_form.as_ref().unwrap();
                assert!(f.ws && f.upgrade);
                handle(&mut app, KeyEvent::from(KeyCode::Left));
                let f = app.proxy_form.as_ref().unwrap();
                assert!(f.ws && !f.upgrade);
            }
        }
    }
    #[test]
    fn trojan_host_hint_asks_for_sni() {
        let mut app = crate::App::from_snapshot(Default::default(), Default::default());
        let mut record = ws_record(json!({"path": "/p", "headers": {"Host": "my.domain"}}));
        record.nodes[0] = json!({"name": "T", "type": "trojan", "server": "192.0.2.9",
            "port": 443, "password": "pw", "udp": true, "network": "ws",
            "ws-opts": {"path": "/p", "headers": {"Host": "my.domain"}}});
        for (lang, hint) in [
            (crate::Lang::Zh, "trojan不会把Host用作SNI"),
            (crate::Lang::En, "trojanneverusesHostasSNI"),
            (crate::Lang::Ja, "trojanはHostをSNIに使わない"),
        ] {
            app.config.settings.lang = lang;
            app.proxy_form = Some(Form::from_record("proxy-001".into(), record.clone()));
            assert_eq!(TYPES[app.proxy_form.as_ref().unwrap().protocol], "trojan");
            select(&mut app, Field::WsHost);
            let view = render(&app, 120);
            assert!(view.contains(hint), "{lang:?}\n{view}");
            assert!(!view.contains("也用作SNI") && !view.contains("alsousedasSNI"));
        }
    }
}
