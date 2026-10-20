//! One add/edit form for subscriptions, individual proxies and pasted links.
use crate::{compose::ProfileSource, App, LineEditor};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    prelude::Frame,
    style::{Modifier, Style},
    widgets::{Paragraph, Wrap},
};
use serde_json::{json, Value};
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
    pub flow: LineEditor,
    pub tls: bool,
    pub ws: bool,
    /// A transport the form cannot edit (grpc, h2, ...), kept until toggled.
    pub kept_network: Option<String>,
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
            flow: Default::default(),
            tls: false,
            ws: false,
            kept_network: None,
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
            if source.nodes.len() == 1
                && TYPES.contains(&source.nodes[0]["type"].as_str().unwrap_or(""))
            {
                f.kind = 1;
                let n = &source.nodes[0];
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
                f.kept_network = n["network"]
                    .as_str()
                    .filter(|net| !matches!(*net, "" | "tcp" | "ws"))
                    .map(str::to_string);
                f.path.load(n["ws-opts"]["path"].as_str().unwrap_or("/"));
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
                    fields.push(Path);
                }
            }
            if p == "vless" {
                fields.push(Flow);
            }
        }
        fields.push(Save);
        fields
    }
    /// The original transport still applies while the protocol is unchanged.
    fn kept_transport(&self) -> Option<&str> {
        let original = self.original.nodes.first()?;
        (original["type"].as_str() == Some(TYPES[self.protocol])).then_some(())?;
        self.kept_network.as_deref()
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
            Flow => &self.flow,
            _ => return None,
        })
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
        result.kind = if self.kind == 0 {
            "subscription"
        } else {
            "proxy"
        }
        .into();
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
            // Keep manually attached nodes while editing an existing subscription.
            if self.original.subscription_url.is_empty() {
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
            if result.nodes.is_empty() {
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
            if matches!(p, "vmess" | "vless" | "tuic") {
                let uuid = self.secret.trimmed();
                if uuid.len() != 36
                    || !uuid.chars().enumerate().all(|(i, c)| {
                        if [8, 13, 18, 23].contains(&i) {
                            c == '-'
                        } else {
                            c.is_ascii_hexdigit()
                        }
                    })
                {
                    return Err("UUID 格式不正确".into());
                }
            }
            let mut n = self
                .original
                .nodes
                .first()
                .filter(|n| n["type"].as_str() == Some(p))
                .cloned()
                .unwrap_or_else(|| json!({}));
            n["name"] = json!(result.name);
            n["type"] = json!(p);
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
                n["congestion-controller"] = json!("bbr");
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
            if matches!(p, "vmess" | "vless" | "trojan") && self.kept_transport().is_none() {
                n["network"] = json!(if self.ws { "ws" } else { "tcp" });
                let obj = n.as_object_mut().unwrap();
                for key in ["grpc-opts", "h2-opts", "http-opts", "xhttp-opts"] {
                    obj.remove(key);
                }
                if self.ws {
                    n["ws-opts"]["path"] = json!(self.path.text);
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
            Field::Transport => {
                // Leaving a kept transport goes to plain TCP first.
                form.ws = form.kept_transport().is_none() && !form.ws;
                form.kept_network = None;
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
                "传输",
                match f.kept_transport() {
                    Some(net) => format!("{net}（保持不变）"),
                    None => if f.ws { "WebSocket" } else { "TCP" }.into(),
                },
            ),
            Path => ("WebSocket 路径", f.path.text.clone()),
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
            let value = if selected && matches!(field, Kind | Protocol | Tls | Transport) {
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
    #[test]
    fn editing_keeps_transports_the_form_cannot_show() {
        let mut record = filled(3).record().unwrap();
        record.nodes[0]["network"] = json!("grpc");
        record.nodes[0]["grpc-opts"] = json!({ "grpc-service-name": "svc" });
        let form = Form::from_record("proxy-001".into(), record.clone());
        assert_eq!(form.kept_network.as_deref(), Some("grpc"));
        assert!(!form.fields().contains(&Field::Path));
        let kept = form.record().unwrap();
        assert_eq!(kept.nodes[0]["network"], "grpc");
        assert_eq!(kept.nodes[0]["grpc-opts"]["grpc-service-name"], "svc");

        let mut other = Form::from_record("proxy-001".into(), record.clone());
        other.protocol = 1;
        assert_eq!(other.kept_transport(), None);
        let other = other.record().unwrap();
        assert_eq!(other.nodes[0]["network"], "tcp");
        assert!(other.nodes[0].get("grpc-opts").is_none());

        let mut ws = Form::from_record("proxy-001".into(), record);
        ws.kept_network = None;
        ws.ws = true;
        let ws = ws.record().unwrap();
        assert_eq!(ws.nodes[0]["network"], "ws");
        assert!(ws.nodes[0].get("grpc-opts").is_none());

        let mut upgrade = ws.clone();
        upgrade.nodes[0]["ws-opts"]["v2ray-http-upgrade"] = json!(true);
        upgrade.nodes[0]["ws-opts"]["headers"] = json!({ "Host": "cdn.example" });
        let edited = Form::from_record("proxy-001".into(), upgrade)
            .record()
            .unwrap();
        assert_eq!(edited.nodes[0]["ws-opts"]["v2ray-http-upgrade"], true);
        assert_eq!(edited.nodes[0]["ws-opts"]["headers"]["Host"], "cdn.example");
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
        for i in 0..TYPES.len() {
            let record = filled(i).record().unwrap();
            let node = &record.nodes[0];
            let doc=format!("mixed-port: 0\nproxies:\n  - {node}\nproxy-groups:\n  - {{name: PROXY, type: select, include-all: true}}\nrules:\n  - MATCH,PROXY\n");
            crate::mihomo::install_config(&cfg, &doc, false)
                .unwrap_or_else(|e| panic!("{}: {e}", TYPES[i]));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
