//! Shell environment output and an opt-in startup block. No system proxy or
//! per-command hook: a new shell asks the selected core for its current ports.
use std::{
    env, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use serde_json::Value;

use crate::{
    mihomo::{self, ControllerConfig},
    ops,
};

const BEGIN: &str = "# >>> terc terminal proxy >>>";
const END: &str = "# <<< terc terminal proxy <<<";
const PROXY_KEYS: &[&str] = &[
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
];
const BYPASS: &str = "localhost,127.0.0.1,::1,.local,.lan,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,100.64.0.0/10,.ts.net";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shell {
    Sh,
    Bash,
    Zsh,
    Fish,
}

impl Shell {
    pub fn parse(name: &str) -> Result<Self, String> {
        match name.rsplit('/').next().unwrap_or(name) {
            "sh" => Ok(Self::Sh),
            "bash" => Ok(Self::Bash),
            "zsh" => Ok(Self::Zsh),
            "fish" => Ok(Self::Fish),
            _ => Err(format!(
                "Unsupported shell {name:?}; use --shell bash, zsh or fish"
            )),
        }
    }
    pub fn current() -> Result<Self, String> {
        Self::parse(&env::var("SHELL").unwrap_or_else(|_| "sh".into()))
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Sh => "sh",
            Self::Bash => "bash",
            Self::Zsh => "zsh",
            Self::Fish => "fish",
        }
    }
    fn quote(self, value: &str) -> String {
        let value = if self == Self::Fish {
            value.replace('\\', "\\\\").replace('\'', "\\'")
        } else {
            value.replace('\'', "'\\''")
        };
        format!("'{value}'")
    }
    pub fn unset(self) -> String {
        if self == Self::Fish {
            PROXY_KEYS
                .iter()
                .map(|key| format!("set -e {key};\n"))
                .collect()
        } else {
            format!("unset {};\n", PROXY_KEYS.join(" "))
        }
    }
}

#[derive(Debug)]
pub struct Environment {
    pub set: Vec<(String, String)>,
    pub unset: Vec<String>,
}

impl Environment {
    pub fn render(&self, shell: Shell) -> String {
        let mut text = String::new();
        for key in &self.unset {
            text.push_str(&if shell == Shell::Fish {
                format!("set -e {key};\n")
            } else {
                format!("unset {key};\n")
            });
        }
        for (key, value) in &self.set {
            let value = shell.quote(value);
            text.push_str(&if shell == Shell::Fish {
                format!("set -gx {key} {value};\n")
            } else {
                format!("export {key}={value};\n")
            });
        }
        text
    }
}

/// An OS cannot listen on port zero. Keep the built-in local bypasses, but
/// don't inherit a broad NO_PROXY while the intended proxy is unavailable.
pub fn unavailable(shell: Shell) -> String {
    Environment {
        set: PROXY_KEYS
            .iter()
            .map(|key| ((*key).into(), "http://127.0.0.1:0".into()))
            .chain(["no_proxy", "NO_PROXY"].map(|key| (key.into(), BYPASS.into())))
            .collect(),
        unset: Vec::new(),
    }
    .render(shell)
}

fn bypass(existing: &[String]) -> String {
    let mut entries: Vec<&str> = Vec::new();
    for item in existing
        .iter()
        .flat_map(|s| s.split(','))
        .chain(BYPASS.split(','))
    {
        let item = item.trim();
        if !item.is_empty() && !entries.contains(&item) {
            entries.push(item);
        }
    }
    entries.join(",")
}

fn from_ports(
    host: &str,
    http: u16,
    socks: u16,
    mixed: u16,
    existing: &[String],
) -> Result<Environment, String> {
    let http = if mixed != 0 { mixed } else { http };
    let socks = if mixed != 0 { mixed } else { socks };
    if http == 0 && socks == 0 {
        return Err("No HTTP, SOCKS or mixed proxy listener is configured".into());
    }
    let mut result = Environment {
        set: Vec::new(),
        unset: Vec::new(),
    };
    let http_url = format!("http://{host}:{http}");
    for key in ["http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"] {
        if http != 0 {
            result.set.push((key.into(), http_url.clone()));
        } else {
            result.unset.push(key.into());
        }
    }
    let all = if socks != 0 {
        format!("socks5h://{host}:{socks}")
    } else {
        http_url
    };
    for key in ["all_proxy", "ALL_PROXY"] {
        result.set.push((key.into(), all.clone()));
    }
    let bypass = bypass(existing);
    for key in ["no_proxy", "NO_PROXY"] {
        result.set.push((key.into(), bypass.clone()));
    }
    Ok(result)
}

/// Only GET /configs: shell startup does not poll connections, scan processes,
/// or invoke system proxy tools. A stopped core keeps its configured endpoint.
pub fn environment(cfg: &ControllerConfig) -> Result<Environment, String> {
    let address = mihomo::controller_socket_addr(&cfg.addr).map_err(|e| e.to_string())?;
    let host = match address.ip() {
        ip if ip.is_unspecified() => "127.0.0.1".into(),
        std::net::IpAddr::V6(ip) => format!("[{ip}]"),
        ip => ip.to_string(),
    };
    let ports = match mihomo::http_request(
        &cfg.addr,
        &cfg.secret,
        "GET",
        "/configs",
        None,
        Duration::from_millis(300),
    ) {
        Ok((200, body)) => {
            let v: Value = serde_json::from_str(&body)
                .map_err(|e| format!("Invalid controller response: {e}"))?;
            let port = |key: &str| {
                v[key]
                    .as_u64()
                    .and_then(|p| u16::try_from(p).ok())
                    .unwrap_or(0)
            };
            (port("port"), port("socks-port"), port("mixed-port"))
        }
        Ok((status, _)) => {
            return Err(format!(
                "Controller returned HTTP {status}; check the selected core and secret"
            ))
        }
        Err(_) => {
            let text = mihomo::read_config_text(cfg)?;
            let chunks = ops::split_chunks(&text);
            let port = |key: &str| {
                chunks
                    .iter()
                    .rev()
                    .find(|c| c.key.as_deref() == Some(key))
                    .and_then(|c| c.lines.first())
                    .and_then(|line| line.split_once(':'))
                    .and_then(|(_, v)| ops::clean_scalar(v).parse::<u16>().ok())
                    .unwrap_or(0)
            };
            (port("port"), port("socks-port"), port("mixed-port"))
        }
    };
    let existing: Vec<String> = ["no_proxy", "NO_PROXY"]
        .iter()
        .filter_map(|key| env::var(key).ok())
        .collect();
    from_ports(&host, ports.0, ports.1, ports.2, &existing)
}

pub struct Integration {
    pub shell: Shell,
    pub files: Vec<PathBuf>,
    cleanup_files: Vec<PathBuf>,
}

impl Integration {
    pub fn current(shell: Shell) -> Result<Self, String> {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or("HOME is not set")?;
        let config_home = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        let zsh_home = env::var_os("ZDOTDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.clone());
        Self::at(shell, &home, &config_home, &zsh_home)
    }
    fn at(shell: Shell, home: &Path, config_home: &Path, zsh_home: &Path) -> Result<Self, String> {
        let files = match shell {
            Shell::Zsh => vec![zsh_home.join(".zshrc")],
            Shell::Fish => vec![config_home.join("fish/config.fish")],
            Shell::Bash => {
                let login = [".bash_profile", ".bash_login", ".profile"].iter().map(|s| home.join(s))
                    .find(|p| p.exists()).unwrap_or_else(|| home.join(".bash_profile"));
                vec![home.join(".bashrc"), login]
            }
            Shell::Sh => return Err("Persistent setup supports bash, zsh and fish; use terc env --shell sh for other POSIX shells".into()),
        };
        let cleanup_files = if shell == Shell::Bash {
            [".bashrc", ".bash_profile", ".bash_login", ".profile"]
                .iter()
                .map(|s| home.join(s))
                .collect()
        } else {
            files.clone()
        };
        Ok(Self {
            shell,
            files,
            cleanup_files,
        })
    }
    pub fn installed(&self) -> bool {
        self.files
            .iter()
            .all(|p| fs::read_to_string(p).is_ok_and(|s| s.contains(BEGIN) && s.contains(END)))
    }
    pub fn install(&self, executable: &Path) -> Result<(), String> {
        let executable = self.shell.quote(&executable.to_string_lossy());
        let unavailable = unavailable(self.shell);
        let command = if self.shell == Shell::Fish {
            format!("if set -l terc_proxy_env ({executable} env --shell fish)\n    printf '%s\\n' $terc_proxy_env | source\nelse\n{unavailable}end")
        } else {
            format!("if terc_proxy_env=$({executable} env --shell {}); then\n    eval \"$terc_proxy_env\"\nelse\n{unavailable}fi\nunset terc_proxy_env", self.shell.name())
        };
        for file in &self.files {
            let original = read_startup(file)?;
            let clean = remove_block(&original)?;
            let updated = format!("{clean}\n{BEGIN}\n{command}\n{END}\n");
            write_startup(file, &original, &updated)?;
        }
        Ok(())
    }
    pub fn uninstall(&self) -> Result<(), String> {
        for file in &self.cleanup_files {
            let original = read_startup(file)?;
            let clean = remove_block(&original)?;
            if clean != original {
                write_startup(file, &original, &clean)?;
            }
        }
        Ok(())
    }
}

fn read_startup(path: &Path) -> Result<String, String> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}
fn write_startup(path: &Path, original: &str, updated: &str) -> Result<(), String> {
    if updated == original {
        return Ok(());
    }
    let write = || -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        if path.exists() {
            let backup = path.with_file_name(format!(
                "{}.terc.bak",
                path.file_name().unwrap().to_string_lossy()
            ));
            if !backup.exists() {
                fs::copy(path, backup)?;
            }
        }
        fs::write(path, updated)
    };
    write().map_err(|e| format!("{}: {e}", path.display()))
}
fn remove_block(text: &str) -> Result<String, String> {
    let mut text = text.to_string();
    while let Some(mut start) = text.find(BEGIN) {
        let end = text[start..]
            .find(END)
            .ok_or("Incomplete terc startup block; repair it before installing or removing")?
            + start
            + END.len();
        let end = end + usize::from(text[end..].starts_with('\n'));
        if start != 0 && text.as_bytes()[start - 1] == b'\n' {
            start -= 1;
        }
        text.replace_range(start..end, "");
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn listener_selection_and_bypass_preserve_user_intent() {
        let e = from_ports(
            "127.0.0.1",
            8080,
            1080,
            7890,
            &["internal.example,.ts.net".into()],
        )
        .unwrap();
        let value = |k| e.set.iter().find(|(key, _)| key == k).unwrap().1.clone();
        assert_eq!(value("HTTPS_PROXY"), "http://127.0.0.1:7890");
        assert_eq!(value("ALL_PROXY"), "socks5h://127.0.0.1:7890");
        assert!(value("NO_PROXY").starts_with("internal.example,.ts.net,"));
        assert_eq!(value("NO_PROXY").matches(".ts.net").count(), 1);
        let e = from_ports("127.0.0.1", 0, 1080, 0, &[]).unwrap();
        assert!(e.unset.contains(&"HTTPS_PROXY".into()));
        assert_eq!(
            e.set[0],
            ("all_proxy".into(), "socks5h://127.0.0.1:1080".into())
        );
        assert!(from_ports("127.0.0.1", 0, 0, 0, &[]).is_err());
    }
    #[test]
    fn shell_output_is_executable_and_cannot_expand_values() {
        let e = Environment {
            set: vec![("http_proxy".into(), "a'b$HOME`echo nope`".into())],
            unset: vec!["ALL_PROXY".into()],
        };
        let script = format!("{}printf '%s' \"$http_proxy\"", e.render(Shell::Sh));
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(script)
            .output()
            .unwrap();
        assert!(out.status.success());
        assert_eq!(String::from_utf8(out.stdout).unwrap(), e.set[0].1);
        assert!(e
            .render(Shell::Fish)
            .contains("set -gx http_proxy 'a\\'b$HOME`echo nope`'"));
        assert!(!Shell::Sh.unset().contains("NO_PROXY"));
        // fish is not installed on every CI host; when available, execute the
        // emitted syntax without reading the operator's startup files.
        let script = format!("{}printf '%s' \"$http_proxy\"", e.render(Shell::Fish));
        match std::process::Command::new("fish")
            .args(["--no-config", "-c", &script])
            .output()
        {
            Ok(out) => {
                assert!(
                    out.status.success(),
                    "{}",
                    String::from_utf8_lossy(&out.stderr)
                );
                assert_eq!(String::from_utf8(out.stdout).unwrap(), e.set[0].1);
            }
            Err(err) => assert_eq!(err.kind(), std::io::ErrorKind::NotFound),
        }
    }
    #[test]
    fn install_is_repeatable_and_uninstall_preserves_startup_content() {
        let home = crate::test_home().join("shell-proxy-roundtrip");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        let original = "export MY_SETTING=keep\n# private settings";
        fs::write(home.join(".zshrc"), original).unwrap();
        let integration = Integration::at(Shell::Zsh, &home, &home.join(".config"), &home).unwrap();
        let exe = Path::new("/home/a user's tools/terc");
        integration.install(exe).unwrap();
        integration.install(exe).unwrap();
        let installed = fs::read_to_string(home.join(".zshrc")).unwrap();
        assert_eq!(installed.matches(BEGIN).count(), 1);
        assert!(installed.contains("env --shell zsh"));
        assert!(integration.installed());
        integration.uninstall().unwrap();
        assert_eq!(fs::read_to_string(home.join(".zshrc")).unwrap(), original);
        assert_eq!(
            fs::read_to_string(home.join(".zshrc.terc.bak")).unwrap(),
            original
        );
        assert!(!integration.installed());
        fs::remove_dir_all(home).unwrap();
    }
    #[test]
    fn bash_covers_login_and_interactive_shells_and_fish_uses_xdg() {
        let home = crate::test_home().join("shell-proxy-layout");
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join(".profile"), "# login\n").unwrap();
        let b =
            Integration::at(Shell::Bash, &home, &home.join("config"), &home.join("zsh")).unwrap();
        assert_eq!(b.files, vec![home.join(".bashrc"), home.join(".profile")]);
        let f = Integration::at(Shell::Fish, &home, &home.join("config"), &home).unwrap();
        assert_eq!(f.files, vec![home.join("config/fish/config.fish")]);
        assert!(remove_block(&format!("mine\n{BEGIN}\nother settings")).is_err());
        fs::remove_dir_all(home).unwrap();
    }

    #[test]
    fn live_ports_win_and_a_stopped_core_keeps_its_disk_endpoint() {
        use std::{
            io::{Read, Write},
            net::TcpListener,
        };
        let home = crate::test_home().join("shell-proxy-core");
        fs::create_dir_all(&home).unwrap();
        fs::write(home.join("config.yaml"), "mixed-port: 47893 # user port\n").unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let cfg = ControllerConfig {
            addr: listener.local_addr().unwrap().to_string(),
            config_dir: home.display().to_string(),
            secret: "test-secret".into(),
            ..ControllerConfig::default()
        };
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0; 4096];
            let n = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);
            assert!(request.starts_with("GET /configs "));
            assert!(request.contains("Authorization: Bearer test-secret"));
            let body = r#"{"mixed-port":37893}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            )
            .unwrap();
        });
        let live = environment(&cfg).unwrap();
        assert!(live.render(Shell::Sh).contains("http://127.0.0.1:37893"));
        server.join().unwrap();
        let offline = environment(&cfg).unwrap();
        assert!(offline.render(Shell::Sh).contains("http://127.0.0.1:47893"));
        assert!(!offline.render(Shell::Sh).contains("unset http_proxy"));
        fs::remove_dir_all(home).unwrap();
    }
}
