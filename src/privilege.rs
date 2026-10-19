//! macOS administrator authorization for the managed Mihomo process.
//! The TUI remains an ordinary user process; no persistent helper is installed.
use std::{
    fs,
    path::Path,
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use crate::mihomo::{self, ControllerConfig};

const ADMIN_SCRIPT: &str =
    "on run argv\n do shell script (item 1 of argv) with administrator privileges\nend run";

fn quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

fn expected_args(cfg: &ControllerConfig) -> String {
    format!(
        " -d {} -f {}",
        cfg.config_dir,
        mihomo::config_yaml_path(cfg).display()
    )
}

pub(crate) fn managed_core(cfg: &ControllerConfig) -> Result<(u32, u32), String> {
    let path = Path::new(&cfg.config_dir).join("terc-core.pid");
    let pid: u32 = fs::read_to_string(path)
        .map_err(|_| {
            "This core is managed externally; use its service manager to authorize TUN".to_string()
        })?
        .trim()
        .parse()
        .map_err(|_| "Invalid managed core PID".to_string())?;
    if pid <= 1 {
        return Err("Invalid managed core PID".into());
    }
    let output = Command::new("ps")
        .args([
            "-ww",
            "-p",
            &pid.to_string(),
            "-o",
            "uid=",
            "-o",
            "command=",
        ])
        .output()
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&output.stdout);
    parse_managed_process(pid, output.status.success(), &text, &expected_args(cfg))
}

fn parse_managed_process(
    pid: u32,
    success: bool,
    text: &str,
    expected: &str,
) -> Result<(u32, u32), String> {
    let (uid, command) = text
        .trim()
        .split_once(char::is_whitespace)
        .unwrap_or(("", ""));
    if !success || !command.contains(expected) {
        return Err("Managed core is no longer running; no other process was stopped".into());
    }
    Ok((
        pid,
        uid.parse()
            .map_err(|_| "Cannot determine managed core owner".to_string())?,
    ))
}

// Re-check process identity after the administrator has approved the dialog.
fn stop_script(cfg: &ControllerConfig, pid: u32) -> String {
    format!(
        r#"case "$(/bin/ps -ww -p {pid} -o command= 2>/dev/null || true)" in
  '') ;;
  *{expected}*)
    /bin/kill -TERM {pid}
    n=0
    while /bin/kill -0 {pid} 2>/dev/null; do
      n=$((n + 1))
      if [ "$n" -ge 50 ]; then echo 'Mihomo did not stop; no replacement was started' >&2; exit 1; fi
      /bin/sleep 0.1
    done ;;
  *) echo 'Managed core identity changed; no process was stopped' >&2; exit 1 ;;
esac
"#,
        expected = quote(&expected_args(cfg))
    )
}

fn launch_script(cfg: &ControllerConfig, bin: &Path, old_pid: Option<u32>) -> String {
    let stop = old_pid.map(|pid| stop_script(cfg, pid)).unwrap_or_default();
    let args = [
        bin.to_string_lossy().into_owned(),
        "-d".into(),
        cfg.config_dir.clone(),
        "-f".into(),
        mihomo::config_yaml_path(cfg).to_string_lossy().into_owned(),
        "-ext-ctl".into(),
        cfg.addr.clone(),
        "-secret".into(),
        cfg.secret.clone(),
    ]
    .iter()
    .map(|s| quote(s))
    .collect::<Vec<_>>()
    .join(" ");
    format!(
        "set -eu\n{stop}/usr/bin/nohup {args} >{log} 2>&1 </dev/null &\necho $! >{pid}\n",
        log = quote(
            &Path::new(&cfg.config_dir)
                .join("terc-core.log")
                .to_string_lossy()
        ),
        pid = quote(
            &Path::new(&cfg.config_dir)
                .join("terc-core.pid")
                .to_string_lossy()
        )
    )
}

fn authorize(script: &str) -> Result<(), String> {
    if !cfg!(target_os = "macos") {
        return Err("Administrator authorization is available on macOS".into());
    }
    let output = Command::new("/usr/bin/osascript")
        .arg("-e")
        .arg(ADMIN_SCRIPT)
        .arg(script)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("Cannot request administrator authorization: {e}"))?;
    if output.status.success() {
        return Ok(());
    }
    let error = String::from_utf8_lossy(&output.stderr);
    if error.contains("-128") {
        return Err(
            "管理员授权已取消，内核保持原状 / Authorization cancelled; core unchanged".into(),
        );
    }
    Err(format!("Administrator operation failed: {}", error.trim()))
}

pub(crate) fn stop_core(cfg: &ControllerConfig, pid: u32) -> Result<(), String> {
    authorize(&format!("set -eu\n{}", stop_script(cfg, pid)))
}

pub(crate) fn start_core(cfg: &ControllerConfig, old_pid: Option<u32>) -> Result<String, String> {
    let bin = mihomo::discover_mihomo_binary().ok_or("Install Mihomo first")?;
    let bin = fs::canonicalize(bin).map_err(|e| e.to_string())?;
    // Reserve the database as the ordinary user too: after TUN is disabled,
    // a later non-privileged core must still be able to open its cache.
    for name in ["terc-core.log", "terc-core.pid", "cache.db"] {
        let mut options = fs::OpenOptions::new();
        options.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        options
            .open(Path::new(&cfg.config_dir).join(name))
            .map_err(|e| e.to_string())?;
    }
    authorize(&launch_script(cfg, &bin, old_pid))?;
    for _ in 0..30 {
        if let Some(error) = tun_log_error(cfg, 0) {
            return Err(format!("TUN 启动失败 / TUN startup failed: {error}"));
        }
        if managed_core(cfg).is_ok_and(|(_, uid)| uid == 0) {
            if let Ok(config) = mihomo::read_runtime_config(cfg) {
                if config
                    .pointer("/tun/enable")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                {
                    return Ok(
                        "管理员授权完成，TUN 已开启 / Authorized Mihomo started; TUN enabled"
                            .into(),
                    );
                }
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(format!(
        "Authorized core started, but TUN is not ready; inspect {}",
        Path::new(&cfg.config_dir).join("terc-core.log").display()
    ))
}

pub(crate) fn tun_log_error(cfg: &ControllerConfig, offset: usize) -> Option<String> {
    let bytes = fs::read(Path::new(&cfg.config_dir).join("terc-core.log")).ok()?;
    let recent = bytes.get(offset..).unwrap_or(&bytes);
    String::from_utf8_lossy(recent)
        .lines()
        .rev()
        .find(|line| line.contains("Start TUN listening error"))
        .map(str::to_string)
}

pub(crate) fn set_tun(
    cfg: &ControllerConfig,
    enable: bool,
    running: bool,
) -> Result<String, String> {
    if cfg!(target_os = "macos") && running && enable {
        if let Ok((pid, uid)) = managed_core(cfg) {
            if uid != 0 {
                let previous = mihomo::read_config_text(cfg)?;
                let runtime = mihomo::read_runtime_config(cfg).map_err(|e| e.to_string())?;
                let mut updated = crate::ops::set_nested_bool(&previous, &["tun", "enable"], true);
                if let Some(mode) = runtime.get("mode").and_then(serde_json::Value::as_str) {
                    updated = crate::ops::set_top_scalar(
                        &updated,
                        "mode",
                        &serde_json::to_string(mode).unwrap(),
                    );
                }
                mihomo::install_config(cfg, &updated, false)?;
                return match start_core(cfg, Some(pid)) {
                    Ok(text) => Ok(text),
                    Err(error) => {
                        // On cancelled authorization the old process is untouched.
                        if managed_core(cfg).is_ok_and(|(current, _)| current == pid) {
                            fs::write(mihomo::config_yaml_path(cfg), previous)
                                .map_err(|e| format!("{error}; restoring config failed: {e}"))?;
                        }
                        Err(error)
                    }
                };
            }
        }
    }
    if running {
        mihomo::set_tun_enabled(cfg, enable).map_err(|e| {
            if cfg!(target_os = "macos") && managed_core(cfg).is_err() {
                format!("TUN change failed: {e}. 该内核由外部程序管理，请通过原服务授权；或先在原程序停止内核，再按 K 由 terc 启动 / Authorize the external core through its service manager, or stop it there and press K to start a terc-managed core.")
            } else { format!("TUN change failed: {e}") }
        })?;
    }
    mihomo::persist_nested_bool(cfg, &["tun", "enable"], enable)?;
    Ok(if !running {
        "TUN 配置已保存，启动内核时生效 / Saved; takes effect at core startup"
    } else if enable {
        "TUN 已开启 / TUN enabled"
    } else {
        "TUN 已关闭 / TUN disabled"
    }
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn admin_script_quotes_arguments_and_checks_identity_before_stopping() {
        let cfg = ControllerConfig {
            config_dir: "/tmp/terc user's config".into(),
            secret: "a'b;$(touch /tmp/never)".into(),
            ..ControllerConfig::default()
        };
        let script = launch_script(&cfg, Path::new("/tmp/a core/mihomo"), Some(12345));
        assert!(script.contains("'/tmp/a core/mihomo'"));
        assert!(script.contains("'a'\\''b;$(touch /tmp/never)'"));
        assert!(
            script.find("Managed core identity changed").unwrap()
                < script.find("/usr/bin/nohup").unwrap()
        );
        // Parse only: never execute the authorization or launch script in tests.
        let mut child = Command::new("/bin/sh")
            .arg("-n")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        child
            .stdin
            .take()
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success());
    }
    #[test]
    fn tun_errors_are_read_only_from_this_operation() {
        let directory = std::env::temp_dir().join(format!("terc-tun-log-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let cfg = ControllerConfig {
            config_dir: directory.to_string_lossy().into_owned(),
            ..ControllerConfig::default()
        };
        let log = directory.join("terc-core.log");
        let old = "error Start TUN listening error: old permission error\n";
        fs::write(&log, old).unwrap();
        assert!(tun_log_error(&cfg, old.len()).is_none());
        fs::write(
            &log,
            format!("{old}error Start TUN listening error: new failure\n"),
        )
        .unwrap();
        assert!(tun_log_error(&cfg, old.len())
            .unwrap()
            .contains("new failure"));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    #[cfg(target_os = "macos")]
    fn administrator_applescript_compiles_without_running_it() {
        let target =
            std::env::temp_dir().join(format!("terc-authorization-{}.scpt", std::process::id()));
        let output = Command::new("/usr/bin/osacompile")
            .arg("-o")
            .arg(&target)
            .arg("-e")
            .arg(ADMIN_SCRIPT)
            .output()
            .unwrap();
        let _ = fs::remove_file(target);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn managed_process_owner_and_arguments_must_match() {
        assert_eq!(
            parse_managed_process(
                42,
                true,
                "  0 /bin/mihomo -d /tmp/a -f /tmp/a/config.yaml",
                " -d /tmp/a -f /tmp/a/config.yaml"
            )
            .unwrap(),
            (42, 0)
        );
        assert!(parse_managed_process(
            42,
            true,
            "501 /bin/unrelated",
            " -d /tmp/a -f /tmp/a/config.yaml"
        )
        .is_err());
        assert!(parse_managed_process(42, false, "", " -d /tmp/a").is_err());
    }
}
