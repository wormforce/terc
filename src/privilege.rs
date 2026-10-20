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

fn process_details(pid: u32) -> Result<(u32, String, std::path::PathBuf), String> {
    let output = Command::new("/bin/ps")
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
    let (uid, command) = text
        .trim()
        .split_once(char::is_whitespace)
        .ok_or("Cannot inspect the controller process")?;
    if !output.status.success() {
        return Err("Controller process has exited".into());
    }
    let uid = uid
        .parse()
        .map_err(|_| "Cannot determine controller process owner")?;
    let output = Command::new("/bin/ps")
        .args(["-ww", "-p", &pid.to_string(), "-o", "comm="])
        .output()
        .map_err(|e| e.to_string())?;
    if !output.status.success() {
        return Err("Cannot inspect controller executable".into());
    }
    let executable = std::path::PathBuf::from(String::from_utf8_lossy(&output.stdout).trim());
    Ok((uid, command.trim().to_string(), executable))
}

fn matching_external_command(cfg: &ControllerConfig, executable: &Path, command: &str) -> bool {
    // Hand-started Homebrew Mihomo commonly omits -f; it then loads config.yaml
    // from -d. Do not adopt a process using another configuration file.
    command == format!("{} -d {}", executable.display(), cfg.config_dir)
        || (command.starts_with(&format!("{} ", executable.display()))
            && command.contains(&expected_args(cfg)))
}

fn listener_pid(output: &str) -> Result<u32, String> {
    let mut pids: Vec<u32> = output
        .lines()
        .filter_map(|l| l.strip_prefix('p')?.parse().ok())
        .collect();
    pids.sort_unstable();
    pids.dedup();
    match pids.as_slice() {
        [pid] if *pid > 1 => Ok(*pid),
        _ => Err(
            "无法唯一识别本地控制器进程 / Cannot uniquely identify the local controller process"
                .into(),
        ),
    }
}

pub(crate) fn controller_core(cfg: &ControllerConfig) -> Result<(u32, u32), String> {
    if let Ok(core) = managed_core(cfg) {
        return Ok(core);
    }
    let address: std::net::SocketAddr = cfg
        .addr
        .parse()
        .map_err(|_| "TUN authorization requires a local IP controller address")?;
    if !address.ip().is_loopback() {
        return Err("TUN authorization is only available for a local controller".into());
    }
    let output = Command::new("/usr/sbin/lsof")
        .args([
            "-nP",
            "-a",
            &format!("-iTCP:{}", address.port()),
            "-sTCP:LISTEN",
            "-Fp",
        ])
        .output()
        .map_err(|e| format!("Cannot identify local controller: {e}"))?;
    let pid = listener_pid(&String::from_utf8_lossy(&output.stdout))?;
    let (uid, command, executable) = process_details(pid)?;
    let actual = fs::canonicalize(&executable).map_err(|e| e.to_string())?;
    let mut known = vec![
        std::path::PathBuf::from("/opt/homebrew/bin/mihomo"),
        std::path::PathBuf::from("/usr/local/bin/mihomo"),
    ];
    if let Some(bin) = mihomo::discover_mihomo_binary() {
        known.push(bin);
    }
    if !known
        .iter()
        .any(|p| fs::canonicalize(p).is_ok_and(|p| p == actual))
        || !matching_external_command(cfg, &executable, &command)
    {
        return Err("控制器不属于使用当前配置的已知 Mihomo，未修改任何进程 / Controller executable or configuration does not match; no process changed".into());
    }
    let current_uid = Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .map_err(|e| e.to_string())?;
    let current_uid: u32 = String::from_utf8_lossy(&current_uid.stdout)
        .trim()
        .parse()
        .map_err(|_| "Cannot determine current user")?;
    if uid != 0 && uid != current_uid {
        return Err(
            "The local Mihomo belongs to another user; authorize it through its service manager"
                .into(),
        );
    }
    if uid != 0 {
        let loaded = Command::new("/bin/launchctl")
            .arg("list")
            .output()
            .map_err(|e| e.to_string())?;
        if String::from_utf8_lossy(&loaded.stdout).lines().any(|line| {
            line.split_whitespace()
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                == Some(pid)
        }) {
            return Err("Mihomo 由 launchd/Homebrew 服务管理，请先在服务管理器停止，再在 设置 → 内核与代理 → 内核服务 启动 / Stop the managed service first, then start Mihomo through terc in Settings → Core & Proxy → Core service".into());
        }
    }
    Ok((pid, uid))
}

// Capture and re-check the exact command after the administrator approves.
fn stop_script(pid: u32, expected_command: &str) -> String {
    format!(
        r#"command=$(/bin/ps -ww -p {pid} -o command= 2>/dev/null | /usr/bin/sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' || true)
if [ -n "$command" ]; then
    if [ "$command" != {expected} ]; then
        echo 'Managed core identity changed; no process was stopped' >&2; exit 1
    fi
    /bin/kill -TERM {pid}
    n=0
    while /bin/kill -0 {pid} 2>/dev/null; do
      n=$((n + 1))
      if [ "$n" -ge 50 ]; then echo 'Mihomo did not stop; no replacement was started' >&2; exit 1; fi
      /bin/sleep 0.1
    done
fi
"#,
        expected = quote(expected_command)
    )
}

fn launch_script(cfg: &ControllerConfig, bin: &Path, old_core: Option<(u32, &str)>) -> String {
    let stop = old_core
        .map(|(pid, command)| stop_script(pid, command))
        .unwrap_or_default();
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
        // Darwin nohup can fail with ENXIO inside an authorized AppleScript shell.
        // Ignore HUP in the shell instead; the child inherits it, and all three
        // standard descriptors are detached from the authorization command.
        "set -eu\n{stop}trap '' HUP\n{args} >{log} 2>&1 </dev/null &\necho $! >{pid}\n",
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

pub(crate) fn stop_core(pid: u32) -> Result<(), String> {
    let (_, command, _) = process_details(pid)?;
    // The caller has already verified the managed PID and configuration.
    authorize(&format!("set -eu\n{}", stop_script(pid, &command)))
}

fn restore_pid_record(path: &Path, previous: Option<&[u8]>) -> std::io::Result<()> {
    match previous {
        Some(bytes) => fs::write(path, bytes),
        None => fs::remove_file(path),
    }
}

pub(crate) fn start_core(cfg: &ControllerConfig, old_pid: Option<u32>) -> Result<String, String> {
    if let Some(conflict) = mihomo::macos_tun_route_conflict() {
        return Err(conflict);
    }
    let old_core = old_pid.map(process_details).transpose()?;
    let bin = match &old_core {
        Some((_, _, executable)) => executable.clone(),
        None => mihomo::discover_mihomo_binary().ok_or("Install Mihomo first")?,
    };
    let bin = fs::canonicalize(bin).map_err(|e| e.to_string())?;
    let pid_path = Path::new(&cfg.config_dir).join("terc-core.pid");
    let previous_pid = fs::read(&pid_path).ok();
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
    let old = old_pid.zip(old_core.as_ref().map(|(_, command, _)| command.as_str()));
    if let Err(error) = authorize(&launch_script(cfg, &bin, old)) {
        restore_pid_record(&pid_path, previous_pid.as_deref())
            .map_err(|e| format!("{error}; could not restore PID record: {e}"))?;
        return Err(error);
    }
    let pid: u32 = fs::read_to_string(&pid_path)
        .map_err(|e| e.to_string())?
        .trim()
        .parse()
        .map_err(|_| "Authorized launch did not return a valid core PID")?;
    for _ in 0..30 {
        if process_details(pid).is_err() {
            let _ = fs::remove_file(&pid_path);
            return Err(startup_exit_message(cfg));
        }
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

fn startup_exit_message(cfg: &ControllerConfig) -> String {
    let path = Path::new(&cfg.config_dir).join("terc-core.log");
    let log = fs::read_to_string(&path).unwrap_or_default();
    let lines: Vec<_> = log.lines().collect();
    let tail = lines[lines.len().saturating_sub(8)..].join("\n");
    format!(
        "内核启动后已退出 / Mihomo exited during startup\n{}\n{tail}",
        path.display()
    )
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
        let (pid, uid) = controller_core(cfg)?;
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
                    if process_details(pid).is_ok_and(|(_, command, executable)| {
                        matching_external_command(cfg, &executable, &command)
                    }) {
                        fs::write(mihomo::config_yaml_path(cfg), previous)
                            .map_err(|e| format!("{error}; restoring config failed: {e}"))?;
                    }
                    Err(error)
                }
            };
        }
    }
    if running {
        if cfg!(target_os = "macos") && enable {
            if let Some(conflict) = mihomo::macos_tun_route_conflict() {
                return Err(conflict);
            }
        }
        mihomo::set_tun_enabled(cfg, enable).map_err(|e| {
            if cfg!(target_os = "macos") && managed_core(cfg).is_err() {
                format!("TUN change failed: {e}. 该内核由外部程序管理，请通过原服务授权；或先在原程序停止内核，再在 设置 → 内核与代理 → 内核服务 由 terc 启动 / Authorize the external core through its service manager, or stop it there and start a terc-managed core in Settings → Core & Proxy → Core service.")
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
        let script = launch_script(
            &cfg,
            Path::new("/tmp/a core/mihomo"),
            Some((12345, "/tmp/old mihomo -d /tmp/terc user's config")),
        );
        assert!(script.contains("'/tmp/a core/mihomo'"));
        assert!(script.contains("'a'\\''b;$(touch /tmp/never)'"));
        assert!(
            script.find("Managed core identity changed").unwrap()
                < script.find("trap '' HUP").unwrap()
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
    #[cfg(target_os = "macos")]
    fn background_core_survives_applescript_exit_and_hangup_without_admin() {
        use std::os::unix::fs::PermissionsExt;
        let directory =
            std::env::temp_dir().join(format!("terc-background-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        let gate = directory.join("continue");
        let marker = directory.join("survived");
        let executable = directory.join("fake core");
        let _ = fs::remove_file(&gate);
        let _ = fs::remove_file(&marker);
        // This harmless stand-in accepts the launcher's arguments. It can only
        // complete after AppleScript exits and the test releases its gate.
        fs::write(&executable, format!("#!/bin/sh\nn=0\nwhile [ ! -f {} ]; do n=$((n+1)); [ \"$n\" -lt 100 ] || exit 1; /bin/sleep 0.05; done\nprintf survived >{}\n", quote(&gate.to_string_lossy()), quote(&marker.to_string_lossy()))).unwrap();
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
        let cfg = ControllerConfig {
            config_dir: directory.to_string_lossy().into_owned(),
            ..ControllerConfig::default()
        };
        let output = Command::new("/usr/bin/osascript")
            .arg("-e")
            .arg("on run argv\n do shell script (item 1 of argv)\nend run")
            .arg(launch_script(&cfg, &executable, None))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let pid = fs::read_to_string(directory.join("terc-core.pid")).unwrap();
        let signal = Command::new("/bin/kill")
            .args(["-HUP", pid.trim()])
            .output()
            .unwrap();
        assert!(
            signal.status.success(),
            "Background stand-in exited with its AppleScript parent"
        );
        fs::write(&gate, "continue").unwrap();
        for _ in 0..50 {
            if marker.exists() {
                break;
            }
            thread::sleep(Duration::from_millis(100));
        }
        let result = fs::read_to_string(&marker);
        let log = fs::read_to_string(directory.join("terc-core.log")).unwrap_or_default();
        let _ = fs::remove_dir_all(directory);
        assert_eq!(
            result
                .unwrap_or_else(|_| panic!("Stand-in failed to survive shell exit and HUP: {log}")),
            "survived"
        );
    }

    #[test]
    fn startup_exit_reports_the_real_log_message() {
        let directory =
            std::env::temp_dir().join(format!("terc-start-error-{}", std::process::id()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join("terc-core.log"),
            "nohup: can't detach from console: No such process\n",
        )
        .unwrap();
        let cfg = ControllerConfig {
            config_dir: directory.to_string_lossy().into_owned(),
            ..ControllerConfig::default()
        };
        assert!(startup_exit_message(&cfg).contains("can't detach from console"));
        let _ = fs::remove_dir_all(directory);
    }

    #[test]
    fn hand_started_homebrew_core_and_explicit_config_are_recognized() {
        let cfg = ControllerConfig {
            config_dir: "/opt/homebrew/etc/mihomo".into(),
            ..ControllerConfig::default()
        };
        let exe = Path::new("/opt/homebrew/bin/mihomo");
        assert!(matching_external_command(
            &cfg,
            exe,
            "/opt/homebrew/bin/mihomo -d /opt/homebrew/etc/mihomo"
        ));
        assert!(matching_external_command(&cfg, exe, "/opt/homebrew/bin/mihomo -d /opt/homebrew/etc/mihomo -f /opt/homebrew/etc/mihomo/config.yaml -ext-ctl 127.0.0.1:9090"));
        assert!(!matching_external_command(
            &cfg,
            exe,
            "/opt/homebrew/bin/mihomo -d /opt/homebrew/etc/other"
        ));
        assert!(!matching_external_command(
            &cfg,
            exe,
            "/opt/homebrew/bin/mihomo -f /tmp/other.yaml -d /opt/homebrew/etc/mihomo"
        ));
        assert_eq!(listener_pid("p5402\np5402\n").unwrap(), 5402);
        assert!(listener_pid("p5402\np5403\n").is_err());
    }

    #[test]
    fn cancelled_adoption_removes_new_pid_record_and_preserves_existing_record() {
        let path = std::env::temp_dir().join(format!("terc-pid-rollback-{}", std::process::id()));
        fs::write(&path, "").unwrap();
        restore_pid_record(&path, None).unwrap();
        assert!(!path.exists());
        fs::write(&path, "").unwrap();
        restore_pid_record(&path, Some(b"5402")).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "5402");
        let _ = fs::remove_file(path);
    }

    #[test]
    #[cfg(target_os = "macos")]
    #[ignore = "read-only diagnosis of the live local controller; never authorizes or changes any process"]
    fn discover_matching_live_controller_read_only() {
        let cfg = ControllerConfig::default();
        let (pid, uid) = controller_core(&cfg).unwrap();
        let (actual_uid, command, executable) = process_details(pid).unwrap();
        assert_eq!(uid, actual_uid);
        assert!(matching_external_command(&cfg, &executable, &command));
        eprintln!("Matched live Mihomo controller PID {pid}, UID {uid}; no process or configuration changed");
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
