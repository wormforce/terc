//! Best-effort desktop notifications.
//!
//! terc deliberately keeps its dependency set small: macOS uses `osascript`
//! and Linux uses `notify-send`. Both are spawned without waiting, and any
//! failure (missing tool, denied permission) is ignored: the in-app toast is
//! still the source of truth.

use std::process::{Command, Stdio};

/// Keep a notification readable in Notification Center.
const MAX_TITLE: usize = 64;
const MAX_BODY: usize = 240;

pub fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('…');
    out
}

#[cfg(target_os = "macos")]
pub fn escape_applescript(text: &str) -> String {
    text.replace('\\', "\\\\").replace('"', "\\\"")
}

/// The command terc would run for this notification, if the platform has a
/// supported backend. Exposed for tests and for `--print-notify-command`.
pub fn command(title: &str, body: &str) -> Option<Command> {
    let title = truncate(title, MAX_TITLE);
    let body = truncate(body, MAX_BODY);
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display notification \"{}\" with title \"{}\"",
            escape_applescript(&body),
            escape_applescript(&title)
        );
        let mut cmd = Command::new("/usr/bin/osascript");
        cmd.arg("-e").arg(script);
        Some(cmd)
    }
    #[cfg(target_os = "linux")]
    {
        let mut cmd = Command::new("notify-send");
        cmd.arg("--app-name=terc").arg(title).arg(body);
        Some(cmd)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (title, body);
        None
    }
}

/// Fire and forget. Returns whether a backend was spawned.
pub fn send(title: &str, body: &str) -> bool {
    let Some(mut cmd) = command(title, body) else {
        return false;
    };
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncates_on_char_boundaries() {
        assert_eq!(truncate("abc", 5), "abc");
        assert_eq!(truncate("abcdef", 4), "abc…");
        assert_eq!(truncate("代理软件", 3), "代理…");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn escapes_applescript_strings() {
        assert_eq!(escape_applescript("a\"b\\c"), "a\\\"b\\\\c");
        let cmd = command("t", "a\"b").unwrap();
        let args: Vec<_> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args[1].contains("a\\\"b"));
    }
}
