//! Non-interactive entry points for scripts and agents.
//!
//! `terc` with no arguments still opens the TUI. Everything below talks to the
//! controller directly and never sends keys to a running TUI. Read-only
//! commands are safe by default; `sysproxy on` requires an explicit `--yes`
//! because it changes how the whole machine reaches the network.

use std::{
    sync::mpsc,
    time::{Duration, Instant},
};

use serde_json::{json, Value};

use crate::{
    mihomo::{self, BackendEvent, CoreSnapshot, Fetch},
    ops, Config, LoadIssue,
};

const USAGE: &str = "\
terc — Mihomo controller (TUI by default)

Usage:
  terc                         open the TUI
  terc status  [--json]        core, mode, ports, system proxy, TUN
  terc proxies [--json]        policy groups and their current node
  terc conns   [--json] [--limit N] [--grep TEXT]
  terc use <group> <node> [--pin] [--json]
  terc mode <rule|global|direct> [--json]
  terc test <group> [--json]   concurrent delay test for a group
  terc dns <name> [--type A] [--json]
  terc explain <target> [--json]
  terc sysproxy on|off [--yes] [--json]
  terc notify-test [--json]    verify desktop notifications
  terc help

Read-only by default. `sysproxy on` needs --yes. JSON is compact for tools.
";

pub fn dispatch(args: &[String]) -> Option<i32> {
    let command = args.first()?;
    if matches!(command.as_str(), "--help" | "-h") {
        print!("{USAGE}");
        return Some(0);
    }
    if command.starts_with('-') {
        print!("{USAGE}");
        return Some(2);
    }
    let rest = &args[1..];
    let json = rest.iter().any(|arg| arg == "--json");
    let code = match command.as_str() {
        "status" => status(json),
        "proxies" => proxies(json),
        "conns" => conns(rest, json),
        "use" => use_node(rest, json),
        "mode" => mode(rest, json),
        "test" => test(rest, json),
        "dns" => dns(rest, json),
        "explain" => explain(rest, json),
        "sysproxy" => sysproxy(rest, json),
        "notify-test" => notify_test(json),
        "help" | "?" => {
            print!("{USAGE}");
            0
        }
        other => {
            eprintln!("terc: unknown command `{other}`\n");
            print!("{USAGE}");
            2
        }
    };
    Some(code)
}

fn load_config() -> Result<Config, String> {
    let (config, issue) = Config::load();
    match issue {
        Some(LoadIssue::Unusable(err)) => Err(err),
        Some(LoadIssue::Unsaved(err)) => {
            eprintln!("terc: warning: {err}");
            Ok(config)
        }
        None => Ok(config),
    }
}

fn snapshot(config: &Config) -> CoreSnapshot {
    mihomo::fetch_snapshot(&config.controller)
}

fn print_json(value: &Value) {
    println!("{value}");
}

fn usage_error(message: &str) -> i32 {
    eprintln!("terc: {message}\n");
    print!("{USAGE}");
    2
}

fn status(json: bool) -> i32 {
    let Ok(config) = load_config() else {
        return 1;
    };
    let snap = snapshot(&config);
    let value = json!({
        "running": snap.running,
        "version": snap.version,
        "mode": snap.mode,
        "http_port": snap.http_port,
        "socks_port": snap.socks_port,
        "mixed_port": snap.mixed_port,
        "sysproxy": snap.sysproxy_enabled,
        "tun": snap.tun_enabled,
        "connections": snap.connections.len(),
        "upload_total": snap.upload_total,
        "download_total": snap.download_total,
        "controller": config.controller.addr,
        "config_dir": config.controller.config_dir,
    });
    if json {
        print_json(&value);
    } else {
        println!(
            "core      {}  {}",
            if snap.running { "running" } else { "stopped" },
            snap.version
        );
        println!("mode      {}", snap.mode);
        println!(
            "ports     http {}  socks {}  mixed {}",
            snap.http_port, snap.socks_port, snap.mixed_port
        );
        println!(
            "sysproxy  {}",
            if snap.sysproxy_enabled { "on" } else { "off" }
        );
        println!("tun       {}", if snap.tun_enabled { "on" } else { "off" });
        println!("conns     {}", snap.connections.len());
        println!(
            "traffic   ↑ {}  ↓ {}",
            snap.upload_total, snap.download_total
        );
    }
    if snap.running {
        0
    } else {
        1
    }
}

fn proxies(json: bool) -> i32 {
    let Ok(config) = load_config() else {
        return 1;
    };
    let snap = snapshot(&config);
    let rows: Vec<Value> = snap
        .groups
        .iter()
        .map(|group| {
            json!({
                "name": group.name,
                "kind": group.kind,
                "now": group.now,
                "fixed": group.fixed,
                "nodes": group.all.len(),
                "test_url": group.test_url,
            })
        })
        .collect();
    if json {
        print_json(&json!({ "groups": rows }));
    } else {
        for group in &snap.groups {
            let now = if group.now.is_empty() {
                &group.fixed
            } else {
                &group.now
            };
            println!(
                "{:<24} {:<10} {:<28} {} nodes{}",
                group.name,
                group.kind,
                now,
                group.all.len(),
                if group.fixed.is_empty() {
                    ""
                } else {
                    " (pinned)"
                }
            );
        }
    }
    0
}

fn conns(args: &[String], json: bool) -> i32 {
    let Ok(config) = load_config() else {
        return 1;
    };
    let limit = flag_value(args, "--limit")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(20);
    let grep = flag_value(args, "--grep").map(|v| v.to_lowercase());
    let snap = snapshot(&config);
    let mut rows: Vec<_> = snap
        .connections
        .iter()
        .filter(|conn| {
            let Some(grep) = &grep else {
                return true;
            };
            [
                &conn.host,
                &conn.sniff_host,
                &conn.process,
                &conn.rule,
                &conn.chains,
            ]
            .iter()
            .any(|value| value.to_lowercase().contains(grep))
        })
        .take(limit)
        .collect();
    rows.sort_by(|a, b| (b.upload + b.download).cmp(&(a.upload + a.download)));
    if json {
        let value: Vec<Value> = rows
            .iter()
            .map(|conn| {
                json!({
                    "host": if conn.sniff_host.is_empty() { &conn.host } else { &conn.sniff_host },
                    "process": conn.process,
                    "rule": conn.rule,
                    "payload": conn.rule_payload,
                    "chains": conn.chains,
                    "upload": conn.upload,
                    "download": conn.download,
                    "up_rate": conn.up_rate,
                    "down_rate": conn.down_rate,
                })
            })
            .collect();
        print_json(&json!({ "connections": value }));
    } else {
        for conn in rows {
            let host = if conn.sniff_host.is_empty() {
                &conn.host
            } else {
                &conn.sniff_host
            };
            println!(
                "{host:<40} {:<20} ↑{:<10} ↓{:<10} {}",
                conn.process, conn.upload, conn.download, conn.chains
            );
        }
    }
    0
}

fn use_node(args: &[String], json: bool) -> i32 {
    let positional: Vec<&str> = args
        .iter()
        .filter(|arg| !arg.starts_with("--"))
        .map(String::as_str)
        .collect();
    if positional.len() < 2 {
        return usage_error("use needs <group> <node>");
    }
    let Ok(config) = load_config() else {
        return 1;
    };
    let pin = args.iter().any(|arg| arg == "--pin");
    match mihomo::select_group_node(&config.controller, positional[0], positional[1], pin) {
        Ok(()) => {
            if json {
                print_json(&json!({
                    "ok": true,
                    "group": positional[0],
                    "node": positional[1],
                    "pinned": pin,
                }));
            } else {
                println!("{} → {}", positional[0], positional[1]);
            }
            0
        }
        Err(err) => {
            eprintln!("terc: {err}");
            1
        }
    }
}

fn mode(args: &[String], json: bool) -> i32 {
    let Some(mode) = args.iter().find(|arg| !arg.starts_with("--")) else {
        return usage_error("mode needs rule, global or direct");
    };
    let normalized = match mode.to_lowercase().as_str() {
        "rule" => "Rule",
        "global" => "Global",
        "direct" => "Direct",
        _ => return usage_error("mode must be rule, global or direct"),
    };
    let Ok(config) = load_config() else {
        return 1;
    };
    match mihomo::switch_routing_mode(&config.controller, normalized) {
        Ok(()) => {
            if json {
                print_json(&json!({ "ok": true, "mode": normalized }));
            } else {
                println!("mode {normalized}");
            }
            0
        }
        Err(err) => {
            eprintln!("terc: {err}");
            1
        }
    }
}

fn test(args: &[String], json: bool) -> i32 {
    let Some(group) = args.iter().find(|arg| !arg.starts_with("--")) else {
        return usage_error("test needs a group name");
    };
    let Ok(config) = load_config() else {
        return 1;
    };
    let snap = snapshot(&config);
    let Some(found) = snap.groups.iter().find(|item| item.name == *group) else {
        eprintln!("terc: no such group: {group}");
        return 1;
    };
    let (tx, rx) = mpsc::channel();
    mihomo::test_group_delays_async(
        config.controller.clone(),
        found.name.clone(),
        found.all.clone(),
        snap.groups.clone(),
        tx,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut delays: Vec<(String, Option<u16>)> = Vec::new();
    while Instant::now() < deadline {
        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(BackendEvent::DelayResult { node, delay, .. }) => delays.push((node, delay)),
            Ok(BackendEvent::GroupTestDone { .. }) => break,
            Ok(_) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    if json {
        let rows: Vec<Value> = delays
            .iter()
            .map(|(node, delay)| json!({ "node": node, "delay_ms": delay }))
            .collect();
        print_json(&json!({ "group": group, "results": rows }));
    } else {
        for (node, delay) in &delays {
            match delay {
                Some(ms) => println!("{node:<40} {ms} ms"),
                None => println!("{node:<40} timeout"),
            }
        }
    }
    0
}

fn dns(args: &[String], json: bool) -> i32 {
    let Some(name) = args.iter().find(|arg| !arg.starts_with("--")) else {
        return usage_error("dns needs a name");
    };
    let qtype = flag_value(args, "--type").unwrap_or("A");
    let Ok(config) = load_config() else {
        return 1;
    };
    match mihomo::query_dns(&config.controller, name, qtype) {
        Ok(message) => {
            if json {
                let answers: Vec<Value> = message
                    .answers
                    .iter()
                    .map(|answer| {
                        json!({ "type": answer.qtype, "ttl": answer.ttl, "data": answer.data })
                    })
                    .collect();
                print_json(
                    &json!({ "name": name, "qtype": qtype, "status": message.status, "answers": answers }),
                );
            } else {
                for answer in &message.answers {
                    println!("{:<6} {:<40} {}s", answer.qtype, answer.data, answer.ttl);
                }
                if message.answers.is_empty() {
                    println!("no answer  rcode {}", message.status);
                }
            }
            0
        }
        Err(err) => {
            eprintln!("terc: {err}");
            1
        }
    }
}

fn explain(args: &[String], json: bool) -> i32 {
    let Some(target) = args.iter().find(|arg| !arg.starts_with("--")) else {
        return usage_error("explain needs a target (host, URL or process:name)");
    };
    let Ok(config) = load_config() else {
        return 1;
    };
    let snap = mihomo::fetch_snapshot_with(
        &config.controller,
        Fetch {
            connections: false,
            rules: true,
            providers: false,
            cached_host: false,
        },
    );
    let report = ops::explain_rules(&snap.rules, target);
    if json {
        let matched = report.matched.as_ref().map(|step| {
            json!({
                "index": step.index + 1,
                "kind": step.kind,
                "payload": step.payload,
                "proxy": step.proxy,
                "reason": step.reason,
            })
        });
        let skipped: Vec<Value> = report
            .uncertain
            .iter()
            .map(|step| {
                json!({
                    "index": step.index + 1,
                    "kind": step.kind,
                    "payload": step.payload,
                    "reason": step.reason,
                })
            })
            .collect();
        print_json(&json!({
            "target": report.target,
            "host": report.host,
            "matched": matched,
            "partial": report.partial,
            "skipped": skipped,
        }));
    } else if let Some(step) = &report.matched {
        println!(
            "MATCH  #{}  {}  {}  →  {}",
            step.index + 1,
            step.kind,
            step.payload,
            step.proxy
        );
        if report.partial {
            println!("note   earlier GEOSITE / rule-set rules still run in the core");
        }
        for skipped in report.uncertain.iter().take(5) {
            println!(
                "skip   #{}  {}  {}  — {}",
                skipped.index + 1,
                skipped.kind,
                skipped.payload,
                skipped.reason
            );
        }
    } else {
        println!("no match  {}", report.target);
    }
    0
}

fn sysproxy(args: &[String], json: bool) -> i32 {
    let Some(action) = args.iter().find(|arg| !arg.starts_with("--")) else {
        return usage_error("sysproxy needs on or off");
    };
    let enable = match action.as_str() {
        "on" => true,
        "off" => false,
        _ => return usage_error("sysproxy takes on or off"),
    };
    if enable && !args.iter().any(|arg| arg == "--yes") {
        eprintln!("terc: enabling the system proxy changes the whole machine; pass --yes");
        return 2;
    }
    let Ok(config) = load_config() else {
        return 1;
    };
    let snap = snapshot(&config);
    let (http, socks) = if enable {
        match mihomo::proxy_ports(&snap) {
            Ok(ports) => ports,
            Err(err) => {
                eprintln!("terc: {err}");
                return 1;
            }
        }
    } else {
        (0, 0)
    };
    match mihomo::set_sysproxy(enable, http, socks) {
        Ok(message) => {
            if json {
                print_json(&json!({ "ok": true, "enabled": enable, "message": message }));
            } else {
                println!("{message}");
            }
            0
        }
        Err(err) => {
            eprintln!("terc: {err}");
            1
        }
    }
}

fn notify_test(json: bool) -> i32 {
    let sent = crate::notify::send("terc", "CLI notification test");
    if json {
        print_json(&json!({ "ok": sent }));
    } else if sent {
        println!("notification sent");
    } else {
        eprintln!("terc: no notification backend on this platform");
    }
    if sent {
        0
    } else {
        1
    }
}

fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    args.iter()
        .position(|arg| arg == flag)
        .and_then(|index| args.get(index + 1))
        .map(String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_args_keep_the_tui() {
        assert!(dispatch(&[]).is_none());
    }

    #[test]
    fn unknown_commands_are_usage_errors_not_the_tui() {
        assert_eq!(dispatch(&["nope".into()]), Some(2));
        assert_eq!(dispatch(&["--nope".into()]), Some(2));
    }

    #[test]
    fn flag_values_are_read_in_order() {
        let args = vec!["--limit".to_string(), "5".into(), "--json".into()];
        assert_eq!(flag_value(&args, "--limit"), Some("5"));
        assert_eq!(flag_value(&args, "--missing"), None);
    }
}
