//! Connection insight: age, per-connection rates, AI tags and a ring of closed long-lived sessions.
//!
//! Mihomo reports no close reason; causes are inferred from terc's own actions.

use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{mihomo::ConnectionItem, Lang};

/// A connection older than this counts as long-lived.
pub const LONG_SECS: i64 = 60;
/// An AI connection that ends on its own sooner than this was an ordinary
/// request (a page load, a finished keep-alive), not a broken session.
const AI_SESSION_SECS: i64 = 10;
const CLOSED_CAP: usize = 50;
/// How long a cause still applies after the action behind it finished.
const CAUSE_GRACE: Duration = Duration::from_secs(6);
/// Safety cap for a cause whose action never reported back.
const CAUSE_MAX: Duration = Duration::from_secs(120);
/// `Snapshot` and `SnapshotDone` can arrive back to back; diffs closer than
/// this would turn into wild rates.
const MIN_RATE_DT: Duration = Duration::from_millis(500);

/// Parses Go's RFC 3339 (`time.RFC3339Nano`) into unix milliseconds.
pub fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let num = |from: usize, len: usize| -> Option<i64> {
        let mut value = 0;
        for &c in b.get(from..from + len)? {
            if !c.is_ascii_digit() {
                return None;
            }
            value = value * 10 + i64::from(c - b'0');
        }
        Some(value)
    };
    if b.len() < 20
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't')
        || b[13] != b':'
        || b[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (num(0, 4)?, num(5, 2)?, num(8, 2)?);
    let (hour, min, sec) = (num(11, 2)?, num(14, 2)?, num(17, 2)?);
    if !(1..=12).contains(&month)
        || day < 1
        || day > days_in_month(year, month)
        || hour > 23
        || min > 59
        || sec > 60
    {
        return None;
    }
    let mut i = 19;
    let mut ms = 0;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            if i - start < 3 {
                ms = ms * 10 + i64::from(b[i] - b'0');
            }
            i += 1;
        }
        let digits = i - start;
        if digits == 0 || digits > 9 {
            return None;
        }
        for _ in digits..3 {
            ms *= 10;
        }
    }
    let offset_min = match *b.get(i)? {
        b'Z' | b'z' => {
            i += 1;
            0
        }
        sign @ (b'+' | b'-') => {
            if b.get(i + 3) != Some(&b':') {
                return None;
            }
            let (oh, om) = (num(i + 1, 2)?, num(i + 4, 2)?);
            if oh > 23 || om > 59 {
                return None;
            }
            i += 6;
            if sign == b'-' {
                -(oh * 60 + om)
            } else {
                oh * 60 + om
            }
        }
        _ => return None,
    };
    if i != b.len() {
        return None;
    }
    // A leap second is folded into :59 rather than rolling the minute over.
    let secs = days_from_civil(year, month, day) * 86_400 + hour * 3600 + min * 60 + sec.min(59)
        - offset_min * 60;
    Some(secs * 1000 + ms)
}

fn days_in_month(year: i64, month: i64) -> i64 {
    match month {
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * ((month + 9) % 12) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// Whole seconds since `start_ms`; `None` for a missing or Go zero time.
pub fn age_secs(start_ms: Option<i64>, now_ms: i64) -> Option<i64> {
    let start = start_ms.filter(|&ms| ms > 0)?;
    Some((now_ms - start).max(0) / 1000)
}

/// `42s`, `5m07s`, `1h02m`, `3d04h`: at most six ASCII cells below 100 days.
pub fn fmt_age(secs: i64) -> String {
    let s = secs.max(0);
    match s {
        0..=59 => format!("{s}s"),
        60..=3599 => format!("{}m{:02}s", s / 60, s % 60),
        3600..=86_399 => format!("{}h{:02}m", s / 3600, s % 3600 / 60),
        _ if s < 100 * 86_400 => format!("{}d{:02}h", s / 86_400, s % 86_400 / 3600),
        _ => format!("{}d", s / 86_400),
    }
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// `host:port`, `[v6]:port` or a bare host, without the port and trailing dot.
pub fn host_only(target: &str) -> &str {
    let host = if let Some(rest) = target.strip_prefix('[') {
        rest.split_once(']').map_or(rest, |(host, _)| host)
    } else {
        match target.rsplit_once(':') {
            Some((host, _)) if !host.contains(':') => host,
            _ => target,
        }
    };
    host.trim_end_matches('.')
}

/// Matches the domain rules of `compose::AI_PRESET`, ignoring case.
/// The preset values are lowercase (checked by a test).
pub fn is_ai_host(host: &str) -> bool {
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        return false;
    }
    let host = host.to_ascii_lowercase();
    crate::compose::AI_PRESET
        .iter()
        .flat_map(|(_, rules)| rules.iter())
        .any(|rule| match rule.split_once(',') {
            Some(("DOMAIN", value)) => host == value,
            Some(("DOMAIN-SUFFIX", value)) => {
                host == value
                    || host
                        .strip_suffix(value)
                        .is_some_and(|rest| rest.ends_with('.'))
            }
            Some(("DOMAIN-KEYWORD", value)) => host.contains(value),
            _ => false,
        })
}

/// AI by destination, sniffed host, or by passing through terc's `AI` group.
pub fn is_ai(item: &ConnectionItem) -> bool {
    is_ai_host(host_only(&item.host))
        || is_ai_host(host_only(&item.sniff_host))
        || item.chains.split(" › ").any(|group| group == "AI")
}

/// A session is what an AI agent's stream looks like to the proxy: an AI
/// destination or a connection that has been open for a while.
pub fn is_session(item: &ConnectionItem, now_ms: i64) -> bool {
    item.ai || age_secs(item.start_ms, now_ms).is_some_and(|age| age >= LONG_SECS)
}

/// Sessions an action would cut; for confirming such actions (not wired yet).
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Affected {
    pub sessions: usize,
    pub ai: usize,
}

#[allow(dead_code)]
pub fn count_sessions<'a>(it: impl Iterator<Item = &'a ConnectionItem>, now_ms: i64) -> Affected {
    let mut out = Affected::default();
    for item in it.filter(|item| is_session(item, now_ms)) {
        out.sessions += 1;
        out.ai += usize::from(item.ai);
    }
    out
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SortKey {
    #[default]
    Bytes,
    Age,
    Rate,
}

impl SortKey {
    pub fn next(self) -> Self {
        match self {
            Self::Bytes => Self::Age,
            Self::Age => Self::Rate,
            Self::Rate => Self::Bytes,
        }
    }

    /// The `App::t` key of the label.
    pub fn key(self) -> &'static str {
        match self {
            Self::Bytes => "conn_sort_bytes",
            Self::Age => "conn_sort_age",
            Self::Rate => "conn_sort_rate",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cause {
    UserClose,
    CloseAll,
    CoreStopped,
    /// A config reload re-initialises proxy providers and drops their connections.
    Reload,
    Tun,
}

impl Cause {
    pub fn label(self, lang: Lang) -> &'static str {
        match (self, lang) {
            (Self::UserClose, Lang::Zh) => "在 terc 中断开",
            (Self::UserClose, Lang::En) => "closed in terc",
            (Self::UserClose, Lang::Ja) => "terc で切断",
            (Self::CloseAll, Lang::Zh) => "terc 全部断开",
            (Self::CloseAll, Lang::En) => "closed all in terc",
            (Self::CloseAll, Lang::Ja) => "terc で全切断",
            (Self::CoreStopped, Lang::Zh) => "内核已停止或重启",
            (Self::CoreStopped, Lang::En) => "core stopped or restarted",
            (Self::CoreStopped, Lang::Ja) => "コア停止または再起動",
            (Self::Reload, Lang::Zh) => "配置重载（订阅提供者节点）",
            (Self::Reload, Lang::En) => "config reload (proxy-provider node)",
            (Self::Reload, Lang::Ja) => "設定リロード（プロバイダーノード）",
            (Self::Tun, Lang::Zh) => "TUN 重建",
            (Self::Tun, Lang::En) => "TUN rebuilt",
            (Self::Tun, Lang::Ja) => "TUN 再構築",
        }
    }
}

pub fn unknown_label(lang: Lang) -> &'static str {
    match lang {
        Lang::Zh => "应用或远端关闭",
        Lang::En => "closed by the app or remote",
        Lang::Ja => "アプリまたは相手側が切断",
    }
}

pub fn bulk_label(n: usize, lang: Lang) -> String {
    match lang {
        Lang::Zh => format!("同时断开 {n} 条（网络切换、睡眠或节点故障？）"),
        Lang::En => format!("{n} closed at once (network change, sleep or node failure?)"),
        Lang::Ja => format!("{n} 件同時に切断（ネットワーク切替・スリープ・ノード障害？）"),
    }
}

/// Which closing connections a cause is given to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scope {
    All,
    Id(String),
    /// Through a `proxy-providers:` node: a reload re-initialises those.
    Providers,
    /// Entered through TUN: a TUN rebuild closes those.
    TunInbound,
}

#[derive(Clone, Debug)]
pub struct ClosedConn {
    pub host: String,
    pub process: String,
    pub chains: String,
    pub provider: String,
    pub ai: bool,
    pub lifetime_secs: Option<i64>,
    pub upload: u64,
    pub download: u64,
    pub closed_ms: i64,
    pub cause: Option<Cause>,
    /// Uncaused sessions that closed in the same observation (0 below 3).
    pub bulk: usize,
}

impl ClosedConn {
    /// The inferred cause, the bulk hint, or the unknown label.
    pub fn describe(&self, lang: Lang) -> String {
        match self.cause {
            Some(cause) => cause.label(lang).to_string(),
            None if self.bulk >= 3 => bulk_label(self.bulk, lang),
            None => unknown_label(lang).to_string(),
        }
    }
}

struct Seen {
    gen: u64,
    up: u64,
    down: u64,
    at: Instant,
    up_rate: u64,
    down_rate: u64,
    ai: bool,
    host: String,
    process: String,
    chains: String,
    provider: String,
    inbound: String,
    start_ms: Option<i64>,
}

impl Scope {
    fn covers(&self, id: &str, seen: &Seen) -> bool {
        match self {
            Self::All => true,
            Self::Id(want) => want == id,
            Self::Providers => !seen.provider.is_empty(),
            Self::TunInbound => seen.inbound.eq_ignore_ascii_case("tun"),
        }
    }
}

struct PendingCause {
    cause: Cause,
    scope: Scope,
    noted: Instant,
    until: Option<Instant>,
}

impl PendingCause {
    fn active(&self, now: Instant) -> bool {
        self.until.map_or(
            now.saturating_duration_since(self.noted) <= CAUSE_MAX,
            |until| now <= until,
        )
    }
}

/// Follows connection ids across full snapshots.
#[derive(Default)]
pub struct Tracker {
    seen: HashMap<String, Seen>,
    gen: u64,
    closed: VecDeque<ClosedConn>,
    cause: Option<PendingCause>,
    was_running: bool,
    totals: (u64, u64),
    restarted: bool,
}

impl Tracker {
    /// Fills rates and AI tags in `conns` and returns the sessions that
    /// disappeared since the previous call.
    pub fn observe(
        &mut self,
        conns: &mut [ConnectionItem],
        running: bool,
        now: Instant,
        now_ms: i64,
    ) -> Vec<ClosedConn> {
        self.gen += 1;
        let gen = self.gen;
        for item in conns.iter_mut() {
            if let Some(seen) = self.seen.get_mut(&item.id) {
                let dt = now.saturating_duration_since(seen.at);
                if dt >= MIN_RATE_DT {
                    let ms = dt.as_millis().max(1) as u64;
                    // A counter that went backwards gives 0, not a huge rate.
                    seen.up_rate = item.upload.saturating_sub(seen.up).saturating_mul(1000) / ms;
                    seen.down_rate =
                        item.download.saturating_sub(seen.down).saturating_mul(1000) / ms;
                    seen.up = item.upload;
                    seen.down = item.download;
                    seen.at = now;
                }
                seen.gen = gen;
                item.up_rate = seen.up_rate;
                item.down_rate = seen.down_rate;
                item.ai = seen.ai;
            } else {
                item.ai = is_ai(item);
                item.up_rate = 0;
                item.down_rate = 0;
                self.seen.insert(
                    item.id.clone(),
                    Seen {
                        gen,
                        up: item.upload,
                        down: item.download,
                        at: now,
                        up_rate: 0,
                        down_rate: 0,
                        ai: item.ai,
                        host: item.host.clone(),
                        process: item.process.clone(),
                        chains: item.chains.clone(),
                        provider: item.provider.clone(),
                        inbound: item.inbound.clone(),
                        start_ms: item.start_ms,
                    },
                );
            }
        }

        let mut closed = Vec::new();
        let pending = self.cause.as_ref().filter(|p| p.active(now));
        let stopped = (self.was_running && !running) || std::mem::take(&mut self.restarted);
        self.seen.retain(|id, seen| {
            if seen.gen == gen {
                return true;
            }
            let lifetime = age_secs(seen.start_ms, now_ms);
            let cause = pending
                .filter(|p| p.scope.covers(id, seen))
                .map(|p| p.cause)
                .or(stopped.then_some(Cause::CoreStopped));
            // A short AI request is recorded only when terc cut it.
            let ai_session =
                seen.ai && (cause.is_some() || lifetime.is_none_or(|age| age >= AI_SESSION_SECS));
            if ai_session || lifetime.is_some_and(|age| age >= LONG_SECS) {
                closed.push(ClosedConn {
                    host: std::mem::take(&mut seen.host),
                    process: std::mem::take(&mut seen.process),
                    chains: std::mem::take(&mut seen.chains),
                    provider: std::mem::take(&mut seen.provider),
                    ai: seen.ai,
                    lifetime_secs: lifetime,
                    upload: seen.up,
                    download: seen.down,
                    closed_ms: now_ms,
                    cause,
                    bulk: 0,
                });
            }
            false
        });

        let uncaused = closed.iter().filter(|c| c.cause.is_none()).count();
        if uncaused >= 3 {
            for entry in closed.iter_mut().filter(|c| c.cause.is_none()) {
                entry.bulk = uncaused;
            }
        }
        for entry in &closed {
            self.closed.push_front(entry.clone());
        }
        self.closed.truncate(CLOSED_CAP);
        if self.cause.as_ref().is_some_and(|p| !p.active(now)) {
            self.cause = None;
        }
        self.was_running = running;
        closed
    }

    /// Attributes closures in `scope` from now on to `cause` until the action
    /// finishes.
    pub fn note(&mut self, cause: Cause, scope: Scope) {
        self.cause = Some(PendingCause {
            cause,
            scope,
            noted: Instant::now(),
            until: None,
        });
    }

    /// Mihomo's upload and download totals only grow within one process, so
    /// lower totals mean the core restarted between two observations, even
    /// when no poll saw it stopped (a supervisor restart within seconds).
    /// Zero for both reads as unknown (a body without totals).
    pub fn note_totals(&mut self, up: u64, down: u64) {
        if (up, down) == (0, 0) {
            return;
        }
        if up < self.totals.0 || down < self.totals.1 {
            self.restarted = true;
        }
        self.totals = (up, down);
    }

    pub fn action_finished(&mut self, now: Instant) {
        if let Some(pending) = self.cause.as_mut().filter(|p| p.until.is_none()) {
            pending.until = Some(now + CAUSE_GRACE);
        }
    }

    /// Newest first.
    pub fn closed(&self) -> &VecDeque<ClosedConn> {
        &self.closed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(id: &str, host: &str, start_ms: Option<i64>) -> ConnectionItem {
        let mut item =
            crate::mihomo::connection_from_value(&serde_json::json!({ "id": id })).unwrap();
        item.host = host.into();
        item.start_ms = start_ms;
        item
    }

    const NOW_MS: i64 = 1_800_000_000_000;

    #[test]
    fn rfc3339_accepts_go_output() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(
            parse_rfc3339_ms("2026-10-20T12:34:56.123456789+08:00"),
            parse_rfc3339_ms("2026-10-20T04:34:56.123Z")
        );
        assert_eq!(
            parse_rfc3339_ms("2026-10-20T04:34:56.123Z"),
            Some(1_792_470_896_123)
        );
        assert_eq!(parse_rfc3339_ms("1970-01-01t00:00:01.5z"), Some(1500));
        assert_eq!(
            parse_rfc3339_ms("1970-01-01T00:00:00-05:30"),
            Some(5 * 3_600_000 + 30 * 60_000)
        );
        assert_eq!(
            parse_rfc3339_ms("2024-02-29T00:00:00Z"),
            Some(1_709_164_800_000)
        );
        assert_eq!(
            parse_rfc3339_ms("2016-12-31T23:59:60Z"),
            parse_rfc3339_ms("2016-12-31T23:59:59Z")
        );
    }

    #[test]
    fn rfc3339_rejects_malformed_input() {
        for bad in [
            "",
            "2023-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-04-31T00:00:00Z",
            "2026-10-20T24:00:00Z",
            "2026-10-20T12:34:56",
            "2026-10-20T12:34:56.1234567890Z",
            "2026-10-20T12:34:56.Z",
            "2026-10-20T12:34:56Zjunk",
            "2026-10-20T12:34:56+0800",
            "2026-10-20T12:34:56+24:00",
            "2026-10-20 12:34:56Z",
            "26-10-20T12:34:56Z",
        ] {
            assert_eq!(parse_rfc3339_ms(bad), None, "{bad}");
        }
    }

    #[test]
    fn go_zero_time_and_skew() {
        let zero = parse_rfc3339_ms("0001-01-01T00:00:00Z");
        assert!(zero.is_some_and(|ms| ms < 0));
        assert_eq!(age_secs(zero, NOW_MS), None);
        assert_eq!(age_secs(None, NOW_MS), None);
        assert_eq!(age_secs(Some(NOW_MS + 5000), NOW_MS), Some(0));
        assert_eq!(age_secs(Some(NOW_MS - 61_999), NOW_MS), Some(61));
    }

    #[test]
    fn fmt_age_boundaries() {
        assert_eq!(fmt_age(-3), "0s");
        assert_eq!(fmt_age(59), "59s");
        assert_eq!(fmt_age(60), "1m00s");
        assert_eq!(fmt_age(307), "5m07s");
        assert_eq!(fmt_age(3599), "59m59s");
        assert_eq!(fmt_age(3600), "1h00m");
        assert_eq!(fmt_age(86_399), "23h59m");
        assert_eq!(fmt_age(86_400), "1d00h");
        assert_eq!(fmt_age(99 * 86_400 + 4 * 3600), "99d04h");
        assert_eq!(fmt_age(150 * 86_400), "150d");
    }

    #[test]
    fn host_only_strips_ports() {
        assert_eq!(host_only("a.com:443"), "a.com");
        assert_eq!(host_only("[::1]:443"), "::1");
        assert_eq!(host_only("1.2.3.4:80"), "1.2.3.4");
        assert_eq!(host_only("a.com.:443"), "a.com");
        assert_eq!(host_only("a.com"), "a.com");
        assert_eq!(host_only("::1"), "::1");
    }

    #[test]
    fn ai_hosts_follow_the_preset() {
        assert!(is_ai_host("api.openai.com"));
        // Only through `DOMAIN-KEYWORD,openai`.
        assert!(is_ai_host("notopenai.org"));
        assert!(is_ai_host("cursor.sh"));
        assert!(is_ai_host("API.Anthropic.COM"));
        assert!(is_ai_host("copilot-proxy.githubusercontent.com"));
        assert!(!is_ai_host("githubusercontent.com"));
        assert!(!is_ai_host("notcursor.sh"));
        assert!(!is_ai_host("example.com"));
        assert!(!is_ai_host(""));
        for (_, rules) in crate::compose::AI_PRESET {
            for rule in *rules {
                let value = rule.split_once(',').map_or("", |(_, v)| v);
                assert_eq!(value, value.to_ascii_lowercase(), "{rule}");
            }
        }
        let mut via_group = item("g", "1.2.3.4:443", None);
        via_group.chains = "AI › HK-01".into();
        assert!(is_ai(&via_group));
        let mut sniffed = item("s", "1.2.3.4:443", None);
        sniffed.sniff_host = "chatgpt.com".into();
        assert!(is_ai(&sniffed));
        assert!(!is_ai(&item("n", "example.com:443", None)));
    }

    #[test]
    fn rates_come_from_id_keyed_diffs() {
        let mut tracker = Tracker::default();
        let t0 = Instant::now();
        let mut conns = vec![item("a", "example.com:443", None)];
        conns[0].upload = 1000;
        conns[0].download = 5000;
        tracker.observe(&mut conns, true, t0, NOW_MS);
        assert_eq!((conns[0].up_rate, conns[0].down_rate), (0, 0));

        conns[0].upload = 3000;
        conns[0].download = 9000;
        tracker.observe(&mut conns, true, t0 + Duration::from_secs(1), NOW_MS);
        assert_eq!((conns[0].up_rate, conns[0].down_rate), (2000, 4000));

        // Snapshot and SnapshotDone back to back: keep the rates.
        conns[0].upload = 100_000;
        tracker.observe(&mut conns, true, t0 + Duration::from_millis(1200), NOW_MS);
        assert_eq!((conns[0].up_rate, conns[0].down_rate), (2000, 4000));

        // The baseline stayed at 1 s, so this diff spans 1 s again.
        conns[0].upload = 0;
        conns[0].download = 13_000;
        tracker.observe(&mut conns, true, t0 + Duration::from_secs(2), NOW_MS);
        assert_eq!((conns[0].up_rate, conns[0].down_rate), (0, 4000));
        assert_eq!(tracker.seen.len(), 1);
    }

    #[test]
    fn long_lived_closures_enter_the_ring() {
        let mut tracker = Tracker::default();
        let t0 = Instant::now();
        let mut conns = vec![
            item("long", "ws.example.com:443", Some(NOW_MS - 90_000)),
            item("short", "example.com:443", Some(NOW_MS - 5_000)),
            item("ai", "api.openai.com:443", Some(NOW_MS - 2_000)),
        ];
        conns[0].upload = 10;
        conns[0].download = 20;
        conns[0].chains = "PROXY › HK".into();
        tracker.observe(&mut conns, true, t0, NOW_MS);
        assert!(conns[2].ai && !conns[0].ai);
        assert_eq!(
            count_sessions(conns.iter(), NOW_MS),
            Affected { sessions: 2, ai: 1 }
        );

        let closed = tracker.observe(&mut [], true, t0 + Duration::from_secs(1), NOW_MS + 1000);
        // The 3-second AI request ended on its own: not a session.
        assert_eq!(closed.len(), 1);
        assert!(tracker.seen.is_empty());
        let long = tracker
            .closed()
            .iter()
            .find(|c| c.host == "ws.example.com:443")
            .unwrap();
        assert_eq!(long.lifetime_secs, Some(91));
        assert_eq!((long.upload, long.download), (10, 20));
        assert_eq!(long.chains, "PROXY › HK");
        assert_eq!(long.closed_ms, NOW_MS + 1000);
        assert_eq!(long.cause, None);
        assert_eq!(long.bulk, 0);
        assert!(tracker.closed().iter().all(|c| c.host != "example.com:443"));
        assert_eq!(long.describe(Lang::En), "closed by the app or remote");
    }

    #[test]
    fn short_ai_requests_count_only_when_terc_cut_them() {
        let mut tracker = Tracker::default();
        let t0 = Instant::now();
        let mut conns = vec![
            item("page", "chatgpt.com:443", Some(NOW_MS - 1_000)),
            item("ab", "ab.chatgpt.com:443", Some(NOW_MS - 1_000)),
            item("cdn", "cdn.oaistatic.com:443", Some(NOW_MS - 1_000)),
            item("ws", "api.openai.com:443", Some(NOW_MS - 15_000)),
        ];
        tracker.observe(&mut conns, true, t0, NOW_MS);
        let closed = tracker.observe(&mut [], true, t0 + Duration::from_secs(1), NOW_MS);
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].host, "api.openai.com:443");
        assert_eq!((closed[0].cause, closed[0].bulk), (None, 0));

        let mut conns = vec![item("page", "chatgpt.com:443", Some(NOW_MS - 1_000))];
        tracker.observe(&mut conns, true, t0, NOW_MS);
        tracker.note(Cause::CloseAll, Scope::All);
        let closed = tracker.observe(&mut [], true, t0 + Duration::from_secs(1), NOW_MS);
        assert_eq!(closed[0].cause, Some(Cause::CloseAll));
        assert_eq!(tracker.closed().len(), 2);
    }

    #[test]
    fn user_close_attaches_only_to_the_noted_id() {
        let mut tracker = Tracker::default();
        let t0 = Instant::now();
        let old = Some(NOW_MS - 120_000);
        let mut conns = vec![item("a", "a.test:443", old), item("b", "b.test:443", old)];
        tracker.observe(&mut conns, true, t0, NOW_MS);
        tracker.note(Cause::UserClose, Scope::Id("a".into()));
        tracker.action_finished(t0);
        let closed = tracker.observe(&mut [], true, t0 + Duration::from_secs(1), NOW_MS);
        let cause = |host: &str| closed.iter().find(|c| c.host == host).unwrap().cause;
        assert_eq!(cause("a.test:443"), Some(Cause::UserClose));
        assert_eq!(cause("b.test:443"), None);
    }

    #[test]
    fn reload_and_tun_causes_reach_only_the_connections_they_cut() {
        let t0 = Instant::now();
        let old = Some(NOW_MS - 120_000);
        let mut sub = item("sub", "sub.test:443", old);
        sub.provider = "airport".into();
        let mut tun = item("tun", "tun.test:443", old);
        tun.inbound = "Tun".into();
        let mut top = item("top", "top.test:443", old);
        top.inbound = "Mixed".into();
        for (cause, scope, hit) in [
            (Cause::Reload, Scope::Providers, "sub.test:443"),
            (Cause::Tun, Scope::TunInbound, "tun.test:443"),
        ] {
            let mut tracker = Tracker::default();
            let mut conns = vec![sub.clone(), tun.clone(), top.clone()];
            tracker.observe(&mut conns, true, t0, NOW_MS);
            tracker.note(cause, scope);
            let closed = tracker.observe(&mut [], true, t0 + Duration::from_secs(1), NOW_MS);
            for c in &closed {
                let want = (c.host == hit).then_some(cause);
                assert_eq!(c.cause, want, "{cause:?} {}", c.host);
            }
        }
    }

    #[test]
    fn close_all_window_ends_after_the_grace_period() {
        let mut tracker = Tracker::default();
        let t0 = Instant::now();
        let old = Some(NOW_MS - 120_000);
        let mut conns = vec![item("a", "a.test:443", old), item("b", "b.test:443", old)];
        tracker.observe(&mut conns, true, t0, NOW_MS);
        tracker.note(Cause::CloseAll, Scope::All);
        tracker.action_finished(t0);
        let mut left = vec![conns[1].clone()];
        let closed = tracker.observe(&mut left, true, t0 + Duration::from_secs(5), NOW_MS);
        assert_eq!(closed[0].cause, Some(Cause::CloseAll));
        let closed = tracker.observe(&mut [], true, t0 + Duration::from_secs(7), NOW_MS);
        assert_eq!(closed[0].cause, None);
        assert!(tracker.cause.is_none());
    }

    #[test]
    fn stopping_core_and_bulk_closures() {
        let mut tracker = Tracker::default();
        let t0 = Instant::now();
        let old = Some(NOW_MS - 120_000);
        let mut conns: Vec<_> = (0..4)
            .map(|i| item(&i.to_string(), &format!("h{i}.test:443"), old))
            .collect();
        tracker.observe(&mut conns.clone(), true, t0, NOW_MS);
        let closed = tracker.observe(&mut [], false, t0 + Duration::from_secs(1), NOW_MS);
        assert_eq!(closed.len(), 4);
        assert!(closed
            .iter()
            .all(|c| c.cause == Some(Cause::CoreStopped) && c.bulk == 0));

        tracker.observe(&mut conns, true, t0 + Duration::from_secs(2), NOW_MS);
        let mut left = vec![conns[0].clone()];
        let closed = tracker.observe(&mut left, true, t0 + Duration::from_secs(3), NOW_MS);
        assert_eq!(closed.len(), 3);
        assert!(closed.iter().all(|c| c.cause.is_none() && c.bulk == 3));
        assert!(closed[0].describe(Lang::En).starts_with("3 closed at once"));

        let closed = tracker.observe(&mut [], true, t0 + Duration::from_secs(4), NOW_MS);
        assert_eq!(closed[0].bulk, 0);
    }

    #[test]
    fn falling_totals_mark_a_restart() {
        let mut tracker = Tracker::default();
        let t0 = Instant::now();
        let mut conns = vec![item("a", "a.test:443", Some(NOW_MS - 120_000))];
        tracker.note_totals(500, 9000);
        tracker.observe(&mut conns, true, t0, NOW_MS);
        tracker.note_totals(600, 9500);
        tracker.observe(&mut conns, true, t0 + Duration::from_secs(1), NOW_MS);
        // Every id replaced and the totals restarted from zero.
        let mut fresh = vec![item("b", "a.test:443", Some(NOW_MS - 1_000))];
        tracker.note_totals(10, 40);
        let closed = tracker.observe(&mut fresh, true, t0 + Duration::from_secs(2), NOW_MS);
        assert_eq!(closed[0].cause, Some(Cause::CoreStopped));
        // Only that one observation.
        let mut long = vec![item("c", "c.test:443", Some(NOW_MS - 120_000))];
        tracker.note_totals(20, 80);
        tracker.observe(&mut long, true, t0 + Duration::from_secs(3), NOW_MS);
        tracker.note_totals(30, 90);
        let closed = tracker.observe(&mut [], true, t0 + Duration::from_secs(4), NOW_MS);
        assert_eq!(closed[0].cause, None);
    }

    #[test]
    fn ring_is_capped_and_newest_first() {
        let mut tracker = Tracker::default();
        let t0 = Instant::now();
        for round in 0..60u64 {
            let mut conns = vec![item(
                &round.to_string(),
                &format!("r{round}.test:443"),
                Some(NOW_MS - 120_000),
            )];
            let at = t0 + Duration::from_secs(round * 2);
            tracker.observe(&mut conns, true, at, NOW_MS);
            assert_eq!(tracker.seen.len(), 1);
            tracker.observe(&mut [], true, at + Duration::from_secs(1), NOW_MS);
        }
        assert_eq!(tracker.closed().len(), CLOSED_CAP);
        assert_eq!(tracker.closed()[0].host, "r59.test:443");
        assert!(tracker.seen.is_empty());
    }

    #[test]
    fn pending_cause_without_finish_expires_at_the_cap() {
        let mut tracker = Tracker::default();
        let t0 = Instant::now();
        tracker.note(Cause::CloseAll, Scope::All);
        let mut conns = vec![item("a", "api.openai.com:443", None)];
        tracker.observe(&mut conns, true, t0, NOW_MS);
        let closed = tracker.observe(&mut [], true, t0 + CAUSE_MAX * 2, NOW_MS);
        assert_eq!(closed[0].cause, None);
        assert!(closed[0].ai);
        assert_eq!(closed[0].lifetime_secs, None);
    }

    #[test]
    fn connection_values_carry_start_and_provider() {
        let item = crate::mihomo::connection_from_value(&serde_json::json!({
            "id": "a",
            "start": "2026-10-20T12:34:56.5+08:00",
            "chains": ["HK-01", "AUTO", "AI"],
            "providerChains": ["sub", "", ""],
        }))
        .unwrap();
        assert_eq!(item.start_ms, Some(1_792_470_896_500));
        assert_eq!(item.start, "2026-10-20T12:34:56.5+08:00");
        assert_eq!(item.provider, "sub");
        assert_eq!((item.up_rate, item.down_rate, item.ai), (0, 0, false));
        let item = crate::mihomo::connection_from_value(&serde_json::json!({
            "id": "b",
            "start": "0001-01-01T00:00:00Z",
            "providerChains": null,
        }))
        .unwrap();
        assert_eq!(item.provider, "");
        assert_eq!(age_secs(item.start_ms, NOW_MS), None);
        let item = crate::mihomo::connection_from_value(&serde_json::json!({ "id": "c" })).unwrap();
        assert_eq!(item.start_ms, None);
    }

    #[test]
    fn sort_keys_cycle() {
        let key = SortKey::default();
        assert_eq!(key, SortKey::Bytes);
        assert_eq!(key.next(), SortKey::Age);
        assert_eq!(key.next().next(), SortKey::Rate);
        assert_eq!(key.next().next().next(), SortKey::Bytes);
    }
}
