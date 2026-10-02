//! Replays the Frida hook logs under `fixtures/socket-hooks/firefox/` against
//! the Firefox TCP and address cache recipes. The logs record what the parent
//! process of Firefox 157.0 did on Windows 11;
//! `scripts/capture/firefox_socket_hooks.py` wrote them.

use std::time::Duration;

use super::{v157_dns_cache, v157_tcp};
use crate::tcp::{
    TcpAddressAdvance, TcpAddressSelection, TcpKeepalivePolicy, TcpKeepaliveSchedule,
};

macro_rules! hook_log {
    ($scenario:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/socket-hooks/firefox/157.0/windows-11-26200/hooks-",
            $scenario,
            ".txt"
        ))
    };
}

const HTTP1_IDLE: &str = hook_log!("http1-idle");
const HTTP1_LONG: &str = hook_log!("http1-long");
const H2: &str = hook_log!("h2");
const WEBSOCKET: &str = hook_log!("websocket");
const BACKUP: &str = hook_log!("backup");
const DNS_CACHE: &str = hook_log!("dns-cache");
const ALL: [&str; 6] = [HTTP1_IDLE, HTTP1_LONG, H2, WEBSOCKET, BACKUP, DNS_CACHE];

/// Scheduling slack for a timer the browser armed.
const SLACK: Duration = Duration::from_millis(500);

type TestResult = Result<(), String>;

fn field<'a>(log: &'a str, key: &str) -> Result<&'a str, String> {
    log.lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .ok_or_else(|| format!("hook log has no {key}"))
}

fn run_count(log: &str) -> Result<usize, String> {
    field(log, "run_count")?
        .parse()
        .map_err(|error| format!("bad run_count: {error}"))
}

/// Values of the numbered lines `run_<run>_<prefix><n>`, in file order.
fn numbered<'a>(log: &'a str, run: usize, prefix: &str) -> Vec<&'a str> {
    let prefix = format!("run_{run}_{prefix}");
    log.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let rest = key.strip_prefix(&prefix)?;
            rest.parse::<usize>().ok().map(|_| value)
        })
        .collect()
}

fn assert_provenance(log: &str) -> TestResult {
    assert_eq!(field(log, "format")?, "phantom-socket-hooks-v1");
    assert_eq!(field(log, "evidence")?, "hook");
    assert_eq!(field(log, "browser")?, "Mozilla Firefox");
    assert_eq!(field(log, "browser_version")?, "157.0");
    assert_eq!(
        field(log, "operating_system")?,
        "Windows 11 Home 10.0.26200 x64"
    );
    for run in 0..run_count(log)? {
        assert_eq!(field(log, &format!("run_{run}_timed_out"))?, "false");
        assert_eq!(field(log, &format!("run_{run}_hook_error_count"))?, "0");
    }
    Ok(())
}

/// One `origin_socket_<i>` line: a socket that connected to the measured
/// origin, with the calls made on it.
struct OriginSocket<'a> {
    address: &'a str,
    connect_ms: u64,
    failed: &'a str,
    before_connect: Vec<&'a str>,
    /// `(milliseconds after the connect, call)`.
    after_connect: Vec<(u64, &'a str)>,
}

impl<'a> OriginSocket<'a> {
    fn parse(line: &'a str) -> Result<Self, String> {
        let mut socket = Self {
            address: "",
            connect_ms: 0,
            failed: "",
            before_connect: Vec::new(),
            after_connect: Vec::new(),
        };
        for part in line.split(',') {
            let (key, value) = part
                .split_once(':')
                .ok_or_else(|| format!("bad origin socket part {part}"))?;
            match key {
                "address" => socket.address = value,
                "connect_ms" => socket.connect_ms = number(value)?,
                "failed" => socket.failed = value,
                "before_connect" => socket.before_connect = value.split(';').collect(),
                "after_connect" if value != "-" => {
                    for call in value.split(';') {
                        let (time, call) = call
                            .strip_prefix('+')
                            .and_then(|call| call.split_once(':'))
                            .ok_or_else(|| format!("bad call {call}"))?;
                        socket.after_connect.push((number(time)?, call));
                    }
                }
                _ => {}
            }
        }
        Ok(socket)
    }

    /// The keepalive calls, `SIO_KEEPALIVE_VALS` with keepalive on, as
    /// `(milliseconds after the connect, idle ms, interval ms)`.
    fn keepalive_on(&self) -> Vec<(u64, u64, u64)> {
        self.after_connect
            .iter()
            .filter_map(|(time, call)| {
                let values = call.strip_prefix("SIO_KEEPALIVE_VALS=1/")?;
                let (idle, interval) = values.split_once('/')?;
                Some((*time, idle.parse().ok()?, interval.parse().ok()?))
            })
            .collect()
    }

    fn turned_keepalive_off(&self) -> bool {
        self.after_connect
            .iter()
            .any(|(_, call)| *call == "SO_KEEPALIVE=0")
    }
}

fn number(text: &str) -> Result<u64, String> {
    text.parse()
        .map_err(|error| format!("bad number {text}: {error}"))
}

fn sockets(log: &str, run: usize) -> Result<Vec<OriginSocket<'_>>, String> {
    numbered(log, run, "origin_socket_")
        .into_iter()
        .map(OriginSocket::parse)
        .collect()
}

fn schedule() -> Result<TcpKeepaliveSchedule, String> {
    match v157_tcp().keepalive {
        TcpKeepalivePolicy::Schedule(schedule) => Ok(schedule),
        other => Err(format!("recipe keepalive is {other:?}")),
    }
}

fn millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// The switch to long-lived keepalive that
/// [`TcpKeepaliveSchedule`] describes, for one probe interval.
fn switch_after(schedule: &TcpKeepaliveSchedule, interval: Duration) -> Duration {
    let time = schedule.short_lived_time.as_secs();
    let idle = schedule.short_lived_idle.as_secs();
    Duration::from_secs(time - time % idle)
        + interval * schedule.probe_count
        + Duration::from_secs(2)
}

/// Every socket Firefox opened to an origin set `TCP_NODELAY` and the
/// recipe's send buffer before connecting, and `SO_LINGER` to `{1, 0}`,
/// which the recipe leaves out because the close is a FIN either way. None
/// set `SO_RANDOMIZE_PORT`, and neither does the recipe.
#[test]
fn firefox_sockets_set_nodelay_and_the_send_buffer_before_connecting() -> TestResult {
    let tcp = v157_tcp();
    assert!(tcp.nodelay);
    assert_eq!(tcp.port_randomization, None);
    let send_buffer = tcp.send_buffer_size.ok_or("recipe has no send buffer")?;
    let expected = [
        "TCP_NODELAY=1".to_owned(),
        format!("SO_SNDBUF={send_buffer}"),
        "SO_LINGER=1/0".to_owned(),
    ];
    let mut count = 0;
    for log in ALL {
        assert_provenance(log)?;
        for run in 0..run_count(log)? {
            for socket in sockets(log, run)? {
                assert_eq!(socket.before_connect, expected, "{}", socket.address);
                count += 1;
            }
        }
    }
    assert!(count >= 30, "{count} sockets");
    Ok(())
}

/// A connection carrying a request got the recipe's short-lived idle time
/// and a one-second interval within milliseconds of connecting, before any
/// TLS handshake.
#[test]
fn firefox_starts_short_lived_keepalive_as_a_connection_opens() -> TestResult {
    let schedule = schedule()?;
    let short = millis(schedule.short_lived_idle);
    let interval = millis(schedule.minimum_interval);
    for log in [HTTP1_IDLE, HTTP1_LONG, H2, WEBSOCKET, DNS_CACHE] {
        for run in 0..run_count(log)? {
            let opened = sockets(log, run)?
                .into_iter()
                .filter(|socket| !socket.keepalive_on().is_empty())
                .collect::<Vec<_>>();
            assert!(!opened.is_empty(), "no connection carried a request");
            for socket in opened {
                let (time, idle, probe_interval) = socket.keepalive_on()[0];
                assert!(time < 50, "{time} ms after the connect");
                assert_eq!((idle, probe_interval), (short, interval));
            }
        }
    }
    Ok(())
}

/// A response that took 85 s moved its connection to the recipe's
/// long-lived idle time at the switch time the schedule computes: 72 s.
#[test]
fn firefox_switches_an_active_connection_to_long_lived_keepalive() -> TestResult {
    let schedule = schedule()?;
    let expected = switch_after(&schedule, schedule.minimum_interval);
    assert_eq!(expected, Duration::from_secs(72));
    let socket = sockets(HTTP1_LONG, 0)?
        .into_iter()
        .next()
        .ok_or("no origin socket")?;
    let calls = socket.keepalive_on();
    assert_eq!(calls.len(), 2, "{calls:?}");
    let (start, _, _) = calls[0];
    let (switch, idle, interval) = calls[1];
    assert_eq!(idle, millis(schedule.long_lived_idle));
    assert_eq!(interval, millis(schedule.minimum_interval));
    let elapsed = Duration::from_millis(switch - start);
    assert!(
        elapsed >= expected && elapsed < expected + SLACK,
        "{elapsed:?}"
    );
    Ok(())
}

/// A connection idle in the pool when the switch fell due stayed
/// short-lived through its 215 s life, including a second request at 99 s.
#[test]
fn firefox_keeps_an_idle_pooled_connection_short_lived() -> TestResult {
    let schedule = schedule()?;
    let socket = sockets(HTTP1_IDLE, 0)?
        .into_iter()
        .next()
        .ok_or("no origin socket")?;
    let requests = numbered(HTTP1_IDLE, 0, "server_connection_")
        .first()
        .and_then(|line| line.split("requests:").nth(1))
        .map(|requests| requests.split(' ').count())
        .ok_or("no server connection")?;
    assert_eq!(requests, 2);
    assert_eq!(socket.keepalive_on().len(), 1);
    assert!(
        socket
            .keepalive_on()
            .iter()
            .all(|(_, idle, _)| *idle == millis(schedule.short_lived_idle))
    );
    let (closed, _) = socket
        .after_connect
        .last()
        .copied()
        .ok_or("no calls after the connect")?;
    assert!(closed > 200_000, "closed at {closed} ms");
    Ok(())
}

/// HTTP/2 turned keepalive off right after the handshake, and nothing
/// turned it on again.
#[test]
fn firefox_turns_keepalive_off_after_http2() -> TestResult {
    for run in 0..run_count(H2)? {
        let socket = sockets(H2, run)?
            .into_iter()
            .find(|socket| !socket.keepalive_on().is_empty())
            .ok_or("no connection carried a request")?;
        assert_eq!(socket.keepalive_on().len(), 1);
        assert!(socket.turned_keepalive_off());
        let (last, call) = socket.after_connect.last().copied().ok_or("no calls")?;
        assert_eq!(call, "SO_KEEPALIVE=0");
        assert!(last < 100, "{last} ms");
    }
    Ok(())
}

/// The 101 response moved the WebSocket connection to long-lived keepalive
/// at once.
#[test]
fn firefox_switches_a_websocket_connection_to_long_lived_at_once() -> TestResult {
    let long = millis(schedule()?.long_lived_idle);
    for run in 0..run_count(WEBSOCKET)? {
        let socket = sockets(WEBSOCKET, run)?
            .into_iter()
            .next()
            .ok_or("no origin socket")?;
        let calls = socket.keepalive_on();
        assert_eq!(calls.len(), 2, "{calls:?}");
        let (time, idle, _) = calls[1];
        assert_eq!(idle, long);
        assert!(time < 100, "{time} ms");
    }
    Ok(())
}

/// Not modeled: with `[::1]` refused slowly and `127.0.0.1` listening,
/// every run started an IPv4 backup 250 ms after the first attempt, and the
/// first attempt moved to `127.0.0.1` only when `[::1]` was refused. The
/// recipe tries the addresses in order, because `TcpBackupConnection`
/// closes the slower attempt that Firefox keeps.
#[test]
fn firefox_starts_an_ipv4_backup_250_ms_after_a_slow_first_attempt() -> TestResult {
    assert_eq!(
        v157_tcp().address_selection,
        TcpAddressSelection::Sequential(TcpAddressAdvance::AfterRefusalOrTimeout)
    );
    let delay = 250;
    let slack = millis(Duration::from_millis(60));
    let runs = run_count(BACKUP)?;
    assert_eq!(runs, 5);
    for run in 0..runs {
        let sockets = sockets(BACKUP, run)?;
        let primary = &sockets[0];
        let backup = &sockets[1];
        let next = &sockets[2];
        assert!(primary.address.starts_with("[::1]:"));
        assert!(backup.address.starts_with("127.0.0.1:"));
        let gap = backup.connect_ms - primary.connect_ms;
        assert!(gap >= delay && gap < delay + slack, "run {run}: {gap} ms");
        let (error, refused_after) = primary
            .failed
            .split_once('+')
            .ok_or("the [::1] attempt did not fail")?;
        assert_eq!(error, "10061");
        assert!(next.address.starts_with("127.0.0.1:"));
        assert!(
            next.connect_ms
                .abs_diff(primary.connect_ms + number(refused_after)?)
                < slack
        );
    }
    Ok(())
}

/// Not modeled: Firefox kept the slower attempt's connection, used it for a
/// later request, and gave it a two-second probe interval, its setup time.
#[test]
fn firefox_keeps_the_slower_connection_with_its_setup_time_interval() -> TestResult {
    for run in 0..run_count(BACKUP)? {
        let sockets = sockets(BACKUP, run)?;
        let slower = &sockets[2];
        let calls = slower.keepalive_on();
        assert_eq!(calls.len(), 1, "run {run}");
        let (time, _, interval) = calls[0];
        assert!(
            time > 2_000,
            "run {run}: first used {time} ms after connecting"
        );
        assert_eq!(interval, 2_000);
        let carried = numbered(BACKUP, run, "server_connection_")
            .get(1)
            .is_some_and(|connection| connection.contains("/slow?i="));
        assert!(carried, "run {run}");
    }
    Ok(())
}

/// Not modeled: once a connection to the origin succeeded over IPv4,
/// Firefox's later connections to it, also after the origin closed every
/// connection, tried `127.0.0.1` alone. Phantom tries both families again.
#[test]
fn firefox_remembers_the_address_family_of_an_origin() -> TestResult {
    for run in 0..run_count(BACKUP)? {
        let sockets = sockets(BACKUP, run)?;
        assert_eq!(sockets.len(), 5, "run {run}");
        for later in &sockets[3..] {
            assert!(later.address.starts_with("127.0.0.1:"), "run {run}");
            assert_eq!(later.failed, "-");
        }
    }
    Ok(())
}

/// Firefox resolved the name with `AI_CANONNAME` alone: no `AI_ADDRCONFIG`,
/// so it sees the same addresses as Phantom's resolver call.
#[test]
fn firefox_resolves_without_ai_addrconfig() -> TestResult {
    for log in ALL {
        for run in 0..run_count(log)? {
            let calls = field(log, &format!("run_{run}_lookup_calls"))?;
            let flags = calls
                .split(' ')
                .filter_map(|call| call.split(":flags=").nth(1))
                .collect::<Vec<_>>();
            assert!(!flags.is_empty());
            for flags in flags {
                assert!(flags.starts_with("AI_CANONNAME:family="), "{flags}");
            }
        }
    }
    Ok(())
}

/// Not modeled: Firefox read the record's TTL with `DnsQuery_A` and kept
/// the answer that long, so connections opened 33, 68, and 98 s after the
/// first needed no lookup. The recipe keeps an answer for 60 s.
#[test]
fn firefox_keeps_an_answer_for_its_record_ttl() -> TestResult {
    assert_eq!(v157_dns_cache().ttl, Duration::from_secs(60));
    assert_eq!(sockets(DNS_CACHE, 0)?.len(), 4);
    let calls = field(DNS_CACHE, "run_0_lookup_calls")?;
    let mut ttl = None;
    for call in calls.split(' ') {
        let time = number(call.split(':').next().unwrap_or_default())?;
        assert!(time < 1_000, "a lookup at {time} ms");
        if let Some(record) = call.split(":A/answer/").nth(1) {
            ttl = Some(number(record)?);
        }
    }
    let ttl = ttl.ok_or("no TTL was read")?;
    assert!(ttl > 95, "TTL {ttl} s");
    Ok(())
}
