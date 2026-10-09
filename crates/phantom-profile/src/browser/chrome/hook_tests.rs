//! Replays the Frida hook logs under `fixtures/socket-hooks/` against the
//! Chromium TCP, UDP, HTTP/1.1, and address cache recipes. The logs record what
//! the network service process of Chrome 154, Edge 154, and Opera 136 did on
//! Windows 11; `scripts/capture/socket_hooks.py` wrote them.

use std::time::Duration;

use super::{v154_dns_cache, v154_http1, v154_tcp, v154_udp};
use crate::tcp::{TcpAddressRacing, TcpAddressSelection, TcpKeepalivePolicy};

struct HookLogs {
    browser: &'static str,
    version: &'static str,
    /// The browser's network code, which the logs name as each call's caller.
    module: &'static str,
    single: &'static str,
    parallel: &'static str,
    idle: &'static str,
    lookups: &'static str,
    lookups_system: &'static str,
    happy_eyeballs: &'static str,
    happy_eyeballs_slow: &'static str,
    /// Chromium 154 sets `SIO_TCP_INITIAL_RTO` on loopback sockets; the
    /// Chromium 152 that Opera 136 builds on does not.
    loopback_fast_fail: bool,
}

macro_rules! hook_logs {
    ($browser:literal, $version:literal, $module:literal, $fast_fail:literal) => {
        HookLogs {
            browser: $browser,
            version: $version,
            module: $module,
            single: hook_log!($browser, $version, "single"),
            parallel: hook_log!($browser, $version, "parallel"),
            idle: hook_log!($browser, $version, "idle"),
            lookups: hook_log!($browser, $version, "lookups"),
            lookups_system: hook_log!($browser, $version, "lookups-system"),
            happy_eyeballs: hook_log!($browser, $version, "happy-eyeballs"),
            happy_eyeballs_slow: hook_log!($browser, $version, "happy-eyeballs-slow"),
            loopback_fast_fail: $fast_fail,
        }
    };
}

macro_rules! hook_log {
    ($browser:literal, $version:literal, $scenario:literal) => {
        include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/socket-hooks/",
            $browser,
            "/",
            $version,
            "/windows-11-26200/hooks-",
            $scenario,
            ".txt"
        ))
    };
}

fn racing() -> Result<TcpAddressRacing, String> {
    match v154_tcp().address_selection {
        TcpAddressSelection::Racing(racing) => Ok(racing),
        _ => Err("recipe does not race".to_owned()),
    }
}

const LOGS: [HookLogs; 3] = [
    hook_logs!("chrome", "154.0.8037.58", "chrome.dll", true),
    hook_logs!("edge", "154.0.4258.48", "msedge.dll", true),
    hook_logs!("opera", "136.0.6008.52", "opera_browser.dll", false),
];

fn field<'a>(log: &'a str, key: &str) -> Result<&'a str, String> {
    log.lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .ok_or_else(|| format!("hook log has no {key}"))
}

fn fields<'a>(log: &'a str, prefix: &str) -> Vec<&'a str> {
    log.lines()
        .filter_map(|line| {
            let (key, value) = line.split_once('=')?;
            let rest = key.strip_prefix(prefix)?;
            rest.parse::<usize>().ok().map(|_| value)
        })
        .collect()
}

fn assert_provenance(log: &str, logs: &HookLogs) -> Result<(), String> {
    assert_eq!(field(log, "format")?, "phantom-socket-hooks-v1");
    assert_eq!(field(log, "evidence")?, "hook");
    assert_eq!(
        field(log, "browser_version")?,
        logs.version,
        "{}",
        logs.browser
    );
    assert_eq!(
        field(log, "operating_system")?,
        "Windows 11 Home 10.0.26200 x64"
    );
    assert_eq!(field(log, "run_0_timed_out")?, "false", "{}", logs.browser);
    assert_eq!(
        field(log, "run_0_hook_error_count")?,
        "0",
        "{}",
        logs.browser
    );
    Ok(())
}

/// Every socket the browsers opened to the origin set `TCP_NODELAY`, the
/// recipe's keepalive idle time and interval, and port randomization, in
/// that order, then, on Chromium 154, the loopback-only SYN retransmission
/// setting, which the recipe leaves out.
#[test]
fn chromium_family_sockets_set_the_chromium_tcp_options() -> Result<(), String> {
    let tcp = v154_tcp();
    assert!(tcp.nodelay);
    // The logs come from Windows 11 build 26200, where the recipe sets the
    // option.
    let randomization = tcp
        .port_randomization
        .ok_or("recipe sets no port randomization")?;
    assert!(randomization.minimum_windows_build <= 26_200);
    let TcpKeepalivePolicy::Fixed(keepalive) = tcp.keepalive else {
        return Err("recipe has no fixed keepalive".to_owned());
    };
    let interval = keepalive.interval.ok_or("recipe has no interval")?;
    let recipe = format!(
        "TCP_NODELAY=1,SIO_KEEPALIVE_VALS=1/{}/{},SO_RANDOMIZE_PORT=1",
        keepalive.idle.as_millis(),
        interval.as_millis()
    );
    for logs in &LOGS {
        let mut expected = recipe.clone();
        if logs.loopback_fast_fail {
            expected.push_str(",SIO_TCP_INITIAL_RTO=0/254");
        }
        for log in [logs.single, logs.parallel] {
            assert_provenance(log, logs)?;
            let sets = fields(log, "run_0_origin_tcp_option_set_");
            assert_eq!(sets.len(), 1, "{}", logs.browser);
            let (count, options) = sets[0].split_once("x ").ok_or("bad option set")?;
            assert!(count.parse::<usize>().map_err(|e| e.to_string())? >= 4);
            assert_eq!(options, expected, "{}", logs.browser);
        }
    }
    Ok(())
}

/// The value of `key` in one flat JSON event of a log, without its quotes.
fn event_value<'a>(event: &'a str, key: &str) -> Option<&'a str> {
    let start = event.find(&format!("\"{key}\":"))? + key.len() + 3;
    let rest = event.get(start..)?;
    match rest.strip_prefix('"') {
        Some(text) => text.split('"').next(),
        None => rest.split([',', '}']).next(),
    }
}

/// One UDP socket that the browser's network code opened.
struct UdpSocket {
    id: String,
    ipv6: bool,
    /// The options set before `connect`, as `OPTION=value`, in call order.
    before_connect: Vec<String>,
    connected: bool,
    /// The options set after `connect`.
    after_connect: Vec<String>,
}

/// The UDP sockets that `module` opened in a log's first run, in order.
fn browser_udp_sockets(log: &str, module: &str) -> Vec<UdpSocket> {
    let mut sockets: Vec<UdpSocket> = Vec::new();
    for line in log.lines() {
        let Some((key, event)) = line.split_once('=') else {
            continue;
        };
        if !key.starts_with("run_0_event_") {
            continue;
        }
        let Some(id) = event_value(event, "socket") else {
            continue;
        };
        match event_value(event, "kind") {
            Some("socket") => {
                if event_value(event, "protocol") == Some("17")
                    && event_value(event, "caller") == Some(module)
                {
                    sockets.push(UdpSocket {
                        id: id.to_owned(),
                        ipv6: event_value(event, "family") == Some("23"),
                        before_connect: Vec::new(),
                        connected: false,
                        after_connect: Vec::new(),
                    });
                }
            }
            // A closed socket's name can come back for a later socket.
            Some("close") => {
                if let Some(socket) = sockets.iter_mut().find(|socket| socket.id == id) {
                    socket.id.clear();
                }
            }
            Some("setsockopt") => {
                if let Some(socket) = sockets.iter_mut().find(|socket| socket.id == id) {
                    let option = format!(
                        "{}={}",
                        event_value(event, "option").unwrap_or("?"),
                        event_value(event, "value").unwrap_or("?")
                    );
                    if socket.connected {
                        socket.after_connect.push(option);
                    } else {
                        socket.before_connect.push(option);
                    }
                }
            }
            Some("connect") => {
                if let Some(socket) = sockets.iter_mut().find(|socket| socket.id == id) {
                    socket.connected = true;
                }
            }
            _ => {}
        }
    }
    sockets
}

/// Every UDP socket the browsers' network code opened set
/// `SO_RANDOMIZE_PORT` before connecting, after only the dual-stack
/// `IPV6_V6ONLY` of an IPv6 socket, as the recipe asks: DNS sockets, the
/// IPv6 reachability probe, and, in the Chrome and Edge logs, QUIC sockets,
/// which set their buffers and ECN after connecting.
#[test]
fn chromium_family_udp_sockets_randomize_their_port_before_connecting() -> Result<(), String> {
    assert!(v154_udp().port_randomization);
    for logs in &LOGS {
        let mut count = 0;
        let mut quic = 0;
        for log in [
            logs.single,
            logs.parallel,
            logs.idle,
            logs.lookups,
            logs.lookups_system,
            logs.happy_eyeballs,
            logs.happy_eyeballs_slow,
        ] {
            assert_provenance(log, logs)?;
            for socket in browser_udp_sockets(log, logs.module) {
                let mut expected = Vec::new();
                if socket.ipv6 {
                    expected.push("IPV6_V6ONLY=0");
                }
                expected.push("SO_RANDOMIZE_PORT=1");
                assert_eq!(socket.before_connect, expected, "{}", logs.browser);
                assert!(socket.connected, "{}", logs.browser);
                if socket.after_connect.first().map(String::as_str) == Some("SO_RCVBUF=1048576") {
                    quic += 1;
                }
                count += 1;
            }
        }
        assert!(count >= 50, "{}: {count} UDP sockets", logs.browser);
        // Opera's runs opened no QUIC connection.
        if logs.browser != "opera" {
            assert!(quic >= 1, "{}: no QUIC socket", logs.browser);
        }
    }
    Ok(())
}

/// Ten concurrent slow requests to one origin never had more than the
/// recipe's six connections open.
#[test]
fn chromium_family_opens_the_http1_bound_to_one_origin() -> Result<(), String> {
    let bound = v154_http1().max_connections_per_origin.get().to_string();
    for logs in &LOGS {
        assert_provenance(logs.parallel, logs)?;
        assert_eq!(
            field(logs.parallel, "run_0_server_max_open_connections")?,
            bound,
            "{}",
            logs.browser
        );
    }
    Ok(())
}

/// With a refused `[::1]` attempt held open by Windows' SYN retransmissions,
/// every IPv4 attempt started the recipe's fallback delay after the IPv6
/// attempt of its connect job, within scheduling slack.
#[test]
fn chromium_family_starts_ipv4_after_the_racing_delay() -> Result<(), String> {
    let racing = racing()?;
    let slack = Duration::from_millis(60);
    for logs in &LOGS {
        let mut logs_with_pending_ipv6 = vec![logs.happy_eyeballs_slow];
        if !logs.loopback_fast_fail {
            logs_with_pending_ipv6.push(logs.happy_eyeballs);
        }
        for log in logs_with_pending_ipv6 {
            assert_provenance(log, logs)?;
            let delays = field(log, "run_0_origin_ipv4_after_ipv6_ms")?;
            assert_ne!(delays, "-", "{}", logs.browser);
            for delay in delays.split(',') {
                let delay = Duration::from_millis(delay.parse::<u64>().map_err(|e| e.to_string())?);
                assert!(
                    delay >= racing.fallback_delay && delay < racing.fallback_delay + slack,
                    "{}: {delay:?}",
                    logs.browser
                );
            }
        }
    }
    Ok(())
}

/// When the `[::1]` attempt fails at once, as Chromium 154 makes it on
/// loopback, the IPv4 attempt follows the failure without waiting for the
/// fallback delay.
#[test]
fn chromium_154_tries_ipv4_right_after_a_failed_ipv6_attempt() -> Result<(), String> {
    let racing = racing()?;
    for logs in LOGS.iter().filter(|logs| logs.loopback_fast_fail) {
        assert_provenance(logs.happy_eyeballs, logs)?;
        for delay in field(logs.happy_eyeballs, "run_0_origin_ipv4_after_ipv6_ms")?.split(',') {
            let delay = Duration::from_millis(delay.parse::<u64>().map_err(|e| e.to_string())?);
            assert!(
                delay < racing.fallback_delay / 2,
                "{}: {delay:?}",
                logs.browser
            );
        }
    }
    Ok(())
}

/// Lookup times in a log's `lookups` line whose entry contains `kind`, with
/// the calls of one lookup, less than a second apart, merged.
fn lookup_times(log: &str, kind: &str) -> Result<Vec<Duration>, String> {
    let mut times = field(log, "run_0_lookups")?
        .split(' ')
        .filter(|lookup| lookup.contains(kind))
        .map(|lookup| {
            lookup
                .split(':')
                .next()
                .and_then(|t| t.parse::<u64>().ok())
                .map(Duration::from_millis)
                .ok_or_else(|| format!("bad lookup {lookup}"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    times.dedup_by(|later, earlier| *later - *earlier < Duration::from_secs(1));
    Ok(times)
}

/// Through the system resolver, which reports no TTL, the browsers looked
/// the name up again only at the first fetch after the recipe's TTL had
/// passed: fetches 10 s apart for 120 s found it cached until then.
#[test]
fn chromium_family_system_resolver_keeps_an_answer_for_the_cache_ttl() -> Result<(), String> {
    let ttl = v154_dns_cache().ttl;
    let fetch_interval = Duration::from_secs(10);
    for logs in &LOGS {
        let log = logs.lookups_system;
        assert_provenance(log, logs)?;
        let times = lookup_times(log, ":getaddrinfo:")?;
        assert!(times.len() >= 2, "{}: {times:?}", logs.browser);
        for pair in times.windows(2) {
            let gap = pair[1] - pair[0];
            assert!(
                gap >= ttl && gap < ttl + fetch_interval,
                "{}: {gap:?}",
                logs.browser
            );
        }
        let last = times.last().copied().unwrap_or_default();
        assert!(
            Duration::from_secs(120).saturating_sub(last) < ttl,
            "{}: no lookup in the last TTL of the run",
            logs.browser
        );
    }
    Ok(())
}

/// With their default built-in DNS client, the browsers sent one HTTPS query
/// and one A query for the name in 120 s of fetches, and answered every later
/// fetch from the cache: the client keeps an answer for its record TTL, at
/// least the recipe's `min_record_ttl`, past the 60 s of an answer without
/// one. The host had no IPv6 route, so no AAAA query was sent, and the HTTPS
/// query went first, in the same millisecond as the A query.
#[test]
fn chromium_family_built_in_resolver_keeps_an_answer_for_its_record_ttl() -> Result<(), String> {
    let recipe = v154_dns_cache();
    assert_eq!(recipe.min_record_ttl, recipe.ttl);
    for logs in &LOGS {
        let log = logs.lookups;
        assert_provenance(log, logs)?;
        let order = field(log, "run_0_lookups")?
            .split(' ')
            .map(|lookup| lookup.split(':').take(3).collect::<Vec<_>>().join(":"))
            .collect::<Vec<_>>();
        assert_eq!(order.len(), 2, "{}: {order:?}", logs.browser);
        let [https, a] = [&order[0], &order[1]].map(|lookup| lookup.split_once(':'));
        let (Some((https_ms, "WSASendTo:HTTPS")), Some((a_ms, "WSASendTo:A"))) = (https, a) else {
            return Err(format!("{}: {order:?}", logs.browser));
        };
        let [https_ms, a_ms] =
            [https_ms, a_ms].map(|ms| ms.parse::<u64>().map_err(|e| e.to_string()));
        let gap = a_ms?.checked_sub(https_ms?);
        assert!(
            gap.is_some_and(|gap| gap <= 1),
            "{}: {order:?}",
            logs.browser
        );
        assert_eq!(
            lookup_times(log, ":WSASendTo:A:")?.len(),
            1,
            "{}",
            logs.browser
        );
        assert_eq!(
            lookup_times(log, ":WSASendTo:HTTPS:")?.len(),
            1,
            "{}",
            logs.browser
        );
        assert!(
            lookup_times(log, ":WSASendTo:AAAA:")?.is_empty(),
            "{}",
            logs.browser
        );
        assert!(
            lookup_times(log, ":getaddrinfo:")?.is_empty(),
            "{}",
            logs.browser
        );
    }
    Ok(())
}

/// A used connection that sat idle 290 s carried the next request; one that
/// sat idle 310 s was closed when the next request came, which opened a new
/// connection. Chromium 154 keeps a used idle socket for 300 s
/// (`net/socket/client_socket_pool.cc:42`) and checks it only when a request
/// reaches its pool, as the recipe's `idle_timeout` does.
#[test]
fn chromium_family_replaces_a_connection_idle_past_300_s_on_the_next_request() -> Result<(), String>
{
    let timeout = v154_http1()
        .idle_timeout
        .checked_on_request()
        .ok_or("recipe keeps idle connections")?;
    let timeout_ms = u64::try_from(timeout.as_millis()).map_err(|e| e.to_string())?;
    for logs in &LOGS {
        let log = logs.idle;
        assert_provenance(log, logs)?;
        let connections = fields(log, "run_0_server_connection_");
        let carrying = |path: &str| {
            connections
                .iter()
                .position(|connection| connection.contains(path))
                .ok_or_else(|| format!("{}: no connection carried {path}", logs.browser))
        };
        let first = carrying("/fast?i=0")?;
        assert_eq!(carrying("/fast?i=1")?, first, "{}", logs.browser);
        let replacement = carrying("/fast?i=2")?;
        assert_ne!(replacement, first, "{}", logs.browser);
        let number = |connection: &str, key: &str| {
            connection
                .split(',')
                .find_map(|part| part.strip_prefix(key)?.parse::<u64>().ok())
                .ok_or_else(|| format!("{}: no {key} in {connection}", logs.browser))
        };
        let idle = number(connections[first], "idle_before_close_ms:")?;
        assert!(
            (timeout_ms..timeout_ms + 20_000).contains(&idle),
            "{}: {idle}",
            logs.browser
        );
        let closed = number(connections[first], "closed:")?;
        let accepted = number(connections[replacement], "accepted:")?;
        assert!(closed.abs_diff(accepted) < 1_000, "{}", logs.browser);
    }
    Ok(())
}
