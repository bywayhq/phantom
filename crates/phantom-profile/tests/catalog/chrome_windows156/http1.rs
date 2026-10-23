use std::time::Duration;

use phantom_profile::{
    Http1IdleTimeout, browser,
    catalog::{ProfileLayer, profile},
};

use super::{TestResult, field};

const PARALLEL: &str = include_str!(
    "../../../../../fixtures/socket-hooks/chrome/156.0.8078.48/windows-11-26200/hooks-parallel.txt"
);
const IDLE: &str = include_str!(
    "../../../../../fixtures/socket-hooks/chrome/156.0.8078.48/windows-11-26200/hooks-idle.txt"
);

fn request_connection(capture: &str, path: &str) -> TestResult<(usize, u64)> {
    for index in 0..field(capture, "run_0_server_connection_count")?.parse::<usize>()? {
        let row = field(capture, &format!("run_0_server_connection_{index}"))?;
        let (_, requests) = row.split_once(",requests:").ok_or("missing requests")?;
        for request in requests.split_whitespace() {
            if request.ends_with(path) {
                let (time, _) = request.split_once(':').ok_or("missing request time")?;
                return Ok((index, time.parse()?));
            }
        }
    }
    Err(format!("missing captured request {path}").into())
}

#[test]
fn windows156_http1_connection_limit_matches_parallel_requests() -> TestResult {
    let selected = profile("chrome-156-windows")?.instantiate(&[ProfileLayer::Http1])?;
    assert_eq!(selected, browser::chrome::v156_windows());
    let settings = selected.http1().ok_or("missing HTTP/1.1 policy")?;
    let captured_limit = field(PARALLEL, "run_0_server_max_open_connections")?.parse::<usize>()?;
    assert_eq!(captured_limit, 6);
    assert_eq!(settings.max_connections_per_origin.get(), captured_limit);

    let mut connections = std::collections::BTreeSet::new();
    for request in 0..10 {
        let (connection, _) = request_connection(PARALLEL, &format!("/slow?i={request}"))?;
        connections.insert(connection);
    }
    assert_eq!(connections.len(), captured_limit);
    Ok(())
}

#[test]
fn windows156_http1_reuses_before_its_limit_and_replaces_on_the_next_request() -> TestResult {
    for capture in [PARALLEL, IDLE] {
        assert_eq!(field(capture, "browser_version")?, "156.0.8078.48");
        assert_eq!(field(capture, "launch_mode")?, "headful");
        assert_eq!(field(capture, "hook_intervention")?, "none");
        assert_eq!(field(capture, "run_count")?, "1");
        assert_eq!(field(capture, "run_0_hook_error_count")?, "0");
        assert_eq!(field(capture, "run_0_timed_out")?, "false");
    }

    let selected = browser::chrome::v156_windows();
    let settings = selected.http1().ok_or("missing HTTP/1.1 policy")?;
    let Http1IdleTimeout::CheckedOnRequest(timeout) = settings.idle_timeout else {
        return Err("expected request-time idle cleanup".into());
    };
    assert_eq!(timeout, Duration::from_secs(300));

    let first = request_connection(IDLE, "/fast?i=0")?;
    let reused = request_connection(IDLE, "/fast?i=1")?;
    let replaced = request_connection(IDLE, "/fast?i=2")?;
    assert_eq!(first.0, reused.0);
    assert_ne!(reused.0, replaced.0);
    assert!(Duration::from_millis(reused.1 - first.1) < timeout);
    assert!(Duration::from_millis(replaced.1 - reused.1) > timeout);

    let row = field(IDLE, &format!("run_0_server_connection_{}", reused.0))?;
    let idle = row
        .split(',')
        .find_map(|item| item.strip_prefix("idle_before_close_ms:"))
        .ok_or("missing idle age at close")?
        .parse::<u64>()?;
    assert!(Duration::from_millis(idle) > timeout);
    Ok(())
}
