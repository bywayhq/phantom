use std::sync::{Arc, Mutex};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::{Duration, timeout},
};

use super::{StreamLog, StreamMode, TestResult, parse_target, serve_http1};

#[test]
fn target_paths_keep_numeric_loopback_addresses() -> TestResult<()> {
    for (host, expected) in [
        ("127.0.0.1", "127.0.0.1:443"),
        ("127.1.2.3", "127.1.2.3:443"),
        ("%3A%3A1", "[::1]:443"),
    ] {
        let path = format!("/.well-known/masque/udp/{host}/443/");
        assert_eq!(parse_target(&path), Some(expected.parse()?));
    }
    Ok(())
}

#[tokio::test]
async fn received_targets_outside_loopback_fail_before_a_relay_response() -> TestResult<()> {
    for host in ["192.0.2.1", "0.0.0.0", "2001%3Adb8%3A%3A1", "%3A%3A"] {
        let (mut peer, stream) = tokio::io::duplex(4096);
        let path = format!("/.well-known/masque/udp/{host}/443/");
        peer.write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade\r\nUpgrade: connect-udp\r\n\r\n")
                .as_bytes(),
        )
        .await?;
        let log = Arc::new(Mutex::new(StreamLog::default()));
        let error = timeout(
            Duration::from_secs(5),
            serve_http1(stream, StreamMode::Relay, log.clone()),
        )
        .await?
        .expect_err("a received nonloopback target started a relay");
        assert_eq!(error.to_string(), "CONNECT-UDP path has no loopback target");
        assert_eq!(log.lock().unwrap().requests[0].path, path);
        // No Upgrade or successful tunnel response precedes rejection.
        assert_eq!(peer.read(&mut [0; 1]).await?, 0);
    }
    Ok(())
}
