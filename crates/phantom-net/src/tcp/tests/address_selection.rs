//! Address selection over loopback: `[::1]` has no listener, so its connect
//! is refused, which on Windows takes about two seconds of SYN
//! retransmissions, long enough for a second attempt to start.

use std::{
    net::{Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use phantom_profile::{TcpAddressSelection, TcpBackupConnection, TcpSettings, chromium, firefox};
use tokio::net::TcpListener;

use super::{super::connect_resolved, TestResult};

/// Two loopback ports: one with an IPv4 listener, and the same port on
/// `[::1]` with nothing listening. `None` when that IPv6 port is taken or
/// the host has no IPv6 loopback.
async fn ipv4_listener_only() -> TestResult<Option<(TcpListener, SocketAddr, SocketAddr)>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let ipv4 = listener.local_addr()?;
    let ipv6 = SocketAddr::new(Ipv6Addr::LOCALHOST.into(), ipv4.port());
    if std::net::TcpListener::bind(ipv6).is_err() {
        return Ok(None);
    }
    Ok(Some((listener, ipv6, ipv4)))
}

/// The Firefox recipe with an IPv4 backup attempt 250 ms in, which the
/// recipe itself leaves out.
fn backup_profile() -> TcpSettings {
    TcpSettings {
        address_selection: TcpAddressSelection::Backup(TcpBackupConnection {
            delay: Duration::from_millis(250),
            known_family_backup_timeout: None,
        }),
        ..firefox::v157_tcp()
    }
}

async fn timed_connect(
    addresses: Vec<SocketAddr>,
    settings: TcpSettings,
) -> TestResult<(SocketAddr, Duration)> {
    let started = Instant::now();
    let stream = connect_resolved(addresses, Some(settings), None, started).await?;
    Ok((stream.peer_addr()?, started.elapsed()))
}

#[tokio::test(flavor = "current_thread")]
async fn every_selection_reaches_ipv4_when_ipv6_is_refused() -> TestResult {
    for settings in [firefox::v157_tcp(), backup_profile(), chromium::v154_tcp()] {
        // A taken `[::1]` port or a host without IPv6 loopback skips this
        // selection only.
        let Some((_listener, ipv6, ipv4)) = ipv4_listener_only().await? else {
            continue;
        };

        let (peer, _) = timed_connect(vec![ipv6, ipv4], settings).await?;

        assert_eq!(peer, ipv4, "{:?}", settings.address_selection);
    }
    Ok(())
}

/// While the refused `[::1]` connect is pending, the IPv4 backup connects
/// 250 ms in and the Chromium profile's second attempt 300 ms in.
#[cfg(windows)]
#[tokio::test(flavor = "current_thread")]
async fn the_second_attempt_starts_after_each_selections_delay() -> TestResult {
    for (settings, delay) in [
        (backup_profile(), Duration::from_millis(250)),
        (chromium::v154_tcp(), Duration::from_millis(300)),
    ] {
        // A taken `[::1]` port or a host without IPv6 loopback skips this
        // selection only.
        let Some((_listener, ipv6, ipv4)) = ipv4_listener_only().await? else {
            continue;
        };

        let (peer, elapsed) = timed_connect(vec![ipv6, ipv4], settings).await?;

        assert_eq!(peer, ipv4);
        assert!(
            elapsed >= delay && elapsed < delay + Duration::from_millis(700),
            "{elapsed:?} for a {delay:?} delay"
        );
    }
    Ok(())
}

/// With only IPv6 addresses, the backup selection starts no backup and waits
/// for the refusal before it tries the second address, while the Chromium
/// profile's second attempt takes that address 300 ms in.
#[cfg(windows)]
#[tokio::test(flavor = "current_thread")]
async fn only_racing_takes_a_second_ipv6_address_early() -> TestResult {
    let (Ok(refused), Ok(listener)) = (
        TcpListener::bind("[::1]:0").await,
        TcpListener::bind("[::1]:0").await,
    ) else {
        return Ok(());
    };
    // Dropping the listener leaves its port refusing connections.
    let refused = {
        let closed = refused;
        closed.local_addr()?
    };
    let listening = listener.local_addr()?;

    let (peer, elapsed) = timed_connect(vec![refused, listening], backup_profile()).await?;
    assert_eq!(peer, listening);
    assert!(elapsed >= Duration::from_secs(1), "backup: {elapsed:?}");

    let (peer, elapsed) = timed_connect(vec![refused, listening], chromium::v154_tcp()).await?;
    assert_eq!(peer, listening);
    assert!(elapsed < Duration::from_secs(1), "Chromium: {elapsed:?}");
    Ok(())
}
