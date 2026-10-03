use std::{io, time::Duration};

use phantom_profile::{
    TcpAddressAdvance, TcpAddressRacing, TcpAddressSelection, TcpKeepalive, TcpKeepalivePolicy,
    TcpPortRandomization, TcpSettings, chromium,
};
use socket2::SockRef;
use tokio::net::TcpListener;

use super::{
    KeepaliveSupport, address_racing::race, check_host_support, check_keepalive_support, connect,
    connect_address, connect_sequentially,
};

mod address_selection;
mod keepalive_paths;
mod paths;
mod port_randomization;
mod slower_connection;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const KEEPALIVE: Duration = Duration::from_secs(45);

fn chromium_like() -> TcpSettings {
    TcpSettings {
        nodelay: true,
        send_buffer_size: None,
        keepalive: TcpKeepalivePolicy::Fixed(TcpKeepalive {
            idle: KEEPALIVE,
            interval: Some(KEEPALIVE),
        }),
        address_selection: TcpAddressSelection::Racing(TcpAddressRacing {
            fallback_delay: Duration::from_millis(300),
        }),
        port_randomization: Some(TcpPortRandomization {
            minimum_windows_build: 22_621,
        }),
    }
}

/// Whether `settings` set `SO_RANDOMIZE_PORT` on this host.
#[cfg(windows)]
fn sets_random_port(settings: &TcpSettings) -> bool {
    settings.port_randomization.is_some_and(|randomization| {
        super::host_reaches_build(randomization.minimum_windows_build).unwrap_or(false)
    })
}

#[cfg(not(windows))]
fn sets_random_port(_settings: &TcpSettings) -> bool {
    false
}

#[tokio::test(flavor = "current_thread")]
async fn connected_socket_carries_requested_options() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let stream = connect("127.0.0.1", port, Some(chromium_like()), None, None).await?;
    let socket = SockRef::from(&stream);

    assert!(socket.tcp_nodelay()?);
    assert!(socket.keepalive()?);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        assert_eq!(socket.tcp_keepalive_time()?, KEEPALIVE);
        assert_eq!(socket.tcp_keepalive_interval()?, KEEPALIVE);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn racing_reaches_ipv4_when_nothing_listens_on_ipv6() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let ipv4 = listener.local_addr()?;
    let ipv6 = std::net::SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), ipv4.port());
    let settings = chromium_like();

    // The IPv6 attempt goes first and either fails (refused, or IPv6
    // unavailable) or is still pending when the fallback attempt reaches IPv4.
    let fallback = tokio::time::sleep(Duration::from_millis(300));
    let stream = race(vec![ipv4, ipv6], fallback, |address| {
        connect_address(address, Some(settings), None)
    })
    .await?;

    assert_eq!(stream.peer_addr()?, ipv4);
    assert!(SockRef::from(&stream).tcp_nodelay()?);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn connect_races_resolved_names() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let stream = connect("127.0.0.1", port, Some(chromium_like()), None, None).await?;

    assert_eq!(stream.peer_addr()?, listener.local_addr()?);
    Ok(())
}

fn keepalive(interval: Option<Duration>) -> TcpSettings {
    TcpSettings {
        nodelay: true,
        keepalive: TcpKeepalivePolicy::Fixed(TcpKeepalive {
            idle: KEEPALIVE,
            interval,
        }),
        ..TcpSettings::default()
    }
}

const FULL_SUPPORT: KeepaliveSupport = KeepaliveSupport {
    idle: true,
    interval: true,
    interval_required: false,
};

#[test]
fn host_check_accepts_what_the_platform_can_apply() {
    assert_eq!(
        check_keepalive_support(&keepalive(Some(KEEPALIVE)), FULL_SUPPORT),
        Ok(())
    );
    assert_eq!(
        check_keepalive_support(&keepalive(None), FULL_SUPPORT),
        Ok(())
    );
    let without_keepalive = TcpSettings {
        keepalive: TcpKeepalivePolicy::Unchanged,
        ..keepalive(None)
    };
    let nothing = KeepaliveSupport {
        idle: false,
        interval: false,
        interval_required: true,
    };
    assert_eq!(check_keepalive_support(&without_keepalive, nothing), Ok(()));
}

#[test]
fn host_check_rejects_an_idle_time_the_platform_would_drop() {
    let support = KeepaliveSupport {
        idle: false,
        ..FULL_SUPPORT
    };

    let result = check_keepalive_support(&keepalive(None), support);

    assert_eq!(result.map_err(|error| error.field()), Err("keepalive.idle"));
}

#[test]
fn host_check_rejects_an_interval_the_platform_cannot_set() {
    let support = KeepaliveSupport {
        interval: false,
        ..FULL_SUPPORT
    };

    let result = check_keepalive_support(&keepalive(Some(KEEPALIVE)), support);

    assert_eq!(
        result.map_err(|error| error.field()),
        Err("keepalive.interval")
    );
    assert_eq!(check_keepalive_support(&keepalive(None), support), Ok(()));
}

#[test]
fn host_check_requires_an_interval_where_windows_semantics_apply() {
    let support = KeepaliveSupport {
        interval_required: true,
        ..FULL_SUPPORT
    };

    let result = check_keepalive_support(&keepalive(None), support);

    assert_eq!(
        result.map_err(|error| error.field()),
        Err("keepalive.interval")
    );
    assert_eq!(
        check_keepalive_support(&keepalive(Some(KEEPALIVE)), support),
        Ok(())
    );
}

#[test]
fn this_host_accepts_the_chromium_recipe() {
    assert_eq!(
        check_host_support(&phantom_profile::chromium::v154_tcp()),
        Ok(())
    );
}

#[cfg(windows)]
#[test]
fn this_windows_host_requires_a_keepalive_interval() {
    let result = check_host_support(&keepalive(None));

    assert_eq!(
        result.map_err(|error| error.field()),
        Err("keepalive.interval")
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn this_host_accepts_an_idle_only_keepalive() {
    assert_eq!(check_host_support(&keepalive(None)), Ok(()));
}

#[tokio::test(flavor = "current_thread")]
async fn settings_that_ask_for_nothing_keep_os_defaults() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let settings = TcpSettings::default();

    let stream = connect("127.0.0.1", port, Some(settings), None, None).await?;
    let socket = SockRef::from(&stream);

    assert!(!socket.tcp_nodelay()?);
    assert!(!socket.keepalive()?);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_settings_fail_before_any_connection() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let settings = TcpSettings {
        nodelay: true,
        keepalive: TcpKeepalivePolicy::Fixed(TcpKeepalive {
            idle: Duration::ZERO,
            interval: None,
        }),
        ..TcpSettings::default()
    };

    let error = match connect("127.0.0.1", port, Some(settings), None, None).await {
        Ok(_) => return Err("invalid keepalive was applied".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    let accepted = tokio::time::timeout(Duration::from_millis(50), listener.accept()).await;
    assert!(accepted.is_err(), "a connection was opened");
    Ok(())
}

#[cfg(windows)]
#[tokio::test(flavor = "current_thread")]
async fn keepalive_without_interval_is_unsupported_on_windows() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let settings = TcpSettings {
        nodelay: true,
        keepalive: TcpKeepalivePolicy::Fixed(TcpKeepalive {
            idle: KEEPALIVE,
            interval: None,
        }),
        ..TcpSettings::default()
    };

    let error = match connect("127.0.0.1", port, Some(settings), None, None).await {
        Ok(_) => return Err("keepalive without an interval was applied".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    Ok(())
}

/// Dials scripted outcomes: `reset` fails with a reset, every other address
/// connects. Returns the addresses dialed, in order.
/// With the family known, a backup connect that is still pending when the
/// backup timeout passes fails as timed out, and the backup moves to its
/// next address, while the primary attempt, which has no timeout, waits on.
#[tokio::test(flavor = "current_thread")]
async fn a_backup_connect_past_the_known_family_timeout_moves_to_the_next_address() -> TestResult {
    let held: std::net::SocketAddr = "192.0.2.1:443".parse()?;
    let answering: std::net::SocketAddr = "192.0.2.2:443".parse()?;
    let timeout = Duration::from_millis(50);
    let plan = super::backup_connection::Plan {
        family: Some(super::AddressFamily::Ipv4),
        known_family_backup_timeout: Some(timeout),
    };
    let dialed = std::cell::RefCell::new(Vec::new());
    let dial = |address: std::net::SocketAddr, limit: Option<Duration>| {
        dialed.borrow_mut().push((address, limit));
        super::within_connect_timeout(limit, async move {
            if address == held {
                std::future::pending::<()>().await;
            }
            Ok(address)
        })
    };

    let won = super::backup_connection::connect(
        vec![held, answering],
        plan,
        std::future::ready(()),
        dial,
        std::time::Instant::now(),
    )
    .await?;

    assert_eq!(won.connected.address, answering);
    assert_eq!(
        *dialed.borrow(),
        [
            (held, None),
            (held, Some(timeout)),
            (answering, Some(timeout))
        ]
    );
    Ok(())
}

fn scripted_dial(
    reset: std::net::SocketAddr,
    dialed: &std::cell::RefCell<Vec<std::net::SocketAddr>>,
) -> impl FnMut(std::net::SocketAddr) -> std::future::Ready<io::Result<std::net::SocketAddr>> + '_ {
    move |address| {
        dialed.borrow_mut().push(address);
        std::future::ready(if address == reset {
            Err(io::ErrorKind::ConnectionReset.into())
        } else {
            Ok(address)
        })
    }
}

/// A reset connect ends the Firefox recipe's attempt at the first address,
/// before its backup starts, as only a refusal or timeout moves Firefox on,
/// while the Chromium recipe's racing and the default sequential selection
/// try the next one.
#[tokio::test(flavor = "current_thread")]
async fn a_reset_connect_stops_firefox_at_the_first_address_but_not_chromium() -> TestResult {
    let first: std::net::SocketAddr = "192.0.2.1:443".parse()?;
    let second: std::net::SocketAddr = "192.0.2.2:443".parse()?;

    let TcpAddressSelection::Backup(backup) =
        phantom_profile::firefox::v157_tcp().address_selection
    else {
        return Err("the Firefox recipe has no backup connection".into());
    };
    let plan = super::backup_connection::Plan {
        family: None,
        known_family_backup_timeout: backup.known_family_backup_timeout,
    };
    let dialed = std::cell::RefCell::new(Vec::new());
    let mut dial = scripted_dial(first, &dialed);
    let attempt = super::backup_connection::connect(
        vec![first, second],
        plan,
        std::future::pending::<()>(),
        |address, _timeout| dial(address),
        std::time::Instant::now(),
    );
    let error = match attempt.await {
        Ok(won) => return Err(format!("connected to {}", won.connected.address).into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    assert_eq!(*dialed.borrow(), [first]);

    let dialed = std::cell::RefCell::new(Vec::new());
    let address = connect_sequentially(
        vec![first, second],
        TcpAddressAdvance::AfterAnyFailure,
        scripted_dial(first, &dialed),
    )
    .await?;
    assert_eq!(address, second);
    assert_eq!(*dialed.borrow(), [first, second]);

    assert!(matches!(
        chromium::v154_tcp().address_selection,
        TcpAddressSelection::Racing(_)
    ));
    let dialed = std::cell::RefCell::new(Vec::new());
    let address = race(
        vec![first, second],
        std::future::pending::<()>(),
        scripted_dial(first, &dialed),
    )
    .await?;
    assert_eq!(address, second);
    assert_eq!(*dialed.borrow(), [first, second]);
    Ok(())
}
