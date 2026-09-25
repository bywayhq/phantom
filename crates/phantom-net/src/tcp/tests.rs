use std::{io, time::Duration};

use phantom_profile::{TcpAddressRacing, TcpKeepalive, TcpSettings};
use socket2::SockRef;
use tokio::net::TcpListener;

use super::{
    KeepaliveSupport, address_racing::race, check_host_support, check_keepalive_support, connect,
    connect_address,
};

mod paths;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const KEEPALIVE: Duration = Duration::from_secs(45);

fn chromium_like() -> TcpSettings {
    TcpSettings {
        nodelay: true,
        keepalive: Some(TcpKeepalive {
            idle: KEEPALIVE,
            interval: Some(KEEPALIVE),
        }),
        address_racing: Some(TcpAddressRacing {
            fallback_delay: Duration::from_millis(300),
        }),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn connected_socket_carries_requested_options() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let stream = connect("127.0.0.1", port, chromium_like(), None).await?;
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
        connect_address(address, settings)
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

    let stream = connect("127.0.0.1", port, chromium_like(), None).await?;

    assert_eq!(stream.peer_addr()?, listener.local_addr()?);
    Ok(())
}

fn keepalive(interval: Option<Duration>) -> TcpSettings {
    TcpSettings {
        nodelay: true,
        keepalive: Some(TcpKeepalive {
            idle: KEEPALIVE,
            interval,
        }),
        address_racing: None,
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
        keepalive: None,
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
    let settings = TcpSettings {
        nodelay: false,
        keepalive: None,
        address_racing: None,
    };

    let stream = connect("127.0.0.1", port, settings, None).await?;
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
        keepalive: Some(TcpKeepalive {
            idle: Duration::ZERO,
            interval: None,
        }),
        address_racing: None,
    };

    let error = match connect("127.0.0.1", port, settings, None).await {
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
        keepalive: Some(TcpKeepalive {
            idle: KEEPALIVE,
            interval: None,
        }),
        address_racing: None,
    };

    let error = match connect("127.0.0.1", port, settings, None).await {
        Ok(_) => return Err("keepalive without an interval was applied".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    Ok(())
}
