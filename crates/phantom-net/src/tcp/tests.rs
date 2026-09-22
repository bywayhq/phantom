use std::{io, time::Duration};

use phantom_profile::{TcpKeepalive, TcpSettings};
use socket2::SockRef;
use tokio::net::TcpListener;

use super::connect;

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
    }
}

#[tokio::test(flavor = "current_thread")]
async fn connected_socket_carries_requested_options() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let stream = connect("127.0.0.1", port, chromium_like()).await?;
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
async fn settings_that_ask_for_nothing_keep_os_defaults() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let settings = TcpSettings {
        nodelay: false,
        keepalive: None,
    };

    let stream = connect("127.0.0.1", port, settings).await?;
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
    };

    let error = match connect("127.0.0.1", port, settings).await {
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
    };

    let error = match connect("127.0.0.1", port, settings).await {
        Ok(_) => return Err("keepalive without an interval was applied".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), io::ErrorKind::Unsupported);
    Ok(())
}
