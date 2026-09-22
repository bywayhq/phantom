use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Waker},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, duplex},
    net::TcpListener,
    time::timeout,
};
use tracing::instrument::WithSubscriber;

use crate::{
    proxy::socks5::{connect_local_to_addresses_with_auth, connect_socks5_tunnel_with_auth},
    proxy::{
        Socks5Auth, Socks5ErrorKind, connect_socks5_tunnel_direct_with_auth,
        connect_socks5_tunnel_local_with_auth,
    },
    tls::test_support::TouchCountingStream,
    tracing_test::OutcomeSubscriber,
};

use super::{TARGET_HOST, TARGET_PORT, TestResult};

#[tokio::test]
async fn username_password_auth_precedes_connect_and_returns_raw_stream() -> TestResult {
    const USERNAME: &str = "proxy-user";
    const PASSWORD: &str = "proxy-password";

    let (client, mut proxy) = duplex(4096);
    let server = tokio::spawn(async move {
        expect_password_greeting(&mut proxy).await?;
        proxy.write_all(&[0x05, 0x02]).await?;
        expect_password_auth(&mut proxy, USERNAME, PASSWORD).await?;
        proxy.write_all(&[0x01, 0x00]).await?;
        let request = super::read_domain_request(&mut proxy).await?;
        proxy
            .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x20, 0xfb])
            .await?;
        let mut payload = [0_u8; 4];
        proxy.read_exact(&mut payload).await?;
        Ok::<_, std::io::Error>((request, payload))
    });

    let auth = Socks5Auth::UsernamePassword {
        username: USERNAME,
        password: PASSWORD,
    };
    let mut tunnel =
        connect_socks5_tunnel_with_auth(client, TARGET_HOST, TARGET_PORT, auth).await?;
    tunnel.write_all(b"ping").await?;

    let (request, payload) = server.await??;
    assert_eq!(
        request,
        [
            &[0x05, 0x01, 0x00, 0x03, TARGET_HOST.len() as u8][..],
            TARGET_HOST.as_bytes(),
            &TARGET_PORT.to_be_bytes(),
        ]
        .concat()
    );
    assert_eq!(&payload, b"ping");
    Ok(())
}

#[tokio::test]
async fn password_rejection_is_typed_traced_and_sends_no_connect() -> TestResult {
    const USERNAME: &str = "private-user";
    const PASSWORD: &str = "private-password";

    OutcomeSubscriber::install_dynamic_callsite_fallback();
    let (client, mut proxy) = duplex(1024);
    let server = tokio::spawn(async move {
        expect_password_greeting(&mut proxy).await?;
        proxy.write_all(&[0x05, 0x02]).await?;
        expect_password_auth(&mut proxy, USERNAME, PASSWORD).await?;
        proxy.write_all(&[0x01, 0x01]).await?;
        let mut remaining = Vec::new();
        proxy.read_to_end(&mut remaining).await?;
        Ok::<_, std::io::Error>(remaining)
    });
    let subscriber = OutcomeSubscriber::default();
    let auth = Socks5Auth::UsernamePassword {
        username: USERNAME,
        password: PASSWORD,
    };

    let error = match connect_socks5_tunnel_with_auth(client, TARGET_HOST, TARGET_PORT, auth)
        .with_subscriber(subscriber.dispatch())
        .await
    {
        Ok(_) => return Err("rejected SOCKS5 authentication succeeded".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), Socks5ErrorKind::Authentication);
    assert_eq!(error.to_string(), "SOCKS5 proxy authentication failed");
    let diagnostics = format!("{error:?} {error}");
    assert!(!diagnostics.contains(USERNAME));
    assert!(!diagnostics.contains(PASSWORD));
    assert_eq!(subscriber.outcomes_for("proxy.socks5"), ["error"]);
    assert_eq!(
        subscriber.error_kinds_for("proxy.socks5"),
        ["authentication_error"]
    );
    assert!(server.await??.is_empty(), "CONNECT followed rejected auth");
    Ok(())
}

#[tokio::test]
async fn invalid_authentication_fails_before_stream_or_proxy_io() -> TestResult {
    let long_username = "u".repeat(256);
    let long_password = "p".repeat(256);
    for auth in [
        Socks5Auth::UsernamePassword {
            username: "",
            password: "password",
        },
        Socks5Auth::UsernamePassword {
            username: "username",
            password: "",
        },
        Socks5Auth::UsernamePassword {
            username: &long_username,
            password: "password",
        },
        Socks5Auth::UsernamePassword {
            username: "username",
            password: &long_password,
        },
    ] {
        let (client, _proxy) = duplex(1024);
        let touches = Arc::new(AtomicUsize::new(0));
        let stream = TouchCountingStream::new(client, touches.clone());

        let error =
            match connect_socks5_tunnel_with_auth(stream, TARGET_HOST, TARGET_PORT, auth).await {
                Ok(_) => return Err("invalid SOCKS5 authentication was accepted".into()),
                Err(error) => error,
            };

        assert_eq!(error.kind(), Socks5ErrorKind::InvalidAuthentication);
        assert_eq!(touches.load(Ordering::SeqCst), 0);
    }

    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let error = match connect_socks5_tunnel_direct_with_auth(
        "127.0.0.1",
        address.port(),
        TARGET_HOST,
        TARGET_PORT,
        Socks5Auth::UsernamePassword {
            username: "",
            password: "password",
        },
    )
    .await
    {
        Ok(_) => return Err("invalid authentication opened a proxy connection".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), Socks5ErrorKind::InvalidAuthentication);
    assert!(matches!(
        listener.accept(),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
    ));
    Ok(())
}

#[test]
fn invalid_authentication_precedes_local_dns_and_runtime_checks() -> TestResult {
    let mut future = Box::pin(connect_socks5_tunnel_local_with_auth(
        "proxy.invalid",
        1080,
        "target.invalid",
        TARGET_PORT,
        Socks5Auth::UsernamePassword {
            username: "username",
            password: "",
        },
    ));
    let mut context = Context::from_waker(Waker::noop());

    let result = match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(result) => result,
        std::task::Poll::Pending => return Err("invalid auth reached local DNS".into()),
    };
    let error = match result {
        Ok(_) => return Err("invalid SOCKS5 authentication was accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), Socks5ErrorKind::InvalidAuthentication);
    Ok(())
}

#[test]
fn authentication_debug_is_redacted() {
    let auth = Socks5Auth::UsernamePassword {
        username: "private-user",
        password: "private-password",
    };
    let debug = format!("{auth:?}");

    assert_eq!(debug, "UsernamePassword(<redacted>)");
    assert!(!debug.contains("private-user"));
    assert!(!debug.contains("private-password"));
}

#[tokio::test]
async fn local_fallback_replays_authentication_for_each_target() -> TestResult {
    const USERNAME: &str = "fallback-user";
    const PASSWORD: &str = "fallback-password";

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let first = SocketAddr::from(([192, 0, 2, 1], TARGET_PORT));
    let second = SocketAddr::from(([198, 51, 100, 2], TARGET_PORT));
    let server = tokio::spawn(async move {
        let mut observed = Vec::new();
        for reply in [0x04, 0x00] {
            let (mut stream, _) = listener.accept().await?;
            expect_password_greeting(&mut stream).await?;
            stream.write_all(&[0x05, 0x02]).await?;
            expect_password_auth(&mut stream, USERNAME, PASSWORD).await?;
            stream.write_all(&[0x01, 0x00]).await?;
            observed.push(super::read_ip_request(&mut stream).await?);
            stream
                .write_all(&[0x05, reply, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await?;
        }
        Ok::<_, std::io::Error>(observed)
    });
    let auth = Socks5Auth::UsernamePassword {
        username: USERNAME,
        password: PASSWORD,
    };

    let tunnel = connect_local_to_addresses_with_auth(
        None,
        "127.0.0.1",
        address.port(),
        [first, second],
        auth,
    )
    .await?;
    drop(tunnel);

    assert_eq!(server.await??, [first, second]);
    Ok(())
}

#[tokio::test]
async fn local_fallback_stops_after_authentication_failure() -> TestResult {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let first = SocketAddr::from(([192, 0, 2, 1], TARGET_PORT));
    let second = SocketAddr::from(([198, 51, 100, 2], TARGET_PORT));
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        expect_password_greeting(&mut stream).await?;
        stream.write_all(&[0x05, 0x02]).await?;
        expect_password_auth(&mut stream, "user", "password").await?;
        stream.write_all(&[0x01, 0x01]).await?;
        stream.shutdown().await?;
        let retried = timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_ok();
        Ok::<_, std::io::Error>(retried)
    });
    let auth = Socks5Auth::UsernamePassword {
        username: "user",
        password: "password",
    };

    let error = match connect_local_to_addresses_with_auth(
        None,
        "127.0.0.1",
        address.port(),
        [first, second],
        auth,
    )
    .await
    {
        Ok(_) => return Err("authentication failure was retried".into()),
        Err(error) => error,
    };

    assert_eq!(error.kind(), Socks5ErrorKind::Authentication);
    assert!(
        !server.await??,
        "authentication failure opened another tunnel"
    );
    Ok(())
}

async fn expect_password_greeting(stream: &mut (impl AsyncRead + Unpin)) -> std::io::Result<()> {
    let mut greeting = [0_u8; 4];
    stream.read_exact(&mut greeting).await?;
    if greeting == [0x05, 0x02, 0x00, 0x02] {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "unexpected authenticated SOCKS5 greeting",
        ))
    }
}

async fn expect_password_auth(
    stream: &mut (impl AsyncRead + Unpin),
    username: &str,
    password: &str,
) -> std::io::Result<()> {
    let mut request = vec![0_u8; username.len() + password.len() + 3];
    stream.read_exact(&mut request).await?;
    let expected = [
        &[0x01, username.len() as u8][..],
        username.as_bytes(),
        &[password.len() as u8],
        password.as_bytes(),
    ]
    .concat();
    if request == expected {
        Ok(())
    } else {
        Err(std::io::Error::other(
            "unexpected SOCKS5 username/password request",
        ))
    }
}
