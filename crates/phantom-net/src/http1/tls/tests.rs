use std::{
    error::Error,
    future::Future,
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Waker},
};

use http_body_util::BodyExt;
use phantom_profile::{
    CipherSuite, ClientHelloExtensionOrder, NamedGroup, SignatureScheme, TlsSettings, TlsVersion,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, duplex},
    net::{TcpSocket, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream as BoringStream;
use tracing::{Dispatch, instrument::WithSubscriber};

use super::{Http1TlsConnector, Http1TlsError, ServerAuthentication};
use crate::tls::test_support::{
    TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn, TouchCountingStream,
    accept_tls, loopback_listener,
};
use crate::tracing_test::{OutcomeSubscriber, poll_once_then_drop};
use crate::{
    http1::{AbsoluteForm, Http1UpgradeOutcome, OriginForm, RequestHeader},
    proxy::{HttpConnectError, HttpsProxyConnector},
};

async fn bounded_tls_test<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    match timeout(TEST_TIMEOUT, future).await {
        Ok(result) => result,
        Err(_) => Err("HTTP/1-over-TLS test exceeded its absolute deadline".into()),
    }
}

#[tokio::test]
async fn dropping_tls_response_head_future_records_cancelled_once() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let subscriber = OutcomeSubscriber::default();
    let (client, _server) = duplex(64 * 1024);
    let pending = poll_once_then_drop(
        connector.send_get(
            client,
            TEST_SERVER_NAME,
            OriginForm::parse("/")?,
            vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
        ),
        subscriber.clone(),
    )
    .await;
    if !pending {
        return Err("HTTP/1-over-TLS response-head future completed before cancellation".into());
    }

    assert_eq!(
        subscriber.outcomes_for("http1.tls.response_head"),
        ["cancelled"]
    );
    assert_eq!(subscriber.outcomes_for("tls.handshake"), ["cancelled"]);
    Ok(())
}

#[tokio::test]
async fn streams_ordered_http1_over_trusted_tls() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let (release_later, wait_for_release) = oneshot::channel();
        let server_task = tokio::spawn(async move {
            let (mut stream, sni) = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nfirst")
                .await?;
            stream.flush().await?;
            wait_for_release.await.map_err(io::Error::other)?;
            stream.write_all(b"later").await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((sni, request))
        });

        let connector = test_connector(&identity)?;
        let tcp = TcpStream::connect(address).await?;
        let response = connector
            .send_get(
                tcp,
                TEST_SERVER_NAME,
                OriginForm::parse("/resource?item=1")?,
                vec![
                    RequestHeader::new("Host", TEST_SERVER_NAME),
                    RequestHeader::new("X-First", "one"),
                    RequestHeader::new("x-repeat", "alpha"),
                    RequestHeader::new("X-Repeat", "beta"),
                ],
            )
            .await?;
        assert_eq!(response.status(), 200);

        let mut body = response.into_body();
        let visible = loop {
            let data = body
                .frame()
                .await
                .ok_or("body ended before any data was observable")??
                .into_data()
                .map_err(|_| "expected a data frame")?;
            if !data.is_empty() {
                break data;
            }
        };

        release_later
            .send(())
            .map_err(|_| "server stopped before later body release")?;
        let remaining = body.collect().await?.to_bytes();
        let mut complete = visible.to_vec();
        complete.extend_from_slice(&remaining);
        assert_eq!(complete, b"firstlater");

        let (sni, request) = server_task.await??;
        assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
        assert_eq!(
            request,
            b"GET /resource?item=1 HTTP/1.1\r\nHost: server.phantom.test\r\nX-First: one\r\nx-repeat: alpha\r\nX-Repeat: beta\r\n\r\n"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rejects_h2_before_writing_http1_bytes() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let server_task = tokio::spawn(async move {
            let (mut stream, sni) = accept_tls(listener, acceptor).await?;
            let mut plaintext = Vec::new();
            if let Err(error) = stream.read_to_end(&mut plaintext).await
                && !plaintext.is_empty()
            {
                return Err(error.into());
            }
            Ok::<_, Box<dyn Error + Send + Sync>>((sni, plaintext))
        });

        let connector = test_connector(&identity)?;
        let tcp = TcpStream::connect(address).await?;
        let subscriber = OutcomeSubscriber::default();
        let result = connector
            .send_get(
                tcp,
                TEST_SERVER_NAME,
                OriginForm::parse("/")?,
                vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
            )
            .with_subscriber(Dispatch::new(subscriber.clone()))
            .await;
        let error = match result {
            Ok(_) => return Err("h2 selection unexpectedly entered HTTP/1".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            Http1TlsError::UnsupportedAlpn { ref selected } if selected.as_ref() == b"h2"
        ));
        assert_eq!(
            subscriber.outcomes_for("http1.tls.response_head"),
            ["unsupported_alpn"]
        );

        let (sni, plaintext) = server_task.await??;
        assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
        assert!(plaintext.is_empty(), "HTTP/1 bytes followed h2 selection");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn no_negotiated_alpn_proceeds_as_http1() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::None)?;
        let server_task = tokio::spawn(async move {
            let (mut stream, sni) = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((sni, request))
        });

        let connector = test_connector(&identity)?;
        let tcp = TcpStream::connect(address).await?;
        let response = connector
            .send_get(
                tcp,
                TEST_SERVER_NAME,
                OriginForm::parse("/health")?,
                vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
            )
            .await?;
        assert_eq!(response.status(), 204);
        assert!(response.into_body().collect().await?.to_bytes().is_empty());

        let (sni, request) = server_task.await??;
        assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
        assert_eq!(
            request,
            b"GET /health HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn disabled_authentication_accepts_untrusted_name_mismatch_and_preserves_sni()
-> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let server_task = tokio::spawn(async move {
            let (_stream, sni) = accept_tls(listener, acceptor).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(sni)
        });

        let connector = Http1TlsConnector::new_with_server_authentication(
            &tls_settings(),
            ServerAuthentication::Disabled,
        )?;
        let tcp = TcpStream::connect(address).await?;
        let connection = connector.connect(tcp, "mismatch.phantom.test").await?;
        drop(connection);

        assert_eq!(
            server_task.await??.as_deref(),
            Some("mismatch.phantom.test")
        );
        Ok(())
    })
    .await
}

#[test]
fn webpki_is_the_default_server_authentication_policy() {
    assert_eq!(
        ServerAuthentication::default(),
        ServerAuthentication::WebPki
    );
}

#[tokio::test]
async fn invalid_request_never_touches_tls_stream() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let touches = Arc::new(AtomicUsize::new(0));
        let (client, _server) = duplex(128);
        let stream = TouchCountingStream::new(client, Arc::clone(&touches));
        let subscriber = OutcomeSubscriber::default();

        let result = connector
            .send_get(
                stream,
                TEST_SERVER_NAME,
                OriginForm::parse("/")?,
                Vec::new(),
            )
            .with_subscriber(Dispatch::new(subscriber.clone()))
            .await;
        assert!(matches!(result, Err(Http1TlsError::Http1(_))));
        assert_eq!(touches.load(Ordering::SeqCst), 0);
        assert_eq!(
            subscriber.outcomes_for("http1.tls.response_head"),
            ["http_preparation_error"]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn direct_preparation_failure_has_tls_wrapper_outcome() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let subscriber = OutcomeSubscriber::default();

    let result = connector
        .send_get_direct(
            "127.0.0.1",
            9,
            TEST_SERVER_NAME,
            OriginForm::parse("/")?,
            Vec::new(),
        )
        .with_subscriber(Dispatch::new(subscriber.clone()))
        .await;
    assert!(matches!(result, Err(Http1TlsError::Http1(_))));
    assert_eq!(
        subscriber.outcomes_for("http1.tls.response_head"),
        ["http_preparation_error"]
    );
    Ok(())
}

#[test]
fn direct_without_runtime_has_tls_wrapper_outcome() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let subscriber = OutcomeSubscriber::default();
    let future = connector
        .send_get_direct(
            "127.0.0.1",
            9,
            TEST_SERVER_NAME,
            OriginForm::parse("/")?,
            vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
        )
        .with_subscriber(Dispatch::new(subscriber.clone()));
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());

    let error = match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(Err(error)) => error,
        std::task::Poll::Ready(Ok(_)) => {
            return Err("direct request completed outside a Tokio runtime".into());
        }
        std::task::Poll::Pending => {
            return Err("direct request waited outside a Tokio runtime".into());
        }
    };
    assert!(matches!(error, Http1TlsError::RuntimeUnavailable));
    assert_eq!(
        subscriber.outcomes_for("http1.tls.response_head"),
        ["runtime_unavailable"]
    );
    Ok(())
}

#[tokio::test]
async fn plaintext_direct_connection_is_reusable_without_tls() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let subscriber = OutcomeSubscriber::default();
        let (address, listener) = loopback_listener().await?;
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let first = read_plaintext_head(&mut stream).await?;
            stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
            let second = read_plaintext_head(&mut stream).await?;
            stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((first, second))
        });

        let connection = connector
            .connect_plaintext_direct("127.0.0.1", address.port())
            .with_subscriber(Dispatch::new(subscriber.clone()))
            .await?;
        for target in ["/first", "/second"] {
            let response = connection
                .send_get(
                    OriginForm::parse(target)?,
                    vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
                )
                .await?;
            assert_eq!(response.status(), 204);
            assert!(response.into_body().collect().await?.to_bytes().is_empty());
        }

        let (first, second) = server_task.await??;
        assert_eq!(
            first,
            b"GET /first HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n"
        );
        assert_eq!(
            second,
            b"GET /second HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n"
        );
        assert_eq!(subscriber.outcomes_for("http1.direct.connect"), ["ok"]);
        assert!(
            subscriber.outcomes_for("http1.tls.connect").is_empty(),
            "plaintext direct connection emitted a TLS wrapper outcome"
        );
        Ok(())
    })
    .await
}

#[test]
fn plaintext_direct_without_runtime_is_runtime_unavailable() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let subscriber = OutcomeSubscriber::default();
    let future = connector
        .connect_plaintext_direct("127.0.0.1", 9)
        .with_subscriber(Dispatch::new(subscriber.clone()));
    let mut future = std::pin::pin!(future);
    let mut context = Context::from_waker(Waker::noop());

    let error = match future.as_mut().poll(&mut context) {
        std::task::Poll::Ready(Err(error)) => error,
        std::task::Poll::Ready(Ok(_)) => {
            return Err("plaintext direct connection completed outside a Tokio runtime".into());
        }
        std::task::Poll::Pending => {
            return Err("plaintext direct connection waited outside a Tokio runtime".into());
        }
    };
    assert!(matches!(error, Http1TlsError::RuntimeUnavailable));
    assert_eq!(
        subscriber.outcomes_for("http1.direct.connect"),
        ["runtime_unavailable"]
    );
    Ok(())
}

#[tokio::test]
async fn plaintext_direct_connect_failure_is_not_a_proxy_error() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let subscriber = OutcomeSubscriber::default();
    // Bound but never listening: connects are refused, and the port stays
    // ours, so no other socket can take it while the test runs.
    let reserved = TcpSocket::new_v4()?;
    reserved.bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let address = reserved.local_addr()?;

    let result = connector
        .connect_plaintext_direct("127.0.0.1", address.port())
        .with_subscriber(Dispatch::new(subscriber.clone()))
        .await;
    let error = match result {
        Err(error) => error,
        Ok(_) => return Err("closed loopback port unexpectedly accepted a connection".into()),
    };
    assert!(matches!(error, Http1TlsError::Connect(_)));
    assert_eq!(
        subscriber.outcomes_for("http1.direct.connect"),
        ["connect_error"]
    );
    Ok(())
}

#[tokio::test]
async fn plaintext_direct_upgrade_preserves_request_and_session_bytes() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let subscriber = OutcomeSubscriber::default();
        let (address, listener) = loopback_listener().await?;
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_plaintext_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Upgrade: websocket\r\n\
                      Connection: Upgrade\r\n\r\n\
                      server-frame",
                )
                .await?;
            stream.flush().await?;
            let mut client_frame = [0_u8; 12];
            stream.read_exact(&mut client_frame).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((request, client_frame))
        });

        let outcome = connector
            .upgrade_get_plaintext_direct(
                "127.0.0.1",
                address.port(),
                OriginForm::parse("/socket?encoding=json")?,
                vec![
                    RequestHeader::new("Host", "127.0.0.1"),
                    RequestHeader::new("Connection", "Upgrade"),
                    RequestHeader::new("Upgrade", "websocket"),
                    RequestHeader::new("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
                    RequestHeader::new("Sec-WebSocket-Version", "13"),
                    RequestHeader::new("X-Order", "last"),
                ],
            )
            .with_subscriber(Dispatch::new(subscriber.clone()))
            .await?;
        let Http1UpgradeOutcome::Upgraded(response) = outcome else {
            return Err("101 response was not upgraded".into());
        };
        assert_eq!(response.status(), 101);

        let mut upgraded = response.into_body();
        let mut server_frame = [0_u8; 12];
        upgraded.read_exact(&mut server_frame).await?;
        assert_eq!(&server_frame, b"server-frame");
        upgraded.write_all(b"client-frame").await?;
        upgraded.flush().await?;

        let (request, client_frame) = server_task.await??;
        assert_eq!(
            request,
            b"GET /socket?encoding=json HTTP/1.1\r\n\
              Host: 127.0.0.1\r\n\
              Connection: Upgrade\r\n\
              Upgrade: websocket\r\n\
              Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
              Sec-WebSocket-Version: 13\r\n\
              X-Order: last\r\n\r\n"
        );
        assert_eq!(&client_frame, b"client-frame");
        assert_eq!(
            subscriber.outcomes_for("http1.direct.upgrade_response_head"),
            ["upgraded"]
        );
        assert!(
            subscriber
                .outcomes_for("http1.tls.upgrade_response_head")
                .is_empty(),
            "plaintext Upgrade emitted a TLS wrapper outcome"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn plaintext_forward_upgrade_preserves_absolute_form_and_coalesced_bytes() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let request = read_plaintext_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Upgrade: websocket\r\n\
                      Connection: Upgrade\r\n\r\n\
                      proxy-frame",
                )
                .await?;
            stream.flush().await?;
            let mut client_frame = [0_u8; 12];
            stream.read_exact(&mut client_frame).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((request, client_frame))
        });

        let outcome = connector
            .upgrade_get_forward_proxy(
                "127.0.0.1",
                address.port(),
                AbsoluteForm::parse("http://origin.phantom.test/socket?encoding=json")?,
                vec![
                    RequestHeader::new("Host", "origin.phantom.test"),
                    RequestHeader::new("Connection", "Upgrade"),
                    RequestHeader::new("Upgrade", "websocket"),
                    RequestHeader::new("X-Order", "last"),
                ],
            )
            .await?;
        let Http1UpgradeOutcome::Upgraded(response) = outcome else {
            return Err("forward proxy 101 response was not upgraded".into());
        };
        let mut upgraded = response.into_body();
        let mut proxy_frame = [0_u8; 11];
        upgraded.read_exact(&mut proxy_frame).await?;
        assert_eq!(&proxy_frame, b"proxy-frame");
        upgraded.write_all(b"client-frame").await?;
        upgraded.flush().await?;

        let (request, client_frame) = server_task.await??;
        assert_eq!(
            request,
            b"GET http://origin.phantom.test/socket?encoding=json HTTP/1.1\r\n\
              Host: origin.phantom.test\r\n\
              Connection: Upgrade\r\n\
              Upgrade: websocket\r\n\
              X-Order: last\r\n\r\n"
        );
        assert_eq!(&client_frame, b"client-frame");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn https_forward_upgrade_uses_proxy_tls_and_preserves_absolute_form() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let server_task = tokio::spawn(async move {
            let (mut stream, sni) = accept_tls(listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 101 Switching Protocols\r\n\
                      Upgrade: websocket\r\n\
                      Connection: Upgrade\r\n\r\n\
                      tls-proxy-frame",
                )
                .await?;
            stream.flush().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((sni, request))
        });

        let connector = test_connector(&identity)?;
        let proxy_connector = test_proxy_connector(&identity)?;
        let outcome = connector
            .upgrade_get_https_forward_proxy(
                &proxy_connector,
                "127.0.0.1",
                address.port(),
                TEST_SERVER_NAME,
                AbsoluteForm::parse("https://origin.phantom.test/socket")?,
                vec![
                    RequestHeader::new("Host", "origin.phantom.test"),
                    RequestHeader::new("Connection", "Upgrade"),
                    RequestHeader::new("Upgrade", "websocket"),
                ],
            )
            .await?;
        let Http1UpgradeOutcome::Upgraded(response) = outcome else {
            return Err("HTTPS forward proxy 101 response was not upgraded".into());
        };
        let mut upgraded = response.into_body();
        let mut proxy_frame = [0_u8; 15];
        upgraded.read_exact(&mut proxy_frame).await?;
        assert_eq!(&proxy_frame, b"tls-proxy-frame");

        let (sni, request) = server_task.await??;
        assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
        assert_eq!(
            request,
            b"GET https://origin.phantom.test/socket HTTP/1.1\r\n\
              Host: origin.phantom.test\r\n\
              Connection: Upgrade\r\n\
              Upgrade: websocket\r\n\r\n"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn https_forward_proxy_uses_dns_sni_and_accepts_http1_alpn() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let server_task = tokio::spawn(async move {
            let (mut stream, sni) = accept_tls(listener, acceptor).await?;
            let selected_alpn = stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec);
            let request = read_head(&mut stream).await?;
            stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((sni, selected_alpn, request))
        });

        let connector = test_connector(&identity)?;
        let proxy_connector = test_proxy_connector(&identity)?;
        let subscriber = OutcomeSubscriber::default();
        let connection = connector
            .connect_https_forward_proxy(
                &proxy_connector,
                "127.0.0.1",
                address.port(),
                TEST_SERVER_NAME,
            )
            .with_subscriber(subscriber.dispatch())
            .await?;
        let response = connection
            .send_get(
                OriginForm::parse("/through-proxy")?,
                vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
            )
            .await?;
        assert_eq!(response.status(), 204);
        assert!(response.into_body().collect().await?.to_bytes().is_empty());

        let (sni, selected_alpn, request) = server_task.await??;
        assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
        assert_eq!(selected_alpn.as_deref(), Some(b"http/1.1".as_slice()));
        assert_eq!(
            request,
            b"GET /through-proxy HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n"
        );
        assert_eq!(subscriber.outcomes_for("http1.proxy.connect"), ["ok"]);
        assert_eq!(
            subscriber.field_values_for("http1.proxy.connect", "transport"),
            ["tls"]
        );
        assert_eq!(
            subscriber.field_values_for("http1.proxy.connect", "proxy_kind"),
            ["forward"]
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn https_forward_proxy_accepts_absent_alpn() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::None)?;
        let server_task = tokio::spawn(async move {
            let (mut stream, sni) = accept_tls(listener, acceptor).await?;
            let selected_alpn = stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec);
            let request = read_head(&mut stream).await?;
            stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>((sni, selected_alpn, request))
        });

        let connector = test_connector(&identity)?;
        let proxy_connector = test_proxy_connector(&identity)?;
        let subscriber = OutcomeSubscriber::default();
        let connection = connector
            .connect_https_forward_proxy(
                &proxy_connector,
                "127.0.0.1",
                address.port(),
                TEST_SERVER_NAME,
            )
            .with_subscriber(subscriber.dispatch())
            .await?;
        let response = connection
            .send_get(
                OriginForm::parse("/without-alpn")?,
                vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
            )
            .await?;
        assert_eq!(response.status(), 204);
        assert!(response.into_body().collect().await?.to_bytes().is_empty());

        let (sni, selected_alpn, request) = server_task.await??;
        assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
        assert_eq!(selected_alpn, None);
        assert_eq!(
            request,
            b"GET /without-alpn HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n"
        );
        assert_eq!(subscriber.outcomes_for("http1.proxy.connect"), ["ok"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn https_forward_proxy_rejects_h2_without_writing_http_bytes() -> TestResult<()> {
    bounded_tls_test(async {
        let identity = TestIdentity::generate()?;
        let (address, listener) = loopback_listener().await?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let server_task = tokio::spawn(async move {
            let (mut stream, sni) = accept_tls(listener, acceptor).await?;
            let selected_alpn = stream.ssl().selected_alpn_protocol().map(<[u8]>::to_vec);
            let mut plaintext = Vec::new();
            if let Err(error) = stream.read_to_end(&mut plaintext).await
                && !plaintext.is_empty()
            {
                return Err(error.into());
            }
            Ok::<_, Box<dyn Error + Send + Sync>>((sni, selected_alpn, plaintext))
        });

        let connector = test_connector(&identity)?;
        let proxy_connector = test_proxy_connector(&identity)?;
        let subscriber = OutcomeSubscriber::default();
        let result = connector
            .connect_https_forward_proxy(
                &proxy_connector,
                "127.0.0.1",
                address.port(),
                TEST_SERVER_NAME,
            )
            .with_subscriber(subscriber.dispatch())
            .await;
        let error = match result {
            Ok(_) => return Err("h2 proxy selection unexpectedly entered HTTP/1".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            Http1TlsError::Proxy(HttpConnectError::UnsupportedAlpn { ref selected })
                if selected.as_ref() == b"h2"
        ));
        assert_eq!(
            subscriber.outcomes_for("http1.proxy.connect"),
            ["proxy_error"]
        );
        assert_eq!(
            subscriber.field_values_for("http1.proxy.connect", "transport"),
            ["tls"]
        );
        assert_eq!(
            subscriber.field_values_for("http1.proxy.connect", "proxy_kind"),
            ["forward"]
        );

        let (sni, selected_alpn, plaintext) = server_task.await??;
        assert_eq!(sni.as_deref(), Some(TEST_SERVER_NAME));
        assert_eq!(selected_alpn.as_deref(), Some(b"h2".as_slice()));
        assert!(plaintext.is_empty(), "HTTP/1 bytes followed h2 selection");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn handshake_failure_has_tls_wrapper_outcome() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let (client, server) = duplex(4096);
    drop(server);
    let subscriber = OutcomeSubscriber::default();

    let result = connector
        .send_get(
            client,
            TEST_SERVER_NAME,
            OriginForm::parse("/")?,
            vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
        )
        .with_subscriber(Dispatch::new(subscriber.clone()))
        .await;
    assert!(matches!(result, Err(Http1TlsError::Tls(_))));
    assert_eq!(
        subscriber.outcomes_for("http1.tls.response_head"),
        ["tls_error"]
    );
    Ok(())
}

#[test]
fn rejects_h2_h3_only_settings_before_stream_io() -> TestResult<()> {
    let mut settings = tls_settings();
    settings.alpn_protocols = vec![Box::from(&b"h2"[..]), Box::from(&b"h3"[..])];

    let bundled_roots_error = match Http1TlsConnector::new(&settings) {
        Ok(_) => return Err("h2/h3-only settings built with bundled roots".into()),
        Err(error) => error,
    };
    assert!(matches!(
        bundled_roots_error,
        Http1TlsError::MissingHttp1Alpn
    ));

    let explicit_roots_error =
        match Http1TlsConnector::new_with_roots(&settings, std::iter::empty::<&[u8]>()) {
            Ok(_) => return Err("h2/h3-only settings built with explicit roots".into()),
            Err(error) => error,
        };
    assert!(matches!(
        explicit_roots_error,
        Http1TlsError::MissingHttp1Alpn
    ));
    Ok(())
}

fn tls_settings() -> TlsSettings {
    TlsSettings {
        min_version: TlsVersion::Tls12,
        max_version: TlsVersion::Tls12,
        cipher_suites: vec![CipherSuite::EcdheEcdsaAes128GcmSha256],
        groups: vec![NamedGroup::X25519, NamedGroup::Secp256r1],
        key_shares: Vec::new(),
        signature_schemes: vec![SignatureScheme::EcdsaSecp256r1Sha256],
        delegated_credential_schemes: Vec::new(),
        alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
        alps: None,
        certificate_compression: Vec::new(),
        session_tickets: true,
        session_tickets_per_origin: 2,
        session_ticket_extension_when_resuming: true,
        record_size_limit: None,
        requested_trust_anchor_ids: None,
        grease: false,
        grease_signature_algorithms: false,
        extension_order: ClientHelloExtensionOrder::BackendDefault,
        ech_grease: false,
        ech_grease_payload_length: None,
        ech_grease_aeads: Vec::new(),
        ech_from_https_records: false,
        request_ocsp_staple: false,
        request_signed_certificate_timestamps: false,
        aes_hardware: true,
    }
}

fn test_connector(identity: &TestIdentity) -> TestResult<Http1TlsConnector> {
    Ok(Http1TlsConnector::new_with_roots(
        &tls_settings(),
        [identity.root_der()],
    )?)
}

fn test_proxy_connector(identity: &TestIdentity) -> TestResult<HttpsProxyConnector> {
    Ok(HttpsProxyConnector::new_with_additional_roots(
        &tls_settings(),
        [identity.root_der()],
    )?)
}

async fn read_head(stream: &mut BoringStream<TcpStream>) -> io::Result<Vec<u8>> {
    read_plaintext_head(stream).await
}

async fn read_plaintext_head<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await?;
        bytes.push(byte[0]);
    }
    Ok(bytes)
}
