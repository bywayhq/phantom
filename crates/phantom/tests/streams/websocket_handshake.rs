//! WebSocket handshake timeout and caller-enabled handshake retry.
//!
//! Each timeout test stalls one step of the opening on a loopback peer and
//! checks that `connect` fails with the handshake timeout. Each retry test
//! counts the connections the peer saw.

use crate::support::tls as tls_support;
use crate::support::websocket as websocket_support;

use std::{
    error::Error,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::Response;
use phantom::{
    AddressResolver, Client, HttpProtocol, HttpProxy, Route, Socks5Proxy, TimeoutPhase,
    WebSocketError, WebSocketErrorKind, WebSocketRequestBuilder, WebSocketRetryPolicy,
    profile::{ClientProfile, Http2PseudoHeader, WebSocketSettings, chromium},
};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};

use tls_support::{
    H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls, client_builder, read_head, tls_settings,
};
use websocket_support::{bounded, header_value, websocket_accept};

const LIMIT: Duration = Duration::from_millis(200);

/// Accepts one connection and holds it open without answering.
fn hold_one_connection(listener: TcpListener) -> JoinHandle<TestResult<()>> {
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        sleep(Duration::from_secs(10)).await;
        drop(stream);
        Ok(())
    })
}

/// Connects, expects the handshake timeout, and checks that it fired at the
/// limit rather than much later.
async fn expect_handshake_timeout(
    builder: WebSocketRequestBuilder,
    protocol: Option<HttpProtocol>,
) -> TestResult<()> {
    let started = Instant::now();
    let error = match builder.handshake_timeout(Some(LIMIT)).connect().await {
        Ok(_) => return Err("stalled opening handshake succeeded".into()),
        Err(error) => error,
    };
    let elapsed = started.elapsed();
    assert_eq!(error.kind(), WebSocketErrorKind::Timeout, "{error}");
    assert_eq!(
        error.timeout_phase(),
        Some(TimeoutPhase::WebSocketHandshake)
    );
    assert!(elapsed >= LIMIT, "timed out early after {elapsed:?}");
    assert!(
        elapsed < Duration::from_secs(3),
        "timed out late after {elapsed:?}"
    );
    let source = std::error::Error::source(&error).ok_or("timeout error has no source")?;
    let source = source
        .downcast_ref::<phantom::RequestError>()
        .ok_or("timeout source is not a RequestError")?;
    assert_eq!(source.protocol(), protocol);
    Ok(())
}

fn http2_profile() -> ClientProfile {
    let mut http2 = chromium::v154_http2();
    http2.extended_connect_pseudo_header_order = Some(vec![
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Protocol,
        Http2PseudoHeader::Authority,
        Http2PseudoHeader::Scheme,
        Http2PseudoHeader::Path,
    ]);
    ClientProfile::new(tls_settings()).with_http2(http2)
}

fn http2_client(identity: &TestIdentity) -> TestResult<Client> {
    Ok(Client::builder(http2_profile())
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

/// A resolver that fails its first `failures` lookups, then answers
/// loopback, and counts every lookup.
fn flaky_resolver(failures: usize, lookups: &Arc<AtomicUsize>) -> AddressResolver {
    let lookups = Arc::clone(lookups);
    AddressResolver::from_fn(move |_host| {
        let lookup = lookups.fetch_add(1, Ordering::SeqCst);
        async move {
            if lookup < failures {
                Err(io::Error::new(io::ErrorKind::NotFound, "lookup failed"))
            } else {
                Ok(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)])
            }
        }
    })
}

fn two_retries() -> WebSocketRetryPolicy {
    WebSocketRetryPolicy::connection_failures(NonZeroUsize::MIN.saturating_add(1), Duration::ZERO)
}

/// Returns an error when `listener` receives another connection soon.
async fn expect_no_further_connection(listener: &TcpListener) -> TestResult<()> {
    match timeout(Duration::from_millis(300), listener.accept()).await {
        Err(_) => Ok(()),
        Ok(_) => Err("client opened another connection after the server answered".into()),
    }
}

/// Answers one plaintext Upgrade with `101` and a valid accept value.
async fn accept_plaintext_upgrade(mut stream: TcpStream) -> TestResult<Vec<u8>> {
    let request = read_head(&mut stream).await?;
    let key = header_value(&request, "sec-websocket-key").ok_or("opening omitted its key")?;
    let accept = websocket_accept(key);
    stream
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\n\
                 Upgrade: websocket\r\n\
                 Connection: Upgrade\r\n\
                 Sec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    stream.flush().await?;
    Ok(request)
}

fn expect_error(result: Result<phantom::WebSocket, WebSocketError>) -> TestResult<WebSocketError> {
    match result {
        Ok(_) => Err("opening handshake succeeded".into()),
        Err(error) => Ok(error),
    }
}

#[tokio::test]
async fn handshake_timeout_fires_while_the_name_lookup_is_pending() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let resolver = AddressResolver::from_fn(|_host| std::future::pending());
        let client = client_builder(&identity, false)
            .dns_resolver(resolver)
            .build()?;
        expect_handshake_timeout(
            client.websocket("ws://stalled.phantom.test/")?,
            Some(HttpProtocol::Http1),
        )
        .await
    })
    .await
}

#[tokio::test]
async fn handshake_timeout_fires_while_the_tls_handshake_is_unanswered() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = hold_one_connection(listener);
        let client = client_builder(&identity, false).build()?;
        expect_handshake_timeout(
            client.websocket(&format!("wss://{address}/"))?,
            Some(HttpProtocol::Http1),
        )
        .await?;
        server.abort();
        Ok(())
    })
    .await
}

#[tokio::test]
async fn handshake_timeout_fires_while_the_upgrade_response_is_pending() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            read_head(&mut stream).await?;
            sleep(Duration::from_secs(10)).await;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let client = client_builder(&identity, false).build()?;
        expect_handshake_timeout(
            client.websocket(&format!("wss://{address}/"))?,
            Some(HttpProtocol::Http1),
        )
        .await?;
        server.abort();
        Ok(())
    })
    .await
}

#[tokio::test]
async fn handshake_timeout_fires_while_an_http_proxy_holds_the_connect() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        for protocol in [HttpProtocol::Http1, HttpProtocol::Http2] {
            let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let proxy_address = proxy.local_addr()?;
            let server = tokio::spawn(async move {
                let (mut stream, _) = proxy.accept().await?;
                read_head(&mut stream).await?;
                sleep(Duration::from_secs(10)).await;
                Ok::<_, Box<dyn Error + Send + Sync>>(())
            });
            let client = Client::builder(http2_profile())
                .add_root_certificate_der(identity.root_der.clone())
                .route(Route::http_proxy(HttpProxy::new(&format!(
                    "http://{proxy_address}"
                ))?))
                .build()?;
            expect_handshake_timeout(
                client.websocket_with_protocol(protocol, "wss://origin.phantom.test/")?,
                Some(protocol),
            )
            .await?;
            server.abort();
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn handshake_timeout_fires_while_a_socks5_proxy_holds_the_greeting() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy.local_addr()?;
        let server = hold_one_connection(proxy);
        let client = client_builder(&identity, false)
            .route(Route::socks5(Socks5Proxy::new(&format!(
                "socks5h://{proxy_address}"
            ))?))
            .build()?;
        expect_handshake_timeout(
            client.websocket("ws://origin.phantom.test/")?,
            Some(HttpProtocol::Http1),
        )
        .await?;
        server.abort();
        Ok(())
    })
    .await
}

#[tokio::test]
async fn handshake_timeout_fires_while_an_extended_connect_is_unanswered() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let mut builder = ::http2::server::Builder::new();
            builder.enable_connect_protocol();
            let mut connection = builder.handshake::<_, Bytes>(stream).await?;
            let accepted = connection.accept().await;
            // Keep the stream and connection alive without answering.
            sleep(Duration::from_secs(10)).await;
            drop(accepted);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let client = http2_client(&identity)?;
        expect_handshake_timeout(
            client.websocket_with_protocol(HttpProtocol::Http2, &format!("wss://{address}/"))?,
            Some(HttpProtocol::Http2),
        )
        .await?;
        server.abort();
        Ok(())
    })
    .await
}

#[tokio::test]
async fn handshake_timeout_covers_a_stream_on_a_pooled_http2_session() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let mut builder = ::http2::server::Builder::new();
            builder.enable_connect_protocol();
            let mut connection = builder.handshake::<_, Bytes>(stream).await?;
            let (_, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before the page request")??;
            respond.send_response(Response::builder().status(200).body(())?, true)?;
            let mut held = Vec::new();
            while let Some(accepted) = connection.accept().await {
                held.push(accepted?);
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let profile = http2_profile().with_websocket(chromium::v154_websocket());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let page = client
            .get_negotiated(&format!("https://{address}/page"))?
            .send()
            .await?;
        assert_eq!(page.status(), 200);
        drop(page);
        expect_handshake_timeout(
            client.websocket_with_profile_policy(&format!("wss://{address}/"))?,
            None,
        )
        .await?;
        server.abort();
        Ok(())
    })
    .await
}

#[tokio::test]
async fn recipe_handshake_timeout_applies_unless_the_caller_removes_it() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let settings = WebSocketSettings {
            handshake_timeout: Some(LIMIT),
            ..chromium::v154_websocket()
        };
        let profile = http2_profile().with_websocket(settings);
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = hold_one_connection(listener);
        let error = expect_error(
            client
                .websocket_with_profile_policy(&format!("ws://{address}/"))?
                .connect()
                .await,
        )?;
        assert_eq!(error.kind(), WebSocketErrorKind::Timeout);
        assert_eq!(
            error.timeout_phase(),
            Some(TimeoutPhase::WebSocketHandshake)
        );
        server.abort();

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = hold_one_connection(listener);
        let unbounded = client
            .websocket(&format!("ws://{address}/"))?
            .handshake_timeout(None)
            .connect();
        assert!(
            timeout(LIMIT * 3, unbounded).await.is_err(),
            "connect ended although the caller removed the timeout"
        );
        server.abort();
        Ok(())
    })
    .await
}

#[tokio::test]
async fn no_handshake_timeout_applies_without_a_recipe() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = hold_one_connection(listener);
        let client = client_builder(&identity, false).build()?;
        let connect = client.websocket(&format!("ws://{address}/"))?.connect();
        assert!(timeout(LIMIT * 2, connect).await.is_err());
        server.abort();
        Ok(())
    })
    .await
}

#[tokio::test]
async fn retry_opens_a_new_connection_after_a_failed_lookup() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let request = accept_plaintext_upgrade(stream).await?;
            expect_no_further_connection(&listener).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(request)
        });
        let lookups = Arc::new(AtomicUsize::new(0));
        let client = client_builder(&identity, false)
            .dns_resolver(flaky_resolver(1, &lookups))
            .build()?;

        let socket = client
            .websocket(&format!("ws://retry.phantom.test:{port}/"))?
            .retry_policy(two_retries())
            .connect()
            .await?;
        drop(socket);

        let request = server.await??;
        assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
        assert_eq!(lookups.load(Ordering::SeqCst), 2);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn retry_covers_a_failed_proxy_lookup_and_an_http2_origin() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns("origin.phantom.test")?;
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let origin_server = tokio::spawn(async move {
            let stream = accept_tls(origin, acceptor).await?;
            let mut builder = ::http2::server::Builder::new();
            builder.enable_connect_protocol();
            let mut connection = builder.handshake::<_, Bytes>(stream).await?;
            let (_, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before extended CONNECT")??;
            let _send = respond.send_response(Response::builder().status(200).body(())?, false)?;
            // Drive the connection until the client closes it.
            while connection.accept().await.is_some() {}
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_port = proxy.local_addr()?.port();
        let (connect_tx, connect_rx) = oneshot::channel();
        let proxy_server = tokio::spawn(async move {
            let (mut downstream, _) = proxy.accept().await?;
            let request = read_head(&mut downstream).await?;
            connect_tx
                .send(request)
                .map_err(|_| "test dropped the CONNECT receiver")?;
            let mut upstream = TcpStream::connect(origin_address).await?;
            downstream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            downstream.flush().await?;
            // The tunnel ends when either side goes away; how it ends is not
            // under test.
            let _ = copy_bidirectional(&mut downstream, &mut upstream).await;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let lookups = Arc::new(AtomicUsize::new(0));
        let client = Client::builder(http2_profile())
            .add_root_certificate_der(identity.root_der.clone())
            .dns_resolver(flaky_resolver(1, &lookups))
            .route(Route::http_proxy(HttpProxy::new(&format!(
                "http://proxy.phantom.test:{proxy_port}"
            ))?))
            .build()?;
        let socket = client
            .websocket_with_protocol(
                HttpProtocol::Http2,
                &format!("wss://origin.phantom.test:{}/", origin_address.port()),
            )?
            .retry_policy(two_retries())
            .connect()
            .await?;
        assert_eq!(socket.handshake_response().status(), 200);
        drop(socket);

        assert_eq!(lookups.load(Ordering::SeqCst), 2);
        let connect = connect_rx.await?;
        proxy_server.abort();
        assert!(connect.starts_with(b"CONNECT origin.phantom.test:"));
        origin_server.abort();
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_exhausted_retry_budget_returns_the_last_setup_failure() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let lookups = Arc::new(AtomicUsize::new(0));
        let client = client_builder(&identity, false)
            .dns_resolver(flaky_resolver(usize::MAX, &lookups))
            .build()?;
        let error = expect_error(
            client
                .websocket("ws://missing.phantom.test/")?
                .retry_policy(two_retries())
                .connect()
                .await,
        )?;
        assert_eq!(error.kind(), WebSocketErrorKind::Connect);
        assert_eq!(lookups.load(Ordering::SeqCst), 3);

        let lookups = Arc::new(AtomicUsize::new(0));
        let client = client_builder(&identity, false)
            .dns_resolver(flaky_resolver(usize::MAX, &lookups))
            .build()?;
        let error = expect_error(
            client
                .websocket("ws://missing.phantom.test/")?
                .connect()
                .await,
        )?;
        assert_eq!(error.kind(), WebSocketErrorKind::Connect);
        assert_eq!(
            lookups.load(Ordering::SeqCst),
            1,
            "retried without a policy"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn no_retry_follows_an_invalid_101_or_a_rejection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let answers: [(&[u8], WebSocketErrorKind); 2] = [
            (
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: websocket\r\n\
                  Connection: Upgrade\r\n\
                  Sec-WebSocket-Accept: bm90IHRoZSBhY2NlcHQgdmFsdWU=\r\n\r\n",
                WebSocketErrorKind::InvalidHandshake,
            ),
            (
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n",
                WebSocketErrorKind::HandshakeRejected,
            ),
        ];
        for (answer, kind) in answers {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                read_head(&mut stream).await?;
                stream.write_all(answer).await?;
                stream.flush().await?;
                expect_no_further_connection(&listener).await?;
                Ok::<_, Box<dyn Error + Send + Sync>>(stream)
            });
            let client = client_builder(&identity, false).build()?;
            let error = expect_error(
                client
                    .websocket(&format!("ws://{address}/"))?
                    .retry_policy(two_retries())
                    .connect()
                    .await,
            )?;
            assert_eq!(error.kind(), kind);
            drop(server.await??);
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn no_retry_follows_an_invalid_extended_connect_answer() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let stream = tls_support::accept_tls_stream(tcp, acceptor).await?;
            let mut builder = ::http2::server::Builder::new();
            builder.enable_connect_protocol();
            let mut connection = builder.handshake::<_, Bytes>(stream).await?;
            let (_, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before extended CONNECT")??;
            // A subprotocol the client did not offer fails the handshake.
            let _send = respond.send_response(
                Response::builder()
                    .status(200)
                    .header("sec-websocket-protocol", "never-offered")
                    .body(())?,
                false,
            )?;
            tokio::spawn(async move { while connection.accept().await.is_some() {} });
            expect_no_further_connection(&listener).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let client = http2_client(&identity)?;
        let error = expect_error(
            client
                .websocket_with_protocol(HttpProtocol::Http2, &format!("wss://{address}/"))?
                .retry_policy(two_retries())
                .connect()
                .await,
        )?;
        assert_eq!(error.kind(), WebSocketErrorKind::InvalidHandshake);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn no_retry_follows_a_tls_failure_or_a_handshake_timeout() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            drop(stream);
            expect_no_further_connection(&listener).await
        });
        let client = client_builder(&identity, false).build()?;
        let error = expect_error(
            client
                .websocket(&format!("wss://{address}/"))?
                .retry_policy(two_retries())
                .connect()
                .await,
        )?;
        assert_eq!(error.kind(), WebSocketErrorKind::Tls, "{error}");
        server.await??;

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address: SocketAddr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            expect_no_further_connection(&listener).await?;
            drop(stream);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });
        let error = expect_error(
            client
                .websocket(&format!("ws://{address}/"))?
                .handshake_timeout(Some(LIMIT))
                .retry_policy(two_retries())
                .connect()
                .await,
        )?;
        assert_eq!(error.kind(), WebSocketErrorKind::Timeout);
        server.await??;
        Ok(())
    })
    .await
}
