//! The opt-in fallback of an exact HTTP/3 request to HTTP/2 when no QUIC
//! connection could be set up.

use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use btls::ssl::SslAcceptor;
use bytes::Bytes;
use http::{Method, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use phantom::{
    Client, ConnectUdpProxy, HttpProtocol, RequestErrorKind, RequestTimeoutOverrides, ResponseInfo,
    RetryPolicy, Route, TimeoutOverride,
    profile::{ClientProfile, Http3ClientSettings, browser::chrome},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::{error::Elapsed, timeout},
};

use crate::support::h2 as h2_support;
use crate::support::h3 as h3_support;
use crate::support::shared_port;
use crate::support::tls as tls_support;
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

use h2_support::{read_frame, write_frame};
use h3_support::{client_settings, quic_server};
use tls_support::{H2_ALPN, TestIdentity, TestResult, accept_tls_stream, tls_settings};

mod deadline_contract;
mod driver_ownership;
mod socks5;
mod wire_contract;

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
/// Long enough that a connection the client should not open would arrive.
const QUIET_WINDOW: Duration = Duration::from_millis(300);

fn fallback() -> RetryPolicy {
    RetryPolicy::none().with_http2_fallback(true)
}

/// An origin that answers QUIC on a UDP port and HTTP/2 over TLS on the TCP
/// port of the same number.
struct Origin {
    port: u16,
    quic: quinn::Endpoint,
    tcp: TcpListener,
}

impl Origin {
    async fn bind(identity: &TestIdentity) -> TestResult<Self> {
        let mut last_error = None;
        for port in shared_port::candidates() {
            let quic = match quic_server(
                quic_config(identity)?,
                SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            ) {
                Ok(quic) => quic,
                Err(error) if shared_port::is_unavailable(&error) => {
                    last_error = Some(error.to_string());
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
                Ok(tcp) => return Ok(Self { port, quic, tcp }),
                Err(error) if shared_port::is_unavailable(&error) => {
                    last_error = Some(error.to_string());
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(format!(
            "no loopback port was free for both UDP and TCP; last error: {}",
            last_error.as_deref().unwrap_or("none")
        )
        .into())
    }

    fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }
}

fn quic_config(identity: &TestIdentity) -> TestResult<quinn::ServerConfig> {
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

fn client(identity: &TestIdentity, http2: bool) -> TestResult<Client> {
    let mut profile = ClientProfile::new(tls_settings()).with_http3(client_settings());
    if http2 {
        profile = profile.with_http2(chrome::v154_http2());
    }
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

/// Refuses `count` QUIC handshakes.
async fn refuse(endpoint: &quinn::Endpoint, count: usize) -> TestResult<()> {
    for _ in 0..count {
        endpoint
            .accept()
            .await
            .ok_or("QUIC endpoint closed before a handshake")?
            .refuse();
    }
    Ok(())
}

/// One HTTP/2 request as the origin received it.
struct Received {
    method: Method,
    path: String,
    body: Bytes,
}

/// Serves one HTTP/2 request over TLS and answers it with `204`.
async fn serve_http2(listener: TcpListener, acceptor: SslAcceptor) -> TestResult<Received> {
    serve_http2_observed(listener, acceptor, None).await
}

async fn serve_http2_observed(
    listener: TcpListener,
    acceptor: SslAcceptor,
    observation: Option<Arc<driver_ownership::DriverObservation>>,
) -> TestResult<Received> {
    let (tcp, _) = listener.accept().await?;
    let stream = accept_tls_stream(tcp, acceptor).await?;
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("HTTP/2 connection closed before a request")??;
    // The connection must be driven for the body's DATA frames to arrive;
    // the driver ends when the client closes the connection.
    let lifetime = observation
        .as_ref()
        .map(|value| driver_ownership::DriverLifetime(Arc::clone(value)));
    let driver = tokio::spawn(async move {
        let _lifetime = lifetime;
        poll_fn(|context| connection.poll_closed(context))
            .await
            .map_err(Into::into)
    });
    let mut driver: ConnectionPeer<TestResult<()>> = ConnectionPeer::from_task(driver);
    let (parts, mut body) = request.into_parts();

    let result: TestResult<Received> = async {
        if let Some(value) = &observation {
            value.publish(driver.abort_handle())?;
        }

        let mut received = Vec::new();
        while let Some(chunk) = match &observation {
            Some(value) => driver_ownership::body_data(&mut body, &received, value).await,
            None => body.data().await,
        } {
            let chunk = chunk?;
            body.flow_control().release_capacity(chunk.len())?;
            received.extend_from_slice(&chunk);
        }

        respond.send_response(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(())?,
            true,
        )?;

        Ok(Received {
            method: parts.method,
            path: parts
                .uri
                .path_and_query()
                .ok_or("HTTP/2 request omitted :path")?
                .to_string(),
            body: Bytes::from(received),
        })
    }
    .await;

    let completed = if result.is_ok() {
        match timeout(TEST_TIMEOUT, &mut driver).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(error.into()),
            Err(error) => finish_with_cleanup(
                Err(FallbackDeadline(error).into()),
                stop_http2_driver(driver).await,
            ),
        }
    } else {
        stop_http2_driver(driver).await
    };

    finish_with_cleanup(result, completed)
}

async fn stop_http2_driver(driver: ConnectionPeer<TestResult<()>>) -> TestResult<()> {
    if driver.is_finished() {
        match driver.await {
            Ok(result) => result,
            Err(error) => Err(error.into()),
        }
    } else {
        driver.stop().await
    }
}

async fn no_tcp_connection(listener: &TcpListener) -> TestResult<()> {
    match timeout(QUIET_WINDOW, listener.accept()).await {
        Err(_) => Ok(()),
        Ok(Ok(_)) => Err("the client opened a TCP connection".into()),
        Ok(Err(error)) => Err(error.into()),
    }
}

#[derive(Debug)]
struct FallbackDeadline(Elapsed);

impl fmt::Display for FallbackDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HTTP/2 fallback test exceeded its deadline")
    }
}

impl Error for FallbackDeadline {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(FallbackDeadline)?
}

/// Keeps ownership across a cancelled wait and removes only observed tasks.
async fn join_worker<T: Send + 'static>(
    worker: &mut Option<ConnectionPeer<TestResult<T>>>,
) -> TestResult<T> {
    let outcome = worker.as_mut().ok_or("fallback worker owner absent")?.await;
    drop(worker.take());

    match outcome {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    }
}

async fn stop_worker<T: Send + 'static>(
    worker: &mut Option<ConnectionPeer<TestResult<T>>>,
) -> TestResult<()> {
    let Some(mut worker) = worker.take() else {
        return Ok(());
    };

    let requested_stop = !worker.is_finished();
    if requested_stop {
        worker.abort();
    }

    match timeout(CLEANUP_TIMEOUT, &mut worker).await {
        Ok(Ok(result)) => result.map(|_| ()),
        Ok(Err(error)) if requested_stop && error.is_cancelled() => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Err(error) => Err(error.into()),
    }
}

/// Lets a signalled parent collect its children before forcing cancellation.
async fn finish_signalled_worker<T: Send + 'static>(
    worker: &mut Option<ConnectionPeer<TestResult<T>>>,
) -> TestResult<()> {
    if worker.is_none() {
        return Ok(());
    }

    // The SOCKS parent can stop two children, each with its own deadline.
    match timeout(CLEANUP_TIMEOUT * 3, join_worker(worker)).await {
        Ok(result) => result.map(|_| ()),
        Err(error) => finish_with_cleanup(Err(error.into()), stop_worker(worker).await),
    }
}

async fn upload_with_fallback(
    path: &str,
    address: &mut Option<SocketAddr>,
) -> TestResult<Received> {
    let mut refused = None;
    let mut served = None;
    let primary = match timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let Origin { port, quic, tcp } = Origin::bind(&identity).await?;
        *address = Some(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        let url = format!("https://127.0.0.1:{port}{path}");
        refused = Some(ConnectionPeer::spawn(async move { refuse(&quic, 1).await }));
        let acceptor = identity.acceptor(H2_ALPN)?;
        served = Some(ConnectionPeer::spawn(serve_http2(tcp, acceptor)));

        let client = client(&identity, true)?;
        let response = client
            .request(HttpProtocol::Http3, Method::POST, &url)?
            .body("payload")
            .retry_policy(fallback())
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);

        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted ResponseInfo")?;
        assert_eq!(info.protocol(), HttpProtocol::Http2);
        assert_eq!(info.retries_performed(), 0);

        response.into_body().collect().await?;
        drop(client);

        join_worker(&mut refused).await?;
        join_worker(&mut served).await
    })
    .await
    {
        Ok(result) => result,
        Err(error) => Err(FallbackDeadline(error).into()),
    };

    let cleanup = stop_worker(&mut refused).await;
    let cleanup = finish_with_cleanup(cleanup, stop_worker(&mut served).await);

    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn a_refused_quic_handshake_sends_the_request_over_http2() -> TestResult<()> {
    let received = upload_with_fallback("/upload", &mut None).await?;

    assert_eq!(received.method, Method::POST);
    assert_eq!(received.path, "/upload");
    assert_eq!(received.body, "payload");
    Ok(())
}

#[tokio::test]
async fn without_the_policy_a_refused_handshake_returns_the_http3_error() -> TestResult<()> {
    let mut refused = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::bind(&identity).await?;
        let url = origin.url("/refused");
        let Origin { quic, tcp, .. } = origin;
        refused = Some(ConnectionPeer::spawn(async move { refuse(&quic, 1).await }));

        let error = client(&identity, true)?
            .get(HttpProtocol::Http3, &url)?
            .send()
            .await
            .err()
            .ok_or("a refused handshake returned a response")?;
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        join_worker(&mut refused).await?;
        no_tcp_connection(&tcp).await
    })
    .await;

    let cleanup = stop_worker(&mut refused).await;

    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn a_one_shot_streaming_body_returns_the_http3_error() -> TestResult<()> {
    let mut refused = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::bind(&identity).await?;
        let url = origin.url("/stream");
        let Origin { quic, tcp, .. } = origin;
        refused = Some(ConnectionPeer::spawn(async move { refuse(&quic, 1).await }));

        let error = client(&identity, true)?
            .request(HttpProtocol::Http3, Method::POST, &url)?
            .streaming_body(Full::new(Bytes::from_static(b"payload")))
            .retry_policy(fallback())
            .send()
            .await
            .err()
            .ok_or("a refused handshake returned a response")?;
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        join_worker(&mut refused).await?;
        no_tcp_connection(&tcp).await
    })
    .await;

    let cleanup = stop_worker(&mut refused).await;

    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn a_failure_after_the_request_was_sent_returns_the_http3_error() -> TestResult<()> {
    let mut server = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::bind(&identity).await?;
        let url = origin.url("/sent");
        let Origin { quic, tcp, .. } = origin;
        server = Some(ConnectionPeer::spawn(async move {
            let incoming = quic.accept().await.ok_or("QUIC endpoint closed")?;
            let connection = incoming.await?;
            let mut h3 = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(
                connection.clone(),
            ))
            .await?;
            let resolver = h3
                .accept()
                .await?
                .ok_or("client closed before sending a request")?;
            resolver.resolve_request().await?;
            // H3_INTERNAL_ERROR after the request arrived: the server may
            // have acted on it.
            connection.close(quinn::VarInt::from_u32(0x102), b"");
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }));

        let error = client(&identity, true)?
            .get(HttpProtocol::Http3, &url)?
            .retry_policy(fallback())
            .send()
            .await
            .err()
            .ok_or("a closed connection returned a response")?;
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        join_worker(&mut server).await?;
        no_tcp_connection(&tcp).await
    })
    .await;

    let cleanup = stop_worker(&mut server).await;

    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn the_fallback_needs_an_http2_profile_and_a_tcp_route_before_any_io() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::bind(&identity).await?;
        let url = origin.url("/checked");

        let error = client(&identity, false)?
            .get(HttpProtocol::Http3, &url)?
            .retry_policy(fallback())
            .send()
            .await
            .err()
            .ok_or("a client without HTTP/2 sent the request")?;
        assert_eq!(error.kind(), RequestErrorKind::ProtocolUnavailable);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http2));

        let proxy = ConnectUdpProxy::new(&format!(
            "https://127.0.0.1:{}/.well-known/masque/udp/{{target_host}}/{{target_port}}/",
            origin.port
        ))?;
        let error = client(&identity, true)?
            .get(HttpProtocol::Http3, &url)?
            .route(Route::connect_udp(proxy))
            .retry_policy(fallback())
            .send()
            .await
            .err()
            .ok_or("a CONNECT-UDP route sent the request")?;
        assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http2));

        // Neither request reached the network.
        match timeout(QUIET_WINDOW, origin.quic.accept()).await {
            Err(_) => {}
            Ok(_) => return Err("a request opened a QUIC connection".into()),
        }
        no_tcp_connection(&origin.tcp).await
    })
    .await
}

/// Sends a GET that may fall back, while the origin's QUIC endpoint never
/// accepts the handshake, and returns how long the request took.
async fn fall_back_from_an_unanswered_handshake(
    timeouts: Option<RequestTimeoutOverrides>,
) -> TestResult<Duration> {
    let mut served = None;
    let primary = match timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let Origin { port, quic, tcp } = Origin::bind(&identity).await?;
        served = Some(ConnectionPeer::spawn(serve_http2(
            tcp,
            identity.acceptor(H2_ALPN)?,
        )));

        let client = client(&identity, true)?;
        let mut request = client
            .get(
                HttpProtocol::Http3,
                &format!("https://127.0.0.1:{port}/quiet"),
            )?
            .retry_policy(fallback());
        if let Some(timeouts) = timeouts {
            request = request.timeouts(timeouts);
        }

        let started = Instant::now();
        let response = request.send().await?;
        let elapsed = started.elapsed();
        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted ResponseInfo")?;
        assert_eq!(info.protocol(), HttpProtocol::Http2);

        response.into_body().collect().await?;
        drop(client);
        assert_eq!(join_worker(&mut served).await?.path, "/quiet");
        drop(quic);
        Ok(elapsed)
    })
    .await
    {
        Ok(result) => result,
        Err(error) => Err(FallbackDeadline(error).into()),
    };

    finish_with_cleanup(primary, stop_worker(&mut served).await)
}

#[tokio::test]
async fn a_handshake_past_the_connect_timeout_falls_back() -> TestResult<()> {
    let elapsed = fall_back_from_an_unanswered_handshake(Some(
        RequestTimeoutOverrides::disabled()
            .connect(TimeoutOverride::Limit(Duration::from_millis(300))),
    ))
    .await?;
    assert!(
        elapsed < Duration::from_secs(4),
        "fell back after {elapsed:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_handshake_past_four_seconds_falls_back() -> TestResult<()> {
    let elapsed = fall_back_from_an_unanswered_handshake(None).await?;
    assert!(
        elapsed >= Duration::from_millis(3_900) && elapsed < Duration::from_secs(10),
        "fell back after {elapsed:?}"
    );
    Ok(())
}

/// What one HTTP/2 connection's client sent before its first request.
struct Http2Start {
    settings: Vec<u8>,
    headers_flags: u8,
}

/// Answers one HTTP/2 GET with `200` from raw frames, keeping the client's
/// SETTINGS payload and HEADERS flags, and holds the connection until
/// `done` fires.
async fn serve_raw_http2(
    listener: TcpListener,
    acceptor: SslAcceptor,
    done: oneshot::Receiver<()>,
) -> TestResult<Http2Start> {
    let (tcp, _) = listener.accept().await?;
    let mut stream = accept_tls_stream(tcp, acceptor).await?;
    let mut preface = [0; 24];
    stream.read_exact(&mut preface).await?;
    if &preface != b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "invalid HTTP/2 client preface").into(),
        );
    }

    let settings = loop {
        let frame = read_frame(&mut stream).await?;
        if frame.kind == 0x4 && frame.flags & 0x1 == 0 {
            if frame.stream_id != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP/2 SETTINGS used a request stream",
                )
                .into());
            }

            if frame.payload.len() % 6 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP/2 SETTINGS payload contains an incomplete setting",
                )
                .into());
            }

            break frame.payload;
        }
    };
    write_frame(&mut stream, 0x4, 0, 0, &[]).await?;
    write_frame(&mut stream, 0x4, 0x1, 0, &[]).await?;
    let headers_flags = loop {
        let frame = read_frame(&mut stream).await?;
        if frame.kind == 0x1 && frame.stream_id == 1 {
            break frame.flags;
        }
    };
    // `:status: 200`, indexed, with END_STREAM and END_HEADERS.
    write_frame(&mut stream, 0x1, 0x1 | 0x4, 1, &[0x88]).await?;
    stream.flush().await?;
    let _ = done.await;
    Ok(Http2Start {
        settings,
        headers_flags,
    })
}

#[tokio::test]
async fn the_http2_attempt_uses_the_profiles_http2_recipe() -> TestResult<()> {
    let mut refused = None;
    let mut served = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let Origin { port, quic, tcp } = Origin::bind(&identity).await?;
        refused = Some(ConnectionPeer::spawn(async move { refuse(&quic, 1).await }));
        let (done, wait_for_done) = oneshot::channel();
        served = Some(ConnectionPeer::spawn(serve_raw_http2(
            tcp,
            identity.acceptor(H2_ALPN)?,
            wait_for_done,
        )));

        let response = client(&identity, true)?
            .get(
                HttpProtocol::Http3,
                &format!("https://127.0.0.1:{port}/recipe"),
            )?
            .retry_policy(fallback())
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;
        let _ = done.send(());
        join_worker(&mut refused).await?;

        let start = join_worker(&mut served).await?;
        // `chrome::v154_http2`: HEADER_TABLE_SIZE 65536, ENABLE_PUSH 0,
        // INITIAL_WINDOW_SIZE 6291456, MAX_HEADER_LIST_SIZE 262144, in order.
        let expected: [(u16, u32); 4] = [(1, 65_536), (2, 0), (4, 6_291_456), (6, 262_144)];
        let (settings, remainder) = start.settings.as_chunks::<6>();
        assert!(remainder.is_empty(), "SETTINGS contained trailing bytes");

        let sent = settings
            .iter()
            .map(|setting| {
                (
                    u16::from_be_bytes([setting[0], setting[1]]),
                    u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(sent, expected);
        // The recipe's HEADERS carry a priority.
        assert_ne!(start.headers_flags & 0x20, 0);
        Ok(())
    })
    .await;

    let cleanup = stop_worker(&mut refused).await;
    let cleanup = finish_with_cleanup(cleanup, stop_worker(&mut served).await);

    finish_with_cleanup(primary, cleanup)
}

fn early_data_quic_config(identity: &TestIdentity) -> TestResult<quinn::ServerConfig> {
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    // QUIC permits only 0 or 0xffffffff here (RFC 9001, section 4.6.1).
    tls.max_early_data_size = u32::MAX;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

#[tokio::test]
async fn a_failed_handshake_after_early_data_falls_back_before_the_request_is_written()
-> TestResult<()> {
    let mut quic_server = None;
    let mut served = None;
    let mut stop = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let untrusted = TestIdentity::generate()?;
        let Origin { port, quic, tcp } = Origin::bind(&identity).await?;
        quic.set_server_config(Some(early_data_quic_config(&identity)?));
        let untrusted_config = early_data_quic_config(&untrusted)?;
        let (read_tx, read) = oneshot::channel::<()>();
        let (failing_tx, failing) = oneshot::channel();
        let (stop_tx, stop_rx) = oneshot::channel::<()>();
        stop = Some(stop_tx);
        quic_server = Some(ConnectionPeer::spawn(async move {
            let operation = async {
                let incoming = quic.accept().await.ok_or("QUIC endpoint closed")?;
                let connection = incoming.await?;
                let mut h3 = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(
                    connection.clone(),
                ))
                .await?;
                let resolver = h3
                    .accept()
                    .await?
                    .ok_or("client closed before sending a request")?;
                let (_, mut stream) = resolver.resolve_request().await?;
                stream
                    .send_response(Response::builder().status(StatusCode::OK).body(())?)
                    .await?;
                stream.finish().await?;
                let _ = read.await;
                connection.close(0u32.into(), b"served");
                drop(h3);
                quic.wait_idle().await;
                // A certificate the client does not trust fails the next
                // handshake after the client has sent its early data.
                quic.set_server_config(Some(untrusted_config));
                let _ = failing_tx.send(());
                while let Some(incoming) = quic.accept().await {
                    // An untrusted issuer sends TLS unknown_ca (48), carried as
                    // QUIC CRYPTO_ERROR 0x130. Other handshake failures stay errors.
                    match incoming.await {
                        Err(quinn::ConnectionError::ConnectionClosed(close))
                            if u64::from(close.error_code) == 0x130 => {}
                        Err(error) => return Err(error.into()),
                        Ok(_) => return Err("the untrusted QUIC handshake completed".into()),
                    }
                }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            };
            tokio::select! {
                biased;
                result = operation => result,
                _ = stop_rx => Ok(()),
            }
        }));

        let profile = ClientProfile::new(tls_settings())
            .with_http2(chrome::v154_http2())
            .with_http3(Http3ClientSettings::new(
                chrome::v154_quic_tls(),
                chrome::v154_quic(),
                chrome::v154_http3(),
                chrome::v154_http3_request(),
            ));
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let first = client
            .get(
                HttpProtocol::Http3,
                &format!("https://127.0.0.1:{port}/first"),
            )?
            .send()
            .await?;
        first.into_body().collect().await?;
        let _ = read_tx.send(());
        failing.await?;

        served = Some(ConnectionPeer::spawn(serve_http2(
            tcp,
            identity.acceptor(H2_ALPN)?,
        )));
        // A POST waits for the resumed handshake before it is written.
        let response = client
            .request(
                HttpProtocol::Http3,
                Method::POST,
                &format!("https://127.0.0.1:{port}/post"),
            )?
            .body("payload")
            .retry_policy(fallback())
            .send()
            .await?;
        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted ResponseInfo")?;
        assert_eq!(info.protocol(), HttpProtocol::Http2);

        response.into_body().collect().await?;
        drop(client);
        let received = join_worker(&mut served).await?;
        assert_eq!(received.path, "/post");
        assert_eq!(received.body, "payload");
        Ok(())
    })
    .await;

    drop(stop.take());
    let cleanup = finish_signalled_worker(&mut quic_server).await;
    let cleanup = finish_with_cleanup(cleanup, stop_worker(&mut served).await);

    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn a_failed_http2_attempt_returns_the_http2_error() -> TestResult<()> {
    let mut refused = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let Origin { port, quic, tcp } = Origin::bind(&identity).await?;
        // The TCP port refuses connections, so the HTTP/2 attempt fails too.
        drop(tcp);
        refused = Some(ConnectionPeer::spawn(async move { refuse(&quic, 1).await }));

        let error = client(&identity, true)?
            .get(
                HttpProtocol::Http3,
                &format!("https://127.0.0.1:{port}/both"),
            )?
            .retry_policy(fallback())
            .send()
            .await
            .err()
            .ok_or("a refused TCP port returned a response")?;
        assert_eq!(error.protocol(), Some(HttpProtocol::Http2));
        assert_eq!(error.kind(), RequestErrorKind::Connect);
        join_worker(&mut refused).await?;
        Ok(())
    })
    .await;

    let cleanup = stop_worker(&mut refused).await;

    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn zero_retry_cap_keeps_exact_http3_and_needs_no_http2_profile() -> TestResult<()> {
    let mut refused = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::bind(&identity).await?;
        let url = origin.url("/no-fallback");
        let Origin { quic, tcp, .. } = origin;
        refused = Some(ConnectionPeer::spawn(async move { refuse(&quic, 1).await }));

        let error = client(&identity, false)?
            .get(HttpProtocol::Http3, &url)?
            .retry_policy(fallback().with_max_retries(Some(0)))
            .send()
            .await
            .err()
            .ok_or("a refused handshake returned a response")?;
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        join_worker(&mut refused).await?;
        no_tcp_connection(&tcp).await
    })
    .await;

    let cleanup = stop_worker(&mut refused).await;

    finish_with_cleanup(primary, cleanup)
}
