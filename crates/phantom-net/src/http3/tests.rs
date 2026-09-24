#[cfg(feature = "qlog")]
use std::num::NonZeroUsize;
use std::{error::Error, net::SocketAddr, sync::Arc};

use btls::{
    ssl::{SslContext, SslMethod, SslVerifyMode},
    x509::X509,
};
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use phantom_profile::{
    Http3QpackDecoderStream, Http3QpackEncoding, Http3Setting, Http3SettingOrder, Http3Settings,
    chromium, quic::QuicTransportSettings,
};
use phantom_quic_btls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{sync::oneshot, task::JoinHandle, time::timeout};

use super::Http3ErrorKind;
use crate::tls::test_support::{TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity};

type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[test]
fn runtime_without_io_returns_runtime_unavailable() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let request = Request::get(format!("https://{TEST_SERVER_NAME}/")).body(())?;
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;

    let error = runtime
        .block_on(send_test_request(
            "127.0.0.1:9".parse()?,
            TEST_SERVER_NAME,
            client,
            request,
        ))
        .err()
        .ok_or("HTTP/3 request completed on a runtime without network I/O")?;

    assert_eq!(error.kind(), Http3ErrorKind::RuntimeUnavailable);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_invalid_request_before_connecting() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let request = Request::get("http://server.phantom.test/").body(())?;
    let result = send_test_request(
        "127.0.0.1:9".parse()?,
        TEST_SERVER_NAME,
        client_config(&identity)?,
        request,
    )
    .await;
    let error = match result {
        Ok(_) => return Err("invalid request unexpectedly reached the network".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), Http3ErrorKind::Request);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn rejects_extension_requests_before_connecting() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connect = Request::builder()
        .method(Method::CONNECT)
        .uri("https://server.phantom.test/")
        .body(())?;
    let mut extended = Request::get("https://server.phantom.test/").body(())?;
    extended
        .extensions_mut()
        .insert(h3::ext::Protocol::CONNECT_UDP);

    for request in [connect, extended] {
        let result = send_test_request(
            "127.0.0.1:9".parse()?,
            TEST_SERVER_NAME,
            client_config(&identity)?,
            request,
        )
        .await;
        let error = match result {
            Ok(_) => return Err("extension request unexpectedly reached the network".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), Http3ErrorKind::Request);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn untrusted_certificate_is_a_handshake_failure() -> TestResult<()> {
    let server_identity = TestIdentity::generate()?;
    let unrelated_identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&server_identity)?;
    let server = tokio::spawn(async move {
        if let Some(incoming) = endpoint.accept().await {
            let _ = incoming.await;
        }
    });
    let request = Request::get(format!("https://{TEST_SERVER_NAME}/")).body(())?;

    let error = timeout(
        TEST_TIMEOUT,
        send_test_request(
            address,
            TEST_SERVER_NAME,
            client_config(&unrelated_identity)?,
            request,
        ),
    )
    .await
    .map_err(|_| "untrusted-certificate request timed out")?
    .err()
    .ok_or("untrusted certificate was accepted")?;

    server.abort();
    assert_eq!(error.kind(), Http3ErrorKind::Handshake);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn wrong_certificate_name_is_a_handshake_failure() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let server = tokio::spawn(async move {
        if let Some(incoming) = endpoint.accept().await {
            let _ = incoming.await;
        }
    });
    let request = Request::get("https://wrong.phantom.test/").body(())?;

    let error = timeout(
        TEST_TIMEOUT,
        send_test_request(
            address,
            "wrong.phantom.test",
            client_config(&identity)?,
            request,
        ),
    )
    .await
    .map_err(|_| "wrong-certificate-name request timed out")?
    .err()
    .ok_or("wrong certificate name was accepted")?;

    server.abort();
    assert_eq!(error.kind(), Http3ErrorKind::Handshake);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn streams_data_and_trailers_over_boringssl_quic() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (first_sent, first_received) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let (_request, mut stream, _connection) = accept_request(&endpoint).await?;
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        stream.send_data(Bytes::from_static(b"first")).await?;
        let _ = first_sent.send(());
        let _ = released.await;
        stream.send_data(Bytes::from_static(b"second")).await?;

        let mut trailers = HeaderMap::new();
        trailers.insert("x-phantom-finished", HeaderValue::from_static("yes"));
        stream.send_trailers(trailers).await?;
        stream.finish().await?;
        let _ = done_received.await;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    });

    let request = Request::get(format!(
        "https://{TEST_SERVER_NAME}:{}/stream",
        address.port()
    ))
    .body(())?;
    let response = timeout(
        TEST_TIMEOUT,
        send_test_request(address, TEST_SERVER_NAME, client, request),
    )
    .await
    .map_err(|_| "HTTP/3 request timed out")??;
    assert_eq!(response.status(), StatusCode::OK);

    let mut body = response.into_body();
    timeout(TEST_TIMEOUT, first_received)
        .await
        .map_err(|_| "server did not send the first body chunk")??;
    let first = next_frame(&mut body).await?;
    assert_eq!(
        first.into_data().map_err(|_| "expected response data")?,
        "first"
    );

    let _ = release.send(());
    let second = next_frame(&mut body).await?;
    assert_eq!(
        second.into_data().map_err(|_| "expected response data")?,
        "second"
    );
    let trailers = next_frame(&mut body)
        .await?
        .into_trailers()
        .map_err(|_| "expected response trailers")?;
    assert_eq!(
        trailers.get("x-phantom-finished"),
        Some(&HeaderValue::from_static("yes"))
    );
    match timeout(TEST_TIMEOUT, body.frame())
        .await
        .map_err(|_| "response body did not finish")?
    {
        None => {}
        Some(Ok(_)) => return Err("response produced a frame after trailers".into()),
        Some(Err(error)) => return Err(error.into()),
    }
    let _ = client_done.send(());
    join_server(server).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn capture_backed_transport_profile_completes_a_request() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = profiled_client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (_request, mut stream, _connection) = accept_request(&endpoint).await?;
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        let _ = done_received.await;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    });
    let settings = chromium::v154_http3();
    let response = timeout(
        TEST_TIMEOUT,
        super::send_request(
            address,
            TEST_SERVER_NAME,
            client,
            &settings,
            &chromium::v154_http3_request(),
            Method::GET,
            &format!("{TEST_SERVER_NAME}:{}", address.port()),
            super::OriginForm::parse("/profiled")?,
            Vec::new(),
        ),
    )
    .await
    .map_err(|_| "profiled HTTP/3 request timed out")??;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let mut body = response.into_body();
    assert!(next_optional_frame(&mut body).await?.is_none());
    let _ = client_done.send(());
    join_server(server).await?;
    Ok(())
}

#[cfg(feature = "qlog")]
#[tokio::test(flavor = "current_thread")]
async fn bounded_qlog_completes_without_recording_request_headers() -> TestResult<()> {
    const SECRET: &str = "phantom-qlog-secret-value";

    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (_request, mut stream, _connection) = accept_request(&endpoint).await?;
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        let _ = done_received.await;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    });
    let capture = super::QlogCapture::new(
        NonZeroUsize::new(64 * 1024).ok_or("qlog test bound must be nonzero")?,
    );

    let response = timeout(
        TEST_TIMEOUT,
        super::send_request_with_qlog(
            address,
            TEST_SERVER_NAME,
            client,
            &test_settings(),
            &chromium::v154_http3_request(),
            Method::GET,
            &format!("{TEST_SERVER_NAME}:{}", address.port()),
            super::OriginForm::parse("/qlog")?,
            vec![super::RequestHeader::new("x-phantom-secret", SECRET)],
            capture.clone(),
        ),
    )
    .await
    .map_err(|_| "qlog HTTP/3 request timed out")??;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let mut body = response.into_body();
    assert!(next_optional_frame(&mut body).await?.is_none());

    let _ = client_done.send(());
    join_server(server).await?;
    timeout(TEST_TIMEOUT, capture.wait_complete())
        .await
        .map_err(|_| "qlog capture did not complete")?;

    let snapshot = capture.snapshot();
    assert!(!snapshot.is_empty());
    assert!(snapshot.len() <= capture.max_bytes().get());
    assert_complete_json_seq(&snapshot)?;
    assert!(
        !snapshot
            .windows(SECRET.len())
            .any(|bytes| bytes == SECRET.as_bytes())
    );
    Ok(())
}

#[cfg(feature = "qlog")]
#[tokio::test(flavor = "current_thread")]
async fn rejects_reusing_a_qlog_capture_as_configuration() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let capture =
        super::QlogCapture::new(NonZeroUsize::new(4096).ok_or("qlog test bound must be nonzero")?);
    let remote = "127.0.0.1:443".parse()?;
    let first = super::endpoint(
        remote,
        Arc::clone(&client),
        super::ConnectionDiagnostics {
            qlog: Some(capture.clone()),
            ..Default::default()
        },
    )?;

    let error = match super::endpoint(
        remote,
        client,
        super::ConnectionDiagnostics {
            qlog: Some(capture.clone()),
            ..Default::default()
        },
    ) {
        Ok(_) => return Err("reused qlog capture unexpectedly configured an endpoint".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), Http3ErrorKind::Configuration);
    assert_eq!(
        error
            .source()
            .and_then(|source| source.downcast_ref::<super::QlogCaptureError>()),
        Some(&super::QlogCaptureError::AlreadyAttached)
    );

    drop(first);
    timeout(TEST_TIMEOUT, capture.wait_complete())
        .await
        .map_err(|_| "qlog capture did not complete after endpoint drop")?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn connects_over_ipv6_when_loopback_is_available() -> TestResult<()> {
    let bind_address: SocketAddr = "[::1]:0".parse()?;
    if std::net::UdpSocket::bind(bind_address).is_err() {
        return Ok(());
    }

    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint_at(&identity, bind_address)?;
    let (client_done, done_received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (_request, mut stream, _connection) = accept_request(&endpoint).await?;
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        let _ = done_received.await;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    });

    let request = Request::get(format!(
        "https://{TEST_SERVER_NAME}:{}/ipv6",
        address.port()
    ))
    .body(())?;
    let response = timeout(
        TEST_TIMEOUT,
        send_test_request(address, TEST_SERVER_NAME, client, request),
    )
    .await
    .map_err(|_| "IPv6 HTTP/3 request timed out")??;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let mut body = response.into_body();
    assert!(next_optional_frame(&mut body).await?.is_none());
    let _ = client_done.send(());
    join_server(server).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_body_cancels_the_peer_stream() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (head_sent, head_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let (_request, mut stream, _connection) = accept_request(&endpoint).await?;
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        let _ = head_sent.send(());

        let chunk = Bytes::from(vec![0; 64 * 1024]);
        loop {
            match stream.send_data(chunk.clone()).await {
                Ok(()) => {}
                Err(h3::error::StreamError::RemoteTerminate { code, .. })
                    if code == h3::error::Code::H3_REQUEST_CANCELLED =>
                {
                    return Ok::<(), Box<dyn Error + Send + Sync>>(());
                }
                Err(error) => {
                    return Err(format!("unexpected cancellation result: {error}").into());
                }
            }
        }
    });

    let request = Request::get(format!(
        "https://{TEST_SERVER_NAME}:{}/cancel",
        address.port()
    ))
    .body(())?;
    let response = timeout(
        TEST_TIMEOUT,
        send_test_request(address, TEST_SERVER_NAME, client, request),
    )
    .await
    .map_err(|_| "HTTP/3 request timed out")??;
    timeout(TEST_TIMEOUT, head_received)
        .await
        .map_err(|_| "server did not send the response head")??;
    drop(response);

    join_server(server).await?;
    Ok(())
}

fn client_config(identity: &TestIdentity) -> TestResult<Arc<QuicClientConfig>> {
    let mut context = SslContext::builder(SslMethod::tls())?;
    context
        .cert_store_mut()
        .add_cert(X509::from_der(identity.root_der())?)?;
    context.set_verify(SslVerifyMode::PEER);
    Ok(Arc::new(QuicClientConfig::new(context.build())))
}

async fn send_test_request(
    remote: SocketAddr,
    server_name: &str,
    client: Arc<QuicClientConfig>,
    request: Request<()>,
) -> Result<Response<super::Http3Body>, super::Http3Error> {
    send_request_head(remote, server_name, client, &test_settings(), request).await
}

/// Sends a `Request<()>` over a new connection without a request profile.
///
/// Test-only: vendored h3 emits its default pseudo-header order and
/// HeaderMap-grouped fields for such a request.
async fn send_request_head(
    remote: SocketAddr,
    server_name: &str,
    client: Arc<QuicClientConfig>,
    settings: &Http3Settings,
    request: Request<()>,
) -> Result<Response<super::Http3Body>, super::Http3Error> {
    let request = super::prepare_request(request, None)?;
    super::send_prepared_request(
        remote,
        server_name,
        client,
        settings,
        request,
        super::ConnectionDiagnostics::default(),
    )
    .await
}

fn test_settings() -> Http3Settings {
    Http3Settings {
        initial_settings: vec![
            Http3Setting::QpackMaxTableCapacity(0),
            Http3Setting::MaxFieldSectionSize(65_536),
            Http3Setting::QpackBlockedStreams(0),
        ],
        setting_order: Http3SettingOrder::Fixed,
        qpack_encoding: Http3QpackEncoding::Stateless,
        qpack_decoder_stream: Http3QpackDecoderStream::Eager,
    }
}

#[cfg(feature = "qlog")]
fn assert_complete_json_seq(bytes: &[u8]) -> TestResult<()> {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        if remaining[0] != 0x1e {
            return Err("qlog record is missing its JSON-SEQ separator".into());
        }
        let end = remaining
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or("qlog snapshot contains a partial record")?;
        let json = &remaining[1..end];
        if json.first() != Some(&b'{') || json.last() != Some(&b'}') {
            return Err("qlog record is not a complete JSON object".into());
        }
        remaining = &remaining[end + 1..];
    }
    Ok(())
}

fn profiled_client_config(identity: &TestIdentity) -> TestResult<Arc<QuicClientConfig>> {
    client_config_with_profile(identity, chromium::v154_quic())
}

fn client_config_with_profile(
    identity: &TestIdentity,
    settings: QuicTransportSettings,
) -> TestResult<Arc<QuicClientConfig>> {
    let mut context = SslContext::builder(SslMethod::tls())?;
    context
        .cert_store_mut()
        .add_cert(X509::from_der(identity.root_der())?)?;
    context.set_verify(SslVerifyMode::PEER);
    Ok(Arc::new(QuicClientConfig::with_transport_profile(
        context.build(),
        settings,
    )?))
}

fn server_endpoint(identity: &TestIdentity) -> TestResult<(std::net::SocketAddr, quinn::Endpoint)> {
    server_endpoint_at(identity, "127.0.0.1:0".parse()?)
}

fn server_endpoint_at(
    identity: &TestIdentity,
    bind_address: SocketAddr,
) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    server_endpoint_with_transport(identity, bind_address, quinn::TransportConfig::default())
}

fn server_endpoint_with_bidi_limit(
    identity: &TestIdentity,
    streams: u32,
) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(streams.into());
    server_endpoint_with_transport(identity, "127.0.0.1:0".parse()?, transport)
}

fn server_endpoint_with_transport(
    identity: &TestIdentity,
    bind_address: SocketAddr,
    transport: quinn::TransportConfig,
) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    config.transport_config(Arc::new(transport));
    let endpoint = quinn::Endpoint::server(config, bind_address)?;
    Ok((endpoint.local_addr()?, endpoint))
}

async fn accept_request(
    endpoint: &quinn::Endpoint,
) -> TestResult<(
    Request<()>,
    h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    h3::server::Connection<h3_quinn::Connection, Bytes>,
)> {
    let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
    let connection = incoming.await?;
    let mut connection = h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
    let resolver = connection
        .accept()
        .await?
        .ok_or("client closed before sending a request")?;
    let (request, stream) = resolver.resolve_request().await?;
    Ok((request, stream, connection))
}

async fn next_frame(body: &mut super::Http3Body) -> TestResult<http_body::Frame<Bytes>> {
    next_optional_frame(body)
        .await?
        .ok_or_else(|| "response body ended early".into())
}

async fn next_optional_frame(
    body: &mut super::Http3Body,
) -> TestResult<Option<http_body::Frame<Bytes>>> {
    timeout(TEST_TIMEOUT, body.frame())
        .await
        .map_err(|_| "response frame timed out")?
        .transpose()
        .map_err(Into::into)
}

async fn join_server(server: JoinHandle<TestResult<()>>) -> TestResult<()> {
    timeout(TEST_TIMEOUT, server)
        .await
        .map_err(|_| "HTTP/3 test server did not finish")???;
    Ok(())
}

mod adversarial;
mod connect_udp;
mod connection;
mod connector;
mod datagram;
mod extended_connect;
mod profile;
mod qpack;
mod quic;
mod request;
