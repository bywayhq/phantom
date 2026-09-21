use std::{error::Error, time::Duration};

use bytes::{Buf, Bytes};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use phantom_profile::{Http3PseudoHeader, Http3RequestSettings, chromium};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::oneshot,
    time::timeout,
};
use tracing::instrument::WithSubscriber;

use super::{
    TestResult, client_config, join_server, profiled_client_config, server_endpoint, test_settings,
};
use crate::{
    OrderedResponseHeaders,
    http3::{
        Http3Connection, Http3Connector, Http3ConnectorErrorKind, Http3Error, Http3ErrorKind,
        Http3ExtendedConnectOutcome, Http3ExtendedConnectStream, Http3ExtendedProtocol, OriginForm,
        RequestHeader,
    },
    tls::test_support::{TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity},
    tracing_test::OutcomeSubscriber,
};

const HEADERS_FRAME: u8 = 0x01;
const NO_STREAM_WINDOW: Duration = Duration::from_millis(100);
const STATUS_200: &[u8] = &[0x00, 0x00, 0xd9];
const SETTINGS_ENABLE_CONNECT_PROTOCOL: u8 = 0x08;

#[tokio::test(flavor = "current_thread")]
async fn extended_connect_waits_for_peer_settings_before_opening_stream() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let connection = accept_raw(&endpoint).await?;
        if timeout(NO_STREAM_WINDOW, connection.accept_bi())
            .await
            .is_ok()
        {
            return Err("client opened a request stream before peer SETTINGS".into());
        }
        let _control =
            send_raw_settings(&connection, &[SETTINGS_ENABLE_CONNECT_PROTOCOL, 1]).await?;
        let (mut response, mut request) = timeout(TEST_TIMEOUT, connection.accept_bi())
            .await
            .map_err(|_| "client never opened the request stream")??;
        let _ = read_headers_frame(&mut request).await?;
        write_headers(&mut response, STATUS_200).await?;
        let _ = done_received.await;
        Ok(())
    });

    let connection = connect(address, client_config(&identity)?).await?;
    let outcome = timeout(TEST_TIMEOUT, send(&connection, address, Vec::new()))
        .await
        .map_err(|_| "extended CONNECT timed out")??;
    assert!(matches!(
        outcome,
        Http3ExtendedConnectOutcome::Accepted { .. }
    ));
    drop(outcome);
    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn absent_enable_connect_protocol_fails_without_request_stream() -> TestResult<()> {
    assert_capability_unavailable(&[0x06, 0x44, 0x00]).await
}

#[tokio::test(flavor = "current_thread")]
async fn zero_enable_connect_protocol_fails_without_request_stream() -> TestResult<()> {
    assert_capability_unavailable(&[SETTINGS_ENABLE_CONNECT_PROTOCOL, 0]).await
}

async fn assert_capability_unavailable(settings: &'static [u8]) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let connection = accept_raw(&endpoint).await?;
        let _control = send_raw_settings(&connection, settings).await?;
        let opened = tokio::select! {
            opened = connection.accept_bi() => opened.is_ok(),
            _ = done_received => false,
        };
        if opened {
            return Err("client opened a request stream without peer capability".into());
        }
        Ok(())
    });

    let connection = connect(address, client_config(&identity)?).await?;
    let error = timeout(TEST_TIMEOUT, send(&connection, address, Vec::new()))
        .await
        .map_err(|_| "extended CONNECT timed out")?
        .err()
        .ok_or("extended CONNECT succeeded without peer capability")?;
    assert_eq!(error.kind(), Http3ErrorKind::ExtendedConnectUnavailable);
    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn extended_connect_emits_configured_five_field_pseudo_order() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (fields_sent, fields_received) = oneshot::channel();
    let (client_done, done_received) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let connection = accept_raw(&endpoint).await?;
        let _control =
            send_raw_settings(&connection, &[SETTINGS_ENABLE_CONNECT_PROTOCOL, 1]).await?;
        let (mut response, mut request) = connection.accept_bi().await?;
        let mut section = read_headers_frame(&mut request).await?;
        let decoded = h3::qpack::decode_stateless(&mut section, u64::MAX)?;
        let fields = decoded
            .fields
            .into_iter()
            .map(|field| (field.name.into_owned(), field.value.into_owned()))
            .collect::<Vec<_>>();
        write_headers(&mut response, STATUS_200).await?;
        let _ = fields_sent.send(fields);
        let _ = done_received.await;
        Ok(())
    });

    let connection = connect(address, client_config(&identity)?).await?;
    let headers = vec![
        RequestHeader::new("sec-websocket-version", "13"),
        RequestHeader::new("x-order", "first"),
        RequestHeader::new("x-order", "second"),
    ];
    let outcome = timeout(TEST_TIMEOUT, send(&connection, address, headers))
        .await
        .map_err(|_| "extended CONNECT timed out")??;
    let fields = fields_received.await?;
    let authority = format!("{TEST_SERVER_NAME}:{}", address.port());
    let expected: Vec<(Vec<u8>, Vec<u8>)> = vec![
        (b":method".to_vec(), b"CONNECT".to_vec()),
        (b":protocol".to_vec(), b"websocket".to_vec()),
        (b":scheme".to_vec(), b"https".to_vec()),
        (b":authority".to_vec(), authority.into_bytes()),
        (b":path".to_vec(), b"/chat?room=1".to_vec()),
        (b"sec-websocket-version".to_vec(), b"13".to_vec()),
        (b"x-order".to_vec(), b"first".to_vec()),
        (b"x-order".to_vec(), b"second".to_vec()),
    ];
    assert_eq!(fields, expected);
    drop(outcome);
    let _ = client_done.send(());
    join_server(server).await
}

#[test]
fn missing_extended_connect_order_fails_before_io() -> TestResult<()> {
    let connector = Http3Connector::new(
        &chromium::v152_http3_tls(),
        &chromium::v152_quic(),
        &chromium::v152_http3(),
        &chromium::v152_http3_request(),
    )?;
    let error = connector
        .validate_extended_connect(
            Http3ExtendedProtocol::WebSocket,
            TEST_SERVER_NAME,
            &OriginForm::parse("/")?,
            &[],
        )
        .err()
        .ok_or("named recipe without an extended CONNECT order was accepted")?;
    assert_eq!(error.kind(), Http3ConnectorErrorKind::ProtocolConfiguration);
    Ok(())
}

#[test]
fn forbidden_extended_connect_fields_fail_before_io() -> TestResult<()> {
    let connector = extended_connector()?;
    for header in [
        RequestHeader::new("host", TEST_SERVER_NAME),
        RequestHeader::new("connection", "upgrade"),
        RequestHeader::new("upgrade", "websocket"),
        RequestHeader::new("content-length", "0"),
        RequestHeader::new("transfer-encoding", "chunked"),
        RequestHeader::new("Sec-WebSocket-Version", "13"),
    ] {
        let error = connector
            .validate_extended_connect(
                Http3ExtendedProtocol::WebSocket,
                TEST_SERVER_NAME,
                &OriginForm::parse("/")?,
                &[header],
            )
            .err()
            .ok_or("forbidden extended CONNECT field was accepted")?;
        assert_eq!(error.kind(), Http3ConnectorErrorKind::Request);
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn accepted_stream_carries_simultaneous_duplex_data() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (request, mut stream, _connection) = accept_extended(&endpoint, false).await?;
        assert_eq!(request.method(), Method::CONNECT);
        assert_eq!(
            request.extensions().get::<h3::ext::Protocol>(),
            Some(&h3::ext::Protocol::WEBSOCKET)
        );
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        stream
            .send_data(Bytes::from_static(b"server-first"))
            .await?;
        let received = recv_all(&mut stream).await?;
        assert_eq!(received, b"client-payload");
        stream.finish().await?;
        let _ = done_received.await;
        Ok(())
    });

    let connection = connect_extended(address, &identity).await?;
    let mut stream = accepted(send(&connection, address, Vec::new()).await?)?;
    let mut first = [0_u8; 12];
    timeout(TEST_TIMEOUT, stream.read_exact(&mut first))
        .await
        .map_err(|_| "server data timed out")??;
    assert_eq!(&first, b"server-first");
    stream.write_all(b"client-payload").await?;
    stream.shutdown().await?;
    let mut rest = Vec::new();
    timeout(TEST_TIMEOUT, stream.read_to_end(&mut rest))
        .await
        .map_err(|_| "server FIN timed out")??;
    assert!(rest.is_empty());
    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn shutdown_sends_fin_without_reset() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (_request, mut stream, _connection) = accept_extended(&endpoint, false).await?;
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        let received = recv_all(&mut stream).await?;
        assert_eq!(received, b"bye");
        assert!(stream.recv_trailers().await?.is_none());
        stream.finish().await?;
        let _ = done_received.await;
        Ok(())
    });

    let connection = connect_extended(address, &identity).await?;
    let mut stream = accepted(send(&connection, address, Vec::new()).await?)?;
    stream.write_all(b"bye").await?;
    stream.shutdown().await?;
    let mut rest = Vec::new();
    timeout(TEST_TIMEOUT, stream.read_to_end(&mut rest))
        .await
        .map_err(|_| "server FIN timed out")??;
    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn rejected_extended_connect_streams_body_with_ordered_fields() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (_request, mut stream, _connection) = accept_extended(&endpoint, false).await?;
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("x-reason", "denied")
                    .body(())?,
            )
            .await?;
        stream.send_data(Bytes::from_static(b"not allowed")).await?;
        stream.finish().await?;
        assert!(recv_all(&mut stream).await?.is_empty());
        let _ = done_received.await;
        Ok(())
    });

    let connection = connect_extended(address, &identity).await?;
    let Http3ExtendedConnectOutcome::Rejected(response) =
        send(&connection, address, Vec::new()).await?
    else {
        return Err("forbidden extended CONNECT was accepted".into());
    };
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        response
            .extensions()
            .get::<OrderedResponseHeaders>()
            .is_some()
    );
    assert_eq!(
        response.headers().get("x-reason"),
        Some(&HeaderValue::from_static("denied"))
    );
    let body = timeout(TEST_TIMEOUT, response.into_body().collect())
        .await
        .map_err(|_| "rejection body timed out")??
        .to_bytes();
    assert_eq!(body, Bytes::from_static(b"not allowed"));
    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn switching_protocols_response_is_protocol_error() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let connection = accept_raw(&endpoint).await?;
        let _control =
            send_raw_settings(&connection, &[SETTINGS_ENABLE_CONNECT_PROTOCOL, 1]).await?;
        let (mut response, mut request) = connection.accept_bi().await?;
        let _ = read_headers_frame(&mut request).await?;
        write_headers(
            &mut response,
            &[0x00, 0x00, 0x5f, 0x09, 0x03, b'1', b'0', b'1'],
        )
        .await?;
        let _ = done_received.await;
        Ok(())
    });

    let connection = connect(address, client_config(&identity)?).await?;
    let error = timeout(TEST_TIMEOUT, send(&connection, address, Vec::new()))
        .await
        .map_err(|_| "extended CONNECT timed out")?
        .err()
        .ok_or("101 response was accepted over HTTP/3")?;
    assert_eq!(error.kind(), Http3ErrorKind::Protocol);
    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn dropped_stream_cancels_only_itself_with_request_cancelled() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (_request, mut stream, mut connection) = accept_extended(&endpoint, false).await?;
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        let error = timeout(TEST_TIMEOUT, stream.recv_data())
            .await
            .map_err(|_| "client reset timed out")?
            .err()
            .ok_or("dropped stream ended gracefully")?;
        assert!(
            matches!(
                error,
                h3::error::StreamError::RemoteTerminate {
                    code: h3::error::Code::H3_REQUEST_CANCELLED
                }
            ),
            "unexpected reset: {error:?}"
        );

        let (request, mut sibling) = connection
            .accept()
            .await?
            .ok_or("client closed before its sibling request")?
            .resolve_request()
            .await?;
        assert_eq!(request.uri().path(), "/sibling");
        sibling
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        sibling.send_data(Bytes::from_static(b"alive")).await?;
        sibling.finish().await?;
        let _ = done_received.await;
        Ok(())
    });

    let connection = connect_extended(address, &identity).await?;
    let stream = accepted(send(&connection, address, Vec::new()).await?)?;
    drop(stream);
    let sibling = Request::get(format!("https://{TEST_SERVER_NAME}/sibling")).body(())?;
    let body = timeout(TEST_TIMEOUT, async {
        connection
            .send_request(sibling, None)
            .await?
            .into_body()
            .collect()
            .await
    })
    .await
    .map_err(|_| "sibling request timed out")??
    .to_bytes();
    assert_eq!(body, Bytes::from_static(b"alive"));
    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn peer_trailers_are_invalid_data() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (_request, mut stream, _connection) = accept_extended(&endpoint, false).await?;
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        stream.send_data(Bytes::from_static(b"x")).await?;
        let mut trailers = HeaderMap::new();
        trailers.insert("x-trailer", HeaderValue::from_static("value"));
        stream.send_trailers(trailers).await?;
        stream.finish().await?;
        let _ = recv_all(&mut stream).await;
        let _ = done_received.await;
        Ok(())
    });

    let connection = connect_extended(address, &identity).await?;
    let mut stream = accepted(send(&connection, address, Vec::new()).await?)?;
    let mut received = Vec::new();
    let error = timeout(TEST_TIMEOUT, stream.read_to_end(&mut received))
        .await
        .map_err(|_| "trailers timed out")?
        .err()
        .ok_or("peer trailers ended the stream successfully")?;
    assert_eq!(received, b"x");
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    stream.shutdown().await?;
    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn datagram_on_extended_stream_aborts_only_that_stream() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel::<()>();
    let (accepted_sent, accepted_received) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (_request, mut stream, mut connection) = accept_extended(&endpoint, true).await?;
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        accepted_received
            .await
            .map_err(|_| "client did not accept the extended CONNECT stream")?;
        let mut datagrams = connection.get_datagram_sender(stream.id());
        datagrams.send_datagram(Bytes::from_static(b"unexpected"))?;
        let error = timeout(TEST_TIMEOUT, stream.recv_data())
            .await
            .map_err(|_| "datagram abort timed out")?
            .err()
            .ok_or("aborted stream ended gracefully")?;
        assert!(
            matches!(
                error,
                h3::error::StreamError::RemoteTerminate {
                    code: h3::error::Code::H3_DATAGRAM_ERROR
                }
            ),
            "unexpected abort: {error:?}"
        );

        let (_request, mut sibling) = connection
            .accept()
            .await?
            .ok_or("client closed before its sibling request")?
            .resolve_request()
            .await?;
        sibling
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        sibling.finish().await?;
        let _ = done_received.await;
        Ok(())
    });

    let settings = chromium::v152_http3();
    let connection = timeout(
        TEST_TIMEOUT,
        super::super::connect_direct(
            address,
            TEST_SERVER_NAME,
            profiled_client_config(&identity)?,
            &settings,
        ),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??;
    let mut stream = accepted(send(&connection, address, Vec::new()).await?)?;
    let _ = accepted_sent.send(());
    let mut buffer = [0_u8; 1];
    let error = timeout(TEST_TIMEOUT, stream.read(&mut buffer))
        .await
        .map_err(|_| "datagram violation timed out")?
        .err()
        .ok_or("stream kept reading after a datagram violation")?;
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    let sibling = Request::get(format!("https://{TEST_SERVER_NAME}/sibling")).body(())?;
    let response = timeout(TEST_TIMEOUT, connection.send_request(sibling, None))
        .await
        .map_err(|_| "sibling request timed out")??;
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);
    drop(stream);
    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn stream_lease_keeps_driver_alive_until_complete() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (_request, mut stream, _connection) = accept_extended(&endpoint, false).await?;
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        let received = recv_all(&mut stream).await?;
        stream.send_data(Bytes::from(received)).await?;
        stream.finish().await?;
        let _ = done_received.await;
        Ok(())
    });

    let connection = connect_extended(address, &identity).await?;
    let mut stream = accepted(send(&connection, address, Vec::new()).await?)?;
    drop(connection);
    stream.write_all(b"echo").await?;
    stream.shutdown().await?;
    let mut echoed = Vec::new();
    timeout(TEST_TIMEOUT, stream.read_to_end(&mut echoed))
        .await
        .map_err(|_| "echo timed out after dropping the connection handle")??;
    assert_eq!(echoed, b"echo");
    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn foreign_connector_connection_is_rejected() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let connection = accept_raw(&endpoint).await?;
        let _control =
            send_raw_settings(&connection, &[SETTINGS_ENABLE_CONNECT_PROTOCOL, 1]).await?;
        let opened = tokio::select! {
            opened = connection.accept_bi() => opened.is_ok(),
            _ = done_received => false,
        };
        if opened {
            return Err("foreign connection opened a request stream".into());
        }
        Ok(())
    });

    let connection = connect(address, client_config(&identity)?).await?;
    let error = extended_connector()?
        .send_extended_connect_on(
            &connection,
            Http3ExtendedProtocol::WebSocket,
            TEST_SERVER_NAME,
            OriginForm::parse("/")?,
            Vec::new(),
        )
        .await
        .err()
        .ok_or("foreign connection was accepted")?;
    assert_eq!(error.kind(), Http3ConnectorErrorKind::Request);
    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn extended_connect_span_records_outcome_without_field_values() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        let (_request, mut stream, _connection) = accept_extended(&endpoint, false).await?;
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        let _ = recv_all(&mut stream).await;
        let _ = done_received.await;
        Ok(())
    });

    let connection = connect_extended(address, &identity).await?;
    let subscriber = OutcomeSubscriber::default();
    let outcome = send(
        &connection,
        address,
        vec![RequestHeader::new("x-secret", "do-not-trace")],
    )
    .with_subscriber(subscriber.dispatch())
    .await?;
    let mut stream = accepted(outcome)?;
    assert_eq!(
        subscriber.outcomes_for("http3.extended_connect.response_head"),
        ["accepted"]
    );
    assert_eq!(
        subscriber.field_values_for("http3.extended_connect.response_head", "extended_protocol"),
        ["websocket"]
    );
    assert_eq!(
        subscriber.field_values_for("http3.extended_connect.response_head", "method"),
        ["CONNECT"]
    );
    stream.shutdown().await?;
    let _ = client_done.send(());
    join_server(server).await
}

fn extended_request_settings() -> Http3RequestSettings {
    let mut settings = chromium::v152_http3_request();
    settings.extended_connect_pseudo_header_order = Some(vec![
        Http3PseudoHeader::Method,
        Http3PseudoHeader::Protocol,
        Http3PseudoHeader::Scheme,
        Http3PseudoHeader::Authority,
        Http3PseudoHeader::Path,
    ]);
    settings
}

fn extended_connector() -> TestResult<Http3Connector> {
    Ok(Http3Connector::new(
        &chromium::v152_http3_tls(),
        &chromium::v152_quic(),
        &chromium::v152_http3(),
        &extended_request_settings(),
    )?)
}

async fn send(
    connection: &Http3Connection,
    address: std::net::SocketAddr,
    headers: Vec<RequestHeader>,
) -> Result<Http3ExtendedConnectOutcome, Http3Error> {
    let authority = format!("{TEST_SERVER_NAME}:{}", address.port());
    let request = super::super::request::prepare_extended_connect(
        &extended_request_settings(),
        Http3ExtendedProtocol::WebSocket.wire_value(),
        &authority,
        OriginForm::parse("/chat?room=1").map_err(|_| {
            Http3Error::without_source(Http3ErrorKind::Request, "invalid test target")
        })?,
        headers,
    )?;
    connection
        .send_extended_connect(Http3ExtendedProtocol::WebSocket, request)
        .await
}

fn accepted(outcome: Http3ExtendedConnectOutcome) -> TestResult<Http3ExtendedConnectStream> {
    match outcome {
        Http3ExtendedConnectOutcome::Accepted { response, stream } => {
            assert_eq!(response.status(), StatusCode::OK);
            Ok(stream)
        }
        Http3ExtendedConnectOutcome::Rejected(response) => {
            Err(format!("extended CONNECT was rejected with {}", response.status()).into())
        }
    }
}

async fn connect(
    address: std::net::SocketAddr,
    client: std::sync::Arc<phantom_quic_btls::QuicClientConfig>,
) -> TestResult<Http3Connection> {
    Ok(timeout(
        TEST_TIMEOUT,
        super::super::connect_direct(address, TEST_SERVER_NAME, client, &test_settings()),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??)
}

async fn connect_extended(
    address: std::net::SocketAddr,
    identity: &TestIdentity,
) -> TestResult<Http3Connection> {
    connect(address, client_config(identity)?).await
}

async fn accept_raw(endpoint: &quinn::Endpoint) -> TestResult<quinn::Connection> {
    let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
    Ok(incoming.await?)
}

async fn send_raw_settings(
    connection: &quinn::Connection,
    settings: &[u8],
) -> TestResult<quinn::SendStream> {
    let mut control = connection.open_uni().await?;
    let length = u8::try_from(settings.len())?;
    control.write_all(&[0x00, 0x04, length]).await?;
    control.write_all(settings).await?;
    Ok(control)
}

async fn read_headers_frame(stream: &mut quinn::RecvStream) -> TestResult<Bytes> {
    let frame_type = read_varint(stream).await?;
    if frame_type != u64::from(HEADERS_FRAME) {
        return Err("request stream did not begin with HEADERS".into());
    }
    let length = usize::try_from(read_varint(stream).await?)?;
    let mut section = vec![0_u8; length];
    stream.read_exact(&mut section).await?;
    Ok(Bytes::from(section))
}

async fn write_headers(stream: &mut quinn::SendStream, field_section: &[u8]) -> TestResult<()> {
    stream
        .write_all(&[HEADERS_FRAME, u8::try_from(field_section.len())?])
        .await?;
    stream.write_all(field_section).await?;
    Ok(())
}

async fn read_varint(stream: &mut quinn::RecvStream) -> TestResult<u64> {
    let mut first = [0];
    stream.read_exact(&mut first).await?;
    let width = 1_usize << (first[0] >> 6);
    let mut encoded = [0; 8];
    encoded[0] = first[0];
    stream.read_exact(&mut encoded[1..width]).await?;
    Ok(encoded[..width]
        .iter()
        .enumerate()
        .fold(0_u64, |value, (index, byte)| {
            let byte = if index == 0 { *byte & 0x3f } else { *byte };
            (value << 8) | u64::from(byte)
        }))
}

async fn accept_extended(
    endpoint: &quinn::Endpoint,
    datagrams: bool,
) -> TestResult<(
    Request<()>,
    h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    h3::server::Connection<h3_quinn::Connection, Bytes>,
)> {
    let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
    let quinn = incoming.await?;
    let mut builder = h3::server::builder();
    builder.enable_extended_connect(true);
    if datagrams {
        builder.enable_datagram(true);
    }
    let mut connection = builder.build(h3_quinn::Connection::new(quinn)).await?;
    let (request, stream) = connection
        .accept()
        .await?
        .ok_or("client closed before sending extended CONNECT")?
        .resolve_request()
        .await?;
    Ok((request, stream, connection))
}

async fn recv_all(
    stream: &mut h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
) -> Result<Vec<u8>, Box<dyn Error + Send + Sync>> {
    let mut received = Vec::new();
    while let Some(mut data) = timeout(TEST_TIMEOUT, stream.recv_data())
        .await
        .map_err(|_| "request data timed out")??
    {
        received.extend_from_slice(&data.copy_to_bytes(data.remaining()));
    }
    Ok(received)
}
