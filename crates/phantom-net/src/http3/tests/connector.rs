use std::{
    future::Future,
    io::Cursor,
    net::{Ipv4Addr, SocketAddr},
    task::{Context, Poll, Waker},
};

use bytes::{Buf, Bytes};
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom_profile::{chromium, edge};
use phantom_testkit::tls::ClientHelloSummary;
use quinn_proto::{Side, crypto, transport_parameters::TransportParameters};

use super::super::{Http3Connector, Http3ConnectorError, Http3ConnectorErrorKind};
use super::{
    TEST_TIMEOUT, TestResult, accept_request, server_endpoint, server_endpoint_with_bidi_limit,
};
use crate::request::{OriginForm, RequestHeader};
use crate::tls::test_support::{TEST_SERVER_NAME, TestIdentity};

#[test]
fn constructor_rejects_tcp_tls_recipe() {
    let result = Http3Connector::new(
        &chromium::v154_tls(),
        &chromium::v154_quic(),
        &chromium::v154_http3(),
        &chromium::v154_http3_request(),
    );
    let error = result
        .err()
        .unwrap_or_else(|| panic!("TCP TLS recipe was accepted for QUIC"));
    assert_eq!(error.kind(), Http3ConnectorErrorKind::InvalidProfile);
}

#[test]
fn datagram_mismatch_is_an_invalid_profile() {
    let mut quic = chromium::v154_quic();
    quic.max_datagram_frame_size = Some(0);
    let result = Http3Connector::new(
        &h3_tls_settings(),
        &quic,
        &chromium::v154_http3(),
        &chromium::v154_http3_request(),
    );
    let error = result
        .err()
        .unwrap_or_else(|| panic!("HTTP/3 DATAGRAM mismatch was accepted"));
    assert_eq!(error.kind(), Http3ConnectorErrorKind::InvalidProfile);
}

#[test]
fn invalid_additional_root_is_a_trust_store_failure() {
    let invalid_root = [0_u8];
    let result = Http3Connector::new_with_additional_roots(
        &h3_tls_settings(),
        &chromium::v154_quic(),
        &chromium::v154_http3(),
        &chromium::v154_http3_request(),
        [&invalid_root[..]],
    );
    let error = result
        .err()
        .unwrap_or_else(|| panic!("invalid trust root was accepted"));
    assert_eq!(error.kind(), Http3ConnectorErrorKind::TrustStore);
}

#[test]
fn chrome_154_quic_client_hello_recipe_matches_windows_capture() -> TestResult<()> {
    let connector = Http3Connector::new(
        &chromium::v154_http3_tls(),
        &chromium::v154_quic(),
        &chromium::v154_http3(),
        &chromium::v154_http3_request(),
    )?;
    for client_hello in [CHROME_154_H3_CLIENT_HELLO_1, CHROME_154_H3_CLIENT_HELLO_2] {
        assert_connector_matches_quic_client_hello(
            &connector,
            CHROME_154_H3_STARTUP,
            client_hello,
        )?;
    }
    Ok(())
}

/// Edge 153 offers the Chromium QUIC ClientHello without trust-anchor IDs.
#[test]
fn edge_153_quic_client_hello_recipe_matches_windows_capture() -> TestResult<()> {
    let connector = Http3Connector::new(
        &edge::v153_http3_tls(),
        &chromium::v154_quic(),
        &chromium::v154_http3(),
        &chromium::v154_http3_request(),
    )?;
    for client_hello in [EDGE_153_H3_CLIENT_HELLO_1, EDGE_153_H3_CLIENT_HELLO_2] {
        assert_connector_matches_quic_client_hello(&connector, EDGE_153_H3_STARTUP, client_hello)?;
    }
    Ok(())
}

fn assert_connector_matches_quic_client_hello(
    connector: &Http3Connector,
    startup: &str,
    client_hello: &str,
) -> TestResult<()> {
    let parameters = TransportParameters::read(
        Side::Server,
        &mut Cursor::new(fixture_hex(startup, "transport_parameters_hex")?),
    )?;
    let mut session = crypto::ClientConfig::start_session(
        connector.test_crypto(),
        1,
        "server.phantom.test",
        &parameters,
    )?;
    let mut handshake = Vec::new();
    assert!(session.write_handshake(&mut handshake).is_none());

    let expected_handshake = fixture_hex(client_hello, "handshake_hex")?;
    let actual = ClientHelloSummary::from_handshake_bytes(&handshake)?;
    let expected = ClientHelloSummary::from_handshake_bytes(&expected_handshake)?;
    assert_eq!(actual.legacy_version(), expected.legacy_version());
    assert_eq!(actual.server_name(), expected.server_name());
    assert_eq!(actual.cipher_suites(), expected.cipher_suites());
    assert_eq!(actual.supported_versions(), expected.supported_versions());
    assert_eq!(actual.supported_groups(), expected.supported_groups());
    assert_eq!(actual.key_share_groups(), expected.key_share_groups());
    assert_eq!(
        actual.signature_algorithms(),
        expected.signature_algorithms()
    );
    assert_eq!(actual.alpn_protocols(), expected.alpn_protocols());
    assert_eq!(
        sorted_trust_anchor_ids(&actual),
        sorted_trust_anchor_ids(&expected)
    );

    let mut actual_extensions = actual.extension_types().to_vec();
    actual_extensions.sort_unstable();
    let mut expected_extensions = expected.extension_types().to_vec();
    expected_extensions.sort_unstable();
    assert_eq!(actual_extensions, expected_extensions);
    let actual_alps =
        client_hello_extension(&handshake, 0x44cd).ok_or("profiled ClientHello omitted ALPS")?;
    let expected_alps = client_hello_extension(&expected_handshake, 0x44cd)
        .ok_or("retained ClientHello omitted ALPS")?;
    assert_eq!(actual_alps, expected_alps);
    assert_eq!(actual_alps, b"\x00\x03\x02h3");
    Ok(())
}

#[test]
fn request_preparation_precedes_runtime_check() -> Result<(), Box<dyn std::error::Error>> {
    let connector = connector()?;
    let request = connector.send_get_direct(
        "127.0.0.1",
        443,
        "example.test",
        "example.test",
        OriginForm::parse("/")?,
        vec![RequestHeader::new("Uppercase", "rejected")],
    );
    let mut request = std::pin::pin!(request);
    let mut context = Context::from_waker(Waker::noop());
    let result = match request.as_mut().poll(&mut context) {
        Poll::Ready(result) => result,
        Poll::Pending => return Err("invalid request waited for a Tokio runtime".into()),
    };
    let error = result
        .err()
        .ok_or("invalid request unexpectedly succeeded")?;
    assert_eq!(error.kind(), Http3ConnectorErrorKind::Request);
    Ok(())
}

#[test]
fn missing_runtime_is_typed() -> Result<(), Box<dyn std::error::Error>> {
    let connector = connector()?;
    let request = connector.send_get_direct(
        "127.0.0.1",
        443,
        "example.test",
        "example.test",
        OriginForm::parse("/")?,
        Vec::new(),
    );
    let mut request = std::pin::pin!(request);
    let mut context = Context::from_waker(Waker::noop());
    let result = match request.as_mut().poll(&mut context) {
        Poll::Ready(result) => result,
        Poll::Pending => return Err("request waited outside a Tokio runtime".into()),
    };
    let error = result.err().ok_or("request unexpectedly succeeded")?;
    assert_eq!(error.kind(), Http3ConnectorErrorKind::RuntimeUnavailable);
    Ok(())
}

#[test]
fn invalid_server_name_precedes_runtime_and_dns() -> Result<(), Box<dyn std::error::Error>> {
    let connector = connector()?;
    let request = connector.send_get_direct(
        "does-not-resolve.invalid",
        443,
        "absolute.example.",
        "absolute.example.",
        OriginForm::parse("/")?,
        Vec::new(),
    );
    let mut request = std::pin::pin!(request);
    let mut context = Context::from_waker(Waker::noop());
    let result = match request.as_mut().poll(&mut context) {
        Poll::Ready(result) => result,
        Poll::Pending => return Err("invalid server name reached runtime or DNS".into()),
    };
    let error = result.err().ok_or("invalid server name was accepted")?;
    assert_eq!(error.kind(), Http3ConnectorErrorKind::Request);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn retries_a_later_resolved_address_before_sending_the_request() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = Http3Connector::new_with_additional_roots(
        &h3_tls_settings(),
        &chromium::v154_quic(),
        &chromium::v154_http3(),
        &chromium::v154_http3_request(),
        [identity.root_der()],
    )?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (request, mut stream, _connection) = accept_request(&endpoint).await?;
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(
            request
                .headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some("7")
        );
        let mut received = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            let remaining = chunk.remaining();
            received.extend_from_slice(&chunk.copy_to_bytes(remaining));
        }
        assert_eq!(received, b"payload");
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        let _ = done_received.await;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    let request = super::super::prepare_traced_request(
        &chromium::v154_http3_request(),
        http::Method::POST,
        TEST_SERVER_NAME,
        OriginForm::parse("/")?,
        Vec::new(),
        Some(Bytes::from_static(b"payload")),
    )?;
    let unusable = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), address.port());

    let response = connector
        .send_prepared_to_addresses(vec![unusable, address], TEST_SERVER_NAME, request)
        .await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    response.into_body().collect().await?;
    let _ = client_done.send(());
    server.await??;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn connection_cannot_cross_connector_identity() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let build_connector = || {
        Http3Connector::new_with_additional_roots(
            &h3_tls_settings(),
            &chromium::v154_quic(),
            &chromium::v154_http3(),
            &chromium::v154_http3_request(),
            [identity.root_der()],
        )
    };
    let first = build_connector()?;
    let second = build_connector()?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
        let connection = incoming.await?;
        let _connection: h3::server::Connection<_, bytes::Bytes> =
            h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
        let _ = done_received.await;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    let host = address.ip().to_string();
    let connection = first
        .connect_direct(&host, address.port(), TEST_SERVER_NAME)
        .await?;

    assert!(!second.can_reuse(&connection).await);
    let error = second
        .send_get_on(
            &connection,
            TEST_SERVER_NAME,
            OriginForm::parse("/")?,
            Vec::new(),
        )
        .await
        .err()
        .ok_or("connection crossed connector identity")?;
    assert_eq!(error.kind(), Http3ConnectorErrorKind::Request);

    drop(connection);
    let _ = client_done.send(());
    server.await??;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn reuse_check_is_prompt_while_a_request_waits_for_peer_settings() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = std::sync::Arc::new(trusting_connector(&identity)?);
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
        let _connection = incoming.await?;
        let _ = done_received.await;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    let connection = tokio::time::timeout(
        TEST_TIMEOUT,
        connector.connect_direct(&address.ip().to_string(), address.port(), TEST_SERVER_NAME),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??;

    let parked = spawn_parked_get(&connector, &connection, OriginForm::parse("/")?).await;
    assert!(!parked.is_finished());
    assert!(
        tokio::time::timeout(REUSE_CHECK_BOUND, connector.can_reuse(&connection))
            .await
            .map_err(|_| "reuse check waited behind a request parked on peer SETTINGS")?
    );

    parked.abort();
    drop(connection);
    let _ = client_done.send(());
    server.await??;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn reuse_check_is_prompt_while_a_request_waits_for_stream_credit() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = std::sync::Arc::new(trusting_connector(&identity)?);
    let (address, endpoint) = server_endpoint_with_bidi_limit(&identity, 1)?;
    let (first_seen, first_received) = tokio::sync::oneshot::channel();
    let (client_done, done_received) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
        let connection = incoming.await?;
        let mut connection: h3::server::Connection<_, Bytes> =
            h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
        let resolver = connection
            .accept()
            .await?
            .ok_or("client closed before sending a request")?;
        let (_request, _held) = resolver.resolve_request().await?;
        let _ = first_seen.send(());
        let _ = done_received.await;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    let connection = tokio::time::timeout(
        TEST_TIMEOUT,
        connector.connect_direct(&address.ip().to_string(), address.port(), TEST_SERVER_NAME),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??;

    let first = spawn_parked_get(&connector, &connection, OriginForm::parse("/")?).await;
    tokio::time::timeout(TEST_TIMEOUT, first_received)
        .await
        .map_err(|_| "server did not receive the first request")??;
    let parked = spawn_parked_get(&connector, &connection, OriginForm::parse("/")?).await;
    assert!(!parked.is_finished());
    assert!(
        tokio::time::timeout(REUSE_CHECK_BOUND, connector.can_reuse(&connection))
            .await
            .map_err(|_| "reuse check waited behind a request parked on MAX_STREAMS")?
    );

    parked.abort();
    first.abort();
    drop(connection);
    let _ = client_done.send(());
    server.await??;
    Ok(())
}

const REUSE_CHECK_BOUND: std::time::Duration = std::time::Duration::from_secs(1);

async fn spawn_parked_get(
    connector: &std::sync::Arc<Http3Connector>,
    connection: &super::super::Http3Connection,
    target: OriginForm,
) -> tokio::task::JoinHandle<Result<(), Http3ConnectorError>> {
    let connector = std::sync::Arc::clone(connector);
    let connection = connection.clone();
    let request = tokio::spawn(async move {
        connector
            .send_get_on(&connection, TEST_SERVER_NAME, target, Vec::new())
            .await
            .map(drop)
    });
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    request
}

fn trusting_connector(identity: &TestIdentity) -> Result<Http3Connector, Http3ConnectorError> {
    Http3Connector::new_with_additional_roots(
        &h3_tls_settings(),
        &chromium::v154_quic(),
        &chromium::v154_http3(),
        &chromium::v154_http3_request(),
        [identity.root_der()],
    )
}

fn connector() -> Result<Http3Connector, Http3ConnectorError> {
    Http3Connector::new(
        &h3_tls_settings(),
        &chromium::v154_quic(),
        &chromium::v154_http3(),
        &chromium::v154_http3_request(),
    )
}

fn h3_tls_settings() -> phantom_profile::TlsSettings {
    chromium::v154_http3_tls()
}

const CHROME_154_H3_STARTUP: &str = include_str!(concat!(
    "../../../../../fixtures/http3/chrome/154.0.8037.58/",
    "windows-11-26200/client-startup.txt"
));
const CHROME_154_H3_CLIENT_HELLO_1: &str = include_str!(concat!(
    "../../../../../fixtures/http3/chrome/154.0.8037.58/",
    "windows-11-26200/quic-client-hello-1.txt"
));
const CHROME_154_H3_CLIENT_HELLO_2: &str = include_str!(concat!(
    "../../../../../fixtures/http3/chrome/154.0.8037.58/",
    "windows-11-26200/quic-client-hello-2.txt"
));
const EDGE_153_H3_STARTUP: &str = include_str!(concat!(
    "../../../../../fixtures/http3/edge/153.0.4234.48/",
    "windows-11-26200/client-startup.txt"
));
const EDGE_153_H3_CLIENT_HELLO_1: &str = include_str!(concat!(
    "../../../../../fixtures/http3/edge/153.0.4234.48/",
    "windows-11-26200/quic-client-hello-1.txt"
));
const EDGE_153_H3_CLIENT_HELLO_2: &str = include_str!(concat!(
    "../../../../../fixtures/http3/edge/153.0.4234.48/",
    "windows-11-26200/quic-client-hello-2.txt"
));

fn fixture_hex(
    fixture: &str,
    field: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let prefix = format!("{field}=");
    let encoded = fixture
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .ok_or("fixture omitted hexadecimal field")?;
    if encoded.len() % 2 != 0 {
        return Err("fixture hexadecimal field has odd length".into());
    }
    encoded
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|digits| {
            let digits = std::str::from_utf8(digits)?;
            Ok(u8::from_str_radix(digits, 16)?)
        })
        .collect()
}

fn client_hello_extension(client_hello: &[u8], expected: u16) -> Option<&[u8]> {
    let mut offset = 4 + 2 + 32;
    offset += 1 + usize::from(*client_hello.get(offset)?);
    let cipher_len = usize::from(u16::from_be_bytes([
        *client_hello.get(offset)?,
        *client_hello.get(offset + 1)?,
    ]));
    offset += 2 + cipher_len;
    offset += 1 + usize::from(*client_hello.get(offset)?);
    let extensions_len = usize::from(u16::from_be_bytes([
        *client_hello.get(offset)?,
        *client_hello.get(offset + 1)?,
    ]));
    offset += 2;
    let end = offset.checked_add(extensions_len)?;
    while offset < end {
        let kind = u16::from_be_bytes([*client_hello.get(offset)?, *client_hello.get(offset + 1)?]);
        let len = usize::from(u16::from_be_bytes([
            *client_hello.get(offset + 2)?,
            *client_hello.get(offset + 3)?,
        ]));
        offset += 4;
        let next = offset.checked_add(len)?;
        let payload = client_hello.get(offset..next)?;
        if kind == expected {
            return Some(payload);
        }
        offset = next;
    }
    None
}

fn sorted_trust_anchor_ids(summary: &ClientHelloSummary) -> Option<Vec<Vec<u8>>> {
    summary.requested_trust_anchor_ids().map(|identifiers| {
        let mut identifiers = identifiers.to_vec();
        identifiers.sort_unstable();
        identifiers
    })
}
