use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    task::{Context, Poll, Waker},
};

use bytes::{Buf, Bytes};
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom_profile::{CipherSuite, TlsVersion, chromium};

use super::super::{Http3Connector, Http3ConnectorError, Http3ConnectorErrorKind};
use super::{TestResult, accept_request, server_endpoint};
use crate::request::{OriginForm, RequestHeader};
use crate::tls::test_support::{TEST_SERVER_NAME, TestIdentity};

#[test]
fn constructor_rejects_tcp_tls_recipe() {
    let result = Http3Connector::new(
        &chromium::v152_macos_tls(),
        &chromium::v152_macos_quic(),
        &chromium::v152_macos_http3(),
        &chromium::v152_macos_http3_request(),
    );
    let error = result
        .err()
        .unwrap_or_else(|| panic!("TCP TLS recipe was accepted for QUIC"));
    assert_eq!(error.kind(), Http3ConnectorErrorKind::InvalidProfile);
}

#[test]
fn datagram_mismatch_is_an_invalid_profile() {
    let mut quic = chromium::v152_macos_quic();
    quic.max_datagram_frame_size = Some(0);
    let result = Http3Connector::new(
        &h3_tls_settings(),
        &quic,
        &chromium::v152_macos_http3(),
        &chromium::v152_macos_http3_request(),
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
        &chromium::v152_macos_quic(),
        &chromium::v152_macos_http3(),
        &chromium::v152_macos_http3_request(),
        [&invalid_root[..]],
    );
    let error = result
        .err()
        .unwrap_or_else(|| panic!("invalid trust root was accepted"));
    assert_eq!(error.kind(), Http3ConnectorErrorKind::TrustStore);
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
        &chromium::v152_macos_quic(),
        &chromium::v152_macos_http3(),
        &chromium::v152_macos_http3_request(),
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
        &chromium::v152_macos_http3_request(),
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
            &chromium::v152_macos_quic(),
            &chromium::v152_macos_http3(),
            &chromium::v152_macos_http3_request(),
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

fn connector() -> Result<Http3Connector, Http3ConnectorError> {
    Http3Connector::new(
        &h3_tls_settings(),
        &chromium::v152_macos_quic(),
        &chromium::v152_macos_http3(),
        &chromium::v152_macos_http3_request(),
    )
}

fn h3_tls_settings() -> phantom_profile::TlsSettings {
    let mut settings = chromium::v152_macos_tls();
    settings.min_version = TlsVersion::Tls13;
    settings.max_version = TlsVersion::Tls13;
    settings.cipher_suites = vec![
        CipherSuite::Aes128GcmSha256,
        CipherSuite::Aes256GcmSha384,
        CipherSuite::Chacha20Poly1305Sha256,
    ];
    settings.alpn_protocols = vec![Box::from(&b"h3"[..])];
    settings.alps = None;
    settings.session_tickets = false;
    settings
}
