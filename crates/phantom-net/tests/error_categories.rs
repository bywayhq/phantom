use std::error::Error;

use bytes::Bytes;
use http::Method;
use http_body_util::BodyExt as _;
use phantom_net::{
    http1::{
        self, Http1Error, Http1ErrorKind, Http1TlsConnector, Http1TlsError, Http1TlsErrorKind,
    },
    http2::{
        self, Http2Error, Http2ErrorKind, Http2TlsConnector, Http2TlsError, Http2TlsErrorKind,
    },
    request::{OriginForm, RequestBody, RequestHeader},
};
use phantom_profile::browser::chrome;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn invalid_fields_are_request_errors_on_both_protocols() -> TestResult {
    let target = OriginForm::parse("/")?;
    let h1 = http1::validate_get(&target, &[])
        .err()
        .ok_or("missing Host accepted")?;
    assert_eq!(h1.kind(), Http1ErrorKind::Request);
    assert!(matches!(h1, Http1Error::MissingHost));
    let h2 = http2::validate_request(
        &Method::GET,
        "example.test",
        &target,
        &[RequestHeader::new("Uppercase", "value")],
        None,
    )
    .err()
    .ok_or("uppercase HTTP/2 field accepted")?;
    assert_eq!(h2.kind(), Http2ErrorKind::Request);
    assert!(matches!(h2, Http2Error::InvalidHeaderName { index: 0 }));
    Ok(())
}

#[test]
fn response_limits_and_connection_failures_have_distinct_categories() {
    assert_eq!(
        Http1Error::ResponseHeadTooLarge { maximum: 1 }.kind(),
        Http1ErrorKind::Response
    );
    assert_eq!(
        Http1Error::ConnectionClosed.kind(),
        Http1ErrorKind::ConnectionClosed
    );
    assert_eq!(
        Http2Error::ResponseHeaderListTooLarge.kind(),
        Http2ErrorKind::Response
    );
    assert_eq!(Http2Error::PingTimeout.kind(), Http2ErrorKind::PingTimeout);
    assert_eq!(
        Http2Error::ReusedConnectionClosed.kind(),
        Http2ErrorKind::ReusedConnectionClosed
    );
    assert_eq!(
        Http2Error::RequestBodyClosed.kind(),
        Http2ErrorKind::ConnectionClosed
    );
    assert_eq!(
        Http2Error::UnsupportedRequestBodyFrame.kind(),
        Http2ErrorKind::RequestBody
    );
    assert_eq!(
        Http2Error::ExtendedConnectProtocolDisabled.kind(),
        Http2ErrorKind::ExtendedConnectUnavailable
    );
}

#[test]
fn missing_alpn_is_a_local_configuration_error() -> TestResult {
    let mut tls = chrome::v154_tcp_tls();
    tls.alpn_protocols = vec![Box::from(&b"other"[..])];
    let h1 = Http1TlsConnector::new(&tls)
        .err()
        .ok_or("missing HTTP/1 ALPN accepted")?;
    assert_eq!(h1.kind(), Http1TlsErrorKind::InvalidConfiguration);
    let h2 = Http2TlsConnector::new(&tls, &chrome::v154_http2())
        .err()
        .ok_or("missing HTTP/2 ALPN accepted")?;
    assert_eq!(h2.kind(), Http2TlsErrorKind::InvalidConfiguration);
    Ok(())
}

#[test]
fn peer_alpn_and_application_settings_failures_are_distinct() {
    let h1 = Http1TlsError::UnsupportedAlpn {
        selected: Box::from(&b"h2"[..]),
    };
    assert_eq!(h1.kind(), Http1TlsErrorKind::UnsupportedAlpn);
    assert_eq!(
        Http2TlsError::MissingNegotiatedAlpn.kind(),
        Http2TlsErrorKind::UnsupportedAlpn
    );
    let h2 = Http2TlsError::InvalidPeerApplicationSettings {
        frame_index: 0,
        offset: 0,
        reason: "invalid frame",
    };
    assert_eq!(h2.kind(), Http2TlsErrorKind::PeerApplicationSettings);
}

#[tokio::test]
async fn bytes_conversion_preserves_payload_and_exact_framing() -> TestResult {
    for bytes in [Bytes::new(), Bytes::from_static(b"request bytes")] {
        let body = RequestBody::from(bytes.clone());
        assert_eq!(body.metadata().exact_length(), Some(bytes.len() as u64));
        assert!(!body.metadata().has_trailers());
        assert_eq!(body.metadata().continue_wait(), None);
        assert_eq!(body.collect().await?.to_bytes(), bytes);
    }
    Ok(())
}

fn source_chain(error: &(dyn Error + 'static)) -> Vec<String> {
    let mut messages = vec![error.to_string()];
    let mut source = error.source();
    while let Some(error) = source {
        messages.push(error.to_string());
        source = error.source();
    }
    messages
}

#[test]
fn proxy_wrappers_keep_typed_sources_without_repeating_their_message() -> TestResult {
    use std::io;

    use phantom_net::{http1_or_2::Http1Or2TlsError, proxy::HttpConnectError};

    const CAUSE: &str = "distinct transport failure marker";
    let errors: Vec<Box<dyn Error>> = vec![
        Box::new(Http1TlsError::Proxy(HttpConnectError::Read(
            io::Error::other(CAUSE),
        ))),
        Box::new(Http2TlsError::Proxy(HttpConnectError::Read(
            io::Error::other(CAUSE),
        ))),
        Box::new(Http1Or2TlsError::Proxy(HttpConnectError::Read(
            io::Error::other(CAUSE),
        ))),
    ];
    for error in errors {
        assert_eq!(error.to_string(), "HTTP proxy failed");
        let proxy = error
            .source()
            .and_then(|source| source.downcast_ref::<HttpConnectError>())
            .ok_or("wrapper omitted typed proxy source")?;
        assert_eq!(proxy.to_string(), "HTTP CONNECT response read failed");
        let transport = proxy
            .source()
            .and_then(|source| source.downcast_ref::<io::Error>())
            .ok_or("proxy omitted typed transport source")?;
        assert_eq!(transport.to_string(), CAUSE);
        assert_eq!(
            source_chain(error.as_ref())
                .join(": ")
                .matches(CAUSE)
                .count(),
            1
        );
    }
    Ok(())
}

#[test]
fn invalid_tls_settings_keep_the_validator_as_the_only_detailed_cause() -> TestResult {
    use phantom_profile::InvalidTlsSettings;

    let mut tls = chrome::v154_tcp_tls();
    tls.cipher_suites.clear();
    let error = Http1TlsConnector::new(&tls)
        .err()
        .ok_or("empty cipher list accepted")?;
    let tls_error = error.source().ok_or("TLS cause missing")?;
    assert_eq!(tls_error.to_string(), "invalid TLS settings");
    let validator = tls_error
        .source()
        .and_then(|source| source.downcast_ref::<InvalidTlsSettings>())
        .ok_or("validator cause missing")?;
    let detail = validator.to_string();
    assert_eq!(
        source_chain(&error)
            .iter()
            .filter(|message| **message == detail)
            .count(),
        1
    );
    Ok(())
}
