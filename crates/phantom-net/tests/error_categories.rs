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
