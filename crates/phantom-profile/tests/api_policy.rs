use phantom_profile::{
    CertificateCompression, ClientHint, ClientHintDelivery, ClientHintSettings, Http1IdleTimeout,
    Http2PseudoHeader, Http3PseudoHeader, Http3Setting, ValidationErrorKind, browser::chrome,
};
use phantom_profile::{RequestField, UrlTrust, WebSocketField};
use std::{error::Error, num::NonZeroU32, time::Duration};

#[test]
fn ordinary_and_websocket_fields_share_the_same_url_trust_selector() {
    let ordinary = RequestField::by_trust("X-Trust", "trusted", "other");
    let websocket = WebSocketField::by_trust("X-Trust", "trusted", "other");
    for (trust, expected) in [
        (UrlTrust::PotentiallyTrustworthy, Some("trusted")),
        (UrlTrust::Untrustworthy, Some("other")),
    ] {
        assert_eq!(ordinary.default_value(trust), expected);
        assert_eq!(websocket.default_value(trust), expected);
    }
}

#[test]
fn url_trust_selects_omission_without_changing_literal_fields() {
    let ordinary = RequestField::trustworthy_only("X-Trust", "trusted");
    let websocket = WebSocketField::trustworthy_only("X-Trust", "trusted");
    assert_eq!(ordinary.default_value(UrlTrust::Untrustworthy), None);
    assert_eq!(websocket.default_value(UrlTrust::Untrustworthy), None);
    assert_eq!(
        ordinary.default_value(UrlTrust::PotentiallyTrustworthy),
        Some("trusted")
    );
    assert_eq!(
        websocket.default_value(UrlTrust::PotentiallyTrustworthy),
        Some("trusted")
    );
    for trust in [UrlTrust::PotentiallyTrustworthy, UrlTrust::Untrustworthy] {
        assert_eq!(
            RequestField::literal("X-Value", "value").default_value(trust),
            Some("value")
        );
        assert_eq!(
            WebSocketField::literal("X-Value", "value").default_value(trust),
            Some("value")
        );
    }
}

#[test]
fn hint_errors_distinguish_invalid_names_from_duplicate_names() {
    let hint = ClientHint::new("sec-ch-ua", "value", ClientHintDelivery::Default);
    let duplicate = ClientHintSettings::new(vec![hint.clone(), hint])
        .validate()
        .unwrap_err();
    assert_eq!(duplicate.kind(), ValidationErrorKind::Duplicate);
    let malformed = ClientHintSettings::new(vec![ClientHint::new(
        "Sec-CH-UA",
        "value",
        ClientHintDelivery::Default,
    )])
    .validate()
    .unwrap_err();
    assert_eq!(malformed.kind(), ValidationErrorKind::InvalidValue);
    assert_eq!(malformed.field(), duplicate.field());
    assert!(duplicate.source().is_none());
}

#[test]
fn http1_and_tcp_errors_keep_their_diagnostics_and_range_category() {
    let mut http1 = chrome::v154_http1();
    http1.idle_timeout = Http1IdleTimeout::ClosedOnTimer(Duration::from_secs(65536));
    let error = http1.validate().unwrap_err();
    assert_eq!(error.kind(), ValidationErrorKind::OutOfRange);
    assert_eq!(error.field(), "idle_timeout");
    assert_eq!(
        error.reason(),
        "a timer's idle limit must be at most 65535 seconds"
    );
    assert_eq!(
        error.to_string(),
        format!("invalid HTTP/1.1 {}: {}", error.field(), error.reason())
    );
    assert!(error.source().is_none());

    let mut tcp = chrome::v154_tcp();
    tcp.send_buffer_size = NonZeroU32::new(u32::MAX);
    let error = tcp.validate().unwrap_err();
    assert_eq!(error.kind(), ValidationErrorKind::OutOfRange);
    assert_eq!(error.field(), "send_buffer_size");
    assert_eq!(
        error.reason(),
        "send buffer size must fit in a signed 32-bit socket option"
    );
    assert!(error.source().is_none());
}

#[test]
fn http2_errors_distinguish_missing_settings_duplicates_and_inconsistent_timers() {
    let mut settings = chrome::v154_http2();
    settings.initial_settings.clear();
    assert_eq!(
        settings.validate().unwrap_err().kind(),
        ValidationErrorKind::Missing
    );

    let mut settings = chrome::v154_http2();
    settings.initial_settings.push(settings.initial_settings[0]);
    assert_eq!(
        settings.validate().unwrap_err().kind(),
        ValidationErrorKind::Duplicate
    );

    let mut settings = chrome::v154_http2();
    settings.idle_ping_after = None;
    settings.idle_ping_timeout = Some(Duration::from_secs(1));
    let inconsistent = settings.validate().unwrap_err();
    assert_eq!(inconsistent.kind(), ValidationErrorKind::Inconsistent);
    assert_eq!(inconsistent.field(), "idle_ping_timeout");
    settings.idle_ping_after = Some(Duration::from_secs(1));
    settings.idle_ping_timeout = Some(Duration::ZERO);
    let range = settings.validate().unwrap_err();
    assert_eq!(range.kind(), ValidationErrorKind::OutOfRange);
    assert_eq!(inconsistent.field(), range.field());
    assert!(range.source().is_none());
}

#[test]
fn http3_errors_distinguish_unsupported_settings_and_duplicate_pseudo_headers() {
    let mut settings = chrome::v154_http3();
    settings
        .initial_settings
        .push(Http3Setting::EnableWebTransportDraft02(true));
    let error = settings.validate().unwrap_err();
    assert_eq!(error.kind(), ValidationErrorKind::Unsupported);
    assert_eq!(error.reason(), "WebTransport is not implemented");
    assert!(error.source().is_none());

    let mut request = chrome::v154_http3_request();
    request.pseudo_header_order = vec![
        Http3PseudoHeader::Method,
        Http3PseudoHeader::Method,
        Http3PseudoHeader::Scheme,
        Http3PseudoHeader::Path,
    ];
    assert_eq!(
        request.validate().unwrap_err().kind(),
        ValidationErrorKind::Duplicate
    );
    assert!(request.pseudo_header_order.pop().is_some());
    assert_eq!(
        request.validate().unwrap_err().kind(),
        ValidationErrorKind::InvalidValue
    );
}

#[test]
fn templates_distinguish_missing_placeholders_invalid_values_and_duplicates() {
    let mut proxy = chrome::v154_proxy_connect();
    proxy.http1_fields.clear();
    let error = proxy.validate().unwrap_err();
    assert_eq!(error.kind(), ValidationErrorKind::Missing);
    assert_eq!(error.field(), "http1_fields");
    assert!(error.source().is_none());

    let mut request = chrome::v154_windows_fetch_template();
    request
        .http2_fields
        .push(RequestField::literal("x-profile-test", "\n"));
    let malformed = request.validate().unwrap_err();
    assert_eq!(malformed.kind(), ValidationErrorKind::InvalidValue);
    assert!(request.http2_fields.pop().is_some());
    request.http2_fields.extend([
        RequestField::literal("x-profile-test", "one"),
        RequestField::literal("x-profile-test", "two"),
    ]);
    let duplicate = request.validate().unwrap_err();
    assert_eq!(duplicate.kind(), ValidationErrorKind::Duplicate);
    assert_eq!(duplicate.field(), malformed.field());
    assert!(duplicate.source().is_none());
}

#[test]
fn tls_errors_distinguish_missing_values_duplicates_and_encoded_limits() {
    let mut settings = chrome::v154_tcp_tls();
    settings.cipher_suites.clear();
    assert_eq!(
        settings.validate().unwrap_err().kind(),
        ValidationErrorKind::Missing
    );

    let mut settings = chrome::v154_tcp_tls();
    settings.certificate_compression = vec![
        CertificateCompression::Brotli,
        CertificateCompression::Brotli,
    ];
    assert_eq!(
        settings.validate().unwrap_err().kind(),
        ValidationErrorKind::Duplicate
    );

    let mut settings = chrome::v154_tcp_tls();
    settings.alps = None;
    settings.alpn_protocols = vec![Box::from(&[b'a'; 255][..]); 256];
    let error = settings.validate().unwrap_err();
    assert_eq!(error.kind(), ValidationErrorKind::TooLarge);
    assert_eq!(error.field(), "alpn_protocols");
    assert!(error.source().is_none());
}

#[test]
fn quic_and_websocket_errors_keep_typed_recovery_categories() {
    let mut quic = chrome::v154_quic();
    quic.max_udp_payload_size = 1199;
    let error = quic.validate().unwrap_err();
    assert_eq!(error.kind(), ValidationErrorKind::OutOfRange);
    assert_eq!(error.field(), "max_udp_payload_size");
    assert!(error.source().is_none());

    let mut websocket = chrome::v154_websocket();
    websocket.handshake_timeout = Some(Duration::ZERO);
    let error = websocket.validate().unwrap_err();
    assert_eq!(error.kind(), ValidationErrorKind::OutOfRange);
    assert_eq!(error.field(), "handshake_timeout");
    assert_eq!(
        error.reason(),
        "a handshake timeout must be positive; None sets no limit"
    );
    assert!(error.source().is_none());
}

#[test]
fn pseudo_header_duplicates_keep_the_original_reason() {
    let mut settings = chrome::v154_http2();
    settings.pseudo_header_order = vec![
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Scheme,
        Http2PseudoHeader::Path,
    ];
    let error = settings.validate().unwrap_err();
    assert_eq!(error.kind(), ValidationErrorKind::Duplicate);
    assert_eq!(
        error.reason(),
        "order must contain method, authority, scheme, and path exactly once"
    );
}
