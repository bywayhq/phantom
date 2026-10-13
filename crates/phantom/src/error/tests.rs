use phantom_net::{
    http1::{Http1Error, Http1TlsError},
    http1_or_2::Http1Or2TlsError,
    http2::{Http2Error, Http2TlsError},
    http3::{ConnectUdpErrorKind, Http3ConnectorErrorKind},
    proxy::{HttpConnectError, HttpConnectErrorKind, Socks5ErrorKind},
};

use super::{
    RequestError, RequestErrorKind, is_http3_setup_failure_kind, is_retryable_connect_udp_kind,
    is_retryable_http_connect_kind, is_retryable_http3_connection_setup_kind,
    is_retryable_socks5_kind, socks5_request_error_kind,
};
use crate::{HttpProtocol, TimeoutPhase};

fn io_error() -> std::io::Error {
    std::io::Error::other("test connection failure")
}

#[test]
fn zero_connect_udp_port_keeps_its_typed_cause() {
    let error =
        RequestError::invalid_connect_udp_target(crate::route::ConnectUdpTargetError::ZeroPort);

    assert_eq!(error.kind(), RequestErrorKind::InvalidTarget);
    assert_eq!(error.to_string(), "connect-udp target port must be nonzero");
    let cause = std::error::Error::source(&error)
        .and_then(|cause| cause.downcast_ref::<crate::route::ConnectUdpTargetError>());
    assert!(matches!(
        cause,
        Some(crate::route::ConnectUdpTargetError::ZeroPort)
    ));
}

#[test]
fn invalid_connect_udp_origin_form_preserves_the_existing_cause() {
    let error = RequestError::invalid_connect_udp_target(
        crate::route::ConnectUdpTargetError::InvalidOriginForm(
            phantom_net::request::InvalidOriginForm,
        ),
    );

    assert_eq!(error.kind(), RequestErrorKind::InvalidTarget);
    assert_eq!(error.to_string(), "invalid request target");
    assert!(
        std::error::Error::source(&error)
            .and_then(|cause| cause.downcast_ref::<phantom_net::request::InvalidOriginForm>())
            .is_some()
    );
}

#[test]
fn build_formatting_keeps_typed_sources_out_of_automatic_output() {
    let sentinel = "private-build-source-path-query";
    let error = super::BuildError::with_source(
        super::BuildErrorKind::TrustStore,
        "trust store failed",
        std::io::Error::other(sentinel),
    );
    assert_eq!(error.to_string(), "trust store failed");
    assert!(!format!("{error:?}").contains(sentinel));
    let cause =
        std::error::Error::source(&error).and_then(|cause| cause.downcast_ref::<std::io::Error>());
    assert_eq!(cause.map(ToString::to_string).as_deref(), Some(sentinel));
    assert_eq!(error.kind(), super::BuildErrorKind::TrustStore);
}

#[test]
fn request_formatting_omits_cause_but_preserves_its_type_and_detail() {
    let sentinel = "private-source-path-query-and-body";
    let error = RequestError::with_source(
        RequestErrorKind::RequestBody,
        Some(HttpProtocol::Http1),
        "request body failed",
        std::io::Error::other(sentinel),
    );
    assert_eq!(error.to_string(), "request body failed");
    assert!(!format!("{error:?}").contains(sentinel));
    let cause =
        std::error::Error::source(&error).and_then(|cause| cause.downcast_ref::<std::io::Error>());
    assert_eq!(cause.map(ToString::to_string).as_deref(), Some(sentinel));
    assert_eq!(error.kind(), RequestErrorKind::RequestBody);
    assert_eq!(error.protocol(), Some(HttpProtocol::Http1));
    assert!(error.origin().is_none());
    assert_eq!(
        error.replay_observation(),
        super::RequestReplayObservation::Unknown
    );
}

#[test]
fn missing_runtime_inside_http1_and_http2_maps_to_runtime_unavailable() {
    let http1 = RequestError::http1(Http1TlsError::Http1(Http1Error::RuntimeUnavailable));
    assert_eq!(http1.kind(), RequestErrorKind::RuntimeUnavailable);
    assert_eq!(http1.protocol(), Some(HttpProtocol::Http1));

    let http2 = RequestError::http2(Http2TlsError::Http2(Http2Error::RuntimeUnavailable));
    assert_eq!(http2.kind(), RequestErrorKind::RuntimeUnavailable);
    assert_eq!(http2.protocol(), Some(HttpProtocol::Http2));
}

#[test]
fn unsupported_transport_outcome_has_no_invented_identity_or_replay_signal() {
    let error = RequestError::unsupported_transport_outcome();

    assert_eq!(error.kind(), RequestErrorKind::ProtocolUnavailable);
    assert_eq!(error.protocol(), None);
    assert_eq!(error.timeout_phase(), None);
    assert!(error.origin().is_none());
    assert!(std::error::Error::source(&error).is_none());
    assert_eq!(
        error.replay_observation(),
        super::RequestReplayObservation::Unknown,
    );
    assert!(!error.is_retryable_connection_setup());
    assert!(!error.http3_setup_failed);
    assert_eq!(
        error.to_string(),
        "transport returned an unsupported connection outcome"
    );
}

#[test]
fn unsupported_route_preserves_the_requested_protocol() {
    let error = RequestError::unsupported_route(HttpProtocol::Http3);

    assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
    assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
    assert!(std::error::Error::source(&error).is_none());
    assert!(!error.is_retryable_connection_setup());
}

#[test]
fn http1_connection_setup_marks_only_pre_transport_connection_failures() {
    let direct = RequestError::http1_connection_setup(Http1TlsError::Connect(io_error()));
    assert_eq!(direct.kind(), RequestErrorKind::Connect);
    assert_eq!(direct.protocol(), Some(HttpProtocol::Http1));
    assert!(std::error::Error::source(&direct).is_some());
    assert!(direct.is_retryable_connection_setup());

    let forward =
        RequestError::http1_connection_setup(Http1TlsError::ForwardProxyConnect(io_error()));
    assert_eq!(forward.kind(), RequestErrorKind::Proxy);
    assert!(forward.is_retryable_connection_setup());

    let proxy = RequestError::http1_connection_setup(Http1TlsError::Proxy(
        HttpConnectError::Connect(io_error()),
    ));
    assert_eq!(proxy.kind(), RequestErrorKind::Proxy);
    assert!(proxy.is_retryable_connection_setup());

    let authentication = RequestError::http1_connection_setup(Http1TlsError::Proxy(
        HttpConnectError::AuthenticationRejected,
    ));
    assert_eq!(authentication.kind(), RequestErrorKind::Proxy);
    assert!(!authentication.is_retryable_connection_setup());

    let ordinary = RequestError::http1(Http1TlsError::Connect(io_error()));
    assert!(!ordinary.is_retryable_connection_setup());
}

#[test]
fn only_the_reused_connection_close_variant_is_replay_classified() {
    for error in [
        RequestError::http1(Http1TlsError::Http1(Http1Error::ConnectionClosed)),
        RequestError::http1(Http1TlsError::Connect(io_error())),
        RequestError::http1_connection_setup(Http1TlsError::Connect(io_error())),
        RequestError::http1_body(Http1Error::ConnectionClosed),
    ] {
        assert!(!error.is_reused_connection_close(), "{error:?}");
    }
}

#[test]
fn an_http2_request_that_never_reached_a_closed_connection_is_reuse_classified() {
    let closed = RequestError::http2_stream(Http2Error::ReusedConnectionClosed);
    assert!(closed.is_reused_connection_close());
    assert!(!closed.is_unprocessed_request());
    let sent = RequestError::http2_stream(Http2Error::PingTimeout);
    assert!(!sent.is_reused_connection_close());
    assert!(!closed.is_http2_ping_failure());
}

#[test]
fn only_a_ping_timeout_is_a_ping_failure() {
    let failed = RequestError::http2_stream(Http2Error::PingTimeout);
    assert!(failed.is_http2_ping_failure());
    assert!(!failed.is_unprocessed_request());
    assert!(!failed.is_retryable_connection_setup());
    let closed = RequestError::http1(Http1TlsError::Http1(Http1Error::ConnectionClosed));
    assert!(!closed.is_http2_ping_failure());
}

#[test]
fn local_http2_failures_are_not_unprocessed() {
    for error in [
        RequestError::http2_stream(Http2Error::RequestBodyClosed),
        RequestError::http2_stream(Http2Error::PingTimeout),
        RequestError::http2_stream(Http2Error::RuntimeUnavailable),
        RequestError::http2(Http2TlsError::Connect(io_error())),
        RequestError::http1(Http1TlsError::Http1(Http1Error::ConnectionClosed)),
    ] {
        assert!(!error.is_unprocessed_request(), "{error:?}");
    }
}

#[test]
fn http2_connection_setup_marks_only_pre_transport_connection_failures() {
    let direct = RequestError::http2_connection_setup(Http2TlsError::Connect(io_error()));
    assert_eq!(direct.kind(), RequestErrorKind::Connect);
    assert_eq!(direct.protocol(), Some(HttpProtocol::Http2));
    assert!(std::error::Error::source(&direct).is_some());
    assert!(direct.is_retryable_connection_setup());

    let proxy = RequestError::http2_connection_setup(Http2TlsError::Proxy(
        HttpConnectError::Connect(io_error()),
    ));
    assert_eq!(proxy.kind(), RequestErrorKind::Proxy);
    assert!(proxy.is_retryable_connection_setup());

    let authentication = RequestError::http2_connection_setup(Http2TlsError::Proxy(
        HttpConnectError::AuthenticationRejected,
    ));
    assert_eq!(authentication.kind(), RequestErrorKind::Proxy);
    assert!(!authentication.is_retryable_connection_setup());

    // A tunnel that waited for a failed pooled setup is classified by the
    // setup's kind.
    let waited_connect = RequestError::http2_connection_setup(Http2TlsError::Proxy(
        HttpConnectError::PooledSetupFailed {
            kind: HttpConnectErrorKind::Connect,
        },
    ));
    assert!(waited_connect.is_retryable_connection_setup());
    let waited_tls = RequestError::http2_connection_setup(Http2TlsError::Proxy(
        HttpConnectError::PooledSetupFailed {
            kind: HttpConnectErrorKind::Tls,
        },
    ));
    assert!(!waited_tls.is_retryable_connection_setup());

    let ordinary = RequestError::http2(Http2TlsError::Connect(io_error()));
    assert!(!ordinary.is_retryable_connection_setup());
}

#[test]
fn http1_or_2_connect_failure_is_retryable_connection_setup() {
    let refused = RequestError::http1_or_2_connection_setup(Http1Or2TlsError::Connect(io_error()));
    assert_eq!(refused.kind(), RequestErrorKind::Connect);
    assert_eq!(refused.protocol(), None);
    assert!(std::error::Error::source(&refused).is_some());
    assert!(refused.is_retryable_connection_setup());

    let runtime = RequestError::http1_or_2_connection_setup(Http1Or2TlsError::RuntimeUnavailable);
    assert_eq!(runtime.kind(), RequestErrorKind::RuntimeUnavailable);
    assert!(!runtime.is_retryable_connection_setup());

    let ordinary = RequestError::http1_or_2(Http1Or2TlsError::Connect(io_error()));
    assert!(!ordinary.is_retryable_connection_setup());
}

#[test]
fn http1_or_2_alpn_failure_is_not_retryable() {
    let alpn = RequestError::http1_or_2_connection_setup(Http1Or2TlsError::UnsupportedAlpn {
        selected: Box::from(&b"h3"[..]),
    });
    assert_eq!(alpn.kind(), RequestErrorKind::Tls);
    assert!(!alpn.is_retryable_connection_setup());

    // A connect error wrapped after selection belongs to the selected protocol.
    let selected = RequestError::http1_or_2_connection_setup(Http1Or2TlsError::Http2(
        Http2TlsError::Connect(io_error()),
    ));
    assert_eq!(selected.protocol(), Some(HttpProtocol::Http2));
    assert!(!selected.is_retryable_connection_setup());
}

#[test]
fn proxy_and_socks_retry_allowlists_exclude_negotiation_failures() {
    assert!(is_retryable_http_connect_kind(
        HttpConnectErrorKind::Connect
    ));
    for kind in [
        HttpConnectErrorKind::InvalidConfiguration,
        HttpConnectErrorKind::InvalidRequest,
        HttpConnectErrorKind::Authentication,
        HttpConnectErrorKind::RuntimeUnavailable,
        HttpConnectErrorKind::Tls,
        HttpConnectErrorKind::UnsupportedProtocol,
        HttpConnectErrorKind::Io,
        HttpConnectErrorKind::InvalidResponse,
        HttpConnectErrorKind::Rejected,
    ] {
        assert!(!is_retryable_http_connect_kind(kind), "{kind:?}");
    }

    for kind in [Socks5ErrorKind::Connect, Socks5ErrorKind::Resolve] {
        assert!(is_retryable_socks5_kind(kind), "{kind:?}");
    }
    for kind in [
        Socks5ErrorKind::InvalidTarget,
        Socks5ErrorKind::InvalidAuthentication,
        Socks5ErrorKind::RuntimeUnavailable,
        Socks5ErrorKind::Negotiation,
        Socks5ErrorKind::Authentication,
        Socks5ErrorKind::Rejected,
    ] {
        assert!(!is_retryable_socks5_kind(kind), "{kind:?}");
    }
}

/// Every SOCKS5 failure category reports the same request category on the
/// exact H1, exact H2, and negotiated legs, because all three classify
/// through one function.
#[test]
fn socks5_failures_classify_the_same_for_every_protocol_selection() {
    for (kind, expected) in [
        (
            Socks5ErrorKind::RuntimeUnavailable,
            RequestErrorKind::RuntimeUnavailable,
        ),
        (Socks5ErrorKind::Resolve, RequestErrorKind::Resolve),
        (Socks5ErrorKind::Connect, RequestErrorKind::Proxy),
        (Socks5ErrorKind::InvalidTarget, RequestErrorKind::Proxy),
        (
            Socks5ErrorKind::InvalidAuthentication,
            RequestErrorKind::Proxy,
        ),
        (Socks5ErrorKind::Negotiation, RequestErrorKind::Proxy),
        (Socks5ErrorKind::Authentication, RequestErrorKind::Proxy),
        (Socks5ErrorKind::Rejected, RequestErrorKind::Proxy),
    ] {
        assert_eq!(socks5_request_error_kind(kind), expected, "{kind:?}");
    }

    // A refused proxy TCP connect is a proxy failure, never the direct
    // `Connect` category, and it stays retryable before dispatch.
    assert_eq!(
        socks5_request_error_kind(Socks5ErrorKind::Connect),
        RequestErrorKind::Proxy
    );
    assert!(is_retryable_socks5_kind(Socks5ErrorKind::Connect));
}

#[test]
fn connect_udp_retry_allowlist_is_only_outer_resolve_and_connect() {
    for kind in [ConnectUdpErrorKind::Resolve, ConnectUdpErrorKind::Connect] {
        assert!(is_retryable_connect_udp_kind(kind), "{kind:?}");
    }
    for kind in [
        ConnectUdpErrorKind::InvalidRequest,
        ConnectUdpErrorKind::Configuration,
        ConnectUdpErrorKind::RuntimeUnavailable,
        ConnectUdpErrorKind::Handshake,
        ConnectUdpErrorKind::UnsupportedProtocol,
        ConnectUdpErrorKind::Authentication,
        ConnectUdpErrorKind::ExtendedConnectUnavailable,
        ConnectUdpErrorKind::DatagramUnavailable,
        ConnectUdpErrorKind::DatagramCapacity,
        ConnectUdpErrorKind::Rejected,
        ConnectUdpErrorKind::Protocol,
    ] {
        assert!(!is_retryable_connect_udp_kind(kind), "{kind:?}");
    }
}

#[test]
fn only_a_failed_quic_connection_or_handshake_allows_the_http2_fallback() {
    for kind in [
        Http3ConnectorErrorKind::Endpoint,
        Http3ConnectorErrorKind::Connect,
        Http3ConnectorErrorKind::Connection,
        Http3ConnectorErrorKind::Handshake,
    ] {
        assert!(is_http3_setup_failure_kind(kind), "{kind:?}");
    }
    for kind in [
        Http3ConnectorErrorKind::Resolve,
        Http3ConnectorErrorKind::Proxy,
        Http3ConnectorErrorKind::InvalidProfile,
        Http3ConnectorErrorKind::TrustStore,
        Http3ConnectorErrorKind::ProtocolConfiguration,
        Http3ConnectorErrorKind::RuntimeUnavailable,
        Http3ConnectorErrorKind::Request,
        Http3ConnectorErrorKind::Protocol,
        Http3ConnectorErrorKind::Local,
        Http3ConnectorErrorKind::ExtendedConnectUnavailable,
    ] {
        assert!(!is_http3_setup_failure_kind(kind), "{kind:?}");
    }

    let connect_timeout = RequestError::timeout(TimeoutPhase::Connect, Some(HttpProtocol::Http3));
    assert!(connect_timeout.is_http3_setup_failure());
    for (phase, protocol) in [
        (TimeoutPhase::ResponseHead, Some(HttpProtocol::Http3)),
        (TimeoutPhase::Total, Some(HttpProtocol::Http3)),
        (TimeoutPhase::Connect, Some(HttpProtocol::Http2)),
    ] {
        assert!(!RequestError::timeout(phase, protocol).is_http3_setup_failure());
    }
}

#[test]
fn http3_connection_setup_retry_allowlist_excludes_non_connection_failures() {
    for kind in [
        Http3ConnectorErrorKind::Resolve,
        Http3ConnectorErrorKind::Endpoint,
        Http3ConnectorErrorKind::Connect,
        Http3ConnectorErrorKind::Connection,
    ] {
        assert!(is_retryable_http3_connection_setup_kind(kind), "{kind:?}");
    }
    for kind in [
        Http3ConnectorErrorKind::InvalidProfile,
        Http3ConnectorErrorKind::TrustStore,
        Http3ConnectorErrorKind::ProtocolConfiguration,
        Http3ConnectorErrorKind::RuntimeUnavailable,
        Http3ConnectorErrorKind::Request,
        Http3ConnectorErrorKind::Handshake,
        Http3ConnectorErrorKind::Protocol,
        Http3ConnectorErrorKind::Local,
    ] {
        assert!(!is_retryable_http3_connection_setup_kind(kind), "{kind:?}");
    }
}
