use std::{error::Error as StdError, fmt};

use phantom_net::{
    http1::{Http1Error, Http1TlsError, TlsErrorKind},
    http1_or_2::{Http1Or2TlsError, Http1Or2TlsErrorKind},
    http2::{Http2Error, Http2TlsError},
    http3::{
        ConnectUdpError, ConnectUdpErrorKind, Http3ConnectorError, Http3ConnectorErrorKind,
        Http3Error,
    },
    proxy::{HttpConnectError, HttpConnectErrorKind, Socks5Error, Socks5ErrorKind},
    request::RequestBodyError,
};
use phantom_profile::{InvalidClientHintSettings, InvalidTlsSettings};

use crate::{HttpProtocol, TimeoutPhase};

type BoxError = Box<dyn StdError + Send + Sync>;

/// Stable category of client-construction failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BuildErrorKind {
    /// The supplied wire profile is internally inconsistent.
    InvalidProfile,
    /// Connection policies are contradictory or unsupported together.
    InvalidPolicy,
    /// A configured trust root could not be loaded.
    TrustStore,
    /// A protocol connector cannot represent the supplied profile.
    ProtocolConfiguration,
    /// The profile enables no protocol implemented by the facade.
    NoSupportedProtocol,
}

/// Error returned while constructing a [`crate::Client`].
#[derive(Debug)]
pub struct BuildError {
    kind: BuildErrorKind,
    message: &'static str,
    source: Option<BoxError>,
}

impl BuildError {
    pub(crate) fn invalid_policy(message: &'static str) -> Self {
        Self {
            kind: BuildErrorKind::InvalidPolicy,
            message,
            source: None,
        }
    }

    pub(crate) fn invalid_tls_profile(source: InvalidTlsSettings) -> Self {
        Self::with_source(
            BuildErrorKind::InvalidProfile,
            "invalid TLS profile",
            source,
        )
    }

    pub(crate) fn invalid_client_hint_profile(source: InvalidClientHintSettings) -> Self {
        Self::with_source(
            BuildErrorKind::InvalidProfile,
            "invalid client-hint profile",
            source,
        )
    }

    pub(crate) fn http1(source: Http1TlsError) -> Self {
        let kind = classify_http1_build_error(&source);
        Self::with_source(kind, "failed to configure HTTP/1", source)
    }

    pub(crate) fn http2(source: Http2TlsError) -> Self {
        let kind = classify_http2_build_error(&source);
        Self::with_source(kind, "failed to configure HTTP/2", source)
    }

    pub(crate) fn http1_or_2(source: Http1Or2TlsError) -> Self {
        let kind = match source.kind() {
            Http1Or2TlsErrorKind::Tls => source
                .source()
                .and_then(|source| source.downcast_ref::<phantom_net::http1::TlsError>())
                .map_or(BuildErrorKind::ProtocolConfiguration, |error| {
                    match error.kind() {
                        TlsErrorKind::TrustStore => BuildErrorKind::TrustStore,
                        TlsErrorKind::InvalidConfiguration => BuildErrorKind::InvalidProfile,
                        _ => BuildErrorKind::ProtocolConfiguration,
                    }
                }),
            Http1Or2TlsErrorKind::InvalidConfiguration | Http1Or2TlsErrorKind::Http2 => {
                BuildErrorKind::InvalidProfile
            }
            _ => BuildErrorKind::ProtocolConfiguration,
        };
        Self::with_source(
            kind,
            "failed to configure HTTP/1.1-or-HTTP/2 negotiation",
            source,
        )
    }

    pub(crate) fn http3(source: Http3ConnectorError) -> Self {
        let kind = match source.kind() {
            Http3ConnectorErrorKind::InvalidProfile => BuildErrorKind::InvalidProfile,
            Http3ConnectorErrorKind::TrustStore => BuildErrorKind::TrustStore,
            _ => BuildErrorKind::ProtocolConfiguration,
        };
        Self::with_source(kind, "failed to configure HTTP/3", source)
    }

    pub(crate) fn https_proxy(source: HttpConnectError) -> Self {
        let kind = match &source {
            HttpConnectError::ProxyTls(error) if error.kind() == TlsErrorKind::TrustStore => {
                BuildErrorKind::TrustStore
            }
            HttpConnectError::ProxyTls(error)
                if error.kind() == TlsErrorKind::InvalidConfiguration =>
            {
                BuildErrorKind::InvalidProfile
            }
            HttpConnectError::MissingHttp1Alpn => BuildErrorKind::ProtocolConfiguration,
            _ => BuildErrorKind::ProtocolConfiguration,
        };
        Self::with_source(kind, "failed to configure HTTPS proxy", source)
    }

    pub(crate) fn no_supported_protocol() -> Self {
        Self {
            kind: BuildErrorKind::NoSupportedProtocol,
            message: "profile configures no supported HTTP protocol",
            source: None,
        }
    }

    fn with_source(
        kind: BuildErrorKind,
        message: &'static str,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message,
            source: Some(Box::new(source)),
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub fn kind(&self) -> BuildErrorKind {
        self.kind
    }
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)?;
        if let Some(source) = &self.source {
            write!(formatter, ": {source}")?;
        }
        Ok(())
    }
}

impl StdError for BuildError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

fn classify_http1_build_error(error: &Http1TlsError) -> BuildErrorKind {
    match error {
        Http1TlsError::Tls(source) if source.kind() == TlsErrorKind::TrustStore => {
            BuildErrorKind::TrustStore
        }
        Http1TlsError::Tls(source) if source.kind() == TlsErrorKind::InvalidConfiguration => {
            BuildErrorKind::InvalidProfile
        }
        Http1TlsError::MissingHttp1Alpn => BuildErrorKind::InvalidProfile,
        _ => BuildErrorKind::ProtocolConfiguration,
    }
}

fn classify_http2_build_error(error: &Http2TlsError) -> BuildErrorKind {
    match error {
        Http2TlsError::Tls(source) if source.kind() == TlsErrorKind::TrustStore => {
            BuildErrorKind::TrustStore
        }
        Http2TlsError::Tls(source) if source.kind() == TlsErrorKind::InvalidConfiguration => {
            BuildErrorKind::InvalidProfile
        }
        Http2TlsError::Http2(Http2Error::InvalidSettings(_)) | Http2TlsError::MissingHttp2Alpn => {
            BuildErrorKind::InvalidProfile
        }
        _ => BuildErrorKind::ProtocolConfiguration,
    }
}

/// Stable category of request or response-body failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestErrorKind {
    /// The request URI is syntactically invalid.
    InvalidUri,
    /// The URI scheme is not supported by this client slice.
    UnsupportedScheme,
    /// The URI authority is missing or invalid.
    InvalidAuthority,
    /// A caller supplied an authority field owned by the facade.
    AuthorityHeader,
    /// A request field is not valid for the selected operation.
    InvalidHeader,
    /// The selected protocol is absent from the client profile.
    ProtocolUnavailable,
    /// The selected route cannot carry the requested protocol.
    UnsupportedRoute,
    /// The URI target cannot be represented as origin-form.
    InvalidTarget,
    /// Redirect policy rejected a response or target.
    Redirect,
    /// Resolving the origin address failed.
    Resolve,
    /// Establishing the direct network connection failed.
    Connect,
    /// Connecting to or negotiating with the configured proxy failed.
    Proxy,
    /// The request lacks a current Tokio runtime with network I/O enabled.
    RuntimeUnavailable,
    /// Local bounded admission capacity is exhausted.
    Capacity,
    /// A configured timeout cannot be represented by the runtime clock.
    InvalidTimeout,
    /// A named request phase exhausted its configured time budget.
    Timeout,
    /// A caller-provided body failed or could not be replayed safely.
    RequestBody,
    /// A response body exceeded the caller's configured collection or decoding limit.
    ResponseBodyLimit,
    /// A response content coding was unsupported, not advertised by the
    /// caller's `Accept-Encoding`, or malformed.
    ContentDecoding,
    /// TLS setup or negotiation failed.
    Tls,
    /// HTTP/1 request or response processing failed.
    Http1,
    /// HTTP/2 request or response processing failed.
    Http2,
    /// HTTP/3 or QUIC request or response processing failed.
    Http3,
}

/// Error returned by a public client request or response body.
#[derive(Debug)]
pub struct RequestError {
    kind: RequestErrorKind,
    protocol: Option<HttpProtocol>,
    timeout_phase: Option<TimeoutPhase>,
    retryability: RequestRetryability,
    message: &'static str,
    source: Option<BoxError>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum RequestRetryability {
    #[default]
    Never,
    ConnectionSetup,
    /// A reused HTTP/1.1 connection closed before any response byte.
    ReusedConnectionClosed,
}

impl RequestError {
    pub(crate) fn invalid_uri(source: http::uri::InvalidUri) -> Self {
        Self::with_source(
            RequestErrorKind::InvalidUri,
            None,
            "invalid request URI",
            source,
        )
    }

    pub(crate) fn invalid_url(source: url::ParseError) -> Self {
        Self::with_source(
            RequestErrorKind::InvalidUri,
            None,
            "invalid request URL",
            source,
        )
    }

    pub(crate) fn invalid_redirect_header(source: http::header::ToStrError) -> Self {
        Self::with_source(
            RequestErrorKind::Redirect,
            None,
            "redirect Location is not valid text",
            source,
        )
    }

    pub(crate) fn invalid_redirect_url(source: url::ParseError) -> Self {
        Self::with_source(
            RequestErrorKind::Redirect,
            None,
            "redirect Location is not a valid URL reference",
            source,
        )
    }

    pub(crate) fn invalid_redirect_uri(source: http::uri::InvalidUri) -> Self {
        Self::with_source(
            RequestErrorKind::Redirect,
            None,
            "redirect target cannot be represented as an HTTP URI",
            source,
        )
    }

    pub(crate) fn invalid_redirect_target(message: &'static str) -> Self {
        Self::without_source(RequestErrorKind::Redirect, message)
    }

    pub(crate) fn ambiguous_redirect_location() -> Self {
        Self::without_source(
            RequestErrorKind::Redirect,
            "redirect response contains multiple Location fields",
        )
    }

    pub(crate) fn redirect_scheme() -> Self {
        Self::without_source(RequestErrorKind::Redirect, "redirect target must use HTTPS")
    }

    pub(crate) fn redirect_limit() -> Self {
        Self::without_source(RequestErrorKind::Redirect, "redirect limit was exhausted")
    }

    pub(crate) fn plaintext_redirect_policy() -> Self {
        Self::without_source(
            RequestErrorKind::Redirect,
            "redirect following is not yet supported for plaintext HTTP requests",
        )
    }

    pub(crate) fn request_body_not_replayable() -> Self {
        Self::without_source(
            RequestErrorKind::RequestBody,
            "one-shot request body cannot be replayed for another wire attempt",
        )
    }

    pub(crate) fn response_body_limit() -> Self {
        Self::without_source(
            RequestErrorKind::ResponseBodyLimit,
            "response body exceeded the configured byte limit",
        )
    }

    pub(crate) fn decoded_body_limit(protocol: HttpProtocol) -> Self {
        Self {
            protocol: Some(protocol),
            ..Self::without_source(
                RequestErrorKind::ResponseBodyLimit,
                "decoded response body exceeded the configured byte limit",
            )
        }
    }

    pub(crate) fn content_decoding(
        protocol: HttpProtocol,
        message: &'static str,
        source: Option<BoxError>,
    ) -> Self {
        Self {
            protocol: Some(protocol),
            source,
            ..Self::without_source(RequestErrorKind::ContentDecoding, message)
        }
    }

    pub(crate) fn invalid_accept_encoding(message: &'static str) -> Self {
        Self::without_source(RequestErrorKind::InvalidHeader, message)
    }

    pub(crate) fn ambiguous_request_trailers() -> Self {
        Self::without_source(
            RequestErrorKind::RequestBody,
            "static and streaming-body-produced request trailers cannot be combined",
        )
    }

    pub(crate) fn unsupported_scheme() -> Self {
        Self::without_source(
            RequestErrorKind::UnsupportedScheme,
            "request URI must use HTTPS unless exact HTTP/1.1 is selected for plaintext HTTP",
        )
    }

    pub(crate) fn invalid_authority(message: &'static str) -> Self {
        Self::without_source(RequestErrorKind::InvalidAuthority, message)
    }

    pub(crate) fn fragment_target() -> Self {
        Self::without_source(
            RequestErrorKind::InvalidTarget,
            "request URI must not contain a fragment",
        )
    }

    pub(crate) fn authority_header() -> Self {
        Self::without_source(
            RequestErrorKind::AuthorityHeader,
            "Host is derived from the request URI and must not be supplied as a request field",
        )
    }

    pub(crate) fn alt_used_header() -> Self {
        Self::without_source(
            RequestErrorKind::InvalidHeader,
            "Alt-Used is managed by the negotiated Alt-Svc client and must not be supplied",
        )
    }

    pub(crate) fn forward_proxy_authorization_header() -> Self {
        Self::without_source(
            RequestErrorKind::InvalidHeader,
            "Proxy-Authorization is not supported for plaintext HTTP requests",
        )
    }

    pub(crate) fn unsupported_protocol(protocol: HttpProtocol) -> Self {
        Self {
            kind: RequestErrorKind::ProtocolUnavailable,
            protocol: Some(protocol),
            timeout_phase: None,
            retryability: RequestRetryability::Never,
            message: "requested protocol is absent from the client profile",
            source: None,
        }
    }

    pub(crate) fn unsupported_negotiation() -> Self {
        Self::without_source(
            RequestErrorKind::ProtocolUnavailable,
            "client profile must configure both HTTP/1.1 and HTTP/2 negotiation",
        )
    }

    pub(crate) fn unsupported_route(protocol: HttpProtocol) -> Self {
        Self {
            kind: RequestErrorKind::UnsupportedRoute,
            protocol: Some(protocol),
            timeout_phase: None,
            retryability: RequestRetryability::Never,
            message: "selected route does not support the requested protocol",
            source: None,
        }
    }

    pub(crate) fn unsupported_negotiated_route() -> Self {
        Self::without_source(
            RequestErrorKind::UnsupportedRoute,
            "HTTP/1.1-or-HTTP/2 negotiation currently requires a direct route",
        )
    }

    pub(crate) fn capacity(protocol: HttpProtocol) -> Self {
        Self::capacity_for(Some(protocol))
    }

    /// Admission failed before ALPN selected an HTTP protocol.
    pub(crate) fn unselected_capacity() -> Self {
        Self::capacity_for(None)
    }

    fn capacity_for(protocol: Option<HttpProtocol>) -> Self {
        Self {
            kind: RequestErrorKind::Capacity,
            protocol,
            timeout_phase: None,
            retryability: RequestRetryability::Never,
            message: "request admission capacity is exhausted",
            source: None,
        }
    }

    pub(crate) fn invalid_timeout() -> Self {
        Self::without_source(
            RequestErrorKind::InvalidTimeout,
            "request timeout exceeds the runtime clock range",
        )
    }

    pub(crate) fn invalid_retry_delay() -> Self {
        Self::without_source(
            RequestErrorKind::InvalidTimeout,
            "retry delay or Retry-After limit exceeds the runtime clock range",
        )
    }

    pub(crate) fn timeout(phase: TimeoutPhase, protocol: Option<HttpProtocol>) -> Self {
        let message = match phase {
            TimeoutPhase::PoolAdmission => "request pool admission timed out",
            TimeoutPhase::Connect => "request connection setup timed out",
            TimeoutPhase::ResponseHead => "request response head timed out",
            TimeoutPhase::ReadIdle => "request response body became idle",
            TimeoutPhase::Total => "request total deadline elapsed",
        };
        Self {
            kind: RequestErrorKind::Timeout,
            protocol,
            timeout_phase: Some(phase),
            retryability: RequestRetryability::Never,
            message,
            source: None,
        }
    }

    pub(crate) fn runtime_timer_unavailable() -> Self {
        Self::without_source(
            RequestErrorKind::RuntimeUnavailable,
            "request timeouts require a Tokio runtime with time enabled",
        )
    }

    pub(crate) fn invalid_target(source: phantom_net::request::InvalidOriginForm) -> Self {
        Self::with_source(
            RequestErrorKind::InvalidTarget,
            None,
            "invalid request target",
            source,
        )
    }

    pub(crate) fn invalid_absolute_target(
        source: phantom_net::request::InvalidAbsoluteForm,
    ) -> Self {
        Self::with_source(
            RequestErrorKind::InvalidTarget,
            None,
            "invalid absolute-form request target",
            source,
        )
    }

    pub(crate) fn http1(source: Http1TlsError) -> Self {
        let kind = if error_chain_contains_request_body(&source) {
            RequestErrorKind::RequestBody
        } else {
            match &source {
                Http1TlsError::RuntimeUnavailable
                | Http1TlsError::Http1(Http1Error::RuntimeUnavailable) => {
                    RequestErrorKind::RuntimeUnavailable
                }
                Http1TlsError::Connect(_) => RequestErrorKind::Connect,
                Http1TlsError::ForwardProxyConnect(_) => RequestErrorKind::Proxy,
                Http1TlsError::Proxy(error)
                    if error.kind()
                        == phantom_net::proxy::HttpConnectErrorKind::RuntimeUnavailable =>
                {
                    RequestErrorKind::RuntimeUnavailable
                }
                Http1TlsError::Socks5Proxy(error)
                    if error.kind() == phantom_net::proxy::Socks5ErrorKind::RuntimeUnavailable =>
                {
                    RequestErrorKind::RuntimeUnavailable
                }
                Http1TlsError::Socks5Proxy(error)
                    if error.kind() == phantom_net::proxy::Socks5ErrorKind::Resolve =>
                {
                    RequestErrorKind::Resolve
                }
                Http1TlsError::Proxy(_) | Http1TlsError::Socks5Proxy(_) => RequestErrorKind::Proxy,
                Http1TlsError::Tls(_) => RequestErrorKind::Tls,
                _ => RequestErrorKind::Http1,
            }
        };
        let retryability = if matches!(
            source,
            Http1TlsError::Http1(Http1Error::ReusedConnectionClosed(_))
        ) {
            RequestRetryability::ReusedConnectionClosed
        } else {
            RequestRetryability::Never
        };
        Self {
            retryability,
            ..Self::with_source(
                kind,
                Some(HttpProtocol::Http1),
                "HTTP/1 request failed",
                source,
            )
        }
    }

    pub(crate) fn http1_connection_setup(source: Http1TlsError) -> Self {
        let retryable = is_retryable_http1_connection_setup(&source);
        let mut error = Self::http1(source);
        if retryable {
            error.retryability = RequestRetryability::ConnectionSetup;
        }
        error
    }

    pub(crate) fn http2(source: Http2TlsError) -> Self {
        let kind = if error_chain_contains_request_body(&source) {
            RequestErrorKind::RequestBody
        } else {
            match &source {
                Http2TlsError::RuntimeUnavailable
                | Http2TlsError::Http2(Http2Error::RuntimeUnavailable) => {
                    RequestErrorKind::RuntimeUnavailable
                }
                Http2TlsError::Connect(_) => RequestErrorKind::Connect,
                Http2TlsError::Proxy(error)
                    if error.kind()
                        == phantom_net::proxy::HttpConnectErrorKind::RuntimeUnavailable =>
                {
                    RequestErrorKind::RuntimeUnavailable
                }
                Http2TlsError::Socks5Proxy(error)
                    if error.kind() == phantom_net::proxy::Socks5ErrorKind::RuntimeUnavailable =>
                {
                    RequestErrorKind::RuntimeUnavailable
                }
                Http2TlsError::Socks5Proxy(error)
                    if error.kind() == phantom_net::proxy::Socks5ErrorKind::Resolve =>
                {
                    RequestErrorKind::Resolve
                }
                Http2TlsError::Proxy(_) | Http2TlsError::Socks5Proxy(_) => RequestErrorKind::Proxy,
                Http2TlsError::Tls(_) => RequestErrorKind::Tls,
                _ => RequestErrorKind::Http2,
            }
        };
        Self::with_source(
            kind,
            Some(HttpProtocol::Http2),
            "HTTP/2 request failed",
            source,
        )
    }

    pub(crate) fn http2_connection_setup(source: Http2TlsError) -> Self {
        let retryable = is_retryable_http2_connection_setup(&source);
        let mut error = Self::http2(source);
        if retryable {
            error.retryability = RequestRetryability::ConnectionSetup;
        }
        error
    }

    pub(crate) fn http1_or_2(source: Http1Or2TlsError) -> Self {
        let (kind, protocol) = match source.kind() {
            Http1Or2TlsErrorKind::RuntimeUnavailable => {
                (RequestErrorKind::RuntimeUnavailable, None)
            }
            Http1Or2TlsErrorKind::Connect => (RequestErrorKind::Connect, None),
            Http1Or2TlsErrorKind::Tls | Http1Or2TlsErrorKind::UnsupportedAlpn => {
                (RequestErrorKind::Tls, None)
            }
            Http1Or2TlsErrorKind::Http1 => (RequestErrorKind::Http1, Some(HttpProtocol::Http1)),
            Http1Or2TlsErrorKind::Http2 => (RequestErrorKind::Http2, Some(HttpProtocol::Http2)),
            Http1Or2TlsErrorKind::InvalidConfiguration => {
                (RequestErrorKind::ProtocolUnavailable, None)
            }
            _ => (RequestErrorKind::Tls, None),
        };
        Self::with_source(
            kind,
            protocol,
            "HTTP/1.1-or-HTTP/2 negotiation failed",
            source,
        )
    }

    /// Marks only pre-TLS connect failures as retryable; TLS and ALPN are terminal.
    pub(crate) fn http1_or_2_connection_setup(source: Http1Or2TlsError) -> Self {
        let retryable = source.kind() == Http1Or2TlsErrorKind::Connect;
        let mut error = Self::http1_or_2(source);
        if retryable {
            error.retryability = RequestRetryability::ConnectionSetup;
        }
        error
    }

    pub(crate) fn negotiated_http1_validation(source: Http1Error) -> Self {
        Self::with_source(
            RequestErrorKind::Http1,
            None,
            "request is not valid for negotiated HTTP/1.1",
            source,
        )
    }

    pub(crate) fn negotiated_http2_validation(source: Http2Error) -> Self {
        Self::with_source(
            RequestErrorKind::Http2,
            None,
            "request is not valid for negotiated HTTP/2",
            source,
        )
    }

    pub(crate) fn http3(source: Http3ConnectorError) -> Self {
        let kind = if error_chain_contains_request_body(&source) {
            RequestErrorKind::RequestBody
        } else {
            match source.kind() {
                Http3ConnectorErrorKind::RuntimeUnavailable => RequestErrorKind::RuntimeUnavailable,
                Http3ConnectorErrorKind::Resolve => RequestErrorKind::Resolve,
                Http3ConnectorErrorKind::Proxy => http3_proxy_failure(&source).map_or(
                    RequestErrorKind::Proxy,
                    Http3ProxyFailure::request_error_kind,
                ),
                Http3ConnectorErrorKind::Endpoint | Http3ConnectorErrorKind::Connect => {
                    RequestErrorKind::Connect
                }
                Http3ConnectorErrorKind::Handshake => RequestErrorKind::Tls,
                _ => RequestErrorKind::Http3,
            }
        };
        Self::with_source(
            kind,
            Some(HttpProtocol::Http3),
            "HTTP/3 request failed",
            source,
        )
    }

    pub(crate) fn http3_connection_setup(source: Http3ConnectorError) -> Self {
        let retryable = match source.kind() {
            Http3ConnectorErrorKind::Proxy => http3_proxy_failure(&source)
                .is_some_and(Http3ProxyFailure::is_retryable_connection_setup),
            kind => is_retryable_http3_connection_setup_kind(kind),
        };
        let mut error = Self::http3(source);
        if retryable {
            error.retryability = RequestRetryability::ConnectionSetup;
        }
        error
    }

    /// Classifies connection setup through a CONNECT-UDP route.
    ///
    /// Only outer proxy resolution or QUIC connection failures may retry; a
    /// retry opens a fresh outer connection and CONNECT-UDP request on the
    /// same route. Inner QUIC failures over an accepted tunnel are terminal.
    pub(crate) fn http3_connect_udp_setup(source: Http3ConnectorError) -> Self {
        let retryable = source.kind() == Http3ConnectorErrorKind::Proxy
            && http3_proxy_failure(&source)
                .is_some_and(Http3ProxyFailure::is_retryable_connection_setup);
        let mut error = Self::http3(source);
        if retryable {
            error.retryability = RequestRetryability::ConnectionSetup;
        }
        error
    }

    pub(crate) fn http1_body(source: Http1Error) -> Self {
        Self::with_source(
            body_error_kind(RequestErrorKind::Http1, &source),
            Some(HttpProtocol::Http1),
            "HTTP/1 response body failed",
            source,
        )
    }

    pub(crate) fn http2_body(source: Http2Error) -> Self {
        Self::with_source(
            body_error_kind(RequestErrorKind::Http2, &source),
            Some(HttpProtocol::Http2),
            "HTTP/2 response body failed",
            source,
        )
    }

    pub(crate) fn http3_body(source: Http3Error) -> Self {
        Self::with_source(
            body_error_kind(RequestErrorKind::Http3, &source),
            Some(HttpProtocol::Http3),
            "HTTP/3 response body failed",
            source,
        )
    }

    fn without_source(kind: RequestErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            protocol: None,
            timeout_phase: None,
            retryability: RequestRetryability::Never,
            message,
            source: None,
        }
    }

    fn with_source(
        kind: RequestErrorKind,
        protocol: Option<HttpProtocol>,
        message: &'static str,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            protocol,
            timeout_phase: None,
            retryability: RequestRetryability::Never,
            message,
            source: Some(Box::new(source)),
        }
    }

    pub(crate) fn is_retryable_connection_setup(&self) -> bool {
        self.retryability == RequestRetryability::ConnectionSetup
    }

    /// Returns whether a reused HTTP/1.1 connection closed before any
    /// response byte; method and body eligibility are checked by the caller.
    pub(crate) fn is_reused_connection_close(&self) -> bool {
        self.retryability == RequestRetryability::ReusedConnectionClosed
    }

    /// Returns the stable failure category.
    #[must_use]
    pub fn kind(&self) -> RequestErrorKind {
        self.kind
    }

    /// Returns the exact protocol involved in the failure, when applicable.
    #[must_use]
    pub fn protocol(&self) -> Option<HttpProtocol> {
        self.protocol
    }

    /// Returns the phase that timed out, when this is a timeout failure.
    #[must_use]
    pub fn timeout_phase(&self) -> Option<TimeoutPhase> {
        self.timeout_phase
    }
}

fn is_retryable_http1_connection_setup(source: &Http1TlsError) -> bool {
    match source {
        Http1TlsError::Connect(_) | Http1TlsError::ForwardProxyConnect(_) => true,
        Http1TlsError::Proxy(error) => is_retryable_http_connect_kind(error.kind()),
        Http1TlsError::Socks5Proxy(error) => is_retryable_socks5_kind(error.kind()),
        _ => false,
    }
}

fn is_retryable_http2_connection_setup(source: &Http2TlsError) -> bool {
    match source {
        Http2TlsError::Connect(_) => true,
        Http2TlsError::Proxy(error) => is_retryable_http_connect_kind(error.kind()),
        Http2TlsError::Socks5Proxy(error) => is_retryable_socks5_kind(error.kind()),
        _ => false,
    }
}

fn is_retryable_http_connect_kind(kind: HttpConnectErrorKind) -> bool {
    kind == HttpConnectErrorKind::Connect
}

fn is_retryable_socks5_kind(kind: Socks5ErrorKind) -> bool {
    matches!(kind, Socks5ErrorKind::Connect | Socks5ErrorKind::Resolve)
}

fn is_retryable_http3_connection_setup_kind(kind: Http3ConnectorErrorKind) -> bool {
    matches!(
        kind,
        Http3ConnectorErrorKind::Resolve
            | Http3ConnectorErrorKind::Endpoint
            | Http3ConnectorErrorKind::Connect
            | Http3ConnectorErrorKind::Connection
    )
}

/// Typed proxy failure carried as the source of an HTTP/3 connector error.
#[derive(Clone, Copy)]
enum Http3ProxyFailure {
    Socks5(Socks5ErrorKind),
    ConnectUdp(ConnectUdpErrorKind),
}

impl Http3ProxyFailure {
    fn request_error_kind(self) -> RequestErrorKind {
        match self {
            Self::Socks5(Socks5ErrorKind::RuntimeUnavailable) => {
                RequestErrorKind::RuntimeUnavailable
            }
            Self::Socks5(Socks5ErrorKind::Resolve) => RequestErrorKind::Resolve,
            Self::Socks5(_) => RequestErrorKind::Proxy,
            Self::ConnectUdp(ConnectUdpErrorKind::RuntimeUnavailable) => {
                RequestErrorKind::RuntimeUnavailable
            }
            Self::ConnectUdp(ConnectUdpErrorKind::Resolve) => RequestErrorKind::Resolve,
            Self::ConnectUdp(_) => RequestErrorKind::Proxy,
        }
    }

    fn is_retryable_connection_setup(self) -> bool {
        match self {
            Self::Socks5(kind) => is_retryable_socks5_kind(kind),
            Self::ConnectUdp(kind) => is_retryable_connect_udp_kind(kind),
        }
    }
}

fn http3_proxy_failure(error: &Http3ConnectorError) -> Option<Http3ProxyFailure> {
    let source = error.source()?;
    if let Some(error) = source.downcast_ref::<ConnectUdpError>() {
        return Some(Http3ProxyFailure::ConnectUdp(error.kind()));
    }
    source
        .downcast_ref::<Socks5Error>()
        .map(|error| Http3ProxyFailure::Socks5(error.kind()))
}

fn is_retryable_connect_udp_kind(kind: ConnectUdpErrorKind) -> bool {
    matches!(
        kind,
        ConnectUdpErrorKind::Resolve | ConnectUdpErrorKind::Connect
    )
}

/// A request-body failure can surface through the response body when the
/// upload continues after an early response head.
fn body_error_kind(
    protocol_kind: RequestErrorKind,
    source: &(dyn StdError + 'static),
) -> RequestErrorKind {
    if error_chain_contains_request_body(source) {
        RequestErrorKind::RequestBody
    } else {
        protocol_kind
    }
}

fn error_chain_contains_request_body(error: &(dyn StdError + 'static)) -> bool {
    let mut current = Some(error);
    while let Some(error) = current {
        if error.is::<RequestBodyError>() {
            return true;
        }
        current = error.source();
    }
    false
}

impl fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)?;
        if let Some(source) = &self.source {
            write!(formatter, ": {source}")?;
        }
        Ok(())
    }
}

impl StdError for RequestError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

#[cfg(test)]
mod tests {
    use phantom_net::{
        http1::{Http1Error, Http1TlsError},
        http1_or_2::Http1Or2TlsError,
        http2::{Http2Error, Http2TlsError},
        http3::{ConnectUdpErrorKind, Http3ConnectorErrorKind},
        proxy::{HttpConnectError, HttpConnectErrorKind, Socks5ErrorKind},
    };

    use super::{
        RequestError, RequestErrorKind, is_retryable_connect_udp_kind,
        is_retryable_http_connect_kind, is_retryable_http3_connection_setup_kind,
        is_retryable_socks5_kind,
    };
    use crate::HttpProtocol;

    fn io_error() -> std::io::Error {
        std::io::Error::other("test connection failure")
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

        let ordinary = RequestError::http2(Http2TlsError::Connect(io_error()));
        assert!(!ordinary.is_retryable_connection_setup());
    }

    #[test]
    fn http1_or_2_connect_failure_is_retryable_connection_setup() {
        let refused =
            RequestError::http1_or_2_connection_setup(Http1Or2TlsError::Connect(io_error()));
        assert_eq!(refused.kind(), RequestErrorKind::Connect);
        assert_eq!(refused.protocol(), None);
        assert!(std::error::Error::source(&refused).is_some());
        assert!(refused.is_retryable_connection_setup());

        let runtime =
            RequestError::http1_or_2_connection_setup(Http1Or2TlsError::RuntimeUnavailable);
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
}
