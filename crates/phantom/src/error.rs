use std::{error::Error as StdError, fmt};

use phantom_net::{
    http1::{Http1Error, Http1TlsError, TlsErrorKind},
    http1_or_2::{Http1Or2TlsError, Http1Or2TlsErrorKind},
    http2::{Http2Error, Http2TlsError},
    http3::{Http3ConnectorError, Http3ConnectorErrorKind, Http3Error},
    proxy::HttpConnectError,
};
use phantom_profile::{InvalidClientHintSettings, InvalidTlsSettings};

use crate::HttpProtocol;

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
    message: &'static str,
    source: Option<BoxError>,
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

    pub(crate) fn unsupported_scheme() -> Self {
        Self::without_source(
            RequestErrorKind::UnsupportedScheme,
            "request URI must use HTTPS",
        )
    }

    pub(crate) fn invalid_authority(message: &'static str) -> Self {
        Self::without_source(RequestErrorKind::InvalidAuthority, message)
    }

    pub(crate) fn authority_header() -> Self {
        Self::without_source(
            RequestErrorKind::AuthorityHeader,
            "Host is derived from the request URI and must not be supplied as a request field",
        )
    }

    pub(crate) fn unsupported_protocol(protocol: HttpProtocol) -> Self {
        Self {
            kind: RequestErrorKind::ProtocolUnavailable,
            protocol: Some(protocol),
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
        Self {
            kind: RequestErrorKind::Capacity,
            protocol: Some(protocol),
            message: "request admission capacity is exhausted",
            source: None,
        }
    }

    pub(crate) fn invalid_target(source: phantom_net::request::InvalidOriginForm) -> Self {
        Self::with_source(
            RequestErrorKind::InvalidTarget,
            None,
            "invalid request target",
            source,
        )
    }

    pub(crate) fn http1(source: Http1TlsError) -> Self {
        let kind = match &source {
            Http1TlsError::RuntimeUnavailable => RequestErrorKind::RuntimeUnavailable,
            Http1TlsError::Connect(_) => RequestErrorKind::Connect,
            Http1TlsError::Proxy(error)
                if error.kind() == phantom_net::proxy::HttpConnectErrorKind::RuntimeUnavailable =>
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
        };
        Self::with_source(
            kind,
            Some(HttpProtocol::Http1),
            "HTTP/1 request failed",
            source,
        )
    }

    pub(crate) fn http2(source: Http2TlsError) -> Self {
        let kind = match &source {
            Http2TlsError::RuntimeUnavailable => RequestErrorKind::RuntimeUnavailable,
            Http2TlsError::Connect(_) => RequestErrorKind::Connect,
            Http2TlsError::Proxy(error)
                if error.kind() == phantom_net::proxy::HttpConnectErrorKind::RuntimeUnavailable =>
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
        };
        Self::with_source(
            kind,
            Some(HttpProtocol::Http2),
            "HTTP/2 request failed",
            source,
        )
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
        let kind = match source.kind() {
            Http3ConnectorErrorKind::RuntimeUnavailable => RequestErrorKind::RuntimeUnavailable,
            Http3ConnectorErrorKind::Resolve => RequestErrorKind::Resolve,
            Http3ConnectorErrorKind::Endpoint | Http3ConnectorErrorKind::Connect => {
                RequestErrorKind::Connect
            }
            Http3ConnectorErrorKind::Handshake => RequestErrorKind::Tls,
            _ => RequestErrorKind::Http3,
        };
        Self::with_source(
            kind,
            Some(HttpProtocol::Http3),
            "HTTP/3 request failed",
            source,
        )
    }

    pub(crate) fn http1_body(source: Http1Error) -> Self {
        Self::with_source(
            RequestErrorKind::Http1,
            Some(HttpProtocol::Http1),
            "HTTP/1 response body failed",
            source,
        )
    }

    pub(crate) fn http2_body(source: Http2Error) -> Self {
        Self::with_source(
            RequestErrorKind::Http2,
            Some(HttpProtocol::Http2),
            "HTTP/2 response body failed",
            source,
        )
    }

    pub(crate) fn http3_body(source: Http3Error) -> Self {
        Self::with_source(
            RequestErrorKind::Http3,
            Some(HttpProtocol::Http3),
            "HTTP/3 response body failed",
            source,
        )
    }

    fn without_source(kind: RequestErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            protocol: None,
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
            message,
            source: Some(Box::new(source)),
        }
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
    use super::{RequestError, RequestErrorKind};
    use crate::HttpProtocol;

    #[test]
    fn unsupported_route_preserves_the_requested_protocol() {
        let error = RequestError::unsupported_route(HttpProtocol::Http3);

        assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
        assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
        assert!(std::error::Error::source(&error).is_none());
    }
}
