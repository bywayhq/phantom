use std::{error::Error as StdError, fmt};

use crate::{
    http2::{Http2Error, Http2TlsError},
    tls::TlsError,
};

/// Stable category of HTTP proxy setup or negotiation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpConnectErrorKind {
    /// TLS or HTTP/2 settings cannot support the selected proxy protocol.
    InvalidConfiguration,
    /// The CONNECT authority or ordered fields are invalid.
    InvalidRequest,
    /// Proxy authentication failed or the challenge was unusable.
    Authentication,
    /// The request was polled outside a Tokio runtime.
    RuntimeUnavailable,
    /// Connecting to the proxy failed.
    Connect,
    /// TLS negotiation with the proxy failed.
    Tls,
    /// The proxy selected an unsupported application protocol.
    UnsupportedProtocol,
    /// Proxy request or response I/O failed.
    Io,
    /// The proxy response was malformed or exceeded a bound.
    InvalidResponse,
    /// The proxy rejected the tunnel request.
    Rejected,
    /// The HTTP/2 session with the proxy failed.
    Http2,
}

/// Error returned while establishing or negotiating an HTTP proxy connection.
#[derive(Debug)]
pub enum HttpConnectError {
    /// TLS settings do not offer HTTP/1.1 to the proxy.
    MissingHttp1Alpn,
    /// HTTP/2 proxy transport was selected, but TLS settings do not offer `h2`.
    MissingH2Alpn,
    /// HTTP/2 proxy transport was selected without HTTP/2 settings.
    MissingHttp2Settings,
    /// Absolute-form forwarding requires HTTP/1.1 transport to the proxy.
    ForwardingRequiresHttp1,
    /// HTTP/2 forwarding requires HTTP/2 transport to the proxy.
    ForwardingRequiresHttp2,
    /// The HTTP Basic username is invalid.
    InvalidBasicUsername,
    /// The HTTP Basic password is invalid.
    InvalidBasicPassword,
    /// The HTTP Basic credential pair cannot fit in a bounded CONNECT request.
    BasicCredentialsTooLarge,
    /// The CONNECT target is not a valid authority with an explicit port.
    InvalidAuthority,
    /// The complete CONNECT request exceeded the field-count bound.
    TooManyHeaders {
        /// Number of ordered CONNECT fields.
        count: usize,
        /// Maximum accepted field count.
        maximum: usize,
    },
    /// The complete CONNECT request exceeded the byte bound.
    RequestHeadTooLarge {
        /// Attempted request-head size.
        bytes: usize,
        /// Maximum accepted request-head size.
        maximum: usize,
    },
    /// A caller-supplied field name is invalid.
    InvalidHeaderName {
        /// Zero-based position in the caller-supplied field list.
        index: usize,
    },
    /// A caller-supplied field value is invalid.
    InvalidHeaderValue {
        /// Zero-based position in the caller-supplied field list.
        index: usize,
    },
    /// `Host` must use the destination-dependent authority placeholder.
    AuthorityHeader,
    /// CONNECT requests cannot contain request-body framing fields.
    RequestFramingHeader,
    /// The CONNECT field sequence contains no authority placeholder.
    MissingAuthorityHeader,
    /// The CONNECT field sequence contains more than one authority placeholder.
    MultipleAuthorityHeaders,
    /// An authentication placeholder was supplied without credentials.
    ProxyAuthorizationPlaceholder,
    /// Challenge-driven authentication requires one authorization placeholder.
    MissingProxyAuthorizationPlaceholder,
    /// The CONNECT fields contain more than one authorization placeholder.
    MultipleProxyAuthorizationPlaceholders,
    /// A literal authorization field is ambiguous with generated credentials.
    ProxyAuthorizationHeader,
    /// A caller-supplied CONNECT-UDP field repeats one Phantom generates:
    /// `Host`, `Connection`, `Upgrade`, or `Capsule-Protocol`.
    ConnectUdpGeneratedHeader {
        /// Zero-based position in the caller-supplied field list.
        index: usize,
    },
    /// A caller-supplied field is connection-specific and forbidden in HTTP/2.
    Http2ConnectionHeader {
        /// Zero-based position in the caller-supplied field list.
        index: usize,
    },
    /// The proxy request was polled outside a Tokio runtime.
    RuntimeUnavailable,
    /// Establishing the TCP connection to the proxy failed.
    Connect(std::io::Error),
    /// Establishing TLS with the proxy failed.
    ProxyTls(TlsError),
    /// The TLS proxy selected a protocol this HTTP proxy operation cannot use.
    UnsupportedAlpn {
        /// Exact ALPN protocol selected by the proxy.
        selected: Box<[u8]>,
    },
    /// The TLS proxy selected no protocol, but HTTP/2 transport requires `h2`.
    MissingNegotiatedAlpn,
    /// HTTP/2 settings, setup, or the CONNECT stream failed on the proxy session.
    ProxyHttp2(Box<Http2TlsError>),
    /// Writing the CONNECT request failed.
    Write(std::io::Error),
    /// Reading the CONNECT response failed.
    Read(std::io::Error),
    /// The CONNECT response head exceeded the fixed byte bound.
    ResponseHeadTooLarge {
        /// Maximum accepted response-head size.
        maximum: usize,
    },
    /// The proxy sent too many informational responses before a final status.
    TooManyInformationalResponses {
        /// Maximum accepted informational response count.
        maximum: usize,
    },
    /// The proxy returned an invalid HTTP/1 response head.
    InvalidResponse,
    /// The proxy sent a malformed authentication challenge.
    MalformedAuthenticationChallenge,
    /// The proxy did not offer a supported authentication challenge.
    UnsupportedAuthenticationChallenge,
    /// The proxy rejected the one authenticated retry.
    AuthenticationRejected,
    /// The proxy returned a non-success status.
    Rejected {
        /// HTTP response status returned by the proxy.
        status: u16,
    },
    /// The shared HTTP/2 proxy connection setup this tunnel waited for
    /// failed; the tunnel that ran it received the original error.
    PooledSetupFailed {
        /// Kind of the failed setup's error.
        kind: HttpConnectErrorKind,
    },
}

impl HttpConnectError {
    /// Reports an unusable `407` challenge to a request that inspected it.
    pub(crate) const fn is_challenge_failure(&self) -> bool {
        matches!(
            self,
            Self::MalformedAuthenticationChallenge | Self::UnsupportedAuthenticationChallenge
        )
    }

    /// Returns the stable failure category.
    #[must_use]
    pub fn kind(&self) -> HttpConnectErrorKind {
        match self {
            Self::MissingHttp1Alpn
            | Self::MissingH2Alpn
            | Self::MissingHttp2Settings
            | Self::ForwardingRequiresHttp1
            | Self::ForwardingRequiresHttp2 => HttpConnectErrorKind::InvalidConfiguration,
            Self::InvalidBasicUsername
            | Self::InvalidBasicPassword
            | Self::BasicCredentialsTooLarge
            | Self::InvalidAuthority
            | Self::TooManyHeaders { .. }
            | Self::RequestHeadTooLarge { .. }
            | Self::InvalidHeaderName { .. }
            | Self::InvalidHeaderValue { .. }
            | Self::AuthorityHeader
            | Self::RequestFramingHeader
            | Self::MissingAuthorityHeader
            | Self::MultipleAuthorityHeaders
            | Self::ProxyAuthorizationPlaceholder
            | Self::MissingProxyAuthorizationPlaceholder
            | Self::MultipleProxyAuthorizationPlaceholders
            | Self::ProxyAuthorizationHeader
            | Self::ConnectUdpGeneratedHeader { .. }
            | Self::Http2ConnectionHeader { .. } => HttpConnectErrorKind::InvalidRequest,
            Self::MalformedAuthenticationChallenge
            | Self::UnsupportedAuthenticationChallenge
            | Self::AuthenticationRejected => HttpConnectErrorKind::Authentication,
            Self::RuntimeUnavailable => HttpConnectErrorKind::RuntimeUnavailable,
            Self::Connect(_) => HttpConnectErrorKind::Connect,
            Self::ProxyTls(_) => HttpConnectErrorKind::Tls,
            Self::UnsupportedAlpn { .. } | Self::MissingNegotiatedAlpn => {
                HttpConnectErrorKind::UnsupportedProtocol
            }
            Self::ProxyHttp2(error) => match error.as_ref() {
                Http2TlsError::Http2(
                    Http2Error::InvalidSettings(_)
                    | Http2Error::UnsupportedSetting
                    | Http2Error::InvalidPriorityDependency { .. }
                    | Http2Error::InvalidPriority { .. },
                ) => HttpConnectErrorKind::InvalidConfiguration,
                Http2TlsError::RuntimeUnavailable => HttpConnectErrorKind::RuntimeUnavailable,
                _ => HttpConnectErrorKind::Http2,
            },
            Self::Write(_) | Self::Read(_) => HttpConnectErrorKind::Io,
            Self::ResponseHeadTooLarge { .. }
            | Self::TooManyInformationalResponses { .. }
            | Self::InvalidResponse => HttpConnectErrorKind::InvalidResponse,
            Self::Rejected { .. } => HttpConnectErrorKind::Rejected,
            Self::PooledSetupFailed { kind } => *kind,
        }
    }
}

impl fmt::Display for HttpConnectError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingHttp1Alpn => {
                formatter.write_str("HTTPS proxy TLS settings must offer http/1.1 through ALPN")
            }
            Self::MissingH2Alpn => formatter.write_str(
                "HTTP/2 proxy transport requires TLS settings that offer h2 through ALPN",
            ),
            Self::MissingHttp2Settings => {
                formatter.write_str("HTTP/2 proxy transport requires HTTP/2 settings")
            }
            Self::ForwardingRequiresHttp1 => formatter
                .write_str("plaintext HTTP forwarding requires HTTP/1.1 transport to the proxy"),
            Self::ForwardingRequiresHttp2 => {
                formatter.write_str("HTTP/2 forwarding requires HTTP/2 transport to the proxy")
            }
            Self::InvalidBasicUsername => {
                formatter.write_str("HTTP Basic proxy username is invalid")
            }
            Self::InvalidBasicPassword => {
                formatter.write_str("HTTP Basic proxy password is invalid")
            }
            Self::BasicCredentialsTooLarge => {
                formatter.write_str("HTTP Basic proxy credentials are too large")
            }
            Self::InvalidAuthority => formatter
                .write_str("HTTP CONNECT target must be a valid authority with an explicit port"),
            Self::TooManyHeaders { count, maximum } => write!(
                formatter,
                "HTTP CONNECT has {count} fields; maximum is {maximum}"
            ),
            Self::RequestHeadTooLarge { bytes, maximum } => write!(
                formatter,
                "HTTP CONNECT request head has {bytes} bytes; maximum is {maximum}"
            ),
            Self::InvalidHeaderName { index } => {
                write!(formatter, "HTTP CONNECT field {index} has an invalid name")
            }
            Self::InvalidHeaderValue { index } => {
                write!(formatter, "HTTP CONNECT field {index} has an invalid value")
            }
            Self::AuthorityHeader => {
                formatter.write_str("HTTP CONNECT Host must use the authority placeholder")
            }
            Self::RequestFramingHeader => {
                formatter.write_str("HTTP CONNECT must not contain request framing fields")
            }
            Self::MissingAuthorityHeader => {
                formatter.write_str("HTTP CONNECT fields must contain one authority placeholder")
            }
            Self::MultipleAuthorityHeaders => formatter
                .write_str("HTTP CONNECT fields must not contain multiple authority placeholders"),
            Self::ProxyAuthorizationPlaceholder => formatter.write_str(
                "HTTP CONNECT authorization placeholder requires challenge-driven credentials",
            ),
            Self::MissingProxyAuthorizationPlaceholder => formatter.write_str(
                "authenticated HTTP CONNECT fields must contain one authorization placeholder",
            ),
            Self::MultipleProxyAuthorizationPlaceholders => formatter.write_str(
                "HTTP CONNECT fields must not contain multiple authorization placeholders",
            ),
            Self::ProxyAuthorizationHeader => formatter
                .write_str("authenticated HTTP CONNECT must use the authorization placeholder"),
            Self::ConnectUdpGeneratedHeader { index } => write!(
                formatter,
                "CONNECT-UDP field {index} repeats a generated field"
            ),
            Self::Http2ConnectionHeader { index } => write!(
                formatter,
                "HTTP/2 CONNECT field {index} is connection-specific"
            ),
            Self::RuntimeUnavailable => {
                formatter.write_str("HTTP CONNECT requires a Tokio runtime")
            }
            Self::Connect(error) => write!(formatter, "proxy TCP connection failed: {error}"),
            Self::ProxyTls(error) => write!(formatter, "proxy TLS negotiation failed: {error}"),
            Self::UnsupportedAlpn { .. } => {
                formatter.write_str("TLS proxy selected an unsupported application protocol")
            }
            Self::MissingNegotiatedAlpn => {
                formatter.write_str("TLS proxy did not select h2 for HTTP/2 proxy transport")
            }
            Self::ProxyHttp2(error) => write!(formatter, "HTTP/2 proxy session failed: {error}"),
            Self::Write(error) => write!(formatter, "HTTP CONNECT request write failed: {error}"),
            Self::Read(error) => write!(formatter, "HTTP CONNECT response read failed: {error}"),
            Self::ResponseHeadTooLarge { maximum } => write!(
                formatter,
                "HTTP CONNECT response head exceeds {maximum} bytes"
            ),
            Self::TooManyInformationalResponses { maximum } => write!(
                formatter,
                "HTTP CONNECT response exceeds {maximum} informational responses"
            ),
            Self::InvalidResponse => {
                formatter.write_str("proxy returned an invalid HTTP CONNECT response")
            }
            Self::MalformedAuthenticationChallenge => {
                formatter.write_str("proxy returned a malformed authentication challenge")
            }
            Self::UnsupportedAuthenticationChallenge => {
                formatter.write_str("proxy did not offer supported authentication")
            }
            Self::AuthenticationRejected => {
                formatter.write_str("proxy rejected HTTP Basic authentication")
            }
            Self::Rejected { status } => {
                write!(
                    formatter,
                    "proxy rejected HTTP CONNECT with status {status}"
                )
            }
            Self::PooledSetupFailed { kind } => write!(
                formatter,
                "the shared HTTP/2 proxy connection setup this tunnel waited for failed: {}",
                kind.description()
            ),
        }
    }
}

impl StdError for HttpConnectError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Connect(error) | Self::Write(error) | Self::Read(error) => Some(error),
            Self::ProxyTls(error) => Some(error),
            Self::ProxyHttp2(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

impl HttpConnectErrorKind {
    /// A short phrase naming the category, for error messages.
    const fn description(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "invalid proxy configuration",
            Self::InvalidRequest => "invalid CONNECT request",
            Self::Authentication => "proxy authentication failure",
            Self::RuntimeUnavailable => "no Tokio runtime",
            Self::Connect => "proxy connect failure",
            Self::Tls => "proxy TLS failure",
            Self::UnsupportedProtocol => "unsupported proxy protocol",
            Self::Io => "proxy I/O failure",
            Self::InvalidResponse => "invalid proxy response",
            Self::Rejected => "proxy rejection",
            Self::Http2 => "proxy HTTP/2 failure",
        }
    }

    pub(super) const fn trace_name(self) -> &'static str {
        match self {
            Self::InvalidConfiguration => "invalid_configuration",
            Self::InvalidRequest => "invalid_request",
            Self::Authentication => "authentication_error",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::Connect => "connect_error",
            Self::Tls => "tls_error",
            Self::UnsupportedProtocol => "unsupported_protocol",
            Self::Io => "io_error",
            Self::InvalidResponse => "invalid_response",
            Self::Rejected => "rejected",
            Self::Http2 => "http2_error",
        }
    }
}
