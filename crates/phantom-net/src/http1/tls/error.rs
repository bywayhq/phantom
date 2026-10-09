use std::{error::Error as StdError, fmt};

use super::{EchFailure, Http1Error, TlsError, trace_alpn};
use crate::proxy::{HttpConnectError, Socks5Error};

/// Stable category of HTTP/1 TLS or proxy setup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http1TlsErrorKind {
    /// The operation requires a Tokio runtime.
    RuntimeUnavailable,
    /// Opening the direct TCP connection failed.
    Connect,
    /// Opening or negotiating the HTTP proxy connection failed.
    HttpProxy,
    /// SOCKS5 connection setup failed.
    Socks5Proxy,
    /// TLS setup or the handshake failed.
    Tls,
    /// HTTP/1 preparation or protocol setup failed.
    Http1,
    /// The peer selected an unsupported application protocol.
    UnsupportedAlpn,
    /// The TLS profile cannot negotiate HTTP/1.1.
    InvalidConfiguration,
}

/// Error returned before an HTTP/1 response is available.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http1TlsError {
    /// The network request was polled outside a Tokio runtime.
    RuntimeUnavailable,
    /// Establishing the direct TCP connection failed.
    Connect(std::io::Error),
    /// Establishing the plaintext HTTP forward-proxy connection failed.
    ForwardProxyConnect(std::io::Error),
    /// HTTP proxy connection setup or negotiation failed.
    Proxy(HttpConnectError),
    /// SOCKS5 proxy negotiation failed.
    Socks5Proxy(Socks5Error),
    /// TLS connector setup or handshake failed.
    Tls(TlsError),
    /// HTTP/1 request preparation or protocol setup failed.
    Http1(Http1Error),
    /// TLS selected a protocol that this HTTP/1 transport cannot speak.
    UnsupportedAlpn {
        /// Exact ALPN protocol bytes selected by the peer.
        selected: Box<[u8]>,
    },
    /// The TLS settings cannot negotiate HTTP/1.1.
    MissingHttp1Alpn,
}

impl fmt::Display for Http1TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeUnavailable => {
                formatter.write_str("HTTP/1 network requests require a Tokio runtime")
            }
            Self::Connect(error) => write!(formatter, "TCP connection failed: {error}"),
            Self::ForwardProxyConnect(error) => {
                write!(formatter, "HTTP forward proxy connection failed: {error}")
            }
            Self::Proxy(error) => write!(formatter, "HTTP proxy failed: {error}"),
            Self::Socks5Proxy(error) => write!(formatter, "SOCKS5 proxy failed: {error}"),
            Self::Tls(error) => write!(formatter, "TLS connection failed: {error}"),
            Self::Http1(error) => write!(formatter, "HTTP/1 request failed: {error}"),
            Self::UnsupportedAlpn { selected } => write!(
                formatter,
                "TLS selected {} ALPN, which is unsupported by the HTTP/1 transport",
                trace_alpn(Some(selected))
            ),
            Self::MissingHttp1Alpn => formatter
                .write_str("HTTP/1 TLS settings must include the exact `http/1.1` ALPN protocol"),
        }
    }
}

impl StdError for Http1TlsError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Connect(error) => Some(error),
            Self::ForwardProxyConnect(error) => Some(error),
            Self::Proxy(error) => Some(error),
            Self::Socks5Proxy(error) => Some(error),
            Self::Tls(error) => Some(error),
            Self::Http1(error) => Some(error),
            Self::RuntimeUnavailable | Self::UnsupportedAlpn { .. } | Self::MissingHttp1Alpn => {
                None
            }
        }
    }
}

impl Http1TlsError {
    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> Http1TlsErrorKind {
        match self {
            Self::RuntimeUnavailable => Http1TlsErrorKind::RuntimeUnavailable,
            Self::Connect(_) => Http1TlsErrorKind::Connect,
            Self::Proxy(_) | Self::ForwardProxyConnect(_) => Http1TlsErrorKind::HttpProxy,
            Self::Socks5Proxy(_) => Http1TlsErrorKind::Socks5Proxy,
            Self::Tls(_) => Http1TlsErrorKind::Tls,
            Self::Http1(_) => Http1TlsErrorKind::Http1,
            Self::UnsupportedAlpn { .. } => Http1TlsErrorKind::UnsupportedAlpn,
            Self::MissingHttp1Alpn => Http1TlsErrorKind::InvalidConfiguration,
        }
    }

    /// Returns why a connection that offered Encrypted Client Hello failed,
    /// when that is the cause.
    #[must_use]
    pub fn ech_failure(&self) -> Option<EchFailure> {
        match self {
            Self::Tls(error) => error.ech_failure(),
            _ => None,
        }
    }
}

impl From<TlsError> for Http1TlsError {
    fn from(error: TlsError) -> Self {
        Self::Tls(error)
    }
}

#[cfg(feature = "https-records")]
impl From<crate::direct::DirectTlsError> for Http1TlsError {
    fn from(error: crate::direct::DirectTlsError) -> Self {
        use crate::direct::{DirectConnectError, DirectTlsError};

        match error {
            DirectTlsError::Direct(DirectConnectError::RuntimeUnavailable) => {
                Self::RuntimeUnavailable
            }
            DirectTlsError::Direct(DirectConnectError::Connect(error)) => Self::Connect(error),
            DirectTlsError::Tls(error) => Self::Tls(error),
        }
    }
}

impl From<HttpConnectError> for Http1TlsError {
    fn from(error: HttpConnectError) -> Self {
        Self::Proxy(error)
    }
}

impl From<Socks5Error> for Http1TlsError {
    fn from(error: Socks5Error) -> Self {
        Self::Socks5Proxy(error)
    }
}

impl From<Http1Error> for Http1TlsError {
    fn from(error: Http1Error) -> Self {
        Self::Http1(error)
    }
}
