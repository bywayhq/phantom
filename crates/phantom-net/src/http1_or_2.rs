//! One-handshake HTTP/1.1 or HTTP/2 selection over TLS ALPN.

use std::{error::Error as StdError, fmt, future::Future};

use phantom_profile::{Http2Settings, TlsSettings};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, Span, debug, debug_span, field};

use crate::{
    direct::{DirectConnectError, connect_tcp},
    http1::{Http1Connection, Http1Error},
    http2::{
        Http2Connection, Http2TlsConnector, Http2TlsError, connect_selected, translate_settings,
        validate_http2,
    },
    tls::{TlsConnector, TlsError, trace_alpn},
};

/// An established connection selected from one TLS ALPN negotiation.
#[derive(Debug)]
pub enum Http1Or2Connection {
    /// HTTP/1.1 was selected, or the peer did not negotiate ALPN.
    Http1(Http1Connection),
    /// The peer selected exact `h2`.
    Http2(Http2Connection),
}

/// Stable category of HTTP/1.1-or-HTTP/2 connection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http1Or2TlsErrorKind {
    /// The request lacks a Tokio runtime with network I/O enabled.
    RuntimeUnavailable,
    /// Establishing the direct TCP connection failed.
    Connect,
    /// TLS setup or negotiation failed before an HTTP protocol was selected.
    Tls,
    /// HTTP/1.1 setup failed after ALPN selection.
    Http1,
    /// HTTP/2 or ALPS setup failed after ALPN selection.
    Http2,
    /// TLS selected an unsupported ALPN protocol.
    UnsupportedAlpn,
    /// The configured profile cannot negotiate both HTTP/1.1 and HTTP/2.
    InvalidConfiguration,
}

/// Error returned while selecting HTTP/1.1 or HTTP/2 over one TLS connection.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http1Or2TlsError {
    /// The network operation was polled without a Tokio I/O runtime.
    RuntimeUnavailable,
    /// Establishing the direct TCP connection failed.
    Connect(std::io::Error),
    /// TLS connector setup or handshake failed.
    Tls(TlsError),
    /// HTTP/1.1 connection setup failed after selection.
    Http1(Http1Error),
    /// HTTP/2 or ALPS setup failed after selection.
    Http2(Http2TlsError),
    /// The peer selected an ALPN protocol other than `h2` or `http/1.1`.
    UnsupportedAlpn {
        /// Exact ALPN bytes selected by the peer.
        selected: Box<[u8]>,
    },
    /// The TLS settings do not offer `http/1.1`.
    MissingHttp1Alpn,
    /// The TLS settings do not offer `h2`.
    MissingHttp2Alpn,
}

impl Http1Or2TlsError {
    /// Returns the stable failure category.
    #[must_use]
    pub fn kind(&self) -> Http1Or2TlsErrorKind {
        match self {
            Self::RuntimeUnavailable => Http1Or2TlsErrorKind::RuntimeUnavailable,
            Self::Connect(_) => Http1Or2TlsErrorKind::Connect,
            Self::Tls(_) => Http1Or2TlsErrorKind::Tls,
            Self::Http1(_) => Http1Or2TlsErrorKind::Http1,
            Self::Http2(_) => Http1Or2TlsErrorKind::Http2,
            Self::UnsupportedAlpn { .. } => Http1Or2TlsErrorKind::UnsupportedAlpn,
            Self::MissingHttp1Alpn | Self::MissingHttp2Alpn => {
                Http1Or2TlsErrorKind::InvalidConfiguration
            }
        }
    }
}

impl fmt::Display for Http1Or2TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeUnavailable => formatter
                .write_str("negotiated HTTP/1.1 or HTTP/2 requests require a Tokio runtime"),
            Self::Connect(error) => write!(formatter, "TCP connection failed: {error}"),
            Self::Tls(error) => write!(formatter, "TLS connection failed: {error}"),
            Self::Http1(error) => write!(formatter, "HTTP/1.1 connection failed: {error}"),
            Self::Http2(error) => write!(formatter, "HTTP/2 connection failed: {error}"),
            Self::UnsupportedAlpn { selected } => write!(
                formatter,
                "TLS selected {} ALPN, which is unsupported by HTTP/1.1-or-HTTP/2 negotiation",
                trace_alpn(Some(selected))
            ),
            Self::MissingHttp1Alpn => {
                formatter.write_str("TLS settings do not offer the required `http/1.1` ALPN")
            }
            Self::MissingHttp2Alpn => {
                formatter.write_str("TLS settings do not offer the required `h2` ALPN")
            }
        }
    }
}

impl StdError for Http1Or2TlsError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Connect(error) => Some(error),
            Self::Tls(error) => Some(error),
            Self::Http1(error) => Some(error),
            Self::Http2(error) => Some(error),
            Self::RuntimeUnavailable
            | Self::UnsupportedAlpn { .. }
            | Self::MissingHttp1Alpn
            | Self::MissingHttp2Alpn => None,
        }
    }
}

impl From<TlsError> for Http1Or2TlsError {
    fn from(error: TlsError) -> Self {
        Self::Tls(error)
    }
}

impl From<Http1Error> for Http1Or2TlsError {
    fn from(error: Http1Error) -> Self {
        Self::Http1(error)
    }
}

impl From<Http2TlsError> for Http1Or2TlsError {
    fn from(error: Http2TlsError) -> Self {
        Self::Http2(error)
    }
}

/// A reusable connector that selects HTTP/1.1 or HTTP/2 from one TLS handshake.
#[derive(Clone, Debug)]
pub struct Http1Or2TlsConnector {
    tls: TlsConnector,
    http2: Http2Settings,
}

impl Http1Or2TlsConnector {
    /// Builds a connector using bundled public roots.
    ///
    /// Both `h2` and `http/1.1` must be present in the TLS ALPN offer.
    pub fn new(tls: &TlsSettings, http2: &Http2Settings) -> Result<Self, Http1Or2TlsError> {
        validate_settings(tls, http2)?;
        Ok(Self {
            tls: TlsConnector::new(tls)?,
            http2: http2.clone(),
        })
    }

    /// Builds a connector with bundled roots plus additional DER certificates.
    pub fn new_with_additional_roots<'a>(
        tls: &TlsSettings,
        http2: &Http2Settings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, Http1Or2TlsError> {
        validate_settings(tls, http2)?;
        Ok(Self {
            tls: TlsConnector::new_with_additional_roots(tls, roots)?,
            http2: http2.clone(),
        })
    }

    /// Reuses an HTTP/2 connector's validated TLS context and settings.
    ///
    /// The connector must also offer `http/1.1`. Reusing it avoids rebuilding
    /// the trust store when exact and negotiated request APIs coexist.
    ///
    /// # Errors
    ///
    /// Returns [`Http1Or2TlsError::MissingHttp1Alpn`] when the connector cannot
    /// negotiate HTTP/1.1.
    pub fn from_http2(connector: &Http2TlsConnector) -> Result<Self, Http1Or2TlsError> {
        if !connector.tls_connector().offers_alpn(b"http/1.1") {
            return Err(Http1Or2TlsError::MissingHttp1Alpn);
        }

        Ok(Self {
            tls: connector.tls_connector().clone(),
            http2: connector.settings().clone(),
        })
    }

    /// Returns a clone with a fresh isolated TLS session cache.
    #[must_use]
    pub fn with_isolated_session_cache(&self) -> Self {
        Self {
            tls: self.tls.with_isolated_session_cache(),
            http2: self.http2.clone(),
        }
    }

    /// Selects HTTP/1.1 or HTTP/2 over an already-connected stream.
    ///
    /// This performs exactly one TLS handshake. `h2` enters HTTP/2;
    /// `http/1.1` or absent ALPN enters HTTP/1.1. No protocol retry or fallback
    /// is attempted after selection.
    ///
    /// # Errors
    ///
    /// Returns [`Http1Or2TlsError`] for TLS, ALPN, ALPS, or protocol setup
    /// failures.
    pub async fn connect<S>(
        &self,
        stream: S,
        server_name: &str,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.trace_connect(async {
            let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
            let stream = self.tls.connect(server_name, stream).await?;
            select_connection(stream, client).await
        })
        .await
    }

    /// Opens one direct TCP connection and selects HTTP/1.1 or HTTP/2 over TLS.
    ///
    /// HTTP/2 settings are prepared before DNS resolution or network I/O.
    ///
    /// # Errors
    ///
    /// Returns [`Http1Or2TlsError`] for runtime, connection, TLS, ALPN, ALPS,
    /// or protocol setup failures.
    pub async fn connect_direct(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
            let stream = connect_tcp(host, port).await.map_err(|error| match error {
                DirectConnectError::RuntimeUnavailable => Http1Or2TlsError::RuntimeUnavailable,
                DirectConnectError::Connect(error) => Http1Or2TlsError::Connect(error),
            })?;
            let stream = self.tls.connect(server_name, stream).await?;
            select_connection(stream, client).await
        })
        .await
    }

    async fn trace_connect<F>(&self, operation: F) -> Result<Http1Or2Connection, Http1Or2TlsError>
    where
        F: Future<Output = Result<Http1Or2Connection, Http1Or2TlsError>>,
    {
        let span = debug_span!(
            "http1_or_2.tls.connect",
            transport = "tls",
            negotiated_alpn = field::Empty,
            selected_protocol = field::Empty,
            outcome = field::Empty,
        );
        let outcome = ConnectOutcome::new(&span);
        let result = operation.instrument(span.clone()).await;
        outcome.finish(&result);
        result
    }
}

async fn select_connection<S>(
    stream: crate::tls::TlsStream<S>,
    client: ::http2::client::Builder,
) -> Result<Http1Or2Connection, Http1Or2TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let negotiated = stream.negotiated_alpn();
    Span::current().record("negotiated_alpn", trace_alpn(negotiated));
    match negotiated {
        Some(b"h2") => {
            Span::current().record("selected_protocol", "h2");
            debug!("TLS selected HTTP/2");
            connect_selected(stream, client)
                .await
                .map(Http1Or2Connection::Http2)
                .map_err(Into::into)
        }
        Some(b"http/1.1") | None => {
            Span::current().record("selected_protocol", "http/1.1");
            debug!("TLS selected HTTP/1.1");
            Http1Connection::connect(stream)
                .await
                .map(Http1Or2Connection::Http1)
                .map_err(Into::into)
        }
        Some(selected) => Err(Http1Or2TlsError::UnsupportedAlpn {
            selected: selected.into(),
        }),
    }
}

fn validate_settings(tls: &TlsSettings, http2: &Http2Settings) -> Result<(), Http1Or2TlsError> {
    require_alpn(tls, b"http/1.1", Http1Or2TlsError::MissingHttp1Alpn)?;
    require_alpn(tls, b"h2", Http1Or2TlsError::MissingHttp2Alpn)?;
    validate_http2(http2)?;
    Ok(())
}

fn require_alpn(
    settings: &TlsSettings,
    required: &[u8],
    error: Http1Or2TlsError,
) -> Result<(), Http1Or2TlsError> {
    settings
        .alpn_protocols
        .iter()
        .any(|protocol| protocol.as_ref() == required)
        .then_some(())
        .ok_or(error)
}

struct ConnectOutcome {
    span: Span,
    recorded: bool,
}

impl ConnectOutcome {
    fn new(span: &Span) -> Self {
        Self {
            span: span.clone(),
            recorded: false,
        }
    }

    fn finish(mut self, result: &Result<Http1Or2Connection, Http1Or2TlsError>) {
        let outcome = match result {
            Ok(_) => "ok",
            Err(Http1Or2TlsError::RuntimeUnavailable) => "runtime_unavailable",
            Err(Http1Or2TlsError::Connect(_)) => "connect_error",
            Err(Http1Or2TlsError::Tls(_)) => "tls_error",
            Err(Http1Or2TlsError::Http1(_)) => "http1_error",
            Err(Http1Or2TlsError::Http2(_)) => "http2_error",
            Err(Http1Or2TlsError::UnsupportedAlpn { .. }) => "unsupported_alpn",
            Err(Http1Or2TlsError::MissingHttp1Alpn | Http1Or2TlsError::MissingHttp2Alpn) => {
                "invalid_configuration"
            }
        };
        self.span.record("outcome", outcome);
        self.recorded = true;
    }
}

impl Drop for ConnectOutcome {
    fn drop(&mut self) {
        if !self.recorded {
            let outcome = if std::thread::panicking() {
                "panicked"
            } else {
                "cancelled"
            };
            self.span.record("outcome", outcome);
        }
    }
}

#[cfg(test)]
mod tests {
    use phantom_profile::chromium::{v152_http2, v152_tls};

    use super::{Http1Or2TlsErrorKind, validate_settings};

    #[test]
    fn negotiation_requires_both_alpn_protocols() {
        let http2 = v152_http2();

        let mut tls = v152_tls();
        tls.alpn_protocols
            .retain(|protocol| protocol.as_ref() != b"http/1.1");
        let error = match validate_settings(&tls, &http2) {
            Ok(()) => panic!("missing HTTP/1.1 was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), Http1Or2TlsErrorKind::InvalidConfiguration);

        let mut tls = v152_tls();
        tls.alpn_protocols
            .retain(|protocol| protocol.as_ref() != b"h2");
        let error = match validate_settings(&tls, &http2) {
            Ok(()) => panic!("missing h2 was accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), Http1Or2TlsErrorKind::InvalidConfiguration);
    }
}
