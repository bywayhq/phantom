//! One-shot HTTP/1.1 requests over the crate's TLS transport.

use std::{error::Error as StdError, fmt, future::Future};

use http::Response;
use phantom_profile::TlsSettings;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, Span, debug, debug_span, field};

use super::{
    Http1Body, Http1Error, OperationOutcome, OriginForm, PreparedGet, RequestHeader,
    send_prepared_get,
};
use crate::{
    direct::{DirectConnectError, connect_tcp},
    tls::{TlsConnector, trace_alpn},
};

pub use crate::tls::{TlsError, TlsErrorKind};

/// A reusable TLS connector for one-shot HTTP/1.1 GET requests.
#[derive(Clone, Debug)]
pub struct Http1TlsConnector {
    tls: TlsConnector,
}

impl Http1TlsConnector {
    /// Builds a connector from validated TLS settings and bundled public roots.
    pub fn new(settings: &TlsSettings) -> Result<Self, Http1TlsError> {
        require_http1_alpn(settings)?;
        TlsConnector::new(settings)
            .map(|tls| Self { tls })
            .map_err(Into::into)
    }

    /// Builds a connector with bundled public roots and additional DER certificates.
    ///
    /// Additional roots extend verification for private authorities; they do
    /// not disable certificate or hostname verification.
    pub fn new_with_additional_roots<'a>(
        settings: &TlsSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, Http1TlsError> {
        require_http1_alpn(settings)?;
        TlsConnector::new_with_additional_roots(settings, roots)
            .map(|tls| Self { tls })
            .map_err(Into::into)
    }

    #[cfg(test)]
    fn new_with_roots<'a>(
        settings: &TlsSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, Http1TlsError> {
        require_http1_alpn(settings)?;
        TlsConnector::new_with_roots(settings, roots)
            .map(|tls| Self { tls })
            .map_err(Into::into)
    }

    /// Sends one empty-body HTTP/1.1 GET over a connected byte stream.
    ///
    /// The target and complete ordered header list are prepared before the
    /// supplied stream is touched. A server-selected ALPN protocol other than
    /// `http/1.1` is rejected before any HTTP bytes are written. No negotiated
    /// ALPN is accepted because HTTP/1.1 remains the TLS default when ALPN is
    /// absent.
    pub async fn send_get<S>(
        &self,
        stream: S,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http1Body>, Http1TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.trace_response_head(async {
            let prepared = PreparedGet::new(target, headers)?;
            self.send_prepared_get(stream, server_name, prepared).await
        })
        .await
    }

    /// Sends one empty-body GET over a new direct TCP and TLS connection.
    ///
    /// The complete request is validated before DNS resolution or TCP I/O.
    /// This method never falls back to another HTTP protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when request preparation, connection setup,
    /// TLS negotiation, or HTTP/1 processing fails.
    ///
    /// # Panics
    ///
    /// Tokio may panic if the current runtime was built without network I/O
    /// enabled.
    pub async fn send_get_direct(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        self.trace_response_head(async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = connect_tcp(host, port).await.map_err(|error| match error {
                DirectConnectError::RuntimeUnavailable => Http1TlsError::RuntimeUnavailable,
                DirectConnectError::Connect(error) => Http1TlsError::Connect(error),
            })?;
            self.send_prepared_get(stream, server_name, prepared).await
        })
        .await
    }

    async fn send_prepared_get<S>(
        &self,
        stream: S,
        server_name: &str,
        prepared: PreparedGet,
    ) -> Result<Response<Http1Body>, Http1TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!("HTTP/1 request prepared");

        let stream = self.tls.connect(server_name, stream).await?;
        let negotiated_alpn = stream.negotiated_alpn();
        Span::current().record("negotiated_alpn", trace_alpn(negotiated_alpn));
        if let Some(selected) = negotiated_alpn {
            if selected != b"http/1.1" {
                debug!("TLS selected an unsupported HTTP/1 ALPN protocol");
                return Err(Http1TlsError::UnsupportedAlpn {
                    selected: selected.into(),
                });
            }
        }

        let response = send_prepared_get(stream, prepared).await?;
        Span::current().record("status", response.status().as_u16());
        Ok(response)
    }

    async fn trace_response_head<F>(
        &self,
        operation: F,
    ) -> Result<Response<Http1Body>, Http1TlsError>
    where
        F: Future<Output = Result<Response<Http1Body>, Http1TlsError>>,
    {
        let span = debug_span!(
            "http1.tls.response_head",
            method = "GET",
            transport = "tls",
            negotiated_alpn = field::Empty,
            status = field::Empty,
            outcome = field::Empty,
        );
        let outcome_guard = OperationOutcome::new(&span);
        let result = operation.instrument(span.clone()).await;
        let outcome = match &result {
            Ok(_) => "ok",
            Err(Http1TlsError::RuntimeUnavailable) => "runtime_unavailable",
            Err(Http1TlsError::Connect(_)) => "connect_error",
            Err(Http1TlsError::Tls(_)) => "tls_error",
            Err(Http1TlsError::Http1(Http1Error::Protocol(_))) => "http_protocol_error",
            Err(Http1TlsError::Http1(Http1Error::AmbiguousResponseFraming)) => "invalid_response",
            Err(Http1TlsError::Http1(_)) => "http_preparation_error",
            Err(Http1TlsError::UnsupportedAlpn { .. }) => "unsupported_alpn",
            Err(Http1TlsError::MissingHttp1Alpn) => "invalid_configuration",
        };
        outcome_guard.finish(outcome);
        result
    }
}

/// Error returned before an HTTP/1-over-TLS response is available.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http1TlsError {
    /// The direct request was polled outside a Tokio runtime.
    RuntimeUnavailable,
    /// Establishing the direct TCP connection failed.
    Connect(std::io::Error),
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
                formatter.write_str("direct HTTP/1 requests require a Tokio runtime")
            }
            Self::Connect(error) => write!(formatter, "TCP connection failed: {error}"),
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
            Self::Tls(error) => Some(error),
            Self::Http1(error) => Some(error),
            Self::RuntimeUnavailable | Self::UnsupportedAlpn { .. } | Self::MissingHttp1Alpn => {
                None
            }
        }
    }
}

impl From<TlsError> for Http1TlsError {
    fn from(error: TlsError) -> Self {
        Self::Tls(error)
    }
}

impl From<Http1Error> for Http1TlsError {
    fn from(error: Http1Error) -> Self {
        Self::Http1(error)
    }
}

fn require_http1_alpn(settings: &TlsSettings) -> Result<(), Http1TlsError> {
    settings
        .alpn_protocols
        .iter()
        .any(|protocol| protocol.as_ref() == b"http/1.1")
        .then_some(())
        .ok_or(Http1TlsError::MissingHttp1Alpn)
}

#[cfg(test)]
mod tests;
