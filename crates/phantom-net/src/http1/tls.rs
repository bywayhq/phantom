//! One-shot HTTP/1.1 requests over the crate's TLS transport.

use std::{error::Error as StdError, fmt};

use http::Response;
use phantom_profile::TlsSettings;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, Span, debug, debug_span, field};

use super::{Http1Body, Http1Error, OriginForm, PreparedGet, RequestHeader, send_prepared_get};
use crate::tls::TlsConnector;

pub use crate::tls::{TlsError, TlsErrorKind};

/// A reusable TLS connector for one-shot HTTP/1.1 GET requests.
#[derive(Clone, Debug)]
pub struct Http1TlsConnector {
    tls: TlsConnector,
}

impl Http1TlsConnector {
    /// Builds a connector from validated TLS settings and bundled public roots.
    pub fn new(settings: &TlsSettings) -> Result<Self, TlsError> {
        TlsConnector::new(settings).map(|tls| Self { tls })
    }

    #[cfg(test)]
    fn new_with_roots<'a>(
        settings: &TlsSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, TlsError> {
        TlsConnector::new_with_roots(settings, roots).map(|tls| Self { tls })
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
        let span = debug_span!(
            "http1.tls.send",
            method = "GET",
            transport = "tls",
            alpn = field::Empty,
            status = field::Empty,
        );
        async {
            let prepared = PreparedGet::new(target, headers)?;
            debug!("HTTP/1 request prepared");

            let stream = self.tls.connect(server_name, stream).await?;
            let negotiated_alpn = stream.negotiated_alpn();
            Span::current().record("alpn", trace_alpn(negotiated_alpn));
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
            debug!("HTTP/1 response headers received");
            Ok(response)
        }
        .instrument(span)
        .await
    }
}

/// Error returned before an HTTP/1-over-TLS response is available.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http1TlsError {
    /// TLS connector setup or handshake failed.
    Tls(TlsError),
    /// HTTP/1 request preparation or protocol setup failed.
    Http1(Http1Error),
    /// TLS selected a protocol that this HTTP/1 transport cannot speak.
    UnsupportedAlpn {
        /// Exact ALPN protocol bytes selected by the peer.
        selected: Box<[u8]>,
    },
}

impl fmt::Display for Http1TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tls(error) => write!(formatter, "TLS connection failed: {error}"),
            Self::Http1(error) => write!(formatter, "HTTP/1 request failed: {error}"),
            Self::UnsupportedAlpn { selected } => write!(
                formatter,
                "TLS selected {} ALPN, which is unsupported by the HTTP/1 transport",
                trace_alpn(Some(selected))
            ),
        }
    }
}

impl StdError for Http1TlsError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Tls(error) => Some(error),
            Self::Http1(error) => Some(error),
            Self::UnsupportedAlpn { .. } => None,
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

fn trace_alpn(protocol: Option<&[u8]>) -> &'static str {
    match protocol {
        None => "none",
        Some(b"http/1.1") => "http/1.1",
        Some(b"h2") => "h2",
        Some(b"h3") => "h3",
        Some(_) => "other",
    }
}

#[cfg(test)]
mod tests;
