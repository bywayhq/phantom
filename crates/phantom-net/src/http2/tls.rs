//! One-shot HTTP/2 requests over the crate's TLS transport.

use std::{error::Error as StdError, fmt, future::Future};

use http::Response;
use phantom_profile::{Http2Settings, TlsSettings};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, Span, debug, debug_span, field};

use super::{
    Http2Body, Http2Error, OperationOutcome, OriginForm, PreparedGet, RequestHeader, alps,
    send_prepared_get, translate_settings,
};
use crate::{
    direct::{DirectConnectError, connect_tcp},
    proxy::{HttpConnectError, HttpConnectHeader, connect_http_tunnel_direct},
    tls::{TlsConnector, trace_alpn},
};

pub use crate::tls::{TlsError, TlsErrorKind};

/// Reusable TLS and HTTP/2 settings for one-shot GET requests.
#[derive(Clone, Debug)]
pub struct Http2TlsConnector {
    tls: TlsConnector,
    http2: Http2Settings,
}

impl Http2TlsConnector {
    /// Builds a connector from validated TLS and HTTP/2 settings.
    pub fn new(tls: &TlsSettings, http2: &Http2Settings) -> Result<Self, Http2TlsError> {
        require_h2_alpn(tls)?;
        validate_http2(http2)?;
        TlsConnector::new(tls)
            .map(|tls| Self {
                tls,
                http2: http2.clone(),
            })
            .map_err(Into::into)
    }

    /// Builds a connector with bundled public roots and additional DER certificates.
    ///
    /// Additional roots extend verification for private authorities; they do
    /// not disable certificate or hostname verification.
    pub fn new_with_additional_roots<'a>(
        tls: &TlsSettings,
        http2: &Http2Settings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, Http2TlsError> {
        require_h2_alpn(tls)?;
        validate_http2(http2)?;
        TlsConnector::new_with_additional_roots(tls, roots)
            .map(|tls| Self {
                tls,
                http2: http2.clone(),
            })
            .map_err(Into::into)
    }

    #[cfg(test)]
    fn new_with_roots<'a>(
        tls: &TlsSettings,
        http2: &Http2Settings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, Http2TlsError> {
        require_h2_alpn(tls)?;
        validate_http2(http2)?;
        TlsConnector::new_with_roots(tls, roots)
            .map(|tls| Self {
                tls,
                http2: http2.clone(),
            })
            .map_err(Into::into)
    }

    /// Sends one empty-body HTTP/2 GET after an exact `h2` TLS negotiation.
    ///
    /// `server_name` controls certificate verification and SNI; `authority`
    /// becomes the HTTP `:authority` value and may include a port. Request
    /// preparation completes before the supplied stream is touched. Missing
    /// ALPN and every selected protocol other than exact `h2` are rejected
    /// before the HTTP/2 connection preface is written.
    pub async fn send_get<S>(
        &self,
        stream: S,
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http2Body>, Http2TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.trace_response_head(async {
            let prepared = PreparedGet::new(&self.http2, authority, target, headers)?;
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
    /// Returns [`Http2TlsError`] when request preparation, connection setup,
    /// TLS negotiation, or HTTP/2 processing fails.
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
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        self.trace_response_head(async {
            let prepared = PreparedGet::new(&self.http2, authority, target, headers)?;
            let stream = connect_tcp(host, port).await.map_err(|error| match error {
                DirectConnectError::RuntimeUnavailable => Http2TlsError::RuntimeUnavailable,
                DirectConnectError::Connect(error) => Http2TlsError::Connect(error),
            })?;
            self.send_prepared_get(stream, server_name, prepared).await
        })
        .await
    }

    /// Sends one empty-body GET through a plaintext HTTP CONNECT proxy.
    ///
    /// The origin request and CONNECT request are validated before DNS
    /// resolution or TCP I/O. Proxy failure never falls back to a direct
    /// connection or another HTTP protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] when request preparation, proxy negotiation,
    /// TLS negotiation, or HTTP/2 processing fails.
    ///
    /// # Panics
    ///
    /// Tokio may panic if the current runtime was built without network I/O
    /// enabled.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_get_http_connect(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        self.trace_response_head(async {
            let prepared = PreparedGet::new(&self.http2, authority, target, headers)?;
            let stream = connect_http_tunnel_direct(
                proxy_host,
                proxy_port,
                connect_authority,
                connect_headers,
            )
            .await?;
            self.send_prepared_get(stream, server_name, prepared).await
        })
        .await
    }

    async fn send_prepared_get<S>(
        &self,
        stream: S,
        server_name: &str,
        mut prepared: PreparedGet,
    ) -> Result<Response<Http2Body>, Http2TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!("HTTP/2 request prepared");

        let stream = self.tls.connect(server_name, stream).await?;
        let negotiated = stream.negotiated_alpn();
        Span::current().record("negotiated_alpn", trace_alpn(negotiated));
        match negotiated {
            Some(b"h2") => {}
            None => {
                debug!("TLS completed without the required HTTP/2 ALPN protocol");
                return Err(Http2TlsError::MissingNegotiatedAlpn);
            }
            Some(selected) => {
                debug!("TLS selected an unsupported HTTP/2 ALPN protocol");
                return Err(Http2TlsError::UnsupportedAlpn {
                    selected: selected.into(),
                });
            }
        }

        let peer_settings = alps::decode(stream.peer_application_settings()).map_err(|error| {
            debug!(
                frame_index = error.frame_index,
                offset = error.offset,
                reason = error.reason(),
                "TLS peer supplied invalid HTTP/2 application settings"
            );
            Http2TlsError::InvalidPeerApplicationSettings {
                frame_index: error.frame_index,
                offset: error.offset,
                reason: error.reason(),
            }
        })?;
        debug!(
            alps_frame_count = peer_settings.frame_count(),
            "HTTP/2 peer application settings decoded"
        );
        if let Some(settings) = peer_settings.into_initial_settings() {
            prepared.apply_initial_peer_settings(settings);
        }

        let response = send_prepared_get(stream, prepared).await?;
        Span::current().record("status", response.status().as_u16());
        Ok(response)
    }

    async fn trace_response_head<F>(
        &self,
        operation: F,
    ) -> Result<Response<Http2Body>, Http2TlsError>
    where
        F: Future<Output = Result<Response<Http2Body>, Http2TlsError>>,
    {
        let span = debug_span!(
            "http2.tls.response_head",
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
            Err(Http2TlsError::RuntimeUnavailable) => "runtime_unavailable",
            Err(Http2TlsError::Connect(_)) => "connect_error",
            Err(Http2TlsError::Proxy(_)) => "proxy_error",
            Err(Http2TlsError::Tls(_)) => "tls_error",
            Err(Http2TlsError::Http2(Http2Error::Protocol(_))) => "http_protocol_error",
            Err(Http2TlsError::Http2(_)) => "http_preparation_error",
            Err(Http2TlsError::MissingNegotiatedAlpn | Http2TlsError::UnsupportedAlpn { .. }) => {
                "unsupported_alpn"
            }
            Err(Http2TlsError::InvalidPeerApplicationSettings { .. }) => "invalid_peer_alps",
            Err(Http2TlsError::MissingHttp2Alpn) => "invalid_configuration",
        };
        outcome_guard.finish(outcome);
        result
    }
}

/// Error returned before an HTTP/2-over-TLS response is available.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http2TlsError {
    /// The network request was polled outside a Tokio runtime.
    RuntimeUnavailable,
    /// Establishing the direct TCP connection failed.
    Connect(std::io::Error),
    /// HTTP CONNECT proxy negotiation failed.
    Proxy(HttpConnectError),
    /// TLS connector setup or handshake failed.
    Tls(TlsError),
    /// HTTP/2 request preparation or protocol setup failed.
    Http2(Http2Error),
    /// The peer completed TLS without selecting an ALPN protocol.
    MissingNegotiatedAlpn,
    /// The peer selected a protocol other than exact `h2`.
    UnsupportedAlpn {
        /// Exact ALPN protocol bytes selected by the peer.
        selected: Box<[u8]>,
    },
    /// The peer's negotiated HTTP/2 ALPS value was malformed or invalid.
    InvalidPeerApplicationSettings {
        /// Zero-based frame position at which decoding failed.
        frame_index: usize,
        /// Byte offset of that frame within the ALPS value.
        offset: usize,
        /// Protocol reason without including any peer-supplied bytes.
        reason: &'static str,
    },
    /// The TLS settings cannot offer exact `h2`.
    MissingHttp2Alpn,
}

impl fmt::Display for Http2TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeUnavailable => {
                formatter.write_str("HTTP/2 network requests require a Tokio runtime")
            }
            Self::Connect(error) => write!(formatter, "TCP connection failed: {error}"),
            Self::Proxy(error) => write!(formatter, "HTTP proxy failed: {error}"),
            Self::Tls(error) => write!(formatter, "TLS connection failed: {error}"),
            Self::Http2(error) => write!(formatter, "HTTP/2 request failed: {error}"),
            Self::MissingNegotiatedAlpn => {
                formatter.write_str("TLS completed without negotiating the required `h2` ALPN")
            }
            Self::UnsupportedAlpn { selected } => write!(
                formatter,
                "TLS selected {} ALPN, which is unsupported by the HTTP/2 transport",
                trace_alpn(Some(selected))
            ),
            Self::InvalidPeerApplicationSettings {
                frame_index,
                offset,
                reason,
            } => write!(
                formatter,
                "invalid HTTP/2 peer application settings at frame {frame_index}, byte {offset}: {reason}"
            ),
            Self::MissingHttp2Alpn => {
                formatter.write_str("HTTP/2 TLS settings must include the exact `h2` ALPN protocol")
            }
        }
    }
}

impl StdError for Http2TlsError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Connect(error) => Some(error),
            Self::Proxy(error) => Some(error),
            Self::Tls(error) => Some(error),
            Self::Http2(error) => Some(error),
            Self::RuntimeUnavailable
            | Self::MissingNegotiatedAlpn
            | Self::UnsupportedAlpn { .. }
            | Self::InvalidPeerApplicationSettings { .. }
            | Self::MissingHttp2Alpn => None,
        }
    }
}

impl From<TlsError> for Http2TlsError {
    fn from(error: TlsError) -> Self {
        Self::Tls(error)
    }
}

impl From<HttpConnectError> for Http2TlsError {
    fn from(error: HttpConnectError) -> Self {
        Self::Proxy(error)
    }
}

impl From<Http2Error> for Http2TlsError {
    fn from(error: Http2Error) -> Self {
        Self::Http2(error)
    }
}

fn require_h2_alpn(settings: &TlsSettings) -> Result<(), Http2TlsError> {
    settings
        .alpn_protocols
        .iter()
        .any(|protocol| protocol.as_ref() == b"h2")
        .then_some(())
        .ok_or(Http2TlsError::MissingHttp2Alpn)
}

fn validate_http2(settings: &Http2Settings) -> Result<(), Http2TlsError> {
    settings.validate().map_err(Http2Error::InvalidSettings)?;
    translate_settings(settings)?;
    Ok(())
}

#[cfg(test)]
mod tests;
