//! One-shot HTTP/2 requests over the crate's TLS transport.

use std::{error::Error as StdError, fmt};

use http::Response;
use phantom_profile::{Http2Settings, TlsSettings};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, debug, debug_span, field};

use super::{
    Http2Body, Http2Error, OriginForm, PreparedGet, RequestHeader, ResponseHeadOutcome, alps,
    send_prepared_get, translate_settings,
};
use crate::tls::{TlsConnector, trace_alpn};

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
        let span = debug_span!(
            "http2.tls.response_head",
            method = "GET",
            transport = "tls",
            negotiated_alpn = field::Empty,
            status = field::Empty,
            outcome = field::Empty,
        );
        let outcome_guard = ResponseHeadOutcome::new(&span);
        let result = async {
            let mut prepared = PreparedGet::new(&self.http2, authority, target, headers)?;
            debug!("HTTP/2 request prepared");

            let stream = self.tls.connect(server_name, stream).await?;
            let negotiated = stream.negotiated_alpn();
            span.record("negotiated_alpn", trace_alpn(negotiated));
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

            let peer_settings =
                alps::decode(stream.peer_application_settings()).map_err(|error| {
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
            span.record("status", response.status().as_u16());
            Ok(response)
        }
        .instrument(span.clone())
        .await;
        let outcome = match &result {
            Err(Http2TlsError::MissingNegotiatedAlpn | Http2TlsError::UnsupportedAlpn { .. }) => {
                "unsupported_alpn"
            }
            Ok(_) => "ok",
            Err(_) => "error",
        };
        outcome_guard.finish(outcome);
        result
    }
}

/// Error returned before an HTTP/2-over-TLS response is available.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http2TlsError {
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
            Self::Tls(error) => Some(error),
            Self::Http2(error) => Some(error),
            Self::MissingNegotiatedAlpn
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
