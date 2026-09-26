use std::{error::Error as StdError, fmt};

use http::Response;
use tokio_tungstenite::tungstenite::{Error as EngineError, error::ProtocolError};

use phantom_net::http2::{Http2Error, Http2ProtocolErrorKind, Http2TlsError};

use crate::{HttpProtocol, RequestError, RequestErrorKind, ResponseBody, TimeoutPhase};

type BoxError = Box<dyn StdError + Send + Sync>;

/// Stable category of WebSocket connection or framing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WebSocketErrorKind {
    /// The WebSocket URI is syntactically invalid.
    InvalidUri,
    /// The URI does not use the `ws` or `wss` WebSocket scheme.
    UnsupportedScheme,
    /// The URI authority is missing or invalid.
    InvalidAuthority,
    /// The ordered opening-handshake fields are invalid.
    InvalidRequest,
    /// The client profile cannot use the selected WebSocket protocol.
    ProtocolUnavailable,
    /// The selected route does not support this WebSocket transport.
    UnsupportedRoute,
    /// The current Tokio runtime cannot perform network I/O.
    RuntimeUnavailable,
    /// Establishing the direct network connection failed.
    Connect,
    /// HTTP forward- or CONNECT-proxy setup, negotiation, or authentication failed.
    Proxy,
    /// TLS setup or negotiation failed.
    Tls,
    /// The HTTP/1.1 opening handshake could not be completed.
    Http1,
    /// The HTTP/2 extended CONNECT handshake could not be completed.
    Http2,
    /// Generating the opening-handshake nonce failed.
    Random,
    /// The opening handshake did not finish within its handshake timeout.
    ///
    /// [`WebSocketError::timeout_phase`] names the phase.
    Timeout,
    /// The server returned an ordinary HTTP response instead of upgrading.
    HandshakeRejected,
    /// The server's `101` response did not satisfy the WebSocket handshake.
    InvalidHandshake,
    /// A frame, message, or write buffer exceeded its configured bound.
    Capacity,
    /// A WebSocket framing rule was violated.
    Protocol,
    /// Text or a close reason was not valid UTF-8.
    InvalidUtf8,
    /// Reading or writing the upgraded connection failed.
    Io,
    /// The peer ended the transport without completing the close handshake.
    AbnormalClosure,
    /// The WebSocket is closed and cannot perform the requested operation.
    Closed,
}

/// Error returned by WebSocket connection and message operations.
pub struct WebSocketError {
    kind: WebSocketErrorKind,
    message: &'static str,
    source: Option<BoxError>,
    response: Option<Box<Response<ResponseBody>>>,
    timeout_phase: Option<TimeoutPhase>,
    /// Set when connection setup failed before any byte reached the origin,
    /// so a caller-enabled handshake retry may open another connection.
    retryable_setup: bool,
}

impl WebSocketError {
    pub(super) fn invalid_uri(source: http::uri::InvalidUri) -> Self {
        Self::with_source(
            WebSocketErrorKind::InvalidUri,
            "invalid WebSocket URI",
            source,
        )
    }

    pub(super) fn unsupported_scheme() -> Self {
        Self::new(
            WebSocketErrorKind::UnsupportedScheme,
            "WebSocket URI must use WS or WSS",
        )
    }

    pub(super) fn invalid_authority(message: &'static str) -> Self {
        Self::new(WebSocketErrorKind::InvalidAuthority, message)
    }

    pub(super) fn invalid_request(message: &'static str) -> Self {
        Self::new(WebSocketErrorKind::InvalidRequest, message)
    }

    pub(super) fn protocol_unavailable(protocol: HttpProtocol) -> Self {
        let message = match protocol {
            HttpProtocol::Http1 => "client profile cannot use HTTP/1.1 for WebSocket",
            HttpProtocol::Http2 => {
                "client profile cannot use HTTP/2 extended CONNECT for WebSocket"
            }
            HttpProtocol::Http3 => "HTTP/3 WebSocket is not implemented",
        };
        Self::new(WebSocketErrorKind::ProtocolUnavailable, message)
    }

    pub(super) fn profile_policy_unavailable() -> Self {
        Self::new(
            WebSocketErrorKind::ProtocolUnavailable,
            "client profile has no WebSocket connection policy",
        )
    }

    pub(super) fn random(source: btls::error::ErrorStack) -> Self {
        Self::with_source(
            WebSocketErrorKind::Random,
            "failed to generate WebSocket handshake nonce",
            source,
        )
    }

    pub(super) fn request(source: RequestError) -> Self {
        let kind = match source.kind() {
            RequestErrorKind::InvalidUri | RequestErrorKind::InvalidTarget => {
                WebSocketErrorKind::InvalidUri
            }
            RequestErrorKind::UnsupportedScheme => WebSocketErrorKind::UnsupportedScheme,
            RequestErrorKind::InvalidAuthority => WebSocketErrorKind::InvalidAuthority,
            RequestErrorKind::InvalidHeader
            | RequestErrorKind::RequestTemplate
            | RequestErrorKind::InvalidTimeout
            | RequestErrorKind::RequestBody
            | RequestErrorKind::ResponseBodyLimit
            | RequestErrorKind::Redirect => WebSocketErrorKind::InvalidRequest,
            RequestErrorKind::ContentDecoding => WebSocketErrorKind::Protocol,
            RequestErrorKind::ProtocolUnavailable => WebSocketErrorKind::ProtocolUnavailable,
            RequestErrorKind::UnsupportedRoute => WebSocketErrorKind::UnsupportedRoute,
            RequestErrorKind::Resolve | RequestErrorKind::Connect => WebSocketErrorKind::Connect,
            RequestErrorKind::Proxy => WebSocketErrorKind::Proxy,
            RequestErrorKind::RuntimeUnavailable => WebSocketErrorKind::RuntimeUnavailable,
            RequestErrorKind::Capacity => WebSocketErrorKind::Capacity,
            RequestErrorKind::Tls => WebSocketErrorKind::Tls,
            RequestErrorKind::Http1 => WebSocketErrorKind::Http1,
            RequestErrorKind::Http2 => WebSocketErrorKind::Http2,
            RequestErrorKind::Http3 => WebSocketErrorKind::Protocol,
            RequestErrorKind::Timeout => WebSocketErrorKind::Timeout,
        };
        let timeout_phase = source.timeout_phase();
        let retryable_setup = source.is_retryable_connection_setup();
        let message = match timeout_phase {
            Some(_) => "WebSocket opening handshake timed out",
            None => "WebSocket transport failed",
        };
        Self {
            timeout_phase,
            retryable_setup,
            ..Self::with_source(kind, message, source)
        }
    }

    pub(super) fn rejected(response: Response<ResponseBody>) -> Self {
        Self {
            kind: WebSocketErrorKind::HandshakeRejected,
            message: "server rejected the WebSocket opening handshake",
            source: None,
            response: Some(Box::new(response)),
            timeout_phase: None,
            retryable_setup: false,
        }
    }

    pub(super) fn invalid_handshake(message: &'static str) -> Self {
        Self::new(WebSocketErrorKind::InvalidHandshake, message)
    }

    #[cfg(feature = "websocket-deflate")]
    pub(super) fn invalid_handshake_source(source: impl StdError + Send + Sync + 'static) -> Self {
        Self::with_source(
            WebSocketErrorKind::InvalidHandshake,
            "server selected an invalid WebSocket extension",
            source,
        )
    }

    pub(super) fn capacity(message: &'static str) -> Self {
        Self::new(WebSocketErrorKind::Capacity, message)
    }

    pub(super) fn protocol(message: &'static str) -> Self {
        Self::new(WebSocketErrorKind::Protocol, message)
    }

    pub(super) fn engine(source: EngineError) -> Self {
        if matches!(&source, EngineError::WriteBufferFull(_)) {
            return Self::capacity("WebSocket write buffer reached its configured limit");
        }
        let kind = match &source {
            EngineError::ConnectionClosed | EngineError::AlreadyClosed => {
                WebSocketErrorKind::Closed
            }
            EngineError::Io(_) => WebSocketErrorKind::Io,
            EngineError::Random(_) => WebSocketErrorKind::Random,
            EngineError::Capacity(_) => WebSocketErrorKind::Capacity,
            EngineError::WriteBufferFull(_) => WebSocketErrorKind::Capacity,
            EngineError::Utf8(_) => WebSocketErrorKind::InvalidUtf8,
            EngineError::Protocol(ProtocolError::ResetWithoutClosingHandshake) => {
                WebSocketErrorKind::AbnormalClosure
            }
            EngineError::Protocol(_) | EngineError::AttackAttempt => WebSocketErrorKind::Protocol,
            EngineError::Tls(_) | EngineError::Url(_) => WebSocketErrorKind::Protocol,
            #[cfg(feature = "websocket-deflate")]
            EngineError::Http(_) | EngineError::HttpFormat(_) => WebSocketErrorKind::Protocol,
        };
        Self::with_source(kind, "WebSocket operation failed", source)
    }

    pub(super) fn engine_io(source: std::io::Error) -> Self {
        Self::engine(EngineError::Io(source))
    }

    pub(super) fn closed() -> Self {
        Self::new(WebSocketErrorKind::Closed, "WebSocket connection is closed")
    }

    fn new(kind: WebSocketErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            source: None,
            response: None,
            timeout_phase: None,
            retryable_setup: false,
        }
    }

    fn with_source(
        kind: WebSocketErrorKind,
        message: &'static str,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message,
            source: Some(Box::new(source)),
            response: None,
            timeout_phase: None,
            retryable_setup: false,
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub fn kind(&self) -> WebSocketErrorKind {
        self.kind
    }

    /// Returns the phase that timed out, when this is a
    /// [`WebSocketErrorKind::Timeout`] failure.
    ///
    /// A handshake timeout reports [`TimeoutPhase::WebSocketHandshake`].
    #[must_use]
    pub fn timeout_phase(&self) -> Option<TimeoutPhase> {
        self.timeout_phase
    }

    /// Returns whether connection setup failed before any byte of the
    /// opening reached the origin, which a
    /// [`WebSocketRetryPolicy`](super::WebSocketRetryPolicy) may retry.
    pub(super) fn is_retryable_connection_setup(&self) -> bool {
        self.retryable_setup
    }

    /// Returns the rejecting HTTP response, when the server did not upgrade.
    #[must_use]
    pub fn response(&self) -> Option<&Response<ResponseBody>> {
        self.response.as_deref()
    }

    /// Consumes the error and returns the rejecting HTTP response, if present.
    #[must_use]
    pub fn into_response(self) -> Option<Response<ResponseBody>> {
        self.response.map(|response| *response)
    }
}

impl fmt::Debug for WebSocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebSocketError")
            .field("kind", &self.kind)
            .field("message", &self.message)
            .field("has_source", &self.source.is_some())
            .field("timeout_phase", &self.timeout_phase)
            .field(
                "response_status",
                &self.response.as_deref().map(Response::status),
            )
            .finish()
    }
}

impl fmt::Display for WebSocketError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)?;
        if let Some(source) = &self.source {
            write!(formatter, ": {source}")?;
        }
        if let Some(response) = &self.response {
            write!(formatter, ": HTTP {}", response.status())?;
        }
        Ok(())
    }
}

impl StdError for WebSocketError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

/// Returns whether the peer refused the extended CONNECT stream before
/// processing anything on it.
///
/// RFC 9113, section 8.7: a stream the peer reset with `REFUSED_STREAM` was
/// closed before it acted on the request, so the opening fields are the only
/// bytes the client sent on it and they can be sent again. Nothing else
/// qualifies. A connection-level error such as `GOAWAY` is deliberately
/// excluded: the session is going away, so reopening on it would fail again.
pub(super) fn refused_extended_connect_stream(error: &Http2TlsError) -> bool {
    /// RFC 9113, section 7.
    const REFUSED_STREAM: u32 = 0x7;

    matches!(
        error,
        Http2TlsError::Http2(Http2Error::Protocol(protocol))
            if protocol.is_remote()
                && protocol.kind() == Http2ProtocolErrorKind::StreamReset
                && protocol.reason_code() == Some(REFUSED_STREAM)
    )
}
