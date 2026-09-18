use std::{error::Error as StdError, fmt};

use http::Response;
use tokio_tungstenite::tungstenite::{Error as EngineError, error::ProtocolError};

use crate::{RequestError, RequestErrorKind, ResponseBody};

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
    /// The client profile cannot negotiate HTTP/1.1.
    ProtocolUnavailable,
    /// The current Tokio runtime cannot perform network I/O.
    RuntimeUnavailable,
    /// Establishing the direct network connection failed.
    Connect,
    /// HTTP CONNECT proxy negotiation failed.
    Proxy,
    /// TLS setup or negotiation failed.
    Tls,
    /// The HTTP/1.1 opening handshake could not be completed.
    Http1,
    /// Generating the opening-handshake nonce failed.
    Random,
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

    pub(super) fn protocol_unavailable() -> Self {
        Self::new(
            WebSocketErrorKind::ProtocolUnavailable,
            "client profile cannot negotiate HTTP/1.1 for WebSocket",
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
            RequestErrorKind::AuthorityHeader
            | RequestErrorKind::InvalidHeader
            | RequestErrorKind::InvalidTimeout
            | RequestErrorKind::RequestBody
            | RequestErrorKind::Redirect => WebSocketErrorKind::InvalidRequest,
            RequestErrorKind::ProtocolUnavailable | RequestErrorKind::UnsupportedRoute => {
                WebSocketErrorKind::ProtocolUnavailable
            }
            RequestErrorKind::Resolve | RequestErrorKind::Connect => WebSocketErrorKind::Connect,
            RequestErrorKind::Proxy => WebSocketErrorKind::Proxy,
            RequestErrorKind::RuntimeUnavailable => WebSocketErrorKind::RuntimeUnavailable,
            RequestErrorKind::Capacity => WebSocketErrorKind::Capacity,
            RequestErrorKind::Tls => WebSocketErrorKind::Tls,
            RequestErrorKind::Http1
            | RequestErrorKind::Http2
            | RequestErrorKind::Http3
            | RequestErrorKind::Timeout => WebSocketErrorKind::Http1,
        };
        Self::with_source(kind, "WebSocket transport failed", source)
    }

    pub(super) fn rejected(response: Response<ResponseBody>) -> Self {
        Self {
            kind: WebSocketErrorKind::HandshakeRejected,
            message: "server rejected the WebSocket opening handshake",
            source: None,
            response: Some(Box::new(response)),
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

    pub(super) fn closed() -> Self {
        Self::new(WebSocketErrorKind::Closed, "WebSocket connection is closed")
    }

    fn new(kind: WebSocketErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            source: None,
            response: None,
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
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub fn kind(&self) -> WebSocketErrorKind {
        self.kind
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
