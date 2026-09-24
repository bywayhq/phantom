use std::{fmt, num::NonZeroUsize};

use bytes::Bytes;
use tokio_tungstenite::tungstenite::{
    Message as EngineMessage,
    protocol::{CloseFrame as EngineCloseFrame, frame::coding::CloseCode},
};

use super::WebSocketError;

/// Rewrites an empty data message so it is sent with RSV1 clear.
///
/// `permessage-deflate` otherwise deflates every text and binary message,
/// which turns an empty payload into a one-byte compressed frame. Firefox 156
/// instead sends the empty payload as it is, so this hands the engine a ready
/// frame with RSV1 clear rather than a message for it to compress. Only an
/// empty payload is rewritten, so no encoder history is skipped: the peer's
/// inflater never sees the frame, and RFC 7692, section 6 lets an
/// uncompressed message appear at any point in a context-takeover stream.
///
/// Every other message, and every message on an uncompressed connection, is
/// returned unchanged.
#[cfg(feature = "websocket-deflate")]
pub(super) fn send_empty_message_uncompressed(message: EngineMessage) -> EngineMessage {
    use tokio_tungstenite::tungstenite::protocol::frame::{
        Frame,
        coding::{Data, OpCode},
    };

    let opcode = match &message {
        EngineMessage::Text(value) if value.is_empty() => Data::Text,
        EngineMessage::Binary(value) if value.is_empty() => Data::Binary,
        _ => return message,
    };
    EngineMessage::Frame(Frame::message(
        Bytes::new(),
        OpCode::Data(opcode),
        /* is_final */ true,
    ))
}

const CONTROL_PAYLOAD_MAX: usize = 125;
const CLOSE_REASON_MAX: usize = 123;
pub(super) const WRITE_BUFFER_SIZE: usize = 128 * 1024;
const FRAME_OVERHEAD_MAX: usize = 14;
const DEFAULT_MAX_MESSAGE_FRAGMENTS: NonZeroUsize = match NonZeroUsize::new(128 * 1024) {
    Some(value) => value,
    None => NonZeroUsize::MIN,
};

/// Frame, message, fragment-count, and write-buffer bounds for one connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebSocketLimits {
    max_frame_size: NonZeroUsize,
    max_message_size: NonZeroUsize,
    max_message_fragments: NonZeroUsize,
    max_write_buffer_size: usize,
}

impl WebSocketLimits {
    /// Creates validated frame and reassembled-message bounds.
    ///
    /// The fragment-count bound starts at 131,072 data frames per message and
    /// can be replaced with [`Self::with_max_message_fragments`].
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketError`] when a frame may exceed the message bound or
    /// when the write-buffer bound cannot be represented.
    pub fn new(
        max_frame_size: NonZeroUsize,
        max_message_size: NonZeroUsize,
    ) -> Result<Self, WebSocketError> {
        if max_frame_size > max_message_size {
            return Err(WebSocketError::capacity(
                "WebSocket frame limit must not exceed the message limit",
            ));
        }
        let max_write_buffer_size = max_message_size
            .get()
            .checked_add(WRITE_BUFFER_SIZE)
            .and_then(|size| size.checked_add(FRAME_OVERHEAD_MAX))
            .ok_or_else(|| {
                WebSocketError::capacity("WebSocket message limit is too large for this platform")
            })?;
        Ok(Self {
            max_frame_size,
            max_message_size,
            max_message_fragments: DEFAULT_MAX_MESSAGE_FRAGMENTS,
            max_write_buffer_size,
        })
    }

    /// Sets the maximum number of data frames accepted for one message.
    ///
    /// The initial text or binary frame and every continuation frame count;
    /// interleaved Ping, Pong, and Close frames do not.
    #[must_use]
    pub const fn with_max_message_fragments(mut self, maximum: NonZeroUsize) -> Self {
        self.max_message_fragments = maximum;
        self
    }

    /// Returns the maximum accepted frame payload size.
    #[must_use]
    pub fn max_frame_size(self) -> NonZeroUsize {
        self.max_frame_size
    }

    /// Returns the maximum accepted or sent reassembled message size.
    #[must_use]
    pub fn max_message_size(self) -> NonZeroUsize {
        self.max_message_size
    }

    /// Returns the maximum number of data frames accepted for one message.
    #[must_use]
    pub const fn max_message_fragments(self) -> NonZeroUsize {
        self.max_message_fragments
    }

    pub(super) fn max_write_buffer_size(self) -> usize {
        self.max_write_buffer_size
    }
}

impl Default for WebSocketLimits {
    fn default() -> Self {
        const FRAME: NonZeroUsize = match NonZeroUsize::new(16 * 1024 * 1024) {
            Some(value) => value,
            None => NonZeroUsize::MIN,
        };
        const MESSAGE: NonZeroUsize = match NonZeroUsize::new(64 * 1024 * 1024) {
            Some(value) => value,
            None => NonZeroUsize::MIN,
        };
        Self {
            max_frame_size: FRAME,
            max_message_size: MESSAGE,
            max_message_fragments: DEFAULT_MAX_MESSAGE_FRAGMENTS,
            max_write_buffer_size: MESSAGE.get() + WRITE_BUFFER_SIZE + FRAME_OVERHEAD_MAX,
        }
    }
}

/// A close code and optional human-readable reason.
#[derive(Clone, Eq, PartialEq)]
pub struct WebSocketCloseFrame {
    code: u16,
    reason: String,
}

impl WebSocketCloseFrame {
    /// Creates a close frame after validating its code and bounded reason.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketError`] for a reserved or untransmittable code, or
    /// when the UTF-8 reason exceeds 123 bytes.
    pub fn new(code: u16, reason: impl Into<String>) -> Result<Self, WebSocketError> {
        if !CloseCode::from(code).is_allowed() {
            return Err(WebSocketError::invalid_request(
                "WebSocket close code cannot be sent on the wire",
            ));
        }
        let reason = reason.into();
        if reason.len() > CLOSE_REASON_MAX {
            return Err(WebSocketError::capacity(
                "WebSocket close reason exceeds 123 UTF-8 bytes",
            ));
        }
        Ok(Self { code, reason })
    }

    /// Returns the numeric close code.
    #[must_use]
    pub fn code(&self) -> u16 {
        self.code
    }

    /// Returns the close reason.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }

    pub(super) fn into_engine(self) -> EngineCloseFrame {
        EngineCloseFrame {
            code: self.code.into(),
            reason: self.reason.into(),
        }
    }

    pub(super) fn from_engine(frame: EngineCloseFrame) -> Self {
        Self {
            code: frame.code.into(),
            reason: frame.reason.to_string(),
        }
    }
}

impl fmt::Debug for WebSocketCloseFrame {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebSocketCloseFrame")
            .field("code", &self.code)
            .field("reason", &"<redacted>")
            .finish()
    }
}

/// One complete WebSocket message or control event.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum WebSocketMessage {
    /// A complete UTF-8 text message.
    Text(String),
    /// A complete binary message.
    Binary(Bytes),
    /// A Ping control event. Phantom sends the matching Pong automatically.
    Ping(Bytes),
    /// A Pong control event.
    Pong(Bytes),
    /// A Close control event.
    Close(Option<WebSocketCloseFrame>),
}

impl WebSocketMessage {
    pub(super) fn into_engine(
        self,
        limits: WebSocketLimits,
    ) -> Result<EngineMessage, WebSocketError> {
        let maximum = limits.max_message_size.get();
        match self {
            Self::Text(value) if value.len() > maximum => Err(WebSocketError::capacity(
                "outgoing WebSocket text message exceeds the configured limit",
            )),
            Self::Binary(value) if value.len() > maximum => Err(WebSocketError::capacity(
                "outgoing WebSocket binary message exceeds the configured limit",
            )),
            Self::Ping(value) if value.len() > CONTROL_PAYLOAD_MAX => Err(
                WebSocketError::capacity("WebSocket Ping payload exceeds 125 bytes"),
            ),
            Self::Pong(value) if value.len() > CONTROL_PAYLOAD_MAX => Err(
                WebSocketError::capacity("WebSocket Pong payload exceeds 125 bytes"),
            ),
            Self::Text(value) => Ok(EngineMessage::Text(value.into())),
            Self::Binary(value) => Ok(EngineMessage::Binary(value)),
            Self::Ping(value) => Ok(EngineMessage::Ping(value)),
            Self::Pong(value) => Ok(EngineMessage::Pong(value)),
            Self::Close(frame) => Ok(EngineMessage::Close(
                frame.map(WebSocketCloseFrame::into_engine),
            )),
        }
    }

    pub(super) fn from_engine(message: EngineMessage) -> Result<Self, WebSocketError> {
        match message {
            EngineMessage::Text(value) => Ok(Self::Text(value.to_string())),
            EngineMessage::Binary(value) => Ok(Self::Binary(value)),
            EngineMessage::Ping(value) => Ok(Self::Ping(value)),
            EngineMessage::Pong(value) => Ok(Self::Pong(value)),
            EngineMessage::Close(frame) => {
                Ok(Self::Close(frame.map(WebSocketCloseFrame::from_engine)))
            }
            EngineMessage::Frame(_) => Err(WebSocketError::protocol(
                "WebSocket engine exposed an unexpected raw frame",
            )),
        }
    }

    pub(super) fn trace_kind(&self) -> &'static str {
        match self {
            Self::Text(_) => "text",
            Self::Binary(_) => "binary",
            Self::Ping(_) => "ping",
            Self::Pong(_) => "pong",
            Self::Close(_) => "close",
        }
    }

    pub(super) fn payload_len(&self) -> usize {
        match self {
            Self::Text(value) => value.len(),
            Self::Binary(value) | Self::Ping(value) | Self::Pong(value) => value.len(),
            Self::Close(Some(frame)) => frame.reason.len() + 2,
            Self::Close(None) => 0,
        }
    }
}

impl fmt::Debug for WebSocketMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WebSocketMessage")
            .field("kind", &self.trace_kind())
            .field("payload_bytes", &self.payload_len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{WebSocketCloseFrame, WebSocketMessage};

    #[test]
    fn debug_output_redacts_message_and_close_contents() -> Result<(), Box<dyn std::error::Error>> {
        let message = WebSocketMessage::Text("unique-message-secret".into());
        let close = WebSocketCloseFrame::new(1000, "unique-close-secret")?;

        assert!(!format!("{message:?}").contains("unique-message-secret"));
        assert!(!format!("{close:?}").contains("unique-close-secret"));
        Ok(())
    }
}
