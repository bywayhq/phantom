use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use http::Response;
use phantom_net::http1::Http1Upgrade;
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::protocol::{Role, WebSocketConfig},
};
use tracing::{Instrument, Span, debug_span, field};

#[cfg(feature = "websocket-deflate")]
use super::NegotiatedPerMessageDeflate;
use super::{
    OperationOutcome, WebSocketCloseFrame, WebSocketError, WebSocketLimits, WebSocketMessage,
    message::WRITE_BUFFER_SIZE,
};

/// One established, exclusively owned WebSocket connection.
///
/// Incoming fragmented data frames are exposed as complete messages. Ping and
/// Close replies are flushed before their event is returned. Dropping this
/// value closes the transport immediately; use [`WebSocket::close`] to send a
/// graceful Close frame first.
pub struct WebSocket {
    socket: Option<WebSocketStream<Http1Upgrade>>,
    handshake: Response<()>,
    selected_protocol: Option<Box<str>>,
    limits: WebSocketLimits,
    #[cfg(feature = "websocket-deflate")]
    permessage_deflate: Option<NegotiatedPerMessageDeflate>,
    pending_incoming: Option<WebSocketMessage>,
}

impl fmt::Debug for WebSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("WebSocket");
        debug
            .field("status", &self.handshake.status())
            .field("has_selected_protocol", &self.selected_protocol.is_some())
            .field("limits", &self.limits);
        #[cfg(feature = "websocket-deflate")]
        debug.field("permessage_deflate", &self.permessage_deflate);
        debug.finish_non_exhaustive()
    }
}

impl WebSocket {
    pub(super) async fn new(
        stream: Http1Upgrade,
        handshake: Response<()>,
        selected_protocol: Option<Box<str>>,
        limits: WebSocketLimits,
        config: WebSocketConfig,
        #[cfg(feature = "websocket-deflate")] permessage_deflate: Option<
            NegotiatedPerMessageDeflate,
        >,
    ) -> Self {
        let socket = WebSocketStream::from_raw_socket(stream, Role::Client, Some(config)).await;
        Self {
            socket: Some(socket),
            handshake,
            selected_protocol,
            limits,
            #[cfg(feature = "websocket-deflate")]
            permessage_deflate,
            pending_incoming: None,
        }
    }

    pub(super) fn engine_config(limits: WebSocketLimits) -> WebSocketConfig {
        WebSocketConfig::default()
            .write_buffer_size(WRITE_BUFFER_SIZE)
            .max_write_buffer_size(limits.max_write_buffer_size())
            .max_message_size(Some(limits.max_message_size().get()))
            .max_frame_size(Some(limits.max_frame_size().get()))
            .max_message_fragments(Some(limits.max_message_fragments().get()))
            .accept_unmasked_frames(false)
    }

    /// Returns the validated `101` response and its ordered-header extension.
    #[must_use]
    pub fn handshake_response(&self) -> &Response<()> {
        &self.handshake
    }

    /// Returns the server-selected subprotocol, if any.
    #[must_use]
    pub fn selected_protocol(&self) -> Option<&str> {
        self.selected_protocol.as_deref()
    }

    /// Returns the effective negotiated compression settings, when selected.
    #[cfg(feature = "websocket-deflate")]
    #[must_use]
    pub fn negotiated_permessage_deflate(&self) -> Option<NegotiatedPerMessageDeflate> {
        self.permessage_deflate
    }

    /// Returns the active frame and message bounds.
    #[must_use]
    pub fn limits(&self) -> WebSocketLimits {
        self.limits
    }

    /// Sends and flushes one complete message.
    ///
    /// A cancelled send has the usual asynchronous write ambiguity; callers
    /// must not retry it blindly. Payloads are never included in tracing.
    pub async fn send(&mut self, message: WebSocketMessage) -> Result<(), WebSocketError> {
        let kind = message.trace_kind();
        let bytes = message.payload_len();
        let span = debug_span!(
            "websocket.send",
            message_kind = kind,
            payload_bytes = bytes,
            outcome = field::Empty,
            error_kind = field::Empty,
        );
        let outcome = OperationOutcome::new(&span);
        let engine_message = match message.into_engine(self.limits) {
            Ok(message) => message,
            Err(error) => {
                outcome.finish("error", Some(error.kind()));
                return Err(error);
            }
        };
        let socket = match self.socket.as_mut() {
            Some(socket) => socket,
            None => {
                let error = WebSocketError::closed();
                outcome.finish("error", Some(error.kind()));
                return Err(error);
            }
        };
        let result = socket
            .send(engine_message)
            .instrument(span.clone())
            .await
            .map_err(WebSocketError::engine);
        match &result {
            Ok(()) => outcome.finish("ok", None),
            Err(error) => outcome.finish("error", Some(error.kind())),
        }
        result
    }

    /// Receives one complete message or control event.
    ///
    /// This operation is cancellation-safe: cancelling it before completion
    /// does not discard a message. An automatic Pong or Close reply is flushed
    /// before the corresponding event is returned.
    pub async fn receive(&mut self) -> Result<WebSocketMessage, WebSocketError> {
        let span = debug_span!(
            "websocket.receive",
            message_kind = field::Empty,
            payload_bytes = field::Empty,
            outcome = field::Empty,
            error_kind = field::Empty,
        );
        let outcome = OperationOutcome::new(&span);
        let result: Result<WebSocketMessage, WebSocketError> = async {
            let message = self.next().await.ok_or_else(WebSocketError::closed)??;
            Span::current().record("message_kind", message.trace_kind());
            Span::current().record("payload_bytes", message.payload_len());
            Ok(message)
        }
        .instrument(span.clone())
        .await;
        match &result {
            Ok(_) => outcome.finish("ok", None),
            Err(error) => outcome.finish("error", Some(error.kind())),
        }
        result
    }

    /// Sends and flushes one Close frame.
    ///
    /// Continue calling [`WebSocket::receive`] to await the peer's Close reply
    /// when a complete graceful shutdown is required.
    pub async fn close(
        &mut self,
        frame: Option<WebSocketCloseFrame>,
    ) -> Result<(), WebSocketError> {
        self.send(WebSocketMessage::Close(frame)).await
    }
}

impl Stream for WebSocket {
    type Item = Result<WebSocketMessage, WebSocketError>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.pending_incoming.is_some() {
            return poll_pending_incoming(this, context);
        }

        let Some(socket) = this.socket.as_mut() else {
            return Poll::Ready(None);
        };
        match Pin::new(socket).poll_next(context) {
            Poll::Ready(Some(Ok(message))) => {
                let message = match WebSocketMessage::from_engine(message) {
                    Ok(message) => message,
                    Err(error) => return Poll::Ready(Some(Err(error))),
                };
                if matches!(
                    message,
                    WebSocketMessage::Ping(_) | WebSocketMessage::Close(_)
                ) {
                    this.pending_incoming = Some(message);
                    poll_pending_incoming(this, context)
                } else {
                    Poll::Ready(Some(Ok(message)))
                }
            }
            Poll::Ready(Some(Err(error))) => {
                this.socket = None;
                Poll::Ready(Some(Err(WebSocketError::engine(error))))
            }
            Poll::Ready(None) => {
                this.socket = None;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

fn poll_pending_incoming(
    socket: &mut WebSocket,
    context: &mut Context<'_>,
) -> Poll<Option<Result<WebSocketMessage, WebSocketError>>> {
    let Some(engine) = socket.socket.as_mut() else {
        socket.pending_incoming = None;
        return Poll::Ready(Some(Err(WebSocketError::closed())));
    };
    match Pin::new(engine).poll_flush(context) {
        Poll::Ready(Ok(())) => Poll::Ready(Some(socket.pending_incoming.take().ok_or_else(|| {
            WebSocketError::protocol("WebSocket control-reply state lost its pending message")
        }))),
        Poll::Ready(Err(error)) => {
            socket.socket = None;
            socket.pending_incoming = None;
            Poll::Ready(Some(Err(WebSocketError::engine(error))))
        }
        Poll::Pending => Poll::Pending,
    }
}

impl Sink<WebSocketMessage> for WebSocket {
    type Error = WebSocketError;

    fn poll_ready(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let Some(socket) = self.get_mut().socket.as_mut() else {
            return Poll::Ready(Err(WebSocketError::closed()));
        };
        Pin::new(socket)
            .poll_ready(context)
            .map_err(WebSocketError::engine)
    }

    fn start_send(self: Pin<&mut Self>, message: WebSocketMessage) -> Result<(), Self::Error> {
        let this = self.get_mut();
        let message = message.into_engine(this.limits)?;
        let socket = this.socket.as_mut().ok_or_else(WebSocketError::closed)?;
        Pin::new(socket)
            .start_send(message)
            .map_err(WebSocketError::engine)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let Some(socket) = self.get_mut().socket.as_mut() else {
            return Poll::Ready(Err(WebSocketError::closed()));
        };
        Pin::new(socket)
            .poll_flush(context)
            .map_err(WebSocketError::engine)
    }

    fn poll_close(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), Self::Error>> {
        let Some(socket) = self.get_mut().socket.as_mut() else {
            return Poll::Ready(Err(WebSocketError::closed()));
        };
        Pin::new(socket)
            .poll_close(context)
            .map_err(WebSocketError::engine)
    }
}
