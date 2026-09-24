use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::{Sink, SinkExt, Stream, StreamExt};
use http::Response;
use phantom_net::{http1::Http1Upgrade, http2::Http2ExtendedConnectStream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::{
        Message as EngineMessage,
        protocol::{Role, WebSocketConfig},
    },
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
///
/// Phantom never reconnects a WebSocket or sends heartbeats. Once
/// [`WebSocket::receive`] reports the end of the connection or a transport or
/// framing error, every later operation fails with
/// [`WebSocketErrorKind::Closed`](crate::WebSocketErrorKind::Closed).
/// `WebSocket` also implements `Stream` and `Sink`.
///
/// # Examples
///
/// ```no_run
/// use phantom::{Client, WebSocketMessage};
///
/// async fn echo(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
///     let mut socket = client.websocket("wss://example.com/events")?.connect().await?;
///
///     socket.send(WebSocketMessage::Text("hello".into())).await?;
///     println!("{:?}", socket.receive().await?);
///     socket.close(None).await?;
///     Ok(())
/// }
/// ```
pub struct WebSocket {
    socket: Option<WebSocketStream<WebSocketIo>>,
    handshake: Response<()>,
    selected_protocol: Option<Box<str>>,
    limits: WebSocketLimits,
    #[cfg(feature = "websocket-deflate")]
    deflate: DeflateState,
    pending_incoming: Option<WebSocketMessage>,
}

/// What one established connection compresses, and how.
///
/// `negotiated` is `None` until the server accepts the offer, which is also
/// what makes the empty-message rule take effect.
#[cfg(feature = "websocket-deflate")]
#[derive(Clone, Copy, Debug)]
pub(super) struct DeflateState {
    pub(super) negotiated: Option<NegotiatedPerMessageDeflate>,
    /// The profile's rule for an empty text or binary message.
    pub(super) compress_empty_messages: bool,
}

impl fmt::Debug for WebSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("WebSocket");
        debug
            .field("status", &self.handshake.status())
            .field("has_selected_protocol", &self.selected_protocol.is_some())
            .field("limits", &self.limits);
        #[cfg(feature = "websocket-deflate")]
        debug.field("permessage_deflate", &self.deflate.negotiated);
        debug.finish_non_exhaustive()
    }
}

impl WebSocket {
    pub(super) async fn new_http1(
        stream: Http1Upgrade,
        handshake: Response<()>,
        selected_protocol: Option<Box<str>>,
        limits: WebSocketLimits,
        config: WebSocketConfig,
        #[cfg(feature = "websocket-deflate")] deflate: DeflateState,
    ) -> Self {
        Self::new(
            WebSocketIo::Http1(stream),
            handshake,
            selected_protocol,
            limits,
            config,
            #[cfg(feature = "websocket-deflate")]
            deflate,
        )
        .await
    }

    pub(super) async fn new_http2(
        stream: Http2ExtendedConnectStream,
        admission: Option<Box<dyn Send + Sync>>,
        handshake: Response<()>,
        selected_protocol: Option<Box<str>>,
        limits: WebSocketLimits,
        config: WebSocketConfig,
        #[cfg(feature = "websocket-deflate")] deflate: DeflateState,
    ) -> Self {
        Self::new(
            WebSocketIo::Http2 {
                stream,
                _admission: admission,
            },
            handshake,
            selected_protocol,
            limits,
            config,
            #[cfg(feature = "websocket-deflate")]
            deflate,
        )
        .await
    }

    async fn new(
        stream: WebSocketIo,
        handshake: Response<()>,
        selected_protocol: Option<Box<str>>,
        limits: WebSocketLimits,
        config: WebSocketConfig,
        #[cfg(feature = "websocket-deflate")] deflate: DeflateState,
    ) -> Self {
        let socket = WebSocketStream::from_raw_socket(stream, Role::Client, Some(config)).await;
        Self {
            socket: Some(socket),
            handshake,
            selected_protocol,
            limits,
            #[cfg(feature = "websocket-deflate")]
            deflate,
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

    /// Returns the validated H1 `101` or H2 2xx opening response.
    ///
    /// Its extensions retain the exact ordered response fields.
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
        self.deflate.negotiated
    }

    /// Returns the active frame and message bounds.
    #[must_use]
    pub fn limits(&self) -> WebSocketLimits {
        self.limits
    }

    /// Applies the profile's empty-message rule to one outgoing message.
    fn for_wire(&self, message: EngineMessage) -> EngineMessage {
        #[cfg(feature = "websocket-deflate")]
        if self.deflate.negotiated.is_some() && !self.deflate.compress_empty_messages {
            return super::message::send_empty_message_uncompressed(message);
        }
        message
    }

    /// Sends and flushes one complete message.
    ///
    /// A cancelled send has the usual asynchronous write ambiguity; callers
    /// must not retry it blindly. Payloads are never included in tracing.
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketError`] with kind:
    ///
    /// - [`WebSocketErrorKind::Capacity`](crate::WebSocketErrorKind::Capacity)
    ///   when a text or binary message exceeds
    ///   [`WebSocketLimits::max_message_size`], a Ping or Pong payload exceeds
    ///   125 bytes, or the write buffer is full; an oversized message is
    ///   rejected before any byte is written;
    /// - [`WebSocketErrorKind::Closed`](crate::WebSocketErrorKind::Closed)
    ///   after the connection has closed or failed;
    /// - [`WebSocketErrorKind::Io`](crate::WebSocketErrorKind::Io) when
    ///   writing to the transport fails;
    /// - [`WebSocketErrorKind::Protocol`](crate::WebSocketErrorKind::Protocol)
    ///   for a send the framing rules forbid, such as data after a Close
    ///   frame.
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
            Ok(message) => self.for_wire(message),
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
    ///
    /// # Errors
    ///
    /// Returns [`WebSocketError`] with kind:
    ///
    /// - [`WebSocketErrorKind::Capacity`](crate::WebSocketErrorKind::Capacity)
    ///   when an incoming frame, message, or fragment count exceeds
    ///   [`WebSocketLimits`];
    /// - [`WebSocketErrorKind::Protocol`](crate::WebSocketErrorKind::Protocol)
    ///   or [`WebSocketErrorKind::InvalidUtf8`](crate::WebSocketErrorKind::InvalidUtf8)
    ///   when the peer breaks a framing rule or sends invalid UTF-8 text;
    /// - [`WebSocketErrorKind::AbnormalClosure`](crate::WebSocketErrorKind::AbnormalClosure)
    ///   when the peer ends the transport without a Close handshake;
    /// - [`WebSocketErrorKind::Io`](crate::WebSocketErrorKind::Io) when
    ///   reading from or writing a reply to the transport fails;
    /// - [`WebSocketErrorKind::Closed`](crate::WebSocketErrorKind::Closed)
    ///   when the connection has already ended.
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
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`WebSocket::send`].
    pub async fn close(
        &mut self,
        frame: Option<WebSocketCloseFrame>,
    ) -> Result<(), WebSocketError> {
        self.send(WebSocketMessage::Close(frame)).await
    }
}

enum WebSocketIo {
    Http1(Http1Upgrade),
    Http2 {
        stream: Http2ExtendedConnectStream,
        /// Per-origin pool admission for a stream on a pooled session.
        ///
        /// It lives exactly as long as the stream, like an ordinary response
        /// body's permit, so dropping the WebSocket or reaching a terminal
        /// state (which drops the transport) releases it.
        _admission: Option<Box<dyn Send + Sync>>,
    },
}

impl AsyncRead for WebSocketIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Http1(stream) => Pin::new(stream).poll_read(context, output),
            Self::Http2 { stream, .. } => Pin::new(stream).poll_read(context, output),
        }
    }
}

impl AsyncWrite for WebSocketIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match &mut *self {
            Self::Http1(stream) => Pin::new(stream).poll_write(context, input),
            Self::Http2 { stream, .. } => Pin::new(stream).poll_write(context, input),
        }
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Http1(stream) => Pin::new(stream).poll_flush(context),
            Self::Http2 { stream, .. } => Pin::new(stream).poll_flush(context),
        }
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        match &mut *self {
            Self::Http1(stream) => Pin::new(stream).poll_shutdown(context),
            Self::Http2 { stream, .. } => Pin::new(stream).poll_shutdown(context),
        }
    }
}

impl WebSocketIo {
    fn poll_shutdown_http2(&mut self, context: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        match self {
            Self::Http1(_) => Poll::Ready(Ok(())),
            Self::Http2 { stream, .. } => Pin::new(stream).poll_shutdown(context),
        }
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
    match Pin::new(&mut *engine).poll_flush(context) {
        Poll::Ready(Ok(())) => {
            let is_close = matches!(socket.pending_incoming, Some(WebSocketMessage::Close(_)));
            if is_close {
                match Pin::new(engine.get_mut())
                    .poll_shutdown_http2(context)
                    .map_err(WebSocketError::engine_io)
                {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(error)) => return Poll::Ready(Some(Err(error))),
                    Poll::Pending => return Poll::Pending,
                }
            }
            Poll::Ready(Some(socket.pending_incoming.take().ok_or_else(|| {
                WebSocketError::protocol("WebSocket control-reply state lost its pending message")
            })))
        }
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
        let message = this.for_wire(message.into_engine(this.limits)?);
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
        match Pin::new(&mut *socket).poll_close(context) {
            Poll::Ready(Ok(())) => Pin::new(socket.get_mut())
                .poll_shutdown_http2(context)
                .map_err(WebSocketError::engine_io),
            Poll::Ready(Err(error)) => Poll::Ready(Err(WebSocketError::engine(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}
