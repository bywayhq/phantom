//! Generic WebSocket message stream.

pub mod frame;

#[cfg(feature = "deflate")]
pub(crate) mod deflate;

mod message;

pub use self::{frame::CloseFrame, message::Message};

use self::{
    frame::{
        coding::{Control as OpCtl, Data as OpData, OpCode},
        Frame, FrameCodec,
    },
    message::{IncompleteMessage, MessageType},
};
use crate::error::{CapacityError, Error, ProtocolError, Result};
use log::*;
use std::{
    io::{self, Read, Write},
    mem::replace,
};

/// Indicates a Client or Server role of the websocket
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// This socket is a server
    Server,
    /// This socket is a client
    Client,
}

/// One ordered parameter in a client `permessage-deflate` offer.
#[cfg(feature = "deflate")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PerMessageDeflateOfferParameter {
    /// `server_no_context_takeover`.
    ServerNoContextTakeover,
    /// `client_no_context_takeover`.
    ClientNoContextTakeover,
    /// `server_max_window_bits=<value>`.
    ServerMaxWindowBits(u8),
    /// `client_max_window_bits`, optionally with a value.
    ClientMaxWindowBits(Option<u8>),
}

/// The configuration for WebSocket connection.
///
/// # Example
/// ```
/// # use tungstenite::protocol::WebSocketConfig;;
/// let conf = WebSocketConfig::default()
///     .read_buffer_size(256 * 1024)
///     .write_buffer_size(256 * 1024);
/// ```
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct WebSocketConfig {
    /// Read buffer capacity. This buffer is eagerly allocated and used for receiving
    /// messages.
    ///
    /// For high read load scenarios a larger buffer, e.g. 128 KiB, improves performance.
    ///
    /// For scenarios where you expect a lot of connections and don't need high read load
    /// performance a smaller buffer, e.g. 4 KiB, would be appropriate to lower total
    /// memory usage.
    ///
    /// The default value is 128 KiB.
    pub read_buffer_size: usize,
    /// The target minimum size of the write buffer to reach before writing the data
    /// to the underlying stream.
    /// The default value is 128 KiB.
    ///
    /// If set to `0` each message will be eagerly written to the underlying stream.
    /// It is often more optimal to allow them to buffer a little, hence the default value.
    ///
    /// Note: [`flush`](WebSocket::flush) will always fully write the buffer regardless.
    pub write_buffer_size: usize,
    /// The max size of the write buffer in bytes. Setting this can provide backpressure
    /// in the case the write buffer is filling up due to write errors.
    /// The default value is unlimited.
    ///
    /// Note: The write buffer only builds up past [`write_buffer_size`](Self::write_buffer_size)
    /// when writes to the underlying stream are failing. So the **write buffer can not
    /// fill up if you are not observing write errors even if not flushing**.
    ///
    /// Note: Should always be at least [`write_buffer_size + 1 message`](Self::write_buffer_size)
    /// and probably a little more depending on error handling strategy.
    /// With deflate enabled, “1 message” means its uncompressed full wire size;
    /// a larger message is unsendable regardless of how much the buffer drains.
    /// A message that compresses larger than its plain form is still sent compressed while
    /// it fits; only when the compressed wire form no longer fits is it sent uncompressed
    /// instead, with outgoing takeover history reset before later compressed output.
    pub max_write_buffer_size: usize,
    /// The maximum size of an incoming message. `None` means no size limit. The default value is 64 MiB
    /// which should be reasonably big for all normal use-cases but small enough to prevent
    /// memory eating by a malicious user.
    pub max_message_size: Option<usize>,
    /// The maximum size of a single incoming message frame. `None` means no size limit. The limit is for
    /// frame payload NOT including the frame header. The default value is 16 MiB which should
    /// be reasonably big for all normal use-cases but small enough to prevent memory eating
    /// by a malicious user.
    pub max_frame_size: Option<usize>,
    /// The maximum number of data frames in one incoming message, including the initial
    /// text or binary frame. Interleaved control frames are not counted. `None` means no
    /// fragment-count limit, which is the default.
    pub max_message_fragments: Option<usize>,
    /// When set to `true`, the server will accept and handle unmasked frames
    /// from the client. According to the RFC 6455, the server must close the
    /// connection to the client in such cases, however it seems like there are
    /// some popular libraries that are sending unmasked frames, ignoring the RFC.
    /// By default this option is set to `false`, i.e. according to RFC 6455.
    pub accept_unmasked_frames: bool,
    #[cfg(feature = "deflate")]
    pub(crate) deflate: Option<deflate::Settings>,
}

/// The effective `permessage-deflate` settings agreed by the handshake.
#[cfg(feature = "deflate")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PerMessageDeflateConfig {
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: u8,
    client_max_window_bits: u8,
}

#[cfg(feature = "deflate")]
impl PerMessageDeflateConfig {
    /// Whether the server resets its compression context after each message.
    pub fn server_no_context_takeover(self) -> bool {
        self.server_no_context_takeover
    }

    /// Whether the client resets its compression context after each message.
    pub fn client_no_context_takeover(self) -> bool {
        self.client_no_context_takeover
    }

    /// The server encoder's negotiated window width.
    pub fn server_max_window_bits(self) -> u8 {
        self.server_max_window_bits
    }

    /// The client encoder's negotiated window width.
    pub fn client_max_window_bits(self) -> u8 {
        self.client_max_window_bits
    }
}

impl Default for WebSocketConfig {
    fn default() -> Self {
        Self {
            read_buffer_size: 128 * 1024,
            write_buffer_size: 128 * 1024,
            max_write_buffer_size: usize::MAX,
            max_message_size: Some(64 << 20),
            max_frame_size: Some(16 << 20),
            max_message_fragments: None,
            accept_unmasked_frames: false,
            #[cfg(feature = "deflate")]
            deflate: None,
        }
    }
}

impl WebSocketConfig {
    /// Offers `permessage-deflate` on this connection, with RFC 7692 defaults.
    ///
    /// A client offers the extension in its handshake; a server accepts an
    /// offer only through [`accept_deflate_offers`]. Enabling it here is not a
    /// promise that the peer agrees — the negotiated outcome is whatever the
    /// handshake settles on, and a peer that declines leaves the connection
    /// uncompressed.
    ///
    /// The client offer carries `client_max_window_bits` with no value, so a server may
    /// select the window this endpoint compresses with; see [`deflate_max_window_bits`].
    ///
    /// [`deflate_max_window_bits`]: WebSocketConfig::deflate_max_window_bits
    ///
    /// [`accept_deflate_offers`]: WebSocketConfig::accept_deflate_offers
    #[cfg(feature = "deflate")]
    pub fn enable_deflate(mut self) -> Self {
        self.deflate.get_or_insert_default();
        self
    }

    /// Caps the LZ77 sliding window for one direction, in bits.
    ///
    /// `role` names the direction, not this endpoint: [`Role::Server`] sets
    /// `server_max_window_bits`, [`Role::Client`] sets `client_max_window_bits`.
    /// Valid values are 8 to 15; a smaller window trades compression ratio for memory.
    ///
    /// Which encoder a setting names decides what it does:
    ///
    /// - **Your own** — [`Role::Client`] on a client, [`Role::Server`] on a server. Always
    ///   applied when permessage-deflate is negotiated, and always saves memory locally.
    /// - **The peer's, on a client** — [`Role::Server`]. A reduced cap is a handshake
    ///   requirement: a response that does not select that cap or less fails the handshake.
    /// - **The peer's, on a server** — [`Role::Client`]. A reduced cap is a preference, not
    ///   a ceiling. An offer carrying `client_max_window_bits` is bound to the cap, or to
    ///   the offer's own lower value. An offer that omits the parameter is still accepted,
    ///   with a bare response and a 15-bit decoder: RFC 7692 §7.1.2.2 forbids naming the
    ///   parameter in a response the offer did not invite, and §7.2.2 then requires a
    ///   32,768-byte decoder window. Such a client bypasses the cap — the decoder window is
    ///   the full 32 KiB rather than the `2^bits` bytes asked for.
    ///   [`accept_deflate_offers`] prefers an offer the cap can bind when a client sends
    ///   more than one.
    ///
    /// A client's own cap is a ceiling rather than a request: the offer names
    /// `client_max_window_bits` without a value, so a server may select this endpoint's
    /// window, and a selection narrows the cap instead of raising it. A selected 8 uses the
    /// interoperable 9-bit zlib construction while retaining the negotiated 8-bit bound.
    /// RFC 7692 §7.1.2.2 reads a response that omits the
    /// parameter as a 32,768-byte peer decoder, so the cap then stands as configured and the
    /// peer must decode whatever we encode with.
    ///
    /// [`accept_deflate_offers`]: WebSocketConfig::accept_deflate_offers
    ///
    /// # Panics
    /// Panics if `bits` is outside 8..=15.
    #[cfg(feature = "deflate")]
    pub fn deflate_max_window_bits(mut self, role: Role, bits: u8) -> Self {
        self.deflate = Some(self.deflate.unwrap_or_default().max_window_bits(role, bits));
        self
    }

    /// Requests that one direction reset its sliding window between messages.
    ///
    /// `role` selects the direction. Disabling context takeover costs most of
    /// the compression ratio — it is the difference between compressing against
    /// the whole conversation and compressing each message alone — and it does
    /// not reduce steady-state memory, because resetting a stream reuses its
    /// arena rather than freeing it. It is a ratio and CPU knob, not a memory
    /// one; for memory use [`deflate_max_window_bits`].
    ///
    /// For a client, setting [`Role::Server`] to `true` is a hard requirement:
    /// a response omitting `server_no_context_takeover` fails the handshake;
    /// preference-plus-fallback is not supported. Per RFC 7692 §7.1.1.2, a
    /// server may ignore this on the client's behalf.
    ///
    /// [`deflate_max_window_bits`]: WebSocketConfig::deflate_max_window_bits
    #[cfg(feature = "deflate")]
    pub fn deflate_no_context_takeover(mut self, role: Role, on: bool) -> Self {
        self.deflate = Some(self.deflate.unwrap_or_default().no_context_takeover(role, on));
        self
    }

    /// Sets the DEFLATE compression level, 0 (store) to 9 (maximum).
    ///
    /// Defaults to the backend's default. Levels above the default cost CPU for
    /// a ratio gain that is small on short messages.
    ///
    /// # Panics
    /// Panics if `level` is above 9.
    #[cfg(feature = "deflate")]
    pub fn deflate_compression_level(mut self, level: u32) -> Self {
        self.deflate = Some(self.deflate.unwrap_or_default().compression_level(level));
        self
    }

    /// Replaces the ordered parameters in the generated client offer.
    ///
    /// An empty slice emits only `permessage-deflate`. Parameter order is
    /// preserved. Duplicate parameters and window widths outside 8..=15 are
    /// rejected.
    #[cfg(feature = "deflate")]
    pub fn deflate_offer_parameters(
        mut self,
        parameters: &[PerMessageDeflateOfferParameter],
    ) -> Result<Self> {
        let settings = self.deflate.unwrap_or_default();
        self.deflate = Some(settings.offer_parameters(parameters)?);
        Ok(self)
    }

    /// Returns the exact client offer generated for the current deflate policy.
    #[cfg(feature = "deflate")]
    pub fn deflate_offer(&self) -> Option<http::HeaderValue> {
        self.deflate.map(deflate::Settings::offer)
    }

    /// Applies a server response to a client-owned custom handshake.
    ///
    /// The returned configuration is socket-ready. A declined offer disables
    /// compression; an unsolicited or malformed selection is an error.
    #[cfg(feature = "deflate")]
    pub fn accept_deflate_response(mut self, headers: &http::HeaderMap) -> Result<Self> {
        self.deflate = match self.deflate {
            Some(offered) => offered.accept_response(headers)?,
            None => {
                if deflate::headers_select_deflate(headers)? {
                    return Err(Error::Protocol(ProtocolError::InvalidHeader(
                        http::header::SEC_WEBSOCKET_EXTENSIONS.clone().into(),
                    )));
                }
                None
            }
        };
        Ok(self)
    }

    /// Returns the effective negotiated deflate settings, when enabled.
    #[cfg(feature = "deflate")]
    pub fn permessage_deflate(&self) -> Option<PerMessageDeflateConfig> {
        self.deflate.map(|settings| PerMessageDeflateConfig {
            server_no_context_takeover: settings.server_no_context_takeover,
            client_no_context_takeover: settings.client_no_context_takeover,
            server_max_window_bits: settings.server_max_window_bits,
            client_max_window_bits: settings.client_max_window_bits,
        })
    }

    /// Answers a client's extension offers for a server-owned handshake.
    ///
    /// Takes every raw `Sec-WebSocket-Extensions` value from the request and
    /// returns a socket-ready config plus the exact response header, if one was
    /// agreed. On decline, the config has compression disabled and the header
    /// is `None`.
    ///
    /// Which offer wins depends on the [`Role::Client`] window preference from
    /// [`deflate_max_window_bits`]. At its default of 15, the first acceptable offer wins.
    /// Under a reduced preference, an offer carrying `client_max_window_bits` outranks an
    /// earlier one that omits it: only the former lets the response hold the client to the
    /// preference, which is what RFC 7692 §7.1.2.2 gives the parameter for — a response
    /// naming it reduces the memory the server reserves for the connection's decompression
    /// context. Wire order decides within each group, and §7.1.3 lets a server pick any
    /// supported offer. This changes which response header you send, never whether an offer
    /// is acceptable.
    ///
    /// If a header is returned, send it and use the config returned with it;
    /// applying only one would put the wire and codec into different states.
    /// Pass that config to [`WebSocket::from_raw_socket`].
    ///
    /// A framework using tungstenite's own handshake needs only
    /// [`enable_deflate`].
    ///
    /// [`enable_deflate`]: WebSocketConfig::enable_deflate
    /// [`deflate_max_window_bits`]: WebSocketConfig::deflate_max_window_bits
    #[cfg(feature = "deflate")]
    pub fn accept_deflate_offers(
        mut self,
        offers: &[http::HeaderValue],
    ) -> (Self, Option<http::HeaderValue>) {
        let accepted = self.deflate.and_then(|settings| settings.accept_offers(offers));
        let response = accepted.map(|(settings, response)| {
            self.deflate = Some(settings);
            response
        });
        if response.is_none() {
            self.deflate = None;
        }
        (self, response)
    }

    /// Set [`Self::read_buffer_size`].
    pub fn read_buffer_size(mut self, read_buffer_size: usize) -> Self {
        self.read_buffer_size = read_buffer_size;
        self
    }

    /// Set [`Self::write_buffer_size`].
    pub fn write_buffer_size(mut self, write_buffer_size: usize) -> Self {
        self.write_buffer_size = write_buffer_size;
        self
    }

    /// Set [`Self::max_write_buffer_size`].
    pub fn max_write_buffer_size(mut self, max_write_buffer_size: usize) -> Self {
        self.max_write_buffer_size = max_write_buffer_size;
        self
    }

    /// Set [`Self::max_message_size`].
    pub fn max_message_size(mut self, max_message_size: Option<usize>) -> Self {
        self.max_message_size = max_message_size;
        self
    }

    /// Set [`Self::max_frame_size`].
    pub fn max_frame_size(mut self, max_frame_size: Option<usize>) -> Self {
        self.max_frame_size = max_frame_size;
        self
    }

    /// Set [`Self::max_message_fragments`].
    pub fn max_message_fragments(mut self, max_message_fragments: Option<usize>) -> Self {
        self.max_message_fragments = max_message_fragments;
        self
    }

    /// Set [`Self::accept_unmasked_frames`].
    pub fn accept_unmasked_frames(mut self, accept_unmasked_frames: bool) -> Self {
        self.accept_unmasked_frames = accept_unmasked_frames;
        self
    }

    /// Panic if values are invalid.
    pub(crate) fn assert_valid(&self) {
        assert!(
            self.max_write_buffer_size > self.write_buffer_size,
            "WebSocketConfig::max_write_buffer_size must be greater than write_buffer_size, \
            see WebSocketConfig docs`"
        );
    }
}

/// WebSocket input-output stream.
///
/// This is THE structure you want to create to be able to speak the WebSocket protocol.
/// It may be created by calling `connect`, `accept` or `client` functions.
///
/// Use [`WebSocket::read`], [`WebSocket::send`] to received and send messages.
#[derive(Debug)]
pub struct WebSocket<Stream> {
    /// The underlying socket.
    socket: Stream,
    /// The context for managing a WebSocket.
    context: WebSocketContext,
}

impl<Stream> WebSocket<Stream> {
    /// Convert a raw socket into a WebSocket without performing a handshake.
    ///
    /// Call this function if you're using Tungstenite as a part of a web framework
    /// or together with an existing one. If you need an initial handshake, use
    /// `connect()` or `accept()` functions of the crate to construct a websocket.
    ///
    /// # Panics
    /// Panics if config is invalid e.g. `max_write_buffer_size <= write_buffer_size`.
    pub fn from_raw_socket(stream: Stream, role: Role, config: Option<WebSocketConfig>) -> Self {
        WebSocket { socket: stream, context: WebSocketContext::new(role, config) }
    }

    /// Convert a raw socket into a WebSocket without performing a handshake.
    ///
    /// Call this function if you're using Tungstenite as a part of a web framework
    /// or together with an existing one. If you need an initial handshake, use
    /// `connect()` or `accept()` functions of the crate to construct a websocket.
    ///
    /// # Panics
    /// Panics if config is invalid e.g. `max_write_buffer_size <= write_buffer_size`.
    pub fn from_partially_read(
        stream: Stream,
        part: Vec<u8>,
        role: Role,
        config: Option<WebSocketConfig>,
    ) -> Self {
        WebSocket {
            socket: stream,
            context: WebSocketContext::from_partially_read(part, role, config),
        }
    }

    /// Consumes the `WebSocket` and returns the underlying stream.
    pub fn into_inner(self) -> Stream {
        self.socket
    }

    /// Returns a shared reference to the inner stream.
    pub fn get_ref(&self) -> &Stream {
        &self.socket
    }
    /// Returns a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut Stream {
        &mut self.socket
    }

    /// Change the configuration.
    ///
    /// # Panics
    /// Panics if config is invalid e.g. `max_write_buffer_size <= write_buffer_size`.
    ///
    /// With the `deflate` feature, also panics if the callback changes deflate settings
    /// the handshake has already agreed. Compression is negotiated once, and a connection
    /// cannot move to different settings mid-stream.
    ///
    /// What survives a panic differs between the two builds, in one direction only. An
    /// invalid configuration is committed before it is rejected, in both. With `deflate`
    /// on the callback runs against a copy, so a panic raised *inside* the callback, or a
    /// rejected deflate change, leaves the live configuration untouched.
    pub fn set_config(&mut self, set_func: impl FnOnce(&mut WebSocketConfig)) {
        self.context.set_config(set_func);
    }

    /// Read the configuration.
    pub fn get_config(&self) -> &WebSocketConfig {
        self.context.get_config()
    }

    /// Check if it is possible to read messages.
    ///
    /// Reading is impossible after receiving `Message::Close`. It is still possible after
    /// sending close frame since the peer still may send some data before confirming close.
    pub fn can_read(&self) -> bool {
        self.context.can_read()
    }

    /// Check if it is possible to write messages.
    ///
    /// Writing gets impossible immediately after sending or receiving `Message::Close`.
    pub fn can_write(&self) -> bool {
        self.context.can_write()
    }
}

impl<Stream: Read + Write> WebSocket<Stream> {
    /// Read a message from stream, if possible.
    ///
    /// This will also queue responses to ping and close messages. These responses
    /// will be written and flushed on the next call to [`read`](Self::read),
    /// [`write`](Self::write) or [`flush`](Self::flush).
    ///
    /// # Closing the connection
    /// When the remote endpoint decides to close the connection this will return
    /// the close message with an optional close frame.
    ///
    /// You should continue calling [`read`](Self::read), [`write`](Self::write) or
    /// [`flush`](Self::flush) to drive the reply to the close frame until [`Error::ConnectionClosed`]
    /// is returned. Once that happens it is safe to drop the underlying connection.
    pub fn read(&mut self) -> Result<Message> {
        self.context.read(&mut self.socket)
    }

    /// Writes and immediately flushes a message.
    /// Equivalent to calling [`write`](Self::write) then [`flush`](Self::flush).
    pub fn send(&mut self, message: Message) -> Result<()> {
        self.write(message)?;
        self.flush()
    }

    /// Write a message to the provided stream, if possible.
    ///
    /// A subsequent call should be made to [`flush`](Self::flush) to flush writes.
    ///
    /// In the event of stream write failure the message frame will be stored
    /// in the write buffer and will try again on the next call to [`write`](Self::write)
    /// or [`flush`](Self::flush).
    ///
    /// If the write buffer would exceed the configured [`WebSocketConfig::max_write_buffer_size`]
    /// [`Err(WriteBufferFull(msg_frame))`](Error::WriteBufferFull) is returned.
    ///
    /// This call will generally not flush. However, if there are queued automatic messages
    /// they will be written and eagerly flushed.
    ///
    /// For example, upon receiving ping messages tungstenite queues pong replies automatically.
    /// The next call to [`read`](Self::read), [`write`](Self::write) or [`flush`](Self::flush)
    /// will write & flush the pong reply. This means you should not respond to ping frames manually.
    ///
    /// You can however send pong frames manually in order to indicate a unidirectional heartbeat
    /// as described in [RFC 6455](https://tools.ietf.org/html/rfc6455#section-5.5.3). Note that
    /// if [`read`](Self::read) returns a ping, you should [`flush`](Self::flush) before passing
    /// a custom pong to [`write`](Self::write), otherwise the automatic queued response to the
    /// ping will not be sent as it will be replaced by your custom pong message.
    ///
    /// # Errors
    /// - If the WebSocket's write buffer is full, [`Error::WriteBufferFull`] will be returned
    ///   along with the equivalent passed message frame.
    /// - If the connection is closed and should be dropped, this will return [`Error::ConnectionClosed`].
    /// - If you try again after [`Error::ConnectionClosed`] was returned either from here or from
    ///   [`read`](Self::read), [`Error::AlreadyClosed`] will be returned. This indicates a program
    ///   error on your part.
    /// - [`Error::Io`] is returned if the underlying connection returns an error
    ///   (consider these fatal except for WouldBlock).
    /// - [`Error::Capacity`] if your message size is bigger than the configured max message size.
    pub fn write(&mut self, message: Message) -> Result<()> {
        self.context.write(&mut self.socket, message)
    }

    /// Flush writes.
    ///
    /// Ensures all messages previously passed to [`write`](Self::write) and automatic
    /// queued pong responses are written & flushed into the underlying stream.
    pub fn flush(&mut self) -> Result<()> {
        self.context.flush(&mut self.socket)
    }

    /// Close the connection.
    ///
    /// This function guarantees that the close frame will be queued.
    /// There is no need to call it again. Calling this function is
    /// the same as calling `write(Message::Close(..))`.
    ///
    /// After queuing the close frame you should continue calling [`read`](Self::read) or
    /// [`flush`](Self::flush) to drive the close handshake to completion.
    ///
    /// The websocket RFC defines that the underlying connection should be closed
    /// by the server. Tungstenite takes care of this asymmetry for you.
    ///
    /// When the close handshake is finished (we have both sent and received
    /// a close message), [`read`](Self::read) or [`flush`](Self::flush) will return
    /// [Error::ConnectionClosed] if this endpoint is the server.
    ///
    /// If this endpoint is a client, [Error::ConnectionClosed] will only be
    /// returned after the server has closed the underlying connection.
    ///
    /// It is thus safe to drop the underlying connection as soon as [Error::ConnectionClosed]
    /// is returned from [`read`](Self::read) or [`flush`](Self::flush).
    pub fn close(&mut self, code: Option<CloseFrame>) -> Result<()> {
        self.context.close(&mut self.socket, code)
    }

    /// Old name for [`read`](Self::read).
    #[deprecated(note = "Use `read`")]
    pub fn read_message(&mut self) -> Result<Message> {
        self.read()
    }

    /// Old name for [`send`](Self::send).
    #[deprecated(note = "Use `send`")]
    pub fn write_message(&mut self, message: Message) -> Result<()> {
        self.send(message)
    }

    /// Old name for [`flush`](Self::flush).
    #[deprecated(note = "Use `flush`")]
    pub fn write_pending(&mut self) -> Result<()> {
        self.flush()
    }
}

/// A context for managing WebSocket stream.
#[derive(Debug)]
pub struct WebSocketContext {
    /// Server or client?
    role: Role,
    /// encoder/decoder of frame.
    frame: FrameCodec,
    /// The state of processing, either "active" or "closing".
    state: WebSocketState,
    /// Receive: an incomplete message being processed.
    incomplete: Option<IncompleteMessage>,
    /// Number of data frames accepted for the incomplete message.
    incomplete_fragment_count: usize,
    /// Send in addition to regular messages E.g. "pong" or "close".
    additional_send: Option<Frame>,
    /// True indicates there is an additional message (like a pong)
    /// that failed to flush previously and we should try again.
    unflushed_additional: bool,
    /// The configuration for the websocket session.
    config: WebSocketConfig,
    #[cfg(feature = "deflate")]
    deflate: Option<deflate::Context>,
    #[cfg(feature = "deflate")]
    compressed_incomplete: bool,
    /// Compression state is no longer usable, by any of the routes that reach it: a failed
    /// inflate, a decompressed-size limit, a frame carrying compressed payload that was
    /// rejected and discarded, or a frame discarded before anything could ask. The last
    /// one is not known to have desynchronised us -- it is no longer provably in step,
    /// which is the same thing for a decoder. Separate from `WebSocketState`
    /// because the states the base terminates with still permit a final flush; this one
    /// must not.
    #[cfg(feature = "deflate")]
    compression_unusable: bool,
}

impl WebSocketContext {
    /// Create a WebSocket context that manages a post-handshake stream.
    ///
    /// # Panics
    /// Panics if config is invalid e.g. `max_write_buffer_size <= write_buffer_size`.
    pub fn new(role: Role, config: Option<WebSocketConfig>) -> Self {
        let conf = config.unwrap_or_default();
        Self::_new(role, FrameCodec::new(conf.read_buffer_size), conf)
    }

    /// Create a WebSocket context that manages a post-handshake stream.
    ///
    /// # Panics
    /// Panics if config is invalid e.g. `max_write_buffer_size <= write_buffer_size`.
    pub fn from_partially_read(part: Vec<u8>, role: Role, config: Option<WebSocketConfig>) -> Self {
        let conf = config.unwrap_or_default();
        Self::_new(role, FrameCodec::from_partially_read(part, conf.read_buffer_size), conf)
    }

    fn _new(role: Role, mut frame: FrameCodec, config: WebSocketConfig) -> Self {
        config.assert_valid();
        frame.set_max_out_buffer_len(config.max_write_buffer_size);
        frame.set_out_buffer_write_len(config.write_buffer_size);
        #[cfg(feature = "deflate")]
        let deflate = config.deflate.map(|settings| deflate::Context::new(role, settings));
        Self {
            role,
            frame,
            state: WebSocketState::Active,
            incomplete: None,
            incomplete_fragment_count: 0,
            additional_send: None,
            unflushed_additional: false,
            config,
            #[cfg(feature = "deflate")]
            deflate,
            #[cfg(feature = "deflate")]
            compressed_incomplete: false,
            #[cfg(feature = "deflate")]
            compression_unusable: false,
        }
    }

    /// Change the configuration.
    ///
    /// # Panics
    /// Panics if config is invalid e.g. `max_write_buffer_size <= write_buffer_size`.
    #[cfg(not(feature = "deflate"))]
    pub fn set_config(&mut self, set_func: impl FnOnce(&mut WebSocketConfig)) {
        set_func(&mut self.config);
        self.config.assert_valid();
        self.frame.set_max_out_buffer_len(self.config.max_write_buffer_size);
        self.frame.set_out_buffer_write_len(self.config.write_buffer_size);
    }

    /// Change the configuration without changing the negotiated compression state.
    ///
    /// # Panics
    /// Panics if config is invalid or the callback changes agreed deflate settings.
    #[cfg(feature = "deflate")]
    pub fn set_config(&mut self, set_func: impl FnOnce(&mut WebSocketConfig)) {
        let mut candidate = self.config;
        set_func(&mut candidate);
        assert_eq!(candidate.deflate, self.config.deflate, "agreed deflate settings are immutable");
        self.config = candidate;
        self.config.assert_valid();
        self.frame.set_max_out_buffer_len(self.config.max_write_buffer_size);
        self.frame.set_out_buffer_write_len(self.config.write_buffer_size);
    }

    /// Read the configuration.
    pub fn get_config(&self) -> &WebSocketConfig {
        &self.config
    }

    /// Check if it is possible to read messages.
    ///
    /// Reading is impossible after receiving `Message::Close`. It is still possible after
    /// sending close frame since the peer still may send some data before confirming close.
    pub fn can_read(&self) -> bool {
        self.state.can_read()
    }

    /// Check if it is possible to write messages.
    ///
    /// Writing gets impossible immediately after sending or receiving `Message::Close`.
    pub fn can_write(&self) -> bool {
        self.state.is_active()
    }

    /// Read a message from the provided stream, if possible.
    ///
    /// This function sends pong and close responses automatically.
    /// However, it never blocks on write.
    pub fn read<Stream>(&mut self, stream: &mut Stream) -> Result<Message>
    where
        Stream: Read + Write,
    {
        // Do not read from already closed connections.
        self.state.check_not_terminated()?;

        loop {
            if self.additional_send.is_some() || self.unflushed_additional {
                // Since we may get ping or close, we need to reply to the messages even during read.
                match self.flush(stream) {
                    Ok(_) => {}
                    Err(Error::Io(err)) if err.kind() == io::ErrorKind::WouldBlock => {
                        // If blocked continue reading, but try again later
                        self.unflushed_additional = true;
                    }
                    Err(err) => return Err(err),
                }
            } else if self.role == Role::Server && !self.state.can_read() {
                self.state = WebSocketState::Terminated;
                return Err(Error::ConnectionClosed);
            }

            // If we get here, either write blocks or we have nothing to write.
            // Thus if read blocks, just let it return WouldBlock.
            if let Some(message) = self.read_message_frame(stream)? {
                trace!("Received WebSocket message");
                return Ok(message);
            }
        }
    }

    /// Write a message to the provided stream.
    ///
    /// A subsequent call should be made to [`flush`](Self::flush) to flush writes.
    ///
    /// In the event of stream write failure the message frame will be stored
    /// in the write buffer and will try again on the next call to [`write`](Self::write)
    /// or [`flush`](Self::flush).
    ///
    /// If the write buffer would exceed the configured [`WebSocketConfig::max_write_buffer_size`]
    /// [`Err(WriteBufferFull(msg_frame))`](Error::WriteBufferFull) is returned.
    pub fn write<Stream>(&mut self, stream: &mut Stream, message: Message) -> Result<()>
    where
        Stream: Read + Write,
    {
        // When terminated, return AlreadyClosed.
        self.state.check_not_terminated()?;

        // Do not write after sending a close frame.
        if !self.state.is_active() {
            return Err(Error::Protocol(ProtocolError::SendAfterClosing));
        }

        let prepare_data = |this: &mut Self, data, opcode| -> Result<Frame> {
            #[cfg(not(feature = "deflate"))]
            let _ = &this;
            let plain = Frame::message(data, OpCode::Data(opcode), true);
            #[cfg(feature = "deflate")]
            if let Some(deflate) = &mut this.deflate {
                // Keep this role-aware: for clients, `wire_size` counts the mask before
                // `buffer_frame` applies it.
                if !this.frame.can_buffer(wire_size(this.role, &plain)) {
                    return Err(Error::WriteBufferFull(Message::Frame(plain).into()));
                }
                let compressed = match deflate.compress(plain.payload()) {
                    Ok(compressed) => compressed,
                    Err(error) => {
                        deflate.reset_encoder();
                        return Err(error);
                    }
                };
                let mut frame = Frame::message(compressed, OpCode::Data(opcode), true);
                frame.header_mut().rsv1 = true;
                if this.frame.can_buffer(wire_size(this.role, &frame)) {
                    return Ok(frame);
                }
                deflate.reset_encoder();
            }
            Ok(plain)
        };

        let frame = match message {
            Message::Text(data) => prepare_data(self, data.into(), OpData::Text)?,
            Message::Binary(data) => prepare_data(self, data, OpData::Binary)?,
            Message::Ping(data) => Frame::ping(data),
            Message::Pong(data) => {
                self.set_additional(Frame::pong(data));
                // Note: user pongs can be user flushed so no need to flush here
                return self._write(stream, None).map(|_| ());
            }
            Message::Close(code) => return self.close(stream, code),
            Message::Frame(frame) => {
                // The encoder's history is private, so a caller cannot keep it in step with
                // a frame it compressed itself. Under context takeover the next ordinary
                // message would then reference a history the peer does not have.
                #[cfg(feature = "deflate")]
                if frame.header().rsv1 && self.deflate.is_some() {
                    return Err(Error::Protocol(ProtocolError::NonZeroReservedBits));
                }
                frame
            }
        };

        let should_flush = self._write(stream, Some(frame))?;
        if should_flush {
            self.flush(stream)?;
        }
        Ok(())
    }

    /// Flush writes.
    ///
    /// Ensures all messages previously passed to [`write`](Self::write) and automatically
    /// queued pong responses are written & flushed into the `stream`.
    #[inline]
    pub fn flush<Stream>(&mut self, stream: &mut Stream) -> Result<()>
    where
        Stream: Read + Write,
    {
        // Queued bytes belong to a connection the codec failure ended, so they are not
        // written and neither is a close frame -- `close` reaches the stream through here.
        // Latched separately from `WebSocketState` because the states the base sets do
        // permit a final flush, and that is not ours to change.
        #[cfg(feature = "deflate")]
        if self.compression_unusable {
            return Err(Error::AlreadyClosed);
        }
        self._write(stream, None)?;
        self.frame.write_out_buffer(stream)?;
        stream.flush()?;
        self.unflushed_additional = false;
        Ok(())
    }

    /// Writes any data in the out_buffer, `additional_send` and given `data`.
    ///
    /// Does **not** flush.
    ///
    /// Returns true if the write contents indicate we should flush immediately.
    fn _write<Stream>(&mut self, stream: &mut Stream, data: Option<Frame>) -> Result<bool>
    where
        Stream: Read + Write,
    {
        if let Some(data) = data {
            self.buffer_frame(stream, data)?;
        }

        // Upon receipt of a Ping frame, an endpoint MUST send a Pong frame in
        // response, unless it already received a Close frame. It SHOULD
        // respond with Pong frame as soon as is practical. (RFC 6455)
        let should_flush = if let Some(msg) = self.additional_send.take() {
            trace!("Sending pong/close");
            match self.buffer_frame(stream, msg) {
                Err(Error::WriteBufferFull(msg)) => {
                    // if an system message would exceed the buffer put it back in
                    // `additional_send` for retry. Otherwise returning this error
                    // may not make sense to the user, e.g. calling `flush`.
                    if let Message::Frame(msg) = *msg {
                        self.set_additional(msg);
                        false
                    } else {
                        unreachable!()
                    }
                }
                Err(err) => return Err(err),
                Ok(_) => true,
            }
        } else {
            self.unflushed_additional
        };

        // If we're closing and there is nothing to send anymore, we should close the connection.
        if self.role == Role::Server && !self.state.can_read() {
            // The underlying TCP connection, in most normal cases, SHOULD be closed
            // first by the server, so that it holds the TIME_WAIT state and not the
            // client (as this would prevent it from re-opening the connection for 2
            // maximum segment lifetimes (2MSL), while there is no corresponding
            // server impact as a TIME_WAIT connection is immediately reopened upon
            // a new SYN with a higher seq number). (RFC 6455)
            self.frame.write_out_buffer(stream)?;
            self.state = WebSocketState::Terminated;
            Err(Error::ConnectionClosed)
        } else {
            Ok(should_flush)
        }
    }

    /// Close the connection.
    ///
    /// This function guarantees that the close frame will be queued.
    /// There is no need to call it again. Calling this function is
    /// the same as calling `send(Message::Close(..))`.
    pub fn close<Stream>(&mut self, stream: &mut Stream, code: Option<CloseFrame>) -> Result<()>
    where
        Stream: Read + Write,
    {
        if let WebSocketState::Active = self.state {
            self.state = WebSocketState::ClosedByUs;
            let frame = Frame::close(code);
            self._write(stream, Some(frame))?;
        }
        self.flush(stream)
    }

    /// Inflate one frame's payload, ending the connection if the decoder fails.
    ///
    /// A failed inflate has already consumed part of the peer's compressed stream, and
    /// DEFLATE offers no way to resynchronise a decoder, so every later frame would
    /// decode to garbage rather than fail. Terminating keeps `read` and `write` off the
    /// stream, and the separate latch keeps `flush` and `close` off it too -- the states
    /// the base terminates with do allow a last flush, and this one must not.
    #[cfg(feature = "deflate")]
    fn decompress(&mut self, payload: &[u8], final_frame: bool) -> Result<bytes::Bytes> {
        let already = self.incomplete.as_ref().map(IncompleteMessage::len).unwrap_or(0);
        let max_size = self.config.max_message_size;
        let deflate = self.deflate.as_mut().expect("a compressed frame requires a codec");
        deflate.decompress(payload, final_frame, already, max_size).inspect_err(|_| {
            self.fail_compression();
        })
    }

    /// Take the connection out of service because compression state is no longer usable.
    ///
    /// The two fields move together and only here: `WebSocketState` stops `read` and
    /// `write`, and the separate flag also stops `flush` and `close`, which the base's own
    /// terminal states deliberately still allow.
    #[cfg(feature = "deflate")]
    fn fail_compression(&mut self) {
        self.compression_unusable = true;
        self.state = WebSocketState::Terminated;
    }

    /// End the connection when a frame whose payload will never reach our decoder carried
    /// compressed bytes. Every rejection that can be followed by another decode asks this
    /// one function, so the answer cannot differ by which of them asked. A frame arriving
    /// after the read side has closed is discarded without asking, because the states that
    /// close it are one-way and no later decode exists to corrupt.
    ///
    /// `FrameCodec` has already split those bytes off the input buffer, and the peer's
    /// compressor produced them, so our decoder can never see them and -- under context
    /// takeover, the default -- can never rebuild the window they belong to. Discarding
    /// them silently leaves a caller free to read on into wrong bytes, or into an error
    /// blaming a later message that was never at fault.
    #[cfg(feature = "deflate")]
    fn fail_compression_on_discarded_frame(&mut self, frame: &Frame) {
        let header = frame.header();
        // RSV1 is an explicit claim on compression state whatever the opcode, so a
        // discarded control frame carrying it counts too. Without RSV1 only a continuation
        // can be carrying compressed bytes: it does when the message it continues was
        // compressed, and when there is no such message it carries bytes nothing left here
        // can classify -- which under this contract is the same answer. An RSV1-clear
        // continuation of an open plain message is the one that stays live. RSV2 and RSV3
        // claim nothing about PMD.
        // "Claims" rather than "carries": the stray-continuation cell below latches because
        // ownership is unclassifiable, not because those bytes are known to be compressed.
        let claims_compression = header.rsv1
            || (matches!(header.opcode, OpCode::Data(OpData::Continue))
                && (self.compressed_incomplete || self.incomplete.is_none()));
        if claims_compression && self.deflate.is_some() {
            self.fail_compression();
        }
    }

    /// Checks one valid data-frame transition before decompression or buffering.
    fn check_message_fragment_count(&mut self, continuing: bool) -> Result<usize> {
        let fragments = if continuing {
            self.incomplete_fragment_count.saturating_add(1)
        } else {
            1
        };
        if let Some(max_fragments) = self.config.max_message_fragments {
            if fragments > max_fragments {
                self.incomplete = None;
                self.incomplete_fragment_count = 0;
                self.state = WebSocketState::Terminated;
                #[cfg(feature = "deflate")]
                {
                    self.compressed_incomplete = false;
                    self.compression_unusable = true;
                }
                return Err(CapacityError::MessageTooFragmented {
                    fragments,
                    max_fragments,
                }
                .into());
            }
        }
        Ok(fragments)
    }

    /// Try to decode one message frame. May return None.
    fn read_message_frame(&mut self, stream: &mut impl Read) -> Result<Option<Message>> {
        let read = self
            .frame
            .read_frame(
                stream,
                self.config.max_frame_size,
                matches!(self.role, Role::Server),
                self.config.accept_unmasked_frames,
            )
            .check_connection_reset(self.state);
        // The only `read_frame` error raised after the payload is split off the input
        // buffer, and it throws the header away with it -- so unlike every other rejection
        // there is nothing left to ask whether those bytes were compressed. Continuing
        // cannot be shown safe, and RFC 6455 requires closing this connection anyway; a
        // caller who needs the frame instead sets `accept_unmasked_frames`, and then no
        // rejection happens here at all.
        #[cfg(feature = "deflate")]
        if self.deflate.is_some()
            && matches!(read, Err(Error::Protocol(ProtocolError::UnmaskedFrameFromClient)))
        {
            self.fail_compression();
        }
        let frame = match read? {
            None => {
                // Connection closed by peer
                return match replace(&mut self.state, WebSocketState::Terminated) {
                    WebSocketState::ClosedByPeer | WebSocketState::CloseAcknowledged => {
                        Err(Error::ConnectionClosed)
                    }
                    _ => Err(Error::Protocol(ProtocolError::ResetWithoutClosingHandshake)),
                };
            }
            Some(frame) => frame,
        };
        #[cfg(feature = "deflate")]
        let mut frame = frame;

        if !self.state.can_read() {
            return Err(Error::Protocol(ProtocolError::ReceivedAfterClosing));
        }
        // MUST be 0 unless an extension is negotiated that defines meanings
        // for non-zero values.  If a nonzero value is received and none of
        // the negotiated extensions defines the meaning of such a nonzero
        // value, the receiving endpoint MUST _Fail the WebSocket
        // Connection_.
        let reserved_bits_set = {
            let hdr = frame.header();
            #[cfg(not(feature = "deflate"))]
            let invalid_rsv1 = hdr.rsv1;
            #[cfg(feature = "deflate")]
            let invalid_rsv1 = hdr.rsv1
                && (self.deflate.is_none()
                    || !matches!(hdr.opcode, OpCode::Data(OpData::Text | OpData::Binary)));
            invalid_rsv1 || hdr.rsv2 || hdr.rsv3
        };
        if reserved_bits_set {
            #[cfg(feature = "deflate")]
            self.fail_compression_on_discarded_frame(&frame);
            return Err(Error::Protocol(ProtocolError::NonZeroReservedBits));
        }

        if self.role == Role::Client && frame.is_masked() {
            // A client MUST close a connection if it detects a masked frame. (RFC 6455)
            #[cfg(feature = "deflate")]
            self.fail_compression_on_discarded_frame(&frame);
            return Err(Error::Protocol(ProtocolError::MaskedFrameFromServer));
        }

        let fragment_count = match frame.header().opcode {
            OpCode::Data(OpData::Text | OpData::Binary) if self.incomplete.is_none() => {
                Some(self.check_message_fragment_count(false)?)
            }
            OpCode::Data(OpData::Continue) if self.incomplete.is_some() => {
                Some(self.check_message_fragment_count(true)?)
            }
            _ => None,
        };

        // The fragment-sequence check that rejects an illegal opcode transition lives in
        // the assembly match below, so test the same condition here: a frame that does not
        // own the message stream must not advance the inflater or overwrite the saved
        // compressed mode before it is rejected. Both are one-way.
        #[cfg(feature = "deflate")]
        if let OpCode::Data(data) = frame.header().opcode {
            if matches!(data, OpData::Continue) == self.incomplete.is_some() {
                let final_frame = frame.header().is_final;
                let compressed = match data {
                    OpData::Text | OpData::Binary => frame.header().rsv1,
                    OpData::Continue => self.compressed_incomplete,
                    OpData::Reserved(_) => false,
                };
                if compressed {
                    let payload = self.decompress(frame.payload(), final_frame)?;
                    let mut header = frame.header().clone();
                    header.rsv1 = false;
                    frame = Frame::from_payload(header, payload);
                }
                match data {
                    OpData::Text | OpData::Binary if !final_frame => {
                        self.compressed_incomplete = compressed;
                    }
                    OpData::Continue if final_frame => self.compressed_incomplete = false,
                    _ => {}
                }
            } else {
                // Skipping this frame is not recoverable either: its bytes went through the
                // peer's compressor and its window moved, while ours cannot. Same question
                // as a frame discarded before the host saw it, so the same classifier
                // answers it. The error below is unchanged either way.
                self.fail_compression_on_discarded_frame(&frame);
            }
        }

        match frame.header().opcode {
            OpCode::Control(ctl) => {
                match ctl {
                    // All control frames MUST have a payload length of 125 bytes or less
                    // and MUST NOT be fragmented. (RFC 6455)
                    _ if !frame.header().is_final => {
                        Err(Error::Protocol(ProtocolError::FragmentedControlFrame))
                    }
                    _ if frame.payload().len() > 125 => {
                        Err(Error::Protocol(ProtocolError::ControlFrameTooBig))
                    }
                    OpCtl::Close => self
                        .do_close(frame.into_close()?)
                        .map(|close| close.map(Message::Close)),
                    OpCtl::Reserved(i) => {
                        Err(Error::Protocol(ProtocolError::UnknownControlFrameType(i)))
                    }
                    OpCtl::Ping => {
                        let data = frame.into_payload();
                        // No ping processing after we sent a close frame.
                        if self.state.is_active() {
                            self.set_additional(Frame::pong(data.clone()));
                        }
                        Ok(Some(Message::Ping(data)))
                    }
                    OpCtl::Pong => Ok(Some(Message::Pong(frame.into_payload()))),
                }
            }

            OpCode::Data(data) => {
                let fin = frame.header().is_final;

                let payload = match (data, self.incomplete.as_mut()) {
                    (OpData::Continue, None) => Err(ProtocolError::UnexpectedContinueFrame),
                    (OpData::Continue, Some(incomplete)) => {
                        incomplete.extend(frame.into_payload(), self.config.max_message_size)?;
                        Ok(None)
                    }
                    (_, Some(_)) => Err(ProtocolError::ExpectedFragment(data)),
                    (OpData::Text, _) => Ok(Some((frame.into_payload(), MessageType::Text))),
                    (OpData::Binary, _) => Ok(Some((frame.into_payload(), MessageType::Binary))),
                    (OpData::Reserved(i), _) => Err(ProtocolError::UnknownDataFrameType(i)),
                }?;

                let result = match (payload, fin) {
                    (None, true) => Ok(Some(self.incomplete.take().unwrap().complete()?)),
                    (None, false) => Ok(None),
                    (Some((payload, t)), true) => {
                        check_max_size(payload.len(), self.config.max_message_size)?;
                        match t {
                            MessageType::Text => Ok(Some(Message::Text(payload.try_into()?))),
                            MessageType::Binary => Ok(Some(Message::Binary(payload))),
                        }
                    }
                    (Some((payload, t)), false) => {
                        let mut incomplete = IncompleteMessage::new(t);
                        incomplete.extend(payload, self.config.max_message_size)?;
                        self.incomplete = Some(incomplete);
                        Ok(None)
                    }
                };
                if result.is_ok() {
                    if let Some(count) = fragment_count {
                        self.incomplete_fragment_count = if fin { 0 } else { count };
                    }
                }
                result
            }
        } // match opcode
    }

    /// Received a close frame. Tells if we need to return a close frame to the user.
    #[allow(clippy::option_option)]
    fn do_close(&mut self, close: Option<CloseFrame>) -> Result<Option<Option<CloseFrame>>> {
        debug!("Received WebSocket close frame");
        if let Some(frame) = &close {
            if !frame.code.is_allowed() {
                return Err(ProtocolError::InvalidCloseCode(frame.code.into()).into());
            }
        }
        match self.state {
            WebSocketState::Active => {
                self.state = WebSocketState::ClosedByPeer;

                let reply = Frame::close(close.clone());
                debug!("Replying with WebSocket close frame");
                self.set_additional(reply);

                Ok(Some(close))
            }
            WebSocketState::ClosedByPeer | WebSocketState::CloseAcknowledged => {
                // It is already closed, just ignore.
                Ok(None)
            }
            WebSocketState::ClosedByUs => {
                // We received a reply.
                self.state = WebSocketState::CloseAcknowledged;
                Ok(Some(close))
            }
            WebSocketState::Terminated => unreachable!(),
        }
    }

    /// Write a single frame into the write-buffer.
    fn buffer_frame<Stream>(&mut self, stream: &mut Stream, mut frame: Frame) -> Result<()>
    where
        Stream: Read + Write,
    {
        #[cfg(feature = "deflate")]
        let carries_compression_state = frame.header().rsv1 && self.deflate.is_some();
        match self.role {
            Role::Server => {}
            Role::Client => {
                // 5.  If the data is being sent by the client, the frame(s) MUST be
                // masked as defined in Section 5.3. (RFC 6455)
                frame.set_random_mask().inspect_err(|_| {
                    #[cfg(feature = "deflate")]
                    if carries_compression_state {
                        self.fail_compression();
                    }
                })?;
            }
        }

        trace!("Sending WebSocket frame");
        self.frame.buffer_frame(stream, frame).check_connection_reset(self.state)
    }

    /// Replace `additional_send` if it is currently a `Pong` message.
    fn set_additional(&mut self, add: Frame) {
        let empty_or_pong = self
            .additional_send
            .as_ref()
            .is_none_or(|f| f.header().opcode == OpCode::Control(OpCtl::Pong));
        if empty_or_pong {
            self.additional_send.replace(add);
        }
    }
}

/// Wire bytes a prepared frame will occupy once `buffer_frame` has masked it.
///
/// Only ever called on a frame built moments earlier in `write`, so the client mask is
/// always still pending.
#[cfg(feature = "deflate")]
fn wire_size(role: Role, frame: &Frame) -> usize {
    debug_assert!(!frame.is_masked(), "wire_size adds the pending client mask itself");
    frame.len() + usize::from(role == Role::Client) * 4
}

fn check_max_size(size: usize, max_size: Option<usize>) -> crate::Result<()> {
    if let Some(max_size) = max_size {
        if size > max_size {
            return Err(Error::Capacity(CapacityError::MessageTooLong { size, max_size }));
        }
    }
    Ok(())
}

/// The current connection state.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum WebSocketState {
    /// The connection is active.
    Active,
    /// We initiated a close handshake.
    ClosedByUs,
    /// The peer initiated a close handshake.
    ClosedByPeer,
    /// The peer replied to our close handshake.
    CloseAcknowledged,
    /// The connection does not exist anymore.
    Terminated,
}

impl WebSocketState {
    /// Tell if we're allowed to process normal messages.
    fn is_active(self) -> bool {
        matches!(self, WebSocketState::Active)
    }

    /// Tell if we should process incoming data. Note that if we send a close frame
    /// but the remote hasn't confirmed, they might have sent data before they receive our
    /// close frame, so we should still pass those to client code, hence ClosedByUs is valid.
    fn can_read(self) -> bool {
        matches!(self, WebSocketState::Active | WebSocketState::ClosedByUs)
    }

    /// Check if the state is active, return error if not.
    fn check_not_terminated(self) -> Result<()> {
        match self {
            WebSocketState::Terminated => Err(Error::AlreadyClosed),
            _ => Ok(()),
        }
    }
}

/// Translate "Connection reset by peer" into `ConnectionClosed` if appropriate.
trait CheckConnectionReset {
    fn check_connection_reset(self, state: WebSocketState) -> Self;
}

impl<T> CheckConnectionReset for Result<T> {
    fn check_connection_reset(self, state: WebSocketState) -> Self {
        match self {
            Err(Error::Io(io_error)) => Err({
                if !state.can_read() && io_error.kind() == io::ErrorKind::ConnectionReset {
                    Error::ConnectionClosed
                } else {
                    Error::Io(io_error)
                }
            }),
            x => x,
        }
    }
}


#[cfg(test)]
mod tests {
    use super::{Message, Role, WebSocket, WebSocketConfig};
    use crate::error::{CapacityError, Error};

    use std::{io, io::Cursor};

    struct WriteMoc<Stream>(Stream);

    impl<Stream> io::Write for WriteMoc<Stream> {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<Stream: io::Read> io::Read for WriteMoc<Stream> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.read(buf)
        }
    }

    #[test]
    fn receive_messages() {
        let incoming = Cursor::new(vec![
            0x89, 0x02, 0x01, 0x02, 0x8a, 0x01, 0x03, 0x01, 0x07, 0x48, 0x65, 0x6c, 0x6c, 0x6f,
            0x2c, 0x20, 0x80, 0x06, 0x57, 0x6f, 0x72, 0x6c, 0x64, 0x21, 0x82, 0x03, 0x01, 0x02,
            0x03,
        ]);
        let mut socket = WebSocket::from_raw_socket(WriteMoc(incoming), Role::Client, None);
        assert_eq!(socket.read().unwrap(), Message::Ping(vec![1, 2].into()));
        assert_eq!(socket.read().unwrap(), Message::Pong(vec![3].into()));
        assert_eq!(socket.read().unwrap(), Message::Text("Hello, World!".into()));
        assert_eq!(socket.read().unwrap(), Message::Binary(vec![0x01, 0x02, 0x03].into()));
    }

    #[test]
    fn size_limiting_text_fragmented() {
        let incoming = Cursor::new(vec![
            0x01, 0x07, 0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x2c, 0x20, 0x80, 0x06, 0x57, 0x6f, 0x72,
            0x6c, 0x64, 0x21,
        ]);
        let limit = WebSocketConfig { max_message_size: Some(10), ..WebSocketConfig::default() };
        let mut socket = WebSocket::from_raw_socket(WriteMoc(incoming), Role::Client, Some(limit));

        assert!(matches!(
            socket.read(),
            Err(Error::Capacity(CapacityError::MessageTooLong { size: 13, max_size: 10 }))
        ));
    }

    #[test]
    fn size_limiting_binary() {
        let incoming = Cursor::new(vec![0x82, 0x03, 0x01, 0x02, 0x03]);
        let limit = WebSocketConfig { max_message_size: Some(2), ..WebSocketConfig::default() };
        let mut socket = WebSocket::from_raw_socket(WriteMoc(incoming), Role::Client, Some(limit));

        assert!(matches!(
            socket.read(),
            Err(Error::Capacity(CapacityError::MessageTooLong { size: 3, max_size: 2 }))
        ));
    }

    #[test]
    fn fragment_count_limit_is_terminal_and_counts_empty_fragments() {
        let incoming = Cursor::new(vec![0x01, 0x00, 0x00, 0x00, 0x80, 0x00]);
        let limit = WebSocketConfig {
            max_message_fragments: Some(2),
            ..WebSocketConfig::default()
        };
        let mut socket = WebSocket::from_raw_socket(WriteMoc(incoming), Role::Client, Some(limit));

        assert!(matches!(
            socket.read(),
            Err(Error::Capacity(CapacityError::MessageTooFragmented {
                fragments: 3,
                max_fragments: 2,
            }))
        ));
        assert!(matches!(socket.read(), Err(Error::AlreadyClosed)));
    }

    #[test]
    fn control_frames_do_not_consume_the_fragment_count() {
        let incoming = Cursor::new(vec![
            0x01, 0x03, b'h', b'e', b'l', 0x89, 0x00, 0x80, 0x02, b'l', b'o',
        ]);
        let limit = WebSocketConfig {
            max_message_fragments: Some(2),
            ..WebSocketConfig::default()
        };
        let mut socket = WebSocket::from_raw_socket(WriteMoc(incoming), Role::Client, Some(limit));

        assert_eq!(socket.read().unwrap(), Message::Ping(Vec::new().into()));
        assert_eq!(socket.read().unwrap(), Message::Text("hello".into()));
    }

    #[test]
    fn set_config_changes_the_configuration() {
        let mut socket =
            WebSocket::from_raw_socket(WriteMoc(Cursor::new(Vec::<u8>::new())), Role::Client, None);
        assert_eq!(socket.get_config().max_message_size, Some(64 << 20));
        assert_eq!(socket.get_config().max_message_fragments, None);

        socket.set_config(|config| {
            config.max_message_size = Some(1024);
            config.max_message_fragments = Some(32);
        });

        assert_eq!(socket.get_config().max_message_size, Some(1024));
        assert_eq!(socket.get_config().max_message_fragments, Some(32));
    }

    /// The feature-on arm applies the callback to a copy, so what survives a panic depends
    /// on which panic it is. Validation still fires after the commit, as upstream does.
    #[cfg(feature = "deflate")]
    #[test]
    fn set_config_panics_leave_the_live_config_in_a_defined_state() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        fn agreed_socket() -> WebSocket<WriteMoc<Cursor<Vec<u8>>>> {
            WebSocket::from_raw_socket(
                WriteMoc(Cursor::new(Vec::<u8>::new())),
                Role::Client,
                Some(WebSocketConfig::default().enable_deflate()),
            )
        }

        let mut invalid = agreed_socket();
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            invalid.set_config(|config| config.max_write_buffer_size = config.write_buffer_size)
        }));
        assert!(outcome.is_err(), "an invalid candidate must still be rejected");
        assert_eq!(
            invalid.get_config().max_write_buffer_size,
            invalid.get_config().write_buffer_size,
            "upstream commits before validating, and the deflate arm keeps that ordering"
        );

        let mut callback = agreed_socket();
        let untouched = callback.get_config().max_message_size;
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            callback.set_config(|config| {
                config.max_message_size = Some(1);
                panic!("the callback itself fails");
            })
        }));
        assert!(outcome.is_err(), "the callback's own panic must propagate");
        assert_eq!(
            callback.get_config().max_message_size,
            untouched,
            "the candidate is discarded, so the callback's edit never lands"
        );

        // An agreed `Some(..)` moving to a different `Some(..)`. Starting from `None` also
        // panics, while measuring that deflate cannot be switched on mid-connection --
        // a different claim from the one this assert makes.
        let mut agreed = agreed_socket();
        let settled = agreed.get_config().deflate;
        assert!(settled.is_some(), "the socket must start from an agreed Some(..)");
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            agreed.set_config(|config| *config = config.deflate_max_window_bits(Role::Client, 10))
        }));
        let message = *outcome
            .expect_err("a deflate change must be rejected")
            .downcast::<String>()
            .expect("assert_eq! panics with a String");
        assert!(message.contains("agreed deflate settings are immutable"), "{message}");
        assert_eq!(agreed.get_config().deflate, settled, "rejection happens before the commit");
    }
}
