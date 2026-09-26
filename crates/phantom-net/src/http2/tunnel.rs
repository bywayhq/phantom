//! Bidirectional byte transport carried by an accepted HTTP/2 CONNECT stream.

use std::{
    any::Any,
    fmt, io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use ::http2::{Reason, RecvStream, SendStream};
use bytes::{Buf, Bytes};
use http::Response;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{Http2Body, connection::ConnectionLease};

const MAX_WRITE_CHUNK: usize = 16 * 1024;

/// Terminal response to an HTTP/2 extended CONNECT request.
#[must_use = "an accepted stream or rejected response body must be handled"]
pub enum Http2ExtendedConnectOutcome {
    /// The peer accepted the tunnel with a successful response status.
    Accepted {
        /// Successful response head, including exact ordered response fields.
        response: Response<()>,
        /// Bidirectional DATA stream created by the accepted request.
        stream: Http2ExtendedConnectStream,
    },
    /// The peer rejected the tunnel; its response body remains readable.
    Rejected(Response<Http2Body>),
}

impl fmt::Debug for Http2ExtendedConnectOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Accepted { response, stream } => formatter
                .debug_struct("Accepted")
                .field("response", response)
                .field("stream", stream)
                .finish(),
            Self::Rejected(response) => formatter.debug_tuple("Rejected").field(response).finish(),
        }
    }
}

/// Terminal response to an RFC 9113 section 8.5 CONNECT request.
pub(crate) enum Http2ClassicConnectOutcome {
    /// The peer returned a 2xx status and the stream now carries tunnel bytes.
    Accepted {
        /// Final successful response status.
        status: u16,
        /// Flow-controlled tunnel byte stream.
        stream: Http2ConnectStream,
    },
    /// The peer returned a final non-2xx status.
    Rejected {
        /// Final response status.
        status: u16,
        /// Semantic response fields, used for authentication challenges.
        headers: http::HeaderMap,
        /// The rejected stream, left open on the client side, when the
        /// profile sends nothing more on it.
        held: Option<Http2RejectedStream>,
    },
}

/// A rejected CONNECT stream whose client side stays open.
///
/// Dropping it resets the stream with CANCEL, so a holder keeps it for as
/// long as the connection should carry no frame for it.
pub(crate) struct Http2RejectedStream {
    _send: SendStream<Bytes>,
    _receive: RecvStream,
}

impl Http2RejectedStream {
    pub(super) fn new(send: SendStream<Bytes>, receive: RecvStream) -> Self {
        Self {
            _send: send,
            _receive: receive,
        }
    }
}

/// A bounded, flow-controlled byte stream carried by HTTP/2 DATA frames.
///
/// Receive capacity is returned only as bytes are consumed. Writes wait for
/// stream capacity before copying and queueing data. Dropping an incomplete
/// stream resets only that stream with `CANCEL`.
pub struct Http2ExtendedConnectStream {
    inner: Http2ConnectStream,
}

impl Http2ExtendedConnectStream {
    pub(super) fn new(
        receive: RecvStream,
        send: SendStream<Bytes>,
        lease: ConnectionLease,
    ) -> Self {
        Self {
            inner: Http2ConnectStream::new(receive, send, lease),
        }
    }

    /// Returns the DATA byte stream, which keeps its connection lease.
    pub(crate) fn into_connect_stream(self) -> Http2ConnectStream {
        self.inner
    }

    /// Retains a value until this stream is completed or dropped.
    #[doc(hidden)]
    pub fn retain_until_stream_complete<T>(&mut self, value: T)
    where
        T: Send + Sync + 'static,
    {
        self.inner.retain_until_stream_complete(value);
    }
}

impl fmt::Debug for Http2ExtendedConnectStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http2ExtendedConnectStream")
            .field("receive_complete", &self.inner.receive_complete)
            .field("send_complete", &self.inner.send_complete)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for Http2ExtendedConnectStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, output)
    }
}

impl AsyncWrite for Http2ExtendedConnectStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, input)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

/// DATA-frame byte stream shared by extended CONNECT and classic proxy CONNECT.
///
/// The stream owns a lease on its connection, so a tunnel that is the only
/// user of a connection also ends that connection when dropped.
pub(crate) struct Http2ConnectStream {
    receive: RecvStream,
    send: SendStream<Bytes>,
    current: Bytes,
    data_ended: bool,
    receive_complete: bool,
    send_complete: bool,
    stream_guard: Option<Box<dyn Any + Send + Sync>>,
    // Declared before the lease so it drops while the connection is open.
    held_rejection: Option<Http2RejectedStream>,
    lease: ConnectionLease,
}

impl Http2ConnectStream {
    pub(super) fn new(
        receive: RecvStream,
        send: SendStream<Bytes>,
        lease: ConnectionLease,
    ) -> Self {
        Self {
            receive,
            send,
            current: Bytes::new(),
            data_ended: false,
            receive_complete: false,
            send_complete: false,
            stream_guard: None,
            held_rejection: None,
            lease,
        }
    }

    /// Retains a value until this stream is completed or dropped.
    pub(crate) fn retain_until_stream_complete<T>(&mut self, value: T)
    where
        T: Send + Sync + 'static,
    {
        // One value per stream; a second would drop the first early.
        debug_assert!(self.stream_guard.is_none());
        self.stream_guard = Some(Box::new(value));
    }

    /// Keeps a rejected stream of the same connection open until this
    /// tunnel is dropped.
    pub(crate) fn hold_rejected_stream(&mut self, stream: Http2RejectedStream) {
        self.held_rejection = Some(stream);
    }

    fn release_guard_if_complete(&mut self) {
        if self.receive_complete && self.send_complete {
            self.stream_guard.take();
        }
    }

    fn poll_trailers(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match ready!(self.receive.poll_trailers(context)) {
            Ok(Some(_)) => {
                self.receive_complete = true;
                self.release_guard_if_complete();
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP/2 CONNECT stream received trailers",
                )))
            }
            Ok(None) => {
                self.receive_complete = true;
                self.release_guard_if_complete();
                Poll::Ready(Ok(()))
            }
            Err(error) => {
                self.receive_complete = true;
                self.release_guard_if_complete();
                Poll::Ready(Err(io::Error::other(error)))
            }
        }
    }
}

impl fmt::Debug for Http2ConnectStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http2ConnectStream")
            .field("receive_complete", &self.receive_complete)
            .field("send_complete", &self.send_complete)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for Http2ConnectStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 || self.receive_complete {
            return Poll::Ready(Ok(()));
        }

        loop {
            if self.current.has_remaining() {
                let count = self.current.remaining().min(output.remaining());
                if let Err(error) = self.receive.flow_control().release_capacity(count) {
                    self.receive_complete = true;
                    self.release_guard_if_complete();
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                output.put_slice(&self.current[..count]);
                self.current.advance(count);
                return Poll::Ready(Ok(()));
            }

            if self.data_ended {
                return self.poll_trailers(context);
            }

            match ready!(self.receive.poll_data(context)) {
                Some(Ok(data)) => {
                    self.current = data;
                }
                Some(Err(error)) => {
                    self.receive_complete = true;
                    self.release_guard_if_complete();
                    return Poll::Ready(Err(io::Error::other(error)));
                }
                None => {
                    self.data_ended = true;
                }
            }
        }
    }
}

impl AsyncWrite for Http2ConnectStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.send_complete {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/2 CONNECT send stream is closed",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let requested = input.len().min(MAX_WRITE_CHUNK);
        self.send.reserve_capacity(requested);
        let capacity = if self.send.capacity() > 0 {
            self.send.capacity()
        } else {
            match ready!(self.send.poll_capacity(context)) {
                Some(Ok(capacity)) => capacity,
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                None => {
                    self.send_complete = true;
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "HTTP/2 CONNECT send stream closed before the write",
                    )));
                }
            }
        };
        let count = capacity.min(requested);
        self.send
            .send_data(Bytes::copy_from_slice(&input[..count]), false)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.send_complete {
            self.send
                .send_data(Bytes::new(), true)
                .map_err(io::Error::other)?;
            self.send_complete = true;
            self.release_guard_if_complete();
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Http2ConnectStream {
    fn drop(&mut self) {
        // A reset on a connection whose driver has stopped would only queue a
        // frame nobody writes, and keeps the stream in the vendored store.
        // The driver can still stop between this check and the reset; the
        // reset is then queued and never written, as before this check.
        if !self.send_complete && !self.lease.is_closed() {
            self.send.send_reset(Reason::CANCEL);
        }
    }
}
