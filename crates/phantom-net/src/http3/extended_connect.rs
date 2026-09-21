//! Bidirectional byte transport carried by an accepted HTTP/3 extended CONNECT stream.

use std::{
    any::Any,
    fmt, io,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::{Buf, Bytes};
use h3::error::Code;
use http::Response;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{Instrument, debug_span, dispatcher, instrument::WithSubscriber};

use super::{
    DatagramMonitor, DriverSignal, Http3Body, Http3Connection, RequestRecvStream,
    RequestSendStream, SHUTDOWN_GRACE,
};
use crate::shutdown_timer;

const MAX_WRITE_CHUNK: usize = 16 * 1024;

/// A protocol that can be bootstrapped with HTTP/3 extended CONNECT.
///
/// RFC 9220 carries the protocol in the `:protocol` pseudo-header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http3ExtendedProtocol {
    /// The WebSocket protocol (`websocket`), RFC 9220.
    WebSocket,
}

impl Http3ExtendedProtocol {
    pub(super) const fn wire_value(self) -> h3::ext::Protocol {
        match self {
            Self::WebSocket => h3::ext::Protocol::WEBSOCKET,
        }
    }

    pub(super) const fn trace_name(self) -> &'static str {
        match self {
            Self::WebSocket => "websocket",
        }
    }
}

/// Terminal response to an HTTP/3 extended CONNECT request.
#[must_use = "an accepted stream or rejected response body must be handled"]
pub enum Http3ExtendedConnectOutcome {
    /// The peer accepted the tunnel with a successful response status.
    Accepted {
        /// Successful response head, including exact ordered response fields.
        response: Response<()>,
        /// Bidirectional DATA stream created by the accepted request.
        stream: Http3ExtendedConnectStream,
    },
    /// The peer rejected the tunnel; its response body remains readable.
    Rejected(Response<Http3Body>),
}

impl fmt::Debug for Http3ExtendedConnectOutcome {
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

/// A bounded byte stream carried by HTTP/3 DATA frames.
///
/// At most one received DATA chunk and one queued outbound frame are buffered,
/// so QUIC stream credit follows consumption. Shutdown ends the send side with
/// FIN. Dropping an incomplete stream aborts only this stream with
/// `H3_REQUEST_CANCELLED` (RFC 9220 section 3). An HTTP Datagram associated
/// with the stream aborts it with `H3_DATAGRAM_ERROR` (RFC 9297 section 2).
pub struct Http3ExtendedConnectStream {
    // Boxed so the accepted outcome stays close in size to a rejection.
    send: Box<RequestSendStream>,
    recv: Box<RequestRecvStream>,
    current: Bytes,
    data_ended: bool,
    receive_complete: bool,
    send_complete: bool,
    aborted: bool,
    datagrams: Option<DatagramMonitor>,
    stream_guard: Option<Box<dyn Any + Send + Sync>>,
    connection: Http3Connection,
}

impl Http3ExtendedConnectStream {
    pub(super) fn new(
        send: RequestSendStream,
        recv: RequestRecvStream,
        connection: Http3Connection,
        datagrams: Option<DatagramMonitor>,
    ) -> Self {
        Self {
            send: Box::new(send),
            recv: Box::new(recv),
            current: Bytes::new(),
            data_ended: false,
            receive_complete: false,
            send_complete: false,
            aborted: false,
            datagrams,
            stream_guard: None,
            connection,
        }
    }

    /// Retains a value until this stream is completed or dropped.
    #[doc(hidden)]
    pub fn retain_until_stream_complete<T>(&mut self, value: T)
    where
        T: Send + Sync + 'static,
    {
        self.stream_guard = Some(Box::new(value));
    }

    fn release_guard_if_complete(&mut self) {
        if self.receive_complete && self.send_complete {
            self.stream_guard.take();
        }
    }

    fn complete_receive(&mut self) {
        self.receive_complete = true;
        self.release_guard_if_complete();
    }

    fn poll_datagram_violation(&mut self, context: &mut Context<'_>) -> io::Result<()> {
        let Some(monitor) = self.datagrams.as_mut() else {
            return Ok(());
        };
        match monitor.poll_violation(context) {
            Poll::Ready(Some(())) => {
                self.datagrams = None;
                self.abort(Code::H3_DATAGRAM_ERROR);
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "peer sent an HTTP Datagram on an extended CONNECT stream without datagram semantics",
                ))
            }
            Poll::Ready(None) => {
                self.datagrams = None;
                Ok(())
            }
            Poll::Pending => Ok(()),
        }
    }

    fn abort(&mut self, code: Code) {
        if !self.receive_complete {
            self.recv.stop_sending(code);
        }
        if !self.send_complete {
            self.send.stop_stream(code);
        }
        self.aborted = true;
        self.send_complete = true;
        self.receive_complete = true;
        self.connection.record(DriverSignal::ProtocolError);
        self.stream_guard.take();
    }

    fn poll_trailers(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match ready!(self.recv.poll_recv_trailers(context)) {
            Ok(Some(_)) => {
                self.complete_receive();
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "HTTP/3 extended CONNECT stream received trailers",
                )))
            }
            Ok(None) => {
                self.complete_receive();
                Poll::Ready(Ok(()))
            }
            Err(error) => {
                self.complete_receive();
                Poll::Ready(Err(io::Error::other(error)))
            }
        }
    }
}

impl fmt::Debug for Http3ExtendedConnectStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http3ExtendedConnectStream")
            .field("receive_complete", &self.receive_complete)
            .field("send_complete", &self.send_complete)
            .finish_non_exhaustive()
    }
}

impl AsyncRead for Http3ExtendedConnectStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_datagram_violation(context)?;
        if output.remaining() == 0 || self.receive_complete {
            return Poll::Ready(Ok(()));
        }

        loop {
            if self.current.has_remaining() {
                let count = self.current.remaining().min(output.remaining());
                output.put_slice(&self.current[..count]);
                self.current.advance(count);
                return Poll::Ready(Ok(()));
            }

            if self.data_ended {
                return self.poll_trailers(context);
            }

            match ready!(self.recv.poll_recv_data(context)) {
                Ok(Some(mut data)) => {
                    self.current = data.copy_to_bytes(data.remaining());
                }
                Ok(None) => self.data_ended = true,
                Err(error) => {
                    self.complete_receive();
                    return Poll::Ready(Err(io::Error::other(error)));
                }
            }
        }
    }
}

impl AsyncWrite for Http3ExtendedConnectStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_datagram_violation(context)?;
        if self.send_complete {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "HTTP/3 extended CONNECT send stream is closed",
            )));
        }
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }

        ready!(self.send.poll_ready(context)).map_err(io::Error::other)?;
        let count = input.len().min(MAX_WRITE_CHUNK);
        self.send
            .start_send_data(Bytes::copy_from_slice(&input[..count]))
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(count))
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_datagram_violation(context)?;
        if self.send_complete {
            return Poll::Ready(Ok(()));
        }
        self.send.poll_ready(context).map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_datagram_violation(context)?;
        if self.send_complete {
            return Poll::Ready(Ok(()));
        }
        ready!(self.send.poll_ready(context)).map_err(io::Error::other)?;
        ready!(self.send.poll_finish(context)).map_err(io::Error::other)?;
        self.send_complete = true;
        self.release_guard_if_complete();
        Poll::Ready(Ok(()))
    }
}

impl Drop for Http3ExtendedConnectStream {
    fn drop(&mut self) {
        if self.aborted {
            retain_connection_for_reset(self.connection.clone());
            return;
        }
        if self.send_complete && self.receive_complete {
            self.connection.record(DriverSignal::Complete);
            return;
        }
        if !self.receive_complete {
            self.recv.stop_sending(Code::H3_REQUEST_CANCELLED);
        }
        if !self.send_complete {
            self.send.stop_stream(Code::H3_REQUEST_CANCELLED);
        }
        self.connection.record(DriverSignal::Cancelled);
        retain_connection_for_reset(self.connection.clone());
    }
}

/// Keeps the connection lease briefly so queued stream resets reach the peer
/// before a final lease starts connection shutdown.
fn retain_connection_for_reset(connection: Http3Connection) {
    let runtime = connection.runtime().clone();
    let dispatch = dispatcher::get_default(Clone::clone);
    let span = debug_span!("http3.extended_connect.reset");
    let task = async move {
        match shutdown_timer::after(SHUTDOWN_GRACE) {
            Ok(deadline) => {
                let _ = deadline.await;
            }
            Err(_) => tokio::task::yield_now().await,
        }
        drop(connection);
    }
    .instrument(span)
    .with_subscriber(dispatch);
    drop(runtime.spawn(task));
}
