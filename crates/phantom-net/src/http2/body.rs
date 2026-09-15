//! Streaming response-body ownership for one-shot HTTP/2 transactions.

use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use ::http2::{Reason, RecvStream, SendStream, client};
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinHandle,
    time::timeout,
};
use tracing::{Instrument, Span, debug, debug_span, field, warn};

use super::Http2Error;

pub(super) const DRIVER_SHUTDOWN_GRACE: Duration = Duration::from_secs(1);

/// Streaming response body for a one-shot HTTP/2 transaction.
///
/// DATA and trailers are yielded as received. If this body is dropped before
/// the stream ends, it explicitly resets the stream with `CANCEL` before the
/// final connection sender is dropped. The still-running driver flushes that
/// reset and then closes the one-shot connection.
#[must_use = "response bodies must be read or deliberately dropped"]
pub struct Http2Body {
    // Declaration order is intentional: an incomplete receive stream must be
    // dropped before DriverTask drops the last request sender.
    incoming: Option<RecvStream>,
    reset: Option<SendStream<Bytes>>,
    driver: DriverTask,
    finished: bool,
    trace: BodyTrace,
}

impl Http2Body {
    pub(super) fn new(
        incoming: RecvStream,
        reset: SendStream<Bytes>,
        mut driver: DriverTask,
    ) -> Self {
        let finished = incoming.is_end_stream();
        let mut trace = BodyTrace::new();
        if finished {
            driver.shutdown();
            trace.finish("complete");
        }
        Self {
            incoming: (!finished).then_some(incoming),
            reset: (!finished).then_some(reset),
            driver,
            finished,
            trace,
        }
    }
}

impl fmt::Debug for Http2Body {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http2Body")
            .field("finished", &self.finished)
            .field("received_bytes", &self.trace.received_bytes)
            .finish_non_exhaustive()
    }
}

impl Body for Http2Body {
    type Data = Bytes;
    type Error = Http2Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }

        let Some(incoming) = self.incoming.as_mut() else {
            self.finished = true;
            self.driver.shutdown();
            self.trace.finish("protocol_error");
            return Poll::Ready(Some(Err(Http2Error::Protocol(
                ::http2::Reason::INTERNAL_ERROR.into(),
            ))));
        };
        match incoming.poll_data(context) {
            Poll::Ready(Some(Ok(data))) => {
                let _ = incoming.flow_control().release_capacity(data.len());
                let end_stream = incoming.is_end_stream();
                self.trace.add_bytes(data.len());
                if end_stream {
                    self.finished = true;
                    self.incoming.take();
                    self.reset.take();
                    self.driver.shutdown();
                    self.trace.finish("complete");
                }
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
            Poll::Ready(Some(Err(error))) => {
                self.finished = true;
                self.incoming.take();
                self.reset.take();
                self.driver.shutdown();
                self.trace.finish("protocol_error");
                Poll::Ready(Some(Err(Http2Error::Protocol(error))))
            }
            Poll::Ready(None) => match incoming.poll_trailers(context) {
                Poll::Ready(Ok(Some(trailers))) => {
                    self.finished = true;
                    self.incoming.take();
                    self.reset.take();
                    self.driver.shutdown();
                    self.trace.finish("complete");
                    Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                }
                Poll::Ready(Ok(None)) => {
                    self.finished = true;
                    self.incoming.take();
                    self.reset.take();
                    self.driver.shutdown();
                    self.trace.finish("complete");
                    Poll::Ready(None)
                }
                Poll::Ready(Err(error)) => {
                    self.finished = true;
                    self.incoming.take();
                    self.reset.take();
                    self.driver.shutdown();
                    self.trace.finish("protocol_error");
                    Poll::Ready(Some(Err(Http2Error::Protocol(error))))
                }
                Poll::Pending => Poll::Pending,
            },
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished
            || self
                .incoming
                .as_ref()
                .is_some_and(RecvStream::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl Drop for Http2Body {
    fn drop(&mut self) {
        if !self.finished {
            if let Some(mut reset) = self.reset.take() {
                reset.send_reset(Reason::CANCEL);
            }
            self.incoming.take();
            self.trace.finish("dropped");
        }
    }
}

struct BodyTrace {
    span: Span,
    received_bytes: u64,
    finished: bool,
}

impl BodyTrace {
    fn new() -> Self {
        Self {
            span: debug_span!("http2.response_body"),
            received_bytes: 0,
            finished: false,
        }
    }

    fn add_bytes(&mut self, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.received_bytes = self.received_bytes.saturating_add(bytes);
    }

    fn finish(&mut self, outcome: &'static str) {
        if self.finished {
            return;
        }
        self.finished = true;
        debug!(
            parent: &self.span,
            body_bytes = self.received_bytes,
            outcome,
            "HTTP/2 response body finished"
        );
    }
}

/// Owns the HTTP/2 connection driver and the last request sender.
///
/// Dropping the sender asks the connection task to shut down. A supervisor
/// gives the task a fixed grace period to flush pending protocol frames, then
/// aborts a permanently stalled driver.
pub(super) struct DriverTask {
    sender: Option<client::SendRequest<Bytes>>,
    handle: Option<JoinHandle<Result<(), ::http2::Error>>>,
}

impl DriverTask {
    pub(super) fn spawn<T>(
        connection: client::Connection<T, Bytes>,
        sender: client::SendRequest<Bytes>,
    ) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            sender: Some(sender),
            handle: Some(tokio::spawn(connection)),
        }
    }

    pub(super) async fn ready(&mut self) -> Result<(), ::http2::Error> {
        let sender = self
            .sender
            .take()
            .ok_or_else(|| ::http2::Error::from(::http2::Reason::INTERNAL_ERROR))?;
        self.sender = Some(sender.ready().await?);
        Ok(())
    }

    pub(super) fn sender_mut(&mut self) -> Result<&mut client::SendRequest<Bytes>, ::http2::Error> {
        self.sender
            .as_mut()
            .ok_or_else(|| ::http2::Error::from(::http2::Reason::INTERNAL_ERROR))
    }

    pub(super) fn shutdown(&mut self) {
        self.sender.take();
        let Some(mut handle) = self.handle.take() else {
            return;
        };
        let span = debug_span!("http2.connection_driver", outcome = field::Empty);
        let instrument = span.clone();
        tokio::spawn(
            async move {
                match timeout(DRIVER_SHUTDOWN_GRACE, &mut handle).await {
                    Ok(Ok(Ok(()))) => {
                        span.record("outcome", "complete");
                        debug!(parent: &span, "HTTP/2 connection driver stopped");
                    }
                    Ok(Ok(Err(error))) => {
                        span.record("outcome", "protocol_error");
                        warn!(
                            parent: &span,
                            reason = ?error.reason(),
                            io_error = error.is_io(),
                            "HTTP/2 connection driver failed"
                        );
                    }
                    Ok(Err(_)) => {
                        span.record("outcome", "task_error");
                        warn!(parent: &span, "HTTP/2 connection driver task failed");
                    }
                    Err(_) => {
                        handle.abort();
                        let _ = handle.await;
                        span.record("outcome", "timeout");
                        warn!(parent: &span, "HTTP/2 connection driver exceeded shutdown grace");
                    }
                }
            }
            .instrument(instrument),
        );
    }
}

impl Drop for DriverTask {
    fn drop(&mut self) {
        self.shutdown();
    }
}
