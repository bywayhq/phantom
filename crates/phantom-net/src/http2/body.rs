//! Streaming response-body ownership for one-shot HTTP/2 transactions.

use std::{
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use ::http2::{Reason, RecvStream, SendStream, client};
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    runtime::Handle,
    task::{JoinError, JoinHandle},
};
use tracing::{
    Dispatch, Instrument, Span, debug, debug_span, dispatcher, field, instrument::WithSubscriber,
    warn,
};

use super::{Http2Error, shutdown_timer};

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

    fn poll_frame_inner(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Http2Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }

        let Some(incoming) = self.incoming.as_mut() else {
            self.finished = true;
            self.driver.shutdown();
            self.trace.finish("protocol_error");
            return Poll::Ready(Some(Err(Http2Error::protocol(::http2::Error::from(
                ::http2::Reason::INTERNAL_ERROR,
            )))));
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
                Poll::Ready(Some(Err(Http2Error::protocol(error))))
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
                    Poll::Ready(Some(Err(Http2Error::protocol(error))))
                }
                Poll::Pending => Poll::Pending,
            },
            Poll::Pending => Poll::Pending,
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
        let span = self.trace.span.clone();
        let dispatch = self.trace.dispatch.clone();
        dispatcher::with_default(&dispatch, || {
            let _entered = span.enter();
            self.as_mut().poll_frame_inner(context)
        })
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
    dispatch: Dispatch,
    span: Span,
    received_bytes: u64,
    finished: bool,
}

impl BodyTrace {
    fn new() -> Self {
        Self {
            dispatch: dispatcher::get_default(Clone::clone),
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
        dispatcher::with_default(&self.dispatch, || {
            debug!(
                parent: &self.span,
                body_bytes = self.received_bytes,
                outcome,
                "HTTP/2 response body finished"
            );
        });
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
    runtime: Handle,
    dispatch: Dispatch,
    span: Span,
}

impl DriverTask {
    pub(super) fn spawn<T>(
        connection: client::Connection<T, Bytes>,
        sender: client::SendRequest<Bytes>,
    ) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let runtime = Handle::current();
        let dispatch = dispatcher::get_default(Clone::clone);
        let span = debug_span!("http2.connection_driver", outcome = field::Empty);
        let handle = runtime.spawn(
            connection
                .instrument(span.clone())
                .with_subscriber(dispatch.clone()),
        );
        Self {
            sender: Some(sender),
            handle: Some(handle),
            runtime,
            dispatch,
            span,
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
        let Some(handle) = self.handle.take() else {
            return;
        };
        let mut driver = AbortDriver::new(handle);
        let span = self.span.clone();
        let outcome = DriverOutcome::new(&span);
        let dispatch = self.dispatch.clone();
        self.runtime.spawn(
            async move {
                let result = wait_for_driver(&mut driver).await;
                match result {
                    DriverShutdown::Finished(Ok(Ok(()))) => {
                        outcome.finish("complete");
                        debug!(parent: &span, "HTTP/2 connection driver stopped");
                    }
                    DriverShutdown::Finished(Ok(Err(error))) => {
                        outcome.finish("protocol_error");
                        warn!(
                            parent: &span,
                            reason = ?error.reason(),
                            io_error = error.is_io(),
                            "HTTP/2 connection driver failed"
                        );
                    }
                    DriverShutdown::Finished(Err(error)) => {
                        outcome.finish("task_error");
                        warn!(
                            parent: &span,
                            cancelled = error.is_cancelled(),
                            panicked = error.is_panic(),
                            "HTTP/2 connection driver task failed"
                        );
                    }
                    DriverShutdown::TimedOut => {
                        driver.abort();
                        outcome.finish("timeout");
                        warn!(parent: &span, "HTTP/2 connection driver exceeded shutdown grace");
                    }
                    DriverShutdown::TimerFailed => {
                        driver.abort();
                        outcome.finish("task_error");
                        warn!(parent: &span, "HTTP/2 shutdown timer service failed");
                    }
                }
            }
            .with_subscriber(dispatch),
        );
    }
}

type DriverResult = Result<Result<(), ::http2::Error>, JoinError>;

enum DriverShutdown {
    Finished(DriverResult),
    TimedOut,
    TimerFailed,
}

async fn wait_for_driver(driver: &mut AbortDriver) -> DriverShutdown {
    let Ok(mut deadline) = shutdown_timer::after(DRIVER_SHUTDOWN_GRACE) else {
        return DriverShutdown::TimerFailed;
    };
    poll_fn(|context| {
        if let Poll::Ready(result) = Pin::new(driver.handle_mut()).poll(context) {
            return Poll::Ready(DriverShutdown::Finished(result));
        }
        match Pin::new(&mut deadline).poll(context) {
            Poll::Ready(Ok(())) => return Poll::Ready(DriverShutdown::TimedOut),
            Poll::Ready(Err(_)) => return Poll::Ready(DriverShutdown::TimerFailed),
            Poll::Pending => {}
        }
        Poll::Pending
    })
    .await
}

struct DriverOutcome {
    span: Span,
    recorded: bool,
}

impl DriverOutcome {
    fn new(span: &Span) -> Self {
        Self {
            span: span.clone(),
            recorded: false,
        }
    }

    fn finish(mut self, outcome: &'static str) {
        self.span.record("outcome", outcome);
        self.recorded = true;
    }
}

impl Drop for DriverOutcome {
    fn drop(&mut self) {
        if !self.recorded {
            self.span.record("outcome", "runtime_shutdown");
        }
    }
}

struct AbortDriver {
    handle: JoinHandle<Result<(), ::http2::Error>>,
}

impl AbortDriver {
    fn new(handle: JoinHandle<Result<(), ::http2::Error>>) -> Self {
        Self { handle }
    }

    fn handle_mut(&mut self) -> &mut JoinHandle<Result<(), ::http2::Error>> {
        &mut self.handle
    }

    fn abort(&self) {
        self.handle.abort();
    }
}

impl Drop for AbortDriver {
    fn drop(&mut self) {
        self.abort();
    }
}

impl Drop for DriverTask {
    fn drop(&mut self) {
        self.shutdown();
    }
}
