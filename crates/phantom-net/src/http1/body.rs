//! Streaming response-body ownership for one-shot HTTP/1.1 transactions.

use std::{
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::Empty;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    runtime::Handle,
    sync::oneshot,
    task::{JoinError, JoinHandle},
};
use tracing::{
    Dispatch, Instrument, Span, debug, debug_span, dispatcher, field, instrument::WithSubscriber,
    warn,
};
use wreq_proto::{body::Incoming, conn::http1};

use super::Http1Error;

/// Streaming response body for a one-shot HTTP/1.1 transaction.
///
/// Dropping this body signals the protocol driver's supervisor on the runtime
/// where the request originated. The supervisor then tears down the byte
/// stream. `Drop` does not wait for teardown to finish.
#[must_use = "response bodies must be read or deliberately dropped"]
pub struct Http1Body {
    incoming: Incoming,
    driver: DriverTask,
    finished: bool,
    trace: BodyTrace,
}

impl Http1Body {
    pub(super) fn new(incoming: Incoming, mut driver: DriverTask) -> Self {
        let finished = incoming.is_end_stream();
        let mut trace = BodyTrace::new();
        if finished {
            driver.finish(DriverSignal::Complete);
            trace.finish("complete");
        }
        Self {
            incoming,
            driver,
            finished,
            trace,
        }
    }
}

impl fmt::Debug for Http1Body {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http1Body")
            .field("finished", &self.finished)
            .field("received_bytes", &self.trace.received_bytes)
            .finish_non_exhaustive()
    }
}

impl Body for Http1Body {
    type Data = Bytes;
    type Error = Http1Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let dispatch = self.trace.dispatch.clone();
        let span = self.trace.span.clone();
        dispatcher::with_default(&dispatch, || {
            let _entered = span.enter();

            if self.finished {
                return Poll::Ready(None);
            }

            match Pin::new(&mut self.incoming).poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        self.trace.add_bytes(data.len());
                    }
                    if self.incoming.is_end_stream() {
                        self.finished = true;
                        self.driver.finish(DriverSignal::Complete);
                        self.trace.finish("complete");
                    }
                    Poll::Ready(Some(Ok(frame)))
                }
                Poll::Ready(Some(Err(error))) => {
                    self.finished = true;
                    self.driver.finish(DriverSignal::ProtocolError);
                    self.trace.finish("protocol_error");
                    Poll::Ready(Some(Err(Http1Error::Protocol(error))))
                }
                Poll::Ready(None) => {
                    self.finished = true;
                    self.driver.finish(DriverSignal::Complete);
                    self.trace.finish("complete");
                    Poll::Ready(None)
                }
                Poll::Pending => Poll::Pending,
            }
        })
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.incoming.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.incoming.size_hint()
    }
}

impl Drop for Http1Body {
    fn drop(&mut self) {
        if !self.finished {
            self.driver.finish(DriverSignal::Cancelled);
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
            span: debug_span!("http1.response_body"),
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
            "HTTP/1 response body finished"
        );
    }
}

/// Signals the connection driver's origin-runtime supervisor when dropped.
///
/// The supervisor owns the connection task, observes its terminal state, and
/// bounds cancellation by aborting the connection task immediately.
pub(super) struct DriverTask {
    terminal: Option<oneshot::Sender<DriverSignal>>,
}

impl DriverTask {
    pub(super) fn spawn<T>(connection: http1::Connection<T, Empty<Bytes>>) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let runtime = Handle::current();
        let dispatch = dispatcher::get_default(Clone::clone);
        let span = debug_span!("http1.connection_driver", outcome = field::Empty);
        let handle = runtime.spawn(
            connection
                .instrument(span.clone())
                .with_subscriber(dispatch),
        );
        let (terminal, terminal_signal) = oneshot::channel();
        let outcome = DriverOutcome::new(span);
        drop(runtime.spawn(supervise_driver(handle, terminal_signal, outcome)));

        Self {
            terminal: Some(terminal),
        }
    }

    fn finish(&mut self, signal: DriverSignal) {
        if let Some(terminal) = self.terminal.take() {
            let _ = terminal.send(signal);
        }
    }
}

impl Drop for DriverTask {
    fn drop(&mut self) {
        self.finish(DriverSignal::Cancelled);
    }
}

#[derive(Clone, Copy)]
enum DriverSignal {
    Complete,
    ProtocolError,
    Cancelled,
}

impl DriverSignal {
    fn outcome(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::ProtocolError => "protocol_error",
            Self::Cancelled => "cancelled",
        }
    }
}

async fn supervise_driver(
    mut handle: JoinHandle<Result<(), wreq_proto::Error>>,
    mut terminal: oneshot::Receiver<DriverSignal>,
    mut outcome: DriverOutcome,
) {
    let event = poll_fn(|context| {
        if let Poll::Ready(result) = Pin::new(&mut handle).poll(context) {
            return Poll::Ready(DriverEvent::Task(result));
        }
        Pin::new(&mut terminal)
            .poll(context)
            .map(DriverEvent::Signal)
    })
    .await;

    match event {
        DriverEvent::Task(result) => match result {
            Ok(Ok(())) => {
                let signal = terminal.await.unwrap_or(DriverSignal::Cancelled);
                outcome.finish(signal.outcome());
            }
            result => outcome.record_failure(result),
        },
        DriverEvent::Signal(signal) => {
            let signal = signal.unwrap_or(DriverSignal::Cancelled);
            handle.abort();
            outcome.record_after_signal(signal, handle.await);
        }
    }
}

enum DriverEvent {
    Task(Result<Result<(), wreq_proto::Error>, JoinError>),
    Signal(Result<DriverSignal, oneshot::error::RecvError>),
}

struct DriverOutcome {
    span: Span,
    recorded: bool,
}

impl DriverOutcome {
    fn new(span: Span) -> Self {
        Self {
            span,
            recorded: false,
        }
    }

    fn record_failure(&mut self, result: Result<Result<(), wreq_proto::Error>, JoinError>) {
        match result {
            Ok(Ok(())) => self.finish("complete"),
            Ok(Err(_error)) => self.protocol_error(),
            Err(error) => self.task_error(&error),
        }
    }

    fn record_after_signal(
        &mut self,
        signal: DriverSignal,
        result: Result<Result<(), wreq_proto::Error>, JoinError>,
    ) {
        match result {
            Ok(Err(_error)) => self.protocol_error(),
            Err(error) if error.is_panic() => self.task_error(&error),
            Ok(Ok(())) | Err(_) => {
                self.finish(signal.outcome());
                if matches!(signal, DriverSignal::Cancelled) {
                    debug!(parent: &self.span, "HTTP/1 connection driver cancelled");
                }
            }
        }
    }

    fn protocol_error(&mut self) {
        self.finish("protocol_error");
        warn!(parent: &self.span, "HTTP/1 connection driver failed");
    }

    fn task_error(&mut self, error: &JoinError) {
        self.finish("task_error");
        warn!(
            parent: &self.span,
            cancelled = error.is_cancelled(),
            panicked = error.is_panic(),
            "HTTP/1 connection driver task failed"
        );
    }

    fn finish(&mut self, outcome: &'static str) {
        if self.recorded {
            return;
        }
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
