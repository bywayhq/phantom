//! Connection-driver lifecycle for one-shot HTTP/1.1 transactions.

use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
};

use bytes::Bytes;
use http_body_util::Empty;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    runtime::Handle,
    sync::oneshot,
    task::{JoinError, JoinHandle},
};
use tracing::{
    Instrument, Span, debug, debug_span, dispatcher, field, instrument::WithSubscriber, warn,
};
use wreq_proto::conn::http1;

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
                .with_subscriber(dispatch.clone()),
        );
        let (terminal, terminal_signal) = oneshot::channel();
        let outcome = DriverOutcome::new(span);
        let supervisor = runtime
            .spawn(supervise_driver(handle, terminal_signal, outcome).with_subscriber(dispatch));
        drop(supervisor);

        Self {
            terminal: Some(terminal),
        }
    }

    pub(super) fn finish(&mut self, signal: DriverSignal) {
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
pub(super) enum DriverSignal {
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
                outcome.record_signal(signal);
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
                self.record_signal(signal);
            }
        }
    }

    fn record_signal(&mut self, signal: DriverSignal) {
        let outcome = signal.outcome();
        self.finish(outcome);
        debug!(parent: &self.span, outcome, "HTTP/1 connection driver stopped");
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
