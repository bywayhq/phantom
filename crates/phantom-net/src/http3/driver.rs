use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
};

use bytes::Bytes;
use tokio::{
    runtime::Handle,
    sync::oneshot,
    task::{JoinError, JoinHandle},
};
use tracing::{
    Instrument, Span, debug, debug_span, dispatcher, field, instrument::WithSubscriber, warn,
};

use crate::shutdown_timer;

type DriverResult = Result<(), h3::error::ConnectionError>;

/// Peer ALPS that reached an early-data connection after its HTTP/3 driver
/// started, and the channel that reports whether the driver applied it.
pub(super) struct LateApplicationSettings {
    pub(super) payload: Vec<u8>,
    pub(super) applied: oneshot::Sender<Result<(), h3::error::ConnectionError>>,
}

pub(super) struct DriverTask {
    terminal: Option<oneshot::Sender<DriverSignal>>,
}

impl DriverTask {
    pub(super) fn spawn(
        driver: h3::client::Connection<h3_quinn::Connection, Bytes>,
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        late_settings: Option<oneshot::Receiver<LateApplicationSettings>>,
    ) -> Self {
        let runtime = Handle::current();
        let dispatch = dispatcher::get_default(Clone::clone);
        let span = debug_span!("http3.connection_driver", outcome = field::Empty);
        let handle = runtime.spawn(
            drive(driver, late_settings)
                .instrument(span.clone())
                .with_subscriber(dispatch.clone()),
        );
        let (terminal, terminal_signal) = oneshot::channel();
        let supervisor = runtime.spawn(
            supervise_driver(
                handle,
                terminal_signal,
                endpoint,
                connection,
                DriverOutcome::new(span),
            )
            .with_subscriber(dispatch),
        );
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
    pub(super) const fn rank(self) -> u8 {
        match self {
            Self::Complete => 0,
            Self::Cancelled => 1,
            Self::ProtocolError => 2,
        }
    }

    pub(super) const fn from_rank(rank: u8) -> Self {
        match rank {
            0 => Self::Complete,
            1 => Self::Cancelled,
            _ => Self::ProtocolError,
        }
    }

    const fn outcome(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::ProtocolError => "protocol_error",
            Self::Cancelled => "cancelled",
        }
    }
}

async fn drive(
    mut driver: h3::client::Connection<h3_quinn::Connection, Bytes>,
    mut late_settings: Option<oneshot::Receiver<LateApplicationSettings>>,
) -> DriverResult {
    let error = poll_fn(|context| {
        // The driver owns the HTTP/3 connection state, so peer ALPS that
        // arrives after it started is applied here, between polls.
        if let Some(receiver) = late_settings.as_mut()
            && let Poll::Ready(received) = Pin::new(receiver).poll(context)
        {
            late_settings = None;
            if let Ok(LateApplicationSettings { payload, applied }) = received {
                let _ = applied.send(driver.apply_peer_application_settings(&payload));
            }
        }
        driver.poll_close(context)
    })
    .await;
    if error.is_h3_no_error() {
        Ok(())
    } else {
        Err(error)
    }
}

async fn supervise_driver(
    mut handle: JoinHandle<DriverResult>,
    mut terminal: oneshot::Receiver<DriverSignal>,
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
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
        DriverEvent::Task(result) => {
            let signal = terminal.await.unwrap_or(DriverSignal::Cancelled);
            outcome.record_task(result, signal);
        }
        DriverEvent::Signal(signal) => {
            let signal = signal.unwrap_or(DriverSignal::Cancelled);
            match wait_for_driver(&mut handle).await {
                DriverShutdown::Finished(result) => outcome.record_task(result, signal),
                DriverShutdown::TimedOut => {
                    connection.close(quinn::VarInt::from_u32(0), b"");
                    handle.abort();
                    let _ = handle.await;
                    outcome.finish("timeout");
                    warn!("HTTP/3 connection driver exceeded shutdown grace");
                }
                DriverShutdown::TimerFailed => {
                    connection.close(quinn::VarInt::from_u32(0), b"");
                    handle.abort();
                    let _ = handle.await;
                    outcome.finish("task_error");
                    warn!("HTTP/3 shutdown timer service failed");
                }
            }
        }
    }

    endpoint.close(quinn::VarInt::from_u32(0), b"");
    let _ = wait_for_idle(&endpoint).await;
}

enum DriverEvent {
    Task(Result<DriverResult, JoinError>),
    Signal(Result<DriverSignal, oneshot::error::RecvError>),
}

enum DriverShutdown {
    Finished(Result<DriverResult, JoinError>),
    TimedOut,
    TimerFailed,
}

async fn wait_for_driver(handle: &mut JoinHandle<DriverResult>) -> DriverShutdown {
    let Ok(mut deadline) = shutdown_timer::after(super::SHUTDOWN_GRACE) else {
        return DriverShutdown::TimerFailed;
    };
    poll_fn(|context| {
        if let Poll::Ready(result) = Pin::new(&mut *handle).poll(context) {
            return Poll::Ready(DriverShutdown::Finished(result));
        }
        match Pin::new(&mut deadline).poll(context) {
            Poll::Ready(Ok(())) => Poll::Ready(DriverShutdown::TimedOut),
            Poll::Ready(Err(_)) => Poll::Ready(DriverShutdown::TimerFailed),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

async fn wait_for_idle(endpoint: &quinn::Endpoint) -> bool {
    let Ok(mut deadline) = shutdown_timer::after(super::SHUTDOWN_GRACE) else {
        return false;
    };
    let mut idle = Box::pin(endpoint.wait_idle());
    poll_fn(|context| {
        if Pin::new(&mut idle).poll(context).is_ready() {
            return Poll::Ready(true);
        }
        match Pin::new(&mut deadline).poll(context) {
            Poll::Ready(_) => Poll::Ready(false),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
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

    fn record_task(&mut self, result: Result<DriverResult, JoinError>, signal: DriverSignal) {
        match result {
            Ok(Ok(())) => self.finish(signal.outcome()),
            Ok(Err(error)) => {
                debug!(
                    parent: &self.span,
                    error = %error,
                    "HTTP/3 connection driver stopped with a protocol error"
                );
                self.finish("protocol_error");
            }
            Err(error) if error.is_panic() => self.finish("task_error"),
            Err(_) => self.finish(signal.outcome()),
        }
        debug!(parent: &self.span, "HTTP/3 connection driver stopped");
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
