use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
};

use bytes::Bytes;
use phantom_quic_btls::ApplicationState;
use tokio::{
    runtime::Handle,
    sync::{oneshot, watch},
    task::{JoinError, JoinHandle},
};
use tracing::{
    Instrument, Span, debug, debug_span, dispatcher, field, instrument::WithSubscriber, warn,
};

use crate::shutdown_timer;

type DriverResult = Result<(), h3::error::ConnectionError>;
pub(super) type ClientDriver = h3::client::Connection<super::early_streams::Transport, Bytes>;

/// The server's answer to a connection's early data, which the driver reads
/// before it polls HTTP/3.
///
/// Quinn discards every stream opened before a rejection and settles
/// `accepted` under the same connection lock (RFC 9001, section 4.6.2), so a
/// driver that checks `accepted` first never polls a discarded stream. After
/// a rejection the driver stops polling the discarded HTTP/3 session, which
/// would otherwise close the QUIC connection, and waits for its
/// `replacement`, built on the same connection.
///
/// `gate` receives the raw answer at once, so the discarded session stops
/// opening request streams before the answer is checked and published; see
/// `early_streams`. Dropping it unanswered closes the gate.
pub(super) struct EarlyAnswer {
    pub(super) accepted: quinn::ZeroRttAccepted,
    pub(super) gate: watch::Sender<Option<bool>>,
    #[cfg(test)]
    pub(super) gate_delay: Option<super::GateDelay>,
    pub(super) answer: oneshot::Sender<bool>,
    pub(super) replacement: oneshot::Receiver<ClientDriver>,
}

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
        driver: ClientDriver,
        endpoint: quinn::Endpoint,
        connection: quinn::Connection,
        early: Option<EarlyAnswer>,
        late_settings: Option<oneshot::Receiver<LateApplicationSettings>>,
        application_state: Option<ApplicationState>,
        round_trip: Option<super::RoundTripRecorder>,
    ) -> Self {
        let runtime = Handle::current();
        let dispatch = dispatcher::get_default(Clone::clone);
        let span = debug_span!("http3.connection_driver", outcome = field::Empty);
        let handle = runtime.spawn(
            drive(driver, early, late_settings, application_state)
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
                round_trip,
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

enum DriveStep {
    Closed(h3::error::ConnectionError),
    Rejected(oneshot::Receiver<ClientDriver>),
}

async fn drive(
    mut driver: ClientDriver,
    mut early: Option<EarlyAnswer>,
    mut late_settings: Option<oneshot::Receiver<LateApplicationSettings>>,
    mut application_state: Option<ApplicationState>,
) -> DriverResult {
    let error = loop {
        let step = poll_fn(|context| {
            if let Some(pending) = early.as_mut()
                && let Poll::Ready(accepted) = Pin::new(&mut pending.accepted).poll(context)
                && let Some(EarlyAnswer {
                    gate,
                    #[cfg(test)]
                    gate_delay,
                    answer,
                    replacement,
                    ..
                }) = early.take()
            {
                #[cfg(test)]
                let gate = match gate_delay {
                    Some(delay) => {
                        let delay = delay.next();
                        drop(tokio::spawn(async move {
                            tokio::time::sleep(delay).await;
                            gate.send_replace(Some(accepted));
                        }));
                        None
                    }
                    None => Some(gate),
                };
                #[cfg(not(test))]
                let gate = Some(gate);
                if let Some(gate) = gate {
                    gate.send_replace(Some(accepted));
                }
                let _ = answer.send(accepted);
                if !accepted {
                    return Poll::Ready(DriveStep::Rejected(replacement));
                }
            }
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
            let closed = driver.poll_close(context);
            // The server's control-stream SETTINGS, once received and applied,
            // go with the session tickets this connection receives, and the
            // tickets held until now are stored.
            if let Some(state) = application_state.as_ref()
                && let Some(settings) = driver.peer_settings_to_remember()
            {
                if state.store(&settings) {
                    debug!("HTTP/3 SETTINGS stored for session resumption");
                }
                application_state = None;
            }
            closed.map(DriveStep::Closed)
        })
        .await;
        match step {
            DriveStep::Closed(error) => break error,
            DriveStep::Rejected(replacement) => {
                // A replacement starts from the completed handshake, so it
                // needs no late ALPS. Without one the connection is already
                // closing, and the discarded session reports how.
                late_settings = None;
                if let Ok(replacement) = replacement.await {
                    debug!("HTTP/3 restarted on the connection after rejected early data");
                    driver = replacement;
                }
            }
        }
    };
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
    round_trip: Option<super::RoundTripRecorder>,
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

    if let Some(round_trip) = round_trip {
        round_trip.at_close(&connection);
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
