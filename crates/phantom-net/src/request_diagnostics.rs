//! Bounded observations of one logical HTTP request.

use std::{
    fmt,
    future::Future,
    num::NonZeroUsize,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use http::Version;

tokio::task_local! {
    static CURRENT: Option<Observation>;
}

/// Live, bounded diagnostics for one logical request.
///
/// Obtain a handle from the facade's `RequestBuilder::diagnostics`. Clones
/// observe the same request, including after a failed or cancelled send.
/// Records contain no URLs, headers, credentials or backend error strings.
#[derive(Clone)]
pub struct RequestDiagnostics(Arc<Mutex<State>>);

impl fmt::Debug for RequestDiagnostics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = self.lock();
        f.debug_struct("RequestDiagnostics")
            .field("capacity", &state.capacity)
            .field("retained_events", &state.events.len())
            .field("dropped_events", &state.dropped)
            .finish()
    }
}

/// A snapshot of request observations. Taking a snapshot does not clear them.
#[derive(Clone, Debug)]
pub struct RequestTimeline {
    /// State of the send future, independently of response body consumption.
    pub outcome: RequestTimelineOutcome,
    /// Time since the send future was first polled, or `None` before polling.
    /// After send finishes, this stops at response headers or the send error.
    pub send_elapsed: Option<Duration>,
    /// Events in start order. Overlapping intervals must not be added together.
    pub events: Vec<RequestTiming>,
    /// Events omitted because the caller's capacity was reached.
    pub dropped_events: usize,
    /// Total admitted origin attempts, including those omitted from `events`.
    /// Admission does not prove that bytes were sent.
    pub admitted_attempts: usize,
}

/// Lifecycle of the public send future.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestTimelineOutcome {
    /// The send future has not been polled.
    NotStarted,
    /// The send future is running.
    Pending,
    /// Response headers were returned. The body may still be pending.
    ResponseHead,
    /// The send future returned an error.
    Failed,
    /// A polled send future was dropped before returning.
    Cancelled,
}

/// One observed phase or admission in a request's timeline.
#[derive(Clone, Debug)]
pub struct RequestTiming {
    /// Monotonic sequence number, also assigned to omitted events.
    pub id: usize,
    /// Zero-based redirect hop.
    pub hop: usize,
    /// Origin admission number, starting at one. `None` means this work
    /// began before admission or could not be attributed to one admission.
    pub admission: Option<usize>,
    /// Protocol known when the phase began.
    pub protocol: Option<Version>,
    /// Observed operation, rather than an inferred network duration.
    pub phase: RequestTimingPhase,
    /// Offset from the first poll of the send future.
    pub started: Duration,
    /// Offset from the same origin, absent while the operation remains pending.
    pub finished: Option<Duration>,
    /// How the observed operation ended.
    pub outcome: RequestTimingOutcome,
}

/// Boundaries observed by request diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestTimingPhase {
    /// Conservative origin HTTP attempt admission, not transmission.
    AttemptAdmission,
    /// Waiting for a pool's request or stream allowance.
    PoolAdmission,
    /// Acquiring a connection: shared waits, new setup and protocol readiness.
    ConnectionAcquisition,
    /// Waiting for local address resolution, including caches and overrides.
    /// This is not the execution time of a shared or background DNS query.
    ResolutionWait,
    /// An operating-system TCP connection attempt, excluding resolution.
    TcpConnect,
    /// The initial TLS handshake future, possibly returning early for 0-RTT.
    TlsHandshake,
    /// The QUIC connection handshake future, excluding address resolution.
    QuicHandshake,
    /// Sending the request and waiting for response headers.
    SendResponseHead,
    /// Body availability through public completion, including caller delays,
    /// decoding and trailers.
    ResponseBody,
}

/// Completion state of an observed phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RequestTimingOutcome {
    /// Still running.
    Pending,
    /// The observed operation completed successfully.
    Completed,
    /// The observed operation returned an error.
    Failed,
    /// Its future was dropped before completing.
    Interrupted,
    /// An unread or partially read response body was dropped.
    Abandoned,
    /// Resolution used a cached answer, IP literal or caller override.
    Cached,
    /// Setup returned to send early data before handshake confirmation.
    EarlyData,
}

struct State {
    capacity: usize,
    started: Option<Instant>,
    send_elapsed: Option<Duration>,
    outcome: RequestTimelineOutcome,
    events: Vec<RequestTiming>,
    next_id: usize,
    dropped: usize,
    admissions: usize,
    hops: usize,
}

impl RequestDiagnostics {
    #[doc(hidden)]
    #[must_use]
    pub fn new(capacity: NonZeroUsize) -> Self {
        Self(Arc::new(Mutex::new(State {
            capacity: capacity.get(),
            started: None,
            send_elapsed: None,
            outcome: RequestTimelineOutcome::NotStarted,
            events: Vec::new(),
            next_id: 0,
            dropped: 0,
            admissions: 0,
            hops: 0,
        })))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Copies the currently retained records. Missing phases are unobserved,
    /// not zero-duration operations. Background work may finish after `send`.
    #[must_use]
    pub fn snapshot(&self) -> RequestTimeline {
        let state = self.lock();
        RequestTimeline {
            outcome: state.outcome,
            send_elapsed: state
                .send_elapsed
                .or_else(|| state.started.map(|start| start.elapsed())),
            events: state.events.clone(),
            dropped_events: state.dropped,
            admitted_attempts: state.admissions,
        }
    }

    #[doc(hidden)]
    pub async fn observe<F, T, E>(&self, operation: F) -> Result<T, E>
    where
        F: Future<Output = Result<T, E>>,
    {
        {
            let mut state = self.lock();
            state.started = Some(Instant::now());
            state.outcome = RequestTimelineOutcome::Pending;
        }
        let mut guard = SendGuard {
            diagnostics: self.clone(),
            finished: false,
        };
        let result = CURRENT
            .scope(
                Some(Observation {
                    diagnostics: self.clone(),
                    hop: 0,
                    admission: Arc::new(AtomicUsize::new(0)),
                }),
                operation,
            )
            .await;
        guard.finish(if result.is_ok() {
            RequestTimelineOutcome::ResponseHead
        } else {
            RequestTimelineOutcome::Failed
        });
        result
    }
}

struct SendGuard {
    diagnostics: RequestDiagnostics,
    finished: bool,
}
impl SendGuard {
    fn finish(&mut self, outcome: RequestTimelineOutcome) {
        let mut state = self.diagnostics.lock();
        state.send_elapsed = state.started.map(|start| start.elapsed());
        state.outcome = outcome;
        self.finished = true;
    }
}
impl Drop for SendGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.finish(RequestTimelineOutcome::Cancelled);
        }
    }
}

/// An owned observer scope, retained with futures that may be detached.
#[doc(hidden)]
#[derive(Clone, Debug)]
pub struct Observation {
    diagnostics: RequestDiagnostics,
    hop: usize,
    admission: Arc<AtomicUsize>,
}

impl Observation {
    pub fn current() -> Option<Self> {
        CURRENT.try_with(Clone::clone).ok().flatten()
    }

    #[must_use]
    pub fn capture() -> Option<Self> {
        Self::current().map(|observer| Self {
            admission: Arc::new(AtomicUsize::new(observer.admission.load(Ordering::Relaxed))),
            ..observer
        })
    }

    #[must_use]
    pub fn branch(&self) -> Self {
        Self {
            diagnostics: self.diagnostics.clone(),
            hop: self.hop,
            admission: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[must_use]
    pub fn hop(&self, hop: usize) -> Self {
        Self {
            hop,
            ..self.branch()
        }
    }

    #[must_use]
    pub fn next_hop() -> Option<Self> {
        Self::current().map(|observer| {
            let hop = {
                let mut state = observer.diagnostics.lock();
                let hop = state.hops;
                state.hops = state.hops.saturating_add(1);
                hop
            };
            observer.hop(hop)
        })
    }

    pub fn scope<F: Future>(observer: Option<Self>, future: F) -> impl Future<Output = F::Output> {
        CURRENT.scope(observer, future)
    }

    pub fn admit(protocol: Option<Version>) {
        if let Some(observer) = Self::current() {
            observer.admit_owned(protocol);
        }
    }

    pub fn admit_replay(&self) {
        // A shared TLS driver can resend several requests outside their task
        // scopes. Record each admission without changing the original scope.
        self.branch().admit_owned(None);
    }

    fn admit_owned(&self, protocol: Option<Version>) {
        let admission = {
            let mut state = self.diagnostics.lock();
            state.admissions = state.admissions.saturating_add(1);
            state.admissions
        };
        self.admission.store(admission, Ordering::Relaxed);
        let mut event = PhaseObservation::begin_with(
            self.clone(),
            RequestTimingPhase::AttemptAdmission,
            protocol,
        );
        event.finish(RequestTimingOutcome::Completed);
    }
}

/// A phase guard owns its observer, even when its future moves to another task.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct PhaseObservation {
    event: Option<(RequestDiagnostics, usize)>,
}

impl PhaseObservation {
    #[must_use]
    pub fn is_retained(&self) -> bool {
        self.event.is_some()
    }

    #[must_use]
    pub fn begin(phase: RequestTimingPhase, protocol: Option<Version>) -> Self {
        let Some(observer) = Observation::current() else {
            return Self { event: None };
        };
        Self::begin_with(observer, phase, protocol)
    }

    fn begin_with(
        observer: Observation,
        phase: RequestTimingPhase,
        protocol: Option<Version>,
    ) -> Self {
        let mut state = observer.diagnostics.lock();
        let id = state.next_id;
        state.next_id = state.next_id.saturating_add(1);
        if state.events.len() == state.capacity {
            state.dropped = state.dropped.saturating_add(1);
            return Self { event: None };
        }
        let Some(started) = state.started.map(|start| start.elapsed()) else {
            return Self { event: None };
        };
        let admission = observer.admission.load(Ordering::Relaxed);
        let index = state.events.len();
        state.events.push(RequestTiming {
            id,
            hop: observer.hop,
            admission: (admission != 0).then_some(admission),
            protocol,
            phase,
            started,
            finished: None,
            outcome: RequestTimingOutcome::Pending,
        });
        drop(state);
        Self {
            event: Some((observer.diagnostics, index)),
        }
    }

    pub fn finish(&mut self, outcome: RequestTimingOutcome) {
        if let Some((diagnostics, index)) = self.event.take() {
            let mut state = diagnostics.lock();
            let elapsed = state.started.map(|start| start.elapsed());
            if let Some(event) = state.events.get_mut(index) {
                event.finished = elapsed;
                event.outcome = outcome;
            }
        }
    }

    pub fn result<T, E>(&mut self, result: &Result<T, E>) {
        self.finish(if result.is_ok() {
            RequestTimingOutcome::Completed
        } else {
            RequestTimingOutcome::Failed
        });
    }

    pub fn nested_result<T, E, Outer>(&mut self, result: &Result<Result<T, E>, Outer>) {
        self.finish(if matches!(result, Ok(Ok(_))) {
            RequestTimingOutcome::Completed
        } else {
            RequestTimingOutcome::Failed
        });
    }

    pub async fn run<F, T, E>(
        phase: RequestTimingPhase,
        protocol: Option<Version>,
        future: F,
    ) -> Result<T, E>
    where
        F: Future<Output = Result<T, E>>,
    {
        let mut observer = Self::begin(phase, protocol);
        let result = future.await;
        observer.result(&result);
        result
    }
}

impl Drop for PhaseObservation {
    fn drop(&mut self) {
        self.finish(RequestTimingOutcome::Interrupted);
    }
}

#[cfg(test)]
mod tests;
