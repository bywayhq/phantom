//! Benchmark-only observation of HTTP/2 driver-supervisor completion.

use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::sync::oneshot;
use tracing::{
    Dispatch, Event, Metadata, Subscriber,
    field::{Field, Visit},
    metadata::LevelFilter,
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

const DRIVER_SPAN: &str = "http2.connection_driver";

pub(super) struct DriverSupervisor {
    dispatch: Dispatch,
    observer: DriverSupervisorObserver,
}

impl DriverSupervisor {
    pub(super) fn new() -> Self {
        let observer = DriverSupervisorObserver::new();
        let dispatch = Dispatch::new(observer.clone());
        Self { dispatch, observer }
    }

    pub(super) fn observe_next(&self) -> (Dispatch, DriverSupervisorFinished) {
        (self.dispatch.clone(), self.observer.observe_next_finish())
    }
}

pub(super) struct DriverSupervisorFinished(oneshot::Receiver<Option<DriverOutcome>>);

impl DriverSupervisorFinished {
    pub(super) async fn wait(self) {
        match self.0.await {
            Ok(Some(DriverOutcome::Complete)) => {}
            Ok(Some(outcome)) => {
                panic!("HTTP/2 driver supervisor recorded non-complete outcome: {outcome:?}")
            }
            Ok(None) => panic!("HTTP/2 driver supervisor closed without recording an outcome"),
            Err(_) => panic!("HTTP/2 driver supervisor ended without closing its span"),
        }
    }
}

#[derive(Clone)]
struct DriverSupervisorObserver {
    next_span_id: Arc<AtomicU64>,
    state: Arc<Mutex<ObserverState>>,
}

impl DriverSupervisorObserver {
    fn new() -> Self {
        Self {
            next_span_id: Arc::new(AtomicU64::new(0)),
            state: Arc::new(Mutex::new(ObserverState {
                spans: HashMap::new(),
                pending_finishes: VecDeque::new(),
            })),
        }
    }

    fn observe_next_finish(&self) -> DriverSupervisorFinished {
        let (finished, receiver) = oneshot::channel();
        self.state().pending_finishes.push_back(finished);
        DriverSupervisorFinished(receiver)
    }

    fn state(&self) -> MutexGuard<'_, ObserverState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

struct ObserverState {
    spans: HashMap<u64, ObservedSpan>,
    pending_finishes: VecDeque<oneshot::Sender<Option<DriverOutcome>>>,
}

struct ObservedSpan {
    references: usize,
    is_driver: bool,
    outcome: Option<DriverOutcome>,
    finished: Option<oneshot::Sender<Option<DriverOutcome>>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DriverOutcome {
    Complete,
    ProtocolError,
    TaskError,
    Timeout,
    RuntimeShutdown,
    Other,
}

impl DriverOutcome {
    fn from_str(value: &str) -> Self {
        match value {
            "complete" => Self::Complete,
            "protocol_error" => Self::ProtocolError,
            "task_error" => Self::TaskError,
            "timeout" => Self::Timeout,
            "runtime_shutdown" => Self::RuntimeShutdown,
            _ => Self::Other,
        }
    }
}

#[derive(Default)]
struct OutcomeVisitor {
    outcome: Option<DriverOutcome>,
}

impl Visit for OutcomeVisitor {
    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "outcome" {
            self.outcome = Some(DriverOutcome::from_str(value));
        }
    }
}

impl Subscriber for DriverSupervisorObserver {
    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        if self.enabled(metadata) {
            Interest::always()
        } else {
            Interest::never()
        }
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(LevelFilter::DEBUG)
    }

    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.is_span() && metadata.name() == DRIVER_SPAN
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let id = self.next_span_id.fetch_add(1, Ordering::Relaxed) + 1;
        let is_driver = attributes.metadata().name() == DRIVER_SPAN;
        let mut state = self.state();
        if is_driver {
            assert!(
                state.spans.values().all(|span| !span.is_driver),
                "HTTP/2 benchmark driver spans must run sequentially"
            );
        }
        let finished = is_driver.then(|| match state.pending_finishes.pop_front() {
            Some(finished) => finished,
            None => panic!("HTTP/2 benchmark driver span has no completion observer"),
        });
        state.spans.insert(
            id,
            ObservedSpan {
                references: 1,
                is_driver,
                outcome: None,
                finished,
            },
        );
        Id::from_u64(id)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        let mut visitor = OutcomeVisitor::default();
        values.record(&mut visitor);
        let Some(outcome) = visitor.outcome else {
            return;
        };
        if let Some(span) = self.state().spans.get_mut(&span.into_u64()) {
            span.outcome = Some(outcome);
        }
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, _event: &Event<'_>) {}

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}

    fn clone_span(&self, id: &Id) -> Id {
        if let Some(span) = self.state().spans.get_mut(&id.into_u64()) {
            span.references += 1;
        }
        id.clone()
    }

    fn try_close(&self, id: Id) -> bool {
        let mut state = self.state();
        let id = id.into_u64();
        let Some(span) = state.spans.get_mut(&id) else {
            return false;
        };
        span.references -= 1;
        if span.references != 0 {
            return false;
        }

        let span = match state.spans.remove(&id) {
            Some(span) => span,
            None => panic!("checked HTTP/2 benchmark span must remain registered"),
        };
        let is_driver = span.is_driver;
        let outcome = span.outcome;
        let finished = span.finished;
        drop(state);
        // The supervisor future owns the final driver-span handle. On the
        // benchmark's current-thread runtime, its close therefore follows all
        // supervisor work and cannot race the awakened benchmark iteration.
        if !is_driver {
            return true;
        }
        if let Some(finished) = finished {
            let _ = finished.send(outcome);
        }
        true
    }
}
