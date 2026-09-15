//! Benchmark-only observation of HTTP/2 driver-supervisor completion.

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

use tokio::sync::oneshot;
use tracing::{
    Dispatch, Event, Metadata, Subscriber,
    metadata::LevelFilter,
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

const DRIVER_SPAN: &str = "http2.connection_driver";

pub(super) struct DriverSupervisorFinished(oneshot::Receiver<()>);

impl DriverSupervisorFinished {
    pub(super) async fn wait(self) {
        if self.0.await.is_err() {
            panic!("HTTP/2 driver supervisor ended without closing its span");
        }
    }
}

#[derive(Clone)]
struct DriverSupervisorObserver {
    next_span_id: Arc<AtomicU64>,
    state: Arc<Mutex<ObserverState>>,
}

impl DriverSupervisorObserver {
    fn new() -> (Self, DriverSupervisorFinished) {
        let (finished, receiver) = oneshot::channel();
        (
            Self {
                next_span_id: Arc::new(AtomicU64::new(0)),
                state: Arc::new(Mutex::new(ObserverState {
                    spans: HashMap::new(),
                    finished: Some(finished),
                })),
            },
            DriverSupervisorFinished(receiver),
        )
    }

    fn state(&self) -> MutexGuard<'_, ObserverState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

pub(super) fn observe_driver_supervisor() -> (Dispatch, DriverSupervisorFinished) {
    let (observer, finished) = DriverSupervisorObserver::new();
    (Dispatch::new(observer), finished)
}

struct ObserverState {
    spans: HashMap<u64, ObservedSpan>,
    finished: Option<oneshot::Sender<()>>,
}

struct ObservedSpan {
    references: usize,
    is_driver: bool,
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
        self.state().spans.insert(
            id,
            ObservedSpan {
                references: 1,
                is_driver: attributes.metadata().name() == DRIVER_SPAN,
            },
        );
        Id::from_u64(id)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

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

        let is_driver = span.is_driver;
        state.spans.remove(&id);
        // The supervisor future owns the final driver-span handle. On the
        // benchmark's current-thread runtime, its close therefore follows all
        // supervisor work and cannot race the awakened benchmark iteration.
        if !is_driver {
            return true;
        }
        if let Some(finished) = state.finished.take() {
            let _ = finished.send(());
        }
        true
    }
}
