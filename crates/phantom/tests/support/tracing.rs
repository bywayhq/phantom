use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};

static DYNAMIC_CALLSITE_FALLBACK: OnceLock<()> = OnceLock::new();

use tracing::{
    Dispatch, Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

#[derive(Clone, Default)]
pub(crate) struct OutcomeSubscriber {
    next_span_id: Arc<AtomicU64>,
    state: Arc<Mutex<CaptureState>>,
}

#[derive(Default)]
struct CaptureState {
    span_names: HashMap<u64, &'static str>,
    outcomes: Vec<(&'static str, String)>,
}

impl OutcomeSubscriber {
    pub(crate) fn dispatch(&self) -> Dispatch {
        DYNAMIC_CALLSITE_FALLBACK.get_or_init(|| {
            let _ = tracing::subscriber::set_global_default(DynamicCallsiteFallback);
        });
        let dispatch = Dispatch::new(self.clone());
        tracing::callsite::rebuild_interest_cache();
        dispatch
    }

    pub(crate) fn outcomes_for(&self, span_name: &str) -> Vec<String> {
        self.state()
            .outcomes
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, outcome)| outcome.clone())
            .collect()
    }

    fn state(&self) -> MutexGuard<'_, CaptureState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

struct DynamicCallsiteFallback;

impl Subscriber for DynamicCallsiteFallback {
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _attributes: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _span: &Id, _values: &Record<'_>) {}

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, _event: &Event<'_>) {}

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

impl Subscriber for OutcomeSubscriber {
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::always()
    }

    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let id = self.next_span_id.fetch_add(1, Ordering::Relaxed) + 1;
        self.state()
            .span_names
            .insert(id, attributes.metadata().name());
        Id::from_u64(id)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        let mut visitor = OutcomeVisitor::default();
        values.record(&mut visitor);
        let Some(outcome) = visitor.outcome else {
            return;
        };
        let mut state = self.state();
        if let Some(name) = state.span_names.get(&span.into_u64()).copied() {
            state.outcomes.push((name, outcome));
        }
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, _event: &Event<'_>) {}

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

#[derive(Default)]
struct OutcomeVisitor {
    outcome: Option<String>,
}

impl Visit for OutcomeVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "outcome" {
            self.outcome = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
}
