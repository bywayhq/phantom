use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
};

use tracing::{
    Dispatch, Event, Metadata, Subscriber, dispatcher,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
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
    response_body_events: Vec<(u64, String)>,
}

impl OutcomeSubscriber {
    pub(crate) fn outcomes_for(&self, span_name: &str) -> Vec<String> {
        self.state()
            .outcomes
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, outcome)| outcome.clone())
            .collect()
    }

    pub(crate) fn response_body_events(&self) -> Vec<(u64, String)> {
        self.state().response_body_events.clone()
    }

    fn state(&self) -> MutexGuard<'_, CaptureState> {
        match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        }
    }
}

pub(crate) async fn poll_once_then_drop<F>(future: F, subscriber: OutcomeSubscriber) -> bool
where
    F: Future,
{
    let dispatch = Dispatch::new(subscriber);
    let mut future = Box::pin(future);
    let pending = std::future::poll_fn(|context| {
        dispatcher::with_default(&dispatch, || {
            Poll::Ready(future.as_mut().poll(context).is_pending())
        })
    })
    .await;
    dispatcher::with_default(&dispatch, || drop(future));
    pending
}

impl Subscriber for OutcomeSubscriber {
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

    fn event(&self, event: &Event<'_>) {
        let Some(parent) = event.parent() else {
            return;
        };
        let span_name = self.state().span_names.get(&parent.into_u64()).copied();
        if !matches!(
            span_name,
            Some("http1.response_body" | "http2.response_body")
        ) {
            return;
        }

        let mut visitor = ResponseBodyVisitor::default();
        event.record(&mut visitor);
        if let (Some(body_bytes), Some(outcome)) = (visitor.body_bytes, visitor.outcome) {
            self.state()
                .response_body_events
                .push((body_bytes, outcome));
        }
    }

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

#[derive(Default)]
struct OutcomeVisitor {
    outcome: Option<String>,
}

impl Visit for OutcomeVisitor {
    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "outcome" {
            self.outcome = Some(value.to_owned());
        }
    }
}

#[derive(Default)]
struct ResponseBodyVisitor {
    body_bytes: Option<u64>,
    outcome: Option<String>,
}

impl Visit for ResponseBodyVisitor {
    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "body_bytes" {
            self.body_bytes = Some(value);
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "outcome" {
            self.outcome = Some(value.to_owned());
        }
    }
}
