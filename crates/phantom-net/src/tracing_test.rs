use std::{
    collections::HashMap,
    future::Future,
    sync::{
        Arc, Mutex, MutexGuard, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
    task::Poll,
};

use tokio::sync::{Notify, futures::Notified};
use tracing::{
    Dispatch, Event, Metadata, Subscriber, dispatcher,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

static DYNAMIC_CALLSITE_FALLBACK: OnceLock<()> = OnceLock::new();

#[derive(Clone, Default)]
pub(crate) struct OutcomeSubscriber {
    next_span_id: Arc<AtomicU64>,
    state: Arc<Mutex<CaptureState>>,
    connection_driver_notify: Arc<Notify>,
}

#[derive(Default)]
struct CaptureState {
    span_names: HashMap<u64, &'static str>,
    span_fields: Vec<(&'static str, &'static str, String)>,
    outcomes: Vec<(&'static str, String)>,
    error_kinds: Vec<(&'static str, String)>,
    tls_versions: Vec<(&'static str, String)>,
    cipher_suites: Vec<(&'static str, String)>,
    response_body_events: Vec<(u64, String)>,
    connection_driver_events: usize,
    response_body_polls_on_origin_dispatch: usize,
}

impl OutcomeSubscriber {
    pub(crate) fn install_dynamic_callsite_fallback() {
        DYNAMIC_CALLSITE_FALLBACK.get_or_init(|| {
            let _ = tracing::subscriber::set_global_default(DynamicCallsiteFallback);
        });
    }

    pub(crate) fn outcomes_for(&self, span_name: &str) -> Vec<String> {
        self.state()
            .outcomes
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, outcome)| outcome.clone())
            .collect()
    }

    pub(crate) fn field_values_for(&self, span_name: &str, field_name: &str) -> Vec<String> {
        self.state()
            .span_fields
            .iter()
            .filter(|(name, field, _)| *name == span_name && *field == field_name)
            .map(|(_, _, value)| value.clone())
            .collect()
    }

    pub(crate) fn error_kinds_for(&self, span_name: &str) -> Vec<String> {
        self.state()
            .error_kinds
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, error_kind)| error_kind.clone())
            .collect()
    }

    pub(crate) fn tls_versions_for(&self, span_name: &str) -> Vec<String> {
        self.state()
            .tls_versions
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, version)| version.clone())
            .collect()
    }

    pub(crate) fn cipher_suites_for(&self, span_name: &str) -> Vec<String> {
        self.state()
            .cipher_suites
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, suite)| suite.clone())
            .collect()
    }

    pub(crate) fn response_body_events(&self) -> Vec<(u64, String)> {
        self.state().response_body_events.clone()
    }

    pub(crate) fn connection_driver_events(&self) -> usize {
        self.state().connection_driver_events
    }

    pub(crate) fn connection_driver_event(&self) -> Notified<'_> {
        self.connection_driver_notify.notified()
    }

    pub(crate) fn response_body_polls_on_origin_dispatch(&self) -> usize {
        self.state().response_body_polls_on_origin_dispatch
    }

    pub(crate) fn dispatch(&self) -> Dispatch {
        Self::install_dynamic_callsite_fallback();
        let dispatch = Dispatch::new(self.clone());
        tracing::callsite::rebuild_interest_cache();
        dispatch
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

pub(crate) async fn poll_once_then_drop<F>(future: F, subscriber: OutcomeSubscriber) -> bool
where
    F: Future,
{
    let dispatch = subscriber.dispatch();
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
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, _metadata: &Metadata<'_>) -> bool {
        true
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let id = self.next_span_id.fetch_add(1, Ordering::Relaxed) + 1;
        let span_name = attributes.metadata().name();
        let mut visitor = SpanFieldVisitor::default();
        attributes.record(&mut visitor);
        let mut state = self.state();
        state.span_names.insert(id, span_name);
        state.span_fields.extend(
            visitor
                .fields
                .into_iter()
                .map(|(field, value)| (span_name, field, value)),
        );
        Id::from_u64(id)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        let mut visitor = OutcomeVisitor::default();
        values.record(&mut visitor);
        if visitor.outcome.is_none()
            && visitor.error_kind.is_none()
            && visitor.tls_version.is_none()
            && visitor.cipher_suite.is_none()
        {
            return;
        }
        let mut state = self.state();
        if let Some(name) = state.span_names.get(&span.into_u64()).copied() {
            if let Some(outcome) = visitor.outcome {
                state.outcomes.push((name, outcome));
            }
            if let Some(error_kind) = visitor.error_kind {
                state.error_kinds.push((name, error_kind));
            }
            if let Some(version) = visitor.tls_version {
                state.tls_versions.push((name, version));
            }
            if let Some(suite) = visitor.cipher_suite {
                state.cipher_suites.push((name, suite));
            }
        }
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let Some(parent) = event.parent() else {
            return;
        };
        let span_name = self.state().span_names.get(&parent.into_u64()).copied();
        if matches!(
            span_name,
            Some("http1.connection_driver" | "http2.connection_driver")
        ) {
            self.state().connection_driver_events += 1;
            self.connection_driver_notify.notify_one();
            return;
        }
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

    fn enter(&self, span: &Id) {
        let span_name = self.state().span_names.get(&span.into_u64()).copied();
        if !matches!(
            span_name,
            Some("http1.response_body" | "http2.response_body")
        ) {
            return;
        }

        let uses_origin = dispatcher::get_default(|dispatch| {
            dispatch
                .downcast_ref::<Self>()
                .is_some_and(|subscriber| Arc::ptr_eq(&subscriber.state, &self.state))
        });
        if uses_origin {
            self.state().response_body_polls_on_origin_dispatch += 1;
        }
    }

    fn exit(&self, _span: &Id) {}
}

#[derive(Default)]
struct SpanFieldVisitor {
    fields: Vec<(&'static str, String)>,
}

impl Visit for SpanFieldVisitor {
    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}

    fn record_str(&mut self, field: &Field, value: &str) {
        self.fields.push((field.name(), value.to_owned()));
    }
}

#[derive(Default)]
struct OutcomeVisitor {
    outcome: Option<String>,
    error_kind: Option<String>,
    tls_version: Option<String>,
    cipher_suite: Option<String>,
}

impl Visit for OutcomeVisitor {
    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}

    fn record_str(&mut self, field: &Field, value: &str) {
        match field.name() {
            "outcome" => self.outcome = Some(value.to_owned()),
            "error_kind" => self.error_kind = Some(value.to_owned()),
            "tls_version" => self.tls_version = Some(value.to_owned()),
            "cipher_suite" => self.cipher_suite = Some(value.to_owned()),
            _ => {}
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
