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
    error_kinds: Vec<(&'static str, String)>,
    selected_protocols: Vec<(&'static str, String)>,
    proxy_authentication_retries: Vec<(&'static str, bool)>,
    refused_stream_retries: Vec<(&'static str, bool)>,
    proxy_attempts: Vec<(&'static str, u64)>,
    retries_performed: Vec<(&'static str, u64)>,
    retry_reasons: Vec<(&'static str, String)>,
    reused_connection_replays: Vec<(&'static str, u64)>,
    unprocessed_replays: Vec<(&'static str, u64)>,
    status_retries: Vec<(&'static str, u64)>,
    early_data: Vec<(&'static str, String)>,
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

    #[allow(dead_code)]
    pub(crate) fn outcomes_for(&self, span_name: &str) -> Vec<String> {
        self.state()
            .outcomes
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, outcome)| outcome.clone())
            .collect()
    }

    #[allow(dead_code)]
    pub(crate) fn error_kinds_for(&self, span_name: &str) -> Vec<String> {
        self.state()
            .error_kinds
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, error_kind)| error_kind.clone())
            .collect()
    }

    #[allow(dead_code)]
    pub(crate) fn selected_protocols_for(&self, span_name: &str) -> Vec<String> {
        self.state()
            .selected_protocols
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, protocol)| protocol.clone())
            .collect()
    }

    #[allow(dead_code)]
    pub(crate) fn proxy_authentication_retries_for(&self, span_name: &str) -> Vec<bool> {
        self.state()
            .proxy_authentication_retries
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, retried)| *retried)
            .collect()
    }

    /// Whether each `websocket.connect` span reopened a refused extended
    /// CONNECT stream. Empty when no span recorded the field, which is what
    /// a connect that never reopened looks like.
    #[allow(dead_code)]
    pub(crate) fn refused_stream_retries_for(&self, span_name: &str) -> Vec<bool> {
        self.state()
            .refused_stream_retries
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, retried)| *retried)
            .collect()
    }

    #[allow(dead_code)]
    pub(crate) fn proxy_attempts_for(&self, span_name: &str) -> Vec<u64> {
        self.state()
            .proxy_attempts
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, attempts)| *attempts)
            .collect()
    }

    #[allow(dead_code)]
    pub(crate) fn retries_performed_for(&self, span_name: &str) -> Vec<u64> {
        self.state()
            .retries_performed
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, retries)| *retries)
            .collect()
    }

    #[allow(dead_code)]
    pub(crate) fn retry_reasons_for(&self, span_name: &str) -> Vec<String> {
        self.state()
            .retry_reasons
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, reason)| reason.clone())
            .collect()
    }

    #[allow(dead_code)]
    pub(crate) fn reused_connection_replays_for(&self, span_name: &str) -> Vec<u64> {
        self.state()
            .reused_connection_replays
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, replays)| *replays)
            .collect()
    }

    #[allow(dead_code)]
    pub(crate) fn unprocessed_replays_for(&self, span_name: &str) -> Vec<u64> {
        self.state()
            .unprocessed_replays
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, replays)| *replays)
            .collect()
    }

    #[allow(dead_code)]
    pub(crate) fn status_retries_for(&self, span_name: &str) -> Vec<u64> {
        self.state()
            .status_retries
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, retries)| *retries)
            .collect()
    }

    /// The `early_data` field of each span of this name, in recording order.
    #[allow(dead_code)]
    pub(crate) fn early_data_for(&self, span_name: &str) -> Vec<String> {
        self.state()
            .early_data
            .iter()
            .filter(|(name, _)| *name == span_name)
            .map(|(_, early_data)| early_data.clone())
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
        let name = attributes.metadata().name();
        let mut visitor = EarlyDataVisitor::default();
        attributes.record(&mut visitor);
        let mut state = self.state();
        state.span_names.insert(id, name);
        if let Some(early_data) = visitor.early_data {
            state.early_data.push((name, early_data));
        }
        Id::from_u64(id)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        // `early_data` is recorded once an HTTP/3 request stream opens.
        let mut early = EarlyDataVisitor::default();
        values.record(&mut early);
        if let Some(early_data) = early.early_data {
            let mut state = self.state();
            if let Some(name) = state.span_names.get(&span.into_u64()).copied() {
                state.early_data.push((name, early_data));
            }
        }
        let mut visitor = OutcomeVisitor::default();
        values.record(&mut visitor);
        if visitor.outcome.is_none()
            && visitor.error_kind.is_none()
            && visitor.selected_protocol.is_none()
            && visitor.proxy_authentication_retry.is_none()
            && visitor.refused_stream_retry.is_none()
            && visitor.proxy_attempts.is_none()
            && visitor.retries_performed.is_none()
            && visitor.retry_reason.is_none()
            && visitor.reused_connection_replays.is_none()
            && visitor.unprocessed_replays.is_none()
            && visitor.status_retries.is_none()
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
            if let Some(protocol) = visitor.selected_protocol {
                state.selected_protocols.push((name, protocol));
            }
            if let Some(retried) = visitor.proxy_authentication_retry {
                state.proxy_authentication_retries.push((name, retried));
            }
            if let Some(retried) = visitor.refused_stream_retry {
                state.refused_stream_retries.push((name, retried));
            }
            if let Some(attempts) = visitor.proxy_attempts {
                state.proxy_attempts.push((name, attempts));
            }
            if let Some(retries) = visitor.retries_performed {
                state.retries_performed.push((name, retries));
            }
            if let Some(reason) = visitor.retry_reason {
                state.retry_reasons.push((name, reason));
            }
            if let Some(replays) = visitor.reused_connection_replays {
                state.reused_connection_replays.push((name, replays));
            }
            if let Some(replays) = visitor.unprocessed_replays {
                state.unprocessed_replays.push((name, replays));
            }
            if let Some(retries) = visitor.status_retries {
                state.status_retries.push((name, retries));
            }
        }
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, _event: &Event<'_>) {}

    fn enter(&self, _span: &Id) {}

    fn exit(&self, _span: &Id) {}
}

/// Reads the `early_data` field an HTTP/3 request span is created with.
#[derive(Default)]
struct EarlyDataVisitor {
    early_data: Option<String>,
}

impl Visit for EarlyDataVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "early_data" {
            self.early_data = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, _field: &Field, _value: &dyn std::fmt::Debug) {}
}

#[derive(Default)]
struct OutcomeVisitor {
    outcome: Option<String>,
    error_kind: Option<String>,
    selected_protocol: Option<String>,
    proxy_authentication_retry: Option<bool>,
    refused_stream_retry: Option<bool>,
    proxy_attempts: Option<u64>,
    retries_performed: Option<u64>,
    retry_reason: Option<String>,
    reused_connection_replays: Option<u64>,
    unprocessed_replays: Option<u64>,
    status_retries: Option<u64>,
}

impl Visit for OutcomeVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "outcome" {
            self.outcome = Some(value.to_owned());
        } else if field.name() == "selected_protocol" {
            self.selected_protocol = Some(value.to_owned());
        } else if field.name() == "retry_reason" {
            self.retry_reason = Some(value.to_owned());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "error_kind" {
            self.error_kind = Some(format!("{value:?}"));
        }
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        if field.name() == "proxy_authentication_retry" {
            self.proxy_authentication_retry = Some(value);
        } else if field.name() == "refused_stream_retry" {
            self.refused_stream_retry = Some(value);
        }
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        if field.name() == "proxy_attempts" {
            self.proxy_attempts = Some(value);
        } else if field.name() == "retries_performed" {
            self.retries_performed = Some(value);
        } else if field.name() == "reused_connection_replays" {
            self.reused_connection_replays = Some(value);
        } else if field.name() == "unprocessed_replays" {
            self.unprocessed_replays = Some(value);
        } else if field.name() == "status_retries" {
            self.status_retries = Some(value);
        }
    }
}
