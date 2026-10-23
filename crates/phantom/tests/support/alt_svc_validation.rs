//! Observe authenticated Alt-Svc publication before sending a dependent request.

use tokio::sync::watch;
use tracing::{
    Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

use super::tls::TestResult;

#[derive(Clone, Copy, Default)]
pub(crate) struct ValidationProgress {
    pub(crate) validated: usize,
    pub(crate) cancelled: usize,
}

#[derive(Clone)]
pub(crate) struct ValidationObservation {
    pub(crate) state: watch::Sender<ValidationProgress>,
}

impl ValidationObservation {
    pub(crate) fn new() -> Self {
        Self {
            state: watch::channel(ValidationProgress::default()).0,
        }
    }

    pub(crate) async fn validated(&self) -> TestResult<()> {
        let mut events = self.state.subscribe();
        events.wait_for(|seen| seen.validated == 1).await?;
        Ok(())
    }
}

impl Subscriber for ValidationObservation {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::always()
    }
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut fields = ValidationFields::default();
        event.record(&mut fields);
        if fields.message == "Alt-Svc validation finished" && fields.validated {
            self.state.send_modify(|seen| seen.validated += 1);
        } else if fields.message == "Alt-Svc validation task ended" && fields.cancelled {
            self.state.send_modify(|seen| seen.cancelled += 1);
        }
    }
}

#[derive(Default)]
struct ValidationFields {
    message: String,
    validated: bool,
    cancelled: bool,
}

impl Visit for ValidationFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "outcome" {
            self.validated = value == "validated";
        }
        if field.name() == "message" {
            self.message = value.to_owned();
        }
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        if field.name() == "cancelled" {
            self.cancelled = value;
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
}
