use tokio::sync::watch;
use tracing::{
    Dispatch, Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

use crate::support::{deadline::FixtureDeadline, tracing::OutcomeSubscriber};

use super::{TEST_TIMEOUT, TestResult};

/// Observes the client driver after it marks the HTTP/3 connection closing.
pub(super) struct GoawayObservation {
    received: watch::Receiver<bool>,
    dispatch: Dispatch,
}

impl GoawayObservation {
    pub(super) fn new() -> Self {
        let (observed, received) = watch::channel(false);
        let captured = OutcomeSubscriber::default();
        // Retain the fixture's dynamic-callsite fallback for concurrent tests.
        drop(captured.dispatch());
        let dispatch = Dispatch::new(Observer { captured, observed });
        tracing::callsite::rebuild_interest_cache();
        Self { received, dispatch }
    }

    pub(super) fn dispatch(&self) -> Dispatch {
        self.dispatch.clone()
    }

    pub(super) async fn wait(&mut self) -> TestResult {
        tokio::time::timeout(TEST_TIMEOUT, self.received.wait_for(|received| *received))
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new(
                    "HTTP/3 client GOAWAY observation exceeded its deadline",
                    elapsed,
                )
            })??;
        Ok(())
    }
}

struct Observer {
    captured: OutcomeSubscriber,
    observed: watch::Sender<bool>,
}

impl Subscriber for Observer {
    fn register_callsite(&self, metadata: &'static Metadata<'static>) -> Interest {
        self.captured.register_callsite(metadata)
    }

    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        self.captured.enabled(metadata)
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        self.captured.new_span(attributes)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        self.captured.record(span, values);
    }

    fn record_follows_from(&self, span: &Id, follows: &Id) {
        self.captured.record_follows_from(span, follows);
    }

    fn event(&self, event: &Event<'_>) {
        if event.metadata().target() == "h3::client::connection" {
            let mut message = GoawayMessage(false);
            event.record(&mut message);
            if message.0 {
                self.observed.send_replace(true);
            }
        }
    }

    fn enter(&self, span: &Id) {
        self.captured.enter(span);
    }

    fn exit(&self, span: &Id) {
        self.captured.exit(span);
    }
}

struct GoawayMessage(bool);

impl Visit for GoawayMessage {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}").starts_with("Server initiated graceful shutdown,");
        }
    }
}
