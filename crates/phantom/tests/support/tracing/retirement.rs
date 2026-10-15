//! Client-side retirement observed by one fixture-owned dispatcher.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use tokio::sync::Notify;
use tracing::{
    Event,
    field::{Field, Visit},
};

#[derive(Clone, Default)]
pub(super) struct ServerRetirement {
    seen: Arc<AtomicBool>,
    ready: Arc<Notify>,
}

impl ServerRetirement {
    pub(super) fn event(&self, event: &Event<'_>) {
        if event.metadata().target() != "h3::client::connection" {
            return;
        }
        let mut message = RetirementMessage::default();
        event.record(&mut message);
        if message.matches {
            // The pinned client emits this only after process_goaway sets
            // the same closing state consulted by connection reuse.
            self.seen.store(true, Ordering::Release);
            self.ready.notify_waiters();
        }
    }

    pub(super) async fn observed(&self) {
        loop {
            let ready = self.ready.notified();
            tokio::pin!(ready);
            ready.as_mut().enable();
            if self.seen.load(Ordering::Acquire) {
                return;
            }
            ready.await;
        }
    }
}

#[derive(Default)]
struct RetirementMessage {
    matches: bool,
}

impl Visit for RetirementMessage {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let value = format!("{value:?}");
            self.matches = value
                .strip_prefix("Server initiated graceful shutdown, last: StreamId(")
                .and_then(|id| id.strip_suffix(')'))
                .and_then(|id| id.parse::<u64>().ok())
                .is_some_and(|id| id % 4 == 0);
        }
    }
}
