//! Checked handshake publication for one current alternative mapping.

use std::{
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::sync::watch;

use super::early_data::EarlyDataOutcome;

/// Records checked, authenticated HTTP/3 setup for an alternative mapping.
///
/// New values start unconfirmed. Register a value with the originating
/// [`super::Http3Connector`] and connection. Clones share the same monotonic
/// result. Confirmation records past setup, independent of later connection
/// health. It does not identify a mapping or select a route on its own.
#[derive(Clone, Default)]
pub struct Http3MappingConfirmation {
    confirmed: Arc<AtomicBool>,
}

impl Http3MappingConfirmation {
    /// Creates an unconfirmed mapping value.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns whether an authenticated connection completed checked H3 setup.
    #[must_use]
    pub fn is_confirmed(&self) -> bool {
        self.confirmed.load(Ordering::Acquire)
    }

    pub(super) fn confirm(&self) {
        self.confirmed.store(true, Ordering::Release);
    }
}

impl fmt::Debug for Http3MappingConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http3MappingConfirmation")
            .field("is_confirmed", &self.is_confirmed())
            .finish()
    }
}

/// One replaceable destination, shared by a connection and its checked answer.
#[derive(Default)]
pub(super) struct MappingPublication {
    pending: Mutex<Option<Weak<AtomicBool>>>,
}

impl MappingPublication {
    pub(super) fn register(
        &self,
        confirmation: &Http3MappingConfirmation,
        outcome: &watch::Receiver<Option<EarlyDataOutcome>>,
    ) -> bool {
        let mut pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        // Read settlement while holding the slot. Completion publishes before
        // taking this lock, so registration cannot miss both publication paths.
        let settled = *outcome.borrow();
        let settled = settled.or_else(|| {
            outcome
                .has_changed()
                .is_err()
                .then_some(EarlyDataOutcome::Failed)
        });
        match settled {
            Some(EarlyDataOutcome::Accepted | EarlyDataOutcome::Rejected) => {
                *pending = None;
                confirmation.confirm();
                true
            }
            Some(EarlyDataOutcome::Invalid(_) | EarlyDataOutcome::Failed) => {
                *pending = None;
                false
            }
            None => {
                *pending = Some(Arc::downgrade(&confirmation.confirmed));
                true
            }
        }
    }

    pub(super) fn complete(&self, outcome: EarlyDataOutcome) {
        let pending = self
            .pending
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
        if matches!(
            outcome,
            EarlyDataOutcome::Accepted | EarlyDataOutcome::Rejected
        ) && let Some(confirmed) = pending.and_then(|pending| pending.upgrade())
        {
            confirmed.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::{Http3MappingConfirmation, MappingPublication};

    #[test]
    fn new_and_default_are_unconfirmed_and_clones_share_confirmation() {
        let confirmation = Http3MappingConfirmation::new();
        let clone = confirmation.clone();
        assert!(!confirmation.is_confirmed());
        assert!(!Http3MappingConfirmation::default().is_confirmed());
        assert_eq!(
            format!("{confirmation:?}"),
            "Http3MappingConfirmation { is_confirmed: false }"
        );

        clone.confirm();
        assert!(confirmation.is_confirmed());
        assert_eq!(
            format!("{confirmation:#?}"),
            "Http3MappingConfirmation {\n    is_confirmed: true,\n}"
        );
    }

    #[test]
    fn pending_registration_does_not_keep_the_destination_alive() {
        let publication = MappingPublication::default();
        let (_sender, outcome) = tokio::sync::watch::channel(None);
        let confirmation = Http3MappingConfirmation::new();
        let weak = Arc::downgrade(&confirmation.confirmed);
        assert!(publication.register(&confirmation, &outcome));
        assert_eq!(Arc::strong_count(&confirmation.confirmed), 1);

        drop(confirmation);
        assert!(weak.upgrade().is_none());
        publication.complete(super::EarlyDataOutcome::Accepted);
        assert!(weak.upgrade().is_none());
    }
}
