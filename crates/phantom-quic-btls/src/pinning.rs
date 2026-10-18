//! Pin-failure observations for one QUIC connection attempt.

use std::{
    error::Error,
    fmt,
    sync::{Arc, OnceLock},
};

/// Why the built-in leaf SPKI restriction failed after normal verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SpkiPinFailure {
    /// The verified leaf matched none of the configured pins.
    Mismatch,
    /// The backend could not complete the configured restriction.
    Backend,
}

impl fmt::Display for SpkiPinFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Mismatch => "server certificate does not match its SPKI pins",
            Self::Backend => "server SPKI verification could not complete",
        })
    }
}

impl Error for SpkiPinFailure {}

/// Captures a typed pin rejection that Quinn's transport error cannot retain.
///
/// Use a fresh capture for each connection attempt. This is an observation;
/// it grants no authority to resume a session or publish tickets.
#[derive(Clone, Debug, Default)]
pub struct SpkiPinFailureCapture(Arc<OnceLock<SpkiPinFailure>>);

impl SpkiPinFailureCapture {
    /// Returns the first pin rejection recorded by this attempt, if any.
    #[must_use]
    pub fn failure(&self) -> Option<SpkiPinFailure> {
        self.0.get().copied()
    }

    pub(crate) fn record(&self, failure: SpkiPinFailure) {
        let _ = self.0.set(failure);
    }
}
