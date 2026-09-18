use std::{num::NonZeroUsize, time::Duration};

/// Policy for retrying requests after connection-establishment failures.
///
/// Retries are disabled by default. This policy applies only to failures that
/// occur while establishing a connection; it does not retry dispatched
/// requests or protocol failures.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetryPolicy {
    maximum_connection_failures: Option<NonZeroUsize>,
    delay: Duration,
}

impl RetryPolicy {
    /// Disables connection-establishment retries.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            maximum_connection_failures: None,
            delay: Duration::ZERO,
        }
    }

    /// Retries at most `maximum` connection-establishment failures.
    ///
    /// Each retry waits for `delay` before starting another connection attempt.
    #[must_use]
    pub const fn connection_failures(maximum: NonZeroUsize, delay: Duration) -> Self {
        Self {
            maximum_connection_failures: Some(maximum),
            delay,
        }
    }

    /// Returns the maximum number of connection failures that may be retried.
    #[must_use]
    pub const fn max_connection_failures(self) -> Option<NonZeroUsize> {
        self.maximum_connection_failures
    }

    /// Returns the delay before each connection retry.
    #[must_use]
    pub const fn delay(self) -> Duration {
        self.delay
    }
}
