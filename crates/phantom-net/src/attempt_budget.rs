//! Shared admission for origin HTTP attempts.

use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

/// A shared, optional allowance for origin HTTP attempts.
///
/// Clone this handle across requests, clients, or threads to share one counter.
/// Initial attempts, redirects and resends each consume one admission. An
/// admission is conservative: setup, cancellation or a local failure may prevent
/// it from sending bytes. Admissions are never refunded.
///
/// DNS, connection setup, proxy negotiation and transport packet retransmissions
/// are not separate origin HTTP attempts. A budget does not enable retries or
/// make an otherwise unsafe request replayable.
#[derive(Clone, Debug)]
pub struct HttpAttemptBudget {
    remaining: Arc<AtomicUsize>,
}

impl HttpAttemptBudget {
    /// Creates an allowance of `maximum` attempts. Zero denies every attempt.
    #[must_use]
    pub fn new(maximum: usize) -> Self {
        Self {
            remaining: Arc::new(AtomicUsize::new(maximum)),
        }
    }

    /// Returns a snapshot of the remaining allowance, not a reservation.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.remaining.load(Ordering::Relaxed)
    }

    /// Admits one attempt atomically or reports exhaustion without spending.
    ///
    /// Use this for attempts made outside Phantom's public client. Requests
    /// carrying this budget are admitted by the client already; do not charge
    /// them a second time here. An external resend should reuse the same handle.
    pub fn try_admit(&self) -> Result<(), HttpAttemptBudgetExhausted> {
        let mut remaining = self.remaining();
        loop {
            let next = remaining.checked_sub(1).ok_or(HttpAttemptBudgetExhausted)?;
            match self.remaining.compare_exchange_weak(
                remaining,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(current) => remaining = current,
            }
        }
    }
}

/// The shared origin HTTP attempt allowance has no admissions left.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpAttemptBudgetExhausted;

impl fmt::Display for HttpAttemptBudgetExhausted {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("shared HTTP attempt budget exhausted")
    }
}

impl Error for HttpAttemptBudgetExhausted {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn concurrent_clones_cannot_overspend() {
        let budget = HttpAttemptBudget::new(137);
        let admitted = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            for _ in 0..16 {
                let budget = budget.clone();
                let admitted = &admitted;
                scope.spawn(move || {
                    while budget.try_admit().is_ok() {
                        admitted.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
        });
        assert_eq!(admitted.load(Ordering::Relaxed), 137);
        assert_eq!(budget.remaining(), 0);
        assert_eq!(budget.try_admit(), Err(HttpAttemptBudgetExhausted));
    }

    #[test]
    fn independent_and_zero_budgets_are_isolated() -> Result<(), HttpAttemptBudgetExhausted> {
        let zero = HttpAttemptBudget::new(0);
        let other = HttpAttemptBudget::new(1);
        assert_eq!(zero.try_admit(), Err(HttpAttemptBudgetExhausted));
        other.try_admit()?;
        assert_eq!(other.remaining(), 0);
        assert_eq!(other.try_admit(), Err(HttpAttemptBudgetExhausted));
        Ok(())
    }
}
