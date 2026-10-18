use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct RetryDelay {
    pub(super) initial: Duration,
    pub(super) maximum: Option<Duration>,
    pub(super) full_jitter: bool,
}

impl RetryDelay {
    pub(super) const fn fixed(initial: Duration) -> Self {
        Self {
            initial,
            maximum: None,
            full_jitter: false,
        }
    }

    pub(super) fn validate(self, now: Instant) -> Result<(), &'static str> {
        if self.maximum.is_some_and(|maximum| maximum < self.initial) {
            return Err("retry backoff cap is below the initial retry delay");
        }
        if now.checked_add(self.initial).is_none()
            || self
                .maximum
                .is_some_and(|maximum| now.checked_add(maximum).is_none())
        {
            return Err("retry delay or backoff cap exceeds the runtime clock range");
        }
        Ok(())
    }

    pub(super) fn sample(self, completed_retries: usize) -> Duration {
        self.sample_with(completed_retries, |upper| fastrand::u128(0..=upper))
    }

    fn sample_with(self, completed_retries: usize, draw: impl FnOnce(u128) -> u128) -> Duration {
        let mut upper = self.initial;
        if let Some(maximum) = self.maximum {
            // A nonzero duration reaches Duration::MAX within 95 doublings.
            // Stop at the cap rather than iterating over an unbounded counter.
            if !upper.is_zero() {
                for _ in 0..completed_retries {
                    upper = upper.saturating_mul(2).min(maximum);
                    if upper == maximum {
                        break;
                    }
                }
            }
        }
        if !self.full_jitter || upper.is_zero() {
            return upper;
        }
        let nanos = draw(upper.as_nanos());
        // A draw bounded by Duration::as_nanos fits the seconds and nanos fields.
        Duration::new(
            (nanos / 1_000_000_000) as u64,
            (nanos % 1_000_000_000) as u32,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exponential_delays_double_then_remain_capped() {
        let delay = RetryDelay {
            initial: Duration::from_millis(100),
            maximum: Some(Duration::from_millis(750)),
            full_jitter: false,
        };
        let actual = [0, 1, 2, 3, 4, usize::MAX].map(|index| delay.sample(index));
        assert_eq!(
            actual,
            [100, 200, 400, 750, 750, 750].map(Duration::from_millis)
        );
    }

    #[test]
    fn zero_and_overflowing_exponents_remain_bounded() {
        let delay = RetryDelay {
            initial: Duration::ZERO,
            maximum: Some(Duration::MAX),
            full_jitter: false,
        };
        assert_eq!(delay.sample(usize::MAX), Duration::ZERO);
        let delay = RetryDelay {
            initial: Duration::from_nanos(1),
            ..delay
        };
        assert_eq!(delay.sample(usize::MAX), Duration::MAX);
    }

    #[test]
    fn full_jitter_includes_zero_and_preserves_subsecond_bounds() {
        let delay = RetryDelay {
            initial: Duration::new(2, 37),
            maximum: Some(Duration::new(3, 71)),
            full_jitter: true,
        };
        assert_eq!(delay.sample_with(0, |_| 0), Duration::ZERO);
        assert_eq!(delay.sample_with(0, |upper| upper), delay.initial);
        assert_eq!(delay.sample_with(1, |upper| upper), Duration::new(3, 71));
        assert_eq!(
            delay.sample_with(1, |_| 1_000_000_019),
            Duration::new(1, 19)
        );
        let fixed = RetryDelay {
            maximum: None,
            ..delay
        };
        assert_eq!(fixed.sample_with(usize::MAX, |upper| upper), delay.initial);
        let largest = RetryDelay {
            initial: Duration::MAX,
            ..fixed
        };
        assert_eq!(largest.sample_with(0, |upper| upper), Duration::MAX);
    }

    #[test]
    fn fixed_and_zero_delays_do_not_draw_randomness_when_unneeded() {
        assert_eq!(
            RetryDelay::fixed(Duration::from_nanos(5))
                .sample_with(usize::MAX, |_| panic!("fixed delay drew randomness")),
            Duration::from_nanos(5)
        );
        let zero = RetryDelay {
            full_jitter: true,
            ..RetryDelay::default()
        };
        assert_eq!(
            zero.sample_with(0, |_| panic!("zero delay drew randomness")),
            Duration::ZERO
        );
    }
}
