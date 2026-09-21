use std::{future::Future, num::NonZeroUsize, time::Duration};

use tracing::Span;

use crate::{
    HttpProtocol, RequestError,
    timeout::{TimeoutBudget, TimeoutPhase},
};

/// Policy for retrying requests after connection-establishment failures.
///
/// Retries are disabled by default. An eligible retry occurs inside the
/// selected H1, H2, or H3 pool, or before ALPN selection in the negotiated
/// H1/H2 pool, before the origin request or body is dispatched, so methods and
/// one-shot streaming bodies are not replayed. TLS, ALPN, proxy negotiation,
/// timeouts, HTTP responses, and protocol failures are not retried.
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

    /// Retries at most `maximum` eligible connection-establishment failures.
    ///
    /// Each retry waits for `delay` before starting another connection attempt.
    /// The complete request's total timeout continues through this delay.
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

    pub(crate) fn validate(self) -> bool {
        self.maximum_connection_failures.is_none()
            || std::time::Instant::now().checked_add(self.delay).is_some()
    }
}

pub(crate) struct ConnectionSetupRetryState {
    policy: RetryPolicy,
    performed: usize,
    request_span: Span,
}

impl ConnectionSetupRetryState {
    pub(crate) fn new(policy: RetryPolicy, request_span: Span) -> Self {
        Self {
            policy,
            performed: 0,
            request_span,
        }
    }

    pub(crate) const fn performed(&self) -> usize {
        self.performed
    }

    pub(crate) async fn retry_after(
        &mut self,
        error: &RequestError,
        protocol: Option<HttpProtocol>,
        timeout_budget: TimeoutBudget,
    ) -> Result<bool, RequestError> {
        let Some(maximum) = self.policy.maximum_connection_failures else {
            return Ok(false);
        };
        if !error.is_retryable_connection_setup() || self.performed >= maximum.get() {
            return Ok(false);
        }

        self.request_span.record("retry_reason", "connection_setup");
        tracing::debug!(
            retry = self.performed + 1,
            reason = "connection_setup",
            "waiting to retry request connection setup"
        );
        timeout_budget.delay(self.policy.delay, protocol).await?;
        self.performed += 1;
        self.request_span.record(
            "retries_performed",
            u64::try_from(self.performed).unwrap_or(u64::MAX),
        );
        Ok(true)
    }
}

pub(crate) async fn acquire_with_retries<Output, Attempt, AttemptFuture>(
    protocol: HttpProtocol,
    timeout_budget: TimeoutBudget,
    retries: &mut ConnectionSetupRetryState,
    attempt: Attempt,
) -> Result<Output, RequestError>
where
    Attempt: FnMut() -> AttemptFuture,
    AttemptFuture: Future<Output = Result<Output, RequestError>>,
{
    acquire_with_retries_for(Some(protocol), timeout_budget, retries, attempt).await
}

/// Retries setup whose HTTP protocol is chosen later by ALPN.
pub(crate) async fn acquire_unselected_with_retries<Output, Attempt, AttemptFuture>(
    timeout_budget: TimeoutBudget,
    retries: &mut ConnectionSetupRetryState,
    attempt: Attempt,
) -> Result<Output, RequestError>
where
    Attempt: FnMut() -> AttemptFuture,
    AttemptFuture: Future<Output = Result<Output, RequestError>>,
{
    acquire_with_retries_for(None, timeout_budget, retries, attempt).await
}

async fn acquire_with_retries_for<Output, Attempt, AttemptFuture>(
    protocol: Option<HttpProtocol>,
    timeout_budget: TimeoutBudget,
    retries: &mut ConnectionSetupRetryState,
    mut attempt: Attempt,
) -> Result<Output, RequestError>
where
    Attempt: FnMut() -> AttemptFuture,
    AttemptFuture: Future<Output = Result<Output, RequestError>>,
{
    loop {
        // Connector futures include bounded proxy-authentication state machines.
        // Keep that backend-specific future off this request future's stack.
        let attempt = Box::pin(attempt());
        let result = timeout_budget
            .run(TimeoutPhase::Connect, protocol, attempt)
            .await;
        match result {
            Ok(output) => return Ok(output),
            Err(error)
                if retries
                    .retry_after(&error, protocol, timeout_budget)
                    .await? => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, future::pending, num::NonZeroUsize, time::Duration};

    use phantom_net::http1::Http1TlsError;
    use tracing::Span;

    use super::{ConnectionSetupRetryState, RetryPolicy, acquire_with_retries};
    use crate::{HttpProtocol, RequestError, RequestErrorKind, RequestTimeouts, TimeoutPhase};

    fn refused_connection() -> RequestError {
        RequestError::http1_connection_setup(Http1TlsError::Connect(std::io::Error::from(
            std::io::ErrorKind::ConnectionRefused,
        )))
    }

    #[test]
    fn policy_is_disabled_by_default_and_retains_explicit_bounds() {
        assert_eq!(RetryPolicy::default(), RetryPolicy::none());
        assert_eq!(RetryPolicy::none().max_connection_failures(), None);
        assert_eq!(RetryPolicy::none().delay(), Duration::ZERO);

        let maximum = NonZeroUsize::MIN;
        let delay = Duration::from_millis(25);
        let policy = RetryPolicy::connection_failures(maximum, delay);
        assert_eq!(policy.max_connection_failures(), Some(maximum));
        assert_eq!(policy.delay(), delay);
    }

    #[tokio::test]
    async fn one_retry_recovers_a_single_refused_setup() -> Result<(), RequestError> {
        let policy = RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::ZERO);
        let mut retries = ConnectionSetupRetryState::new(policy, Span::none());
        let budget = crate::timeout::TimeoutBudget::new(RequestTimeouts::default())?;
        let mut outcomes = VecDeque::from([Err(refused_connection()), Ok(7_u8)]);

        let value = acquire_with_retries(HttpProtocol::Http1, budget, &mut retries, || {
            let outcome = outcomes
                .pop_front()
                .unwrap_or_else(|| Err(refused_connection()));
            async move { outcome }
        })
        .await?;

        assert_eq!(value, 7);
        assert_eq!(retries.performed(), 1);
        assert!(outcomes.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn exhausted_budget_returns_the_last_connection_error() -> Result<(), RequestError> {
        let policy = RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::ZERO);
        let mut retries = ConnectionSetupRetryState::new(policy, Span::none());
        let budget = crate::timeout::TimeoutBudget::new(RequestTimeouts::default())?;
        let mut attempts = 0;

        let result = acquire_with_retries(HttpProtocol::Http2, budget, &mut retries, || {
            attempts += 1;
            async { Err::<(), _>(refused_connection()) }
        })
        .await;
        let error = match result {
            Err(error) => error,
            Ok(()) => return Err(refused_connection()),
        };

        assert_eq!(attempts, 2);
        assert_eq!(retries.performed(), 1);
        assert_eq!(error.kind(), RequestErrorKind::Connect);
        Ok(())
    }

    #[tokio::test]
    async fn one_retry_budget_is_shared_across_acquisition_calls() -> Result<(), RequestError> {
        let policy = RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::ZERO);
        let mut retries = ConnectionSetupRetryState::new(policy, Span::none());
        let budget = crate::timeout::TimeoutBudget::new(RequestTimeouts::default())?;
        let mut first_outcomes = VecDeque::from([Err(refused_connection()), Ok(())]);

        acquire_with_retries(HttpProtocol::Http1, budget, &mut retries, || {
            let outcome = first_outcomes
                .pop_front()
                .unwrap_or_else(|| Err(refused_connection()));
            async move { outcome }
        })
        .await?;

        let mut later_attempts = 0;
        let result = acquire_with_retries(HttpProtocol::Http2, budget, &mut retries, || {
            later_attempts += 1;
            async { Err::<(), _>(refused_connection()) }
        })
        .await;
        let error = match result {
            Err(error) => error,
            Ok(()) => return Err(refused_connection()),
        };

        assert_eq!(retries.performed(), 1);
        assert_eq!(later_attempts, 1);
        assert_eq!(error.kind(), RequestErrorKind::Connect);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn connect_timeout_is_terminal_without_consuming_retry_budget() -> Result<(), RequestError>
    {
        let policy = RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::ZERO);
        let mut retries = ConnectionSetupRetryState::new(policy, Span::none());
        let budget = crate::timeout::TimeoutBudget::new(
            RequestTimeouts::default().connect(Duration::from_millis(100)),
        )?;
        let mut attempts = 0;

        let result = acquire_with_retries(HttpProtocol::Http3, budget, &mut retries, || {
            attempts += 1;
            pending::<Result<(), RequestError>>()
        })
        .await;
        let error = match result {
            Err(error) => error,
            Ok(()) => return Err(refused_connection()),
        };

        assert_eq!(attempts, 1);
        assert_eq!(retries.performed(), 0);
        assert_eq!(error.kind(), RequestErrorKind::Timeout);
        assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Connect));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn connect_timeout_restarts_for_each_setup_attempt() -> Result<(), RequestError> {
        let policy = RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::ZERO);
        let mut retries = ConnectionSetupRetryState::new(policy, Span::none());
        let budget = crate::timeout::TimeoutBudget::new(
            RequestTimeouts::default().connect(Duration::from_millis(100)),
        )?;
        let mut attempts = 0;

        acquire_with_retries(HttpProtocol::Http2, budget, &mut retries, || {
            attempts += 1;
            let attempt = attempts;
            async move {
                tokio::time::sleep(if attempt == 1 {
                    Duration::from_millis(60)
                } else {
                    Duration::from_millis(75)
                })
                .await;
                if attempt == 1 {
                    Err(refused_connection())
                } else {
                    Ok(())
                }
            }
        })
        .await?;

        assert_eq!(attempts, 2);
        assert_eq!(retries.performed(), 1);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn retry_delay_observes_the_original_total_deadline() -> Result<(), RequestError> {
        let policy =
            RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::from_millis(200));
        let mut retries = ConnectionSetupRetryState::new(policy, Span::none());
        let budget = crate::timeout::TimeoutBudget::new(
            RequestTimeouts::default().total(Duration::from_millis(100)),
        )?;
        let mut attempts = 0;

        let result = acquire_with_retries(HttpProtocol::Http3, budget, &mut retries, || {
            attempts += 1;
            async { Err::<(), _>(refused_connection()) }
        })
        .await;
        let error = match result {
            Err(error) => error,
            Ok(()) => return Err(refused_connection()),
        };

        assert_eq!(attempts, 1);
        assert_eq!(retries.performed(), 0);
        assert_eq!(error.kind(), RequestErrorKind::Timeout);
        assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
        Ok(())
    }
}
