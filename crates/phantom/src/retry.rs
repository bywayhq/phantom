use std::{future::Future, num::NonZeroUsize, time::Duration};

use tracing::Span;

use crate::{
    HttpProtocol, RequestError,
    timeout::{TimeoutBudget, TimeoutPhase},
};

/// Policy for retrying requests after connection failures.
///
/// Retries are disabled by default. An eligible connection-setup retry occurs
/// inside the selected H1, H2, or H3 pool, or before ALPN selection in the
/// negotiated H1/H2 pool, before the origin request or body is dispatched, so
/// methods and one-shot streaming bodies are not replayed. TLS, ALPN, proxy
/// negotiation, timeouts, HTTP responses, and protocol failures are not
/// retried.
///
/// [`with_reused_connection_replay`](Self::with_reused_connection_replay)
/// separately opts into the one post-dispatch replay class: an idempotent
/// HTTP/1.1 request whose reused keep-alive connection closed before any
/// response byte.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetryPolicy {
    maximum_connection_failures: Option<NonZeroUsize>,
    delay: Duration,
    reused_connection_replay: bool,
}

impl RetryPolicy {
    /// Disables connection-setup retries and reused-connection replay.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            maximum_connection_failures: None,
            delay: Duration::ZERO,
            reused_connection_replay: false,
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
            reused_connection_replay: false,
        }
    }

    /// Sets whether a request is replayed after its reused HTTP/1.1
    /// connection closes before any response byte.
    ///
    /// When enabled, an exact or negotiated HTTP/1.1 request is sent once
    /// more on a fresh connection over the same route when all of these hold:
    /// it was written to a keep-alive connection that had already delivered a
    /// response, that connection closed or was reset before any byte of the
    /// new response arrived, the method is idempotent (RFC 9110, section
    /// 9.2.2), and the body is absent or owned bytes. A one-shot streaming
    /// body, a fresh connection, or a failure after any response byte returns
    /// the original error. At most one replay occurs per redirect hop, without
    /// a delay, and it does not consume the connection-setup retry budget.
    #[must_use]
    pub const fn with_reused_connection_replay(self, enabled: bool) -> Self {
        Self {
            reused_connection_replay: enabled,
            ..self
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

    /// Returns whether reused-connection replay is enabled.
    #[must_use]
    pub const fn reused_connection_replay(self) -> bool {
        self.reused_connection_replay
    }

    pub(crate) fn validate(self) -> bool {
        self.maximum_connection_failures.is_none()
            || std::time::Instant::now().checked_add(self.delay).is_some()
    }
}

/// Request-scoped retry accounting that spans every redirect hop.
pub(crate) struct ConnectionSetupRetryState {
    policy: RetryPolicy,
    performed: usize,
    reused_connection_replays: usize,
    request_span: Span,
}

impl ConnectionSetupRetryState {
    pub(crate) fn new(policy: RetryPolicy, request_span: Span) -> Self {
        Self {
            policy,
            performed: 0,
            reused_connection_replays: 0,
            request_span,
        }
    }

    /// Returns connection-setup retries only; replays are counted separately.
    pub(crate) const fn performed(&self) -> usize {
        self.performed
    }

    pub(crate) const fn replays_reused_connections(&self) -> bool {
        self.policy.reused_connection_replay
    }

    /// Counts one reused-connection replay without touching the setup budget.
    pub(crate) fn record_reused_connection_replay(&mut self) {
        self.reused_connection_replays += 1;
        self.request_span.record(
            "reused_connection_replays",
            u64::try_from(self.reused_connection_replays).unwrap_or(u64::MAX),
        );
        tracing::debug!(
            replay = self.reused_connection_replays,
            reason = "reused_connection_closed",
            "replaying request on a fresh HTTP/1.1 connection"
        );
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
        assert!(!policy.reused_connection_replay());
    }

    #[test]
    fn reused_connection_replay_is_independent_of_setup_retries() {
        let replay_only = RetryPolicy::none().with_reused_connection_replay(true);
        assert!(replay_only.reused_connection_replay());
        assert_eq!(replay_only.max_connection_failures(), None);
        assert!(!RetryPolicy::default().reused_connection_replay());

        let maximum = NonZeroUsize::MIN;
        let delay = Duration::from_millis(25);
        let combined =
            RetryPolicy::connection_failures(maximum, delay).with_reused_connection_replay(true);
        assert_eq!(combined.max_connection_failures(), Some(maximum));
        assert_eq!(combined.delay(), delay);
        assert!(combined.reused_connection_replay());
        assert!(
            !combined
                .with_reused_connection_replay(false)
                .reused_connection_replay()
        );
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
