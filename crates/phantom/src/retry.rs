use std::{error::Error as StdError, fmt, future::Future, num::NonZeroUsize, time::Duration};

use http::{HeaderMap, StatusCode};
use tracing::Span;

use crate::{
    HttpProtocol, RequestError,
    timeout::{TimeoutBudget, TimeoutPhase},
};

mod retry_after;

/// Policy for retrying requests after connection failures or, when opted in,
/// retryable response statuses.
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
/// response byte. [`with_status_retry`](Self::with_status_retry) separately
/// opts into repeating idempotent requests that received a caller-listed
/// status.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetryPolicy {
    maximum_connection_failures: Option<NonZeroUsize>,
    delay: Duration,
    reused_connection_replay: bool,
    status_retry: Option<StatusRetry>,
}

impl RetryPolicy {
    /// Disables connection-setup retries, reused-connection replay, and
    /// status retries.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            maximum_connection_failures: None,
            delay: Duration::ZERO,
            reused_connection_replay: false,
            status_retry: None,
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
            status_retry: None,
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

    /// Repeats idempotent requests whose response has a status listed by
    /// `status_retry`.
    ///
    /// This is caller policy, never browser or profile behavior. A response is
    /// retried only when its status is listed, the method is idempotent (RFC
    /// 9110, section 9.2.2), the request body is absent or owned bytes, and the
    /// request-scoped budget, shared by every redirect hop, is not exhausted.
    /// Otherwise the response is returned unchanged. Each intermediate response
    /// updates cookies, client hints, and Alt-Svc exactly as a returned
    /// response would, and its body is then dropped without being read. The
    /// retry waits for the [`StatusRetry`] delay under the request's total
    /// timeout and keeps the route, the exact protocol or negotiated
    /// selection rule, and any Alt-Svc alternative in use.
    #[must_use]
    pub const fn with_status_retry(self, status_retry: StatusRetry) -> Self {
        Self {
            status_retry: Some(status_retry),
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

    /// Returns the status-retry policy, when enabled.
    #[must_use]
    pub const fn status_retry(self) -> Option<StatusRetry> {
        self.status_retry
    }

    pub(crate) fn validate(self) -> bool {
        let now = std::time::Instant::now();
        (self.maximum_connection_failures.is_none() || now.checked_add(self.delay).is_some())
            && self.status_retry.is_none_or(|status_retry| {
                now.checked_add(status_retry.delay).is_some()
                    && status_retry
                        .retry_after_limit
                        .is_none_or(|limit| now.checked_add(limit).is_some())
            })
    }
}

/// Statuses a [`StatusRetry`] may list, in bit order.
///
/// Each reports a condition that a later identical request can clear: 408
/// (RFC 9110, section 15.5.9), 425 (RFC 8470, section 5.2), 429 (RFC 6585,
/// section 4), and the transient server statuses 500, 502, 503, and 504.
/// `421 Misdirected Request` is excluded: repeating it on the same route and
/// connection target cannot succeed.
const RETRYABLE_STATUSES: [StatusCode; 7] = [
    StatusCode::REQUEST_TIMEOUT,
    StatusCode::TOO_EARLY,
    StatusCode::TOO_MANY_REQUESTS,
    StatusCode::INTERNAL_SERVER_ERROR,
    StatusCode::BAD_GATEWAY,
    StatusCode::SERVICE_UNAVAILABLE,
    StatusCode::GATEWAY_TIMEOUT,
];

/// Opt-in caller policy that repeats requests after retryable statuses.
///
/// Attach it with [`RetryPolicy::with_status_retry`]. Only `408`, `425`,
/// `429`, `500`, `502`, `503`, and `504` may be listed. Every retry waits for
/// the constant delay unless [`honor_retry_after`](Self::honor_retry_after)
/// is set and the response carries a valid `Retry-After` field.
///
/// # Examples
///
/// ```
/// use std::{num::NonZeroUsize, time::Duration};
///
/// use http::StatusCode;
/// use phantom::{RetryPolicy, StatusRetry};
///
/// # fn main() -> Result<(), phantom::StatusRetryError> {
/// let status_retry = StatusRetry::new(
///     &[StatusCode::SERVICE_UNAVAILABLE, StatusCode::TOO_MANY_REQUESTS],
///     NonZeroUsize::MIN.saturating_add(1),
///     Duration::from_millis(250),
/// )?
/// .honor_retry_after(Duration::from_secs(5));
/// let policy = RetryPolicy::none().with_status_retry(status_retry);
/// assert!(policy.status_retry().is_some());
///
/// let misdirected = [StatusCode::MISDIRECTED_REQUEST];
/// assert!(StatusRetry::new(&misdirected, NonZeroUsize::MIN, Duration::ZERO).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusRetry {
    statuses: u8,
    maximum: NonZeroUsize,
    delay: Duration,
    retry_after_limit: Option<Duration>,
}

impl StatusRetry {
    /// Retries at most `maximum` responses per request whose status is in
    /// `statuses`, waiting `delay` before each retry.
    ///
    /// # Errors
    ///
    /// Returns [`StatusRetryError`] when `statuses` is empty or lists a status
    /// outside the retryable set, including `421 Misdirected Request`.
    pub fn new(
        statuses: &[StatusCode],
        maximum: NonZeroUsize,
        delay: Duration,
    ) -> Result<Self, StatusRetryError> {
        let mut bits = 0_u8;
        for status in statuses {
            let index = retryable_index(*status).ok_or(StatusRetryError {
                status: Some(*status),
            })?;
            bits |= 1 << index;
        }
        if bits == 0 {
            return Err(StatusRetryError { status: None });
        }
        Ok(Self {
            statuses: bits,
            maximum,
            delay,
            retry_after_limit: None,
        })
    }

    /// Uses a valid `Retry-After` field (RFC 9110, section 10.2.3) instead of
    /// the constant delay, up to `maximum_delay`.
    ///
    /// Both `delta-seconds` and the IMF-fixdate `HTTP-date` form are accepted;
    /// a date becomes a delay against the system clock. A requested delay
    /// above `maximum_delay` returns the response without waiting or
    /// retrying. A missing, repeated, obsolete-format, or malformed field
    /// falls back to the constant delay.
    #[must_use]
    pub const fn honor_retry_after(self, maximum_delay: Duration) -> Self {
        Self {
            retry_after_limit: Some(maximum_delay),
            ..self
        }
    }

    /// Returns whether `status` is listed for retry.
    #[must_use]
    pub fn retries(self, status: StatusCode) -> bool {
        retryable_index(status).is_some_and(|index| self.statuses & (1 << index) != 0)
    }

    /// Returns the maximum number of status retries per request.
    #[must_use]
    pub const fn max_retries(self) -> NonZeroUsize {
        self.maximum
    }

    /// Returns the constant delay before each status retry.
    #[must_use]
    pub const fn delay(self) -> Duration {
        self.delay
    }

    /// Returns the largest honored `Retry-After` delay, when enabled.
    #[must_use]
    pub const fn retry_after_limit(self) -> Option<Duration> {
        self.retry_after_limit
    }

    /// Returns the delay before retrying `status`, or `None` to return it.
    fn delay_for(self, status: StatusCode, headers: &HeaderMap) -> Option<Duration> {
        if !self.retries(status) {
            return None;
        }
        let Some(limit) = self.retry_after_limit else {
            return Some(self.delay);
        };
        match retry_after::requested_delay(headers, std::time::SystemTime::now()) {
            Some(requested) if requested > limit => None,
            Some(requested) => Some(requested),
            None => Some(self.delay),
        }
    }
}

fn retryable_index(status: StatusCode) -> Option<usize> {
    RETRYABLE_STATUSES
        .iter()
        .position(|retryable| *retryable == status)
}

/// A [`StatusRetry`] status list that cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusRetryError {
    status: Option<StatusCode>,
}

impl StatusRetryError {
    /// Returns the rejected status, or `None` when the list was empty.
    #[must_use]
    pub const fn status(self) -> Option<StatusCode> {
        self.status
    }
}

impl fmt::Display for StatusRetryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            Some(status) => write!(
                formatter,
                "status {} is not retryable; only 408, 425, 429, 500, 502, 503, and 504 are",
                status.as_u16()
            ),
            None => formatter.write_str("status retry requires at least one status"),
        }
    }
}

impl StdError for StatusRetryError {}

/// Request-scoped retry accounting that spans every redirect hop.
pub(crate) struct ConnectionSetupRetryState {
    policy: RetryPolicy,
    performed: usize,
    reused_connection_replays: usize,
    status_retries: usize,
    request_span: Span,
}

impl ConnectionSetupRetryState {
    pub(crate) fn new(policy: RetryPolicy, request_span: Span) -> Self {
        Self {
            policy,
            performed: 0,
            reused_connection_replays: 0,
            status_retries: 0,
            request_span,
        }
    }

    /// Returns the delay before retrying a response with this status and
    /// fields, when the policy, listed statuses, `Retry-After` limit, and
    /// remaining request-scoped budget permit it.
    ///
    /// Consumes no budget; [`Self::record_status_retry`] does.
    pub(crate) fn status_retry_delay(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
    ) -> Option<Duration> {
        let status_retry = self.policy.status_retry?;
        if self.status_retries >= status_retry.maximum.get() {
            return None;
        }
        status_retry.delay_for(status, headers)
    }

    /// Counts one status retry against the request-scoped budget.
    pub(crate) fn record_status_retry(&mut self, status: StatusCode, delay: Duration) {
        self.status_retries += 1;
        self.request_span.record(
            "status_retries",
            u64::try_from(self.status_retries).unwrap_or(u64::MAX),
        );
        tracing::debug!(
            retry = self.status_retries,
            status = status.as_u16(),
            delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            reason = "status",
            "waiting to retry request after a retryable status"
        );
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

    use http::{HeaderMap, HeaderValue, StatusCode, header::RETRY_AFTER};
    use phantom_net::http1::Http1TlsError;
    use tracing::Span;

    use super::{
        ConnectionSetupRetryState, RetryPolicy, StatusRetry, StatusRetryError, acquire_with_retries,
    };
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

    #[test]
    fn status_retry_accepts_only_the_retryable_allowlist() {
        let allowlist = [
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_EARLY,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::GATEWAY_TIMEOUT,
        ];
        let all = StatusRetry::new(&allowlist, NonZeroUsize::MIN, Duration::ZERO);
        assert!(all.is_ok_and(|policy| allowlist.iter().all(|status| policy.retries(*status))));

        for status in [
            StatusCode::MISDIRECTED_REQUEST,
            StatusCode::OK,
            StatusCode::NOT_FOUND,
            StatusCode::PROXY_AUTHENTICATION_REQUIRED,
            StatusCode::NOT_IMPLEMENTED,
        ] {
            let error = StatusRetry::new(
                &[StatusCode::SERVICE_UNAVAILABLE, status],
                NonZeroUsize::MIN,
                Duration::ZERO,
            );
            assert_eq!(error.err().and_then(StatusRetryError::status), Some(status));
        }
        let empty = StatusRetry::new(&[], NonZeroUsize::MIN, Duration::ZERO);
        assert_eq!(empty.err().map(StatusRetryError::status), Some(None));
    }

    #[test]
    fn status_retry_lists_only_configured_statuses() -> Result<(), StatusRetryError> {
        let policy = StatusRetry::new(
            &[
                StatusCode::SERVICE_UNAVAILABLE,
                StatusCode::SERVICE_UNAVAILABLE,
            ],
            NonZeroUsize::MIN,
            Duration::from_millis(5),
        )?;
        assert!(policy.retries(StatusCode::SERVICE_UNAVAILABLE));
        assert!(!policy.retries(StatusCode::BAD_GATEWAY));
        assert_eq!(policy.retry_after_limit(), None);
        assert_eq!(
            policy
                .honor_retry_after(Duration::from_secs(3))
                .retry_after_limit(),
            Some(Duration::from_secs(3))
        );
        assert_eq!(RetryPolicy::none().status_retry(), None);
        assert_eq!(
            RetryPolicy::none().with_status_retry(policy).status_retry(),
            Some(policy)
        );
        Ok(())
    }

    #[test]
    fn status_retry_delay_uses_retry_after_only_within_its_limit() -> Result<(), StatusRetryError> {
        let status_retry = StatusRetry::new(
            &[StatusCode::SERVICE_UNAVAILABLE],
            NonZeroUsize::MIN,
            Duration::from_millis(5),
        )?;
        let mut delayed = HeaderMap::new();
        delayed.insert(RETRY_AFTER, HeaderValue::from_static("2"));
        let mut distant = HeaderMap::new();
        distant.insert(RETRY_AFTER, HeaderValue::from_static("20"));
        let mut obsolete = HeaderMap::new();
        obsolete.insert(
            RETRY_AFTER,
            HeaderValue::from_static("Sunday, 06-Nov-94 08:49:37 GMT"),
        );
        let unavailable = StatusCode::SERVICE_UNAVAILABLE;

        let constant = status_retry.delay_for(unavailable, &delayed);
        assert_eq!(constant, Some(Duration::from_millis(5)));
        let honoring = status_retry.honor_retry_after(Duration::from_secs(10));
        assert_eq!(
            honoring.delay_for(unavailable, &delayed),
            Some(Duration::from_secs(2))
        );
        assert_eq!(honoring.delay_for(unavailable, &distant), None);
        assert_eq!(
            honoring.delay_for(unavailable, &obsolete),
            Some(Duration::from_millis(5))
        );
        assert_eq!(honoring.delay_for(StatusCode::BAD_GATEWAY, &delayed), None);
        Ok(())
    }

    #[test]
    fn status_retry_budget_is_request_scoped() -> Result<(), StatusRetryError> {
        let status_retry = StatusRetry::new(
            &[StatusCode::SERVICE_UNAVAILABLE],
            NonZeroUsize::MIN,
            Duration::ZERO,
        )?;
        let mut retries = ConnectionSetupRetryState::new(
            RetryPolicy::none().with_status_retry(status_retry),
            Span::none(),
        );
        let headers = HeaderMap::new();
        let unavailable = StatusCode::SERVICE_UNAVAILABLE;

        assert_eq!(
            retries.status_retry_delay(unavailable, &headers),
            Some(Duration::ZERO)
        );
        retries.record_status_retry(unavailable, Duration::ZERO);
        assert_eq!(retries.status_retry_delay(unavailable, &headers), None);
        assert_eq!(retries.performed(), 0);
        Ok(())
    }

    #[test]
    fn status_retry_delay_must_fit_the_runtime_clock() -> Result<(), StatusRetryError> {
        let status_retry = StatusRetry::new(
            &[StatusCode::SERVICE_UNAVAILABLE],
            NonZeroUsize::MIN,
            Duration::ZERO,
        )?;
        assert!(
            RetryPolicy::none()
                .with_status_retry(status_retry)
                .validate()
        );
        let huge = StatusRetry::new(
            &[StatusCode::SERVICE_UNAVAILABLE],
            NonZeroUsize::MIN,
            Duration::MAX,
        )?;
        assert!(!RetryPolicy::none().with_status_retry(huge).validate());
        let huge_limit = status_retry.honor_retry_after(Duration::MAX);
        assert!(!RetryPolicy::none().with_status_retry(huge_limit).validate());
        Ok(())
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
