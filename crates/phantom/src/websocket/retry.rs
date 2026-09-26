//! Caller-enabled retry of a WebSocket opening whose connection setup failed.

use std::{future::Future, num::NonZeroUsize, time::Duration};

use tokio::time::Instant;
use tracing::Span;

use super::WebSocketError;
use crate::RequestError;

/// Policy for opening a WebSocket again after its connection setup failed.
///
/// The default, equal to [`WebSocketRetryPolicy::none`], opens once. That is
/// what a browser does: a page's `WebSocket` that fails to connect reports the
/// failure, and only the page can construct another. A retry is caller
/// policy, never browser or profile behavior. Set it for one connect with
/// [`WebSocketRequestBuilder::retry_policy`](super::WebSocketRequestBuilder::retry_policy).
///
/// Only a failure that happened before any byte of the opening reached the
/// origin is retried: a failed name lookup, a refused or failed TCP connect
/// to the origin or proxy, and a SOCKS5 proxy that could not connect or
/// resolve. The same failures are the retryable connection-setup class of
/// [`RetryPolicy`](crate::RetryPolicy). TLS, proxy authentication or
/// rejection, the opening exchange, a
/// [`HandshakeRejected`](super::WebSocketErrorKind::HandshakeRejected) or
/// [`InvalidHandshake`](super::WebSocketErrorKind::InvalidHandshake) answer,
/// and a handshake [`Timeout`](super::WebSocketErrorKind::Timeout) return the
/// error at once, so no retry follows a response from the server. A stream
/// on a pooled HTTP/2 session is not retried either.
///
/// A retry is a new opening: it resolves, connects, and sends the opening
/// with a fresh `Sec-WebSocket-Key` on the same route, protocol, and profile
/// policy. Each attempt has its own
/// [`handshake_timeout`](super::WebSocketRequestBuilder::handshake_timeout);
/// the delays between attempts are outside it.
///
/// # Examples
///
/// ```
/// use std::{num::NonZeroUsize, time::Duration};
///
/// use phantom::WebSocketRetryPolicy;
///
/// let policy = WebSocketRetryPolicy::connection_failures(
///     NonZeroUsize::MIN.saturating_add(1),
///     Duration::from_millis(500),
/// );
/// assert_eq!(policy.max_connection_failures(), NonZeroUsize::new(2));
/// assert_eq!(WebSocketRetryPolicy::default(), WebSocketRetryPolicy::none());
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WebSocketRetryPolicy {
    maximum_connection_failures: Option<NonZeroUsize>,
    delay: Duration,
}

impl WebSocketRetryPolicy {
    /// Opens once and returns every failure.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            maximum_connection_failures: None,
            delay: Duration::ZERO,
        }
    }

    /// Retries at most `maximum` connection-setup failures, waiting `delay`
    /// before each new attempt.
    ///
    /// A `delay` the runtime clock cannot represent makes
    /// [`connect`](super::WebSocketRequestBuilder::connect) fail with
    /// [`InvalidRequest`](super::WebSocketErrorKind::InvalidRequest) before
    /// any I/O.
    #[must_use]
    pub const fn connection_failures(maximum: NonZeroUsize, delay: Duration) -> Self {
        Self {
            maximum_connection_failures: Some(maximum),
            delay,
        }
    }

    /// Returns the maximum number of connection-setup failures retried, or
    /// `None` when retries are off.
    #[must_use]
    pub const fn max_connection_failures(self) -> Option<NonZeroUsize> {
        self.maximum_connection_failures
    }

    /// Returns the delay before each retry.
    #[must_use]
    pub const fn delay(self) -> Duration {
        self.delay
    }

    fn validate(self) -> Result<(), WebSocketError> {
        if self.maximum_connection_failures.is_some()
            && Instant::now().checked_add(self.delay).is_none()
        {
            return Err(WebSocketError::request(RequestError::invalid_retry_delay()));
        }
        Ok(())
    }
}

/// Runs `attempt` until it succeeds, fails with an error the policy does
/// not retry, or the policy's budget is spent, and returns the last result.
///
/// `attempt` receives the zero-based attempt number.
pub(super) async fn open_with_retries<Output, Attempt, AttemptFuture>(
    policy: WebSocketRetryPolicy,
    span: &Span,
    mut attempt: Attempt,
) -> Result<Output, WebSocketError>
where
    Attempt: FnMut(usize) -> AttemptFuture,
    AttemptFuture: Future<Output = Result<Output, WebSocketError>>,
{
    policy.validate()?;
    let maximum = policy
        .maximum_connection_failures
        .map_or(0, NonZeroUsize::get);
    let mut performed = 0;
    loop {
        let error = match attempt(performed).await {
            Ok(output) => return Ok(output),
            Err(error) => error,
        };
        if performed >= maximum || !error.is_retryable_connection_setup() {
            return Err(error);
        }
        performed += 1;
        span.record(
            "handshake_retries",
            u64::try_from(performed).unwrap_or(u64::MAX),
        );
        tracing::debug!(
            retry = performed,
            delay_ms = u64::try_from(policy.delay.as_millis()).unwrap_or(u64::MAX),
            reason = "connection_setup",
            "waiting to retry WebSocket connection setup"
        );
        if !policy.delay.is_zero() {
            let deadline = Instant::now()
                .checked_add(policy.delay)
                .ok_or_else(|| WebSocketError::request(RequestError::invalid_retry_delay()))?;
            crate::timeout::sleep_until(deadline)
                .await
                .map_err(WebSocketError::request)?;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, num::NonZeroUsize, time::Duration};

    use phantom_net::http1::Http1TlsError;
    use tracing::Span;

    use super::{WebSocketRetryPolicy, open_with_retries};
    use crate::{
        RequestError, TimeoutPhase,
        websocket::{WebSocketError, WebSocketErrorKind},
    };

    fn refused() -> WebSocketError {
        WebSocketError::request(RequestError::http1_connection_setup(
            Http1TlsError::Connect(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
        ))
    }

    fn two_retries(delay: Duration) -> WebSocketRetryPolicy {
        WebSocketRetryPolicy::connection_failures(NonZeroUsize::MIN.saturating_add(1), delay)
    }

    #[test]
    fn policy_is_off_by_default() {
        assert_eq!(
            WebSocketRetryPolicy::default(),
            WebSocketRetryPolicy::none()
        );
        assert_eq!(WebSocketRetryPolicy::none().max_connection_failures(), None);
        assert_eq!(WebSocketRetryPolicy::none().delay(), Duration::ZERO);
    }

    #[tokio::test]
    async fn without_a_policy_a_setup_failure_is_returned_after_one_attempt() {
        let mut attempts = 0;
        let result = open_with_retries(WebSocketRetryPolicy::none(), &Span::none(), |_| {
            attempts += 1;
            async { Err::<(), _>(refused()) }
        })
        .await;

        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(WebSocketErrorKind::Connect)
        );
        assert_eq!(attempts, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn setup_failures_are_retried_after_the_delay_until_one_succeeds() {
        let started = tokio::time::Instant::now();
        let mut outcomes = VecDeque::from([Err(refused()), Err(refused()), Ok(7_u8)]);
        let mut numbers = Vec::new();

        let value = open_with_retries(
            two_retries(Duration::from_millis(300)),
            &Span::none(),
            |n| {
                numbers.push(n);
                let outcome = outcomes.pop_front().unwrap_or_else(|| Err(refused()));
                async move { outcome }
            },
        )
        .await;

        assert_eq!(value.ok(), Some(7));
        assert_eq!(numbers, [0, 1, 2]);
        assert_eq!(started.elapsed(), Duration::from_millis(600));
    }

    #[tokio::test]
    async fn an_exhausted_budget_returns_the_last_setup_failure() {
        let mut attempts = 0;
        let result = open_with_retries(two_retries(Duration::ZERO), &Span::none(), |_| {
            attempts += 1;
            async { Err::<(), _>(refused()) }
        })
        .await;

        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(WebSocketErrorKind::Connect)
        );
        assert_eq!(attempts, 3);
    }

    #[tokio::test]
    async fn failures_after_setup_and_timeouts_are_not_retried() {
        let terminal: [fn() -> WebSocketError; 4] = [
            || WebSocketError::invalid_handshake("wrong Sec-WebSocket-Accept"),
            || {
                WebSocketError::request(RequestError::http1_connection_setup(
                    Http1TlsError::MissingHttp1Alpn,
                ))
            },
            || {
                WebSocketError::request(RequestError::timeout(
                    TimeoutPhase::WebSocketHandshake,
                    None,
                ))
            },
            || WebSocketError::request(RequestError::capacity(crate::HttpProtocol::Http2)),
        ];
        for error in terminal {
            let mut attempts = 0;
            let result = open_with_retries(two_retries(Duration::ZERO), &Span::none(), |_| {
                attempts += 1;
                async move { Err::<(), _>(error()) }
            })
            .await;
            assert!(result.is_err());
            assert_eq!(attempts, 1);
        }
    }

    #[tokio::test]
    async fn a_delay_beyond_the_clock_fails_before_the_first_attempt() {
        let mut attempts = 0;
        let result = open_with_retries(two_retries(Duration::MAX), &Span::none(), |_| {
            attempts += 1;
            async { Ok::<_, WebSocketError>(()) }
        })
        .await;

        assert_eq!(
            result.err().map(|error| error.kind()),
            Some(WebSocketErrorKind::InvalidRequest)
        );
        assert_eq!(attempts, 0);
    }
}
