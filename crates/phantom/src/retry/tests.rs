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

#[tokio::test(start_paused = true)]
async fn setup_and_status_retries_share_one_cap() -> Result<(), Box<dyn std::error::Error>> {
    let policy = RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::ZERO)
        .with_status_retry(StatusRetry::new(
            &[StatusCode::SERVICE_UNAVAILABLE],
            NonZeroUsize::MIN,
            Duration::ZERO,
        )?)
        .with_max_retries(Some(1));
    let mut retries = ConnectionSetupRetryState::new(policy, Span::none());
    let budget = crate::timeout::TimeoutBudget::new(RequestTimeouts::new())?;
    assert!(
        retries
            .retry_after(&refused_connection(), Some(HttpProtocol::Http1), budget)
            .await?
    );
    assert_eq!(retries.performed(), 1);
    assert_eq!(retries.caller_retries, 1);
    assert_eq!(
        retries.status_retry_delay(StatusCode::SERVICE_UNAVAILABLE, &HeaderMap::new()),
        None
    );
    let mut retries = ConnectionSetupRetryState::new(policy, Span::none());
    assert_eq!(
        retries.status_retry_delay(StatusCode::SERVICE_UNAVAILABLE, &HeaderMap::new()),
        Some(Duration::ZERO)
    );
    retries.record_status_retry(StatusCode::SERVICE_UNAVAILABLE, Duration::ZERO);
    assert!(
        !retries
            .retry_after(&refused_connection(), Some(HttpProtocol::Http1), budget)
            .await?
    );
    assert_eq!(retries.performed(), 0);
    assert_eq!(retries.caller_retries, 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn zero_cap_denies_setup_without_waiting_or_charging() -> Result<(), RequestError> {
    let policy = RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::from_secs(30))
        .with_max_retries(Some(0));
    let mut retries = ConnectionSetupRetryState::new(policy, Span::none());
    let started = tokio::time::Instant::now();
    let budget = crate::timeout::TimeoutBudget::new(RequestTimeouts::new())?;
    assert!(
        !retries
            .retry_after(&refused_connection(), Some(HttpProtocol::Http1), budget)
            .await?
    );
    assert_eq!(started.elapsed(), Duration::ZERO);
    assert_eq!(retries.caller_retries, 0);
    assert_eq!(retries.performed(), 0);
    Ok(())
}

#[test]
fn cap_does_not_enable_classes_or_change_retirement_flags() {
    assert_eq!(RetryPolicy::none().max_retries(), None);
    let none = RetryPolicy::none().with_max_retries(Some(5));
    let retries = ConnectionSetupRetryState::new(none, Span::none());
    assert!(retries.caller_retry_available());
    assert!(!retries.replays_reused_connections());
    assert!(!retries.unprocessed_replay_available());
    assert!(!retries.falls_back_to_http2());
    assert_eq!(
        retries.status_retry_delay(StatusCode::SERVICE_UNAVAILABLE, &HeaderMap::new()),
        None
    );
    let enabled = none
        .with_reused_connection_replay(true)
        .with_unprocessed_replay(Some(NonZeroUsize::MIN))
        .with_http2_fallback(true)
        .with_max_retries(Some(0));
    let retries = ConnectionSetupRetryState::new(enabled, Span::none());
    assert!(retries.replays_reused_connections());
    assert!(retries.replays_unprocessed_requests());
    assert!(retries.falls_back_to_http2());
    assert!(!retries.caller_retry_available());
    assert!(!retries.unprocessed_replay_available());
    assert!(
        retries
            .for_alternative_setup()
            .replays_unprocessed_requests()
    );
}

#[test]
fn replay_classes_spend_the_same_cap() {
    let policy = RetryPolicy::none()
        .with_unprocessed_replay(NonZeroUsize::new(3))
        .with_max_retries(Some(2));
    let mut retries = ConnectionSetupRetryState::new(policy, Span::none());
    retries.record_reused_connection_replay();
    assert!(retries.unprocessed_replay_available());
    retries.record_unprocessed_replay(Some(HttpProtocol::Http2));
    assert!(!retries.caller_retry_available());
    assert!(!retries.unprocessed_replay_available());
    assert_eq!(retries.performed(), 0);
    assert_eq!(retries.caller_retries, 2);
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
fn http2_fallback_is_disabled_by_default_and_independent() {
    assert!(!RetryPolicy::default().http2_fallback());
    assert!(!RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::ZERO).http2_fallback());
    let policy = RetryPolicy::none().with_http2_fallback(true);
    assert!(policy.http2_fallback());
    assert_eq!(policy.max_connection_failures(), None);
    assert!(!policy.with_http2_fallback(false).http2_fallback());

    let retries = ConnectionSetupRetryState::new(policy, Span::none());
    assert!(retries.falls_back_to_http2());
    assert!(!retries.for_alternative_setup().falls_back_to_http2());
}

#[test]
fn unprocessed_replay_is_disabled_by_default_and_independent() {
    assert_eq!(RetryPolicy::default().unprocessed_replay(), None);
    assert_eq!(
        RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::ZERO).unprocessed_replay(),
        None
    );
    let two = NonZeroUsize::new(2);
    let policy = RetryPolicy::none()
        .with_reused_connection_replay(true)
        .with_unprocessed_replay(two);
    assert_eq!(policy.unprocessed_replay(), two);
    assert!(policy.reused_connection_replay());
    assert_eq!(policy.max_connection_failures(), None);
    assert_eq!(
        policy.with_unprocessed_replay(None).unprocessed_replay(),
        None
    );
}

#[test]
fn unprocessed_replay_budget_is_request_scoped() {
    let policy = RetryPolicy::none().with_unprocessed_replay(NonZeroUsize::new(2));
    let mut retries = ConnectionSetupRetryState::new(policy, Span::none());
    assert!(retries.replays_unprocessed_requests());
    assert!(retries.unprocessed_replay_available());
    retries.record_unprocessed_replay(Some(HttpProtocol::Http2));
    assert!(retries.unprocessed_replay_available());
    retries.record_unprocessed_replay(Some(HttpProtocol::Http3));
    assert!(!retries.unprocessed_replay_available());
    assert_eq!(retries.performed(), 0);

    let alternative = retries.for_alternative_setup();
    assert!(alternative.replays_unprocessed_requests());
    assert_eq!(alternative.policy.max_connection_failures(), None);

    let disabled = ConnectionSetupRetryState::new(RetryPolicy::none(), Span::none());
    assert!(!disabled.replays_unprocessed_requests());
    assert!(!disabled.unprocessed_replay_available());
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
async fn connect_timeout_is_terminal_without_consuming_retry_budget() -> Result<(), RequestError> {
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
    let policy = RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::from_millis(200));
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
    assert_eq!(retries.caller_retries, 0);
    Ok(())
}
