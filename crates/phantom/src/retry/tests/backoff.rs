use super::*;

#[test]
fn backoff_validation_rejects_inverted_and_unrepresentable_caps() -> Result<(), StatusRetryError> {
    let initial = Duration::from_millis(100);
    let policy = RetryPolicy::connection_failures(NonZeroUsize::MIN, initial)
        .with_exponential_backoff(Duration::from_secs(2))
        .with_full_jitter(true);
    assert_eq!(policy.delay(), initial);
    assert_eq!(policy.backoff_limit(), Some(Duration::from_secs(2)));
    assert!(policy.full_jitter());
    assert!(policy.validate().is_ok());
    assert!(
        policy
            .with_exponential_backoff(Duration::ZERO)
            .validate()
            .is_err()
    );
    assert!(
        policy
            .with_exponential_backoff(Duration::MAX)
            .validate()
            .is_err()
    );

    let status = StatusRetry::new(
        &[StatusCode::SERVICE_UNAVAILABLE],
        NonZeroUsize::MIN,
        initial,
    )?
    .with_exponential_backoff(Duration::from_secs(2))
    .with_full_jitter(true);
    assert_eq!(status.delay(), initial);
    assert_eq!(status.backoff_limit(), Some(Duration::from_secs(2)));
    assert!(status.full_jitter());
    assert!(
        RetryPolicy::none()
            .with_status_retry(status)
            .validate()
            .is_ok()
    );
    assert!(
        RetryPolicy::none()
            .with_status_retry(status.with_exponential_backoff(Duration::ZERO))
            .validate()
            .is_err()
    );
    assert!(
        RetryPolicy::none()
            .with_status_retry(status.with_exponential_backoff(Duration::MAX))
            .validate()
            .is_err()
    );
    Ok(())
}

#[test]
fn status_backoff_counts_only_status_retries_and_keeps_the_server_floor()
-> Result<(), StatusRetryError> {
    let status = StatusRetry::new(
        &[StatusCode::SERVICE_UNAVAILABLE],
        NonZeroUsize::MIN.saturating_add(4),
        Duration::from_secs(2),
    )?
    .with_exponential_backoff(Duration::from_secs(7))
    .honor_retry_after(Duration::from_secs(20));
    let policy = RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::ZERO)
        .with_status_retry(status);
    let mut state = ConnectionSetupRetryState::new(policy, Span::none());
    let unavailable = StatusCode::SERVICE_UNAVAILABLE;
    let empty = HeaderMap::new();
    state.performed = 1;
    for seconds in [2, 4, 7, 7] {
        let delay = state.status_retry_delay(unavailable, &empty);
        assert_eq!(delay, Some(Duration::from_secs(seconds)));
        state.record_status_retry(unavailable, Duration::from_secs(seconds));
    }
    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, HeaderValue::from_static("1"));
    assert_eq!(
        status.delay_for(unavailable, &headers, 0),
        Some(Duration::from_secs(2))
    );
    headers.insert(RETRY_AFTER, HeaderValue::from_static("10"));
    assert_eq!(
        status.delay_for(unavailable, &headers, 0),
        Some(Duration::from_secs(10))
    );
    let jittered = status.with_full_jitter(true);
    // The configured upper bound is below the server floor, for every draw.
    assert_eq!(
        jittered.delay_for(unavailable, &headers, usize::MAX),
        Some(Duration::from_secs(10))
    );
    headers.insert(RETRY_AFTER, HeaderValue::from_static("21"));
    assert_eq!(jittered.delay_for(unavailable, &headers, 0), None);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn exponential_setup_waits_stay_within_the_shared_retry_cap() -> Result<(), RequestError> {
    let policy = RetryPolicy::connection_failures(
        NonZeroUsize::MIN.saturating_add(4),
        Duration::from_secs(1),
    )
    .with_exponential_backoff(Duration::from_secs(5))
    .with_max_retries(Some(2));
    let mut state = ConnectionSetupRetryState::new(policy, Span::none());
    let budget = crate::timeout::TimeoutBudget::new(RequestTimeouts::new())?;
    let started = tokio::time::Instant::now();
    let mut attempts = 0;
    let result = acquire_with_retries(HttpProtocol::Http1, budget, &mut state, || {
        attempts += 1;
        async { Err::<(), _>(refused_connection()) }
    })
    .await;
    assert!(result.is_err());
    assert_eq!(attempts, 3);
    assert_eq!(state.performed(), 2);
    assert_eq!(state.caller_retries, 2);
    assert_eq!(started.elapsed(), Duration::from_secs(3));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn growing_setup_delay_cannot_extend_the_total_deadline() -> Result<(), RequestError> {
    let policy = RetryPolicy::connection_failures(
        NonZeroUsize::MIN.saturating_add(4),
        Duration::from_secs(1),
    )
    .with_exponential_backoff(Duration::from_secs(8));
    let mut state = ConnectionSetupRetryState::new(policy, Span::none());
    let budget =
        crate::timeout::TimeoutBudget::new(RequestTimeouts::new().total(Duration::from_secs(2)))?;
    let started = tokio::time::Instant::now();
    let mut attempts = 0;
    let error = acquire_with_retries(HttpProtocol::Http1, budget, &mut state, || {
        attempts += 1;
        async { Err::<(), _>(refused_connection()) }
    })
    .await
    .err()
    .ok_or_else(refused_connection)?;
    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
    assert_eq!(attempts, 2);
    assert_eq!(state.performed(), 1);
    assert_eq!(state.caller_retries, 1);
    assert_eq!(started.elapsed(), Duration::from_secs(2));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn cancellation_during_backoff_never_starts_or_charges_another_setup()
-> Result<(), RequestError> {
    let policy = RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::from_secs(1))
        .with_exponential_backoff(Duration::from_secs(5));
    let mut state = ConnectionSetupRetryState::new(policy, Span::none());
    let budget = crate::timeout::TimeoutBudget::new(RequestTimeouts::new())?;
    let mut attempts = 0;
    {
        let retry = acquire_with_retries(HttpProtocol::Http1, budget, &mut state, || {
            attempts += 1;
            async { Err::<(), _>(refused_connection()) }
        });
        tokio::select! {
            biased;
            _ = retry => panic!("retry finished before cancellation"),
            () = tokio::time::sleep(Duration::from_millis(20)) => {}
        }
    }
    tokio::time::advance(Duration::from_secs(10)).await;
    assert_eq!(attempts, 1);
    assert_eq!(state.performed(), 0);
    assert_eq!(state.caller_retries, 0);
    Ok(())
}
