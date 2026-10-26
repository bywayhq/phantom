use super::*;
use phantom::{BuildErrorKind, HttpAttemptBudget, RequestErrorKind};

#[tokio::test]
async fn backoff_retries_preserve_the_origin_attempt_allowance() -> TestResult {
    let server = ScriptedServer::start(&[UNAVAILABLE, UNAVAILABLE, OK]).await?;
    let result = async {
        let initial = Duration::from_millis(5);
        let client = retrying_client(
            status_retry(5, initial)?.with_exponential_backoff(Duration::from_millis(20)),
        )?;
        let budget = HttpAttemptBudget::new(3);
        let response = client
            .get_with_protocol(HttpProtocol::Http1, &server.url("http", "/backoff"))?
            .attempt_budget(budget.clone())
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
        assert_eq!(budget.remaining(), 0);
        assert_eq!(server.received()?.len(), 3);
        Ok(())
    }
    .await;
    server.finish(result).await
}

#[tokio::test]
async fn exhausted_allowance_prevents_a_jittered_backoff_resend() -> TestResult {
    let server = ScriptedServer::start(&[UNAVAILABLE]).await?;
    let result = async {
        let client = retrying_client(
            status_retry(5, Duration::from_secs(30))?
                .with_exponential_backoff(Duration::from_secs(60))
                .with_full_jitter(true),
        )?;
        let budget = HttpAttemptBudget::new(1);
        let error = tokio::time::timeout(Duration::from_secs(2), async {
            client
                .get_with_protocol(HttpProtocol::Http1, &server.url("http", "/budget"))?
                .attempt_budget(budget.clone())
                .send()
                .await
        })
        .await?
        .err()
        .ok_or("exhausted allowance sent another request")?;
        assert_eq!(error.kind(), RequestErrorKind::AttemptBudgetExhausted);
        assert_eq!(server.received()?.len(), 1);
        Ok(())
    }
    .await;
    server.finish(result).await
}

#[tokio::test]
async fn invalid_backoff_cap_fails_before_connecting() -> TestResult {
    let policy = RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::from_secs(2))
        .with_exponential_backoff(Duration::from_secs(1));
    let error = plain_builder()
        .retry_policy(policy)
        .build()
        .err()
        .ok_or("invalid cap built a client")?;
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    assert!(error.to_string().contains("backoff cap is below"));

    let server = ScriptedServer::start(&[OK]).await?;
    let result = async {
        let error = plain_builder()
            .build()?
            .get_with_protocol(HttpProtocol::Http1, &server.url("http", "/invalid"))?
            .retry_policy(policy)
            .send()
            .await
            .err()
            .ok_or("invalid cap sent a request")?;
        assert_eq!(error.kind(), RequestErrorKind::InvalidTimeout);
        assert!(error.to_string().contains("backoff cap is below"));
        assert!(server.received()?.is_empty());
        Ok(())
    }
    .await;
    server.finish(result).await
}
