//! Peer-observed shared origin attempt admission through the public client.

use super::*;
use phantom::{HttpAttemptBudget, RequestErrorKind};

#[tokio::test]
async fn exhausted_attempt_budget_stops_before_status_retry_delay() -> TestResult {
    let server = ScriptedServer::start(&[UNAVAILABLE]).await?;
    let result = async {
        let client = retrying_client(status_retry(1, Duration::from_secs(30))?)?;
        let budget = HttpAttemptBudget::new(1);
        let error = tokio::time::timeout(Duration::from_secs(2), async {
            client
                .get(HttpProtocol::Http1, &server.url("http", "/"))?
                .attempt_budget(budget.clone())
                .send()
                .await
        })
        .await?
        .err()
        .ok_or("status retry exceeded shared allowance")?;
        assert_eq!(error.kind(), RequestErrorKind::AttemptBudgetExhausted);
        assert_eq!(budget.remaining(), 0);
        assert_eq!(server.received()?.len(), 1);
        Ok(())
    }
    .await;
    server.finish(result).await
}

#[tokio::test]
async fn concurrent_requests_and_cloned_clients_share_one_allowance() -> TestResult {
    let server = ScriptedServer::start(&[OK; 7]).await?;
    let result = async {
        let client = plain_builder().build()?;
        let budget = HttpAttemptBudget::new(7);
        let requests = (0..32).map(|_| {
            let client = client.clone();
            let budget = budget.clone();
            let url = server.url("http", "/shared");
            async move {
                let result = client
                    .get(HttpProtocol::Http1, &url)?
                    .attempt_budget(budget)
                    .send()
                    .await;
                match result {
                    Ok(response) => {
                        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
                        Ok::<_, Box<dyn Error + Send + Sync>>(true)
                    }
                    Err(error) => {
                        assert_eq!(error.kind(), RequestErrorKind::AttemptBudgetExhausted);
                        assert_eq!(
                            error.replay_observation(),
                            phantom::RequestReplayObservation::Unknown
                        );
                        Ok(false)
                    }
                }
            }
        });
        let results = futures_util::future::join_all(requests).await;
        let mut successes = 0;
        for result in results {
            successes += usize::from(result?);
        }
        assert_eq!(successes, 7);
        assert_eq!(server.received()?.len(), 7);
        assert_eq!(budget.remaining(), 0);
        Ok(())
    }
    .await;
    server.finish(result).await
}

#[tokio::test]
async fn zero_independent_and_absent_budgets_do_not_affect_each_other() -> TestResult {
    let server = ScriptedServer::start(&[OK; 3]).await?;
    let result = async {
        let client = plain_builder().build()?;
        let zero = HttpAttemptBudget::new(0);
        let other = HttpAttemptBudget::new(2);
        let error = client
            .get(HttpProtocol::Http1, &server.url("http", "/blocked"))?
            .attempt_budget(zero)
            .send()
            .await
            .err()
            .ok_or("zero budget sent a request")?;
        assert_eq!(error.kind(), RequestErrorKind::AttemptBudgetExhausted);
        assert!(server.received()?.is_empty());
        for path in ["/first", "/external-resend"] {
            client
                .get(HttpProtocol::Http1, &server.url("http", path))?
                .attempt_budget(other.clone())
                .send()
                .await?
                .into_body()
                .collect()
                .await?;
        }
        assert_eq!(other.remaining(), 0);
        client
            .get(HttpProtocol::Http1, &server.url("http", "/unbudgeted"))?
            .send()
            .await?
            .into_body()
            .collect()
            .await?;
        assert_eq!(
            request_lines(&server.received()?),
            [
                "GET /first HTTP/1.1",
                "GET /external-resend HTTP/1.1",
                "GET /unbudgeted HTTP/1.1"
            ]
        );
        Ok(())
    }
    .await;
    server.finish(result).await
}

#[tokio::test]
async fn redirects_and_enabled_status_retries_spend_the_same_allowance() -> TestResult {
    let redirect = "HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n";
    let server = ScriptedServer::start(&[UNAVAILABLE, redirect, UNAVAILABLE]).await?;
    let result = async {
        let client = Client::builder(
            ClientProfile::new(tls_settings())
                .with_http2(phantom::profile::browser::chrome::v154_http2()),
        )
        .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
        .retry_policy(RetryPolicy::none().with_status_retry(status_retry(5, Duration::ZERO)?))
        .build()?;
        let budget = HttpAttemptBudget::new(3);
        let mut request = client
            .get_negotiated(&server.url("http", "/"))?
            .attempt_budget(budget.clone());
        let diagnostics = request.diagnostics(NonZeroUsize::MIN.saturating_add(127));
        let error = request
            .send()
            .await
            .err()
            .ok_or("retry exceeded shared allowance")?;
        assert_eq!(error.kind(), RequestErrorKind::AttemptBudgetExhausted);
        assert_eq!(budget.remaining(), 0);
        let snapshot = diagnostics.snapshot();
        assert_eq!(snapshot.outcome, phantom::RequestTimelineOutcome::Failed);
        assert_eq!(snapshot.admitted_attempts, 3);
        assert_eq!(snapshot.dropped_events, 0);
        let admissions = snapshot
            .events
            .iter()
            .filter(|event| event.phase == phantom::RequestTimingPhase::AttemptAdmission)
            .map(|event| (event.hop, event.admission))
            .collect::<Vec<_>>();
        assert_eq!(admissions, [(0, Some(1)), (0, Some(2)), (1, Some(3))]);

        assert_eq!(
            request_lines(&server.received()?),
            ["GET / HTTP/1.1", "GET / HTTP/1.1", "GET /next HTTP/1.1"]
        );
        Ok(())
    }
    .await;
    server.finish(result).await
}
