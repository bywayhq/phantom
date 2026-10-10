use std::{error::Error, fmt, time::Duration};

use tracing::instrument::WithSubscriber;

use super::{
    Client, ConnectUdpProxy, HttpProtocol, MasqueProxy, OutcomeSubscriber, ProxyMode,
    RequestErrorKind, Route, TestResult, bounded, client_builder, identities,
    observed_zero_request_retries,
};

#[derive(Debug)]
struct OperationFailure;

impl fmt::Display for OperationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled proxy operation failed")
    }
}

impl Error for OperationFailure {}

fn find_source<'a, T: Error + 'static>(mut error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    loop {
        if let Some(found) = error.downcast_ref::<T>() {
            return Some(found);
        }
        error = error.source()?;
    }
}

#[tokio::test(start_paused = true)]
async fn the_actual_connect_udp_bound_retains_elapsed() -> TestResult<()> {
    let operation = bounded(std::future::pending::<TestResult<()>>());
    tokio::pin!(operation);
    assert!(futures_util::poll!(&mut operation).is_pending());
    tokio::time::advance(Duration::from_secs(30)).await;

    let error = operation.await.err().ok_or("pending operation completed")?;
    assert!(find_source::<tokio::time::error::Elapsed>(error.as_ref()).is_some());
    Ok(())
}

#[tokio::test]
async fn the_connect_udp_bound_keeps_an_inner_typed_failure() -> TestResult<()> {
    let error = bounded(async { Err(Box::new(OperationFailure) as Box<dyn Error + Send + Sync>) })
        .await
        .err()
        .ok_or("failed operation was accepted")?;
    assert!(find_source::<OperationFailure>(error.as_ref()).is_some());
    Ok(())
}

#[tokio::test]
async fn the_connect_udp_bound_keeps_a_successful_operation() -> TestResult<()> {
    bounded(async { Ok(()) }).await
}

fn rejecting_client(
    origin: &super::TestIdentity,
    proxy_identity: &super::TestIdentity,
    proxy: &MasqueProxy,
) -> TestResult<Client> {
    Ok(client_builder(origin, proxy_identity)
        .route(Route::connect_udp(ConnectUdpProxy::new(&proxy.template())?))
        .build()?)
}

#[tokio::test]
async fn an_unobserved_real_proxy_rejection_cannot_prove_zero_retries() -> TestResult<()> {
    bounded(async {
        let (origin_identity, proxy_identity) = identities()?;
        let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Reject(502))?;
        let client = rejecting_client(&origin_identity, &proxy_identity, &proxy)?;
        let subscriber = OutcomeSubscriber::default();

        let error = client
            .get(HttpProtocol::Http3, "https://127.0.0.1:9/unobserved")?
            .send()
            .await
            .err()
            .ok_or("proxy rejection succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert_eq!(proxy.requests().len(), 1);
        assert!(
            subscriber
                .retries_performed_for("client.request")
                .is_empty()
        );

        assert!(
            !observed_zero_request_retries(&subscriber),
            "an unobserved request was accepted as zero retries"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_observed_real_proxy_rejection_reports_zero_retries() -> TestResult<()> {
    bounded(async {
        let (origin_identity, proxy_identity) = identities()?;
        let proxy = MasqueProxy::spawn(&proxy_identity, ProxyMode::Reject(502))?;
        let client = rejecting_client(&origin_identity, &proxy_identity, &proxy)?;
        let subscriber = OutcomeSubscriber::default();

        let error = client
            .get(HttpProtocol::Http3, "https://127.0.0.1:9/observed")?
            .send()
            .with_subscriber(subscriber.dispatch())
            .await
            .err()
            .ok_or("proxy rejection succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert_eq!(proxy.requests().len(), 1);
        assert_eq!(subscriber.retries_performed_for("client.request"), [0]);

        assert!(observed_zero_request_retries(&subscriber));
        Ok(())
    })
    .await
}
