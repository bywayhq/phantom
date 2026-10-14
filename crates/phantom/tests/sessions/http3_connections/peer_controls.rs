use super::*;

#[tokio::test]
async fn a_delayed_goaway_keeps_default_limit_replacement_ordered() -> TestResult {
    draining_default_limit(true).await
}

#[tokio::test]
async fn a_delayed_goaway_keeps_configured_limit_replacement_ordered() -> TestResult {
    draining_configured_limit(true).await
}

#[derive(Debug)]
struct RequestFailure;

impl std::fmt::Display for RequestFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("request worker failed after its response")
    }
}

impl std::error::Error for RequestFailure {}

#[tokio::test]
async fn an_early_caller_failure_keeps_the_completed_original_request_worker() -> TestResult {
    let identity = TestIdentity::generate()?;
    let mut origin = Origin::start(&identity)?;
    let mut requests = Requests::default();
    let client = client_builder(&identity).build()?;
    let uri = origin.uri("warm");
    requests.spawn(async move {
        finish(send(&client, &uri).await?).await?;
        Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, RequestFailure).into())
    });
    assert_eq!(origin.settle(1).await?, (1, 1));
    timeout(TEST_TIMEOUT, async {
        while !requests.peer(0)?.is_finished() {
            tokio::task::yield_now().await;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await??;
    let caller = Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "caller failed").into());
    let error = requests
        .finish(caller)
        .await
        .err()
        .ok_or("request failure disappeared")?;
    let failures = error
        .downcast_ref::<crate::support::tunnel_proxy::connection_peer::FixtureFailures>()
        .ok_or("simultaneous caller and request causes missing")?;
    assert_eq!(
        failures
            .primary
            .downcast_ref::<std::io::Error>()
            .ok_or("caller I/O cause missing")?
            .kind(),
        std::io::ErrorKind::InvalidInput
    );
    let worker = failures
        .cleanup
        .downcast_ref::<std::io::Error>()
        .ok_or("original request I/O cause missing")?;
    assert_eq!(worker.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(
        worker
            .get_ref()
            .is_some_and(|cause| cause.is::<RequestFailure>())
    );
    origin.finish(Ok(())).await
}

#[tokio::test]
async fn dropping_an_origin_ends_its_original_held_response_with_runtime_live() -> TestResult {
    let identity = TestIdentity::generate()?;
    let mut origin = Origin::start(&identity)?;
    let address = origin.address;
    let mut requests = Requests::default();
    let client = client_builder(&identity).build()?;
    finish(send(&client, &origin.uri("warm")).await?).await?;
    let held = spawn_held(&mut requests, &client, &origin, &["held"]);
    assert_eq!(origin.settle(2).await?, (1, 2));
    drop(origin);
    let outcome = timeout(Duration::from_secs(5), requests.peer(held.start)?.join()).await??;
    assert!(outcome.is_err(), "held response survived its origin owner");
    let rebound = timeout(Duration::from_secs(5), async {
        loop {
            match phantom_testkit::udp::bind(address) {
                Ok(socket) => break Ok::<_, std::io::Error>(socket),
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                    tokio::task::yield_now().await;
                }
                Err(error) => break Err(error),
            }
        }
    })
    .await??;
    assert_eq!(rebound.local_addr()?, address);
    requests.finish(Ok(())).await
}

#[tokio::test]
async fn explicit_origin_cleanup_joins_the_original_response_tree() -> TestResult {
    let identity = TestIdentity::generate()?;
    let mut origin = Origin::start(&identity)?;
    let address = origin.address;
    let mut requests = Requests::default();
    let client = client_builder(&identity).build()?;
    finish(send(&client, &origin.uri("warm")).await?).await?;
    let held = spawn_held(&mut requests, &client, &origin, &["held"]);
    assert_eq!(origin.settle(2).await?, (1, 2));
    origin.finish(Ok(())).await?;
    let outcome = timeout(Duration::from_secs(5), requests.peer(held.start)?.join()).await??;
    assert!(outcome.is_err(), "held response survived explicit cleanup");
    let rebound = phantom_testkit::udp::bind(address)?;
    assert_eq!(rebound.local_addr()?, address);
    requests.finish(Ok(())).await
}

#[tokio::test]
async fn a_real_held_response_failure_keeps_its_original_watch_error() -> TestResult {
    let identity = TestIdentity::generate()?;
    let mut origin = Origin::start(&identity)?;
    let mut requests = Requests::default();
    let client = client_builder(&identity).build()?;
    finish(send(&client, &origin.uri("warm")).await?).await?;
    let held = spawn_held(&mut requests, &client, &origin, &["held"]);
    assert_eq!(origin.settle(2).await?, (1, 2));
    let (replacement, _) = watch::channel(false);
    drop(std::mem::replace(&mut origin.release, replacement));
    let error = timeout(TEST_TIMEOUT, origin.next_request())
        .await?
        .err()
        .ok_or("original response failure was hidden")?;
    assert!(error.is::<watch::error::RecvError>());
    let error = origin
        .finish(Err::<(), _>(error))
        .await
        .err()
        .ok_or("response failure was discarded during cleanup")?;
    assert!(error.is::<watch::error::RecvError>());
    let outcome = timeout(Duration::from_secs(5), requests.peer(held.start)?.join()).await??;
    assert!(
        outcome.is_err(),
        "failed response worker unexpectedly succeeded"
    );
    requests.finish(Ok(())).await?;
    Ok(())
}

#[tokio::test]
async fn a_closed_event_stream_does_not_satisfy_the_quiet_window() -> TestResult {
    let identity = TestIdentity::generate()?;
    let mut origin = Origin::start(&identity)?;
    let client = client_builder(&identity).build()?;
    finish(send(&client, &origin.uri("warm")).await?).await?;
    origin.events.close();
    let result = origin.settle(1).await;
    assert!(result.is_err(), "closed origin was treated as a quiet one");
    origin.finish(Ok(())).await
}
