use super::*;

#[tokio::test]
async fn dropping_an_origin_ends_its_original_held_response_with_runtime_live() -> TestResult {
    let identity = TestIdentity::generate()?;
    let mut origin = Origin::start(&identity)?;
    let address = origin.address;
    let client = client_builder(&identity).build()?;
    finish(send(&client, &origin.uri("warm")).await?).await?;
    let mut held = spawn_held(&client, &origin, &["held"]);
    assert_eq!(origin.settle(2).await?, (1, 2));
    drop(origin);
    let outcome = timeout(Duration::from_secs(5), held[0].join()).await??;
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
    Ok(())
}

#[tokio::test]
async fn explicit_origin_cleanup_joins_the_original_response_tree() -> TestResult {
    let identity = TestIdentity::generate()?;
    let mut origin = Origin::start(&identity)?;
    let address = origin.address;
    let client = client_builder(&identity).build()?;
    finish(send(&client, &origin.uri("warm")).await?).await?;
    let mut held = spawn_held(&client, &origin, &["held"]);
    assert_eq!(origin.settle(2).await?, (1, 2));
    origin.finish(Ok(())).await?;
    let outcome = timeout(Duration::from_secs(5), held[0].join()).await??;
    assert!(outcome.is_err(), "held response survived explicit cleanup");
    let rebound = phantom_testkit::udp::bind(address)?;
    assert_eq!(rebound.local_addr()?, address);
    Ok(())
}

#[tokio::test]
async fn a_real_held_response_failure_keeps_its_original_watch_error() -> TestResult {
    let identity = TestIdentity::generate()?;
    let mut origin = Origin::start(&identity)?;
    let client = client_builder(&identity).build()?;
    finish(send(&client, &origin.uri("warm")).await?).await?;
    let held = spawn_held(&client, &origin, &["held"]);
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
    drop(held);
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
