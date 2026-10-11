use phantom::RequestError;

use super::{
    Backup, DESTINATION_RESPONSE, Faults, FixtureFailures, HEAD, ORIGIN_RESPONSE, TestIdentity,
    TestResult, finish_cross_origin, finish_with_cleanup, rejected_caller, retains_fault,
    retains_pair,
};

#[tokio::test]
async fn dropping_the_actual_collection_closes_both_original_pending_workers() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut backup = Backup::prepare(&identity, Faults::None).await?;
    let primary = async {
        backup.pending(&identity).await?;
        let origin = backup.origin.peer.take().ok_or("original origin missing")?;
        let destination = backup
            .destination
            .peer
            .take()
            .ok_or("original destination missing")?;
        let mut collection = Box::pin(finish_cross_origin(Ok(None), origin, destination));
        assert!(futures_util::poll!(&mut collection).is_pending());

        drop(collection);
        let origin = backup.origin.destroyed().await;
        let destination = backup.destination.destroyed().await;
        finish_with_cleanup(origin, destination)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn first_original_failure_closes_the_second_pending_worker_before_backup() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut backup = Backup::prepare(&identity, Faults::Origin).await?;
    let primary = async {
        backup.pending(&identity).await?;
        backup.origin.fault_completed(ORIGIN_RESPONSE).await?;
        assert!(!backup.destination.abort.is_finished());
        let error = backup
            .collect(Ok(None))
            .await
            .err()
            .ok_or("original first serving failure was accepted")?;
        retains_fault(error.as_ref(), &backup.origin.marker)?;

        backup.destination.destroyed().await
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn collection_keeps_both_completed_original_serving_causes() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut backup = Backup::prepare(&identity, Faults::Both).await?;
    let primary = async {
        backup.pending(&identity).await?;
        backup.origin.fault_completed(ORIGIN_RESPONSE).await?;
        backup
            .destination
            .fault_completed(DESTINATION_RESPONSE)
            .await?;
        let error = backup
            .collect(Ok(None))
            .await
            .err()
            .ok_or("both original serving failures were accepted")?;

        retains_pair(error.as_ref(), &backup)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn real_caller_failure_keeps_both_completed_original_serving_causes() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut backup = Backup::prepare(&identity, Faults::Both).await?;
    let primary = async {
        backup.pending(&identity).await?;
        backup.origin.fault_completed(ORIGIN_RESPONSE).await?;
        backup
            .destination
            .fault_completed(DESTINATION_RESPONSE)
            .await?;
        let caller = rejected_caller(&identity);
        assert!(caller.is_err());
        let error = backup
            .collect(caller)
            .await
            .err()
            .ok_or("real caller failure was accepted")?;
        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("caller failure discarded both completed serving causes")?;
        let caller = failures
            .primary
            .downcast_ref::<RequestError>()
            .ok_or("original caller error type changed")?;
        assert_eq!(caller.kind(), phantom::RequestErrorKind::InvalidUri);
        assert!(
            std::error::Error::source(caller)
                .is_some_and(|source| source.is::<http::uri::InvalidUri>())
        );

        retains_pair(failures.cleanup.as_ref(), &backup)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn canonical_collection_keeps_the_first_original_typed_serving_cause() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut backup = Backup::prepare(&identity, Faults::Origin).await?;
    let primary = async {
        backup.pending(&identity).await?;
        backup.origin.fault_completed(ORIGIN_RESPONSE).await?;
        backup.healthy_destination(&identity).await?;
        let error = backup
            .collect(Ok(None))
            .await
            .err()
            .ok_or("original completed serving failure was accepted")?;

        retains_fault(error.as_ref(), &backup.origin.marker)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn explicit_abort_closes_both_original_pending_workers() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut backup = Backup::prepare(&identity, Faults::None).await?;
    let primary = async {
        backup.pending(&identity).await?;
        backup.origin.abort.abort();
        backup.destination.abort.abort();
        backup.origin.destroyed().await?;
        backup.destination.destroyed().await?;
        let origin = backup.origin.cancelled().await;
        let destination = backup.destination.cancelled().await;
        finish_with_cleanup(origin, destination)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn healthy_original_pair_keeps_all_five_literal_requests_and_responses() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut backup = Backup::prepare(&identity, Faults::None).await?;
    let primary = async {
        backup.pending(&identity).await?;
        backup.origin.response(ORIGIN_RESPONSE).await?;
        backup.origin.connection_closed().await?;
        drop(backup.origin.client.take());
        let redirect = format!(
            "HTTP/1.1 302 Found\r\nLocation: https://{}/events\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            backup.destination.address,
        );
        for attempt in 1..3 {
            backup.origin.pending(&identity).await?;
            backup.origin.response(redirect.as_bytes()).await?;
            backup.origin.connection_closed().await?;
            if attempt == 1 {
                drop(backup.origin.client.take());
            }
        }
        backup.origin.destroyed().await?;
        backup.healthy_destination(&identity).await?;
        let (origin, destination) = backup.collect(Ok(None)).await?;
        let expected = std::str::from_utf8(HEAD)?;
        assert_eq!(origin, [expected; 3]);
        assert_eq!(destination, [expected; 2]);
        assert_eq!(backup.origin.state.borrow().heads, 3);
        assert_eq!(backup.destination.state.borrow().heads, 2);
        assert_eq!(backup.origin.state.borrow().shutdowns, 3);
        assert_eq!(backup.destination.state.borrow().shutdowns, 2);
        assert!(!backup.origin.state.borrow().fault_taken);
        assert!(!backup.destination.state.borrow().fault_taken);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn destination_failure_keeps_its_cause_and_closes_the_pending_origin() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut backup = Backup::prepare(&identity, Faults::Destination).await?;
    let primary = async {
        backup.pending(&identity).await?;
        backup.destination.fault_completed(DESTINATION_RESPONSE).await?;
        assert!(!backup.origin.abort.is_finished());

        let retained = match backup.collect(Ok(None)).await {
            Err(error) if error.is::<std::io::Error>() => {
                retains_fault(error.as_ref(), &backup.destination.marker)
            }
            Err(error) => Err(error),
            Ok(_) => Err("original destination serving failure was accepted".into()),
        };
        let closed = backup.origin.destroyed().await;
        finish_with_cleanup(retained, closed)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}
