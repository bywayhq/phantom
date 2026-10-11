use phantom::RequestError;
use tokio::task::JoinError;

use crate::support::tunnel_proxy::connection_peer::FixtureFailures;

use super::{
    Backup, HEAD, TestIdentity, TestResult, collect, finish_with_cleanup, rejected_caller,
    retains_fault,
};

#[tokio::test]
async fn dropping_the_actual_collection_closes_the_original_pending_managed_id_worker()
-> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut backup = Backup::prepare(&identity, false).await?;
    let primary = async {
        backup.pending(&identity).await?;
        let peer = backup.take_peer()?;
        let mut collection = Box::pin(collect(Ok(None), peer));
        assert!(futures_util::poll!(&mut collection).is_pending());

        drop(collection);
        backup.destroyed().await
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn real_caller_failure_closes_the_original_pending_managed_id_worker() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut backup = Backup::prepare(&identity, false).await?;
    let primary = async {
        backup.pending(&identity).await?;
        let caller = rejected_caller(&identity);
        assert!(caller.is_err());
        let error = backup
            .collect(caller)
            .await
            .err()
            .ok_or("real managed-ID caller failure succeeded")?;
        let original = error
            .downcast_ref::<RequestError>()
            .ok_or("original managed-ID caller error type changed")?;
        assert_eq!(original.kind(), phantom::RequestErrorKind::InvalidUri);
        assert!(
            std::error::Error::source(original)
                .is_some_and(|source| source.is::<http::uri::InvalidUri>())
        );

        backup.destroyed().await
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn real_caller_failure_keeps_the_completed_original_managed_id_serving_cause()
-> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut backup = Backup::prepare(&identity, true).await?;
    let primary = async {
        backup.pending(&identity).await?;
        backup.responses().await?;
        assert!(backup.state.borrow().fault_taken);
        let caller = rejected_caller(&identity);
        assert!(caller.is_err());
        let error = backup
            .collect(caller)
            .await
            .err()
            .ok_or("real caller and original serving failure succeeded")?;
        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("caller failure discarded the completed original managed-ID serving cause")?;
        let original = failures
            .primary
            .downcast_ref::<RequestError>()
            .ok_or("original managed-ID caller error type changed")?;
        assert_eq!(original.kind(), phantom::RequestErrorKind::InvalidUri);
        assert!(
            std::error::Error::source(original)
                .is_some_and(|source| source.is::<http::uri::InvalidUri>())
        );

        retains_fault(failures.cleanup.as_ref(), &backup.marker)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn healthy_original_managed_id_worker_keeps_three_literal_requests_and_responses()
-> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut backup = Backup::prepare(&identity, false).await?;
    let primary = async {
        backup.pending(&identity).await?;
        backup.responses().await?;
        let heads = backup.collect(Ok(None)).await?;
        assert_eq!(heads, [std::str::from_utf8(HEAD)?; 3]);
        assert!(!backup.state.borrow().fault_taken);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn explicit_abort_joins_the_original_managed_id_workers_pending_read() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut backup = Backup::prepare(&identity, false).await?;
    let primary = async {
        backup.pending(&identity).await?;
        backup.abort.abort();
        backup.destroyed().await?;
        let error = backup
            .collect(Ok(None))
            .await
            .err()
            .ok_or("original aborted managed-ID worker succeeded")?;
        let original = error
            .downcast_ref::<JoinError>()
            .ok_or("original managed-ID worker cancellation was replaced")?;
        assert!(original.is_cancelled());
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn canonical_collection_keeps_the_completed_original_managed_id_serving_cause()
-> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut backup = Backup::prepare(&identity, true).await?;
    let primary = async {
        backup.pending(&identity).await?;
        backup.responses().await?;
        assert!(backup.state.borrow().fault_taken);
        let error = backup
            .collect(Ok(None))
            .await
            .err()
            .ok_or("original completed managed-ID serving failure succeeded")?;

        retains_fault(error.as_ref(), &backup.marker)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}
