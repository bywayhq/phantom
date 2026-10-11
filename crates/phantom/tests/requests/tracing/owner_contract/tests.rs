use tokio::task::JoinError;

use crate::support::tunnel_proxy::{FixtureFailures, finish_with_cleanup};

use super::{Backup, REQUEST_HEAD, TestResult, retains_fault};

#[tokio::test]
async fn healthy_original_peer_keeps_its_literal_result_and_closes_its_socket() -> TestResult<()> {
    let (mut backup, control, _) = Backup::prepare(false);
    let primary = async {
        backup.pending(control).await?;
        backup.release.take().ok_or("actual release sender missing")?
            .send(()).map_err(|_| "original peer stopped before release")?;
        let observed = backup.collect(Ok(None)).await?;
        backup.closed().await?;
        assert_eq!(observed, REQUEST_HEAD);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn explicit_abort_stops_the_original_waiting_peer() -> TestResult<()> {
    let (mut backup, control, _) = Backup::prepare(false);
    let primary = async {
        backup.pending(control).await?;
        backup.peer.as_ref().ok_or("original peer missing")?.abort();
        let error = backup.collect(Ok(None)).await.err()
            .ok_or("explicitly aborted original peer returned success")?;
        backup.closed().await?;
        let cancelled = error.downcast_ref::<JoinError>()
            .ok_or("original abort result was replaced")?;
        assert!(cancelled.is_cancelled());
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn dropping_the_original_owner_stops_its_peer_before_backup() -> TestResult<()> {
    let (mut backup, control, _) = Backup::prepare(false);
    let primary = async {
        backup.pending(control).await?;
        drop(backup.peer.take());
        backup.closed().await
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn canonical_collection_keeps_the_completed_original_peer_error() -> TestResult<()> {
    let (mut backup, control, identity) = Backup::prepare(true);
    let primary = async {
        let (caller, _) = backup.caller_failure(control).await?;
        assert!(caller.is::<phantom::RequestError>());
        let error = backup.collect(Ok(None)).await.err()
            .ok_or("completed peer failure was accepted")?;
        backup.finished().await?;
        retains_fault(error.as_ref(), &identity)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn real_caller_failure_keeps_the_completed_original_cleanup_cause() -> TestResult<()> {
    let (mut backup, control, identity) = Backup::prepare(true);
    let primary = async {
        let (caller, kind) = backup.caller_failure(control).await?;
        let error = backup.collect(Err(caller)).await.err()
            .ok_or("actual caller failure was discarded")?;
        backup.finished().await?;
        let failures = error.downcast_ref::<FixtureFailures>()
            .ok_or("caller failure discarded its already-completed peer failure")?;
        let original_caller = failures.primary.downcast_ref::<phantom::RequestError>()
            .ok_or("original typed caller error was replaced")?;
        assert_eq!(original_caller.kind(), kind);
        retains_fault(failures.cleanup.as_ref(), &identity)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}
