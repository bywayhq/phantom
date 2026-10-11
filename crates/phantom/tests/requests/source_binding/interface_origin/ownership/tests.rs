use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinError,
    time::timeout,
};

use crate::support::tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup};

use super::{Backup, LIMIT, Outcome, REQUEST, RESPONSE, TestResult, retains_fault};

#[tokio::test]
async fn healthy_original_interface_origin_keeps_its_literal_response_and_peer() -> TestResult<()> {
    let (mut backup, control, _) = Backup::prepare(false);
    let primary = async {
        backup.pending(control).await?;
        let client = backup
            .client
            .as_mut()
            .ok_or("original raw client missing")?;
        let expected = client.local_addr()?;
        timeout(LIMIT, client.write_all(REQUEST)).await??;
        let peer = backup
            .collect(Ok(Outcome::Answered))
            .await?
            .ok_or("healthy original interface-origin was skipped")?;
        let mut response = vec![0_u8; RESPONSE.len()];
        let client = backup
            .client
            .as_mut()
            .ok_or("original raw client missing")?;
        timeout(LIMIT, client.read_exact(&mut response)).await??;
        backup.closed().await?;
        assert_eq!(response, RESPONSE);
        assert_eq!(peer, expected);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn explicit_abort_joins_the_original_interface_origins_pending_read() -> TestResult<()> {
    let (mut backup, control, _) = Backup::prepare(false);
    let primary = async {
        backup.pending(control).await?;
        backup
            .peer
            .as_ref()
            .ok_or("original interface-origin peer missing")?
            .abort();
        let error = backup
            .collect(Ok(Outcome::Answered))
            .await
            .err()
            .ok_or("aborted original interface-origin returned success")?;
        backup.closed().await?;
        let original = error
            .downcast_ref::<JoinError>()
            .ok_or("original interface-origin cancellation was replaced")?;
        assert!(original.is_cancelled());
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn capability_skip_cancels_the_original_pending_interface_origin() -> TestResult<()> {
    let (mut backup, control, _) = Backup::prepare(false);
    let primary = async {
        backup.pending(control).await?;
        assert!(
            backup
                .collect(Ok(Outcome::CapabilityUnavailable))
                .await?
                .is_none()
        );
        backup.closed().await
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn dropping_the_original_interface_origin_owner_closes_it_before_backup() -> TestResult<()> {
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
async fn canonical_interface_collection_keeps_the_completed_original_io_cause() -> TestResult<()> {
    let (mut backup, control, identity) = Backup::prepare(true);
    let primary = async {
        let (caller, _) = backup.caller_failure(control).await?;
        assert!(caller.is::<super::super::super::RequestError>());
        let error = backup
            .collect(Ok(Outcome::Answered))
            .await
            .err()
            .ok_or("completed original interface-origin failure succeeded")?;
        backup.finished().await?;
        retains_fault(error.as_ref(), &identity)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn real_interface_caller_failure_keeps_the_completed_original_serving_cause() -> TestResult<()>
{
    let (mut backup, control, identity) = Backup::prepare(true);
    let primary = async {
        let (caller, kind) = backup.caller_failure(control).await?;
        let error = backup
            .collect(Err(caller))
            .await
            .err()
            .ok_or("actual interface-origin caller failure was discarded")?;
        backup.finished().await?;
        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("actual interface-origin caller discarded its completed peer cause")?;
        let caller = failures
            .primary
            .downcast_ref::<super::super::super::RequestError>()
            .ok_or("original typed interface-origin caller was replaced")?;
        assert_eq!(caller.kind(), kind);
        retains_fault(failures.cleanup.as_ref(), &identity)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}
