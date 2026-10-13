use phantom::RequestError;
use tokio::time::timeout;

use crate::support::tunnel_proxy::connection_peer::FixtureFailures;

use super::{Backup, LIMIT, Mode, TestResult, caller, finish_with_cleanup, retains_fault};

#[tokio::test]
async fn healthy_terminal_status_keeps_the_original_wire_and_no_retry_outcome() -> TestResult<()> {
    let mut backup = Backup::prepare(Mode::Healthy).await?;
    let primary = async {
        let body = timeout(
            LIMIT,
            caller(
                &backup.client,
                &format!("http://{}/terminal", backup.address),
                &backup.subscriber,
            ),
        )
        .await??;
        let (_body, (head, no_second_connection)) = backup.collect(Ok(body)).await?;
        backup.destroyed().await?;
        assert_eq!(
            head,
            format!("GET /terminal HTTP/1.1\r\nHost: {}\r\n\r\n", backup.address).as_bytes()
        );
        assert!(no_second_connection);
        assert!(
            backup
                .subscriber
                .retry_reasons_for("client.request")
                .is_empty()
        );
        assert!(
            backup
                .subscriber
                .retries_performed_for("client.request")
                .is_empty()
        );
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn explicit_abort_joins_the_original_terminal_peers_pending_read() -> TestResult<()> {
    let mut backup = Backup::prepare(Mode::Healthy).await?;
    let primary = async {
        backup.pending().await?;
        let peer = backup.take_peer()?;
        peer.abort();
        let error = timeout(LIMIT, peer)
            .await?
            .err()
            .ok_or("original aborted terminal peer succeeded")?;
        backup.destroyed().await?;
        assert!(error.is_cancelled());
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn dropping_the_original_terminal_peer_closes_its_pending_read_before_backup()
-> TestResult<()> {
    let mut backup = Backup::prepare(Mode::Healthy).await?;
    let primary = async {
        backup.pending().await?;
        drop(backup.take_peer()?);
        backup.destroyed().await
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn real_terminal_caller_failure_closes_the_original_pending_peer_before_backup()
-> TestResult<()> {
    let mut backup = Backup::prepare(Mode::Healthy).await?;
    let primary = async {
        backup.pending().await?;
        let caller = backup.rejected_caller().await;
        assert!(caller.is_err());
        let error = backup
            .collect(caller)
            .await
            .err()
            .ok_or("real terminal caller failure succeeded")?;
        let original = error
            .downcast_ref::<RequestError>()
            .ok_or("original terminal caller error type changed")?;
        assert_eq!(original.kind(), phantom::RequestErrorKind::InvalidUri);
        backup.destroyed().await
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn real_terminal_caller_keeps_the_completed_original_flush_failure() -> TestResult<()> {
    let mut backup = Backup::prepare(Mode::FailFlush).await?;
    let primary = async {
        backup.pending().await?;
        backup.response().await?;
        backup.completed().await?;
        backup.destroyed().await?;
        assert!(backup.state.borrow().flushed && backup.state.borrow().fault_taken);
        let caller = backup.rejected_caller().await;
        assert!(caller.is_err());
        let error = backup
            .collect(caller)
            .await
            .err()
            .ok_or("real caller and completed terminal failure succeeded")?;
        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("terminal caller discarded its completed original flush cause")?;
        let original = failures
            .primary
            .downcast_ref::<RequestError>()
            .ok_or("original terminal caller error type changed")?;
        assert_eq!(original.kind(), phantom::RequestErrorKind::InvalidUri);
        retains_fault(failures.cleanup.as_ref(), &backup.marker)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn original_terminal_second_accept_keeps_its_configured_typed_failure() -> TestResult<()> {
    let mut backup = Backup::prepare(Mode::FailAccept).await?;
    let primary = async {
        backup.pending().await?;
        backup.response().await?;
        backup.completed().await?;
        backup.destroyed().await?;
        assert!(backup.state.borrow().accept_pending && backup.state.borrow().fault_taken);
        let error = backup
            .collect(Ok(()))
            .await
            .err()
            .ok_or("original terminal accept failure was reduced to a boolean")?;
        retains_fault(error.as_ref(), &backup.marker)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn original_terminal_collector_expiry_retains_elapsed_and_closes_the_pending_peer()
-> TestResult<()> {
    let mut backup = Backup::prepare(Mode::Healthy).await?;
    let primary = async {
        backup.pending().await?;
        let peer = backup.take_peer()?;
        let observer = LIMIT * 2 + std::time::Duration::from_secs(2);
        let error = timeout(observer, super::collect(Ok(()), peer))
            .await?
            .err()
            .ok_or("original pending terminal collection succeeded without expiring")?;
        assert_eq!(error.to_string(), "terminal-status peer did not finish");
        assert!(
            std::error::Error::source(error.as_ref())
                .is_some_and(|source| source.is::<tokio::time::error::Elapsed>())
        );

        backup.destroyed().await
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}
