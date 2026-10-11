use tokio::time::timeout;

use crate::support::tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup};

use super::{Backup, LIMIT, Mode, RequestError, TestResult, retains_fault};

#[tokio::test]
async fn healthy_original_retry_exchange_keeps_its_wire_and_outcomes() -> TestResult<()> {
    let (mut backup, request, server, _) = Backup::prepare(Mode::Healthy);
    let primary = async {
        backup.start(request, server).await?;
        let caller = backup.caller().await;
        let (head, framed, no_second_connection) = backup.collect(caller).await?;
        backup.destroyed().await?;
        let address = backup.address.ok_or("original retry address missing")?;
        assert_eq!(
            head,
            format!(
                "POST /retried HTTP/1.1\r\nHost: {address}\r\nX-First: one\r\nX-Repeat: alpha\r\nX-Repeat: beta\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n\r\n"
            )
            .as_bytes()
        );
        assert_eq!(
            framed,
            b"7\r\npayload\r\n0\r\nX-Trailer: first\r\nX-Trailer: second\r\n\r\n"
        );
        assert!(no_second_connection);
        assert_eq!(
            backup.subscriber.selected_protocols_for("client.request"),
            ["http/1.1"]
        );
        assert_eq!(
            backup.subscriber.retry_reasons_for("client.request"),
            ["connection_setup"]
        );
        assert_eq!(backup.subscriber.retries_performed_for("client.request"), [1]);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn explicit_abort_joins_both_original_pending_retry_tasks() -> TestResult<()> {
    let (mut backup, request, server, _) = Backup::prepare(Mode::HoldResponse);
    let primary = async {
        backup.start(request, server).await?;
        backup.pending().await?;
        let mut exchange = backup.exchange.take().ok_or("original exchange missing")?;
        let request = exchange.request.take().ok_or("original request missing")?;
        let server = exchange.server.take().ok_or("original server missing")?;
        request.abort();
        server.abort();
        let request_error = timeout(LIMIT, request)
            .await?
            .err()
            .ok_or("aborted original request returned success")?;
        let server_error = timeout(LIMIT, server)
            .await?
            .err()
            .ok_or("aborted original server returned success")?;
        backup.destroyed().await?;
        assert!(request_error.is_cancelled());
        assert!(server_error.is_cancelled());
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn canonical_retry_collection_keeps_the_completed_original_flush_cause() -> TestResult<()> {
    let (mut backup, request, server, identity) = Backup::prepare(Mode::FailFlush);
    let primary = async {
        backup.start(request, server).await?;
        backup.caller().await?;
        timeout(
            LIMIT,
            backup
                .state
                .wait_for(|state| state.flushed && state.server_pending),
        )
        .await??;
        backup.release()?;
        backup.server_finished().await?;
        let error = backup
            .collect(Ok(()))
            .await
            .err()
            .ok_or("original retry flush error was accepted")?;
        backup.destroyed().await?;
        assert!(backup.state.borrow().fault_taken);
        retains_fault(error.as_ref(), &identity)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn dropping_the_original_retry_owner_stops_both_tasks_before_backup() -> TestResult<()> {
    let (mut backup, request, server, _) = Backup::prepare(Mode::HoldResponse);
    let primary = async {
        backup.start(request, server).await?;
        backup.pending().await?;
        drop(backup.exchange.take());
        backup.destroyed().await
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn real_retry_caller_failure_keeps_the_completed_original_write_cause() -> TestResult<()> {
    let (mut backup, request, server, identity) = Backup::prepare(Mode::FailWrite);
    let primary = async {
        backup.start(request, server).await?;
        let caller = backup
            .caller()
            .await
            .err()
            .ok_or("faulted original retry server answered the actual caller")?;
        let kind = caller
            .downcast_ref::<RequestError>()
            .ok_or("original retry caller error was replaced")?
            .kind();
        backup.destroyed().await?;
        {
            let state = backup.state.borrow();
            assert!(state.body_read && state.fault_taken);
            let address = backup.address.ok_or("original retry address missing")?;
            assert_eq!(
                state.head,
                format!(
                    "POST /retried HTTP/1.1\r\nHost: {address}\r\nX-First: one\r\nX-Repeat: alpha\r\nX-Repeat: beta\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n\r\n"
                )
                .as_bytes()
            );
            assert_eq!(
                state.framed,
                b"7\r\npayload\r\n0\r\nX-Trailer: first\r\nX-Trailer: second\r\n\r\n"
            );
        }

        let error = backup
            .collect(Err(caller))
            .await
            .err()
            .ok_or("actual retry caller error was accepted")?;
        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("retry caller discarded its completed original server cause")?;
        let original_caller = failures
            .primary
            .downcast_ref::<RequestError>()
            .ok_or("original typed retry caller error was replaced")?;
        assert_eq!(original_caller.kind(), kind);
        retains_fault(failures.cleanup.as_ref(), &identity)
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}
