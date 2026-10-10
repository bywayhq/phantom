use std::{
    error::Error,
    fmt,
    future::{Future, pending, poll_fn},
    task::Poll,
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex},
    sync::oneshot,
    task::AbortHandle,
    time::{Elapsed, timeout},
};

use super::{
    TestResult, bounded_peer_test, host, peer_task::PeerTask, read_head, target,
    wait_for_driver_outcome,
};
use crate::{
    http1::{PreparedGet, send_prepared_upgrade},
    tracing_test::OutcomeSubscriber,
};

const OBSERVATION_WINDOW: Duration = Duration::from_millis(100);
const COMPLETION_DEADLINE: Duration = Duration::from_secs(1);
const RESPONSE: &[u8] = b"HTTP/1.1 204 No Content\r\n\r\n";

async fn exchange(client: &mut DuplexStream) -> std::io::Result<()> {
    client
        .write_all(b"GET /resource?item=1 HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .await?;
    let mut response = vec![0; RESPONSE.len()];
    client.read_exact(&mut response).await?;
    assert_eq!(response, RESPONSE);
    Ok(())
}

async fn cleanup(handle: &AbortHandle) -> TestResult {
    handle.abort();
    timeout(COMPLETION_DEADLINE, async {
        while !handle.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

fn has_elapsed(mut error: &(dyn Error + 'static)) -> bool {
    loop {
        if error.downcast_ref::<Elapsed>().is_some() {
            return true;
        }
        let Some(source) = error.source() else {
            return false;
        };
        error = source;
    }
}

#[tokio::test]
async fn dropping_peer_after_response_releases_its_stream() -> TestResult {
    let (mut client, mut server) = duplex(4096);
    let peer = PeerTask::spawn(async move {
        let request = read_head(&mut server).await?;
        assert_eq!(
            request,
            b"GET /resource?item=1 HTTP/1.1\r\nHost: example.test\r\n\r\n"
        );
        server.write_all(RESPONSE).await?;
        read_head(&mut server).await
    });
    let handle = peer.abort_handle();
    let exchanged = timeout(COMPLETION_DEADLINE, exchange(&mut client)).await;

    drop(peer);
    let mut byte = [0; 1];
    let closed = timeout(OBSERVATION_WINDOW, client.read(&mut byte)).await;
    cleanup(&handle).await?;

    exchanged??;
    assert_eq!(closed??, 0);
    Ok(())
}

#[tokio::test]
async fn cancelling_workflow_after_response_releases_its_peer() -> TestResult {
    let (mut client, mut server) = duplex(4096);
    let (ready_tx, ready_rx) = oneshot::channel();
    let mut workflow = Box::pin(async move {
        let peer = PeerTask::spawn(async move {
            read_head(&mut server).await?;
            server.write_all(RESPONSE).await?;
            read_head(&mut server).await
        });
        let _ = ready_tx.send(peer.abort_handle());
        pending::<()>().await;
        drop(peer);
    });
    poll_fn(|context| {
        assert!(workflow.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    let handle = ready_rx.await?;
    let exchanged = timeout(COMPLETION_DEADLINE, exchange(&mut client)).await;

    drop(workflow);
    let mut byte = [0; 1];
    let closed = timeout(OBSERVATION_WINDOW, client.read(&mut byte)).await;
    cleanup(&handle).await?;

    exchanged??;
    assert_eq!(closed??, 0);
    Ok(())
}

#[tokio::test]
async fn cancelling_workflow_after_upgrade_request_releases_transaction() -> TestResult {
    let (client, mut server) = duplex(4096);
    let prepared = PreparedGet::new(target()?, vec![host()])?;
    let (ready_tx, ready_rx) = oneshot::channel();
    let mut workflow = Box::pin(async move {
        let transaction = PeerTask::spawn(send_prepared_upgrade(client, prepared, None));
        let _ = ready_tx.send(transaction.abort_handle());
        pending::<()>().await;
        drop(transaction);
    });
    poll_fn(|context| {
        assert!(workflow.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    let handle = ready_rx.await?;
    let request = timeout(COMPLETION_DEADLINE, read_head(&mut server)).await;

    drop(workflow);
    let mut byte = [0; 1];
    let closed = timeout(OBSERVATION_WINDOW, server.read(&mut byte)).await;
    cleanup(&handle).await?;

    assert_eq!(
        request??,
        b"GET /resource?item=1 HTTP/1.1\r\nHost: example.test\r\n\r\n"
    );
    assert_eq!(closed??, 0);
    Ok(())
}

#[derive(Debug)]
struct PeerFault(u32);

impl fmt::Display for PeerFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "injected peer fault {}", self.0)
    }
}

impl Error for PeerFault {}

#[tokio::test]
async fn completed_peer_retains_its_typed_failure_after_response() -> TestResult {
    let (mut client, mut server) = duplex(4096);
    let peer = PeerTask::spawn(async move {
        read_head(&mut server).await?;
        server.write_all(RESPONSE).await?;
        Err::<(), _>(std::io::Error::other(PeerFault(731)))
    });
    let handle = peer.abort_handle();
    let exchanged = timeout(COMPLETION_DEADLINE, exchange(&mut client)).await;
    let joined = timeout(COMPLETION_DEADLINE, peer).await;
    cleanup(&handle).await?;

    exchanged??;
    let error = match joined?? {
        Ok(()) => return Err("peer fault was lost".into()),
        Err(error) => error,
    };
    let fault = error
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<PeerFault>())
        .ok_or("typed peer cause was lost")?;
    assert_eq!(fault.0, 731);
    Ok(())
}

#[tokio::test]
async fn absolute_peer_deadline_retains_elapsed() -> TestResult {
    let result = bounded_peer_test(pending::<TestResult>()).await;
    let error = match result {
        Ok(()) => return Err("pending workflow passed its deadline".into()),
        Err(error) => error,
    };
    assert!(
        has_elapsed(error.as_ref()),
        "deadline cause was replaced: {error}"
    );
    Ok(())
}

#[tokio::test]
async fn missing_driver_outcome_retains_elapsed() -> TestResult {
    let subscriber = OutcomeSubscriber::default();
    let result = wait_for_driver_outcome(&subscriber, "complete").await;
    let error = match result {
        Ok(()) => return Err("missing driver outcome was accepted".into()),
        Err(error) => error,
    };
    assert!(
        has_elapsed(error.as_ref()),
        "deadline cause was replaced: {error}"
    );
    assert!(
        subscriber
            .outcomes_for("http1.connection_driver")
            .is_empty()
    );
    Ok(())
}

#[tokio::test]
async fn bounded_peer_workflow_preserves_success_and_typed_error() -> TestResult {
    bounded_peer_test(async { Ok(()) }).await?;
    let result = bounded_peer_test(async { Err(Box::new(PeerFault(732)) as Box<dyn Error>) }).await;
    let error = match result {
        Ok(()) => return Err("workflow fault was lost".into()),
        Err(error) => error,
    };
    let fault = error
        .downcast_ref::<PeerFault>()
        .ok_or("workflow cause was replaced")?;
    assert_eq!(fault.0, 732);
    Ok(())
}
