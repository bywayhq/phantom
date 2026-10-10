use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    task::Poll,
    time::Duration,
};

use phantom_profile::browser::chrome::v154_http2;
use tokio::{io::duplex, sync::oneshot, task::AbortHandle, time::timeout};

use super::{finish_lifecycle_peer, spawn_reset_peer, wait_for_origin_driver};
use crate::http2::PreparedRequest;
use crate::http2::tests::{
    TestResult, next_nonempty_data, reset_observing_server, send_once, target,
};
use crate::tracing_test::OutcomeSubscriber;

const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);
const QUIET_WINDOW: Duration = Duration::from_millis(100);

#[tokio::test]
async fn a_primary_failure_observes_the_already_completed_peer_failure() -> TestResult<()> {
    let (client, server) = duplex(64 * 1024);
    let peer = spawn_reset_peer(async move {
        let (reason, closed) = reset_observing_server(server).await?;
        assert_eq!(reason, ::http2::Reason::CANCEL);
        assert!(closed);
        Err(CompletedPeerFault {
            cause: ::http2::Error::from(::http2::Reason::INTERNAL_ERROR),
        }
        .into())
    });
    let cleanup = ResetCleanup(peer.abort_handle());
    let response = send_once(client, {
        let settings = v154_http2();
        let target = target()?;
        move || {
            PreparedRequest::new(
                &settings,
                http::Method::GET,
                "example.test",
                target,
                vec![],
                None,
            )
        }
    })
    .await?;
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    assert_eq!(next_nonempty_data(&mut body).await?, "partial");
    drop(body);
    timeout(CONTROL_TIMEOUT, until_finished(&cleanup.0)).await?;

    let (sender, receiver) = oneshot::channel::<()>();
    drop(sender);
    let primary = receiver.await.map_err(Into::into);
    let observed = finish_lifecycle_peer(peer, primary).await;
    cleanup.stop().await?;
    let error = observed
        .err()
        .ok_or("primary failure was accepted as success")?;

    assert!(has_cause::<oneshot::error::RecvError>(&*error));
    assert!(error.to_string().contains("peer marker 913"));
    Ok(())
}

#[tokio::test]
async fn dropping_lifecycle_observation_stops_a_peer_after_actual_partial_data() -> TestResult<()> {
    let (client, server) = duplex(64 * 1024);
    let peer = spawn_reset_peer(reset_observing_server(server));
    let cleanup = ResetCleanup(peer.abort_handle());
    let response = send_once(client, {
        let settings = v154_http2();
        let target = target()?;
        move || {
            PreparedRequest::new(
                &settings,
                http::Method::GET,
                "example.test",
                target,
                vec![],
                None,
            )
        }
    })
    .await?;
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    assert_eq!(next_nonempty_data(&mut body).await?, "partial");

    let mut observation = Box::pin(finish_lifecycle_peer(peer, Ok(())));
    poll_fn(|context| match observation.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(Ok(())),
        Poll::Ready(result) => Poll::Ready(match result {
            Err(error) => Err(error),
            Ok(()) => Err("live partial response peer finished before body Drop".into()),
        }),
    })
    .await?;
    drop(observation);
    let stopped = timeout(QUIET_WINDOW, until_finished(&cleanup.0))
        .await
        .is_ok();

    // Snapshot ownership while the body is live, then let its reset reach the peer.
    drop(body);
    let drained = timeout(CONTROL_TIMEOUT, until_finished(&cleanup.0)).await;
    let cleanup_result = cleanup.stop().await;
    match (drained, cleanup_result) {
        (Ok(()), Ok(())) => {}
        (Err(error), Ok(())) => return Err(error.into()),
        (Ok(()), Err(error)) => return Err(error),
        (Err(primary), Err(cleanup)) => {
            return Err(LifecycleCleanupFailure { primary, cleanup }.into());
        }
    }

    assert!(
        stopped,
        "partial-response peer outlived its observation boundary"
    );
    Ok(())
}

#[tokio::test]
async fn a_driver_telemetry_deadline_keeps_its_actual_elapsed_cause() -> TestResult<()> {
    let (client, server) = duplex(64 * 1024);
    let peer = spawn_reset_peer(reset_observing_server(server));
    let cleanup = ResetCleanup(peer.abort_handle());
    let response = send_once(client, {
        let settings = v154_http2();
        let target = target()?;
        move || {
            PreparedRequest::new(
                &settings,
                http::Method::GET,
                "example.test",
                target,
                vec![],
                None,
            )
        }
    })
    .await?;
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    assert_eq!(next_nonempty_data(&mut body).await?, "partial");
    drop(body);
    finish_lifecycle_peer(peer, Ok(())).await?;
    cleanup.stop().await?;

    // A separate subscriber saw none of that completed driver's events.
    let absent_observer = OutcomeSubscriber::default();
    let error = wait_for_origin_driver(&absent_observer)
        .await
        .err()
        .ok_or("absent telemetry observer was treated as complete")?;

    assert!(has_cause::<tokio::time::error::Elapsed>(&*error));
    Ok(())
}

#[tokio::test]
async fn a_completed_peer_http2_failure_is_observed_with_its_original_type() -> TestResult<()> {
    let (client, server) = duplex(64 * 1024);
    let peer = spawn_reset_peer(async move {
        let (reason, closed) = reset_observing_server(server).await?;
        assert_eq!(reason, ::http2::Reason::CANCEL);
        assert!(closed);
        Err(CompletedPeerFault {
            cause: ::http2::Error::from(::http2::Reason::INTERNAL_ERROR),
        }
        .into())
    });
    let cleanup = ResetCleanup(peer.abort_handle());
    let response = send_once(client, {
        let settings = v154_http2();
        let target = target()?;
        move || {
            PreparedRequest::new(
                &settings,
                http::Method::GET,
                "example.test",
                target,
                vec![],
                None,
            )
        }
    })
    .await?;
    assert_eq!(response.status(), 200);
    let mut body = response.into_body();
    assert_eq!(next_nonempty_data(&mut body).await?, "partial");
    drop(body);
    let observed = finish_lifecycle_peer(peer, Ok(())).await;
    cleanup.stop().await?;
    let error = observed
        .err()
        .ok_or("typed peer failure was accepted as success")?;

    let cause = h2_cause(&*error).ok_or("completed peer HTTP/2 error lost its type")?;
    assert_eq!(cause.reason(), Some(::http2::Reason::INTERNAL_ERROR));
    Ok(())
}

#[derive(Debug)]
struct LifecycleCleanupFailure {
    primary: tokio::time::error::Elapsed,
    cleanup: Box<dyn Error + Send + Sync>,
}

impl fmt::Display for LifecycleCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}; lifecycle control cleanup failed: {}",
            self.primary, self.cleanup
        )
    }
}

impl Error for LifecycleCleanupFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.primary)
    }
}

struct ResetCleanup(AbortHandle);

impl ResetCleanup {
    async fn stop(self) -> TestResult<()> {
        self.0.abort();
        timeout(CONTROL_TIMEOUT, until_finished(&self.0)).await?;
        Ok(())
    }
}

impl Drop for ResetCleanup {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn until_finished(handle: &AbortHandle) {
    while !handle.is_finished() {
        tokio::task::yield_now().await;
    }
}

fn has_cause<E: Error + 'static>(mut error: &(dyn Error + 'static)) -> bool {
    loop {
        if error.is::<E>() {
            return true;
        }
        let Some(source) = error.source() else {
            return false;
        };
        error = source;
    }
}

fn h2_cause<'a>(mut error: &'a (dyn Error + 'static)) -> Option<&'a ::http2::Error> {
    loop {
        if let Some(cause) = error.downcast_ref::<::http2::Error>() {
            return Some(cause);
        }
        error = error.source()?;
    }
}

#[derive(Debug)]
struct CompletedPeerFault {
    cause: ::http2::Error,
}

impl fmt::Display for CompletedPeerFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "completed peer marker 913: {:?}",
            self.cause.reason()
        )
    }
}

impl Error for CompletedPeerFault {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.cause)
    }
}
