use std::{
    error::Error,
    fmt,
    future::{pending, poll_fn},
    io,
    sync::Arc,
    task::Poll,
    time::Duration,
};

use tokio::{
    sync::{oneshot, watch},
    task::AbortHandle,
    time::{advance, error::Elapsed, timeout},
};

use super::{QuicOrigin, TEST_ECH_KEYS, TEST_TIMEOUT, origin_identity};
use crate::support::{tls::TestResult, tunnel_proxy::connection_peer::finish_with_cleanup};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(2);

struct CountControl {
    recorded: watch::Sender<usize>,
    parent_entered: oneshot::Receiver<()>,
    tcp_entered: Option<oneshot::Receiver<()>>,
    backup: CountBackup,
}

impl CountControl {
    async fn entered(&mut self) -> TestResult<()> {
        timeout(CLEANUP_TIMEOUT, &mut self.parent_entered).await??;
        if let Some(entered) = &mut self.tcp_entered {
            timeout(CLEANUP_TIMEOUT, entered).await??;
        }

        Ok(())
    }
}

struct CountBackup {
    parent: AbortHandle,
    tcp: Option<AbortHandle>,
    parent_destroyed: oneshot::Receiver<()>,
    tcp_destroyed: Option<oneshot::Receiver<()>>,
}

impl CountBackup {
    fn abort(&self) {
        self.parent.abort();
        if let Some(tcp) = &self.tcp {
            tcp.abort();
        }
    }

    async fn stop(&mut self) -> TestResult<()> {
        self.abort();
        let parent = match timeout(CLEANUP_TIMEOUT, &mut self.parent_destroyed).await {
            Ok(result) => result.map_err(Into::into),
            Err(error) => Err(error.into()),
        };
        let tcp = match &mut self.tcp_destroyed {
            Some(destroyed) => match timeout(CLEANUP_TIMEOUT, destroyed).await {
                Ok(result) => result.map_err(Into::into),
                Err(error) => Err(error.into()),
            },
            None => Ok(()),
        };
        finish_with_cleanup(parent, tcp)
    }
}

impl Drop for CountBackup {
    fn drop(&mut self) {
        self.abort();
    }
}

struct TaskDestroyed(Option<oneshot::Sender<()>>);

impl Drop for TaskDestroyed {
    fn drop(&mut self) {
        if let Some(destroyed) = self.0.take() {
            // A cancelled control may already have dropped its receiver.
            let _ = destroyed.send(());
        }
    }
}

#[derive(Debug)]
struct ParentFailure(Arc<()>);

impl fmt::Display for ParentFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled count parent failure")
    }
}

impl Error for ParentFailure {}

#[tokio::test(start_paused = true)]
async fn a_missing_quic_count_retains_its_actual_elapsed_cause() -> TestResult<()> {
    missing_count(
        0,
        None,
        1,
        0,
        "the origin saw fewer than 1 QUIC connections",
    )
    .await
}

#[tokio::test(start_paused = true)]
async fn a_missing_tcp_count_retains_its_actual_elapsed_cause() -> TestResult<()> {
    missing_count(
        1,
        Some(0),
        1,
        1,
        "the origin served fewer than 1 TCP connections",
    )
    .await
}

#[tokio::test(start_paused = true)]
async fn a_ready_quic_count_preserves_the_parent_result() -> TestResult<()> {
    ready_counts(2, None, 2, 0).await
}

#[tokio::test(start_paused = true)]
async fn ready_quic_and_tcp_counts_preserve_the_tcp_count() -> TestResult<()> {
    ready_counts(2, Some(3), 2, 3).await
}

#[tokio::test(start_paused = true)]
async fn ready_counts_preserve_a_concrete_parent_inner_failure() -> TestResult<()> {
    let identity = Arc::new(());
    let failure = io::Error::new(
        io::ErrorKind::PermissionDenied,
        ParentFailure(Arc::clone(&identity)),
    );
    let (origin, mut control) = controlled_origin(1, Some(1), Some(failure))?;
    let outcome = async {
        control.entered().await?;
        origin
            .finish(1, 1)
            .await
            .err()
            .ok_or_else(|| "failed count parent completed successfully".into())
    }
    .await;
    let error = finish_with_cleanup(outcome, control.backup.stop().await)?;

    let io = error
        .downcast_ref::<io::Error>()
        .ok_or("missing original count parent I/O failure")?;
    assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);

    let failure = io
        .get_ref()
        .and_then(|error| error.downcast_ref::<ParentFailure>())
        .ok_or("missing original typed count parent cause")?;

    assert!(Arc::ptr_eq(&identity, &failure.0));
    Ok(())
}

async fn missing_count(
    recorded: usize,
    served: Option<usize>,
    quic: usize,
    tcp: usize,
    context: &str,
) -> TestResult<()> {
    let (origin, mut control) = controlled_origin(recorded, served, None)?;
    let outcome = async {
        control.entered().await?;

        if *control.recorded.borrow() != recorded {
            return Err("QUIC count control changed its initial value".into());
        }

        if let Some((served, _)) = &origin.tcp
            && *served.borrow() != 0
        {
            return Err("TCP count control was already satisfied".into());
        }

        let mut finish = Box::pin(origin.finish(quic, tcp));
        let first_poll = poll_fn(|context| Poll::Ready(finish.as_mut().poll(context))).await;
        if first_poll.is_ready() {
            return Err("actual count wait was not pending".into());
        }

        advance(TEST_TIMEOUT).await;
        finish
            .await
            .err()
            .ok_or_else(|| "missing count completed successfully".into())
    }
    .await;
    let error = finish_with_cleanup(outcome, control.backup.stop().await)?;
    assert_eq!(error.to_string(), context);
    assert!(
        has_elapsed(error.as_ref()),
        "count deadline discarded its actual typed Elapsed cause"
    );
    Ok(())
}

async fn ready_counts(
    recorded: usize,
    served: Option<usize>,
    quic: usize,
    tcp: usize,
) -> TestResult<()> {
    let (origin, mut control) = controlled_origin(recorded, served, None)?;
    let outcome = async {
        control.entered().await?;

        if *control.recorded.borrow() != recorded {
            return Err("QUIC count control changed its initial value".into());
        }

        origin.finish(quic, tcp).await
    }
    .await;
    let (observed, served) = finish_with_cleanup(outcome, control.backup.stop().await)?;
    assert!(observed.is_empty());
    assert_eq!(served, tcp);
    Ok(())
}

fn controlled_origin(
    recorded_count: usize,
    served_count: Option<usize>,
    failure: Option<io::Error>,
) -> TestResult<(QuicOrigin, CountControl)> {
    let identity = origin_identity()?;
    let context = QuicOrigin::context(&identity, 1, &TEST_ECH_KEYS[0])?;
    let (stop, stopped) = oneshot::channel();
    let (recorded, recorded_receiver) = watch::channel(recorded_count);
    let (parent_started, parent_entered) = oneshot::channel();
    let (parent_done, parent_destroyed) = oneshot::channel();
    let parent_guard = TaskDestroyed(Some(parent_done));
    let task = tokio::spawn(async move {
        let _guard = parent_guard;
        parent_started
            .send(())
            .map_err(|_| "count control closed")?;
        stopped.await?;
        match failure {
            Some(error) => Err(error.into()),
            None => Ok(Vec::new()),
        }
    });
    let mut backup = CountBackup {
        parent: task.abort_handle(),
        tcp: None,
        parent_destroyed,
        tcp_destroyed: None,
    };

    let mut tcp_entered = None;
    let tcp = served_count.map(|count| {
        let served = Arc::new(watch::Sender::new(count));
        let (started, entered) = oneshot::channel();
        let (done, destroyed) = oneshot::channel();
        let guard = TaskDestroyed(Some(done));
        let task = tokio::spawn(async move {
            let _guard = guard;
            // Entry is not a network witness; cancellation may drop its receiver.
            let _ = started.send(());
            pending::<()>().await;
        });
        backup.tcp = Some(task.abort_handle());
        backup.tcp_destroyed = Some(destroyed);
        tcp_entered = Some(entered);
        (served, task)
    });
    let origin = QuicOrigin {
        port: 0,
        context,
        stop,
        task,
        recorded: recorded_receiver,
        tcp,
    };

    Ok((
        origin,
        CountControl {
            recorded,
            parent_entered,
            tcp_entered,
            backup,
        },
    ))
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
