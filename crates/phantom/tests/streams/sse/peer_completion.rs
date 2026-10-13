use std::{
    any::Any,
    error::Error,
    fmt,
    future::Future,
    pin::Pin,
    sync::{Mutex, mpsc},
    task::{Context, Poll},
    thread::{self, JoinHandle},
    time::Duration,
};

use tokio::{
    sync::{oneshot, watch},
    task::{AbortHandle, JoinError},
    time::{Instant, timeout, timeout_at},
};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, connection_peer::FixtureFailures, finish_with_cleanup},
};

use super::{TEST_TIMEOUT, TestResult};

/// Own an SSE worker and distinguish its normal stop from external cancellation.
#[derive(Debug)]
pub(super) struct SsePeer<P> {
    worker: ConnectionPeer<TestResult<WorkerOutcome<P>>>,
    stop: watch::Sender<bool>,
    collected: bool,
    failure: Option<Box<dyn Error + Send + Sync>>,
}

#[derive(Debug)]
enum WorkerOutcome<P> {
    Completed(P),
    Stopped,
}

impl<P: Send + 'static> SsePeer<P> {
    pub(super) fn spawn(future: impl Future<Output = TestResult<P>> + Send + 'static) -> Self {
        let (stop, mut stopped) = watch::channel(false);
        let worker = ConnectionPeer::spawn(async move {
            tokio::select! {
                biased;
                result = future => result.map(WorkerOutcome::Completed),
                result = stopped.changed() => {
                    result?;
                    Ok(WorkerOutcome::Stopped)
                }
            }
        });
        Self {
            worker,
            stop,
            collected: false,
            failure: None,
        }
    }

    pub(super) fn abort_handle(&self) -> AbortHandle {
        self.worker.abort_handle()
    }

    pub(super) fn abort(&self) {
        self.worker.abort();
    }

    pub(super) fn is_finished(&self) -> bool {
        self.worker.is_finished()
    }

    pub(super) fn stop_signal(&self) -> watch::Sender<bool> {
        self.stop.clone()
    }

    pub(super) fn request_stop(&self) {
        self.stop.send_replace(true);
    }

    pub(super) fn is_collected(&self) -> bool {
        self.collected
    }

    fn retain_failure(&mut self, error: Box<dyn Error + Send + Sync>) {
        self.failure = Some(match self.failure.take() {
            Some(primary) => Box::new(FixtureFailures {
                primary,
                cleanup: error,
            }),
            None => error,
        });
    }

    /// Keep the caller's original failure on the owner before any cleanup await.
    pub(super) async fn finish<C>(
        &mut self,
        caller: TestResult<C>,
        peer_timeout: Duration,
    ) -> TestResult<(C, P)> {
        let value = match caller {
            Ok(value) => Some(value),
            Err(error) => {
                self.retain_failure(error);
                None
            }
        };
        if self.failure.is_some() {
            self.request_stop();
        }
        let wait_timeout = if self.failure.is_some() {
            TEST_TIMEOUT
        } else {
            peer_timeout
        };

        let joined = match timeout(wait_timeout, &mut *self).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(error.into()),
            Err(elapsed) => {
                self.retain_failure(
                    FixtureDeadline::new("SSE peer exceeded its deadline", elapsed).into(),
                );
                self.request_stop();
                match timeout(TEST_TIMEOUT, &mut *self).await {
                    Ok(Ok(result)) => result,
                    Ok(Err(error)) => Err(error.into()),
                    Err(elapsed) => Err(FixtureDeadline::new(
                        "SSE peer cleanup exceeded its deadline",
                        elapsed,
                    )
                    .into()),
                }
            }
        };
        let peer_value = match joined {
            Ok(value) => value,
            Err(error) => {
                self.retain_failure(error);
                None
            }
        };
        if let Some(error) = self.failure.take() {
            return Err(error);
        }

        let value = value.ok_or("SSE caller completed without a value")?;
        let peer_value = peer_value.ok_or("SSE peer stopped without a caller failure")?;
        Ok((value, peer_value))
    }
}

impl<P> Future for SsePeer<P> {
    type Output = Result<TestResult<Option<P>>, JoinError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        if this.collected {
            return Poll::Ready(Ok(Err("SSE peer outcome already collected".into())));
        }
        let joined = match Pin::new(&mut this.worker).poll(context) {
            Poll::Ready(joined) => joined,
            Poll::Pending => return Poll::Pending,
        };
        this.collected = true;
        Poll::Ready(joined.map(|result| {
            result.map(|outcome| match outcome {
                WorkerOutcome::Completed(value) => Some(value),
                WorkerOutcome::Stopped => None,
            })
        }))
    }
}

/// Keep the original peer outside its caller deadline, then collect both outcomes.
pub(super) async fn run<C, P: Send + 'static>(
    peer: &mut SsePeer<P>,
    caller_deadline: Instant,
    peer_timeout: Duration,
    caller: impl Future<Output = TestResult<C>>,
) -> TestResult<(C, P)> {
    tokio::pin!(caller);
    let caller_result = match timeout_at(caller_deadline, &mut caller).await {
        Ok(result) => result,
        Err(elapsed) => Err(FixtureDeadline::new("SSE test exceeded its deadline", elapsed).into()),
    };
    peer.finish(caller_result, peer_timeout).await
}

/// Bound paused-clock callers without adding a timer to their virtual protocol clock.
pub(super) async fn run_wall_clock<C, P: Send + 'static>(
    peer: &mut SsePeer<P>,
    caller_deadline: std::time::Instant,
    peer_timeout: Duration,
    caller: impl Future<Output = TestResult<C>>,
) -> TestResult<(C, P)> {
    let mut deadline = match WallClockDeadline::start(caller_deadline) {
        Ok(deadline) => deadline,
        Err(error) => return peer.finish(Err(error), peer_timeout).await,
    };
    tokio::pin!(caller);
    let caller_result = tokio::select! {
        biased;
        result = &mut caller => Some(result),
        result = &mut deadline.completed => match result {
            Ok(()) => None,
            Err(error) => Some(Err(error.into())),
        },
    };
    let timer_result = deadline.finish();
    let caller_result = match caller_result {
        Some(result) => finish_with_cleanup(result, timer_result),
        None => match timer_result {
            Err(error) => Err(error),
            Ok(()) => Err("SSE wall-clock deadline stopped before its caller completed".into()),
        },
    };
    peer.finish(caller_result, peer_timeout).await
}

#[derive(Debug)]
struct WallClockDeadline {
    stop: Option<mpsc::Sender<()>>,
    worker: Option<JoinHandle<Result<(), mpsc::RecvTimeoutError>>>,
    completed: oneshot::Receiver<()>,
}

impl WallClockDeadline {
    fn start(deadline: std::time::Instant) -> TestResult<Self> {
        let (stop, stopped) = mpsc::channel();
        let (complete, completed) = oneshot::channel();
        let worker = thread::Builder::new()
            .name("sse-caller-deadline".into())
            .spawn(move || {
                let result = stopped
                    .recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()));
                // A dropped caller no longer needs this wake; the original result
                // remains on the joined worker rather than in the notification.
                let _ = complete.send(());
                result
            })?;
        Ok(Self {
            stop: Some(stop),
            worker: Some(worker),
            completed,
        })
    }

    fn stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            // A failed send means the worker already retired its receiver.
            // Its original expiry or panic is collected by the following join.
            let _ = stop.send(());
        }
    }

    fn finish(mut self) -> TestResult<()> {
        self.stop();
        let worker = self
            .worker
            .take()
            .ok_or("SSE deadline worker already collected")?;
        match worker.join() {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(WallClockWaitFailure(error).into()),
            Err(payload) => Err(WallClockPanic(Mutex::new(payload)).into()),
        }
    }
}

impl Drop for WallClockDeadline {
    fn drop(&mut self) {
        self.stop();
        if let Some(worker) = self.worker.take() {
            // An externally destroyed caller cannot receive timer failures.
            // Stop and join this finite wait; peer Drop remains an abort fallback.
            let _ = worker.join();
        }
    }
}

#[derive(Debug)]
struct WallClockWaitFailure(mpsc::RecvTimeoutError);

impl fmt::Display for WallClockWaitFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.0 {
            mpsc::RecvTimeoutError::Timeout => "SSE caller exceeded its wall-clock deadline",
            mpsc::RecvTimeoutError::Disconnected => "SSE deadline stop channel disconnected",
        })
    }
}

impl Error for WallClockWaitFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

// Mutex preserves the original Send-only panic payload behind a Sync error.
struct WallClockPanic(Mutex<Box<dyn Any + Send>>);

impl fmt::Debug for WallClockPanic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("WallClockPanic")
            .field(&self.0)
            .finish()
    }
}

impl fmt::Display for WallClockPanic {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SSE wall-clock deadline worker panicked")
    }
}

impl Error for WallClockPanic {}

#[cfg(test)]
mod tests {
    use std::{net::Ipv4Addr, sync::mpsc::RecvTimeoutError, time::Duration};

    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        time::{Instant, advance, timeout},
    };

    use crate::support::tls::is_peer_gone;

    use super::{SsePeer, TEST_TIMEOUT, TestResult, run_wall_clock};

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn wall_clock_expiry_collects_the_actual_socket_peer_without_advancing_its_clock()
    -> TestResult<()> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let mut peer = SsePeer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            stream.write_all(b"!").await?;
            stream.read_u8().await?;
            Ok(())
        });
        let mut client = TcpStream::connect(address).await?;
        assert_eq!(client.read_u8().await?, b'!');

        let started = Instant::now();
        let deadline = std::time::Instant::now() + Duration::from_millis(50);
        let error = run_wall_clock(&mut peer, deadline, TEST_TIMEOUT, async {
            advance(Duration::from_secs(10)).await;
            client.read_u8().await?;
            Ok(())
        })
        .await
        .err()
        .ok_or("pending socket caller completed before wall-clock expiry")?;
        assert_eq!(
            error
                .source()
                .and_then(|cause| cause.downcast_ref::<RecvTimeoutError>()),
            Some(&RecvTimeoutError::Timeout),
        );
        assert_eq!(
            Instant::now().duration_since(started),
            Duration::from_secs(10)
        );
        assert!(
            peer.is_collected(),
            "original peer outcome was not collected"
        );

        tokio::time::resume();
        match timeout(TEST_TIMEOUT, client.read(&mut [0_u8; 1])).await? {
            Ok(0) => {}
            Err(error) if is_peer_gone(&error) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err("stopped SSE peer left unexpected response bytes".into()),
        }
        let rebound = TcpListener::bind(address).await?;
        assert_eq!(rebound.local_addr()?, address);
        Ok(())
    }
}
