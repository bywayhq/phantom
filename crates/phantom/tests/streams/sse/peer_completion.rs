use std::{
    error::Error,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    sync::watch,
    task::{AbortHandle, JoinError},
    time::{Instant, timeout, timeout_at},
};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, connection_peer::FixtureFailures},
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
