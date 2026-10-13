use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    sync::oneshot,
    task::{AbortHandle, JoinError, JoinSet},
    time::{Instant, timeout_at},
};

use crate::support::{
    tls::TestResult,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const DRAIN_BUDGET: Duration = Duration::from_secs(5);
const PUBLICATION_GRACE: Duration = Duration::from_secs(1);

/// Owns the coordinator; Drop requests its cancellation without joining it.
pub(crate) struct RelayPeer {
    task: ConnectionPeer<TestResult<()>>,
    stop: Option<oneshot::Sender<Instant>>,
}

impl RelayPeer {
    pub(crate) fn spawn<F>(operation: impl FnOnce(oneshot::Receiver<Instant>) -> F) -> Self
    where
        F: Future<Output = TestResult<()>> + Send + 'static,
    {
        let (stop, stopping) = oneshot::channel();

        Self {
            task: ConnectionPeer::spawn(operation(stopping)),
            stop: Some(stop),
        }
    }

    pub(crate) fn abort(&self) {
        self.task.abort();
    }

    pub(crate) fn abort_handle(&self) -> AbortHandle {
        self.task.abort_handle()
    }

    pub(crate) fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    pub(crate) fn into_aborted_task(self) -> ConnectionPeer<TestResult<()>> {
        self.task.abort();
        self.task
    }

    pub(crate) async fn stop(&mut self) -> TestResult<()> {
        let deadline = Instant::now() + DRAIN_BUDGET;
        if let Some(stop) = self.stop.take() {
            // A disconnected receiver means the coordinator already returned;
            // its actual result below remains authoritative.
            let _ = stop.send(deadline);
        }

        // The coordinator has its own absolute drain deadline. This grace
        // observes publication/join; it does not extend that drain budget.
        timeout_at(deadline + PUBLICATION_GRACE, &mut self.task).await??
    }
}

impl Future for RelayPeer {
    type Output = Result<TestResult<()>, JoinError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.get_mut().task).poll(context)
    }
}

/// Owns every accepted receiver or queued send and observes its typed result.
pub(crate) struct RelayWorkers {
    tasks: JoinSet<TestResult<()>>,
    stops: Vec<oneshot::Sender<Instant>>,
}

impl RelayWorkers {
    pub(crate) fn new() -> Self {
        Self {
            tasks: JoinSet::new(),
            stops: Vec::new(),
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    pub(crate) fn spawn<F>(
        &mut self,
        operation: impl FnOnce(oneshot::Receiver<Instant>) -> F,
    ) -> AbortHandle
    where
        F: Future<Output = TestResult<()>> + Send + 'static,
    {
        let (stop, stopping) = oneshot::channel();
        let task = self.tasks.spawn(operation(stopping));
        self.stops.push(stop);

        task
    }

    pub(crate) fn spawn_operation(
        &mut self,
        operation: impl Future<Output = TestResult<()>> + Send + 'static,
    ) -> AbortHandle {
        self.spawn(|stopping| async move {
            tokio::select! {
                biased;
                result = operation => result,
                stopped = stopping => {
                    stopped?;
                    Ok(())
                }
            }
        })
    }

    pub(crate) async fn completed(&mut self) -> TestResult<()> {
        match self.tasks.join_next().await {
            Some(result) => result?,
            None => Ok(()),
        }
    }

    pub(crate) async fn finish(mut self, deadline: Instant) -> TestResult<()> {
        let mut outcome = Ok(());
        while let Some(result) = self.tasks.try_join_next() {
            outcome = finish_with_cleanup(outcome, result.map_err(Into::into).and_then(|v| v));
        }

        for stop in self.stops.drain(..) {
            // Completed receivers have dropped their stop channel. Their
            // actual outcomes were or will be observed from the JoinSet.
            let _ = stop.send(deadline);
        }

        while !self.tasks.is_empty() {
            match timeout_at(deadline, self.tasks.join_next()).await {
                Ok(Some(result)) => {
                    outcome =
                        finish_with_cleanup(outcome, result.map_err(Into::into).and_then(|v| v));
                }
                Ok(None) => break,
                Err(error) => {
                    outcome = finish_with_cleanup(outcome, Err(error.into()));
                    // Retain any outcomes already available at the deadline.
                    // Remaining tasks are aborted by JoinSet's Drop, not joined.
                    while let Some(result) = self.tasks.try_join_next() {
                        outcome = finish_with_cleanup(
                            outcome,
                            result.map_err(Into::into).and_then(|v| v),
                        );
                    }
                    break;
                }
            }
        }

        outcome
    }
}

pub(crate) fn drain_deadline() -> Instant {
    Instant::now() + DRAIN_BUDGET
}

pub(crate) async fn stop_fixture_peer<T: Send + 'static>(
    peer: Option<ConnectionPeer<TestResult<T>>>,
) -> TestResult<()> {
    match peer {
        Some(peer) if peer.is_finished() => peer.await?.map(|_| ()),
        Some(peer) => peer.stop().await,
        None => Ok(()),
    }
}
