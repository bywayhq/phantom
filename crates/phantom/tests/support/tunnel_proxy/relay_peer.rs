use std::{error::Error, fmt, future::Future, sync::Arc, time::Duration};

use tokio::{
    sync::oneshot,
    time::{Instant, timeout_at},
};

use super::{ConnectionPeer, TestResult, finish_with_cleanup};
use crate::support::deadline::FixtureDeadline;

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
enum RelayOutcome {
    Finished(TestResult<()>),
    Stopped,
}

#[derive(Debug)]
pub(super) struct RelayPeer {
    task: Option<ConnectionPeer<RelayOutcome>>,
    stop: Option<oneshot::Sender<()>>,
}

impl RelayPeer {
    pub(super) fn spawn(future: impl Future<Output = TestResult<()>> + Send + 'static) -> Self {
        let (stop, stopped) = oneshot::channel();
        let task = ConnectionPeer::spawn(async move {
            tokio::select! {
                biased;
                result = future => RelayOutcome::Finished(result),
                signal = stopped => match signal {
                    Ok(()) => RelayOutcome::Stopped,
                    Err(error) => RelayOutcome::Finished(Err(error.into())),
                },
            }
        });
        Self {
            task: Some(task),
            stop: Some(stop),
        }
    }

    pub(super) fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(ConnectionPeer::is_finished)
    }

    #[cfg(test)]
    pub(super) fn abort_handle(&self) -> Option<tokio::task::AbortHandle> {
        self.task.as_ref().map(ConnectionPeer::abort_handle)
    }

    fn request_stop(&mut self) {
        if let Some(stop) = self.stop.take() {
            // A finished worker has already dropped its receiver. Its original
            // task result, including any external cancellation, is still joined.
            let _ = stop.send(());
        }
    }

    async fn collect(&mut self, deadline: Instant) -> TestResult<()> {
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        let joined = timeout_at(deadline, task).await.map_err(|elapsed| {
            FixtureDeadline::new("tunnel relay cleanup exceeded five seconds", elapsed)
        })?;
        self.task = None;
        match joined? {
            RelayOutcome::Finished(result) => result,
            RelayOutcome::Stopped => Ok(()),
        }
    }
}

/// Shares an original collected cause with a retained owner across cleanup retries.
#[derive(Clone, Debug)]
pub(super) struct RelayFailure(Arc<RetainedCause>);

// Keep the box allocation: converting it directly to an Arc moves its cause.
#[derive(Debug)]
pub(super) struct RetainedCause {
    pub(super) error: Box<dyn Error + Send + Sync>,
}

impl fmt::Display for RelayFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.0.error.as_ref(), formatter)
    }
}

impl Error for RelayFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.error.as_ref())
    }
}

pub(super) fn retain_failure(failure: &mut Option<RelayFailure>, result: TestResult<()>) {
    if let Err(error) = result {
        let combined: TestResult<()> = match failure.take() {
            Some(previous) => finish_with_cleanup(Err(Box::new(previous)), Err(error)),
            None => Err(error),
        };
        *failure = combined
            .err()
            .map(|error| RelayFailure(Arc::new(RetainedCause { error })));
    }
}

pub(super) async fn collect_relays(
    peers: &mut Vec<RelayPeer>,
    failure: &mut Option<RelayFailure>,
) -> TestResult<()> {
    for peer in peers.iter_mut() {
        peer.request_stop();
    }

    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    for peer in peers.iter_mut() {
        retain_failure(failure, peer.collect(deadline).await);
    }
    peers.retain(|peer| peer.task.is_some());
    match failure.as_ref() {
        Some(failure) => Err(Box::new(failure.clone())),
        None => Ok(()),
    }
}

/// Owns unfinished relays when the consuming convenience shutdown fails.
#[derive(Debug)]
pub(crate) struct TunnelCleanupFailure {
    pub(super) peers: Vec<RelayPeer>,
    pub(super) failure: Option<RelayFailure>,
}

impl TunnelCleanupFailure {
    pub(crate) async fn finish(&mut self) -> TestResult<()> {
        collect_relays(&mut self.peers, &mut self.failure).await
    }
}

impl fmt::Display for TunnelCleanupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("tunnel cleanup failed with relays still owned")
    }
}

impl Error for TunnelCleanupFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.failure
            .as_ref()
            .map(|failure| failure as &(dyn Error + 'static))
    }
}
