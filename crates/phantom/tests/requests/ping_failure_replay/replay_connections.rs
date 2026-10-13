use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, Weak},
    time::Duration,
};

use tokio::{
    sync::oneshot,
    task::{AbortHandle, Id},
    time::{Instant, timeout_at},
};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

use super::TestResult;

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

struct Registered {
    id: Id,
    peer: ConnectionPeer<ReplayOutcome>,
    stop: Option<oneshot::Sender<()>>,
}

enum ReplayOutcome {
    Finished(TestResult),
    Stopped,
}

struct State {
    peers: Vec<Registered>,
    admitted: usize,
    maximum: usize,
    closed: bool,
    primary: Option<TestResult>,
    cleanup: TestResult,
}

/// The caller retains every original task, including descendants, across its deadline.
pub(crate) struct ReplayConnections {
    state: Arc<Mutex<State>>,
}

/// Descendants can register work without keeping their own task owners alive.
#[derive(Clone)]
pub(crate) struct ReplaySpawner {
    state: Weak<Mutex<State>>,
}

impl ReplayConnections {
    pub(crate) fn new(maximum: usize) -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                peers: Vec::new(),
                admitted: 0,
                maximum,
                closed: false,
                primary: None,
                cleanup: Ok(()),
            })),
        }
    }

    pub(crate) fn spawner(&self) -> ReplaySpawner {
        ReplaySpawner {
            state: Arc::downgrade(&self.state),
        }
    }

    pub(crate) async fn finish(&mut self, primary: TestResult) -> TestResult {
        {
            let mut state = lock(&self.state);
            state.closed = true;
            state.primary = Some(match state.primary.take() {
                Some(previous) => finish_with_cleanup(previous, primary),
                None => primary,
            });
            if state.primary.as_ref().is_some_and(Result::is_err) {
                for registered in &mut state.peers {
                    if let Some(stop) = registered.stop.take() {
                        // A missing receiver leaves the original task outcome to its join.
                        let _ = stop.send(());
                    }
                }
            }
        }

        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let mut index = 0;
        while index < lock(&self.state).peers.len() {
            // Admission is closed. Only this borrowed finish call removes entries,
            // after collecting their outcomes; interruption keeps them on the owner.
            let joined = timeout_at(
                deadline,
                poll_fn(|context| {
                    let mut state = lock(&self.state);
                    Pin::new(&mut state.peers[index].peer).poll(context)
                }),
            )
            .await;

            let mut state = lock(&self.state);
            let task = state.peers[index].id;
            let outcome: TestResult = match joined {
                Ok(outcome) => {
                    state.peers.remove(index);
                    match outcome {
                        Ok(ReplayOutcome::Finished(outcome)) => outcome,
                        Ok(ReplayOutcome::Stopped) => Ok(()),
                        Err(error) => Err(error.into()),
                    }
                }
                Err(elapsed) => {
                    state.peers[index].peer.abort();
                    index += 1;
                    Err(FixtureDeadline::new("replay connection did not stop", elapsed).into())
                }
            };
            let outcome = outcome.map_err(|cause| {
                Box::new(ReplayConnectionFailure { task, cause }) as Box<dyn Error + Send + Sync>
            });
            let cleanup = std::mem::replace(&mut state.cleanup, Ok(()));
            state.cleanup = finish_with_cleanup(cleanup, outcome);
        }

        let mut state = lock(&self.state);
        let primary = state
            .primary
            .take()
            .ok_or("replay completion lost its caller outcome")?;
        let cleanup = std::mem::replace(&mut state.cleanup, Ok(()));
        finish_with_cleanup(primary, cleanup)
    }
}

impl Drop for ReplayConnections {
    fn drop(&mut self) {
        let mut state = lock(&self.state);
        state.closed = true;
        for registered in &state.peers {
            registered.peer.abort();
        }
    }
}

impl ReplaySpawner {
    pub(crate) fn spawn(
        &self,
        future: impl Future<Output = TestResult> + Send + 'static,
    ) -> TestResult<AbortHandle> {
        let state = self
            .state
            .upgrade()
            .ok_or("replay connection owner was dropped")?;
        let mut state = lock(&state);
        if state.closed {
            return Err("replay connection owner has stopped".into());
        }
        if state.admitted == state.maximum {
            return Err("replay connection task count exceeds its script limit".into());
        }
        let (stop, stopped) = oneshot::channel();
        let peer = ConnectionPeer::spawn(async move {
            tokio::pin!(future);
            tokio::select! {
                biased;
                outcome = &mut future => ReplayOutcome::Finished(outcome),
                stopped = stopped => match stopped {
                    Ok(()) => ReplayOutcome::Stopped,
                    Err(error) => ReplayOutcome::Finished(Err(error.into())),
                },
            }
        });
        let abort = peer.abort_handle();
        state.admitted += 1;
        state.peers.push(Registered {
            id: abort.id(),
            peer,
            stop: Some(stop),
        });
        Ok(abort)
    }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    match state.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[derive(Debug)]
pub(super) struct ReplayConnectionFailure {
    pub(super) task: Id,
    pub(super) cause: Box<dyn Error + Send + Sync>,
}

impl fmt::Display for ReplayConnectionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "replay connection task {} failed: {}",
            self.task, self.cause
        )
    }
}

impl Error for ReplayConnectionFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.cause.as_ref())
    }
}

#[cfg(test)]
mod tests;
