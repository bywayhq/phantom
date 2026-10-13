use super::TestResult;
use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};
use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, Weak},
};
use tokio::{
    sync::oneshot,
    task::{AbortHandle, Id},
    time::{Instant, timeout_at},
};

// Twenty H2 response workers, two connections, the listener and two CONNECT
// relays fit within sixty-four lifetime admissions. This is a fixture bound.
const MAX_TASKS: usize = 64;
struct Registered {
    peer: Option<ConnectionPeer<TestResult>>,
    cancel: Option<oneshot::Sender<()>>,
    id: Id,
}
struct State {
    tasks: Vec<Registered>,
    admitted: usize,
    stopped: bool,
    failures: Vec<Box<dyn Error + Send + Sync>>,
}
pub(super) struct Connections {
    state: Arc<Mutex<State>>,
}
#[derive(Clone)]
pub(super) struct Spawner {
    state: Weak<Mutex<State>>,
}
impl Connections {
    pub(super) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                tasks: Vec::new(),
                admitted: 0,
                stopped: false,
                failures: Vec::new(),
            })),
        }
    }
    pub(super) fn spawner(&self) -> Spawner {
        Spawner {
            state: Arc::downgrade(&self.state),
        }
    }
    pub(super) async fn finish(&mut self, failed: bool, deadline: Instant) -> TestResult {
        let count = {
            let mut state = lock(&self.state);
            state.stopped = true;
            if failed {
                for task in &mut state.tasks {
                    // A closed receiver means this worker has already finished;
                    // its JoinHandle below still supplies the actual outcome.
                    if let Some(cancel) = task.cancel.take() {
                        let _ = cancel.send(());
                    }
                }
            }
            state.tasks.len()
        };
        for index in 0..count {
            if lock(&self.state).tasks[index].peer.is_none() {
                continue;
            }
            // Poll only the stored JoinHandle. Serving futures never run under
            // this lock; interrupted collection leaves the original handle here.
            let joined = timeout_at(
                deadline,
                poll_fn(|context| {
                    let mut state = lock(&self.state);
                    Pin::new(
                        state.tasks[index]
                            .peer
                            .as_mut()
                            .expect("uncollected worker"),
                    )
                    .poll(context)
                }),
            )
            .await;
            let mut state = lock(&self.state);
            let task = &mut state.tasks[index];
            let id = task.id;
            let outcome = match joined {
                Ok(joined) => {
                    drop(task.peer.take());
                    match joined {
                        Ok(outcome) => outcome,
                        Err(error) => Err(error.into()),
                    }
                }
                Err(elapsed) => {
                    task.peer.as_ref().expect("uncollected worker").abort();
                    Err(FixtureDeadline::new(
                        "negotiated worker cleanup exceeded its deadline",
                        elapsed,
                    )
                    .into())
                }
            };
            if let Err(error) = contextual(id, outcome) {
                state.failures.push(error);
            }
        }
        let failures = std::mem::take(&mut lock(&self.state).failures);
        failures.into_iter().fold(Ok(()), |result, error| {
            finish_with_cleanup(result, Err(error))
        })
    }
}
impl Drop for Connections {
    fn drop(&mut self) {
        let mut state = lock(&self.state);
        state.stopped = true;
        for task in &state.tasks {
            if let Some(peer) = &task.peer {
                peer.abort();
            }
        }
    }
}
impl Spawner {
    pub(super) fn spawn(
        &self,
        future: impl Future<Output = TestResult> + Send + 'static,
    ) -> TestResult<AbortHandle> {
        let state = self
            .state
            .upgrade()
            .ok_or("negotiated worker owner was dropped")?;
        let mut state = lock(&state);
        if state.stopped {
            return Err("negotiated worker admission has stopped".into());
        }
        if state.admitted == MAX_TASKS {
            return Err("negotiated worker count exceeded its script limit".into());
        }
        let (cancel, cancelled) = oneshot::channel();
        let peer = ConnectionPeer::spawn(async move {
            tokio::select! {
                biased;
                result = future => result,
                _ = cancelled => Ok(()),
            }
        });
        let abort = peer.abort_handle();
        state.admitted += 1;
        state.tasks.push(Registered {
            peer: Some(peer),
            cancel: Some(cancel),
            id: abort.id(),
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
pub(super) fn contextual(task: Id, result: TestResult) -> TestResult {
    result.map_err(|cause| Box::new(WorkerFailure { task, cause }) as Box<dyn Error + Send + Sync>)
}
#[derive(Debug)]
pub(super) struct WorkerFailure {
    pub(super) task: Id,
    pub(super) cause: Box<dyn Error + Send + Sync>,
}
impl fmt::Display for WorkerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "negotiated worker {} failed: {}",
            self.task, self.cause
        )
    }
}
impl Error for WorkerFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.cause.as_ref())
    }
}
