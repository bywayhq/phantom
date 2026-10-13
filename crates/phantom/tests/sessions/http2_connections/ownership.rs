use std::{
    future::{Future, poll_fn},
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, Weak},
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    sync::{oneshot, watch},
    task::{AbortHandle, JoinError},
    time::{Instant, timeout_at},
};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

use super::TestResult;

const MAX_TASKS: usize = 64;

enum Outcome {
    Finished(TestResult),
    Stopped,
}

struct Registered {
    peer: Option<ConnectionPeer<Outcome>>,
    stop: Option<oneshot::Sender<()>>,
}

struct State {
    tasks: Vec<Registered>,
    stopped: bool,
    signals: Vec<OriginSignals>,
}

struct OriginSignals {
    _release: watch::Sender<bool>,
    _goaway: watch::Sender<Option<usize>>,
}

pub(super) struct Work {
    state: Arc<Mutex<State>>,
    primary: TestResult,
    cleanup: TestResult,
}

#[derive(Clone)]
pub(super) struct Spawner {
    state: Weak<Mutex<State>>,
}

pub(super) struct Task {
    state: Weak<Mutex<State>>,
    index: usize,
    abort: AbortHandle,
}

impl Work {
    pub(super) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(State {
                tasks: Vec::new(),
                stopped: false,
                signals: Vec::new(),
            })),
            primary: Ok(()),
            cleanup: Ok(()),
        }
    }

    pub(super) fn spawner(&self) -> Spawner {
        Spawner {
            state: Arc::downgrade(&self.state),
        }
    }

    pub(super) async fn finish(&mut self, primary: TestResult) -> TestResult {
        self.primary = finish_with_cleanup(std::mem::replace(&mut self.primary, Ok(())), primary);
        let count = {
            let mut state = lock(&self.state);
            state.stopped = true;
            for task in &mut state.tasks {
                if let Some(stop) = task.stop.take() {
                    // Closed receivers still have their original outcome below.
                    let _ = stop.send(());
                }
            }
            state.tasks.len()
        };

        let deadline = Instant::now() + Duration::from_secs(5);
        for index in 0..count {
            if lock(&self.state).tasks[index].peer.is_none() {
                continue;
            }

            let joined = timeout_at(
                deadline,
                poll_fn(|context| {
                    let mut state = lock(&self.state);
                    let Some(peer) = state.tasks[index].peer.as_mut() else {
                        return Poll::Ready(Ok(Outcome::Finished(Err(
                            "HTTP/2 fixture worker disappeared before collection".into(),
                        ))));
                    };
                    Pin::new(peer).poll(context)
                }),
            )
            .await;
            let cleanup = match joined {
                Ok(joined) => {
                    lock(&self.state).tasks[index].peer.take();
                    match joined {
                        Ok(Outcome::Finished(result)) => result,
                        Ok(Outcome::Stopped) => Ok(()),
                        Err(error) => Err(error.into()),
                    }
                }
                Err(elapsed) => {
                    if let Some(peer) = &lock(&self.state).tasks[index].peer {
                        peer.abort();
                    }
                    Err(FixtureDeadline::new(
                        "HTTP/2 fixture cleanup exceeded its deadline",
                        elapsed,
                    )
                    .into())
                }
            };
            self.cleanup =
                finish_with_cleanup(std::mem::replace(&mut self.cleanup, Ok(())), cleanup);
        }

        finish_with_cleanup(
            std::mem::replace(&mut self.primary, Ok(())),
            std::mem::replace(&mut self.cleanup, Ok(())),
        )
    }
}

impl Drop for Work {
    fn drop(&mut self) {
        let mut state = lock(&self.state);
        state.stopped = true;
        for task in &mut state.tasks {
            if let Some(stop) = task.stop.take() {
                // Drop cannot await; the owned handle is the cancellation backup.
                let _ = stop.send(());
            }
            if let Some(peer) = &task.peer {
                peer.abort();
            }
        }
    }
}

impl Spawner {
    pub(super) fn retain_signals(
        &self,
        release: watch::Sender<bool>,
        goaway: watch::Sender<Option<usize>>,
    ) -> TestResult {
        let state = self
            .state
            .upgrade()
            .ok_or("HTTP/2 fixture owner was dropped")?;
        // The origin's control channels stay open through explicit worker cleanup.
        lock(&state).signals.push(OriginSignals {
            _release: release,
            _goaway: goaway,
        });
        Ok(())
    }

    pub(super) fn spawn(
        &self,
        future: impl Future<Output = TestResult> + Send + 'static,
    ) -> TestResult<Task> {
        let state = self
            .state
            .upgrade()
            .ok_or("HTTP/2 fixture owner was dropped")?;
        let mut state = lock(&state);
        if state.stopped {
            return Err("HTTP/2 fixture worker admission has stopped".into());
        }
        // Four origins, twenty callers and twenty-four responses fit in sixty-four admissions.
        if state.tasks.len() == MAX_TASKS {
            return Err("HTTP/2 fixture exceeded its scripted worker count".into());
        }

        let (stop, stopped) = oneshot::channel();
        let peer = ConnectionPeer::spawn(async move {
            tokio::select! {
                biased;
                result = future => Outcome::Finished(result),
                signal = stopped => match signal {
                    Ok(()) => Outcome::Stopped,
                    Err(error) => Outcome::Finished(Err(error.into())),
                },
            }
        });
        let task = Task {
            state: self.state.clone(),
            index: state.tasks.len(),
            abort: peer.abort_handle(),
        };
        state.tasks.push(Registered {
            peer: Some(peer),
            stop: Some(stop),
        });
        Ok(task)
    }
}

impl Task {
    pub(super) fn abort(&self) {
        if let Some(state) = self.state.upgrade()
            && let Some(stop) = lock(&state).tasks[self.index].stop.take()
        {
            // This signals the original future; Work still collects its outcome.
            let _ = stop.send(());
        }
    }

    pub(super) fn is_finished(&self) -> bool {
        self.abort.is_finished()
    }
}

impl Future for Task {
    type Output = Result<TestResult, JoinError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let Some(state) = self.state.upgrade() else {
            return Poll::Ready(Ok(Err(
                "HTTP/2 fixture owner was dropped before join".into()
            )));
        };
        let mut state = lock(&state);
        let task = &mut state.tasks[self.index];
        let Some(peer) = task.peer.as_mut() else {
            return Poll::Ready(Ok(Err("HTTP/2 fixture worker was already joined".into())));
        };
        match Pin::new(peer).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                task.peer.take();
                Poll::Ready(result.map(|outcome| match outcome {
                    Outcome::Finished(result) => result,
                    Outcome::Stopped => Err("HTTP/2 fixture worker stopped before join".into()),
                }))
            }
        }
    }
}

fn lock(state: &Mutex<State>) -> MutexGuard<'_, State> {
    // A test panic must still let Drop reach and abort every original handle.
    match state.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    }
}

#[cfg(test)]
mod tests {
    use std::{error::Error, io, sync::Arc};

    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
        time::timeout,
    };

    use super::super::{Mode, Origin, TEST_TIMEOUT, send, spawn_held};
    use super::*;
    use crate::support::{
        tls::{TestIdentity, client_builder},
        tunnel_proxy::connection_peer::FixtureFailures,
    };

    struct HeldOrigin {
        origin: Origin,
        _client: phantom::Client,
        response: http::Response<phantom::ResponseBody>,
        request: Task,
    }

    async fn held_origin(work: &Work) -> TestResult<HeldOrigin> {
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity, None, work.spawner()).await?;
        let client = client_builder(&identity, true).build()?;
        let response = send(&client, Mode::Exact, &origin.uri("head-held")).await?;
        assert_eq!(origin.next_request().await?, 0);

        let request = spawn_held(&client, &origin, &["held-second"])?
            .pop()
            .ok_or("actual held request missing")?;
        assert_eq!(origin.next_request().await?, 0);
        assert!(!request.is_finished());
        Ok(HeldOrigin {
            origin,
            _client: client,
            response,
            request,
        })
    }

    fn witnesses(work: &Work) -> Vec<AbortHandle> {
        lock(&work.state)
            .tasks
            .iter()
            .filter_map(|task| task.peer.as_ref().map(ConnectionPeer::abort_handle))
            .collect()
    }

    async fn stopped(witnesses: &[AbortHandle]) -> TestResult {
        timeout(TEST_TIMEOUT, async {
            while witnesses.iter().any(|task| !task.is_finished()) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    fn caller_cause(
        error: &(dyn Error + Send + Sync + 'static),
    ) -> TestResult<&(dyn Error + Send + Sync + 'static)> {
        if let Some(causes) = error.downcast_ref::<FixtureFailures>() {
            assert_shutdown_disconnects(causes.cleanup.as_ref())?;
            Ok(causes.primary.as_ref())
        } else {
            Ok(error)
        }
    }

    fn assert_shutdown_disconnects(error: &(dyn Error + Send + Sync + 'static)) -> TestResult {
        if let Some(causes) = error.downcast_ref::<FixtureFailures>() {
            assert_shutdown_disconnects(causes.primary.as_ref())?;
            return assert_shutdown_disconnects(causes.cleanup.as_ref());
        }

        let original = error
            .downcast_ref::<http2::Error>()
            .ok_or("retained cleanup failure was not an HTTP/2 error")?;
        let disconnected = original
            .get_io()
            .ok_or("retained HTTP/2 cleanup error lacked its original I/O cause")?;
        assert!(matches!(
            disconnected.kind(),
            io::ErrorKind::BrokenPipe
                | io::ErrorKind::ConnectionReset
                | io::ErrorKind::ConnectionAborted
        ));
        Ok(())
    }

    #[tokio::test]
    async fn dropping_the_root_owner_stops_actual_listener_connection_response_and_request()
    -> TestResult {
        let work = Work::new();
        let held = held_origin(&work).await?;
        let witnesses = witnesses(&work);
        // Listener, accepted connection, two responses and the held caller.
        assert_eq!(witnesses.len(), 5);
        let address = held.origin.address;

        drop(work);
        stopped(&witnesses).await?;
        let rebound = TcpListener::bind(address).await?;
        assert_eq!(rebound.local_addr()?, address);
        drop(held.response);
        drop(held.origin);
        Ok(())
    }

    #[tokio::test]
    async fn a_caller_deadline_keeps_the_actual_workers_owned_until_explicit_cleanup() -> TestResult
    {
        let mut work = Work::new();
        let mut held = held_origin(&work).await?;
        let witnesses = witnesses(&work);
        assert_eq!(witnesses.len(), 5);
        let address = held.origin.address;

        let elapsed = timeout(Duration::ZERO, &mut held.request)
            .await
            .err()
            .ok_or("held caller unexpectedly completed")?;
        assert!(witnesses.iter().all(|task| !task.is_finished()));
        let primary: TestResult = Err(elapsed.into());
        let error = work
            .finish(primary)
            .await
            .err()
            .ok_or("caller deadline was discarded")?;
        assert!(caller_cause(error.as_ref())?.is::<tokio::time::error::Elapsed>());
        stopped(&witnesses).await?;
        let rebound = TcpListener::bind(address).await?;
        assert_eq!(rebound.local_addr()?, address);
        drop(held);
        Ok(())
    }

    #[tokio::test]
    async fn caller_failure_cleanup_keeps_its_original_cause_and_stops_actual_workers() -> TestResult
    {
        let mut work = Work::new();
        let held = held_origin(&work).await?;
        let witnesses = witnesses(&work);
        let token = Arc::new(());
        let primary: TestResult = Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            CallerFailure {
                token: token.clone(),
            },
        )
        .into());

        let error = work
            .finish(primary)
            .await
            .err()
            .ok_or("caller failure was discarded")?;
        let original = caller_cause(error.as_ref())?
            .downcast_ref::<io::Error>()
            .ok_or("original caller I/O error missing")?;
        let payload = original
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<CallerFailure>())
            .ok_or("original caller payload missing")?;
        assert_eq!(original.kind(), io::ErrorKind::InvalidInput);
        assert!(Arc::ptr_eq(&token, &payload.token));
        stopped(&witnesses).await?;
        drop(held);
        Ok(())
    }

    #[tokio::test]
    async fn an_actual_accepted_tls_failure_survives_caller_failure_cleanup() -> TestResult {
        let mut work = Work::new();
        let identity = TestIdentity::generate()?;
        let mut origin = Origin::start(&identity, None, work.spawner()).await?;
        let mut peer = TcpStream::connect(origin.address).await?;
        peer.write_all(b"not a TLS record").await?;
        peer.shutdown().await?;
        assert_eq!(origin.next_accepted().await?, 0);
        let witnesses = witnesses(&work);
        assert_eq!(witnesses.len(), 2);
        stopped(&witnesses[1..]).await?;
        let token = Arc::new(());
        let primary: TestResult = Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            CallerFailure {
                token: token.clone(),
            },
        )
        .into());

        let error = work
            .finish(primary)
            .await
            .err()
            .ok_or("accepted TLS failure was discarded")?;
        let causes = error
            .downcast_ref::<crate::support::tunnel_proxy::connection_peer::FixtureFailures>()
            .ok_or("simultaneous original failures missing")?;
        let original = causes
            .primary
            .downcast_ref::<io::Error>()
            .ok_or("original caller I/O error missing")?;
        let payload = original
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<CallerFailure>())
            .ok_or("original caller payload missing")?;
        assert!(Arc::ptr_eq(&token, &payload.token));
        assert!(causes.cleanup.is::<btls::ssl::Error>());
        stopped(&witnesses).await?;
        drop((peer, origin));
        Ok(())
    }

    #[derive(Debug)]
    struct CallerFailure {
        token: Arc<()>,
    }

    impl std::fmt::Display for CallerFailure {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("injected HTTP/2 caller failure")
        }
    }

    impl std::error::Error for CallerFailure {}
}
