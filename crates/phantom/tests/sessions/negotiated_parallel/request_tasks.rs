use std::{error::Error, fmt, future::Future, time::Duration};

use http::Response;
use phantom::{RequestError, ResponseBody};
use tokio::{
    sync::oneshot,
    task::JoinError,
    time::{Instant, timeout, timeout_at},
};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

use super::{
    Outcome, TEST_TIMEOUT, TestResult,
    connection_tasks::{Connections, contextual},
};

struct Caller<T> {
    peer: Option<ConnectionPeer<TestResult<T>>>,
    cancel: Option<oneshot::Sender<()>>,
    cooperative: bool,
}
impl<T: Send + 'static> Caller<T> {
    fn spawn(future: impl Future<Output = TestResult<T>> + Send + 'static) -> Self {
        let (cancel, cancelled) = oneshot::channel();
        let peer = ConnectionPeer::spawn(async move {
            tokio::select! {
                biased;
                result = future => result,
                _ = cancelled => Err(Box::new(RequestedCancellation) as Box<dyn Error + Send + Sync>),
            }
        });
        Self {
            peer: Some(peer),
            cancel: Some(cancel),
            cooperative: false,
        }
    }
}
pub(super) struct Work {
    pub(super) connections: Connections,
    responses: Vec<Caller<Response<ResponseBody>>>,
    outcomes: Vec<Caller<Outcome>>,
    primary: Option<TestResult>,
    failures: Vec<Box<dyn Error + Send + Sync>>,
}
impl Work {
    pub(super) fn new() -> Self {
        Self {
            connections: Connections::new(),
            responses: Vec::new(),
            outcomes: Vec::new(),
            primary: None,
            failures: Vec::new(),
        }
    }
    pub(super) fn spawn_response(
        &mut self,
        future: impl Future<Output = Result<Response<ResponseBody>, RequestError>> + Send + 'static,
    ) -> TestResult<usize> {
        // The recipe loop starts two seventh requests; other scripts start one.
        if self.responses.len() == 8 {
            return Err("negotiated response caller count exceeded its script limit".into());
        }
        let index = self.responses.len();
        self.responses
            .push(Caller::spawn(async move { Ok(future.await?) }));
        Ok(index)
    }
    pub(super) fn response_peer(
        &mut self,
        index: usize,
    ) -> TestResult<&mut ConnectionPeer<TestResult<Response<ResponseBody>>>> {
        self.responses
            .get_mut(index)
            .and_then(|caller| caller.peer.as_mut())
            .ok_or_else(|| "negotiated response caller was already collected".into())
    }
    pub(super) async fn response(&mut self, index: usize) -> TestResult<Response<ResponseBody>> {
        let joined = timeout(TEST_TIMEOUT, self.response_peer(index)?)
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new("negotiated response caller exceeded its deadline", elapsed)
            })?;
        drop(self.responses[index].peer.take());
        joined?
    }
    pub(super) fn spawn_outcome(
        &mut self,
        future: impl Future<Output = TestResult<Outcome>> + Send + 'static,
    ) -> TestResult<usize> {
        if self.outcomes.len() == 24 {
            return Err("negotiated outcome caller count exceeded its script limit".into());
        }
        let index = self.outcomes.len();
        self.outcomes.push(Caller::spawn(future));
        Ok(index)
    }
    pub(super) fn outcome_peer(
        &mut self,
        index: usize,
    ) -> TestResult<&mut ConnectionPeer<TestResult<Outcome>>> {
        self.outcomes
            .get_mut(index)
            .and_then(|caller| caller.peer.as_mut())
            .ok_or_else(|| "negotiated outcome caller was already collected".into())
    }
    pub(super) fn abort_outcome(&mut self, index: usize) -> TestResult {
        self.outcome_peer(index)?.abort();
        Ok(())
    }
    pub(super) async fn outcome(&mut self, index: usize) -> TestResult<Outcome> {
        let joined = timeout(TEST_TIMEOUT, self.outcome_peer(index)?)
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new("negotiated outcome caller exceeded its deadline", elapsed)
            })?;
        drop(self.outcomes[index].peer.take());
        joined?
    }
    pub(super) async fn cancelled_outcome(
        &mut self,
        index: usize,
    ) -> TestResult<Result<TestResult<Outcome>, JoinError>> {
        let joined = timeout(TEST_TIMEOUT, self.outcome_peer(index)?)
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new("negotiated cancelled caller exceeded its deadline", elapsed)
            })?;
        drop(self.outcomes[index].peer.take());
        Ok(joined)
    }
    pub(super) async fn finish(&mut self, primary: TestResult) -> TestResult {
        self.primary = Some(match self.primary.take() {
            Some(previous) => finish_with_cleanup(previous, primary),
            None => primary,
        });
        let failed = self.primary.as_ref().is_some_and(Result::is_err);
        let deadline = Instant::now() + Duration::from_secs(5);
        collect(&mut self.responses, failed, deadline, &mut self.failures).await;
        collect(&mut self.outcomes, failed, deadline, &mut self.failures).await;
        if let Err(error) = self.connections.finish(failed, deadline).await {
            self.failures.push(error);
        }
        let cleanup = std::mem::take(&mut self.failures)
            .into_iter()
            .fold(Ok(()), |result, error| {
                finish_with_cleanup(result, Err(error))
            });
        finish_with_cleanup(
            self.primary
                .take()
                .expect("cleanup retained its primary outcome"),
            cleanup,
        )
    }
}
// The two caller types above retain their guards and accumulated failures in
// Work if the surrounding caller interrupts this collection.
async fn collect<T: Send + 'static>(
    callers: &mut [Caller<T>],
    failed: bool,
    deadline: Instant,
    failures: &mut Vec<Box<dyn Error + Send + Sync>>,
) {
    if failed {
        for caller in &mut *callers {
            if caller.peer.is_some()
                && let Some(cancel) = caller.cancel.take()
            {
                caller.cooperative = cancel.send(()).is_ok();
            }
        }
    }
    for caller in callers {
        let Some(task) = caller.peer.as_mut() else {
            continue;
        };
        let id = task.abort_handle().id();
        let outcome = match timeout_at(deadline, &mut *task).await {
            Ok(joined) => {
                drop(caller.peer.take());
                match joined {
                    Ok(Err(error)) if caller.cooperative && error.is::<RequestedCancellation>() => {
                        Ok(())
                    }
                    Ok(value) => value.map(|_| ()),
                    Err(error) => Err(error.into()),
                }
            }
            Err(elapsed) => {
                task.abort();
                Err(FixtureDeadline::new(
                    "negotiated caller cleanup exceeded its deadline",
                    elapsed,
                )
                .into())
            }
        };
        if let Err(error) = contextual(id, outcome) {
            failures.push(error);
        }
    }
}
#[derive(Debug)]
struct RequestedCancellation;
impl fmt::Display for RequestedCancellation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("negotiated caller shutdown requested")
    }
}
impl Error for RequestedCancellation {}
