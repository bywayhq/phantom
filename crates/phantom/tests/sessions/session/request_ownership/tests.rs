use std::{future::Future, io, net::SocketAddr, pin::Pin, time::Duration};

use phantom::{RequestError, RequestErrorKind};
use tokio::{
    net::TcpListener,
    sync::{oneshot, watch},
    task::AbortHandle,
    time::timeout,
};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup},
};

use super::{
    H2_ALPN, HeldState, HoldObservation, Ipv4Addr, RequestControl, RequestObservation,
    RequestState, ResponseHold, TEST_TIMEOUT, TestIdentity, TestResult, bounded, cold_requests,
    finish_cold, independent_requests, reuse_ownership, test_client,
};

const LIMIT: Duration = Duration::from_secs(5);
const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);
const FAILURE: &str = "injected concurrent request serving read failure";
const INVALID_URI: &str = "https://127.0.0.1/invalid uri";

#[tokio::test]
async fn healthy_cold_request_pair_keeps_barrier_streams_paths_and_204() -> TestResult<()> {
    let mut fixture = Fixture::start(Mode::Cold, 2, None).await?;
    let session = test_client(&fixture.identity, true)?;
    let mut caller = Box::pin(cold_requests(&session, fixture.address, fixture.control.take()));
    let primary: TestResult<()> = async {
        fixture.pending(&mut caller, [true, true], &[2]).await?;
        fixture.release_responses()?;
        fixture.release_collection()?;
        timeout(LIMIT, &mut caller).await??;
        Ok(())
    }.await;
    drop(caller);
    drop(session);
    let primary: TestResult<()> = async {
        primary?;
        let requests = fixture.cold_result(Ok(())).await?;
        let mut ids = requests.iter().map(|(id, _)| *id).collect::<Vec<_>>();
        let mut paths = requests.into_iter().map(|(_, path)| path).collect::<Vec<_>>();
        ids.sort_unstable();
        paths.sort_unstable();
        assert_eq!(ids, [1, 3]);
        assert_eq!(paths, ["/first".to_owned(), "/second".to_owned()]);
        fixture.closed().await
    }.await;
    finish_with_cleanup(primary, fixture.stop().await)
}

#[tokio::test]
async fn healthy_independent_request_pair_keeps_both_original_h2_results() -> TestResult<()> {
    let mut fixture = Fixture::start(Mode::Independent, 1, None).await?;
    let first = test_client(&fixture.identity, true)?;
    let second = test_client(&fixture.identity, true)?;
    let mut caller = Box::pin(independent_requests(first, second, fixture.address, fixture.control.take()));
    let primary: TestResult<()> = async {
        fixture.pending(&mut caller, [true, true], &[1, 1]).await?;
        fixture.release_responses()?;
        fixture.release_collection()?;
        timeout(LIMIT, &mut caller).await??;
        let mut requests = fixture.independent_result(Ok(())).await?;
        requests.sort_unstable();
        assert_eq!(requests, [vec![(1, "/first".to_owned())], vec![(1, "/second".to_owned())]]);
        fixture.closed().await
    }.await;
    drop(caller);
    finish_with_cleanup(primary, fixture.stop().await)
}

#[tokio::test]
async fn dropping_actual_pending_request_caller_destroys_both_sends_before_backup() -> TestResult<()> {
    let mut fixture = Fixture::start(Mode::Independent, 1, None).await?;
    let first = test_client(&fixture.identity, true)?;
    let second = test_client(&fixture.identity, true)?;
    let mut caller = Box::pin(independent_requests(first, second, fixture.address, fixture.control.take()));
    let primary: TestResult<()> = fixture.pending(&mut caller, [true, true], &[1, 1]).await;
    drop(caller);
    let primary: TestResult<()> = async {
        primary?;
        fixture.requests_destroyed([true, true]).await?;
        fixture.independent_result(Ok(())).await?;
        fixture.closed().await
    }.await;
    finish_with_cleanup(primary, fixture.stop().await)
}

#[tokio::test]
async fn actual_request_deadline_destroys_both_pending_sends_before_backup() -> TestResult<()> {
    let mut fixture = Fixture::start(Mode::Cold, 2, None).await?;
    let session = test_client(&fixture.identity, true)?;
    let mut caller = Box::pin(bounded(cold_requests(&session, fixture.address, fixture.control.take())));
    let primary: TestResult<()> = async {
        fixture.pending(&mut caller, [true, true], &[2]).await?;
        fixture.release_collection()?;
        let error = timeout(TEST_TIMEOUT + LIMIT, &mut caller).await?
            .err().ok_or("held actual requests completed before the caller deadline")?;
        let deadline = error.downcast_ref::<FixtureDeadline>().ok_or("actual request deadline type changed")?;
        assert!(std::error::Error::source(deadline).is_some_and(|source| source.is::<tokio::time::error::Elapsed>()));
        Ok(())
    }.await;
    drop(caller);
    drop(session);
    let primary: TestResult<()> = async {
        primary?;
        fixture.requests_destroyed([true, true]).await?;
        fixture.cold_result(Ok(())).await?;
        fixture.closed().await
    }.await;
    finish_with_cleanup(primary, fixture.stop().await)
}

#[tokio::test]
async fn first_original_request_error_destroys_its_actual_pending_sibling() -> TestResult<()> {
    let mut fixture = Fixture::start(Mode::Cold, 1, None).await?;
    fixture.targets([INVALID_URI.to_owned(), format!("https://{}/second", fixture.address)])?;
    let session = test_client(&fixture.identity, true)?;
    let mut caller = Box::pin(cold_requests(&session, fixture.address, fixture.control.take()));
    let primary: TestResult<()> = async {
        fixture.pending(&mut caller, [false, true], &[1]).await?;
        fixture.ready(&mut caller, [true, false]).await?;
        fixture.original_syntax_failure()?;
        fixture.release_collection()?;
        let error = timeout(LIMIT, &mut caller).await?.err().ok_or("invalid first request succeeded")?;
        retains_request(error.as_ref(), RequestErrorKind::InvalidUri)?;
        Ok(())
    }.await;
    drop(caller);
    drop(session);
    let primary: TestResult<()> = async {
        primary?;
        fixture.requests_destroyed([true, true]).await?;
        fixture.cold_result(Ok(())).await?;
        fixture.closed().await
    }.await;
    finish_with_cleanup(primary, fixture.stop().await)
}

#[tokio::test]
async fn two_completed_original_request_errors_keep_both_distinct_causes() -> TestResult<()> {
    let mut fixture = Fixture::start(Mode::Independent, 1, None).await?;
    fixture.targets([INVALID_URI.to_owned(), "http://127.0.0.1/second".to_owned()])?;
    let first = test_client(&fixture.identity, true)?;
    let second = test_client(&fixture.identity, true)?;
    let mut caller = Box::pin(independent_requests(first, second, fixture.address, fixture.control.take()));
    let primary: TestResult<()> = async {
        fixture.ready(&mut caller, [true, true]).await?;
        fixture.requests_destroyed([true, true]).await?;
        fixture.original_syntax_failure()?;
        assert_eq!(fixture.requests.borrow().kinds[1], Some(RequestErrorKind::UnsupportedScheme));
        fixture.release_collection()?;
        let error = timeout(LIMIT, &mut caller).await?.err().ok_or("two invalid requests succeeded")?;
        let failures = error.downcast_ref::<FixtureFailures>()
            .ok_or("first request join discarded the completed original second request error")?;
        retains_request(failures.primary.as_ref(), RequestErrorKind::InvalidUri)?;
        retains_request(failures.cleanup.as_ref(), RequestErrorKind::UnsupportedScheme)
    }.await;
    drop(caller);
    finish_with_cleanup(primary, fixture.stop().await)
}

#[tokio::test]
async fn cold_caller_error_keeps_its_completed_original_h2_serving_cause() -> TestResult<()> {
    let mut fixture = Fixture::start(Mode::Cold, 1, Some(io::Error::new(io::ErrorKind::PermissionDenied, FAILURE))).await?;
    fixture.targets([INVALID_URI.to_owned(), format!("https://{}/second", fixture.address)])?;
    let session = test_client(&fixture.identity, true)?;
    let mut caller = Box::pin(cold_requests(&session, fixture.address, fixture.control.take()));
    let caller_result: TestResult<TestResult<()>> = async {
        fixture.pending(&mut caller, [false, true], &[1]).await?;
        fixture.ready(&mut caller, [true, false]).await?;
        fixture.original_syntax_failure()?;
        fixture.fail_serving()?;
        let observed = &mut fixture.holds[0].observed;
        drive_until(&mut caller, async {
            timeout(LIMIT, observed.wait_for(|state| state.completed_error.is_some())).await??;
            Ok(())
        }).await?;
        assert_eq!(fixture.holds[0].observed.borrow().completed_error,
            Some((io::ErrorKind::PermissionDenied, FAILURE.to_owned())));
        fixture.server_finished(&mut caller).await?;
        fixture.ready(&mut caller, [true, true]).await?;
        assert!(fixture.requests.borrow().kinds[1].is_some(), "original second request did not retain an actual request failure");
        fixture.release_collection()?;
        timeout(LIMIT, &mut caller).await.map_err(Into::into)
    }.await;
    drop(caller);
    drop(session);
    let primary: TestResult<()> = async {
        let result = caller_result?;
        let error = fixture.cold_result(result).await.err().ok_or("invalid cold caller succeeded")?;
        let failures = error.downcast_ref::<FixtureFailures>()
            .ok_or("cold caller discarded its completed original H2 serving cause")?;
        retains_request(failures.primary.as_ref(), RequestErrorKind::InvalidUri)?;
        let original = failures.cleanup.downcast_ref::<::http2::Error>()
            .ok_or("original completed H2 serving error type changed")?;
        let io = original.get_io().ok_or("original completed H2 I/O cause missing")?;
        assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(io.to_string(), FAILURE);
        Ok(())
    }.await;
    finish_with_cleanup(primary, fixture.stop().await)
}

enum Mode {
    Cold,
    Independent,
}

enum Peer {
    Cold(reuse_ownership::Server),
    Independent(reuse_ownership::IndependentServer),
}

impl Peer {
    fn abort_handle(&self) -> AbortHandle {
        match self {
            Self::Cold(peer) => peer.abort_handle(),
            Self::Independent(peer) => peer.abort_handle(),
        }
    }
}

struct Hold {
    release: Option<oneshot::Sender<()>>,
    observed: watch::Receiver<HeldState>,
}

impl Hold {
    fn new() -> (Self, ResponseHold) {
        let (state, observed) = watch::channel(HeldState::default());
        let (release, released) = oneshot::channel();
        (Self { release: Some(release), observed },
            ResponseHold { release: released, observed: HoldObservation(state) })
    }
}

struct Fixture {
    identity: TestIdentity,
    address: SocketAddr,
    server: Option<Peer>,
    server_abort: AbortHandle,
    holds: Vec<Hold>,
    requests: watch::Receiver<RequestState>,
    control: Option<RequestControl>,
    collect: Option<oneshot::Sender<()>>,
    arm: Option<oneshot::Sender<()>>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.requests.borrow().tasks {
            task.abort();
        }
        self.server_abort.abort();
    }
}

impl Fixture {
    async fn start(mode: Mode, count: usize, fault: Option<io::Error>) -> TestResult<Self> {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (state, requests) = watch::channel(RequestState::default());
        let (collect, collect_after) = oneshot::channel();
        let control = RequestControl { observed: RequestObservation(state), collect_after, targets: None };
        let (first, first_hold) = Hold::new();
        let (arm, armed) = oneshot::channel();
        let fault = fault.map(|fault| reuse_ownership::request_fault_control(fault, armed));
        let (server, holds) = match mode {
            Mode::Cold => (Peer::Cold(reuse_ownership::spawn_server_held(listener, acceptor,
                count, fault, Some(first_hold))), vec![first]),
            Mode::Independent => {
                let (second, second_hold) = Hold::new();
                (Peer::Independent(reuse_ownership::spawn_independent_held(listener, acceptor,
                    [first_hold, second_hold])), vec![first, second])
            }
        };
        let server_abort = server.abort_handle();
        Ok(Self { identity, address, server: Some(server), server_abort, holds,
            requests, control: Some(control), collect: Some(collect), arm: Some(arm) })
    }

    fn targets(&mut self, targets: [String; 2]) -> TestResult<()> {
        self.control.as_mut().ok_or("original request control missing")?.targets = Some(targets);
        Ok(())
    }

    fn original_syntax_failure(&self) -> TestResult<()> {
        let original = self.requests.borrow();
        if original.kinds[0] != Some(RequestErrorKind::InvalidUri) || !original.syntax_sources[0] {
            return Err("original first request did not retain its actual URI syntax failure".into());
        }
        Ok(())
    }

    async fn pending<F>(&mut self, caller: &mut Pin<Box<F>>, required: [bool; 2], counts: &[usize]) -> TestResult<()>
    where F: Future<Output = TestResult<()>> {
        let requests = &mut self.requests;
        drive_until(caller, async {
            timeout(LIMIT, requests.wait_for(|state| {
                state.tasks.len() == 2 && required.iter().enumerate().all(|(index, required)|
                    !required || (state.pending[index] && !state.ready[index] && !state.destroyed[index]))
            })).await??;
            Ok(())
        }).await?;
        if counts.len() != self.holds.len() {
            return Err("held actual peer count changed".into());
        }
        for (hold, count) in self.holds.iter_mut().zip(counts) {
            drive_until(caller, async {
                timeout(LIMIT, hold.observed.wait_for(|state| state.requests.len() == *count
                    && state.read_pending && state.driver_pending && !state.destroyed)).await??;
                Ok(())
            }).await?;
        }
        if self.requests.borrow().tasks.iter().enumerate().any(|(index, task)| required[index] && task.is_finished()) {
            return Err("original pending request task finished before the target operation".into());
        }
        Ok(())
    }

    async fn ready<F>(&mut self, caller: &mut Pin<Box<F>>, required: [bool; 2]) -> TestResult<()>
    where F: Future<Output = TestResult<()>> {
        let requests = &mut self.requests;
        drive_until(caller, async {
            timeout(LIMIT, requests.wait_for(|state| required.iter().enumerate()
                .all(|(index, required)| !required || state.ready[index]))).await??;
            Ok(())
        }).await
    }

    async fn server_finished<F>(&self, caller: &mut Pin<Box<F>>) -> TestResult<()>
    where F: Future<Output = TestResult<()>> {
        drive_until(caller, async {
            timeout(LIMIT, async {
                while !self.server_abort.is_finished() { tokio::task::yield_now().await; }
            }).await?;
            Ok(())
        }).await
    }

    async fn requests_destroyed(&mut self, required: [bool; 2]) -> TestResult<()> {
        timeout(OBSERVATION_LIMIT, self.requests.wait_for(|state| required.iter().enumerate()
            .all(|(index, required)| !required || state.destroyed[index]))).await??;
        timeout(LIMIT, async {
            while self.requests.borrow().tasks.iter().enumerate()
                .any(|(index, task)| required[index] && !task.is_finished()) {
                tokio::task::yield_now().await;
            }
        }).await?;
        Ok(())
    }

    fn release_responses(&mut self) -> TestResult<()> {
        for hold in &mut self.holds {
            hold.release.take().ok_or("original response release missing")?.send(())
                .map_err(|_| "original response release receiver closed")?;
        }
        Ok(())
    }

    fn release_collection(&mut self) -> TestResult<()> {
        self.collect.take().ok_or("original request collection release missing")?.send(())
            .map_err(|_| "original request collection receiver closed")?;
        Ok(())
    }

    fn fail_serving(&mut self) -> TestResult<()> {
        self.arm.take().ok_or("original serving failure release missing")?.send(())
            .map_err(|_| "original serving failure receiver closed")?;
        Ok(())
    }

    async fn cold_result(&mut self, caller: TestResult<()>) -> TestResult<reuse_ownership::Requests> {
        let Some(Peer::Cold(server)) = self.server.take() else {
            return Err("original cold peer missing".into());
        };
        timeout(LIMIT, finish_cold(caller, server)).await?
    }

    async fn independent_result(&mut self, caller: TestResult<()>) -> TestResult<[reuse_ownership::Requests; 2]> {
        let Some(Peer::Independent(server)) = self.server.take() else {
            return Err("original independent peer missing".into());
        };
        timeout(LIMIT, reuse_ownership::collect_independent(caller, server)).await?
    }

    async fn closed(&mut self) -> TestResult<()> {
        for hold in &mut self.holds {
            timeout(LIMIT, hold.observed.wait_for(|state| state.closed && state.destroyed)).await??;
        }
        timeout(LIMIT, async {
            while !self.server_abort.is_finished() { tokio::task::yield_now().await; }
        }).await?;
        Ok(())
    }

    async fn stop(&mut self) -> TestResult<()> {
        for task in &self.requests.borrow().tasks { task.abort(); }
        let requested = !self.server_abort.is_finished();
        self.server_abort.abort();
        let joined = match self.server.take() {
            Some(Peer::Cold(mut server)) => match timeout(LIMIT, &mut server).await {
                Ok(Ok(result)) => result.map(|_| ()),
                Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            },
            Some(Peer::Independent(mut server)) => match timeout(LIMIT, &mut server).await {
                Ok(Ok(result)) => result.map(|_| ()),
                Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            },
            None => Ok(()),
        };
        let finished: TestResult<()> = timeout(LIMIT, async {
            while !self.server_abort.is_finished()
                || self.requests.borrow().tasks.iter().any(|task| !task.is_finished()) {
                tokio::task::yield_now().await;
            }
            Ok(())
        }).await.map_err(Into::into).and_then(|result| result);
        finish_with_cleanup(joined, finished)
    }
}

async fn drive_until<F>(caller: &mut Pin<Box<F>>, condition: impl Future<Output = TestResult<()>>) -> TestResult<()>
where F: Future<Output = TestResult<()>> {
    tokio::select! {
        biased;
        result = caller => finish_with_cleanup(Err("canonical request caller finished before its prerequisite".into()), result),
        result = condition => result,
    }
}

fn retains_request(error: &(dyn std::error::Error + 'static), kind: RequestErrorKind) -> TestResult<()> {
    let original = request_cause(error, kind).ok_or("original request error type or kind changed")?;
    assert_eq!(original.kind(), kind);
    if kind == RequestErrorKind::InvalidUri {
        assert!(std::error::Error::source(original).is_some_and(|source| source.is::<http::uri::InvalidUri>()));
    }
    Ok(())
}

fn request_cause(error: &(dyn std::error::Error + 'static), kind: RequestErrorKind) -> Option<&RequestError> {
    if let Some(original) = error.downcast_ref::<RequestError>() {
        return (original.kind() == kind).then_some(original);
    }
    let failures = error.downcast_ref::<FixtureFailures>()?;
    request_cause(failures.primary.as_ref(), kind).or_else(|| request_cause(failures.cleanup.as_ref(), kind))
}
