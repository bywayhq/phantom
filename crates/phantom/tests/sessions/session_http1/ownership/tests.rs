use std::{future::Future, pin::Pin, time::Duration};

use phantom::{
    Client, HttpProtocol, RequestBuilder, RequestError, RequestErrorKind, Response, ResponseBody,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{oneshot, watch},
    time::timeout,
};

use crate::support::{
    deadline::FixtureDeadline,
    tls,
    tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup},
};

use super::super::TEST_TIMEOUT;
use super::{
    ActiveBody, Control, Observation, QueuedControl, QueuedObservation, QueuedState, State,
    TestResult, active_body, queued_requests, reuse_requests,
};

const LIMIT: Duration = Duration::from_secs(5);
const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);
const INVALID_URI: &str = "https://127.0.0.1/invalid uri";

#[tokio::test]
async fn dropping_actual_pending_caller_destroys_its_original_handshake_peer() -> TestResult {
    let (mut fixture, control) = Fixture::new(None);
    let mut caller = Box::pin(reuse_requests(Some(control)));
    let primary: TestResult = async {
        fixture.connect(&mut caller).await?;
        fixture.release()?;
        fixture.caller_pending(&mut caller).await
    }
    .await;

    drop(caller);

    let primary: TestResult = async {
        primary?;
        fixture.destroyed().await?;
        fixture.closed().await
    }
    .await;

    finish_with_cleanup(primary, fixture.stop().await)
}

#[tokio::test]
async fn actual_caller_deadline_destroys_its_original_pending_handshake_peer() -> TestResult {
    let (mut fixture, control) = Fixture::new(None);
    let mut caller = Box::pin(reuse_requests(Some(control)));
    let primary: TestResult = async {
        fixture.connect(&mut caller).await?;
        fixture.release()?;
        fixture.caller_pending(&mut caller).await?;

        let error = timeout(TEST_TIMEOUT + LIMIT, &mut caller)
            .await?
            .err()
            .ok_or("original pending caller completed before its deadline")?;
        assert_eq!(error.to_string(), "HTTP/1 session test exceeded deadline");
        Ok(())
    }
    .await;

    drop(caller);

    let primary: TestResult = async {
        primary?;
        fixture.destroyed().await?;
        fixture.closed().await
    }
    .await;

    finish_with_cleanup(primary, fixture.stop().await)
}

#[tokio::test]
async fn actual_five_second_caller_deadline_retains_its_original_elapsed() -> TestResult {
    let (mut fixture, control) = Fixture::new(None);
    let mut caller = Box::pin(reuse_requests(Some(control)));
    let primary: TestResult = async {
        fixture.connect(&mut caller).await?;
        fixture.release()?;
        fixture.caller_pending(&mut caller).await?;

        let error = timeout(TEST_TIMEOUT + LIMIT, &mut caller)
            .await?
            .err()
            .ok_or("original pending caller completed before its deadline")?;
        let deadline = error
            .downcast_ref::<FixtureDeadline>()
            .ok_or("HTTP/1 caller discarded its original timeout Elapsed")?;
        assert!(
            std::error::Error::source(deadline)
                .is_some_and(|source| source.is::<tokio::time::error::Elapsed>())
        );
        Ok(())
    }
    .await;

    drop(caller);

    let primary: TestResult = async {
        primary?;
        fixture.destroyed().await?;
        fixture.closed().await
    }
    .await;

    finish_with_cleanup(primary, fixture.stop().await)
}

#[tokio::test]
async fn original_input_failure_destroys_its_actual_pending_handshake_peer() -> TestResult {
    let (mut fixture, control) = Fixture::new(Some(INVALID_URI.to_owned()));
    let mut caller = Box::pin(reuse_requests(Some(control)));
    let primary: TestResult = async {
        fixture.connect(&mut caller).await?;
        fixture.release()?;

        let error = timeout(LIMIT, &mut caller)
            .await?
            .err()
            .ok_or("original invalid URI caller succeeded")?;
        original_uri_failure(error.as_ref())
    }
    .await;

    drop(caller);

    let primary: TestResult = async {
        primary?;
        fixture.destroyed().await?;
        fixture.closed().await
    }
    .await;

    finish_with_cleanup(primary, fixture.stop().await)
}

#[tokio::test]
async fn completed_original_tls_peer_and_uri_caller_keep_both_causes() -> TestResult {
    let (mut fixture, control) = Fixture::new(Some(INVALID_URI.to_owned()));
    let mut caller = Box::pin(reuse_requests(Some(control)));
    let primary: TestResult = async {
        fixture.connect(&mut caller).await?;

        let socket = fixture
            .socket
            .as_mut()
            .ok_or("original peer client missing")?;
        socket.write_all(b"not a TLS handshake").await?;
        socket.shutdown().await?;

        timeout(
            LIMIT,
            fixture
                .observed
                .wait_for(|state| state.completed_tls_error.is_some()),
        )
        .await??;
        fixture.finished().await?;

        let original_message = fixture
            .observed
            .borrow()
            .completed_tls_error
            .clone()
            .ok_or("original TLS handshake failure observation missing")?;

        fixture.release()?;
        let error = timeout(LIMIT, &mut caller)
            .await?
            .err()
            .ok_or("original invalid URI caller succeeded")?;
        original_uri_failure(error.as_ref())?;

        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("HTTP/1 caller discarded its completed original TLS peer cause")?;
        original_uri_failure(failures.primary.as_ref())?;

        let original = failures
            .cleanup
            .downcast_ref::<btls::ssl::Error>()
            .ok_or("original completed TLS handshake error type changed")?;
        assert_eq!(original.to_string(), original_message);
        Ok(())
    }
    .await;

    drop(caller);

    let primary: TestResult = async {
        primary?;
        fixture.destroyed().await?;
        fixture.closed().await
    }
    .await;

    finish_with_cleanup(primary, fixture.stop().await)
}

struct Fixture {
    observed: watch::Receiver<State>,
    start: Option<oneshot::Sender<()>>,
    socket: Option<TcpStream>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(server) = &self.observed.borrow().server {
            server.abort();
        }
    }
}

impl Fixture {
    fn new(first_target: Option<String>) -> (Self, Control) {
        let (state, observed) = watch::channel(State::default());
        let (start, started) = oneshot::channel();
        (
            Self {
                observed,
                start: Some(start),
                socket: None,
            },
            Control {
                observed: Observation(state),
                start: started,
                first_target,
            },
        )
    }

    async fn connect<F>(&mut self, caller: &mut Pin<Box<F>>) -> TestResult
    where
        F: Future<Output = TestResult>,
    {
        let observed = &mut self.observed;
        drive_until(caller, async {
            timeout(
                LIMIT,
                observed.wait_for(|state| state.address.is_some() && state.server.is_some()),
            )
            .await??;
            Ok(())
        })
        .await?;

        let address = self
            .observed
            .borrow()
            .address
            .ok_or("original peer address missing")?;
        self.socket = Some(timeout(LIMIT, TcpStream::connect(address)).await??);
        timeout(
            LIMIT,
            self.observed
                .wait_for(|state| state.accepted && state.handshake_pending && !state.destroyed),
        )
        .await??;
        Ok(())
    }

    fn release(&mut self) -> TestResult {
        self.start
            .take()
            .ok_or("original caller preparation release missing")?
            .send(())
            .map_err(|_| "original caller preparation receiver closed")?;
        Ok(())
    }

    async fn caller_pending<F>(&mut self, caller: &mut Pin<Box<F>>) -> TestResult
    where
        F: Future<Output = TestResult>,
    {
        let observed = &mut self.observed;
        drive_until(caller, async {
            timeout(
                LIMIT,
                observed.wait_for(|state| {
                    state.caller_pending && state.handshake_pending && !state.destroyed
                }),
            )
            .await??;
            Ok(())
        })
        .await
    }

    async fn destroyed(&mut self) -> TestResult {
        timeout(
            OBSERVATION_LIMIT,
            self.observed.wait_for(|state| state.destroyed),
        )
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new(
                "original HTTP/1 peer remained live after caller exit",
                elapsed,
            )
        })??;

        self.finished().await
    }

    async fn finished(&self) -> TestResult {
        let server = self
            .observed
            .borrow()
            .server
            .clone()
            .ok_or("original server handle missing")?;

        timeout(LIMIT, async {
            while !server.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    async fn closed(&mut self) -> TestResult {
        let socket = self.socket.as_mut().ok_or("original peer client missing")?;

        match timeout(OBSERVATION_LIMIT, socket.read_to_end(&mut Vec::new())).await? {
            Ok(_) => Ok(()),
            Err(error) if tls::is_peer_gone(&error) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn stop(&mut self) -> TestResult {
        let server = self.observed.borrow().server.clone();
        let Some(server) = server else {
            return Ok(());
        };

        server.abort();

        self.finished().await?;
        if self.socket.is_some() {
            self.closed().await?;
        }

        Ok(())
    }
}

async fn drive_until<F>(
    caller: &mut Pin<Box<F>>,
    condition: impl Future<Output = TestResult>,
) -> TestResult
where
    F: Future<Output = TestResult>,
{
    tokio::select! {
        biased;
        result = caller => finish_with_cleanup(Err("original HTTP/1 caller finished before its prerequisite".into()), result),
        result = condition => result,
    }
}

fn original_uri_failure(error: &(dyn std::error::Error + 'static)) -> TestResult {
    if let Some(original) = error.downcast_ref::<RequestError>() {
        assert_eq!(original.kind(), RequestErrorKind::InvalidUri);
        assert!(
            std::error::Error::source(original)
                .is_some_and(|source| source.is::<http::uri::InvalidUri>())
        );
        return Ok(());
    }

    let failures = error
        .downcast_ref::<FixtureFailures>()
        .ok_or("original URI request error type changed")?;
    original_uri_failure(failures.primary.as_ref())
}

#[tokio::test]
async fn dropping_original_queued_caller_destroys_its_actual_pending_waiter() -> TestResult {
    let (mut fixture, control) = QueuedFixture::start().await?;
    let [first, second] = fixture.requests()?;
    let mut caller = Box::pin(queued_requests(first, second, Some(control)));
    let primary = fixture.pending(&mut caller).await;

    drop(caller);

    let primary: TestResult = async {
        primary?;
        fixture.destroyed().await?;
        fixture.close_origin().await
    }
    .await;

    finish_with_cleanup(primary, fixture.stop().await)
}

#[tokio::test]
async fn original_queued_caller_deadline_destroys_its_actual_pending_waiter() -> TestResult {
    let (mut fixture, control) = QueuedFixture::start().await?;
    let [first, second] = fixture.requests()?;
    let mut caller = Box::pin(super::super::bounded(queued_requests(
        first,
        second,
        Some(control),
    )));
    let primary: TestResult = async {
        fixture.pending(&mut caller).await?;

        let error = timeout(TEST_TIMEOUT + LIMIT, &mut caller)
            .await?
            .err()
            .ok_or("original queued caller completed before its deadline")?;
        assert_eq!(error.to_string(), "HTTP/1 session test exceeded deadline");
        Ok(())
    }
    .await;

    drop(caller);

    let primary: TestResult = async {
        primary?;
        fixture.destroyed().await?;
        fixture.close_origin().await
    }
    .await;

    finish_with_cleanup(primary, fixture.stop().await)
}

#[tokio::test]
async fn locally_cancelled_original_pending_waiter_is_joined_before_backup() -> TestResult {
    let (mut fixture, control) = QueuedFixture::start().await?;
    let [first, second] = fixture.requests()?;
    let mut caller = Box::pin(queued_requests(first, second, Some(control)));
    let primary: TestResult = async {
        fixture.pending(&mut caller).await?;
        fixture.release_collection()?;
        let observed = &mut fixture.observed;
        drive_until(&mut caller, async {
            timeout(LIMIT, observed.wait_for(|state| state.selected.is_some())).await??;
            Ok(())
        })
        .await?;

        fixture.destroyed().await?;
        let state = fixture.observed.borrow().clone();
        let selected = state.selected.ok_or("original selected waiter missing")?;
        let sibling = 1 - selected;
        assert!(state.stop_requested[sibling]);
        assert!(
            !state.ready[sibling],
            "original pending sibling completed before local cancellation"
        );

        fixture.release_return()?;
        timeout(LIMIT, &mut caller).await??;
        if !fixture
            .observed
            .borrow()
            .joined
            .iter()
            .all(|joined| *joined)
        {
            return Err("locally requested original sibling cancellation was not joined".into());
        }
        Ok(())
    }
    .await;

    drop(caller);

    let primary: TestResult = async {
        primary?;
        fixture.close_origin().await
    }
    .await;

    finish_with_cleanup(primary, fixture.stop().await)
}

struct QueuedFixture {
    observed: watch::Receiver<QueuedState>,
    collect: Option<oneshot::Sender<()>>,
    returned: Option<oneshot::Sender<()>>,
    session: Option<Client>,
    active: Option<Response<ResponseBody>>,
    address: std::net::SocketAddr,
    server: Option<tokio::task::JoinHandle<TestResult>>,
    server_abort: tokio::task::AbortHandle,
}

impl Drop for QueuedFixture {
    fn drop(&mut self) {
        for task in self.observed.borrow().tasks.iter().flatten() {
            task.abort();
        }
        self.server_abort.abort();
    }
}

impl QueuedFixture {
    async fn start() -> TestResult<(Self, QueuedControl)> {
        let (state, observed) = watch::channel(QueuedState::default());
        let observed_owner = QueuedObservation(state);
        let (collect, collect_after) = oneshot::channel();
        let (returned, return_after) = oneshot::channel();
        let ActiveBody {
            session,
            active,
            address,
            server,
        } = timeout(LIMIT, active_body(Some(observed_owner.clone()))).await??;
        let server_abort = server.abort_handle();

        Ok((
            Self {
                observed,
                collect: Some(collect),
                returned: Some(returned),
                session: Some(session),
                active: Some(active),
                address,
                server: Some(server),
                server_abort,
            },
            QueuedControl {
                observed: observed_owner,
                collect_after,
                return_after,
            },
        ))
    }

    fn requests(&self) -> TestResult<[RequestBuilder; 2]> {
        let session = self
            .session
            .as_ref()
            .ok_or("original active HTTP/1 client missing")?;
        Ok([
            session.get(
                HttpProtocol::Http1,
                &format!("https://{}/waiting-one", self.address),
            )?,
            session.get(
                HttpProtocol::Http1,
                &format!("https://{}/waiting-two", self.address),
            )?,
        ])
    }

    async fn pending<F>(&mut self, caller: &mut Pin<Box<F>>) -> TestResult
    where
        F: Future<Output = TestResult>,
    {
        let observed = &self.observed;
        drive_until(caller, async {
            timeout(LIMIT, async {
                loop {
                    let state = observed.borrow().clone();
                    let pending = (0..2).any(|index| {
                        state.pending[index]
                            && !state.ready[index]
                            && !state.destroyed[index]
                            && state.ready[1 - index]
                            && state.kinds[1 - index] == Some(RequestErrorKind::Capacity)
                            && state.tasks[index]
                                .as_ref()
                                .is_some_and(|task| !task.is_finished())
                            && state.tasks[1 - index]
                                .as_ref()
                                .is_some_and(|task| task.is_finished())
                    });
                    if state.tasks.iter().all(Option::is_some)
                        && state.peer_pending
                        && !state.peer_destroyed
                        && pending
                    {
                        return Ok(());
                    }

                    tokio::task::yield_now().await;
                }
            })
            .await?
        })
        .await
    }

    async fn destroyed(&mut self) -> TestResult {
        timeout(
            OBSERVATION_LIMIT,
            self.observed
                .wait_for(|state| state.destroyed.iter().all(|destroyed| *destroyed)),
        )
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new(
                "original HTTP/1 queued requests remained live after caller exit",
                elapsed,
            )
        })??;

        self.finished_requests().await
    }

    async fn finished_requests(&self) -> TestResult {
        timeout(LIMIT, async {
            while self
                .observed
                .borrow()
                .tasks
                .iter()
                .flatten()
                .any(|task| !task.is_finished())
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    fn release_collection(&mut self) -> TestResult {
        self.collect
            .take()
            .ok_or("original queued collection release missing")?
            .send(())
            .map_err(|_| "original queued collection receiver closed")?;
        Ok(())
    }

    fn release_return(&mut self) -> TestResult {
        self.returned
            .take()
            .ok_or("original queued return release missing")?
            .send(())
            .map_err(|_| "original queued return receiver closed")?;
        Ok(())
    }

    async fn close_origin(&mut self) -> TestResult {
        drop(self.active.take());
        drop(self.session.take());

        let server = self
            .server
            .as_mut()
            .ok_or("original active-body server missing")?;
        let joined = timeout(LIMIT, server).await;
        if joined.is_ok() {
            self.server.take();
        }

        let result = joined??;
        result?;

        timeout(
            LIMIT,
            self.observed
                .wait_for(|state| state.peer_closed && state.peer_destroyed),
        )
        .await??;
        Ok(())
    }

    async fn stop(&mut self) -> TestResult {
        for task in self.observed.borrow().tasks.iter().flatten() {
            task.abort();
        }
        let requests = self.finished_requests().await;

        drop(self.active.take());
        drop(self.session.take());

        let requested = !self.server_abort.is_finished();
        if requested {
            self.server_abort.abort();
        }
        let serving = match self.server.as_mut() {
            Some(server) => match timeout(LIMIT, server).await {
                Ok(Ok(result)) => result,
                Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            },
            None => Ok(()),
        };

        finish_with_cleanup(requests, serving)
    }
}
