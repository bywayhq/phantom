use std::{future::Future, pin::Pin, time::Duration};

use phantom::{RequestError, RequestErrorKind};
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
use super::{Control, Observation, State, TestResult, reuse_requests};

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

pub(super) async fn drive_until<F>(
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

pub(super) fn original_uri_failure(error: &(dyn std::error::Error + 'static)) -> TestResult {
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
