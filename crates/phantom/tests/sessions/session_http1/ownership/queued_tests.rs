use std::{future::Future, pin::Pin, time::Duration};

use phantom::{Client, HttpProtocol, RequestBuilder, RequestErrorKind, Response, ResponseBody};
use tokio::{
    sync::{oneshot, watch},
    time::timeout,
};

use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup},
};

use super::super::TEST_TIMEOUT;
use super::tests::drive_until;
use super::{
    ActiveBody, QueuedControl, QueuedObservation, QueuedPair, QueuedState, TestResult, active_body,
    queued_requests,
};

const LIMIT: Duration = Duration::from_secs(5);
const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);

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

#[tokio::test]
async fn completed_foreign_waiter_cancellation_and_caller_deadline_keep_both_causes() -> TestResult
{
    let (mut fixture, control) = QueuedFixture::start().await?;
    let [first, second] = fixture.requests()?;
    let mut requests = QueuedPair::new(first, second, Some(control.observed.clone()));
    let mut caller = Box::pin(super::super::bounded(requests.drive(Some(control))));

    let operation: TestResult = async {
        fixture.pending(&mut caller).await?;

        let state = fixture.observed.borrow().clone();
        let pending = (0..2)
            .find(|index| state.pending[*index] && !state.ready[*index])
            .ok_or("original pending waiter missing before foreign cancellation")?;
        let task = state.tasks[pending]
            .as_ref()
            .ok_or("original pending task handle missing")?;

        task.abort();
        fixture.destroyed().await?;

        timeout(TEST_TIMEOUT + LIMIT, &mut caller).await?
    }
    .await;

    drop(caller);

    let collected = requests.finish(operation).await;
    drop(requests);

    let primary: TestResult = async {
        let error = collected
            .err()
            .ok_or("original cancelled waiter and caller deadline succeeded")?;
        let checked: TestResult = (|| {
            let failures = error
                .downcast_ref::<FixtureFailures>()
                .ok_or("original completed waiter cancellation was discarded at caller deadline")?;

            let deadline = failures
                .primary
                .downcast_ref::<FixtureDeadline>()
                .ok_or("original queued caller deadline type changed")?;
            assert_eq!(
                deadline.to_string(),
                "HTTP/1 session test exceeded deadline"
            );
            assert!(
                std::error::Error::source(deadline)
                    .is_some_and(|source| source.is::<tokio::time::error::Elapsed>())
            );

            let original = failures
                .cleanup
                .downcast_ref::<tokio::task::JoinError>()
                .ok_or("original completed foreign cancellation JoinError type changed")?;
            assert!(original.is_cancelled());
            Ok(())
        })();

        if let Err(check) = checked {
            return finish_with_cleanup(Err(check), Err(error));
        }

        let state = fixture.observed.borrow().clone();
        assert!(state.joined.iter().all(|joined| *joined));
        assert!(!state.stop_requested.iter().any(|requested| *requested));

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
    server: Option<super::Server>,
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
        let mut preparing = None;
        let prepared = match timeout(
            LIMIT,
            active_body(Some(observed_owner.clone()), &mut preparing),
        )
        .await
        {
            Ok(result) => result,
            Err(elapsed) => Err(FixtureDeadline::new(
                "HTTP/1 active-body setup exceeded deadline",
                elapsed,
            )
            .into()),
        };

        let ActiveBody {
            session,
            active,
            address,
            server,
        } = super::collect_peer(prepared, preparing).await?;
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
            session.get_with_protocol(
                HttpProtocol::Http1,
                &format!("https://{}/waiting-one", self.address),
            )?,
            session.get_with_protocol(
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
