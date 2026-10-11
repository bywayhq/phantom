use std::{io, time::Duration};

use bytes::Bytes;
use tokio::{
    sync::{oneshot, watch},
    task::AbortHandle,
    time::timeout,
};

use super::{
    Backup, ConnectionPeer, Control, FixtureFailures, LIMIT, Mode, OBSERVATION_LIMIT,
    Observation, ServerTask, State, TestResult, collect, collect_independent,
    finish_with_cleanup, open_raw_request, read_failure, retains_h2_cause, tls_support,
};

const SECOND_FAILURE: &str = "injected second session reuse serving read failure";

#[tokio::test]
async fn caller_failure_keeps_the_completed_first_child_while_second_accept_is_pending() -> TestResult<()> {
    let mut backup = Backup::start(Mode::Independent, Some(read_failure())).await?;
    let primary = async {
        backup.raw_request().await?;
        backup.pending_second().await?;
        backup.fail_read().await?;
        assert!(!backup.abort.as_ref().ok_or("original coordinator witness missing")?.is_finished());

        let caller = backup.invalid_header().await?;
        let kind = caller.kind();
        let Some(ServerTask::Independent(server)) = backup.server.take() else {
            return Err("original independent reuse coordinator missing".into());
        };

        let observer = LIMIT * 2 + Duration::from_secs(2);
        let error = timeout(observer, collect_independent(Err(caller.into()), server)).await?
            .err().ok_or("invalid independent caller succeeded")?;
        backup.closed().await?;
        assert!(backup.observed.borrow().coordinator_destroyed);

        let errors = error.downcast_ref::<FixtureFailures>()
            .ok_or("independent caller discarded its completed first child cause")?;
        let caller = errors.primary.downcast_ref::<phantom::RequestError>()
            .ok_or("original independent caller type changed")?;
        assert_eq!(caller.kind(), kind);
        retains_h2_cause(errors.cleanup.as_ref())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn original_coordinator_deadline_keeps_elapsed_and_closes_its_first_child() -> TestResult<()> {
    let mut backup = Backup::start(Mode::Independent, None).await?;
    let primary = async {
        backup.raw_request().await?;
        backup.pending_second().await?;
        let Some(ServerTask::Independent(server)) = backup.server.take() else {
            return Err("original independent reuse coordinator missing".into());
        };

        let observer = LIMIT * 2 + Duration::from_secs(2);
        let error = timeout(observer, collect_independent(Ok(()), server)).await?
            .err().ok_or("pending original coordinator succeeded")?;
        assert_eq!(error.to_string(), "reuse coordinator did not finish");
        assert!(std::error::Error::source(error.as_ref())
            .is_some_and(|source| source.is::<tokio::time::error::Elapsed>()));
        backup.closed().await?;
        assert!(backup.observed.borrow().coordinator_destroyed);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn original_server_deadline_retains_elapsed_and_joins_its_pending_driver() -> TestResult<()> {
    let mut backup = Backup::start(Mode::Ordinary, None).await?;
    let primary = async {
        backup.raw_request().await?;
        backup.pending().await?;
        let Some(ServerTask::Ordinary(server)) = backup.server.take() else {
            return Err("original ordinary reuse server missing".into());
        };

        let observer = LIMIT * 2 + Duration::from_secs(2);
        let error = timeout(observer, collect(Ok(()), server)).await?
            .err().ok_or("pending original reuse server succeeded")?;
        assert_eq!(error.to_string(), "reuse server did not finish");
        assert!(std::error::Error::source(error.as_ref())
            .is_some_and(|source| source.is::<tokio::time::error::Elapsed>()));

        backup.closed().await
    }
    .await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn first_completed_child_failure_closes_the_second_original_pending_driver() -> TestResult<()> {
    let mut pair = Pair::start(false).await?;
    let primary = async {
        pair.acquired().await?;
        pair.backup.fail_read().await?;
        assert!(!pair.second_witness()?.is_finished());
        pair.release()?;
        let error = pair.backup.independent_result().await
            .err().ok_or("faulted first original child succeeded")?;
        let retained = retains_h2_cause(error.as_ref());
        let first_closed = pair.backup.closed().await;
        let witness = pair.second_witness()?;
        let second_closed = pair.second.closed(&mut pair.second_state, &witness).await;
        finish_with_cleanup(finish_with_cleanup(retained, first_closed), second_closed)
    }
    .await;
    finish_with_cleanup(primary, pair.stop().await)
}

#[tokio::test]
async fn a_finished_foreign_second_child_cancel_keeps_its_original_join_error() -> TestResult<()> {
    let mut pair = Pair::start(false).await?;
    let primary = async {
        pair.acquired().await?;
        let witness = pair.second_witness()?;
        witness.abort();
        pair.second.closed(&mut pair.second_state, &witness).await?;
        assert!(!pair.backup.observed.borrow().children[0].is_finished());
        pair.release()?;
        let error = pair.backup.independent_result().await
            .err().ok_or("foreign cancelled second original child succeeded")?;
        let original = error.downcast_ref::<tokio::task::JoinError>()
            .ok_or("foreign finished original child cancellation was replaced")?;
        assert!(original.is_cancelled());

        pair.backup.closed().await
    }
    .await;
    finish_with_cleanup(primary, pair.stop().await)
}

#[tokio::test]
async fn collection_keeps_both_completed_original_h2_child_causes() -> TestResult<()> {
    let mut pair = Pair::start(true).await?;
    let primary = async {
        pair.acquired().await?;
        pair.backup.fail_read().await?;
        pair.arm.take().ok_or("second original fault gate missing")?
            .send(()).map_err(|_| "second original fault gate closed")?;
        timeout(LIMIT, pair.second_state.wait_for(|state| state.fault_taken)).await??;
        let witness = pair.second_witness()?;
        pair.second.closed(&mut pair.second_state, &witness).await?;
        pair.backup.closed().await?;
        pair.release()?;
        let error = pair.backup.independent_result().await
            .err().ok_or("both completed original child failures succeeded")?;
        let failures = error.downcast_ref::<FixtureFailures>()
            .ok_or("first original child failure discarded the second original cause")?;
        retains_h2_cause(failures.primary.as_ref())?;
        let original = failures.cleanup.downcast_ref::<::http2::Error>()
            .ok_or("second original H2 error type changed")?;
        let io = original.get_io().ok_or("second original H2 I/O cause missing")?;
        assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(io.to_string(), SECOND_FAILURE);
        Ok(())
    }
    .await;
    finish_with_cleanup(primary, pair.stop().await)
}

struct Pair {
    backup: Backup,
    second: SecondClient,
    second_state: watch::Receiver<State>,
    arm: Option<oneshot::Sender<()>>,
    released: Option<oneshot::Sender<()>>,
}

impl Pair {
    async fn start(failing: bool) -> TestResult<Self> {
        let (state, second_state) = watch::channel(State::default());
        let (arm, armed) = oneshot::channel();
        let (released, collect_after) = oneshot::channel();
        let control = Control {
            observed: Observation(state),
            fault: failing.then(|| io::Error::new(io::ErrorKind::PermissionDenied, SECOND_FAILURE)),
            armed,
        };
        let backup = Backup::start_controlled(
            Mode::Independent, Some(read_failure()), Some(control), Some(collect_after),
        ).await?;

        Ok(Self {
            backup,
            second: SecondClient::default(),
            second_state,
            arm: Some(arm),
            released: Some(released),
        })
    }

    async fn acquired(&mut self) -> TestResult<()> {
        self.backup.raw_request().await?;
        self.backup.pending_second().await?;
        open_raw_request(
            &self.backup.identity, self.backup.address,
            &mut self.second.sender, &mut self.second.driver,
        ).await?;
        timeout(LIMIT, self.second_state.wait_for(|state| state.closed_pending)).await??;
        timeout(LIMIT, self.backup.observed.wait_for(|state| state.children.len() == 2)).await??;
        assert!(!self.second_witness()?.is_finished());
        assert!(self.second.sender.is_some());
        assert!(self.second.driver.as_ref().is_some_and(|driver| !driver.is_finished()));
        Ok(())
    }

    fn second_witness(&self) -> TestResult<AbortHandle> {
        self.backup.observed.borrow().children.get(1).cloned()
            .ok_or_else(|| "second original child witness missing".into())
    }

    fn release(&mut self) -> TestResult<()> {
        self.released.take().ok_or("original coordinator collection gate missing")?
            .send(()).map_err(|_| "original coordinator stopped before collection release".into())
    }

    async fn stop(&mut self) -> TestResult<()> {
        let backup = self.backup.stop().await;
        drop(self.released.take());
        let second = self.second.stop().await;
        finish_with_cleanup(backup, second)
    }
}

#[derive(Default)]
struct SecondClient {
    sender: Option<::http2::client::SendRequest<Bytes>>,
    driver: Option<ConnectionPeer<Result<(), ::http2::Error>>>,
}

impl SecondClient {
    async fn closed(&mut self, state: &mut watch::Receiver<State>, witness: &AbortHandle) -> TestResult<()> {
        timeout(OBSERVATION_LIMIT, state.wait_for(|state| state.destroyed)).await??;
        timeout(LIMIT, async {
            while !witness.is_finished() {
                tokio::task::yield_now().await;
            }
        }).await?;

        let driver = self.driver.as_mut().ok_or("second original client driver missing")?;
        let joined = timeout(LIMIT, driver).await?;
        self.driver.take();
        match joined? {
            Ok(()) => Ok(()),
            Err(error) if error.get_io().is_some_and(tls_support::is_peer_gone) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    async fn stop(&mut self) -> TestResult<()> {
        drop(self.sender.take());
        let Some(mut driver) = self.driver.take() else {
            return Ok(());
        };

        let requested = !driver.is_finished();
        if requested {
            driver.abort();
        }

        match timeout(LIMIT, &mut driver).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) if error.get_io().is_some_and(tls_support::is_peer_gone) => Ok(()),
            Ok(Ok(Err(error))) => Err(error.into()),
            Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(error) => Err(error.into()),
        }
    }
}
