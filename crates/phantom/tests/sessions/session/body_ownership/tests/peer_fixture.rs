use std::{
    error::Error,
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
    time::Duration,
};

use phantom::{RequestError, RequestErrorKind};
use tokio::{
    io::{copy, sink},
    net::TcpStream,
    sync::{oneshot, watch},
    task::Id,
    time::timeout,
};

use super::super::{Control, Observation, PeerState, Setup, TestResult};
use crate::support::{
    deadline::FixtureDeadline,
    tls,
    tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup},
};

const LIMIT: Duration = Duration::from_secs(5);
const OBSERVATION_LIMIT: Duration = Duration::from_secs(1);

pub(in super::super::super) struct Fixture {
    ready: oneshot::Receiver<Setup>,
    state: watch::Receiver<PeerState>,
    resume: Option<oneshot::Sender<()>>,
    setup: Option<Setup>,
    socket: Option<TcpStream>,
    queued_backup_started: bool,
}

impl Fixture {
    pub(in super::super::super) fn new(target: Option<&str>) -> (Control, Self) {
        let (observed, state) = watch::channel(PeerState::default());
        let (setup, ready) = oneshot::channel();
        let (resume, held) = oneshot::channel();
        let control = Control {
            observed: Observation(observed),
            setup,
            resume: held,
            target: target.map(str::to_owned),
        };

        (
            control,
            Self {
                ready,
                state,
                resume: Some(resume),
                setup: None,
                socket: None,
                queued_backup_started: false,
            },
        )
    }

    pub(in super::super::super) async fn start<F>(
        &mut self,
        caller: &mut Pin<Box<F>>,
    ) -> TestResult<()>
    where
        F: Future<Output = TestResult<()>> + ?Sized,
    {
        if self.resume.is_none() {
            let recovery = self.recover_queued();
            let result = match timeout(LIMIT, caller.as_mut()).await {
                Ok(result) => finish_with_cleanup(
                    Err("canonical session caller ended before its prerequisite".into()),
                    result,
                ),
                Err(elapsed) => Err(FixtureDeadline::new(
                    "canonical caller completion timed out",
                    elapsed,
                )
                .into()),
            };

            return finish_with_cleanup(result, recovery);
        }

        let setup = match drive_until(caller, async { Ok((&mut self.ready).await?) }).await {
            Ok(setup) => setup,
            Err(error) => return finish_with_cleanup(Err(error), self.recover_queued()),
        };
        let address = setup.address;
        self.setup = Some(setup);

        if self.socket.is_none() {
            self.socket = Some(timeout(LIMIT, TcpStream::connect(address)).await??);
        }

        drive_until(caller, async {
            self.state
                .wait_for(|state| state.accepted && state.read_pending && !state.destroyed)
                .await?;
            Ok(())
        })
        .await?;

        let setup = self.setup.as_ref().ok_or("actual peer setup missing")?;
        if setup.peer.is_finished() {
            return Err("actual accepted read did not leave its original task pending".into());
        }

        Ok(())
    }

    pub(in super::super::super) async fn prepare_queued<F>(
        &mut self,
        caller: &mut Pin<Box<F>>,
    ) -> TestResult<Setup>
    where
        F: Future<Output = TestResult<()>> + ?Sized,
    {
        let setup = timeout(
            LIMIT,
            poll_fn(|context| {
                if let Poll::Ready(result) = caller.as_mut().poll(context) {
                    return Poll::Ready(finish_with_cleanup(
                        Err("canonical caller ended before queuing setup".into()),
                        result,
                    ));
                }

                if self.ready.is_terminated() || self.setup.is_some() {
                    return Poll::Ready(Err("actual setup queue was already consumed".into()));
                }

                if self.ready.is_empty() {
                    return Poll::Pending;
                }

                Poll::Ready(
                    self.state
                        .borrow()
                        .published
                        .clone()
                        .ok_or_else(|| "original queued publication missing".into()),
                )
            }),
        )
        .await
        .map_err(|elapsed| FixtureDeadline::new("actual setup publication timed out", elapsed))??;

        self.socket = Some(timeout(LIMIT, TcpStream::connect(setup.address)).await??);

        timeout(
            LIMIT,
            self.state
                .wait_for(|state| state.accepted && state.read_pending && !state.destroyed),
        )
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new("actual queued peer read prerequisite timed out", elapsed)
        })??;

        if setup.peer.is_finished() || self.ready.is_empty() || self.setup.is_some() {
            return Err("original queued setup did not retain its pending accepted peer".into());
        }

        Ok(setup)
    }

    pub(in super::super::super) fn close_queued_resume(&mut self) -> TestResult<()> {
        if self.ready.is_empty() || self.setup.is_some() {
            return Err("original setup was not queued before caller completion".into());
        }

        let resume = self
            .resume
            .take()
            .ok_or("actual caller resume owner missing")?;

        drop(resume);
        Ok(())
    }

    pub(in super::super::super) async fn queued_exit(&mut self, setup: &Setup) -> TestResult<()> {
        if self.queued_backup_started {
            return Err("queued setup target followed explicit backup".into());
        }

        if self.socket.is_none() {
            return Err("actual queued accepted socket missing before target".into());
        }

        let observed = self
            .observe_queued_exit(
                setup,
                OBSERVATION_LIMIT,
                "queued peer remained live after canonical acquisition cleanup",
            )
            .await;

        if self.queued_backup_started {
            return finish_with_cleanup(
                observed,
                Err("queued setup target followed explicit backup".into()),
            );
        }

        observed
    }

    pub(in super::super::super) async fn backup_queued(&mut self) -> TestResult<()> {
        self.queued_backup_started = true;

        let setup = self.state.borrow().published.clone();
        let Some(setup) = setup else {
            return Ok(());
        };

        if !setup.peer.is_finished() {
            setup.peer.abort();
        }
        if let Some(sibling) = &setup.sibling
            && !sibling.is_finished()
        {
            sibling.abort();
        }

        self.observe_queued_exit(&setup, LIMIT, "queued backup destruction timed out")
            .await
    }

    async fn observe_queued_exit(
        &mut self,
        setup: &Setup,
        bound: Duration,
        purpose: &'static str,
    ) -> TestResult<()> {
        let destroyed = match timeout(bound, self.state.wait_for(|state| state.destroyed)).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(elapsed) => Err(FixtureDeadline::new(purpose, elapsed).into()),
        };

        let finished = timeout(LIMIT, async {
            while !setup.peer.is_finished()
                || setup
                    .sibling
                    .as_ref()
                    .is_some_and(|peer| !peer.is_finished())
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new("queued original task completion timed out", elapsed).into()
        });

        let closed = if self.socket.is_some() {
            self.closed().await
        } else {
            Ok(())
        };

        finish_with_cleanup(finish_with_cleanup(destroyed, finished), closed)
    }

    pub(in super::super::super) fn foreign_abort(&self) -> TestResult<Vec<Id>> {
        let setup = self.setup.as_ref().ok_or("actual peer setup missing")?;

        let mut ids = vec![setup.peer.id()];
        setup.peer.abort();
        if let Some(sibling) = &setup.sibling {
            ids.push(sibling.id());
            sibling.abort();
        }

        Ok(ids)
    }

    pub(in super::super::super) fn resume(&mut self) -> TestResult<()> {
        self.resume
            .take()
            .ok_or("actual caller resume owner missing")?
            .send(())
            .map_err(|_| "actual caller ended before resume".into())
    }

    pub(in super::super::super) async fn finished(&self) -> TestResult<()> {
        let setup = self.setup.as_ref().ok_or("actual peer setup missing")?;

        timeout(LIMIT, async {
            while !setup.peer.is_finished()
                || setup
                    .sibling
                    .as_ref()
                    .is_some_and(|peer| !peer.is_finished())
            {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        if !self.state.borrow().destroyed {
            return Err("finished original peer did not record its actual destruction".into());
        }

        Ok(())
    }

    pub(in super::super::super) async fn exited(
        &mut self,
        message: &'static str,
    ) -> TestResult<()> {
        timeout(
            OBSERVATION_LIMIT,
            self.state.wait_for(|state| state.destroyed),
        )
        .await
        .map_err(|elapsed| FixtureDeadline::new(message, elapsed))??;

        self.finished().await?;
        self.closed().await
    }

    async fn closed(&mut self) -> TestResult<()> {
        let socket = self
            .socket
            .as_mut()
            .ok_or("actual accepted socket missing")?;

        match timeout(LIMIT, copy(socket, &mut sink())).await? {
            Ok(_) => Ok(()),
            Err(error) if tls::is_peer_gone(&error) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    pub(in super::super::super) async fn stop(&mut self) -> TestResult<()> {
        let recovery = self.recover_queued();

        if let Some(setup) = &self.setup {
            if !setup.peer.is_finished() {
                setup.peer.abort();
            }
            if let Some(sibling) = &setup.sibling
                && !sibling.is_finished()
            {
                sibling.abort();
            }
        }

        let finished = if self.setup.is_some() {
            self.finished().await
        } else {
            Ok(())
        };

        let closed = if self.socket.is_some() {
            self.closed().await
        } else {
            Ok(())
        };

        finish_with_cleanup(recovery, finish_with_cleanup(finished, closed))
    }

    fn recover_queued(&mut self) -> TestResult<()> {
        if self.setup.is_some() {
            return Ok(());
        }

        if self.ready.is_terminated() {
            return if self.state.borrow().published.is_some() {
                Err("consumed setup did not retain its original peer".into())
            } else {
                Ok(())
            };
        }

        match self.ready.try_recv() {
            Ok(setup) => {
                self.setup = Some(setup);
                Ok(())
            }
            Err(oneshot::error::TryRecvError::Empty) => Ok(()),
            Err(error) if self.state.borrow().published.is_some() => Err(error.into()),
            Err(oneshot::error::TryRecvError::Closed) => Ok(()),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.ready.close();
        if self.setup.is_none()
            && !self.ready.is_terminated()
            && let Ok(setup) = self.ready.try_recv()
        {
            self.setup = Some(setup);
        }

        if let Some(setup) = &self.setup {
            if !setup.peer.is_finished() {
                setup.peer.abort();
            }
            if let Some(sibling) = &setup.sibling
                && !sibling.is_finished()
            {
                sibling.abort();
            }
        }
    }
}

async fn drive_until<F, T>(
    caller: &mut Pin<Box<F>>,
    condition: impl Future<Output = TestResult<T>>,
) -> TestResult<T>
where
    F: Future<Output = TestResult<()>> + ?Sized,
{
    timeout(LIMIT, async {
        tokio::select! {
            biased;
            result = caller => finish_with_cleanup(Err("canonical session caller ended before its prerequisite".into()), result),
            result = condition => result,
        }
    }).await?
}

pub(in super::super::super) fn deadline_target(
    result: TestResult<()>,
    target: TestResult<()>,
) -> TestResult<()> {
    match result {
        Err(error)
            if error.downcast_ref::<FixtureDeadline>().is_some()
                && error.to_string() == "session test exceeded its deadline"
                && error
                    .source()
                    .is_some_and(|source| source.is::<tokio::time::error::Elapsed>()) =>
        {
            match target {
                Ok(()) => Ok(()),
                Err(target) => finish_with_cleanup(Err(error), Err(target)),
            }
        }
        result => finish_with_cleanup(
            finish_with_cleanup(
                Err("original session deadline cause missing".into()),
                result,
            ),
            target,
        ),
    }
}

pub(in super::super::super) fn completed_target(
    result: TestResult<()>,
    ids: &[Id],
) -> TestResult<()> {
    let error = result
        .err()
        .ok_or("failed canonical request unexpectedly succeeded")?;

    if !original_uri(error.as_ref()) {
        return finish_with_cleanup(
            Err(error),
            Err("actual InvalidUri parser cause missing".into()),
        );
    }

    if !ids.iter().all(|id| original_cancel(error.as_ref(), *id)) {
        return finish_with_cleanup(
            Err(error),
            Err("completed original peer cancellation cause missing".into()),
        );
    }

    Ok(())
}

fn original_uri(error: &(dyn Error + 'static)) -> bool {
    if let Some(original) = error.downcast_ref::<RequestError>() {
        return original.kind() == RequestErrorKind::InvalidUri
            && original
                .source()
                .is_some_and(|source| source.is::<http::uri::InvalidUri>());
    }

    error
        .downcast_ref::<FixtureFailures>()
        .is_some_and(|failures| {
            original_uri(failures.primary.as_ref()) || original_uri(failures.cleanup.as_ref())
        })
}

fn original_cancel(error: &(dyn Error + 'static), id: Id) -> bool {
    if let Some(original) = error.downcast_ref::<tokio::task::JoinError>() {
        return original.is_cancelled() && original.id() == id;
    }

    error
        .downcast_ref::<FixtureFailures>()
        .is_some_and(|failures| {
            original_cancel(failures.primary.as_ref(), id)
                || original_cancel(failures.cleanup.as_ref(), id)
        })
}
