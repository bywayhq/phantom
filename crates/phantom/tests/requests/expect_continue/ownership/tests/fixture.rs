use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
    time::Duration,
};

use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    sync::{oneshot, watch},
    time::timeout,
};

use super::super::{Control, Observation, Setup, State, http3_tests::ExternalQuic};
use super::{Case, TestResult};
use crate::support::{deadline::FixtureDeadline, tls, tunnel_proxy::finish_with_cleanup};

const LIMIT: Duration = Duration::from_secs(5);
const TARGET_LIMIT: Duration = Duration::from_secs(1);

enum HeldPeer {
    Tcp(TcpStream),
    Quic(ExternalQuic),
}

pub(super) struct Fixture {
    ready: oneshot::Receiver<Setup>,
    state: watch::Receiver<State>,
    resume: Option<oneshot::Sender<()>>,
    setup: Option<Setup>,
    peer: Option<HeldPeer>,
    backup_started: bool,
}

impl Fixture {
    pub(super) fn new(target: Option<&str>) -> (Control, Self) {
        let (observed, state) = watch::channel(State::default());
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
                peer: None,
                backup_started: false,
            },
        )
    }

    pub(super) async fn start<F: Future<Output = TestResult> + ?Sized>(
        &mut self,
        case: Case,
        caller: &mut Pin<Box<F>>,
    ) -> TestResult {
        let setup = timeout(LIMIT, async {
            tokio::select! {
                biased;
                result = caller.as_mut() => finish_with_cleanup(Err("canonical caller ended before actual setup".into()), result),
                result = &mut self.ready => Ok(result?),
            }
        }).await.map_err(|elapsed| FixtureDeadline::new("actual fixture setup timed out", elapsed))??;

        self.setup = Some(setup.clone());
        self.connect(case, &setup).await?;
        self.pending_prerequisite(&setup).await
    }

    pub(super) async fn queued<F: Future<Output = TestResult> + ?Sized>(
        &mut self,
        case: Case,
        caller: &mut Pin<Box<F>>,
    ) -> TestResult<Setup> {
        let setup = timeout(
            LIMIT,
            poll_fn(|context| {
                if let Poll::Ready(result) = caller.as_mut().poll(context) {
                    return Poll::Ready(finish_with_cleanup(
                        Err("canonical caller ended before queued setup".into()),
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
                        .ok_or_else(|| "actual publication metadata missing".into()),
                )
            }),
        )
        .await
        .map_err(|elapsed| FixtureDeadline::new("actual queued setup timed out", elapsed))??;

        self.connect(case, &setup).await?;
        self.pending_prerequisite(&setup).await?;

        if self.ready.is_empty() || self.setup.is_some() {
            return Err("original setup did not remain queued".into());
        }

        Ok(setup)
    }

    async fn connect(&mut self, case: Case, setup: &Setup) -> TestResult {
        self.peer = Some(match case {
            Case::Http1 | Case::Http2 => {
                HeldPeer::Tcp(timeout(LIMIT, TcpStream::connect(setup.address)).await??)
            }
            Case::Http3 => HeldPeer::Quic(
                ExternalQuic::connect(
                    setup.address,
                    setup.root.clone().ok_or("original QUIC root missing")?,
                )
                .await?,
            ),
        });

        Ok(())
    }

    async fn pending_prerequisite(&mut self, setup: &Setup) -> TestResult {
        let tcp = matches!(self.peer, Some(HeldPeer::Tcp(_)));
        timeout(
            LIMIT,
            self.state
                .wait_for(|state| state.pending && (!tcp || state.accepted) && !state.destroyed),
        )
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new(
                "original accepted acquisition did not poll pending",
                elapsed,
            )
        })??;

        if setup.peer.is_finished() {
            return Err("original acquisition task already finished".into());
        }

        Ok(())
    }

    pub(super) fn resume(&mut self) -> TestResult {
        self.resume
            .take()
            .ok_or("actual resume owner missing")?
            .send(())
            .map_err(|_| "canonical caller ended before resume".into())
    }

    pub(super) fn close_resume(&mut self) -> TestResult {
        let resume = self.resume.take().ok_or("actual resume owner missing")?;

        drop(resume);
        Ok(())
    }

    pub(super) async fn foreign_abort(&mut self) -> TestResult<tokio::task::Id> {
        let setup = self
            .setup
            .as_ref()
            .ok_or("original acquired setup missing")?;
        let id = setup.peer.id();
        setup.peer.abort();

        self.finished(setup, LIMIT).await?;
        Ok(id)
    }

    async fn finished(&self, setup: &Setup, bound: Duration) -> TestResult {
        timeout(bound, async {
            while !setup.peer.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|elapsed| {
            FixtureDeadline::new("original peer task remained unfinished", elapsed)
        })?;

        if !self.state.borrow().destroyed {
            return Err("original task did not record destruction".into());
        }

        Ok(())
    }

    pub(super) async fn exited(&mut self, queued: Option<&Setup>) -> TestResult {
        if self.backup_started {
            return Err("ownership target followed explicit backup".into());
        }

        let setup = queued
            .cloned()
            .or_else(|| self.setup.clone())
            .ok_or("original setup missing before target")?;
        let destroyed =
            match timeout(TARGET_LIMIT, self.state.wait_for(|state| state.destroyed)).await {
                Ok(Ok(_)) => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(elapsed) => Err(FixtureDeadline::new(
                    "original peer remained live after canonical caller exit",
                    elapsed,
                )
                .into()),
            };

        let finished = self.finished(&setup, TARGET_LIMIT).await;

        let closed = self.closed(TARGET_LIMIT).await;

        finish_with_cleanup(finish_with_cleanup(destroyed, finished), closed)
    }

    async fn closed(&mut self, bound: Duration) -> TestResult {
        match self.peer.as_mut() {
            Some(HeldPeer::Tcp(stream)) => {
                match timeout(bound, stream.read(&mut [0_u8; 1])).await {
                    Ok(Ok(0)) => Ok(()),
                    Ok(Ok(_)) => Err("held pre-request socket received unexpected bytes".into()),
                    Ok(Err(error)) if tls::is_peer_gone(&error) => Ok(()),
                    Ok(Err(error)) => Err(error.into()),
                    Err(elapsed) => Err(FixtureDeadline::new(
                        "original accepted socket remained live",
                        elapsed,
                    )
                    .into()),
                }
            }
            Some(HeldPeer::Quic(peer)) => peer.closed(bound).await,
            None => Err("actual held peer missing before closure observation".into()),
        }
    }

    pub(super) async fn stop(&mut self) -> TestResult {
        self.backup_started = true;

        let published = self.state.borrow().published.clone();
        let mut recovery = Ok(());
        let setup = if let Some(setup) = &self.setup {
            Some(setup.clone())
        } else if !self.ready.is_terminated() {
            match self.ready.try_recv() {
                Ok(setup) => Some(setup),
                Err(error) if published.is_some() => {
                    recovery = Err(error.into());
                    published
                }
                Err(oneshot::error::TryRecvError::Empty | oneshot::error::TryRecvError::Closed) => {
                    None
                }
            }
        } else {
            published
        };

        let stopped = if let Some(setup) = setup {
            if !setup.peer.is_finished() {
                setup.peer.abort();
            }

            self.finished(&setup, LIMIT).await
        } else {
            Ok(())
        };

        let closed = if self.peer.is_some() {
            self.closed(LIMIT).await
        } else {
            Ok(())
        };

        let external = match self.peer.as_mut() {
            Some(HeldPeer::Quic(peer)) => peer.stop().await,
            _ => Ok(()),
        };

        finish_with_cleanup(
            recovery,
            finish_with_cleanup(finish_with_cleanup(stopped, closed), external),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Panic/early-drop backup cannot join; explicit stop observes completion.
        if let Some(setup) = &self.setup {
            if !setup.peer.is_finished() {
                setup.peer.abort();
            }
        } else if let Some(setup) = &self.state.borrow().published {
            if !setup.peer.is_finished() {
                setup.peer.abort();
            }
        }
    }
}
