use std::{
    future::{Future, poll_fn},
    net::SocketAddr,
    pin::Pin,
    task::Poll,
    time::Duration,
};

use tokio::{
    sync::{oneshot, watch},
    task::{AbortHandle, coop},
    time::timeout,
};

use super::TestResult;
use crate::support::{
    deadline::FixtureDeadline,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) async fn join<T: Send + 'static>(
    server: &mut Option<ConnectionPeer<TestResult<T>>>,
) -> TestResult<T> {
    let joined = server
        .as_mut()
        .ok_or("original expect-continue peer missing before join")?
        .await;

    drop(server.take());
    joined?
}

pub(super) async fn finish<T: Send + 'static>(
    caller: TestResult,
    server: Option<ConnectionPeer<TestResult<T>>>,
) -> TestResult {
    let Some(mut server) = server else {
        return caller;
    };

    // A completed JoinHandle can otherwise yield Pending solely for budgeting.
    let ready = coop::unconstrained(poll_fn(|context| {
        match Pin::new(&mut server).poll(context) {
            Poll::Ready(result) => Poll::Ready(Some(result)),
            Poll::Pending => Poll::Ready(None),
        }
    }))
    .await;

    let requested = ready.is_none() && !server.is_finished();
    if requested {
        server.abort();
    }

    let joined = match ready {
        Some(result) => Ok(result),
        None => timeout(CLEANUP_TIMEOUT, coop::unconstrained(&mut server))
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new("expect-continue peer cleanup exceeded deadline", elapsed)
            }),
    };

    let cleanup = match joined {
        Ok(Ok(result)) => result.map(|_| ()),
        Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Err(error) => Err(error.into()),
    };

    finish_with_cleanup(caller, cleanup)
}

pub(super) async fn finish_quic<T: Send + 'static>(
    caller: TestResult,
    server: Option<ConnectionPeer<TestResult<T>>>,
    lifetime: &mut Option<QuicLifetime>,
) -> TestResult {
    if let Some(lifetime) = lifetime.as_mut() {
        lifetime.shutdown();
    }

    let result = finish(caller, server).await;

    let idle = match lifetime.as_ref() {
        Some(lifetime) => timeout(CLEANUP_TIMEOUT, lifetime.endpoint.wait_idle())
            .await
            .map_err(|elapsed| {
                FixtureDeadline::new(
                    "expect-continue QUIC endpoint cleanup exceeded deadline",
                    elapsed,
                )
                .into()
            }),
        None => Ok(()),
    };

    finish_with_cleanup(result, idle)
}

pub(super) enum QuicRelease {
    Released,
    Shutdown,
}

pub(super) struct QuicLifetime {
    endpoint: quinn::Endpoint,
    release: Option<oneshot::Sender<QuicRelease>>,
}

impl QuicLifetime {
    pub(super) fn new(endpoint: quinn::Endpoint) -> (Self, oneshot::Receiver<QuicRelease>) {
        let (release, received) = oneshot::channel();

        (
            Self {
                endpoint,
                release: Some(release),
            },
            received,
        )
    }

    pub(super) fn release(&mut self) -> TestResult {
        self.release
            .take()
            .ok_or("original HTTP/3 release sender missing")?
            .send(QuicRelease::Released)
            .map_err(|_| "original HTTP/3 peer ended before client release".into())
    }

    pub(super) fn shutdown(&mut self) {
        self.endpoint.close(
            quinn::VarInt::from_u32(0x100),
            b"Connection was closed by the server",
        );

        if let Some(release) = self.release.take() {
            // A missing receiver means the original peer has already ended;
            // its task result, rather than this notification, carries the cause.
            let _ = release.send(QuicRelease::Shutdown);
        }
    }
}

impl Drop for QuicLifetime {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[derive(Clone, Debug)]
pub(super) struct Setup {
    pub(super) address: SocketAddr,
    pub(super) peer: AbortHandle,
    pub(super) root: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct State {
    pub(super) accepted: bool,
    pub(super) pending: bool,
    pub(super) destroyed: bool,
    pub(super) published: Option<Setup>,
}

#[derive(Clone, Debug)]
pub(super) struct Observation(pub(super) watch::Sender<State>);

impl Observation {
    pub(super) fn accepted(&self) {
        self.0.send_modify(|state| state.accepted = true);
    }
}

pub(super) struct PeerLife(pub(super) Option<Observation>);

impl Drop for PeerLife {
    fn drop(&mut self) {
        if let Some(observed) = &self.0 {
            observed.0.send_modify(|state| state.destroyed = true);
        }
    }
}

pub(super) struct Control {
    pub(super) observed: Observation,
    pub(super) setup: oneshot::Sender<Setup>,
    pub(super) resume: oneshot::Receiver<()>,
    pub(super) target: Option<String>,
}

impl Control {
    pub(super) async fn coordinate(self, setup: Setup) -> TestResult<Option<String>> {
        self.observed
            .0
            .send_modify(|state| state.published = Some(setup.clone()));

        self.setup
            .send(setup)
            .map_err(|_| "expect-continue setup observer ended")?;

        self.resume.await?;

        Ok(self.target)
    }
}

pub(super) async fn observed<F: Future>(future: F, observation: Option<&Observation>) -> F::Output {
    tokio::pin!(future);

    poll_fn(|context| {
        let result = future.as_mut().poll(context);
        if result.is_pending()
            && let Some(observed) = observation
        {
            let pending = observed.0.borrow().pending;
            if !pending {
                observed.0.send_modify(|state| state.pending = true);
            }
        }

        result
    })
    .await
}

mod http3_tests;
mod reader_tests;
mod tests;
