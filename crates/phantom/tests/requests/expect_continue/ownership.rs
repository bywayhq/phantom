use std::{
    future::{Future, poll_fn},
    net::SocketAddr,
};

use tokio::{
    sync::{oneshot, watch},
    task::AbortHandle,
};

use super::TestResult;

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
mod tests;
