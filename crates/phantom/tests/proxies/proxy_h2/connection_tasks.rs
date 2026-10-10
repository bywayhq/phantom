use std::{
    future::Future,
    io,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::time::timeout;

use crate::support::{
    tls::TestResult,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

pub(crate) fn finish_peer<T: Send + 'static>(
    operation: TestResult<()>,
    peer: impl Into<ConnectionPeer<TestResult<T>>>,
) -> impl Future<Output = TestResult<T>> {
    let mut peer = peer.into();
    async move {
        let stopping = operation.is_err() && !peer.is_finished();
        if stopping {
            peer.abort();
        }

        let completed = match timeout(CLEANUP_TIMEOUT, &mut peer).await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) if stopping && error.is_cancelled() => {
                return match operation {
                    Err(primary) => Err(primary),
                    Ok(()) => Err(error.into()),
                };
            }
            Ok(Err(error)) => Err(error.into()),
            Err(error) => finish_with_cleanup(Err(error.into()), peer.stop().await),
        };

        match (operation, completed) {
            (Ok(()), result) => result,
            (Err(primary), Ok(_)) => Err(primary),
            (Err(primary), Err(cleanup)) => finish_with_cleanup(Err(primary), Err(cleanup)),
        }
    }
}

pub(crate) async fn stop_peers(peers: Vec<ConnectionPeer<TestResult<()>>>) -> TestResult<()> {
    for peer in &peers {
        peer.abort();
    }

    let mut outcome = Ok(());
    for peer in peers {
        outcome = finish_with_cleanup(outcome, peer.stop().await);
    }
    outcome
}

pub(crate) async fn stop_peer<T: Send + 'static>(
    mut peer: ConnectionPeer<TestResult<T>>,
) -> TestResult<Option<T>> {
    let stopping = !peer.is_finished();
    if stopping {
        peer.abort();
    }

    match timeout(CLEANUP_TIMEOUT, &mut peer).await {
        Ok(Ok(result)) => result.map(Some),
        Ok(Err(error)) if stopping && error.is_cancelled() => Ok(None),
        Ok(Err(error)) => Err(error.into()),
        Err(error) => finish_with_cleanup(Err(error.into()), peer.stop().await),
    }
}

pub(crate) async fn stop_optional<T: Send + 'static>(
    peer: Option<ConnectionPeer<TestResult<T>>>,
) -> TestResult<()> {
    match peer {
        Some(peer) => stop_peer(peer).await.map(|_| ()),
        None => Ok(()),
    }
}

pub(crate) type ConnectionRegistry = Arc<Mutex<Vec<ConnectionPeer<TestResult<()>>>>>;

pub(crate) struct AcceptedConnections {
    registry: ConnectionRegistry,
}

impl AcceptedConnections {
    pub(crate) fn new() -> Self {
        Self {
            registry: Arc::new(Mutex::new(Vec::new())),
        }
    }

    pub(crate) fn registry(&self) -> ConnectionRegistry {
        Arc::clone(&self.registry)
    }

    pub(crate) fn completed(&self) -> TestResult<usize> {
        Ok(self
            .registry
            .lock()
            .map_err(|_| io::Error::other("accepted connection registry poisoned"))?
            .iter()
            .filter(|peer| peer.is_finished())
            .count())
    }

    pub(crate) async fn finish(self) -> TestResult<()> {
        let (peers, observation) = match self.registry.lock() {
            Ok(mut registry) => (std::mem::take(&mut *registry), Ok(())),
            Err(poisoned) => (
                std::mem::take(&mut *poisoned.into_inner()),
                Err(io::Error::other("accepted connection registry poisoned").into()),
            ),
        };

        finish_with_cleanup(observation, stop_peers(peers).await)
    }
}

impl Drop for AcceptedConnections {
    fn drop(&mut self) {
        // Poison remains an observation error; teardown must still abort owners.
        let registry = self
            .registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for peer in registry.iter() {
            peer.abort();
        }
    }
}
