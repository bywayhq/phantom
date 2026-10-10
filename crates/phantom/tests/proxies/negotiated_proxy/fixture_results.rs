use std::time::Duration;

use tokio::{sync::watch, time::timeout};

use super::{OriginObservations, OriginRecord, TestResult, tunnel_proxy};
use tunnel_proxy::{ConnectionPeer, EstablishedTunnel};

const PEER_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) struct TunnelPeer<T> {
    peer: Option<ConnectionPeer<TestResult<EstablishedTunnel<T>>>>,
}

impl<T: Send + 'static> TunnelPeer<T> {
    pub(super) fn new(peer: ConnectionPeer<TestResult<EstablishedTunnel<T>>>) -> Self {
        Self { peer: Some(peer) }
    }

    pub(super) async fn observe(&mut self) -> TestResult<T> {
        let peer = self.peer.take().ok_or("CONNECT peer already observed")?;
        peer.await??.cancel().await
    }

    pub(super) async fn finish(self) -> TestResult<()> {
        let Some(peer) = self.peer else {
            return Ok(());
        };
        if let Some(tunnel) = stop_peer(peer).await? {
            tunnel.cancel().await?;
        }
        Ok(())
    }
}

pub(super) struct OriginPeer {
    peer: Option<ConnectionPeer<TestResult<OriginObservations>>>,
    shutdown: watch::Sender<bool>,
}

impl OriginPeer {
    pub(super) fn new(
        peer: ConnectionPeer<TestResult<OriginObservations>>,
        shutdown: watch::Sender<bool>,
    ) -> Self {
        Self {
            peer: Some(peer),
            shutdown,
        }
    }

    pub(super) async fn observe(&mut self) -> TestResult<Vec<OriginRecord>> {
        let peer = self.peer.take().ok_or("origin peer already observed")?;
        peer.await??.finish().await
    }

    pub(super) async fn finish(self) -> TestResult<()> {
        let Some(mut peer) = self.peer else {
            return Ok(());
        };
        // A completed parent needs no shutdown notification.
        let _ = self.shutdown.send(true);
        match timeout(PEER_TIMEOUT, &mut peer).await {
            Ok(joined) => joined??.finish().await.map(|_| ()),
            Err(elapsed) => {
                let cleanup = match stop_peer(peer).await {
                    Ok(Some(observed)) => observed.finish().await.map(|_| ()),
                    Ok(None) => Ok(()),
                    Err(error) => Err(error),
                };
                tunnel_proxy::finish_with_cleanup(Err(elapsed.into()), cleanup)
            }
        }
    }
}

/// Abort pending work, but observe a result that already completed.
pub(super) async fn stop_peer<T: Send + 'static>(
    mut peer: ConnectionPeer<TestResult<T>>,
) -> TestResult<Option<T>> {
    peer.abort();
    match timeout(PEER_TIMEOUT, &mut peer).await? {
        Ok(result) => result.map(Some),
        Err(error) if error.is_cancelled() => Ok(None),
        Err(error) => Err(error.into()),
    }
}

pub(super) async fn finish_raw_origin<T: Send + 'static>(
    peer: Option<ConnectionPeer<TestResult<T>>>,
) -> TestResult<()> {
    if let Some(peer) = peer {
        stop_peer(peer).await?;
    }
    Ok(())
}
