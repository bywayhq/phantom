//! Ownership and completed outcomes for an ordinary CONNECT serving task.

use std::future::Future;

use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

use super::{
    TaskProbe, TaskRole, TestResult,
    connection_tasks::{AcceptedConnections, ConnectionRegistry, finish_peer, stop_peer},
};

pub(super) struct ConnectPeer<T> {
    peer: ConnectionPeer<TestResult<T>>,
    children: AcceptedConnections,
}

impl<T: Send + 'static> ConnectPeer<T> {
    pub(super) fn spawn<F>(
        probe: Option<TaskProbe>,
        start: impl FnOnce(ConnectionRegistry) -> F,
    ) -> Self
    where
        F: Future<Output = TestResult<T>> + Send + 'static,
    {
        let children = AcceptedConnections::new();
        let future = start(children.registry());
        let peer = match probe {
            Some(probe) => probe.spawn(TaskRole::ProxyConnection, future),
            None => ConnectionPeer::spawn(future),
        };

        Self { peer, children }
    }

    pub(super) fn is_finished(&self) -> bool {
        self.peer.is_finished()
    }

    pub(super) async fn finish(self) -> TestResult<T> {
        let outcome = finish_peer(Ok(()), self.peer).await;

        // Stop registration before collecting the separately owned child outcomes.
        let cleanup = self.children.finish().await;
        finish_with_cleanup(outcome, cleanup)
    }

    pub(super) async fn stop(self) -> TestResult<()> {
        let outcome = stop_peer(self.peer).await.map(|_| ());

        let cleanup = self.children.finish().await;
        finish_with_cleanup(outcome, cleanup)
    }
}

pub(super) async fn stop_connect_peer<T: Send + 'static>(
    peer: Option<ConnectPeer<T>>,
) -> TestResult<()> {
    match peer {
        Some(peer) => peer.stop().await,
        None => Ok(()),
    }
}
