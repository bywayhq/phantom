use std::{error::Error, fmt};

use phantom::Client;
use tokio::time::{error::Elapsed, timeout};

use crate::support::tunnel_proxy::{
    ConnectionPeer, connection_peer::FixtureFailures, finish_with_cleanup,
};

use super::{TEST_TIMEOUT, TestResult};

pub(super) async fn finish_peer<T: Send + 'static>(
    operation: TestResult<()>,
    peer: ConnectionPeer<TestResult<T>>,
) -> TestResult<T> {
    if let Err(primary) = operation {
        let cleanup = peer.stop().await;
        return finish_with_cleanup(Err(primary), cleanup);
    }

    observe_peer(peer).await
}

pub(super) async fn finish_peers<P: Send + 'static, O: Send + 'static>(
    operation: TestResult<()>,
    proxy: ConnectionPeer<TestResult<P>>,
    origin: ConnectionPeer<TestResult<O>>,
) -> TestResult<(P, O)> {
    if let Err(primary) = operation {
        let (proxy, origin) = tokio::join!(proxy.stop(), origin.stop());
        let cleanup = finish_with_cleanup(proxy, origin);
        return finish_with_cleanup(Err(primary), cleanup);
    }

    let (proxy, origin) = tokio::join!(observe_peer(proxy), observe_peer(origin));
    match (proxy, origin) {
        (Ok(proxy), Ok(origin)) => Ok((proxy, origin)),
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(Box::new(FixtureFailures { primary, cleanup })),
    }
}

pub(super) async fn finish_h2_peers<P: Send + 'static, O: Send + 'static>(
    operation: TestResult<()>,
    client: Client,
    proxy: ConnectionPeer<TestResult<P>>,
    origin: ConnectionPeer<TestResult<O>>,
) -> TestResult<(P, O)> {
    if operation.is_ok() {
        drop(client);
        finish_peers(operation, proxy, origin).await
    } else {
        let result = finish_peers(operation, proxy, origin).await;
        drop(client);
        result
    }
}

async fn observe_peer<T: Send + 'static>(mut peer: ConnectionPeer<TestResult<T>>) -> TestResult<T> {
    match timeout(TEST_TIMEOUT, &mut peer).await {
        Ok(joined) => joined?,
        Err(source) => {
            let primary = ConnectDeadline { source };
            let cleanup = peer.stop().await;
            finish_with_cleanup(Err(primary.into()), cleanup)
        }
    }
}

#[derive(Debug)]
pub(super) struct ConnectDeadline {
    pub(super) source: Elapsed,
}

impl fmt::Display for ConnectDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("proxy integration test exceeded its deadline")
    }
}

impl Error for ConnectDeadline {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}
