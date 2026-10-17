use std::{
    future::{Future, pending},
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
};

use quinn::Endpoint;
use tokio::{
    sync::{oneshot, watch},
    task::JoinSet,
    time::timeout,
};

use super::super::{
    AlternativeBehavior, SharedObservations, h3_endpoint, run_alternative_connections,
};
use super::{CONTROL_TIMEOUT, TestIdentity, TestResult};

struct EndpointAtDrop {
    endpoint: Endpoint,
    was_open: Arc<AtomicBool>,
}

impl Drop for EndpointAtDrop {
    fn drop(&mut self) {
        let mut incoming = std::pin::pin!(self.endpoint.accept());
        self.was_open.store(
            incoming
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending(),
            Ordering::SeqCst,
        );
    }
}

#[tokio::test]
async fn alternative_worker_joins_children_before_closing_its_endpoint() -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let endpoint = h3_endpoint(&identity, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let retained_endpoint = endpoint.clone();
        let was_open = Arc::new(AtomicBool::new(false));
        let probe = EndpointAtDrop {
            endpoint: endpoint.clone(),
            was_open: Arc::clone(&was_open),
        };
        let mut connections = JoinSet::new();
        let (ready, observed) = oneshot::channel();
        connections.spawn(async move {
            let _probe = probe;
            ready.send(()).map_err(|_| "child observer cancelled")?;
            pending::<TestResult<()>>().await
        });
        observed.await?;
        let (shutdown, shutdown_rx) = watch::channel(false);
        shutdown.send(true)?;
        run_alternative_connections(
            endpoint,
            AlternativeBehavior::responses([]),
            Arc::new(SharedObservations::default()),
            shutdown_rx,
            connections,
        )
        .await?;
        assert!(
            was_open.load(Ordering::SeqCst),
            "endpoint closed before child destruction"
        );
        let mut incoming = std::pin::pin!(retained_endpoint.accept());
        assert!(matches!(
            incoming
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop())),
            Poll::Ready(None)
        ));
        Ok(())
    })
    .await?
}
