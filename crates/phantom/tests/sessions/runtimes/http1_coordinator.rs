use std::{
    future::pending,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    task::AbortHandle,
    time::timeout,
};

use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

use super::{TestResult, http1_peer};

const LIMIT: Duration = Duration::from_secs(5);

pub(super) struct Http1Coordinator {
    task: Option<ConnectionPeer<TestResult>>,
    stop: Option<oneshot::Sender<()>>,
    abort: AbortHandle,
}

impl Http1Coordinator {
    pub(super) fn spawn<S>(
        listener: TcpListener,
        accepted: Arc<AtomicUsize>,
        stream: impl Fn(TcpStream) -> S + Send + 'static,
        observed: impl Fn(&http1_peer::PeerTask) + Send + 'static,
    ) -> Self
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (stop, stopped) = oneshot::channel();
        let task = ConnectionPeer::spawn(async move {
            let shutdown = async {
                // Only a sent stop signal ends accepts; sender Drop is not a request.
                if stopped.await.is_err() {
                    pending::<()>().await;
                }
            };
            tokio::pin!(shutdown);
            let mut peers = Vec::new();
            let mut result: TestResult = Ok(());
            loop {
                let incoming = tokio::select! {
                    () = &mut shutdown => break,
                    incoming = listener.accept() => incoming,
                };
                let (socket, _) = match incoming {
                    Ok(socket) => socket,
                    Err(error) => {
                        result = Err(error.into());
                        break;
                    }
                };

                accepted.fetch_add(1, Ordering::SeqCst);
                let peer = http1_peer::spawn(stream(socket));
                observed(&peer);
                peers.push(peer);
            }

            let peers = peers
                .into_iter()
                .map(|peer| {
                    let requested = !peer.is_finished();
                    if requested {
                        peer.abort();
                    }

                    (peer, requested)
                })
                .collect::<Vec<_>>();

            for (mut peer, requested) in peers {
                let outcome = match timeout(LIMIT, &mut peer).await {
                    Ok(Ok(result)) => result,
                    Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                    Ok(Err(error)) => Err(error.into()),
                    Err(error) => Err(error.into()),
                };

                result = finish_with_cleanup(result, outcome);
            }
            result
        });
        let abort = task.abort_handle();
        Self {
            task: Some(task),
            stop: Some(stop),
            abort,
        }
    }

    pub(super) async fn shutdown(&mut self) -> TestResult {
        if let Some(stop) = self.stop.take() {
            // A finished receiver is harmless because its original result is joined below.
            let _ = stop.send(());
        }

        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };

        let joined = timeout(LIMIT, task).await?;
        self.task.take();
        joined?
    }
}

pub(super) async fn finish(primary: TestResult, coordinator: &mut Http1Coordinator) -> TestResult {
    let cleanup = coordinator.shutdown().await;
    finish_with_cleanup(primary, cleanup)
}

mod ownership;
