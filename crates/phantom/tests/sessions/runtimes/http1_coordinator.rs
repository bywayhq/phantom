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
    task::{AbortHandle, JoinHandle},
    time::timeout,
};

use super::{TestResult, http1_peer};

const LIMIT: Duration = Duration::from_secs(5);

pub(super) struct Http1Coordinator {
    task: Option<JoinHandle<TestResult>>,
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
        let task = tokio::spawn(async move {
            let shutdown = async {
                // Only a sent stop signal ends accepts; sender Drop is not a request.
                if stopped.await.is_err() {
                    pending::<()>().await;
                }
            };
            tokio::pin!(shutdown);
            let mut peers = Vec::new();
            loop {
                let incoming = tokio::select! {
                    () = &mut shutdown => break,
                    incoming = listener.accept() => incoming,
                };
                let Ok((socket, _)) = incoming else {
                    break;
                };

                accepted.fetch_add(1, Ordering::SeqCst);
                let peer = http1_peer::spawn(stream(socket));
                observed(&peer);
                peers.push(peer);
            }
            Ok(())
        });
        let abort = task.abort_handle();
        Self { task: Some(task), stop: Some(stop), abort }
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
    primary?;
    coordinator.shutdown().await
}

mod ownership;
