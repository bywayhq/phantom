use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use tokio::task::{AbortHandle, JoinError, JoinHandle};

// HTTP/1 peers and transactions keep their original typed task results.
pub(super) struct PeerTask<T> {
    task: JoinHandle<T>,
}

impl<T: Send + 'static> PeerTask<T> {
    pub(super) fn spawn(future: impl Future<Output = T> + Send + 'static) -> Self {
        Self {
            task: tokio::spawn(future),
        }
    }
}

impl<T> PeerTask<T> {
    pub(super) fn abort_handle(&self) -> AbortHandle {
        self.task.abort_handle()
    }
}

impl<T> Future for PeerTask<T> {
    type Output = Result<T, JoinError>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut self.task).poll(context)
    }
}
