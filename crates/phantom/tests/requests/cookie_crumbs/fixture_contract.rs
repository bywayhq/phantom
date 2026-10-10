use std::{
    io,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::oneshot,
    task::{AbortHandle, JoinHandle},
    time::timeout,
};

use super::TestResult;

const DEADLINE: Duration = Duration::from_secs(10);
const QUIET: Duration = Duration::from_millis(150);

mod h2;
mod h3;

struct TaskDropped(Option<oneshot::Sender<()>>);

impl Drop for TaskDropped {
    fn drop(&mut self) {
        if let Some(notify) = self.0.take() {
            let _receiver_gone = notify.send(());
        }
    }
}

struct AbortBackup(AbortHandle);

impl Drop for AbortBackup {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct FailingRead<T> {
    inner: T,
    fail: oneshot::Receiver<()>,
}

impl<T: AsyncRead + Unpin> AsyncRead for FailingRead<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match Pin::new(&mut self.fail).poll(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "cookie recorder injected read failure913",
            ))),
            Poll::Ready(Err(error)) => Poll::Ready(Err(io::Error::other(error))),
            Poll::Pending => Pin::new(&mut self.inner).poll_read(context, buffer),
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for FailingRead<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

fn peer_with_destruction<T: Send + 'static>(
    future: impl std::future::Future<Output = TestResult<T>> + Send + 'static,
) -> (
    JoinHandle<TestResult<T>>,
    AbortBackup,
    oneshot::Receiver<()>,
) {
    let (notify, stopped) = oneshot::channel();
    let guard = TaskDropped(Some(notify));
    let peer = tokio::spawn(async move {
        let _guard = guard;
        future.await
    });
    let backup = AbortBackup(peer.abort_handle());
    (peer, backup, stopped)
}

async fn destruction_before_backup(
    stopped: &mut oneshot::Receiver<()>,
    backup: &AbortBackup,
) -> TestResult<bool> {
    let observed = match timeout(QUIET, &mut *stopped).await {
        Ok(result) => {
            result?;
            true
        }
        Err(_) => false,
    };

    if !observed {
        backup.0.abort();
        timeout(DEADLINE, stopped).await??;
    }
    Ok(observed)
}
