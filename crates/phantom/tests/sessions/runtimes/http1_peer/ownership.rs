use std::{
    error::Error,
    fmt, io,
    net::Ipv4Addr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::AbortHandle,
    time::timeout,
};

use crate::support::{tls::is_peer_gone, tunnel_proxy::finish_with_cleanup};

use super::{PeerTask, TestResult, spawn};

const LIMIT: Duration = Duration::from_secs(5);
const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);
const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: runtime.test\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone";

#[derive(Clone, Copy)]
enum FaultBoundary {
    Read,
    Write,
}

#[derive(Debug)]
struct FailureIdentity;

#[derive(Debug)]
struct ServingFailure(Arc<FailureIdentity>);

impl fmt::Display for ServingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected runtime HTTP1 serving failure")
    }
}

impl Error for ServingFailure {}

struct Fault {
    boundary: FaultBoundary,
    error: io::Error,
}

struct ObservedStream {
    stream: TcpStream,
    pending: watch::Sender<bool>,
    destroyed: watch::Sender<bool>,
    reached: watch::Sender<bool>,
    fault: Option<Fault>,
}

impl Drop for ObservedStream {
    fn drop(&mut self) {
        self.destroyed.send_replace(true);
    }
}

impl AsyncRead for ObservedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let mut byte = [0_u8; 1];
        let mut observed = ReadBuf::new(&mut byte);
        let result = Pin::new(&mut this.stream).poll_read(context, &mut observed);
        if result.is_pending() {
            this.pending.send_replace(true);
        }

        if matches!(&result, Poll::Ready(Ok(()))) {
            if !observed.filled().is_empty()
                && matches!(&this.fault, Some(Fault { boundary: FaultBoundary::Read, .. }))
                && let Some(fault) = this.fault.take()
            {
                this.reached.send_replace(true);
                return Poll::Ready(Err(fault.error));
            }

            buffer.put_slice(observed.filled());
        }
        result
    }
}

impl AsyncWrite for ObservedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_write(context, bytes);
        if matches!(&result, Poll::Ready(Ok(length)) if *length != 0)
            && matches!(&this.fault, Some(Fault { boundary: FaultBoundary::Write, .. }))
            && let Some(fault) = this.fault.take()
        {
            this.reached.send_replace(true);
            return Poll::Ready(Err(fault.error));
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(context)
    }
}

struct Backup {
    task: Option<PeerTask>,
    witness: AbortHandle,
    client: TcpStream,
    pending: watch::Receiver<bool>,
    destroyed: watch::Receiver<bool>,
    reached: watch::Receiver<bool>,
}

impl Backup {
    async fn bind(boundary: Option<FaultBoundary>) -> TestResult<(Self, Arc<FailureIdentity>)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (client, accepted) = timeout(LIMIT, async {
            tokio::try_join!(TcpStream::connect(address), listener.accept())
        }).await??;
        let (stream, _) = accepted;
        let (pending, pending_receiver) = watch::channel(false);
        let (destroyed, destroyed_receiver) = watch::channel(false);
        let (reached, reached_receiver) = watch::channel(false);
        let identity = Arc::new(FailureIdentity);
        let fault = boundary.map(|boundary| Fault {
            boundary,
            error: io::Error::new(
                io::ErrorKind::PermissionDenied,
                ServingFailure(Arc::clone(&identity)),
            ),
        });

        let task = spawn(ObservedStream { stream, pending, destroyed, reached, fault });
        let witness = task.abort_handle();
        Ok((Self {
            task: Some(task), witness, client,
            pending: pending_receiver,
            destroyed: destroyed_receiver,
            reached: reached_receiver,
        }, identity))
    }

    async fn pending(&mut self) -> TestResult {
        timeout(LIMIT, self.pending.wait_for(|pending| *pending)).await??;
        Ok(())
    }

    async fn destroyed(&mut self) -> TestResult {
        timeout(OBSERVATION_LIMIT, self.destroyed.wait_for(|destroyed| *destroyed)).await??;
        timeout(LIMIT, async {
            while !self.witness.is_finished() {
                tokio::task::yield_now().await;
            }
        }).await?;
        Ok(())
    }

    async fn joined(&mut self) -> TestResult {
        let task = self.task.as_mut().ok_or("original runtime peer result missing")?;
        let joined = timeout(LIMIT, task).await?;
        self.task.take();
        joined?
    }

    async fn closed(&mut self) -> TestResult<Vec<u8>> {
        let mut received = Vec::new();
        match timeout(LIMIT, self.client.read_to_end(&mut received)).await? {
            Ok(_) => {}
            Err(error) if is_peer_gone(&error) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(received)
    }

    async fn stop(&mut self) -> TestResult {
        let result = if let Some(task) = self.task.as_mut() {
            let cancelled = !task.is_finished();
            if cancelled {
                task.abort();
            }
            match timeout(LIMIT, task).await {
                Ok(joined) => {
                    self.task.take();
                    match joined {
                        Ok(result) => result,
                        Err(error) if cancelled && error.is_cancelled() => Ok(()),
                        Err(error) => Err(error.into()),
                    }
                }
                Err(error) => Err(error.into()),
            }
        } else {
            // The drop control deliberately gives up the sole result handle.
            self.witness.abort();
            timeout(LIMIT, async {
                while !self.witness.is_finished() {
                    tokio::task::yield_now().await;
                }
            }).await.map_err(Into::into)
        };
        let closed = self.closed().await.map(|_| ());
        finish_with_cleanup(result, closed)
    }
}

impl Drop for Backup {
    fn drop(&mut self) {
        self.witness.abort();
    }
}

fn retains_fault(result: TestResult, identity: &Arc<FailureIdentity>) -> TestResult {
    let Err(error) = result else {
        return Err("original runtime peer discarded its completed serving failure".into());
    };

    let Some(original) = error.downcast_ref::<io::Error>() else {
        return Err(error);
    };

    if original.kind() != io::ErrorKind::PermissionDenied
        || !original.get_ref().and_then(|cause| cause.downcast_ref::<ServingFailure>())
            .is_some_and(|cause| Arc::ptr_eq(&cause.0, identity))
    {
        return Err(error);
    }

    Ok(())
}

#[tokio::test]
async fn healthy_runtime_peer_returns_its_literal_response_and_completes_on_actual_eof() -> TestResult {
    let (mut backup, _) = Backup::bind(None).await?;
    let primary = async {
        backup.pending().await?;
        timeout(LIMIT, backup.client.write_all(REQUEST)).await??;
        timeout(LIMIT, backup.client.shutdown()).await??;
        let received = backup.closed().await?;
        backup.destroyed().await?;
        backup.joined().await?;

        assert_eq!(received, RESPONSE);
        Ok(())
    }.await;
    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn explicit_abort_joins_and_destroys_the_original_runtime_peers_pending_socket() -> TestResult {
    let (mut backup, _) = Backup::bind(None).await?;
    let primary = async {
        backup.pending().await?;
        backup.task.as_ref().ok_or("original runtime peer missing")?.abort();
        let task = backup.task.as_mut().ok_or("original runtime peer missing")?;
        let joined = timeout(LIMIT, task).await?;
        backup.task.take();
        let cancellation = match joined {
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
            Ok(result) => finish_with_cleanup(result, Err("runtime peer completed before requested abort".into())),
        };
        backup.destroyed().await?;
        let received = backup.closed().await?;

        cancellation?;
        assert!(received.is_empty());
        Ok(())
    }.await;
    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn dropping_the_original_runtime_peer_handle_destroys_its_pending_socket_with_runtime_live() -> TestResult {
    let (mut backup, _) = Backup::bind(None).await?;
    let primary = async {
        backup.pending().await?;
        let task = backup.task.take().ok_or("original runtime peer missing")?;
        drop(task);
        backup.destroyed().await?;
        let received = backup.closed().await?;

        assert!(received.is_empty());
        Ok(())
    }.await;
    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

async fn completed_fault(boundary: FaultBoundary) -> TestResult {
    let (mut backup, identity) = Backup::bind(Some(boundary)).await?;
    let primary = async {
        backup.pending().await?;
        timeout(LIMIT, backup.client.write_all(REQUEST)).await??;
        timeout(LIMIT, backup.reached.wait_for(|reached| *reached)).await??;
        backup.destroyed().await?;
        let received = backup.closed().await?;
        let original = backup.joined().await;

        match boundary {
            FaultBoundary::Read => assert!(received.is_empty()),
            FaultBoundary::Write => {
                assert!(!received.is_empty());
                assert!(RESPONSE.starts_with(&received));
            }
        }
        retains_fault(original, &identity)
    }.await;
    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn runtime_peer_retains_its_original_completed_read_failure_after_actual_io() -> TestResult {
    completed_fault(FaultBoundary::Read).await
}

#[tokio::test]
async fn runtime_peer_retains_its_original_completed_write_failure_after_actual_io() -> TestResult {
    completed_fault(FaultBoundary::Write).await
}
