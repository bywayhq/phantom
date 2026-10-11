use std::{
    error::Error,
    fmt, io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    sync::{oneshot, watch},
    task::{AbortHandle, JoinError, JoinHandle},
    time::timeout,
};

use super::{Event, Server, TestResult};
use crate::support::tunnel_proxy::finish_with_cleanup;

const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);
const BACKUP_LIMIT: Duration = Duration::from_secs(5);
const REQUEST: &[u8] = b"GET /prime HTTP/1.1\r\nHost: owner.test\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone";

enum Fault {
    Read(io::Error),
    Write(io::Error),
}

#[derive(Clone, Copy)]
enum FaultBoundary {
    Read,
    Write,
}

pub(super) enum ResultOwner {
    Backup(oneshot::Sender<JoinHandle<TestResult>>),
    Coordinator(oneshot::Sender<AbortHandle>),
}

pub(super) struct PeerControl {
    result_owner: ResultOwner,
    pending: watch::Sender<bool>,
    destroyed: watch::Sender<bool>,
    reached: watch::Sender<bool>,
    armed: Arc<AtomicBool>,
    fault: Option<Fault>,
}

impl PeerControl {
    pub(super) fn attach(
        self,
        stream: TcpStream,
    ) -> (ObservedStream, ResultOwner) {
        (
            ObservedStream {
                stream,
                pending: self.pending,
                destroyed: self.destroyed,
                reached: self.reached,
                armed: self.armed,
                fault: self.fault,
                response_written: false,
            },
            self.result_owner,
        )
    }
}

pub(super) struct ObservedStream {
    stream: TcpStream,
    pending: watch::Sender<bool>,
    destroyed: watch::Sender<bool>,
    reached: watch::Sender<bool>,
    armed: Arc<AtomicBool>,
    fault: Option<Fault>,
    response_written: bool,
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
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.stream).poll_read(context, buffer);
        if result.is_pending() && this.response_written {
            this.pending.send_replace(true);
        }
        if matches!(&result, Poll::Ready(Ok(())))
            && buffer.filled().len() > before
            && this.armed.load(Ordering::Acquire)
            && matches!(&this.fault, Some(Fault::Read(_)))
            && let Some(Fault::Read(error)) = this.fault.take()
        {
            this.reached.send_replace(true);
            return Poll::Ready(Err(error));
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
        if matches!(&result, Poll::Ready(Ok(length)) if *length != 0) {
            this.response_written = true;
            if this.armed.load(Ordering::Acquire)
                && matches!(&result, Poll::Ready(Ok(length)) if *length == bytes.len())
                && matches!(&this.fault, Some(Fault::Write(_)))
                && let Some(Fault::Write(error)) = this.fault.take()
            {
                this.reached.send_replace(true);
                return Poll::Ready(Err(error));
            }
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
    returned: Option<oneshot::Receiver<JoinHandle<TestResult>>>,
    peer: Option<JoinHandle<TestResult>>,
    completion_returned: Option<oneshot::Receiver<AbortHandle>>,
    completion: Option<AbortHandle>,
    server: Option<Server>,
    client: Option<TcpStream>,
    pending: watch::Receiver<bool>,
    destroyed: watch::Receiver<bool>,
    reached: watch::Receiver<bool>,
    armed: Arc<AtomicBool>,
}

impl Backup {
    fn prepare(fault: Option<Fault>) -> (Self, PeerControl) {
        let (returned, receiver) = oneshot::channel();
        let (pending, pending_receiver) = watch::channel(false);
        let (destroyed, destroyed_receiver) = watch::channel(false);
        let (reached, reached_receiver) = watch::channel(false);
        let armed = Arc::new(AtomicBool::new(false));
        (
            Self {
                returned: Some(receiver),
                peer: None,
                completion_returned: None,
                completion: None,
                server: None,
                client: None,
                pending: pending_receiver,
                destroyed: destroyed_receiver,
                reached: reached_receiver,
                armed: Arc::clone(&armed),
            },
            PeerControl {
                result_owner: ResultOwner::Backup(returned),
                pending,
                destroyed,
                reached,
                armed,
                fault,
            },
        )
    }

    fn prepare_owned(fault: Option<Fault>) -> (Self, PeerControl) {
        let (mut backup, mut control) = Self::prepare(fault);
        let (completion, receiver) = oneshot::channel();
        backup.returned.take();
        backup.completion_returned = Some(receiver);
        control.result_owner = ResultOwner::Coordinator(completion);
        (backup, control)
    }

    async fn prime(&mut self, control: PeerControl) -> TestResult {
        self.server = Some(Server::start_observed(Some(control)).await?);
        let server = self.server.as_mut().ok_or("server owner missing")?;
        self.client = Some(timeout(OBSERVATION_LIMIT, TcpStream::connect(server.address)).await??);
        let client = self.client.as_mut().ok_or("client owner missing")?;

        timeout(OBSERVATION_LIMIT, client.write_all(REQUEST)).await??;
        let mut response = vec![0; RESPONSE.len()];
        timeout(OBSERVATION_LIMIT, client.read_exact(&mut response)).await??;
        if response != RESPONSE {
            return Err("the actual healthy prime response changed".into());
        }

        if server.next().await? != Event::Accepted(0)
            || server.next_request().await? != (0, "prime".to_owned())
        {
            return Err("the actual healthy request was not accepted and recorded".into());
        }

        if let Some(receiver) = self.returned.as_mut() {
            self.peer = Some(timeout(OBSERVATION_LIMIT, receiver).await??);
            self.returned.take();
        } else {
            let receiver = self
                .completion_returned
                .as_mut()
                .ok_or("completion receiver missing")?;
            self.completion = Some(timeout(OBSERVATION_LIMIT, receiver).await??);
            self.completion_returned.take();
        }
        timeout(OBSERVATION_LIMIT, self.pending.wait_for(|pending| *pending)).await??;
        let finished = match (&self.peer, &self.completion) {
            (Some(peer), _) => peer.is_finished(),
            (_, Some(completion)) => completion.is_finished(),
            _ => return Err("actual peer witness missing".into()),
        };
        if finished {
            return Err("accepted peer completed before its held-read witness".into());
        }

        Ok(())
    }

    async fn owned_peer_completed(&self) -> TestResult {
        let completion = self.completion.as_ref().ok_or("completion witness missing")?;
        timeout(OBSERVATION_LIMIT, async {
            while !completion.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    async fn closed(&mut self) -> TestResult {
        timeout(
            OBSERVATION_LIMIT,
            self.destroyed.wait_for(|destroyed| *destroyed),
        )
        .await??;
        let client = self.client.as_mut().ok_or("client owner missing")?;
        match timeout(OBSERVATION_LIMIT, client.read(&mut [0_u8; 1])).await? {
            Ok(0) => Ok(()),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                ) =>
            {
                Ok(())
            }
            Err(error) => Err(error.into()),
            Ok(_) => Err("accepted peer sent unexpected bytes instead of closing".into()),
        }
    }

    async fn completed(&mut self) -> TestResult<Result<TestResult, JoinError>> {
        let peer = self.peer.as_mut().ok_or("peer owner missing")?;
        let result = timeout(OBSERVATION_LIMIT, peer).await?;
        self.peer.take();
        Ok(result)
    }

    async fn stop(&mut self) -> TestResult {
        let coordinator = match self.server.take() {
            Some(server) => server.shutdown().await,
            None => Ok(()),
        };
        let publication = if self.peer.is_none() {
            if let Some(receiver) = self.returned.as_mut() {
                match timeout(BACKUP_LIMIT, receiver).await {
                    Ok(Ok(peer)) => {
                        self.peer = Some(peer);
                        Ok(())
                    }
                    Ok(Err(_)) if self.client.is_none() => Ok(()),
                    Ok(Err(error)) => Err(error.into()),
                    Err(error) => Err(error.into()),
                }
            } else {
                Ok(())
            }
        } else {
            Ok(())
        };

        let outcome = if let Some(peer) = self.peer.as_mut() {
            let requested = !peer.is_finished();
            if requested {
                peer.abort();
            }
            match timeout(BACKUP_LIMIT, peer).await {
                Ok(Ok(result)) => result,
                // The Server owner may already have requested this cancellation.
                Ok(Err(error)) if error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            }
        } else {
            Ok(())
        };
        self.client.take();
        finish_with_cleanup(coordinator, finish_with_cleanup(publication, outcome))
    }
}

impl Drop for Backup {
    fn drop(&mut self) {
        if let Some(peer) = &self.peer {
            peer.abort();
        }
        if let Some(receiver) = self.returned.as_mut()
            && let Ok(peer) = receiver.try_recv()
        {
            peer.abort();
        }
    }
}

#[derive(Debug)]
struct LocalServingFailure(Arc<()>);

impl fmt::Display for LocalServingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled local HTTP/1 serving failure")
    }
}

impl Error for LocalServingFailure {}

#[tokio::test]
async fn healthy_accepted_peer_completes_after_client_eof() -> TestResult {
    let (mut backup, control) = Backup::prepare(None);
    let primary = async {
        backup.prime(control).await?;
        backup
            .client
            .as_mut()
            .ok_or("client missing")?
            .shutdown()
            .await?;
        backup.closed().await?;
        backup.completed().await???;
        Ok(())
    }
    .await;

    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn explicit_abort_destroys_the_actual_pending_accepted_peer() -> TestResult {
    let (mut backup, control) = Backup::prepare(None);
    let primary = async {
        backup.prime(control).await?;
        backup.peer.as_ref().ok_or("peer missing")?.abort();
        let error = backup
            .completed()
            .await?
            .err()
            .ok_or("explicit abort did not cancel the actual peer")?;
        if !error.is_cancelled() {
            return Err(error.into());
        }

        backup.closed().await
    }
    .await;

    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn dropping_server_destroys_its_actual_pending_accepted_peer() -> TestResult {
    let (mut backup, control) = Backup::prepare(None);
    let primary = async {
        backup.prime(control).await?;
        backup.server.take();
        backup.closed().await
    }
    .await;

    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn completed_http1_peer_retains_its_original_local_read_failure() -> TestResult {
    fault_result(FaultBoundary::Read).await
}

#[tokio::test]
async fn completed_http1_peer_retains_its_original_local_write_failure() -> TestResult {
    fault_result(FaultBoundary::Write).await
}

#[tokio::test]
async fn ordinary_owned_peer_completes_and_shuts_down_after_healthy_eof() -> TestResult {
    let (mut backup, control) = Backup::prepare_owned(None);
    let primary = async {
        backup.prime(control).await?;
        backup
            .client
            .as_mut()
            .ok_or("client missing")?
            .shutdown()
            .await?;
        backup.closed().await?;
        backup.owned_peer_completed().await?;
        backup
            .server
            .take()
            .ok_or("server owner missing")?
            .shutdown()
            .await
    }
    .await;

    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn ordinary_shutdown_retains_its_completed_workers_original_local_error() -> TestResult {
    let identity = Arc::new(());
    let error = io::Error::new(
        io::ErrorKind::PermissionDenied,
        LocalServingFailure(Arc::clone(&identity)),
    );
    let (mut backup, control) = Backup::prepare_owned(Some(Fault::Read(error)));
    let primary = async {
        backup.prime(control).await?;
        backup.armed.store(true, Ordering::Release);
        timeout(
            OBSERVATION_LIMIT,
            backup
                .client
                .as_mut()
                .ok_or("client missing")?
                .write_all(b"!"),
        )
        .await??;
        timeout(OBSERVATION_LIMIT, backup.reached.wait_for(|reached| *reached)).await??;
        backup.closed().await?;
        backup.owned_peer_completed().await?;

        let outcome = backup
            .server
            .take()
            .ok_or("server owner missing")?
            .shutdown()
            .await;
        let observed = match outcome {
            Err(error) => error,
            Ok(()) => return Err("ordinary shutdown discarded its completed worker error".into()),
        };
        let Some(io) = observed.downcast_ref::<io::Error>() else {
            return Err(observed);
        };
        if io.kind() != io::ErrorKind::PermissionDenied {
            return Err(observed);
        }

        let Some(cause) = io
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<LocalServingFailure>())
        else {
            return Err(observed);
        };
        if !Arc::ptr_eq(&cause.0, &identity) {
            return finish_with_cleanup(
                Err(observed),
                Err("ordinary shutdown replaced the original local error identity".into()),
            );
        }
        Ok(())
    }
    .await;

    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

async fn fault_result(boundary: FaultBoundary) -> TestResult {
    let identity = Arc::new(());
    let error = io::Error::new(
        io::ErrorKind::PermissionDenied,
        LocalServingFailure(Arc::clone(&identity)),
    );
    let write = matches!(boundary, FaultBoundary::Write);
    let fault = match boundary {
        FaultBoundary::Write => Fault::Write(error),
        FaultBoundary::Read => Fault::Read(error),
    };
    let (mut backup, control) = Backup::prepare(Some(fault));
    let primary = async {
        backup.prime(control).await?;
        backup.armed.store(true, Ordering::Release);
        let bytes = if write { REQUEST } else { b"!" };
        timeout(
            OBSERVATION_LIMIT,
            backup
                .client
                .as_mut()
                .ok_or("client missing")?
                .write_all(bytes),
        )
        .await??;
        timeout(
            OBSERVATION_LIMIT,
            backup.reached.wait_for(|reached| *reached),
        )
        .await??;
        let outcome = backup.completed().await?;
        let outcome = match outcome {
            Ok(result) => result,
            Err(error) => Err(error.into()),
        };
        let prerequisite = async {
            if write {
                let mut response = vec![0; RESPONSE.len()];
                timeout(
                    OBSERVATION_LIMIT,
                    backup
                        .client
                        .as_mut()
                        .ok_or("client missing")?
                        .read_exact(&mut response),
                )
                .await??;
                if response != RESPONSE {
                    return Err("actual pre-fault response write changed".into());
                }
            }

            backup.closed().await
        }
        .await;
        if prerequisite.is_err() {
            return finish_with_cleanup(outcome, prerequisite);
        }

        let observed = match outcome {
            Err(error) => error,
            Ok(()) => {
                return Err("completed HTTP/1 worker discarded its original local error".into());
            }
        };
        let Some(io) = observed.downcast_ref::<io::Error>() else {
            return Err(observed);
        };
        if io.kind() != io::ErrorKind::PermissionDenied {
            return Err(observed);
        }

        let Some(cause) = io
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<LocalServingFailure>())
        else {
            return Err(observed);
        };
        if !Arc::ptr_eq(&cause.0, &identity) {
            return finish_with_cleanup(
                Err(observed),
                Err("original local serving identity replaced".into()),
            );
        }

        Ok(())
    }
    .await;

    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}
