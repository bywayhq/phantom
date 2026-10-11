use std::{
    error::Error,
    fmt, io,
    net::{Ipv4Addr, SocketAddr},
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
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
    task::JoinHandle,
    time::timeout,
};

use super::{
    Client, H1_ALPN, LOOPBACK, ORIGIN, TestIdentity, TestResult, client_builder,
    closing_origin_observed, get_ok, serve_keep_alive_observed,
};
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

const LIMIT: Duration = Duration::from_secs(5);
const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);
const REQUEST: &[u8] = b"GET / HTTP/1.1\r\nHost: origin.phantom.test\r\n\r\n";
const CLOSING_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

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
        formatter.write_str("injected DNS origin serving failure")
    }
}

impl Error for ServingFailure {}

struct Fault {
    boundary: FaultBoundary,
    error: io::Error,
}

pub(super) struct WorkerControl {
    skip: usize,
    after_response: bool,
    returned: oneshot::Sender<JoinHandle<TestResult<()>>>,
    pending: watch::Sender<bool>,
    destroyed: watch::Sender<bool>,
    reached: watch::Sender<bool>,
    armed: Arc<AtomicBool>,
    fault: Option<Fault>,
}

impl WorkerControl {
    pub(super) fn select(&mut self) -> bool {
        if self.skip == 0 {
            true
        } else {
            self.skip -= 1;
            false
        }
    }

    pub(super) fn attach<T>(
        self,
        stream: T,
    ) -> (
        ObservedStream<T>,
        oneshot::Sender<JoinHandle<TestResult<()>>>,
    ) {
        (
            ObservedStream {
                stream,
                after_response: self.after_response,
                response_written: false,
                pending: self.pending,
                destroyed: self.destroyed,
                reached: self.reached,
                armed: self.armed,
                fault: self.fault,
            },
            self.returned,
        )
    }
}

pub(super) fn return_worker(
    returned: oneshot::Sender<JoinHandle<TestResult<()>>>,
    task: JoinHandle<TestResult<()>>,
) {
    if let Err(task) = returned.send(task) {
        // The observation caller stopped before receiving its original handle.
        task.abort();
    }
}

pub(super) struct ObservedStream<T> {
    stream: T,
    after_response: bool,
    response_written: bool,
    pending: watch::Sender<bool>,
    destroyed: watch::Sender<bool>,
    reached: watch::Sender<bool>,
    armed: Arc<AtomicBool>,
    fault: Option<Fault>,
}

impl<T> Drop for ObservedStream<T> {
    fn drop(&mut self) {
        self.destroyed.send_replace(true);
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ObservedStream<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.stream).poll_read(context, buffer);
        if result.is_pending() && (!this.after_response || this.response_written) {
            this.pending.send_replace(true);
        }
        if matches!(&result, Poll::Ready(Ok(())))
            && buffer.filled().len() > before
            && this.armed.load(Ordering::Acquire)
            && matches!(
                &this.fault,
                Some(Fault {
                    boundary: FaultBoundary::Read,
                    ..
                })
            )
            && let Some(fault) = this.fault.take()
        {
            this.reached.send_replace(true);
            return Poll::Ready(Err(fault.error));
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ObservedStream<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_write(context, bytes);
        if matches!(&result, Poll::Ready(Ok(length)) if *length != 0) {
            this.response_written = true;
        }
        if !bytes.is_empty()
            && matches!(&result, Poll::Ready(Ok(length)) if *length == bytes.len())
            && this.armed.load(Ordering::Acquire)
            && matches!(
                &this.fault,
                Some(Fault {
                    boundary: FaultBoundary::Write,
                    ..
                })
            )
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

enum Origin {
    Closing(ConnectionPeer<()>),
    KeepAlive(ConnectionPeer<TestResult<Vec<Option<String>>>>),
}

struct Backup {
    origin: Option<Origin>,
    returned: Option<oneshot::Receiver<JoinHandle<TestResult<()>>>>,
    worker: Option<ConnectionPeer<TestResult<()>>>,
    plain_client: Option<TcpStream>,
    tls_client: Option<Client>,
    pending: watch::Receiver<bool>,
    destroyed: watch::Receiver<bool>,
    reached: watch::Receiver<bool>,
    armed: Arc<AtomicBool>,
}

impl Backup {
    fn prepare(
        boundary: Option<FaultBoundary>,
        skip: usize,
    ) -> (Self, WorkerControl, Arc<FailureIdentity>) {
        let identity = Arc::new(FailureIdentity);
        let fault = boundary.map(|boundary| Fault {
            boundary,
            error: io::Error::new(
                io::ErrorKind::PermissionDenied,
                ServingFailure(Arc::clone(&identity)),
            ),
        });
        let (returned, receiver) = oneshot::channel();
        let (pending, pending_receiver) = watch::channel(false);
        let (destroyed, destroyed_receiver) = watch::channel(false);
        let (reached, reached_receiver) = watch::channel(false);
        let armed = Arc::new(AtomicBool::new(false));
        (
            Self {
                origin: None,
                returned: Some(receiver),
                worker: None,
                plain_client: None,
                tls_client: None,
                pending: pending_receiver,
                destroyed: destroyed_receiver,
                reached: reached_receiver,
                armed: Arc::clone(&armed),
            },
            WorkerControl {
                skip,
                after_response: false,
                returned,
                pending,
                destroyed,
                reached,
                armed,
                fault,
            },
            identity,
        )
    }

    async fn receive_worker(&mut self) -> TestResult<()> {
        let receiver = self.returned.as_mut().ok_or("worker receiver missing")?;
        let task = timeout(LIMIT, receiver).await??;
        self.worker = Some(ConnectionPeer::from_task(task));
        self.returned.take();
        timeout(LIMIT, self.pending.wait_for(|pending| *pending)).await??;
        Ok(())
    }

    async fn start_closing(&mut self, control: WorkerControl, prime_first: bool) -> TestResult<()> {
        let (port, task) = closing_origin_observed(Some(control)).await?;
        self.origin = Some(Origin::Closing(ConnectionPeer::from_task(task)));
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        if prime_first {
            let mut client = timeout(LIMIT, TcpStream::connect(address)).await??;
            timeout(LIMIT, client.write_all(REQUEST)).await??;
            closing_response(&mut client).await?;
        }

        self.plain_client = Some(timeout(LIMIT, TcpStream::connect(address)).await??);
        self.receive_worker().await
    }

    async fn prime_keep_alive(&mut self, mut control: WorkerControl) -> TestResult<String> {
        control.after_response = true;
        let identity = TestIdentity::generate_for_dns(ORIGIN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let acceptor = identity.acceptor(H1_ALPN)?;
        self.origin = Some(Origin::KeepAlive(ConnectionPeer::spawn(
            serve_keep_alive_observed(listener, acceptor, Some(control)),
        )));
        self.tls_client = Some(
            client_builder(&identity, false)
                .resolve(ORIGIN, [LOOPBACK])
                .build()?,
        );
        let url = format!("https://{ORIGIN}:{port}/");
        let client = self.tls_client.as_ref().ok_or("TLS client missing")?;
        timeout(LIMIT, get_ok(client, &url)).await??;
        self.receive_worker().await?;
        Ok(url)
    }

    async fn destroyed(&mut self) -> TestResult<()> {
        timeout(
            OBSERVATION_LIMIT,
            self.destroyed.wait_for(|destroyed| *destroyed),
        )
        .await??;
        let worker = self.worker.as_ref().ok_or("original worker missing")?;
        timeout(LIMIT, async {
            while !worker.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    async fn joined_worker(&mut self) -> TestResult<()> {
        let worker = self.worker.as_mut().ok_or("original worker missing")?;
        let joined = timeout(LIMIT, worker).await?;
        self.worker.take();
        joined?
    }

    async fn abort_closing_coordinator(&mut self) -> TestResult<()> {
        let Some(Origin::Closing(mut task)) = self.origin.take() else {
            return Err("closing coordinator missing".into());
        };
        task.abort();
        let joined = timeout(LIMIT, &mut task).await?;
        match joined {
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
            Ok(()) => Err("closing coordinator completed before requested cancellation".into()),
        }
    }

    async fn keep_alive_names(&mut self) -> TestResult<Vec<Option<String>>> {
        let Some(Origin::KeepAlive(mut task)) = self.origin.take() else {
            return Err("keepalive coordinator missing".into());
        };
        timeout(LIMIT, &mut task).await??
    }

    async fn stop(&mut self) -> TestResult<()> {
        self.plain_client.take();
        self.tls_client.take();
        let origin = match self.origin.take() {
            Some(Origin::Closing(mut task)) => {
                task.abort();
                match timeout(LIMIT, &mut task).await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) if error.is_cancelled() => Ok(()),
                    Ok(Err(error)) => Err(error.into()),
                    Err(error) => Err(error.into()),
                }
            }
            Some(Origin::KeepAlive(task)) => task.stop().await,
            None => Ok(()),
        };
        let received = if let Some(receiver) = self.returned.take() {
            match timeout(LIMIT, receiver).await {
                Ok(Ok(task)) => {
                    self.worker = Some(ConnectionPeer::from_task(task));
                    Ok(())
                }
                // Setup may stop before an accepted worker exists.
                Ok(Err(_)) => Ok(()),
                Err(error) => Err(error.into()),
            }
        } else {
            Ok(())
        };
        let worker = match self.worker.take() {
            Some(worker) => worker.stop().await,
            None => Ok(()),
        };
        finish_with_cleanup(finish_with_cleanup(origin, received), worker)
    }
}

async fn closing_response(client: &mut TcpStream) -> TestResult<()> {
    let mut response = vec![0; CLOSING_RESPONSE.len()];
    timeout(LIMIT, client.read_exact(&mut response)).await??;
    if response != CLOSING_RESPONSE {
        return Err("actual closing response changed".into());
    }
    match timeout(LIMIT, client.read(&mut [0_u8; 1])).await? {
        Ok(0) => Ok(()),
        Err(error) if super::tls::is_peer_gone(&error) => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => Err("closing origin did not close after its literal response".into()),
    }
}

fn retains_fault(result: TestResult<()>, identity: &Arc<FailureIdentity>) -> TestResult<()> {
    let Err(error) = result else {
        return Err("original DNS worker discarded its completed serving failure".into());
    };

    let Some(original) = error.downcast_ref::<io::Error>() else {
        return Err(error);
    };

    let matched = original.kind() == io::ErrorKind::PermissionDenied
        && original
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<ServingFailure>())
            .is_some_and(|cause| Arc::ptr_eq(&cause.0, identity));
    if !matched {
        return Err(error);
    }

    Ok(())
}

#[tokio::test]
async fn closing_worker_returns_its_literal_response_after_an_actual_pending_read() -> TestResult<()>
{
    let (mut backup, control, _) = Backup::prepare(None, 0);
    let primary = async {
        backup.start_closing(control, false).await?;
        let client = backup.plain_client.as_mut().ok_or("plain client missing")?;
        timeout(LIMIT, client.write_all(REQUEST)).await??;
        closing_response(client).await?;
        backup.destroyed().await?;
        backup.joined_worker().await
    }
    .await;
    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn explicit_abort_destroys_the_closing_origins_actual_pending_worker() -> TestResult<()> {
    let (mut backup, control, _) = Backup::prepare(None, 1);
    let primary = async {
        backup.start_closing(control, true).await?;
        backup
            .worker
            .as_ref()
            .ok_or("original worker missing")?
            .abort();
        backup.destroyed().await
    }
    .await;
    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn aborting_the_closing_coordinator_destroys_its_actual_pending_worker() -> TestResult<()> {
    let (mut backup, control, _) = Backup::prepare(None, 1);
    let primary = async {
        backup.start_closing(control, true).await?;
        backup.abort_closing_coordinator().await?;
        backup.destroyed().await
    }
    .await;
    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

async fn closing_fault(boundary: FaultBoundary) -> TestResult<()> {
    let (mut backup, control, identity) = Backup::prepare(Some(boundary), 0);
    let primary = async {
        backup.start_closing(control, false).await?;
        backup.armed.store(true, Ordering::Release);
        let client = backup.plain_client.as_mut().ok_or("plain client missing")?;
        timeout(LIMIT, client.write_all(REQUEST)).await??;
        timeout(LIMIT, backup.reached.wait_for(|reached| *reached)).await??;
        backup.destroyed().await?;
        let result = backup.joined_worker().await;
        retains_fault(result, &identity)
    }
    .await;
    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn closing_worker_retains_its_original_completed_read_failure() -> TestResult<()> {
    closing_fault(FaultBoundary::Read).await
}

#[tokio::test]
async fn closing_worker_retains_its_original_completed_write_failure() -> TestResult<()> {
    closing_fault(FaultBoundary::Write).await
}

#[tokio::test]
async fn healthy_keepalive_worker_completes_after_its_clients_literal_response_and_eof()
-> TestResult<()> {
    let (mut backup, control, _) = Backup::prepare(None, 0);
    let primary = async {
        backup.prime_keep_alive(control).await?;
        backup.tls_client.take();
        backup.destroyed().await?;
        backup.joined_worker().await?;
        if backup.keep_alive_names().await? != [Some(ORIGIN.to_owned())] {
            return Err("actual keepalive SNI changed".into());
        }
        Ok(())
    }
    .await;
    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn explicit_abort_destroys_the_keepalive_origins_actual_pending_worker() -> TestResult<()> {
    let (mut backup, control, _) = Backup::prepare(None, 0);
    let primary = async {
        backup.prime_keep_alive(control).await?;
        backup
            .worker
            .as_ref()
            .ok_or("original worker missing")?
            .abort();
        backup.destroyed().await
    }
    .await;
    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

async fn keep_alive_fault(boundary: FaultBoundary) -> TestResult<()> {
    let (mut backup, control, identity) = Backup::prepare(Some(boundary), 0);
    let primary = async {
        let url = backup.prime_keep_alive(control).await?;
        backup.armed.store(true, Ordering::Release);
        let client = backup.tls_client.as_ref().ok_or("TLS client missing")?;
        let caller = timeout(LIMIT, get_ok(client, &url)).await?;
        timeout(LIMIT, backup.reached.wait_for(|reached| *reached)).await??;
        backup.destroyed().await?;
        let result = backup.joined_worker().await;
        let oracle = retains_fault(result, &identity);
        // This request follows a deliberately failed serving operation.
        if let Err(error) = caller {
            let expected = expected_caller_close(error.as_ref());
            if !expected {
                return finish_with_cleanup(oracle, Err(error));
            }
        }
        oracle
    }
    .await;
    let cleanup = backup.stop().await;
    finish_with_cleanup(primary, cleanup)
}

fn expected_caller_close(error: &(dyn Error + 'static)) -> bool {
    if !error
        .downcast_ref::<phantom::RequestError>()
        .is_some_and(|error| error.kind() == phantom::RequestErrorKind::Http1)
    {
        return false;
    }

    let mut source = error.source();
    while let Some(current) = source {
        if let Some(io) = current.downcast_ref::<io::Error>() {
            return super::tls::is_peer_gone(io);
        }
        if let Some(http1) = current.downcast_ref::<phantom_net::http1::Http1Error>()
            && http1.kind() == phantom_net::http1::Http1ErrorKind::ReusedConnectionClosed
        {
            return true;
        }
        source = current.source();
    }
    false
}

#[tokio::test]
async fn keepalive_worker_retains_its_original_completed_read_failure() -> TestResult<()> {
    keep_alive_fault(FaultBoundary::Read).await
}

#[tokio::test]
async fn keepalive_worker_retains_its_original_completed_write_failure() -> TestResult<()> {
    keep_alive_fault(FaultBoundary::Write).await
}
