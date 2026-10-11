use std::{
    error::Error,
    fmt, io,
    net::Ipv4Addr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use phantom::{Client, HttpProtocol, RequestError, RequestErrorKind, profile::ClientProfile};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::AbortHandle,
    time::timeout,
};

use crate::support::{
    tls::{is_peer_gone, tls_settings},
    tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup},
};

use super::{Http1Coordinator, LIMIT, TestResult, finish};

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
        formatter.write_str("injected ordinary runtime HTTP1 serving failure")
    }
}

impl Error for ServingFailure {}

#[derive(Clone, Default)]
struct StreamState {
    pending: bool,
    reached: bool,
    destroyed: bool,
}

struct ObservedStream {
    stream: TcpStream,
    state: watch::Sender<StreamState>,
    fault: Option<(FaultBoundary, io::Error)>,
}

impl Drop for ObservedStream {
    fn drop(&mut self) {
        self.state.send_modify(|state| state.destroyed = true);
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
            this.state.send_modify(|state| state.pending = true);
        }

        if matches!(&result, Poll::Ready(Ok(()))) {
            if !observed.filled().is_empty()
                && matches!(&this.fault, Some((FaultBoundary::Read, _)))
                && let Some((_, error)) = this.fault.take()
            {
                this.state.send_modify(|state| state.reached = true);
                return Poll::Ready(Err(error));
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
            && matches!(&this.fault, Some((FaultBoundary::Write, _)))
            && let Some((_, error)) = this.fault.take()
        {
            this.state.send_modify(|state| state.reached = true);
            return Poll::Ready(Err(error));
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
    coordinator: Option<Http1Coordinator>,
    original: AbortHandle,
    child: watch::Receiver<Option<AbortHandle>>,
    client: Option<TcpStream>,
    state: watch::Receiver<StreamState>,
    accepted: Arc<AtomicUsize>,
}

impl Backup {
    async fn bind(boundary: Option<FaultBoundary>) -> TestResult<(Self, Arc<FailureIdentity>)> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let accepted = Arc::new(AtomicUsize::new(0));
        let (state, receiver) = watch::channel(StreamState::default());
        let (child, child_receiver) = watch::channel(None);
        let identity = Arc::new(FailureIdentity);
        let cause = Arc::clone(&identity);
        let coordinator = Http1Coordinator::spawn(
            listener,
            Arc::clone(&accepted),
            move |stream| ObservedStream {
                stream,
                state: state.clone(),
                fault: boundary.map(|boundary| {
                    (boundary, io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        ServingFailure(Arc::clone(&cause)),
                    ))
                }),
            },
            move |peer| { child.send_replace(Some(peer.abort_handle())); },
        );
        let original = coordinator.abort.clone();
        let mut backup = Self {
            coordinator: Some(coordinator), original,
            child: child_receiver, client: None, state: receiver, accepted,
        };
        let connected: TestResult<TcpStream> = match timeout(LIMIT, TcpStream::connect(address)).await {
            Ok(result) => result.map_err(Into::into),
            Err(error) => Err(error.into()),
        };
        let client = match connected {
            Ok(client) => client,
            Err(error) => return finish_with_cleanup(Err(error), backup.stop().await),
        };

        backup.client = Some(client);
        Ok((backup, identity))
    }

    fn coordinator(&mut self) -> TestResult<&mut Http1Coordinator> {
        self.coordinator.as_mut().ok_or_else(|| "original coordinator missing".into())
    }

    async fn pending(&mut self) -> TestResult {
        timeout(LIMIT, self.state.wait_for(|state| state.pending)).await??;
        timeout(LIMIT, self.child.wait_for(Option::is_some)).await??;
        Ok(())
    }

    async fn child_finished(&mut self) -> TestResult {
        timeout(OBSERVATION_LIMIT, self.state.wait_for(|state| state.destroyed)).await??;
        let original = self.child.borrow().clone().ok_or("original child witness missing")?;
        timeout(LIMIT, async {
            while !original.is_finished() {
                tokio::task::yield_now().await;
            }
        }).await?;
        Ok(())
    }

    async fn coordinator_finished(&self) -> TestResult {
        timeout(LIMIT, async {
            while !self.original.is_finished() {
                tokio::task::yield_now().await;
            }
        }).await?;
        Ok(())
    }

    async fn closed(&mut self) -> TestResult<Vec<u8>> {
        let Some(client) = self.client.as_mut() else {
            return Ok(Vec::new());
        };

        let mut received = Vec::new();
        match timeout(LIMIT, client.read_to_end(&mut received)).await? {
            Ok(_) => {}
            Err(error) if is_peer_gone(&error) => {}
            Err(error) => return Err(error.into()),
        }
        Ok(received)
    }

    async fn completed_fault(&mut self, boundary: FaultBoundary) -> TestResult {
        self.pending().await?;
        let client = self.client.as_mut().ok_or("real caller socket missing")?;
        timeout(LIMIT, client.write_all(REQUEST)).await??;
        timeout(LIMIT, self.state.wait_for(|state| state.reached)).await??;
        self.child_finished().await?;
        let received = self.closed().await?;

        match boundary {
            FaultBoundary::Read => assert!(received.is_empty()),
            FaultBoundary::Write => {
                assert!(!received.is_empty());
                assert!(RESPONSE.starts_with(&received));
            }
        }
        Ok(())
    }

    async fn stop(&mut self) -> TestResult {
        let result = if let Some(coordinator) = self.coordinator.as_mut() {
            let primary = coordinator.shutdown().await;
            let cancellation = if let Some(task) = coordinator.task.as_mut() {
                let requested = !task.is_finished();
                if requested {
                    task.abort();
                }
                let joined = timeout(LIMIT, task).await;
                match joined {
                    Ok(joined) => {
                        coordinator.task.take();
                        match joined {
                            Ok(result) => result,
                            Err(error) if requested && error.is_cancelled() => Ok(()),
                            Err(error) => Err(error.into()),
                        }
                    }
                    Err(error) => Err(error.into()),
                }
            } else {
                Ok(())
            };
            finish_with_cleanup(primary, cancellation)
        } else {
            self.original.abort();
            self.coordinator_finished().await
        };
        let has_child = self.child.borrow().is_some();
        let child = if has_child {
            self.child_finished().await
        } else {
            Ok(())
        };
        let closed = self.closed().await.map(|_| ());
        finish_with_cleanup(finish_with_cleanup(result, child), closed)
    }
}

impl Drop for Backup {
    fn drop(&mut self) {
        self.original.abort();
        if let Some(child) = self.child.borrow().as_ref() {
            child.abort();
        }
    }
}

fn retains_fault(error: &(dyn Error + 'static), identity: &Arc<FailureIdentity>) -> TestResult {
    let original = error.downcast_ref::<io::Error>()
        .ok_or("ordinary coordinator discarded the original serving I/O error")?;
    if original.kind() != io::ErrorKind::PermissionDenied {
        return Err("ordinary coordinator changed the original serving error kind".into());
    }

    let cause = original.get_ref().and_then(|cause| cause.downcast_ref::<ServingFailure>())
        .ok_or("ordinary coordinator discarded the original typed serving cause")?;
    if !Arc::ptr_eq(&cause.0, identity) {
        return Err("ordinary coordinator changed the original serving identity".into());
    }

    Ok(())
}

#[tokio::test]
async fn healthy_ordinary_coordinator_keeps_the_literal_response_and_original_completion() -> TestResult {
    let (mut backup, _) = Backup::bind(None).await?;
    let primary = async {
        backup.pending().await?;
        let client = backup.client.as_mut().ok_or("real caller socket missing")?;
        timeout(LIMIT, client.write_all(REQUEST)).await??;
        timeout(LIMIT, client.shutdown()).await??;
        let received = backup.closed().await?;
        backup.child_finished().await?;
        finish(Ok(()), backup.coordinator()?).await?;
        backup.coordinator_finished().await?;

        assert_eq!(received, RESPONSE);
        assert_eq!(backup.accepted.load(Ordering::SeqCst), 1);
        Ok(())
    }.await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn explicit_ordinary_coordinator_stop_destroys_its_actual_pending_child_vector() -> TestResult {
    let (mut backup, _) = Backup::bind(None).await?;
    let primary = async {
        backup.pending().await?;
        backup.coordinator()?.shutdown().await?;
        backup.coordinator_finished().await?;
        backup.child_finished().await?;
        let received = backup.closed().await?;

        assert!(received.is_empty());
        assert_eq!(backup.accepted.load(Ordering::SeqCst), 1);
        Ok(())
    }.await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn ordinary_coordinator_owner_drop_destroys_its_original_pending_child_with_runtime_live() -> TestResult {
    let (mut backup, _) = Backup::bind(None).await?;
    let primary = async {
        backup.pending().await?;
        drop(backup.coordinator.take());
        backup.child_finished().await?;
        backup.coordinator_finished().await?;
        let received = backup.closed().await?;

        assert!(received.is_empty());
        Ok(())
    }.await;
    finish_with_cleanup(primary, backup.stop().await)
}

async fn completed_cause(boundary: FaultBoundary) -> TestResult {
    let (mut backup, identity) = Backup::bind(Some(boundary)).await?;
    let primary = async {
        backup.completed_fault(boundary).await?;
        let result = backup.coordinator()?.shutdown().await;
        backup.coordinator_finished().await?;
        let error = result.err().ok_or("ordinary coordinator accepted its completed child failure")?;
        retains_fault(error.as_ref(), &identity)
    }.await;
    finish_with_cleanup(primary, backup.stop().await)
}

#[tokio::test]
async fn ordinary_coordinator_shutdown_retains_its_original_completed_read_failure() -> TestResult {
    completed_cause(FaultBoundary::Read).await
}

#[tokio::test]
async fn ordinary_coordinator_shutdown_retains_its_original_completed_write_failure() -> TestResult {
    completed_cause(FaultBoundary::Write).await
}

#[tokio::test]
async fn ordinary_coordinator_caller_failure_keeps_both_original_typed_causes() -> TestResult {
    let client = Client::builder(ClientProfile::new(tls_settings())).build()?;
    let (mut backup, identity) = Backup::bind(Some(FaultBoundary::Read)).await?;
    let primary = async {
        backup.completed_fault(FaultBoundary::Read).await?;
        let caller = client.get(HttpProtocol::Http1, "http://runtime.test/\n")
            .err().ok_or("actual invalid caller URI was accepted")?;
        assert_eq!(caller.kind(), RequestErrorKind::InvalidUri);
        assert!(caller.source().is_some_and(|cause| cause.is::<http::uri::InvalidUri>()));
        let result = finish(Err(Box::new(caller)), backup.coordinator()?).await;

        let error = result.err().ok_or("actual caller failure was discarded")?;
        let both = error.downcast_ref::<FixtureFailures>()
            .ok_or("actual caller failure discarded its completed ordinary child cause")?;
        let caller = both.primary.downcast_ref::<RequestError>()
            .ok_or("actual typed caller failure was replaced")?;
        assert_eq!(caller.kind(), RequestErrorKind::InvalidUri);
        assert!(caller.source().is_some_and(|cause| cause.is::<http::uri::InvalidUri>()));
        retains_fault(both.cleanup.as_ref(), &identity)?;
        backup.coordinator_finished().await
    }.await;
    finish_with_cleanup(primary, backup.stop().await)
}
