use std::{
    error::Error,
    fmt,
    future::Future,
    io,
    net::Ipv4Addr,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use http::{Method, Request, StatusCode, Version};
use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, RequestError, RequestErrorKind};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpListener,
    sync::oneshot,
    task::{AbortHandle, JoinHandle},
    time::timeout,
};

use crate::support::tunnel_proxy::{
    ConnectionPeer, connection_peer::FixtureFailures, finish_with_cleanup,
};

use super::{
    H1_ALPN, TestIdentity, TestResult, alps_client, alps_origin_answering_with_io,
    answer_http1_hint_requests, answer_http3_hint_requests, assert_http1_hints, bounded, client,
    finish_hint_operation, server_endpoint,
};

const EXCHANGE: Duration = Duration::from_secs(15);
const CLEANUP: Duration = Duration::from_secs(5);
const OBSERVE: Duration = Duration::from_millis(100);

#[tokio::test]
async fn explicit_cancel_releases_the_actual_http1_hint_peer() -> TestResult<()> {
    observe_owner(HttpProtocol::Http1, Exit::ExplicitCancel).await
}

#[tokio::test]
async fn explicit_cancel_releases_the_actual_http3_hint_peer() -> TestResult<()> {
    observe_owner(HttpProtocol::Http3, Exit::ExplicitCancel).await
}

#[tokio::test]
async fn an_http1_operation_error_releases_the_actual_hint_peer() -> TestResult<()> {
    observe_owner(HttpProtocol::Http1, Exit::OperationError).await
}

#[tokio::test]
async fn an_http3_operation_error_releases_the_actual_hint_peer() -> TestResult<()> {
    observe_owner(HttpProtocol::Http3, Exit::OperationError).await
}

#[tokio::test]
async fn an_unpolled_http1_finish_owns_the_actual_hint_peer() -> TestResult<()> {
    observe_owner(HttpProtocol::Http1, Exit::Unpolled).await
}

#[tokio::test]
async fn an_unpolled_http3_finish_owns_the_actual_hint_peer() -> TestResult<()> {
    observe_owner(HttpProtocol::Http3, Exit::Unpolled).await
}

#[tokio::test]
async fn an_expired_http1_operation_releases_the_actual_hint_peer() -> TestResult<()> {
    observe_owner(HttpProtocol::Http1, Exit::Deadline).await
}

#[tokio::test]
async fn an_expired_http3_operation_releases_the_actual_hint_peer() -> TestResult<()> {
    observe_owner(HttpProtocol::Http3, Exit::Deadline).await
}

#[tokio::test]
async fn an_ordinary_alps_operation_observes_its_actual_completed_peer() -> TestResult<()> {
    observe_alps(AlpsExit::Healthy).await
}

#[tokio::test]
async fn directly_joining_the_alps_peer_retains_its_typed_read_failure() -> TestResult<()> {
    observe_alps(AlpsExit::ReadFailure).await
}

#[tokio::test]
async fn an_alps_operation_error_retains_its_completed_peer_failure() -> TestResult<()> {
    observe_alps(AlpsExit::PrimaryAndReadFailure).await
}

enum Exit {
    ExplicitCancel,
    OperationError,
    Unpolled,
    Deadline,
}

enum Observation {
    Http1(oneshot::Receiver<Vec<u8>>),
    Http3(oneshot::Receiver<Request<()>>),
}

struct HintOwnerCase {
    client: Client,
    url: String,
    peer: Option<JoinHandle<TestResult<()>>>,
    backup: AbortBackup,
    observed: Option<Observation>,
    destroyed: oneshot::Receiver<()>,
    client_done: Option<oneshot::Sender<()>>,
}

struct AbortBackup(AbortHandle);

impl Drop for AbortBackup {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct Destroyed(Option<oneshot::Sender<()>>);

impl Drop for Destroyed {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            // Destruction has no recoverable caller; the receiver owns observation failure.
            let _ = sender.send(());
        }
    }
}

async fn observe_owner(protocol: HttpProtocol, exit: Exit) -> TestResult<()> {
    let mut case = owner_case(protocol).await?;
    let operation = async {
        collect_first(&case.client, protocol, &case.url).await?;

        match case
            .observed
            .take()
            .ok_or("hint observation was already consumed")?
        {
            Observation::Http1(observed) => {
                let head = observed.await?;
                assert!(std::str::from_utf8(&head)?.starts_with("GET /ownership HTTP/1.1\r\n"));
                assert_http1_hints(&head, false)?;
            }
            Observation::Http3(observed) => {
                let request = observed.await?;
                assert_eq!(request.method(), Method::GET);
                assert_eq!(request.uri().path(), "/ownership");
                assert_eq!(request.version(), Version::HTTP_3);
                assert_eq!(request.headers()["sec-ch-ua"], "baseline");
                assert!(!request.headers().contains_key("sec-ch-ua-arch"));
                assert!(!request.headers().contains_key("sec-ch-ua-platform-version"));
            }
        }

        assert!(
            !case.backup.0.is_finished(),
            "real hint peer ended before caller exit"
        );
        let peer = case
            .peer
            .take()
            .ok_or("actual hint peer was already transferred")?;
        let primary = match exit {
            Exit::ExplicitCancel => {
                ConnectionPeer::from_task(peer).stop().await?;
                None
            }
            Exit::OperationError => {
                let primary = invalid_uri(&case.client, protocol)?;
                Some(
                    finish_hint_operation(peer, async { Err(primary.into()) })
                        .await
                        .err()
                        .ok_or("actual hint caller ignored its input error")?,
                )
            }
            Exit::Unpolled => {
                let finish = finish_hint_operation(peer, std::future::pending::<TestResult<()>>());
                drop(finish);
                None
            }
            Exit::Deadline => Some(
                bounded(finish_hint_operation(
                    peer,
                    std::future::pending::<TestResult<()>>(),
                ))
                .await
                .err()
                .ok_or("actual hint deadline did not expire")?,
            ),
        };
        let released = timeout(OBSERVE, &mut case.destroyed).await;
        Ok::<_, Box<dyn Error + Send + Sync>>((primary, released))
    };
    let result = match timeout(EXCHANGE, operation).await {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };

    // Backup begins only after the actual lifetime snapshot; the client stays alive.
    case.backup.0.abort();
    let joined = match case.peer.take() {
        Some(peer) => ConnectionPeer::from_task(peer).stop().await,
        None => Ok(()),
    };
    let cleanup = finish_with_cleanup(joined, wait_finished(&case.backup.0).await);
    let (primary, released) = finish_with_cleanup(result, cleanup)?;
    drop(case.client_done.take());
    drop(case.client);

    if let Some(error) = primary {
        match exit {
            Exit::OperationError => {
                let error = find_cause::<RequestError>(error.as_ref())
                    .ok_or("actual hint input error was replaced")?;
                assert_eq!(error.kind(), RequestErrorKind::InvalidUri);
            }
            Exit::Deadline => {
                assert_eq!(error.to_string(), "client-hint test timed out");
                assert!(find_cause::<tokio::time::error::Elapsed>(error.as_ref()).is_some());
            }
            Exit::ExplicitCancel | Exit::Unpolled => return Err("unexpected hint primary".into()),
        }
    }
    assert!(
        matches!(released, Ok(Ok(()))),
        "actual hint peer survived its caller exit before backup cleanup"
    );
    Ok(())
}

async fn owner_case(protocol: HttpProtocol) -> TestResult<HintOwnerCase> {
    let identity = TestIdentity::generate()?;
    let client = client(&identity)?;
    let (destroy, destroyed) = oneshot::channel();
    let witness = Destroyed(Some(destroy));
    let (url, peer, observed, client_done) = match protocol {
        HttpProtocol::Http1 => {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let acceptor = identity.acceptor(H1_ALPN)?;
            let (record, recorded) = oneshot::channel();
            let peer = tokio::spawn(async move {
                let _witness = witness;
                answer_http1_hint_requests(listener, acceptor, Some(record))
                    .await
                    .map(|_| ())
            });
            (
                format!("https://{address}/ownership"),
                peer,
                Observation::Http1(recorded),
                None,
            )
        }
        HttpProtocol::Http3 => {
            let (address, endpoint) = server_endpoint(&identity)?;
            let (done, completed) = oneshot::channel();
            let (record, recorded) = oneshot::channel();
            let peer = tokio::spawn(async move {
                let _witness = witness;
                answer_http3_hint_requests(endpoint, completed, Some(record)).await
            });
            (
                format!("https://{address}/ownership"),
                peer,
                Observation::Http3(recorded),
                Some(done),
            )
        }
        HttpProtocol::Http2 => return Err("H2 ownership is observed through actual ALPS IO".into()),
        _ => return Err("unsupported hint ownership protocol".into()),
    };
    let backup = AbortBackup(peer.abort_handle());
    Ok(HintOwnerCase {
        client,
        url,
        peer: Some(peer),
        backup,
        observed: Some(observed),
        destroyed,
        client_done,
    })
}

async fn collect_first(client: &Client, protocol: HttpProtocol, url: &str) -> TestResult<()> {
    let response = client.get(protocol, url)?.send().await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.into_body().collect().await?.to_bytes().is_empty());
    Ok(())
}

fn invalid_uri(client: &Client, protocol: HttpProtocol) -> TestResult<RequestError> {
    match client.get(protocol, "https://127.0.0.1/\r\n") {
        Err(error) => {
            assert_eq!(error.kind(), RequestErrorKind::InvalidUri);
            assert!(
                error
                    .source()
                    .is_some_and(|cause| cause.is::<http::uri::InvalidUri>())
            );
            Ok(error)
        }
        Ok(_) => Err("actual malformed hint URI unexpectedly parsed".into()),
    }
}

async fn wait_finished(peer: &AbortHandle) -> TestResult<()> {
    timeout(CLEANUP, async {
        while !peer.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

fn find_cause<'a, T: Error + 'static>(mut error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    loop {
        if let Some(cause) = error.downcast_ref::<T>() {
            return Some(cause);
        }
        error = error.source()?;
    }
}

enum AlpsExit {
    Healthy,
    ReadFailure,
    PrimaryAndReadFailure,
}

async fn observe_alps(exit: AlpsExit) -> TestResult<()> {
    let (enable_fault, wait_for_fault) = oneshot::channel();
    let invoked = Arc::new(AtomicBool::new(false));
    let read_invoked = Arc::clone(&invoked);
    let (record, recorded) = oneshot::channel();
    let (identity, origin, peer) = alps_origin_answering_with_io(
        "Sec-CH-UA-Arch",
        move |inner| FaultRead {
            inner,
            wait_for_fault: Some(wait_for_fault),
            invoked: read_invoked,
        },
        Some(record),
    )
    .await?;
    let backup = AbortBackup(peer.abort_handle());
    let mut peer = Some(peer);
    let mut client = None;
    let operation = async {
        client = Some(alps_client(&identity)?);
        let client = client.as_ref().ok_or("ALPS client was not retained")?;
        collect_first(client, HttpProtocol::Http2, &format!("{origin}/ownership")).await?;
        let request = recorded.await?;
        assert_eq!(request.method, Method::GET);
        assert_eq!(request.uri.path(), "/ownership");
        assert_eq!(request.version, Version::HTTP_2);
        assert!(request.body_ended);
        assert_eq!(request.headers["sec-ch-ua"], "baseline");
        assert_eq!(request.headers["sec-ch-ua-arch"], "\"arm\"");
        assert!(!request.ordered_names.is_empty());

        if matches!(exit, AlpsExit::Healthy) {
            let peer = peer.take().ok_or("ALPS peer was already transferred")?;
            let names = finish_hint_operation(peer, async { Ok(()) }).await?;
            assert!(!names.is_empty());
            assert!(!invoked.load(Ordering::SeqCst));
            drop(enable_fault);
            return Ok(None);
        }

        enable_fault
            .send(())
            .map_err(|_| "actual ALPS reader ended before fault injection")?;
        wait_finished(&backup.0).await?;
        assert!(
            invoked.load(Ordering::SeqCst),
            "actual ALPS reader did not invoke its fault"
        );
        let primary = match exit {
            AlpsExit::ReadFailure => Ok(()),
            AlpsExit::PrimaryAndReadFailure => {
                Err(invalid_uri(client, HttpProtocol::Http2)?.into())
            }
            AlpsExit::Healthy => return Err("unexpected ALPS exit".into()),
        };
        let peer = peer.take().ok_or("ALPS peer was already transferred")?;
        let error = finish_hint_operation(peer, async { primary })
            .await
            .err()
            .ok_or("actual ALPS read failure was discarded")?;
        Ok::<_, Box<dyn Error + Send + Sync>>(Some(error))
    };
    let result = match timeout(EXCHANGE, operation).await {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };

    backup.0.abort();
    let joined = match peer {
        Some(peer) => ConnectionPeer::from_task(peer).stop().await,
        None => Ok(()),
    };
    let cleanup = finish_with_cleanup(joined, wait_finished(&backup.0).await);
    let result = finish_with_cleanup(result, cleanup);
    drop(client);
    let Some(error) = result? else {
        return Ok(());
    };

    match exit {
        AlpsExit::ReadFailure => assert_read_failure(error.as_ref())?,
        AlpsExit::PrimaryAndReadFailure => {
            let primary = find_cause::<RequestError>(error.as_ref())
                .ok_or("ALPS caller lost its actual URI input error")?;
            assert_eq!(primary.kind(), RequestErrorKind::InvalidUri);
            let failures = error
                .downcast_ref::<FixtureFailures>()
                .ok_or("ALPS caller discarded its independently completed peer failure")?;
            assert_read_failure(failures.cleanup.as_ref())?;
        }
        AlpsExit::Healthy => return Err("healthy ALPS exchange unexpectedly failed".into()),
    }
    Ok(())
}

fn assert_read_failure(error: &(dyn Error + 'static)) -> TestResult<()> {
    let h2 = find_cause::<::http2::Error>(error).ok_or("actual ALPS H2 error was replaced")?;
    let io = h2
        .get_io()
        .ok_or("actual ALPS H2 error omitted its IO cause")?;
    assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(io.to_string(), "controlled post-response hint read failure");
    Ok(())
}

#[derive(Debug)]
struct HintReadFailure;

impl fmt::Display for HintReadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled post-response hint read failure")
    }
}

impl Error for HintReadFailure {}

struct FaultRead<I> {
    inner: I,
    wait_for_fault: Option<oneshot::Receiver<()>>,
    invoked: Arc<AtomicBool>,
}

impl<I: AsyncRead + Unpin> AsyncRead for FaultRead<I> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.invoked.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                HintReadFailure,
            )));
        }
        let signal = match this.wait_for_fault.as_mut() {
            Some(wait_for_fault) => Pin::new(wait_for_fault).poll(context),
            None => return Pin::new(&mut this.inner).poll_read(context, buffer),
        };
        match signal {
            Poll::Ready(Ok(())) => {
                this.wait_for_fault = None;
                this.invoked.store(true, Ordering::SeqCst);
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    HintReadFailure,
                )))
            }
            Poll::Ready(Err(error)) => {
                this.wait_for_fault = None;
                Poll::Ready(Err(io::Error::other(error)))
            }
            Poll::Pending => Pin::new(&mut this.inner).poll_read(context, buffer),
        }
    }
}

impl<I: AsyncWrite + Unpin> AsyncWrite for FaultRead<I> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(context, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }
    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}
