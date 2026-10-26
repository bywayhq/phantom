use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    pin::Pin,
    sync::Arc,
    time::Duration,
};

use btls::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use http_body_util::BodyExt;
use phantom::ProxyConfigErrorKind;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
    task::AbortHandle,
    time::timeout,
};
use tokio_btls::SslStream;

use super::super::{
    H1_ALPN, HttpProtocol, HttpProxy, Route, TestIdentity, TestResult, client_builder, read_head,
    tls_support,
};
use super::{OriginOutcome, OriginReturn, PeerControls, PeerReturns, ProxyAuthPeers, ProxyReturn};
use crate::support::tunnel_proxy::{
    ConnectionPeer, connection_peer::FixtureFailures, finish_with_cleanup,
};

const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);
const BACKUP_LIMIT: Duration = Duration::from_secs(5);
const FIRST_RESPONSE: &[u8] = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";

pub(super) struct OriginObservation {
    pending: watch::Sender<bool>,
    destroyed: watch::Sender<bool>,
}

pub(super) struct OriginLifetime(watch::Sender<bool>);

impl OriginObservation {
    pub(super) fn lifetime(&self) -> OriginLifetime {
        OriginLifetime(self.destroyed.clone())
    }
}

impl Drop for OriginLifetime {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

pub(super) struct ObservedFailure {
    error: io::Error,
    reached: watch::Sender<bool>,
}

impl ObservedFailure {
    pub(super) fn finish(self) -> io::Error {
        self.reached.send_replace(true);
        self.error
    }
}

pub(super) async fn observed_second_head(
    stream: &mut (impl AsyncRead + Unpin),
    observation: Option<&OriginObservation>,
) -> io::Result<Vec<u8>> {
    let Some(observation) = observation else {
        return read_head(stream).await;
    };

    let head = read_head(stream);
    tokio::pin!(head);
    poll_fn(|context| {
        let result = head.as_mut().poll(context);
        if result.is_pending() {
            observation.pending.send_replace(true);
        }

        result
    })
    .await
}

struct Backup {
    origin: oneshot::Receiver<Option<OriginReturn>>,
    proxy: oneshot::Receiver<Option<ProxyReturn>>,
    origin_abort: Option<AbortHandle>,
    proxy_abort: Option<AbortHandle>,
    origin_abort_requested: bool,
    pending: watch::Receiver<bool>,
    destroyed: watch::Receiver<bool>,
    origin_fault: watch::Receiver<bool>,
    proxy_fault: watch::Receiver<bool>,
}

impl Backup {
    fn prepare(
        origin_fault: Option<io::Error>,
        proxy_fault: Option<io::Error>,
    ) -> (Self, PeerControls) {
        let (origin, origin_return) = oneshot::channel();
        let (proxy, proxy_return) = oneshot::channel();
        let (pending, pending_receiver) = watch::channel(false);
        let (destroyed, destroyed_receiver) = watch::channel(false);
        let (origin_reached, origin_fault_receiver) = watch::channel(false);
        let (proxy_reached, proxy_fault_receiver) = watch::channel(false);

        (
            Self {
                origin: origin_return,
                proxy: proxy_return,
                origin_abort: None,
                proxy_abort: None,
                origin_abort_requested: false,
                pending: pending_receiver,
                destroyed: destroyed_receiver,
                origin_fault: origin_fault_receiver,
                proxy_fault: proxy_fault_receiver,
            },
            PeerControls {
                returns: PeerReturns { origin, proxy },
                origin: OriginObservation { pending, destroyed },
                origin_fault: origin_fault.map(|error| ObservedFailure {
                    error,
                    reached: origin_reached,
                }),
                proxy_fault: proxy_fault.map(|error| ObservedFailure {
                    error,
                    reached: proxy_reached,
                }),
            },
        )
    }

    fn acquired(&mut self, peers: &ProxyAuthPeers) {
        self.origin_abort = peers.origin.as_ref().map(ConnectionPeer::abort_handle);
        self.proxy_abort = peers.proxy.as_ref().map(ConnectionPeer::abort_handle);
    }

    fn abort_origin(&mut self) -> TestResult<()> {
        let origin = self
            .origin_abort
            .as_ref()
            .ok_or("origin handle was not retained")?;
        self.origin_abort_requested = true;
        origin.abort();
        Ok(())
    }

    async fn stop(&mut self) -> TestResult<()> {
        let origin = match timeout(BACKUP_LIMIT, &mut self.origin).await {
            Ok(Ok(Some(returned))) => {
                stop_origin(
                    returned.peer,
                    self.origin_abort_requested || returned.stop_requested,
                )
                .await
            }
            Ok(Ok(None)) => Ok(()),
            Ok(Err(_)) if self.origin_abort.is_none() => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(error) => Err(error.into()),
        };

        let proxy = match timeout(BACKUP_LIMIT, &mut self.proxy).await {
            Ok(Ok(Some(returned))) => {
                let mut task = returned.peer;
                let requested = returned.stop_requested || !task.is_finished();
                if requested {
                    task.abort();
                }

                match timeout(BACKUP_LIMIT, &mut task).await {
                    Ok(Ok(result)) => result.map(|_| ()),
                    Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
                    Ok(Err(error)) => Err(error.into()),
                    Err(error) => {
                        task.abort();
                        Err(error.into())
                    }
                }
            }
            Ok(Ok(None)) => Ok(()),
            Ok(Err(_)) if self.proxy_abort.is_none() => Ok(()),
            Ok(Err(error)) => Err(error.into()),
            Err(error) => Err(error.into()),
        };

        finish_with_cleanup(origin, proxy)
    }
}

impl Drop for Backup {
    fn drop(&mut self) {
        for handle in [&self.origin_abort, &self.proxy_abort]
            .into_iter()
            .flatten()
        {
            handle.abort();
        }

        if let Ok(Some(returned)) = self.origin.try_recv() {
            returned.peer.abort();
        }

        if let Ok(Some(returned)) = self.proxy.try_recv() {
            returned.peer.abort();
        }
    }
}

async fn stop_origin(
    mut task: ConnectionPeer<OriginOutcome>,
    already_requested: bool,
) -> TestResult<()> {
    let requested = already_requested || !task.is_finished();
    if requested {
        task.abort();
    }

    match timeout(BACKUP_LIMIT, &mut task).await {
        Ok(Ok(result)) => result.map(|_| ()),
        Ok(Err(error)) if requested && error.is_cancelled() => Ok(()),
        Ok(Err(error)) => Err(error.into()),
        Err(error) => {
            task.abort();
            Err(error.into())
        }
    }
}

#[derive(Debug)]
struct OriginDropDeadline(tokio::time::error::Elapsed);

impl fmt::Display for OriginDropDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("proxy-auth owner left its actual pending origin alive")
    }
}

impl Error for OriginDropDeadline {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

enum PendingContract {
    SetupRejection,
    ExplicitAbort,
}

async fn pending_origin(contract: PendingContract) -> TestResult<()> {
    let (mut backup, controls) = Backup::prepare(None, None);
    let mut peers = None;
    let mut client = None;
    let mut setup_error = None;

    let primary: TestResult<()> = async {
        let identity = TestIdentity::generate()?;
        let mut connector = SslConnector::bare_builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::PEER);
        connector
            .cert_store_mut()
            .add_cert(X509::from_der(&identity.root_der)?)?;
        connector.set_alpn_protos(H1_ALPN)?;
        let ssl = connector.build().configure()?.into_ssl("127.0.0.1")?;

        peers = Some(ProxyAuthPeers::start_origin(&identity, Some(controls)).await?);
        let peers_ref = peers.as_ref().ok_or("origin owner was not retained")?;
        backup.acquired(peers_ref);
        let address = peers_ref.origin_address;

        let tcp = timeout(BACKUP_LIMIT, TcpStream::connect(address)).await??;
        client = Some(SslStream::new(ssl, tcp)?);
        let stream = client.as_mut().ok_or("trusted client was not retained")?;
        timeout(BACKUP_LIMIT, Pin::new(&mut *stream).connect()).await??;
        assert_eq!(
            stream.ssl().selected_alpn_protocol(),
            Some(&b"http/1.1"[..])
        );

        timeout(BACKUP_LIMIT, async {
            stream
                .write_all(b"GET /first HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await?;
            stream.flush().await
        })
        .await??;
        let response = timeout(BACKUP_LIMIT, read_head(stream)).await??;
        assert_eq!(response, FIRST_RESPONSE);

        drop(timeout(BACKUP_LIMIT, backup.pending.wait_for(|pending| *pending)).await??);

        match contract {
            PendingContract::SetupRejection => {
                let error = HttpProxy::new("socks5://127.0.0.1:1")
                    .err()
                    .ok_or("injected proxy setup was accepted")?;
                assert_eq!(error.kind(), ProxyConfigErrorKind::UnsupportedScheme);
                setup_error = Some(error);
            }
            PendingContract::ExplicitAbort => backup.abort_origin()?,
        }

        drop(peers.take());

        timeout(
            OBSERVATION_LIMIT,
            backup.destroyed.wait_for(|destroyed| *destroyed),
        )
        .await
        .map_err(OriginDropDeadline)??;

        let closed = timeout(OBSERVATION_LIMIT, stream.get_mut().read(&mut [0_u8; 1])).await?;
        assert!(
            matches!(closed, Ok(0))
                || matches!(closed, Err(ref error) if tls_support::is_peer_gone(error))
        );

        let rebound = TcpListener::bind(address).await?;
        assert_eq!(rebound.local_addr()?, address);
        Ok(())
    }
    .await;

    drop(peers.take());
    let primary = match (primary, setup_error) {
        (Err(error), Some(setup)) => finish_with_cleanup(Err(setup.into()), Err(error)),
        (result, _) => result,
    };

    let cleanup = backup.stop().await;
    drop(client);

    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn setup_rejection_closes_the_actual_pending_origin_before_backup() -> TestResult<()> {
    pending_origin(PendingContract::SetupRejection).await
}

#[tokio::test]
async fn explicitly_aborting_the_actual_pending_origin_closes_its_socket() -> TestResult<()> {
    pending_origin(PendingContract::ExplicitAbort).await
}

#[derive(Debug)]
struct OriginFailure(Arc<()>);

#[derive(Debug)]
struct ProxyFailure(Arc<()>);

impl fmt::Display for OriginFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("completed origin fault")
    }
}

impl fmt::Display for ProxyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("completed proxy fault")
    }
}

impl Error for OriginFailure {}
impl Error for ProxyFailure {}

#[tokio::test]
async fn finish_retains_both_actual_completed_peer_failures() -> TestResult<()> {
    let origin_identity = Arc::new(());
    let proxy_identity = Arc::new(());
    let (mut backup, controls) = Backup::prepare(
        Some(io::Error::new(
            io::ErrorKind::PermissionDenied,
            OriginFailure(Arc::clone(&origin_identity)),
        )),
        Some(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            ProxyFailure(Arc::clone(&proxy_identity)),
        )),
    );
    let mut peers = None;

    let primary: TestResult<()> = async {
        let identity = TestIdentity::generate()?;
        peers = Some(ProxyAuthPeers::start_origin(&identity, Some(controls)).await?);
        let peers_ref = peers.as_mut().ok_or("peer owner was not retained")?;
        backup.acquired(peers_ref);
        let address = peers_ref.origin_address;
        let proxy_address = peers_ref.start_proxy().await?;
        backup.acquired(peers_ref);

        let route = Route::http_proxy(
            HttpProxy::new(&format!("http://{proxy_address}"))?
                .with_basic_auth("alice", "secret")?,
        );
        let session = client_builder(&identity, false).route(route).build()?;

        for path in ["first", "second"] {
            let request = session
                .get_with_protocol(HttpProtocol::Http1, &format!("https://{address}/{path}"))?;
            let response = timeout(BACKUP_LIMIT, request.send()).await??;
            assert_eq!(response.status(), 204);
            timeout(BACKUP_LIMIT, response.into_body().collect()).await??;
        }
        drop(session);

        timeout(BACKUP_LIMIT, async {
            while !peers_ref
                .origin
                .as_ref()
                .ok_or("origin handle missing")?
                .is_finished()
                || !peers_ref
                    .proxy
                    .as_ref()
                    .ok_or("proxy handle missing")?
                    .is_finished()
            {
                tokio::task::yield_now().await;
            }

            TestResult::Ok(())
        })
        .await??;

        assert!(*backup.origin_fault.borrow());
        assert!(*backup.proxy_fault.borrow());

        let target = peers.take().ok_or("peer owner missing")?.finish().await;
        let oracle: TestResult<()> = (|| {
            let error = target
                .as_ref()
                .err()
                .ok_or("both completed peer failures were discarded")?;
            let failures = error
                .downcast_ref::<FixtureFailures>()
                .ok_or("proxy-auth finish discarded its completed origin failure")?;
            let proxy = failures
                .primary
                .downcast_ref::<io::Error>()
                .ok_or("proxy I/O cause lost")?;
            let origin = failures
                .cleanup
                .downcast_ref::<io::Error>()
                .ok_or("origin I/O cause lost")?;
            assert_eq!(proxy.kind(), io::ErrorKind::ConnectionRefused);
            assert_eq!(origin.kind(), io::ErrorKind::PermissionDenied);
            let proxy = proxy
                .get_ref()
                .and_then(|error| error.downcast_ref::<ProxyFailure>())
                .ok_or("proxy marker lost")?;
            let origin = origin
                .get_ref()
                .and_then(|error| error.downcast_ref::<OriginFailure>())
                .ok_or("origin marker lost")?;
            assert!(Arc::ptr_eq(&proxy.0, &proxy_identity));
            assert!(Arc::ptr_eq(&origin.0, &origin_identity));

            Ok(())
        })();

        match oracle {
            Ok(()) => Ok(()),
            Err(error) => finish_with_cleanup(target, Err(error)),
        }
    }
    .await;

    drop(peers.take());
    let cleanup = backup.stop().await;

    finish_with_cleanup(primary, cleanup)
}
