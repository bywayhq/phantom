use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use btls::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use phantom::{HttpProtocol, RequestError, RequestErrorKind, RequestHeader};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf},
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
    task::{AbortHandle, JoinError},
    time::{error::Elapsed, timeout},
};
use tokio_btls::SslStream;

use super::{H1_ALPN, Observed, Server, TestIdentity, TestResult, read_head};
use crate::support::{
    tls::is_peer_gone,
    tunnel_proxy::{ConnectionPeer, connection_peer::FixtureFailures, finish_with_cleanup},
};

const CONTROL_LIMIT: Duration = Duration::from_secs(5);
const DROP_LIMIT: Duration = Duration::from_secs(1);
const HEAD_BOUND: usize = 32 * 1024;
const REPLY: &[u8] = b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n";

#[derive(Clone, Default)]
pub(super) struct Snapshot {
    address: Option<SocketAddr>,
    abort: Option<AbortHandle>,
    head_bytes: usize,
    head_pending: bool,
    head_failure: Option<(io::ErrorKind, String)>,
    destroyed: bool,
    joined: bool,
    transfer_failed: bool,
}

pub(super) type Signals = watch::Sender<Snapshot>;

pub(super) struct Observation {
    signals: Signals,
    transfer: Option<oneshot::Sender<Server>>,
}

impl Observation {
    pub(super) fn signals(&self) -> Signals {
        self.signals.clone()
    }
}

struct WorkerLifetime(Signals);

impl Drop for WorkerLifetime {
    fn drop(&mut self) {
        self.0.send_modify(|value| value.destroyed = true);
    }
}

pub(super) fn spawn_worker(
    future: impl Future<Output = TestResult<Observed>> + Send + 'static,
    observation: Option<Signals>,
    address: SocketAddr,
) -> Server {
    let Some(signals) = observation else {
        return tokio::spawn(future);
    };

    let lifetime = WorkerLifetime(signals.clone());
    let task = tokio::spawn(async move {
        let _lifetime = lifetime;
        future.await
    });

    signals.send_modify(|value| {
        value.address = Some(address);
        value.abort = Some(task.abort_handle());
    });

    task
}

struct HeadRead<'a> {
    stream: &'a mut SslStream<TcpStream>,
    signals: Signals,
}

impl AsyncRead for HeadRead<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut *this.stream).poll_read(context, buffer);
        if matches!(result, Poll::Ready(Ok(()))) {
            let bytes = buffer.filled().len() - before;
            this.signals.send_modify(|value| value.head_bytes += bytes);
        }

        result
    }
}

pub(super) async fn observe_head(
    stream: &mut SslStream<TcpStream>,
    observation: Option<Signals>,
) -> io::Result<Vec<u8>> {
    let Some(signals) = observation else {
        return read_head(stream).await;
    };

    let mut reader = HeadRead {
        stream,
        signals: signals.clone(),
    };
    let mut future = Box::pin(read_head(&mut reader));
    poll_fn(|context| {
        let result = future.as_mut().poll(context);
        match &result {
            Poll::Pending => {
                signals.send_modify(|value| {
                    if value.head_bytes != 0 {
                        value.head_pending = true;
                    }
                });
            }
            Poll::Ready(Err(error)) => {
                signals.send_modify(|value| {
                    value.head_failure = Some((error.kind(), error.to_string()));
                });
            }
            Poll::Ready(Ok(_)) => {}
        }

        result
    })
    .await
}

pub(super) struct ObservedServer {
    task: Option<Server>,
    observation: Option<Observation>,
}

pub(super) fn adopt(task: Server, observation: Option<Observation>) -> ObservedServer {
    if let Some(value) = &observation {
        value
            .signals
            .send_modify(|snapshot| snapshot.abort = Some(task.abort_handle()));
    }

    ObservedServer {
        task: Some(task),
        observation,
    }
}

impl Drop for ObservedServer {
    fn drop(&mut self) {
        let Some(task) = self.task.take() else {
            return;
        };
        let Some(observation) = self.observation.as_mut() else {
            return;
        };
        if let Some(sender) = observation.transfer.take()
            && let Err(task) = sender.send(task)
        {
            task.abort();
            observation
                .signals
                .send_modify(|value| value.transfer_failed = true);
        }
    }
}

impl Future for ObservedServer {
    type Output = Result<TestResult<Observed>, JoinError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();
        let Some(task) = this.task.as_mut() else {
            return Poll::Ready(Ok(Err(ObservationFailure::PolledAfterCompletion.into())));
        };
        let result = Pin::new(task).poll(context);
        if result.is_ready() {
            drop(this.task.take());
            if let Some(value) = &this.observation {
                value.signals.send_modify(|snapshot| snapshot.joined = true);
            }
        }

        result
    }
}

#[derive(Debug, thiserror::Error)]
enum ObservationFailure {
    #[error("template observation transfer failed")]
    Transfer,
    #[error("template observation did not transfer its original worker")]
    MissingWorker,
    #[error("template worker join was polled after completion")]
    PolledAfterCompletion,
    #[error("template origin Drop did not destroy its actual pending worker")]
    OriginDropDeadline(#[source] Elapsed),
}

struct Backup {
    state: watch::Receiver<Snapshot>,
    transfer: Option<oneshot::Receiver<Server>>,
    server: Option<ObservedServer>,
    client: Option<SslStream<TcpStream>>,
}

impl Drop for Backup {
    fn drop(&mut self) {
        if let Some(abort) = self.state.borrow().abort.as_ref() {
            abort.abort();
        }
    }
}

impl Backup {
    fn prepare() -> (Self, Observation) {
        let (signals, state) = watch::channel(Snapshot::default());
        let (sender, receiver) = oneshot::channel();
        let observation = Observation {
            signals,
            transfer: Some(sender),
        };
        let backup = Self {
            state,
            transfer: Some(receiver),
            server: None,
            client: None,
        };

        (backup, observation)
    }

    fn snapshot(&self) -> TestResult<Snapshot> {
        let value = self.state.borrow().clone();
        if value.transfer_failed {
            return Err(ObservationFailure::Transfer.into());
        }

        Ok(value)
    }

    async fn wait_for(&mut self, predicate: impl FnMut(&Snapshot) -> bool) -> TestResult<()> {
        timeout(CONTROL_LIMIT, async {
            self.state.wait_for(predicate).await.map(|_| ())
        })
        .await??;

        self.snapshot()?;
        Ok(())
    }

    async fn destroyed(&mut self) -> TestResult<()> {
        timeout(DROP_LIMIT, async {
            self.state.wait_for(|value| value.destroyed).await.map(|_| ())
        })
        .await
        .map_err(ObservationFailure::OriginDropDeadline)??;

        self.snapshot()?;
        Ok(())
    }

    async fn completed(&mut self) -> TestResult<()> {
        self.wait_for(|value| value.destroyed).await?;

        let abort = self
            .snapshot()?
            .abort
            .ok_or(ObservationFailure::MissingWorker)?;
        timeout(CONTROL_LIMIT, async {
            while !abort.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        Ok(())
    }

    async fn connect(&mut self, observation: Observation) -> TestResult<()> {
        let identity = TestIdentity::generate()?;
        let mut connector = SslConnector::bare_builder(SslMethod::tls())?;
        connector.set_verify(SslVerifyMode::PEER);
        connector
            .cert_store_mut()
            .add_cert(X509::from_der(&identity.root_der)?)?;
        connector.set_alpn_protos(H1_ALPN)?;
        let ssl = connector.build().configure()?.into_ssl("127.0.0.1")?;

        let (url, task) =
            super::serve_http1_observed(&identity, Some(observation.signals())).await?;
        self.server = Some(adopt(task, Some(observation)));

        let uri: http::Uri = url.parse()?;
        let address: SocketAddr = uri
            .authority()
            .ok_or("template origin URL has no authority")?
            .as_str()
            .parse()?;
        let tcp = timeout(CONTROL_LIMIT, TcpStream::connect(address)).await??;
        self.client = Some(SslStream::new(ssl, tcp)?);
        let stream = self.client()?;
        timeout(CONTROL_LIMIT, Pin::new(&mut *stream).connect()).await??;

        if stream.ssl().selected_alpn_protocol() != Some(&b"http/1.1"[..]) {
            return Err("template control did not authenticate HTTP/1.1".into());
        }

        Ok(())
    }

    fn client(&mut self) -> TestResult<&mut SslStream<TcpStream>> {
        self.client
            .as_mut()
            .ok_or_else(|| "template client was not retained".into())
    }

    async fn partial_head(&mut self) -> TestResult<()> {
        let stream = self.client()?;
        timeout(CONTROL_LIMIT, async {
            stream
                .write_all(b"GET /pending HTTP/1.1\r\nHost: localhost\r\n")
                .await?;
            stream.flush().await
        })
        .await??;

        self.wait_for(|value| value.head_pending && value.head_bytes != 0)
            .await
    }

    async fn closed(&mut self) -> TestResult<()> {
        let closed = timeout(CONTROL_LIMIT, self.client()?.read(&mut [0_u8; 1])).await?;
        match closed {
            Ok(0) => {}
            Err(error) if is_peer_gone(&error) => {}
            Err(error) => return Err(error.into()),
            Ok(_) => return Err("template origin sent an unexpected byte after shutdown".into()),
        }

        self.rebind().await
    }

    async fn rebind(&self) -> TestResult<()> {
        let address = self
            .snapshot()?
            .address
            .ok_or("template origin address was not retained")?;
        let listener = timeout(CONTROL_LIMIT, TcpListener::bind(address)).await??;
        if listener.local_addr()? != address {
            return Err("template origin listener did not release its original address".into());
        }

        Ok(())
    }

    async fn finish(mut self) -> TestResult<()> {
        drop(self.server.take());
        let snapshot = self.state.borrow().clone();
        let observation = if snapshot.transfer_failed {
            Err(ObservationFailure::Transfer.into())
        } else {
            Ok(())
        };
        let cleanup: TestResult<()> = async {
            if snapshot.abort.is_none() || snapshot.joined {
                return Ok(());
            }

            let receiver = self
                .transfer
                .as_mut()
                .ok_or(ObservationFailure::MissingWorker)?;
            let task = timeout(CONTROL_LIMIT, receiver).await??;
            let mut peer = ConnectionPeer::from_task(task);
            let requested_stop = !peer.is_finished();
            if requested_stop {
                peer.abort();
            }

            match timeout(CONTROL_LIMIT, &mut peer).await {
                Ok(Ok(result)) => result.map(|_| ()),
                Ok(Err(error)) if requested_stop && error.is_cancelled() => Ok(()),
                Ok(Err(error)) => Err(error.into()),
                Err(error) => Err(error.into()),
            }
        }
        .await;

        drop(self.client.take());
        finish_with_cleanup(observation, cleanup)
    }
}

#[derive(Debug)]
struct SetupFailure(Arc<()>);

impl fmt::Display for SetupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("injected template caller setup rejection")
    }
}

impl Error for SetupFailure {}

fn setup_identity(target: &TestResult<Observed>, identity: &Arc<()>) -> TestResult<()> {
    let error = target
        .as_ref()
        .err()
        .ok_or("template caller accepted injected setup rejection")?;
    let failure = error
        .downcast_ref::<SetupFailure>()
        .ok_or("template caller replaced its setup failure")?;
    if !Arc::ptr_eq(&failure.0, identity) {
        return Err("template caller replaced its original setup identity".into());
    }

    Ok(())
}

fn evidence(target: TestResult<Observed>, oracle: TestResult<()>) -> TestResult<()> {
    match oracle {
        Ok(()) => Ok(()),
        Err(error) => finish_with_cleanup(target.map(|_| ()), Err(error)),
    }
}

#[tokio::test]
async fn template_origin_drop_closes_its_actual_pending_head() -> TestResult<()> {
    let (mut backup, observation) = Backup::prepare();
    let primary: TestResult<()> = async {
        backup.connect(observation).await?;
        backup.partial_head().await?;
        let before = backup.snapshot()?;
        if before.destroyed || before.abort.as_ref().is_none_or(AbortHandle::is_finished) {
            return Err("template worker ended before the Drop target".into());
        }

        drop(backup.server.take());
        backup.destroyed().await?;
        backup.closed().await
    }
    .await;

    finish_with_cleanup(primary, backup.finish().await)
}

#[tokio::test]
async fn explicit_template_worker_abort_closes_its_actual_pending_head() -> TestResult<()> {
    let (mut backup, observation) = Backup::prepare();
    let primary: TestResult<()> = async {
        backup.connect(observation).await?;
        backup.partial_head().await?;
        let abort = backup
            .snapshot()?
            .abort
            .ok_or(ObservationFailure::MissingWorker)?;
        if abort.is_finished() {
            return Err("template worker ended before explicit abort".into());
        }

        abort.abort();
        let server = backup
            .server
            .take()
            .ok_or(ObservationFailure::MissingWorker)?;
        let joined = timeout(CONTROL_LIMIT, server).await?;
        match joined {
            Err(error) if error.is_cancelled() && error.id() == abort.id() => {}
            Err(error) => return Err(error.into()),
            Ok(Err(error)) => return Err(error),
            Ok(Ok(_)) => {
                return Err(
                    "template explicit abort did not return its original cancelled join".into(),
                );
            }
        }

        backup.destroyed().await?;
        backup.closed().await
    }
    .await;

    finish_with_cleanup(primary, backup.finish().await)
}

#[tokio::test]
async fn template_origin_completes_a_trusted_literal_request() -> TestResult<()> {
    let (mut backup, observation) = Backup::prepare();
    let primary: TestResult<()> = async {
        backup.connect(observation).await?;
        let stream = backup.client()?;
        timeout(CONTROL_LIMIT, async {
            stream
                .write_all(b"GET /healthy HTTP/1.1\r\nHost: localhost\r\nX-Probe: literal\r\n\r\n")
                .await?;
            stream.flush().await
        })
        .await??;
        let response = timeout(CONTROL_LIMIT, read_head(stream)).await??;
        if response != REPLY {
            return Err("template origin did not deliver the literal 204 response".into());
        }

        let server = backup
            .server
            .take()
            .ok_or(ObservationFailure::MissingWorker)?;
        let observed = timeout(CONTROL_LIMIT, server).await???;
        if observed.fields != vec![("X-Probe".to_owned(), "literal".to_owned())]
            || observed.priority.is_some()
        {
            return Err("template origin did not preserve the literal request fields".into());
        }

        backup.destroyed().await?;
        backup.closed().await
    }
    .await;

    finish_with_cleanup(primary, backup.finish().await)
}

#[tokio::test]
async fn send_with_setup_rejection_stops_its_acquired_origin() -> TestResult<()> {
    let (mut backup, observation) = Backup::prepare();
    let identity = Arc::new(());
    let injected = Arc::clone(&identity);
    let target = timeout(
        CONTROL_LIMIT,
        super::send_with_observed(
            &super::firefox(),
            phantom::profile::RequestTemplate {
                http1_fields: Vec::new(),
                http2_fields: Vec::new(),
                http3_fields: None,
                http2_priority: None,
                requested_client_hint_placement: false,
                restarts_for_connection_accept_ch: false,
            },
            HttpProtocol::Http1,
            Vec::new(),
            phantom::profile::CookiePlacement::last(),
            move |_, _| Err(Box::new(SetupFailure(injected))),
            Some(observation),
        ),
    )
    .await;
    let primary: TestResult<()> = async {
        let target = target?;
        let oracle: TestResult<()> = async {
            setup_identity(&target, &identity)?;
            let acquired = backup.snapshot()?;
            if acquired.address.is_none() || acquired.abort.is_none() {
                return Err("setup rejection did not acquire the original template worker".into());
            }

            backup.destroyed().await?;
            backup.completed().await?;
            backup.rebind().await
        }
        .await;

        evidence(target, oracle)
    }
    .await;

    finish_with_cleanup(primary, backup.finish().await)
}

#[tokio::test]
async fn default_observe_setup_rejection_stops_its_acquired_origin() -> TestResult<()> {
    let (mut backup, observation) = Backup::prepare();
    let identity = Arc::new(());
    let injected = Arc::clone(&identity);
    let target = timeout(
        CONTROL_LIMIT,
        super::default_profile::observe_with_owner(
            HttpProtocol::Http1,
            false,
            move |_| Err(Box::new(SetupFailure(injected))),
            Some(observation),
        ),
    )
    .await;
    let primary: TestResult<()> = async {
        let target = target?;
        let oracle: TestResult<()> = async {
            setup_identity(&target, &identity)?;
            let acquired = backup.snapshot()?;
            if acquired.address.is_none() || acquired.abort.is_none() {
                return Err("setup rejection did not acquire the original template worker".into());
            }

            backup.destroyed().await?;
            backup.completed().await?;
            backup.rebind().await
        }
        .await;

        evidence(target, oracle)
    }
    .await;

    finish_with_cleanup(primary, backup.finish().await)
}

#[tokio::test]
async fn default_observe_keeps_real_caller_and_completed_worker_causes() -> TestResult<()> {
    let (mut backup, observation) = Backup::prepare();
    let target = timeout(
        CONTROL_LIMIT,
        super::default_profile::observe_with_owner(
            HttpProtocol::Http1,
            false,
            |request| {
                Ok(request
                    .without_template()
                    .header(RequestHeader::new("X-Large", vec![b'x'; HEAD_BOUND - 32])))
            },
            Some(observation),
        ),
    )
    .await;
    let primary: TestResult<()> = async {
        let target = target?;
        let oracle: TestResult<()> = async {
            backup.wait_for(|value| value.head_failure.is_some()).await?;
            let before = backup.snapshot()?;
            if before.head_bytes != HEAD_BOUND
                || before.head_failure
                    != Some((
                        io::ErrorKind::InvalidData,
                        "request head exceeded test bound".to_owned(),
                    ))
            {
                return Err("legal caller header did not reach the actual reader bound".into());
            }

            backup.completed().await?;
            backup.rebind().await?;

            let error = target
                .as_ref()
                .err()
                .ok_or("oversized template request unexpectedly succeeded")?;
            let caller = if let Some(caller) = error.downcast_ref::<RequestError>() {
                caller
            } else {
                error
                    .downcast_ref::<FixtureFailures>()
                    .and_then(|causes| causes.primary.downcast_ref::<RequestError>())
                    .ok_or("template completion replaced the original caller error")?
            };
            if caller.kind() != RequestErrorKind::Http1 {
                return Err("template completion returned the wrong caller failure category".into());
            }

            let causes = error
                .downcast_ref::<FixtureFailures>()
                .ok_or("template caller discarded its completed origin error")?;
            let worker = causes
                .cleanup
                .downcast_ref::<io::Error>()
                .ok_or("template completion replaced the original worker I/O error")?;
            if worker.kind() != io::ErrorKind::InvalidData
                || worker.to_string() != "request head exceeded test bound"
            {
                return Err("template completion changed its actual reader-bound failure".into());
            }

            Ok(())
        }
        .await;

        evidence(target, oracle)
    }
    .await;

    finish_with_cleanup(primary, backup.finish().await)
}
