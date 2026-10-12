use std::{
    error::Error, fmt, future::poll_fn, io, net::SocketAddr, sync::Arc, task::Poll, time::Duration,
};

use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode, Uri, Version};
use phantom::{HttpProtocol, RequestError, RequestErrorKind};
use phantom_net::http3::{Http3Error, Http3ErrorKind};
use rustls::pki_types::CertificateDer;
use tokio::{
    net::UdpSocket,
    sync::{oneshot, watch},
    task::{AbortHandle, Id, JoinError},
    time::{error::Elapsed, timeout},
};

use super::{ORIGIN_NAME, Observed, QuicOrigin, TEST_ECH_KEYS, origin_identity};
use crate::support::{
    tls::{TestIdentity, TestResult},
    tunnel_proxy::connection_peer::{FixtureFailures, finish_with_cleanup},
};

const DEADLINE: Duration = Duration::from_secs(5);
const DESTRUCTION: Duration = Duration::from_secs(2);
const INTERNAL_ERROR: u32 = 0x102;

type Driver = h3::client::Connection<h3_quinn::Connection, Bytes>;
type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

#[derive(Debug)]
struct PendingHandshakeFinishDeadline(Elapsed);

impl fmt::Display for PendingHandshakeFinishDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QUIC origin finish exceeded its pending-handshake deadline")
    }
}

impl Error for PendingHandshakeFinishDeadline {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

pub(super) struct TaskObservation {
    pub(super) started: watch::Sender<Option<AbortHandle>>,
    destroyed: watch::Sender<bool>,
}

impl TaskObservation {
    fn new() -> (Self, TaskControl) {
        let started = watch::Sender::new(None);
        let (destroyed, receiver) = watch::channel(false);
        (
            Self {
                started: started.clone(),
                destroyed,
            },
            TaskControl {
                started,
                destroyed: receiver,
            },
        )
    }
}

impl Drop for TaskObservation {
    fn drop(&mut self) {
        self.destroyed.send_replace(true);
    }
}

pub(super) struct OriginObservation {
    pub(super) parent: TaskObservation,
    pub(super) child: Vec<ServingObservation>,
    pub(super) handshake: Option<oneshot::Sender<()>>,
}

pub(super) struct ServingObservation {
    pub(super) task: TaskObservation,
    pending: Option<oneshot::Sender<()>>,
    request: Option<oneshot::Sender<RequestSeen>>,
    outcome: Option<oneshot::Sender<Option<h3::error::ConnectionError>>>,
    pub(super) reset_response: bool,
    stream_outcome: Option<oneshot::Sender<bool>>,
}

impl ServingObservation {
    pub(super) fn record_outcome(&mut self, result: &TestResult<()>) -> TestResult<()> {
        let error = result
            .as_ref()
            .err()
            .and_then(|error| error.downcast_ref::<h3::error::ConnectionError>())
            .cloned();
        if let Some(sender) = self.outcome.take() {
            sender.send(error).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "serving outcome observer closed")
            })?;
        }

        if let Some(sender) = self.stream_outcome.take() {
            let closed = result
                .as_ref()
                .err()
                .is_some_and(|error| closed_stream(error.as_ref()));
            sender.send(closed).map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "stream outcome observer closed")
            })?;
        }

        Ok(())
    }

    pub(super) fn record_request(&mut self, request: &Request<()>) -> TestResult<()> {
        if let Some(sender) = self.request.take() {
            sender
                .send(RequestSeen {
                    method: request.method().clone(),
                    uri: request.uri().clone(),
                    version: request.version(),
                })
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "request observer closed")
                })?;
        }

        Ok(())
    }
}

pub(super) async fn observe_accept<T>(
    accept: impl Future<Output = Result<T, h3::error::ConnectionError>>,
    observation: Option<&mut ServingObservation>,
) -> TestResult<T> {
    let Some(observation) = observation else {
        return accept.await.map_err(Into::into);
    };

    let mut accept = Box::pin(accept);
    let mut pending = observation.pending.take();
    poll_fn(|context| {
        let result = accept.as_mut().poll(context);
        if result.is_pending()
            && let Some(sender) = pending.take()
            && sender.send(()).is_err()
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "H3 accept observer closed",
            )
            .into()));
        }

        result.map_err(Into::into)
    })
    .await
}

pub(super) async fn observe_connecting(
    connecting: quinn::Connecting,
    mut pending: Option<oneshot::Sender<()>>,
) -> TestResult<Result<quinn::Connection, quinn::ConnectionError>> {
    if pending.is_none() {
        return Ok(connecting.await);
    }

    let mut connecting = Box::pin(connecting);
    poll_fn(|context| {
        let result = connecting.as_mut().poll(context);
        if result.is_pending()
            && let Some(sender) = pending.take()
            && sender.send(()).is_err()
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "QUIC handshake observer closed",
            )
            .into()));
        }

        result.map(Ok)
    })
    .await
}

struct RequestSeen {
    method: Method,
    uri: Uri,
    version: Version,
}

struct TaskControl {
    started: watch::Sender<Option<AbortHandle>>,
    destroyed: watch::Receiver<bool>,
}

impl TaskControl {
    fn handle(&self) -> TestResult<AbortHandle> {
        self.started
            .borrow()
            .clone()
            .ok_or_else(|| "actual QUIC fixture task was not published".into())
    }

    async fn finished(&mut self) -> TestResult<()> {
        let handle = self.handle()?;
        timeout(DESTRUCTION, async {
            self.destroyed.wait_for(|destroyed| *destroyed).await?;
            while !handle.is_finished() {
                tokio::task::yield_now().await;
            }

            Ok::<_, watch::error::RecvError>(())
        })
        .await??;

        Ok(())
    }
}

struct Backup {
    parent: TaskControl,
    child: TaskControl,
    server: Option<quinn::Endpoint>,
    peer: Option<quinn::Endpoint>,
    outcome: Option<oneshot::Receiver<Option<h3::error::ConnectionError>>>,
    bridge: Option<UdpSocket>,
    additional_children: Vec<TaskControl>,
    additional_peers: Vec<quinn::Endpoint>,
}

impl Backup {
    fn new() -> (
        Self,
        OriginObservation,
        oneshot::Receiver<()>,
        oneshot::Receiver<RequestSeen>,
    ) {
        let (parent, parent_control) = TaskObservation::new();
        let (task, child_control) = TaskObservation::new();
        let (pending, pending_receiver) = oneshot::channel();
        let (request, request_receiver) = oneshot::channel();
        let (outcome, outcome_receiver) = oneshot::channel();
        (
            Self {
                parent: parent_control,
                child: child_control,
                server: None,
                peer: None,
                outcome: Some(outcome_receiver),
                bridge: None,
                additional_children: Vec::new(),
                additional_peers: Vec::new(),
            },
            OriginObservation {
                parent,
                child: vec![ServingObservation {
                    task,
                    pending: Some(pending),
                    request: Some(request),
                    outcome: Some(outcome),
                    reset_response: false,
                    stream_outcome: None,
                }],
                handshake: None,
            },
            pending_receiver,
            request_receiver,
        )
    }

    fn add_child(
        &mut self,
        observation: &mut OriginObservation,
    ) -> (
        oneshot::Receiver<()>,
        oneshot::Receiver<RequestSeen>,
        oneshot::Receiver<Option<h3::error::ConnectionError>>,
    ) {
        let (task, control) = TaskObservation::new();
        let (pending, pending_receiver) = oneshot::channel();
        let (request, request_receiver) = oneshot::channel();
        let (outcome, outcome_receiver) = oneshot::channel();
        self.additional_children.push(control);
        observation.child.push(ServingObservation {
            task,
            pending: Some(pending),
            request: Some(request),
            outcome: Some(outcome),
            reset_response: false,
            stream_outcome: None,
        });

        (pending_receiver, request_receiver, outcome_receiver)
    }

    fn spawn(
        &mut self,
        identity: &TestIdentity,
        observation: OriginObservation,
    ) -> TestResult<QuicOrigin> {
        let context = QuicOrigin::context(identity, 1, &TEST_ECH_KEYS[0])?;
        let endpoint = QuicOrigin::endpoint(&context, 0)?;
        let port = endpoint.local_addr()?.port();
        self.server = Some(endpoint.clone());

        Ok(QuicOrigin::start_serving_observed(
            endpoint,
            port,
            context,
            None,
            None,
            Some(observation),
        ))
    }

    async fn stop(&mut self) -> TestResult<()> {
        let mut outcome = Ok(());
        if let Ok(handle) = self.parent.handle() {
            handle.abort();
            outcome = finish_with_cleanup(outcome, self.parent.finished().await);
        }

        // Re-read after parent destruction: publication precedes its next await.
        if let Ok(handle) = self.child.handle() {
            handle.abort();
            outcome = finish_with_cleanup(outcome, self.child.finished().await);
        }
        for child in &mut self.additional_children {
            if let Ok(handle) = child.handle() {
                handle.abort();
                outcome = finish_with_cleanup(outcome, child.finished().await);
            }
        }

        for endpoint in [&self.server, &self.peer]
            .into_iter()
            .flatten()
            .chain(&self.additional_peers)
        {
            endpoint.close(0_u32.into(), b"QUIC owner control complete");
        }
        for endpoint in [&self.server, &self.peer]
            .into_iter()
            .flatten()
            .chain(&self.additional_peers)
        {
            outcome = finish_with_cleanup(
                outcome,
                timeout(DEADLINE, endpoint.wait_idle())
                    .await
                    .map_err(Into::into),
            );
        }

        drop(self.bridge.take());

        outcome
    }
}

impl Drop for Backup {
    fn drop(&mut self) {
        // Drop requests closure; explicit stop observes destruction and idle.
        for task in [&self.parent, &self.child]
            .into_iter()
            .chain(&self.additional_children)
        {
            if let Ok(handle) = task.handle() {
                handle.abort();
            }
        }
        for endpoint in [&self.server, &self.peer]
            .into_iter()
            .flatten()
            .chain(&self.additional_peers)
        {
            endpoint.close(0_u32.into(), b"QUIC owner control dropped");
        }
    }
}

struct Peer {
    connection: quinn::Connection,
    driver: Driver,
    send: Sender,
}

impl Peer {
    async fn connect(
        backup: &mut Backup,
        identity: &TestIdentity,
        origin: &QuicOrigin,
        pending: oneshot::Receiver<()>,
    ) -> TestResult<Self> {
        let endpoint = client_endpoint(identity)?;
        if backup.peer.is_none() {
            backup.peer = Some(endpoint.clone());
        } else {
            backup.additional_peers.push(endpoint.clone());
        }
        let address = SocketAddr::from(([127, 0, 0, 1], origin.port));
        let connection = timeout(DEADLINE, endpoint.connect(address, ORIGIN_NAME)?).await??;
        let (mut driver, send) = timeout(
            DEADLINE,
            h3::client::new(h3_quinn::Connection::new(connection.clone())),
        )
        .await??;

        // No application settings are supplied: readiness requires decoded peer SETTINGS.
        let mut settings = send.peer_settings();
        drive(&mut driver, async {
            settings.ready().await?;
            pending.await?;
            Ok(())
        })
        .await?;

        if backup.child.handle()?.is_finished() || *backup.child.destroyed.borrow() {
            return Err("H3 serving child ended before the held request observation".into());
        }

        Ok(Self {
            connection,
            driver,
            send,
        })
    }
}

async fn drive<T>(
    driver: &mut Driver,
    operation: impl Future<Output = TestResult<T>>,
) -> TestResult<T> {
    timeout(DEADLINE, async {
        tokio::select! {
            result = operation => result,
            error = poll_fn(|context| driver.poll_close(context)) => Err(error.into()),
        }
    })
    .await?
}

fn client_endpoint(identity: &TestIdentity) -> TestResult<quinn::Endpoint> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(identity.root_der.clone()))?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        phantom_testkit::udp::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?,
        Arc::new(quinn::TokioRuntime),
    )?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));

    Ok(endpoint)
}

fn assert_observed(observed: &[Observed]) {
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].outer_server_name.as_deref(), Some(ORIGIN_NAME));
    assert_eq!(observed[0].server_name.as_deref(), Some(ORIGIN_NAME));
    assert_eq!(observed[0].closed_with, None);
}

fn remote_code(error: &h3::error::ConnectionError) -> Option<u64> {
    match error {
        h3::error::ConnectionError::Remote(
            h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code },
        ) => Some(*error_code),
        _ => None,
    }
}

fn collect_remote_codes(
    mut error: &(dyn std::error::Error + 'static),
    codes: &mut Vec<u64>,
) -> TestResult<()> {
    loop {
        if let Some(failures) = error.downcast_ref::<FixtureFailures>() {
            collect_remote_codes(failures.primary.as_ref(), codes)?;
            collect_remote_codes(failures.cleanup.as_ref(), codes)?;
            return Ok(());
        }

        if let Some(error) = error.downcast_ref::<h3::error::ConnectionError>() {
            codes.push(
                remote_code(error).ok_or("serving failure was not a remote application close")?,
            );
            return Ok(());
        }

        error = error
            .source()
            .ok_or("QUIC finish omitted an actual typed serving failure")?;
    }
}

fn closed_stream(error: &(dyn Error + 'static)) -> bool {
    matches!(
        error.downcast_ref::<h3::error::StreamError>(),
        Some(h3::error::StreamError::Undefined(cause))
            if matches!(cause.downcast_ref::<quinn::WriteError>(), Some(quinn::WriteError::ClosedStream))
    )
}

fn request_reset(mut error: &(dyn Error + 'static)) -> TestResult<()> {
    let request = error
        .downcast_ref::<RequestError>()
        .ok_or("actual request failure omitted RequestError")?;
    if request.kind() != RequestErrorKind::Http3 {
        return Err("actual reset request failed outside HTTP/3".into());
    }

    let mut protocol_seen = false;
    loop {
        if let Some(protocol) = error.downcast_ref::<Http3Error>() {
            if protocol.kind() != Http3ErrorKind::Protocol {
                return Err("actual reset request lost its protocol category".into());
            }

            protocol_seen = true;
        }

        if let Some(stream) = error.downcast_ref::<h3::error::StreamError>() {
            if !protocol_seen {
                return Err("actual reset request omitted its concrete protocol error".into());
            }

            return match stream {
                h3::error::StreamError::RemoteTerminate { code, .. }
                    if *code == h3::error::Code::H3_INTERNAL_ERROR =>
                {
                    Ok(())
                }
                h3::error::StreamError::ConnectionError(cause)
                    if remote_code(cause) == Some(0x100) =>
                {
                    Ok(())
                }
                _ => Err("actual reset request returned an unrelated H3 failure".into()),
            };
        }

        error = error
            .source()
            .ok_or("actual reset request omitted its typed H3 cause")?;
    }
}

fn contains_closed_stream(error: &(dyn Error + 'static)) -> bool {
    if let Some(failures) = error.downcast_ref::<FixtureFailures>() {
        return contains_closed_stream(failures.primary.as_ref())
            || contains_closed_stream(failures.cleanup.as_ref());
    }

    closed_stream(error) || error.source().is_some_and(contains_closed_stream)
}

fn cancelled_worker_id(mut error: &(dyn Error + 'static)) -> TestResult<Id> {
    loop {
        if let Some(joined) = error.downcast_ref::<JoinError>() {
            if !joined.is_cancelled() {
                return Err("actual worker join did not retain its external cancellation".into());
            }

            return Ok(joined.id());
        }

        error = error
            .source()
            .ok_or("QUIC finish omitted the actual cancelled JoinError")?;
    }
}

#[tokio::test]
async fn a_verified_quic_peer_receives_the_literal_h3_response() -> TestResult<()> {
    let (mut backup, observation, pending, request_seen) = Backup::new();
    let result = async {
        let identity = origin_identity()?;
        let origin = backup.spawn(&identity, observation)?;
        let mut peer = Peer::connect(&mut backup, &identity, &origin, pending).await?;
        let uri = origin.url("/quic-owner?probe=1");
        let request = Request::builder().method(Method::GET).uri(&uri).body(())?;
        let response = drive(&mut peer.driver, async {
            let mut stream = peer.send.send_request(request).await?;
            stream.finish().await?;
            let response = stream.recv_response().await?;
            let mut body = Vec::new();
            while let Some(mut chunk) = stream.recv_data().await? {
                let count = chunk.remaining();
                body.extend_from_slice(&chunk.copy_to_bytes(count));
            }

            Ok((response, body))
        })
        .await?;
        let seen = timeout(DEADLINE, request_seen).await??;
        let (observed, tcp) = timeout(DEADLINE, origin.finish(1, 0)).await??;
        let destroyed = backup.child.finished().await;
        Ok((uri, seen, response, observed, tcp, destroyed, peer))
    }
    .await;
    let (result, _peer) = match result {
        Ok((uri, seen, response, observed, tcp, destroyed, peer)) => (
            destroyed.map(|()| (uri, seen, response, observed, tcp)),
            Some(peer),
        ),
        Err(error) => (Err(error), None),
    };

    let cleanup = backup.stop().await;
    let (uri, seen, (response, body), observed, tcp) = finish_with_cleanup(result, cleanup)?;

    assert_eq!(seen.method, Method::GET);
    assert_eq!(seen.uri.to_string(), uri);
    assert_eq!(seen.version, Version::HTTP_3);
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_3);
    assert_eq!(body, b"ok");
    assert_eq!(tcp, 0);
    assert_observed(&observed);
    Ok(())
}

#[tokio::test]
async fn explicit_quic_finish_destroys_the_pending_h3_handler() -> TestResult<()> {
    let (mut backup, observation, pending, _request_seen) = Backup::new();
    let result = async {
        let identity = origin_identity()?;
        let origin = backup.spawn(&identity, observation)?;
        let peer = Peer::connect(&mut backup, &identity, &origin, pending).await?;
        let (observed, tcp) = timeout(DEADLINE, origin.finish(1, 0)).await??;
        let destroyed = backup.child.finished().await;
        Ok((observed, tcp, destroyed, peer))
    }
    .await;
    let (result, _peer) = match result {
        Ok((observed, tcp, destroyed, peer)) => (destroyed.map(|()| (observed, tcp)), Some(peer)),
        Err(error) => (Err(error), None),
    };

    let cleanup = backup.stop().await;
    let (observed, tcp) = finish_with_cleanup(result, cleanup)?;

    assert_eq!(tcp, 0);
    assert_observed(&observed);
    Ok(())
}

#[tokio::test]
async fn dropping_the_quic_origin_destroys_its_pending_h3_handler() -> TestResult<()> {
    let (mut backup, observation, pending, _request_seen) = Backup::new();
    let result = async {
        let identity = origin_identity()?;
        let origin = backup.spawn(&identity, observation)?;
        let peer = Peer::connect(&mut backup, &identity, &origin, pending).await?;
        drop(origin);
        let destroyed = backup.child.finished().await;
        Ok((destroyed, peer))
    }
    .await;
    let (result, _peer) = match result {
        Ok((destroyed, peer)) => (destroyed, Some(peer)),
        Err(error) => (Err(error), None),
    };

    let cleanup = backup.stop().await;

    finish_with_cleanup(result, cleanup)
}

#[tokio::test]
async fn quic_finish_retains_the_completed_remote_h3_failure() -> TestResult<()> {
    let (mut backup, observation, pending, _request_seen) = Backup::new();
    let result = async {
        let identity = origin_identity()?;
        let origin = backup.spawn(&identity, observation)?;
        let peer = Peer::connect(&mut backup, &identity, &origin, pending).await?;
        peer.connection
            .close(INTERNAL_ERROR.into(), b"owner control remote H3 failure");
        backup.child.finished().await?;
        let actual = timeout(
            DEADLINE,
            backup
                .outcome
                .take()
                .ok_or("serving outcome receiver was already consumed")?,
        )
        .await??
        .ok_or("actual H3 serving result was not a connection error")?;
        if !matches!(
            actual,
            h3::error::ConnectionError::Remote(
                h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code }
            ) if error_code == u64::from(INTERNAL_ERROR)
        ) {
            return Err("actual serving failure was not remote H3_INTERNAL_ERROR".into());
        }

        let outcome = timeout(DEADLINE, origin.finish(1, 0)).await?;
        Ok((outcome, peer))
    }
    .await;
    let (result, _peer) = match result {
        Ok((outcome, peer)) => (Ok(outcome), Some(peer)),
        Err(error) => (Err(error), None),
    };

    let result = result.and_then(|outcome| {
        let error = outcome
            .err()
            .ok_or("QUIC origin discarded its completed remote H3 failure")?;
        let mut cause: &(dyn std::error::Error + 'static) = error.as_ref();
        loop {
            if let Some(h3::error::ConnectionError::Remote(
                h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code },
            )) = cause.downcast_ref::<h3::error::ConnectionError>()
            {
                return Ok(*error_code);
            }

            cause = cause
                .source()
                .ok_or("QUIC finish omitted the typed remote H3 application code")?;
        }
    });
    let cleanup = backup.stop().await;

    let error_code = finish_with_cleanup(result, cleanup)?;
    assert_eq!(error_code, u64::from(INTERNAL_ERROR));
    Ok(())
}

#[tokio::test]
async fn quic_finish_stops_its_actual_pending_handshake() -> TestResult<()> {
    let (mut backup, mut observation, _pending, _request_seen) = Backup::new();
    let (handshake_pending, pending) = oneshot::channel();
    observation.handshake = Some(handshake_pending);
    let result = async {
        let identity = origin_identity()?;
        let origin = backup.spawn(&identity, observation)?;
        let origin_address = SocketAddr::from(([127, 0, 0, 1], origin.port));
        let socket = phantom_testkit::udp::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
        socket.set_nonblocking(true)?;
        backup.bridge = Some(UdpSocket::from_std(socket)?);
        let bridge = backup
            .bridge
            .as_ref()
            .ok_or("bridge socket was not retained")?;
        let endpoint = client_endpoint(&identity)?;
        backup.peer = Some(endpoint.clone());
        let connecting = endpoint.connect(bridge.local_addr()?, ORIGIN_NAME)?;
        let mut datagram = [0_u8; 65_535];
        let (initial, client_address) =
            timeout(DEADLINE, bridge.recv_from(&mut datagram)).await??;
        if initial < 1_200 || client_address == origin_address {
            return Err("bridge did not receive the actual client's Initial datagram".into());
        }
        let forwarded = timeout(
            DEADLINE,
            bridge.send_to(&datagram[..initial], origin_address),
        )
        .await??;
        if forwarded != initial {
            return Err("bridge did not forward the whole actual Initial datagram".into());
        }
        timeout(DEADLINE, async {
            loop {
                let (response, source) = bridge.recv_from(&mut datagram).await?;
                if source == origin_address && response != 0 {
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                }
                if source != client_address || response == 0 {
                    return Err("bridge received an unrelated or empty datagram".into());
                }

                let forwarded = bridge
                    .send_to(&datagram[..response], origin_address)
                    .await?;
                if forwarded != response {
                    return Err("bridge did not forward the whole client datagram".into());
                }
            }
        })
        .await??;

        timeout(DEADLINE, pending).await??;

        let outcome = timeout(DEADLINE, origin.finish(0, 0))
            .await
            .map_err(PendingHandshakeFinishDeadline);
        Ok((outcome, connecting))
    }
    .await;
    let (result, _connecting) = match result {
        Ok((outcome, connecting)) => (
            outcome.map_err(Into::into).and_then(|result| result),
            Some(connecting),
        ),
        Err(error) => (Err(error), None),
    };

    let cleanup = backup.stop().await;

    let (observed, tcp) = finish_with_cleanup(result, cleanup)?;
    assert!(observed.is_empty());
    assert_eq!(tcp, 0);
    Ok(())
}

#[tokio::test]
async fn quic_finish_retains_both_completed_remote_failures() -> TestResult<()> {
    let (mut backup, mut observation, first_pending, _first_request) = Backup::new();
    let (second_pending, _second_request, second_outcome) = backup.add_child(&mut observation);
    let result = async {
        let identity = origin_identity()?;
        let origin = backup.spawn(&identity, observation)?;
        let first = Peer::connect(&mut backup, &identity, &origin, first_pending).await?;
        let second = Peer::connect(&mut backup, &identity, &origin, second_pending).await?;
        first
            .connection
            .close(0x102_u32.into(), b"first real serving failure");
        second
            .connection
            .close(0x103_u32.into(), b"second real serving failure");
        backup.child.finished().await?;
        backup
            .additional_children
            .first_mut()
            .ok_or("second serving task was not registered")?
            .finished()
            .await?;
        let first_actual = timeout(
            DEADLINE,
            backup
                .outcome
                .take()
                .ok_or("first outcome receiver was consumed")?,
        )
        .await??
        .ok_or("first actual serving outcome was not a connection error")?;
        let second_actual = timeout(DEADLINE, second_outcome)
            .await??
            .ok_or("second actual serving outcome was not a connection error")?;
        if remote_code(&first_actual) != Some(0x102) || remote_code(&second_actual) != Some(0x103) {
            return Err(
                "actual serving outcomes lost their distinct remote application codes".into(),
            );
        }

        let outcome = timeout(DEADLINE, origin.finish(2, 0)).await?;
        Ok((outcome, first, second))
    }
    .await;
    let (result, _peers) = match result {
        Ok((outcome, first, second)) => (Ok(outcome), Some((first, second))),
        Err(error) => (Err(error), None),
    };

    let result = result.and_then(|outcome| {
        let error = outcome
            .err()
            .ok_or("QUIC origin discarded both completed serving failures")?;
        let mut codes = Vec::new();
        collect_remote_codes(error.as_ref(), &mut codes)?;
        codes.sort_unstable();
        Ok(codes)
    });

    let cleanup = backup.stop().await;

    let codes = finish_with_cleanup(result, cleanup)?;
    assert_eq!(codes, [0x102, 0x103]);
    Ok(())
}

#[tokio::test]
async fn quic_caller_retains_its_request_and_completed_serving_failures() -> TestResult<()> {
    let (mut backup, mut observation, _pending, request_seen) = Backup::new();
    let (stream_outcome, actual_stream_outcome) = oneshot::channel();
    let child = observation
        .child
        .first_mut()
        .ok_or("serving observation missing")?;
    child.reset_response = true;
    child.stream_outcome = Some(stream_outcome);
    let mut retained_client = None;
    let result = async {
        let identity = origin_identity()?;
        let mut dns = super::published_record().await?;
        let origin = backup.spawn(&identity, observation)?;
        retained_client = Some(super::client(&identity, &dns, super::profile(false))?);
        let client = retained_client
            .as_ref()
            .ok_or("actual client was not retained")?;
        let uri = origin.url("/quic-caller-failure?probe=1");
        let operation = async {
            let error = timeout(DEADLINE, client.get(HttpProtocol::Http3, &uri)?.send())
                .await?
                .err()
                .ok_or("the actually reset request returned a response")?;
            request_reset(&error)?;
            let seen = timeout(DEADLINE, request_seen).await??;
            if seen.method != Method::GET
                || seen.uri.to_string() != uri
                || seen.version != Version::HTTP_3
            {
                return Err("origin did not parse the literal HTTP/3 GET".into());
            }
            backup.child.finished().await?;
            if !timeout(DEADLINE, actual_stream_outcome).await?? {
                return Err("completed serving outcome was not actual ClosedStream".into());
            }

            Err(error.into())
        };
        let outcome = timeout(DEADLINE, origin.finish_after(1, 0, operation)).await?;
        let error = outcome
            .err()
            .ok_or("the failed request unexpectedly succeeded")?;
        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("QUIC caller discarded its completed serving failure after the request error")?;
        request_reset(failures.primary.as_ref())?;
        if !contains_closed_stream(failures.cleanup.as_ref()) {
            return Err("QUIC caller omitted the actual completed ClosedStream cause".into());
        }

        dns.finish().await?;
        Ok(())
    }
    .await;

    let cleanup = backup.stop().await;

    finish_with_cleanup(result, cleanup)
}

#[tokio::test]
async fn quic_finish_retains_the_externally_cancelled_workers_identity() -> TestResult<()> {
    let (mut backup, observation, pending, _request_seen) = Backup::new();
    let result = async {
        let identity = origin_identity()?;
        let origin = backup.spawn(&identity, observation)?;
        let peer = Peer::connect(&mut backup, &identity, &origin, pending).await?;
        let actual = backup.child.handle()?;
        let expected_id = actual.id();
        actual.abort();
        backup.child.finished().await?;

        let outcome = timeout(DEADLINE, origin.finish(1, 0)).await?;
        Ok((outcome, expected_id, peer))
    }
    .await;
    let (result, _peer) = match result {
        Ok((outcome, expected_id, peer)) => (Ok((outcome, expected_id)), Some(peer)),
        Err(error) => (Err(error), None),
    };

    let result = result.and_then(|(outcome, expected_id)| {
        let error = outcome
            .err()
            .ok_or("QUIC origin discarded its externally cancelled serving worker")?;
        let actual_id = cancelled_worker_id(error.as_ref())?;
        Ok((actual_id, expected_id))
    });

    let cleanup = backup.stop().await;

    let (actual_id, expected_id) = finish_with_cleanup(result, cleanup)?;
    assert_eq!(actual_id, expected_id);
    Ok(())
}
