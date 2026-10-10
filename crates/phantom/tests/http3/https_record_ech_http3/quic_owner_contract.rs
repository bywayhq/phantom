use std::{future::poll_fn, io, net::SocketAddr, sync::Arc, task::Poll, time::Duration};

use bytes::{Buf, Bytes};
use http::{Method, Request, StatusCode, Uri, Version};
use rustls::pki_types::CertificateDer;
use tokio::{
    sync::{oneshot, watch},
    task::AbortHandle,
    time::timeout,
};

use super::{ORIGIN_NAME, Observed, QuicOrigin, TEST_ECH_KEYS, origin_identity};
use crate::support::{
    tls::{TestIdentity, TestResult},
    tunnel_proxy::finish_with_cleanup,
};

const DEADLINE: Duration = Duration::from_secs(5);
const DESTRUCTION: Duration = Duration::from_secs(2);
const INTERNAL_ERROR: u32 = 0x102;

type Driver = h3::client::Connection<h3_quinn::Connection, Bytes>;
type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

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
    pub(super) child: ServingObservation,
}

pub(super) struct ServingObservation {
    pub(super) task: TaskObservation,
    pending: Option<oneshot::Sender<()>>,
    request: Option<oneshot::Sender<RequestSeen>>,
    outcome: Option<oneshot::Sender<Option<h3::error::ConnectionError>>>,
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
            },
            OriginObservation {
                parent,
                child: ServingObservation {
                    task,
                    pending: Some(pending),
                    request: Some(request),
                    outcome: Some(outcome),
                },
            },
            pending_receiver,
            request_receiver,
        )
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

        for endpoint in [&self.server, &self.peer].into_iter().flatten() {
            endpoint.close(0_u32.into(), b"QUIC owner control complete");
        }
        for endpoint in [&self.server, &self.peer].into_iter().flatten() {
            outcome = finish_with_cleanup(
                outcome,
                timeout(DEADLINE, endpoint.wait_idle())
                    .await
                    .map_err(Into::into),
            );
        }

        outcome
    }
}

impl Drop for Backup {
    fn drop(&mut self) {
        // Drop requests closure; explicit stop observes destruction and idle.
        for task in [&self.parent, &self.child] {
            if let Ok(handle) = task.handle() {
                handle.abort();
            }
        }
        for endpoint in [&self.server, &self.peer].into_iter().flatten() {
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
        backup.peer = Some(endpoint.clone());
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
    let cleanup = backup.stop().await;
    let (uri, seen, (response, body), observed, tcp, destroyed, _peer) =
        finish_with_cleanup(result, cleanup)?;

    destroyed?;
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
    let cleanup = backup.stop().await;
    let (observed, tcp, destroyed, _peer) = finish_with_cleanup(result, cleanup)?;

    destroyed?;
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
    let cleanup = backup.stop().await;
    let (destroyed, _peer) = finish_with_cleanup(result, cleanup)?;

    destroyed
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
    let cleanup = backup.stop().await;
    let (outcome, _peer) = finish_with_cleanup(result, cleanup)?;

    let error = outcome
        .err()
        .ok_or("QUIC origin discarded its completed remote H3 failure")?;
    let mut cause: &(dyn std::error::Error + 'static) = error.as_ref();
    loop {
        if let Some(h3::error::ConnectionError::Remote(
            h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code },
        )) = cause.downcast_ref::<h3::error::ConnectionError>()
        {
            assert_eq!(*error_code, u64::from(INTERNAL_ERROR));
            return Ok(());
        }

        cause = cause
            .source()
            .ok_or("QUIC finish omitted the typed remote H3 application code")?;
    }
}
