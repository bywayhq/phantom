use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    future::pending,
    net::{Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use http::{HeaderValue, Method, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, ResponseInfo,
    profile::{ClientProfile, browser::chrome},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::{oneshot, watch},
    task::JoinSet,
    time::timeout,
};

use super::{
    AlternativeBehavior, Http3UpgradeFixture, OriginPlan, PlannedResponse, SharedObservations,
    UpgradeScript, h3_endpoint, run_alternative_connections, run_origin_connections,
    stop_alternative_connections, stop_origin_connections,
};
use crate::support::{
    h3::client_settings,
    tls::{H2_ALPN, TestIdentity, TestResult, tls_settings},
};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

#[path = "worker_results/shutdown_order.rs"]
mod shutdown_order;

#[tokio::test]
async fn completed_h3_request_accepts_clean_client_close_and_joins_its_peer() -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, assert_completed_h3_close(None)).await?
}

#[tokio::test]
async fn completed_h3_request_retains_remote_protocol_error_after_join() -> TestResult<()> {
    timeout(
        CONTROL_TIMEOUT,
        assert_completed_h3_close(Some(h3::error::Code::H3_GENERAL_PROTOCOL_ERROR)),
    )
    .await?
}

async fn assert_completed_h3_close(close: Option<h3::error::Code>) -> TestResult<()> {
    use crate::support::tunnel_proxy::connection_peer::{ConnectionPeer, finish_with_cleanup};

    let identity = TestIdentity::generate()?;
    let endpoint = h3_endpoint(&identity, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let address = endpoint.local_addr()?;
    let mut roots = rustls::RootCertStore::empty();
    roots.add(rustls::pki_types::CertificateDer::from(
        identity.root_der.clone(),
    ))?;
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)?;
    let mut client = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        phantom_testkit::udp::bind("127.0.0.1:0".parse()?)?,
        Arc::new(quinn::TokioRuntime),
    )?;
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let observations = Arc::new(SharedObservations::default());
    let observed = Arc::clone(&observations);
    let owner = endpoint.clone();
    let (_shutdown, shutdown) = watch::channel(false);
    let mut peer = ConnectionPeer::spawn(async move {
        let incoming = owner
            .accept()
            .await
            .ok_or("H3 close peer ended before handshake")?;
        super::serve_alternative_connection(
            incoming,
            AlternativeBehavior::responses([]),
            Some(Arc::new(Mutex::new(VecDeque::from([
                PlannedResponse::new(StatusCode::OK).body("close-worker"),
            ])))),
            observed,
            shutdown,
        )
        .await
    });
    let mut driver = None;
    let mut protocol_sender = None;
    let operation: TestResult<()> = async {
        let connection = client.connect(address, "127.0.0.1")?.await?;
        let (mut h3, mut send) = h3::client::builder()
            .build::<_, _, bytes::Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await?;
        driver = Some(ConnectionPeer::spawn(async move {
            Ok::<_, Box<dyn Error + Send + Sync>>(h3.wait_idle().await)
        }));
        let mut stream = send
            .send_request(
                http::Request::builder()
                    .uri(format!("https://{address}/completed-close"))
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        let response = stream.recv_response().await?;
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            use bytes::Buf;
            while chunk.has_remaining() {
                let bytes = chunk.chunk();
                body.extend_from_slice(bytes);
                let consumed = bytes.len();
                chunk.advance(consumed);
            }
        }
        assert_eq!(body, b"close-worker");
        drop(stream);
        if let Some(code) = close {
            connection.close(
                quinn::VarInt::from_u64(code.value())?,
                b"protocol-error control",
            );
            // Keep the sender until the explicit protocol close is collected.
            protocol_sender = Some(send);
        } else {
            // Use the actual last-sender drop, not raw code zero.
            drop(send);
        }
        Ok(())
    }
    .await;
    let collected: TestResult<()> = async {
        let result = timeout(CONTROL_TIMEOUT, &mut peer).await??;
        let driver = driver.as_mut().ok_or("H3 close driver was not constructed")?;
        let driver_close = timeout(CONTROL_TIMEOUT, driver).await???;
        match close {
            None => {
                result?;
                assert!(driver_close.is_h3_no_error());
            }
            Some(code) => {
                let error = result.err().ok_or("remote protocol error was accepted")?;
                assert!(matches!(
                    find_source::<h3::error::ConnectionError>(error.as_ref()),
                    Some(h3::error::ConnectionError::Remote(
                        h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code },
                        ..,
                    )) if *error_code == code.value()
                ));
                assert!(matches!(driver_close,
                    h3::error::ConnectionError::Remote(
                        h3::quic::ConnectionErrorIncoming::Undefined(ref error), ..
                    ) if matches!(error.downcast_ref::<quinn::ConnectionError>(), Some(quinn::ConnectionError::LocallyClosed))
                ));
            }
        }
        assert_eq!(observations.alternative_connections.load(Ordering::SeqCst), 1);
        let requests = observations.alternative_requests.lock().map_err(|_| "close observation poisoned")?;
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].method, Method::GET);
        assert_eq!(requests[0].path_and_query.as_deref(), Some("/completed-close"));
        Ok(())
    }
    .await;
    drop(protocol_sender);
    endpoint.close(0_u32.into(), b"close control complete");
    client.close(0_u32.into(), b"close control complete");
    let peer_cleanup = peer.shutdown().await;
    let driver_cleanup = match &mut driver {
        Some(driver) => driver.shutdown().await,
        None => Ok(()),
    };
    let endpoints_cleanup: TestResult<()> = async {
        timeout(CONTROL_TIMEOUT, endpoint.wait_idle()).await?;
        timeout(CONTROL_TIMEOUT, client.wait_idle()).await?;
        Ok(())
    }
    .await;
    finish_with_cleanup(
        operation,
        finish_with_cleanup(
            collected,
            finish_with_cleanup(
                peer_cleanup,
                finish_with_cleanup(driver_cleanup, endpoints_cleanup),
            ),
        ),
    )
}

#[derive(Debug)]
struct FirstChildFailure(Arc<()>);

impl fmt::Display for FirstChildFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("first controlled connection failed")
    }
}

impl Error for FirstChildFailure {}

#[derive(Debug)]
struct SecondChildFailure(Arc<()>);

impl fmt::Display for SecondChildFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("second controlled connection failed")
    }
}

impl Error for SecondChildFailure {}

struct ChildStopped {
    stopped: Arc<AtomicBool>,
    observed: Option<oneshot::Sender<()>>,
}

impl Drop for ChildStopped {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(observer) = self.observed.take() {
            // The enclosing deadline may already have cancelled observation.
            let _ = observer.send(());
        }
    }
}

#[derive(Clone, Copy)]
enum Worker {
    Origin,
    Alternative,
}

enum Phase {
    Active,
    Shutdown,
}

fn find_source<'a, T: Error + 'static>(mut error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    loop {
        if let Some(cause) = error.downcast_ref::<T>() {
            return Some(cause);
        }

        error = error.source()?;
    }
}

async fn run_boundary(
    worker: Worker,
    phase: Phase,
    identity: &TestIdentity,
    connections: JoinSet<TestResult<()>>,
    shutdown: watch::Receiver<bool>,
) -> TestResult<()> {
    match (worker, phase) {
        (Worker::Origin, Phase::Active) => {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            run_origin_connections(
                listener,
                identity.acceptor(H2_ALPN)?,
                Arc::new(Mutex::new(VecDeque::new())),
                OriginPlan {
                    alt_svc: HeaderValue::from_static("h3=\":443\"; ma=3600"),
                    raw_canonical_origin: None,
                },
                Arc::new(SharedObservations::default()),
                shutdown,
                connections,
            )
            .await
        }
        (Worker::Alternative, Phase::Active) => {
            let endpoint = h3_endpoint(identity, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
            run_alternative_connections(
                endpoint,
                AlternativeBehavior::responses([]),
                Arc::new(SharedObservations::default()),
                shutdown,
                connections,
            )
            .await
        }
        (Worker::Origin, Phase::Shutdown) => stop_origin_connections(connections).await,
        (Worker::Alternative, Phase::Shutdown) => stop_alternative_connections(connections).await,
    }
}

async fn driven_child(
    connections: &mut JoinSet<TestResult<()>>,
) -> TestResult<(
    tokio::io::DuplexStream,
    Arc<AtomicBool>,
    oneshot::Receiver<()>,
)> {
    let (mut client, mut peer) = tokio::io::duplex(64);
    let stopped = Arc::new(AtomicBool::new(false));
    let worker_stopped = Arc::clone(&stopped);
    let (destroyed, destruction) = oneshot::channel();
    connections.spawn(async move {
        let _stopped = ChildStopped {
            stopped: worker_stopped,
            observed: Some(destroyed),
        };
        let mut head = [0_u8; 4];
        peer.read_exact(&mut head).await?;
        assert_eq!(&head, b"OWN2");
        peer.write_all(b"ACK2").await?;

        let result = pending::<TestResult<()>>().await;
        drop(peer);
        result
    });
    client.write_all(b"OWN2").await?;
    let mut reply = [0_u8; 4];
    client.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"ACK2");
    Ok((client, stopped, destruction))
}

async fn completed_failures(
    connections: &mut JoinSet<TestResult<()>>,
) -> TestResult<(Weak<()>, Weak<()>)> {
    let first = Arc::new(());
    let first_retained = Arc::downgrade(&first);
    let (ready, observed) = oneshot::channel();
    connections.spawn(async move {
        ready
            .send(())
            .map_err(|_| "first child observer cancelled")?;
        Err(Box::new(FirstChildFailure(first)) as Box<dyn Error + Send + Sync>)
    });
    observed.await?;

    let second = Arc::new(());
    let second_retained = Arc::downgrade(&second);
    let (ready, observed) = oneshot::channel();
    connections.spawn(async move {
        ready
            .send(())
            .map_err(|_| "second child observer cancelled")?;
        Err(Box::new(SecondChildFailure(second)) as Box<dyn Error + Send + Sync>)
    });
    observed.await?;
    Ok((first_retained, second_retained))
}

async fn assert_failed_children_observed(worker: Worker, phase: Phase) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut connections = JoinSet::new();
    let (mut client, stopped, destruction) = driven_child(&mut connections).await?;
    let (first, second) = completed_failures(&mut connections).await?;
    let (_shutdown, shutdown_rx) = watch::channel(false);

    let result = run_boundary(worker, phase, &identity, connections, shutdown_rx).await;
    let stopped_before_return = stopped.load(Ordering::SeqCst);
    let error = result.err().ok_or("two failed connections were accepted")?;
    let first_survived = first.upgrade().is_some();
    let second_survived = second.upgrade().is_some();
    let typed_primary = find_source::<FirstChildFailure>(error.as_ref())
        .is_some_and(|cause| Arc::strong_count(&cause.0) == 1)
        || find_source::<SecondChildFailure>(error.as_ref())
            .is_some_and(|cause| Arc::strong_count(&cause.0) == 1);
    drop(error);

    // JoinSet Drop aborts on the defective baseline too. Observe destruction
    // and socket release before reporting the skipped results or early return.
    destruction.await?;
    let mut byte = [0_u8; 1];
    assert_eq!(client.read(&mut byte).await?, 0);
    assert!(first.upgrade().is_none());
    assert!(second.upgrade().is_none());
    assert!(
        typed_primary,
        "worker lost its original typed primary cause"
    );

    assert_eq!(
        (first_survived, second_survived, stopped_before_return),
        (true, true, true),
        "worker must retain both completed causes and join its driven sibling"
    );
    Ok(())
}

#[tokio::test]
async fn active_origin_failure_retains_both_causes_and_joins_its_driven_sibling() -> TestResult<()>
{
    timeout(
        CONTROL_TIMEOUT,
        assert_failed_children_observed(Worker::Origin, Phase::Active),
    )
    .await?
}

#[tokio::test]
async fn active_alternative_failure_retains_both_causes_and_joins_its_driven_sibling()
-> TestResult<()> {
    timeout(
        CONTROL_TIMEOUT,
        assert_failed_children_observed(Worker::Alternative, Phase::Active),
    )
    .await?
}

#[tokio::test]
async fn origin_shutdown_retains_both_causes_and_joins_its_driven_sibling() -> TestResult<()> {
    timeout(
        CONTROL_TIMEOUT,
        assert_failed_children_observed(Worker::Origin, Phase::Shutdown),
    )
    .await?
}

#[tokio::test]
async fn alternative_shutdown_retains_both_causes_and_joins_its_driven_sibling() -> TestResult<()> {
    timeout(
        CONTROL_TIMEOUT,
        assert_failed_children_observed(Worker::Alternative, Phase::Shutdown),
    )
    .await?
}

async fn assert_cancelled_child_drained(worker: Worker) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut connections = JoinSet::new();
    let (mut client, stopped, destruction) = driven_child(&mut connections).await?;
    let (_shutdown, shutdown_rx) = watch::channel(false);

    run_boundary(worker, Phase::Shutdown, &identity, connections, shutdown_rx).await?;
    assert!(stopped.load(Ordering::SeqCst));
    destruction.await?;
    let mut byte = [0_u8; 1];
    assert_eq!(client.read(&mut byte).await?, 0);
    Ok(())
}

#[tokio::test]
async fn origin_shutdown_accepts_its_requested_child_cancellation_after_join() -> TestResult<()> {
    timeout(
        CONTROL_TIMEOUT,
        assert_cancelled_child_drained(Worker::Origin),
    )
    .await?
}

#[tokio::test]
async fn alternative_shutdown_accepts_its_requested_child_cancellation_after_join() -> TestResult<()>
{
    timeout(
        CONTROL_TIMEOUT,
        assert_cancelled_child_drained(Worker::Alternative),
    )
    .await?
}

#[tokio::test]
async fn successful_workers_keep_literal_h2_and_h3_requests_and_counts() -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            "127.0.0.1",
            UpgradeScript::new(
                [PlannedResponse::new(StatusCode::OK)
                    .body("origin-worker")
                    .advertise_alternative()],
                AlternativeBehavior::responses([
                    PlannedResponse::new(StatusCode::OK).body("alternative-worker")
                ]),
            ),
        )
        .await?;
        let authority = format!("127.0.0.1:{}", fixture.origin_address().port());
        let profile = ClientProfile::new(tls_settings())
            .with_http2(chrome::v154_http2())
            .with_http3(client_settings());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .alt_svc(NonZeroUsize::MIN)
            .build()?;

        let origin = client
            .get(&fixture.origin_url("/worker-learn"))?
            .send()
            .await?;
        assert_eq!(origin.status(), StatusCode::OK);
        assert_eq!(
            origin
                .extensions()
                .get::<ResponseInfo>()
                .map(ResponseInfo::protocol),
            Some(HttpProtocol::Http2)
        );
        assert_eq!(
            origin.into_body().collect().await?.to_bytes(),
            "origin-worker"
        );

        let alternative = client
            .get(&fixture.origin_url("/worker-upgrade"))?
            .send()
            .await?;
        assert_eq!(alternative.status(), StatusCode::OK);
        assert_eq!(
            alternative
                .extensions()
                .get::<ResponseInfo>()
                .map(ResponseInfo::protocol),
            Some(HttpProtocol::Http3)
        );
        assert_eq!(
            alternative.into_body().collect().await?.to_bytes(),
            "alternative-worker"
        );
        drop(client);

        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 1);
        assert_eq!(observed.origin_requests.len(), 1);
        assert_eq!(observed.alternative_requests.len(), 1);
        for (request, path) in [
            (&observed.origin_requests[0], "/worker-learn"),
            (&observed.alternative_requests[0], "/worker-upgrade"),
        ] {
            assert_eq!(request.method, Method::GET);
            assert_eq!(request.authority.as_deref(), Some(authority.as_str()));
            assert_eq!(request.path_and_query.as_deref(), Some(path));
        }
        Ok(())
    })
    .await?
}
