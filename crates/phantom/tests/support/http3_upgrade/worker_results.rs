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
            .get_negotiated(&fixture.origin_url("/worker-learn"))?
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
            .get_negotiated(&fixture.origin_url("/worker-upgrade"))?
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
