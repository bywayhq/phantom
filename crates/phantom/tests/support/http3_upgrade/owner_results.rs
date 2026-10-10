use std::{
    error::Error,
    fmt,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Weak,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use http::{Method, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, ResponseInfo,
    profile::{ClientProfile, browser::chrome},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{oneshot, watch},
    task::JoinHandle,
    time::timeout,
};

use super::{
    AlternativeBehavior, Http3UpgradeFixture, OriginHttp3Service, PlannedResponse,
    SharedObservations, UpgradeScript, h3_endpoint,
};
use crate::support::{
    h3::client_settings,
    tls::{TestIdentity, TestResult, tls_settings},
};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct OriginFailure {
    retained: Arc<()>,
}

impl fmt::Display for OriginFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled origin owner failed")
    }
}

impl Error for OriginFailure {}

#[derive(Debug)]
struct AlternativeFailure {
    retained: Arc<()>,
}

impl fmt::Display for AlternativeFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled alternative owner failed")
    }
}

impl Error for AlternativeFailure {}

fn origin_failure() -> (OriginFailure, Weak<()>) {
    let retained = Arc::new(());
    let observer = Arc::downgrade(&retained);
    (OriginFailure { retained }, observer)
}

fn alternative_failure() -> (AlternativeFailure, Weak<()>) {
    let retained = Arc::new(());
    let observer = Arc::downgrade(&retained);
    (AlternativeFailure { retained }, observer)
}

fn find_source<'a, T: Error + 'static>(mut error: &'a (dyn Error + 'static)) -> Option<&'a T> {
    loop {
        if let Some(cause) = error.downcast_ref::<T>() {
            return Some(cause);
        }

        error = error.source()?;
    }
}

fn controlled_fixture(
    shutdown: watch::Sender<bool>,
    origin_task: JoinHandle<TestResult<()>>,
    alternative_task: JoinHandle<TestResult<()>>,
    origin_http3_tasks: Option<Vec<JoinHandle<TestResult<()>>>>,
) -> TestResult<Http3UpgradeFixture> {
    let identity = TestIdentity::generate()?;
    let alternative_endpoint = h3_endpoint(&identity, SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let address = alternative_endpoint.local_addr()?;
    let origin_http3 = match origin_http3_tasks {
        Some(tasks) => Some(OriginHttp3Service {
            endpoints: vec![h3_endpoint(
                &identity,
                SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            )?],
            observations: Arc::new(SharedObservations::default()),
            tasks,
        }),
        None => None,
    };

    Ok(Http3UpgradeFixture {
        origin_name: "owner-results.test".to_owned(),
        // These addresses are metadata only in task-result controls.
        origin_address: address,
        alternative_address: address,
        alternative_endpoint,
        observations: Arc::new(SharedObservations::default()),
        shutdown,
        origin_task,
        alternative_task,
        origin_http3,
    })
}

#[tokio::test]
async fn finish_retains_two_distinct_completed_owner_failures() -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let (origin_error, origin_retained) = origin_failure();
        let (alternative_error, alternative_retained) = alternative_failure();
        let (origin_ready, wait_origin) = oneshot::channel();
        let (alternative_ready, wait_alternative) = oneshot::channel();
        let origin_task = tokio::spawn(async move {
            origin_ready
                .send(())
                .map_err(|_| "origin result observer cancelled")?;
            Err(Box::new(origin_error) as Box<dyn Error + Send + Sync>)
        });
        let alternative_task = tokio::spawn(async move {
            alternative_ready
                .send(())
                .map_err(|_| "alternative result observer cancelled")?;
            Err(Box::new(alternative_error) as Box<dyn Error + Send + Sync>)
        });
        wait_origin.await?;
        wait_alternative.await?;
        let (shutdown, _receiver) = watch::channel(false);
        let fixture = controlled_fixture(shutdown, origin_task, alternative_task, None)?;
        let retained_endpoint = fixture.alternative_endpoint.clone();

        let error = fixture
            .finish()
            .await
            .err()
            .ok_or("two owner failures were accepted")?;
        assert!(find_source::<OriginFailure>(error.as_ref()).is_some());
        let origin_survived = origin_retained.upgrade().is_some();
        let alternative_survived = alternative_retained.upgrade().is_some();
        drop(error);

        assert!(origin_retained.upgrade().is_none());
        assert!(alternative_retained.upgrade().is_none());
        assert!(origin_survived);
        assert!(
            alternative_survived,
            "the returned error lost the alternative's owned typed failure"
        );
        drop(retained_endpoint);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn finish_retains_two_distinct_completed_origin_http3_failures() -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let (first_error, first_retained) = origin_failure();
        let (second_error, second_retained) = alternative_failure();
        let (first_ready, wait_first) = oneshot::channel();
        let (second_ready, wait_second) = oneshot::channel();
        let first = tokio::spawn(async move {
            first_ready
                .send(())
                .map_err(|_| "first origin H3 observer cancelled")?;
            Err(Box::new(first_error) as Box<dyn Error + Send + Sync>)
        });
        let second = tokio::spawn(async move {
            second_ready
                .send(())
                .map_err(|_| "second origin H3 observer cancelled")?;
            Err(Box::new(second_error) as Box<dyn Error + Send + Sync>)
        });
        wait_first.await?;
        wait_second.await?;
        let (shutdown, _receiver) = watch::channel(false);
        let fixture = controlled_fixture(
            shutdown,
            tokio::spawn(async { Ok(()) }),
            tokio::spawn(async { Ok(()) }),
            Some(vec![first, second]),
        )?;

        let error = fixture
            .finish()
            .await
            .err()
            .ok_or("origin H3 failures were accepted")?;
        assert!(find_source::<OriginFailure>(error.as_ref()).is_some());
        let first_survived = first_retained.upgrade().is_some();
        let second_survived = second_retained.upgrade().is_some();
        drop(error);

        assert!(first_retained.upgrade().is_none());
        assert!(second_retained.upgrade().is_none());
        assert!(first_survived);
        assert!(
            second_survived,
            "the returned error lost the second origin H3 failure"
        );
        Ok(())
    })
    .await?
}

struct WorkerStopped {
    stopped: Arc<AtomicBool>,
    observed: Option<oneshot::Sender<()>>,
}

impl Drop for WorkerStopped {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(observer) = self.observed.take() {
            // The enclosing timeout may already have cancelled its observer.
            let _ = observer.send(());
        }
    }
}

enum FailedOwner {
    Origin,
    Alternative,
    OriginHttp3,
}

async fn assert_sibling_stopped_before_return(failed: FailedOwner) -> TestResult<()> {
    let (shutdown, mut shutdown_rx) = watch::channel(false);
    let (mut client, mut peer) = tokio::io::duplex(64);
    let stopped = Arc::new(AtomicBool::new(false));
    let (destroyed, destruction) = oneshot::channel();
    let (shutdown_seen, shutdown_observed) = oneshot::channel();
    let (release, released) = oneshot::channel();
    let worker_stopped = Arc::clone(&stopped);
    let worker = tokio::spawn(async move {
        let _stopped = WorkerStopped {
            stopped: worker_stopped,
            observed: Some(destroyed),
        };
        let mut head = [0_u8; 4];
        peer.read_exact(&mut head).await?;
        assert_eq!(&head, b"OWN1");
        peer.write_all(b"ACK1").await?;

        // Sender closure already stops the actual fixture workers.
        if let Ok(()) = shutdown_rx.changed().await {
            assert!(*shutdown_rx.borrow());
        }
        shutdown_seen
            .send(())
            .map_err(|_| "shutdown observer cancelled")?;
        released.await?;
        Ok(())
    });
    client.write_all(b"OWN1").await?;
    let mut response = [0_u8; 4];
    client.read_exact(&mut response).await?;
    assert_eq!(&response, b"ACK1");

    let (primary, _retained) = origin_failure();
    let (failed_ready, wait_failed) = oneshot::channel();
    let failed_task = tokio::spawn(async move {
        failed_ready
            .send(())
            .map_err(|_| "failed owner observer cancelled")?;
        Err(Box::new(primary) as Box<dyn Error + Send + Sync>)
    });
    wait_failed.await?;

    let fixture = match failed {
        FailedOwner::Origin => controlled_fixture(shutdown, failed_task, worker, None)?,
        FailedOwner::Alternative => controlled_fixture(
            shutdown,
            tokio::spawn(async { Ok(()) }),
            failed_task,
            Some(vec![worker]),
        )?,
        FailedOwner::OriginHttp3 => controlled_fixture(
            shutdown,
            tokio::spawn(async { Ok(()) }),
            tokio::spawn(async { Ok(()) }),
            Some(vec![failed_task, worker]),
        )?,
    };
    let retained_endpoint = fixture.alternative_endpoint.clone();
    let finish = async {
        let result = fixture.finish().await;
        let stopped_before_return = stopped.load(Ordering::SeqCst);
        (result, stopped_before_return)
    };
    let controller = async {
        shutdown_observed.await?;
        release
            .send(())
            .map_err(|_| "controlled sibling ended before release")?;
        destruction.await?;
        let mut byte = [0_u8; 1];
        assert_eq!(client.read(&mut byte).await?, 0);
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    };

    // Poll the real finish path before releasing its already-driven sibling.
    let ((result, stopped_before_return), controlled) = tokio::join!(biased; finish, controller);
    controlled?;
    let error = result.err().ok_or("failed owner was accepted")?;
    assert!(find_source::<OriginFailure>(error.as_ref()).is_some());
    assert!(
        stopped_before_return,
        "finish returned before its driven sibling stopped"
    );
    drop(retained_endpoint);
    Ok(())
}

#[tokio::test]
async fn an_origin_failure_waits_for_its_driven_alternative_before_returning() -> TestResult<()> {
    timeout(
        CONTROL_TIMEOUT,
        assert_sibling_stopped_before_return(FailedOwner::Origin),
    )
    .await?
}

#[tokio::test]
async fn an_alternative_failure_waits_for_driven_origin_http3_before_returning() -> TestResult<()> {
    timeout(
        CONTROL_TIMEOUT,
        assert_sibling_stopped_before_return(FailedOwner::Alternative),
    )
    .await?
}

#[tokio::test]
async fn an_origin_http3_failure_waits_for_its_driven_sibling_before_returning() -> TestResult<()> {
    timeout(
        CONTROL_TIMEOUT,
        assert_sibling_stopped_before_return(FailedOwner::OriginHttp3),
    )
    .await?
}

#[tokio::test]
async fn a_single_owner_failure_remains_downcastable() -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let (error, retained) = origin_failure();
        let (shutdown, _receiver) = watch::channel(false);
        let fixture = controlled_fixture(
            shutdown,
            tokio::spawn(async move { Err(Box::new(error) as Box<dyn Error + Send + Sync>) }),
            tokio::spawn(async { Ok(()) }),
            None,
        )?;

        let error = fixture
            .finish()
            .await
            .err()
            .ok_or("single owner failure was accepted")?;
        let primary =
            find_source::<OriginFailure>(error.as_ref()).ok_or("typed origin cause was lost")?;
        assert_eq!(Arc::strong_count(&primary.retained), 1);
        assert!(retained.upgrade().is_some());
        drop(error);

        assert!(retained.upgrade().is_none());
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn a_successful_fixture_finish_preserves_the_actual_origin_request_count() -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let fixture = Http3UpgradeFixture::spawn(
            &identity,
            "127.0.0.1",
            UpgradeScript::new(
                [PlannedResponse::new(StatusCode::OK).body("owner-results")],
                AlternativeBehavior::responses([]),
            ),
        )
        .await?;
        let authority = format!("127.0.0.1:{}", fixture.origin_address().port());
        let profile = ClientProfile::new(tls_settings())
            .with_http2(chrome::v154_http2())
            .with_http3(client_settings());
        let client = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let response = client
            .get(HttpProtocol::Http2, &fixture.origin_url("/finish-positive"))?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .extensions()
                .get::<ResponseInfo>()
                .map(ResponseInfo::protocol),
            Some(HttpProtocol::Http2)
        );
        assert_eq!(
            response.into_body().collect().await?.to_bytes(),
            "owner-results"
        );
        drop(client);

        let observed = fixture.finish().await?;
        assert_eq!(observed.origin_request_count, 1);
        assert_eq!(observed.origin_requests.len(), 1);
        assert_eq!(observed.origin_requests[0].method, Method::GET);
        assert_eq!(
            observed.origin_requests[0].authority.as_deref(),
            Some(authority.as_str())
        );
        assert_eq!(
            observed.origin_requests[0].path_and_query.as_deref(),
            Some("/finish-positive")
        );
        assert_eq!(observed.alternative_connections, 0);
        assert!(observed.alternative_requests.is_empty());
        Ok(())
    })
    .await?
}
