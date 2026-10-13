use std::{
    error::Error,
    fmt, io,
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use http::{StatusCode, Version};
use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, ResponseInfo};
use tokio::{
    sync::watch,
    task::{AbortHandle, JoinHandle},
    time::timeout,
};

use super::{H1_ALPN, ORIGIN_NAME, Opening, Origin, TEST_ECH_KEYS, ech_acceptor, origin_identity};
use crate::support::{tls::TestResult, tunnel_proxy::connection_peer::FixtureFailures};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) struct ServingObservation {
    workers: std::vec::IntoIter<ObservedServing>,
}

impl ServingObservation {
    pub(super) fn spawn(
        &mut self,
        serving: impl Future<Output = TestResult<()>> + Send + 'static,
    ) -> TestResult<JoinHandle<TestResult<()>>> {
        let worker = self
            .workers
            .next()
            .ok_or("more serving workers than observed")?;

        let task = tokio::spawn(async move {
            serving.await?;
            worker.reached_outcome.store(true, Ordering::Release);
            match worker.failure {
                Some(error) => Err(error.into()),
                None => Ok(()),
            }
        });
        // Each control gives this worker one initially empty witness slot.
        drop(worker.started.send_replace(Some(task.abort_handle())));
        Ok(task)
    }
}

struct ObservedServing {
    failure: Option<io::Error>,
    started: watch::Sender<Option<AbortHandle>>,
    reached_outcome: Arc<AtomicBool>,
}

struct ServingBackup {
    started: [watch::Sender<Option<AbortHandle>>; 2],
    reached_outcomes: [Arc<AtomicBool>; 2],
}

impl ServingBackup {
    async fn finished_workers(&self) -> TestResult<Vec<AbortHandle>> {
        let mut handles = Vec::new();
        for started in &self.started {
            let mut receiver = started.subscribe();
            let handle = timeout(CONTROL_TIMEOUT, receiver.wait_for(Option::is_some))
                .await??
                .as_ref()
                .ok_or("serving worker handle was not published")?
                .clone();
            handles.push(handle);
        }

        timeout(CONTROL_TIMEOUT, async {
            while handles.iter().any(|task| !task.is_finished()) {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        for reached in &self.reached_outcomes {
            assert!(
                reached.load(Ordering::Acquire),
                "actual serving did not reach its controlled outcome"
            );
        }

        Ok(handles)
    }
}

impl Drop for ServingBackup {
    fn drop(&mut self) {
        for started in &self.started {
            if let Some(handle) = started.borrow().as_ref() {
                handle.abort();
            }
        }
    }
}

#[derive(Debug)]
struct ServingFailure {
    connection: usize,
    identity: Arc<()>,
}

impl fmt::Display for ServingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "controlled serving failure {}", self.connection)
    }
}

impl Error for ServingFailure {}

#[tokio::test]
async fn finishing_an_origin_retains_two_completed_serving_io_failures() -> TestResult<()> {
    timeout(Duration::from_secs(12), async {
        let first_identity = Arc::new(());
        let second_identity = Arc::new(());
        let failures = [
            Some(io::Error::new(
                io::ErrorKind::PermissionDenied,
                ServingFailure {
                    connection: 1,
                    identity: Arc::clone(&first_identity),
                },
            )),
            Some(io::Error::new(
                io::ErrorKind::InvalidData,
                ServingFailure {
                    connection: 2,
                    identity: Arc::clone(&second_identity),
                },
            )),
        ];
        let (client, origin, backup) = driven_origin(failures).await?;
        let workers = backup.finished_workers().await?;
        assert_eq!(workers.len(), 2);

        let error = timeout(CONTROL_TIMEOUT, origin.finish())
            .await?
            .err()
            .ok_or("exact ECH origin discarded its completed serving failures")?;
        let failures = error
            .downcast_ref::<FixtureFailures>()
            .ok_or("exact ECH origin did not retain both completed serving causes")?;
        assert_serving_failure(
            failures.primary.as_ref(),
            io::ErrorKind::PermissionDenied,
            1,
            &first_identity,
        )?;
        assert_serving_failure(
            failures.cleanup.as_ref(),
            io::ErrorKind::InvalidData,
            2,
            &second_identity,
        )?;

        drop(client);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn finishing_an_origin_preserves_successful_serving_observations() -> TestResult<()> {
    timeout(Duration::from_secs(12), async {
        let (client, origin, backup) = driven_origin([None, None]).await?;
        let workers = backup.finished_workers().await?;
        assert_eq!(workers.len(), 2);

        let observed = timeout(CONTROL_TIMEOUT, origin.finish()).await??;
        assert_eq!(observed.len(), 2);
        for seen in observed {
            assert_eq!(seen.outer_server_name.as_deref(), Some(ORIGIN_NAME));
            assert!(!seen.ech_accepted);
        }

        drop(client);
        Ok(())
    })
    .await?
}

async fn driven_origin(
    failures: [Option<io::Error>; 2],
) -> TestResult<(Client, Origin, ServingBackup)> {
    let identity = origin_identity()?;
    let acceptor = ech_acceptor(&identity, H1_ALPN, 1, &TEST_ECH_KEYS[0])?;
    let client = Client::builder(Opening::profile(false))
        .add_root_certificate_der(identity.root_der.clone())
        .resolve(ORIGIN_NAME, [Ipv4Addr::LOCALHOST.into()])
        .build()?;
    let started = [watch::Sender::new(None), watch::Sender::new(None)];
    let reached_outcomes = [
        Arc::new(AtomicBool::new(false)),
        Arc::new(AtomicBool::new(false)),
    ];
    let workers = failures
        .into_iter()
        .zip(started.iter().cloned())
        .zip(reached_outcomes.iter().cloned())
        .map(|((failure, started), reached_outcome)| ObservedServing {
            failure,
            started,
            reached_outcome,
        })
        .collect::<Vec<_>>()
        .into_iter();
    let backup = ServingBackup {
        started,
        reached_outcomes,
    };
    let origin = Origin::spawn_serving_observed(
        acceptor,
        vec![Opening::Http1; 2],
        None,
        Some(ServingObservation { workers }),
    )
    .await?;

    for path in ["/serving-first", "/serving-second"] {
        let response = client
            .get(
                HttpProtocol::Http1,
                &format!("https://{ORIGIN_NAME}:{}{path}", origin.port),
            )?
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.version(), Version::HTTP_11);
        assert_eq!(
            response
                .extensions()
                .get::<ResponseInfo>()
                .map(ResponseInfo::protocol),
            Some(HttpProtocol::Http1)
        );
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
    }

    Ok((client, origin, backup))
}

fn assert_serving_failure(
    error: &(dyn Error + 'static),
    kind: io::ErrorKind,
    connection: usize,
    identity: &Arc<()>,
) -> TestResult<()> {
    let io = error
        .downcast_ref::<io::Error>()
        .ok_or("missing original serving I/O failure")?;
    assert_eq!(io.kind(), kind);

    let cause = io
        .get_ref()
        .and_then(|cause| cause.downcast_ref::<ServingFailure>())
        .ok_or("missing original typed serving failure payload")?;
    assert_eq!(cause.connection, connection);
    assert!(Arc::ptr_eq(&cause.identity, identity));
    Ok(())
}
