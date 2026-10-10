use std::{
    error::Error,
    fmt,
    future::{Future, poll_fn},
    io,
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Duration,
};

use http::{StatusCode, Version};
use http_body_util::BodyExt;
use phantom::{Client, RequestError};
use phantom_testkit::dns::DnsServer;
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{Barrier, oneshot, watch},
    task::{AbortHandle, JoinHandle},
    time::timeout,
};
use tokio_btls::SslStream;

use super::{
    ORIGIN_NAME, Observed, PUBLIC_NAME, Replayed, TEST_ECH_KEYS, TestResult, chrome, client_with,
    collect_parallel_requests, ech_acceptor, ech_config, ech_config_list, ech_tls_settings,
    finish_parallel_operation, https_rdata, spawn_parallel_origin, write_response,
};
use crate::support::{
    ech::{origin_identity, record_server},
    h3::client_settings,
    tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup},
};

const OBSERVATION_TIMEOUT: Duration = Duration::from_secs(2);
const CONTROL_TIMEOUT: Duration = Duration::from_secs(12);

pub(super) struct Lifetime(watch::Sender<bool>);

impl Drop for Lifetime {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

pub(super) struct ParallelObservation {
    workers: std::vec::IntoIter<WorkerObservation>,
    pub(super) prime_started: watch::Sender<Option<AbortHandle>>,
    pub(super) pending_accept: Option<oneshot::Sender<()>>,
    pub(super) collect_after: Option<oneshot::Receiver<()>>,
}

impl ParallelObservation {
    pub(super) fn next_worker(&mut self) -> Option<WorkerObservation> {
        self.workers.next()
    }
}

pub(super) struct WorkerObservation {
    pub(super) started: watch::Sender<Option<AbortHandle>>,
    head: Option<oneshot::Sender<Head>>,
    pending_barrier: Option<oneshot::Sender<()>>,
    _lifetime: Lifetime,
    response: ResponseWire,
    failure: Option<io::Error>,
    reached_outcome: Arc<AtomicBool>,
}

impl WorkerObservation {
    pub(super) fn record_head(&mut self, bytes: Vec<u8>, seen: &Observed) -> TestResult<()> {
        if let Some(head) = self.head.take() {
            head.send(Head {
                bytes,
                outer_name: seen.outer_server_name.clone(),
                inner_name: seen.inner_server_name.clone(),
                ech_accepted: seen.ech_accepted,
            })
            .map_err(|_| {
                io::Error::new(io::ErrorKind::BrokenPipe, "parallel head observer closed")
            })?;
        }
        Ok(())
    }

    pub(super) async fn wait_at_barrier(&mut self, barrier: &Barrier) -> TestResult<()> {
        match self.pending_barrier.take() {
            Some(pending) => {
                observe_pending(barrier.wait(), pending).await?;
            }
            None => {
                barrier.wait().await;
            }
        }
        Ok(())
    }

    pub(super) async fn respond(&self, tls: &mut SslStream<Replayed>) -> TestResult<()> {
        match self.response {
            ResponseWire::Complete => write_response(tls).await,
            ResponseWire::Truncated => {
                tls.write_all(b"HTTP/1.1 200").await?;
                tls.shutdown().await?;
                Ok(())
            }
        }
    }

    pub(super) fn outcome(&mut self) -> TestResult<()> {
        self.reached_outcome.store(true, Ordering::Release);
        match self.failure.take() {
            Some(error) => Err(error.into()),
            None => Ok(()),
        }
    }
}

pub(super) async fn observe_pending<F: Future>(
    future: F,
    pending: oneshot::Sender<()>,
) -> TestResult<F::Output> {
    let mut future = Box::pin(future);
    let mut pending = Some(pending);
    poll_fn(|context| {
        let result = future.as_mut().poll(context);
        if result.is_pending()
            && let Some(pending) = pending.take()
            && pending.send(()).is_err()
        {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "parallel pending observer closed",
            )
            .into()));
        }
        result.map(Ok)
    })
    .await
}

#[derive(Clone, Copy)]
enum ResponseWire {
    Complete,
    Truncated,
}

struct Head {
    bytes: Vec<u8>,
    outer_name: Option<String>,
    inner_name: Option<String>,
    ech_accepted: bool,
}

struct WorkerWitness {
    started: watch::Sender<Option<AbortHandle>>,
    destroyed: watch::Receiver<bool>,
    head: oneshot::Receiver<Head>,
    pending_barrier: oneshot::Receiver<()>,
    reached_outcome: Arc<AtomicBool>,
}

struct Backup {
    parent: AbortHandle,
    parent_destroyed: watch::Receiver<bool>,
    prime_started: watch::Sender<Option<AbortHandle>>,
    workers: [WorkerWitness; 2],
}

impl Backup {
    async fn completed_workers(&self) -> TestResult<()> {
        for worker in &self.workers {
            let mut started = worker.started.subscribe();
            let handle = timeout(OBSERVATION_TIMEOUT, started.wait_for(Option::is_some))
                .await??
                .as_ref()
                .ok_or("parallel worker handle was not published")?
                .clone();
            timeout(OBSERVATION_TIMEOUT, async {
                while !handle.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            assert!(
                worker.reached_outcome.load(Ordering::Acquire),
                "parallel worker did not reach its actual post-response outcome"
            );
        }
        Ok(())
    }

    async fn stop(&mut self) -> TestResult<()> {
        self.abort_all();
        timeout(
            OBSERVATION_TIMEOUT,
            self.parent_destroyed.wait_for(|done| *done),
        )
        .await??;

        // No new prime task can be registered after the parent is destroyed.
        let prime = self.prime_started.borrow().as_ref().cloned();
        if let Some(prime) = prime {
            prime.abort();
            timeout(OBSERVATION_TIMEOUT, async {
                while !prime.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
        }

        for worker in &mut self.workers {
            timeout(OBSERVATION_TIMEOUT, worker.destroyed.wait_for(|done| *done)).await??;
            let handle = worker.started.borrow().as_ref().cloned();
            if let Some(handle) = handle {
                timeout(OBSERVATION_TIMEOUT, async {
                    while !handle.is_finished() {
                        tokio::task::yield_now().await;
                    }
                })
                .await?;
            }
        }
        Ok(())
    }

    fn abort_all(&self) {
        self.parent.abort();
        if let Some(prime) = self.prime_started.borrow().as_ref() {
            prime.abort();
        }
        for worker in &self.workers {
            if let Some(handle) = worker.started.borrow().as_ref() {
                handle.abort();
            }
        }
    }
}

impl Drop for Backup {
    fn drop(&mut self) {
        self.abort_all();
    }
}

struct Driven {
    server: JoinHandle<TestResult<(Vec<Observed>, Vec<Observed>)>>,
    client: Client,
    dns: DnsServer,
    port: u16,
    pending_accept: oneshot::Receiver<()>,
    release_collection: oneshot::Sender<()>,
    backup: Backup,
}

#[derive(Debug)]
struct WorkerFailure {
    worker: usize,
    identity: Arc<()>,
}

impl fmt::Display for WorkerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "controlled parallel worker failure {}",
            self.worker
        )
    }
}

impl Error for WorkerFailure {}

enum StopOwner {
    Abandon,
    AbortParent,
    AbortTree,
}

#[tokio::test]
async fn abandoning_the_parallel_origin_destroys_its_waiting_worker() -> TestResult<()> {
    observe_destruction(StopOwner::Abandon).await
}

#[tokio::test]
async fn joining_the_aborted_parallel_parent_destroys_its_waiting_worker() -> TestResult<()> {
    observe_destruction(StopOwner::AbortParent).await
}

#[tokio::test]
async fn explicitly_stopping_parent_and_worker_destroys_the_barrier_wait() -> TestResult<()> {
    observe_destruction(StopOwner::AbortTree).await
}

async fn observe_destruction(stop: StopOwner) -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let Driven {
            server,
            client,
            dns,
            port,
            mut pending_accept,
            release_collection,
            mut backup,
        } = driven([ResponseWire::Complete; 2], [None, None]).await?;
        let mut request = Box::pin(request(client.clone(), port, 0));
        let observation = async {
            poll_fn(|context| -> Poll<TestResult<()>> {
                if let Poll::Ready(result) = request.as_mut().poll(context) {
                    return Poll::Ready(result.and_then(|()| {
                        Err(
                            "parallel response completed before the missing barrier participant"
                                .into(),
                        )
                    }));
                }
                match std::pin::Pin::new(&mut backup.workers[0].pending_barrier).poll(context) {
                    Poll::Ready(result) => Poll::Ready(result.map_err(Into::into)),
                    Poll::Pending => Poll::Pending,
                }
            })
            .await?;
            timeout(OBSERVATION_TIMEOUT, &mut pending_accept).await??;
            let head = timeout(OBSERVATION_TIMEOUT, &mut backup.workers[0].head).await??;
            assert_head(&head, port)?;
            assert!(head.bytes.starts_with(b"GET /parallel-0 HTTP/1.1\r\n"));

            match stop {
                StopOwner::Abandon => drop(server),
                StopOwner::AbortParent | StopOwner::AbortTree => {
                    backup.parent.abort();
                    let joined = timeout(OBSERVATION_TIMEOUT, server).await?;
                    assert!(matches!(joined, Err(ref error) if error.is_cancelled()));
                    timeout(
                        OBSERVATION_TIMEOUT,
                        backup.parent_destroyed.wait_for(|done| *done),
                    )
                    .await??;
                    if matches!(stop, StopOwner::AbortTree) {
                        backup.abort_all();
                    }
                }
            }

            let destroyed = timeout(
                OBSERVATION_TIMEOUT,
                backup.workers[0].destroyed.wait_for(|done| *done),
            )
            .await;
            match destroyed {
                Ok(result) => {
                    result?;
                    Ok(true)
                }
                Err(_) => Ok(false),
            }
        }
        .await;

        let before_backup = finish_with_cleanup(observation, backup.stop().await)?;
        drop(request);
        drop(release_collection);
        drop(client);
        drop(dns);
        assert!(
            before_backup,
            "parallel ECH worker outlived its owner while waiting at the actual barrier"
        );
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn collecting_parallel_workers_retains_both_completed_failures() -> TestResult<()> {
    observe_outcomes(OutcomeCase::TwoWorkers).await
}

#[tokio::test]
async fn collecting_parallel_workers_preserves_real_successful_responses() -> TestResult<()> {
    observe_outcomes(OutcomeCase::Success).await
}

#[tokio::test]
async fn a_truncated_parallel_response_keeps_the_completed_worker_failure() -> TestResult<()> {
    observe_outcomes(OutcomeCase::ClientAndWorker).await
}

enum OutcomeCase {
    TwoWorkers,
    Success,
    ClientAndWorker,
}

async fn observe_outcomes(case: OutcomeCase) -> TestResult<()> {
    timeout(CONTROL_TIMEOUT, async {
        let first = Arc::new(());
        let second = Arc::new(());
        let failures = match case {
            OutcomeCase::TwoWorkers => [
                Some(worker_failure(0, io::ErrorKind::PermissionDenied, &first)),
                Some(worker_failure(1, io::ErrorKind::InvalidData, &second)),
            ],
            OutcomeCase::Success => [None, None],
            OutcomeCase::ClientAndWorker => [
                None,
                Some(worker_failure(1, io::ErrorKind::PermissionDenied, &second)),
            ],
        };
        let responses = match case {
            OutcomeCase::ClientAndWorker => [ResponseWire::Truncated, ResponseWire::Complete],
            _ => [ResponseWire::Complete; 2],
        };
        let Driven {
            server,
            client,
            dns,
            port,
            pending_accept,
            release_collection,
            mut backup,
        } = driven(responses, failures).await?;
        // The response fault follows accept order; either request can receive it.
        let requests = (0..2)
            .map(|index| request(client.clone(), port, index))
            .collect();
        let operation = collect_parallel_requests(requests).await;
        let checked = async {
            if matches!(case, OutcomeCase::ClientAndWorker) {
                assert_client_protocol_error(
                    operation
                        .as_ref()
                        .err()
                        .ok_or("truncated response was accepted")?
                        .as_ref(),
                )?;
            } else {
                assert!(
                    operation.is_ok(),
                    "successful response operation failed: {operation:?}"
                );
            }

            let mut heads = Vec::new();
            for worker in &mut backup.workers {
                let head = timeout(OBSERVATION_TIMEOUT, &mut worker.head).await??;
                assert_head(&head, port)?;
                heads.push(head.bytes);
            }
            assert!(
                heads
                    .iter()
                    .any(|head| head.starts_with(b"GET /parallel-0 HTTP/1.1\r\n"))
            );
            assert!(
                heads
                    .iter()
                    .any(|head| head.starts_with(b"GET /parallel-1 HTTP/1.1\r\n"))
            );
            backup.completed_workers().await?;
            release_collection
                .send(())
                .map_err(|_| "parallel collector closed before release")?;
            timeout(OBSERVATION_TIMEOUT, async {
                while !server.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await?;

            finish_parallel_operation(server, async { operation }).await
        }
        .await;
        let result = finish_with_cleanup(checked, backup.stop().await);
        drop(pending_accept);
        drop(client);
        drop(dns);

        match case {
            OutcomeCase::Success => {
                let (prime, parallel) = result?;
                assert_eq!(prime.len(), 1);
                assert_eq!(parallel.len(), 2);
                Ok(())
            }
            OutcomeCase::TwoWorkers | OutcomeCase::ClientAndWorker => {
                let error = result
                    .err()
                    .ok_or("parallel fixture lost its failed outcomes")?;
                let failures = error
                    .downcast_ref::<FixtureFailures>()
                    .ok_or("parallel fixture did not retain both completed causes")?;
                if matches!(case, OutcomeCase::TwoWorkers) {
                    assert_worker_failure(
                        failures.primary.as_ref(),
                        0,
                        io::ErrorKind::PermissionDenied,
                        &first,
                    )?;
                    assert_worker_failure(
                        failures.cleanup.as_ref(),
                        1,
                        io::ErrorKind::InvalidData,
                        &second,
                    )?;
                } else {
                    assert_client_protocol_error(failures.primary.as_ref())?;
                    assert_worker_failure(
                        failures.cleanup.as_ref(),
                        1,
                        io::ErrorKind::PermissionDenied,
                        &second,
                    )?;
                }
                Ok(())
            }
        }
    })
    .await?
}

async fn driven(
    responses: [ResponseWire; 2],
    failures: [Option<io::Error>; 2],
) -> TestResult<Driven> {
    let identity = origin_identity()?;
    let acceptor = ech_acceptor(&identity)?;
    let config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
    let dns = record_server(vec![https_rdata(&ech_config_list(&[config]))]).await?;
    let profile = phantom::profile::ClientProfile::new(ech_tls_settings())
        .with_http2(chrome::v154_http2())
        .with_http3(client_settings())
        .with_http1(chrome::v154_http1());
    let client = client_with(&identity, &dns, profile)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let (pending_accept, wait_for_accept) = oneshot::channel();
    let (release_collection, collect_after) = oneshot::channel();
    let (parent_destroyed, wait_for_parent) = watch::channel(false);
    let (prime_started, _) = watch::channel(None);
    let mut observations = Vec::new();
    let mut witnesses = Vec::new();
    for (response, failure) in responses.into_iter().zip(failures) {
        let (started, _) = watch::channel(None);
        let (head, wait_for_head) = oneshot::channel();
        let (pending_barrier, wait_for_barrier) = oneshot::channel();
        let (destroyed, wait_for_destruction) = watch::channel(false);
        let reached_outcome = Arc::new(AtomicBool::new(false));
        observations.push(WorkerObservation {
            started: started.clone(),
            head: Some(head),
            pending_barrier: Some(pending_barrier),
            _lifetime: Lifetime(destroyed),
            response,
            failure,
            reached_outcome: Arc::clone(&reached_outcome),
        });
        witnesses.push(WorkerWitness {
            started,
            destroyed: wait_for_destruction,
            head: wait_for_head,
            pending_barrier: wait_for_barrier,
            reached_outcome,
        });
    }
    let workers: [WorkerWitness; 2] = witnesses
        .try_into()
        .map_err(|_| "expected two worker witnesses")?;
    let server = spawn_parallel_origin(
        listener,
        acceptor,
        2,
        Some(ParallelObservation {
            workers: observations.into_iter(),
            prime_started: prime_started.clone(),
            pending_accept: Some(pending_accept),
            collect_after: Some(collect_after),
        }),
        Some(Lifetime(parent_destroyed)),
    );
    let mut backup = Backup {
        parent: server.abort_handle(),
        parent_destroyed: wait_for_parent,
        prime_started,
        workers,
    };

    if let Err(error) = request(client.clone(), port, usize::MAX).await {
        return finish_with_cleanup(Err(error), backup.stop().await);
    }

    // Preserve the ordinary cache-settling interval; actual ECH is asserted below.
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(Driven {
        server,
        client,
        dns,
        port,
        pending_accept: wait_for_accept,
        release_collection,
        backup,
    })
}

async fn request(client: Client, port: u16, index: usize) -> TestResult<()> {
    let path = if index == usize::MAX {
        "/prime".to_owned()
    } else {
        format!("/parallel-{index}")
    };
    let response = client
        .get_negotiated(&format!("https://{ORIGIN_NAME}:{port}{path}"))?
        .send()
        .await?;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_11);
    assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
    Ok(())
}

fn assert_head(head: &Head, port: u16) -> TestResult<()> {
    assert!(head.bytes.starts_with(b"GET /parallel-"));
    assert!(head.bytes.ends_with(b"\r\n\r\n"));
    let authority = format!("host: {ORIGIN_NAME}:{port}\r\n");
    assert!(
        head.bytes
            .windows(authority.len())
            .any(|bytes| bytes.eq_ignore_ascii_case(authority.as_bytes()))
    );
    assert_eq!(head.outer_name.as_deref(), Some(PUBLIC_NAME));
    assert!(head.ech_accepted);
    assert_eq!(head.inner_name.as_deref(), Some(ORIGIN_NAME));
    Ok(())
}

fn worker_failure(worker: usize, kind: io::ErrorKind, identity: &Arc<()>) -> io::Error {
    io::Error::new(
        kind,
        WorkerFailure {
            worker,
            identity: Arc::clone(identity),
        },
    )
}

fn assert_worker_failure(
    error: &(dyn Error + 'static),
    worker: usize,
    kind: io::ErrorKind,
    identity: &Arc<()>,
) -> TestResult<()> {
    let error = error
        .downcast_ref::<io::Error>()
        .ok_or("parallel worker lost its I/O error")?;
    assert_eq!(error.kind(), kind);

    let cause = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<WorkerFailure>())
        .ok_or("parallel worker lost its typed original cause")?;
    assert_eq!(cause.worker, worker);
    assert!(Arc::ptr_eq(&cause.identity, identity));
    Ok(())
}

fn assert_client_protocol_error(error: &(dyn Error + 'static)) -> TestResult<()> {
    let request = error
        .downcast_ref::<RequestError>()
        .ok_or("incomplete response lost its request error")?;
    assert_eq!(request.kind(), phantom::RequestErrorKind::Http1);
    assert!(matches!(
        request
            .source()
            .and_then(|error| error.downcast_ref::<phantom_net::http1::Http1Error>()),
        Some(phantom_net::http1::Http1Error::Protocol(_))
    ));
    Ok(())
}
