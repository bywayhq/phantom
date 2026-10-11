use std::{
    error::Error,
    fmt, io,
    pin::Pin,
    sync::{
        Arc, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use btls::{
    ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::timeout,
};
use tokio_btls::SslStream;

use super::{Client, TestResult, assert_closed, test_identity};
use crate::{CaptureResult, Captured, HOSTNAME, capture_errors, record_tcp};

const CONTROL_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) struct ServingFault {
    slot: usize,
    error: io::Error,
    reached: Arc<AtomicBool>,
}

pub(crate) fn observe_serving(
    result: io::Result<bool>,
    captured: &Captured,
    slot: usize,
) -> io::Result<bool> {
    if !matches!(result, Ok(true)) {
        return result;
    }

    let mut fault = captured
        .serving_fault
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if fault.as_ref().is_some_and(|fault| fault.slot == slot) {
        let fault = fault.take().ok_or_else(|| {
            io::Error::other("post-serving fault was removed before observation")
        })?;
        fault.reached.store(true, Ordering::Release);
        return Err(fault.error);
    }

    result
}

struct OriginResources {
    listener: TcpListener,
    acceptor: SslAcceptor,
    trust_root: Vec<u8>,
    captured: Arc<Captured>,
    tasks: JoinSet<CaptureResult<()>>,
}

impl OriginResources {
    async fn start() -> CaptureResult<Self> {
        let (identity, trust_root) = test_identity()?;
        let acceptor = identity.acceptor(None)?;
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        Ok(Self {
            listener,
            acceptor,
            trust_root,
            captured: Arc::new(Captured::default()),
            tasks: JoinSet::new(),
        })
    }

    async fn peer(&mut self) -> CaptureResult<Client> {
        timeout(CONTROL_TIMEOUT, async {
            let tcp = TcpStream::connect(self.listener.local_addr()?).await?;
            let (accepted, _) = self.listener.accept().await?;
            let slot = self.captured.reserve_tcp();
            self.tasks.spawn(record_tcp(
                accepted,
                self.acceptor.clone(),
                Arc::clone(&self.captured),
                slot,
            ));

            let mut builder = SslConnector::bare_builder(SslMethod::tls())?;
            builder.set_verify(SslVerifyMode::PEER);
            builder
                .cert_store_mut()
                .add_cert(X509::from_der(&self.trust_root)?)?;
            let ssl = builder.build().configure()?.into_ssl(HOSTNAME)?;
            let mut tls = SslStream::new(ssl, tcp)?;
            Pin::new(&mut tls).connect().await?;
            Ok(BufReader::new(tls))
        })
        .await?
    }

    async fn record_outcome(&mut self) -> CaptureResult<()> {
        let joined = timeout(CONTROL_TIMEOUT, self.tasks.join_next())
            .await?
            .ok_or("origin worker was not registered")?;
        joined?
    }

    async fn stop(&mut self) -> CaptureResult<()> {
        self.tasks.abort_all();
        let mut errors = Vec::new();
        loop {
            let joined = match timeout(CONTROL_TIMEOUT, self.tasks.join_next()).await {
                Ok(Some(joined)) => joined,
                Ok(None) => break,
                Err(error) => {
                    errors.push(error.into());
                    break;
                }
            };
            match joined {
                Ok(Ok(())) => {}
                Ok(Err(error)) => errors.push(error),
                Err(error) if error.is_cancelled() => {}
                Err(error) => errors.push(error.into()),
            }
        }

        capture_errors(errors)
    }
}

async fn receive_page(peer: &mut Client) -> TestResult {
    timeout(CONTROL_TIMEOUT, async {
        peer.write_all(b"GET /origin-serving HTTP/1.1\r\nhost: server.phantom.test\r\n\r\n")
            .await?;
        peer.flush().await?;

        let mut status = String::new();
        peer.read_line(&mut status).await?;
        assert_eq!(status, "HTTP/1.1 200 OK\r\n");
        let mut length = None;
        loop {
            let mut line = String::new();
            let read = peer.read_line(&mut line).await?;
            if read == 0 {
                return Err("origin response ended before its header delimiter".into());
            }
            if line == "\r\n" {
                break;
            }
            if let Some(value) = line.strip_prefix("content-length: ") {
                length = Some(value.trim().parse::<usize>()?);
            }
        }

        let expected = b"<!doctype html><meta charset=utf-8><link rel=icon href=\"data:,\">ok\n";
        assert_eq!(length, Some(expected.len()));
        let mut body = vec![0; expected.len()];
        peer.read_exact(&mut body).await?;
        assert_eq!(body, expected);
        Ok(())
    })
    .await?
}

fn with_backup(primary: TestResult, cleanup: TestResult) -> TestResult {
    capture_errors(primary.err().into_iter().chain(cleanup.err()).collect())
}

#[derive(Debug)]
struct LocalServingFailure(Arc<()>);

impl fmt::Display for LocalServingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled local failure after actual TCP serving")
    }
}

impl Error for LocalServingFailure {}

#[tokio::test]
async fn a_trusted_tcp_peer_receives_the_literal_capture_page() -> TestResult {
    let mut resources = OriginResources::start().await?;
    let result = async {
        let mut peer = resources.peer().await?;
        receive_page(&mut peer).await?;
        resources.record_outcome().await?;
        assert_closed(&mut peer).await?;

        let (records, quic) = resources.captured.take();
        assert_eq!(records.len(), 1);
        assert!(records[0].handshake.is_ok());
        assert!(!records[0].records.is_empty());
        assert!(records[0].request_served);
        assert!(resources.captured.page_served());
        assert!(quic.is_empty());
        Ok(())
    }
    .await;
    let cleanup = resources.stop().await;

    with_backup(result, cleanup)
}

#[tokio::test]
async fn a_trusted_idle_tcp_peer_remains_a_partial_capture_beside_a_healthy_peer() -> TestResult {
    let mut resources = OriginResources::start().await?;
    let result = async {
        let mut healthy = resources.peer().await?;
        receive_page(&mut healthy).await?;
        resources.record_outcome().await?;
        assert_closed(&mut healthy).await?;

        let mut idle = resources.peer().await?;
        idle.shutdown().await?;
        resources.record_outcome().await?;
        assert_closed(&mut idle).await?;

        let (records, quic) = resources.captured.take();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| record.handshake.is_ok()));
        assert!(records.iter().all(|record| !record.records.is_empty()));
        assert!(records[0].request_served);
        assert!(!records[1].request_served);
        assert!(resources.captured.page_served());
        assert!(quic.is_empty());
        Ok(())
    }
    .await;
    let cleanup = resources.stop().await;

    with_backup(result, cleanup)
}

#[tokio::test]
async fn record_tcp_retains_a_local_post_serving_failure_beside_a_healthy_peer() -> TestResult {
    let mut resources = OriginResources::start().await?;
    let identity = Arc::new(());
    let reached = Arc::new(AtomicBool::new(false));
    let result = async {
        let mut healthy = resources.peer().await?;
        receive_page(&mut healthy).await?;
        resources.record_outcome().await?;
        assert_closed(&mut healthy).await?;

        *resources
            .captured
            .serving_fault
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(ServingFault {
            slot: 1,
            error: io::Error::new(
                io::ErrorKind::PermissionDenied,
                LocalServingFailure(Arc::clone(&identity)),
            ),
            reached: Arc::clone(&reached),
        });
        let mut faulted = resources.peer().await?;
        receive_page(&mut faulted).await?;
        let outcome = resources.record_outcome().await;
        assert_closed(&mut faulted).await?;

        assert!(reached.load(Ordering::Acquire));
        let (records, quic) = resources.captured.take();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| record.handshake.is_ok()));
        assert!(records.iter().all(|record| !record.records.is_empty()));
        assert!(records[0].request_served);
        assert!(!records[1].request_served);
        assert!(resources.captured.page_served());
        assert!(quic.is_empty());

        let error = outcome
            .err()
            .ok_or("record_tcp discarded the original local post-serving failure")?;
        let io = error
            .downcast_ref::<io::Error>()
            .ok_or("record_tcp replaced the original local I/O failure")?;
        assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);
        let cause = io
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<LocalServingFailure>())
            .ok_or("record_tcp replaced the original local failure payload")?;
        assert!(Arc::ptr_eq(&cause.0, &identity));
        Ok(())
    }
    .await;
    let cleanup = resources.stop().await;

    with_backup(result, cleanup)
}

mod owner_contract;
