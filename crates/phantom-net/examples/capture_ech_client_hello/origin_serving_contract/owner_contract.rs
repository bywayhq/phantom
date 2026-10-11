use std::{
    error::Error,
    io, mem,
    pin::Pin,
    sync::{
        Arc, PoisonError,
        atomic::{AtomicBool, Ordering},
    },
};

use btls::{
    ssl::{SslConnector, SslMethod, SslVerifyMode},
    x509::X509,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    task::JoinSet,
    time::timeout,
};
use tokio_btls::SslStream;

use super::{
    CONTROL_TIMEOUT, LocalServingFailure, OriginResources, ServingFault, receive_page, with_backup,
};
use crate::tests::{Client, Server, ServerMode, TestResult, assert_closed, exchange};
use crate::{CaptureResult, GRACE_PERIOD, HOSTNAME, capture_errors, finish_capture, spawn_origin_tcp};

struct CaptureOrigin {
    resources: OriginResources,
    tasks: JoinSet<()>,
}

impl CaptureOrigin {
    async fn start() -> CaptureResult<Self> {
        Ok(Self {
            resources: OriginResources::start().await?,
            tasks: JoinSet::new(),
        })
    }

    async fn peer(&mut self) -> CaptureResult<Client> {
        timeout(CONTROL_TIMEOUT, async {
            let tcp = TcpStream::connect(self.resources.listener.local_addr()?).await?;
            self.accept().await?;

            let mut builder = SslConnector::bare_builder(SslMethod::tls())?;
            builder.set_verify(SslVerifyMode::PEER);
            builder
                .cert_store_mut()
                .add_cert(X509::from_der(&self.resources.trust_root)?)?;
            let ssl = builder.build().configure()?.into_ssl(HOSTNAME)?;
            let mut tls = SslStream::new(ssl, tcp)?;
            Pin::new(&mut tls).connect().await?;
            Ok(BufReader::new(tls))
        })
        .await?
    }

    async fn accept(&mut self) -> TestResult {
        let (tcp, peer) = self.resources.listener.accept().await?;
        spawn_origin_tcp(
            &mut self.tasks,
            tcp,
            peer,
            self.resources.acceptor.clone(),
            Arc::clone(&self.resources.captured),
        );
        Ok(())
    }

    async fn speculative_eof(&mut self) -> TestResult {
        timeout(CONTROL_TIMEOUT, async {
            let mut tcp = TcpStream::connect(self.resources.listener.local_addr()?).await?;
            self.accept().await?;
            tcp.shutdown().await?;
            let mut byte = [0];
            assert!(matches!(tcp.read(&mut byte).await, Ok(0) | Err(_)));
            Ok(())
        })
        .await?
    }

    async fn finish(&mut self, dns: &mut Server) -> TestResult {
        let capture = dns.take_capture()?;
        let tasks = mem::take(&mut self.tasks);
        let mut finish = Box::pin(finish_capture(Ok(()), tasks, capture));
        match timeout(GRACE_PERIOD + CONTROL_TIMEOUT, finish.as_mut()).await {
            Ok(result) => result,
            Err(primary) => {
                let backup = timeout(CONTROL_TIMEOUT, finish.as_mut()).await;
                let mut errors = vec![Box::new(primary) as Box<dyn Error + Send + Sync>];
                match backup {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => errors.push(error),
                    Err(error) => errors.push(error.into()),
                }
                capture_errors(errors)
            }
        }
    }

    async fn stop(&mut self) -> TestResult {
        self.tasks.abort_all();
        let mut errors = Vec::new();
        loop {
            match timeout(CONTROL_TIMEOUT, self.tasks.join_next()).await {
                Ok(Some(Ok(()))) => {}
                Ok(Some(Err(error))) if error.is_cancelled() => {}
                Ok(Some(Err(error))) => errors.push(error.into()),
                Ok(None) => break,
                Err(error) => {
                    errors.push(error.into());
                    break;
                }
            }
        }
        if let Err(error) = self.resources.stop().await {
            errors.push(error);
        }
        capture_errors(errors)
    }
}

async fn backup(origin: &mut CaptureOrigin, dns: &mut Server) -> TestResult {
    let origin = origin.stop().await;
    let dns = if dns.task.is_some() {
        dns.stop().await
    } else {
        Ok(())
    };
    capture_errors(origin.err().into_iter().chain(dns.err()).collect())
}

#[tokio::test]
async fn finish_capture_observes_two_healthy_registered_tcp_workers() -> TestResult {
    let mut origin = CaptureOrigin::start().await?;
    let mut dns = Server::start(ServerMode::Capture).await?;
    let result = async {
        let mut dns_peer = dns.client().await?;
        exchange(&mut dns_peer, HOSTNAME, 1).await?;
        let mut first = origin.peer().await?;
        receive_page(&mut first).await?;
        assert_closed(&mut first).await?;
        let mut second = origin.peer().await?;
        receive_page(&mut second).await?;
        assert_closed(&mut second).await?;

        origin.finish(&mut dns).await?;
        assert_closed(&mut dns_peer).await?;
        assert_eq!(dns.descriptions(), [format!("A {HOSTNAME}")]);
        let (records, quic) = origin.resources.captured.take();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| record.handshake.is_ok()));
        assert!(records.iter().all(|record| !record.records.is_empty()));
        assert!(records.iter().all(|record| record.request_served));
        assert!(origin.resources.captured.page_served());
        assert!(quic.is_empty());
        Ok(())
    }
    .await;
    let cleanup = backup(&mut origin, &mut dns).await;

    with_backup(result, cleanup)
}

#[tokio::test]
async fn finish_capture_keeps_idle_and_speculative_eof_beside_a_healthy_tcp_worker() -> TestResult {
    let mut origin = CaptureOrigin::start().await?;
    let mut dns = Server::start(ServerMode::Capture).await?;
    let result = async {
        let mut dns_peer = dns.client().await?;
        exchange(&mut dns_peer, HOSTNAME, 1).await?;
        let mut healthy = origin.peer().await?;
        receive_page(&mut healthy).await?;
        assert_closed(&mut healthy).await?;
        let mut idle = origin.peer().await?;
        idle.shutdown().await?;
        assert_closed(&mut idle).await?;
        origin.speculative_eof().await?;

        origin.finish(&mut dns).await?;
        assert_closed(&mut dns_peer).await?;
        assert_eq!(dns.descriptions(), [format!("A {HOSTNAME}")]);
        let (records, quic) = origin.resources.captured.take();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| record.handshake.is_ok()));
        assert!(records.iter().all(|record| !record.records.is_empty()));
        assert!(records[0].request_served);
        assert!(!records[1].request_served);
        assert!(origin.resources.captured.page_served());
        assert!(quic.is_empty());
        Ok(())
    }
    .await;
    let cleanup = backup(&mut origin, &mut dns).await;

    with_backup(result, cleanup)
}

#[tokio::test]
async fn finish_capture_retains_a_local_tcp_serving_failure_beside_a_healthy_worker() -> TestResult {
    let mut origin = CaptureOrigin::start().await?;
    let mut dns = Server::start(ServerMode::Capture).await?;
    let identity = Arc::new(());
    let reached = Arc::new(AtomicBool::new(false));
    let result = async {
        let mut dns_peer = dns.client().await?;
        exchange(&mut dns_peer, HOSTNAME, 1).await?;
        let mut healthy = origin.peer().await?;
        receive_page(&mut healthy).await?;
        assert_closed(&mut healthy).await?;

        *origin
            .resources
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
        let mut faulted = origin.peer().await?;
        receive_page(&mut faulted).await?;
        assert_closed(&mut faulted).await?;
        assert!(reached.load(Ordering::Acquire));

        let outcome = origin.finish(&mut dns).await;
        assert_closed(&mut dns_peer).await?;
        assert_eq!(dns.descriptions(), [format!("A {HOSTNAME}")]);
        let (records, quic) = origin.resources.captured.take();
        assert_eq!(records.len(), 2);
        assert!(records.iter().all(|record| record.handshake.is_ok()));
        assert!(records.iter().all(|record| !record.records.is_empty()));
        assert!(records[0].request_served);
        assert!(!records[1].request_served);
        assert!(origin.resources.captured.page_served());
        assert!(quic.is_empty());

        let error = outcome
            .err()
            .ok_or("finish_capture discarded the registered worker's original serving failure")?;
        let io = error
            .downcast_ref::<io::Error>()
            .ok_or("finish_capture replaced the original local I/O failure")?;
        assert_eq!(io.kind(), io::ErrorKind::PermissionDenied);
        let cause = io
            .get_ref()
            .and_then(|cause| cause.downcast_ref::<LocalServingFailure>())
            .ok_or("finish_capture replaced the original local failure payload")?;
        assert!(Arc::ptr_eq(&cause.0, &identity));
        Ok(())
    }
    .await;
    let cleanup = backup(&mut origin, &mut dns).await;

    with_backup(result, cleanup)
}
