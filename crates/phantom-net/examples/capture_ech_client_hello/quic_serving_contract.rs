use std::{
    error::Error,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use h3::error::StreamError;

use self::capture_origin::QuicCapture;
use super::{TestResult, assert_closed, exchange};
use crate::{Captured, HOSTNAME, capture_errors};

mod capture_origin;
mod observation_contract;
mod peer_input_contract;
mod peer_response_contract;
mod request_fatal_contract;
pub(crate) mod request_resolution_contract;
pub(crate) mod response_delivery;

pub(crate) struct QuicServingFault {
    slot: usize,
    error: StreamError,
    reached: Arc<AtomicBool>,
}

pub(crate) fn observe_response(
    result: Result<(), StreamError>,
    captured: &Captured,
    slot: usize,
) -> Result<(), StreamError> {
    if result.is_err() {
        return result;
    }

    let mut fault = captured.quic_serving_fault.lock().map_err(|error| {
        StreamError::Undefined(Box::new(QuicObservationFailure {
            boundary: "response consumption",
            diagnostic: error.to_string(),
        }))
    })?;
    if fault.as_ref().is_some_and(|fault| fault.slot == slot) {
        let fault = fault.take().ok_or_else(|| {
            StreamError::Undefined("post-response fault was removed before observation".into())
        })?;
        fault.reached.store(true, Ordering::Release);
        return Err(fault.error);
    }

    result
}

#[derive(Debug)]
struct QuicObservationFailure {
    boundary: &'static str,
    diagnostic: String,
}

impl fmt::Display for QuicObservationFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "QUIC serving {} observation failed: {}",
            self.boundary, self.diagnostic
        )
    }
}

impl Error for QuicObservationFailure {}

fn install_fault(
    captured: &Captured,
    fault: QuicServingFault,
) -> Result<(), QuicObservationFailure> {
    let mut installed =
        captured
            .quic_serving_fault
            .lock()
            .map_err(|error| QuicObservationFailure {
                boundary: "fault installation",
                diagnostic: error.to_string(),
            })?;
    response_delivery::install(captured, fault.slot)?;
    *installed = Some(fault);
    Ok(())
}

#[derive(Debug)]
struct LocalQuicServingFailure(Arc<()>);

impl fmt::Display for LocalQuicServingFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled local failure after actual HTTP/3 response completion")
    }
}

impl Error for LocalQuicServingFailure {}

#[tokio::test]
async fn finish_capture_observes_two_healthy_registered_quic_workers() -> TestResult {
    let mut capture = QuicCapture::default();
    let result = async {
        capture.start().await?;
        let mut dns_peer = capture
            .dns
            .as_ref()
            .ok_or("DNS owner missing")?
            .client()
            .await?;
        exchange(&mut dns_peer, HOSTNAME, 1).await?;
        let mut first = capture.peer().await?;
        first.page().await?;
        let mut second = capture.peer().await?;
        second.page().await?;
        first.close().await?;
        second.close().await?;
        first.completed().await?;
        second.completed().await?;

        capture.finish().await?;
        assert_closed(&mut dns_peer).await?;
        capture.observe_closed().await?;
        assert!(first.worker.is_finished());
        assert!(second.worker.is_finished());
        assert_eq!(
            capture
                .dns
                .as_ref()
                .ok_or("DNS owner missing")?
                .descriptions(),
            [format!("A {HOSTNAME}")]
        );
        let (tcp, quic) = capture.captured.take();
        assert!(tcp.is_empty());
        assert_eq!(quic.len(), 2);
        assert!(quic.iter().all(|record| record.handshake.is_ok()));
        assert!(quic.iter().all(|record| !record.client_hello.is_empty()));
        assert!(
            quic.iter()
                .all(|record| record.outer_server_name.as_deref() == Some(HOSTNAME.as_bytes()))
        );
        assert!(
            quic.iter()
                .all(|record| record.extension_types.contains(&16))
        );
        assert!(quic.iter().all(|record| record.request_served));
        assert!(capture.captured.page_served());
        Ok(())
    }
    .await;
    let cleanup = capture.stop().await;

    capture_errors(result.err().into_iter().chain(cleanup.err()).collect())
}

#[tokio::test]
async fn finish_capture_keeps_an_idle_handshaken_quic_peer_beside_a_healthy_worker() -> TestResult {
    let mut capture = QuicCapture::default();
    let result = async {
        capture.start().await?;
        let mut dns_peer = capture
            .dns
            .as_ref()
            .ok_or("DNS owner missing")?
            .client()
            .await?;
        exchange(&mut dns_peer, HOSTNAME, 1).await?;
        let mut healthy = capture.peer().await?;
        healthy.page().await?;
        let idle = capture.peer().await?;
        healthy.close().await?;
        idle.close().await?;
        healthy.completed().await?;
        idle.completed().await?;

        capture.finish().await?;
        assert_closed(&mut dns_peer).await?;
        capture.observe_closed().await?;
        assert!(healthy.worker.is_finished());
        assert!(idle.worker.is_finished());
        assert_eq!(
            capture
                .dns
                .as_ref()
                .ok_or("DNS owner missing")?
                .descriptions(),
            [format!("A {HOSTNAME}")]
        );
        let (tcp, quic) = capture.captured.take();
        assert!(tcp.is_empty());
        assert_eq!(quic.len(), 2);
        assert!(quic.iter().all(|record| record.handshake.is_ok()));
        assert!(quic.iter().all(|record| !record.client_hello.is_empty()));
        assert!(quic[0].request_served);
        assert!(!quic[1].request_served);
        assert!(capture.captured.page_served());
        Ok(())
    }
    .await;
    let cleanup = capture.stop().await;

    capture_errors(result.err().into_iter().chain(cleanup.err()).collect())
}

#[tokio::test]
async fn finish_capture_retains_a_local_quic_response_failure_beside_a_healthy_worker() -> TestResult
{
    let mut capture = QuicCapture::default();
    let identity = Arc::new(());
    let reached = Arc::new(AtomicBool::new(false));
    let result = async {
        capture.start().await?;
        let mut dns_peer = capture
            .dns
            .as_ref()
            .ok_or("DNS owner missing")?
            .client()
            .await?;
        exchange(&mut dns_peer, HOSTNAME, 1).await?;
        let mut healthy = capture.peer().await?;
        healthy.page().await?;

        install_fault(
            &capture.captured,
            QuicServingFault {
                slot: 1,
                error: StreamError::Undefined(Box::new(LocalQuicServingFailure(Arc::clone(
                    &identity,
                )))),
                reached: Arc::clone(&reached),
            },
        )?;
        let mut faulted = capture.peer().await?;
        faulted.page().await?;
        assert!(reached.load(Ordering::Acquire));
        healthy.close().await?;
        faulted.close().await?;
        healthy.completed().await?;
        faulted.completed().await?;

        let outcome = capture.finish().await;
        let prerequisite: TestResult = async {
            assert_closed(&mut dns_peer).await?;
            capture.observe_closed().await?;
            assert!(healthy.worker.is_finished());
            assert!(faulted.worker.is_finished());
            assert_eq!(
                capture
                    .dns
                    .as_ref()
                    .ok_or("DNS owner missing")?
                    .descriptions(),
                [format!("A {HOSTNAME}")]
            );
            let (tcp, quic) = capture.captured.take();
            assert!(tcp.is_empty());
            assert_eq!(quic.len(), 2);
            assert!(quic.iter().all(|record| record.handshake.is_ok()));
            assert!(quic.iter().all(|record| !record.client_hello.is_empty()));
            assert!(quic[0].request_served);
            assert!(!quic[1].request_served);
            assert!(capture.captured.page_served());
            Ok(())
        }
        .await;
        if let Err(error) = prerequisite {
            return capture_errors(outcome.err().into_iter().chain(Some(error)).collect());
        }

        let error = outcome
            .err()
            .ok_or("finish_capture discarded the original local QUIC response failure")?;
        let stream = error
            .downcast_ref::<StreamError>()
            .ok_or("finish_capture replaced the original HTTP/3 stream error")?;
        let StreamError::Undefined(cause) = stream else {
            return Err("finish_capture replaced the original local QUIC failure variant".into());
        };
        let cause = cause
            .downcast_ref::<LocalQuicServingFailure>()
            .ok_or("finish_capture replaced the original local QUIC failure payload")?;
        assert!(Arc::ptr_eq(&cause.0, &identity));
        Ok(())
    }
    .await;
    let cleanup = capture.stop().await;

    capture_errors(result.err().into_iter().chain(cleanup.err()).collect())
}
