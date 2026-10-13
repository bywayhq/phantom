use std::{
    error::Error,
    fmt,
    sync::{Arc, OnceLock},
    time::Duration,
};

use bytes::Bytes;
use h3::error::StreamError;
use tokio::time::timeout;

use super::super::{TestResult, assert_closed, exchange};
use super::{QuicObservationFailure, capture_origin::QuicCapture};
use crate::{CaptureFailures, Captured, HOSTNAME, capture_errors};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(3);

type ResolvedRequest = Result<
    (
        http::Request<()>,
        h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    ),
    StreamError,
>;

pub(crate) struct RequestFault {
    slot: usize,
    error: StreamError,
    observed: Arc<OnceLock<(http::Method, http::Uri)>>,
}

pub(crate) fn observe_request(
    result: ResolvedRequest,
    captured: &Captured,
    slot: usize,
) -> ResolvedRequest {
    let (request, stream) = match result {
        Ok(resolved) => resolved,
        Err(error) => return Err(error),
    };

    let mut installed = captured.quic_request_fault.lock().map_err(|error| {
        StreamError::Undefined(Box::new(QuicObservationFailure {
            boundary: "request consumption",
            diagnostic: error.to_string(),
        }))
    })?;
    if installed.as_ref().is_some_and(|fault| fault.slot == slot) {
        let fault = installed.take().ok_or_else(|| {
            StreamError::Undefined("post-resolution fault was removed before observation".into())
        })?;
        if fault
            .observed
            .set((request.method().clone(), request.uri().clone()))
            .is_err()
        {
            return Err(StreamError::Undefined(Box::new(CaptureFailures(vec![
                Box::new(fault.error),
                Box::new(QuicObservationFailure {
                    boundary: "request publication",
                    diagnostic: "request observation was already published".to_owned(),
                }),
            ]))));
        }
        return Err(fault.error);
    }

    Ok((request, stream))
}

#[derive(Debug)]
struct LocalQuicResolutionFailure(Arc<()>);

impl fmt::Display for LocalQuicResolutionFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled local failure after actual HTTP/3 request resolution")
    }
}

impl Error for LocalQuicResolutionFailure {}

#[tokio::test]
async fn finish_capture_retains_a_controlled_post_resolution_failure() -> TestResult {
    let mut capture = QuicCapture::default();
    let identity = Arc::new(());
    let observed = Arc::new(OnceLock::new());
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

        *capture
            .captured
            .quic_request_fault
            .lock()
            .map_err(|error| QuicObservationFailure {
                boundary: "request fault installation",
                diagnostic: error.to_string(),
            })? = Some(RequestFault {
            slot: 1,
            error: StreamError::Undefined(Box::new(LocalQuicResolutionFailure(Arc::clone(
                &identity,
            )))),
            observed: Arc::clone(&observed),
        });
        let mut faulted = capture.peer().await?;
        let uri = format!("https://{HOSTNAME}/controlled-resolution").parse::<http::Uri>()?;
        let request = http::Request::get(uri.clone()).body(())?;
        let mut stream = timeout(REQUEST_TIMEOUT, faulted.requests.send_request(request)).await??;
        timeout(REQUEST_TIMEOUT, stream.finish()).await??;
        faulted.completed().await?;

        let (method, actual_uri) = observed.get().ok_or("actual request was not resolved")?;
        assert_eq!(*method, http::Method::GET);
        assert_eq!(*actual_uri, uri);
        healthy.close().await?;
        faulted.close().await?;
        healthy.completed().await?;

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
            assert!(
                quic.iter()
                    .all(|record| record.outer_server_name.as_deref() == Some(HOSTNAME.as_bytes()))
            );
            assert!(quic[0].request_served);
            assert!(!quic[1].request_served);
            assert!(capture.captured.page_served());
            Ok(())
        }
        .await;
        if let Err(prerequisite) = prerequisite {
            return capture_errors(
                outcome
                    .err()
                    .into_iter()
                    .chain(Some(prerequisite))
                    .collect(),
            );
        }

        let error = outcome
            .err()
            .ok_or("finish_capture discarded the controlled post-resolution failure")?;
        let error = error
            .downcast_ref::<StreamError>()
            .ok_or("finish_capture replaced the original resolution error")?;
        let StreamError::Undefined(cause) = error else {
            return Err("finish_capture changed the original resolution error variant".into());
        };
        let cause = cause
            .downcast_ref::<LocalQuicResolutionFailure>()
            .ok_or("finish_capture replaced the original resolution failure payload")?;
        assert!(Arc::ptr_eq(&cause.0, &identity));
        drop(stream);
        Ok(())
    }
    .await;
    let cleanup = capture.stop().await;

    capture_errors(result.err().into_iter().chain(cleanup.err()).collect())
}
