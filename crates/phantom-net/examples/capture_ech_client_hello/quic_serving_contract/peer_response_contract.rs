use std::time::Duration;

use h3::error::StreamError;
use tokio::time::timeout;

use super::super::{TestResult, assert_closed, exchange};
use super::capture_origin::QuicCapture;
use crate::{HOSTNAME, capture_errors};

const PEER_TIMEOUT: Duration = Duration::from_secs(3);

#[tokio::test]
async fn tiny_peer_header_limit_retains_the_original_outgoing_response_error() -> TestResult {
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
        let mut limited = capture.peer_with_header_limit(1).await?;

        let request = http::Request::get(format!("https://{HOSTNAME}/tiny-headers")).body(())?;
        let mut stream = timeout(PEER_TIMEOUT, limited.requests.send_request(request)).await??;
        timeout(PEER_TIMEOUT, stream.finish()).await??;
        // Keep the actual request stream alive until the serving worker completes.
        limited.completed().await?;
        healthy.close().await?;
        limited.close().await?;
        healthy.completed().await?;

        let outcome = capture.finish().await;
        let prerequisite: TestResult = async {
            assert_closed(&mut dns_peer).await?;
            capture.observe_closed().await?;
            assert!(healthy.worker.is_finished());
            assert!(limited.worker.is_finished());
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
        if let Err(prerequisite) = prerequisite {
            return capture_errors(outcome.err().into_iter().chain(Some(prerequisite)).collect());
        }

        let error = outcome
            .err()
            .ok_or("finish_capture discarded the actual outgoing header budget failure")?;
        let error = error
            .downcast_ref::<StreamError>()
            .ok_or("finish_capture replaced the original HTTP/3 response error")?;
        let StreamError::HeaderTooBig {
            actual_size,
            max_size,
            ..
        } = error
        else {
            return Err("finish_capture changed the outgoing header budget error variant".into());
        };
        assert_eq!(*max_size, 1);
        // :status=200 and content-type=text/html contribute 42 and 53 bytes.
        assert_eq!(*actual_size, 95);
        drop(stream);
        Ok(())
    }
    .await;
    let cleanup = capture.stop().await;

    capture_errors(result.err().into_iter().chain(cleanup.err()).collect())
}
