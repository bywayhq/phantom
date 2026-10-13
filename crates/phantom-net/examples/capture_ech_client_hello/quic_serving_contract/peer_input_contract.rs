use std::time::Duration;

use h3::error::Code;
use tokio::time::timeout;

use super::super::{TestResult, assert_closed, exchange};
use super::capture_origin::QuicCapture;
use crate::{HOSTNAME, capture_errors};

const PEER_TIMEOUT: Duration = Duration::from_secs(3);

enum MalformedInput {
    RequestData,
    ControlData,
}

#[tokio::test]
async fn malformed_request_data_keeps_a_healthy_sibling_and_partial_capture() -> TestResult {
    exercise(MalformedInput::RequestData).await
}

#[tokio::test]
async fn illegal_control_data_keeps_a_healthy_sibling_and_partial_capture() -> TestResult {
    exercise(MalformedInput::ControlData).await
}

async fn exercise(input: MalformedInput) -> TestResult {
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
        let malformed = capture.raw_peer().await?;

        let mut control = timeout(PEER_TIMEOUT, malformed.connection.open_uni()).await??;
        // CONTROL stream type, SETTINGS frame type, empty SETTINGS payload.
        timeout(PEER_TIMEOUT, control.write_all(&[0, 4, 0])).await??;
        let request = match input {
            MalformedInput::RequestData => {
                let (mut send, receive) =
                    timeout(PEER_TIMEOUT, malformed.connection.open_bi()).await??;
                // A literal empty DATA frame is invalid before request HEADERS.
                timeout(PEER_TIMEOUT, send.write_all(&[0, 0])).await??;
                send.finish()?;
                Some((send, receive))
            }
            MalformedInput::ControlData => {
                timeout(PEER_TIMEOUT, control.write_all(&[0, 0])).await??;
                None
            }
        };

        let closed = timeout(PEER_TIMEOUT, malformed.connection.closed()).await?;
        if !matches!(
            &closed,
            quinn::ConnectionError::ApplicationClosed(close)
                if u64::from(close.error_code) == Code::H3_FRAME_UNEXPECTED.value()
        ) {
            return Err(closed.into());
        }
        timeout(PEER_TIMEOUT, async {
            while !malformed.worker.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        drop(request);
        drop(control);
        healthy.close().await?;
        healthy.completed().await?;

        let outcome = capture.finish().await;
        let prerequisite: TestResult = async {
            assert_closed(&mut dns_peer).await?;
            capture.observe_closed().await?;
            assert!(healthy.worker.is_finished());
            assert!(malformed.worker.is_finished());
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

        capture_errors(
            outcome
                .err()
                .into_iter()
                .chain(prerequisite.err())
                .collect(),
        )
    }
    .await;
    let cleanup = capture.stop().await;

    capture_errors(result.err().into_iter().chain(cleanup.err()).collect())
}
