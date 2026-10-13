use std::time::Duration;

use h3::error::Code;
use tokio::time::timeout;

use super::super::{TestResult, assert_closed, exchange};
use super::capture_origin::QuicCapture;
use crate::{HOSTNAME, capture_errors};

const PEER_TIMEOUT: Duration = Duration::from_secs(3);

#[tokio::test]
async fn truncated_request_headers_send_frame_error_and_keep_a_partial_capture() -> TestResult {
    // HEADERS type, four declared payload bytes, one actual byte, then FIN.
    exercise(&[1, 4, 0], Code::H3_FRAME_ERROR).await
}

#[tokio::test]
async fn incomplete_qpack_prefix_sends_decompression_error_and_keeps_a_partial_capture()
-> TestResult {
    // Complete one-byte HEADERS payload with a missing QPACK integer continuation.
    exercise(&[1, 1, 0xff], Code::QPACK_DECOMPRESSION_FAILED).await
}

async fn exercise(frame: &[u8], expected: Code) -> TestResult {
    let mut capture = QuicCapture::default();
    let mut unexpected_close = None;
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
        let (mut send, receive) = timeout(PEER_TIMEOUT, malformed.connection.open_bi()).await??;
        timeout(PEER_TIMEOUT, send.write_all(frame)).await??;
        send.finish()?;

        let closed = timeout(PEER_TIMEOUT, malformed.connection.closed()).await?;
        if !matches!(
            &closed,
            quinn::ConnectionError::ApplicationClosed(close)
                if u64::from(close.error_code) == expected.value()
        ) {
            unexpected_close = Some(closed);
        }
        timeout(PEER_TIMEOUT, async {
            while !malformed.worker.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        drop(send);
        drop(receive);
        drop(control);
        healthy.close().await?;
        healthy.completed().await?;

        let outcome = capture.finish().await;
        let prerequisite: TestResult = async {
            assert_closed(&mut dns_peer).await?;
            capture.observe_closed().await?;
            if !healthy.worker.is_finished() || !malformed.worker.is_finished() {
                return Err("a registered QUIC worker remained active after capture finish".into());
            }
            if capture
                .dns
                .as_ref()
                .ok_or("DNS owner missing")?
                .descriptions()
                != [format!("A {HOSTNAME}")]
            {
                return Err("the real DoH request was not recorded".into());
            }
            let (tcp, quic) = capture.captured.take();
            if !tcp.is_empty() || quic.len() != 2 {
                return Err("capture did not retain exactly the two actual QUIC peers".into());
            }
            if quic.iter().any(|record| record.handshake.is_err()) {
                return Err("an actual QUIC handshake was not captured successfully".into());
            }
            if quic.iter().any(|record| record.client_hello.is_empty()) {
                return Err("an actual QUIC ClientHello was not recorded".into());
            }
            if quic
                .iter()
                .any(|record| record.outer_server_name.as_deref() != Some(HOSTNAME.as_bytes()))
            {
                return Err("a captured QUIC peer lost its original server name".into());
            }
            if !quic[0].request_served || quic[1].request_served {
                return Err(
                    "capture did not distinguish the healthy and malformed requests".into(),
                );
            }
            if !capture.captured.page_served() {
                return Err("the healthy sibling did not serve the literal page".into());
            }
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
    let result = capture_errors(
        unexpected_close
            .map(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            .into_iter()
            .chain(result.err())
            .collect(),
    );
    let cleanup = capture.stop().await;

    capture_errors(result.err().into_iter().chain(cleanup.err()).collect())
}
