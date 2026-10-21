use super::*;

const DEADLINE: Duration = Duration::from_secs(5);
// HPACK literals with new names, without Huffman coding or table insertion:
// x-a: first, x-b: middle, x-a: [0x80, 0xff, 'z'].
const INTERLEAVED: &[u8] = b"\x00\x03x-a\x05first\x00\x03x-b\x06middle\x00\x03x-a\x03\x80\xffz";

struct Client {
    peer: DuplexStream,
    sender: super::super::SendRequest<Bytes>,
    driver: tokio::task::JoinHandle<Result<(), crate::Error>>,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

impl Client {
    async fn open(limit: Option<u32>) -> Self {
        let (io, mut peer) = duplex(16 * 1024);
        let mut builder = super::super::Builder::new();
        if let Some(limit) = limit {
            builder.local_max_header_list_size(limit);
        }
        let (sender, connection) = builder
            .handshake(io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);
        accept_client_handshake(&mut peer).await;
        Self {
            peer,
            sender,
            driver,
        }
    }

    async fn begin(
        &mut self,
        id: u32,
        end_request: bool,
    ) -> (crate::RecvStream, crate::SendStream<Bytes>) {
        let (response, send) = self
            .sender
            .send_request(data_budget_request(), end_request)
            .expect("request rejected");
        loop {
            let frame = read_raw_frame(&mut self.peer).await;
            assert_ne!(frame.kind, 7, "unexpected GOAWAY");
            if frame.kind == 1 {
                assert_eq!(frame.stream_id, id);
                break;
            }
        }
        write_raw_frame(&mut self.peer, 1, 4, id, &[0x88]).await;
        let response = response.await.expect("response head failed");
        assert_eq!(response.status(), 200);
        (response.into_body(), send)
    }

    async fn healthy(&mut self, id: u32) {
        let (mut body, send) = self.begin(id, true).await;
        assert!(body.take_ordered_trailers().is_none());
        write_raw_frame(&mut self.peer, 0, 1, id, b"healthy").await;
        assert_eq!(
            body.data()
                .await
                .expect("healthy DATA missing")
                .expect("healthy DATA failed"),
            "healthy"
        );
        assert!(body.data().await.is_none());
        assert!(body
            .trailers()
            .await
            .expect("healthy trailers failed")
            .is_none());
        assert!(body.take_ordered_trailers().is_none());
        drop((body, send));
        assert_connection_open(&mut self.peer).await;
    }
}

fn assert_interleaved(ordered: OrderedHeaders) {
    let fields = ordered.as_slice();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields[0].0.as_str(), "x-a");
    assert_eq!(fields[0].1.as_bytes(), b"first");
    assert_eq!(fields[1].0.as_str(), "x-b");
    assert_eq!(fields[1].1.as_bytes(), b"middle");
    assert_eq!(fields[2].0.as_str(), "x-a");
    assert_eq!(fields[2].1.as_bytes(), b"\x80\xffz");
}

#[tokio::test]
async fn received_trailers_retain_interleaved_duplicates_across_continuation() {
    timeout(DEADLINE, async {
        let mut client = Client::open(None).await;
        let (mut body, send) = client.begin(1, true).await;
        assert!(body.take_ordered_trailers().is_none());
        write_raw_frame(&mut client.peer, 0, 0, 1, b"body").await;
        // Split within a literal value: no decoded field block exists until
        // CONTINUATION completes the independent HPACK bytes above.
        write_raw_frame(&mut client.peer, 1, 1, 1, &INTERLEAVED[..8]).await;
        write_raw_frame(&mut client.peer, 9, 4, 1, &INTERLEAVED[8..]).await;
        assert_connection_open(&mut client.peer).await;
        assert_eq!(
            body.data()
                .await
                .expect("DATA missing")
                .expect("DATA failed"),
            "body"
        );
        assert!(body.data().await.is_none());
        let semantic = body
            .trailers()
            .await
            .expect("trailers failed")
            .expect("trailers missing");
        assert_eq!(
            semantic
                .get_all("x-a")
                .iter()
                .map(HeaderValue::as_bytes)
                .collect::<Vec<_>>(),
            [b"first".as_slice(), b"\x80\xffz"]
        );
        assert_eq!(semantic["x-b"], "middle");
        assert_interleaved(
            body.take_ordered_trailers()
                .expect("ordered trailers missing"),
        );
        assert!(body.take_ordered_trailers().is_none());
        assert!(body
            .trailers()
            .await
            .expect("second trailer poll failed")
            .is_none());
        assert!(body.take_ordered_trailers().is_none());
        drop((body, send));
        client.healthy(3).await;
    })
    .await
    .expect("ordered trailer test timed out");
}

#[tokio::test]
async fn empty_trailers_and_later_body_poll_have_distinct_metadata_lifetimes() {
    timeout(DEADLINE, async {
        let mut client = Client::open(None).await;
        let (mut first, first_send) = client.begin(1, true).await;
        let (mut second, second_send) = client.begin(3, true).await;
        // Arrive out of request order to prove sidecars stay with their stream.
        write_raw_frame(&mut client.peer, 1, 5, 3, INTERLEAVED).await;
        write_raw_frame(&mut client.peer, 1, 5, 1, &[]).await;
        assert!(first
            .trailers()
            .await
            .expect("empty trailers failed")
            .expect("empty trailers absent")
            .is_empty());
        assert!(first
            .take_ordered_trailers()
            .expect("empty ordered trailers absent")
            .as_slice()
            .is_empty());
        assert_eq!(
            second
                .trailers()
                .await
                .expect("second trailers failed")
                .expect("second trailers absent")
                .len(),
            3
        );
        // The matching trailer delivery is intentionally not taken before the
        // next body poll. It must not remain as stale metadata afterwards.
        assert!(second.data().await.is_none());
        assert!(second.take_ordered_trailers().is_none());
        drop((first, first_send, second, second_send));
        client.healthy(5).await;
    })
    .await
    .expect("trailer lifetime test timed out");
}

#[tokio::test]
async fn trailer_decoded_limit_rejects_boundary_without_partial_success_or_sibling_failure() {
    timeout(DEADLINE, async {
        // RFC header-list accounting: x-a:a is 3+1+32=36 bytes;
        // x-b:vvvvvvvvv is 3+9+32=44. The combined 80-byte block must
        // not become a successful first-field prefix at an 80-byte ceiling.
        // The existing receive policy rejects size >= configured ceiling.
        let block = b"\x00\x03x-a\x01a\x00\x03x-b\x09vvvvvvvvv";
        for limit in [79, 80, 81] {
            let mut client = Client::open(Some(limit)).await;
            let (mut body, send) = client.begin(1, true).await;
            let (mut sibling, sibling_send) = client.begin(3, true).await;
            write_raw_frame(&mut client.peer, 1, 5, 1, block).await;
            let trailers = body.trailers().await;
            if limit == 81 {
                let trailers = trailers
                    .expect("below-limit trailers failed")
                    .expect("trailers missing");
                assert_eq!(trailers["x-a"], "a");
                assert_eq!(trailers["x-b"], "vvvvvvvvv");
                let ordered = body.take_ordered_trailers().expect("order missing");
                assert_eq!(
                    ordered
                        .as_slice()
                        .iter()
                        .map(|(name, value)| (name.as_str(), value.as_bytes()))
                        .collect::<Vec<_>>(),
                    [("x-a", b"a".as_slice()), ("x-b", b"vvvvvvvvv".as_slice())]
                );
            } else {
                let error = trailers.expect_err("limit produced truncated trailer success");
                assert!(error.is_reset() && error.is_library(), "{error:?}");
                assert!(error.is_header_list_too_large(), "{error:?}");
                assert_eq!(error.reason(), Some(crate::Reason::PROTOCOL_ERROR));
                assert!(body.take_ordered_trailers().is_none());
            }
            write_raw_frame(&mut client.peer, 0, 1, 3, b"ok").await;
            assert_eq!(
                sibling
                    .data()
                    .await
                    .expect("sibling missing")
                    .expect("sibling failed"),
                "ok"
            );
            assert!(sibling.data().await.is_none());
            assert!(sibling
                .trailers()
                .await
                .expect("sibling trailers failed")
                .is_none());
            assert!(sibling.take_ordered_trailers().is_none());
            drop((body, send, sibling, sibling_send));
            assert_connection_open(&mut client.peer).await;
        }
    })
    .await
    .expect("trailer limit test timed out");
}

#[tokio::test]
async fn trailer_limit_is_typed_when_data_is_polled_first() {
    timeout(DEADLINE, async {
        let mut client = Client::open(Some(80)).await;
        let (mut body, send) = client.begin(1, true).await;
        let block = b"\x00\x03x-a\x01a\x00\x03x-b\x09vvvvvvvvv";
        write_raw_frame(&mut client.peer, 1, 5, 1, block).await;
        let error = body
            .data()
            .await
            .expect("limit error absent")
            .expect_err("oversized trailers accepted");
        assert!(error.is_header_list_too_large(), "{error:?}");
        assert!(body.take_ordered_trailers().is_none());
        drop((body, send));
        client.healthy(3).await;
    })
    .await
    .expect("DATA-first trailer limit test timed out");
}

#[tokio::test]
async fn failed_receive_never_publishes_buffered_order_and_keeps_sibling_usable() {
    timeout(DEADLINE, async {
        for reason in [
            crate::Reason::CANCEL,
            crate::Reason::INTERNAL_ERROR,
            crate::Reason::NO_ERROR,
        ] {
            let mut client = Client::open(None).await;
            let (mut body, mut send) = client.begin(1, false).await;
            let (mut sibling, sibling_send) = client.begin(3, true).await;
            write_raw_frame(&mut client.peer, 1, 5, 1, INTERLEAVED).await;
            write_raw_frame(&mut client.peer, 3, 0, 1, &u32::from(reason).to_be_bytes()).await;
            assert_connection_open(&mut client.peer).await;
            assert_eq!(
                poll_fn(|cx| send.poll_reset(cx))
                    .await
                    .expect("reset missing"),
                reason
            );
            // Existing semantic buffering is preserved. Only successful receive
            // state may expose the companion order; NO_ERROR is the RFC 9113
            // completed-response exception already supported by this backend.
            assert!(body
                .trailers()
                .await
                .expect("buffered map failed")
                .is_some());
            if reason == crate::Reason::NO_ERROR {
                assert_interleaved(
                    body.take_ordered_trailers()
                        .expect("retained order missing"),
                );
            } else {
                assert!(body.take_ordered_trailers().is_none());
                let error = body
                    .data()
                    .await
                    .expect("reset error missing")
                    .expect_err("reset accepted");
                assert_eq!(error.reason(), Some(reason));
            }
            write_raw_frame(&mut client.peer, 0, 1, 3, b"healthy").await;
            assert_eq!(
                sibling
                    .data()
                    .await
                    .expect("sibling DATA missing")
                    .expect("sibling failed"),
                "healthy"
            );
            assert!(sibling.data().await.is_none());
            assert!(sibling.take_ordered_trailers().is_none());
            drop((body, send, sibling, sibling_send));
        }
    })
    .await
    .expect("reset trailer metadata test timed out");
}

#[tokio::test]
async fn local_cancellation_does_not_publish_order_for_queued_trailers() {
    timeout(DEADLINE, async {
        let mut client = Client::open(None).await;
        let (mut body, mut send) = client.begin(1, false).await;
        write_raw_frame(&mut client.peer, 1, 5, 1, INTERLEAVED).await;
        assert_connection_open(&mut client.peer).await;
        send.send_reset(crate::Reason::CANCEL);
        assert!(body
            .trailers()
            .await
            .expect("buffered map failed")
            .is_some());
        assert!(body.take_ordered_trailers().is_none());
        drop((body, send));
        client.healthy(3).await;
    })
    .await
    .expect("cancelled trailer metadata test timed out");
}

#[tokio::test]
async fn malformed_and_truncated_trailers_never_publish_metadata() {
    timeout(DEADLINE, async {
        let mut client = Client::open(None).await;
        let (mut body, send) = client.begin(1, true).await;
        // A trailers field block without END_STREAM is a stream error.
        write_raw_frame(&mut client.peer, 1, 4, 1, INTERLEAVED).await;
        assert!(body.trailers().await.is_err());
        assert!(body.take_ordered_trailers().is_none());
        drop((body, send));
        client.healthy(3).await;

        let mut client = Client::open(None).await;
        let (mut body, send) = client.begin(1, true).await;
        write_raw_frame(&mut client.peer, 1, 1, 1, &INTERLEAVED[..8]).await;
        client.peer.shutdown().await.expect("peer shutdown failed");
        assert!(body.trailers().await.is_err());
        assert!(body.take_ordered_trailers().is_none());
        drop((body, send));
    })
    .await
    .expect("invalid trailer metadata test timed out");
}

#[tokio::test]
async fn connection_eof_invalidates_already_delivered_trailer_metadata() {
    timeout(DEADLINE, async {
        let mut client = Client::open(None).await;
        let (mut body, send) = client.begin(1, false).await;
        write_raw_frame(&mut client.peer, 1, 5, 1, INTERLEAVED).await;
        assert!(body
            .trailers()
            .await
            .expect("buffered map failed")
            .is_some());
        // The receive half finished, but the upload is still open. Real
        // transport EOF must invalidate its unclaimed receive metadata.
        client.peer.shutdown().await.expect("peer shutdown failed");
        let _connection_result = (&mut client.driver).await.expect("driver panicked");
        assert!(body.take_ordered_trailers().is_none());
        let error = body
            .data()
            .await
            .expect("EOF failure absent")
            .expect_err("EOF failure lost");
        assert!(error.is_io(), "{error:?}");
        drop((body, send));
    })
    .await
    .expect("connection EOF trailer test timed out");
}
