use super::*;

const DEADLINE: Duration = Duration::from_secs(5);

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
    async fn open(max_push: u32, reset_limit: Option<usize>) -> Self {
        let (io, mut peer) = duplex(16 * 1024);
        let (sender, connection) = super::super::Builder::new()
            .enable_push(true)
            .max_concurrent_streams(max_push)
            .max_local_error_reset_streams(reset_limit)
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

    async fn request(&mut self, method: &str, id: u32) -> super::super::ResponseFuture {
        let request = Request::builder()
            .method(method)
            .uri("https://example.com/")
            .body(())
            .expect("static request must build");
        let (response, send) = self
            .sender
            .send_request(request, true)
            .expect("request rejected");
        drop(send);
        read_request_headers(&mut self.peer, id).await;
        response
    }

    async fn healthy(&mut self) {
        let response = self.request("GET", 3).await;
        write_raw_frame(&mut self.peer, 1, 5, 3, &[0x88]).await;
        assert_eq!(
            response.await.expect("healthy response failed").status(),
            200
        );
        assert_connection_open(&mut self.peer).await;
    }

    async fn close(mut self) {
        self.driver.abort();
        match (&mut self.driver).await {
            Err(error) => assert!(error.is_cancelled(), "driver panicked: {error}"),
            Ok(result) => panic!("driver exited before cleanup: {result:?}"),
        }
    }
}

// Independent HPACK literals without Huffman coding or dynamic-table insertion.
// Static name index 28 is content-length; index 8 is :status.
fn content_lengths(block: &mut Vec<u8>, values: &[&str]) {
    for value in values {
        block.extend_from_slice(&[0x0f, 0x0d, value.len() as u8]);
        block.extend_from_slice(value.as_bytes());
    }
}

fn request_block(values: &[&str]) -> Vec<u8> {
    // Indexed GET, https and /, with a literal :authority of example.com.
    let mut block = b"\x82\x87\x01\x0bexample.com\x84".to_vec();
    content_lengths(&mut block, values);
    block
}

async fn push(peer: &mut DuplexStream, id: u32, lengths: &[&str]) {
    let mut payload = id.to_be_bytes().to_vec();
    payload.extend_from_slice(&request_block(lengths));
    write_raw_frame(peer, 5, 4, 1, &payload).await;
}

async fn read_control(peer: &mut DuplexStream) -> RawFrame {
    loop {
        let frame = read_raw_frame(peer).await;
        if frame.kind != 4 {
            return frame;
        }
        assert_eq!(frame.flags, 1, "unexpected peer SETTINGS");
    }
}

async fn reset(peer: &mut DuplexStream, id: u32, reason: crate::Reason) {
    let frame = read_control(peer).await;
    assert_eq!((frame.kind, frame.flags, frame.stream_id), (3, 0, id));
    assert_eq!(frame.payload, u32::from(reason).to_be_bytes());
}

async fn calm(peer: &mut DuplexStream) {
    let frame = read_control(peer).await;
    assert_eq!((frame.kind, frame.flags, frame.stream_id), (7, 0, 0));
    assert_eq!(&frame.payload[..4], &[0, 0, 0, 0]);
    assert_eq!(
        &frame.payload[4..8],
        &u32::from(crate::Reason::ENHANCE_YOUR_CALM).to_be_bytes()
    );
    assert_eq!(&frame.payload[8..], b"too_many_internal_resets");
}

#[tokio::test]
async fn response_content_lengths_must_all_parse_and_agree_including_head() {
    timeout(DEADLINE, async {
        for method in ["GET", "HEAD"] {
            for (values, valid) in [
                (["2", "2", "2"], true),
                (["2", "02", "002"], true),
                (["2", "3", "2"], false),
                (["2", "2", "3"], false),
                (["2", "2", "invalid"], false),
                (["2", "2", "18446744073709551616"], false),
            ] {
                let mut client = Client::open(1, Some(20)).await;
                let response = client.request(method, 1).await;
                let mut block = vec![0x88];
                content_lengths(&mut block, &values);
                write_raw_frame(&mut client.peer, 1, 4, 1, &block).await;
                if valid {
                    let bytes = if method == "HEAD" {
                        &b""[..]
                    } else {
                        &b"ok"[..]
                    };
                    write_raw_frame(&mut client.peer, 0, 1, 1, bytes).await;
                    let mut body = response.await.expect("equal lengths rejected").into_body();
                    let mut received = Vec::new();
                    while let Some(chunk) = body.data().await {
                        received.extend_from_slice(&chunk.expect("valid body rejected"));
                    }
                    assert_eq!(received, bytes);
                } else {
                    reset(&mut client.peer, 1, crate::Reason::PROTOCOL_ERROR).await;
                    let error = response.await.expect_err("invalid lengths accepted");
                    assert_eq!(error.reason(), Some(crate::Reason::PROTOCOL_ERROR));
                    assert!(error.is_library() && error.is_reset());
                }
                client.healthy().await;
                client.close().await;
            }
        }
    })
    .await
    .expect("duplicate content-length test timed out");
}

#[tokio::test]
async fn promised_content_lengths_all_require_zero_and_rejection_releases_budget() {
    timeout(DEADLINE, async {
        for lengths in [
            ["0", "1"],
            ["1", "0"],
            ["0", "invalid"],
            ["0", "18446744073709551616"],
        ] {
            let mut client = Client::open(1, Some(20)).await;
            let mut response = client.request("GET", 1).await;
            let mut promises = response.push_promises();
            push(&mut client.peer, 2, &lengths).await;
            reset(&mut client.peer, 2, crate::Reason::PROTOCOL_ERROR).await;

            // A malformed reserved stream must release the single receive slot.
            push(&mut client.peer, 4, &["0", "00"]).await;
            write_raw_frame(&mut client.peer, 1, 5, 4, &[0x88]).await;
            let promise = promises
                .push_promise()
                .await
                .expect("valid promise missing")
                .expect("valid promise rejected");
            assert_eq!(
                promise
                    .request()
                    .headers()
                    .get_all("content-length")
                    .iter()
                    .count(),
                2
            );
            let (_, pushed) = promise.into_parts();
            assert_eq!(pushed.await.expect("pushed response failed").status(), 200);
            write_raw_frame(&mut client.peer, 1, 5, 1, &[0x88]).await;
            assert_eq!(
                response.await.expect("parent response failed").status(),
                200
            );
            drop(promises);
            client.healthy().await;
            client.close().await;
        }
    })
    .await
    .expect("promised content-length test timed out");
}

#[tokio::test]
async fn reserved_pushes_use_one_slot_through_informational_and_final_headers() {
    timeout(DEADLINE, async {
        let mut client = Client::open(1, Some(20)).await;
        let mut response = client.request("GET", 1).await;
        let mut promises = response.push_promises();
        push(&mut client.peer, 2, &[]).await;
        let first = promises
            .push_promise()
            .await
            .expect("first promise missing")
            .expect("first promise failed");
        push(&mut client.peer, 4, &[]).await;
        reset(&mut client.peer, 4, crate::Reason::REFUSED_STREAM).await;

        write_raw_frame(&mut client.peer, 1, 4, 2, b"\x08\x03100").await;
        write_raw_frame(&mut client.peer, 1, 4, 2, b"\x08\x03103").await;
        assert_connection_open(&mut client.peer).await;
        write_raw_frame(&mut client.peer, 1, 4, 2, &[0x88]).await;
        push(&mut client.peer, 6, &[]).await;
        reset(&mut client.peer, 6, crate::Reason::REFUSED_STREAM).await;
        write_raw_frame(&mut client.peer, 0, 1, 2, &[]).await;
        let (_, pushed) = first.into_parts();
        let mut body = pushed
            .await
            .expect("reserved response counted twice")
            .into_body();
        while let Some(chunk) = body.data().await {
            assert!(chunk.expect("pushed body failed").is_empty());
        }

        push(&mut client.peer, 8, &[]).await;
        let next = promises
            .push_promise()
            .await
            .expect("released slot not reused")
            .expect("later promise failed");
        write_raw_frame(
            &mut client.peer,
            3,
            0,
            8,
            &u32::from(crate::Reason::CANCEL).to_be_bytes(),
        )
        .await;
        assert_eq!(
            next.into_parts()
                .1
                .await
                .expect_err("peer reset lost")
                .reason(),
            Some(crate::Reason::CANCEL)
        );
        write_raw_frame(&mut client.peer, 1, 5, 1, &[0x88]).await;
        assert_eq!(
            response.await.expect("parent response failed").status(),
            200
        );
        drop(promises);
        client.healthy().await;
        client.close().await;
    })
    .await
    .expect("reserved push concurrency test timed out");
}

#[tokio::test]
async fn refused_pushes_consume_local_reset_budget_including_zero() {
    timeout(DEADLINE, async {
        for limit in [0, 2] {
            let mut client = Client::open(0, Some(limit)).await;
            let _response = client.request("GET", 1).await;
            for n in 0..=limit {
                let id = 2 * (n + 1) as u32;
                push(&mut client.peer, id, &[]).await;
                if n < limit {
                    reset(&mut client.peer, id, crate::Reason::REFUSED_STREAM).await;
                } else {
                    calm(&mut client.peer).await;
                }
            }
            let error = (&mut client.driver)
                .await
                .expect("driver panicked")
                .expect_err("reset budget not enforced");
            assert!(error.is_library() && error.is_go_away());
            assert_eq!(error.reason(), Some(crate::Reason::ENHANCE_YOUR_CALM));
        }
    })
    .await
    .expect("refused push reset budget test timed out");
}

#[tokio::test]
async fn refused_pushes_with_unlimited_reset_budget_leave_connection_usable() {
    timeout(DEADLINE, async {
        let mut client = Client::open(0, None).await;
        let response = client.request("GET", 1).await;
        for id in [2, 4, 6, 8] {
            push(&mut client.peer, id, &[]).await;
            reset(&mut client.peer, id, crate::Reason::REFUSED_STREAM).await;
        }
        write_raw_frame(&mut client.peer, 1, 5, 1, &[0x88]).await;
        assert_eq!(
            response.await.expect("parent response failed").status(),
            200
        );
        client.healthy().await;
        client.close().await;
    })
    .await
    .expect("unlimited refusal budget test timed out");
}

#[tokio::test]
async fn refused_requests_consume_server_local_reset_budget() {
    timeout(DEADLINE, async {
        let (io, mut peer) = duplex(16 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = crate::server::Builder::new()
                .max_concurrent_streams(0)
                .max_local_error_reset_streams(Some(2))
                .handshake::<_, Bytes>(io)
                .await
                .expect("server handshake failed");
            let error = connection
                .accept()
                .await
                .expect("connection ended without error")
                .expect_err("refused request accepted");
            assert!(error.is_library() && error.is_go_away());
            assert_eq!(error.reason(), Some(crate::Reason::ENHANCE_YOUR_CALM));
        });
        peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .expect("preface write failed");
        write_raw_frame(&mut peer, 4, 0, 0, &[]).await;
        let settings = read_raw_frame(&mut peer).await;
        assert_eq!((settings.kind, settings.flags), (4, 0));
        write_raw_frame(&mut peer, 4, 1, 0, &[]).await;
        for id in [1, 3, 5] {
            write_raw_frame(&mut peer, 1, 5, id, &request_block(&[])).await;
            if id < 5 {
                reset(&mut peer, id, crate::Reason::REFUSED_STREAM).await;
            } else {
                calm(&mut peer).await;
            }
        }
        server.await.expect("server driver panicked");
    })
    .await
    .expect("refused request reset budget test timed out");
}
