use super::*;

const INITIAL: u32 = 131_072;
const TARGET: u32 = 12_582_912;
const BOOST: u32 = TARGET - INITIAL;
const DEADLINE: Duration = Duration::from_secs(5);

// Abort on unwind and timeout as well as success; no detached connection task
// survives a failed wire assertion.
struct Client {
    peer: DuplexStream,
    sender: super::super::SendRequest<Bytes>,
    driver: tokio::task::JoinHandle<Result<(), crate::Error>>,
}

impl Client {
    async fn close(mut self) {
        self.driver.abort();
        match (&mut self.driver).await {
            Err(error) => assert!(error.is_cancelled(), "connection driver panicked: {error}"),
            Ok(result) => panic!("connection driver exited before cleanup: {result:?}"),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

fn builder() -> super::super::Builder {
    let mut builder = super::super::Builder::new();
    builder
        .initial_window_size(INITIAL)
        .initial_stream_window_target(Some(TARGET));
    builder
}

async fn client(builder: super::super::Builder, capacity: usize, ack: bool) -> Client {
    let (io, peer) = duplex(capacity);
    let (sender, connection) = builder
        .handshake::<_, Bytes>(io)
        .await
        .expect("client handshake failed");
    let mut client = Client {
        peer,
        sender,
        driver: tokio::spawn(connection),
    };
    read_client_preface(&mut client.peer).await;
    let settings = read_raw_frame(&mut client.peer).await;
    assert_eq!(
        (settings.kind, settings.flags, settings.stream_id),
        (4, 0, 0)
    );
    write_raw_frame(&mut client.peer, 4, 0, 0, &[]).await;
    if ack {
        write_raw_frame(&mut client.peer, 4, 1, 0, &[]).await;
        // Observe processing of the initial SETTINGS ACK before requests are
        // queued, so the post-ACK accounting controls have a real barrier.
        let frames = drain_to_probe(&mut client.peer).await;
        assert!(frames.iter().all(|frame| frame.stream_id == 0));
    }
    client
}

async fn next_stream_frame(peer: &mut DuplexStream) -> RawFrame {
    loop {
        let frame = read_raw_frame(peer).await;
        assert_ne!(frame.kind, 7, "unexpected GOAWAY: {:?}", frame.payload);
        if frame.stream_id != 0 {
            return frame;
        }
        assert!(matches!((frame.kind, frame.flags), (4, 1) | (8, 0)));
    }
}

fn assert_update(frame: RawFrame, stream_id: u32, increment: u32) {
    assert_eq!(
        (frame.kind, frame.flags, frame.stream_id),
        (8, 0, stream_id)
    );
    assert_eq!(frame.payload, increment.to_be_bytes());
}

// A processed PING bounds the absence check without a sleep. Already queued
// request frames are flushed before the driver reads and acknowledges it.
async fn drain_to_probe(peer: &mut DuplexStream) -> Vec<RawFrame> {
    write_raw_frame(peer, 6, 0, 0, b"window!!").await;
    let mut frames = Vec::new();
    loop {
        let frame = read_raw_frame(peer).await;
        assert_ne!(frame.kind, 7, "unexpected GOAWAY: {:?}", frame.payload);
        if (frame.kind, frame.flags, frame.stream_id) == (6, 1, 0) {
            assert_eq!(frame.payload, b"window!!");
            return frames;
        }
        frames.push(frame);
    }
}

#[tokio::test]
async fn opening_window_update_follows_each_request_before_any_other_stream() {
    timeout(DEADLINE, async {
        let mut client = client(builder(), 128, true).await;
        let (first, _) = client
            .sender
            .send_request(data_budget_request(), true)
            .unwrap();
        let (second, _) = client
            .sender
            .send_request(data_budget_request(), true)
            .unwrap();
        for id in [1, 3] {
            let headers = next_stream_frame(&mut client.peer).await;
            assert_eq!(
                (headers.kind, headers.stream_id, headers.flags & 5),
                (1, id, 5)
            );
            assert_update(read_raw_frame(&mut client.peer).await, id, BOOST);
        }
        let extra = drain_to_probe(&mut client.peer).await;
        assert!(extra.iter().all(|frame| frame.stream_id == 0));
        drop((first, second));
        client.close().await;
    })
    .await
    .expect("opening-window request order timed out");
}

#[tokio::test]
async fn opening_window_update_follows_continuation_before_data_and_not_trailers() {
    timeout(DEADLINE, async {
        let mut client = client(builder(), 64, true).await;
        let mut request = data_budget_request();
        *request.method_mut() = Method::POST;
        request.headers_mut().insert(
            "x-long",
            HeaderValue::from_str(&"x".repeat(60_000)).unwrap(),
        );
        let (response, mut body) = client.sender.send_request(request, false).unwrap();
        body.send_data(Bytes::from_static(b"body"), false).unwrap();
        body.send_trailers(HeaderMap::new()).unwrap();
        let mut headers = next_stream_frame(&mut client.peer).await;
        assert_eq!((headers.kind, headers.stream_id), (1, 1));
        assert_eq!(
            headers.flags & 4,
            0,
            "header block must require CONTINUATION"
        );
        let mut continuations = 0;
        while headers.flags & 4 == 0 {
            headers = read_raw_frame(&mut client.peer).await;
            assert_eq!((headers.kind, headers.stream_id), (9, 1));
            continuations += 1;
        }
        assert!(continuations > 0);
        assert_update(read_raw_frame(&mut client.peer).await, 1, BOOST);
        let data = read_raw_frame(&mut client.peer).await;
        assert_eq!((data.kind, data.stream_id, data.flags & 1), (0, 1, 0));
        assert_eq!(data.payload, b"body");
        let trailers = read_raw_frame(&mut client.peer).await;
        assert_eq!(
            (trailers.kind, trailers.stream_id, trailers.flags & 5),
            (1, 1, 5)
        );
        let extra = drain_to_probe(&mut client.peer).await;
        assert!(extra.iter().all(|frame| frame.stream_id == 0));
        drop((response, body));
        client.close().await;
    })
    .await
    .expect("opening-window continuation and trailer order timed out");
}

#[tokio::test]
async fn opening_window_update_keeps_preface_ping_immediately_after_headers() {
    timeout(DEADLINE, async {
        let mut builder = builder();
        builder.preface_ping(Duration::ZERO);
        let mut client = client(builder, 64, true).await;
        let mut request = data_budget_request();
        *request.method_mut() = Method::POST;
        request.headers_mut().insert(
            "x-long",
            HeaderValue::from_str(&"x".repeat(60_000)).unwrap(),
        );
        let (response, mut body) = client.sender.send_request(request, false).unwrap();
        body.send_data(Bytes::from_static(b"body"), true).unwrap();
        let mut headers = next_stream_frame(&mut client.peer).await;
        assert_eq!((headers.kind, headers.stream_id), (1, 1));
        assert_eq!(headers.flags & 4, 0);
        while headers.flags & 4 == 0 {
            headers = read_raw_frame(&mut client.peer).await;
            assert_eq!((headers.kind, headers.stream_id), (9, 1));
        }
        let ping = read_raw_frame(&mut client.peer).await;
        assert_eq!((ping.kind, ping.flags, ping.stream_id), (6, 0, 0));
        assert_eq!(ping.payload, 1_u64.to_be_bytes());
        assert_update(read_raw_frame(&mut client.peer).await, 1, BOOST);
        let data = read_raw_frame(&mut client.peer).await;
        assert_eq!((data.kind, data.stream_id), (0, 1));
        assert_eq!(data.payload, b"body");
        drop((response, body));
        client.close().await;
    })
    .await
    .expect("opening-window preface-PING fence timed out");
}

#[tokio::test]
async fn opening_window_none_equal_and_cleared_policy_emit_no_update() {
    timeout(DEADLINE, async {
        for case in 0..3 {
            let mut builder = if case == 0 {
                let mut builder = super::super::Builder::new();
                builder.initial_window_size(INITIAL);
                builder
            } else {
                builder()
            };
            if case != 0 {
                builder.initial_stream_window_target(if case == 1 { None } else { Some(INITIAL) });
            }
            let mut client = client(builder, 128, true).await;
            let response = send_empty_request(&mut client.sender).await;
            let headers = next_stream_frame(&mut client.peer).await;
            assert_eq!((headers.kind, headers.stream_id), (1, 1));
            let extra = drain_to_probe(&mut client.peer).await;
            assert!(extra.iter().all(|frame| frame.stream_id == 0));
            drop(response);
            client.close().await;
        }
    })
    .await
    .expect("opening-window absent and equal targets timed out");
}

#[tokio::test]
async fn opening_window_invalid_targets_fail_before_writing_the_preface() {
    timeout(DEADLINE, async {
        for target in [0, INITIAL - 1, 1 << 31, u32::MAX] {
            let mut builder = builder();
            // Validation uses the final advertised size, independent of setter order.
            builder
                .initial_stream_window_target(Some(target))
                .initial_window_size(INITIAL);
            let (io, mut peer) = duplex(128);
            let error = builder
                .handshake::<_, Bytes>(io)
                .await
                .expect_err("invalid target accepted");
            assert!(error.is_io());
            assert_eq!(
                error.into_io().unwrap().kind(),
                std::io::ErrorKind::InvalidInput
            );
            let mut written = Vec::new();
            peer.read_to_end(&mut written).await.unwrap();
            assert!(
                written.is_empty(),
                "invalid policy wrote a connection preface"
            );
        }
    })
    .await
    .expect("opening-window invalid policy timed out");
}

#[tokio::test]
async fn opening_window_zero_and_maximum_targets_work_before_initial_settings_ack() {
    timeout(DEADLINE, async {
        for target in [0, crate::proto::MAX_WINDOW_SIZE] {
            let mut builder = builder();
            builder
                .initial_window_size(0)
                .initial_stream_window_target(Some(target));
            let mut client = client(builder, 128, false).await;
            let response = send_empty_request(&mut client.sender).await;
            let headers = next_stream_frame(&mut client.peer).await;
            assert_eq!((headers.kind, headers.stream_id), (1, 1));
            if target != 0 {
                assert_update(read_raw_frame(&mut client.peer).await, 1, target);
            }
            write_raw_frame(&mut client.peer, 4, 1, 0, &[]).await;
            let extra = drain_to_probe(&mut client.peer).await;
            assert!(extra.iter().all(|frame| frame.stream_id == 0));
            drop(response);
            client.close().await;
        }
    })
    .await
    .expect("opening-window boundary targets timed out");
}

#[tokio::test]
async fn opening_window_credit_is_real_before_and_after_initial_settings_ack() {
    timeout(DEADLINE, async {
        for ack in [false, true] {
            let mut builder = builder();
            builder
                .initial_window_size(8)
                .initial_stream_window_target(Some(32));
            let mut client = client(builder, 128, ack).await;
            let response = send_empty_request(&mut client.sender).await;
            let headers = next_stream_frame(&mut client.peer).await;
            assert_eq!((headers.kind, headers.stream_id), (1, 1));
            assert_update(read_raw_frame(&mut client.peer).await, 1, 24);
            write_raw_frame(&mut client.peer, 1, 4, 1, &[0x88]).await;
            write_raw_frame(&mut client.peer, 0, 0, 1, &[0x61; 32]).await;
            let mut response = response.await.unwrap();
            assert_eq!(response.body_mut().data().await.unwrap().unwrap().len(), 32);
            assert_eq!(response.body_mut().flow_control().used_capacity(), 32);
            assert_eq!(response.body_mut().flow_control().available_capacity(), 0);
            if !ack {
                write_raw_frame(&mut client.peer, 4, 1, 0, &[]).await;
            }
            let extra = drain_to_probe(&mut client.peer).await;
            assert!(extra.iter().all(|frame| frame.stream_id == 0));
            assert_eq!(response.body_mut().flow_control().available_capacity(), 0);
            write_raw_frame(&mut client.peer, 0, 0, 1, b"x").await;
            let error = response
                .body_mut()
                .data()
                .await
                .unwrap()
                .expect_err("excess stream credit accepted");
            assert_eq!(error.reason(), Some(crate::Reason::FLOW_CONTROL_ERROR));
            let reset = next_stream_frame(&mut client.peer).await;
            assert_eq!((reset.kind, reset.stream_id), (3, 1));
            assert_eq!(
                reset.payload,
                u32::from(crate::Reason::FLOW_CONTROL_ERROR).to_be_bytes()
            );
            client.close().await;
        }
    })
    .await
    .expect("opening-window receive accounting timed out");
}

#[tokio::test]
async fn opening_window_accepts_a_firefox_sized_response_without_released_capacity() {
    timeout(DEADLINE, async {
        let mut builder = builder();
        builder.initial_connection_window_size(262_144);
        let mut client = client(builder, 256 * 1024, true).await;
        let response = send_empty_request(&mut client.sender).await;
        let headers = next_stream_frame(&mut client.peer).await;
        assert_eq!((headers.kind, headers.stream_id), (1, 1));
        assert_update(read_raw_frame(&mut client.peer).await, 1, BOOST);
        write_raw_frame(&mut client.peer, 1, 4, 1, &[0x88]).await;
        for _ in 0..12 {
            write_raw_frame(&mut client.peer, 0, 0, 1, &[0x61; 16_384]).await;
        }
        let mut response = response.await.unwrap();
        let mut received = 0;
        while received < 196_608 {
            received += response.body_mut().data().await.unwrap().unwrap().len();
        }
        assert_eq!(received, 196_608);
        let flow = response.body_mut().flow_control();
        assert_eq!(flow.used_capacity(), received);
        assert_eq!(
            flow.available_capacity(),
            (TARGET as usize - received) as isize
        );
        flow.release_capacity(received).unwrap();
        assert_eq!(flow.used_capacity(), 0);
        assert_eq!(flow.available_capacity(), TARGET as isize);
        write_raw_frame(&mut client.peer, 0, 1, 1, &[]).await;
        while let Some(data) = response.body_mut().data().await {
            assert!(data.unwrap().is_empty());
        }
        client.close().await;
    })
    .await
    .expect("opening-window response above advertised baseline timed out");
}

#[tokio::test]
async fn opening_window_waits_for_stream_admission_and_omits_cancelled_streams() {
    timeout(DEADLINE, async {
        let mut builder = builder();
        builder
            .initial_max_send_streams(1)
            .retain_initial_max_send_streams(true);
        let mut client = client(builder, 128, true).await;
        let (first, _) = client
            .sender
            .send_request(data_budget_request(), true)
            .unwrap();
        let headers = next_stream_frame(&mut client.peer).await;
        assert_eq!((headers.kind, headers.stream_id), (1, 1));
        assert_update(read_raw_frame(&mut client.peer).await, 1, BOOST);
        let mut cancelled_sender = client.sender.clone();
        let (cancelled, cancelled_body) = cancelled_sender
            .send_request(data_budget_request(), true)
            .unwrap();
        let mut other = client.sender.clone();
        let (last, _) = other.send_request(data_budget_request(), true).unwrap();
        let extra = drain_to_probe(&mut client.peer).await;
        assert!(
            extra.iter().all(|frame| frame.stream_id == 0),
            "pending stream reached the wire"
        );
        drop((cancelled, cancelled_body, cancelled_sender));
        write_raw_frame(&mut client.peer, 1, 5, 1, &[0x88]).await;
        assert_eq!(first.await.unwrap().status(), StatusCode::OK);
        // The existing cancellation path retains HEADERS before RST_STREAM,
        // since resetting an idle stream would be a protocol error. It must
        // not grant receive credit to that cancelled stream.
        let cancelled_headers = next_stream_frame(&mut client.peer).await;
        assert_eq!(
            (cancelled_headers.kind, cancelled_headers.stream_id),
            (1, 3)
        );
        let reset = read_raw_frame(&mut client.peer).await;
        assert_eq!((reset.kind, reset.stream_id), (3, 3));
        assert_eq!(
            reset.payload,
            u32::from(crate::Reason::CANCEL).to_be_bytes()
        );
        let headers = next_stream_frame(&mut client.peer).await;
        assert_eq!((headers.kind, headers.stream_id), (1, 5));
        assert_update(read_raw_frame(&mut client.peer).await, 5, BOOST);
        let extra = drain_to_probe(&mut client.peer).await;
        assert!(extra.iter().all(|frame| frame.stream_id == 0));
        drop(last);
        client.close().await;
    })
    .await
    .expect("opening-window pending and cancelled streams timed out");
}

// Drive the actual connection beside one bounded peer operation. The caller
// retains the connection between operations to invoke its public SETTINGS API;
// no background task or command/watch channel is needed for this control.
async fn drive<F: Future>(
    connection: &mut super::super::Connection<DuplexStream, Bytes>,
    operation: F,
) -> F::Output {
    tokio::select! {
        result = connection => panic!("connection exited during peer operation: {result:?}"),
        output = operation => output,
    }
}

#[tokio::test]
async fn opening_window_later_settings_adjust_old_credit_once_and_new_stream_baseline() {
    timeout(DEADLINE, async {
        // One change below the opening target and one above it: the latter
        // raises an existing boosted stream but emits no new-stream boost.
        for changed_initial in [16_u32, 40] {
            let mut builder = builder();
            builder
                .initial_window_size(8)
                .initial_stream_window_target(Some(32));
            let (io, mut peer) = duplex(512);
            let (mut sender, mut connection) = builder.handshake::<_, Bytes>(io).await.unwrap();
            drive(&mut connection, async {
                accept_client_handshake(&mut peer).await;
                let frames = drain_to_probe(&mut peer).await;
                assert!(frames.iter().all(|frame| frame.stream_id == 0));
            })
            .await;

            let (response, _) = sender.send_request(data_budget_request(), true).unwrap();
            let mut first = drive(&mut connection, async {
                let headers = next_stream_frame(&mut peer).await;
                assert_eq!((headers.kind, headers.stream_id), (1, 1));
                assert_update(read_raw_frame(&mut peer).await, 1, 24);
                write_raw_frame(&mut peer, 1, 4, 1, &[0x88]).await;
                write_raw_frame(&mut peer, 0, 0, 1, b"held").await;
                let mut response = response.await.unwrap();
                assert_eq!(
                    response.body_mut().data().await.unwrap().unwrap(),
                    b"held"[..]
                );
                response
            })
            .await;
            assert_eq!(first.body_mut().flow_control().used_capacity(), 4);
            assert_eq!(first.body_mut().flow_control().available_capacity(), 28);

            connection.set_initial_window_size(changed_initial).unwrap();
            let settings = drive(&mut connection, read_raw_frame(&mut peer)).await;
            assert_eq!(
                (settings.kind, settings.flags, settings.stream_id),
                (4, 0, 0)
            );
            assert_eq!(settings.payload, settings_payload(&[(4, changed_initial)]));
            assert_eq!(first.body_mut().flow_control().available_capacity(), 28);
            drive(&mut connection, async {
                write_raw_frame(&mut peer, 4, 1, 0, &[]).await;
                let frames = drain_to_probe(&mut peer).await;
                assert!(frames.iter().all(|frame| frame.stream_id == 0));
            })
            .await;
            let old_grant = 32 + changed_initial - 8;
            assert_eq!(first.body_mut().flow_control().used_capacity(), 4);
            assert_eq!(
                first.body_mut().flow_control().available_capacity(),
                (old_grant - 4) as isize
            );

            let (response, _) = sender.send_request(data_budget_request(), true).unwrap();
            let mut next = drive(&mut connection, async {
                let headers = next_stream_frame(&mut peer).await;
                assert_eq!((headers.kind, headers.stream_id), (1, 3));
                let increment = 32_u32.saturating_sub(changed_initial);
                if increment != 0 {
                    assert_update(read_raw_frame(&mut peer).await, 3, increment);
                }
                let frames = drain_to_probe(&mut peer).await;
                assert!(frames.iter().all(|frame| frame.stream_id == 0));
                write_raw_frame(&mut peer, 1, 4, 3, &[0x88]).await;
                response.await.unwrap()
            })
            .await;
            let new_grant = 32_u32.max(changed_initial);
            assert_eq!(next.body_mut().flow_control().used_capacity(), 0);
            assert_eq!(
                next.body_mut().flow_control().available_capacity(),
                new_grant as isize
            );
            assert_eq!(
                first.body_mut().flow_control().available_capacity(),
                (old_grant - 4) as isize
            );

            drive(&mut connection, async {
                for (id, response, remaining, grant) in [
                    (1, &mut first, old_grant - 4, old_grant),
                    (3, &mut next, new_grant, new_grant),
                ] {
                    write_raw_frame(&mut peer, 0, 0, id, &vec![b'a'; remaining as usize]).await;
                    assert_eq!(
                        response.body_mut().data().await.unwrap().unwrap().len(),
                        remaining as usize
                    );
                    assert_eq!(
                        response.body_mut().flow_control().used_capacity(),
                        grant as usize
                    );
                    assert_eq!(response.body_mut().flow_control().available_capacity(), 0);
                    write_raw_frame(&mut peer, 0, 0, id, b"x").await;
                    let error = response
                        .body_mut()
                        .data()
                        .await
                        .unwrap()
                        .expect_err("later SETTINGS doubled receive credit");
                    assert_eq!(error.reason(), Some(crate::Reason::FLOW_CONTROL_ERROR));
                    let reset = next_stream_frame(&mut peer).await;
                    assert_eq!((reset.kind, reset.stream_id), (3, id));
                    assert_eq!(
                        reset.payload,
                        u32::from(crate::Reason::FLOW_CONTROL_ERROR).to_be_bytes()
                    );
                }
            })
            .await;
        }
    })
    .await
    .expect("opening-window later SETTINGS accounting timed out");
}
