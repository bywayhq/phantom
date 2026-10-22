use super::*;

const DEADLINE: Duration = Duration::from_secs(5);

struct Client {
    peer: DuplexStream,
    sender: super::super::SendRequest<Bytes>,
    driver: tokio::task::JoinHandle<Result<(), crate::Error>>,
}

impl Client {
    async fn open(builder: super::super::Builder) -> Self {
        let (io, mut peer) = duplex(128 * 1024);
        let (sender, connection) = builder.handshake(io).await.expect("handshake failed");
        let driver = tokio::spawn(connection);
        accept_client_handshake(&mut peer).await;
        let mut client = Self {
            peer,
            sender,
            driver,
        };
        client.probe().await;
        client
    }

    async fn headers(&mut self) -> RawFrame {
        loop {
            let frame = read_raw_frame(&mut self.peer).await;
            assert_ne!(frame.kind, 7, "unexpected GOAWAY: {:?}", frame.payload);
            if frame.kind == 1 {
                return frame;
            }
            assert_eq!(frame.stream_id, 0, "unexpected stream frame");
        }
    }

    async fn probe(&mut self) -> Vec<RawFrame> {
        write_raw_frame(&mut self.peer, 6, 0, 0, b"bands!!!").await;
        let mut frames = Vec::new();
        loop {
            let frame = read_raw_frame(&mut self.peer).await;
            assert_ne!(frame.kind, 7, "unexpected GOAWAY: {:?}", frame.payload);
            if (frame.kind, frame.flags, frame.stream_id) == (6, 1, 0) {
                assert_eq!(frame.payload, b"bands!!!");
                return frames;
            }
            frames.push(frame);
        }
    }

    async fn close(mut self) {
        self.driver.abort();
        match (&mut self.driver).await {
            Err(error) => assert!(error.is_cancelled(), "driver panicked: {error}"),
            Ok(result) => panic!("driver exited before cleanup: {result:?}"),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

fn request(weight: u8) -> Request<()> {
    let mut request = data_budget_request();
    request
        .extensions_mut()
        .insert(HeadersFrameOverrides::new().weight_band(weight, true));
    request
}

fn assert_priority(frame: &RawFrame, parent: u32, weight: u8, exclusive: bool) {
    assert_eq!(frame.kind, 1);
    assert_ne!(frame.flags & 0x20, 0, "HEADERS priority missing");
    assert_eq!(frame.payload[4], weight);
    let dependency = u32::from_be_bytes(frame.payload[..4].try_into().unwrap());
    assert_eq!(dependency & 0x7fff_ffff, parent);
    assert_eq!(dependency >> 31 != 0, exclusive);
}

#[tokio::test]
async fn newest_same_band_and_nearest_higher_band_follow_emission_order() {
    timeout(DEADLINE, async {
        let mut client = Client::open(super::super::Builder::new()).await;
        let mut live = Vec::new();
        let mut ids = Vec::new();
        // Expected parents refer to peer-observed IDs, not a captured sequence.
        for (weight, parent_position) in [
            (100, None),
            (200, None),
            (150, Some(1)),
            (150, Some(2)),
            (50, Some(0)),
            (255, None),
            (0, Some(4)),
        ] {
            live.push(client.sender.send_request(request(weight), true).unwrap());
            let frame = client.headers().await;
            let parent = parent_position.map_or(0, |position| ids[position]);
            assert_priority(&frame, parent, weight, true);
            ids.push(frame.stream_id);
        }
        client.close().await;
    })
    .await
    .expect("band ordering timed out");
}

#[tokio::test]
async fn fixed_overrides_remain_exact_and_do_not_join_bands() {
    timeout(DEADLINE, async {
        let mut builder = super::super::Builder::new();
        builder.headers_stream_dependency(StreamDependency::new(StreamId::zero(), 255, true));
        let mut client = Client::open(builder).await;
        let fixed = client
            .sender
            .send_request(data_budget_request(), true)
            .unwrap();
        assert_priority(&client.headers().await, 0, 255, true);
        let band = client.sender.send_request(request(100), true).unwrap();
        let band_frame = client.headers().await;
        assert_priority(&band_frame, 0, 100, true);

        let mut overridden = request(200);
        overridden.extensions_mut().insert(
            HeadersFrameOverrides::new()
                .weight_band(200, true)
                .stream_dependency(StreamDependency::new(
                    StreamId::from(band_frame.stream_id),
                    17,
                    false,
                )),
        );
        let override_stream = client.sender.send_request(overridden, true).unwrap();
        assert_priority(&client.headers().await, band_frame.stream_id, 17, false);
        let next = client.sender.send_request(request(150), true).unwrap();
        assert_priority(&client.headers().await, 0, 150, true);
        drop((fixed, band, override_stream, next));
        client.close().await;
    })
    .await
    .expect("fixed override control timed out");
}

#[tokio::test]
async fn cloned_senders_share_bands_but_separate_sessions_do_not() {
    timeout(DEADLINE, async {
        let mut first = Client::open(super::super::Builder::new()).await;
        let mut clone = first.sender.clone();
        let a = first.sender.send_request(request(100), true).unwrap();
        let a_frame = first.headers().await;
        let mut other_authority = request(100);
        *other_authority.uri_mut() = "https://other.example/".parse().unwrap();
        let b = clone.send_request(other_authority, true).unwrap();
        assert_priority(&first.headers().await, a_frame.stream_id, 100, true);

        let mut second = Client::open(super::super::Builder::new()).await;
        let c = second.sender.send_request(request(100), true).unwrap();
        assert_priority(&second.headers().await, 0, 100, true);
        drop((a, b, c, clone));
        first.close().await;
        second.close().await;
    })
    .await
    .expect("session isolation timed out");
}

#[tokio::test]
async fn completed_responses_leave_bands_before_buffered_bodies_are_consumed() {
    timeout(DEADLINE, async {
        let mut client = Client::open(super::super::Builder::new()).await;
        let mut held = Vec::new();
        for ending in 0..3 {
            let (response, upload) = client.sender.send_request(request(200), true).unwrap();
            let frame = client.headers().await;
            assert_priority(&frame, 0, 200, true);
            write_raw_frame(
                &mut client.peer,
                1,
                if ending == 0 { 5 } else { 4 },
                frame.stream_id,
                &[0x88],
            )
            .await;
            if ending != 0 {
                write_raw_frame(
                    &mut client.peer,
                    0,
                    if ending == 1 { 1 } else { 0 },
                    frame.stream_id,
                    b"unread",
                )
                .await;
                if ending == 2 {
                    write_raw_frame(
                        &mut client.peer,
                        1,
                        5,
                        frame.stream_id,
                        b"\x00\x05x-end\x03yes",
                    )
                    .await;
                }
            }
            client.probe().await;
            held.push((response.await.unwrap(), upload));
        }
        let next = client.sender.send_request(request(100), true).unwrap();
        assert_priority(&client.headers().await, 0, 100, true);
        drop((held, next));
        client.close().await;
    })
    .await
    .expect("response completion timed out");
}

#[tokio::test]
async fn half_closed_streams_remain_parents_until_reset_or_local_completion() {
    timeout(DEADLINE, async {
        let mut client = Client::open(super::super::Builder::new()).await;
        let (response, mut upload) = client.sender.send_request(request(200), false).unwrap();
        let frame = client.headers().await;
        write_raw_frame(&mut client.peer, 1, 5, frame.stream_id, &[0x88]).await;
        let held = response.await.unwrap();
        let same = client.sender.send_request(request(200), true).unwrap();
        let same_frame = client.headers().await;
        assert_priority(&same_frame, frame.stream_id, 200, true);
        // Remove the newer stream by peer reset, leaving the half-closed one.
        write_raw_frame(
            &mut client.peer,
            3,
            0,
            same_frame.stream_id,
            &u32::from(crate::Reason::CANCEL).to_be_bytes(),
        )
        .await;
        client.probe().await;
        let next = client.sender.send_request(request(100), true).unwrap();
        let next_frame = client.headers().await;
        assert_priority(&next_frame, frame.stream_id, 100, true);
        // This empty final DATA closes the upload; the response is still held.
        upload.send_data(Bytes::new(), true).unwrap();
        let frames = client.probe().await;
        assert!(frames
            .iter()
            .any(|f| (f.kind, f.flags, f.stream_id) == (0, 1, frame.stream_id)));
        let higher = client.sender.send_request(request(150), true).unwrap();
        assert_priority(&client.headers().await, 0, 150, true);
        drop((held, upload, same, next, higher));
        client.close().await;
    })
    .await
    .expect("half-closed stream lifecycle timed out");
}

#[tokio::test]
async fn local_reset_removes_a_live_parent_while_reset_is_retained() {
    timeout(DEADLINE, async {
        let mut client = Client::open(super::super::Builder::new()).await;
        let (response, mut upload) = client.sender.send_request(request(200), true).unwrap();
        let frame = client.headers().await;
        upload.send_reset(crate::Reason::CANCEL);
        let frames = client.probe().await;
        assert!(frames
            .iter()
            .any(|f| (f.kind, f.stream_id) == (3, frame.stream_id)));
        let next = client.sender.send_request(request(100), true).unwrap();
        assert_priority(&client.headers().await, 0, 100, true);
        drop((response, upload, next));
        client.close().await;
    })
    .await
    .expect("local reset lifecycle timed out");
}

#[tokio::test]
async fn pending_open_uses_current_live_bands_and_cancelled_open_never_joins() {
    timeout(DEADLINE, async {
        let mut builder = super::super::Builder::new();
        builder
            .initial_max_send_streams(1)
            .retain_initial_max_send_streams(true);
        let mut client = Client::open(builder).await;
        let (first, _) = client.sender.send_request(request(200), true).unwrap();
        let first_frame = client.headers().await;
        let pending = client.sender.send_request(request(100), true).unwrap();
        assert!(client.probe().await.iter().all(|f| f.stream_id == 0));
        write_raw_frame(&mut client.peer, 1, 5, first_frame.stream_id, &[0x88]).await;
        let pending_frame = client.headers().await;
        assert_priority(&pending_frame, 0, 100, true);
        let cancelled = client.sender.send_request(request(200), true).unwrap();
        drop(cancelled);
        assert!(client.probe().await.iter().all(|f| f.stream_id == 0));
        write_raw_frame(&mut client.peer, 1, 5, pending_frame.stream_id, &[0x88]).await;
        let cancelled_frame = client.headers().await;
        assert_priority(&cancelled_frame, 0, 200, true);
        let reset = read_raw_frame(&mut client.peer).await;
        assert_eq!(
            (reset.kind, reset.stream_id),
            (3, cancelled_frame.stream_id)
        );
        assert_eq!(
            reset.payload,
            u32::from(crate::Reason::CANCEL).to_be_bytes()
        );
        let next = client.sender.send_request(request(100), true).unwrap();
        assert_priority(&client.headers().await, 0, 100, true);
        drop((first, pending, next));
        client.close().await;
    })
    .await
    .expect("pending-open lifecycle timed out");
}

#[tokio::test]
async fn queued_disable_suppresses_live_band_fields_including_fragmented_headers() {
    timeout(DEADLINE, async {
        let (io, mut peer) = duplex(128 * 1024);
        let (mut sender, connection) = super::super::Builder::new()
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        let mut request = request(100);
        request.headers_mut().insert(
            "x-large",
            HeaderValue::from_str(&"z".repeat(30_000)).unwrap(),
        );
        let queued = sender.send_request(request, true).unwrap();
        write_raw_frame(&mut peer, 4, 0, 0, &settings_payload(&[(9, 1)])).await;
        let driver = tokio::spawn(connection);
        let mut client = Client {
            peer,
            sender,
            driver,
        };
        read_client_preface(&mut client.peer).await;
        let mut ack_seen = false;
        let headers = loop {
            let frame = read_raw_frame(&mut client.peer).await;
            assert_ne!(frame.kind, 7, "unexpected GOAWAY");
            assert_ne!(frame.kind, 2, "suppressed request sent PRIORITY");
            if frame.kind == 1 {
                break frame;
            }
            if (frame.kind, frame.flags) == (4, 1) {
                ack_seen = true;
            }
        };
        assert!(ack_seen, "HEADERS preceded processed peer SETTINGS");
        assert_eq!(headers.flags & 0x21, 1);
        assert_eq!(headers.flags & 4, 0);
        let mut block = headers.payload;
        loop {
            let frame = read_raw_frame(&mut client.peer).await;
            assert_eq!((frame.kind, frame.stream_id), (9, headers.stream_id));
            assert_eq!(frame.flags & !4, 0);
            block.extend_from_slice(&frame.payload);
            if frame.flags & 4 != 0 {
                break;
            }
        }
        let fields = decode_header_block(&block);
        assert!(fields
            .iter()
            .any(|(n, v)| n == "x-large" && v.as_bytes() == "z".repeat(30_000).as_bytes()));
        drop(queued);
        client.close().await;
    })
    .await
    .expect("live-band suppression timed out");
}

#[tokio::test]
async fn fragmented_initial_headers_preserve_end_stream_and_exact_payload() {
    timeout(DEADLINE, async {
        let mut client = Client::open(super::super::Builder::new()).await;
        let mut opening = request(0);
        opening
            .extensions_mut()
            .insert(HeadersFrameOverrides::new().weight_band(0, false));
        opening.headers_mut().insert(
            "x-large",
            HeaderValue::from_str(&"z".repeat(30_000)).unwrap(),
        );
        let held = client.sender.send_request(opening, true).unwrap();
        let headers = client.headers().await;
        assert_priority(&headers, 0, 0, false);
        assert_eq!(headers.flags & 1, 1);
        assert_eq!(headers.flags & 4, 0);
        let mut block = headers.payload[5..].to_vec();
        loop {
            let frame = read_raw_frame(&mut client.peer).await;
            assert_eq!((frame.kind, frame.stream_id), (9, headers.stream_id));
            assert_eq!(frame.flags & !4, 0);
            block.extend_from_slice(&frame.payload);
            if frame.flags & 4 != 0 {
                break;
            }
        }
        let fields = decode_header_block(&block);
        assert!(fields
            .iter()
            .any(|(n, v)| n == "x-large" && v.as_bytes() == "z".repeat(30_000).as_bytes()));
        let next = client.sender.send_request(request(0), true).unwrap();
        assert_priority(&client.headers().await, headers.stream_id, 0, true);
        drop((held, next));
        client.close().await;
    })
    .await
    .expect("fragmented live-band HEADERS timed out");
}

#[tokio::test]
async fn trailing_headers_do_not_register_the_initial_band_again() {
    timeout(DEADLINE, async {
        let mut client = Client::open(super::super::Builder::new()).await;
        let (first, mut upload) = client.sender.send_request(request(200), false).unwrap();
        let first_frame = client.headers().await;
        let second = client.sender.send_request(request(200), true).unwrap();
        let second_frame = client.headers().await;
        assert_priority(&second_frame, first_frame.stream_id, 200, true);
        let mut trailers = HeaderMap::new();
        trailers.insert("x-end", HeaderValue::from_static("yes"));
        upload.send_trailers(trailers).unwrap();
        let trailing = client.headers().await;
        assert_eq!(
            (trailing.stream_id, trailing.flags),
            (first_frame.stream_id, 5)
        );
        let third = client.sender.send_request(request(100), true).unwrap();
        assert_priority(&client.headers().await, second_frame.stream_id, 100, true);
        drop((first, upload, second, third));
        client.close().await;
    })
    .await
    .expect("live-band trailer control timed out");
}

#[tokio::test]
async fn rejected_header_conversion_never_enters_a_band() {
    timeout(DEADLINE, async {
        let mut client = Client::open(super::super::Builder::new()).await;
        let mut invalid = request(255);
        invalid.extensions_mut().insert(OrderedHeaders::new(vec![(
            HeaderName::from_static("x-missing"),
            HeaderValue::from_static("value"),
        )]));
        let error = client
            .sender
            .send_request(invalid, true)
            .err()
            .expect("invalid ordered fields accepted");
        assert_eq!(error.reason(), None);
        assert!(error.to_string().contains("malformed headers"));
        assert!(client
            .probe()
            .await
            .iter()
            .all(|frame| frame.stream_id == 0));
        let next = client.sender.send_request(request(100), true).unwrap();
        assert_priority(&client.headers().await, 0, 100, true);
        drop(next);
        client.close().await;
    })
    .await
    .expect("header conversion control timed out");
}

#[tokio::test]
async fn write_backpressure_defers_parent_selection_until_codec_readiness() {
    timeout(DEADLINE, async {
        let (io, mut peer) = duplex(64);
        let (mut sender, mut connection) = super::super::Builder::new()
            .handshake::<_, Bytes>(io)
            .await
            .unwrap();
        drive_idle_ping_checkpoint(&mut connection, async {
            accept_client_handshake(&mut peer).await;
            assert_connection_open(&mut peer).await;
        })
        .await;
        let mut large = request(200);
        large.headers_mut().insert(
            "x-large",
            HeaderValue::from_str(&"z".repeat(30_000)).unwrap(),
        );
        let (first, mut upload) = sender.send_request(large, true).unwrap();
        drive_idle_ping_checkpoint(&mut connection, std::future::ready(())).await;
        // Read just the first frame head. Its remaining bytes fill the tiny pipe,
        // so the codec cannot accept the next request yet.
        let mut head = [0; 9];
        peer.read_exact(&mut head).await.unwrap();
        assert_eq!(head[3], 1);
        assert_ne!(head[4] & 0x20, 0);
        assert_eq!(head[4] & 4, 0);
        let first_id = u32::from_be_bytes(head[5..].try_into().unwrap());
        let length =
            (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
        let second = sender.send_request(request(100), true).unwrap();
        upload.send_reset(crate::Reason::CANCEL);
        let driver = tokio::spawn(connection);
        let mut client = Client {
            peer,
            sender,
            driver,
        };
        let mut payload = vec![0; length];
        client.peer.read_exact(&mut payload).await.unwrap();
        let mut reset_seen = false;
        let next = loop {
            let frame = read_raw_frame(&mut client.peer).await;
            match frame.kind {
                9 => assert_eq!(frame.stream_id, first_id),
                3 => {
                    assert_eq!(frame.stream_id, first_id);
                    reset_seen = true;
                }
                1 => break frame,
                _ => assert_eq!(frame.stream_id, 0, "unexpected stream frame"),
            }
        };
        assert_priority(&next, 0, 100, true);
        let remaining = client.probe().await;
        assert!(
            reset_seen
                || remaining
                    .iter()
                    .any(|frame| (frame.kind, frame.stream_id) == (3, first_id))
        );
        drop((first, upload, second));
        client.close().await;
    })
    .await
    .expect("write-backpressure selection timed out");
}
