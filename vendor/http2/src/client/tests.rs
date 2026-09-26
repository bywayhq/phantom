use std::{
    future::{poll_fn, Future},
    io::Cursor,
    ops::ControlFlow,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use bytes::{BufMut, Bytes, BytesMut};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Version};
use tokio::{
    io::{duplex, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    time::timeout,
};

use super::Peer;
use crate::{
    codec::{SendError, UserError},
    ext::{
        HeadersFrameOverrides, HpackEncoderProfile, HuffmanCoding, OrderedHeaders, StaticNameIndex,
    },
    frame::{Headers, PseudoId, PseudoOrder, Settings, StreamDependency, StreamId},
    hpack::{huffman, Decoder, Encoder, Header},
};

const A: HeaderName = HeaderName::from_static("x-a");
const B: HeaderName = HeaderName::from_static("x-b");

#[test]
fn ordered_headers_encode_interleaved_duplicates_exactly() {
    let mut request = request_with_headers();
    request.extensions_mut().insert(OrderedHeaders::new(vec![
        (A, HeaderValue::from_static("a1")),
        (B, HeaderValue::from_static("b1")),
        (A, HeaderValue::from_static("a2")),
    ]));

    let frame = convert(request).expect("matching ordered headers were rejected");
    assert_eq!(
        decode_ordinary_fields(frame),
        vec![
            (A, HeaderValue::from_static("a1")),
            (B, HeaderValue::from_static("b1")),
            (A, HeaderValue::from_static("a2")),
        ]
    );
}

#[test]
fn ordered_headers_reject_semantic_mismatch() {
    let mismatches = [
        vec![
            (A, HeaderValue::from_static("a1")),
            (B, HeaderValue::from_static("b1")),
        ],
        vec![
            (A, HeaderValue::from_static("a1")),
            (B, HeaderValue::from_static("b1")),
            (A, HeaderValue::from_static("a2")),
            (B, HeaderValue::from_static("extra")),
        ],
        vec![
            (A, HeaderValue::from_static("a1")),
            (B, HeaderValue::from_static("b1")),
            (A, HeaderValue::from_static("different")),
        ],
        vec![
            (A, HeaderValue::from_static("a2")),
            (B, HeaderValue::from_static("b1")),
            (A, HeaderValue::from_static("a1")),
        ],
    ];

    for ordered in mismatches {
        let mut request = request_with_headers();
        request
            .extensions_mut()
            .insert(OrderedHeaders::new(ordered));

        let error = match convert(request) {
            Ok(_) => panic!("mismatched ordered headers were accepted"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            SendError::User(UserError::MalformedHeaders)
        ));
        assert_eq!(error.to_string(), "malformed headers");
    }
}

#[test]
fn absent_ordered_headers_use_header_map_iteration() {
    let request = request_with_headers();
    let expected = request
        .headers()
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Vec<_>>();

    let frame = convert(request).expect("ordinary request was rejected");
    assert_eq!(decode_ordinary_fields(frame), expected);
}

#[tokio::test]
async fn handshake_preserves_interleaved_ordered_headers() {
    timeout(Duration::from_secs(2), async {
        let (client_io, mut peer_io) = duplex(16 * 1024);
        let (sender, connection) = super::handshake(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);

        let mut request = request_with_headers();
        request.extensions_mut().insert(OrderedHeaders::new(vec![
            (A, HeaderValue::from_static("a1")),
            (B, HeaderValue::from_static("b1")),
            (A, HeaderValue::from_static("a2")),
        ]));
        let mut sender = sender.ready().await.expect("sender never became ready");
        let (_response, send) = sender
            .send_request(request, true)
            .expect("request was rejected");
        drop(send);

        let mut preface = [0_u8; 24];
        peer_io
            .read_exact(&mut preface)
            .await
            .expect("client preface was truncated");
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        let header_block = loop {
            let mut head = [0_u8; 9];
            peer_io
                .read_exact(&mut head)
                .await
                .expect("frame header was truncated");
            let length =
                (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
            let mut payload = vec![0_u8; length];
            peer_io
                .read_exact(&mut payload)
                .await
                .expect("frame payload was truncated");
            if head[3] == 1 {
                break payload;
            }
        };

        assert_eq!(
            decode_header_block(&header_block),
            vec![
                (A, HeaderValue::from_static("a1")),
                (B, HeaderValue::from_static("b1")),
                (A, HeaderValue::from_static("a2")),
            ]
        );
        driver.abort();
    })
    .await
    .expect("ordered-header handshake test timed out");
}

#[tokio::test]
async fn headers_frame_overrides_apply_to_one_request_only() {
    timeout(Duration::from_secs(2), async {
        let (client_io, mut peer_io) = duplex(16 * 1024);
        let mut builder = super::Builder::new();
        builder
            .headers_pseudo_order(
                PseudoOrder::builder()
                    .extend([
                        PseudoId::Method,
                        PseudoId::Authority,
                        PseudoId::Scheme,
                        PseudoId::Path,
                    ])
                    .build(),
            )
            .headers_stream_dependency(StreamDependency::new(StreamId::zero(), 255, true));
        let (sender, connection) = builder
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);

        let mut overridden = request_with_headers();
        overridden.extensions_mut().insert(
            HeadersFrameOverrides::new()
                .pseudo_order(
                    PseudoOrder::builder()
                        .extend([
                            PseudoId::Method,
                            PseudoId::Path,
                            PseudoId::Authority,
                            PseudoId::Scheme,
                        ])
                        .build(),
                )
                .stream_dependency(StreamDependency::new(StreamId::zero(), 21, false)),
        );
        let mut sender = sender.ready().await.expect("sender never became ready");
        let (_first, first) = sender
            .send_request(overridden, true)
            .expect("overridden request was rejected");
        drop(first);
        let mut sender = sender.ready().await.expect("sender never became ready");
        let (_second, second) = sender
            .send_request(request_with_headers(), true)
            .expect("default request was rejected");
        drop(second);

        read_client_preface(&mut peer_io).await;
        let mut decoder = Decoder::new(4096);
        let mut headers = Vec::new();
        while headers.len() < 2 {
            let frame = read_raw_frame(&mut peer_io).await;
            if frame.kind == 1 {
                assert_ne!(frame.flags & 0x20, 0, "HEADERS omitted priority");
                let priority = (
                    frame.payload[0] & 0x80 != 0,
                    u32::from_be_bytes([
                        frame.payload[0] & 0x7f,
                        frame.payload[1],
                        frame.payload[2],
                        frame.payload[3],
                    ]),
                    frame.payload[4],
                );
                let pseudo = decode_pseudo_names(&mut decoder, &frame.payload[5..]);
                headers.push((frame.stream_id, priority, pseudo));
            }
        }

        assert_eq!(
            headers,
            vec![
                (
                    1,
                    (false, 0, 21),
                    vec![":method", ":path", ":authority", ":scheme"]
                ),
                (
                    3,
                    (true, 0, 255),
                    vec![":method", ":authority", ":scheme", ":path"]
                ),
            ]
        );
        driver.abort();
    })
    .await
    .expect("HEADERS override test timed out");
}

/// The builder's HPACK profile reaches the first HEADERS frame on the wire.
///
/// `PATCH` and `13` are the two cases the captures separate: a method with no
/// full static entry, and a value whose Huffman form ties with the raw one.
#[tokio::test]
async fn hpack_encoder_profile_shapes_the_first_headers_block() {
    let chromium = HpackEncoderProfile::new()
        .literal_pseudo_headers([PseudoId::Method])
        .huffman_coding(HuffmanCoding::WhenShorter);
    let firefox = HpackEncoderProfile::new()
        .static_name_index(StaticNameIndex::Highest)
        .huffman_coding(HuffmanCoding::WhenNotLonger);

    let mut coded_patch = BytesMut::new();
    huffman::encode(b"PATCH", &mut coded_patch);
    let mut coded_tie = BytesMut::new();
    huffman::encode(b"13", &mut coded_tie);

    // Literal without indexing naming `:method GET`. Huffman codes `PATCH`
    // in five bytes, the raw length, so the value is sent raw as well.
    assert_eq!(coded_patch.len(), b"PATCH".len());
    let chromium_method = vec![0x02, 0x05, b'P', b'A', b'T', b'C', b'H'];
    let chromium_tie = vec![0x40 | 17, 0x02, b'1', b'3'];

    // Incremental indexing naming `:method POST`, then a coded tie value.
    let mut firefox_method = vec![0x40 | 3, 0x80 | coded_patch.len() as u8];
    firefox_method.extend_from_slice(&coded_patch);
    let mut firefox_tie = vec![0x40 | 17, 0x80 | coded_tie.len() as u8];
    firefox_tie.extend_from_slice(&coded_tie);

    for (profile, method, tie) in [
        (chromium, chromium_method, chromium_tie),
        (firefox, firefox_method, firefox_tie),
    ] {
        let block = timeout(Duration::from_secs(2), first_headers_block(profile))
            .await
            .expect("HPACK profile test timed out");
        assert!(
            contains(&block, &method),
            "block {block:?} omitted the method representation {method:?}"
        );
        assert!(
            contains(&block, &tie),
            "block {block:?} omitted the tie representation {tie:?}"
        );
    }
}

/// Returns the HPACK block of the first HEADERS a profiled client sends.
async fn first_headers_block(profile: HpackEncoderProfile) -> Vec<u8> {
    let (client_io, mut peer_io) = duplex(16 * 1024);
    let mut builder = super::Builder::new();
    builder.hpack_encoder_profile(profile);
    let (sender, connection) = builder
        .handshake::<_, Bytes>(client_io)
        .await
        .expect("client handshake failed");
    let driver = tokio::spawn(connection);

    let mut request = Request::new(());
    *request.method_mut() = Method::PATCH;
    *request.uri_mut() = "https://example.test/resource"
        .parse()
        .expect("static request URI must parse");
    *request.version_mut() = Version::HTTP_2;
    request.headers_mut().append(
        HeaderName::from_static("accept-language"),
        HeaderValue::from_static("13"),
    );
    let mut sender = sender.ready().await.expect("sender never became ready");
    let (_response, body) = sender
        .send_request(request, true)
        .expect("profiled request was rejected");
    drop(body);

    read_client_preface(&mut peer_io).await;
    let block = loop {
        let frame = read_raw_frame(&mut peer_io).await;
        if frame.kind == 1 {
            assert_eq!(frame.flags & 0x20, 0, "test expects no priority fields");
            break frame.payload;
        }
    };
    driver.abort();
    block
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

#[tokio::test]
async fn handshake_preserves_interleaved_ordered_sensitive_trailers() {
    timeout(Duration::from_secs(2), async {
        let (client_io, mut peer_io) = duplex(16 * 1024);
        let (sender, connection) = super::handshake(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);

        let mut sender = sender.ready().await.expect("sender never became ready");
        let (_response, mut send) = sender
            .send_request(request_with_headers(), false)
            .expect("request was rejected");

        let mut a1 = HeaderValue::from_static("secret-a1");
        a1.set_sensitive(true);
        let b1 = HeaderValue::from_static("b1");
        let a2 = HeaderValue::from_static("a2");
        let ordered = vec![(A, a1.clone()), (B, b1.clone()), (A, a2.clone())];
        let mut semantic = HeaderMap::new();
        semantic.append(A, a1);
        semantic.append(B, b1);
        semantic.append(A, a2);

        let mismatch = send
            .send_ordered_trailers(semantic.clone(), OrderedHeaders::new(ordered[..2].to_vec()))
            .expect_err("mismatched ordered trailers were accepted");
        assert_eq!(mismatch.to_string(), "user error: malformed headers");
        send.send_ordered_trailers(semantic, OrderedHeaders::new(ordered.clone()))
            .expect("ordered trailers were rejected");

        let mut preface = [0_u8; 24];
        peer_io
            .read_exact(&mut preface)
            .await
            .expect("client preface was truncated");
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        let mut blocks = Vec::new();
        while blocks.len() < 2 {
            let mut head = [0_u8; 9];
            peer_io
                .read_exact(&mut head)
                .await
                .expect("frame header was truncated");
            let length =
                (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
            let mut payload = vec![0_u8; length];
            peer_io
                .read_exact(&mut payload)
                .await
                .expect("frame payload was truncated");
            if head[3] == 1 {
                blocks.push((head[4], payload));
            }
        }

        assert_eq!(blocks[0].0 & 0x1, 0, "initial HEADERS ended the stream");
        assert_eq!(blocks[1].0 & 0x1, 0x1, "trailers omitted END_STREAM");
        assert_eq!(
            blocks[1].1.first().expect("trailer block was empty") & 0xf0,
            0x10,
            "sensitive first trailer was not encoded as never-indexed"
        );
        let mut decoder = Decoder::new(4096);
        let _ = decode_header_block_with(&mut decoder, &blocks[0].1);
        let trailers = decode_header_block_with(&mut decoder, &blocks[1].1);
        assert_eq!(trailers, ordered);

        driver.abort();
    })
    .await
    .expect("ordered-trailer handshake test timed out");
}

#[tokio::test]
async fn dropping_final_client_stream_flushes_reset_before_close() {
    timeout(Duration::from_secs(2), async {
        let (client_io, server_io) = duplex(16 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = crate::server::handshake(server_io)
                .await
                .expect("server handshake failed");
            let (request, mut respond) = connection
                .accept()
                .await
                .expect("connection closed before request")
                .expect("request failed");
            let mut send = respond
                .send_response(Response::new(()), false)
                .expect("response headers failed");
            send.send_data(Bytes::from_static(b"partial"), false)
                .expect("response DATA failed");

            let reason = tokio::select! {
                biased;
                result = poll_fn(|cx| send.poll_reset(cx)) => {
                    result.expect("client reset was not observable")
                }
                incoming = connection.accept() => {
                    assert!(incoming.is_some(), "connection closed without a reset");
                    panic!("client sent an unexpected second request");
                }
            };
            assert_eq!(reason, crate::Reason::CANCEL);
            drop(request);
            drop(send);
            drop(respond);
            poll_fn(|cx| connection.poll_closed(cx))
                .await
                .expect("connection did not close after reset");
        });

        let (sender, connection) = super::handshake(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);
        let mut sender = sender.ready().await.expect("sender never became ready");
        let (response, mut send) = sender
            .send_request(request_with_headers(), true)
            .expect("request was rejected");
        let response = response.await.expect("response headers failed");
        let mut incoming = response.into_body();
        assert_eq!(
            incoming
                .data()
                .await
                .expect("response ended before DATA")
                .expect("response DATA failed"),
            "partial"
        );

        send.send_reset(crate::Reason::CANCEL);
        drop(incoming);
        drop(send);
        drop(sender);
        server.await.expect("server task panicked");
        driver
            .await
            .expect("client driver task panicked")
            .expect("client driver failed");
    })
    .await
    .expect("reset-and-close handshake test timed out");
}

#[tokio::test]
async fn pending_shutdown_is_not_self_woken_after_idle_close_transition() {
    let shutdown_polls = Arc::new(AtomicUsize::new(0));
    let (sender, mut connection) = super::handshake(PendingShutdownIo {
        shutdown_polls: Arc::clone(&shutdown_polls),
    })
    .await
    .expect("client handshake failed");
    drop(sender);

    let wake_count = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountWake(Arc::clone(&wake_count))));
    let mut context = Context::from_waker(&waker);

    assert!(Pin::new(&mut connection).poll(&mut context).is_pending());
    assert_eq!(wake_count.load(Ordering::SeqCst), 1);
    assert_eq!(shutdown_polls.load(Ordering::SeqCst), 0);

    assert!(Pin::new(&mut connection).poll(&mut context).is_pending());
    assert_eq!(shutdown_polls.load(Ordering::SeqCst), 1);
    assert_eq!(wake_count.load(Ordering::SeqCst), 1);

    assert!(Pin::new(&mut connection).poll(&mut context).is_pending());
    assert_eq!(shutdown_polls.load(Ordering::SeqCst), 2);
    assert_eq!(wake_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn full_codec_does_not_repeat_idle_close_self_wake() {
    let write_polls = Arc::new(AtomicUsize::new(0));
    let (sender, mut connection) = super::handshake(PendingWriteIo {
        write_polls: Arc::clone(&write_polls),
        preface_written: false,
    })
    .await
    .expect("client handshake failed");
    connection.inner.fill_write_capacity_for_test();
    drop(sender);

    let wake_count = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountWake(Arc::clone(&wake_count))));
    let mut context = Context::from_waker(&waker);

    assert!(Pin::new(&mut connection).poll(&mut context).is_pending());
    assert_eq!(wake_count.load(Ordering::SeqCst), 1);
    let after_transition = write_polls.load(Ordering::SeqCst);

    assert!(Pin::new(&mut connection).poll(&mut context).is_pending());
    assert!(write_polls.load(Ordering::SeqCst) > after_transition);
    assert_eq!(wake_count.load(Ordering::SeqCst), 1);

    assert!(Pin::new(&mut connection).poll(&mut context).is_pending());
    assert_eq!(wake_count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn seeded_peer_limits_apply_to_the_first_request() {
    let (client_io, _peer_io) = duplex(16 * 1024);
    let mut peer_settings = Settings::default();
    peer_settings.set_max_concurrent_streams(Some(0));
    let mut builder = super::Builder::new();
    builder.initial_peer_settings(peer_settings);
    let (mut sender, _connection) = builder
        .handshake::<_, Bytes>(client_io)
        .await
        .expect("client handshake failed");
    let (_response, send) = sender
        .send_request(request_with_headers(), true)
        .expect("request was rejected");
    drop(send);
    let pending = poll_fn(|context| Poll::Ready(sender.poll_ready(context).is_pending())).await;
    assert!(pending, "seeded concurrency limit was not applied");

    let (client_io, _peer_io) = duplex(16 * 1024);
    let mut peer_settings = Settings::default();
    peer_settings.set_initial_window_size(Some(0));
    let mut builder = super::Builder::new();
    builder.initial_peer_settings(peer_settings);
    let (mut sender, mut connection) = builder
        .handshake::<_, Bytes>(client_io)
        .await
        .expect("client handshake failed");
    let (_response, mut send) = sender
        .send_request(request_with_headers(), false)
        .expect("request was rejected");
    send.reserve_capacity(1);
    let wake_count = Arc::new(AtomicUsize::new(0));
    let waker = Waker::from(Arc::new(CountWake(wake_count)));
    let mut context = Context::from_waker(&waker);
    assert!(Pin::new(&mut connection).poll(&mut context).is_pending());
    assert_eq!(send.capacity(), 0, "seeded stream window was not applied");
}

#[tokio::test]
async fn extended_connect_readiness_is_immediate_for_enabled_seed() {
    let (client_io, _peer_io) = duplex(16 * 1024);
    let mut peer_settings = Settings::default();
    peer_settings.set_enable_connect_protocol(Some(1));
    let mut builder = super::Builder::new();
    builder.initial_peer_settings(peer_settings);
    let (mut sender, _connection) = builder
        .handshake::<_, Bytes>(client_io)
        .await
        .expect("client handshake failed");

    let mut context = Context::from_waker(Waker::noop());
    assert!(matches!(
        sender.poll_extended_connect_protocol_ready(&mut context),
        Poll::Ready(Ok(true))
    ));
}

#[tokio::test]
async fn extended_connect_readiness_waits_for_wire_settings_and_wakes() {
    timeout(Duration::from_secs(2), async {
        let (client_io, mut peer_io) = duplex(16 * 1024);
        let (mut sender, connection) = super::handshake(client_io)
            .await
            .expect("client handshake failed");
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountWake(Arc::clone(&wake_count))));
        let mut context = Context::from_waker(&waker);
        assert!(sender
            .poll_extended_connect_protocol_ready(&mut context)
            .is_pending());

        let driver = tokio::spawn(connection);
        read_client_preface(&mut peer_io).await;
        let initial = read_raw_frame(&mut peer_io).await;
        assert_eq!((initial.kind, initial.flags), (4, 0));
        write_raw_frame(&mut peer_io, 4, 0, 0, &settings_payload(&[(8, 1)])).await;
        let ack = read_raw_frame(&mut peer_io).await;
        assert_eq!((ack.kind, ack.flags, ack.stream_id), (4, 1, 0));
        assert!(wake_count.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            sender.poll_extended_connect_protocol_ready(&mut context),
            Poll::Ready(Ok(true))
        ));
        driver.abort();
    })
    .await
    .expect("wire readiness test timed out");
}

#[tokio::test]
async fn extended_connect_readiness_reports_wire_default_false() {
    timeout(Duration::from_secs(2), async {
        let (client_io, mut peer_io) = duplex(16 * 1024);
        let (mut sender, connection) = super::handshake(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);
        read_client_preface(&mut peer_io).await;
        let initial = read_raw_frame(&mut peer_io).await;
        assert_eq!((initial.kind, initial.flags), (4, 0));
        write_raw_frame(&mut peer_io, 4, 0, 0, &[]).await;
        let ack = read_raw_frame(&mut peer_io).await;
        assert_eq!((ack.kind, ack.flags, ack.stream_id), (4, 1, 0));
        assert!(!sender
            .extended_connect_protocol_ready()
            .await
            .expect("readiness failed"));
        driver.abort();
    })
    .await
    .expect("wire disabled-readiness test timed out");
}

#[tokio::test]
async fn extended_connect_readiness_wakes_with_connection_error() {
    timeout(Duration::from_secs(2), async {
        let (client_io, mut peer_io) = duplex(16 * 1024);
        let (mut sender, connection) = super::handshake(client_io)
            .await
            .expect("client handshake failed");
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountWake(Arc::clone(&wake_count))));
        let mut context = Context::from_waker(&waker);
        assert!(sender
            .poll_extended_connect_protocol_ready(&mut context)
            .is_pending());

        let driver = tokio::spawn(connection);
        read_client_preface(&mut peer_io).await;
        let initial = read_raw_frame(&mut peer_io).await;
        assert_eq!((initial.kind, initial.flags), (4, 0));
        write_raw_frame(&mut peer_io, 6, 0, 0, &[0; 8]).await;
        driver
            .await
            .expect("client driver task panicked")
            .expect_err("non-SETTINGS first peer frame was accepted");
        assert!(wake_count.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            sender.poll_extended_connect_protocol_ready(&mut context),
            Poll::Ready(Err(_))
        ));
    })
    .await
    .expect("readiness connection-error test timed out");
}

#[tokio::test]
async fn extended_connect_readiness_wakes_when_peer_closes_before_settings() {
    timeout(Duration::from_secs(2), async {
        let (client_io, mut peer_io) = duplex(16 * 1024);
        let (mut sender, connection) = super::handshake(client_io)
            .await
            .expect("client handshake failed");
        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = Waker::from(Arc::new(CountWake(Arc::clone(&wake_count))));
        let mut context = Context::from_waker(&waker);
        assert!(sender
            .poll_extended_connect_protocol_ready(&mut context)
            .is_pending());

        let driver = tokio::spawn(connection);
        read_client_preface(&mut peer_io).await;
        let initial = read_raw_frame(&mut peer_io).await;
        assert_eq!((initial.kind, initial.flags), (4, 0));
        drop(peer_io);
        driver
            .await
            .expect("client driver task panicked")
            .expect_err("clean EOF before peer settings was accepted");
        assert!(wake_count.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            sender.poll_extended_connect_protocol_ready(&mut context),
            Poll::Ready(Err(_))
        ));
    })
    .await
    .expect("readiness EOF test timed out");
}

#[tokio::test]
async fn seeded_peer_settings_change_first_headers_without_an_ack() {
    timeout(Duration::from_secs(2), async {
        let (client_io, mut peer_io) = duplex(16 * 1024);
        let mut peer_settings = Settings::default();
        peer_settings.set_header_table_size(Some(0));
        peer_settings.set_no_rfc7540_priorities(true);
        let mut builder = super::Builder::new();
        builder
            .headers_stream_dependency(StreamDependency::new(StreamId::zero(), 255, true))
            .initial_peer_settings(peer_settings);
        let (mut sender, connection) = builder
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);
        sender = sender.ready().await.expect("sender never became ready");
        let (_response, send) = sender
            .send_request(request_with_headers(), true)
            .expect("request was rejected");
        drop(send);

        read_client_preface(&mut peer_io).await;
        let mut settings_acks = 0;
        let headers = loop {
            let frame = read_raw_frame(&mut peer_io).await;
            if frame.kind == 4 && frame.flags & 1 != 0 {
                settings_acks += 1;
            }
            assert_ne!(frame.kind, 2, "peer-disabled PRIORITY frame was sent");
            if frame.kind == 1 {
                break frame;
            }
        };
        assert_eq!(settings_acks, 0, "seeded settings were acknowledged");
        assert_eq!(
            headers.flags & 0x20,
            0,
            "HEADERS retained RFC 7540 priority"
        );
        assert_eq!(
            headers.payload.first(),
            Some(&0x20),
            "seeded header-table limit was not applied to HPACK"
        );

        write_raw_frame(&mut peer_io, 4, 0, 0, &[]).await;
        let ack = read_raw_frame(&mut peer_io).await;
        assert_eq!((ack.kind, ack.flags, ack.stream_id), (4, 1, 0));
        assert!(ack.payload.is_empty());
        driver.abort();
    })
    .await
    .expect("seeded-settings wire test timed out");
}

#[tokio::test]
async fn seed_controls_whether_a_non_settings_first_peer_frame_is_valid() {
    timeout(Duration::from_secs(2), async {
        let (client_io, mut peer_io) = duplex(16 * 1024);
        let (_sender, connection) = super::handshake(client_io)
            .await
            .expect("client handshake failed");
        read_client_preface(&mut peer_io).await;
        write_raw_frame(&mut peer_io, 6, 0, 0, &[0; 8]).await;
        let error = connection
            .await
            .expect_err("non-SETTINGS first peer frame was accepted without a seed");
        assert_eq!(error.reason(), Some(crate::Reason::PROTOCOL_ERROR));

        let (client_io, mut peer_io) = duplex(16 * 1024);
        let mut builder = super::Builder::new();
        builder.initial_peer_settings(Settings::default());
        let (_sender, connection) = builder
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);
        read_client_preface(&mut peer_io).await;
        let client_settings = read_raw_frame(&mut peer_io).await;
        assert_eq!(
            (client_settings.kind, client_settings.flags),
            (4, 0),
            "client preface omitted its initial SETTINGS"
        );
        write_raw_frame(&mut peer_io, 6, 0, 0, &[0; 8]).await;
        let pong = read_raw_frame(&mut peer_io).await;
        assert_eq!((pong.kind, pong.flags, pong.stream_id), (6, 1, 0));
        assert_eq!(pong.payload, [0; 8]);
        driver.abort();
    })
    .await
    .expect("initial peer frame test timed out");
}

#[tokio::test]
async fn seeded_sticky_settings_reject_later_disable() {
    timeout(Duration::from_secs(2), async {
        for setting_id in [8, 9] {
            let (client_io, mut peer_io) = duplex(16 * 1024);
            let mut peer_settings = Settings::default();
            if setting_id == 8 {
                peer_settings.set_enable_connect_protocol(Some(1));
            } else {
                peer_settings.set_no_rfc7540_priorities(true);
            }
            let mut builder = super::Builder::new();
            builder.initial_peer_settings(peer_settings);
            let (sender, connection) = builder
                .handshake::<_, Bytes>(client_io)
                .await
                .expect("client handshake failed");
            let driver = tokio::spawn(connection);
            read_client_preface(&mut peer_io).await;
            let initial = read_raw_frame(&mut peer_io).await;
            assert_eq!((initial.kind, initial.flags), (4, 0));
            if setting_id == 8 {
                assert!(sender.is_extended_connect_protocol_enabled());
            }

            write_raw_frame(&mut peer_io, 4, 0, 0, &settings_payload(&[(setting_id, 1)])).await;
            let ack = read_raw_frame(&mut peer_io).await;
            assert_eq!((ack.kind, ack.flags, ack.stream_id), (4, 1, 0));

            write_raw_frame(&mut peer_io, 4, 0, 0, &settings_payload(&[(setting_id, 0)])).await;
            let error = driver
                .await
                .expect("client driver task panicked")
                .expect_err("peer disabled a sticky seeded setting");
            assert_eq!(error.reason(), Some(crate::Reason::PROTOCOL_ERROR));
        }
    })
    .await
    .expect("seeded sticky-settings test timed out");
}

#[tokio::test]
async fn wire_settings_transitions_remain_sticky() {
    timeout(Duration::from_secs(2), async {
        let (client_io, mut peer_io) = duplex(16 * 1024);
        let (sender, connection) = super::handshake(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);
        read_client_preface(&mut peer_io).await;
        let initial = read_raw_frame(&mut peer_io).await;
        assert_eq!((initial.kind, initial.flags), (4, 0));

        write_raw_frame(&mut peer_io, 4, 0, 0, &settings_payload(&[(8, 0), (9, 0)])).await;
        assert_eq!(read_raw_frame(&mut peer_io).await.flags, 1);
        assert!(!sender.is_extended_connect_protocol_enabled());

        write_raw_frame(&mut peer_io, 4, 0, 0, &settings_payload(&[(8, 1), (9, 0)])).await;
        assert_eq!(read_raw_frame(&mut peer_io).await.flags, 1);
        assert!(sender.is_extended_connect_protocol_enabled());

        write_raw_frame(&mut peer_io, 4, 0, 0, &settings_payload(&[(8, 0)])).await;
        let error = driver
            .await
            .expect("client driver task panicked")
            .expect_err("peer disabled extended CONNECT after enabling it");
        assert_eq!(error.reason(), Some(crate::Reason::PROTOCOL_ERROR));

        let (client_io, mut peer_io) = duplex(16 * 1024);
        let (_sender, connection) = super::handshake(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);
        read_client_preface(&mut peer_io).await;
        let _initial = read_raw_frame(&mut peer_io).await;
        write_raw_frame(&mut peer_io, 4, 0, 0, &settings_payload(&[(9, 0)])).await;
        assert_eq!(read_raw_frame(&mut peer_io).await.flags, 1);
        write_raw_frame(&mut peer_io, 4, 0, 0, &settings_payload(&[(9, 1)])).await;
        let error = driver
            .await
            .expect("client driver task panicked")
            .expect_err("peer changed SETTINGS_NO_RFC7540_PRIORITIES");
        assert_eq!(error.reason(), Some(crate::Reason::PROTOCOL_ERROR));
    })
    .await
    .expect("wire sticky-settings test timed out");
}

#[tokio::test]
async fn client_rejects_server_enable_push_one_but_accepts_zero() {
    timeout(Duration::from_secs(2), async {
        for (value, accepted) in [(0, true), (1, false)] {
            let (client_io, mut peer_io) = duplex(16 * 1024);
            let (_sender, connection) = super::handshake(client_io)
                .await
                .expect("client handshake failed");
            let driver = tokio::spawn(connection);
            read_client_preface(&mut peer_io).await;
            let _initial = read_raw_frame(&mut peer_io).await;
            write_raw_frame(&mut peer_io, 4, 0, 0, &settings_payload(&[(2, value)])).await;

            if accepted {
                let ack = read_raw_frame(&mut peer_io).await;
                assert_eq!((ack.kind, ack.flags, ack.stream_id), (4, 1, 0));
                driver.abort();
            } else {
                let error = driver
                    .await
                    .expect("client driver task panicked")
                    .expect_err("server SETTINGS_ENABLE_PUSH = 1 was accepted");
                assert_eq!(error.reason(), Some(crate::Reason::PROTOCOL_ERROR));
            }
        }
    })
    .await
    .expect("server ENABLE_PUSH settings test timed out");
}

// Ported from hyperium/h2 #940 (`c12d782`, tests/h2-tests/tests/stream_states.rs)
// with a raw-frame peer in place of upstream's mock. Under the default 65,535
// connection window the budget is 32,767 bytes and each one-byte DATA frame
// that is charged costs 255, so 200 streams exhaust it unless final frames are
// exempt and dropping a body releases its buffered charges.
#[tokio::test]
async fn many_small_final_data_frames_do_not_exhaust_budget() {
    const NUM_STREAMS: u32 = 200;

    timeout(Duration::from_secs(5), async {
        let (client_io, mut peer) = duplex(64 * 1024);
        let (mut client, connection) = super::handshake(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);
        accept_client_handshake(&mut peer).await;

        let requests = tokio::spawn(async move {
            let mut responses = Vec::new();
            for _ in 0..NUM_STREAMS {
                poll_fn(|cx| client.poll_ready(cx))
                    .await
                    .expect("sender never became ready");
                responses.push(
                    client
                        .send_request(data_budget_request(), true)
                        .expect("request was rejected")
                        .0,
                );
            }

            // Wait for every response without polling any response body. This
            // ensures all final DATA frames can be buffered concurrently.
            let mut received = Vec::new();
            for response in responses {
                received.push(response.await.expect("response headers failed"));
            }
            (client, received)
        });

        for i in 0..NUM_STREAMS {
            read_request_headers(&mut peer, 1 + i * 2).await;
        }
        for i in 0..NUM_STREAMS {
            let stream_id = 1 + i * 2;
            // HEADERS with END_HEADERS and indexed `:status: 200`.
            write_raw_frame(&mut peer, 1, 0x4, stream_id, &[0x88]).await;
            write_raw_frame(&mut peer, 0, 0x1, stream_id, b"a").await;
        }

        // Keep the sender and bodies alive so the connection cannot idle-close
        // before the liveness check.
        let (_client, received) = requests.await.expect("request task panicked");
        assert_eq!(received.len(), NUM_STREAMS as usize);
        assert_connection_open(&mut peer).await;
        driver.abort();
    })
    .await
    .expect("final DATA frame budget test timed out");
}

#[tokio::test]
async fn dropping_buffered_data_frames_releases_budget() {
    const NUM_STREAMS: u32 = 200;

    timeout(Duration::from_secs(5), async {
        let (client_io, mut peer) = duplex(64 * 1024);
        let (mut client, connection) = super::handshake(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);
        accept_client_handshake(&mut peer).await;

        let requests = tokio::spawn(async move {
            for _ in 0..NUM_STREAMS {
                poll_fn(|cx| client.poll_ready(cx))
                    .await
                    .expect("sender never became ready");
                let response = client
                    .send_request(data_budget_request(), true)
                    .expect("request was rejected")
                    .0
                    .await
                    .expect("response headers failed");
                assert_eq!(response.status(), StatusCode::CONFLICT);

                let mut body = response.into_body();
                while body.flow_control().used_capacity() < 2 {
                    tokio::task::yield_now().await;
                }
                drop(body);
            }
            client
        });

        for i in 0..NUM_STREAMS {
            let stream_id = 1 + i * 2;
            read_request_headers(&mut peer, stream_id).await;
            // HEADERS with END_HEADERS and `:status: 409` as a literal
            // without indexing that names static-table entry 8.
            write_raw_frame(
                &mut peer,
                1,
                0x4,
                stream_id,
                &[0x08, 0x03, b'4', b'0', b'9'],
            )
            .await;
            write_raw_frame(&mut peer, 0, 0, stream_id, b"a").await;
            write_raw_frame(&mut peer, 0, 0x1, stream_id, b"b").await;
        }

        // Keep the sender alive so the connection cannot idle-close before
        // the liveness check.
        let _client = requests.await.expect("request task panicked");
        assert_connection_open(&mut peer).await;
        driver.abort();
    })
    .await
    .expect("dropped DATA frame budget test timed out");
}

#[tokio::test]
async fn retained_initial_stream_limit_holds_until_the_peer_states_one() {
    timeout(Duration::from_secs(5), async {
        let (mut peer, mut sender, _responses, driver) = limited_client(2, true).await;
        read_request_headers(&mut peer, 1).await;
        read_request_headers(&mut peer, 3).await;
        assert_eq!(sender.current_max_send_streams(), 2);

        // Initial SETTINGS without SETTINGS_MAX_CONCURRENT_STREAMS. A request
        // opened before them would arrive before their ACK.
        write_raw_frame(&mut peer, 4, 0, 0, &[]).await;
        read_settings_ack(&mut peer).await;
        assert_eq!(sender.current_max_send_streams(), 2);
        assert_no_request_before_ping_ack(&mut peer).await;

        write_raw_frame(&mut peer, 4, 0, 0, &settings_payload(&[(3, 3)])).await;
        read_request_headers(&mut peer, 5).await;
        assert_eq!(sender.current_max_send_streams(), 3);
        poll_fn(|cx| sender.poll_ready(cx))
            .await
            .expect("sender never became ready");
        driver.abort();
    })
    .await
    .expect("retained stream limit test timed out");
}

#[tokio::test]
async fn retained_initial_stream_limit_holds_through_a_seed_without_a_limit() {
    timeout(Duration::from_secs(5), async {
        let (client_io, mut peer) = duplex(64 * 1024);
        let mut builder = super::Builder::new();
        builder
            .initial_max_send_streams(2)
            .retain_initial_max_send_streams(true)
            .initial_peer_settings(Settings::default());
        let (mut sender, connection) = builder
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);
        let mut responses = Vec::new();
        for _ in 0..3 {
            let (response, _) = sender
                .send_request(data_budget_request(), true)
                .expect("request was rejected");
            responses.push(response);
        }
        read_client_preface(&mut peer).await;
        read_request_headers(&mut peer, 1).await;
        read_request_headers(&mut peer, 3).await;
        // The seed counts as the initial SETTINGS, so a PING may come first.
        assert_no_request_before_ping_ack(&mut peer).await;
        assert_eq!(sender.current_max_send_streams(), 2);

        write_raw_frame(&mut peer, 4, 0, 0, &settings_payload(&[(3, 3)])).await;
        read_request_headers(&mut peer, 5).await;
        assert_eq!(sender.current_max_send_streams(), 3);
        driver.abort();
    })
    .await
    .expect("seeded stream limit test timed out");
}

#[tokio::test]
async fn initial_stream_limit_is_lifted_by_settings_without_a_limit_by_default() {
    timeout(Duration::from_secs(5), async {
        let (mut peer, sender, _responses, driver) = limited_client(2, false).await;
        read_request_headers(&mut peer, 1).await;
        read_request_headers(&mut peer, 3).await;
        assert_eq!(sender.current_max_send_streams(), 2);

        // The third request opens only once the peer's SETTINGS lift the
        // limit, so it follows their ACK.
        write_raw_frame(&mut peer, 4, 0, 0, &[]).await;
        read_settings_ack(&mut peer).await;
        read_request_headers(&mut peer, 5).await;
        assert_eq!(sender.current_max_send_streams(), usize::MAX);
        driver.abort();
    })
    .await
    .expect("default stream limit test timed out");
}

#[tokio::test]
async fn initial_stream_id_numbers_requests_from_it() {
    timeout(Duration::from_secs(5), async {
        let (client_io, mut peer) = duplex(64 * 1024);
        let mut builder = super::Builder::new();
        builder.initial_stream_id(3);
        let (mut sender, connection) = builder
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);
        accept_client_handshake(&mut peer).await;
        let mut responses = Vec::new();
        for stream_id in [3, 5, 7] {
            poll_fn(|cx| sender.poll_ready(cx))
                .await
                .expect("sender never became ready");
            let (response, _) = sender
                .send_request(data_budget_request(), true)
                .expect("request was rejected");
            responses.push(response);
            read_request_headers(&mut peer, stream_id).await;
        }
        driver.abort();
    })
    .await
    .expect("initial stream id test timed out");
}

#[tokio::test]
async fn stated_stream_limit_is_lowered_to_the_cap() {
    timeout(Duration::from_secs(5), async {
        let (client_io, mut peer) = duplex(64 * 1024);
        let mut builder = super::Builder::new();
        builder.max_send_streams_cap(2);
        let (mut sender, connection) = builder
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);
        read_client_preface(&mut peer).await;
        let initial = read_raw_frame(&mut peer).await;
        assert_eq!((initial.kind, initial.flags), (4, 0));
        write_raw_frame(&mut peer, 4, 0, 0, &settings_payload(&[(3, 1000)])).await;
        read_settings_ack(&mut peer).await;
        assert_eq!(sender.current_max_send_streams(), 2);

        let mut responses = Vec::new();
        for _ in 0..3 {
            let (response, _) = sender
                .send_request(data_budget_request(), true)
                .expect("request was rejected");
            responses.push(response);
        }
        read_request_headers(&mut peer, 1).await;
        read_request_headers(&mut peer, 3).await;
        assert_no_request_before_ping_ack(&mut peer).await;

        // A stated value under the cap applies unchanged.
        write_raw_frame(&mut peer, 4, 0, 0, &settings_payload(&[(3, 1)])).await;
        read_settings_ack(&mut peer).await;
        assert_eq!(sender.current_max_send_streams(), 1);
        driver.abort();
    })
    .await
    .expect("stream limit cap test timed out");
}

const PREFACE_IDLE: Duration = Duration::from_millis(250);
const PAST_PREFACE_IDLE: Duration = Duration::from_millis(400);

#[tokio::test]
async fn preface_ping_follows_request_headers_only_after_read_idle() {
    timeout(Duration::from_secs(5), async {
        let (mut peer, mut sender, driver) = preface_ping_client().await;
        let mut responses = Vec::new();

        responses.push(send_empty_request(&mut sender).await);
        let (headers, ping) = read_request_frame(&mut peer).await;
        assert_eq!((headers.kind, headers.stream_id, ping), (1, 1, None));

        tokio::time::sleep(PAST_PREFACE_IDLE).await;
        responses.push(send_empty_request(&mut sender).await);
        let (headers, ping) = read_request_frame(&mut peer).await;
        assert_eq!((headers.kind, headers.stream_id), (1, 3));
        assert_eq!(ping, Some(1_u64.to_be_bytes()));
        write_raw_frame(&mut peer, 6, 1, 0, &1_u64.to_be_bytes()).await;

        // Reading the ACK restarts the idle time.
        responses.push(send_empty_request(&mut sender).await);
        let (headers, ping) = read_request_frame(&mut peer).await;
        assert_eq!((headers.kind, headers.stream_id, ping), (1, 5, None));

        tokio::time::sleep(PAST_PREFACE_IDLE).await;
        responses.push(send_empty_request(&mut sender).await);
        let (headers, ping) = read_request_frame(&mut peer).await;
        assert_eq!((headers.kind, headers.stream_id), (1, 7));
        assert_eq!(ping, Some(2_u64.to_be_bytes()));
        driver.abort();
    })
    .await
    .expect("preface PING test timed out");
}

#[tokio::test]
async fn preface_ping_is_not_repeated_while_one_awaits_its_ack() {
    timeout(Duration::from_secs(5), async {
        let (mut peer, mut sender, driver) = preface_ping_client().await;
        let mut responses = Vec::new();
        tokio::time::sleep(PAST_PREFACE_IDLE).await;
        responses.push(send_empty_request(&mut sender).await);
        let (_, ping) = read_request_frame(&mut peer).await;
        assert_eq!(ping, Some(1_u64.to_be_bytes()));

        tokio::time::sleep(PAST_PREFACE_IDLE).await;
        responses.push(send_empty_request(&mut sender).await);
        let (headers, ping) = read_request_frame(&mut peer).await;
        assert_eq!((headers.kind, headers.stream_id, ping), (1, 3, None));
        driver.abort();
    })
    .await
    .expect("preface PING in flight test timed out");
}

#[tokio::test]
async fn preface_ping_follows_non_empty_request_data_after_read_idle() {
    timeout(Duration::from_secs(5), async {
        let (mut peer, mut sender, driver) = preface_ping_client().await;
        poll_fn(|cx| sender.poll_ready(cx))
            .await
            .expect("sender never became ready");
        let (_response, mut body) = sender
            .send_request(data_budget_request(), false)
            .expect("request was rejected");
        let (headers, ping) = read_request_frame(&mut peer).await;
        assert_eq!((headers.kind, ping), (1, None));

        // Large enough for the codec to write the payload after the frame
        // head, so the PING must wait for the whole frame.
        let chunk = Bytes::from(vec![0x61; 4096]);
        tokio::time::sleep(PAST_PREFACE_IDLE).await;
        body.send_data(chunk.clone(), false)
            .expect("data was rejected");
        let (data, ping) = read_request_frame(&mut peer).await;
        assert_eq!((data.kind, data.payload.as_slice()), (0, &chunk[..]));
        assert_eq!(ping, Some(1_u64.to_be_bytes()));
        write_raw_frame(&mut peer, 6, 1, 0, &1_u64.to_be_bytes()).await;

        // An empty DATA frame owes no PING.
        tokio::time::sleep(PAST_PREFACE_IDLE).await;
        body.send_data(Bytes::new(), true)
            .expect("end of stream was rejected");
        let (data, ping) = read_request_frame(&mut peer).await;
        assert_eq!((data.kind, data.flags, ping), (0, 1, None));
        driver.abort();
    })
    .await
    .expect("preface PING after DATA test timed out");
}

/// Opens a client that sends a preface PING after `PREFACE_IDLE` without a
/// read, and completes the peer side of its handshake.
async fn preface_ping_client() -> (
    DuplexStream,
    super::SendRequest<Bytes>,
    tokio::task::JoinHandle<Result<(), crate::Error>>,
) {
    let (client_io, mut peer) = duplex(64 * 1024);
    let mut builder = super::Builder::new();
    builder.preface_ping(PREFACE_IDLE);
    let (sender, connection) = builder
        .handshake::<_, Bytes>(client_io)
        .await
        .expect("client handshake failed");
    let driver = tokio::spawn(connection);
    accept_client_handshake(&mut peer).await;
    (peer, sender, driver)
}

async fn send_empty_request(sender: &mut super::SendRequest<Bytes>) -> super::ResponseFuture {
    poll_fn(|cx| sender.poll_ready(cx))
        .await
        .expect("sender never became ready");
    sender
        .send_request(data_budget_request(), true)
        .expect("request was rejected")
        .0
}

/// Reads the next HEADERS or DATA frame and the payload of a PING that the
/// client wrote immediately after it, if any.
///
/// A probe PING from the peer bounds the wait: the client writes its own
/// PING together with the request frame, so it arrives before the probe's
/// ACK.
async fn read_request_frame(peer: &mut DuplexStream) -> (RawFrame, Option<[u8; 8]>) {
    let request = loop {
        let frame = read_raw_frame(peer).await;
        assert_ne!(frame.kind, 7, "client sent GOAWAY: {:?}", frame.payload);
        assert!(
            frame.kind != 6 || frame.flags & 0x1 != 0,
            "a PING came before the request frame"
        );
        if matches!(frame.kind, 0 | 1) {
            break frame;
        }
    };
    write_raw_frame(peer, 6, 0, 0, b"probe!!!").await;
    let mut ping = None;
    let mut first = true;
    loop {
        let frame = read_raw_frame(peer).await;
        assert_ne!(frame.kind, 7, "client sent GOAWAY: {:?}", frame.payload);
        if frame.kind == 6 && frame.flags & 0x1 != 0 && frame.payload == b"probe!!!" {
            return (request, ping);
        }
        if frame.kind == 6 && frame.flags & 0x1 == 0 {
            assert!(first, "a frame came between the request frame and the PING");
            ping = Some(frame.payload.try_into().expect("PING payload is 8 bytes"));
        }
        first = false;
    }
}

/// Opens a client whose peer has not sent SETTINGS, limited to `limit`
/// streams until then, and sends `limit + 1` requests. The response futures
/// are returned so that no stream is cancelled while the test runs.
async fn limited_client(
    limit: usize,
    retain: bool,
) -> (
    DuplexStream,
    super::SendRequest<Bytes>,
    Vec<super::ResponseFuture>,
    tokio::task::JoinHandle<Result<(), crate::Error>>,
) {
    let (client_io, mut peer) = duplex(64 * 1024);
    let mut builder = super::Builder::new();
    builder
        .initial_max_send_streams(limit)
        .retain_initial_max_send_streams(retain);
    let (mut sender, connection) = builder
        .handshake::<_, Bytes>(client_io)
        .await
        .expect("client handshake failed");
    let driver = tokio::spawn(connection);
    read_client_preface(&mut peer).await;
    let initial = read_raw_frame(&mut peer).await;
    assert_eq!((initial.kind, initial.flags), (4, 0));
    let mut responses = Vec::new();
    for _ in 0..=limit {
        // Only the request past the limit waits to open, so no request
        // needs readiness before it is sent.
        let (response, _) = sender
            .send_request(data_budget_request(), true)
            .expect("request was rejected");
        responses.push(response);
    }
    (peer, sender, responses, driver)
}

/// Sends a PING and fails if a request HEADERS arrives before its ACK.
async fn assert_no_request_before_ping_ack(peer: &mut DuplexStream) {
    write_raw_frame(peer, 6, 0, 0, b"limited!").await;
    loop {
        let frame = read_raw_frame(peer).await;
        assert_ne!(
            frame.kind, 1,
            "stream {} opened past the limit",
            frame.stream_id
        );
        assert_ne!(frame.kind, 7, "client sent GOAWAY: {:?}", frame.payload);
        if frame.kind == 6 && frame.flags & 0x1 != 0 {
            assert_eq!(frame.payload, b"limited!");
            return;
        }
    }
}

/// Reads frames until the client acknowledges the peer's SETTINGS.
async fn read_settings_ack(peer: &mut DuplexStream) {
    loop {
        let frame = read_raw_frame(peer).await;
        assert_ne!(
            frame.kind, 1,
            "stream {} opened past the limit",
            frame.stream_id
        );
        if (frame.kind, frame.flags) == (4, 1) {
            return;
        }
    }
}

fn data_budget_request() -> Request<()> {
    Request::builder()
        .uri("https://http2.akamai.com/")
        .body(())
        .expect("static request must build")
}

/// Completes the peer side of the handshake with empty SETTINGS.
async fn accept_client_handshake(peer: &mut DuplexStream) {
    read_client_preface(peer).await;
    let initial = read_raw_frame(peer).await;
    assert_eq!((initial.kind, initial.flags), (4, 0));
    write_raw_frame(peer, 4, 0, 0, &[]).await;
    write_raw_frame(peer, 4, 1, 0, &[]).await;
}

/// Skips connection-level frames until the request HEADERS for `stream_id`.
async fn read_request_headers(peer: &mut DuplexStream, stream_id: u32) {
    loop {
        let frame = read_raw_frame(peer).await;
        assert_ne!(frame.kind, 7, "client sent GOAWAY: {:?}", frame.payload);
        if frame.kind == 1 {
            assert_eq!(frame.stream_id, stream_id);
            assert_eq!(frame.flags & 0x5, 0x5, "request must be one complete block");
            return;
        }
    }
}

/// Proves the client still answers PING and has not sent GOAWAY.
async fn assert_connection_open(peer: &mut DuplexStream) {
    write_raw_frame(peer, 6, 0, 0, b"budget!!").await;
    loop {
        let frame = read_raw_frame(peer).await;
        assert_ne!(frame.kind, 7, "client sent GOAWAY: {:?}", frame.payload);
        if frame.kind == 6 && frame.flags & 0x1 != 0 {
            assert_eq!(frame.payload, b"budget!!");
            return;
        }
    }
}

struct RawFrame {
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: Vec<u8>,
}

async fn read_client_preface(peer: &mut DuplexStream) {
    let mut preface = [0_u8; 24];
    peer.read_exact(&mut preface)
        .await
        .expect("client preface was truncated");
    assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
}

async fn read_raw_frame(peer: &mut DuplexStream) -> RawFrame {
    let mut head = [0_u8; 9];
    peer.read_exact(&mut head)
        .await
        .expect("frame header was truncated");
    let length = (usize::from(head[0]) << 16) | (usize::from(head[1]) << 8) | usize::from(head[2]);
    let mut payload = vec![0_u8; length];
    peer.read_exact(&mut payload)
        .await
        .expect("frame payload was truncated");
    RawFrame {
        kind: head[3],
        flags: head[4],
        stream_id: u32::from_be_bytes([head[5], head[6], head[7], head[8]]) & 0x7fff_ffff,
        payload,
    }
}

async fn write_raw_frame(
    peer: &mut DuplexStream,
    kind: u8,
    flags: u8,
    stream_id: u32,
    payload: &[u8],
) {
    let length = payload.len();
    assert!(length <= 0x00ff_ffff);
    let mut head = [0_u8; 9];
    head[0] = ((length >> 16) & 0xff) as u8;
    head[1] = ((length >> 8) & 0xff) as u8;
    head[2] = (length & 0xff) as u8;
    head[3] = kind;
    head[4] = flags;
    head[5..].copy_from_slice(&(stream_id & 0x7fff_ffff).to_be_bytes());
    peer.write_all(&head)
        .await
        .expect("frame head write failed");
    peer.write_all(payload)
        .await
        .expect("frame payload write failed");
}

fn settings_payload(settings: &[(u16, u32)]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(settings.len() * 6);
    for (id, value) in settings {
        payload.extend_from_slice(&id.to_be_bytes());
        payload.extend_from_slice(&value.to_be_bytes());
    }
    payload
}

fn request_with_headers() -> Request<()> {
    let mut request = Request::new(());
    *request.method_mut() = Method::GET;
    *request.uri_mut() = "https://example.test/resource"
        .parse()
        .expect("static request URI must parse");
    *request.version_mut() = Version::HTTP_2;
    request
        .headers_mut()
        .append(A, HeaderValue::from_static("a1"));
    request
        .headers_mut()
        .append(B, HeaderValue::from_static("b1"));
    request
        .headers_mut()
        .append(A, HeaderValue::from_static("a2"));
    request
}

fn convert(request: Request<()>) -> Result<Headers, SendError> {
    Peer::convert_send_message(StreamId::from(1), request, None, true, None, None)
}

fn decode_ordinary_fields(headers: Headers) -> Vec<(HeaderName, HeaderValue)> {
    let mut encoder = Encoder::default();
    let mut encoded = BytesMut::new();
    let continuation = headers.encode(&mut encoder, &mut (&mut encoded).limit(16 * 1024));
    assert!(continuation.is_none(), "test header block was fragmented");

    let mut payload = BytesMut::from(&encoded[9..]);
    let mut cursor = Cursor::new(&mut payload);
    let mut decoder = Decoder::new(4096);
    let mut fields = Vec::new();
    decoder
        .decode(&mut cursor, |header| {
            if let Header::Field { name, value } = header {
                fields.push((name, value));
            }
            ControlFlow::Continue(())
        })
        .expect("encoded header block must decode");
    fields
}

fn decode_header_block(encoded: &[u8]) -> Vec<(HeaderName, HeaderValue)> {
    let mut decoder = Decoder::new(4096);
    decode_header_block_with(&mut decoder, encoded)
}

fn decode_header_block_with(
    decoder: &mut Decoder,
    encoded: &[u8],
) -> Vec<(HeaderName, HeaderValue)> {
    let mut payload = BytesMut::from(encoded);
    let mut cursor = Cursor::new(&mut payload);
    let mut fields = Vec::new();
    decoder
        .decode(&mut cursor, |header| {
            if let Header::Field { name, value } = header {
                fields.push((name, value));
            }
            ControlFlow::Continue(())
        })
        .expect("encoded header block must decode");
    fields
}

fn decode_pseudo_names(decoder: &mut Decoder, encoded: &[u8]) -> Vec<&'static str> {
    let mut payload = BytesMut::from(encoded);
    let mut cursor = Cursor::new(&mut payload);
    let mut names = Vec::new();
    decoder
        .decode(&mut cursor, |header| {
            let name = match header {
                Header::Method(_) => ":method",
                Header::Authority(_) => ":authority",
                Header::Scheme(_) => ":scheme",
                Header::Path(_) => ":path",
                Header::Protocol(_) => ":protocol",
                Header::Status(_) => ":status",
                Header::Field { .. } => return ControlFlow::Continue(()),
            };
            names.push(name);
            ControlFlow::Continue(())
        })
        .expect("encoded header block must decode");
    names
}

struct PendingShutdownIo {
    shutdown_polls: Arc<AtomicUsize>,
}

struct PendingWriteIo {
    write_polls: Arc<AtomicUsize>,
    preface_written: bool,
}

impl AsyncRead for PendingWriteIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for PendingWriteIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if !self.preface_written {
            self.preface_written = true;
            return Poll::Ready(Ok(buf.len()));
        }
        self.write_polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncRead for PendingShutdownIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for PendingShutdownIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.shutdown_polls.fetch_add(1, Ordering::SeqCst);
        Poll::Pending
    }
}

struct CountWake(Arc<AtomicUsize>);

impl Wake for CountWake {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

const ALTSVC: u8 = 10;
const ORIGIN: &[u8] = b"https://example.test";

#[tokio::test]
async fn client_surfaces_stream_zero_altsvc_frame_with_origin() {
    let exchange = response_after_altsvc(&[
        (0, altsvc_payload(ORIGIN, b"h3=\":443\"")),
        (1, altsvc_payload(b"", b"h3=\":8443\"")),
    ])
    .await;
    let frames = exchange
        .response
        .extensions()
        .get::<crate::ext::AltSvcFrames>()
        .expect("ALTSVC frames were not attached to the response");
    let observed: Vec<_> = frames
        .as_slice()
        .iter()
        .map(|frame| (frame.origin(), frame.field_value()))
        .collect();
    assert_eq!(
        observed,
        [
            (Some(ORIGIN), b"h3=\":443\"".as_slice()),
            (None, b"h3=\":8443\"".as_slice()),
        ]
    );
    exchange.driver.abort();
}

#[tokio::test]
async fn client_ignores_stream_zero_altsvc_frame_without_origin() {
    let exchange = response_after_altsvc(&[(0, altsvc_payload(b"", b"h3=\":443\""))]).await;
    assert!(exchange
        .response
        .extensions()
        .get::<crate::ext::AltSvcFrames>()
        .is_none());
    exchange.driver.abort();
}

#[tokio::test]
async fn client_ignores_request_stream_altsvc_frame_with_origin() {
    let exchange = response_after_altsvc(&[(1, altsvc_payload(ORIGIN, b"h3=\":443\""))]).await;
    assert!(exchange
        .response
        .extensions()
        .get::<crate::ext::AltSvcFrames>()
        .is_none());
    exchange.driver.abort();
}

#[tokio::test]
async fn truncated_altsvc_origin_length_is_ignored_without_connection_error() {
    let oversized_value = vec![b'a'; 16 * 1024 + 1];
    let mut exchange = response_after_altsvc(&[
        (0, vec![0]),
        (0, vec![0, 10, b'x']),
        (0, altsvc_payload(ORIGIN, &oversized_value)),
    ])
    .await;
    assert_eq!(exchange.response.status(), 200);
    assert!(exchange
        .response
        .extensions()
        .get::<crate::ext::AltSvcFrames>()
        .is_none());

    write_raw_frame(&mut exchange.peer, 6, 0, 0, &[7; 8]).await;
    loop {
        let frame = read_raw_frame(&mut exchange.peer).await;
        assert_ne!(frame.kind, 7, "client sent GOAWAY after malformed ALTSVC");
        if frame.kind == 6 && frame.flags == 1 {
            assert_eq!(frame.payload, [7; 8]);
            break;
        }
    }
    assert!(!exchange.driver.is_finished());
    exchange.driver.abort();
}

#[tokio::test]
async fn altsvc_frame_queue_is_bounded_and_drops_oldest() {
    let frames: Vec<_> = (0..20)
        .map(|index| (0, altsvc_payload(ORIGIN, format!("v{index}").as_bytes())))
        .collect();
    let exchange = response_after_altsvc(&frames).await;
    let delivered: Vec<_> = exchange
        .response
        .extensions()
        .get::<crate::ext::AltSvcFrames>()
        .expect("ALTSVC frames were not attached to the response")
        .as_slice()
        .iter()
        .map(|frame| frame.field_value().to_vec())
        .collect();
    let expected: Vec<_> = (4..20)
        .map(|index| format!("v{index}").into_bytes())
        .collect();
    assert_eq!(delivered, expected);
    exchange.driver.abort();
}

#[tokio::test]
async fn server_ignores_altsvc_frames() {
    timeout(Duration::from_secs(2), async {
        let (server_io, mut peer) = duplex(16 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = crate::server::handshake(server_io)
                .await
                .expect("server handshake failed");
            let (request, mut respond) = connection
                .accept()
                .await
                .expect("connection closed before request")
                .expect("request failed");
            assert!(request
                .extensions()
                .get::<crate::ext::AltSvcFrames>()
                .is_none());
            respond
                .send_response(Response::new(()), true)
                .expect("response headers failed");
            poll_fn(|cx| connection.poll_closed(cx))
                .await
                .expect("server connection failed after ALTSVC");
        });

        peer.write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .expect("preface write failed");
        write_raw_frame(&mut peer, 4, 0, 0, &[]).await;
        write_raw_frame(
            &mut peer,
            ALTSVC,
            0,
            0,
            &altsvc_payload(ORIGIN, b"h3=\":443\""),
        )
        .await;
        // :method GET, :scheme https, :path /, :authority example.test
        let mut block = vec![0x82, 0x87, 0x84, 0x01, 12];
        block.extend_from_slice(b"example.test");
        write_raw_frame(&mut peer, 1, 0x5, 1, &block).await;
        loop {
            let frame = read_raw_frame(&mut peer).await;
            assert_ne!(frame.kind, 7, "server sent GOAWAY after ALTSVC");
            if frame.kind == 1 && frame.stream_id == 1 {
                break;
            }
        }
        drop(peer);
        server.await.expect("server task panicked");
    })
    .await
    .expect("server ALTSVC test timed out");
}

struct AltSvcExchange {
    response: Response<crate::RecvStream>,
    driver: tokio::task::JoinHandle<Result<(), crate::Error>>,
    peer: DuplexStream,
}

/// Opens stream 1, then sends SETTINGS, the ALTSVC frames, and a 200 response.
async fn response_after_altsvc(frames: &[(u32, Vec<u8>)]) -> AltSvcExchange {
    timeout(Duration::from_secs(2), async {
        let (client_io, mut peer) = duplex(64 * 1024);
        // Accept frames larger than the ALTSVC part bound so that bound, not
        // the frame-size limit, decides whether an oversized frame is kept.
        let (sender, connection) = super::Builder::new()
            .max_frame_size(64 * 1024)
            .handshake::<_, Bytes>(client_io)
            .await
            .expect("client handshake failed");
        let driver = tokio::spawn(connection);
        read_client_preface(&mut peer).await;
        write_raw_frame(&mut peer, 4, 0, 0, &[]).await;

        let mut sender = sender.ready().await.expect("sender never became ready");
        let (response, _send) = sender
            .send_request(request_with_headers(), true)
            .expect("request was rejected");
        while read_raw_frame(&mut peer).await.kind != 1 {}

        for (stream_id, payload) in frames {
            write_raw_frame(&mut peer, ALTSVC, 0, *stream_id, payload).await;
        }
        // HEADERS with END_STREAM | END_HEADERS and indexed `:status: 200`.
        write_raw_frame(&mut peer, 1, 0x5, 1, &[0x88]).await;
        let response = response.await.expect("response headers failed");
        AltSvcExchange {
            response,
            driver,
            peer,
        }
    })
    .await
    .expect("ALTSVC exchange timed out")
}

fn altsvc_payload(origin: &[u8], value: &[u8]) -> Vec<u8> {
    let length = u16::try_from(origin.len()).expect("test origin fits Origin-Len");
    let mut payload = length.to_be_bytes().to_vec();
    payload.extend_from_slice(origin);
    payload.extend_from_slice(value);
    payload
}

async fn informational_limit_outcome(
    sent: usize,
) -> Result<Response<crate::RecvStream>, crate::Error> {
    let (client_io, server_io) = duplex(16 * 1024);
    let server = tokio::spawn(async move {
        let mut connection = crate::server::handshake(server_io)
            .await
            .expect("server handshake failed");
        let (_request, mut respond) = connection
            .accept()
            .await
            .expect("connection closed before request")
            .expect("request failed");
        for _ in 0..sent {
            respond
                .send_informational(Response::builder().status(103).body(()).unwrap())
                .expect("informational response failed");
        }
        // The client may already have reset the stream; only its outcome matters.
        let _ = respond.send_response(Response::new(()), true);
        let _ = poll_fn(|cx| connection.poll_closed(cx)).await;
    });

    let mut builder = super::Builder::new();
    builder.max_informational_responses(2);
    let (sender, connection) = builder
        .handshake::<_, Bytes>(client_io)
        .await
        .expect("client handshake failed");
    let driver = tokio::spawn(connection);
    let mut sender = sender.ready().await.expect("sender never became ready");
    let (response, _send) = sender
        .send_request(request_with_headers(), true)
        .expect("request was rejected");
    let outcome = response.await;
    driver.abort();
    server.abort();
    outcome
}

#[tokio::test]
async fn informational_responses_up_to_the_limit_are_accepted() {
    timeout(Duration::from_secs(2), async {
        let response = informational_limit_outcome(2)
            .await
            .expect("final response after two informational responses failed");
        assert_eq!(response.status(), 200);
    })
    .await
    .expect("informational limit test timed out");
}

#[tokio::test]
async fn informational_response_over_the_limit_resets_with_typed_error() {
    timeout(Duration::from_secs(2), async {
        let error = informational_limit_outcome(3)
            .await
            .expect_err("third informational response was accepted");
        assert!(error.is_too_many_informational_responses(), "{error:?}");
        assert!(!error.is_header_list_too_large());
        assert!(error.is_reset() && error.is_library());
        assert_eq!(error.reason(), Some(crate::Reason::ENHANCE_YOUR_CALM));
    })
    .await
    .expect("informational limit test timed out");
}
