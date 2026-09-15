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
use http::{HeaderName, HeaderValue, Method, Request, Response, Version};
use tokio::{
    io::{duplex, AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    time::timeout,
};

use super::Peer;
use crate::{
    codec::{SendError, UserError},
    ext::OrderedHeaders,
    frame::{Headers, StreamId},
    hpack::{Decoder, Encoder, Header},
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
    let mut payload = BytesMut::from(encoded);
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
