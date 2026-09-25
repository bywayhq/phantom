use std::{
    future::Future,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use futures_util::{future, task::noop_waker_ref};
use http::Request;
use tokio::sync::oneshot;

use crate::{
    client,
    proto::headers::Header,
    qpack,
    quic::{self, ConnectionErrorIncoming, StreamErrorIncoming},
};

use super::{h3_quinn, Pair};

const PEER_DYNAMIC_SETTINGS: &[u8] = &[0x00, 0x04, 0x05, 0x01, 0x50, 0x00, 0x07, 0x10];
const PEER_DYNAMIC_APPLICATION_SETTINGS: &[u8] = &[0x04, 0x05, 0x01, 0x50, 0x00, 0x07, 0x10];
const EMPTY_PEER_SETTINGS: &[u8] = &[0x00, 0x04, 0x00];
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn dynamic_request_does_not_open_a_bidi_stream_before_peer_settings() {
    let mut pair = Pair::default();
    let endpoint = pair.server_inner();
    let (client_connection, server_connection) = tokio::join!(pair.client(), async {
        endpoint.accept().await.unwrap().await.unwrap()
    });
    let bidi_polls = Arc::new(AtomicUsize::new(0));
    let observed = ObservedConnection::new(client_connection, Arc::clone(&bidi_polls));

    let mut builder = client::builder();
    builder.send_grease(false).enable_dynamic_qpack(true);
    let (mut driver, mut sender) = builder.build::<_, _, Bytes>(observed).await.unwrap();
    let driver_task =
        tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });

    let request = Request::get("https://localhost/wait").body(()).unwrap();
    let mut request = Box::pin(sender.send_request(request));
    let mut context = Context::from_waker(noop_waker_ref());
    assert!(request.as_mut().poll(&mut context).is_pending());
    assert_eq!(bidi_polls.load(Ordering::Acquire), 0);

    let mut control = server_connection.open_uni().await.unwrap();
    control.write_all(PEER_DYNAMIC_SETTINGS).await.unwrap();

    let mut stream = tokio::time::timeout(TEST_TIMEOUT, request)
        .await
        .expect("request remained blocked after peer SETTINGS")
        .unwrap();
    assert!(bidi_polls.load(Ordering::Acquire) > 0);
    stream.finish().await.unwrap();

    server_connection.close(0_u32.into(), b"test complete");
    drop((control, stream, sender));
    let _ = driver_task.await.unwrap();
}

#[tokio::test]
async fn dynamic_request_uses_peer_application_settings_before_wire_settings() {
    let mut pair = Pair::default();
    let endpoint = pair.server_inner();
    let (client_connection, server_connection) = tokio::join!(pair.client(), async {
        endpoint.accept().await.unwrap().await.unwrap()
    });
    let bidi_polls = Arc::new(AtomicUsize::new(0));
    let observed = ObservedConnection::new(client_connection, Arc::clone(&bidi_polls));

    let mut builder = client::builder();
    builder
        .send_grease(false)
        .enable_dynamic_qpack(true)
        .peer_application_settings(PEER_DYNAMIC_APPLICATION_SETTINGS)
        .unwrap();
    let (mut driver, mut sender) = builder.build::<_, _, Bytes>(observed).await.unwrap();
    let driver_task =
        tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });

    let request = Request::get("https://localhost/alps").body(()).unwrap();
    let mut stream = tokio::time::timeout(TEST_TIMEOUT, sender.send_request(request))
        .await
        .expect("request waited for redundant wire SETTINGS")
        .unwrap();
    assert!(bidi_polls.load(Ordering::Acquire) > 0);
    stream.finish().await.unwrap();

    server_connection.close(0_u32.into(), b"test complete");
    drop((stream, sender));
    let _ = driver_task.await.unwrap();
}

#[tokio::test]
async fn default_request_is_stateless_without_waiting_for_peer_settings() {
    let mut pair = Pair::default();
    let endpoint = pair.server_inner();
    let (client_connection, server_connection) = tokio::join!(pair.client(), async {
        endpoint.accept().await.unwrap().await.unwrap()
    });
    let (captured, captured_rx) = oneshot::channel();

    let server = async move {
        let (_response, mut request) = server_connection.accept_bi().await.unwrap();
        let (frame_type, payload) = read_frame(&mut request).await;
        assert_eq!(frame_type, 0x01);

        let expected = stateless_request_block("https://localhost/default");
        assert_eq!(payload, expected);

        let mut control = server_connection.open_uni().await.unwrap();
        control.write_all(EMPTY_PEER_SETTINGS).await.unwrap();
        captured.send(()).unwrap();
        server_connection.close(0_u32.into(), b"test complete");
        drop(control);
    };

    let client = async move {
        let mut builder = client::builder();
        builder.send_grease(false);
        let (mut driver, mut sender) = builder
            .build::<_, _, Bytes>(client_connection)
            .await
            .unwrap();
        let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let request = async move {
            let mut stream = sender
                .send_request(Request::get("https://localhost/default").body(()).unwrap())
                .await
                .unwrap();
            stream.finish().await.unwrap();
            captured_rx.await.unwrap();
        };
        let ((), _) = tokio::join!(request, drive);
    };

    tokio::time::timeout(TEST_TIMEOUT, async {
        tokio::join!(server, client);
    })
    .await
    .expect("default request waited for peer SETTINGS");
}

#[tokio::test]
async fn dynamic_request_emits_the_encoder_and_field_section_bytes() {
    let mut pair = Pair::default();
    let endpoint = pair.server_inner();
    let (client_connection, server_connection) = tokio::join!(pair.client(), async {
        endpoint.accept().await.unwrap().await.unwrap()
    });
    let (expected_instructions, expected_block) =
        dynamic_request_bytes("https://localhost/dynamic");
    let (captured, captured_rx) = oneshot::channel();

    let server = async move {
        let mut control = server_connection.open_uni().await.unwrap();
        control.write_all(PEER_DYNAMIC_SETTINGS).await.unwrap();

        let mut critical = accept_client_critical_streams(&server_connection).await;
        let mut instructions = vec![0; expected_instructions.len()];
        critical
            .encoder
            .read_exact(&mut instructions)
            .await
            .unwrap();
        assert_eq!(instructions, expected_instructions);

        let (_response, mut request) = server_connection.accept_bi().await.unwrap();
        let (frame_type, payload) = read_frame(&mut request).await;
        assert_eq!(frame_type, 0x01);
        assert_eq!(payload, expected_block);

        captured.send(()).unwrap();
        server_connection.close(0_u32.into(), b"test complete");
        drop((control, critical));
    };

    let client = async move {
        let mut builder = client::builder();
        builder.send_grease(false).enable_dynamic_qpack(true);
        let (mut driver, mut sender) = builder
            .build::<_, _, Bytes>(client_connection)
            .await
            .unwrap();
        let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let request = async move {
            let mut stream = sender
                .send_request(Request::get("https://localhost/dynamic").body(()).unwrap())
                .await
                .unwrap();
            stream.finish().await.unwrap();
            captured_rx.await.unwrap();
        };
        let ((), _) = tokio::join!(request, drive);
    };

    tokio::time::timeout(TEST_TIMEOUT, async {
        tokio::join!(server, client);
    })
    .await
    .expect("dynamic request did not complete");
}

#[tokio::test]
async fn dynamic_request_uses_remembered_settings_before_any_peer_settings() {
    let mut pair = Pair::default();
    let endpoint = pair.server_inner();
    let (client_connection, server_connection) = tokio::join!(pair.client(), async {
        endpoint.accept().await.unwrap().await.unwrap()
    });
    let (expected_instructions, expected_block) =
        dynamic_request_bytes("https://localhost/remembered");
    let (captured, captured_rx) = oneshot::channel();

    // The server sends no SETTINGS, so the encoder can only use the
    // remembered table capacity and blocked-stream limit.
    let server = async move {
        let mut critical = accept_client_critical_streams(&server_connection).await;
        let mut instructions = vec![0; expected_instructions.len()];
        critical
            .encoder
            .read_exact(&mut instructions)
            .await
            .unwrap();
        assert_eq!(instructions, expected_instructions);

        let (_response, mut request) = server_connection.accept_bi().await.unwrap();
        let (frame_type, payload) = read_frame(&mut request).await;
        assert_eq!(frame_type, 0x01);
        assert_eq!(payload, expected_block);

        captured.send(()).unwrap();
        server_connection.close(0_u32.into(), b"test complete");
        drop(critical);
    };

    let client = async move {
        let mut builder = client::builder();
        builder
            .send_grease(false)
            .enable_dynamic_qpack(true)
            .remembered_peer_settings(PEER_DYNAMIC_APPLICATION_SETTINGS)
            .unwrap();
        let (mut driver, mut sender) = builder
            .build::<_, _, Bytes>(client_connection)
            .await
            .unwrap();
        let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let request = async move {
            let mut stream = sender
                .send_request(
                    Request::get("https://localhost/remembered")
                        .body(())
                        .unwrap(),
                )
                .await
                .unwrap();
            stream.finish().await.unwrap();
            captured_rx.await.unwrap();
        };
        let ((), _) = tokio::join!(request, drive);
    };

    tokio::time::timeout(TEST_TIMEOUT, async {
        tokio::join!(server, client);
    })
    .await
    .expect("request waited for peer SETTINGS despite remembered settings");
}

#[tokio::test]
async fn chromium_stream_order_writes_the_encoder_stream_type_with_its_first_instructions() {
    let mut pair = Pair::default();
    let endpoint = pair.server_inner();
    let (client_connection, server_connection) = tokio::join!(pair.client(), async {
        endpoint.accept().await.unwrap().await.unwrap()
    });
    let (expected_instructions, expected_block) =
        dynamic_request_bytes("https://localhost/chromium");
    let (captured, captured_rx) = oneshot::channel();

    let server = async move {
        let mut control = server_connection.open_uni().await.unwrap();
        control.write_all(PEER_DYNAMIC_SETTINGS).await.unwrap();

        // The control stream is client stream 2. The decoder stream (6)
        // carries no feedback here; QUIC opens it implicitly when stream 10
        // arrives (RFC 9000, section 2.1). The encoder stream is 10, and its
        // type comes with the table capacity and the request's inserts.
        let mut client_control = server_connection.accept_uni().await.unwrap();
        assert_eq!(u64::from(client_control.id()), 2);
        assert_eq!(read_varint(&mut client_control).await, 0x00);
        let decoder = server_connection.accept_uni().await.unwrap();
        assert_eq!(u64::from(decoder.id()), 6);
        let mut encoder = server_connection.accept_uni().await.unwrap();
        assert_eq!(u64::from(encoder.id()), 10);
        let mut instructions = vec![0; expected_instructions.len() + 1];
        encoder.read_exact(&mut instructions).await.unwrap();
        assert_eq!(instructions[0], 0x02);
        assert_eq!(&instructions[1..], expected_instructions);

        let (_response, mut request) = server_connection.accept_bi().await.unwrap();
        let (frame_type, payload) = read_frame(&mut request).await;
        assert_eq!(frame_type, 0x01);
        assert_eq!(payload, expected_block);

        captured.send(()).unwrap();
        server_connection.close(0_u32.into(), b"test complete");
        drop((control, client_control, decoder, encoder));
    };

    let client = async move {
        let mut builder = client::builder();
        builder
            .send_grease(false)
            .enable_dynamic_qpack(true)
            .defer_qpack_decoder_stream(true)
            .qpack_decoder_stream_first(true)
            .defer_qpack_encoder_stream(true);
        let (mut driver, mut sender) = builder
            .build::<_, _, Bytes>(client_connection)
            .await
            .unwrap();
        let drive = async move { future::poll_fn(|cx| driver.poll_close(cx)).await };
        let request = async move {
            let mut stream = sender
                .send_request(Request::get("https://localhost/chromium").body(()).unwrap())
                .await
                .unwrap();
            stream.finish().await.unwrap();
            captured_rx.await.unwrap();
        };
        let ((), _) = tokio::join!(request, drive);
    };

    tokio::time::timeout(TEST_TIMEOUT, async {
        tokio::join!(server, client);
    })
    .await
    .expect("request with the Chromium QPACK stream order did not complete");
}

fn stateless_request_block(uri: &'static str) -> Vec<u8> {
    let request = Request::get(uri).body(()).unwrap();
    let (parts, ()) = request.into_parts();
    let header = Header::request(parts.method, parts.uri, parts.headers, parts.extensions).unwrap();
    let mut block = Vec::new();
    qpack::encode_stateless(&mut block, header).unwrap();
    block
}

fn dynamic_request_bytes(uri: &'static str) -> (Vec<u8>, Vec<u8>) {
    let request = Request::get(uri).body(()).unwrap();
    let (parts, ()) = request.into_parts();
    let header = Header::request(parts.method, parts.uri, parts.headers, parts.extensions).unwrap();
    let mut encoder = qpack::Encoder::default();
    let mut instructions = Vec::new();
    encoder
        .set_max_table_capacity(4096, &mut instructions)
        .unwrap();
    encoder.set_max_blocked_streams(16).unwrap();
    let mut block = Vec::new();
    assert!(
        encoder
            .encode(0, &mut block, &mut instructions, header)
            .unwrap()
            > 0
    );
    (instructions, block)
}

struct ClientCriticalStreams {
    _control: quinn::RecvStream,
    encoder: quinn::RecvStream,
    _decoder: quinn::RecvStream,
}

async fn accept_client_critical_streams(connection: &quinn::Connection) -> ClientCriticalStreams {
    let mut control = None;
    let mut encoder = None;
    let mut decoder = None;
    while control.is_none() || encoder.is_none() || decoder.is_none() {
        let mut stream = connection.accept_uni().await.unwrap();
        match read_varint(&mut stream).await {
            0x00 => assert!(control.replace(stream).is_none()),
            0x02 => assert!(encoder.replace(stream).is_none()),
            0x03 => assert!(decoder.replace(stream).is_none()),
            stream_type => panic!("unexpected client stream type {stream_type:#x}"),
        }
    }
    ClientCriticalStreams {
        _control: control.unwrap(),
        encoder: encoder.unwrap(),
        _decoder: decoder.unwrap(),
    }
}

async fn read_frame(stream: &mut quinn::RecvStream) -> (u64, Vec<u8>) {
    let frame_type = read_varint(stream).await;
    let length = usize::try_from(read_varint(stream).await).unwrap();
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await.unwrap();
    (frame_type, payload)
}

async fn read_varint(stream: &mut quinn::RecvStream) -> u64 {
    let mut first = [0];
    stream.read_exact(&mut first).await.unwrap();
    let width = 1_usize << (first[0] >> 6);
    let mut encoded = [0; 8];
    encoded[0] = first[0];
    stream.read_exact(&mut encoded[1..width]).await.unwrap();
    encoded[..width]
        .iter()
        .enumerate()
        .fold(0_u64, |value, (index, byte)| {
            let byte = if index == 0 { *byte & 0x3f } else { *byte };
            (value << 8) | u64::from(byte)
        })
}

struct ObservedConnection {
    inner: h3_quinn::Connection,
    bidi_polls: Arc<AtomicUsize>,
}

impl ObservedConnection {
    fn new(inner: h3_quinn::Connection, bidi_polls: Arc<AtomicUsize>) -> Self {
        Self { inner, bidi_polls }
    }
}

impl quic::Connection<Bytes> for ObservedConnection {
    type RecvStream = <h3_quinn::Connection as quic::Connection<Bytes>>::RecvStream;
    type OpenStreams = ObservedOpenStreams;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        <h3_quinn::Connection as quic::Connection<Bytes>>::poll_accept_recv(&mut self.inner, cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        <h3_quinn::Connection as quic::Connection<Bytes>>::poll_accept_bidi(&mut self.inner, cx)
    }

    fn opener(&self) -> Self::OpenStreams {
        ObservedOpenStreams {
            inner: <h3_quinn::Connection as quic::Connection<Bytes>>::opener(&self.inner),
            bidi_polls: Arc::clone(&self.bidi_polls),
        }
    }
}

impl quic::OpenStreams<Bytes> for ObservedConnection {
    type BidiStream = <h3_quinn::Connection as quic::OpenStreams<Bytes>>::BidiStream;
    type SendStream = <h3_quinn::Connection as quic::OpenStreams<Bytes>>::SendStream;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        self.bidi_polls.fetch_add(1, Ordering::AcqRel);
        <h3_quinn::Connection as quic::OpenStreams<Bytes>>::poll_open_bidi(&mut self.inner, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        <h3_quinn::Connection as quic::OpenStreams<Bytes>>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: crate::error::Code, reason: &[u8]) {
        <h3_quinn::Connection as quic::OpenStreams<Bytes>>::close(&mut self.inner, code, reason);
    }
}

struct ObservedOpenStreams {
    inner: h3_quinn::OpenStreams,
    bidi_polls: Arc<AtomicUsize>,
}

impl quic::OpenStreams<Bytes> for ObservedOpenStreams {
    type BidiStream = <h3_quinn::OpenStreams as quic::OpenStreams<Bytes>>::BidiStream;
    type SendStream = <h3_quinn::OpenStreams as quic::OpenStreams<Bytes>>::SendStream;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        self.bidi_polls.fetch_add(1, Ordering::AcqRel);
        <h3_quinn::OpenStreams as quic::OpenStreams<Bytes>>::poll_open_bidi(&mut self.inner, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        <h3_quinn::OpenStreams as quic::OpenStreams<Bytes>>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: crate::error::Code, reason: &[u8]) {
        <h3_quinn::OpenStreams as quic::OpenStreams<Bytes>>::close(&mut self.inner, code, reason);
    }
}
