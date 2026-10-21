use std::{future::Future, time::Duration};

use bytes::Bytes;
use futures_util::future;
use http::Request;
use tokio::task::JoinHandle;

use crate::{
    client,
    error::{Code, ConnectionError, StreamError},
};

use super::{h3_quinn, Pair};
use h3_quinn::quinn;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
// Independently encoded RFC 9204 literals (no Huffman/dynamic references).
// The middle literal sets N; the last value contains valid non-UTF8 field bytes.
const INTERLEAVED: &[u8] = b"\x00\x00\x23x-a\x05first\x33x-b\x06middle\x23x-a\x03\x80\xffz";
const STATUS_200: &[u8] = b"\x01\x03\x00\x00\xd9";

type Stream = client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

struct Peer {
    response: quinn::SendStream,
    _request: quinn::RecvStream,
}

struct Harness {
    sender: client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    peer: quinn::Connection,
    driver: JoinHandle<ConnectionError>,
    _control: quinn::SendStream,
    _endpoint: quinn::Endpoint,
}

impl Harness {
    async fn new(limit: u64) -> Self {
        let mut pair = Pair::default();
        let endpoint = pair.server_inner();
        let (connection, peer) = tokio::join!(pair.client(), async {
            endpoint.accept().await.unwrap().await.unwrap()
        });
        let mut control = peer.open_uni().await.unwrap();
        control.write_all(b"\x00\x04\x00").await.unwrap();
        let (mut driver, sender) = client::builder()
            .send_grease(false)
            .max_field_section_size(limit)
            .build::<_, _, Bytes>(connection)
            .await
            .unwrap();
        let driver = tokio::spawn(async move { future::poll_fn(|cx| driver.poll_close(cx)).await });
        Self {
            sender,
            peer,
            driver,
            _control: control,
            _endpoint: endpoint,
        }
    }

    async fn open(&mut self) -> (Stream, Peer) {
        let mut stream = self
            .sender
            .send_request(Request::get("https://localhost/trailers").body(()).unwrap())
            .await
            .unwrap();
        stream.finish().await.unwrap();
        let (response, request) = self.peer.accept_bi().await.unwrap();
        (
            stream,
            Peer {
                response,
                _request: request,
            },
        )
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.driver.abort();
        self.peer.close(0_u32.into(), b"test complete");
    }
}

async fn bounded(test: impl Future<Output = ()>) {
    tokio::time::timeout(TEST_TIMEOUT, test)
        .await
        .expect("trailer exchange stalled");
}

async fn write_trailers(peer: &mut Peer, fields: &[u8]) {
    // These test sections are shorter than 64 bytes: frame type/length are one byte.
    assert!(fields.len() < 64);
    peer.response.write_all(STATUS_200).await.unwrap();
    peer.response
        .write_all(&[1, fields.len() as u8])
        .await
        .unwrap();
    peer.response.write_all(fields).await.unwrap();
    peer.response.finish().unwrap();
}

async fn receive(stream: &mut Stream) -> http::HeaderMap {
    assert_eq!(stream.recv_response().await.unwrap().status(), 200);
    assert!(stream.recv_data().await.unwrap().is_none());
    stream.recv_trailers().await.unwrap().expect("trailers")
}

fn assert_interleaved(ordered: crate::ext::OrderedHeaders) {
    let actual: Vec<_> = ordered
        .as_slice()
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_bytes(), value.is_sensitive()))
        .collect();
    assert_eq!(
        actual,
        vec![
            ("x-a", &b"first"[..], false),
            ("x-b", &b"middle"[..], true),
            ("x-a", &b"\x80\xffz"[..], false),
        ]
    );
}

#[tokio::test]
async fn received_trailers_retain_qpack_order_duplicates_bytes_and_never_indexed() {
    bounded(async {
        let mut harness = Harness::new(1024).await;
        let (mut stream, mut peer) = harness.open().await;
        assert!(stream.take_ordered_trailers().is_none());
        write_trailers(&mut peer, INTERLEAVED).await;
        let semantic = receive(&mut stream).await;
        assert_eq!(
            semantic
                .get_all("x-a")
                .iter()
                .map(|v| v.as_bytes())
                .collect::<Vec<_>>(),
            vec![&b"first"[..], &b"\x80\xffz"[..]]
        );
        assert!(semantic["x-b"].is_sensitive());
        assert_interleaved(stream.take_ordered_trailers().unwrap());
        assert!(stream.take_ordered_trailers().is_none());
        assert!(stream.recv_trailers().await.unwrap().is_none());
        assert!(stream.take_ordered_trailers().is_none());
    })
    .await;
}

#[tokio::test]
async fn fragmented_trailers_wait_for_fin_and_cancelled_receive_future_can_resume() {
    bounded(async {
        let mut harness = Harness::new(1024).await;
        let (mut stream, mut peer) = harness.open().await;
        peer.response.write_all(STATUS_200).await.unwrap();
        peer.response
            .write_all(&[1, INTERLEAVED.len() as u8])
            .await
            .unwrap();
        peer.response.write_all(&INTERLEAVED[..7]).await.unwrap();
        stream.recv_response().await.unwrap();
        let mut receiving = Box::pin(stream.recv_trailers());
        future::poll_fn(|cx| {
            assert!(receiving.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(receiving);
        assert!(stream.take_ordered_trailers().is_none());
        for byte in &INTERLEAVED[7..] {
            peer.response.write_all(&[*byte]).await.unwrap();
        }
        // Complete HEADERS without FIN still cannot publish successful trailers.
        assert!(stream.recv_data().await.unwrap().is_none());
        let mut receiving = Box::pin(stream.recv_trailers());
        future::poll_fn(|cx| {
            assert!(receiving.as_mut().poll(cx).is_pending());
            std::task::Poll::Ready(())
        })
        .await;
        drop(receiving);
        assert!(stream.take_ordered_trailers().is_none());
        peer.response.finish().unwrap();
        stream.recv_trailers().await.unwrap().unwrap();
        assert_interleaved(stream.take_ordered_trailers().unwrap());
    })
    .await;
}

#[tokio::test]
async fn ordered_trailers_are_stream_local_and_follow_the_receive_half_on_split() {
    bounded(async {
        let mut harness = Harness::new(1024).await;
        let (mut first, mut first_peer) = harness.open().await;
        let (mut second, mut second_peer) = harness.open().await;
        write_trailers(&mut first_peer, INTERLEAVED).await;
        write_trailers(&mut second_peer, b"\x00\x00").await;
        receive(&mut first).await;
        let (_send, mut recv) = first.split();
        assert_interleaved(recv.take_ordered_trailers().unwrap());
        assert!(receive(&mut second).await.is_empty());
        assert!(second
            .take_ordered_trailers()
            .unwrap()
            .as_slice()
            .is_empty());
        assert!(recv.take_ordered_trailers().is_none());
    })
    .await;
}

#[tokio::test]
async fn next_receive_poll_or_local_stop_discards_delivered_trailer_order() {
    bounded(async {
        let mut harness = Harness::new(1024).await;
        for action in 0..3 {
            let (mut stream, mut peer) = harness.open().await;
            write_trailers(&mut peer, INTERLEAVED).await;
            receive(&mut stream).await;
            match action {
                0 => {
                    assert!(stream.recv_data().await.unwrap().is_none());
                }
                1 => stream.stop_sending(Code::H3_REQUEST_CANCELLED),
                _ => stream.stop_stream(Code::H3_REQUEST_CANCELLED),
            }
            assert!(stream.take_ordered_trailers().is_none());
        }
    })
    .await;
}

#[tokio::test]
async fn reset_or_dropped_stream_does_not_publish_order_or_poison_a_sibling() {
    bounded(async {
        let mut harness = Harness::new(1024).await;
        let (mut failed, mut failed_peer) = harness.open().await;
        let (mut healthy, mut healthy_peer) = harness.open().await;
        failed_peer.response.write_all(STATUS_200).await.unwrap();
        failed_peer
            .response
            .write_all(&[1, INTERLEAVED.len() as u8])
            .await
            .unwrap();
        failed_peer.response.write_all(INTERLEAVED).await.unwrap();
        failed.recv_response().await.unwrap();
        assert!(failed.recv_data().await.unwrap().is_none());
        failed_peer
            .response
            .reset(quinn::VarInt::try_from(Code::H3_REQUEST_CANCELLED.value()).unwrap())
            .unwrap();
        assert!(failed.recv_trailers().await.is_err());
        assert!(failed.take_ordered_trailers().is_none());
        drop(failed);
        let (mut cancelled, mut cancelled_peer) = harness.open().await;
        cancelled_peer.response.write_all(STATUS_200).await.unwrap();
        cancelled.recv_response().await.unwrap();
        cancelled.stop_sending(Code::H3_REQUEST_CANCELLED);
        assert!(cancelled.take_ordered_trailers().is_none());
        drop(cancelled);
        assert_eq!(
            cancelled_peer
                .response
                .stopped()
                .await
                .unwrap()
                .unwrap()
                .into_inner(),
            Code::H3_REQUEST_CANCELLED.value()
        );
        write_trailers(&mut healthy_peer, INTERLEAVED).await;
        receive(&mut healthy).await;
        assert_interleaved(healthy.take_ordered_trailers().unwrap());
    })
    .await;
}

#[tokio::test]
async fn decoded_trailer_limit_is_inclusive_and_does_not_publish_a_prefix() {
    bounded(async {
        // Independent RFC 9204 section accounting: x-a:a = 3+1+32 = 36,
        // x-b:vvvvvvvvv = 3+9+32 = 44. The two-field section is exactly 80 bytes.
        let fields = b"\x00\x00\x23x-a\x01a\x23x-b\x09vvvvvvvvv";
        for limit in [79, 80, 81] {
            let mut harness = Harness::new(limit).await;
            let (mut stream, mut peer) = harness.open().await;
            let (mut sibling, mut sibling_peer) = harness.open().await;
            write_trailers(&mut peer, fields).await;
            stream.recv_response().await.unwrap();
            assert!(stream.recv_data().await.unwrap().is_none());
            if limit == 79 {
                assert!(matches!(
                    stream.recv_trailers().await,
                    Err(StreamError::HeaderTooBig {
                        actual_size: 80,
                        max_size: 79
                    })
                ));
                assert!(stream.take_ordered_trailers().is_none());
            } else {
                assert_eq!(stream.recv_trailers().await.unwrap().unwrap().len(), 2);
                assert_eq!(stream.take_ordered_trailers().unwrap().as_slice().len(), 2);
            }
            write_trailers(&mut sibling_peer, b"\x00\x00").await;
            assert!(receive(&mut sibling).await.is_empty());
            assert!(sibling
                .take_ordered_trailers()
                .unwrap()
                .as_slice()
                .is_empty());
        }
    })
    .await;
}

#[tokio::test]
async fn pseudo_headers_in_trailers_fail_without_order_and_preserve_a_sibling() {
    bounded(async {
        let mut harness = Harness::new(1024).await;
        let (mut stream, mut peer) = harness.open().await;
        let (mut sibling, mut sibling_peer) = harness.open().await;
        write_trailers(&mut peer, b"\x00\x00\xd9").await;
        stream.recv_response().await.unwrap();
        assert!(stream.recv_data().await.unwrap().is_none());
        assert!(matches!(
            stream.recv_trailers().await,
            Err(StreamError::StreamError {
                code: Code::H3_MESSAGE_ERROR,
                ..
            })
        ));
        assert!(stream.take_ordered_trailers().is_none());
        write_trailers(&mut sibling_peer, b"\x00\x00").await;
        receive(&mut sibling).await;
    })
    .await;
}

#[tokio::test]
async fn truncated_or_extra_frames_after_trailers_never_publish_order() {
    bounded(async {
        // A partial HEADERS payload, DATA after trailers, and truncated QPACK index.
        for tail in [
            &b"\x01\x06\x00\x00"[..],
            &b"\x01\x02\x00\x00\x00\x00"[..],
            &b"\x01\x03\x00\x00\xff"[..],
        ] {
            let mut harness = Harness::new(1024).await;
            let (mut stream, mut peer) = harness.open().await;
            peer.response.write_all(STATUS_200).await.unwrap();
            peer.response.write_all(tail).await.unwrap();
            peer.response.finish().unwrap();
            stream.recv_response().await.unwrap();
            assert!(stream.recv_trailers().await.is_err());
            assert!(stream.take_ordered_trailers().is_none());
        }
    })
    .await;
}

#[tokio::test]
async fn observed_connection_failure_invalidates_delivered_trailer_order() {
    bounded(async {
        let mut harness = Harness::new(1024).await;
        let (mut stream, mut peer) = harness.open().await;
        write_trailers(&mut peer, INTERLEAVED).await;
        receive(&mut stream).await;
        harness.peer.close(
            quinn::VarInt::try_from(Code::H3_INTERNAL_ERROR.value()).unwrap(),
            b"test failure",
        );
        (&mut harness.driver).await.unwrap();
        assert!(stream.take_ordered_trailers().is_none());
    })
    .await;
}
