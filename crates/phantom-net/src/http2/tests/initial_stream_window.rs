//! Opening receive credit through the public connection API and a raw peer.

use bytes::Bytes;
use http::Method;
use http_body_util::BodyExt;
use phantom_profile::{Http2Setting, browser::firefox::v157_http2};
use tokio::{
    io::{AsyncReadExt, duplex},
    net::TcpStream,
    sync::oneshot,
};

use super::{
    TestResult, bounded_peer_test,
    ping_peer::{read_frame, start, write_frame},
    target,
};
use crate::http2::{Http2Connection, Http2Error, RequestHeader};

const BOOST: u32 = 12_451_840;
const PROBE: &[u8; 8] = b"credit!!";
type Frame = (u8, u8, u32, Vec<u8>);

async fn next_stream(peer: &mut TcpStream) -> TestResult<Frame> {
    loop {
        let frame = read_frame(peer).await?;
        assert_ne!(frame.0, 7, "unexpected GOAWAY");
        if frame.2 != 0 {
            return Ok(frame);
        }
        if (frame.0, frame.1) == (6, 0) {
            write_frame(peer, 6, 1, 0, &frame.3).await?;
        }
    }
}

async fn fence(peer: &mut TcpStream) -> TestResult<Vec<Frame>> {
    write_frame(peer, 6, 0, 0, PROBE).await?;
    let mut frames = Vec::new();
    loop {
        let frame = read_frame(peer).await?;
        assert_ne!(frame.0, 7, "unexpected GOAWAY");
        if (frame.0, frame.1, frame.2) == (6, 1, 0) {
            assert_eq!(frame.3, PROBE);
            return Ok(frames);
        }
        frames.push(frame);
    }
}

fn update(frame: Frame, stream: u32, increment: u32) {
    assert_eq!((frame.0, frame.1, frame.2), (8, 0, stream));
    assert_eq!(frame.3, increment.to_be_bytes());
}

#[tokio::test]
async fn public_connection_grants_after_continuation_before_data_and_not_trailers() -> TestResult<()>
{
    bounded_peer_test(async {
        let settings = v157_http2();
        let (mut peer, connection) = start(&settings).await?;
        // Finish the peer SETTINGS exchange before queuing request frames.
        // Only its ACK and the initial connection credit may precede this fence.
        let mut startup = fence(&mut peer).await?;
        assert_eq!(startup.len(), 2);
        let ack = startup
            .iter()
            .position(|frame| (frame.0, frame.1, frame.2) == (4, 1, 0))
            .ok_or("missing initial peer SETTINGS acknowledgment")?;
        assert!(startup.remove(ack).3.is_empty());
        update(
            startup.remove(0),
            0,
            settings.initial_connection_window_size - 65_535,
        );
        let (done_tx, done_rx) = oneshot::channel();
        let caller = async {
            let response = connection
                .send_request_with_trailers(
                    Method::POST,
                    "example.test",
                    target()?,
                    // Fit the header bound while requiring CONTINUATION frames.
                    vec![RequestHeader::new("x-long", "x".repeat(30_000))],
                    Some(Bytes::from_static(b"body")),
                    vec![RequestHeader::new("x-end", "complete")],
                )
                .await?;
            assert_eq!(response.status(), 200);
            assert!(response.into_body().collect().await?.to_bytes().is_empty());
            done_tx.send(()).map_err(|()| "peer dropped completion")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let observer = async {
            let mut headers = next_stream(&mut peer).await?;
            assert_eq!((headers.0, headers.2, headers.1 & 4), (1, 3, 0));
            let mut continuations = 0;
            while headers.1 & 4 == 0 {
                headers = read_frame(&mut peer).await?;
                assert_eq!((headers.0, headers.2), (9, 3));
                continuations += 1;
            }
            assert!(continuations > 0);
            update(read_frame(&mut peer).await?, 3, BOOST);
            let data = read_frame(&mut peer).await?;
            assert_eq!((data.0, data.2, data.1 & 1), (0, 3, 0));
            assert_eq!(data.3, b"body");
            let trailers = read_frame(&mut peer).await?;
            assert_eq!((trailers.0, trailers.2, trailers.1 & 5), (1, 3, 5));
            assert!(fence(&mut peer).await?.iter().all(|frame| frame.2 == 0));
            write_frame(&mut peer, 1, 5, 3, &[0x88]).await?;
            done_rx.await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(caller, observer)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_connection_accepts_more_than_advertised_credit_before_body_poll() -> TestResult<()>
{
    bounded_peer_test(async {
        let (mut peer, connection) = start(&v157_http2()).await?;
        let (parsed_tx, parsed_rx) = oneshot::channel();
        let (done_tx, done_rx) = oneshot::channel();
        let caller = async {
            let response = connection
                .send_get("example.test", target()?, Vec::new())
                .await?;
            // No body poll or capacity release occurs before the peer's PING ACK.
            parsed_rx.await?;
            let bytes = response.into_body().collect().await?.to_bytes();
            assert_eq!(bytes.len(), 196_608);
            assert!(bytes.iter().all(|byte| *byte == b'a'));
            done_tx.send(()).map_err(|()| "peer dropped completion")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let observer = async {
            let headers = next_stream(&mut peer).await?;
            assert_eq!((headers.0, headers.2), (1, 3));
            update(read_frame(&mut peer).await?, 3, BOOST);
            write_frame(&mut peer, 1, 4, 3, &[0x88]).await?;
            for index in 0..12 {
                write_frame(&mut peer, 0, u8::from(index == 11), 3, &[b'a'; 16_384]).await?;
            }
            assert!(fence(&mut peer).await?.iter().all(|frame| frame.2 == 0));
            parsed_tx
                .send(())
                .map_err(|()| "caller dropped parse barrier")?;
            done_rx.await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(caller, observer)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_connection_grant_is_finite_before_and_after_settings_ack() -> TestResult<()> {
    bounded_peer_test(async {
        for ack in [false, true] {
            let mut settings = v157_http2();
            for setting in &mut settings.initial_settings {
                if let Http2Setting::InitialWindowSize(value) = setting {
                    *value = 8;
                }
            }
            settings.initial_stream_window_target = Some(32);
            let (mut peer, connection) = start(&settings).await?;
            if ack {
                write_frame(&mut peer, 4, 1, 0, &[]).await?;
                assert!(fence(&mut peer).await?.iter().all(|frame| frame.2 == 0));
            }
            let (head_tx, head_rx) = oneshot::channel();
            let (reset_tx, reset_rx) = oneshot::channel();
            let (done_tx, done_rx) = oneshot::channel();
            let caller = async {
                let response = connection
                    .send_get("example.test", target()?, Vec::new())
                    .await?;
                head_tx.send(()).map_err(|()| "peer dropped head barrier")?;
                reset_rx.await?;
                assert!(response.into_body().collect().await.is_err());
                done_tx.send(()).map_err(|()| "peer dropped completion")?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            };
            let observer = async {
                let headers = next_stream(&mut peer).await?;
                assert_eq!((headers.0, headers.2), (1, 3));
                update(read_frame(&mut peer).await?, 3, 24);
                write_frame(&mut peer, 1, 4, 3, &[0x88]).await?;
                head_rx.await?;
                write_frame(&mut peer, 0, 0, 3, &[b'a'; 32]).await?;
                if !ack {
                    write_frame(&mut peer, 4, 1, 0, &[]).await?;
                }
                assert!(fence(&mut peer).await?.iter().all(|frame| frame.2 == 0));
                write_frame(&mut peer, 0, 0, 3, b"x").await?;
                let reset = next_stream(&mut peer).await?;
                assert_eq!((reset.0, reset.2), (3, 3));
                assert_eq!(reset.3, 3_u32.to_be_bytes()); // FLOW_CONTROL_ERROR
                reset_tx
                    .send(())
                    .map_err(|()| "caller dropped reset barrier")?;
                done_rx.await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            };
            tokio::try_join!(caller, observer)?;
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn public_connection_none_equal_and_chromium_targets_emit_no_opening_update() -> TestResult<()>
{
    bounded_peer_test(async {
        let mut absent = v157_http2();
        absent.initial_stream_window_target = None;
        let mut equal = v157_http2();
        equal.initial_stream_window_target = Some(131_072);
        for settings in [
            absent,
            equal,
            phantom_profile::browser::chrome::v154_http2(),
        ] {
            let first = settings.streams.first_stream_id;
            let (mut peer, connection) = start(&settings).await?;
            let (done_tx, done_rx) = oneshot::channel();
            let caller = async {
                let response = connection
                    .send_get("example.test", target()?, Vec::new())
                    .await?;
                assert!(response.into_body().collect().await?.to_bytes().is_empty());
                done_tx.send(()).map_err(|()| "peer dropped completion")?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            };
            let observer = async {
                let headers = next_stream(&mut peer).await?;
                assert_eq!((headers.0, headers.2), (1, first));
                assert!(fence(&mut peer).await?.iter().all(|frame| frame.2 == 0));
                write_frame(&mut peer, 1, 5, first, &[0x88]).await?;
                done_rx.await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            };
            tokio::try_join!(caller, observer)?;
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn invalid_stream_target_returns_before_touching_the_transport() -> TestResult<()> {
    bounded_peer_test(async {
        for target_window in [0, 131_071, 1 << 31, u32::MAX] {
            for extended in [false, true] {
                let mut settings = v157_http2();
                settings.initial_stream_window_target = Some(target_window);
                let (client, mut peer) = duplex(128);
                let result = if extended {
                    Http2Connection::connect_extended(client, &settings).await
                } else {
                    Http2Connection::connect(client, &settings).await
                };
                assert!(matches!(result, Err(Http2Error::InvalidSettings(_))));
                let mut wire = Vec::new();
                peer.read_to_end(&mut wire).await?;
                assert!(wire.is_empty());
            }
        }
        Ok(())
    })
    .await
}
