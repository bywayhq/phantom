//! Literal HPACK response trailers through the public body owner.

use http::Method;
use http_body_util::BodyExt;
use phantom_profile::browser::chrome::v154_http2;
use tokio::{net::TcpStream, sync::oneshot};

use super::{
    TestResult, bounded_peer_test,
    ping_peer::{read_frame, start, write_frame},
    target,
};

async fn stream_frame(peer: &mut TcpStream) -> TestResult<(u8, u8, u32, Vec<u8>)> {
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

#[tokio::test]
async fn ordered_response_trailers_are_owned_and_absence_has_no_sidecar() -> TestResult<()> {
    bounded_peer_test(async {
        for with_trailers in [false, true] {
            let (mut peer, connection) = start(&v154_http2()).await?;
            let (done, received) = oneshot::channel();
            let caller = async {
                let response = connection
                    .send_request(Method::GET, "example.test", target()?, Vec::new(), None)
                    .await?;
                let mut body = response.into_body();
                assert!(body.take_received_trailers().is_none());
                assert_eq!(
                    body.frame().await.ok_or("missing DATA")??.into_data().ok(),
                    Some(bytes::Bytes::from_static(b"ok"))
                );
                if with_trailers {
                    assert!(
                        body.frame()
                            .await
                            .ok_or("missing trailers")??
                            .trailers_ref()
                            .is_some()
                    );
                    let ordered = body.take_received_trailers().ok_or("missing sidecar")?;
                    assert_eq!(
                        ordered
                            .iter()
                            .map(|field| (field.name(), field.value()))
                            .collect::<Vec<_>>(),
                        vec![
                            ("a", b"1".as_slice()),
                            ("b", b"\xff".as_slice()),
                            ("a", b"3".as_slice())
                        ]
                    );
                    assert!(body.take_received_trailers().is_none());
                }
                assert!(body.frame().await.is_none());
                assert!(body.take_received_trailers().is_none());
                done.send(()).map_err(|()| "peer dropped completion")?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            };
            let observer = async {
                let (kind, _, stream, _) = stream_frame(&mut peer).await?;
                assert_eq!(kind, 1);
                write_frame(&mut peer, 1, 4, stream, &[0x88]).await?;
                write_frame(&mut peer, 0, u8::from(!with_trailers), stream, b"ok").await?;
                if with_trailers {
                    // Literal fields without indexing or Huffman encoding.
                    write_frame(
                        &mut peer,
                        1,
                        5,
                        stream,
                        b"\x00\x01a\x011\x00\x01b\x01\xff\x00\x01a\x013",
                    )
                    .await?;
                }
                received.await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            };
            tokio::try_join!(caller, observer)?;
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn abandoned_response_cancels_only_its_stream_before_sibling_trailers() -> TestResult<()> {
    bounded_peer_test(async {
        let (mut peer, connection) = start(&v154_http2()).await?;
        let (done, received) = oneshot::channel();
        let caller = async {
            let mut selected = connection
                .send_request(Method::GET, "example.test", target()?, Vec::new(), None)
                .await?;
            let healthy = connection
                .send_request(Method::GET, "example.test", target()?, Vec::new(), None)
                .await?;
            assert!(selected.body_mut().take_received_trailers().is_none());
            drop(selected);
            let mut body = healthy.into_body();
            assert!(
                body.frame()
                    .await
                    .ok_or("missing sibling trailers")??
                    .trailers_ref()
                    .is_some()
            );
            let trailers = body
                .take_received_trailers()
                .ok_or("missing sibling sidecar")?;
            assert_eq!(
                trailers
                    .iter()
                    .next()
                    .ok_or("missing sibling field")?
                    .value(),
                b"healthy"
            );
            assert!(body.frame().await.is_none());
            done.send(()).map_err(|()| "peer dropped completion")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let observer = async {
            let (kind, _, selected, _) = stream_frame(&mut peer).await?;
            assert_eq!(kind, 1);
            write_frame(&mut peer, 1, 4, selected, &[0x88]).await?;
            let (kind, _, healthy, _) = stream_frame(&mut peer).await?;
            assert_eq!(kind, 1);
            assert_ne!(selected, healthy);
            write_frame(&mut peer, 1, 4, healthy, &[0x88]).await?;
            loop {
                let (kind, _, stream, payload) = stream_frame(&mut peer).await?;
                if kind == 3 {
                    assert_eq!(stream, selected);
                    assert_eq!(payload, 8_u32.to_be_bytes());
                    break;
                }
            }
            write_frame(&mut peer, 1, 5, healthy, b"\x00\x01a\x07healthy").await?;
            received.await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(caller, observer)?;
        Ok(())
    })
    .await
}
