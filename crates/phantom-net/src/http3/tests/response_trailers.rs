//! Independently encoded response field blocks and stream cancellation.

use http::Request;
use http_body_util::BodyExt;

use super::{
    TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, client_config, oneshot,
    server_endpoint, test_settings, timeout,
};

#[derive(Clone, Copy)]
enum Tail {
    Absent,
    Ordered,
    InvalidSuffix,
}

pub(super) async fn raw_connection(
    endpoint: &quinn::Endpoint,
) -> TestResult<(
    quinn::Connection,
    Vec<quinn::SendStream>,
    Vec<quinn::RecvStream>,
)> {
    let connection = endpoint.accept().await.ok_or("endpoint closed")?.await?;
    let mut control = connection.open_uni().await?;
    control.write_all(&[0, 4, 0]).await?; // Control stream and empty SETTINGS.
    let mut encoder = connection.open_uni().await?;
    encoder.write_all(&[2]).await?;
    let mut decoder = connection.open_uni().await?;
    decoder.write_all(&[3]).await?;
    let mut incoming = Vec::new();
    let mut seen = [false; 3];
    for _ in 0..3 {
        let mut stream = connection.accept_uni().await?;
        let mut kind = [0];
        stream.read_exact(&mut kind).await?;
        let index = match kind[0] {
            0 => 0,
            2 => 1,
            3 => 2,
            _ => return Err("unexpected client stream type".into()),
        };
        assert!(!std::mem::replace(&mut seen[index], true));
        incoming.push(stream);
    }
    Ok((connection, vec![control, encoder, decoder], incoming))
}

async fn response_head(stream: &mut quinn::SendStream) -> TestResult<()> {
    // HEADERS, length 3, QPACK prefix 0/0, static :status 200 (index 25).
    stream.write_all(&[1, 3, 0, 0, 0xd9]).await?;
    Ok(())
}

async fn ordered_tail(stream: &mut quinn::SendStream) -> TestResult<()> {
    // Literal names/values, no Huffman coding: a:1, never-indexed b:ff, a:3.
    stream
        .write_all(b"\x01\x0e\x00\x00\x21a\x011\x31b\x01\xff\x21a\x013")
        .await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn ordered_sidecar_requires_validated_quic_eof_and_absence_stays_absent() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        for tail in [Tail::Absent, Tail::Ordered, Tail::InvalidSuffix] {
            let identity = TestIdentity::generate()?;
            let client = client_config(&identity)?;
            let (address, endpoint) = server_endpoint(&identity)?;
            let (done, received) = oneshot::channel();
            let caller = async {
                let connection = crate::http3::connect_direct(
                    address,
                    TEST_SERVER_NAME,
                    client,
                    &test_settings(),
                )
                .await?;
                let response = connection
                    .send_request(
                        Request::get(format!("https://{TEST_SERVER_NAME}:{}/", address.port()))
                            .body(())?,
                        None,
                    )
                    .await?;
                let mut body = response.into_body();
                assert!(body.take_received_trailers().is_none());
                assert_eq!(
                    body.frame().await.ok_or("missing DATA")??.into_data().ok(),
                    Some(bytes::Bytes::from_static(b"ok"))
                );
                match tail {
                    Tail::Absent => assert!(body.frame().await.is_none()),
                    Tail::InvalidSuffix => {
                        assert!(
                            body.frame()
                                .await
                                .ok_or("missing invalid-tail error")?
                                .is_err()
                        );
                        assert!(body.frame().await.is_none());
                    }
                    Tail::Ordered => {
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
                        assert_eq!(
                            ordered
                                .iter()
                                .map(|field| field.is_sensitive())
                                .collect::<Vec<_>>(),
                            vec![false, true, false]
                        );
                        assert!(body.frame().await.is_none());
                    }
                }
                assert!(body.take_received_trailers().is_none());
                done.send(()).map_err(|()| "peer dropped completion")?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            };
            let observer = async {
                let (connection, _send, _receive) = raw_connection(&endpoint).await?;
                let (mut response, mut request) = connection.accept_bi().await?;
                assert!(!request.read_to_end(8192).await?.is_empty());
                response_head(&mut response).await?;
                response.write_all(b"\x00\x02ok").await?;
                if !matches!(tail, Tail::Absent) {
                    ordered_tail(&mut response).await?;
                }
                if matches!(tail, Tail::InvalidSuffix) {
                    response.write_all(b"\x00\x01x").await?;
                }
                response.finish()?;
                received.await?;
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
            };
            tokio::try_join!(caller, observer)?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "HTTP/3 response trailer test timed out")?
}

#[tokio::test(flavor = "current_thread")]
async fn abandoned_stream_leaves_live_sibling_trailers_and_connection_reuse_intact()
-> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let client = client_config(&identity)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (done, received) = oneshot::channel();
        let caller = async {
            let connection =
                crate::http3::connect_direct(address, TEST_SERVER_NAME, client, &test_settings())
                    .await?;
            let uri = format!("https://{TEST_SERVER_NAME}:{}/", address.port());
            let selected = connection
                .send_request(Request::get(uri.as_str()).body(())?, None)
                .await?;
            let healthy = connection
                .send_request(Request::get(uri.as_str()).body(())?, None)
                .await?;
            drop(selected);
            let mut body = healthy.into_body();
            assert!(
                body.frame()
                    .await
                    .ok_or("missing sibling trailers")??
                    .trailers_ref()
                    .is_some()
            );
            assert_eq!(
                body.take_received_trailers()
                    .ok_or("missing sibling sidecar")?
                    .len(),
                3
            );
            assert!(body.frame().await.is_none());
            let mut reused = connection
                .send_request(Request::get(uri.as_str()).body(())?, None)
                .await?
                .into_body();
            assert!(reused.frame().await.is_none());
            assert!(reused.take_received_trailers().is_none());
            done.send(()).map_err(|()| "peer dropped completion")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let observer = async {
            let (connection, _send, _receive) = raw_connection(&endpoint).await?;
            let (mut selected, mut request) = connection.accept_bi().await?;
            assert!(!request.read_to_end(8192).await?.is_empty());
            response_head(&mut selected).await?;
            let (mut healthy, mut request) = connection.accept_bi().await?;
            assert!(!request.read_to_end(8192).await?.is_empty());
            response_head(&mut healthy).await?;
            assert_eq!(
                selected.stopped().await?,
                Some(quinn::VarInt::from_u32(0x10c))
            );
            ordered_tail(&mut healthy).await?;
            healthy.finish()?;
            let (mut reused, mut request) = connection.accept_bi().await?;
            assert!(!request.read_to_end(8192).await?.is_empty());
            response_head(&mut reused).await?;
            reused.finish()?;
            received.await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(caller, observer)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "HTTP/3 sibling trailer test timed out")?
}
