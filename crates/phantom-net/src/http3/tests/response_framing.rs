//! Literal QPACK/QUIC peers, independent of the HTTP/3 response encoder.

use http::{Method, Request};
use http_body_util::BodyExt;

use super::{
    Http3ErrorKind, TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, client_config,
    oneshot, response_trailers::raw_connection, server_endpoint, test_settings, timeout,
};

fn head(status: &[u8; 3], lengths: &[&[u8]]) -> TestResult<Vec<u8>> {
    // QPACK prefix 0/0, literal :status (length 7 + continuation 0), static-name content-length (index 4).
    let mut block = b"\x00\x00\x27\x00:status\x03".to_vec();
    block.extend_from_slice(status);
    for length in lengths {
        assert!(length.len() < 127);
        block.extend_from_slice(&[0x54, u8::try_from(length.len())?]);
        block.extend_from_slice(length);
    }
    assert!(block.len() < 64);
    let mut frame = vec![1, u8::try_from(block.len())?];
    frame.extend(block);
    Ok(frame)
}

async fn exchange(
    method: Method,
    status: &[u8; 3],
    lengths: &[&[u8]],
    data: &[u8],
    reject: bool,
) -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let client = client_config(&identity)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (done, received) = oneshot::channel();
        let caller = async {
            let connection =
                crate::http3::connect_direct(address, TEST_SERVER_NAME, client, &test_settings())
                    .await?;
            let result = connection
                .send_request(
                    Request::builder()
                        .method(method)
                        .uri(format!("https://{TEST_SERVER_NAME}:{}/", address.port()))
                        .body(())?,
                    None,
                )
                .await;
            let failure = match result {
                Err(error) => Some(error),
                Ok(response) => {
                    let mut body = response.into_body();
                    let mut bytes = Vec::new();
                    let mut failure = None;
                    while let Some(frame) = body.frame().await {
                        match frame {
                            Ok(frame) => {
                                if let Ok(chunk) = frame.into_data() {
                                    bytes.extend_from_slice(&chunk);
                                }
                            }
                            Err(error) => {
                                failure = Some(error);
                                break;
                            }
                        }
                    }
                    assert!(body.take_received_trailers().is_none());
                    if !reject {
                        assert_eq!(bytes, data);
                    }
                    failure
                }
            };
            if reject {
                assert_eq!(
                    failure
                        .ok_or("malformed HTTP/3 response was accepted")?
                        .kind(),
                    Http3ErrorKind::Protocol
                );
            } else if let Some(error) = failure {
                return Err(error.into());
            }
            done.send(()).map_err(|()| "peer dropped completion")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let observer = async {
            let (connection, _send, _receive) = raw_connection(&endpoint).await?;
            let (mut response, mut request) = connection.accept_bi().await?;
            assert!(!request.read_to_end(8192).await?.is_empty());
            response.write_all(&head(status, lengths)?).await?;
            if !data.is_empty() {
                assert!(data.len() < 64);
                response.write_all(&[0, u8::try_from(data.len())?]).await?;
                response.write_all(data).await?;
            }
            response.finish()?;
            received.await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(caller, observer)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "HTTP/3 response framing test timed out")?
}

#[tokio::test(flavor = "current_thread")]
async fn response_rejects_short_and_overlong_content_length() -> TestResult<()> {
    exchange(Method::GET, b"200", &[b"2"], b"x", true).await?;
    exchange(Method::GET, b"200", &[b"0"], b"x", true).await
}

#[tokio::test(flavor = "current_thread")]
async fn response_rejects_malformed_and_conflicting_content_length() -> TestResult<()> {
    for lengths in [vec![b"x".as_slice()], vec![b"1".as_slice(), b"2"]] {
        exchange(Method::GET, b"200", &lengths, b"", true).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn response_accepts_exact_streaming_and_bodyless_metadata_lengths() -> TestResult<()> {
    exchange(Method::GET, b"200", &[b"1"], b"x", false).await?;
    exchange(Method::GET, b"200", &[], b"x", false).await?;
    exchange(Method::HEAD, b"200", &[b"123"], b"", false).await?;
    exchange(Method::GET, b"304", &[b"123"], b"", false).await?;
    exchange(Method::GET, b"204", &[], b"", false).await
}

#[tokio::test(flavor = "current_thread")]
async fn response_rejects_data_for_bodyless_status_or_method() -> TestResult<()> {
    exchange(Method::HEAD, b"200", &[b"1"], b"x", true).await?;
    exchange(Method::GET, b"304", &[b"1"], b"x", true).await?;
    exchange(Method::GET, b"204", &[], b"x", true).await
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_response_length_resets_only_its_stream_and_preserves_reuse() -> TestResult<()> {
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
            let mut selected = connection
                .send_request(Request::get(uri.as_str()).body(())?, None)
                .await?
                .into_body();
            let mut healthy = connection
                .send_request(Request::get(uri.as_str()).body(())?, None)
                .await?
                .into_body();
            assert_eq!(
                selected
                    .frame()
                    .await
                    .ok_or("missing overlong DATA error")?
                    .err()
                    .ok_or("overlong DATA accepted")?
                    .kind(),
                Http3ErrorKind::Protocol
            );
            assert!(selected.take_received_trailers().is_none());
            assert_eq!(
                healthy
                    .frame()
                    .await
                    .ok_or("missing healthy DATA")??
                    .into_data()
                    .ok(),
                Some(bytes::Bytes::from_static(b"ok"))
            );
            assert!(healthy.frame().await.is_none());
            let mut reused = connection
                .send_request(Request::get(uri.as_str()).body(())?, None)
                .await?
                .into_body();
            assert!(reused.frame().await.is_none());
            done.send(()).map_err(|()| "peer dropped completion")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let observer = async {
            let (connection, _send, _receive) = raw_connection(&endpoint).await?;
            let (mut selected, mut request) = connection.accept_bi().await?;
            assert!(!request.read_to_end(8192).await?.is_empty());
            selected.write_all(&head(b"200", &[b"0"])?).await?;
            let (mut healthy, mut request) = connection.accept_bi().await?;
            assert!(!request.read_to_end(8192).await?.is_empty());
            healthy.write_all(&head(b"200", &[b"2"])?).await?;
            // The healthy response is live before the invalid DATA is sent.
            selected.write_all(b"\x00\x01x").await?;
            assert_eq!(
                selected.stopped().await?,
                Some(quinn::VarInt::from_u32(0x10e))
            );
            healthy.write_all(b"\x00\x02ok").await?;
            healthy.finish()?;
            let (mut reused, mut request) = connection.accept_bi().await?;
            assert!(!request.read_to_end(8192).await?.is_empty());
            reused.write_all(&head(b"200", &[b"0"])?).await?;
            reused.finish()?;
            received.await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(caller, observer)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "HTTP/3 invalid-length isolation test timed out")?
}
