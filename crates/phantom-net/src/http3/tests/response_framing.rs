//! Literal QPACK/QUIC peers, independent of the HTTP/3 response encoder.

use http::{Method, Request};
use http_body_util::BodyExt;
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

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
    for lengths in [
        vec![b"x".as_slice()],
        vec![b"1".as_slice(), b"2"],
        vec![b"18446744073709551616".as_slice()],
    ] {
        exchange(Method::GET, b"200", &lengths, b"", true).await?;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn response_accepts_exact_streaming_and_bodyless_metadata_lengths() -> TestResult<()> {
    exchange(Method::GET, b"200", &[b"1"], b"x", false).await?;
    exchange(Method::GET, b"200", &[b"1", b"01"], b"x", false).await?;
    exchange(Method::GET, b"200", &[b"1, 01"], b"x", false).await?;
    exchange(Method::GET, b"200", &[], b"x", false).await?;
    exchange(Method::HEAD, b"200", &[b"123"], b"", false).await?;
    exchange(Method::GET, b"304", &[b"123"], b"", false).await?;
    exchange(Method::GET, b"204", &[], b"", false).await?;
    exchange(Method::GET, b"205", &[], b"", false).await?;
    exchange(Method::GET, b"205", &[b"0"], b"", false).await
}

#[tokio::test(flavor = "current_thread")]
async fn short_response_with_trailers_does_not_publish_retained_fields() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let client = client_config(&identity)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (done, received) = oneshot::channel();
        let caller = async {
            let connection =
                crate::http3::connect_direct(address, TEST_SERVER_NAME, client, &test_settings())
                    .await?;
            let mut body = connection
                .send_request(
                    Request::get(format!("https://{TEST_SERVER_NAME}:{}/", address.port()))
                        .body(())?,
                    None,
                )
                .await?
                .into_body();
            assert_eq!(
                body.frame()
                    .await
                    .ok_or("missing short DATA")??
                    .into_data()
                    .ok(),
                Some(bytes::Bytes::from_static(b"x"))
            );
            let error = body
                .frame()
                .await
                .ok_or("short body ended successfully")?
                .err()
                .ok_or("short body published successful trailers")?;
            assert_eq!(error.kind(), Http3ErrorKind::Protocol);
            assert!(body.take_received_trailers().is_none());
            assert!(body.frame().await.is_none());
            done.send(()).map_err(|()| "peer dropped completion")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let observer = async {
            let (connection, _send, _receive) = raw_connection(&endpoint).await?;
            let (mut response, mut request) = connection.accept_bi().await?;
            assert!(!request.read_to_end(8192).await?.is_empty());
            response.write_all(&head(b"200", &[b"2"])?).await?;
            response.write_all(b"\x00\x01x").await?;
            // Literal trailer a:1, following the underlength DATA section.
            response.write_all(b"\x01\x06\x00\x00\x21a\x011").await?;
            response.finish()?;
            received.await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(caller, observer)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "HTTP/3 short-body trailer test timed out")?
}

#[tokio::test(flavor = "current_thread")]
async fn response_rejects_data_for_bodyless_status_or_method() -> TestResult<()> {
    exchange(Method::HEAD, b"200", &[b"1"], b"x", true).await?;
    exchange(Method::GET, b"304", &[b"1"], b"x", true).await?;
    exchange(Method::GET, b"204", &[], b"x", true).await?;
    exchange(Method::GET, b"205", &[], b"x", true).await
}

#[tokio::test(flavor = "current_thread")]
async fn response_rejects_forbidden_bodyless_content_length() -> TestResult<()> {
    exchange(Method::GET, b"204", &[b"0"], b"", true).await?;
    exchange(Method::GET, b"205", &[b"1"], b"", true).await
}

#[tokio::test(flavor = "current_thread")]
async fn malformed_continue_does_not_release_the_waiting_request_body() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let client = client_config(&identity)?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (done, received) = oneshot::channel();
        let polls = Arc::new(AtomicUsize::new(0));
        let observed = polls.clone();
        let source = http_body_util::Full::new(bytes::Bytes::from_static(b"payload")).map_frame(
            move |frame| {
                observed.fetch_add(1, Ordering::SeqCst);
                frame
            },
        );
        let prepared = crate::http3::request::prepare_profiled_request_body(
            &phantom_profile::browser::chrome::v154_http3_request(),
            Method::POST,
            TEST_SERVER_NAME,
            crate::request::OriginForm::parse("/upload")?,
            Vec::new(),
            Some(
                crate::request::RequestBody::streaming(source)
                    .expect_continue(Duration::from_secs(30)),
            ),
        )?;
        let caller = async {
            let connection =
                crate::http3::connect_direct(address, TEST_SERVER_NAME, client, &test_settings())
                    .await?;
            let error = connection
                .send_prepared_request(prepared)
                .await
                .err()
                .ok_or("malformed Continue was accepted")?;
            assert_eq!(error.kind(), Http3ErrorKind::Protocol);
            assert_eq!(polls.load(Ordering::SeqCst), 0);
            done.send(()).map_err(|()| "peer dropped completion")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let observer = async {
            let (connection, _send, _receive) = raw_connection(&endpoint).await?;
            let (mut response, mut request) = connection.accept_bi().await?;
            // Read exactly the request HEADERS; the upload must remain gated.
            let mut byte = [0];
            request.read_exact(&mut byte).await?;
            assert_eq!(byte[0], 1);
            request.read_exact(&mut byte).await?;
            let width = 1usize << (byte[0] >> 6);
            let mut length = usize::from(byte[0] & 63);
            for _ in 1..width {
                request.read_exact(&mut byte).await?;
                length = (length << 8) | usize::from(byte[0]);
            }
            assert!(length <= 8192);
            request.read_exact(&mut vec![0; length]).await?;
            response.write_all(&head(b"100", &[b"0"])?).await?;
            match request.read_chunk(1, true).await {
                Err(quinn::ReadError::Reset(code)) => {
                    assert_eq!(code, quinn::VarInt::from_u32(0x10e));
                }
                _ => return Err("malformed Continue released or failed to reset the upload".into()),
            }
            received.await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(caller, observer)?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "HTTP/3 malformed Continue test timed out")?
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
