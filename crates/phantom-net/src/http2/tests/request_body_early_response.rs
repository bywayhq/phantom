use std::{future::poll_fn, time::Duration};

use bytes::Bytes;
use http::{Method, Response, StatusCode};
use http_body_util::BodyExt;
use phantom_profile::chromium::v152_http2;
use tokio::time::timeout;

use super::{PEER_TEST_TIMEOUT, TestResult, bounded_peer_test};
use crate::http2::{Http2Connection, OriginForm, RequestBody};

#[tokio::test]
async fn early_final_response_cancels_upload_and_preserves_connection() -> TestResult<()> {
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(run_peer(server));
        let connection = Http2Connection::connect(client, &v152_http2()).await?;

        let response = timeout(
            Duration::from_secs(1),
            connection.send_request_body(
                Method::POST,
                "example.test",
                OriginForm::parse("/upload")?,
                Vec::new(),
                Some(RequestBody::streaming(http_body_util::Full::new(
                    Bytes::from(vec![b'R'; 70_000]),
                ))),
            ),
        )
        .await
        .map_err(|_| "early final response was blocked behind the upload")?
        .map_err(|error| format!("initial request failed: {error:?}"))?;
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        response
            .into_body()
            .collect()
            .await
            .map_err(|error| format!("early response body failed: {error:?}"))?;

        let followup = match connection
            .send_get(
                "example.test",
                OriginForm::parse("/after-early-response")?,
                Vec::new(),
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                let peer_result = peer.await;
                return Err(format!(
                    "follow-up request failed: {error:?}; peer result: {peer_result:?}"
                )
                .into());
            }
        };
        assert_eq!(followup.status(), StatusCode::NO_CONTENT);
        followup.into_body().collect().await?;
        drop(connection);
        peer.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn early_incomplete_response_keeps_uploading_until_the_body_is_sent() -> TestResult<()> {
    const UPLOAD_BYTES: usize = 200_000;
    bounded_peer_test(async {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let peer = tokio::spawn(run_streaming_peer(server, UPLOAD_BYTES));
        let connection = Http2Connection::connect(client, &v152_http2()).await?;

        let response = connection
            .send_request_body(
                Method::POST,
                "example.test",
                OriginForm::parse("/duplex")?,
                Vec::new(),
                Some(RequestBody::streaming(http_body_util::Full::new(
                    Bytes::from(vec![b'U'; UPLOAD_BYTES]),
                ))),
            )
            .await
            .map_err(|error| format!("request failed: {error:?}"))?;
        assert_eq!(response.status(), StatusCode::OK);
        let body = response
            .into_body()
            .collect()
            .await
            .map_err(|error| format!("response body failed: {error:?}"))?
            .to_bytes();

        assert_eq!(peer.await??, UPLOAD_BYTES);
        assert_eq!(body, UPLOAD_BYTES.to_string());
        Ok(())
    })
    .await
}

/// Answers with headers first, then responds only after the whole request
/// body arrives, like a streaming or full-duplex endpoint.
async fn run_streaming_peer(stream: tokio::io::DuplexStream, expected: usize) -> TestResult<usize> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before the upload")??;
    let mut response =
        respond.send_response(Response::builder().status(StatusCode::OK).body(())?, false)?;

    let mut incoming = request.into_body();
    let mut received = 0;
    let body_finished = poll_fn(|context| {
        loop {
            match incoming.poll_data(context) {
                std::task::Poll::Ready(Some(Ok(data))) => {
                    received += data.len();
                    let _ = incoming.flow_control().release_capacity(data.len());
                }
                std::task::Poll::Ready(Some(Err(error))) => {
                    return std::task::Poll::Ready(Err(error));
                }
                std::task::Poll::Ready(None) => return std::task::Poll::Ready(Ok(())),
                std::task::Poll::Pending => break,
            }
        }
        match connection.poll_closed(context) {
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
            std::task::Poll::Ready(Ok(())) | std::task::Poll::Pending => std::task::Poll::Pending,
        }
    });
    timeout(PEER_TEST_TIMEOUT, body_finished)
        .await
        .map_err(|_| "client stopped uploading after the early response head")??;
    assert_eq!(received, expected);

    response.send_data(Bytes::from(received.to_string()), true)?;
    tokio::spawn(async move { poll_fn(|context| connection.poll_closed(context)).await });
    Ok(received)
}

async fn run_peer(stream: tokio::io::DuplexStream) -> TestResult<()> {
    let mut builder = ::http2::server::Builder::new();
    builder.initial_window_size(0);
    let mut connection = builder.handshake::<_, Bytes>(stream).await?;

    let (request, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before the upload")??;
    assert_eq!(request.method(), Method::POST);
    assert_eq!(request.uri().path(), "/upload");
    let mut response = respond.send_response(
        Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .body(())?,
        true,
    )?;
    let reset = timeout(
        PEER_TEST_TIMEOUT,
        poll_fn(|context| {
            if let std::task::Poll::Ready(result) = response.poll_reset(context) {
                return std::task::Poll::Ready(result);
            }
            match connection.poll_closed(context) {
                std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
                std::task::Poll::Ready(Ok(())) | std::task::Poll::Pending => {
                    std::task::Poll::Pending
                }
            }
        }),
    )
    .await
    .map_err(|_| "early final response did not cancel the upload")??;
    assert_eq!(reset, ::http2::Reason::CANCEL);
    drop(request);
    drop(response);
    drop(respond);

    let (followup, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before the follow-up request")??;
    assert_eq!(followup.uri().path(), "/after-early-response");
    respond.send_response(
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(())?,
        true,
    )?;
    drop(followup);
    drop(respond);
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(())
}
