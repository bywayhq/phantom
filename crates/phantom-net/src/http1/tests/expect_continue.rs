use std::time::Duration;

use bytes::Bytes;
use http::Method;
use http_body_util::BodyExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    time::timeout,
};

use super::{TestResult, bounded_peer_test, host, read_head, target};
use crate::{
    http1::{Http1Error, RequestHeader, send_request_body},
    request::RequestBody,
};

/// Longer than any test runs, so only `100 Continue` releases the body.
const LONG_WAIT: Duration = Duration::from_secs(30);
/// Long enough that a body that did not wait would arrive within it.
const NO_BODY_WINDOW: Duration = Duration::from_millis(100);

fn waiting_body(bytes: &'static [u8]) -> RequestBody {
    RequestBody::from_bytes(Bytes::from_static(bytes)).expect_continue(LONG_WAIT)
}

#[tokio::test]
async fn generated_expectation_follows_framing_and_the_body_waits_for_100() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let transaction = tokio::spawn(send_request_body(
            client,
            Method::POST,
            target()?,
            vec![host(), RequestHeader::new("X-Order", "before-length")],
            Some(waiting_body(b"payload")),
        ));

        let head = read_head(&mut server).await?;
        assert_eq!(
            head,
            b"POST /resource?item=1 HTTP/1.1\r\nHost: example.test\r\nX-Order: before-length\r\nContent-Length: 7\r\nExpect: 100-continue\r\n\r\n"
        );
        let mut byte = [0_u8; 1];
        assert!(
            timeout(NO_BODY_WINDOW, server.read_exact(&mut byte))
                .await
                .is_err(),
            "the body did not wait for 100 Continue"
        );

        server.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        let mut body = [0_u8; 7];
        server.read_exact(&mut body).await?;
        assert_eq!(&body, b"payload");
        server
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await?;
        transaction.await??.into_body().collect().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_caller_expectation_keeps_its_spelling_and_position() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let transaction = tokio::spawn(send_request_body(
            client,
            Method::PUT,
            target()?,
            vec![
                host(),
                RequestHeader::new("EXPECT", "100-Continue"),
                RequestHeader::new("X-After", "1"),
            ],
            Some(waiting_body(b"data")),
        ));

        let head = read_head(&mut server).await?;
        assert_eq!(
            head,
            b"PUT /resource?item=1 HTTP/1.1\r\nHost: example.test\r\nEXPECT: 100-Continue\r\nX-After: 1\r\nContent-Length: 4\r\n\r\n"
        );
        server.write_all(b"HTTP/1.1 100 Continue\r\n\r\n").await?;
        let mut body = [0_u8; 4];
        server.read_exact(&mut body).await?;
        assert_eq!(&body, b"data");
        server
            .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
            .await?;
        transaction.await??.into_body().collect().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_empty_body_sends_no_expectation() -> TestResult {
    bounded_peer_test(async {
        let (client, mut server) = duplex(4096);
        let transaction = tokio::spawn(send_request_body(
            client,
            Method::POST,
            target()?,
            vec![host()],
            Some(waiting_body(b"")),
        ));

        let head = read_head(&mut server).await?;
        assert!(
            !head
                .to_ascii_lowercase()
                .windows(7)
                .any(|w| w == b"expect:"),
            "an empty body sent an expectation: {}",
            String::from_utf8_lossy(&head)
        );
        server.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
        transaction.await??.into_body().collect().await?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_caller_expectation_other_than_100_continue_never_touches_the_stream() -> TestResult {
    for headers in [
        vec![host(), RequestHeader::new("Expect", "gzip")],
        vec![
            host(),
            RequestHeader::new("Expect", "100-continue"),
            RequestHeader::new("expect", "100-continue"),
        ],
    ] {
        let invalid_index = headers.len() - 1;
        let (client, mut server) = duplex(64);
        let result = send_request_body(
            client,
            Method::POST,
            target()?,
            headers,
            Some(waiting_body(b"data")),
        )
        .await;
        assert!(
            matches!(
                result,
                Err(Http1Error::InvalidHeaderValue { index, .. }) if index == invalid_index
            ),
            "unexpected result: {result:?}"
        );
        let mut received = Vec::new();
        server.read_to_end(&mut received).await?;
        assert!(received.is_empty());
    }
    Ok(())
}
