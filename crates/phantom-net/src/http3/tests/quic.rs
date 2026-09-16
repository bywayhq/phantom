use bytes::Bytes;
use http::{Request, Response, StatusCode};
use tokio::{sync::oneshot, time::timeout};

use super::{
    TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, client_config, join_server,
    next_optional_frame, send_test_request, server_endpoint,
};

#[tokio::test(flavor = "current_thread")]
async fn completes_after_one_server_retry() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let first = timeout(TEST_TIMEOUT, endpoint.accept())
            .await
            .map_err(|_| "initial QUIC attempt timed out")?
            .ok_or("test endpoint closed before the initial attempt")?;
        assert!(!first.remote_address_validated());
        assert!(first.may_retry());
        first.retry()?;

        let retried = timeout(TEST_TIMEOUT, async {
            for _ in 0..8 {
                let incoming = endpoint
                    .accept()
                    .await
                    .ok_or("test endpoint closed before the retried attempt")?;
                if incoming.remote_address_validated() {
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(incoming);
                }
                assert!(incoming.may_retry());
                incoming.ignore();
            }
            Err("too many unvalidated Initial retransmissions after Retry".into())
        })
        .await
        .map_err(|_| "retried QUIC attempt timed out")??;
        assert!(retried.remote_address_validated());
        assert!(!retried.may_retry());

        let connection = retried.await?;
        let mut connection: h3::server::Connection<_, Bytes> =
            h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
        let resolver = connection
            .accept()
            .await?
            .ok_or("client closed before sending the retried request")?;
        let (_request, mut stream) = resolver.resolve_request().await?;
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        let _ = done_received.await;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });

    let request = Request::get(format!(
        "https://{TEST_SERVER_NAME}:{}/retry",
        address.port()
    ))
    .body(())?;
    let response = timeout(
        TEST_TIMEOUT,
        send_test_request(address, TEST_SERVER_NAME, client, request),
    )
    .await
    .map_err(|_| "HTTP/3 request did not complete after Retry")??;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let mut body = response.into_body();
    assert!(next_optional_frame(&mut body).await?.is_none());

    let _ = client_done.send(());
    join_server(server).await
}
