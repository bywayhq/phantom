use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use tokio::{sync::oneshot, time::timeout};

use super::{
    TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, client_config, join_server,
    server_endpoint, test_settings,
};

type ServerConnection = h3::server::Connection<h3_quinn::Connection, Bytes>;
type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[tokio::test(flavor = "current_thread")]
async fn sequential_requests_share_one_connection() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        for (path, payload) in [("/first", "first"), ("/second", "second")] {
            let (request, mut stream) = accept_stream(&mut connection).await?;
            assert_eq!(request.uri().path(), path);
            send_response(&mut stream, payload).await?;
        }
        let _ = done_received.await;
        Ok(())
    });

    let connection = timeout(
        TEST_TIMEOUT,
        super::super::connect_direct(address, TEST_SERVER_NAME, client, &test_settings()),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??;

    for (path, expected) in [("/first", "first"), ("/second", "second")] {
        let response = timeout(
            TEST_TIMEOUT,
            connection.send_request(test_request(address.port(), path)?),
        )
        .await
        .map_err(|_| "sequential HTTP/3 request timed out")??;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(collect_body(response.into_body()).await?, expected);
    }

    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn concurrent_request_bodies_complete_independently() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (release_slow, slow_released) = oneshot::channel();
    let (fast_finished, fast_observed) = oneshot::channel();
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        let mut fast = None;
        let mut slow = None;

        for _ in 0..2 {
            let (request, stream) = accept_stream(&mut connection).await?;
            match request.uri().path() {
                "/fast" => fast = Some(stream),
                "/slow" => slow = Some(stream),
                path => return Err(format!("unexpected request path: {path}").into()),
            }
        }

        let mut fast = fast.ok_or("fast request was not received")?;
        let mut slow = slow.ok_or("slow request was not received")?;
        slow.send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        send_response(&mut fast, "fast").await?;
        let _ = fast_finished.send(());

        let _ = slow_released.await;
        slow.send_data(Bytes::from_static(b"slow")).await?;
        slow.finish().await?;
        let _ = done_received.await;
        Ok(())
    });

    let connection = timeout(
        TEST_TIMEOUT,
        super::super::connect_direct(address, TEST_SERVER_NAME, client, &test_settings()),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??;
    let fast = connection.send_request(test_request(address.port(), "/fast")?);
    let slow = connection.send_request(test_request(address.port(), "/slow")?);
    let (fast, slow) = timeout(TEST_TIMEOUT, async { tokio::try_join!(fast, slow) })
        .await
        .map_err(|_| "concurrent HTTP/3 response heads timed out")??;

    assert_eq!(fast.status(), StatusCode::OK);
    assert_eq!(slow.status(), StatusCode::OK);
    assert_eq!(collect_body(fast.into_body()).await?, "fast");
    timeout(TEST_TIMEOUT, fast_observed)
        .await
        .map_err(|_| "fast response did not finish independently")??;

    let _ = release_slow.send(());
    assert_eq!(collect_body(slow.into_body()).await?, "slow");
    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_one_body_preserves_connection_reuse() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        let (request, mut cancelled) = accept_stream(&mut connection).await?;
        assert_eq!(request.uri().path(), "/cancel");
        cancelled
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;

        let (request, mut later) = accept_stream(&mut connection).await?;
        assert_eq!(request.uri().path(), "/later");
        send_response(&mut later, "later").await?;
        drop(cancelled);

        let _ = done_received.await;
        Ok(())
    });

    let connection = timeout(
        TEST_TIMEOUT,
        super::super::connect_direct(address, TEST_SERVER_NAME, client, &test_settings()),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??;
    let cancelled = timeout(
        TEST_TIMEOUT,
        connection.send_request(test_request(address.port(), "/cancel")?),
    )
    .await
    .map_err(|_| "cancelled HTTP/3 response head timed out")??;
    drop(cancelled);

    let later = timeout(
        TEST_TIMEOUT,
        connection.send_request(test_request(address.port(), "/later")?),
    )
    .await
    .map_err(|_| "HTTP/3 request after body drop timed out")??;
    assert_eq!(later.status(), StatusCode::OK);
    assert_eq!(collect_body(later.into_body()).await?, "later");

    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn goaway_stops_new_requests_without_cancelling_an_existing_body() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (goaway_sent, goaway_received) = oneshot::channel();
    let (release_body, body_released) = oneshot::channel();
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        let (request, mut stream) = accept_stream(&mut connection).await?;
        assert_eq!(request.uri().path(), "/before-goaway");
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        connection.shutdown(0).await?;
        let _ = goaway_sent.send(());

        let _ = body_released.await;
        stream.send_data(Bytes::from_static(b"complete")).await?;
        stream.finish().await?;
        let _ = done_received.await;
        Ok(())
    });

    let connection = timeout(
        TEST_TIMEOUT,
        super::super::connect_direct(address, TEST_SERVER_NAME, client, &test_settings()),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??;
    let response = connection
        .send_request(test_request(address.port(), "/before-goaway")?)
        .await?;
    goaway_received.await?;

    timeout(TEST_TIMEOUT, async {
        while connection.is_reusable().await {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "HTTP/3 GOAWAY was not observed")?;
    assert!(
        connection
            .send_request(test_request(address.port(), "/after-goaway")?)
            .await
            .is_err()
    );

    let _ = release_body.send(());
    assert_eq!(collect_body(response.into_body()).await?, "complete");
    let _ = client_done.send(());
    join_server(server).await
}

async fn accept_connection(endpoint: &quinn::Endpoint) -> TestResult<ServerConnection> {
    let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
    let connection = incoming.await?;
    Ok(h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?)
}

async fn accept_stream(
    connection: &mut ServerConnection,
) -> TestResult<(Request<()>, ServerStream)> {
    let resolver = connection
        .accept()
        .await?
        .ok_or("client closed before sending a request")?;
    Ok(resolver.resolve_request().await?)
}

async fn send_response(stream: &mut ServerStream, payload: &'static str) -> TestResult<()> {
    stream
        .send_response(Response::builder().status(StatusCode::OK).body(())?)
        .await?;
    stream
        .send_data(Bytes::from_static(payload.as_bytes()))
        .await?;
    stream.finish().await?;
    Ok(())
}

async fn collect_body(body: super::super::Http3Body) -> TestResult<Bytes> {
    let body = timeout(TEST_TIMEOUT, body.collect())
        .await
        .map_err(|_| "HTTP/3 response body timed out")??;
    Ok(body.to_bytes())
}

fn test_request(port: u16, path: &str) -> TestResult<Request<()>> {
    Ok(Request::get(format!("https://{TEST_SERVER_NAME}:{port}{path}")).body(())?)
}
