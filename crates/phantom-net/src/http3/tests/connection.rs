use bytes::{Buf, Bytes};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
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
            connection.send_request(test_request(address.port(), path)?, None),
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
async fn response_trailers_preserve_body_and_connection_reuse() -> TestResult<()> {
    const TOKEN: &str = "0123456789abcdef0123456789abcdef";
    const RESOURCE: &str = "/.well-known/phantom/h3-trailers-body/0123456789abcdef0123456789abcdef";
    const CALLBACK: &str = "/.well-known/phantom/h3-trailers/0123456789abcdef0123456789abcdef";

    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        let (request, mut stream) = accept_stream(&mut connection).await?;
        assert_eq!(request.uri().path(), RESOURCE);
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        stream
            .send_data(Bytes::from_static(b"phantom-h3-response-trailers-v1\n"))
            .await?;
        let mut trailers = HeaderMap::new();
        trailers.insert("x-phantom-trailer-token", HeaderValue::from_static(TOKEN));
        stream.send_trailers(trailers).await?;
        stream.finish().await?;

        let (request, mut callback) = accept_stream(&mut connection).await?;
        assert_eq!(request.uri().path(), CALLBACK);
        send_response(&mut callback, "complete").await?;
        let _ = done_received.await;
        Ok(())
    });

    let connection = timeout(
        TEST_TIMEOUT,
        super::super::connect_direct(address, TEST_SERVER_NAME, client, &test_settings()),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??;
    let response = timeout(
        TEST_TIMEOUT,
        connection.send_request(test_request(address.port(), RESOURCE)?, None),
    )
    .await
    .map_err(|_| "HTTP/3 trailers response timed out")??;
    let body = timeout(TEST_TIMEOUT, response.into_body().collect())
        .await
        .map_err(|_| "HTTP/3 trailers body timed out")??;
    assert_eq!(
        body.trailers()
            .and_then(|trailers| trailers.get("x-phantom-trailer-token")),
        Some(&HeaderValue::from_static(TOKEN))
    );
    assert_eq!(
        body.to_bytes(),
        Bytes::from_static(b"phantom-h3-response-trailers-v1\n")
    );

    let callback = timeout(
        TEST_TIMEOUT,
        connection.send_request(test_request(address.port(), CALLBACK)?, None),
    )
    .await
    .map_err(|_| "request after HTTP/3 trailers timed out")??;
    assert_eq!(collect_body(callback.into_body()).await?, "complete");

    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn owned_body_is_flow_controlled_and_received_exactly() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();
    let expected = Bytes::from(vec![b'x'; 2 * 1024 * 1024]);
    let server_expected = expected.clone();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        let (request, mut stream) = accept_stream(&mut connection).await?;
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri().path(), "/upload");
        assert_eq!(
            request
                .headers()
                .get("content-length")
                .and_then(|value| value.to_str().ok()),
            Some("2097152")
        );

        let mut received = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            let remaining = chunk.remaining();
            received.extend_from_slice(&chunk.copy_to_bytes(remaining));
        }
        assert_eq!(Bytes::from(received), server_expected);
        send_response(&mut stream, "accepted").await?;
        let _ = done_received.await;
        Ok(())
    });

    let connection = timeout(
        TEST_TIMEOUT,
        super::super::connect_direct(address, TEST_SERVER_NAME, client, &test_settings()),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??;
    let request = Request::post(format!(
        "https://{TEST_SERVER_NAME}:{}/upload",
        address.port()
    ))
    .body(())?;
    let response = timeout(
        TEST_TIMEOUT,
        connection.send_request(request, Some(expected)),
    )
    .await
    .map_err(|_| "HTTP/3 upload timed out")??;
    assert_eq!(collect_body(response.into_body()).await?, "accepted");

    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn early_final_response_and_stop_sending_preserve_connection_reuse() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        let (request, mut rejected) = accept_stream(&mut connection).await?;
        assert_eq!(request.method(), http::Method::POST);
        assert_eq!(request.uri().path(), "/rejected");
        rejected
            .send_response(
                Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(())?,
            )
            .await?;
        rejected.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
        rejected.finish().await?;

        let (request, mut later) = accept_stream(&mut connection).await?;
        assert_eq!(request.uri().path(), "/later");
        send_response(&mut later, "later").await?;
        let _ = done_received.await;
        Ok(())
    });

    let connection = timeout(
        TEST_TIMEOUT,
        super::super::connect_direct(address, TEST_SERVER_NAME, client, &test_settings()),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??;
    let rejected = timeout(
        TEST_TIMEOUT,
        connection.send_request(
            Request::post(format!(
                "https://{TEST_SERVER_NAME}:{}/rejected",
                address.port()
            ))
            .body(())?,
            Some(Bytes::from(vec![b'x'; 8 * 1024 * 1024])),
        ),
    )
    .await
    .map_err(|_| "early HTTP/3 response timed out")??;
    assert_eq!(rejected.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(collect_body(rejected.into_body()).await?.is_empty());

    let later = connection
        .send_request(test_request(address.port(), "/later")?, None)
        .await?;
    assert_eq!(collect_body(later.into_body()).await?, "later");

    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn cancelling_body_upload_resets_only_that_stream() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (request_seen, request_received) = oneshot::channel();
    let (check_cancel, cancellation_requested) = oneshot::channel();
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        let (request, mut cancelled) = accept_stream(&mut connection).await?;
        assert_eq!(request.uri().path(), "/cancel-upload");
        let _ = request_seen.send(());
        let _ = cancellation_requested.await;
        loop {
            match cancelled.recv_data().await {
                Ok(Some(_)) => {}
                Err(h3::error::StreamError::RemoteTerminate { code, .. })
                    if code == h3::error::Code::H3_REQUEST_CANCELLED =>
                {
                    break;
                }
                Ok(None) => return Err("cancelled upload completed normally".into()),
                Err(error) => return Err(format!("unexpected upload cancellation: {error}").into()),
            }
        }

        let (request, mut later) = accept_stream(&mut connection).await?;
        assert_eq!(request.uri().path(), "/after-cancel");
        send_response(&mut later, "reused").await?;
        let _ = done_received.await;
        Ok(())
    });

    let connection = timeout(
        TEST_TIMEOUT,
        super::super::connect_direct(address, TEST_SERVER_NAME, client, &test_settings()),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??;
    let request = Request::post(format!(
        "https://{TEST_SERVER_NAME}:{}/cancel-upload",
        address.port()
    ))
    .body(())?;
    let upload_connection = connection.clone();
    let pending = tokio::spawn(async move {
        upload_connection
            .send_request(request, Some(Bytes::from(vec![b'x'; 8 * 1024 * 1024])))
            .await
    });
    request_received.await?;
    pending.abort();
    let _ = pending.await;
    let _ = check_cancel.send(());

    let later = timeout(
        TEST_TIMEOUT,
        connection.send_request(test_request(address.port(), "/after-cancel")?, None),
    )
    .await
    .map_err(|_| "request after upload cancellation timed out")??;
    assert_eq!(collect_body(later.into_body()).await?, "reused");

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
    let fast = connection.send_request(test_request(address.port(), "/fast")?, None);
    let slow = connection.send_request(test_request(address.port(), "/slow")?, None);
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
        connection.send_request(test_request(address.port(), "/cancel")?, None),
    )
    .await
    .map_err(|_| "cancelled HTTP/3 response head timed out")??;
    drop(cancelled);

    let later = timeout(
        TEST_TIMEOUT,
        connection.send_request(test_request(address.port(), "/later")?, None),
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
        .send_request(test_request(address.port(), "/before-goaway")?, None)
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
            .send_request(test_request(address.port(), "/after-goaway")?, None)
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
