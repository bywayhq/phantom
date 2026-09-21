use std::{
    collections::VecDeque,
    error::Error as _,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::BodyExt;
use tokio::{sync::oneshot, time::timeout};

use super::{
    TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, client_config, join_server,
    server_endpoint, test_settings,
};
use crate::request::RequestHeader;
use crate::request::{RequestBody, RequestBodyError, RequestBodyErrorKind, RequestTrailerName};

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
async fn static_trailers_follow_data_and_support_trailer_only_requests() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        for (path, expected_body) in [
            ("/data-and-trailers", Bytes::from_static(b"payload")),
            ("/trailers-only", Bytes::new()),
        ] {
            let (request, mut stream) = accept_stream(&mut connection).await?;
            assert_eq!(request.uri().path(), path);
            assert_eq!(collect_request_body(&mut stream).await?, expected_body);
            let trailers = stream.recv_trailers().await?.ok_or("trailers missing")?;
            assert_eq!(
                trailers
                    .get_all("x-repeat")
                    .iter()
                    .map(HeaderValue::as_bytes)
                    .collect::<Vec<_>>(),
                [b"alpha".as_slice(), b"beta".as_slice()]
            );
            assert!(
                trailers
                    .get("x-secret")
                    .is_some_and(HeaderValue::is_sensitive)
            );
            send_response(&mut stream, "accepted").await?;
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
    for (path, body) in [
        (
            "/data-and-trailers",
            Some(RequestBody::from_bytes(Bytes::from_static(b"payload"))),
        ),
        ("/trailers-only", None),
    ] {
        let prepared = crate::http3::request::prepare_profiled_request_body_with_trailers(
            &phantom_profile::chromium::v152_http3_request(),
            http::Method::POST,
            TEST_SERVER_NAME,
            crate::http3::OriginForm::parse(path)?,
            Vec::new(),
            body,
            vec![
                RequestHeader::new("x-repeat", "alpha"),
                RequestHeader::new("x-secret", "value").sensitive(),
                RequestHeader::new("x-repeat", "beta"),
            ],
        )?;
        let response = timeout(TEST_TIMEOUT, connection.send_prepared_request(prepared))
            .await
            .map_err(|_| "static request trailers timed out")??;
        assert_eq!(collect_body(response.into_body()).await?, "accepted");
    }

    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn body_produced_trailers_follow_the_declared_order_and_sensitivity() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        let (request, mut stream) = accept_stream(&mut connection).await?;
        assert_eq!(request.uri().path(), "/dynamic-trailers");
        assert_eq!(collect_request_body(&mut stream).await?, b"data".as_slice());
        let trailers = stream
            .recv_trailers()
            .await?
            .ok_or("dynamic trailers missing")?;
        assert_eq!(
            trailers
                .get_all("x-repeat")
                .iter()
                .map(HeaderValue::as_bytes)
                .collect::<Vec<_>>(),
            [b"first".as_slice(), b"second".as_slice()]
        );
        assert!(
            trailers
                .get("x-middle")
                .is_some_and(HeaderValue::is_sensitive)
        );
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
        "https://{TEST_SERVER_NAME}:{}/dynamic-trailers",
        address.port()
    ))
    .body(())?;
    let prepared =
        crate::http3::request::prepare_request_body(request, Some(dynamic_trailer_body(false)))?;
    let response = timeout(TEST_TIMEOUT, connection.send_prepared_request(prepared))
        .await
        .map_err(|_| "dynamic request trailers timed out")??;
    assert_eq!(collect_body(response.into_body()).await?, "accepted");

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
async fn streaming_body_frames_are_received_exactly_without_content_length() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        let (request, mut stream) = accept_stream(&mut connection).await?;
        assert_eq!(request.uri().path(), "/stream-upload");
        assert!(request.headers().get("content-length").is_none());
        assert_eq!(collect_request_body(&mut stream).await?, "alphabetagamma");
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
        "https://{TEST_SERVER_NAME}:{}/stream-upload",
        address.port()
    ))
    .body(())?;
    let body = RequestBody::streaming(TestBody::data([
        Bytes::from_static(b"alpha"),
        Bytes::from_static(b"beta"),
        Bytes::from_static(b"gamma"),
    ]));
    let prepared = crate::http3::request::prepare_request_body(request, Some(body))?;
    let response = timeout(TEST_TIMEOUT, connection.send_prepared_request(prepared))
        .await
        .map_err(|_| "streaming HTTP/3 upload timed out")??;
    assert_eq!(collect_body(response.into_body()).await?, "accepted");

    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn streaming_body_failures_reset_only_their_streams() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        loop {
            let resolver = connection
                .accept()
                .await?
                .ok_or("client closed before sending a request")?;
            let (request, mut failed) = match resolver.resolve_request().await {
                Ok(stream) => stream,
                Err(h3::error::StreamError::RemoteTerminate { code, .. })
                    if code == h3::error::Code::H3_REQUEST_CANCELLED =>
                {
                    continue;
                }
                Err(error) => return Err(error.into()),
            };
            if request.uri().path() == "/after-source-error" {
                send_response(&mut failed, "reused").await?;
                break;
            }
            assert!(matches!(
                request.uri().path(),
                "/source-error" | "/trailers" | "/trailer-mismatch" | "/length-mismatch"
            ));
            loop {
                match failed.recv_data().await {
                    Ok(Some(_)) => {}
                    Err(h3::error::StreamError::RemoteTerminate { code, .. })
                        if code == h3::error::Code::H3_REQUEST_CANCELLED =>
                    {
                        break;
                    }
                    Ok(None) => return Err("failed streaming upload completed normally".into()),
                    Err(error) => {
                        return Err(format!("unexpected upload failure: {error}").into());
                    }
                }
            }
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
    for (path, body, expected_kind) in [
        (
            "/source-error",
            RequestBody::streaming(TestBody::source_error()),
            RequestBodyErrorKind::Source,
        ),
        (
            "/trailers",
            RequestBody::streaming(TestBody::trailers()),
            RequestBodyErrorKind::TrailersUnsupported,
        ),
        (
            "/length-mismatch",
            RequestBody::streaming(TestBody::length_mismatch()),
            RequestBodyErrorKind::LengthMismatch,
        ),
        (
            "/trailer-mismatch",
            dynamic_trailer_body(true),
            RequestBodyErrorKind::TrailersMismatch,
        ),
    ] {
        let request = Request::post(format!(
            "https://{TEST_SERVER_NAME}:{}{path}",
            address.port()
        ))
        .body(())?;
        let static_trailers = if path == "/trailer-mismatch" {
            Vec::new()
        } else {
            vec![RequestHeader::new("x-must-not-arrive", "value")]
        };
        let prepared = crate::http3::request::prepare_request_body_with_trailers(
            request,
            Some(body),
            static_trailers,
        )?;
        let error = timeout(TEST_TIMEOUT, connection.send_prepared_request(prepared))
            .await
            .map_err(|_| "streaming body error timed out")?
            .err()
            .ok_or("invalid streaming body was accepted")?;
        assert_eq!(error.kind(), super::super::Http3ErrorKind::Request);
        let body_error = error
            .source()
            .and_then(|source| source.downcast_ref::<RequestBodyError>())
            .ok_or("HTTP/3 error omitted typed request-body source")?;
        assert_eq!(body_error.kind(), expected_kind);
    }

    let later = timeout(
        TEST_TIMEOUT,
        connection.send_request(test_request(address.port(), "/after-source-error")?, None),
    )
    .await
    .map_err(|_| "request after body source error timed out")??;
    assert_eq!(collect_body(later.into_body()).await?, "reused");

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
async fn early_response_head_keeps_uploading_beside_the_response_body() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        let (request, mut stream) = accept_stream(&mut connection).await?;
        assert_eq!(request.uri().path(), "/echo");
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        let upload = collect_request_body(&mut stream).await?;
        stream.send_data(upload).await?;
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
    let (chunks, body) = ChannelBody::new();
    chunks.send(Ok(Bytes::from_static(b"early-"))).await?;
    let request = Request::post(format!(
        "https://{TEST_SERVER_NAME}:{}/echo",
        address.port()
    ))
    .body(())?;
    let prepared =
        crate::http3::request::prepare_request_body(request, Some(RequestBody::streaming(body)))?;
    let response = timeout(TEST_TIMEOUT, connection.send_prepared_request(prepared))
        .await
        .map_err(|_| "early HTTP/3 response head timed out")??;
    assert_eq!(response.status(), StatusCode::OK);

    chunks.send(Ok(Bytes::from_static(b"late"))).await?;
    drop(chunks);
    assert_eq!(collect_body(response.into_body()).await?, "early-late");

    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn complete_early_response_stops_the_unfinished_upload() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        let (request, mut stream) = accept_stream(&mut connection).await?;
        assert_eq!(request.uri().path(), "/complete-early");
        send_response(&mut stream, "complete").await?;
        loop {
            match stream.recv_data().await {
                Ok(Some(_)) => {}
                Err(h3::error::StreamError::RemoteTerminate { code, .. })
                    if code == h3::error::Code::H3_REQUEST_CANCELLED =>
                {
                    break;
                }
                Ok(None) => return Err("unfinished upload ended with FIN".into()),
                Err(error) => return Err(format!("unexpected upload end: {error}").into()),
            }
        }

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
    let (chunks, body) = ChannelBody::new();
    chunks.send(Ok(Bytes::from_static(b"partial"))).await?;
    let request = Request::post(format!(
        "https://{TEST_SERVER_NAME}:{}/complete-early",
        address.port()
    ))
    .body(())?;
    let prepared =
        crate::http3::request::prepare_request_body(request, Some(RequestBody::streaming(body)))?;
    let response = timeout(TEST_TIMEOUT, connection.send_prepared_request(prepared))
        .await
        .map_err(|_| "early HTTP/3 response head timed out")??;
    assert_eq!(collect_body(response.into_body()).await?, "complete");

    let later = timeout(
        TEST_TIMEOUT,
        connection.send_request(test_request(address.port(), "/later")?, None),
    )
    .await
    .map_err(|_| "request after the early response timed out")??;
    assert_eq!(collect_body(later.into_body()).await?, "later");

    drop(chunks);
    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn upload_failure_after_early_response_head_fails_the_response_body() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let mut connection = accept_connection(&endpoint).await?;
        let (request, mut stream) = accept_stream(&mut connection).await?;
        assert_eq!(request.uri().path(), "/fails-late");
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        loop {
            match stream.recv_data().await {
                Ok(Some(_)) => {}
                Err(h3::error::StreamError::RemoteTerminate { code, .. })
                    if code == h3::error::Code::H3_REQUEST_CANCELLED =>
                {
                    break;
                }
                Ok(None) => return Err("failed upload ended with FIN".into()),
                Err(error) => return Err(format!("unexpected upload end: {error}").into()),
            }
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
    let (chunks, body) = ChannelBody::new();
    chunks.send(Ok(Bytes::from_static(b"prefix"))).await?;
    let request = Request::post(format!(
        "https://{TEST_SERVER_NAME}:{}/fails-late",
        address.port()
    ))
    .body(())?;
    let prepared =
        crate::http3::request::prepare_request_body(request, Some(RequestBody::streaming(body)))?;
    let response = timeout(TEST_TIMEOUT, connection.send_prepared_request(prepared))
        .await
        .map_err(|_| "early HTTP/3 response head timed out")??;

    chunks
        .send(Err(std::io::Error::other("synthetic late body failure")))
        .await?;
    let error = timeout(TEST_TIMEOUT, response.into_body().collect())
        .await
        .map_err(|_| "HTTP/3 response body timed out")?
        .err()
        .ok_or("response body completed after its upload failed")?;
    assert_eq!(error.kind(), super::super::Http3ErrorKind::Request);

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
        while connection.is_reusable() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| "HTTP/3 GOAWAY was not observed")?;
    // GOAWAY was observed before the stream opened, so nothing was sent and
    // the failure carries the not-processed signal (RFC 9114, section 5.2).
    let refused = match connection
        .send_request(test_request(address.port(), "/after-goaway")?, None)
        .await
    {
        Ok(_) => return Err("request opened a stream after GOAWAY".into()),
        Err(error) => error,
    };
    assert_eq!(
        refused.unprocessed(),
        Some(super::super::Http3Unprocessed::GoAway)
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

async fn collect_request_body(stream: &mut ServerStream) -> TestResult<Bytes> {
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        let remaining = chunk.remaining();
        body.extend_from_slice(&chunk.copy_to_bytes(remaining));
    }
    Ok(Bytes::from(body))
}

struct ChannelBody {
    chunks: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
}

impl ChannelBody {
    fn new() -> (
        tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
        Self,
    ) {
        let (sender, chunks) = tokio::sync::mpsc::channel(1);
        (sender, Self { chunks })
    }
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.chunks
            .poll_recv(context)
            .map(|chunk| chunk.map(|chunk| chunk.map(Frame::data)))
    }
}

struct TestBody {
    frames: VecDeque<Result<Frame<Bytes>, std::io::Error>>,
    exact_length: Option<u64>,
}

impl TestBody {
    fn data<const N: usize>(chunks: [Bytes; N]) -> Self {
        Self {
            frames: chunks.into_iter().map(Frame::data).map(Ok).collect(),
            exact_length: None,
        }
    }

    fn source_error() -> Self {
        Self {
            frames: [
                Ok(Frame::data(Bytes::from_static(b"prefix"))),
                Err(std::io::Error::other("synthetic request body failure")),
            ]
            .into(),
            exact_length: None,
        }
    }

    fn trailers() -> Self {
        Self {
            frames: [Ok(Frame::trailers(HeaderMap::new()))].into(),
            exact_length: None,
        }
    }

    fn length_mismatch() -> Self {
        Self {
            frames: [Ok(Frame::data(Bytes::from_static(b"short")))].into(),
            exact_length: Some(7),
        }
    }
}

fn dynamic_trailer_body(mismatch: bool) -> RequestBody {
    let mut trailers = HeaderMap::new();
    let mut middle = HeaderValue::from_static("between");
    middle.set_sensitive(true);
    trailers.append("x-repeat", HeaderValue::from_static("first"));
    if mismatch {
        trailers.insert("x-other", middle);
    } else {
        trailers.insert("x-middle", middle);
    }
    trailers.append("x-repeat", HeaderValue::from_static("second"));
    RequestBody::streaming_with_trailers(
        TestBody {
            frames: [
                Ok(Frame::data(Bytes::from_static(b"data"))),
                Ok(Frame::trailers(trailers)),
            ]
            .into(),
            exact_length: None,
        },
        vec![
            RequestTrailerName::new("x-repeat"),
            RequestTrailerName::new("x-middle"),
            RequestTrailerName::new("x-repeat"),
        ],
    )
}

impl Body for TestBody {
    type Data = Bytes;
    type Error = std::io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Ready(self.frames.pop_front())
    }

    fn size_hint(&self) -> SizeHint {
        self.exact_length
            .map_or_else(SizeHint::default, SizeHint::with_exact)
    }
}

fn test_request(port: u16, path: &str) -> TestResult<Request<()>> {
    Ok(Request::get(format!("https://{TEST_SERVER_NAME}:{port}{path}")).body(())?)
}
