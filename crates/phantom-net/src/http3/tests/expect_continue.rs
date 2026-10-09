use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::ext::OrderedHeaders;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom_profile::browser::chrome;
use tokio::{sync::oneshot, time::timeout};

use super::{TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, client_config, join_server};
use crate::{
    http3::{Http3ErrorKind, OriginForm, RequestHeader},
    request::RequestBody,
};

/// Longer than any test runs, so only `100 Continue` releases the body.
const LONG_WAIT: Duration = Duration::from_secs(30);
/// Long enough that a body that did not wait would arrive within it.
const NO_BODY_WINDOW: Duration = Duration::from_millis(200);

type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

fn waiting_body() -> RequestBody {
    RequestBody::from_bytes(Bytes::from_static(b"payload")).expect_continue(LONG_WAIT)
}

fn prepare(
    headers: Vec<RequestHeader>,
) -> TestResult<Result<crate::http3::request::PreparedRequest, crate::http3::Http3Error>> {
    Ok(crate::http3::request::prepare_profiled_request_body(
        &chrome::v154_http3_request(),
        http::Method::POST,
        TEST_SERVER_NAME,
        OriginForm::parse("/upload")?,
        headers,
        Some(waiting_body()),
    ))
}

fn ordered_names(prepared: crate::http3::request::PreparedRequest) -> TestResult<Vec<String>> {
    let (request, _, _) = prepared.into_parts();
    let ordered = request
        .extensions()
        .get::<OrderedHeaders>()
        .ok_or("prepared request omitted ordered headers")?;
    Ok(ordered
        .as_slice()
        .iter()
        .map(|(name, _)| name.as_str().to_owned())
        .collect())
}

#[test]
fn generated_expectation_follows_content_length() -> TestResult<()> {
    let prepared = prepare(vec![RequestHeader::new("x-before", "value")])??;
    let (request, _, _) = prepared.into_parts();
    assert_eq!(
        request
            .headers()
            .get("expect")
            .map(|value| value.as_bytes()),
        Some(b"100-continue".as_slice())
    );
    let prepared = prepare(vec![RequestHeader::new("x-before", "value")])??;
    assert_eq!(
        ordered_names(prepared)?,
        ["x-before", "content-length", "expect"]
    );
    Ok(())
}

#[test]
fn a_caller_expectation_keeps_its_position_and_must_be_100_continue() -> TestResult<()> {
    let prepared = prepare(vec![
        RequestHeader::new("expect", "100-continue"),
        RequestHeader::new("x-after", "value"),
    ])??;
    assert_eq!(
        ordered_names(prepared)?,
        ["expect", "x-after", "content-length"]
    );

    for headers in [
        vec![RequestHeader::new("expect", "gzip")],
        vec![
            RequestHeader::new("expect", "100-continue"),
            RequestHeader::new("expect", "100-continue"),
        ],
    ] {
        let error = prepare(headers)?
            .err()
            .ok_or("an invalid expect field was accepted")?;
        assert_eq!(error.kind(), Http3ErrorKind::Request);
    }
    Ok(())
}

async fn no_data_within_window(stream: &mut ServerStream) -> TestResult<()> {
    match timeout(NO_BODY_WINDOW, stream.recv_data()).await {
        Err(_) => Ok(()),
        Ok(_) => Err("the body did not wait for 100 Continue".into()),
    }
}

async fn connect(
    identity: &TestIdentity,
    address: std::net::SocketAddr,
) -> TestResult<crate::http3::Http3Connection> {
    let client = client_config(identity)?;
    Ok(timeout(
        TEST_TIMEOUT,
        crate::http3::connect_direct(address, TEST_SERVER_NAME, client, &super::test_settings()),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??)
}

#[tokio::test(flavor = "current_thread")]
async fn the_body_waits_for_100_continue() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = super::server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let (request, mut stream, _connection) = super::accept_request(&endpoint).await?;
        assert_eq!(
            request
                .headers()
                .get("expect")
                .map(|value| value.as_bytes()),
            Some(b"100-continue".as_slice())
        );
        no_data_within_window(&mut stream).await?;
        stream
            .send_response(Response::builder().status(StatusCode::CONTINUE).body(())?)
            .await?;
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await? {
            let remaining = chunk.remaining();
            body.extend_from_slice(&chunk.copy_to_bytes(remaining));
        }
        assert_eq!(body, b"payload");
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        stream.finish().await?;
        let _ = done_received.await;
        Ok(())
    });

    let connection = connect(&identity, address).await?;
    let response = timeout(
        TEST_TIMEOUT,
        connection.send_prepared_request(prepare(Vec::new())??),
    )
    .await
    .map_err(|_| "HTTP/3 response timed out")??;
    assert_eq!(response.status(), StatusCode::OK);
    timeout(TEST_TIMEOUT, response.into_body().collect())
        .await
        .map_err(|_| "HTTP/3 response body timed out")??;
    let _ = client_done.send(());
    join_server(server).await
}

#[tokio::test(flavor = "current_thread")]
async fn a_final_response_first_cancels_the_upload_without_data() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = super::server_endpoint(&identity)?;
    let (client_done, done_received) = oneshot::channel();

    let server = tokio::spawn(async move {
        let (_request, mut stream, _connection) = super::accept_request(&endpoint).await?;
        no_data_within_window(&mut stream).await?;
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::EXPECTATION_FAILED)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        match timeout(TEST_TIMEOUT, stream.recv_data()).await {
            Ok(Err(h3::error::StreamError::RemoteTerminate { code, .. }))
                if code == h3::error::Code::H3_REQUEST_CANCELLED => {}
            Ok(Ok(Some(_))) => return Err("the withheld body was sent".into()),
            Ok(Ok(None)) => return Err("the withheld body ended with FIN".into()),
            Ok(Err(error)) => return Err(format!("unexpected upload end: {error}").into()),
            Err(_) => return Err("the upload was never cancelled".into()),
        }
        let _ = done_received.await;
        Ok(())
    });

    let connection = connect(&identity, address).await?;
    let response = timeout(
        TEST_TIMEOUT,
        connection.send_prepared_request(prepare(Vec::new())??),
    )
    .await
    .map_err(|_| "HTTP/3 response timed out")??;
    assert_eq!(response.status(), StatusCode::EXPECTATION_FAILED);
    timeout(TEST_TIMEOUT, response.into_body().collect())
        .await
        .map_err(|_| "HTTP/3 response body timed out")??;
    let _ = client_done.send(());
    join_server(server).await
}
