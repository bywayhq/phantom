//! The wait for `100 Continue` on an exact HTTP/3 request.

use crate::support::h3 as h3_support;
use crate::support::tls as tls_support;

use std::{
    error::Error,
    num::NonZeroUsize,
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes};
use http::{Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{Client, ClientBuilder, HttpProtocol, RedirectPolicy, profile::ClientProfile};
use tokio::{sync::oneshot, time::timeout};

use h3_support::{accept_request, client_settings, server_endpoint};
use tls_support::{TestIdentity, tls_settings};

use super::{NO_BODY_WINDOW, TestResult, bounded};

type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

fn http3_client_builder(identity: &TestIdentity) -> ClientBuilder {
    let mut tcp_tls = tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    Client::builder(ClientProfile::new(tcp_tls).with_http3(client_settings()))
        .add_root_certificate_der(identity.root_der.clone())
}

fn field<'a>(request: &'a Request<()>, name: &str) -> Option<&'a [u8]> {
    request.headers().get(name).map(|value| value.as_bytes())
}

/// Requires that no DATA arrives on `stream` for [`NO_BODY_WINDOW`].
async fn assert_no_data_arrives(stream: &mut ServerStream) -> TestResult {
    match timeout(NO_BODY_WINDOW, stream.recv_data()).await {
        Err(_) => Ok(()),
        Ok(_) => Err("the body did not wait for 100 Continue".into()),
    }
}

async fn read_body(stream: &mut ServerStream) -> TestResult<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        let remaining = chunk.remaining();
        body.extend_from_slice(&chunk.copy_to_bytes(remaining));
    }
    Ok(body)
}

/// Requires that the client cancels the upload, with
/// `H3_REQUEST_CANCELLED`, before any of its body arrives.
async fn assert_upload_cancelled(stream: &mut ServerStream) -> TestResult {
    match timeout(Duration::from_secs(5), stream.recv_data()).await {
        Ok(Err(h3::error::StreamError::RemoteTerminate { code, .. }))
            if code == h3::error::Code::H3_REQUEST_CANCELLED =>
        {
            Ok(())
        }
        Ok(Ok(Some(_))) => Err("the withheld body was sent".into()),
        Ok(Ok(None)) => Err("the withheld body ended with FIN".into()),
        Ok(Err(error)) => Err(format!("unexpected upload end: {error}").into()),
        Err(_) => Err("the upload was never cancelled".into()),
    }
}

#[tokio::test]
async fn an_http3_body_waits_for_100_continue() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (request, mut stream, _connection) = accept_request(&endpoint).await?;
            let expect = field(&request, "expect").map(<[u8]>::to_vec);
            let length = field(&request, "content-length").map(<[u8]>::to_vec);
            assert_no_data_arrives(&mut stream).await?;
            stream
                .send_response(Response::builder().status(StatusCode::CONTINUE).body(())?)
                .await?;
            let body = read_body(&mut stream).await?;
            stream
                .send_response(Response::builder().status(StatusCode::OK).body(())?)
                .await?;
            stream.send_data(Bytes::from_static(b"ok")).await?;
            stream.finish().await?;
            let _ = done_received.await;
            Ok::<_, Box<dyn Error + Send + Sync>>((expect, length, body))
        });

        let client = http3_client_builder(&identity).build()?;
        let response = client
            .request(
                HttpProtocol::Http3,
                Method::PUT,
                &format!("https://{address}/upload"),
            )?
            .body("payload")
            .expect_continue(Duration::from_secs(10))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
        let _ = client_done.send(());

        let (expect, length, body) = server.await??;
        assert_eq!(expect.as_deref(), Some(b"100-continue".as_slice()));
        assert_eq!(length.as_deref(), Some(b"7".as_slice()));
        assert_eq!(body, b"payload");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_http3_body_is_sent_when_the_wait_ends() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (_request, mut stream, _connection) = accept_request(&endpoint).await?;
            let head_read = Instant::now();
            let body = read_body(&mut stream).await?;
            let waited = head_read.elapsed();
            stream
                .send_response(Response::builder().status(StatusCode::OK).body(())?)
                .await?;
            stream.finish().await?;
            let _ = done_received.await;
            Ok::<_, Box<dyn Error + Send + Sync>>((body, waited))
        });

        let client = http3_client_builder(&identity).build()?;
        let response = client
            .request(
                HttpProtocol::Http3,
                Method::PUT,
                &format!("https://{address}/upload"),
            )?
            .body("payload")
            .expect_continue(Duration::from_millis(500))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;
        let _ = client_done.send(());

        let (body, waited) = server.await??;
        assert_eq!(body, b"payload");
        assert!(
            waited >= Duration::from_millis(400) && waited < Duration::from_secs(5),
            "body after {waited:?}"
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_http3_final_response_first_cancels_the_upload_without_data() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (_request, mut stream, _connection) = accept_request(&endpoint).await?;
            assert_no_data_arrives(&mut stream).await?;
            stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::EXPECTATION_FAILED)
                        .body(())?,
                )
                .await?;
            stream.finish().await?;
            assert_upload_cancelled(&mut stream).await?;
            let _ = done_received.await;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let client = http3_client_builder(&identity).build()?;
        let response = client
            .request(
                HttpProtocol::Http3,
                Method::PUT,
                &format!("https://{address}/upload"),
            )?
            .body("payload")
            .expect_continue(Duration::from_secs(10))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::EXPECTATION_FAILED);
        response.into_body().collect().await?;
        let _ = client_done.send(());
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_http3_final_response_with_a_body_cancels_the_upload_without_data() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (_request, mut stream, _connection) = accept_request(&endpoint).await?;
            stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::EXPECTATION_FAILED)
                        .body(())?,
                )
                .await?;
            stream.send_data(Bytes::from_static(b"no")).await?;
            stream.finish().await?;
            assert_upload_cancelled(&mut stream).await?;
            let _ = done_received.await;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let client = http3_client_builder(&identity).build()?;
        let response = client
            .request(
                HttpProtocol::Http3,
                Method::PUT,
                &format!("https://{address}/upload"),
            )?
            .body("payload")
            .expect_continue(Duration::from_secs(10))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::EXPECTATION_FAILED);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "no");
        let _ = client_done.send(());
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn an_http3_redirect_that_keeps_the_body_waits_again() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            let (first, mut first_stream, mut connection) = accept_request(&endpoint).await?;
            let first_expect = field(&first, "expect").map(<[u8]>::to_vec);
            first_stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::TEMPORARY_REDIRECT)
                        .header("location", "/next")
                        .body(())?,
                )
                .await?;
            first_stream.finish().await?;
            assert_upload_cancelled(&mut first_stream).await?;

            let resolver = connection
                .accept()
                .await?
                .ok_or("client closed before the redirected request")?;
            let (second, mut second_stream) = resolver.resolve_request().await?;
            let second_path = second.uri().path().to_owned();
            let second_expect = field(&second, "expect").map(<[u8]>::to_vec);
            assert_no_data_arrives(&mut second_stream).await?;
            second_stream
                .send_response(Response::builder().status(StatusCode::CONTINUE).body(())?)
                .await?;
            let body = read_body(&mut second_stream).await?;
            second_stream
                .send_response(Response::builder().status(StatusCode::OK).body(())?)
                .await?;
            second_stream.finish().await?;
            let _ = done_received.await;
            Ok::<_, Box<dyn Error + Send + Sync>>((first_expect, second_path, second_expect, body))
        });

        let client = http3_client_builder(&identity)
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .build()?;
        let response = client
            .request(
                HttpProtocol::Http3,
                Method::PUT,
                &format!("https://{address}/upload"),
            )?
            .body("payload")
            .expect_continue(Duration::from_secs(10))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;
        let _ = client_done.send(());

        let (first_expect, second_path, second_expect, body) = server.await??;
        assert_eq!(first_expect.as_deref(), Some(b"100-continue".as_slice()));
        assert_eq!(second_path, "/next");
        assert_eq!(second_expect.as_deref(), Some(b"100-continue".as_slice()));
        assert_eq!(body, b"payload");
        Ok(())
    })
    .await
}
