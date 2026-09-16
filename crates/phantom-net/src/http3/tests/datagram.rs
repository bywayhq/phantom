use std::{
    error::Error,
    future::{Future, poll_fn},
    task::Poll,
    time::Duration,
};

use bytes::Bytes;
use h3_datagram::datagram_handler::HandleDatagramsExt;
use http::{Request, Response, StatusCode};
use http_body_util::BodyExt;
use phantom_profile::chromium;
use tokio::{sync::oneshot, time::timeout};

use super::{TestResult, join_server, profiled_client_config, server_endpoint};
use crate::tls::test_support::{TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity};

#[tokio::test(flavor = "current_thread")]
async fn unexpected_datagram_aborts_get_stream() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = profiled_client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (head_sent, head_received) = oneshot::channel();
    let (release, released) = oneshot::channel();

    let server = tokio::spawn(async move {
        let (_request, mut stream, connection) = accept_datagram_request(&endpoint).await?;
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        let _ = head_sent.send(());
        let _ = released.await;

        stream
            .send_data(Bytes::from_static(b"queued before violation"))
            .await?;
        tokio::time::sleep(Duration::from_millis(20)).await;

        let mut sender = connection.get_datagram_sender(stream.id());
        sender.send_datagram(Bytes::from_static(b"unexpected"))?;

        let chunk = Bytes::from(vec![0; 64 * 1024]);
        loop {
            match stream.send_data(chunk.clone()).await {
                Ok(()) => {}
                Err(h3::error::StreamError::RemoteTerminate { code, .. })
                    if code == h3::error::Code::H3_DATAGRAM_ERROR =>
                {
                    return Ok::<(), Box<dyn Error + Send + Sync>>(());
                }
                Err(error) => {
                    return Err(
                        format!("unexpected datagram cancellation result: {error:?}").into(),
                    );
                }
            }
        }
    });

    let request = Request::get(format!(
        "https://{TEST_SERVER_NAME}:{}/unexpected-datagram",
        address.port()
    ))
    .body(())?;
    let settings = chromium::v152_macos_http3();
    let response = timeout(
        TEST_TIMEOUT,
        super::super::send_request(address, TEST_SERVER_NAME, client, &settings, request),
    )
    .await
    .map_err(|_| "HTTP/3 request timed out")??;
    timeout(TEST_TIMEOUT, head_received)
        .await
        .map_err(|_| "server did not send response headers")??;

    let mut body = response.into_body();
    let mut pending_frame = Box::pin(body.frame());
    poll_fn(|context| {
        assert!(pending_frame.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(pending_frame);

    let _ = release.send(());
    join_server(server).await?;
    tokio::time::sleep(super::super::SHUTDOWN_GRACE + Duration::from_millis(20)).await;

    let frame = timeout(TEST_TIMEOUT, body.frame())
        .await
        .map_err(|_| "response body did not produce queued data")?
        .ok_or("response body ended before producing queued data")??;
    let data = frame
        .into_data()
        .map_err(|_| "response body produced trailers instead of queued data")?;
    assert_eq!(data, Bytes::from_static(b"queued before violation"));

    let frame = timeout(TEST_TIMEOUT, body.frame())
        .await
        .map_err(|_| "response body did not observe the datagram")?;
    let error = match frame {
        Some(Err(error)) => error,
        Some(Ok(_)) => return Err("body produced data after an unexpected datagram".into()),
        None => return Err("body ended after an unexpected datagram without an error".into()),
    };
    assert_eq!(error.kind(), super::super::Http3ErrorKind::Protocol);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn datagram_before_response_aborts_get_stream() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = profiled_client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;

    let server = tokio::spawn(async move {
        let (_request, mut stream, connection) = accept_datagram_request(&endpoint).await?;
        let mut sender = connection.get_datagram_sender(stream.id());
        sender.send_datagram(Bytes::from_static(b"unexpected"))?;
        tokio::time::sleep(Duration::from_millis(20)).await;

        match stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await
        {
            Err(h3::error::StreamError::RemoteTerminate { code, .. })
                if code == h3::error::Code::H3_DATAGRAM_ERROR =>
            {
                Ok::<(), Box<dyn Error + Send + Sync>>(())
            }
            Ok(()) => {
                Err("client accepted response headers after the pre-response datagram".into())
            }
            Err(error) => Err(format!("unexpected pre-response cancellation: {error:?}").into()),
        }
    });

    let request = Request::get(format!(
        "https://{TEST_SERVER_NAME}:{}/pre-response-datagram",
        address.port()
    ))
    .body(())?;
    let settings = chromium::v152_macos_http3();
    let result = timeout(
        TEST_TIMEOUT,
        super::super::send_request(address, TEST_SERVER_NAME, client, &settings, request),
    )
    .await
    .map_err(|_| "HTTP/3 request timed out")?;
    let error = match result {
        Ok(_) => return Err("pre-response datagram unexpectedly produced a response".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), super::super::Http3ErrorKind::Protocol);
    join_server(server).await?;
    Ok(())
}

async fn accept_datagram_request(
    endpoint: &quinn::Endpoint,
) -> TestResult<(
    Request<()>,
    h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    h3::server::Connection<h3_quinn::Connection, Bytes>,
)> {
    let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
    let connection = incoming.await?;
    let mut builder = h3::server::builder();
    builder.enable_datagram(true);
    let mut connection = builder.build(h3_quinn::Connection::new(connection)).await?;
    let resolver = connection
        .accept()
        .await?
        .ok_or("client closed before sending a request")?;
    let (request, stream) = resolver.resolve_request().await?;
    Ok((request, stream, connection))
}
