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
async fn datagram_violation_is_isolated_to_its_request_stream() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let client = profiled_client_config(&identity)?;
    let (address, endpoint) = server_endpoint(&identity)?;
    let (heads_sent, heads_received) = oneshot::channel();
    let (release_datagram, datagram_released) = oneshot::channel();
    let (client_done, done_received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
        let quinn = incoming.await?;
        let mut builder = h3::server::builder();
        builder.enable_datagram(true);
        let mut connection = builder.build(h3_quinn::Connection::new(quinn)).await?;

        let first = connection
            .accept()
            .await?
            .ok_or("client closed before the first request")?
            .resolve_request()
            .await?;
        let second = connection
            .accept()
            .await?
            .ok_or("client closed before the second request")?
            .resolve_request()
            .await?;
        let ((first_request, first_stream), (second_request, second_stream)) = (first, second);
        let (mut violated, mut sibling) = if first_request.uri().path() == "/violated"
            && second_request.uri().path() == "/sibling"
        {
            (first_stream, second_stream)
        } else if first_request.uri().path() == "/sibling"
            && second_request.uri().path() == "/violated"
        {
            (second_stream, first_stream)
        } else {
            return Err("server received unexpected request paths".into());
        };

        violated
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        sibling
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        let _ = heads_sent.send(());
        let _ = datagram_released.await;
        sibling.send_data(Bytes::from_static(b"sibling")).await?;
        sibling.finish().await?;

        let mut datagrams = connection.get_datagram_sender(violated.id());
        datagrams.send_datagram(Bytes::from_static(b"unexpected"))?;

        let (request, mut later) = connection
            .accept()
            .await?
            .ok_or("client closed before the later request")?
            .resolve_request()
            .await?;
        if request.uri().path() != "/later" {
            return Err("server received an unexpected later request".into());
        }
        later
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        later.send_data(Bytes::from_static(b"later")).await?;
        later.finish().await?;
        let _ = done_received.await;
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    });

    let settings = chromium::v152_macos_http3();
    let connection =
        super::super::connect_direct(address, TEST_SERVER_NAME, client, &settings).await?;
    let violated = Request::get(format!("https://{TEST_SERVER_NAME}/violated")).body(())?;
    let sibling = Request::get(format!("https://{TEST_SERVER_NAME}/sibling")).body(())?;
    let (violated, sibling) = tokio::join!(
        connection.send_request(violated, None),
        connection.send_request(sibling, None)
    );
    let mut violated = violated?.into_body();
    heads_received.await?;
    let _ = release_datagram.send(());
    let sibling = sibling?.into_body().collect().await?.to_bytes();
    assert_eq!(sibling, Bytes::from_static(b"sibling"));

    let error = violated
        .frame()
        .await
        .ok_or("violated stream ended without an error")?
        .err()
        .ok_or("violated stream produced data after its datagram")?;
    assert_eq!(error.kind(), super::super::Http3ErrorKind::Protocol);

    let later = connection
        .send_request(
            Request::get(format!("https://{TEST_SERVER_NAME}/later")).body(())?,
            None,
        )
        .await?
        .into_body()
        .collect()
        .await?
        .to_bytes();
    assert_eq!(later, Bytes::from_static(b"later"));
    let _ = client_done.send(());
    join_server(server).await?;
    Ok(())
}

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
