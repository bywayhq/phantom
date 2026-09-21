//! HTTP/2 session admission and connection-lifecycle integration tests.

#[allow(dead_code)]
#[path = "support/h2.rs"]
mod h2_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    num::NonZeroUsize,
    pin::Pin,
    task::Poll,
    time::Duration,
};

use btls::ssl::{Ssl, SslAcceptor};
use bytes::Bytes;
use http::{Method, Response};
use http_body_util::BodyExt;
use phantom::{HttpProtocol, RequestErrorKind};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use h2_support::{accept_client_preface, read_request_headers, write_frame};
use tls_support::{H2_ALPN, TestIdentity, client_builder, test_client};

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn http2_admission_is_bounded_until_body_drop_and_cancel_safe() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;

            let (first_request, mut first) = connection
                .accept()
                .await
                .ok_or("connection closed before held request")??;
            let mut first_body =
                first.send_response(Response::builder().status(200).body(())?, false)?;
            first_body.send_data(Bytes::from_static(b"held"), false)?;

            let (later_request, mut later) = connection
                .accept()
                .await
                .ok_or("connection closed before admitted request")??;
            later.send_response(Response::builder().status(204).body(())?, true)?;
            drop(first_body);
            drop(first);
            drop(later);
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>([
                first_request.uri().path().to_owned(),
                later_request.uri().path().to_owned(),
            ])
        });

        let one = NonZeroUsize::MIN;
        let session = client_builder(&identity, true)
            .max_concurrent_http2_requests_per_origin(one)
            .max_pending_http2_requests_per_origin(one)
            .build()?;
        let held = session
            .get(HttpProtocol::Http2, &format!("https://{address}/held"))?
            .send()
            .await?
            .into_body();

        let mut cancelled = Box::pin(
            session
                .get(HttpProtocol::Http2, &format!("https://{address}/cancelled"))?
                .send(),
        );
        assert_pending(
            cancelled.as_mut(),
            "cancelled waiter unexpectedly completed",
        )
        .await?;
        drop(cancelled);

        let mut admitted = Box::pin(
            session
                .get(HttpProtocol::Http2, &format!("https://{address}/admitted"))?
                .send(),
        );
        assert_pending(admitted.as_mut(), "admitted waiter unexpectedly completed").await?;

        let result = session
            .get(HttpProtocol::Http2, &format!("https://{address}/excess"))?
            .send()
            .await;
        let error = match result {
            Ok(_) => return Err("excess request was admitted".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Capacity);

        drop(held);
        let response = admitted.await?;
        assert_eq!(response.status(), 204);
        response.into_body().collect().await?;
        drop(session);

        assert_eq!(server.await??, ["/held", "/admitted"]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn peer_http2_stream_limit_remains_authoritative() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut builder = ::http2::server::Builder::new();
            builder.max_concurrent_streams(1);
            let mut connection = builder.handshake::<_, Bytes>(stream).await?;

            let (_, mut first) = connection
                .accept()
                .await
                .ok_or("connection closed before first request")??;
            let first_body =
                first.send_response(Response::builder().status(200).body(())?, false)?;
            let (_, mut second) = connection
                .accept()
                .await
                .ok_or("connection closed before peer admitted second request")??;
            second.send_response(Response::builder().status(204).body(())?, true)?;
            drop(first_body);
            drop(first);
            drop(second);
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let two = NonZeroUsize::new(2).ok_or("two must be non-zero")?;
        let session = test_client(&identity, true)?
            .session_builder()
            .max_concurrent_http2_requests_per_origin(two)
            .build()?;
        let first = session
            .get(HttpProtocol::Http2, &format!("https://{address}/first"))?
            .send()
            .await?
            .into_body();
        let second = session
            .get(HttpProtocol::Http2, &format!("https://{address}/second"))?
            .send();
        tokio::pin!(second);
        assert_pending(
            second.as_mut(),
            "peer stream limit did not hold the second request",
        )
        .await?;

        drop(first);
        let response = second.await?;
        assert_eq!(response.status(), 204);
        response.into_body().collect().await?;
        drop(session);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn goaway_replaces_connection_while_eligible_body_finishes() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let mut first = accept_tls(&listener, &acceptor).await?;
            accept_client_preface(&mut first).await?;
            read_request_headers(&mut first, 1).await?;

            write_frame(&mut first, 0x1, 0x4, 1, &[0x88]).await?;
            write_frame(&mut first, 0x7, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0]).await?;
            write_frame(&mut first, 0x0, 0, 1, b"before").await?;
            first.flush().await?;

            let replacement = accept_tls(&listener, &acceptor).await?;
            let replacement = tokio::spawn(serve_requests(replacement, 1));
            write_frame(&mut first, 0x0, 0x1, 1, b"after").await?;
            first.flush().await?;

            let requests = replacement.await??;
            Ok::<_, Box<dyn Error + Send + Sync>>(requests)
        });

        let session = test_client(&identity, true)?.session();
        let response = session
            .get(HttpProtocol::Http2, &format!("https://{address}/held"))?
            .send()
            .await?;
        let mut held = response.into_body();
        assert_eq!(next_data(&mut held).await?, "before");

        let later = session
            .get(HttpProtocol::Http2, &format!("https://{address}/later"))?
            .send()
            .await?;
        assert_eq!(later.status(), 204);
        later.into_body().collect().await?;
        assert_eq!(held.collect().await?.to_bytes(), "after");
        drop(session);

        assert_eq!(server.await??, vec![(1, "/later".to_owned())]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn graceful_goaway_retries_a_bodyless_get_once_on_a_replacement() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let mut first = accept_tls(&listener, &acceptor).await?;
            accept_client_preface(&mut first).await?;
            read_request_headers(&mut first, 1).await?;
            write_frame(&mut first, 0x7, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]).await?;
            first.flush().await?;
            first.shutdown().await?;

            let replacement = accept_tls(&listener, &acceptor).await?;
            serve_requests(replacement, 1).await
        });

        let session = test_client(&identity, true)?.session();
        let response = session
            .get(HttpProtocol::Http2, &format!("https://{address}/failed"))?
            .send()
            .await?;
        assert_eq!(response.status(), 204);
        response.into_body().collect().await?;
        drop(session);

        assert_eq!(server.await??, vec![(1, "/failed".to_owned())]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn goaway_processed_boundary_preserves_lower_stream_and_retries_higher_stream()
-> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let server = tokio::spawn(async move {
            let mut first = accept_tls(&listener, &acceptor).await?;
            accept_client_preface(&mut first).await?;
            read_request_headers(&mut first, 1).await?;
            read_request_headers(&mut first, 3).await?;

            write_frame(&mut first, 0x1, 0x5, 1, &[0x89]).await?;
            write_frame(&mut first, 0x7, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0]).await?;
            first.flush().await?;
            first.shutdown().await?;

            let replacement = accept_tls(&listener, &acceptor).await?;
            serve_requests(replacement, 1).await
        });

        let two = NonZeroUsize::new(2).ok_or("two must be non-zero")?;
        let session = test_client(&identity, true)?
            .session_builder()
            .max_concurrent_http2_requests_per_origin(two)
            .build()?;
        let lower = session
            .get(HttpProtocol::Http2, &format!("https://{address}/lower"))?
            .send();
        let higher = session
            .get(HttpProtocol::Http2, &format!("https://{address}/higher"))?
            .send();
        let (lower, higher) = tokio::join!(lower, higher);

        let lower = lower?;
        assert_eq!(lower.status(), 204);
        lower.into_body().collect().await?;
        let higher = higher?;
        assert_eq!(higher.status(), 204);
        higher.into_body().collect().await?;
        drop(session);

        assert_eq!(server.await??, vec![(1, "/higher".to_owned())]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn graceful_goaway_retry_is_bounded_to_one_replacement() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done_tx, client_done_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let mut stream = accept_tls(&listener, &acceptor).await?;
                accept_client_preface(&mut stream).await?;
                read_request_headers(&mut stream, 1).await?;
                write_frame(&mut stream, 0x7, 0, 0, &[0, 0, 0, 0, 0, 0, 0, 0]).await?;
                stream.flush().await?;
                stream.shutdown().await?;
            }

            tokio::select! {
                biased;
                accepted = listener.accept() => {
                    accepted?;
                    Ok::<_, Box<dyn Error + Send + Sync>>(false)
                }
                completed = client_done_rx => {
                    completed.map_err(|_| "client stopped before reporting completion")?;
                    Ok(true)
                }
            }
        });

        let session = test_client(&identity, true)?.session();
        let result = session
            .get(HttpProtocol::Http2, &format!("https://{address}/bounded"))?
            .send()
            .await;
        let error = match result {
            Ok(_) => return Err("request survived a second graceful GOAWAY".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Http2);
        client_done_tx
            .send(())
            .map_err(|_| "server stopped before client completion")?;
        assert!(server.await??, "a second retry opened a third connection");
        Ok(())
    })
    .await
}

#[tokio::test]
async fn graceful_goaway_does_not_replay_a_request_body() -> TestResult<()> {
    assert_goaway_not_retried(
        Method::GET,
        Some(Bytes::from_static(b"owned body")),
        "/body",
        0,
    )
    .await
}

#[tokio::test]
async fn graceful_goaway_does_not_replay_another_method() -> TestResult<()> {
    assert_goaway_not_retried(Method::POST, None, "/post", 0).await
}

#[tokio::test]
async fn error_goaway_does_not_replay_a_bodyless_get() -> TestResult<()> {
    assert_goaway_not_retried(Method::GET, None, "/protocol-error", 1).await
}

async fn assert_goaway_not_retried(
    method: Method,
    body: Option<Bytes>,
    path: &'static str,
    reason_code: u32,
) -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done_tx, client_done_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(&listener, &acceptor).await?;
            accept_client_preface(&mut stream).await?;
            read_request_headers(&mut stream, 1).await?;
            let mut goaway = [0_u8; 8];
            goaway[4..].copy_from_slice(&reason_code.to_be_bytes());
            write_frame(&mut stream, 0x7, 0, 0, &goaway).await?;
            stream.flush().await?;
            stream.shutdown().await?;

            tokio::select! {
                biased;
                accepted = listener.accept() => {
                    accepted?;
                    Ok::<_, Box<dyn Error + Send + Sync>>(false)
                }
                completed = client_done_rx => {
                    completed.map_err(|_| "client stopped before reporting completion")?;
                    Ok(true)
                }
            }
        });

        let session = test_client(&identity, true)?.session();
        let mut request = session.request(
            HttpProtocol::Http2,
            method,
            &format!("https://{address}{path}"),
        )?;
        if let Some(body) = body {
            request = request.body(body);
        }
        let result = request.send().await;
        let error = match result {
            Ok(_) => return Err("ineligible request was replayed after GOAWAY".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Http2);
        client_done_tx
            .send(())
            .map_err(|_| "server stopped before client completion")?;
        assert!(
            server.await??,
            "ineligible replay opened a replacement connection"
        );
        Ok(())
    })
    .await
}

async fn assert_pending<F>(mut future: Pin<&mut F>, message: &'static str) -> TestResult<()>
where
    F: Future,
{
    poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(Ok(())),
        Poll::Ready(_) => Poll::Ready(Err(message.into())),
    })
    .await
}

async fn next_data(body: &mut phantom::ResponseBody) -> TestResult<Bytes> {
    loop {
        let frame = body.frame().await.ok_or("response body ended")??;
        if let Ok(data) = frame.into_data() {
            if !data.is_empty() {
                return Ok(data);
            }
        }
    }
}

async fn serve_requests(
    stream: SslStream<TcpStream>,
    count: usize,
) -> TestResult<Vec<(u32, String)>> {
    let mut connection = ::http2::server::handshake(stream).await?;
    let mut requests = Vec::with_capacity(count);
    for _ in 0..count {
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("connection closed before expected request")??;
        requests.push((
            respond.stream_id().as_u32(),
            request.uri().path().to_owned(),
        ));
        respond.send_response(Response::builder().status(204).body(())?, true)?;
    }
    poll_fn(|context| connection.poll_closed(context)).await?;
    Ok(requests)
}

async fn accept_tls(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "session test exceeded its deadline")?
}
