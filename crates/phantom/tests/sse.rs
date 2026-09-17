//! Public SSE response-decoder integration tests.

#![cfg(feature = "sse")]

#[path = "support/h3.rs"]
mod h3_support;
#[path = "sse/idle.rs"]
mod idle;
#[path = "sse/reconnect.rs"]
mod reconnect;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;
#[path = "support/tracing.rs"]
mod tracing_support;

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode, header};
use phantom::{Client, HttpProtocol, SseErrorKind, SseLimits, SseStream, profile::ClientProfile};
use tokio::{io::AsyncWriteExt, net::TcpListener, sync::oneshot, time::timeout};
use tracing::instrument::WithSubscriber;

use h3_support::{accept_request, client_settings, server_endpoint};
use tls_support::{H1_ALPN, TestIdentity, accept_tls, read_head, test_client};
use tracing_support::OutcomeSubscriber;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
type TestResult<T> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn stream_is_pull_driven_and_pending_reads_are_cancellation_safe() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let (partial_sent, partial_received) = oneshot::channel();
        let (resume, resumed) = oneshot::channel();
        let (finish, finished) = oneshot::channel();
        let server = tokio::spawn(async move {
            let mut stream = accept_tls(listener, acceptor).await?;
            let _ = read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\n\
                      Content-Type: Text/Event-Stream; charset=utf-8\r\n\
                      Content-Encoding: identity\r\n\
                      Transfer-Encoding: chunked\r\n\r\n",
                )
                .await?;
            write_chunk(&mut stream, b"\xef\xbb\xbfretry: 25\ndata: hel").await?;
            partial_sent
                .send(())
                .map_err(|_| "client stopped before partial event")?;
            resumed.await.map_err(|_| "client did not resume stream")?;
            write_chunk(&mut stream, b"lo\rid: first\r\r").await?;
            finished
                .await
                .map_err(|_| "client did not request final event")?;
            write_chunk(&mut stream, b"data: second\n\n").await?;
            stream.write_all(b"0\r\n\r\n").await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let response = test_client(&identity, false)?
            .get(HttpProtocol::Http1, &format!("https://{address}/events"))?
            .send()
            .await?;
        let status = response.status();
        let mut events = SseStream::from_response(response)?.into_body();
        assert_eq!(status, 200);
        partial_received
            .await
            .map_err(|_| "server stopped before partial event")?;

        let subscriber = OutcomeSubscriber::default();
        let pending = timeout(
            Duration::from_millis(25),
            events.next_event().with_subscriber(subscriber.dispatch()),
        )
        .await;
        assert!(pending.is_err(), "partial event unexpectedly dispatched");
        assert_eq!(subscriber.outcomes_for("sse.next_event"), ["cancelled"]);

        resume
            .send(())
            .map_err(|_| "server stopped before stream resumed")?;
        let first = events.next_event().await?.ok_or("first event missing")?;
        assert_eq!(first.data(), "hello");
        assert_eq!(first.event(), "message");
        assert_eq!(first.id(), "first");
        assert_eq!(events.last_event_id(), "first");
        assert_eq!(events.retry_delay(), Some(Duration::from_millis(25)));

        finish
            .send(())
            .map_err(|_| "server stopped before final event")?;
        let second = events.next_event().await?.ok_or("second event missing")?;
        assert_eq!(second.data(), "second");
        assert_eq!(second.id(), "first");
        assert_eq!(events.next_event().await?, None);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn response_validation_and_decode_failures_have_stable_categories() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;

        let response = fixed_response(
            &identity,
            b"HTTP/1.1 204 No Content\r\nContent-Type: text/event-stream\r\n\r\n",
        )
        .await?;
        let error = SseStream::from_response(response)
            .err()
            .ok_or("204 SSE response was accepted")?;
        assert_eq!(error.kind(), SseErrorKind::UnexpectedStatus);

        let response = fixed_response(
            &identity,
            b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 0\r\n\r\n",
        )
        .await?;
        let error = SseStream::from_response(response)
            .err()
            .ok_or("non-SSE content type was accepted")?;
        assert_eq!(error.kind(), SseErrorKind::InvalidContentType);

        let response = fixed_response(
            &identity,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n",
        )
        .await?;
        let error = SseStream::from_response(response)
            .err()
            .ok_or("encoded SSE response was accepted")?;
        assert_eq!(error.kind(), SseErrorKind::UnsupportedContentEncoding);

        let response = fixed_response(
            &identity,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: 11\r\n\r\ndata: abc\n\n",
        )
        .await?;
        let mut events = SseStream::from_response_with_limits(response, SseLimits::new(4, 32))?
            .into_body();
        let error = events
            .next_event()
            .await
            .err()
            .ok_or("oversized SSE line was accepted")?;
        assert_eq!(error.kind(), SseErrorKind::LineTooLong);

        let response = fixed_response(
            &identity,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nZ\r\n",
        )
        .await?;
        let mut events = SseStream::from_response(response)?.into_body();
        let error = events
            .next_event()
            .await
            .err()
            .ok_or("malformed SSE body framing was accepted")?;
        assert_eq!(error.kind(), SseErrorKind::Body);
        assert!(error.source().is_some());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn decoder_consumes_http2_response_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(tls_support::H2_ALPN)?;
        let server = tokio::spawn(async move {
            let stream = accept_tls(listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (_, mut respond) = connection
                .accept()
                .await
                .ok_or("HTTP/2 connection closed before SSE request")??;
            let response = Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "text/event-stream")
                .body(())?;
            let mut send = respond.send_response(response, false)?;
            send.send_data(Bytes::from_static(b"data: h2\n\n"), true)?;
            drop(send);
            drop(respond);
            poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let response = test_client(&identity, true)?
            .get(HttpProtocol::Http2, &format!("https://{address}/events"))?
            .send()
            .await?;
        let mut events = SseStream::from_response(response)?.into_body();
        assert_eq!(
            events
                .next_event()
                .await?
                .map(|event| event.data().to_owned()),
            Some("h2".to_owned())
        );
        assert_eq!(events.next_event().await?, None);
        server.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn decoder_consumes_http3_response_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = server_endpoint(&identity)?;
        let (client_done, done_received) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (_, mut stream, _connection) = accept_request(&endpoint).await?;
            stream
                .send_response(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/event-stream")
                        .body(())?,
                )
                .await?;
            stream
                .send_data(Bytes::from_static(b"data: h3\n\n"))
                .await?;
            stream.finish().await?;
            done_received
                .await
                .map_err(|_| "client stopped before HTTP/3 SSE completion")?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        let response = h3_client(&identity)?
            .get(HttpProtocol::Http3, &format!("https://{address}/events"))?
            .send()
            .await?;
        let mut events = SseStream::from_response(response)?.into_body();
        assert_eq!(
            events
                .next_event()
                .await?
                .map(|event| event.data().to_owned()),
            Some("h3".to_owned())
        );
        assert_eq!(events.next_event().await?, None);
        client_done
            .send(())
            .map_err(|_| "HTTP/3 SSE server stopped before completion")?;
        server.await??;
        Ok(())
    })
    .await
}

fn h3_client(identity: &TestIdentity) -> TestResult<Client> {
    let mut tcp_tls = tls_support::tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let profile = ClientProfile::new(tcp_tls).with_http3(client_settings());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

async fn fixed_response(
    identity: &TestIdentity,
    response: &'static [u8],
) -> TestResult<http::Response<phantom::ResponseBody>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let server = tokio::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        let _ = read_head(&mut stream).await?;
        stream.write_all(response).await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let response = test_client(identity, false)?
        .get(HttpProtocol::Http1, &format!("https://{address}/events"))?
        .send()
        .await?;
    server.await??;
    Ok(response)
}

async fn write_chunk(
    stream: &mut (impl tokio::io::AsyncWrite + Unpin),
    bytes: &[u8],
) -> std::io::Result<()> {
    stream
        .write_all(format!("{:x}\r\n", bytes.len()).as_bytes())
        .await?;
    stream.write_all(bytes).await?;
    stream.write_all(b"\r\n").await?;
    stream.flush().await
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "SSE test exceeded its deadline")?
}
