//! Public exact-protocol connection retry behavior.

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;
#[path = "support/tracing.rs"]
mod tracing_support;

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::{Ipv4Addr, SocketAddr, TcpListener as StdTcpListener},
    num::NonZeroUsize,
    time::Duration,
};

use bytes::Bytes;
use http::{Method, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use phantom::{
    Client, HttpProtocol, RequestErrorKind, RequestHeader, ResponseInfo, RetryPolicy,
    profile::ClientProfile,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    time::{sleep, timeout},
};
use tracing::instrument::WithSubscriber;

use tls_support::{
    H2_ALPN, TestIdentity, accept_tls_stream, client_builder, read_head, tls_settings,
};
use tracing_support::OutcomeSubscriber;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
const RETRY_DELAY: Duration = Duration::from_millis(500);
const NEGOTIATED_RETRY_DELAY: Duration = Duration::from_secs(2);
const TRACE_POLL_INTERVAL: Duration = Duration::from_millis(1);
const SECOND_CONNECTION_WINDOW: Duration = Duration::from_millis(100);
const EXPECTED_CHUNKED_BODY: &[u8] =
    b"7\r\npayload\r\n0\r\nX-Trailer: first\r\nX-Trailer: second\r\n\r\n";
type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;

#[tokio::test]
async fn request_retry_override_waits_for_observed_failure_before_exact_h1_dispatch() -> TestResult
{
    bounded(async {
        let address = unused_loopback_address()?;
        let client = Client::builder(ClientProfile::new(tls_settings()))
            .retry_policy(RetryPolicy::none())
            .build()?;
        let subscriber = OutcomeSubscriber::default();
        let request = client
            .request(
                HttpProtocol::Http1,
                Method::POST,
                &format!("http://{address}/retried"),
            )?
            .header(RequestHeader::new("X-First", "one"))
            .header(RequestHeader::new("X-Repeat", "alpha"))
            .header(RequestHeader::new("X-Repeat", "beta"))
            .streaming_body(Full::new(Bytes::from_static(b"payload")))
            .trailers(vec![
                RequestHeader::new("X-Trailer", "first"),
                RequestHeader::new("X-Trailer", "second"),
            ])
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                RETRY_DELAY,
            ));
        let request_task = tokio::spawn(request.send().with_subscriber(subscriber.dispatch()));

        wait_for_retry_reason(&subscriber).await?;
        let listener = TcpListener::bind(address).await?;
        let server = tokio::spawn(serve_one_chunked_request(listener));

        let response = request_task.await??;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted retry metadata")?;
        assert_eq!(info.protocol(), HttpProtocol::Http1);
        assert_eq!(info.retries_performed(), 1);
        response.into_body().collect().await?;

        let (head, framed, had_no_second_connection) = server.await??;
        assert_eq!(
            head,
            format!(
                "POST /retried HTTP/1.1\r\nHost: {address}\r\nX-First: one\r\nX-Repeat: alpha\r\nX-Repeat: beta\r\nTransfer-Encoding: chunked\r\nTrailer: X-Trailer\r\n\r\n"
            )
            .as_bytes()
        );
        assert_eq!(framed, EXPECTED_CHUNKED_BODY);
        assert!(had_no_second_connection);
        assert_eq!(
            subscriber.selected_protocols_for("client.request"),
            ["http/1.1"]
        );
        assert_eq!(
            subscriber.retry_reasons_for("client.request"),
            ["connection_setup"]
        );
        assert_eq!(subscriber.retries_performed_for("client.request"), [1]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn terminal_http_status_is_not_retried() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
                .await?;
            stream.flush().await?;
            let second = timeout(SECOND_CONNECTION_WINDOW, listener.accept()).await;
            Ok::<_, Box<dyn Error + Send + Sync>>((head, second.is_err()))
        });

        let client = Client::builder(ClientProfile::new(tls_settings()))
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                RETRY_DELAY,
            ))
            .build()?;
        let subscriber = OutcomeSubscriber::default();
        let response = client
            .get(HttpProtocol::Http1, &format!("http://{address}/terminal"))?
            .send()
            .with_subscriber(subscriber.dispatch())
            .await?;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted retry metadata")?;
        assert_eq!(info.protocol(), HttpProtocol::Http1);
        assert_eq!(info.retries_performed(), 0);
        response.into_body().collect().await?;

        let (head, had_no_second_connection) = server.await??;
        assert_eq!(
            head,
            format!("GET /terminal HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()
        );
        assert!(had_no_second_connection);
        assert!(subscriber.retry_reasons_for("client.request").is_empty());
        assert!(
            subscriber
                .retries_performed_for("client.request")
                .is_empty()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_connection_failure_does_not_enter_the_exact_protocol_retry_loop() -> TestResult
{
    bounded(async {
        let identity = TestIdentity::generate()?;
        let address = unused_loopback_address()?;
        let client = client_builder(&identity, true).build()?;
        let subscriber = OutcomeSubscriber::default();
        let request = client
            .get_negotiated(&format!("https://{address}/negotiated"))?
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                NEGOTIATED_RETRY_DELAY,
            ));

        // Refused loopback connects take about two seconds on Windows, so a
        // wall-clock window cannot separate one attempt from a retry. The
        // retry reason is recorded before the retry delay starts.
        let result = tokio::select! {
            result = request.send().with_subscriber(subscriber.dispatch()) => result,
            () = wait_for_any_retry_reason(&subscriber) => {
                return Err("negotiated request entered the exact-protocol retry loop".into());
            }
        };
        let error = match result {
            Ok(_) => return Err("negotiated request unexpectedly succeeded".into()),
            Err(error) => error,
        };

        assert_eq!(error.kind(), RequestErrorKind::Connect);
        assert_eq!(error.protocol(), None);
        assert!(subscriber.retry_reasons_for("client.request").is_empty());
        assert!(
            subscriber
                .retries_performed_for("client.request")
                .is_empty()
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn exact_http2_retries_connection_setup_before_dispatch() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let address = unused_loopback_address()?;
        let client = client_builder(&identity, true)
            .retry_policy(RetryPolicy::none())
            .build()?;
        let subscriber = OutcomeSubscriber::default();
        let request = client
            .get(
                HttpProtocol::Http2,
                &format!("https://{address}/retried-h2"),
            )?
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                RETRY_DELAY,
            ));
        let request_task = tokio::spawn(request.send().with_subscriber(subscriber.dispatch()));

        wait_for_retry_reason(&subscriber).await?;
        let listener = TcpListener::bind(address).await?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let stream = accept_tls_stream(tcp, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("HTTP/2 connection closed before retried request")??;
            respond.send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
                true,
            )?;
            let path = request.uri().path().to_owned();
            drop(request);
            drop(respond);
            poll_fn(|context| connection.poll_closed(context)).await?;
            let second = timeout(SECOND_CONNECTION_WINDOW, listener.accept()).await;
            Ok::<_, Box<dyn Error + Send + Sync>>((path, second.is_err()))
        });

        let response = request_task.await??;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted retry metadata")?;
        assert_eq!(info.protocol(), HttpProtocol::Http2);
        assert_eq!(info.retries_performed(), 1);
        response.into_body().collect().await?;
        drop(client);

        let (path, had_no_second_connection) = server.await??;
        assert_eq!(path, "/retried-h2");
        assert!(had_no_second_connection);
        assert_eq!(subscriber.selected_protocols_for("client.request"), ["h2"]);
        assert_eq!(
            subscriber.retry_reasons_for("client.request"),
            ["connection_setup"]
        );
        assert_eq!(subscriber.retries_performed_for("client.request"), [1]);
        Ok(())
    })
    .await
}

fn unused_loopback_address() -> TestResult<SocketAddr> {
    let listener = StdTcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

async fn wait_for_retry_reason(subscriber: &OutcomeSubscriber) -> TestResult {
    timeout(TEST_TIMEOUT, async {
        loop {
            if subscriber.retry_reasons_for("client.request") == ["connection_setup"] {
                return;
            }
            sleep(TRACE_POLL_INTERVAL).await;
        }
    })
    .await
    .map_err(|_| "request did not report its refused connection attempt")?;
    Ok(())
}

async fn wait_for_any_retry_reason(subscriber: &OutcomeSubscriber) {
    while subscriber.retry_reasons_for("client.request").is_empty() {
        sleep(TRACE_POLL_INTERVAL).await;
    }
}

async fn serve_one_chunked_request(listener: TcpListener) -> TestResult<(Vec<u8>, Vec<u8>, bool)> {
    let (mut stream, _) = listener.accept().await?;
    let head = read_head(&mut stream).await?;
    let mut framed = vec![0_u8; EXPECTED_CHUNKED_BODY.len()];
    stream.read_exact(&mut framed).await?;
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
        .await?;
    stream.flush().await?;
    let second = timeout(SECOND_CONNECTION_WINDOW, listener.accept()).await;
    Ok((head, framed, second.is_err()))
}

async fn bounded<F>(future: F) -> TestResult
where
    F: Future<Output = TestResult>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "connection retry test exceeded its deadline")?
}
