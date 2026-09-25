//! Public connection retry and negotiated pre-selection admission behavior.

#[path = "support/reserved_port.rs"]
mod reserved_port;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;
#[path = "support/tracing.rs"]
mod tracing_support;

use std::{
    error::Error,
    future::{Future, poll_fn},
    net::Ipv4Addr,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use bytes::Bytes;
use http::{Method, Response, StatusCode};
use http_body::{Body, Frame, SizeHint};
use http_body_util::{BodyExt, Full};
use phantom::{
    Client, HttpProtocol, RedirectPolicy, RequestErrorKind, RequestHeader, ResponseInfo,
    RetryPolicy, profile::ClientProfile,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::{sleep, timeout},
};
use tracing::instrument::WithSubscriber;

use reserved_port::ReservedPort;
use tls_support::{
    H1_ALPN, H2_ALPN, TestIdentity, accept_tls_stream, client_builder, read_head, tls_settings,
};
use tracing_support::OutcomeSubscriber;

const TEST_TIMEOUT: Duration = Duration::from_secs(5);
// Covers two refused Windows loopback connects (about two seconds each) plus a
// retry delay; no assertion depends on this wall-clock window.
const LONG_TEST_TIMEOUT: Duration = Duration::from_secs(20);
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
        let reserved = ReservedPort::bind()?;
        let address = reserved.address();
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
        let listener = reserved.listen()?;
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
async fn negotiated_connection_refusal_is_retried_before_alpn_selection() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let reserved = ReservedPort::bind()?;
        let address = reserved.address();
        let client = client_builder(&identity, true).build()?;
        let subscriber = OutcomeSubscriber::default();
        let request = client
            .get_negotiated(&format!("https://{address}/negotiated"))?
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                RETRY_DELAY,
            ));
        let request_task = tokio::spawn(request.send().with_subscriber(subscriber.dispatch()));

        // No protocol is selected before the refused connect is retried.
        wait_for_retry_reason(&subscriber).await?;
        assert!(
            subscriber
                .selected_protocols_for("client.request")
                .is_empty()
        );
        let listener = reserved.listen()?;
        let server = tokio::spawn(serve_h2_requests(listener, acceptor, 1));

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

        let (paths, had_no_second_connection) = server.await??;
        assert_eq!(paths, ["/negotiated"]);
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

#[tokio::test]
async fn negotiated_tls_failure_is_terminal() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (client_done_tx, client_done_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let mut hello = [0_u8; 5];
            stream.read_exact(&mut hello).await?;
            stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await?;
            stream.flush().await?;
            drop(stream);
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

        let client = client_builder(&identity, true)
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                Duration::ZERO,
            ))
            .build()?;
        let subscriber = OutcomeSubscriber::default();
        let result = client
            .get_negotiated(&format!("https://{address}/tls"))?
            .send()
            .with_subscriber(subscriber.dispatch())
            .await;
        let error = match result {
            Ok(_) => return Err("negotiated request accepted a non-TLS peer".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Tls);
        assert_eq!(error.protocol(), None);
        client_done_tx
            .send(())
            .map_err(|_| "server stopped before client completion")?;
        assert!(server.await??, "TLS failure opened a retry connection");
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
async fn negotiated_retry_delay_releases_connection_lock_for_queued_request() -> TestResult {
    bounded_within(LONG_TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let reserved = ReservedPort::bind()?;
        let address = reserved.address();
        let client = client_builder(&identity, true).build()?;
        let subscriber = OutcomeSubscriber::default();
        let delayed = client
            .get_negotiated(&format!("https://{address}/delayed"))?
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                NEGOTIATED_RETRY_DELAY,
            ));
        let delayed_task = tokio::spawn(delayed.send().with_subscriber(subscriber.dispatch()));

        // The retry reason is recorded when the delay starts.
        wait_for_retry_reason(&subscriber).await?;
        let listener = reserved.listen()?;
        let server = tokio::spawn(serve_h2_requests(listener, acceptor, 2));

        // A lock held across the delay would let the delayed request connect
        // first; the server-side stream order below proves the opposite.
        let queued = client
            .get_negotiated(&format!("https://{address}/queued"))?
            .send()
            .await?;
        assert_eq!(queued.status(), StatusCode::NO_CONTENT);
        assert!(
            !delayed_task.is_finished(),
            "delayed request finished before its retry delay elapsed"
        );
        queued.into_body().collect().await?;

        let delayed = delayed_task.await??;
        assert_eq!(delayed.status(), StatusCode::NO_CONTENT);
        let info = delayed
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted retry metadata")?;
        assert_eq!(info.protocol(), HttpProtocol::Http2);
        assert_eq!(info.retries_performed(), 1);
        delayed.into_body().collect().await?;
        drop(client);

        let (paths, had_no_second_connection) = server.await??;
        assert_eq!(paths, ["/queued", "/delayed"]);
        assert!(had_no_second_connection);
        assert_eq!(subscriber.retries_performed_for("client.request"), [1]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn negotiated_retry_budget_is_shared_across_redirect_hops() -> TestResult {
    bounded_within(LONG_TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let origin = ReservedPort::bind()?;
        // The redirect target stays reserved and never listens.
        let target = ReservedPort::bind()?;
        let target_address = target.address();
        let client = client_builder(&identity, true)
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                RETRY_DELAY,
            ))
            .build()?;
        let subscriber = OutcomeSubscriber::default();
        let request = client.get_negotiated(&format!("https://{}/start", origin.address()))?;
        let request_task = tokio::spawn(request.send().with_subscriber(subscriber.dispatch()));

        wait_for_retry_reason(&subscriber).await?;
        let listener = origin.listen()?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let head = read_head(&mut stream).await?;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 307 Temporary Redirect\r\nLocation: https://{target_address}/next\r\nContent-Length: 0\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            stream.flush().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(head)
        });

        // With the one retry already spent on the first hop, the target's
        // refusal is terminal.
        let error = match request_task.await? {
            Ok(_) => return Err("redirect target unexpectedly answered".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Connect);
        assert_eq!(error.protocol(), None);

        let head = server.await??;
        assert!(head.starts_with(b"GET /start HTTP/1.1\r\n"));
        assert_eq!(subscriber.selected_protocols_for("client.request"), ["http/1.1"]);
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
async fn negotiated_one_shot_body_is_not_polled_before_retry() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let reserved = ReservedPort::bind()?;
        let address = reserved.address();
        let client = client_builder(&identity, true).build()?;
        let subscriber = OutcomeSubscriber::default();
        let polls = Arc::new(AtomicUsize::new(0));
        let request = client
            .request_negotiated(Method::POST, &format!("https://{address}/upload"))?
            .streaming_body(PollCountingBody {
                inner: Full::new(Bytes::from_static(b"payload")),
                polls: Arc::clone(&polls),
            })
            .retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                RETRY_DELAY,
            ));
        let request_task = tokio::spawn(request.send().with_subscriber(subscriber.dispatch()));

        wait_for_retry_reason(&subscriber).await?;
        assert_eq!(
            polls.load(Ordering::SeqCst),
            0,
            "one-shot body was polled before the retried connection"
        );
        let listener = reserved.listen()?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut stream = accept_tls_stream(tcp, acceptor).await?;
            let head = read_head(&mut stream).await?;
            let mut body = [0_u8; 7];
            stream.read_exact(&mut body).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            stream.flush().await?;
            let second = timeout(SECOND_CONNECTION_WINDOW, listener.accept()).await;
            Ok::<_, Box<dyn Error + Send + Sync>>((head, body, second.is_err()))
        });

        let response = request_task.await??;
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted retry metadata")?;
        assert_eq!(info.protocol(), HttpProtocol::Http1);
        assert_eq!(info.retries_performed(), 1);
        response.into_body().collect().await?;

        let (head, body, had_no_second_connection) = server.await??;
        assert!(head.starts_with(b"POST /upload HTTP/1.1\r\n"));
        assert_eq!(&body, b"payload");
        assert!(had_no_second_connection);
        assert!(polls.load(Ordering::SeqCst) > 0);
        assert_eq!(subscriber.retries_performed_for("client.request"), [1]);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn exact_http2_retries_connection_setup_before_dispatch() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let reserved = ReservedPort::bind()?;
        let address = reserved.address();
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
        let listener = reserved.listen()?;
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

#[tokio::test]
async fn negotiated_pre_selection_admission_is_bounded() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (accepted_tx, accepted_rx) = oneshot::channel();
        // The server never answers TLS, so the first request keeps its
        // pre-selection admission for the whole test.
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            accepted_tx
                .send(())
                .map_err(|_| "client stopped before setup stalled")?;
            let _held = stream;
            std::future::pending::<()>().await;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        });

        // One active and one waiting pre-selection slot: the larger of the
        // H1 (1 active, 1 waiting) and H2 (1 active, 1 waiting) limits.
        let one = NonZeroUsize::MIN;
        let client = client_builder(&identity, true)
            .max_pending_http1_requests_per_origin(one)
            .max_concurrent_http2_requests_per_origin(one)
            .max_pending_http2_requests_per_origin(one)
            .build()?;
        let url = format!("https://{address}/admission");
        let setup = tokio::spawn(client.get_negotiated(&url)?.send());
        accepted_rx
            .await
            .map_err(|_| "server stopped before accepting setup")?;

        let mut waiting = Box::pin(client.get_negotiated(&url)?.send());
        assert_pending(waiting.as_mut(), "queued request left admission").await?;
        let error = match client.get_negotiated(&url)?.send().await {
            Ok(_) => return Err("request exceeded pre-selection admission".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Capacity);
        assert_eq!(error.protocol(), None);
        assert_pending(waiting.as_mut(), "queued request left admission").await?;

        setup.abort();
        server.abort();
        Ok(())
    })
    .await
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

async fn serve_h2_requests(
    listener: TcpListener,
    acceptor: btls::ssl::SslAcceptor,
    count: usize,
) -> TestResult<(Vec<String>, bool)> {
    let (tcp, _) = listener.accept().await?;
    let stream = accept_tls_stream(tcp, acceptor).await?;
    let mut connection = ::http2::server::handshake(stream).await?;
    let mut paths = Vec::with_capacity(count);
    for _ in 0..count {
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("HTTP/2 connection closed before an expected request")??;
        respond.send_response(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(())?,
            true,
        )?;
        paths.push(request.uri().path().to_owned());
    }
    poll_fn(|context| connection.poll_closed(context)).await?;
    let second = timeout(SECOND_CONNECTION_WINDOW, listener.accept()).await;
    Ok((paths, second.is_err()))
}

/// Counts polls of a one-shot request body.
struct PollCountingBody {
    inner: Full<Bytes>,
    polls: Arc<AtomicUsize>,
}

impl Body for PollCountingBody {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_frame(context)
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
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

async fn assert_pending<F>(mut future: Pin<&mut F>, message: &'static str) -> TestResult
where
    F: Future,
{
    poll_fn(|context| match future.as_mut().poll(context) {
        Poll::Pending => Poll::Ready(Ok(())),
        Poll::Ready(_) => Poll::Ready(Err(message.into())),
    })
    .await
}

async fn bounded<F>(future: F) -> TestResult
where
    F: Future<Output = TestResult>,
{
    bounded_within(TEST_TIMEOUT, future).await
}

async fn bounded_within<F>(deadline: Duration, future: F) -> TestResult
where
    F: Future<Output = TestResult>,
{
    timeout(deadline, future)
        .await
        .map_err(|_| "connection retry test exceeded its deadline")?
}
