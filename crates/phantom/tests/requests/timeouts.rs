//! Public phase-aware request timeout behavior.

use crate::support::h2 as h2_support;
use crate::support::h3 as h3_support;
use crate::support::tls as tls_support;

use std::{error::Error, net::Ipv4Addr, num::NonZeroUsize, time::Duration};

use http::{Response, StatusCode};
use http_body::Body;
use http_body_util::BodyExt;
use phantom::{
    BuildErrorKind, Client, HttpProtocol, RedirectPolicy, RequestErrorKind, RequestTimeouts,
    TimeoutPhase, profile::ClientProfile,
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::oneshot,
    time::{sleep, timeout},
};

use tls_support::{
    H1_ALPN, H2_ALPN, TestIdentity, accept_tls, accept_tls_stream, client_builder, read_head,
};

type TestResult<T = ()> = Result<T, Box<dyn Error + Send + Sync>>;
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn timeout_policy_is_owned_by_the_client_and_rejects_clock_overflow() -> TestResult {
    let identity = TestIdentity::generate()?;
    let policy = RequestTimeouts::new()
        .pool_admission(Duration::from_secs(1))
        .connect(Duration::from_secs(2))
        .response_head(Duration::from_secs(3))
        .read_idle(Duration::from_secs(4))
        .total(Duration::from_secs(5));
    let client = client_builder(&identity, false)
        .request_timeouts(policy)
        .build()?;

    assert_eq!(client.request_timeouts(), policy);
    assert_eq!(
        policy.pool_admission_duration(),
        Some(Duration::from_secs(1))
    );
    assert_eq!(policy.connect_duration(), Some(Duration::from_secs(2)));
    assert_eq!(
        policy.response_head_duration(),
        Some(Duration::from_secs(3))
    );
    assert_eq!(policy.read_idle_duration(), Some(Duration::from_secs(4)));
    assert_eq!(policy.total_duration(), Some(Duration::from_secs(5)));
    assert!(format!("{client:?}").contains("request_timeouts"));

    let error = client_builder(&identity, false)
        .request_timeouts(RequestTimeouts::new().total(Duration::MAX))
        .build()
        .err()
        .ok_or("unrepresentable client timeout was accepted")?;
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn request_override_validation_precedes_network_io() -> TestResult {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let client = client_builder(&identity, false).build()?;

    let error = client
        .get(HttpProtocol::Http1, &format!("https://{address}/"))?
        .timeouts(RequestTimeouts::new().total(Duration::MAX))
        .send()
        .await
        .err()
        .ok_or("unrepresentable request timeout was accepted")?;

    assert_eq!(error.kind(), RequestErrorKind::InvalidTimeout);
    assert_eq!(error.timeout_phase(), None);
    assert!(
        timeout(Duration::from_millis(1), listener.accept())
            .await
            .is_err(),
        "invalid timeout touched the network"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn connection_setup_timeout_is_typed_and_installs_no_connection() -> TestResult {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await?;
        std::future::pending::<()>().await;
        Ok::<_, Box<dyn Error + Send + Sync>>(stream)
    });
    let client = client_builder(&identity, false)
        .request_timeouts(RequestTimeouts::new().connect(Duration::from_secs(1)))
        .build()?;

    let error = client
        .get(HttpProtocol::Http1, &format!("https://{address}/"))?
        .send()
        .await
        .err()
        .ok_or("stalled TLS setup did not time out")?;

    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.protocol(), Some(HttpProtocol::Http1));
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Connect));
    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn admission_timeout_does_not_cancel_the_active_http1_exchange() -> TestResult {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let server = tokio::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        read_head(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx")
            .await?;
        std::future::pending::<()>().await;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let client = client_builder(&identity, false)
        .max_pending_http1_requests_per_origin(NonZeroUsize::MIN)
        .request_timeouts(RequestTimeouts::new().pool_admission(Duration::from_secs(1)))
        .build()?;
    let first = client
        .get(HttpProtocol::Http1, &format!("https://{address}/first"))?
        .send()
        .await?;

    let error = client
        .get(HttpProtocol::Http1, &format!("https://{address}/second"))?
        .send()
        .await
        .err()
        .ok_or("pending request did not reach its admission timeout")?;

    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::PoolAdmission));
    assert!(!first.body().is_end_stream());
    drop(first);
    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn response_head_timeout_retires_http1_connection() -> TestResult {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let server = tokio::spawn(async move {
        let (first_tcp, _) = listener.accept().await?;
        let mut first = accept_tls_stream(first_tcp, acceptor.clone()).await?;
        read_head(&mut first).await?;
        sleep(Duration::from_secs(2)).await;
        drop(first);

        let (second_tcp, _) = listener.accept().await?;
        let mut second = accept_tls_stream(second_tcp, acceptor).await?;
        read_head(&mut second).await?;
        second
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let client = client_builder(&identity, false)
        .request_timeouts(RequestTimeouts::new().response_head(Duration::from_secs(1)))
        .build()?;

    let error = client
        .get(HttpProtocol::Http1, &format!("https://{address}/stalled"))?
        .send()
        .await
        .err()
        .ok_or("stalled response head did not time out")?;
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::ResponseHead));

    client
        .get(
            HttpProtocol::Http1,
            &format!("https://{address}/replacement"),
        )?
        .timeouts(RequestTimeouts::default())
        .send()
        .await?
        .into_body()
        .collect()
        .await?;
    server.await??;
    Ok(())
}

#[tokio::test]
async fn response_head_timeout_cancels_only_the_http2_stream() -> TestResult {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H2_ALPN)?;
    let server = tokio::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        h2_support::accept_client_preface(&mut stream).await?;
        h2_support::read_request_headers(&mut stream, 1).await?;

        let mut saw_reset = false;
        let mut answered_later = false;
        loop {
            let frame = h2_support::read_frame(&mut stream).await?;
            if frame.kind == 0x3 && frame.stream_id == 1 {
                assert_eq!(frame.payload, [0, 0, 0, 8]);
                saw_reset = true;
                if answered_later {
                    break;
                }
            }
            if frame.kind == 0x1 && frame.stream_id == 3 {
                h2_support::write_frame(&mut stream, 0x1, 0x5, 3, &[0x89]).await?;
                stream.flush().await?;
                answered_later = true;
                if saw_reset {
                    break;
                }
            }
        }
        Ok::<_, Box<dyn Error + Send + Sync>>(saw_reset)
    });
    let client = client_builder(&identity, true)
        .request_timeouts(RequestTimeouts::new().response_head(Duration::from_millis(100)))
        .build()?;

    let error = client
        .get(HttpProtocol::Http2, &format!("https://{address}/stalled"))?
        .send()
        .await
        .err()
        .ok_or("stalled HTTP/2 response head did not time out")?;
    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.protocol(), Some(HttpProtocol::Http2));
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::ResponseHead));

    timeout(TEST_TIMEOUT, async {
        client
            .get(HttpProtocol::Http2, &format!("https://{address}/later"))?
            .timeouts(RequestTimeouts::default())
            .send()
            .await?
            .into_body()
            .collect()
            .await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "HTTP/2 connection did not survive response-head timeout")??;
    assert!(
        timeout(TEST_TIMEOUT, server)
            .await
            .map_err(|_| "HTTP/2 server did not finish after timeout")???
    );
    Ok(())
}

#[tokio::test]
async fn response_head_timeout_cancels_only_the_http3_stream() -> TestResult {
    let identity = TestIdentity::generate()?;
    let (address, endpoint) = h3_support::server_endpoint(&identity)?;
    let (request_seen, request_received) = oneshot::channel();
    let (inspect_cancel, cancellation_requested) = oneshot::channel();
    let (cancel_checked, cancellation_checked) = oneshot::channel();
    let (client_done, done_received) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (request, mut cancelled, mut connection) =
            h3_support::accept_request(&endpoint).await?;
        assert_eq!(request.uri().path(), "/stalled");
        request_seen
            .send(())
            .map_err(|_| "client stopped before the HTTP/3 request was observed")?;
        cancellation_requested
            .await
            .map_err(|_| "client stopped before HTTP/3 cancellation inspection")?;
        sleep(Duration::from_millis(50)).await;
        let cancellation = cancelled
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await
            .err()
            .ok_or("timed-out HTTP/3 response stream remained writable")?;
        let cancellation_detail = format!("{cancellation:?}");
        let expected_cancellation = matches!(
            cancellation,
            h3::error::StreamError::RemoteTerminate { code, .. }
                if code == h3::error::Code::H3_REQUEST_CANCELLED
        );
        cancel_checked
            .send(cancellation_detail.clone())
            .map_err(|_| "client stopped before HTTP/3 cancellation was reported")?;
        if !expected_cancellation {
            return Err(format!("unexpected HTTP/3 cancellation: {cancellation_detail}").into());
        }

        let resolver = connection
            .accept()
            .await?
            .ok_or("client closed before the later HTTP/3 request")?;
        let (request, mut later) = resolver.resolve_request().await?;
        assert_eq!(request.uri().path(), "/later");
        later
            .send_response(
                Response::builder()
                    .status(StatusCode::NO_CONTENT)
                    .body(())?,
            )
            .await?;
        later.finish().await?;
        let _ = done_received.await;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let client = http3_client(&identity)?;

    let request = client
        .get(HttpProtocol::Http3, &format!("https://{address}/stalled"))?
        .timeouts(RequestTimeouts::new().response_head(Duration::from_millis(100)));
    let request = tokio::spawn(async move { request.send().await });
    request_received
        .await
        .map_err(|_| "HTTP/3 server stopped before observing the request")?;
    let error = request
        .await
        .map_err(|error| format!("HTTP/3 timeout task failed: {error}"))?
        .err()
        .ok_or("stalled HTTP/3 response head did not time out")?;
    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::ResponseHead));
    inspect_cancel
        .send(())
        .map_err(|_| "HTTP/3 server stopped before cancellation inspection")?;
    let cancellation = cancellation_checked
        .await
        .map_err(|_| "HTTP/3 server stopped during cancellation inspection")?;
    assert!(
        cancellation.contains("H3_REQUEST_CANCELLED"),
        "unexpected cancellation: {cancellation}"
    );

    timeout(TEST_TIMEOUT, async {
        client
            .get(HttpProtocol::Http3, &format!("https://{address}/later"))?
            .timeouts(RequestTimeouts::default())
            .send()
            .await?
            .into_body()
            .collect()
            .await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await
    .map_err(|_| "HTTP/3 connection did not survive response-head timeout")??;
    let _ = client_done.send(());
    timeout(TEST_TIMEOUT, server)
        .await
        .map_err(|_| "HTTP/3 server did not finish after timeout")???;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn read_idle_timeout_retires_http1_connection() -> TestResult {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let (head_sent, wait_for_head) = oneshot::channel();
    let (release_first, first_released) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (first_tcp, _) = listener.accept().await?;
        let mut first = accept_tls_stream(first_tcp, acceptor.clone()).await?;
        read_head(&mut first).await?;
        first
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx")
            .await?;
        head_sent
            .send(())
            .map_err(|_| "client stopped before the response head was sent")?;
        first_released
            .await
            .map_err(|_| "client stopped before releasing the first connection")?;
        drop(first);

        let (second_tcp, _) = listener.accept().await?;
        let mut second = accept_tls_stream(second_tcp, acceptor).await?;
        read_head(&mut second).await?;
        second
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let client = client_builder(&identity, false)
        .request_timeouts(RequestTimeouts::new().read_idle(Duration::from_secs(1)))
        .build()?;
    let response = client
        .get(HttpProtocol::Http1, &format!("https://{address}/stalled"))?
        .send()
        .await?;
    wait_for_head
        .await
        .map_err(|_| "server stopped before the response head was sent")?;

    let body = tokio::spawn(async move { response.into_body().collect().await });
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_secs(2)).await;
    let error = body
        .await?
        .err()
        .ok_or("idle response body did not time out")?;
    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::ReadIdle));
    release_first
        .send(())
        .map_err(|_| "server stopped before first-connection release")?;

    client
        .get(
            HttpProtocol::Http1,
            &format!("https://{address}/replacement"),
        )?
        .timeouts(RequestTimeouts::default())
        .send()
        .await?
        .into_body()
        .collect()
        .await?;
    server.await??;
    Ok(())
}

#[tokio::test]
async fn total_deadline_continues_through_response_body_eof() -> TestResult {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let server = tokio::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        read_head(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx")
            .await?;
        std::future::pending::<()>().await;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let client = client_builder(&identity, false)
        .request_timeouts(
            RequestTimeouts::new()
                .read_idle(Duration::from_secs(5))
                .total(Duration::from_millis(500)),
        )
        .build()?;
    let response = client
        .get(HttpProtocol::Http1, &format!("https://{address}/stalled"))?
        .send()
        .await?;
    let error = timeout(TEST_TIMEOUT, response.into_body().collect())
        .await
        .map_err(|_| "response body did not observe its total deadline")?
        .err()
        .ok_or("response body escaped the whole-operation deadline")?;
    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
    server.abort();
    let _ = server.await;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn total_deadline_is_shared_by_redirect_hops() -> TestResult {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let server = tokio::spawn(async move {
        let mut stream = accept_tls(listener, acceptor).await?;
        read_head(&mut stream).await?;
        sleep(Duration::from_secs(4)).await;
        stream
            .write_all(b"HTTP/1.1 302 Found\r\nLocation: /final\r\nContent-Length: 0\r\n\r\n")
            .await?;
        read_head(&mut stream).await?;
        sleep(Duration::from_secs(4)).await;
        let _ = stream
            .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
            .await;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    });
    let client = client_builder(&identity, false)
        .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
        .request_timeouts(
            RequestTimeouts::new()
                .response_head(Duration::from_secs(5))
                .total(Duration::from_secs(6)),
        )
        .build()?;

    let error = client
        .get(HttpProtocol::Http1, &format!("https://{address}/start"))?
        .send()
        .await
        .err()
        .ok_or("redirect chain escaped its total deadline")?;

    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
    server.abort();
    let _ = server.await;
    Ok(())
}

#[test]
fn runtime_without_time_returns_a_typed_error() -> TestResult {
    let identity = TestIdentity::generate()?;
    let client = client_builder(&identity, false)
        .request_timeouts(RequestTimeouts::new().connect(Duration::from_secs(1)))
        .build()?;
    let request = client.get(HttpProtocol::Http1, "https://127.0.0.1:9/")?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;

    let error = runtime
        .block_on(request.send())
        .err()
        .ok_or("request completed on a runtime without time enabled")?;

    assert_eq!(error.kind(), RequestErrorKind::RuntimeUnavailable);
    assert_eq!(error.timeout_phase(), None);
    Ok(())
}

fn http3_client(identity: &TestIdentity) -> TestResult<Client> {
    let mut tcp_tls = tls_support::tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let profile = ClientProfile::new(tcp_tls).with_http3(h3_support::client_settings());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}
