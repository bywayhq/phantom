use std::{
    error::Error,
    future::pending,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures_util::poll;
use phantom::{
    Client, ClientBuilder, ConnectedStream, HeaderHookError, HttpAttemptBudget, HttpProtocol,
    RedirectPolicy, RequestErrorKind, RequestHeader, RequestTimeouts, RetryPolicy, StatusCode,
    StatusRetry, TcpConnector, TimeoutPhase,
    profile::{ClientProfile, Http2PseudoHeader, browser::chrome},
};
use tokio::{
    io::{AsyncWriteExt, DuplexStream},
    sync::{mpsc, oneshot},
    time::{Instant, advance, sleep, timeout},
};

#[cfg(feature = "sse")]
use phantom::RequestError;

use crate::support::{
    h2,
    tls::{TestResult, read_head, tls_settings},
};

const URL: &str = "http://hooks.invalid/start";
const LIMIT: Duration = Duration::from_secs(10);

fn builder() -> (
    ClientBuilder,
    mpsc::Receiver<DuplexStream>,
    Arc<AtomicUsize>,
) {
    let (sender, receiver) = mpsc::channel(2);
    let calls = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&calls);
    let connector = TcpConnector::from_fn(move |_| {
        let sender = sender.clone();
        observed.fetch_add(1, Ordering::SeqCst);
        async move {
            let (client, peer) = tokio::io::duplex(8192);
            sender
                .send(peer)
                .await
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?;
            Ok(ConnectedStream::new(client))
        }
    });
    let mut http2 = chrome::v154_http2();
    http2.pseudo_header_order = vec![
        Http2PseudoHeader::Scheme,
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Authority,
        Http2PseudoHeader::Path,
    ];
    (
        Client::builder(ClientProfile::new(tls_settings()).with_http2(http2))
            .tcp_connector(connector),
        receiver,
        calls,
    )
}

#[tokio::test]
async fn mixed_client_and_request_hooks_preserve_registration_and_field_order() -> TestResult<()> {
    timeout(LIMIT, async {
        let (builder, mut peers, _) = builder();
        let order = Arc::new(Mutex::new(Vec::new()));
        let first = Arc::clone(&order);
        let second = Arc::clone(&order);
        let third = Arc::clone(&order);
        let client = builder
            .header_hook(move |headers| {
                first.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(1);
                headers.append(RequestHeader::new("X-Order", "one"))
            })
            .async_header_hook(move |headers| {
                let order = Arc::clone(&second);
                Box::pin(async move {
                    tokio::task::yield_now().await;
                    order.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(2);
                    headers.append(RequestHeader::new("X-Order", "two"))
                })
            })
            .header_hook(move |headers| {
                third.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(3);
                headers.append(RequestHeader::new("X-Order", "three"))
            })
            .build()?;
        let fourth = Arc::clone(&order);
        let fifth = Arc::clone(&order);
        let caller = async {
            let response = client.get_with_protocol(HttpProtocol::Http1, URL)?
                .async_header_hook(move |headers| {
                    let order = Arc::clone(&fourth);
                    Box::pin(async move {
                        tokio::task::yield_now().await;
                        order.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(4);
                        headers.append(RequestHeader::new("X-Order", "four"))
                    })
                })
                .header_hook(move |headers| {
                    fifth.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push(5);
                    headers.append(RequestHeader::new("X-Order", "five"))
                })
                .send().await?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        let peer = async {
            let mut stream = peers.recv().await.ok_or("connector did not open")?;
            let head = String::from_utf8(read_head(&mut stream).await?)?;
            assert!(head.contains("X-Order: one\r\nX-Order: two\r\nX-Order: three\r\nX-Order: four\r\nX-Order: five\r\n"));
            stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        tokio::try_join!(caller, peer)?;
        assert_eq!(*order.lock().unwrap_or_else(|poisoned| poisoned.into_inner()), [1, 2, 3, 4, 5]);
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    }).await?
}

struct PendingHook(Arc<AtomicBool>);

impl Drop for PendingHook {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn cancelling_a_pending_hook_drops_its_future_without_admitting_an_attempt() -> TestResult<()>
{
    let (builder, mut peers, calls) = builder();
    let client = builder.build()?;
    let dropped = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&dropped);
    let budget = HttpAttemptBudget::new(1);
    let mut send = Box::pin(
        client
            .get_with_protocol(HttpProtocol::Http1, URL)?
            .attempt_budget(budget.clone())
            .async_header_hook(move |headers| {
                let observed = Arc::clone(&observed);
                Box::pin(async move {
                    let _owner = PendingHook(observed);
                    pending::<()>().await;
                    headers.append(RequestHeader::new("X-Late", "never"))
                })
            })
            .send(),
    );

    assert!(poll!(send.as_mut()).is_pending());
    assert!(!dropped.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(budget.remaining(), 1);
    assert!(peers.try_recv().is_err());
    drop(send);
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_total_deadline_cancels_the_hook_without_restarting_between_hooks() -> TestResult<()> {
    let (builder, _, calls) = builder();
    let finished_second = Arc::new(AtomicBool::new(false));
    let observed = Arc::clone(&finished_second);
    let dropped = Arc::new(AtomicBool::new(false));
    let hook_dropped = Arc::clone(&dropped);
    let client = builder
        .request_timeouts(RequestTimeouts::new().total(Duration::from_millis(100)))
        .async_header_hook(|_| {
            Box::pin(async {
                sleep(Duration::from_millis(60)).await;
                Ok(())
            })
        })
        .async_header_hook(move |_| {
            let observed = Arc::clone(&observed);
            let hook_dropped = Arc::clone(&hook_dropped);
            Box::pin(async move {
                let _owner = PendingHook(hook_dropped);
                sleep(Duration::from_millis(60)).await;
                observed.store(true, Ordering::SeqCst);
                Ok(())
            })
        })
        .build()?;
    let start = Instant::now();
    let error = client
        .get_with_protocol(HttpProtocol::Http1, URL)?
        .send()
        .await
        .err()
        .ok_or("hooks exceeded the shared total deadline")?;
    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
    assert_eq!(Instant::now() - start, Duration::from_millis(100));
    assert!(!finished_second.load(Ordering::SeqCst));
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn the_hook_deadline_continues_through_response_body_reads() -> TestResult<()> {
    let (builder, mut peers, _) = builder();
    let client = builder
        .request_timeouts(RequestTimeouts::new().total(Duration::from_millis(100)))
        .async_header_hook(|_| {
            Box::pin(async {
                sleep(Duration::from_millis(60)).await;
                Ok(())
            })
        })
        .build()?;
    let (release, waiting) = oneshot::channel::<()>();
    let peer = async move {
        let mut stream = peers.recv().await.ok_or("connector did not open")?;
        read_head(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx")
            .await?;
        waiting
            .await
            .map_err(|_| "caller dropped the response peer")?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    };
    let caller = async {
        let start = Instant::now();
        let response = client
            .get_with_protocol(HttpProtocol::Http1, URL)?
            .send()
            .await?;
        advance(Duration::from_millis(50)).await;
        let error = response
            .into_body()
            .collect_with_limit(2)
            .await
            .err()
            .ok_or("response body ignored the hook's total deadline")?;
        assert_eq!(Instant::now() - start, Duration::from_millis(110));
        assert_eq!(error.kind(), RequestErrorKind::Timeout);
        assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
        release
            .send(())
            .map_err(|_| "peer stopped before release")?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    };
    tokio::try_join!(peer, caller)?;
    Ok(())
}

#[derive(Debug)]
struct HookFailure(Arc<()>);

impl std::fmt::Display for HookFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("hook failure")
    }
}

impl Error for HookFailure {}

#[tokio::test]
async fn asynchronous_hook_failures_preserve_the_original_error_before_io() -> TestResult<()> {
    let (builder, _, calls) = builder();
    let marker = Arc::new(());
    let observed = Arc::clone(&marker);
    let client = builder
        .async_header_hook(move |_| {
            let observed = Arc::clone(&observed);
            Box::pin(async move {
                tokio::task::yield_now().await;
                Err(HeaderHookError::new(HookFailure(observed)))
            })
        })
        .build()?;
    let error = client
        .get_with_protocol(HttpProtocol::Http1, URL)?
        .send()
        .await
        .err()
        .ok_or("failing async hook sent a request")?;
    assert_eq!(error.kind(), RequestErrorKind::HeaderHook);
    let cause = error
        .source()
        .and_then(|source| source.downcast_ref::<HeaderHookError>())
        .and_then(Error::source)
        .and_then(|source| source.downcast_ref::<HookFailure>())
        .ok_or("async hook failure lost its source")?;
    assert!(Arc::ptr_eq(&cause.0, &marker));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn retries_and_redirects_reuse_async_header_edits_without_reinvoking_the_hook()
-> TestResult<()> {
    timeout(LIMIT, async {
        let (builder, mut peers, _) = builder();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let client = builder.redirect_policy(RedirectPolicy::limited(std::num::NonZeroUsize::MIN))
            .retry_policy(RetryPolicy::none().with_status_retry(StatusRetry::new(
                &[StatusCode::SERVICE_UNAVAILABLE], std::num::NonZeroUsize::MIN, Duration::ZERO,
            )?))
            .async_header_hook(move |headers| {
                let calls = Arc::clone(&observed);
                Box::pin(async move {
                    tokio::task::yield_now().await;
                    calls.fetch_add(1, Ordering::SeqCst);
                    headers.append(RequestHeader::new("X-Hook", "one"))?;
                    headers.append(RequestHeader::new("Authorization", "secret"))
                })
            }).build()?;
        let peer = async {
            for response in [
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
                b"HTTP/1.1 302 Found\r\nLocation: http://other.invalid/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
            ] {
                let mut first = peers.recv().await.ok_or("origin connection missing")?;
                let first_head = String::from_utf8(read_head(&mut first).await?)?;
                assert!(first_head.contains("Authorization: secret\r\n"));
                assert_eq!(first_head.matches("X-Hook: one\r\n").count(), 1);
                first.write_all(response).await?;
            }
            let mut second = peers.recv().await.ok_or("redirect connection missing")?;
            let second_head = String::from_utf8(read_head(&mut second).await?)?;
            assert_eq!(second_head.matches("X-Hook: one\r\n").count(), 1);
            assert!(!second_head.to_ascii_lowercase().contains("authorization:"));
            second.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        let caller = async {
            assert_eq!(client.get_with_protocol(HttpProtocol::Http1, URL)?.send().await?.status(), StatusCode::NO_CONTENT);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        tokio::try_join!(caller, peer)?;
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    }).await?
}

#[tokio::test]
async fn cancelling_a_header_hook_preserves_an_existing_http2_stream() -> TestResult<()> {
    timeout(LIMIT, async {
        let (builder, mut peers, calls) = builder();
        let client = builder.build()?;
        let (release, waiting) = oneshot::channel::<()>();
        let peer = async move {
            let mut stream = peers.recv().await.ok_or("HTTP/2 connection missing")?;
            h2::accept_client_preface(&mut stream).await?;
            h2::read_request_headers(&mut stream, 1).await?;
            h2::write_frame(&mut stream, 1, 4, 1, &[0x88]).await?;
            waiting
                .await
                .map_err(|_| "caller stopped before body release")?;
            h2::write_frame(&mut stream, 0, 1, 1, b"ok").await?;
            h2::read_request_headers(&mut stream, 3).await?;
            h2::write_frame(&mut stream, 1, 5, 3, &[0x88]).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        let caller = async {
            let response = client
                .get_with_protocol(HttpProtocol::Http2, URL)?
                .send()
                .await?;
            let mut cancelled = Box::pin(
                client
                    .get_with_protocol(HttpProtocol::Http2, URL)?
                    .async_header_hook(|_| Box::pin(pending()))
                    .send(),
            );
            assert!(poll!(cancelled.as_mut()).is_pending());
            drop(cancelled);
            release.send(()).map_err(|_| "HTTP/2 peer stopped early")?;
            assert_eq!(
                response.into_body().collect_with_limit(2).await?.as_ref(),
                b"ok"
            );
            assert_eq!(
                client
                    .get_with_protocol(HttpProtocol::Http2, URL)?
                    .send()
                    .await?
                    .status(),
                StatusCode::OK
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        tokio::try_join!(peer, caller)?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await?
}

#[tokio::test]
async fn async_hooks_cannot_invalidate_prepared_body_metadata() -> TestResult<()> {
    let (builder, _, calls) = builder();
    let client = builder.build()?;
    let error = client
        .request_with_protocol(HttpProtocol::Http1, phantom::Method::POST, URL)?
        .prepared_body(phantom::PreparedRequestBody::form([("key", "value")], 100)?)
        .header(RequestHeader::new(
            "Content-Type",
            "application/x-www-form-urlencoded",
        ))
        .async_header_hook(|headers| Box::pin(async move { headers.remove("content-type") }))
        .send()
        .await
        .err()
        .ok_or("async hook removed prepared body metadata")?;
    assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[cfg(feature = "sse")]
#[tokio::test]
async fn async_hooks_cannot_replace_the_event_sources_managed_id() -> TestResult<()> {
    let (builder, _, calls) = builder();
    let client = builder
        .async_header_hook(|headers| {
            Box::pin(async move { headers.append(RequestHeader::new("Last-Event-ID", "caller")) })
        })
        .build()?;
    let error = client
        .event_source(HttpProtocol::Http1, URL)?
        .max_reconnects(0)
        .connect()
        .await
        .err()
        .ok_or("async hook replaced the managed event ID")?;
    let request = error
        .source()
        .and_then(|source| source.downcast_ref::<RequestError>())
        .ok_or("event source lost the header hook failure")?;
    assert_eq!(request.kind(), RequestErrorKind::HeaderHook);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}
