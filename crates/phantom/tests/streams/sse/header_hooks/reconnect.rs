use std::{
    error::Error,
    fmt, io,
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures_util::poll;
use phantom::{
    HeaderHookError, HttpProtocol, RedirectPolicy, RequestErrorKind, RequestHeader, RetryPolicy,
    StatusCode, StatusRetry,
};
use tokio::{io::AsyncWriteExt, sync::Notify, time::timeout};

use crate::support::tls::read_head;

use super::{LIMIT, PendingHook, TestResult, URL, builder, request_error};

#[tokio::test]
async fn mixed_hooks_refresh_each_get_without_rerunning_on_retries_or_redirects() -> TestResult<()>
{
    timeout(LIMIT, async {
        let (builder, mut peers, connections) = builder();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let client = builder
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .retry_policy(RetryPolicy::none().with_status_retry(StatusRetry::new(
                &[StatusCode::SERVICE_UNAVAILABLE], NonZeroUsize::MIN, Duration::ZERO,
            )?))
            .header_hook(|headers| {
                headers.append(RequestHeader::new("Authorization", "secret"))?;
                headers.append(RequestHeader::new("X-Order", "client-sync"))
            })
            .async_header_hook(|headers| Box::pin(async move {
                tokio::task::yield_now().await;
                headers.append(RequestHeader::new("X-Order", "client-async"))
            }))
            .build()?;
        let peer = async move {
            let body = "id: first\ndata: one\n\n";
            let responses = [
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                "HTTP/1.1 302 Found\r\nLocation: http://other.invalid/stream\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()),
                "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_owned(),
            ];
            let mut heads = Vec::new();
            for response in responses {
                let mut stream = peers.recv().await.ok_or("opening connection missing")?;
                heads.push(String::from_utf8(read_head(&mut stream).await?)?);
                stream.write_all(response.as_bytes()).await?;
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(heads)
        };
        let caller = async {
            let response = client.event_source(HttpProtocol::Http1, URL)?
                .header_hook(|headers| headers.append(RequestHeader::new("X-Order", "source-sync")))
                .async_header_hook(move |headers| {
                    let calls = Arc::clone(&observed);
                    Box::pin(async move {
                        tokio::task::yield_now().await;
                        let generation = calls.fetch_add(1, Ordering::SeqCst) + 1;
                        headers.append(RequestHeader::new("X-Generation", generation.to_string()))?;
                        headers.append(RequestHeader::new("X-Order", "source-async"))
                    })
                })
                .initial_retry(Duration::ZERO).max_reconnects(1).connect().await?;
            let mut source = response.into_body();
            assert_eq!(source.next_event().await?.ok_or("first event missing")?.id(), "first");
            assert_eq!(source.next_event().await?, None);
            assert!(source.is_closed());
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        let (heads, ()) = tokio::try_join!(peer, caller)?;
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(connections.load(Ordering::SeqCst), 4);
        for (index, head) in heads.iter().enumerate() {
            let generation = if index == 3 { 2 } else { 1 };
            assert_eq!(head.matches("X-Generation:").count(), 1);
            assert!(head.contains(&format!("X-Generation: {generation}\r\n")));
            assert!(head.contains("X-Order: client-sync\r\nX-Order: client-async\r\nX-Order: source-sync\r\nX-Generation:"));
            assert!(head.contains("\r\nX-Order: source-async\r\n"));
            assert_eq!(head.contains("Authorization: secret\r\n"), index != 2);
            assert_eq!(head.contains("Last-Event-ID: first\r\n"), index == 3);
        }
        assert!(heads[3].starts_with("GET /events HTTP/1.1\r\n"));
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    }).await?
}

#[tokio::test]
async fn skipping_header_hooks_clears_earlier_hooks_and_keeps_the_same_pool() -> TestResult<()> {
    timeout(LIMIT, async {
        let (builder, mut peers, connections) = builder();
        let client = builder
            .header_hook(|_| {
                Err(HeaderHookError::new(io::Error::other(
                    "client hook must be skipped",
                )))
            })
            .build()?;
        let peer = async move {
            let mut stream = peers.recv().await.ok_or("pooled connection missing")?;
            read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await?;
            let head = String::from_utf8(read_head(&mut stream).await?)?;
            assert!(head.contains("X-Allowed: after-clear\r\n"));
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        let caller = async {
            client
                .get_with_protocol(HttpProtocol::Http1, URL)?
                .without_header_hooks()
                .send()
                .await?
                .into_body()
                .collect_with_limit(0)
                .await?;
            let response = client
                .event_source(HttpProtocol::Http1, URL)?
                .header_hook(|_| {
                    Err(HeaderHookError::new(io::Error::other(
                        "source hook must be cleared",
                    )))
                })
                .without_header_hooks()
                .async_header_hook(|headers| {
                    Box::pin(async move {
                        headers.append(RequestHeader::new("X-Allowed", "after-clear"))
                    })
                })
                .connect()
                .await?;
            assert_eq!(response.status(), StatusCode::NO_CONTENT);
            assert_eq!(connections.load(Ordering::SeqCst), 1);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        tokio::try_join!(peer, caller)?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    })
    .await?
}

#[tokio::test]
async fn cancelling_a_read_keeps_its_pending_reconnect_hook_and_committed_id() -> TestResult<()> {
    timeout(LIMIT, async {
        let (builder, mut peers, connections) = builder();
        let client = builder.build()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let entered = Arc::new(Notify::new());
        let signal = Arc::clone(&entered);
        let release = Arc::new(Notify::new());
        let waiting = Arc::clone(&release);
        let dropped = Arc::new(AtomicBool::new(false));
        let lifetime = Arc::clone(&dropped);
        let peer = async move {
            let mut stream = peers.recv().await.ok_or("source connection missing")?;
            read_head(&mut stream).await?;
            let body = "id: first\ndata: one\n\n";
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await?;
            let head = String::from_utf8(read_head(&mut stream).await?)?;
            assert!(head.contains("Last-Event-ID: first\r\n"));
            assert!(head.contains("X-Resumed: yes\r\n"));
            stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        let caller = async {
            let response = client.event_source(HttpProtocol::Http1, URL)?
                .async_header_hook(move |headers| {
                    let index = observed.fetch_add(1, Ordering::SeqCst);
                    let signal = Arc::clone(&signal);
                    let waiting = Arc::clone(&waiting);
                    let lifetime = Arc::clone(&lifetime);
                    Box::pin(async move {
                        if index == 0 { return Ok(()); }
                        let _owner = PendingHook(lifetime);
                        signal.notify_one();
                        waiting.notified().await;
                        headers.append(RequestHeader::new("X-Resumed", "yes"))
                    })
                }).initial_retry(Duration::ZERO).max_reconnects(1).connect().await?;
            let mut source = response.into_body();
            assert_eq!(source.next_event().await?.ok_or("first event missing")?.id(), "first");
            {
                let next = source.next_event();
                tokio::pin!(next);
                tokio::select! {
                    result = &mut next => return Err(format!("reconnect did not await its hook: {result:?}").into()),
                    () = entered.notified() => {}
                }
            }
            assert!(!dropped.load(Ordering::SeqCst));
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            {
                let mut next = Box::pin(source.next_event());
                assert!(poll!(next.as_mut()).is_pending());
            }
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            release.notify_one();
            assert_eq!(source.next_event().await?, None);
            assert!(dropped.load(Ordering::SeqCst));
            assert_eq!(connections.load(Ordering::SeqCst), 1);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        tokio::try_join!(peer, caller)?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    }).await?
}

#[derive(Debug)]
struct HookFailure(Arc<()>);

impl fmt::Display for HookFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("source hook failed")
    }
}

impl Error for HookFailure {}

#[tokio::test]
async fn reconnect_hook_failure_is_terminal_and_keeps_its_original_cause() -> TestResult<()> {
    timeout(LIMIT, async {
        let (builder, mut peers, connections) = builder();
        let client = builder.build()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = Arc::clone(&calls);
        let marker = Arc::new(());
        let failure = Arc::clone(&marker);
        let peer = async move {
            let mut stream = peers.recv().await.ok_or("initial connection missing")?;
            read_head(&mut stream).await?;
            let body = "data: first\n\n";
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await?;
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        let caller = async {
            let response = client.event_source(HttpProtocol::Http1, URL)?
                .async_header_hook(move |_| {
                    let index = observed.fetch_add(1, Ordering::SeqCst);
                    let failure = Arc::clone(&failure);
                    Box::pin(async move {
                        if index == 0 { Ok(()) } else { Err(HeaderHookError::new(HookFailure(failure))) }
                    })
                }).initial_retry(Duration::ZERO).max_reconnects(5).connect().await?;
            let mut source = response.into_body();
            assert_eq!(source.next_event().await?.ok_or("first event missing")?.data(), "first");
            let error = source.next_event().await.err().ok_or("failing hook did not end the source")?;
            let request = request_error(&error)?;
            assert_eq!(request.kind(), RequestErrorKind::HeaderHook);
            let original = request.source().and_then(|cause| cause.downcast_ref::<HeaderHookError>())
                .and_then(Error::source).and_then(|cause| cause.downcast_ref::<HookFailure>())
                .ok_or("source hook lost its original cause")?;
            assert!(Arc::ptr_eq(&original.0, &marker));
            assert!(source.is_closed());
            assert_eq!(source.next_event().await?, None);
            assert_eq!(calls.load(Ordering::SeqCst), 2);
            assert_eq!(connections.load(Ordering::SeqCst), 1);
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        };
        tokio::try_join!(peer, caller)?;
        Ok::<_, Box<dyn Error + Send + Sync>>(())
    }).await?
}
