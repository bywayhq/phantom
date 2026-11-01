use super::*;

#[tokio::test(start_paused = true)]
async fn one_deadline_covers_request_header_and_error_callbacks() -> TestResult<()> {
    let (builder, _, calls) = builder();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let mut observer = Probe::new("client", &recorded);
    observer.request = Step::Delay(Duration::from_millis(60));
    observer.error = Step::Delay(Duration::from_millis(20));
    let client = builder
        .async_request_hooks(observer)
        .request_timeouts(RequestTimeouts::new().total(Duration::from_millis(100)))
        .async_header_hook(|_| {
            Box::pin(async {
                sleep(Duration::from_millis(30)).await;
                Ok(())
            })
        })
        .build()?;
    let start = Instant::now();
    let error = client
        .get_with_protocol(HttpProtocol::Http1, URL)?
        .header(RequestHeader::new("Host", "forbidden.invalid"))
        .send()
        .await
        .err()
        .ok_or("request ignored its deadline")?;
    assert_eq!(Instant::now() - start, Duration::from_millis(100));
    assert_eq!(error.kind(), RequestErrorKind::InvalidHeader);
    assert_eq!(error.timeout_phase(), None);
    let failure = error
        .source()
        .and_then(|source| source.downcast_ref::<RequestErrorHookFailure>())
        .ok_or("terminal timeout lost the original failure")?;
    assert_eq!(
        failure.original_error().kind(),
        RequestErrorKind::InvalidHeader
    );
    assert_eq!(failure.hook_error().kind(), RequestErrorKind::Timeout);
    assert_eq!(
        failure.hook_error().timeout_phase(),
        Some(TimeoutPhase::Total)
    );
    assert_eq!(
        events(&recorded),
        ["client:request", "client:error:InvalidHeader"]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn response_callback_and_body_keep_the_initial_request_deadline() -> TestResult<()> {
    let (builder, mut peers, _) = builder();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let mut observer = Probe::new("client", &recorded);
    observer.request = Step::Delay(Duration::from_millis(30));
    observer.response = Step::Delay(Duration::from_millis(30));
    let client = builder
        .async_request_hooks(observer)
        .request_timeouts(RequestTimeouts::new().total(Duration::from_millis(100)))
        .async_header_hook(|_| {
            Box::pin(async {
                sleep(Duration::from_millis(20)).await;
                Ok(())
            })
        })
        .build()?;
    let (release, waiting) = tokio::sync::oneshot::channel();
    let peer = async {
        let mut stream = peers.recv().await.ok_or("response connection missing")?;
        read_head(&mut stream).await?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx")
            .await?;
        waiting.await.map_err(|_| "caller dropped body peer")?;
        TestResult::Ok(())
    };
    let caller = async {
        let start = Instant::now();
        let response = client
            .get_with_protocol(HttpProtocol::Http1, URL)?
            .send()
            .await?;
        assert_eq!(Instant::now() - start, Duration::from_millis(80));
        let error = response
            .into_body()
            .collect_with_limit(2)
            .await
            .err()
            .ok_or("body ignored the shared deadline")?;
        assert_eq!(Instant::now() - start, Duration::from_millis(100));
        assert_eq!(error.kind(), RequestErrorKind::Timeout);
        assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
        assert_eq!(events(&recorded), ["client:request", "client:response:200"]);
        release.send(()).map_err(|_| "body peer stopped early")?;
        TestResult::Ok(())
    };
    tokio::try_join!(peer, caller)?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn request_timeout_drops_the_callback_and_allows_a_ready_error_observer() -> TestResult<()> {
    let (builder, _, calls) = builder();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let dropped = Arc::new(AtomicUsize::new(0));
    let mut observer = Probe::new("client", &recorded);
    observer.request = Step::Pending {
        entered: Arc::new(Notify::new()),
        dropped: Arc::clone(&dropped),
    };
    let client = builder
        .async_request_hooks(observer)
        .request_timeouts(RequestTimeouts::new().total(Duration::from_millis(100)))
        .build()?;
    let start = Instant::now();
    let error = client
        .get_with_protocol(HttpProtocol::Http1, URL)?
        .send()
        .await
        .err()
        .ok_or("pending request callback completed")?;
    assert_eq!(Instant::now() - start, Duration::from_millis(100));
    assert_eq!(error.kind(), RequestErrorKind::Timeout);
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
    assert!(error.source().is_none());
    assert_eq!(
        events(&recorded),
        ["client:request", "client:error:Timeout"]
    );
    assert_eq!(dropped.load(Ordering::SeqCst), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn invalid_or_unavailable_timers_do_not_admit_an_async_callback() -> TestResult<()> {
    use phantom::{RequestTimeoutOverrides, TimeoutOverride};
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let (builder, _, calls) = builder();
    let client = builder
        .async_request_hooks(Probe::new("client", &recorded))
        .request_timeouts(RequestTimeouts::new().total(Duration::from_secs(1)))
        .build()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    for (override_, expected) in [
        (
            RequestTimeoutOverrides::new(),
            RequestErrorKind::RuntimeUnavailable,
        ),
        (
            RequestTimeoutOverrides::disabled().total(TimeoutOverride::Limit(Duration::MAX)),
            RequestErrorKind::InvalidTimeout,
        ),
    ] {
        let error = runtime
            .block_on(
                client
                    .get_with_protocol(HttpProtocol::Http1, URL)?
                    .timeouts(override_)
                    .send(),
            )
            .err()
            .ok_or("invalid timer admitted a callback")?;
        assert_eq!(error.kind(), expected);
        assert!(error.origin().is_some());
        assert!(events(&recorded).is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    Ok(())
}
