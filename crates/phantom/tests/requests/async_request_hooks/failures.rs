use super::*;

fn callback_cause(error: &RequestError) -> TestResult<&Cause> {
    error
        .source()
        .and_then(|source| source.downcast_ref::<RequestHookError>())
        .and_then(Error::source)
        .and_then(|source| source.downcast_ref::<Cause>())
        .ok_or_else(|| "callback lost its typed cause".into())
}

#[tokio::test]
async fn request_failure_enters_error_once_without_spending_an_attempt() -> TestResult<()> {
    let (builder, _, calls) = builder();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let marker = Arc::new(());
    let mut observer = Probe::new("client", &recorded);
    observer.request = Step::Fail(Arc::clone(&marker));
    let client = builder.async_request_hooks(observer).build()?;
    let budget = HttpAttemptBudget::new(1);
    let error = client
        .get_with_protocol(HttpProtocol::Http1, URL)?
        .request_hooks(SyncProbe(Probe::new("request", &recorded)))
        .attempt_budget(budget.clone())
        .send()
        .await
        .err()
        .ok_or("failed callback sent")?;
    assert_eq!(error.kind(), RequestErrorKind::RequestHook);
    assert!(error.origin().is_some());
    assert!(Arc::ptr_eq(&callback_cause(&error)?.0, &marker));
    assert_eq!(
        events(&recorded),
        [
            "client:request",
            "client:error:RequestHook",
            "request:error:RequestHook"
        ]
    );
    assert_eq!(budget.remaining(), 1);
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!format!("{error:?} {error}").contains("secret"));
    Ok(())
}

#[tokio::test]
async fn error_callback_failure_preserves_both_causes_and_original_metadata() -> TestResult<()> {
    let (builder, _, calls) = builder();
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let original = Arc::new(());
    let callback = Arc::new(());
    let mut observer = Probe::new("client", &recorded);
    observer.error = Step::Fail(Arc::clone(&callback));
    let marker = Arc::clone(&original);
    let client = builder
        .async_request_hooks(observer)
        .header_hook(move |_| Err(HeaderHookError::new(Cause(Arc::clone(&marker)))))
        .build()?;
    let error = client
        .get_with_protocol(HttpProtocol::Http1, URL)?
        .send()
        .await
        .err()
        .ok_or("header failure succeeded")?;
    assert_eq!(error.kind(), RequestErrorKind::HeaderHook);
    assert_eq!(error.protocol(), None);
    assert_eq!(error.timeout_phase(), None);
    let failure = error
        .source()
        .and_then(|source| source.downcast_ref::<RequestErrorHookFailure>())
        .ok_or("error callback discarded the original failure")?;
    assert_eq!(error.origin(), failure.original_error().origin());
    assert_eq!(
        error.replay_observation(),
        failure.original_error().replay_observation()
    );
    let cause = failure
        .original_error()
        .source()
        .and_then(|source| source.downcast_ref::<HeaderHookError>())
        .and_then(Error::source)
        .and_then(|source| source.downcast_ref::<Cause>())
        .ok_or("lost header cause")?;
    assert!(Arc::ptr_eq(&cause.0, &original));
    assert_eq!(failure.hook_error().kind(), RequestErrorKind::RequestHook);
    assert!(Arc::ptr_eq(
        &callback_cause(failure.hook_error())?.0,
        &callback
    ));
    assert_eq!(
        events(&recorded),
        ["client:request", "client:error:HeaderHook"]
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(!format!("{failure:?} {failure} {error:?} {error}").contains("secret"));
    Ok(())
}

#[tokio::test]
async fn response_failure_drops_the_body_without_entering_error() -> TestResult<()> {
    timeout(LIMIT, async {
        let (builder, mut peers, _) = builder();
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let marker = Arc::new(());
        let mut observer = Probe::new("client", &recorded);
        observer.response = Step::Fail(Arc::clone(&marker));
        let client = builder.async_request_hooks(observer).build()?;
        let peer = async {
            use tokio::io::AsyncReadExt;
            let mut stream = peers.recv().await.ok_or("response connection missing")?;
            read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
                .await?;
            let mut byte = [0];
            assert_eq!(stream.read(&mut byte).await?, 0);
            TestResult::Ok(())
        };
        let caller = async {
            let mut request = client.get_with_protocol(HttpProtocol::Http1, URL)?;
            let trace = request.diagnostics(std::num::NonZeroUsize::MIN.saturating_add(15));
            let error = request
                .send()
                .await
                .err()
                .ok_or("failed response hook returned a body")?;
            assert_eq!(
                trace.snapshot().outcome,
                phantom::RequestTimelineOutcome::Failed
            );
            assert_eq!(error.kind(), RequestErrorKind::RequestHook);
            assert_eq!(error.protocol(), Some(HttpProtocol::Http1));
            assert!(Arc::ptr_eq(&callback_cause(&error)?.0, &marker));
            assert_eq!(events(&recorded), ["client:request", "client:response:200"]);
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        TestResult::Ok(())
    })
    .await?
}
