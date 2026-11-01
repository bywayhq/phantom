use super::*;

use futures_util::poll;

#[tokio::test]
async fn unpolled_sends_have_no_callbacks() -> TestResult<()> {
    let recorded = Arc::new(Mutex::new(Vec::new()));
    let (builder, _, calls) = builder();
    let client = builder
        .async_request_hooks(Probe::new("client", &recorded))
        .build()?;
    drop(client.get_with_protocol(HttpProtocol::Http1, URL)?.send());
    assert!(events(&recorded).is_empty());
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[tokio::test]
async fn shutdown_waits_for_request_and_error_callbacks_until_the_send_is_dropped() -> TestResult<()>
{
    for phase in ["request", "error"] {
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let (builder, _, calls) = builder();
        let dropped = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(Notify::new());
        let step = Step::Pending {
            entered: Arc::clone(&entered),
            dropped: Arc::clone(&dropped),
        };
        let mut observer = Probe::new("client", &recorded);
        if phase == "request" {
            observer.request = step;
        } else {
            observer.error = step;
        }
        let client = builder.async_request_hooks(observer).build()?;
        let mut request = client
            .get_with_protocol(HttpProtocol::Http1, URL)?
            .header_hook(|_| Err(HeaderHookError::new(io::Error::other("header failure"))));
        let trace = request.diagnostics(std::num::NonZeroUsize::MIN);
        let mut send = Box::pin(request.send());
        tokio::select! {
            result = &mut send => return Err(format!("callback did not wait: {result:?}").into()),
            () = entered.notified() => {}
        }
        assert_eq!(
            trace.snapshot().outcome,
            phantom::RequestTimelineOutcome::Pending
        );
        let mut shutdown = Box::pin(client.shutdown());
        assert!(poll!(shutdown.as_mut()).is_pending());
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        drop(send);
        assert_eq!(
            trace.snapshot().outcome,
            phantom::RequestTimelineOutcome::Cancelled
        );
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
        shutdown.await;
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            events(&recorded),
            if phase == "request" {
                vec!["client:request"]
            } else {
                vec!["client:request", "client:error:HeaderHook"]
            }
        );
    }
    Ok(())
}

#[tokio::test]
async fn cancelling_a_response_callback_preserves_a_live_http2_sibling() -> TestResult<()> {
    use crate::support::h2;
    timeout(LIMIT, async {
        let (builder, mut peers, calls) = builder();
        let client = builder.build()?;
        let recorded = Arc::new(Mutex::new(Vec::new()));
        let dropped = Arc::new(AtomicUsize::new(0));
        let entered = Arc::new(Notify::new());
        let mut observer = Probe::new("request", &recorded);
        observer.response = Step::Pending { entered: Arc::clone(&entered), dropped: Arc::clone(&dropped) };
        let (release, waiting) = tokio::sync::oneshot::channel();
        let peer = async {
            let mut stream = peers.recv().await.ok_or("HTTP/2 connection missing")?;
            h2::accept_client_preface(&mut stream).await?;
            h2::read_request_headers(&mut stream, 1).await?;
            h2::write_frame(&mut stream, 1, 4, 1, &[0x88]).await?;
            h2::read_request_headers(&mut stream, 3).await?;
            h2::write_frame(&mut stream, 1, 4, 3, &[0x88]).await?;
            waiting.await.map_err(|_| "caller dropped the sibling peer")?;
            h2::write_frame(&mut stream, 0, 1, 1, b"tail").await?;
            h2::read_request_headers(&mut stream, 5).await?;
            h2::write_frame(&mut stream, 1, 5, 5, &[0x88]).await?;
            TestResult::Ok(())
        };
        let caller = async {
            let sibling = client.get_with_protocol(HttpProtocol::Http2, URL)?.send().await?;
            let mut request = client.get_with_protocol(HttpProtocol::Http2, URL)?.async_request_hooks(observer);
            let trace = request.diagnostics(std::num::NonZeroUsize::MIN.saturating_add(15));
            let mut send = Box::pin(request.send());
            tokio::select! {
                result = &mut send => return Err(format!("response callback did not wait: {result:?}").into()),
                () = entered.notified() => {}
            }
            assert_eq!(trace.snapshot().outcome, phantom::RequestTimelineOutcome::Pending);
            drop(send);
            assert_eq!(trace.snapshot().outcome, phantom::RequestTimelineOutcome::Cancelled);
            assert_eq!(dropped.load(Ordering::SeqCst), 1);
            assert_eq!(events(&recorded), ["request:request", "request:response:200"]);
            release.send(()).map_err(|_| "HTTP/2 peer stopped early")?;
            assert_eq!(sibling.into_body().collect_with_limit(4).await?.as_ref(), b"tail");
            assert_eq!(client.get_with_protocol(HttpProtocol::Http2, URL)?.send().await?.status(), StatusCode::OK);
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        TestResult::Ok(())
    }).await?
}
