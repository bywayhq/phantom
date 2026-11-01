use std::{future::pending, sync::Arc};

use futures_util::poll;
use phantom::{HttpAttemptBudget, RedirectDecision, RequestTimeouts, TimeoutPhase};
use tokio::sync::Notify;

use super::*;

#[tokio::test]
async fn pending_decision_delays_the_next_attempt_and_follow_keeps_the_shared_allowance()
-> TestResult<()> {
    let mut server = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (heads_tx, mut heads) = tokio::sync::mpsc::unbounded_channel();
        server = Some(HopServer::spawn(listener, heads_tx, |path| {
            (path == "/start").then(|| "/final".into())
        }));
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let observed = Arc::clone(&entered);
        let waiting = Arc::clone(&release);
        let client = client_builder(&identity, false)
            .redirect_policy(RedirectPolicy::custom_async(NonZeroUsize::MIN, move |hop| {
                let entered = Arc::clone(&observed);
                let release = Arc::clone(&waiting);
                Box::pin(async move {
                    entered.notify_one();
                    release.notified().await;
                    assert_eq!(hop.to_url().path(), "/final");
                    Ok(RedirectDecision::Follow)
                })
            }))
            .build()?;
        let budget = HttpAttemptBudget::new(2);
        let mut send = Box::pin(client
            .get_with_protocol(HttpProtocol::Http1, &format!("http://{address}/start"))?
            .attempt_budget(budget.clone())
            .send());
        tokio::select! {
            () = entered.notified() => {},
            result = send.as_mut() => return Err(format!("request ended before decision: {result:?}").into()),
        }
        assert_eq!(budget.remaining(), 1);
        assert!(heads.recv().await.ok_or("initial request absent")?.starts_with(b"GET /start "));
        assert!(heads.try_recv().is_err());
        assert!(poll!(send.as_mut()).is_pending());

        release.notify_one();
        let response = send.await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;
        assert_eq!(budget.remaining(), 0);
        assert!(heads.recv().await.ok_or("followed request absent")?.starts_with(b"GET /final "));
        assert!(heads.try_recv().is_err());
        Ok(())
    }).await;
    let cleanup = match server.as_mut() {
        Some(peer) => peer.shutdown().await,
        None => Ok(()),
    };
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn stopping_an_awaited_decision_returns_the_original_body_without_draining_it()
-> TestResult<()> {
    let mut server = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (release, waiting) = oneshot::channel();
        server = Some(ConnectionPeer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = tls_support::read_head(&mut stream).await?;
            assert!(head.starts_with(b"GET /start "));
            stream.write_all(b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 4\r\nConnection: close\r\n\r\nre").await?;
            waiting.await.map_err(|_| "caller stopped before body release")?;
            stream.write_all(b"st").await?;
            Ok(())
        }));
        let client = client_builder(&identity, false)
            .redirect_policy(RedirectPolicy::custom_async(NonZeroUsize::MIN, |_| {
                Box::pin(async {
                    tokio::task::yield_now().await;
                    Ok(RedirectDecision::Stop)
                })
            }))
            .build()?;
        let budget = HttpAttemptBudget::new(1);
        let response = client.get_with_protocol(HttpProtocol::Http1, &format!("http://{address}/start"))?
            .attempt_budget(budget.clone()).send().await?;
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(budget.remaining(), 0);
        release.send(()).map_err(|_| "peer stopped before body release")?;
        assert_eq!(response.into_body().collect_with_limit(4).await?.as_ref(), b"rest");
        Ok(())
    }).await;
    let cleanup = match server.as_mut() {
        Some(peer) => peer.shutdown().await,
        None => Ok(()),
    };
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn cancelling_a_redirect_decision_keeps_an_active_http2_sibling_and_connection()
-> TestResult<()> {
    let mut server = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (done, mut finished) = oneshot::channel();
        server = Some(ConnectionPeer::spawn(async move {
            let (stream, _) = listener.accept().await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (healthy, mut respond) = accept_request(&mut connection).await?;
            assert_eq!(healthy.uri().path(), "/healthy");
            let mut healthy_body = respond.send_response(Response::new(()), false)?;
            let (redirect, mut respond) = accept_request(&mut connection).await?;
            assert_eq!(redirect.uri().path(), "/start");
            let mut redirect_body = respond.send_response(
                Response::builder().status(StatusCode::FOUND).header("location", "/next").body(())?,
                false,
            )?;
            tokio::select! {
                reset = poll_fn(|context| redirect_body.poll_reset(context)) => {
                    assert_eq!(reset?, ::http2::Reason::CANCEL);
                },
                request = connection.accept() => return Err(format!("unexpected hop before cancellation: {request:?}").into()),
            }
            healthy_body.send_data(Bytes::from_static(b"ok"), true)?;
            let (reused, mut respond) = accept_request(&mut connection).await?;
            assert_eq!(reused.uri().path(), "/reused");
            respond.send_response(Response::new(()), true)?;
            tokio::select! {
                result = &mut finished => result?,
                closed = poll_fn(|context| connection.poll_closed(context)) => {
                    finish_h2_redirect(closed)?;
                    finished.await?;
                },
            }
            Ok(())
        }));
        let client = client_builder(&identity, false).build()?;
        let healthy = client.get_with_protocol(HttpProtocol::Http2, &format!("http://{address}/healthy"))?.send().await?;
        let entered = Arc::new(Notify::new());
        let observed = Arc::clone(&entered);
        let budget = HttpAttemptBudget::new(2);
        let mut cancelled = Box::pin(client.get_with_protocol(HttpProtocol::Http2, &format!("http://{address}/start"))?
            .attempt_budget(budget.clone())
            .redirect_policy(RedirectPolicy::custom_async(NonZeroUsize::MIN, move |_| {
                let entered = Arc::clone(&observed);
                Box::pin(async move {
                    entered.notify_one();
                    pending().await
                })
            })).send());
        tokio::select! {
            () = entered.notified() => {},
            result = cancelled.as_mut() => return Err(format!("request ended before decision: {result:?}").into()),
        }
        assert_eq!(budget.remaining(), 1);
        drop(cancelled);
        assert_eq!(healthy.into_body().collect_with_limit(2).await?.as_ref(), b"ok");
        let response = client.get_with_protocol(HttpProtocol::Http2, &format!("http://{address}/reused"))?.send().await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect_with_limit(0).await?;
        done.send(()).map_err(|_| "HTTP/2 peer stopped before completion")?;
        server.as_mut().ok_or("HTTP/2 peer absent")?.join().await??;
        Ok(())
    }).await;
    let cleanup = match server.as_mut() {
        Some(peer) => peer.shutdown().await,
        None => Ok(()),
    };
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn request_total_deadline_bounds_an_awaited_redirect_decision() -> TestResult<()> {
    let mut server = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (heads_tx, mut heads) = tokio::sync::mpsc::unbounded_channel();
        server = Some(HopServer::spawn(listener, heads_tx, |_| Some("/next".into())));
        let entered = Arc::new(Notify::new());
        let observed = Arc::clone(&entered);
        let client = client_builder(&identity, false)
            .request_timeouts(RequestTimeouts::new().total(Duration::from_secs(3)))
            .redirect_policy(RedirectPolicy::custom_async(NonZeroUsize::MIN, move |_| {
                let entered = Arc::clone(&observed);
                Box::pin(async move {
                    entered.notify_one();
                    pending().await
                })
            })).build()?;
        let budget = HttpAttemptBudget::new(2);
        let mut send = Box::pin(client.get_with_protocol(HttpProtocol::Http1, &format!("http://{address}/start"))?
            .attempt_budget(budget.clone()).send());
        tokio::select! {
            () = entered.notified() => {},
            result = send.as_mut() => return Err(format!("request ended before decision: {result:?}").into()),
        }
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(3)).await;
        let result = send.await;
        tokio::time::resume();
        let error = result.err().ok_or("pending decision escaped the deadline")?;
        assert_eq!(error.kind(), RequestErrorKind::Timeout);
        assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
        assert_eq!(budget.remaining(), 1);
        assert!(heads.recv().await.ok_or("initial request absent")?.starts_with(b"GET /start "));
        assert!(heads.try_recv().is_err());
        Ok(())
    }).await;
    let cleanup = match server.as_mut() {
        Some(peer) => peer.shutdown().await,
        None => Ok(()),
    };
    finish_with_cleanup(primary, cleanup)
}
