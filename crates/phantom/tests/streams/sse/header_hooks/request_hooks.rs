use std::{
    future::Future,
    io,
    pin::Pin,
    sync::{Arc, Mutex, atomic::Ordering},
    time::Duration,
};

use phantom::{
    AsyncRequestHooks, HttpProtocol, RequestErrorKind, RequestHookContext, RequestHookError,
    RequestHooks, ResponseHookContext,
};
use tokio::{io::AsyncWriteExt, time::timeout};

use crate::support::tls::read_head;

use super::{LIMIT, TestResult, URL, builder, request_error};

type Calls = Arc<Mutex<Vec<&'static str>>>;

struct ClientObserver(Calls);

impl RequestHooks for ClientObserver {
    fn on_request(&self, _: &RequestHookContext<'_>) {
        self.0
            .lock()
            .expect("observer mutex poisoned")
            .push("client request");
    }

    fn on_response(&self, _: &ResponseHookContext<'_>) {
        self.0
            .lock()
            .expect("observer mutex poisoned")
            .push("client response");
    }
}

struct SourceObserver(Calls);

impl AsyncRequestHooks for SourceObserver {
    fn on_request<'a>(
        &'a self,
        _: &'a RequestHookContext<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<(), RequestHookError>> + Send + 'a>> {
        Box::pin(async move {
            tokio::task::yield_now().await;
            self.0
                .lock()
                .expect("observer mutex poisoned")
                .push("source request");
            Ok(())
        })
    }

    fn on_response<'a>(
        &'a self,
        _: &'a ResponseHookContext<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<(), RequestHookError>> + Send + 'a>> {
        Box::pin(async move {
            tokio::task::yield_now().await;
            self.0
                .lock()
                .expect("observer mutex poisoned")
                .push("source response");
            Ok(())
        })
    }
}

#[tokio::test]
async fn each_get_observes_client_then_source_hooks() -> TestResult<()> {
    timeout(LIMIT, async {
        let (builder, mut peers, _) = builder();
        let calls = Calls::default();
        let client = builder.request_hooks(ClientObserver(Arc::clone(&calls))).build()?;
        let peer = async move {
            let mut stream = peers.recv().await.ok_or("source connection missing")?;
            read_head(&mut stream).await?;
            let body = "data: first\n\n";
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\n\r\n{body}", body.len()).as_bytes()).await?;
            read_head(&mut stream).await?;
            stream.write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n").await?;
            TestResult::Ok(())
        };
        let caller = async {
            let mut source = client.event_source(HttpProtocol::Http1, URL)?
                .request_hooks(ClientObserver(Arc::clone(&calls)))
                .async_request_hooks(SourceObserver(Arc::clone(&calls)))
                .initial_retry(Duration::ZERO).max_reconnects(1)
                .connect().await?.into_body();
            assert_eq!(source.next_event().await?.ok_or("first event missing")?.data(), "first");
            assert_eq!(source.next_event().await?, None);
            TestResult::Ok(())
        };
        tokio::try_join!(peer, caller)?;
        assert_eq!(*calls.lock().expect("observer mutex poisoned"), [
            "client request", "source request", "client response", "source response",
            "client request", "source request", "client response", "source response",
        ]);
        TestResult::Ok(())
    }).await?
}

struct Reject;

impl AsyncRequestHooks for Reject {
    fn on_request<'a>(
        &'a self,
        _: &'a RequestHookContext<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<(), RequestHookError>> + Send + 'a>> {
        Box::pin(async { Err(RequestHookError::new(io::Error::other("observer rejected"))) })
    }
}

#[tokio::test]
async fn rejected_source_observer_never_opens_or_reconnects() -> TestResult<()> {
    let (builder, mut peers, connections) = builder();
    let client = builder.build()?;
    let error = client
        .event_source(HttpProtocol::Http1, URL)?
        .async_request_hooks(Reject)
        .initial_retry(Duration::ZERO)
        .max_reconnects(3)
        .connect()
        .await
        .expect_err("observer must reject");
    assert_eq!(request_error(&error)?.kind(), RequestErrorKind::RequestHook);
    assert_eq!(connections.load(Ordering::SeqCst), 0);
    assert!(peers.try_recv().is_err());
    Ok(())
}
