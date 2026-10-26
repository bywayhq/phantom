//! Logical callbacks retain replay, credential and streaming ownership rules.

use std::{
    net::Ipv4Addr,
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::Duration,
};

use phantom::{
    Client, HeaderHookError, HttpAttemptBudget, HttpProtocol, RedirectPolicy,
    RequestErrorHookContext, RequestErrorKind, RequestHeader, RequestHookContext, RequestHooks,
    ResponseHookContext, RetryPolicy, StatusCode, StatusRetry, profile::ClientProfile,
};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use crate::support::tls::{TestResult, read_head, tls_settings};

const LIMIT: Duration = Duration::from_secs(10);

#[derive(Clone)]
struct Recorder {
    label: &'static str,
    events: Arc<Mutex<Vec<String>>>,
}

impl Recorder {
    fn record(&self, event: String) {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(format!("{}:{event}", self.label));
    }
}

impl RequestHooks for Recorder {
    fn on_request(&self, request: &RequestHookContext<'_>) {
        assert!(!format!("{request:?}").contains("secret"));
        self.record(format!(
            "start:{}:{}",
            request.method(),
            request.uri().path()
        ));
    }

    fn on_response(&self, response: &ResponseHookContext<'_>) {
        assert!(!format!("{response:?}").contains("secret"));
        let Some(info) = response.info() else {
            panic!("response metadata missing");
        };
        assert_eq!(response.version(), http::Version::HTTP_11);
        self.record(format!(
            "head:{}:{}:{}:{}",
            response.status().as_u16(),
            response.request().uri().path(),
            info.effective_uri().path(),
            info.redirects_followed()
        ));
    }

    fn on_error(&self, error: &RequestErrorHookContext<'_>) {
        assert!(error.error().origin().is_some());
        assert!(!format!("{error:?}").contains("secret"));
        self.record(format!(
            "error:{:?}:{}",
            error.error().kind(),
            error.request().uri().path()
        ));
    }
}

fn recorder(label: &'static str, events: &Arc<Mutex<Vec<String>>>) -> Recorder {
    Recorder {
        label,
        events: events.clone(),
    }
}

#[tokio::test]
async fn retries_and_redirects_have_one_callback_pair_before_body_completion() -> TestResult<()> {
    timeout(LIMIT, async {
        let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let second = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let initial = format!("http://{}/initial?secret=one", first.local_addr()?);
        let final_uri = format!("http://{}/final?secret=two", second.local_addr()?);
        let events = Arc::new(Mutex::new(Vec::new()));
        let header_events = events.clone();
        let client = Client::builder(ClientProfile::new(tls_settings()))
            .request_hooks(recorder("client", &events))
            .header_hook(move |headers| {
                header_events.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).push("header".into());
                headers.append(RequestHeader::new("X-Hook", "one"))
            })
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .retry_policy(RetryPolicy::none().with_status_retry(StatusRetry::new(
                &[StatusCode::SERVICE_UNAVAILABLE], NonZeroUsize::MIN, Duration::ZERO)?))
            .build()?;
        let peer = async {
            let mut received = Vec::new();
            for response in [
                "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                format!("HTTP/1.1 302 Found\r\nLocation: {final_uri}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
            ] {
                let (mut socket, _) = first.accept().await?;
                received.push(String::from_utf8(read_head(&mut socket).await?)?);
                socket.write_all(response.as_bytes()).await?;
            }
            let (mut socket, _) = second.accept().await?;
            received.push(String::from_utf8(read_head(&mut socket).await?)?);
            // The head succeeds, but the body cannot reach its declared length.
            socket.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\nX-Secret: secret\r\nConnection: close\r\n\r\nx").await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(received)
        };
        let caller = async {
            let response = client.get_with_protocol(HttpProtocol::Http1, &initial)?
                .request_hooks(recorder("request", &events))
                .header(RequestHeader::new("Authorization", "secret"))
                .header(RequestHeader::new("Cookie", "secret=one"))
                .send().await?;
            assert_eq!(response.status(), StatusCode::NOT_FOUND);
            let before_body = events.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).clone();
            assert_eq!(before_body, ["client:start:GET:/initial", "request:start:GET:/initial",
                "header", "client:head:404:/initial:/final:1", "request:head:404:/initial:/final:1"]);
            assert!(response.into_body().collect_with_limit(100).await.is_err());
            assert_eq!(*events.lock().unwrap_or_else(|poisoned| poisoned.into_inner()), before_body);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let (received, ()) = tokio::try_join!(peer, caller)?;
        assert!(received[0].contains("Authorization: secret\r\n"));
        assert!(received[1].contains("Authorization: secret\r\n"));
        assert!(!received[2].to_ascii_lowercase().contains("authorization:"));
        assert!(!received[2].to_ascii_lowercase().contains("cookie:"));
        for head in received { assert_eq!(head.matches("X-Hook: one\r\n").count(), 1); }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }).await?
}

#[tokio::test]
async fn preparation_errors_notify_both_hooks_without_connecting() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("http://{}/secret", listener.local_addr()?);
    let events = Arc::new(Mutex::new(Vec::new()));
    let client = Client::builder(ClientProfile::new(tls_settings()))
        .request_hooks(recorder("client", &events))
        .build()?;
    let error = client
        .get_with_protocol(HttpProtocol::Http1, &url)?
        .request_hooks(recorder("request", &events))
        .header_hook(|_| Err(HeaderHookError::new(std::io::Error::other("secret"))))
        .send()
        .await
        .err()
        .ok_or("header hook unexpectedly succeeded")?;
    assert_eq!(error.kind(), RequestErrorKind::HeaderHook);
    assert_eq!(
        *events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()),
        [
            "client:start:GET:/secret",
            "request:start:GET:/secret",
            "client:error:HeaderHook:/secret",
            "request:error:HeaderHook:/secret"
        ]
    );
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn shared_budget_exhaustion_is_one_terminal_error_without_a_send() -> TestResult<()> {
    let events = Arc::new(Mutex::new(Vec::new()));
    let client = Client::builder(ClientProfile::new(tls_settings()))
        .request_hooks(recorder("client", &events))
        .build()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let url = format!("http://{}/budget", listener.local_addr()?);
    let clone = client.clone();
    let requests = [&client, &clone].map(|client| {
        client
            .get_with_protocol(HttpProtocol::Http1, &url)
            .map(|request| request.attempt_budget(HttpAttemptBudget::new(0)))
    });
    let [first, second] = requests;
    let (first, second) = tokio::join!(first?.send(), second?.send());
    for result in [first, second] {
        assert_eq!(
            result
                .err()
                .ok_or("budget unexpectedly allowed send")?
                .kind(),
            RequestErrorKind::AttemptBudgetExhausted
        );
    }
    let events = events
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    assert_eq!(
        events
            .iter()
            .filter(|event| event.as_str() == "client:start:GET:/budget")
            .count(),
        2
    );
    assert_eq!(
        events
            .iter()
            .filter(|event| event.as_str() == "client:error:AttemptBudgetExhausted:/budget")
            .count(),
        2
    );
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn unpolled_and_cancelled_sends_do_not_invent_terminal_callbacks() -> TestResult<()> {
    timeout(LIMIT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let uri = format!("http://{}/cancel", listener.local_addr()?);
        let events = Arc::new(Mutex::new(Vec::new()));
        let client = Client::builder(ClientProfile::new(tls_settings()))
            .request_hooks(recorder("client", &events)).build()?;
        drop(client.get_with_protocol(HttpProtocol::Http1, &uri)?.send());
        assert!(events.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).is_empty());
        let peer = async {
            let (mut socket, _) = listener.accept().await?;
            read_head(&mut socket).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(socket)
        };
        let mut send = Box::pin(client.get_with_protocol(HttpProtocol::Http1, &uri)?.send());
        let socket = tokio::select! {
            result = &mut send => return Err(format!("request completed before cancellation: {result:?}").into()),
            socket = peer => socket?,
        };
        drop(send);
        drop(socket);
        assert_eq!(*events.lock().unwrap_or_else(|poisoned| poisoned.into_inner()), ["client:start:GET:/cancel"]);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }).await?
}
