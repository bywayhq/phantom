use std::{
    error::Error,
    fmt,
    future::{Future, pending},
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use phantom::{
    AsyncRequestHooks, Client, ClientBuilder, ConnectedStream, HeaderHookError, HttpAttemptBudget,
    HttpProtocol, RedirectPolicy, RequestError, RequestErrorHookContext, RequestErrorHookFailure,
    RequestErrorKind, RequestHeader, RequestHookContext, RequestHookError, RequestHooks,
    RequestTimeouts, ResponseHookContext, RetryPolicy, StatusCode, StatusRetry, TcpConnector,
    TimeoutPhase,
    profile::{ClientProfile, browser::chrome},
};
use tokio::{
    io::{AsyncWriteExt, DuplexStream},
    sync::{Notify, mpsc},
    time::{Instant, sleep, timeout},
};

use crate::support::tls::{TestResult, read_head, tls_settings};

mod cancellation;
mod deadlines;
mod failures;

const URL: &str = "http://hooks.invalid/private?secret=one";
const LIMIT: Duration = Duration::from_secs(10);
type HookFuture<'a> = Pin<Box<dyn Future<Output = Result<(), RequestHookError>> + Send + 'a>>;

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
    (
        Client::builder(ClientProfile::new(tls_settings()).with_http2(chrome::v154_http2()))
            .tcp_connector(connector),
        receiver,
        calls,
    )
}

#[derive(Debug)]
struct Cause(Arc<()>);

impl fmt::Display for Cause {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("secret callback failure")
    }
}

impl Error for Cause {}

enum Step {
    Ready,
    Fail(Arc<()>),
    Delay(Duration),
    Pending {
        entered: Arc<Notify>,
        dropped: Arc<AtomicUsize>,
    },
}

struct PendingCall(Arc<AtomicUsize>);

impl Drop for PendingCall {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

struct Probe {
    label: &'static str,
    events: Arc<Mutex<Vec<String>>>,
    request: Step,
    response: Step,
    error: Step,
}

impl Probe {
    fn new(label: &'static str, events: &Arc<Mutex<Vec<String>>>) -> Self {
        Self {
            label,
            events: Arc::clone(events),
            request: Step::Ready,
            response: Step::Ready,
            error: Step::Ready,
        }
    }

    fn record(&self, phase: &str) {
        self.events
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(format!("{}:{phase}", self.label));
    }

    async fn run(&self, step: &Step) -> Result<(), RequestHookError> {
        match step {
            Step::Ready => Ok(()),
            Step::Fail(marker) => Err(RequestHookError::new(Cause(Arc::clone(marker)))),
            Step::Delay(duration) => {
                sleep(*duration).await;
                Ok(())
            }
            Step::Pending { entered, dropped } => {
                let _call = PendingCall(Arc::clone(dropped));
                entered.notify_one();
                pending().await
            }
        }
    }
}

impl AsyncRequestHooks for Probe {
    fn on_request<'a>(&'a self, context: &'a RequestHookContext<'_>) -> HookFuture<'a> {
        Box::pin(async move {
            assert!(!format!("{context:?}").contains("secret"));
            self.record("request");
            self.run(&self.request).await
        })
    }

    fn on_response<'a>(&'a self, context: &'a ResponseHookContext<'_>) -> HookFuture<'a> {
        Box::pin(async move {
            assert!(!format!("{context:?}").contains("secret"));
            assert!(context.info().is_some());
            self.record(&format!("response:{}", context.status().as_u16()));
            self.run(&self.response).await
        })
    }

    fn on_error<'a>(&'a self, context: &'a RequestErrorHookContext<'_>) -> HookFuture<'a> {
        Box::pin(async move {
            assert!(context.error().origin().is_some());
            assert!(!format!("{context:?}").contains("secret"));
            self.record(&format!("error:{:?}", context.error().kind()));
            self.run(&self.error).await
        })
    }
}

struct SyncProbe(Probe);

impl RequestHooks for SyncProbe {
    fn on_request(&self, _: &RequestHookContext<'_>) {
        self.0.record("request");
    }
    fn on_response(&self, context: &ResponseHookContext<'_>) {
        self.0
            .record(&format!("response:{}", context.status().as_u16()));
    }
    fn on_error(&self, context: &RequestErrorHookContext<'_>) {
        self.0
            .record(&format!("error:{:?}", context.error().kind()));
    }
}

fn events(events: &Arc<Mutex<Vec<String>>>) -> Vec<String> {
    events
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
}

#[tokio::test]
async fn mixed_hooks_observe_one_final_head_across_retries_and_redirects() -> TestResult<()> {
    timeout(LIMIT, async {
        for async_client in [true, false] {
            let (builder, mut peers, _) = builder();
            let recorded = Arc::new(Mutex::new(Vec::new()));
            let observer = Probe::new("client", &recorded);
            let builder = if async_client { builder.async_request_hooks(observer) }
                else { builder.request_hooks(SyncProbe(observer)) };
            let client = builder.redirect_policy(RedirectPolicy::limited(std::num::NonZeroUsize::MIN))
                .retry_policy(RetryPolicy::none().with_status_retry(StatusRetry::new(
                    &[StatusCode::SERVICE_UNAVAILABLE], std::num::NonZeroUsize::MIN, Duration::ZERO,
                )?)).build()?;
            let peer = async {
                for head in [
                    b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
                    b"HTTP/1.1 302 Found\r\nLocation: http://other.invalid/final\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".as_slice(),
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 10\r\nConnection: close\r\n\r\nx".as_slice(),
                ] {
                    let mut stream = peers.recv().await.ok_or("request connection missing")?;
                    read_head(&mut stream).await?;
                    stream.write_all(head).await?;
                }
                TestResult::Ok(())
            };
            let caller = async {
                let observer = Probe::new("request", &recorded);
                let request = client.get_with_protocol(HttpProtocol::Http1, URL)?;
                let request = if async_client { request.request_hooks(SyncProbe(observer)) }
                    else { request.async_request_hooks(observer) };
                let response = request.send().await?;
                assert_eq!(events(&recorded), ["client:request", "request:request", "client:response:404", "request:response:404"]);
                let mut shutdown = Box::pin(client.shutdown());
                assert!(futures_util::poll!(shutdown.as_mut()).is_pending());
                assert!(response.into_body().collect_with_limit(100).await.is_err());
                shutdown.await;
                assert_eq!(events(&recorded).len(), 4);
                TestResult::Ok(())
            };
            tokio::try_join!(peer, caller)?;
        }
        TestResult::Ok(())
    }).await?
}
