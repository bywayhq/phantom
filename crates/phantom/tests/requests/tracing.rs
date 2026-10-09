//! Facade tracing over real requests with private wire canaries.

use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    future::Future,
    io,
    net::Ipv4Addr,
    num::NonZeroUsize,
    pin::Pin,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ::tracing::{
    Dispatch, Event, Metadata, Subscriber,
    field::{Field, Visit},
    instrument::WithSubscriber,
    span::{Attributes, Id, Record},
    subscriber::Interest,
};
use bytes::Bytes;
use http::{Method, StatusCode};
use phantom::{
    Client, HttpProtocol, RequestErrorKind, RequestHeader, RequestTimeoutOverrides, RetryPolicy,
    StatusRetry, TimeoutOverride, TimeoutPhase, profile::ClientProfile,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

use crate::support::tls::{TestResult, read_head, tls_settings};

#[derive(Clone, Default)]
struct Capture {
    next_id: Arc<AtomicU64>,
    state: Arc<Mutex<State>>,
}

#[derive(Debug)]
struct Observation {
    name: &'static str,
    target: &'static str,
    fields: BTreeMap<String, String>,
}

#[derive(Default)]
struct State {
    spans: HashMap<u64, Observation>,
    events: Vec<Observation>,
}

#[derive(Default)]
struct Values(BTreeMap<String, String>);

impl Visit for Values {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

impl Capture {
    fn dispatch(&self) -> Dispatch {
        let dispatch = Dispatch::new(self.clone());
        ::tracing::callsite::rebuild_interest_cache();
        dispatch
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn span_field(&self, span_name: &str, field: &str) -> TestResult<String> {
        let state = self.state();
        let mut matching = state.spans.values().filter(|span| span.name == span_name);
        let span = matching
            .next()
            .ok_or("expected facade span was not captured")?;
        assert!(
            matching.next().is_none(),
            "test made more than one matching operation"
        );
        span.fields
            .get(field)
            .cloned()
            .ok_or_else(|| format!("missing {field} on {span_name}").into())
    }

    fn event_has(&self, target: &str, fields: &[(&str, &str)]) -> bool {
        self.state().events.iter().any(|event| {
            event.target == target
                && fields.iter().all(|(name, value)| {
                    event
                        .fields
                        .get(*name)
                        .is_some_and(|actual| actual.as_str() == *value)
                })
        })
    }

    fn assert_private(&self, canaries: &[String]) {
        let state = self.state();
        assert!(!state.spans.is_empty(), "an empty capture proves nothing");
        for observation in state.spans.values().chain(&state.events) {
            for value in observation.fields.values() {
                for canary in canaries {
                    assert!(
                        !value.contains(canary),
                        "private value in {} field capture",
                        observation.name
                    );
                }
            }
        }
    }
}

impl Subscriber for Capture {
    fn register_callsite(&self, _metadata: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target().starts_with("phantom::")
    }

    fn new_span(&self, attributes: &Attributes<'_>) -> Id {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        let mut values = Values::default();
        attributes.record(&mut values);
        self.state().spans.insert(
            id,
            Observation {
                name: attributes.metadata().name(),
                target: attributes.metadata().target(),
                fields: values.0,
            },
        );
        Id::from_u64(id)
    }

    fn record(&self, span: &Id, values: &Record<'_>) {
        let mut captured = Values::default();
        values.record(&mut captured);
        if let Some(span) = self.state().spans.get_mut(&span.into_u64()) {
            span.fields.extend(captured.0);
        }
    }

    fn record_follows_from(&self, _span: &Id, _follows: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let mut values = Values::default();
        event.record(&mut values);
        self.state().events.push(Observation {
            name: event.metadata().name(),
            target: event.metadata().target(),
            fields: values.0,
        });
    }

    fn enter(&self, _span: &Id) {}
    fn exit(&self, _span: &Id) {}
}

fn canaries() -> TestResult<Vec<String>> {
    let marker = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    Ok([
        "path",
        "query",
        "authorization",
        "cookie",
        "upload",
        "response-header",
        "response-body",
    ]
    .map(|kind| format!("{marker:x}-{kind}"))
    .to_vec())
}

fn client() -> TestResult<Client> {
    Ok(Client::builder(ClientProfile::new(tls_settings())).build()?)
}

async fn bounded<F: Future<Output = TestResult<()>>>(future: F) -> TestResult<()> {
    timeout(Duration::from_secs(15), future)
        .await
        .map_err(|_| "tracing wire test exceeded its deadline")?
}

#[tokio::test]
async fn facade_traces_preserve_counts_and_retry_status_without_private_wire_values()
-> TestResult<()> {
    bounded(async {
        let private = canaries()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let url = format!("http://{address}/{}?private={}", private[0], private[1]);
        let upload = Bytes::copy_from_slice(private[4].as_bytes());
        let response_body = private[6].clone();
        let response_header = private[5].clone();
        let upload_length = upload.len();
        let peer = tokio::spawn(async move {
            let mut observed = Vec::new();
            for status in [503, 200] {
                let (mut stream, _) = listener.accept().await?;
                let head = read_head(&mut stream).await?;
                let mut body = vec![0; upload_length];
                stream.read_exact(&mut body).await?;
                observed.push((head, body));
                let body = if status == 200 { response_body.as_str() } else { "" };
                let reply = format!("HTTP/1.1 {status} Status\r\nContent-Length: {}\r\nX-Private: {response_header}\r\nSet-Cookie: private={response_header}\r\nConnection: close\r\n\r\n{body}", body.len());
                stream.write_all(reply.as_bytes()).await?;
                stream.shutdown().await?;
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
        });
        let status_retry = StatusRetry::new(&[StatusCode::SERVICE_UNAVAILABLE], NonZeroUsize::MIN, Duration::ZERO)?;
        let client = Client::builder(ClientProfile::new(tls_settings()))
            .retry_policy(RetryPolicy::none().with_status_retry(status_retry)).build()?;
        let capture = Capture::default();
        let response = client.request(HttpProtocol::Http1, Method::PUT, &url)?
            .headers(vec![RequestHeader::bearer_authorization(&private[2])?, RequestHeader::new("Cookie", format!("private={}", private[3]))])
            .body(upload.clone()).send().with_subscriber(capture.dispatch()).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers().get("x-private").ok_or("missing private response header")?.to_str()?, private[5]);
        let body = response.into_body().collect_with_limit(1024).with_subscriber(capture.dispatch()).await?;
        assert_eq!(body.as_ref(), private[6].as_bytes());
        for (head, body) in peer.await?? {
            let head = std::str::from_utf8(&head)?;
            for canary in &private[..4] { assert!(head.contains(canary)); }
            assert_eq!(body.as_slice(), upload.as_ref());
        }
        for (name, value) in [("method", "PUT"), ("body_kind", "bytes"), ("protocol", "http/1.1"), ("selected_protocol", "http/1.1"), ("route", "direct"), ("status_retries", "1"), ("retries_performed", "0"), ("outcome", "ok")] {
            assert_eq!(capture.span_field("client.request", name)?, value);
        }
        assert_eq!(capture.span_field("client.request", "body_bytes")?, upload.len().to_string());
        assert!(capture.event_has("phantom::retry", &[("status", "503"), ("retry", "1"), ("reason", "status")]));
        capture.assert_private(&private);
        Ok(())
    }).await
}

#[tokio::test]
async fn a_deferred_body_failure_keeps_the_completed_request_trace_private() -> TestResult<()> {
    bounded(async {
        let private = canaries()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let response_header = private[5].clone();
        let invalid_chunk = private[6].clone();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            stream.write_all(format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Private: {response_header}\r\nConnection: close\r\n\r\n{invalid_chunk}\r\n").as_bytes()).await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
        });
        let capture = Capture::default();
        let response = client()?.get(HttpProtocol::Http1, &format!("http://{address}/{}?private={}", private[0], private[1]))?
            .send().with_subscriber(capture.dispatch()).await?;
        assert_eq!(response.status(), StatusCode::OK);
        let error = response.into_body().collect_with_limit(1024).with_subscriber(capture.dispatch()).await.err().ok_or("invalid chunk accepted")?;
        assert_eq!(error.kind(), RequestErrorKind::Http1);
        assert!(std::str::from_utf8(&peer.await??)?.contains(&private[1]));
        assert_eq!(capture.span_field("client.request", "outcome")?, "ok");
        capture.assert_private(&private);
        Ok(())
    }).await
}

struct FailingBody {
    ready: oneshot::Receiver<()>,
    message: String,
    failed: bool,
}

impl http_body::Body for FailingBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Bytes>, io::Error>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        let readiness = Pin::new(&mut self.ready).poll(context);
        if readiness.is_pending() {
            return Poll::Pending;
        }
        self.failed = true;
        let message = match readiness {
            Poll::Ready(Ok(())) => self.message.clone(),
            _ => "peer stopped before the body failure".to_owned(),
        };
        Poll::Ready(Some(Err(io::Error::other(message))))
    }
}

#[tokio::test]
async fn a_caller_body_cause_remains_inspectable_without_entering_facade_traces() -> TestResult<()>
{
    bounded(async {
        let private = canaries()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (ready, body_ready) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            ready
                .send(())
                .map_err(|_| "client stopped before request body polling")?;
            released
                .await
                .map_err(|_| "client did not release the failed-body peer")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
        });
        let capture = Capture::default();
        let body = FailingBody {
            ready: body_ready,
            message: private[4].clone(),
            failed: false,
        };
        let error = client()?
            .request(
                HttpProtocol::Http1,
                Method::PUT,
                &format!("http://{address}/{}?private={}", private[0], private[1]),
            )?
            .streaming_body(body)
            .send()
            .with_subscriber(capture.dispatch())
            .await
            .err()
            .ok_or("failed body was accepted")?;
        assert_eq!(error.kind(), RequestErrorKind::RequestBody);
        let mut cause: &(dyn std::error::Error + 'static) = &error;
        let body_cause = loop {
            if let Some(source) = cause.downcast_ref::<io::Error>() {
                break source;
            }
            cause = cause
                .source()
                .ok_or("request lost the typed caller body cause")?;
        };
        assert_eq!(body_cause.to_string(), private[4]);
        release
            .send(())
            .map_err(|_| "peer stopped before body failure inspection")?;
        assert!(std::str::from_utf8(&peer.await??)?.contains(&private[1]));
        assert_eq!(capture.span_field("client.request", "body_kind")?, "stream");
        assert_eq!(capture.span_field("client.request", "outcome")?, "error");
        capture.assert_private(&private);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn dropping_a_polled_send_records_cancellation_without_its_uri() -> TestResult<()> {
    bounded(async {
        let private = canaries()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (seen, received) = oneshot::channel();
        let (release, released) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            seen.send(()).map_err(|_| "client stopped before the request was observed")?;
            released.await.map_err(|_| "client did not release stalled peer")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
        });
        let capture = Capture::default();
        let request = client()?.get(HttpProtocol::Http1, &format!("http://{address}/{}?private={}", private[0], private[1]))?;
        let mut sending = Box::pin(request.send().with_subscriber(capture.dispatch()));
        tokio::select! {
            result = &mut sending => { return Err(format!("stalled request completed: {}", result.is_ok()).into()); }
            result = received => { result.map_err(|_| "peer stopped before reading the request")?; }
        }
        drop(sending);
        release.send(()).map_err(|_| "peer stopped before cancellation")?;
        assert!(std::str::from_utf8(&peer.await??)?.contains(&private[1]));
        assert_eq!(capture.span_field("client.request", "outcome")?, "cancelled");
        capture.assert_private(&private);
        Ok(())
    }).await
}

#[tokio::test]
async fn a_stalled_response_records_the_timeout_phase_without_its_uri() -> TestResult<()> {
    bounded(async {
        let private = canaries()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (release, released) = oneshot::channel();
        let peer = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            let head = read_head(&mut stream).await?;
            released
                .await
                .map_err(|_| "client did not release timed-out peer")?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(head)
        });
        let capture = Capture::default();
        let error = client()?
            .get(
                HttpProtocol::Http1,
                &format!("http://{address}/{}?private={}", private[0], private[1]),
            )?
            .timeouts(
                RequestTimeoutOverrides::disabled()
                    .response_head(TimeoutOverride::Limit(Duration::from_millis(100))),
            )
            .send()
            .with_subscriber(capture.dispatch())
            .await
            .err()
            .ok_or("stalled request succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::Timeout);
        assert_eq!(error.timeout_phase(), Some(TimeoutPhase::ResponseHead));
        release
            .send(())
            .map_err(|_| "peer stopped before timeout")?;
        assert!(std::str::from_utf8(&peer.await??)?.contains(&private[1]));
        assert_eq!(capture.span_field("client.request", "outcome")?, "timeout");
        assert_eq!(
            capture.span_field("client.request", "timeout_phase")?,
            "response_head"
        );
        capture.assert_private(&private);
        Ok(())
    })
    .await
}
