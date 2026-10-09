use std::{
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_core::Stream;
use http::{HeaderValue, Response, StatusCode};
use tokio::time::Instant;
use tracing::{debug, debug_span, field};

use crate::{RequestError, RequestErrorKind, ResponseBody, timeout::DeadlineTimer};

use super::{SseError, SseErrorKind, SseEvent, SseLimits, SseOutcome, SseStream};

mod request;

pub use request::{SseHeader, SseRequestBuilder};
use request::{SseRequest, effective_retry};

type ReconnectFuture =
    Pin<Box<dyn Future<Output = Result<Response<ResponseBody>, RequestError>> + Send + 'static>>;

/// Returns whether a failed attempt may succeed on a later reconnect.
///
/// Input, policy, and route failures are deterministic: repeating the same
/// request would fail identically, so they end the event source at once.
fn is_reconnectable(error: &RequestError) -> bool {
    match error.kind() {
        RequestErrorKind::Resolve
        | RequestErrorKind::Connect
        | RequestErrorKind::Proxy
        | RequestErrorKind::Capacity
        | RequestErrorKind::Timeout
        | RequestErrorKind::Tls
        | RequestErrorKind::Http1
        | RequestErrorKind::Http2
        | RequestErrorKind::Http3 => true,
        RequestErrorKind::InvalidUri
        | RequestErrorKind::UnsupportedScheme
        | RequestErrorKind::InvalidAuthority
        | RequestErrorKind::InvalidHeader
        | RequestErrorKind::HeaderHook
        | RequestErrorKind::RequestTemplate
        | RequestErrorKind::ProtocolUnavailable
        | RequestErrorKind::UnsupportedRoute
        | RequestErrorKind::InvalidTarget
        | RequestErrorKind::Redirect
        | RequestErrorKind::RuntimeUnavailable
        | RequestErrorKind::InvalidTimeout
        | RequestErrorKind::RequestBody
        | RequestErrorKind::ResponseBodyLimit
        | RequestErrorKind::ContentDecoding => false,
    }
}

#[derive(Debug)]
enum ReconnectFailure {
    Request(RequestError),
    IdleTimeout,
}

/// A pull-driven event [`Stream`] with bounded reconnects.
///
/// Start one with [`Client::event_source`](crate::Client::event_source) and
/// [`SseRequestBuilder::connect`]. After a disconnect, a body failure, or an
/// idle timeout, the source waits [`Self::retry_delay`] and sends the request
/// again with the committed `Last-Event-ID`, on the same exact protocol and
/// route; a client whose retry policy enables
/// [`RetryPolicy::with_http2_fallback`](crate::RetryPolicy::with_http2_fallback)
/// may send an HTTP/3 connect over HTTP/2. Reconnects stop after the builder's
/// [`max_reconnects`](SseRequestBuilder::max_reconnects) budget (3 by
/// default); browsers reconnect without a limit. A 204 response closes the
/// source. Reads and reconnects run only while you poll the source. There is
/// no background task or event queue.
///
/// Polling yields one event at a time. A terminal error is returned once,
/// followed by `None`. [`Self::next_event`] uses the same polling operation.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
///
/// use phantom::{Client, HttpProtocol};
///
/// async fn read(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
///     let response = client
///         .event_source(HttpProtocol::Http2, "https://example.com/events")?
///         .idle_timeout(Duration::from_secs(30))
///         .max_reconnects(4)
///         .connect()
///         .await?;
///     let mut events = response.into_body();
///
///     while let Some(event) = events.next_event().await? {
///         println!("{}: {}", event.event(), event.data());
///     }
///     Ok(())
/// }
/// ```
#[must_use = "SSE event sources must be read, closed, or deliberately dropped"]
pub struct SseEventSource {
    request: SseRequest,
    stream: Option<SseStream>,
    limits: SseLimits,
    idle_timeout: Option<Duration>,
    last_event_id: String,
    retry_delay: Duration,
    min_retry: Option<Duration>,
    max_reconnects: usize,
    reconnects: usize,
    reconnect_at: Option<Instant>,
    reconnect_timer: Option<DeadlineTimer>,
    read_outcome: Option<SseOutcome>,
    reconnect_request: Option<ReconnectFuture>,
    last_failure: Option<ReconnectFailure>,
    closed: bool,
}

impl fmt::Debug for SseEventSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SseEventSource")
            .field("protocol", &self.request.protocol)
            .field("limits", &self.limits)
            .field("idle_timeout", &self.idle_timeout)
            .field("min_retry", &self.min_retry)
            .field("max_reconnects", &self.max_reconnects)
            .field("reconnects", &self.reconnects)
            .field("waiting", &self.reconnect_at.is_some())
            .field("connecting", &self.reconnect_request.is_some())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl SseEventSource {
    #[allow(clippy::too_many_arguments)]
    fn open(
        request: SseRequest,
        limits: SseLimits,
        idle_timeout: Option<Duration>,
        initial_retry: Duration,
        min_retry: Option<Duration>,
        max_reconnects: usize,
        reconnects: usize,
        stream: SseStream,
    ) -> Self {
        Self {
            request,
            stream: Some(stream),
            limits,
            idle_timeout,
            last_event_id: String::new(),
            retry_delay: initial_retry,
            min_retry,
            max_reconnects,
            reconnects,
            reconnect_at: None,
            reconnect_timer: None,
            read_outcome: None,
            reconnect_request: None,
            last_failure: None,
            closed: false,
        }
    }

    fn closed(
        request: SseRequest,
        limits: SseLimits,
        idle_timeout: Option<Duration>,
        initial_retry: Duration,
        min_retry: Option<Duration>,
        max_reconnects: usize,
        reconnects: usize,
    ) -> Self {
        Self {
            request,
            stream: None,
            limits,
            idle_timeout,
            last_event_id: String::new(),
            retry_delay: initial_retry,
            min_retry,
            max_reconnects,
            reconnects,
            reconnect_at: None,
            reconnect_timer: None,
            read_outcome: None,
            reconnect_request: None,
            last_failure: None,
            closed: true,
        }
    }

    /// Reads the next event, reconnecting within the configured finite budget.
    ///
    /// Dropping a pending call preserves an established stream, a scheduled
    /// reconnect deadline, or an in-flight reconnect request. Dropping the
    /// event source cancels all further work.
    ///
    /// # Errors
    ///
    /// Returns [`SseError`] with kind:
    ///
    /// - [`SseErrorKind::ReconnectLimit`] when the reconnect budget is spent
    ///   after a disconnect or a failed reconnect request, or
    ///   [`SseErrorKind::IdleTimeout`] when the idle timeout fired last;
    /// - [`SseErrorKind::Request`] when a reconnect request fails in a way a
    ///   repeat cannot fix (such as a redirect or route error), or the
    ///   committed ID is not a valid field value;
    /// - [`SseErrorKind::UnexpectedStatus`],
    ///   [`SseErrorKind::InvalidContentType`], or
    ///   [`SseErrorKind::UnsupportedContentEncoding`] when a reconnect
    ///   response fails validation;
    /// - [`SseErrorKind::LineTooLong`] or [`SseErrorKind::EventTooLarge`]
    ///   when the stream exceeds its [`SseLimits`];
    /// - [`SseErrorKind::InvalidReconnectDelay`] or
    ///   [`SseErrorKind::InvalidIdleTimeout`] when a delay cannot be added to
    ///   the runtime clock.
    ///
    /// Every error closes the source; later calls return `Ok(None)`.
    pub async fn next_event(&mut self) -> Result<Option<SseEvent>, SseError> {
        NextEvent { source: self }.await
    }

    /// Returns the persistent last-event ID observed so far.
    #[must_use]
    pub fn last_event_id(&self) -> &str {
        self.stream
            .as_ref()
            .map_or(&self.last_event_id, SseStream::last_event_id)
    }

    /// Returns the delay the next reconnect waits.
    ///
    /// This is the latest valid `retry` value, or the initial delay, raised to
    /// [`SseRequestBuilder::min_retry`] when one is configured.
    #[must_use]
    pub fn retry_delay(&self) -> Duration {
        let delay = self
            .stream
            .as_ref()
            .and_then(SseStream::retry_delay)
            .unwrap_or(self.retry_delay);
        effective_retry(delay, self.min_retry)
    }

    /// Returns the number of reconnect requests started so far.
    #[must_use]
    pub const fn reconnects(&self) -> usize {
        self.reconnects
    }

    /// Returns the configured response-body idle timeout.
    #[must_use]
    pub const fn idle_timeout(&self) -> Option<Duration> {
        self.idle_timeout
    }

    /// Returns whether the source has stopped permanently.
    #[must_use]
    pub const fn is_closed(&self) -> bool {
        self.closed
    }

    /// Stops the source and releases an active response body.
    pub fn close(&mut self) {
        self.cancel_read_outcome();
        self.close_state();
    }

    fn close_state(&mut self) {
        self.sync_stream_state();
        self.stream = None;
        self.reconnect_at = None;
        self.reconnect_timer = None;
        self.reconnect_request = None;
        self.last_failure = None;
        self.closed = true;
    }

    fn poll_event(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<SseEvent, SseError>>> {
        loop {
            if self.closed {
                return Poll::Ready(None);
            }
            if let Some(stream) = self.stream.as_mut() {
                let result = match Pin::new(stream).poll_next(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(result) => result,
                };
                self.sync_stream_state();
                match result {
                    Some(Ok(event)) => return Poll::Ready(Some(Ok(event))),
                    None => self.stream = None,
                    Some(Err(mut error)) if error.kind() == SseErrorKind::Body => {
                        self.last_failure = error.source.take().map(ReconnectFailure::Request);
                        self.stream = None;
                    }
                    Some(Err(error)) if error.kind() == SseErrorKind::IdleTimeout => {
                        self.last_failure = Some(ReconnectFailure::IdleTimeout);
                        self.stream = None;
                    }
                    Some(Err(error)) => {
                        self.close_state();
                        return Poll::Ready(Some(Err(error)));
                    }
                }
            }
            match self.poll_reconnect(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Ok(true)) => {}
                Poll::Ready(Ok(false)) => return Poll::Ready(None),
                Poll::Ready(Err(error)) => {
                    self.close_state();
                    return Poll::Ready(Some(Err(error)));
                }
            }
        }
    }

    fn cancel_read_outcome(&mut self) {
        if let Some(stream) = self.stream.as_mut() {
            stream.cancel_read_outcome();
        }
        self.read_outcome = None;
    }

    fn sync_stream_state(&mut self) {
        if let Some(stream) = &self.stream {
            self.last_event_id = stream.last_event_id().to_owned();
            if let Some(delay) = stream.retry_delay() {
                self.retry_delay = delay;
            }
        }
    }

    fn poll_reconnect(&mut self, context: &mut Context<'_>) -> Poll<Result<bool, SseError>> {
        if self.reconnect_request.is_none() {
            if self.reconnects >= self.max_reconnects {
                self.closed = true;
                return Poll::Ready(Err(match self.last_failure.take() {
                    Some(ReconnectFailure::IdleTimeout) => SseError::idle_timeout(),
                    Some(ReconnectFailure::Request(error)) => {
                        SseError::reconnect_limit(Some(error))
                    }
                    None => SseError::reconnect_limit(None),
                }));
            }

            let deadline = match self.reconnect_at {
                Some(deadline) => deadline,
                None => {
                    let delay = effective_retry(self.retry_delay, self.min_retry);
                    let Some(deadline) = Instant::now().checked_add(delay) else {
                        self.closed = true;
                        return Poll::Ready(Err(SseError::invalid_reconnect_delay()));
                    };
                    self.reconnect_at = Some(deadline);
                    deadline
                }
            };
            if self.reconnect_timer.is_none() {
                self.reconnect_timer = match DeadlineTimer::new(deadline) {
                    Ok(timer) => Some(timer),
                    Err(error) => return Poll::Ready(Err(SseError::request(error))),
                };
            }
            if let Some(timer) = self.reconnect_timer.as_mut() {
                match timer.poll_expired(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(SseError::request(error))),
                    Poll::Ready(Ok(())) => {}
                }
            }
            self.reconnect_at = None;
            self.reconnect_timer = None;
            self.reconnects += 1;
            debug!(
                attempt = self.reconnects,
                maximum = self.max_reconnects,
                "reconnecting SSE event source"
            );
            if HeaderValue::from_bytes(self.last_event_id.as_bytes()).is_err() {
                self.closed = true;
                return Poll::Ready(Err(SseError::unrepresentable_last_event_id()));
            }
            self.reconnect_request = Some(self.request.send_owned(self.last_event_id.clone()));
        }

        let response = match self.reconnect_request.as_mut() {
            Some(request) => match request.as_mut().poll(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(response) => response,
            },
            None => {
                self.closed = true;
                return Poll::Ready(Err(SseError::request_state()));
            }
        };
        let response = match response {
            Ok(response) => response,
            Err(error) if is_reconnectable(&error) => {
                self.reconnect_request = None;
                self.last_failure = Some(ReconnectFailure::Request(error));
                return Poll::Ready(Ok(true));
            }
            Err(error) => {
                self.reconnect_request = None;
                self.closed = true;
                return Poll::Ready(Err(SseError::request(error)));
            }
        };
        self.reconnect_request = None;
        if response.status() == StatusCode::NO_CONTENT {
            self.close_state();
            return Poll::Ready(Ok(false));
        }

        let response = match SseStream::from_response_with_state(
            response,
            self.limits,
            self.last_event_id.clone(),
            self.retry_delay,
            self.idle_timeout,
        ) {
            Ok(response) => response,
            Err(error) => {
                self.closed = true;
                return Poll::Ready(Err(error));
            }
        };
        self.stream = Some(response.into_body());
        self.last_failure = None;
        Poll::Ready(Ok(true))
    }
}

impl Stream for SseEventSource {
    type Item = Result<SseEvent, SseError>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let source = self.get_mut();
        let protocol = source.request.protocol.trace_name();
        let span = source
            .read_outcome
            .get_or_insert_with(|| {
                SseOutcome::new(&debug_span!(
                    "sse.event_source.next_event",
                    protocol,
                    reconnects = field::Empty,
                    outcome = field::Empty,
                ))
            })
            .span
            .clone();
        let result = span.in_scope(|| source.poll_event(context));
        if let Poll::Ready(item) = &result {
            span.record("reconnects", source.reconnects);
            if let Some(outcome) = source.read_outcome.take() {
                outcome.finish(match item {
                    Some(Ok(_)) => "event",
                    None => "closed",
                    Some(Err(error)) if error.kind() == SseErrorKind::IdleTimeout => "idle_timeout",
                    Some(Err(error)) if error.kind() == SseErrorKind::ReconnectLimit => {
                        "reconnect_limit"
                    }
                    Some(Err(_)) => "error",
                });
            }
        }
        result
    }
}

struct NextEvent<'a> {
    source: &'a mut SseEventSource,
}

impl Future for NextEvent<'_> {
    type Output = Result<Option<SseEvent>, SseError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.get_mut().source)
            .poll_next(context)
            .map(Option::transpose)
    }
}

impl Drop for NextEvent<'_> {
    fn drop(&mut self) {
        self.source.cancel_read_outcome();
    }
}
