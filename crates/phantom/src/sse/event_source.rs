use std::{fmt, future::Future, pin::Pin, time::Duration};

use http::{HeaderValue, Response, StatusCode};
use tokio::time::Instant;
use tracing::{Instrument, debug, debug_span, field};

use crate::{RequestError, RequestErrorKind, ResponseBody};

use super::{SseError, SseErrorKind, SseEvent, SseLimits, SseOutcome, SseStream};

mod request;

use request::SseRequest;
pub use request::SseRequestBuilder;

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
        | RequestErrorKind::AuthorityHeader
        | RequestErrorKind::InvalidHeader
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

/// Pull-driven server-sent event source with bounded reconnects.
#[must_use = "SSE event sources must be read, closed, or deliberately dropped"]
pub struct SseEventSource {
    request: SseRequest,
    stream: Option<SseStream>,
    limits: SseLimits,
    idle_timeout: Option<Duration>,
    last_event_id: String,
    retry_delay: Duration,
    max_reconnects: usize,
    reconnects: usize,
    reconnect_at: Option<Instant>,
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
            .field("max_reconnects", &self.max_reconnects)
            .field("reconnects", &self.reconnects)
            .field("waiting", &self.reconnect_at.is_some())
            .field("connecting", &self.reconnect_request.is_some())
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

impl SseEventSource {
    fn open(
        request: SseRequest,
        limits: SseLimits,
        idle_timeout: Option<Duration>,
        initial_retry: Duration,
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
            max_reconnects,
            reconnects,
            reconnect_at: None,
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
            max_reconnects,
            reconnects,
            reconnect_at: None,
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
    /// Returns [`SseError`] for terminal response or decoding failures and when
    /// the reconnect budget is exhausted.
    pub async fn next_event(&mut self) -> Result<Option<SseEvent>, SseError> {
        let span = debug_span!(
            "sse.event_source.next_event",
            protocol = self.request.protocol.trace_name(),
            reconnects = field::Empty,
            outcome = field::Empty,
        );
        let outcome = SseOutcome::new(&span);
        let result = self.next_event_inner().instrument(span.clone()).await;
        span.record("reconnects", self.reconnects);
        outcome.finish(match &result {
            Ok(Some(_)) => "event",
            Ok(None) => "closed",
            Err(error) if error.kind() == SseErrorKind::IdleTimeout => "idle_timeout",
            Err(error) if error.kind() == SseErrorKind::ReconnectLimit => "reconnect_limit",
            Err(_) => "error",
        });
        result
    }

    /// Returns the persistent last-event ID observed so far.
    #[must_use]
    pub fn last_event_id(&self) -> &str {
        self.stream
            .as_ref()
            .map_or(&self.last_event_id, SseStream::last_event_id)
    }

    /// Returns the current reconnect delay.
    #[must_use]
    pub fn retry_delay(&self) -> Duration {
        self.stream
            .as_ref()
            .and_then(SseStream::retry_delay)
            .unwrap_or(self.retry_delay)
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
        self.sync_stream_state();
        self.stream = None;
        self.reconnect_at = None;
        self.reconnect_request = None;
        self.last_failure = None;
        self.closed = true;
    }

    async fn next_event_inner(&mut self) -> Result<Option<SseEvent>, SseError> {
        loop {
            if self.closed {
                return Ok(None);
            }

            if let Some(stream) = self.stream.as_mut() {
                let result = stream.next_event().await;
                self.sync_stream_state();
                match result {
                    Ok(Some(event)) => return Ok(Some(event)),
                    Ok(None) => self.stream = None,
                    Err(mut error) if error.kind() == SseErrorKind::Body => {
                        self.last_failure = error.source.take().map(ReconnectFailure::Request);
                        self.stream = None;
                    }
                    Err(error) if error.kind() == SseErrorKind::IdleTimeout => {
                        self.last_failure = Some(ReconnectFailure::IdleTimeout);
                        self.stream = None;
                    }
                    Err(error) => {
                        self.closed = true;
                        self.stream = None;
                        return Err(error);
                    }
                }
            }

            if !self.reconnect().await? {
                return Ok(None);
            }
        }
    }

    fn sync_stream_state(&mut self) {
        if let Some(stream) = &self.stream {
            self.last_event_id = stream.last_event_id().to_owned();
            if let Some(delay) = stream.retry_delay() {
                self.retry_delay = delay;
            }
        }
    }

    async fn reconnect(&mut self) -> Result<bool, SseError> {
        if self.reconnect_request.is_none() {
            if self.reconnects >= self.max_reconnects {
                self.closed = true;
                return Err(match self.last_failure.take() {
                    Some(ReconnectFailure::IdleTimeout) => SseError::idle_timeout(),
                    Some(ReconnectFailure::Request(error)) => {
                        SseError::reconnect_limit(Some(error))
                    }
                    None => SseError::reconnect_limit(None),
                });
            }

            let deadline = match self.reconnect_at {
                Some(deadline) => deadline,
                None => {
                    let Some(deadline) = Instant::now().checked_add(self.retry_delay) else {
                        self.closed = true;
                        return Err(SseError::invalid_reconnect_delay());
                    };
                    self.reconnect_at = Some(deadline);
                    deadline
                }
            };
            if let Err(error) = crate::timeout::sleep_until(deadline).await {
                self.closed = true;
                return Err(SseError::request(error));
            }
            self.reconnect_at = None;
            self.reconnects += 1;
            debug!(
                attempt = self.reconnects,
                maximum = self.max_reconnects,
                "reconnecting SSE event source"
            );
            if HeaderValue::from_bytes(self.last_event_id.as_bytes()).is_err() {
                self.closed = true;
                return Err(SseError::unrepresentable_last_event_id());
            }
            self.reconnect_request = Some(self.request.send_owned(self.last_event_id.clone()));
        }

        let response = match self.reconnect_request.as_mut() {
            Some(request) => request.await,
            None => {
                self.closed = true;
                return Err(SseError::request_state());
            }
        };
        let response = match response {
            Ok(response) => response,
            Err(error) if is_reconnectable(&error) => {
                self.reconnect_request = None;
                self.last_failure = Some(ReconnectFailure::Request(error));
                return Ok(true);
            }
            Err(error) => {
                self.reconnect_request = None;
                self.closed = true;
                return Err(SseError::request(error));
            }
        };
        self.reconnect_request = None;
        if response.status() == StatusCode::NO_CONTENT {
            self.close();
            return Ok(false);
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
                return Err(error);
            }
        };
        self.stream = Some(response.into_body());
        self.last_failure = None;
        Ok(true)
    }
}
