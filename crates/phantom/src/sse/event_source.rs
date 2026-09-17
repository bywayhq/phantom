use std::{fmt, future::Future, pin::Pin, time::Duration};

use http::{Response, StatusCode};
use tokio::time::{Instant, sleep_until};
use tracing::{Instrument, debug, debug_span, field};

use crate::{RequestError, ResponseBody};

use super::{SseError, SseErrorKind, SseEvent, SseLimits, SseOutcome, SseStream};

mod request;

use request::SseRequest;
pub use request::SseRequestBuilder;

type ReconnectFuture =
    Pin<Box<dyn Future<Output = Result<Response<ResponseBody>, RequestError>> + Send + 'static>>;

/// Pull-driven server-sent event source with bounded reconnects.
#[must_use = "SSE event sources must be read, closed, or deliberately dropped"]
pub struct SseEventSource {
    request: SseRequest,
    stream: Option<SseStream>,
    limits: SseLimits,
    last_event_id: String,
    retry_delay: Duration,
    max_reconnects: usize,
    reconnects: usize,
    reconnect_at: Option<Instant>,
    reconnect_request: Option<ReconnectFuture>,
    last_failure: Option<RequestError>,
    closed: bool,
}

impl fmt::Debug for SseEventSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SseEventSource")
            .field("protocol", &self.request.protocol)
            .field("limits", &self.limits)
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
        initial_retry: Duration,
        max_reconnects: usize,
        reconnects: usize,
        stream: SseStream,
    ) -> Self {
        Self {
            request,
            stream: Some(stream),
            limits,
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
        initial_retry: Duration,
        max_reconnects: usize,
        reconnects: usize,
    ) -> Self {
        Self {
            request,
            stream: None,
            limits,
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
                        self.last_failure = error.source.take();
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
                return Err(SseError::reconnect_limit(self.last_failure.take()));
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
            sleep_until(deadline).await;
            self.reconnect_at = None;
            self.reconnects += 1;
            debug!(
                attempt = self.reconnects,
                maximum = self.max_reconnects,
                "reconnecting SSE event source"
            );
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
            Err(error) => {
                self.reconnect_request = None;
                self.last_failure = Some(error);
                return Ok(true);
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
