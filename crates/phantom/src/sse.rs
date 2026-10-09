use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_core::Stream;
use http::{Response, StatusCode, header};
use http_body::Body;
use tokio::time::Instant;
use tracing::{debug_span, field};

use crate::{RequestError, ResponseBody, timeout::DeadlineTimer};

use self::decoder::Decoder;

mod decoder;
mod event_source;

pub use event_source::{SseEventSource, SseHeader, SseRequestBuilder};

const DEFAULT_MAX_LINE_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_EVENT_BYTES: usize = 1024 * 1024;

/// Memory limits applied while decoding one server-sent event stream.
///
/// [`SseLimits::default`] allows lines up to 64 KiB and event blocks up to
/// 1 MiB. Apply other limits with [`SseStream::from_response_with_limits`] or
/// [`SseRequestBuilder::limits`]. A line or event block over its limit fails
/// with [`SseErrorKind::LineTooLong`] or [`SseErrorKind::EventTooLarge`] and
/// releases the response body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SseLimits {
    max_line_bytes: usize,
    max_event_bytes: usize,
}

impl SseLimits {
    /// Creates limits from a maximum line length and aggregate event-block size.
    ///
    /// Both limits count encoded bytes and exclude line terminators. Any value
    /// is accepted; a zero limit rejects the first nonempty line or event
    /// block, respectively.
    #[must_use]
    pub const fn new(max_line_bytes: usize, max_event_bytes: usize) -> Self {
        Self {
            max_line_bytes,
            max_event_bytes,
        }
    }

    /// Returns the maximum encoded bytes accepted before a line ending.
    #[must_use]
    pub const fn max_line_bytes(self) -> usize {
        self.max_line_bytes
    }

    /// Returns the maximum aggregate encoded bytes in one event block.
    #[must_use]
    pub const fn max_event_bytes(self) -> usize {
        self.max_event_bytes
    }
}

impl Default for SseLimits {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_LINE_BYTES, DEFAULT_MAX_EVENT_BYTES)
    }
}

/// One event dispatched from a `text/event-stream` response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SseEvent {
    data: String,
    event: String,
    id: String,
}

impl SseEvent {
    /// Returns the event data, with multiple `data` fields joined by newlines.
    #[must_use]
    pub fn data(&self) -> &str {
        &self.data
    }

    /// Returns the event type, or `message` when the stream omitted one.
    #[must_use]
    pub fn event(&self) -> &str {
        &self.event
    }

    /// Returns the stream's persistent last-event ID at dispatch time.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

/// Stable category of SSE response or decoding failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SseErrorKind {
    /// The request could not be prepared or sent.
    Request,
    /// The caller supplied a literal field reserved for SSE reconnect state
    /// or an invalid `Last-Event-ID` placeholder.
    InvalidRequestHeader,
    /// The reconnect delay cannot be represented by the runtime clock.
    InvalidReconnectDelay,
    /// The idle timeout cannot be represented by the runtime clock.
    InvalidIdleTimeout,
    /// The response status was not 200 OK.
    UnexpectedStatus,
    /// The response did not have a `text/event-stream` content type.
    InvalidContentType,
    /// The response applies a content encoding that this decoder cannot accept.
    UnsupportedContentEncoding,
    /// A line exceeded [`SseLimits::max_line_bytes`].
    LineTooLong,
    /// An event block exceeded [`SseLimits::max_event_bytes`].
    EventTooLarge,
    /// Reading the underlying HTTP response body failed.
    Body,
    /// The response body produced no DATA before the configured deadline.
    IdleTimeout,
    /// The configured reconnect-attempt budget was exhausted.
    ReconnectLimit,
}

/// Error returned while validating or decoding an SSE response.
#[derive(Debug)]
pub struct SseError {
    kind: SseErrorKind,
    message: &'static str,
    source: Option<RequestError>,
}

impl SseError {
    fn without_source(kind: SseErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            source: None,
        }
    }

    fn body(source: RequestError) -> Self {
        Self {
            kind: SseErrorKind::Body,
            message: "SSE response body failed",
            source: Some(source),
        }
    }

    fn request(source: RequestError) -> Self {
        Self {
            kind: SseErrorKind::Request,
            message: "SSE request failed",
            source: Some(source),
        }
    }

    fn request_state() -> Self {
        Self::without_source(
            SseErrorKind::Request,
            "SSE reconnect request state is unavailable",
        )
    }

    fn unrepresentable_last_event_id() -> Self {
        Self::without_source(
            SseErrorKind::Request,
            "committed SSE event ID cannot be sent as a Last-Event-ID field value",
        )
    }

    fn invalid_request_header(message: &'static str) -> Self {
        Self::without_source(SseErrorKind::InvalidRequestHeader, message)
    }

    fn invalid_reconnect_delay() -> Self {
        Self::without_source(
            SseErrorKind::InvalidReconnectDelay,
            "SSE reconnect delay exceeds the runtime clock range",
        )
    }

    fn invalid_idle_timeout() -> Self {
        Self::without_source(
            SseErrorKind::InvalidIdleTimeout,
            "SSE idle timeout exceeds the runtime clock range",
        )
    }

    fn idle_timeout() -> Self {
        Self::without_source(
            SseErrorKind::IdleTimeout,
            "SSE response body reached its idle timeout",
        )
    }

    fn reconnect_limit(source: Option<RequestError>) -> Self {
        Self {
            kind: SseErrorKind::ReconnectLimit,
            message: "SSE reconnect limit was reached",
            source,
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> SseErrorKind {
        self.kind
    }
}

impl fmt::Display for SseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)?;
        if let Some(source) = &self.source {
            write!(formatter, ": {source}")?;
        }
        Ok(())
    }
}

impl StdError for SseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

/// A pull-driven event decoder implementing [`Stream`].
///
/// A stream reads one response and never reconnects; use
/// [`Client::event_source`](crate::Client::event_source) for a source that
/// resumes with `Last-Event-ID`. It has no idle timeout.
///
/// The stream has no background task or event queue. Dropping a pending
/// [`SseStream::next_event`] future leaves the decoder and response body ready
/// for the next call; dropping the stream preserves the underlying protocol's
/// cancellation behavior.
///
/// Polling yields one event at a time. A terminal error is returned once,
/// followed by `None`. [`Self::next_event`] uses the same polling operation.
#[must_use = "SSE streams must be read or deliberately dropped"]
pub struct SseStream {
    body: Option<ResponseBody>,
    decoder: Decoder,
    idle_timeout: Option<Duration>,
    idle_deadline: Option<Instant>,
    idle_timer: Option<DeadlineTimer>,
    read_outcome: Option<SseOutcome>,
    finished: bool,
}

impl SseStream {
    /// Validates and converts a response using [`SseLimits::default`].
    ///
    /// # Errors
    ///
    /// Returns [`SseError`] with kind:
    ///
    /// - [`SseErrorKind::UnexpectedStatus`] for a status other than 200 OK;
    /// - [`SseErrorKind::InvalidContentType`] when `Content-Type` is missing,
    ///   repeated, or has an essence other than `text/event-stream`;
    /// - [`SseErrorKind::UnsupportedContentEncoding`] for any content coding
    ///   other than `identity`, even when the request enabled content
    ///   decoding.
    pub fn from_response(response: Response<ResponseBody>) -> Result<Response<Self>, SseError> {
        Self::from_response_with_limits(response, SseLimits::default())
    }

    /// Validates and converts a response using caller-supplied decoding limits.
    ///
    /// # Errors
    ///
    /// Returns [`SseError`] for the same metadata failures as
    /// [`SseStream::from_response`].
    pub fn from_response_with_limits(
        response: Response<ResponseBody>,
        limits: SseLimits,
    ) -> Result<Response<Self>, SseError> {
        validate_response(&response)?;
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            Self {
                body: Some(body),
                decoder: Decoder::new(limits),
                idle_timeout: None,
                idle_deadline: None,
                idle_timer: None,
                read_outcome: None,
                finished: false,
            },
        ))
    }

    fn from_response_with_state(
        response: Response<ResponseBody>,
        limits: SseLimits,
        last_event_id: String,
        retry_delay: Duration,
        idle_timeout: Option<Duration>,
    ) -> Result<Response<Self>, SseError> {
        validate_response(&response)?;
        let idle_deadline = idle_timeout
            .map(|timeout| {
                Instant::now()
                    .checked_add(timeout)
                    .ok_or_else(SseError::invalid_idle_timeout)
            })
            .transpose()?;
        let (parts, body) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            Self {
                body: Some(body),
                decoder: Decoder::with_state(limits, last_event_id, Some(retry_delay)),
                idle_timeout,
                idle_deadline,
                idle_timer: None,
                read_outcome: None,
                finished: false,
            },
        ))
    }

    /// Reads until the next complete event or the response body ends.
    ///
    /// An event without a terminating blank line is discarded at end of body.
    /// Empty-data blocks update persistent ID and retry state but are not
    /// returned as events.
    ///
    /// # Errors
    ///
    /// Returns [`SseError`] with kind [`SseErrorKind::LineTooLong`] or
    /// [`SseErrorKind::EventTooLarge`] when a limit is exceeded, or
    /// [`SseErrorKind::Body`] when the response body fails. After an error the
    /// body is released and later calls return `Ok(None)`.
    pub async fn next_event(&mut self) -> Result<Option<SseEvent>, SseError> {
        NextEvent { stream: self }.await
    }

    /// Returns the persistent last-event ID observed so far.
    #[must_use]
    pub fn last_event_id(&self) -> &str {
        &self.decoder.last_event_id
    }

    /// Returns the latest valid `retry` duration observed in the stream.
    #[must_use]
    pub const fn retry_delay(&self) -> Option<Duration> {
        self.decoder.retry_delay
    }

    /// Returns the active decoder limits.
    #[must_use]
    pub const fn limits(&self) -> SseLimits {
        self.decoder.limits
    }

    fn poll_event(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<SseEvent, SseError>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        loop {
            match self.decoder.decode_available() {
                Ok(Some(event)) => return Poll::Ready(Some(Ok(event))),
                Ok(None) => {}
                Err(error) => {
                    self.finish();
                    return Poll::Ready(Some(Err(error)));
                }
            }
            if self.body.is_none() {
                self.finish();
                return Poll::Ready(None);
            }
            if self.idle_timer.is_none() {
                self.idle_timer = match self.idle_deadline.map(DeadlineTimer::new).transpose() {
                    Ok(timer) => timer,
                    Err(error) => {
                        self.finish();
                        return Poll::Ready(Some(Err(SseError::request(error))));
                    }
                };
            }
            let frame = match self.body.as_mut() {
                Some(body) => Pin::new(body).poll_frame(context),
                None => Poll::Ready(None),
            };
            match frame {
                Poll::Pending => {
                    match self
                        .idle_timer
                        .as_mut()
                        .map(|timer| timer.poll_expired(context))
                    {
                        Some(Poll::Ready(result)) => {
                            self.finish();
                            let error = match result {
                                Ok(()) => SseError::idle_timeout(),
                                Err(error) => SseError::request(error),
                            };
                            return Poll::Ready(Some(Err(error)));
                        }
                        Some(Poll::Pending) | None => return Poll::Pending,
                    }
                }
                Poll::Ready(Some(Ok(frame))) => {
                    if let Ok(data) = frame.into_data() {
                        if let Err(error) = self.reset_idle_deadline() {
                            self.finish();
                            return Poll::Ready(Some(Err(error)));
                        }
                        self.decoder.replace_chunk(data);
                    }
                }
                Poll::Ready(Some(Err(error))) => {
                    self.finish();
                    return Poll::Ready(Some(Err(SseError::body(error))));
                }
                Poll::Ready(None) => {
                    self.finish();
                    return Poll::Ready(None);
                }
            }
        }
    }

    fn cancel_read_outcome(&mut self) {
        self.read_outcome = None;
    }

    fn reset_idle_deadline(&mut self) -> Result<(), SseError> {
        let Some(timeout) = self.idle_timeout else {
            return Ok(());
        };
        self.idle_timer = None;
        self.idle_deadline = Some(
            Instant::now()
                .checked_add(timeout)
                .ok_or_else(SseError::invalid_idle_timeout)?,
        );
        Ok(())
    }

    fn finish(&mut self) {
        self.finished = true;
        self.body = None;
        self.idle_timer = None;
        self.decoder.discard_pending();
    }
}

impl Stream for SseStream {
    type Item = Result<SseEvent, SseError>;

    fn poll_next(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.get_mut();
        let span = stream
            .read_outcome
            .get_or_insert_with(|| {
                SseOutcome::new(&debug_span!("sse.next_event", outcome = field::Empty))
            })
            .span
            .clone();
        let result = span.in_scope(|| stream.poll_event(context));
        if let Poll::Ready(item) = &result {
            if let Some(outcome) = stream.read_outcome.take() {
                outcome.finish(match item {
                    Some(Ok(_)) => "event",
                    None => "eof",
                    Some(Err(error)) => match error.kind() {
                        SseErrorKind::LineTooLong => "line_limit",
                        SseErrorKind::EventTooLarge => "event_limit",
                        SseErrorKind::Body => "body_error",
                        SseErrorKind::IdleTimeout => "idle_timeout",
                        _ => "error",
                    },
                });
            }
        }
        result
    }
}

struct NextEvent<'a> {
    stream: &'a mut SseStream,
}

impl Future for NextEvent<'_> {
    type Output = Result<Option<SseEvent>, SseError>;

    fn poll(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        Pin::new(&mut *self.get_mut().stream)
            .poll_next(context)
            .map(Option::transpose)
    }
}

impl Drop for NextEvent<'_> {
    fn drop(&mut self) {
        self.stream.cancel_read_outcome();
    }
}

impl fmt::Debug for SseStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SseStream")
            .field("limits", &self.decoder.limits)
            .field("idle_timeout", &self.idle_timeout)
            .field("buffered_line_bytes", &self.decoder.line.len())
            .field("buffered_event_bytes", &self.decoder.event_bytes)
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

fn validate_response(response: &Response<ResponseBody>) -> Result<(), SseError> {
    if response.status() != StatusCode::OK {
        return Err(SseError::without_source(
            SseErrorKind::UnexpectedStatus,
            "SSE response status must be 200 OK",
        ));
    }

    let mut content_types = response.headers().get_all(header::CONTENT_TYPE).iter();
    let content_type = content_types.next().ok_or_else(|| {
        SseError::without_source(
            SseErrorKind::InvalidContentType,
            "SSE response must have content type text/event-stream",
        )
    })?;
    let valid_content_type = content_type
        .to_str()
        .ok()
        .and_then(|value| value.split(';').next())
        .is_some_and(|essence| essence.trim().eq_ignore_ascii_case("text/event-stream"));
    if content_types.next().is_some() || !valid_content_type {
        return Err(SseError::without_source(
            SseErrorKind::InvalidContentType,
            "SSE response must have content type text/event-stream",
        ));
    }

    for value in response.headers().get_all(header::CONTENT_ENCODING) {
        let value = value.to_str().map_err(|_| {
            SseError::without_source(
                SseErrorKind::UnsupportedContentEncoding,
                "SSE response uses an unsupported content encoding",
            )
        })?;
        if value
            .split(',')
            .map(str::trim)
            .any(|encoding| !encoding.eq_ignore_ascii_case("identity"))
        {
            return Err(SseError::without_source(
                SseErrorKind::UnsupportedContentEncoding,
                "SSE response uses an unsupported content encoding",
            ));
        }
    }

    Ok(())
}

struct SseOutcome {
    span: tracing::Span,
    recorded: bool,
}

impl SseOutcome {
    fn new(span: &tracing::Span) -> Self {
        Self {
            span: span.clone(),
            recorded: false,
        }
    }

    fn finish(mut self, outcome: &'static str) {
        self.span.record("outcome", outcome);
        self.recorded = true;
    }
}

impl Drop for SseOutcome {
    fn drop(&mut self) {
        if !self.recorded {
            let outcome = if std::thread::panicking() {
                "panicked"
            } else {
                "cancelled"
            };
            self.span.record("outcome", outcome);
        }
    }
}

#[cfg(test)]
mod tests;
