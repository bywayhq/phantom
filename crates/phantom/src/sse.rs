use std::{error::Error as StdError, fmt, future::poll_fn, pin::Pin, time::Duration};

use http::{Response, StatusCode, header};
use http_body::Body;
use tracing::{Instrument, debug_span, field};

use crate::{RequestError, ResponseBody};

use self::decoder::Decoder;

mod decoder;

const DEFAULT_MAX_LINE_BYTES: usize = 64 * 1024;
const DEFAULT_MAX_EVENT_BYTES: usize = 1024 * 1024;

/// Memory limits applied while decoding one server-sent event stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SseLimits {
    max_line_bytes: usize,
    max_event_bytes: usize,
}

impl SseLimits {
    /// Creates limits from a maximum line length and aggregate event-block size.
    ///
    /// Both limits count encoded bytes and exclude line terminators. A zero
    /// limit rejects the first nonempty line or event block, respectively.
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

/// Pull-based decoder over Phantom's existing streaming response body.
///
/// The stream has no background task or event queue. Dropping a pending
/// [`SseStream::next_event`] future leaves the decoder and response body ready
/// for the next call; dropping the stream preserves the underlying protocol's
/// cancellation behavior.
#[must_use = "SSE streams must be read or deliberately dropped"]
pub struct SseStream {
    body: Option<ResponseBody>,
    decoder: Decoder,
    finished: bool,
}

impl SseStream {
    /// Validates and converts a response using [`SseLimits::default`].
    ///
    /// # Errors
    ///
    /// Returns [`SseError`] unless the response is 200 OK, its content-type
    /// essence is `text/event-stream`, and it has no non-identity content
    /// encoding.
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
    /// Returns [`SseError`] when a configured bound is exceeded or the
    /// underlying response body fails.
    pub async fn next_event(&mut self) -> Result<Option<SseEvent>, SseError> {
        let span = debug_span!("sse.next_event", outcome = field::Empty);
        let outcome = SseOutcome::new(&span);
        let result = self.next_event_inner().instrument(span.clone()).await;
        outcome.finish(match &result {
            Ok(Some(_)) => "event",
            Ok(None) => "eof",
            Err(error) => match error.kind() {
                SseErrorKind::LineTooLong => "line_limit",
                SseErrorKind::EventTooLarge => "event_limit",
                SseErrorKind::Body => "body_error",
                _ => "error",
            },
        });
        result
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

    async fn next_event_inner(&mut self) -> Result<Option<SseEvent>, SseError> {
        if self.finished {
            return Ok(None);
        }

        loop {
            match self.decoder.decode_available() {
                Ok(Some(event)) => return Ok(Some(event)),
                Ok(None) => {}
                Err(error) => {
                    self.finish();
                    return Err(error);
                }
            }

            let Some(body) = self.body.as_mut() else {
                self.finish();
                return Ok(None);
            };
            let frame = poll_fn(|context| Pin::new(&mut *body).poll_frame(context)).await;
            match frame {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        self.decoder.replace_chunk(data);
                    }
                }
                Some(Err(error)) => {
                    self.finish();
                    return Err(SseError::body(error));
                }
                None => {
                    self.finish();
                    return Ok(None);
                }
            }
        }
    }

    fn finish(&mut self) {
        self.finished = true;
        self.body = None;
        self.decoder.discard_pending();
    }
}

impl fmt::Debug for SseStream {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SseStream")
            .field("limits", &self.decoder.limits)
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
