//! Bounded Rust SSE decoding and operation-owned event results.

use std::{error::Error, time::Duration};

use phantom::{RequestError, SseError, SseErrorKind, SseEvent, SseLimits};
use serde::Deserialize;

use super::response::{ReadLease, Stream};
use crate::error::Failure;

pub(crate) const MAX_LINE: usize = 1024 * 1024;
pub(crate) const MAX_EVENT: usize = 8 * 1024 * 1024;
// UTF-8 replacement can expand each encoded byte to three bytes. The
// persistent ID may come from an earlier block, separately bounded by MAX_LINE.
pub(crate) const MAX_RESULT: usize = 3 * (MAX_LINE + MAX_EVENT) + 7;

#[derive(Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Limits {
    pub(crate) line: usize,
    pub(crate) event: usize,
}

impl Limits {
    pub(crate) fn core(self) -> Result<SseLimits, Failure> {
        if self.line > MAX_LINE || self.event > MAX_EVENT {
            return Err(Failure::new("invalid_sse_limits"));
        }
        Ok(SseLimits::new(self.line, self.event))
    }
}

pub(crate) struct Read {
    pub(crate) event: Option<SseEvent>,
    pub(crate) last_event_id: String,
    pub(crate) retry: Option<Duration>,
    pub(crate) error: Option<Failure>,
    pub(crate) cause: Option<Failure>,
    pub(crate) trailers: Option<super::trailers::Snapshot>,
}

impl Read {
    pub(crate) fn finished(&self) -> bool {
        self.event.is_none() || self.error.is_some()
    }

    pub(crate) fn id(&self) -> &str {
        self.event
            .as_ref()
            .map_or(&self.last_event_id, SseEvent::id)
    }
}

impl ReadLease {
    pub(super) async fn next_event(mut self) -> Result<Read, Failure> {
        self.stream = self
            .owner
            .stream
            .lock()
            .map_err(|_| Failure::new("internal"))?
            .take();
        let Some(Stream::Events(stream)) = self.stream.as_mut() else {
            return Err(Failure::new("body_type"));
        };
        let changed = self.owner.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        if self.owner.closed.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(Failure::new("sse_closed"));
        }
        let event = tokio::select! {
            biased;
            () = &mut changed => return Err(Failure::new("sse_closed")),
            result = stream.next_event() => result,
        };
        let last_event_id = if matches!(&event, Ok(Some(_))) {
            String::new()
        } else {
            stream.last_event_id().to_owned()
        };
        let retry = stream.retry_delay();
        let trailers = if matches!(&event, Ok(None)) {
            Some(super::trailers::snapshot(stream.trailers())?)
        } else {
            None
        };
        let (event, error, cause) = match event {
            Ok(event) => (event, None, None),
            Err(error) => {
                let cause = error
                    .source()
                    .and_then(|source| source.downcast_ref::<RequestError>())
                    .map(Failure::from);
                (None, Some(failure(&error)), cause)
            }
        };
        let result = Read {
            event,
            last_event_id,
            retry,
            error,
            cause,
            trailers,
        };
        if !result.finished() {
            let mut slot = self
                .owner
                .stream
                .lock()
                .map_err(|_| Failure::new("internal"))?;
            if self.owner.closed.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(Failure::new("sse_closed"));
            }
            *slot = self.stream.take();
            self.restored = true;
        }
        Ok(result)
    }
}

pub(crate) fn failure(error: &SseError) -> Failure {
    Failure::new(match error.kind() {
        SseErrorKind::UnexpectedStatus => "sse_unexpected_status",
        SseErrorKind::InvalidContentType => "sse_invalid_content_type",
        SseErrorKind::UnsupportedContentEncoding => "sse_unsupported_content_encoding",
        SseErrorKind::LineTooLong => "sse_line_too_long",
        SseErrorKind::EventTooLarge => "sse_event_too_large",
        SseErrorKind::Body => "sse_body",
        SseErrorKind::Request => "sse_request",
        SseErrorKind::InvalidRequestHeader => "sse_invalid_request_header",
        SseErrorKind::InvalidReconnectDelay => "sse_invalid_reconnect_delay",
        SseErrorKind::InvalidIdleTimeout => "sse_invalid_idle_timeout",
        SseErrorKind::IdleTimeout => "sse_idle_timeout",
        SseErrorKind::ReconnectLimit => "sse_reconnect_limit",
        _ => "sse_unknown",
    })
}
