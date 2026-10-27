//! One-response SSE decoding on the existing request admission and cancellation.

use std::{
    error::Error as _,
    fmt,
    sync::{Arc, MutexGuard, PoisonError},
};

use napi::Result;
use phantom::{SseEvent, SseLimits, SseStream};

use super::{EOF, Exchange, RetainedBody};
use crate::error::failure;

#[derive(Default)]
pub(crate) struct EventState {
    pub(crate) last_event_id: String,
    pub(crate) retry_ms: Option<u64>,
}

impl fmt::Debug for EventState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EventState")
            .field("last_event_id_bytes", &self.last_event_id.len())
            .field("retry_ms", &self.retry_ms)
            .finish()
    }
}

impl Exchange {
    pub(crate) fn open_events(self: &Arc<Self>, limits: SseLimits) -> Result<()> {
        let _reading = self.start_reading()?;
        let mut retained = self.body.lock().unwrap_or_else(PoisonError::into_inner);
        self.check()?;
        let body = match retained.as_ref() {
            Some(RetainedBody::Http(body)) if !body.started => body,
            _ => {
                return Err(failure(
                    "BodyUsed",
                    "events require an unread response body",
                ));
            }
        };
        SseStream::validate_response(&body.response).map_err(error)?;
        let Some(RetainedBody::Http(body)) = retained.take() else {
            return Err(failure("Internal", "validated response body is absent"));
        };
        let events = SseStream::from_response_with_limits(body.response, limits)
            .map_err(error)?
            .into_body();
        *retained = Some(RetainedBody::Events(events));
        Ok(())
    }

    pub(crate) fn event_state(&self) -> MutexGuard<'_, EventState> {
        self.event_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) async fn next_event(self: Arc<Self>) -> Result<Option<SseEvent>> {
        let _reading = self.start_reading()?;
        if self.terminal.load(std::sync::atomic::Ordering::Acquire) == EOF {
            return Ok(None);
        }
        let mut events = {
            let mut retained = self.body.lock().unwrap_or_else(PoisonError::into_inner);
            self.check()?;
            match retained.take() {
                Some(RetainedBody::Events(events)) => events,
                other => {
                    *retained = other;
                    return Err(failure("BodyUsed", "response body is not an event stream"));
                }
            }
        };
        let result = tokio::select! {
            biased;
            error = self.interrupted() => Err(error),
            event = events.next_event() => event.map_err(error),
        };
        let retry_ms = match events
            .retry_delay()
            .map(|delay| u64::try_from(delay.as_millis()))
            .transpose()
        {
            Ok(retry) => retry,
            Err(_) => {
                self.fail();
                return Err(failure(
                    "Internal",
                    "SSE retry delay exceeds u64 milliseconds",
                ));
            }
        };
        *self
            .event_state
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = EventState {
            last_event_id: events.last_event_id().to_owned(),
            retry_ms,
        };
        match &result {
            Ok(Some(_)) => {
                let mut retained = self.body.lock().unwrap_or_else(PoisonError::into_inner);
                if let Err(error) = self.check() {
                    drop(retained);
                    self.fail();
                    return Err(error);
                }
                *retained = Some(RetainedBody::Events(events));
            }
            Ok(None) => self.finish(EOF, events.into_trailers()),
            Err(_) => self.fail(),
        }
        result
    }
}

pub(crate) fn error(error: phantom::SseError) -> napi::Error {
    if let Some(source) = error
        .source()
        .and_then(|source| source.downcast_ref::<phantom::RequestError>())
    {
        return crate::error::request_ref(source);
    }
    napi::Error::new(
        napi::Status::GenericFailure,
        format!("PHANTOM_SSE:{:?}:{error}", error.kind()),
    )
}

#[cfg(test)]
mod tests {
    use super::{EventState, Exchange};

    #[test]
    fn exchange_debug_retains_event_metadata_without_the_event_id() {
        let exchange = Exchange::new();
        *exchange.event_state() = EventState {
            last_event_id: "secret-é-id".to_owned(),
            retry_ms: Some(17),
        };

        let output = format!("{exchange:?}");
        assert!(output.contains("last_event_id_bytes: 12"));
        assert!(output.contains("retry_ms: Some(17)"));
        assert!(!output.contains("secret"));
        assert!(!output.contains('é'));
    }
}
