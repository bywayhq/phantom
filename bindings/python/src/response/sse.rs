use std::sync::{Arc, Mutex};

use phantom::{SseError, SseErrorKind, SseLimits, SseStream};
use pyo3::prelude::*;

use super::{BodyOwner, EXPIRED, OPEN, ReadLease, Stream};
use crate::error;

#[derive(Default)]
struct State {
    last_event_id: String,
    retry_ms: Option<u128>,
}

#[pyclass]
pub(crate) struct NativeEventStream {
    owner: Arc<BodyOwner>,
    state: Arc<Mutex<State>>,
}

impl NativeEventStream {
    pub(super) fn from_response(
        owner: &Arc<BodyOwner>,
        maximum_line_bytes: usize,
        maximum_event_bytes: usize,
    ) -> PyResult<Self> {
        let mut lease = ReadLease::acquire(owner)?;
        if owner.state.load(std::sync::atomic::Ordering::SeqCst) != OPEN {
            return Err(owner.closed_error());
        }
        let Some(Stream::Body(body)) = lease.stream.as_ref() else {
            lease.restore()?;
            return Err(error::input("body_consumed"));
        };
        if body.head.is_none() {
            lease.restore()?;
            return Err(error::input("body_consumed"));
        }
        let Some(Stream::Body(mut body)) = lease.stream.take() else {
            return Err(error::input("body_state"));
        };
        let head = body.head.take().ok_or_else(|| error::input("body_state"))?;
        let response = phantom::Response::from_parts(head, body.body);
        if let Err(error) = SseStream::validate_response(&response) {
            let (head, body) = response.into_parts();
            lease.stream = Some(Stream::Body(super::BodyStream {
                body,
                pending: phantom::Bytes::new(),
                head: Some(head),
            }));
            lease.restore()?;
            return Err(sse_error(error));
        }
        let stream = SseStream::from_response_with_limits(
            response,
            SseLimits::new(maximum_line_bytes, maximum_event_bytes),
        )
        .map_err(sse_error)?
        .into_body();
        lease.stream = Some(Stream::Events(stream));
        lease.restore()?;
        Ok(Self {
            owner: Arc::clone(owner),
            state: Arc::new(Mutex::new(State::default())),
        })
    }
}

#[pymethods]
impl NativeEventStream {
    #[getter]
    fn last_event_id(&self) -> PyResult<String> {
        Ok(self
            .state
            .lock()
            .map_err(|_| error::input("body_state"))?
            .last_event_id
            .clone())
    }

    #[getter]
    fn retry_ms(&self) -> PyResult<Option<u128>> {
        Ok(self
            .state
            .lock()
            .map_err(|_| error::input("body_state"))?
            .retry_ms)
    }

    fn next_event<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let owner = Arc::clone(&self.owner);
        let state = Arc::clone(&self.state);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let mut lease = ReadLease::acquire(&owner)?;
            let Some(Stream::Events(stream)) = lease.stream.as_mut() else {
                if owner.state.load(std::sync::atomic::Ordering::SeqCst) == EXPIRED {
                    return Err(owner.closed_error());
                }
                return Ok(None::<(String, String, String)>);
            };
            let changed = owner.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if owner.state.load(std::sync::atomic::Ordering::SeqCst) != OPEN {
                return Err(owner.closed_error());
            }
            let result = tokio::select! {
                biased;
                () = &mut changed => return Err(owner.closed_error()),
                result = stream.next_event() => result,
            };
            {
                let mut state = state.lock().map_err(|_| error::input("body_state"))?;
                state.last_event_id = stream.last_event_id().to_owned();
                state.retry_ms = stream.retry_delay().map(|delay| delay.as_millis());
            }
            match result {
                Ok(Some(event)) => {
                    let fields = (
                        event.data().to_owned(),
                        event.event().to_owned(),
                        event.id().to_owned(),
                    );
                    lease.restore()?;
                    Ok(Some(fields))
                }
                Ok(None) => {
                    lease.complete()?;
                    Ok(None)
                }
                Err(error) => Err(sse_error(error)),
            }
        })
    }
}

fn sse_error(error: SseError) -> PyErr {
    if let Some(source) = std::error::Error::source(&error)
        .and_then(|source| source.downcast_ref::<phantom::RequestError>())
    {
        // Preserve body timeout/transport categories, without exposing content.
        return error::request_ref(source);
    }
    let kind = match error.kind() {
        SseErrorKind::UnexpectedStatus => "unexpected_status",
        SseErrorKind::InvalidContentType => "invalid_content_type",
        SseErrorKind::UnsupportedContentEncoding => "unsupported_content_encoding",
        SseErrorKind::LineTooLong => "line_too_long",
        SseErrorKind::EventTooLarge => "event_too_large",
        SseErrorKind::Body => "body",
        _ => "unknown",
    };
    error::NativeError::new_err(("sse", kind, None::<String>, None::<String>))
}
