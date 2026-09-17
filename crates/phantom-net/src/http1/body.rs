//! Streaming HTTP/1.1 response-body ownership.

use std::{
    any::Any,
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use tracing::{Dispatch, Span, debug, debug_span, dispatcher};
use wreq_proto::body::Incoming;

use super::{
    Http1Error,
    connection::ConnectionLease,
    driver::{DriverSignal, DriverTask},
};

/// Streaming response body for one HTTP/1.1 request.
#[must_use = "response bodies must be read or deliberately dropped"]
pub struct Http1Body {
    incoming: Incoming,
    owner: Option<BodyOwner>,
    stream_guard: Option<Box<dyn Any + Send + Sync>>,
    reusable: bool,
    finished: bool,
    trace: BodyTrace,
}

impl Http1Body {
    pub(super) fn new(incoming: Incoming, mut lease: ConnectionLease, reusable: bool) -> Self {
        let finished = incoming.is_end_stream();
        let mut trace = BodyTrace::new();
        if finished {
            lease.complete(reusable);
            trace.finish("complete");
        }
        Self {
            incoming,
            owner: (!finished).then_some(BodyOwner::Reusable(lease)),
            stream_guard: None,
            reusable,
            finished,
            trace,
        }
    }

    pub(super) fn new_one_shot(incoming: Incoming, driver: DriverTask) -> Self {
        let finished = incoming.is_end_stream();
        let mut trace = BodyTrace::new();
        if finished {
            driver.finish(DriverSignal::Complete);
            trace.finish("complete");
        }
        Self {
            incoming,
            owner: (!finished).then_some(BodyOwner::OneShot(driver)),
            stream_guard: None,
            reusable: false,
            finished,
            trace,
        }
    }

    /// Retains a value until this request completes or is cancelled.
    #[doc(hidden)]
    pub fn retain_until_stream_complete<T>(&mut self, value: T)
    where
        T: Send + Sync + 'static,
    {
        if !self.finished {
            self.stream_guard = Some(Box::new(value));
        }
    }

    fn complete(&mut self) {
        if let Some(owner) = self.owner.take() {
            owner.complete(self.reusable);
        }
        self.stream_guard.take();
    }

    fn stop(&mut self, signal: DriverSignal) {
        if let Some(owner) = self.owner.take() {
            owner.stop(signal);
        }
        self.stream_guard.take();
    }
}

enum BodyOwner {
    Reusable(ConnectionLease),
    OneShot(DriverTask),
}

impl BodyOwner {
    fn complete(self, reusable: bool) {
        match self {
            Self::Reusable(mut lease) => lease.complete(reusable),
            Self::OneShot(driver) => driver.finish(DriverSignal::Complete),
        }
    }

    fn stop(self, signal: DriverSignal) {
        match self {
            Self::Reusable(mut lease) => lease.stop(signal),
            Self::OneShot(driver) => driver.finish(signal),
        }
    }
}

impl fmt::Debug for Http1Body {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http1Body")
            .field("finished", &self.finished)
            .field("received_bytes", &self.trace.received_bytes)
            .finish_non_exhaustive()
    }
}

impl Body for Http1Body {
    type Data = Bytes;
    type Error = Http1Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let dispatch = self.trace.dispatch.clone();
        let span = self.trace.span.clone();
        dispatcher::with_default(&dispatch, || {
            let _entered = span.enter();

            if self.finished {
                return Poll::Ready(None);
            }

            match Pin::new(&mut self.incoming).poll_frame(context) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        self.trace.add_bytes(data.len());
                    }
                    if self.incoming.is_end_stream() {
                        self.finished = true;
                        self.complete();
                        self.trace.finish("complete");
                    }
                    Poll::Ready(Some(Ok(frame)))
                }
                Poll::Ready(Some(Err(error))) => {
                    self.finished = true;
                    self.stop(DriverSignal::ProtocolError);
                    let error = Http1Error::from(error);
                    self.trace.finish(match &error {
                        Http1Error::ChunkSizeLineTooLarge { .. } => "invalid_response",
                        _ => "protocol_error",
                    });
                    Poll::Ready(Some(Err(error)))
                }
                Poll::Ready(None) => {
                    self.finished = true;
                    self.complete();
                    self.trace.finish("complete");
                    Poll::Ready(None)
                }
                Poll::Pending => Poll::Pending,
            }
        })
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.incoming.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.incoming.size_hint()
    }
}

impl Drop for Http1Body {
    fn drop(&mut self) {
        if !self.finished {
            self.stop(DriverSignal::Cancelled);
            self.trace.finish("dropped");
        }
    }
}

struct BodyTrace {
    dispatch: Dispatch,
    span: Span,
    received_bytes: u64,
    finished: bool,
}

impl BodyTrace {
    fn new() -> Self {
        Self {
            dispatch: dispatcher::get_default(Clone::clone),
            span: debug_span!("http1.response_body"),
            received_bytes: 0,
            finished: false,
        }
    }

    fn add_bytes(&mut self, bytes: usize) {
        let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
        self.received_bytes = self.received_bytes.saturating_add(bytes);
    }

    fn finish(&mut self, outcome: &'static str) {
        if self.finished {
            return;
        }
        self.finished = true;
        dispatcher::with_default(&self.dispatch, || {
            debug!(
                parent: &self.span,
                body_bytes = self.received_bytes,
                outcome,
                "HTTP/1 response body finished"
            );
        });
    }
}
