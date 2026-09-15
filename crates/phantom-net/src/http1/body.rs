//! Streaming response-body ownership for one-shot HTTP/1.1 transactions.

use std::{
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
    driver::{DriverSignal, DriverTask},
};

/// Streaming response body for a one-shot HTTP/1.1 transaction.
///
/// Dropping this body signals the protocol driver's supervisor on the runtime
/// where the request originated. The supervisor then tears down the byte
/// stream. `Drop` does not wait for teardown to finish.
#[must_use = "response bodies must be read or deliberately dropped"]
pub struct Http1Body {
    incoming: Incoming,
    driver: DriverTask,
    finished: bool,
    trace: BodyTrace,
}

impl Http1Body {
    pub(super) fn new(incoming: Incoming, mut driver: DriverTask) -> Self {
        let finished = incoming.is_end_stream();
        let mut trace = BodyTrace::new();
        if finished {
            driver.finish(DriverSignal::Complete);
            trace.finish("complete");
        }
        Self {
            incoming,
            driver,
            finished,
            trace,
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
                        self.driver.finish(DriverSignal::Complete);
                        self.trace.finish("complete");
                    }
                    Poll::Ready(Some(Ok(frame)))
                }
                Poll::Ready(Some(Err(error))) => {
                    self.finished = true;
                    self.driver.finish(DriverSignal::ProtocolError);
                    self.trace.finish("protocol_error");
                    Poll::Ready(Some(Err(Http1Error::Protocol(error))))
                }
                Poll::Ready(None) => {
                    self.finished = true;
                    self.driver.finish(DriverSignal::Complete);
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
            self.driver.finish(DriverSignal::Cancelled);
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
