//! Streaming response-body ownership for one-shot HTTP/2 transactions.

use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use ::http2::{Reason, RecvStream, SendStream};
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use tracing::{Dispatch, Span, debug, debug_span, dispatcher};

use super::{Http2Error, driver::DriverTask};

/// Streaming response body for a one-shot HTTP/2 transaction.
///
/// DATA and trailers are yielded as received. If this body is dropped before
/// the stream ends, it explicitly resets the stream with `CANCEL` before the
/// final connection sender is dropped. The still-running driver flushes that
/// reset and then closes the one-shot connection.
#[must_use = "response bodies must be read or deliberately dropped"]
pub struct Http2Body {
    // Declaration order is intentional: an incomplete receive stream must be
    // dropped before DriverTask drops the last request sender.
    incoming: Option<RecvStream>,
    reset: Option<SendStream<Bytes>>,
    driver: DriverTask,
    finished: bool,
    trace: BodyTrace,
}

impl Http2Body {
    pub(super) fn new(
        incoming: RecvStream,
        reset: SendStream<Bytes>,
        mut driver: DriverTask,
    ) -> Self {
        let finished = incoming.is_end_stream();
        let mut trace = BodyTrace::new();
        if finished {
            driver.shutdown();
            trace.finish("complete");
        }
        Self {
            incoming: (!finished).then_some(incoming),
            reset: (!finished).then_some(reset),
            driver,
            finished,
            trace,
        }
    }

    fn poll_frame_inner(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Http2Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }

        let Some(incoming) = self.incoming.as_mut() else {
            self.finished = true;
            self.driver.shutdown();
            self.trace.finish("protocol_error");
            return Poll::Ready(Some(Err(Http2Error::protocol(::http2::Error::from(
                ::http2::Reason::INTERNAL_ERROR,
            )))));
        };
        match incoming.poll_data(context) {
            Poll::Ready(Some(Ok(data))) => {
                let _ = incoming.flow_control().release_capacity(data.len());
                let end_stream = incoming.is_end_stream();
                self.trace.add_bytes(data.len());
                if end_stream {
                    self.finished = true;
                    self.incoming.take();
                    self.reset.take();
                    self.driver.shutdown();
                    self.trace.finish("complete");
                }
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
            Poll::Ready(Some(Err(error))) => {
                self.finished = true;
                self.incoming.take();
                self.reset.take();
                self.driver.shutdown();
                self.trace.finish("protocol_error");
                Poll::Ready(Some(Err(Http2Error::protocol(error))))
            }
            Poll::Ready(None) => match incoming.poll_trailers(context) {
                Poll::Ready(Ok(Some(trailers))) => {
                    self.finished = true;
                    self.incoming.take();
                    self.reset.take();
                    self.driver.shutdown();
                    self.trace.finish("complete");
                    Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                }
                Poll::Ready(Ok(None)) => {
                    self.finished = true;
                    self.incoming.take();
                    self.reset.take();
                    self.driver.shutdown();
                    self.trace.finish("complete");
                    Poll::Ready(None)
                }
                Poll::Ready(Err(error)) => {
                    self.finished = true;
                    self.incoming.take();
                    self.reset.take();
                    self.driver.shutdown();
                    self.trace.finish("protocol_error");
                    Poll::Ready(Some(Err(Http2Error::protocol(error))))
                }
                Poll::Pending => Poll::Pending,
            },
            Poll::Pending => Poll::Pending,
        }
    }
}

impl fmt::Debug for Http2Body {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http2Body")
            .field("finished", &self.finished)
            .field("received_bytes", &self.trace.received_bytes)
            .finish_non_exhaustive()
    }
}

impl Body for Http2Body {
    type Data = Bytes;
    type Error = Http2Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let span = self.trace.span.clone();
        let dispatch = self.trace.dispatch.clone();
        dispatcher::with_default(&dispatch, || {
            let _entered = span.enter();
            self.as_mut().poll_frame_inner(context)
        })
    }

    fn is_end_stream(&self) -> bool {
        self.finished
            || self
                .incoming
                .as_ref()
                .is_some_and(RecvStream::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl Drop for Http2Body {
    fn drop(&mut self) {
        if !self.finished {
            if let Some(mut reset) = self.reset.take() {
                reset.send_reset(Reason::CANCEL);
            }
            self.incoming.take();
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
            span: debug_span!("http2.response_body"),
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
                "HTTP/2 response body finished"
            );
        });
    }
}
