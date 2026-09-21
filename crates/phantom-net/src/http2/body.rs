//! Streaming HTTP/2 response-body ownership.

use std::{
    any::Any,
    fmt,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
};

use ::http2::{Reason, RecvStream, SendStream};
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use tracing::{Dispatch, Span, debug, debug_span, dispatcher};

use super::{
    Http2Error,
    connection::{ConnectionLease, PendingUpload},
};

/// Streaming response body for one HTTP/2 stream.
///
/// DATA and trailers are yielded as received. When the server answered before
/// the request body was sent, polling this body also continues that upload.
/// If this body is dropped before the stream ends, it resets only this stream
/// with `CANCEL`. The connection
/// stays alive while another connection handle or response-body lease exists.
#[must_use = "response bodies must be read or deliberately dropped"]
pub struct Http2Body {
    incoming: Option<RecvStream>,
    reset: Option<SendStream<Bytes>>,
    // `Mutex` makes the unsynchronized future `Sync`; it is only accessed
    // through `&mut self`, so it never blocks.
    upload: Option<Mutex<PendingUpload>>,
    lease: Option<ConnectionLease>,
    stream_guard: Option<Box<dyn Any + Send + Sync>>,
    finished: bool,
    trace: BodyTrace,
}

impl Http2Body {
    pub(super) fn new(
        incoming: RecvStream,
        reset: SendStream<Bytes>,
        lease: ConnectionLease,
    ) -> Self {
        Self::from_parts(incoming, Some(reset), None, lease)
    }

    /// Builds a body for a complete response whose upload was abandoned.
    pub(super) fn without_upload(incoming: RecvStream, lease: ConnectionLease) -> Self {
        Self::from_parts(incoming, None, None, lease)
    }

    /// Builds a body that keeps sending the request body while it is read.
    pub(super) fn with_pending_upload(
        incoming: RecvStream,
        upload: PendingUpload,
        lease: ConnectionLease,
    ) -> Self {
        Self::from_parts(incoming, None, Some(upload), lease)
    }

    fn from_parts(
        incoming: RecvStream,
        reset: Option<SendStream<Bytes>>,
        upload: Option<PendingUpload>,
        lease: ConnectionLease,
    ) -> Self {
        let finished = incoming.is_end_stream();
        let mut trace = BodyTrace::new();
        if finished {
            trace.finish("complete");
        }
        Self {
            incoming: (!finished).then_some(incoming),
            reset: reset.filter(|_| !finished),
            upload: upload.filter(|_| !finished).map(Mutex::new),
            lease: (!finished).then_some(lease),
            stream_guard: None,
            finished,
            trace,
        }
    }

    /// Retains a value until this stream completes or is cancelled.
    #[doc(hidden)]
    pub fn retain_until_stream_complete<T>(&mut self, value: T)
    where
        T: Send + Sync + 'static,
    {
        if !self.finished {
            self.stream_guard = Some(Box::new(value));
        }
    }

    fn finish_stream(&mut self) {
        self.incoming.take();
        self.upload.take();
        self.reset.take();
        self.lease.take();
        self.stream_guard.take();
    }

    fn poll_frame_inner(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Http2Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }

        if let Some(upload) = self.upload.as_mut() {
            let upload = upload
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            match upload.as_mut().poll(context) {
                Poll::Ready(Ok(stream)) => {
                    self.upload = None;
                    self.reset = Some(stream);
                }
                Poll::Ready(Err(error)) => {
                    self.finished = true;
                    self.finish_stream();
                    self.trace.finish("request_body_error");
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Pending => {}
            }
        }

        let Some(incoming) = self.incoming.as_mut() else {
            self.finished = true;
            self.finish_stream();
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
                    self.finish_stream();
                    self.trace.finish("complete");
                }
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
            Poll::Ready(Some(Err(error))) => {
                self.finished = true;
                self.finish_stream();
                self.trace.finish("protocol_error");
                Poll::Ready(Some(Err(Http2Error::protocol(error))))
            }
            Poll::Ready(None) => match incoming.poll_trailers(context) {
                Poll::Ready(Ok(Some(trailers))) => {
                    self.finished = true;
                    self.finish_stream();
                    self.trace.finish("complete");
                    Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                }
                Poll::Ready(Ok(None)) => {
                    self.finished = true;
                    self.finish_stream();
                    self.trace.finish("complete");
                    Poll::Ready(None)
                }
                Poll::Ready(Err(error)) => {
                    self.finished = true;
                    self.finish_stream();
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
            self.upload.take();
            self.incoming.take();
            self.lease.take();
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
