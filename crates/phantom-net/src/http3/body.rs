use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Buf, Bytes};
use h3::error::Code;
use http_body::{Body, Frame, SizeHint};
use tracing::{Dispatch, Span, debug, debug_span, dispatcher};

use super::{DriverSignal, DriverTask, Http3Error, Http3ErrorKind, RequestStream};

#[derive(Clone, Copy)]
enum ReceiveState {
    Data,
    Trailers,
    Done,
}

#[must_use = "response bodies must be read or deliberately dropped"]
/// Streaming response body for a one-shot HTTP/3 transaction.
pub struct Http3Body {
    stream: Option<RequestStream>,
    driver: DriverTask,
    state: ReceiveState,
    trace: BodyTrace,
}

impl Http3Body {
    pub(super) fn new(stream: RequestStream, driver: DriverTask) -> Self {
        Self {
            stream: Some(stream),
            driver,
            state: ReceiveState::Data,
            trace: BodyTrace::new(),
        }
    }

    fn finish(&mut self, signal: DriverSignal, outcome: &'static str) {
        self.state = ReceiveState::Done;
        self.stream.take();
        self.driver.finish(signal);
        self.trace.finish(outcome);
    }

    fn poll_frame_inner(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Http3Error>>> {
        loop {
            let state = self.state;
            if matches!(state, ReceiveState::Done) {
                return Poll::Ready(None);
            }
            let Some(stream) = self.stream.as_mut() else {
                self.finish(DriverSignal::ProtocolError, "protocol_error");
                return Poll::Ready(Some(Err(Http3Error::without_source(
                    Http3ErrorKind::Local,
                    "HTTP/3 request driver is unavailable",
                ))));
            };
            match state {
                ReceiveState::Data => match stream.poll_recv_data(context) {
                    Poll::Ready(Ok(Some(mut data))) => {
                        let data = data.copy_to_bytes(data.remaining());
                        self.trace.add_bytes(data.len());
                        return Poll::Ready(Some(Ok(Frame::data(data))));
                    }
                    Poll::Ready(Ok(None)) => self.state = ReceiveState::Trailers,
                    Poll::Ready(Err(error)) => {
                        self.finish(DriverSignal::ProtocolError, "protocol_error");
                        return Poll::Ready(Some(Err(error.into())));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                ReceiveState::Trailers => match stream.poll_recv_trailers(context) {
                    Poll::Ready(Ok(Some(trailers))) => {
                        self.finish(DriverSignal::Complete, "complete");
                        return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                    }
                    Poll::Ready(Ok(None)) => {
                        self.finish(DriverSignal::Complete, "complete");
                        return Poll::Ready(None);
                    }
                    Poll::Ready(Err(error)) => {
                        self.finish(DriverSignal::ProtocolError, "protocol_error");
                        return Poll::Ready(Some(Err(error.into())));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                ReceiveState::Done => return Poll::Ready(None),
            }
        }
    }
}

impl fmt::Debug for Http3Body {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http3Body")
            .field("finished", &matches!(self.state, ReceiveState::Done))
            .field("received_bytes", &self.trace.received_bytes)
            .finish_non_exhaustive()
    }
}

impl Body for Http3Body {
    type Data = Bytes;
    type Error = Http3Error;

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
        matches!(self.state, ReceiveState::Done)
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl Drop for Http3Body {
    fn drop(&mut self) {
        if matches!(self.state, ReceiveState::Done) {
            return;
        }
        if let Some(stream) = self.stream.as_mut() {
            stream.stop_sending(Code::H3_REQUEST_CANCELLED);
            stream.stop_stream(Code::H3_REQUEST_CANCELLED);
        }
        self.finish(DriverSignal::Cancelled, "dropped");
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
            span: debug_span!("http3.response_body"),
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
                "HTTP/3 response body finished"
            );
        });
    }
}
