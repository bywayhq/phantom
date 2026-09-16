use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use tracing::{Dispatch, Span, debug, debug_span, dispatcher};

use self::task::{BodyEvent, BodyTask};
use super::{
    DatagramMonitor, Http3Connection, Http3Error, Http3ErrorKind, RequestRecvStream,
    RequestSendStream,
};

pub(super) fn defer_datagram_abort(
    send: RequestSendStream,
    recv: RequestRecvStream,
    connection: Http3Connection,
) {
    task::defer_datagram_abort(send, recv, connection);
}

#[must_use = "response bodies must be read or deliberately dropped"]
/// Streaming response body for one HTTP/3 request stream.
pub struct Http3Body {
    task: BodyTask,
    done: bool,
    trace: BodyTrace,
}

impl Http3Body {
    pub(super) fn new(
        send: RequestSendStream,
        recv: RequestRecvStream,
        connection: Http3Connection,
        datagrams: Option<DatagramMonitor>,
    ) -> Self {
        let trace = BodyTrace::new();
        let runtime = connection.runtime().clone();
        let task = BodyTask::spawn(
            send,
            recv,
            connection,
            datagrams,
            runtime,
            trace.dispatch.clone(),
            trace.span.clone(),
        );
        Self {
            task,
            done: false,
            trace,
        }
    }

    /// Retains a value until the response stream has completed its cleanup.
    ///
    /// This hook lets the facade tie local admission to the actual stream
    /// lifecycle, including bounded reset work after an incomplete body is
    /// dropped.
    #[doc(hidden)]
    pub fn retain_until_stream_cleanup<T>(&mut self, value: T)
    where
        T: Send + 'static,
    {
        self.task.retain_until_cleanup(value);
    }

    fn finish(&mut self, outcome: &'static str) {
        self.done = true;
        self.trace.finish(outcome);
    }

    fn poll_frame_inner(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Http3Error>>> {
        if self.done {
            return Poll::Ready(None);
        }
        match self.task.poll_event(context) {
            Poll::Ready(Some(BodyEvent::Frame(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.trace.add_bytes(data.len());
                }
                if frame.trailers_ref().is_some() {
                    self.finish("complete");
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(BodyEvent::End)) => {
                self.finish("complete");
                Poll::Ready(None)
            }
            Poll::Ready(Some(BodyEvent::Error(error))) => {
                self.finish("protocol_error");
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => {
                self.finish("task_error");
                Poll::Ready(Some(Err(Http3Error::without_source(
                    Http3ErrorKind::Local,
                    "HTTP/3 response body task stopped without a terminal event",
                ))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl fmt::Debug for Http3Body {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http3Body")
            .field("finished", &self.done)
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
        self.done
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl Drop for Http3Body {
    fn drop(&mut self) {
        if !self.done {
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

mod task;

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
