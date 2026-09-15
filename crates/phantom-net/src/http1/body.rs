//! Streaming response-body ownership for one-shot HTTP/1.1 transactions.

use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use http_body_util::Empty;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinHandle,
};
use wreq_proto::{body::Incoming, conn::http1};

use super::Http1Error;

/// Streaming response body for a one-shot HTTP/1.1 transaction.
///
/// Dropping this body schedules cancellation of the protocol driver. Once the
/// runtime observes that cancellation, dropping the driver tears down its byte
/// stream. `Drop` does not wait for teardown to finish.
#[must_use = "response bodies must be read or deliberately dropped"]
pub struct Http1Body {
    incoming: Incoming,
    driver: DriverTask,
    finished: bool,
}

impl Http1Body {
    pub(super) fn new(incoming: Incoming, mut driver: DriverTask) -> Self {
        let finished = incoming.is_end_stream();
        if finished {
            driver.cancel();
        }
        Self {
            incoming,
            driver,
            finished,
        }
    }
}

impl fmt::Debug for Http1Body {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http1Body")
            .field("finished", &self.finished)
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
        if self.finished {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.incoming).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if self.incoming.is_end_stream() {
                    self.finished = true;
                    self.driver.cancel();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.finished = true;
                self.driver.cancel();
                Poll::Ready(Some(Err(Http1Error::Protocol(error))))
            }
            Poll::Ready(None) => {
                self.finished = true;
                self.driver.cancel();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.incoming.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.incoming.size_hint()
    }
}

/// Owns the connection driver and schedules its cancellation when dropped.
///
/// Cancellation is observed asynchronously by Tokio. Only then is the
/// connection future, and therefore its underlying stream, dropped.
pub(super) struct DriverTask {
    handle: Option<JoinHandle<Result<(), wreq_proto::Error>>>,
}

impl DriverTask {
    // Aborting the task only schedules cancellation. The runtime later drops
    // the connection future and its stream; callers must not infer synchronous
    // transport teardown from this guard's `Drop`.
    pub(super) fn spawn<T>(connection: http1::Connection<T, Empty<Bytes>>) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            handle: Some(tokio::spawn(connection)),
        }
    }

    fn cancel(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for DriverTask {
    fn drop(&mut self) {
        self.cancel();
    }
}
