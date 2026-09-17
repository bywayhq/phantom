use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use crate::{
    HttpProtocol, RequestError,
    timeout::{ResponseTimeouts, TimeoutBudget},
};
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use phantom_net::{http1::Http1Body, http2::Http2Body, http3::Http3Body};

/// Streaming response body returned by the public client.
///
/// Dropping an incomplete body preserves the selected protocol's cancellation
/// behavior and bounded driver teardown.
#[must_use = "response bodies must be read or deliberately dropped"]
pub struct ResponseBody {
    inner: Option<ResponseBodyInner>,
    timeouts: Option<ResponseTimeouts>,
}

enum ResponseBodyInner {
    Http1(Http1Body),
    Http2(Http2Body),
    Http3(Http3Body),
}

impl ResponseBody {
    pub(crate) fn http1(body: Http1Body) -> Self {
        Self {
            inner: Some(ResponseBodyInner::Http1(body)),
            timeouts: None,
        }
    }

    pub(crate) fn http1_with_guard<T>(mut body: Http1Body, guard: T) -> Self
    where
        T: Send + Sync + 'static,
    {
        body.retain_until_stream_complete(guard);
        Self::http1(body)
    }

    pub(crate) fn http2(body: Http2Body) -> Self {
        Self {
            inner: Some(ResponseBodyInner::Http2(body)),
            timeouts: None,
        }
    }

    pub(crate) fn http2_with_guard<T>(mut body: Http2Body, guard: T) -> Self
    where
        T: Send + Sync + 'static,
    {
        body.retain_until_stream_complete(guard);
        Self::http2(body)
    }

    pub(crate) fn http3(body: Http3Body) -> Self {
        Self {
            inner: Some(ResponseBodyInner::Http3(body)),
            timeouts: None,
        }
    }

    pub(crate) fn http3_with_guard<T>(mut body: Http3Body, guard: T) -> Self
    where
        T: Send + 'static,
    {
        body.retain_until_stream_cleanup(guard);
        Self::http3(body)
    }

    pub(crate) fn apply_timeouts(
        &mut self,
        budget: TimeoutBudget,
        protocol: HttpProtocol,
    ) -> Result<(), RequestError> {
        if !self.is_end_stream() {
            self.timeouts = budget.response_body(protocol)?;
        }
        Ok(())
    }
}

impl fmt::Debug for ResponseBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            Some(ResponseBodyInner::Http1(body)) => {
                formatter.debug_tuple("Http1").field(body).finish()
            }
            Some(ResponseBodyInner::Http2(body)) => {
                formatter.debug_tuple("Http2").field(body).finish()
            }
            Some(ResponseBodyInner::Http3(body)) => {
                formatter.debug_tuple("Http3").field(body).finish()
            }
            None => formatter.write_str("Closed"),
        }
    }
}

impl Body for ResponseBody {
    type Data = Bytes;
    type Error = RequestError;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let result = match this.inner.as_mut() {
            Some(ResponseBodyInner::Http1(body)) => Pin::new(body)
                .poll_frame(context)
                .map(|frame| frame.map(|result| result.map_err(RequestError::http1_body))),
            Some(ResponseBodyInner::Http2(body)) => Pin::new(body)
                .poll_frame(context)
                .map(|frame| frame.map(|result| result.map_err(RequestError::http2_body))),
            Some(ResponseBodyInner::Http3(body)) => Pin::new(body)
                .poll_frame(context)
                .map(|frame| frame.map(|result| result.map_err(RequestError::http3_body))),
            None => Poll::Ready(None),
        };
        match result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(timeouts) = this.timeouts.as_mut() {
                    if let Err(error) = timeouts.record_activity() {
                        this.inner.take();
                        this.timeouts.take();
                        return Poll::Ready(Some(Err(error)));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(frame) => {
                if frame.is_none() || frame.as_ref().is_some_and(Result::is_err) {
                    this.timeouts.take();
                }
                Poll::Ready(frame)
            }
            Poll::Pending => {
                if let Some(timeouts) = this.timeouts.as_mut() {
                    if let Poll::Ready(error) = timeouts.poll_expired(context) {
                        tracing::debug!(
                            timeout_phase =
                                error.timeout_phase().map(crate::TimeoutPhase::trace_name),
                            "response body timed out"
                        );
                        this.inner.take();
                        this.timeouts.take();
                        return Poll::Ready(Some(Err(error)));
                    }
                }
                Poll::Pending
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            Some(ResponseBodyInner::Http1(body)) => body.is_end_stream(),
            Some(ResponseBodyInner::Http2(body)) => body.is_end_stream(),
            Some(ResponseBodyInner::Http3(body)) => body.is_end_stream(),
            None => true,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            Some(ResponseBodyInner::Http1(body)) => body.size_hint(),
            Some(ResponseBodyInner::Http2(body)) => body.size_hint(),
            Some(ResponseBodyInner::Http3(body)) => body.size_hint(),
            None => SizeHint::with_exact(0),
        }
    }
}
