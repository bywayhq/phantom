use std::{
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use crate::RequestError;
use bytes::Bytes;
use http_body::{Body, Frame, SizeHint};
use phantom_net::{http1::Http1Body, http2::Http2Body, http3::Http3Body};

/// Streaming response body returned by the public client.
///
/// Dropping an incomplete body preserves the selected protocol's cancellation
/// behavior and bounded driver teardown.
#[must_use = "response bodies must be read or deliberately dropped"]
pub struct ResponseBody {
    inner: ResponseBodyInner,
}

enum ResponseBodyInner {
    Http1(Http1Body),
    Http2(Http2Body),
    Http3(Http3Body),
}

impl ResponseBody {
    pub(crate) fn http1(body: Http1Body) -> Self {
        Self {
            inner: ResponseBodyInner::Http1(body),
        }
    }

    pub(crate) fn http2(body: Http2Body) -> Self {
        Self {
            inner: ResponseBodyInner::Http2(body),
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
            inner: ResponseBodyInner::Http3(body),
        }
    }

    pub(crate) fn http3_with_guard<T>(mut body: Http3Body, guard: T) -> Self
    where
        T: Send + 'static,
    {
        body.retain_until_stream_cleanup(guard);
        Self::http3(body)
    }
}

impl fmt::Debug for ResponseBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            ResponseBodyInner::Http1(body) => formatter.debug_tuple("Http1").field(body).finish(),
            ResponseBodyInner::Http2(body) => formatter.debug_tuple("Http2").field(body).finish(),
            ResponseBodyInner::Http3(body) => formatter.debug_tuple("Http3").field(body).finish(),
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
        match &mut self.get_mut().inner {
            ResponseBodyInner::Http1(body) => Pin::new(body)
                .poll_frame(context)
                .map(|frame| frame.map(|result| result.map_err(RequestError::http1_body))),
            ResponseBodyInner::Http2(body) => Pin::new(body)
                .poll_frame(context)
                .map(|frame| frame.map(|result| result.map_err(RequestError::http2_body))),
            ResponseBodyInner::Http3(body) => Pin::new(body)
                .poll_frame(context)
                .map(|frame| frame.map(|result| result.map_err(RequestError::http3_body))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.inner {
            ResponseBodyInner::Http1(body) => body.is_end_stream(),
            ResponseBodyInner::Http2(body) => body.is_end_stream(),
            ResponseBodyInner::Http3(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.inner {
            ResponseBodyInner::Http1(body) => body.size_hint(),
            ResponseBodyInner::Http2(body) => body.size_hint(),
            ResponseBodyInner::Http3(body) => body.size_hint(),
        }
    }
}
