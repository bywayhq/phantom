use std::{
    fmt,
    future::poll_fn,
    pin::Pin,
    task::{Context, Poll},
};

use crate::{
    HttpProtocol, RequestError,
    content_coding::{ContentDecoder, Pump},
    timeout::{ResponseTimeouts, TimeoutBudget},
};
use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use http_body::{Body, Frame, SizeHint};
use phantom_net::{http1::Http1Body, http2::Http2Body, http3::Http3Body};

/// Streaming response body returned by the public client.
///
/// `ResponseBody` implements [`http_body::Body`] with [`RequestError`] as its
/// error. Read it frame by frame, or use [`Self::collect_with_limit`] for a
/// bounded buffer. Dropping an incomplete body preserves the selected
/// protocol's cancellation behavior and bounded driver teardown.
///
/// # Frame errors
///
/// A frame error is a [`RequestError`] with kind:
///
/// - [`Timeout`](crate::RequestErrorKind::Timeout) when the request's
///   [`read_idle`](crate::RequestTimeouts::read_idle) or
///   [`total`](crate::RequestTimeouts::total) limit elapses;
/// - [`ContentDecoding`](crate::RequestErrorKind::ContentDecoding) or
///   [`ResponseBodyLimit`](crate::RequestErrorKind::ResponseBodyLimit) when
///   content decoding is enabled and the coded data is rejected or exceeds
///   its decoded-byte cap;
/// - [`Http1`](crate::RequestErrorKind::Http1),
///   [`Http2`](crate::RequestErrorKind::Http2), or
///   [`Http3`](crate::RequestErrorKind::Http3) when the transport fails;
/// - [`RequestBody`](crate::RequestErrorKind::RequestBody) when a request
///   body still uploading after an early response head fails; or
/// - [`RuntimeUnavailable`](crate::RequestErrorKind::RuntimeUnavailable) or
///   [`InvalidTimeout`](crate::RequestErrorKind::InvalidTimeout) when a
///   configured timeout cannot be armed.
///
/// # Examples
///
/// ```no_run
/// use http_body_util::BodyExt;
/// use phantom::{Client, HttpProtocol, RequestError};
///
/// async fn count_bytes(client: &Client) -> Result<usize, RequestError> {
///     let response = client.get(HttpProtocol::Http2, "https://example.com/")?.send().await?;
///     let mut body = response.into_body();
///     let mut received = 0;
///     while let Some(frame) = body.frame().await {
///         if let Ok(data) = frame?.into_data() {
///             received += data.len();
///         }
///     }
///     Ok(received)
/// }
/// ```
#[must_use = "response bodies must be read or deliberately dropped"]
pub struct ResponseBody {
    inner: Option<ResponseBodyInner>,
    timeouts: Option<ResponseTimeouts>,
    content: Option<ContentState>,
    held_trailers: Option<HeaderMap>,
}

/// Opt-in content decoding applied above the wire body.
enum ContentState {
    Decode(Box<ContentDecoder>),
    /// The coding chain was rejected; the first poll reports it.
    Reject(RequestError),
}

enum ResponseBodyInner {
    Http1(Http1Body),
    Http2(Http2Body),
    Http3(Http3Body),
}

impl ResponseBody {
    /// Collects this response body while enforcing an inclusive byte limit.
    ///
    /// Trailers are consumed and discarded. If the data exceeds
    /// `maximum_bytes`, the body is dropped immediately so the selected
    /// protocol can cancel the incomplete stream. With content decoding,
    /// `maximum_bytes` counts decoded bytes.
    ///
    /// # Errors
    ///
    /// Returns a [`RequestError`] with kind
    /// [`ResponseBodyLimit`](crate::RequestErrorKind::ResponseBodyLimit) when
    /// the data exceeds `maximum_bytes`, or any frame error listed on
    /// [`ResponseBody`].
    pub async fn collect_with_limit(mut self, maximum_bytes: usize) -> Result<Bytes, RequestError> {
        let mut collected = BytesMut::new();
        let mut length = 0usize;

        while let Some(frame) = poll_fn(|context| Pin::new(&mut self).poll_frame(context)).await {
            let frame = frame?;
            let Ok(data) = frame.into_data() else {
                continue;
            };
            length = match checked_body_length(length, data.len(), maximum_bytes) {
                Ok(length) => length,
                Err(error) => {
                    self.close();
                    return Err(error);
                }
            };
            collected.extend_from_slice(&data);
        }

        Ok(collected.freeze())
    }

    pub(crate) fn http1(body: Http1Body) -> Self {
        Self {
            inner: Some(ResponseBodyInner::Http1(body)),
            timeouts: None,
            content: None,
            held_trailers: None,
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
            content: None,
            held_trailers: None,
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
            content: None,
            held_trailers: None,
        }
    }

    pub(crate) fn http3_with_guard<T>(mut body: Http3Body, guard: T) -> Self
    where
        T: Send + 'static,
    {
        body.retain_until_stream_cleanup(guard);
        Self::http3(body)
    }

    /// Decodes the remaining wire body through `decoder`.
    pub(crate) fn decode_content(&mut self, decoder: ContentDecoder) {
        self.content = Some(ContentState::Decode(Box::new(decoder)));
    }

    /// Fails the first body poll with `error` and cancels the wire body.
    pub(crate) fn reject_content(&mut self, error: RequestError) {
        self.content = Some(ContentState::Reject(error));
    }

    /// Drops the wire body so the selected protocol cancels an incomplete stream.
    fn close(&mut self) {
        self.inner.take();
        self.timeouts.take();
        self.content.take();
        self.held_trailers.take();
    }

    fn poll_decoded_frame(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, RequestError>>> {
        loop {
            let Some(ContentState::Decode(decoder)) = self.content.as_mut() else {
                return Poll::Ready(None);
            };
            match decoder.pump() {
                Err(error) => {
                    self.close();
                    return Poll::Ready(Some(Err(error)));
                }
                Ok(Pump::Data(data)) => {
                    // Decoded output counts as body activity, and buffered
                    // high-ratio input must not outrun the total deadline.
                    if let Some(timeouts) = self.timeouts.as_mut() {
                        let expired = match timeouts.record_activity() {
                            Err(error) => Some(error),
                            Ok(()) => match timeouts.poll_expired(context) {
                                Poll::Ready(error) => Some(error),
                                Poll::Pending => None,
                            },
                        };
                        if let Some(error) = expired {
                            self.close();
                            return Poll::Ready(Some(Err(error)));
                        }
                    }
                    return Poll::Ready(Some(Ok(Frame::data(data))));
                }
                Ok(Pump::Finished) => {
                    let trailers = self.held_trailers.take();
                    self.close();
                    return Poll::Ready(trailers.map(|trailers| Ok(Frame::trailers(trailers))));
                }
                Ok(Pump::NeedInput) => {}
            }

            let protocol = self.protocol();
            let frame = match self.poll_wire_frame(context) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(error))) => {
                    self.close();
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(frame) => frame,
            };
            let Some(ContentState::Decode(decoder)) = self.content.as_mut() else {
                return Poll::Ready(None);
            };
            match frame {
                None => decoder.end_input(),
                Some(Ok(frame)) => match frame.into_data() {
                    Ok(_) if self.held_trailers.is_some() => {
                        self.close();
                        return Poll::Ready(Some(Err(RequestError::content_decoding(
                            protocol,
                            "response body produced data after its trailers",
                            None,
                        ))));
                    }
                    Ok(data) => decoder.push(data),
                    Err(frame) => {
                        if let Ok(trailers) = frame.into_trailers() {
                            self.held_trailers = Some(trailers);
                        }
                    }
                },
                Some(Err(error)) => {
                    self.close();
                    return Poll::Ready(Some(Err(error)));
                }
            }
        }
    }

    const fn protocol(&self) -> HttpProtocol {
        match self.inner {
            Some(ResponseBodyInner::Http2(_)) => HttpProtocol::Http2,
            Some(ResponseBodyInner::Http3(_)) => HttpProtocol::Http3,
            Some(ResponseBodyInner::Http1(_)) | None => HttpProtocol::Http1,
        }
    }

    fn poll_wire_frame(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, RequestError>>> {
        let result = match self.inner.as_mut() {
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
                if let Some(timeouts) = self.timeouts.as_mut()
                    && let Err(error) = timeouts.record_activity()
                {
                    self.inner.take();
                    self.timeouts.take();
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(frame) => {
                // Decoding keeps its deadlines until buffered input is drained.
                if self.content.is_none()
                    && (frame.is_none() || frame.as_ref().is_some_and(Result::is_err))
                {
                    self.timeouts.take();
                }
                Poll::Ready(frame)
            }
            Poll::Pending => {
                if let Some(timeouts) = self.timeouts.as_mut()
                    && let Poll::Ready(error) = timeouts.poll_expired(context)
                {
                    tracing::debug!(
                        timeout_phase = error.timeout_phase().map(crate::TimeoutPhase::trace_name),
                        "response body timed out"
                    );
                    self.inner.take();
                    self.timeouts.take();
                    return Poll::Ready(Some(Err(error)));
                }
                Poll::Pending
            }
        }
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

fn checked_body_length(
    current: usize,
    additional: usize,
    maximum: usize,
) -> Result<usize, RequestError> {
    current
        .checked_add(additional)
        .filter(|length| *length <= maximum)
        .ok_or_else(RequestError::response_body_limit)
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
        match this.content.take() {
            None => this.poll_wire_frame(context),
            Some(ContentState::Reject(error)) => {
                this.close();
                Poll::Ready(Some(Err(error)))
            }
            Some(state @ ContentState::Decode(_)) => {
                this.content = Some(state);
                this.poll_decoded_frame(context)
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        if self.content.is_some() {
            return false;
        }
        match &self.inner {
            Some(ResponseBodyInner::Http1(body)) => body.is_end_stream(),
            Some(ResponseBodyInner::Http2(body)) => body.is_end_stream(),
            Some(ResponseBodyInner::Http3(body)) => body.is_end_stream(),
            None => true,
        }
    }

    fn size_hint(&self) -> SizeHint {
        if self.content.is_some() {
            return SizeHint::default();
        }
        match &self.inner {
            Some(ResponseBodyInner::Http1(body)) => body.size_hint(),
            Some(ResponseBodyInner::Http2(body)) => body.size_hint(),
            Some(ResponseBodyInner::Http3(body)) => body.size_hint(),
            None => SizeHint::with_exact(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::checked_body_length;
    use crate::RequestErrorKind;

    #[test]
    fn collection_limit_is_inclusive() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(checked_body_length(3, 2, 5)?, 5);
        Ok(())
    }

    #[test]
    fn collection_limit_rejects_excess_and_arithmetic_overflow() {
        let Err(excess) = checked_body_length(3, 3, 5) else {
            panic!("excess length was accepted");
        };
        assert_eq!(excess.kind(), RequestErrorKind::ResponseBodyLimit);

        let Err(overflow) = checked_body_length(usize::MAX, 1, usize::MAX) else {
            panic!("overflowing length was accepted");
        };
        assert_eq!(overflow.kind(), RequestErrorKind::ResponseBodyLimit);
    }
}
