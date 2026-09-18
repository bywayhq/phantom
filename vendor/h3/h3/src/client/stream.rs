use bytes::{Buf, Bytes};
use futures_util::{future, ready};
use http::{HeaderMap, Response};
use quic::StreamId;
#[cfg(feature = "tracing")]
use tracing::instrument;

use super::outbound_qpack;
use crate::{
    connection::{self},
    error::{
        connection_error_creators::{CloseStream, HandleFrameStreamErrorOnRequestStream},
        internal_error::InternalConnectionError,
        Code, StreamError,
    },
    ext::OrderedHeaders,
    proto::{frame::Frame, headers::Header},
    qpack,
    quic::{self},
    shared_state::{ConnectionState, SharedState},
};
use std::{
    convert::TryFrom,
    task::{Context, Poll},
};

/// Manage request bodies transfer, response and trailers.
///
/// Once a request has been sent via [`crate::client::SendRequest::send_request()`], a response can be awaited by calling
/// [`RequestStream::recv_response()`]. A body for this request can be sent with [`RequestStream::send_data()`], then the request
/// shall be completed by either sending trailers with  [`RequestStream::finish()`].
///
/// After receiving the response's headers, it's body can be read by [`RequestStream::recv_data()`] until it returns
/// `None`. Then the trailers will eventually be available via [`RequestStream::recv_trailers()`].
///
/// TODO: If data is polled before the response has been received, an error will be thrown.
///
/// TODO: If trailers are polled but the body hasn't been fully received, an UNEXPECT_FRAME error will be
/// thrown
///
/// Whenever the client wants to cancel this request, it can call [`RequestStream::stop_sending()`], which will
/// put an end to any transfer concerning it.
///
/// # Examples
///
/// ```rust
/// # use h3::{quic, client::*};
/// # use http::{Request, Response};
/// # use bytes::Buf;
/// # use tokio::io::AsyncWriteExt;
/// # async fn doc<T,B>(mut req_stream: RequestStream<T, B>) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     T: quic::RecvStream,
/// # {
/// // Prepare the HTTP request to send to the server
/// let request = Request::get("https://www.example.com/").body(())?;
///
/// // Receive the response
/// let response = req_stream.recv_response().await?;
/// // Receive the body
/// while let Some(mut chunk) = req_stream.recv_data().await? {
///     let mut out = tokio::io::stdout();
///     out.write_all_buf(&mut chunk).await?;
///     out.flush().await?;
/// }
/// # Ok(())
/// # }
/// # pub fn main() {}
/// ```
///
/// [`send_request()`]: struct.SendRequest.html#method.send_request
/// [`recv_response()`]: #method.recv_response
/// [`recv_data()`]: #method.recv_data
/// [`send_data()`]: #method.send_data
/// [`send_trailers()`]: #method.send_trailers
/// [`recv_trailers()`]: #method.recv_trailers
/// [`finish()`]: #method.finish
/// [`stop_sending()`]: #method.stop_sending
pub struct RequestStream<S, B> {
    pub(super) inner: connection::RequestStream<S, B>,
    pub(super) response_headers: Option<Bytes>,
    pub(super) outbound_qpack: Option<outbound_qpack::Sender>,
}

impl<S, B> ConnectionState for RequestStream<S, B> {
    fn shared_state(&self) -> &SharedState {
        &self.inner.conn_state
    }
}

impl<S, B> CloseStream for RequestStream<S, B> {}

impl<S, B> RequestStream<S, B>
where
    S: quic::RecvStream,
{
    /// Receive the HTTP/3 response
    ///
    /// This should be called before trying to receive any data with [`recv_data()`].
    ///
    /// [`recv_data()`]: #method.recv_data
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_response(&mut self) -> Result<Response<()>, StreamError> {
        future::poll_fn(|cx| self.poll_recv_response(cx)).await
    }

    fn poll_recv_response(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Response<()>, StreamError>> {
        if self.response_headers.is_none() {
            let frame = match ready!(self.inner.stream.poll_next(cx)) {
                Ok(Some(frame)) => frame,
                Ok(None) => {
                    return Poll::Ready(Err(self.handle_connection_error_on_stream(
                        InternalConnectionError::new(
                            Code::H3_FRAME_UNEXPECTED,
                            "Stream finished without receiving response headers".to_string(),
                        ),
                    )));
                }
                Err(error) => {
                    self.inner.stream.cancel_request();
                    return Poll::Ready(Err(
                        self.handle_frame_stream_error_on_request_stream(error)
                    ));
                }
            };

            let Frame::Headers(encoded) = frame else {
                return Poll::Ready(Err(self.handle_connection_error_on_stream(
                    InternalConnectionError::new(
                        Code::H3_FRAME_UNEXPECTED,
                        "First response frame is not headers".to_string(),
                    ),
                )));
            };
            self.response_headers = Some(encoded);
        }

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        //= type=TODO
        //# A client MUST treat
        //# receipt of a PUSH_PROMISE frame that contains a larger push ID than
        //# the client has advertised as a connection error of H3_ID_ERROR.

        //= https://www.rfc-editor.org/rfc/rfc9114#section-7.2.5
        //= type=TODO
        //# If a client
        //# receives a push ID that has already been promised and detects a
        //# mismatch, it MUST respond with a connection error of type
        //# H3_GENERAL_PROTOCOL_ERROR.

        let encoded = self.response_headers.as_ref().unwrap().clone();
        let decoded = match ready!(self.inner.poll_decode_header_section(&encoded, cx)) {
            Ok(decoded) => decoded,
            Err(error @ StreamError::HeaderTooBig { .. }) => {
                self.response_headers = None;
                self.inner.stop_sending(Code::H3_REQUEST_CANCELLED);
                return Poll::Ready(Err(error));
            }
            Err(error) => {
                self.response_headers = None;
                return Poll::Ready(Err(error));
            }
        };
        self.response_headers = None;

        let qpack::Decoded { fields, .. } = decoded;

        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
        //# Malformed requests or responses that are
        //# detected MUST be treated as a stream error of type H3_MESSAGE_ERROR.
        //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.2
        //# Clients MUST NOT
        //# accept a malformed response.
        let (status, headers, ordered_headers) = match Header::try_from(fields)
            .map_err(|_e| {
                self.inner.stop_sending(Code::H3_REQUEST_CANCELLED);
                StreamError::StreamError {
                    code: Code::H3_MESSAGE_ERROR,
                    reason: "Received malformed header".to_string(),
                }
            })
            .and_then(|header| {
                header.into_response_parts().map_err(|_e| {
                    self.inner.stop_sending(Code::H3_REQUEST_CANCELLED);
                    StreamError::StreamError {
                        code: Code::H3_MESSAGE_ERROR,
                        reason: "Received malformed header".to_string(),
                    }
                })
            }) {
            Ok(parts) => parts,
            Err(error) => return Poll::Ready(Err(error)),
        };
        let mut resp = Response::new(());
        *resp.status_mut() = status;
        *resp.headers_mut() = headers;
        *resp.version_mut() = http::Version::HTTP_3;
        if let Some(ordered_headers) = ordered_headers {
            resp.extensions_mut().insert(ordered_headers);
        }

        Poll::Ready(Ok(resp))
    }

    /// Receive some of the response body.
    ///
    /// This returns a chunk of the response body, or `None` if the response body is finished.
    // TODO what if called before recv_response ?
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_data(&mut self) -> Result<Option<impl Buf>, StreamError> {
        future::poll_fn(|cx| self.poll_recv_data(cx)).await
    }

    /// Receive some of the response body.
    ///
    /// This returns a chunk of the response body, or `None` if the response body is finished.
    pub fn poll_recv_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<impl Buf>, StreamError>> {
        self.inner.poll_recv_data(cx)
    }

    /// Receive an optional set of trailers for the response.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn recv_trailers(&mut self) -> Result<Option<HeaderMap>, StreamError> {
        future::poll_fn(|cx| self.poll_recv_trailers(cx)).await
    }

    /// Poll receive an optional set of trailers for the response.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn poll_recv_trailers(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<HeaderMap>, StreamError>> {
        let res = self.inner.poll_recv_trailers(cx);
        if let Poll::Ready(Err(StreamError::HeaderTooBig { .. })) = &res {
            self.inner.stream.stop_sending(Code::H3_REQUEST_CANCELLED);
        }
        res
    }

    /// Tell the peer to stop sending into the underlying QUIC stream
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub fn stop_sending(&mut self, error_code: Code) {
        // TODO take by value to prevent any further call as this request is cancelled
        // rename `cancel()` ?
        self.inner.stop_sending(error_code)
    }

    /// Returns the underlying stream id
    pub fn id(&self) -> StreamId {
        self.inner.stream.id()
    }
}

impl<S, B> RequestStream<S, B>
where
    S: quic::SendStream<B>,
    B: Buf,
{
    /// Send some data on the request body.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_data(&mut self, buf: B) -> Result<(), StreamError> {
        self.inner.send_data(buf).await
    }

    /// Stop a stream with an error code
    ///
    /// The code can be [`Code::H3_NO_ERROR`].
    pub fn stop_stream(&mut self, error_code: Code) {
        self.inner.stop_stream(error_code);
    }

    /// Send a set of trailers to end the request.
    ///
    /// [`RequestStream::finish()`] must be called to finalize a request.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<(), StreamError> {
        self.inner.send_trailers(trailers).await
    }

    /// Send trailers with an exact ordinary-field order.
    ///
    /// Dynamic QPACK uses the connection-owned encoder state also used by the
    /// initial request field section. [`RequestStream::finish()`] must still be
    /// called to finalize the request.
    pub async fn send_ordered_trailers(
        &mut self,
        trailers: HeaderMap,
        ordered: OrderedHeaders,
    ) -> Result<(), StreamError> {
        let headers = Header::ordered_trailer(trailers, ordered)
            .map_err(|error| StreamError::InvalidRequest(error.to_string()))?;

        if let Some(mut outbound) = self.outbound_qpack.clone() {
            let fields = headers.into_iter().collect::<Vec<_>>();
            let mem_size = fields.iter().try_fold(0_u64, |size, field| {
                u64::try_from(field.mem_size())
                    .ok()
                    .and_then(|field_size| size.checked_add(field_size))
            });
            let Some(mem_size) = mem_size else {
                return Err(StreamError::InvalidRequest(
                    "trailer field-section size is not representable".to_string(),
                ));
            };

            outbound
                .wait_ready()
                .await
                .map_err(|_| self.outbound_qpack_closed())?;
            if let Some(error) = self.check_peer_connection_closing() {
                return Err(error);
            }
            let max_size = self.settings().max_field_section_size;
            if mem_size > max_size {
                return Err(StreamError::HeaderTooBig {
                    actual_size: mem_size,
                    max_size,
                });
            }

            let permit = outbound
                .reserve()
                .await
                .map_err(|_| self.outbound_qpack_closed())?;
            if let Some(error) = self.check_peer_connection_closing() {
                return Err(error);
            }
            let stream_id = quic::SendStream::send_id(&self.inner.stream).into_inner();
            let (command, encoded) = outbound_qpack::EncodeCommand::new(stream_id, fields);
            let _ = permit.send(command);
            let encoded = encoded
                .await
                .map_err(|_| self.outbound_qpack_closed())?
                .map_err(|error| self.map_outbound_qpack_error(error))?;
            let outbound_qpack::Encoded { block, publication } = encoded;
            self.inner.send_encoded_trailers(block).await?;
            publication.published();
            return Ok(());
        }

        let mut block = bytes::BytesMut::new();
        let mem_size = qpack::encode_stateless(&mut block, headers).map_err(|_| {
            self.handle_connection_error_on_stream(InternalConnectionError {
                code: Code::H3_INTERNAL_ERROR,
                message: "Failed to encode ordered trailers".to_string(),
            })
        })?;
        let max_size = self.settings().max_field_section_size;
        if mem_size > max_size {
            return Err(StreamError::HeaderTooBig {
                actual_size: mem_size,
                max_size,
            });
        }
        self.inner.send_encoded_trailers(block.freeze()).await
    }

    fn outbound_qpack_closed(&mut self) -> StreamError {
        self.existing_connection_error().unwrap_or_else(|| {
            self.handle_connection_error_on_stream(InternalConnectionError::new(
                Code::H3_INTERNAL_ERROR,
                "outbound QPACK driver stopped".to_string(),
            ))
        })
    }

    fn map_outbound_qpack_error(&mut self, error: outbound_qpack::EncodeError) -> StreamError {
        let message = error.to_string();
        match error {
            outbound_qpack::EncodeError::InstructionsTooLarge { .. } => {
                StreamError::InvalidRequest(message)
            }
            outbound_qpack::EncodeError::Codec(_) => {
                self.handle_connection_error_on_stream(InternalConnectionError::new(
                    Code::H3_INTERNAL_ERROR,
                    format!("failed to encode trailer fields with QPACK: {message}"),
                ))
            }
        }
    }

    /// End the request without trailers.
    ///
    /// [`RequestStream::finish()`] must be called to finalize a request.
    #[cfg_attr(feature = "tracing", instrument(skip_all, level = "trace"))]
    pub async fn finish(&mut self) -> Result<(), StreamError> {
        self.inner.finish().await
    }

    //= https://www.rfc-editor.org/rfc/rfc9114#section-4.1.1
    //= type=TODO
    //# Implementations SHOULD cancel requests by abruptly terminating any
    //# directions of a stream that are still open.  To do so, an
    //# implementation resets the sending parts of streams and aborts reading
    //# on the receiving parts of streams; see Section 2.4 of
    //# [QUIC-TRANSPORT].
}

impl<S, B> RequestStream<S, B>
where
    S: quic::BidiStream<B>,
    B: Buf,
{
    /// Split this stream into two halves that can be driven independently.
    pub fn split(
        self,
    ) -> (
        RequestStream<S::SendStream, B>,
        RequestStream<S::RecvStream, B>,
    ) {
        let (send, recv) = self.inner.split();
        (
            RequestStream {
                inner: send,
                response_headers: None,
                outbound_qpack: self.outbound_qpack,
            },
            RequestStream {
                inner: recv,
                response_headers: self.response_headers,
                outbound_qpack: None,
            },
        )
    }
}
