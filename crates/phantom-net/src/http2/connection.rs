//! Reusable HTTP/2 connection ownership.

use std::{
    fmt,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use ::http2::{Reason, SendStream, client};
use bytes::Bytes;
use http::{Method, Request, Response};
use phantom_profile::Http2Settings;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, debug, debug_span, field};

use crate::accept_ch::AcceptCh;
use crate::request::{RequestBody, RequestBodyMetadata};

use super::{
    Http2Body, Http2Error, OperationOutcome, OriginForm, RequestHeader, driver::DriverTask,
    prepare_request, translate_settings, upload::send_body,
};

/// An established HTTP/2 connection that can open concurrent request streams.
///
/// Clones share one connection. Dropping the last clone starts bounded driver
/// shutdown after every outstanding response body releases its stream lease.
#[derive(Clone)]
pub struct Http2Connection {
    inner: Arc<ConnectionInner>,
}

impl Http2Connection {
    /// Establishes HTTP/2 over an already-connected byte stream.
    ///
    /// The settings are validated before the stream is touched.
    ///
    /// # Errors
    ///
    /// Returns [`Http2Error`] when settings validation or the HTTP/2 handshake
    /// fails.
    pub async fn connect<T>(stream: T, settings: &Http2Settings) -> Result<Self, Http2Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        settings.validate().map_err(Http2Error::InvalidSettings)?;
        let client = translate_settings(settings)?;
        Self::connect_with_builder(stream, client).await
    }

    /// Sends one empty-body GET on this connection.
    ///
    /// The authority, target, and complete ordered header list are validated
    /// before this method touches the connection. Ordinary header order and
    /// duplicate positions are emitted exactly as supplied.
    ///
    /// # Errors
    ///
    /// Returns [`Http2Error`] when request validation or stream processing
    /// fails.
    pub async fn send_get(
        &self,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http2Body>, Http2Error> {
        self.send_request(Method::GET, authority, target, headers, None)
            .await
    }

    /// Sends one request on this connection.
    ///
    /// The complete request is validated before this method touches the
    /// connection. `None` ends the request on HEADERS. `Some` sends an owned,
    /// flow-controlled DATA sequence, including an empty terminal DATA frame
    /// when the value is empty.
    ///
    /// # Errors
    ///
    /// Returns [`Http2Error`] when request validation, upload, or response
    /// processing fails.
    pub async fn send_request(
        &self,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http2Body>, Http2Error> {
        self.send_request_body(
            method,
            authority,
            target,
            headers,
            body.map(RequestBody::from_bytes),
        )
        .await
    }

    /// Sends one request with a pull-driven body on this connection.
    ///
    /// The body's initial exact size hint controls `Content-Length`
    /// validation. Unknown-length bodies omit an automatic length and reject a
    /// caller-supplied one. Request trailers fail explicitly.
    ///
    /// # Errors
    ///
    /// Returns [`Http2Error`] when request validation, body production,
    /// upload, or response processing fails.
    pub async fn send_request_body(
        &self,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<RequestBody>,
    ) -> Result<Response<Http2Body>, Http2Error> {
        let metadata = body.as_ref().map(RequestBody::metadata);
        let request = prepare_request(method, authority, target, headers, metadata)?;
        self.send_prepared_request(request, body).await
    }

    /// Returns whether the connection driver has stopped.
    ///
    /// A connection may become closed between this observation and a later
    /// request. Callers must still handle request errors.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.driver.is_finished()
    }

    /// Returns whether this connection is currently eligible for another stream.
    ///
    /// This snapshot observes connection errors such as a received GOAWAY but
    /// does not reserve capacity. A later send can still fail.
    #[must_use]
    pub fn is_reusable(&self) -> bool {
        if self.is_closed() {
            return false;
        }
        let Some(sender) = self.inner.sender() else {
            return false;
        };
        let mut sender = sender.clone();
        let mut context = Context::from_waker(Waker::noop());
        matches!(sender.poll_ready(&mut context), Poll::Ready(Ok(())))
    }

    /// Returns the raw `Accept-CH` field value carried through ALPS for `origin`.
    ///
    /// `origin` must use the canonical ASCII origin serialization. The value is
    /// immutable connection metadata and is not persisted across connections.
    #[must_use]
    pub fn accept_ch_for_origin(&self, origin: &str) -> Option<&[u8]> {
        self.inner.accept_ch.for_origin(origin)
    }

    pub(super) async fn connect_with_builder<T>(
        stream: T,
        client: client::Builder,
    ) -> Result<Self, Http2Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::connect_with_builder_and_accept_ch(stream, client, AcceptCh::default()).await
    }

    pub(super) async fn connect_with_builder_and_accept_ch<T>(
        stream: T,
        client: client::Builder,
        accept_ch: AcceptCh,
    ) -> Result<Self, Http2Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (sender, connection) = client
            .handshake(stream)
            .await
            .map_err(Http2Error::protocol)?;
        let driver = DriverTask::spawn(connection);
        Ok(Self {
            inner: Arc::new(ConnectionInner {
                sender: Some(sender),
                driver,
                accept_ch,
            }),
        })
    }

    pub(super) async fn send_prepared_request(
        &self,
        request: Request<()>,
        body: Option<RequestBody>,
    ) -> Result<Response<Http2Body>, Http2Error> {
        let method = request.method().clone();
        let body_bytes = body
            .as_ref()
            .map(RequestBody::metadata)
            .and_then(RequestBodyMetadata::exact_length);
        let span = debug_span!(
            "http2.response_head",
            method = %method,
            protocol = "h2",
            body_bytes = field::debug(body_bytes),
            status = field::Empty,
            outcome = field::Empty,
        );
        let outcome = OperationOutcome::new(&span);
        let result = async {
            debug!("HTTP/2 stream started");
            let mut sender = self
                .inner
                .sender()
                .ok_or_else(connection_closed)
                .map_err(Http2Error::protocol)?
                .clone()
                .ready()
                .await
                .map_err(Http2Error::protocol)?;
            let end_of_stream = body.is_none();
            let (response, reset) = sender
                .send_request(request, end_of_stream)
                .map_err(Http2Error::protocol)?;
            let mut response = Box::pin(response);
            let mut early_response = None;
            let reset = if let Some(body) = body {
                let mut upload = RequestStreamGuard::new(reset);
                {
                    let mut upload_future = Box::pin(send_body(upload.stream_mut()?, body));
                    tokio::select! {
                        biased;
                        result = &mut response => {
                            early_response = Some(result.map_err(Http2Error::protocol)?);
                        }
                        result = &mut upload_future => result?,
                    }
                }
                upload.disarm()?
            } else {
                reset
            };
            let response = match early_response {
                Some(response) => response,
                None => response.await.map_err(Http2Error::protocol)?,
            };

            span.record("status", response.status().as_u16());
            debug!("HTTP/2 response headers received");
            let (mut parts, incoming) = response.into_parts();
            let ordered_headers = parts
                .extensions
                .remove::<::http2::ext::OrderedHeaders>()
                .map(|headers| {
                    crate::OrderedResponseHeaders::from_normalized_fields(headers.as_slice())
                })
                .ok_or(Http2Error::MissingResponseHeaderOrder)?;
            parts.extensions.insert(ordered_headers);
            Ok(Response::from_parts(
                parts,
                Http2Body::new(incoming, reset, self.lease()),
            ))
        }
        .instrument(span.clone())
        .await;
        let terminal_outcome = match &result {
            Ok(_) => "ok",
            Err(Http2Error::Protocol(_)) => "protocol_error",
            Err(_) => "request_error",
        };
        outcome.finish(terminal_outcome);
        result
    }

    fn lease(&self) -> ConnectionLease {
        ConnectionLease {
            _inner: Arc::clone(&self.inner),
        }
    }
}

struct RequestStreamGuard {
    stream: Option<SendStream<Bytes>>,
}

impl RequestStreamGuard {
    fn new(stream: SendStream<Bytes>) -> Self {
        Self {
            stream: Some(stream),
        }
    }

    fn stream_mut(&mut self) -> Result<&mut SendStream<Bytes>, Http2Error> {
        self.stream.as_mut().ok_or(Http2Error::RequestBodyClosed)
    }

    fn disarm(mut self) -> Result<SendStream<Bytes>, Http2Error> {
        self.stream.take().ok_or(Http2Error::RequestBodyClosed)
    }
}

impl Drop for RequestStreamGuard {
    fn drop(&mut self) {
        if let Some(stream) = self.stream.as_mut() {
            stream.send_reset(Reason::CANCEL);
        }
    }
}

impl fmt::Debug for Http2Connection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http2Connection")
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

pub(super) struct ConnectionLease {
    _inner: Arc<ConnectionInner>,
}

struct ConnectionInner {
    // Option lets Drop close the final sender before supervising the driver.
    sender: Option<client::SendRequest<Bytes>>,
    driver: DriverTask,
    accept_ch: AcceptCh,
}

impl ConnectionInner {
    fn sender(&self) -> Option<&client::SendRequest<Bytes>> {
        self.sender.as_ref()
    }
}

impl Drop for ConnectionInner {
    fn drop(&mut self) {
        self.sender.take();
        self.driver.shutdown();
    }
}

fn connection_closed() -> ::http2::Error {
    ::http2::Error::from(::http2::Reason::INTERNAL_ERROR)
}
