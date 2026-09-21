//! Reusable HTTP/2 connection ownership.

use std::{
    fmt,
    future::Future,
    pin::Pin,
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
    Http2Body, Http2Error, Http2ExtendedConnectOutcome, Http2ExtendedConnectStream,
    OperationOutcome, OriginForm, RequestHeader,
    driver::DriverTask,
    prepare_extended_connect, prepare_request,
    request::PreparedRequestTrailers,
    translate_extended_connect_settings, translate_settings,
    tunnel::{Http2ClassicConnectOutcome, Http2ConnectStream},
    upload::send_body,
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

    /// Establishes HTTP/2 for exact extended CONNECT requests.
    ///
    /// This requires a separately configured five-field pseudo-header order.
    /// Ordinary pooled connections cannot be silently reused because their
    /// connection-wide encoder order omits `:protocol`.
    ///
    /// # Errors
    ///
    /// Returns [`Http2Error`] when the profile has no verified extended
    /// CONNECT order, settings validation fails, or the handshake fails.
    pub async fn connect_extended<T>(
        stream: T,
        settings: &Http2Settings,
    ) -> Result<Self, Http2Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        settings.validate().map_err(Http2Error::InvalidSettings)?;
        let client = translate_extended_connect_settings(settings)?;
        Self::connect_with_builder_kind(stream, client, true).await
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
        self.send_request_with_trailers(method, authority, target, headers, body, Vec::new())
            .await
    }

    /// Sends one owned request body followed by exact ordered static trailers.
    ///
    /// Trailer validation completes before the connection is touched. Trailer
    /// fields do not contribute to `Content-Length`, which describes DATA only.
    ///
    /// # Errors
    ///
    /// Returns [`Http2Error`] when request or trailer validation, upload, or
    /// response processing fails.
    pub async fn send_request_with_trailers(
        &self,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
        trailers: Vec<RequestHeader>,
    ) -> Result<Response<Http2Body>, Http2Error> {
        self.send_request_body_with_trailers(
            method,
            authority,
            target,
            headers,
            body.map(RequestBody::from_bytes),
            trailers,
        )
        .await
    }

    /// Sends one request with a pull-driven body on this connection.
    ///
    /// The body's initial exact size hint controls `Content-Length`
    /// validation. Unknown-length bodies omit an automatic length and reject a
    /// caller-supplied one. Body-produced trailers require a declared ordered
    /// name plan on [`RequestBody`].
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
        self.send_request_body_with_trailers(method, authority, target, headers, body, Vec::new())
            .await
    }

    /// Sends one pull-driven request body followed by exact ordered trailers.
    ///
    /// Static trailers or the body's declared trailer-name plan are validated
    /// before the connection or body is touched. They cannot be combined.
    ///
    /// # Errors
    ///
    /// Returns [`Http2Error`] when request or trailer validation, body
    /// production, upload, or response processing fails.
    pub async fn send_request_body_with_trailers(
        &self,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<RequestBody>,
        trailers: Vec<RequestHeader>,
    ) -> Result<Response<Http2Body>, Http2Error> {
        PreparedRequestTrailers::validate_body_plan(body.as_ref(), &trailers)?;
        let metadata = body.as_ref().map(RequestBody::metadata);
        let request = prepare_request(method, authority, target, headers, metadata)?;
        let trailers = PreparedRequestTrailers::new(trailers)?;
        self.send_prepared_request(request, body, trailers).await
    }

    /// Opens a WebSocket extended CONNECT stream without protocol fallback.
    ///
    /// The request is validated before the connection is touched. This waits
    /// for the peer's initial settings and does not send request HEADERS unless
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` was enabled.
    ///
    /// # Errors
    ///
    /// Returns [`Http2Error`] for invalid request fields, a connection not
    /// created with [`Self::connect_extended`], absent peer capability, or a
    /// protocol-driver failure.
    pub async fn send_extended_connect(
        &self,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http2ExtendedConnectOutcome, Http2Error> {
        let request = prepare_extended_connect(authority, target, headers)?;
        self.send_prepared_extended_connect(request).await
    }

    /// Sends one prepared RFC 9298 CONNECT-UDP extended CONNECT request.
    ///
    /// Like [`Self::send_extended_connect`], HEADERS are sent only after the
    /// peer's SETTINGS enable extended CONNECT (RFC 8441 section 3).
    pub(crate) async fn send_connect_udp(
        &self,
        request: Request<()>,
    ) -> Result<Http2ExtendedConnectOutcome, Http2Error> {
        self.send_prepared_extended_connect(request).await
    }

    async fn send_prepared_extended_connect(
        &self,
        request: Request<()>,
    ) -> Result<Http2ExtendedConnectOutcome, Http2Error> {
        if !self.inner.extended_connect {
            return Err(Http2Error::ExtendedConnectConnectionRequired);
        }

        let span = debug_span!(
            "http2.extended_connect.response_head",
            method = "CONNECT",
            protocol = "h2",
            status = field::Empty,
            outcome = field::Empty,
        );
        let outcome = OperationOutcome::new(&span);
        let result = async {
            let mut sender = self
                .inner
                .sender()
                .ok_or_else(connection_closed)
                .map_err(Http2Error::protocol)?
                .clone();
            if !sender
                .extended_connect_protocol_ready()
                .await
                .map_err(Http2Error::protocol)?
            {
                return Err(Http2Error::ExtendedConnectProtocolDisabled);
            }
            let mut sender = sender.ready().await.map_err(Http2Error::protocol)?;
            let (response, send) = sender
                .send_request(request, false)
                .map_err(Http2Error::protocol)?;
            let mut send = RequestStreamGuard::new(send);
            let response = match response.await {
                Ok(response) => response,
                Err(error) => {
                    // A failed response already ended the stream; an explicit
                    // reset would only queue a frame on a dead connection.
                    drop(send.disarm());
                    return Err(Http2Error::protocol(error));
                }
            };
            span.record("status", response.status().as_u16());

            let accepted = response.status().is_success();
            let (mut parts, incoming) = response.into_parts();
            let ordered_headers = parts
                .extensions
                .remove::<::http2::ext::OrderedHeaders>()
                .map(|headers| {
                    crate::OrderedResponseHeaders::from_normalized_fields(headers.as_slice())
                })
                .ok_or(Http2Error::MissingResponseHeaderOrder)?;
            parts.extensions.insert(ordered_headers);
            if let Some(frames) = parts.extensions.remove::<::http2::ext::AltSvcFrames>() {
                parts
                    .extensions
                    .insert(super::AltSvcFrames::from_http2(&frames));
            }

            if accepted {
                let stream =
                    Http2ExtendedConnectStream::new(incoming, send.disarm()?, self.lease());
                Ok(Http2ExtendedConnectOutcome::Accepted {
                    response: Response::from_parts(parts, ()),
                    stream,
                })
            } else {
                send.stream_mut()?
                    .send_data(Bytes::new(), true)
                    .map_err(Http2Error::protocol)?;
                Ok(Http2ExtendedConnectOutcome::Rejected(Response::from_parts(
                    parts,
                    Http2Body::new(incoming, send.disarm()?, self.lease()),
                )))
            }
        }
        .instrument(span.clone())
        .await;
        let terminal_outcome = match &result {
            Ok(Http2ExtendedConnectOutcome::Accepted { .. }) => "accepted",
            Ok(Http2ExtendedConnectOutcome::Rejected(_)) => "rejected",
            Err(Http2Error::Protocol(_)) => "protocol_error",
            Err(_) => "request_error",
        };
        outcome.finish(terminal_outcome);
        result
    }

    /// Sends one prepared RFC 9113 section 8.5 CONNECT request.
    ///
    /// A 2xx response yields the stream as a flow-controlled byte tunnel. Any
    /// other final status resets the stream and reports the status and fields.
    pub(crate) async fn send_classic_connect(
        &self,
        request: Request<()>,
    ) -> Result<Http2ClassicConnectOutcome, Http2Error> {
        let span = debug_span!(
            "http2.connect.response_head",
            method = "CONNECT",
            protocol = "h2",
            status = field::Empty,
            outcome = field::Empty,
        );
        let outcome = OperationOutcome::new(&span);
        let result = async {
            let mut sender = self
                .inner
                .sender()
                .ok_or_else(connection_closed)
                .map_err(Http2Error::protocol)?
                .clone()
                .ready()
                .await
                .map_err(Http2Error::protocol)?;
            let (response, send) = sender
                .send_request(request, false)
                .map_err(Http2Error::protocol)?;
            let send = RequestStreamGuard::new(send);
            let response = match response.await {
                Ok(response) => response,
                Err(error) => {
                    // A failed response already ended the stream; an explicit
                    // reset would only queue a frame on a dead connection.
                    drop(send.disarm());
                    return Err(Http2Error::protocol(error));
                }
            };
            let status = response.status();
            span.record("status", status.as_u16());
            let (parts, incoming) = response.into_parts();
            if status.is_success() {
                Ok(Http2ClassicConnectOutcome::Accepted {
                    status: status.as_u16(),
                    stream: Http2ConnectStream::new(incoming, send.disarm()?, self.lease()),
                })
            } else {
                // Dropping the guard resets the rejected stream with CANCEL.
                drop(send);
                drop(incoming);
                Ok(Http2ClassicConnectOutcome::Rejected {
                    status: status.as_u16(),
                    headers: parts.headers,
                })
            }
        }
        .instrument(span.clone())
        .await;
        let terminal_outcome = match &result {
            Ok(Http2ClassicConnectOutcome::Accepted { .. }) => "accepted",
            Ok(Http2ClassicConnectOutcome::Rejected { .. }) => "rejected",
            Err(Http2Error::Protocol(_)) => "protocol_error",
            Err(_) => "request_error",
        };
        outcome.finish(terminal_outcome);
        result
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
        Self::connect_with_builder_kind_and_accept_ch(stream, client, accept_ch, false).await
    }

    pub(super) async fn connect_extended_with_builder_and_accept_ch<T>(
        stream: T,
        client: client::Builder,
        accept_ch: AcceptCh,
    ) -> Result<Self, Http2Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::connect_with_builder_kind_and_accept_ch(stream, client, accept_ch, true).await
    }

    async fn connect_with_builder_kind<T>(
        stream: T,
        client: client::Builder,
        extended_connect: bool,
    ) -> Result<Self, Http2Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self::connect_with_builder_kind_and_accept_ch(
            stream,
            client,
            AcceptCh::default(),
            extended_connect,
        )
        .await
    }

    async fn connect_with_builder_kind_and_accept_ch<T>(
        stream: T,
        client: client::Builder,
        accept_ch: AcceptCh,
        extended_connect: bool,
    ) -> Result<Self, Http2Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| Http2Error::RuntimeUnavailable)?;
        let (sender, connection) = client
            .handshake(stream)
            .await
            .map_err(Http2Error::protocol)?;
        let driver = DriverTask::spawn(runtime, connection);
        Ok(Self {
            inner: Arc::new(ConnectionInner {
                sender: Some(sender),
                driver,
                accept_ch,
                extended_connect,
            }),
        })
    }

    pub(super) async fn send_prepared_request(
        &self,
        request: Request<()>,
        body: Option<RequestBody>,
        trailers: Option<PreparedRequestTrailers>,
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
            let end_of_stream = body.is_none() && trailers.is_none();
            let (response, reset) = sender
                .send_request(request, end_of_stream)
                .map_err(Http2Error::protocol)?;
            let mut response = Box::pin(response);
            let (stream, early_response) = if end_of_stream {
                (RequestStream::Complete(reset), None)
            } else {
                let mut upload = upload_request_body(reset, body, trailers);
                tokio::select! {
                    biased;
                    result = &mut response => {
                        let early = result.map_err(Http2Error::protocol)?;
                        // RFC 9113 section 8.1: only a complete response lets
                        // the client stop sending. Otherwise the server may
                        // still read the body, so the upload continues.
                        let stream = if early.body().is_end_stream() {
                            RequestStream::Abandoned(upload)
                        } else {
                            RequestStream::Uploading(upload)
                        };
                        (stream, Some(early))
                    }
                    result = &mut upload => (RequestStream::Complete(result?), None),
                }
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
            if let Some(frames) = parts.extensions.remove::<::http2::ext::AltSvcFrames>() {
                parts
                    .extensions
                    .insert(super::AltSvcFrames::from_http2(&frames));
            }
            let body = match stream {
                RequestStream::Complete(reset) => Http2Body::new(incoming, reset, self.lease()),
                RequestStream::Abandoned(upload) => {
                    // Read the completed response state before dropping the
                    // unfinished upload resets the stream with CANCEL.
                    let body = Http2Body::without_upload(incoming, self.lease());
                    drop(upload);
                    body
                }
                RequestStream::Uploading(upload) => {
                    Http2Body::with_pending_upload(incoming, upload, self.lease())
                }
            };
            Ok(Response::from_parts(parts, body))
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

/// Request-side state when the response head is returned.
enum RequestStream {
    Complete(SendStream<Bytes>),
    Abandoned(PendingUpload),
    Uploading(PendingUpload),
}

pub(super) type PendingUpload =
    Pin<Box<dyn Future<Output = Result<SendStream<Bytes>, Http2Error>> + Send>>;

/// Sends the request body on an owned stream.
///
/// Dropping the returned future before it completes resets the stream with
/// `CANCEL`; completion returns the stream for response-body cancellation.
fn upload_request_body(
    stream: SendStream<Bytes>,
    body: Option<RequestBody>,
    trailers: Option<PreparedRequestTrailers>,
) -> PendingUpload {
    Box::pin(async move {
        let mut upload = RequestStreamGuard::new(stream);
        send_body(upload.stream_mut()?, body, trailers).await?;
        upload.disarm()
    })
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
    extended_connect: bool,
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
