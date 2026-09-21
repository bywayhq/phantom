use std::{
    future::poll_fn,
    pin::pin,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
};

use bytes::Bytes;
use h3::{ConnectionState, client::PeerSettings};
use http::{Request, Response};
use tokio::{runtime::Handle, sync::Mutex};
use tracing::{Instrument, debug_span, field};

use crate::accept_ch::AcceptCh;

use super::{
    DatagramRouter, DriverSignal, DriverTask, Http3Body, Http3Error, Http3ErrorKind,
    Http3ExtendedConnectOutcome, Http3ExtendedConnectStream, Http3ExtendedProtocol, PendingRequest,
    RequestRecvStream, ResponseHeadError, body, driver_unavailable, receive_response,
    request::PreparedRequest,
    upload::{RequestSend, UploadError},
};
use crate::request::RequestBody;

type RequestSender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;

/// Cloneable handle to one established HTTP/3 connection.
///
/// Clones open independent request streams over the same QUIC connection. The
/// final connection or response-body lease starts bounded driver shutdown.
/// Send requests through the [`super::Http3Connector`] that opened the handle.
#[derive(Clone)]
pub struct Http3Connection {
    inner: Arc<ConnectionInner>,
}

struct ConnectionInner {
    // Serializes `send_request` so stream IDs, QPACK encoder instructions, and
    // datagram monitor registration follow call order. Health checks must not
    // take this lock: `send_request` can wait for peer SETTINGS, QPACK
    // admission, or MAX_STREAMS credit while holding it.
    sender: Mutex<Option<RequestSender>>,
    state: PeerSettings,
    driver: DriverTask,
    datagrams: Option<DatagramRouter>,
    quinn: quinn::Connection,
    signal: AtomicU8,
    connector_identity: Option<Arc<()>>,
    runtime: Handle,
    accept_ch: AcceptCh,
}

impl Http3Connection {
    pub(super) fn new(
        sender: RequestSender,
        driver: DriverTask,
        datagrams: Option<DatagramRouter>,
        quinn: quinn::Connection,
        connector_identity: Option<Arc<()>>,
        accept_ch: AcceptCh,
    ) -> Self {
        Self {
            inner: Arc::new(ConnectionInner {
                state: sender.peer_settings(),
                sender: Mutex::new(Some(sender)),
                driver,
                datagrams,
                quinn,
                signal: AtomicU8::new(DriverSignal::Complete.rank()),
                connector_identity,
                runtime: Handle::current(),
                accept_ch,
            }),
        }
    }

    /// Returns this connection's ALPS-delivered `Accept-CH` value for `origin`.
    ///
    /// The lookup is an exact byte match against the origin serialized in the
    /// peer's HTTP/3 `ACCEPT_CH` frame. The metadata is immutable and remains
    /// scoped to this connection.
    #[must_use]
    pub fn accept_ch_for_origin(&self, origin: &str) -> Option<&[u8]> {
        self.inner.accept_ch.for_origin(origin)
    }

    #[cfg(test)]
    pub(super) async fn send_request(
        &self,
        request: Request<()>,
        body: Option<Bytes>,
    ) -> Result<Response<Http3Body>, Http3Error> {
        let request = super::prepare_request(request, body)?;
        self.send_prepared_request(request).await
    }

    pub(super) async fn send_prepared_request(
        &self,
        prepared: PreparedRequest,
    ) -> Result<Response<Http3Body>, Http3Error> {
        let method = prepared.method().clone();
        let body_bytes = prepared.body_len();
        let has_body = prepared.has_body();
        let span = debug_span!(
            "http3.response_head",
            method = %method,
            protocol = "h3",
            body_bytes = body_bytes.unwrap_or(0),
            body_length_known = body_bytes.is_some(),
            has_body,
            status = field::Empty,
            outcome = field::Empty,
        );
        let result = async {
            let (request, body, trailers) = prepared.into_parts();
            let stream = {
                let mut sender = self.inner.sender.lock().await;
                let sender = sender.as_mut().ok_or_else(driver_unavailable)?;
                sender.send_request(request).await?
            };
            let stream_id = stream.id();
            let mut pending = PendingRequest::new(stream);
            let mut datagrams = self
                .inner
                .datagrams
                .as_ref()
                .map(|router| router.monitor(stream_id));
            let mut send = RequestSend::stream(pending.take_send()?);
            let exchange_result = exchange(
                &mut send,
                pending.recv_mut()?,
                body,
                trailers,
                datagrams.as_mut(),
            )
            .await;
            let response = match exchange_result {
                Ok(response) => response,
                Err(ResponseHeadError::RequestBody(error)) => return Err(error),
                Err(ResponseHeadError::Stream(error)) => return Err(error.into()),
                Err(ResponseHeadError::UnsupportedDatagram) => {
                    datagrams.take();
                    let recv = pending.into_recv()?;
                    body::defer_datagram_abort(send, recv, self.clone());
                    return Err(Http3Error::without_source(
                        Http3ErrorKind::Protocol,
                        "peer sent an HTTP Datagram for a request without datagram semantics",
                    ));
                }
                Err(ResponseHeadError::SwitchingProtocols) => {
                    return Err(Http3Error::without_source(
                        Http3ErrorKind::Protocol,
                        "peer sent a 101 response over HTTP/3",
                    ));
                }
            };
            span.record("status", response.status().as_u16());

            let (mut parts, ()) = response.into_parts();
            let ordered_headers = parts
                .extensions
                .remove::<h3::ext::OrderedHeaders>()
                .map(|headers| {
                    crate::OrderedResponseHeaders::from_normalized_fields(headers.as_slice())
                })
                .ok_or_else(|| {
                    Http3Error::without_source(
                        Http3ErrorKind::Protocol,
                        "HTTP/3 response header order was not captured",
                    )
                })?;
            parts.extensions.insert(ordered_headers);
            let recv = pending.into_recv()?;
            Ok(Response::from_parts(
                parts,
                Http3Body::new(send, recv, self.clone(), datagrams),
            ))
        }
        .instrument(span.clone())
        .await;
        span.record("outcome", if result.is_ok() { "ok" } else { "error" });
        result
    }

    /// Opens one extended CONNECT stream after the peer enables it.
    ///
    /// No request stream is opened unless the peer's SETTINGS, from ALPS or
    /// the control stream, carry `SETTINGS_ENABLE_CONNECT_PROTOCOL = 1`
    /// (RFC 9220 section 3, RFC 8441 section 3).
    pub(super) async fn send_extended_connect(
        &self,
        protocol: Http3ExtendedProtocol,
        request: Request<()>,
    ) -> Result<Http3ExtendedConnectOutcome, Http3Error> {
        let span = debug_span!(
            "http3.extended_connect.response_head",
            method = "CONNECT",
            protocol = "h3",
            extended_protocol = protocol.trace_name(),
            status = field::Empty,
            outcome = field::Empty,
        );
        let result = async {
            let mut peer_settings = {
                let sender = self.inner.sender.lock().await;
                sender
                    .as_ref()
                    .ok_or_else(driver_unavailable)?
                    .peer_settings()
            };
            if !peer_settings.ready().await?.enable_extended_connect() {
                return Err(Http3Error::without_source(
                    Http3ErrorKind::ExtendedConnectUnavailable,
                    "HTTP/3 peer did not enable extended CONNECT",
                ));
            }
            let stream = {
                let mut sender = self.inner.sender.lock().await;
                let sender = sender.as_mut().ok_or_else(driver_unavailable)?;
                sender.send_request(request).await?
            };
            let stream_id = stream.id();
            let mut pending = PendingRequest::new(stream);
            let mut datagrams = self
                .inner
                .datagrams
                .as_ref()
                .map(|router| router.monitor(stream_id));
            let response = {
                let (_, recv) = pending.streams_mut()?;
                receive_response(recv, datagrams.as_mut()).await
            };
            let response = match response {
                Ok(response) => response,
                Err(ResponseHeadError::Stream(error)) => return Err(error.into()),
                Err(ResponseHeadError::UnsupportedDatagram) => {
                    datagrams.take();
                    let (send, recv) = pending.into_streams()?;
                    body::defer_datagram_abort(RequestSend::stream(send), recv, self.clone());
                    return Err(Http3Error::without_source(
                        Http3ErrorKind::Protocol,
                        "peer sent an HTTP Datagram for a request without datagram semantics",
                    ));
                }
                Err(ResponseHeadError::SwitchingProtocols) => {
                    return Err(Http3Error::without_source(
                        Http3ErrorKind::Protocol,
                        "peer sent a 101 response over HTTP/3",
                    ));
                }
                Err(ResponseHeadError::RequestBody(error)) => return Err(error),
            };
            span.record("status", response.status().as_u16());

            let accepted = response.status().is_success();
            let (mut parts, ()) = response.into_parts();
            let ordered_headers = parts
                .extensions
                .remove::<h3::ext::OrderedHeaders>()
                .map(|headers| {
                    crate::OrderedResponseHeaders::from_normalized_fields(headers.as_slice())
                })
                .ok_or_else(|| {
                    Http3Error::without_source(
                        Http3ErrorKind::Protocol,
                        "HTTP/3 response header order was not captured",
                    )
                })?;
            parts.extensions.insert(ordered_headers);
            let (mut send, recv) = pending.into_streams()?;
            if accepted {
                return Ok(Http3ExtendedConnectOutcome::Accepted {
                    response: Response::from_parts(parts, ()),
                    stream: Http3ExtendedConnectStream::new(send, recv, self.clone(), datagrams),
                });
            }
            let mut recv = recv;
            if let Err(error) = poll_fn(|context| send.poll_finish(context)).await {
                recv.stop_sending(h3::error::Code::H3_REQUEST_CANCELLED);
                send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
                return Err(error.into());
            }
            let body = Http3Body::new(RequestSend::stream(send), recv, self.clone(), datagrams);
            Ok(Http3ExtendedConnectOutcome::Rejected(Response::from_parts(
                parts, body,
            )))
        }
        .instrument(span.clone())
        .await;
        let outcome = match &result {
            Ok(Http3ExtendedConnectOutcome::Accepted { .. }) => "accepted",
            Ok(Http3ExtendedConnectOutcome::Rejected(_)) => "rejected",
            Err(error) if error.kind() == Http3ErrorKind::ExtendedConnectUnavailable => {
                "capability_unavailable"
            }
            Err(error) if error.kind() == Http3ErrorKind::Protocol => "protocol_error",
            Err(_) => "request_error",
        };
        span.record("outcome", outcome);
        result
    }

    pub(super) fn is_reusable(&self) -> bool {
        if self.inner.quinn.close_reason().is_some() {
            return false;
        }
        if self
            .inner
            .datagrams
            .as_ref()
            .is_some_and(DatagramRouter::is_failed)
        {
            return false;
        }
        !self.inner.state.is_closing() && self.inner.state.get_conn_error().is_none()
    }

    pub(super) fn belongs_to(&self, identity: &Arc<()>) -> bool {
        self.inner
            .connector_identity
            .as_ref()
            .is_some_and(|connection| Arc::ptr_eq(connection, identity))
    }

    pub(super) fn runtime(&self) -> &Handle {
        &self.inner.runtime
    }

    pub(super) fn record(&self, signal: DriverSignal) {
        self.inner.signal.fetch_max(signal.rank(), Ordering::AcqRel);
    }
}

async fn exchange(
    send: &mut RequestSend,
    recv: &mut RequestRecvStream,
    body: Option<RequestBody>,
    trailers: Option<super::request::PreparedTrailers>,
    datagrams: Option<&mut super::DatagramMonitor>,
) -> Result<Response<()>, ResponseHeadError> {
    if body.is_none() && trailers.is_none() {
        if let RequestSend::Stream(stream) = send {
            stream.finish().await.map_err(ResponseHeadError::Stream)?;
        }
        return receive_response(recv, datagrams).await;
    }

    send.start_upload(body, trailers);
    let mut response = pin!(receive_response(recv, datagrams));
    tokio::select! {
        biased;
        // RFC 9114 section 4.1: a response can precede the end of the request.
        // The upload stays in `send` and continues beside the response body.
        response = &mut response => response,
        uploaded = send.uploaded() => match uploaded {
            Ok(()) => response.await,
            Err(UploadError::Body(error)) => Err(ResponseHeadError::RequestBody(error)),
            Err(UploadError::Stream(upload_error)) => match response.await {
                Ok(response) => Ok(response),
                Err(ResponseHeadError::Stream(_)) => Err(ResponseHeadError::Stream(upload_error)),
                Err(error) => Err(error),
            },
        },
    }
}

impl std::fmt::Debug for Http3Connection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Http3Connection")
            .field("closed", &self.inner.quinn.close_reason().is_some())
            .finish_non_exhaustive()
    }
}

impl Drop for ConnectionInner {
    fn drop(&mut self) {
        self.sender.get_mut().take();
        let signal = DriverSignal::from_rank(self.signal.load(Ordering::Acquire));
        self.driver.finish(signal);
    }
}
