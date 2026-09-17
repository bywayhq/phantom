use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use bytes::Bytes;
use h3::ConnectionState;
#[cfg(test)]
use http::Request;
use http::Response;
use http_body_util::BodyExt as _;
use tokio::{runtime::Handle, sync::Mutex};
use tracing::{Instrument, debug_span, field};

use crate::accept_ch::AcceptCh;

use super::{
    DatagramRouter, DriverSignal, DriverTask, Http3Body, Http3Error, Http3ErrorKind,
    PendingRequest, RequestRecvStream, RequestSendStream, ResponseHeadError, body,
    receive_response, request::PreparedRequest,
};
use crate::request::RequestBody;

type RequestSender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
const REQUEST_BODY_CHUNK_BYTES: usize = 64 * 1024;

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
    sender: Mutex<Option<RequestSender>>,
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
            let (request, body) = prepared.into_parts();
            let stream = {
                let mut sender = self.inner.sender.lock().await;
                let sender = sender.as_mut().ok_or_else(|| {
                    Http3Error::without_source(
                        Http3ErrorKind::Local,
                        "HTTP/3 request driver is unavailable",
                    )
                })?;
                sender.send_request(request).await?
            };
            let stream_id = stream.id();
            let mut pending = PendingRequest::new(stream);
            let mut datagrams = self
                .inner
                .datagrams
                .as_ref()
                .map(|router| router.monitor(stream_id));
            let exchange_result = {
                let (send, recv) = pending.streams_mut()?;
                exchange(send, recv, body, datagrams.as_mut()).await
            };
            let response = match exchange_result {
                Ok(response) => response,
                Err(ResponseHeadError::RequestBody(error)) => return Err(error),
                Err(ResponseHeadError::Stream(error)) => return Err(error.into()),
                Err(ResponseHeadError::UnsupportedDatagram) => {
                    datagrams.take();
                    let (send, recv) = pending.into_streams()?;
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
            let (send, recv) = pending.into_streams()?;
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

    pub(super) async fn is_reusable(&self) -> bool {
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
        let sender = self.inner.sender.lock().await;
        sender
            .as_ref()
            .is_some_and(|sender| !sender.is_closing() && sender.get_conn_error().is_none())
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
    send: &mut RequestSendStream,
    recv: &mut RequestRecvStream,
    body: Option<RequestBody>,
    datagrams: Option<&mut super::DatagramMonitor>,
) -> Result<Response<()>, ResponseHeadError> {
    let Some(body) = body else {
        send.finish().await.map_err(ResponseHeadError::Stream)?;
        return receive_response(recv, datagrams).await;
    };

    let mut upload = Box::pin(send_body(send, body));
    let mut response = Box::pin(receive_response(recv, datagrams));

    tokio::select! {
        biased;
        response = &mut response => {
            drop(upload);
            if response.is_ok() {
                send.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
            }
            response
        }
        upload = &mut upload => {
            match upload {
                Ok(()) => response.await,
                Err(UploadError::Body(error)) => Err(ResponseHeadError::RequestBody(error)),
                Err(UploadError::Stream(upload_error)) => match response.await {
                    Ok(response) => Ok(response),
                    Err(ResponseHeadError::Stream(_)) => {
                        Err(ResponseHeadError::Stream(upload_error))
                    }
                    Err(error) => Err(error),
                },
            }
        }
    }
}

async fn send_body(send: &mut RequestSendStream, mut body: RequestBody) -> Result<(), UploadError> {
    while let Some(frame) = body.frame().await {
        let frame = frame
            .map_err(Http3Error::request_body)
            .map_err(UploadError::Body)?;
        let mut data = frame.into_data().map_err(|_| {
            UploadError::Body(Http3Error::without_source(
                Http3ErrorKind::Request,
                "HTTP/3 request trailers are not supported",
            ))
        })?;
        if data.is_empty() {
            send.send_data(data).await.map_err(UploadError::Stream)?;
        } else {
            while !data.is_empty() {
                let chunk_len = data.len().min(REQUEST_BODY_CHUNK_BYTES);
                send.send_data(data.split_to(chunk_len))
                    .await
                    .map_err(UploadError::Stream)?;
            }
        }
    }
    send.finish().await.map_err(UploadError::Stream)
}

enum UploadError {
    Body(Http3Error),
    Stream(h3::error::StreamError),
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
