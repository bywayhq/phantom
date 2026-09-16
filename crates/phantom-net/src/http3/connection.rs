use std::sync::{
    Arc,
    atomic::{AtomicU8, Ordering},
};

use bytes::Bytes;
use h3::ConnectionState;
use http::{Request, Response};
use tokio::{runtime::Handle, sync::Mutex};
use tracing::{Instrument, debug_span, field};

#[cfg(test)]
use super::prepare_request;
use super::{
    DatagramRouter, DriverSignal, DriverTask, Http3Body, Http3Error, Http3ErrorKind,
    PendingRequest, ResponseHeadError, body, receive_response,
};

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
    sender: Mutex<Option<RequestSender>>,
    driver: DriverTask,
    datagrams: Option<DatagramRouter>,
    quinn: quinn::Connection,
    signal: AtomicU8,
    connector_identity: Option<Arc<()>>,
    runtime: Handle,
}

impl Http3Connection {
    pub(super) fn new(
        sender: RequestSender,
        driver: DriverTask,
        datagrams: Option<DatagramRouter>,
        quinn: quinn::Connection,
        connector_identity: Option<Arc<()>>,
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
            }),
        }
    }

    #[cfg(test)]
    pub(super) async fn send_request(
        &self,
        request: Request<()>,
    ) -> Result<Response<Http3Body>, Http3Error> {
        let request = prepare_request(request)?;
        self.send_prepared_request(request).await
    }

    pub(super) async fn send_prepared_request(
        &self,
        request: Request<()>,
    ) -> Result<Response<Http3Body>, Http3Error> {
        let span = debug_span!(
            "http3.response_head",
            method = %request.method(),
            protocol = "h3",
            status = field::Empty,
            outcome = field::Empty,
        );
        let result = async {
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
            let mut pending = PendingRequest::new(stream);
            let stream_id = pending.stream_mut()?.id();
            let mut datagrams = self
                .inner
                .datagrams
                .as_ref()
                .map(|router| router.monitor(stream_id));
            pending.stream_mut()?.finish().await?;
            let response = match receive_response(pending.stream_mut()?, datagrams.as_mut()).await {
                Ok(response) => response,
                Err(ResponseHeadError::Stream(error)) => return Err(error.into()),
                Err(ResponseHeadError::UnsupportedDatagram) => {
                    datagrams.take();
                    let stream = pending.into_stream()?;
                    body::defer_datagram_abort(stream, self.clone());
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
            let stream = pending.into_stream()?;
            Ok(Response::from_parts(
                parts,
                Http3Body::new(stream, self.clone(), datagrams),
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
