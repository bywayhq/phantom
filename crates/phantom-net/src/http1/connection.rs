//! Reusable HTTP/1.1 connection ownership.

use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use bytes::Bytes;
use http::{
    Response,
    header::{CONNECTION, CONTENT_LENGTH, TRANSFER_ENCODING},
};
use http_body_util::Empty;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore},
};
use tracing::{Instrument, Span, debug, debug_span, field};
use wreq_proto::conn::http1;

use super::{
    Http1Body, Http1Error, OperationOutcome, PreparedGet,
    driver::{DriverSignal, DriverTask},
    response_head::ResponseHeadObserver,
};

/// An established HTTP/1.1 connection that executes requests sequentially.
///
/// Clones share one connection. A response body retains the sole request
/// permit until it completes or is dropped, so requests are never pipelined.
#[derive(Clone)]
pub struct Http1Connection {
    inner: Arc<ConnectionInner>,
}

impl Http1Connection {
    /// Establishes HTTP/1.1 over an already-connected byte stream.
    ///
    /// # Errors
    ///
    /// Returns [`Http1Error`] when the protocol handshake fails.
    pub async fn connect<T>(stream: T) -> Result<Self, Http1Error>
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (stream, observer) = ResponseHeadObserver::wrap(stream);
        let (sender, connection) = http1::Builder::default()
            .handshake::<_, Empty<Bytes>>(stream)
            .await?;
        Ok(Self {
            inner: Arc::new(ConnectionInner {
                sender: Mutex::new(sender),
                request_permit: Arc::new(Semaphore::new(1)),
                observer,
                driver: DriverTask::spawn(connection),
                reusable: AtomicBool::new(true),
            }),
        })
    }

    /// Sends one empty-body GET after validating its wire representation.
    ///
    /// # Errors
    ///
    /// Returns [`Http1Error`] when validation, dispatch, or response-head
    /// processing fails.
    pub async fn send_get(
        &self,
        target: super::OriginForm,
        headers: Vec<super::RequestHeader>,
    ) -> Result<Response<Http1Body>, Http1Error> {
        self.send_prepared_get(PreparedGet::new(target, headers)?)
            .await
    }

    /// Returns whether this connection is eligible for another request.
    ///
    /// This is a snapshot. The peer can still close an idle connection before
    /// the next request reaches it; Phantom does not replay that request.
    #[must_use]
    pub fn is_reusable(&self) -> bool {
        self.inner.reusable.load(Ordering::Acquire) && !self.inner.driver.is_finished()
    }

    pub(super) async fn send_prepared_get(
        &self,
        prepared: PreparedGet,
    ) -> Result<Response<Http1Body>, Http1Error> {
        let span = debug_span!(
            "http1.response_head",
            method = "GET",
            protocol = "http/1.1",
            status = field::Empty,
            outcome = field::Empty,
        );
        let outcome = OperationOutcome::new(&span);
        let result = async {
            debug!("HTTP/1 transaction started");
            let permit = Arc::clone(&self.inner.request_permit)
                .acquire_owned()
                .await
                .map_err(|_| Http1Error::ConnectionClosed)?;
            if !self.is_reusable() {
                return Err(Http1Error::ConnectionClosed);
            }

            let mut sender = self.inner.sender.lock().await;
            self.inner.observer.begin();
            if let Err(error) = sender.ready().await {
                self.inner.stop(DriverSignal::ProtocolError);
                return Err(Http1Error::Protocol(error));
            }
            let request_allows_reuse = prepared.allows_reuse();
            let response_future = sender.try_send_request(prepared.into_request());
            let mut in_flight = InFlightGuard::new(&self.inner);
            let response = match response_future.await {
                Ok(response) => response,
                Err(error) => {
                    in_flight.stop(DriverSignal::ProtocolError);
                    return Err(Http1Error::Protocol(error.into_error()));
                }
            };
            in_flight.complete();
            drop(sender);

            Span::current().record("status", response.status().as_u16());
            if response.status() == http::StatusCode::SWITCHING_PROTOCOLS {
                self.inner.stop(DriverSignal::Cancelled);
                return Err(Http1Error::UnexpectedUpgrade);
            }
            if response.headers().contains_key(TRANSFER_ENCODING)
                && response.headers().contains_key(CONTENT_LENGTH)
            {
                self.inner.stop(DriverSignal::Cancelled);
                return Err(Http1Error::AmbiguousResponseFraming);
            }

            let reusable = request_allows_reuse && response_allows_reuse(&response);
            if !reusable {
                self.inner.reusable.store(false, Ordering::Release);
            }
            debug!("HTTP/1 response headers received");
            let (mut parts, incoming) = response.into_parts();
            let Some(ordered_headers) = self.inner.observer.take() else {
                self.inner.stop(DriverSignal::ProtocolError);
                return Err(Http1Error::MissingResponseHeaderOrder);
            };
            parts.extensions.insert(ordered_headers);
            Ok(Response::from_parts(
                parts,
                Http1Body::new(
                    incoming,
                    ConnectionLease::new(Arc::clone(&self.inner), permit),
                    reusable,
                ),
            ))
        }
        .instrument(span.clone())
        .await;
        let terminal_outcome = match &result {
            Ok(_) => "ok",
            Err(Http1Error::AmbiguousResponseFraming) => "invalid_response",
            Err(Http1Error::Protocol(_) | Http1Error::ConnectionClosed) => "protocol_error",
            Err(_) => "request_error",
        };
        outcome.finish(terminal_outcome);
        result
    }
}

impl fmt::Debug for Http1Connection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http1Connection")
            .field("reusable", &self.is_reusable())
            .finish_non_exhaustive()
    }
}

pub(super) struct ConnectionLease {
    inner: Option<Arc<ConnectionInner>>,
    permit: Option<OwnedSemaphorePermit>,
}

impl ConnectionLease {
    fn new(inner: Arc<ConnectionInner>, permit: OwnedSemaphorePermit) -> Self {
        Self {
            inner: Some(inner),
            permit: Some(permit),
        }
    }

    pub(super) fn complete(&mut self, reusable: bool) {
        if !reusable {
            self.stop(DriverSignal::Complete);
        }
        self.permit.take();
        self.inner.take();
    }

    pub(super) fn stop(&mut self, signal: DriverSignal) {
        if let Some(inner) = self.inner.as_ref() {
            inner.stop(signal);
        }
        self.permit.take();
        self.inner.take();
    }
}

struct ConnectionInner {
    sender: Mutex<http1::SendRequest<Empty<Bytes>>>,
    request_permit: Arc<Semaphore>,
    observer: ResponseHeadObserver,
    driver: DriverTask,
    reusable: AtomicBool,
}

struct InFlightGuard<'a> {
    inner: &'a ConnectionInner,
    active: bool,
}

impl<'a> InFlightGuard<'a> {
    fn new(inner: &'a ConnectionInner) -> Self {
        Self {
            inner,
            active: true,
        }
    }

    fn complete(&mut self) {
        self.active = false;
    }

    fn stop(&mut self, signal: DriverSignal) {
        if self.active {
            self.inner.stop(signal);
            self.active = false;
        }
    }
}

impl Drop for InFlightGuard<'_> {
    fn drop(&mut self) {
        self.stop(DriverSignal::Cancelled);
    }
}

impl ConnectionInner {
    fn stop(&self, signal: DriverSignal) {
        self.reusable.store(false, Ordering::Release);
        self.driver.finish(signal);
    }
}

impl Drop for ConnectionInner {
    fn drop(&mut self) {
        self.driver.finish(DriverSignal::Complete);
    }
}

fn response_allows_reuse(response: &Response<wreq_proto::body::Incoming>) -> bool {
    let keep_alive = match response.version() {
        http::Version::HTTP_11 => !header_has_token(response, CONNECTION, "close"),
        _ => false,
    };
    keep_alive && response_is_self_delimited(response)
}

fn response_is_self_delimited(response: &Response<wreq_proto::body::Incoming>) -> bool {
    if matches!(response.status().as_u16(), 204 | 304) {
        return true;
    }
    if response.headers().contains_key(TRANSFER_ENCODING) {
        return response
            .headers()
            .get_all(TRANSFER_ENCODING)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .flat_map(|value| value.split(','))
            .next_back()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("chunked"));
    }
    response.headers().contains_key(CONTENT_LENGTH)
}

fn header_has_token(
    response: &Response<wreq_proto::body::Incoming>,
    name: http::header::HeaderName,
    token: &str,
) -> bool {
    response.headers().get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|value| {
            value
                .split(',')
                .any(|value| value.trim().eq_ignore_ascii_case(token))
        })
    })
}
