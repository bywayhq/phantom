//! Reusable HTTP/2 connection ownership.

use std::{fmt, sync::Arc};

use ::http2::client;
use bytes::Bytes;
use http::{Request, Response};
use phantom_profile::Http2Settings;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, debug, debug_span, field};

use super::{
    Http2Body, Http2Error, OperationOutcome, OriginForm, RequestHeader, driver::DriverTask,
    prepare_request, translate_settings,
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
        let request = prepare_request(authority, target, headers)?;
        self.send_prepared_get(request).await
    }

    /// Returns whether the connection driver has stopped.
    ///
    /// A connection may become closed between this observation and a later
    /// request. Callers must still handle request errors.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.inner.driver.is_finished()
    }

    pub(super) async fn connect_with_builder<T>(
        stream: T,
        client: client::Builder,
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
            }),
        })
    }

    pub(super) async fn send_prepared_get(
        &self,
        request: Request<()>,
    ) -> Result<Response<Http2Body>, Http2Error> {
        let span = debug_span!(
            "http2.response_head",
            method = "GET",
            protocol = "h2",
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
            let (response, reset) = sender
                .send_request(request, true)
                .map_err(Http2Error::protocol)?;
            let response = response.await.map_err(Http2Error::protocol)?;

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
