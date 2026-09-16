//! HTTP/1.1 Upgrade transactions over an existing byte stream.

use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{
    Response, StatusCode,
    header::{CONTENT_LENGTH, TRANSFER_ENCODING},
};
use http_body_util::Empty;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{Instrument, Span, debug, debug_span, field};
use wreq_proto::{conn::http1, upgrade};

use super::{
    Http1Body, Http1Error, OperationOutcome, PreparedGet,
    driver::{DriverSignal, DriverTask},
    response_head::ResponseHeadObserver,
};

/// Result of an HTTP/1.1 request that may switch protocols.
pub enum Http1UpgradeOutcome {
    /// The peer accepted the protocol switch and yielded the underlying stream.
    Upgraded(Response<Http1Upgrade>),
    /// The peer returned an ordinary HTTP response instead of switching protocols.
    Rejected(Response<Http1Body>),
}

impl fmt::Debug for Http1UpgradeOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Upgraded(response) => formatter
                .debug_tuple("Upgraded")
                .field(&response.status())
                .finish(),
            Self::Rejected(response) => formatter
                .debug_tuple("Rejected")
                .field(&response.status())
                .finish(),
        }
    }
}

/// Byte stream returned after an HTTP/1.1 protocol switch.
pub struct Http1Upgrade {
    inner: upgrade::Upgraded,
}

impl fmt::Debug for Http1Upgrade {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http1Upgrade")
            .finish_non_exhaustive()
    }
}

impl AsyncRead for Http1Upgrade {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(context, buffer)
    }
}

impl AsyncWrite for Http1Upgrade {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(context, buffers)
    }
}

pub(super) async fn send_prepared_upgrade<T>(
    stream: T,
    prepared: PreparedGet,
) -> Result<Http1UpgradeOutcome, Http1Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let span = debug_span!(
        "http1.upgrade.response_head",
        method = "GET",
        protocol = "http/1.1",
        status = field::Empty,
        outcome = field::Empty,
    );
    let outcome = OperationOutcome::new(&span);
    let result = async {
        debug!("HTTP/1 Upgrade transaction started");
        let (stream, observed_headers) = ResponseHeadObserver::wrap(stream);
        observed_headers.begin();
        let (mut sender, connection) = http1::Builder::default()
            .handshake::<_, Empty<Bytes>>(stream)
            .await?;
        let driver = DriverTask::spawn(connection.with_upgrades());

        sender.ready().await?;
        let mut response = sender
            .try_send_request(prepared.into_request())
            .await
            .map_err(|error| Http1Error::Protocol(error.into_error()))?;
        drop(sender);

        Span::current().record("status", response.status().as_u16());
        if response.headers().contains_key(TRANSFER_ENCODING)
            && response.headers().contains_key(CONTENT_LENGTH)
        {
            return Err(Http1Error::AmbiguousResponseFraming);
        }

        let ordered_headers = observed_headers
            .take()
            .ok_or(Http1Error::MissingResponseHeaderOrder)?;
        if response.status() != StatusCode::SWITCHING_PROTOCOLS {
            let (mut parts, incoming) = response.into_parts();
            parts.extensions.insert(ordered_headers);
            return Ok(Http1UpgradeOutcome::Rejected(Response::from_parts(
                parts,
                Http1Body::new_one_shot(incoming, driver),
            )));
        }

        let pending_upgrade = upgrade::on(&mut response);
        let (mut parts, incoming) = response.into_parts();
        drop(incoming);
        parts.extensions.insert(ordered_headers);
        let upgraded = pending_upgrade.await?;
        driver.finish(DriverSignal::Complete);
        Ok(Http1UpgradeOutcome::Upgraded(Response::from_parts(
            parts,
            Http1Upgrade { inner: upgraded },
        )))
    }
    .instrument(span.clone())
    .await;
    outcome.finish(match &result {
        Ok(Http1UpgradeOutcome::Upgraded(_)) => "upgraded",
        Ok(Http1UpgradeOutcome::Rejected(_)) => "rejected",
        Err(Http1Error::Protocol(_)) => "protocol_error",
        Err(Http1Error::AmbiguousResponseFraming) => "invalid_response",
        Err(_) => "request_error",
    });
    result
}
