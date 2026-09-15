//! A one-shot HTTP/1.1 client transaction.
//!
//! The core transaction accepts an already-connected byte stream, while
//! [`Http1TlsConnector`] composes it with the crate's TLS transport. This
//! module owns no connection pool. Completing or dropping the body schedules
//! cancellation of the protocol task; destruction of the underlying stream is
//! eventual.

use std::{error::Error as StdError, fmt};

use bytes::Bytes;
use http::{
    Response,
    header::{CONTENT_LENGTH, TRANSFER_ENCODING},
};
use http_body_util::Empty;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, Span, debug, debug_span, field};
use wreq_proto::conn::http1;

use body::DriverTask;
use request::PreparedGet;

#[cfg(test)]
use request::{MAX_REQUEST_HEADER_BYTES, MAX_REQUEST_HEADERS};

pub use crate::request::{OriginForm, RequestHeader};
pub use body::Http1Body;

/// Error returned by a one-shot HTTP/1.1 transaction.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http1Error {
    /// The request contained more headers than the fixed safety bound.
    TooManyHeaders {
        /// Number of supplied headers.
        count: usize,
        /// Maximum accepted number of headers.
        maximum: usize,
    },
    /// The aggregate request header bytes exceeded the fixed safety bound.
    HeadersTooLarge {
        /// Number of supplied field-name and field-value bytes.
        bytes: usize,
        /// Maximum accepted aggregate bytes.
        maximum: usize,
    },
    /// A request field name was not an HTTP token.
    InvalidHeaderName {
        /// Position in the ordered header list.
        index: usize,
    },
    /// A request field value contained bytes forbidden by HTTP.
    InvalidHeaderValue {
        /// Position in the ordered header list.
        index: usize,
        /// Field name supplied at that position.
        name: Box<str>,
    },
    /// No `Host` field was supplied.
    MissingHost,
    /// More than one `Host` field was supplied.
    MultipleHost,
    /// Request body framing is unavailable for this empty-body GET slice.
    RequestFramingHeader {
        /// Forbidden framing field name.
        name: Box<str>,
    },
    /// The response contained both `Transfer-Encoding` and `Content-Length`.
    AmbiguousResponseFraming,
    /// The HTTP protocol driver failed.
    Protocol(wreq_proto::Error),
}

impl fmt::Display for Http1Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyHeaders { count, maximum } => {
                write!(
                    formatter,
                    "request has {count} headers; maximum is {maximum}"
                )
            }
            Self::HeadersTooLarge { bytes, maximum } => write!(
                formatter,
                "request field names and values total {bytes} bytes; maximum is {maximum}"
            ),
            Self::InvalidHeaderName { index } => {
                write!(
                    formatter,
                    "request header at index {index} has an invalid field name"
                )
            }
            Self::InvalidHeaderValue { index, name } => write!(
                formatter,
                "request header {name:?} at index {index} has an invalid field value"
            ),
            Self::MissingHost => {
                formatter.write_str("request must contain exactly one Host header")
            }
            Self::MultipleHost => {
                formatter.write_str("request must not contain more than one Host header")
            }
            Self::RequestFramingHeader { name } => write!(
                formatter,
                "{name} is not allowed on this empty-body GET request"
            ),
            Self::AmbiguousResponseFraming => formatter.write_str(
                "response contains both Transfer-Encoding and Content-Length; connection discarded",
            ),
            Self::Protocol(error) => write!(formatter, "HTTP/1.1 protocol error: {error}"),
        }
    }
}

impl StdError for Http1Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            _ => None,
        }
    }
}

impl From<wreq_proto::Error> for Http1Error {
    fn from(error: wreq_proto::Error) -> Self {
        Self::Protocol(error)
    }
}

impl Http1Error {
    fn trace_kind(&self) -> &'static str {
        match self {
            Self::TooManyHeaders { .. } => "too_many_headers",
            Self::HeadersTooLarge { .. } => "headers_too_large",
            Self::InvalidHeaderName { .. } => "invalid_header_name",
            Self::InvalidHeaderValue { .. } => "invalid_header_value",
            Self::MissingHost => "missing_host",
            Self::MultipleHost => "multiple_host",
            Self::RequestFramingHeader { .. } => "request_framing_header",
            Self::AmbiguousResponseFraming => "invalid_response_framing",
            Self::Protocol(_) => "protocol",
        }
    }
}

/// Sends one empty-body HTTP/1.1 GET over an already-connected stream.
///
/// Header spelling, ordering, and duplicates are emitted exactly as supplied.
/// The stream is intentionally one-shot: completing or dropping the returned
/// body schedules its teardown, as does a body error. Dropping this future
/// after the driver starts also schedules cancellation. In both cases stream
/// teardown is eventual rather than synchronously complete when `Drop` returns.
pub async fn send_get<T>(
    stream: T,
    target: OriginForm,
    headers: Vec<RequestHeader>,
) -> Result<Response<Http1Body>, Http1Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let span = debug_span!(
        "http1.request.prepare",
        method = "GET",
        protocol = "http/1.1",
        outcome = field::Empty,
        error_kind = field::Empty,
    );
    let outcome = OperationOutcome::new(&span);
    let prepared = {
        let _entered = span.enter();
        PreparedGet::new(target, headers)
    };
    match &prepared {
        Ok(_) => outcome.finish("ok"),
        Err(error) => outcome.finish_with_error_kind("error", error.trace_kind()),
    }
    let prepared = prepared?;
    send_prepared_get(stream, prepared).await
}

async fn send_prepared_get<T>(
    stream: T,
    prepared: PreparedGet,
) -> Result<Response<Http1Body>, Http1Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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
        let (mut sender, connection) = http1::Builder::default()
            .handshake::<_, Empty<Bytes>>(stream)
            .await?;
        let driver = DriverTask::spawn(connection);

        sender.ready().await?;
        let response = sender
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

        debug!("HTTP/1 response headers received");
        let (parts, incoming) = response.into_parts();
        Ok(Response::from_parts(
            parts,
            Http1Body::new(incoming, driver),
        ))
    }
    .instrument(span.clone())
    .await;
    let terminal_outcome = match &result {
        Ok(_) => "ok",
        Err(Http1Error::AmbiguousResponseFraming) => "invalid_response",
        Err(Http1Error::Protocol(_)) => "protocol_error",
        Err(_) => "request_error",
    };
    outcome.finish(terminal_outcome);
    result
}

struct OperationOutcome {
    span: Span,
    recorded: bool,
}

impl OperationOutcome {
    fn new(span: &Span) -> Self {
        Self {
            span: span.clone(),
            recorded: false,
        }
    }

    fn finish(mut self, outcome: &'static str) {
        self.span.record("outcome", outcome);
        self.recorded = true;
    }

    fn finish_with_error_kind(mut self, outcome: &'static str, error_kind: &'static str) {
        self.span.record("outcome", outcome);
        self.span.record("error_kind", error_kind);
        self.recorded = true;
    }
}

impl Drop for OperationOutcome {
    fn drop(&mut self) {
        if !self.recorded {
            self.span.record("outcome", "cancelled");
        }
    }
}

#[cfg(test)]
mod tests;

mod body;
mod request;
mod tls;

pub use tls::{Http1TlsConnector, Http1TlsError, TlsError, TlsErrorKind};
