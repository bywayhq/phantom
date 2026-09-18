//! HTTP/1.1 client transactions and reusable connection ownership.
//!
//! The core transaction accepts an already-connected byte stream, while
//! [`Http1TlsConnector`] composes it with the crate's TLS transport. This
//! module owns no connection pool. [`send_get`] remains a one-shot convenience;
//! [`Http1Connection`] exposes sequential keep-alive reuse.

use std::{error::Error as StdError, fmt};

use bytes::Bytes;
use http::{Method, Response};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Span, debug_span, field};

use request::{PreparedGet, PreparedRequest};
use upgrade::send_prepared_upgrade;

#[cfg(test)]
use request::{
    MAX_REQUEST_HEADER_BYTES, MAX_REQUEST_HEADERS, MAX_REQUEST_TRAILER_BYTES, MAX_REQUEST_TRAILERS,
};

pub use crate::request::{AbsoluteForm, InvalidAbsoluteForm, OriginForm, RequestHeader};
use crate::request::{RequestBody, RequestBodyMetadata};
pub use body::Http1Body;
pub use connection::Http1Connection;
pub use upgrade::{Http1Upgrade, Http1UpgradeOutcome};

/// Error returned by an HTTP/1.1 connection or request.
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
    /// The request contained more trailers than the fixed safety bound.
    TooManyTrailers {
        /// Number of supplied trailers.
        count: usize,
        /// Maximum accepted number of trailers.
        maximum: usize,
    },
    /// Aggregate request-trailer bytes exceeded the fixed safety bound.
    TrailersTooLarge {
        /// Number of supplied field-name and field-value bytes.
        bytes: usize,
        /// Maximum accepted aggregate bytes.
        maximum: usize,
    },
    /// The response contained more fields than the fixed safety bound.
    TooManyResponseHeaders {
        /// Maximum accepted number of response fields.
        maximum: usize,
    },
    /// One response head exceeded the fixed wire-byte safety bound.
    ResponseHeadTooLarge {
        /// Maximum accepted bytes from the status line through the empty line.
        maximum: usize,
    },
    /// One chunk-size line exceeded the fixed wire-byte safety bound.
    ChunkSizeLineTooLarge {
        /// Maximum accepted bytes in one chunk-size line.
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
    /// A request-trailer field name was not an HTTP token.
    InvalidTrailerName {
        /// Position in the ordered trailer list.
        index: usize,
    },
    /// A request-trailer value contained bytes forbidden by HTTP.
    InvalidTrailerValue {
        /// Position in the ordered trailer list.
        index: usize,
        /// Field name supplied at that position.
        name: Box<str>,
    },
    /// A request trailer is forbidden by HTTP semantics.
    ForbiddenTrailer {
        /// Position in the ordered trailer list.
        index: usize,
        /// Forbidden field name.
        name: Box<str>,
    },
    /// The explicit `Trailer` declaration did not match the supplied trailers.
    InvalidTrailerDeclaration {
        /// Position of the inconsistent declaration.
        index: usize,
    },
    /// A request with trailers also supplied `Content-Length`.
    RequestTrailersWithContentLength {
        /// Position of the conflicting field.
        index: usize,
    },
    /// No `Host` field was supplied.
    MissingHost,
    /// More than one `Host` field was supplied.
    MultipleHost,
    /// `Host` did not match the authority in an absolute-form target.
    MismatchedHost {
        /// Position of the mismatched `Host` field.
        index: usize,
    },
    /// `Connection` nominated an authority or framing field for removal.
    ConnectionNominatesCriticalField {
        /// Position of the invalid `Connection` field.
        index: usize,
    },
    /// Standard CONNECT cannot be represented by an origin-form target.
    ConnectUnsupported,
    /// A transfer-coding field was supplied, or framing was added to Upgrade.
    RequestFramingHeader {
        /// Forbidden framing field name.
        name: Box<str>,
    },
    /// `Content-Length` was not the canonical decimal request-body length.
    InvalidContentLength {
        /// Position in the ordered header list.
        index: usize,
    },
    /// More than one `Content-Length` field was supplied.
    DuplicateContentLength {
        /// Position of the duplicate field in the ordered header list.
        index: usize,
    },
    /// The response contained both `Transfer-Encoding` and `Content-Length`.
    AmbiguousResponseFraming,
    /// An ordinary request received an unsolicited protocol switch.
    UnexpectedUpgrade,
    /// The HTTP backend completed a response without its ordered field capture.
    MissingResponseHeaderOrder,
    /// The established connection can no longer accept a request.
    ConnectionClosed,
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
            Self::TooManyTrailers { count, maximum } => write!(
                formatter,
                "request has {count} trailers; maximum is {maximum}"
            ),
            Self::TrailersTooLarge { bytes, maximum } => write!(
                formatter,
                "request trailer names and values total {bytes} bytes; maximum is {maximum}"
            ),
            Self::TooManyResponseHeaders { maximum } => {
                write!(
                    formatter,
                    "response has more than {maximum} header fields; connection discarded"
                )
            }
            Self::ResponseHeadTooLarge { maximum } => write!(
                formatter,
                "response head exceeds {maximum} wire bytes; connection discarded"
            ),
            Self::ChunkSizeLineTooLarge { maximum } => write!(
                formatter,
                "response chunk-size line exceeds {maximum} wire bytes; connection discarded"
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
            Self::InvalidTrailerName { index } => write!(
                formatter,
                "request trailer at index {index} has an invalid field name"
            ),
            Self::InvalidTrailerValue { index, name } => write!(
                formatter,
                "request trailer {name:?} at index {index} has an invalid field value"
            ),
            Self::ForbiddenTrailer { index, name } => write!(
                formatter,
                "request trailer {name:?} at index {index} is forbidden"
            ),
            Self::InvalidTrailerDeclaration { index } => write!(
                formatter,
                "request Trailer declaration at index {index} does not match the supplied trailers"
            ),
            Self::RequestTrailersWithContentLength { index } => write!(
                formatter,
                "request Content-Length at index {index} conflicts with request trailers"
            ),
            Self::MissingHost => {
                formatter.write_str("request must contain exactly one Host header")
            }
            Self::MultipleHost => {
                formatter.write_str("request must not contain more than one Host header")
            }
            Self::MismatchedHost { index } => write!(
                formatter,
                "request Host header at index {index} does not match the absolute-form authority"
            ),
            Self::ConnectionNominatesCriticalField { index } => write!(
                formatter,
                "request Connection header at index {index} names Host or a framing field"
            ),
            Self::ConnectUnsupported => {
                formatter.write_str("HTTP/1 CONNECT requires an authority-form request API")
            }
            Self::RequestFramingHeader { name } => {
                write!(formatter, "{name} is not allowed on this HTTP/1 request")
            }
            Self::InvalidContentLength { index } => write!(
                formatter,
                "request Content-Length at index {index} is not the canonical body length"
            ),
            Self::DuplicateContentLength { index } => write!(
                formatter,
                "request contains a duplicate Content-Length field at index {index}"
            ),
            Self::AmbiguousResponseFraming => formatter.write_str(
                "response contains both Transfer-Encoding and Content-Length; connection discarded",
            ),
            Self::UnexpectedUpgrade => {
                formatter.write_str("ordinary HTTP/1 request received an unexpected 101 response")
            }
            Self::MissingResponseHeaderOrder => {
                formatter.write_str("HTTP/1 response header order was not captured")
            }
            Self::ConnectionClosed => formatter.write_str("HTTP/1 connection is closed"),
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
        if error.is_chunk_size_line_too_large() {
            Self::ChunkSizeLineTooLarge {
                maximum: limits::MAX_CHUNK_SIZE_LINE_BYTES,
            }
        } else {
            Self::Protocol(error)
        }
    }
}

impl Http1Error {
    fn trace_kind(&self) -> &'static str {
        match self {
            Self::TooManyHeaders { .. } => "too_many_headers",
            Self::HeadersTooLarge { .. } => "headers_too_large",
            Self::TooManyTrailers { .. } => "too_many_trailers",
            Self::TrailersTooLarge { .. } => "trailers_too_large",
            Self::TooManyResponseHeaders { .. } => "too_many_response_headers",
            Self::ResponseHeadTooLarge { .. } => "response_head_too_large",
            Self::ChunkSizeLineTooLarge { .. } => "chunk_size_line_too_large",
            Self::InvalidHeaderName { .. } => "invalid_header_name",
            Self::InvalidHeaderValue { .. } => "invalid_header_value",
            Self::InvalidTrailerName { .. } => "invalid_trailer_name",
            Self::InvalidTrailerValue { .. } => "invalid_trailer_value",
            Self::ForbiddenTrailer { .. } => "forbidden_trailer",
            Self::InvalidTrailerDeclaration { .. } => "invalid_trailer_declaration",
            Self::RequestTrailersWithContentLength { .. } => "request_trailers_with_content_length",
            Self::MissingHost => "missing_host",
            Self::MultipleHost => "multiple_host",
            Self::MismatchedHost { .. } => "mismatched_host",
            Self::ConnectionNominatesCriticalField { .. } => "connection_nominates_critical_field",
            Self::ConnectUnsupported => "connect_unsupported",
            Self::RequestFramingHeader { .. } => "request_framing_header",
            Self::InvalidContentLength { .. } => "invalid_content_length",
            Self::DuplicateContentLength { .. } => "duplicate_content_length",
            Self::AmbiguousResponseFraming => "invalid_response_framing",
            Self::UnexpectedUpgrade => "unexpected_upgrade",
            Self::MissingResponseHeaderOrder => "missing_response_header_order",
            Self::ConnectionClosed => "connection_closed",
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
    send_request(stream, Method::GET, target, headers, None).await
}

/// Sends one HTTP/1.1 request over an already-connected stream.
///
/// Header spelling, ordering, and duplicates are emitted exactly as supplied.
/// A missing `Content-Length` is appended only when the owned body is nonempty.
/// The stream and cancellation behavior match [`send_get`].
pub async fn send_request<T>(
    stream: T,
    method: Method,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<Bytes>,
) -> Result<Response<Http1Body>, Http1Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let body_bytes = body.as_ref().map_or(0, Bytes::len);
    let has_body = body.is_some();
    let span = debug_span!(
        "http1.request.prepare",
        method = %method,
        protocol = "http/1.1",
        body_bytes,
        has_body,
        outcome = field::Empty,
        error_kind = field::Empty,
    );
    let outcome = OperationOutcome::new(&span);
    let prepared = {
        let _entered = span.enter();
        PreparedRequest::new(method, target, headers, body)
    };
    match &prepared {
        Ok(_) => outcome.finish("ok"),
        Err(error) => outcome.finish_with_error_kind("error", error.trace_kind()),
    }
    let prepared = prepared?;
    send_prepared_request(stream, prepared).await
}

/// Sends one pull-driven HTTP/1.1 request body over an already-connected stream.
///
/// Exact initial size hints use `Content-Length`; unknown sizes use chunked
/// transfer coding. Header and framing validation completes before the body is
/// polled or the stream is touched.
pub async fn send_request_body<T>(
    stream: T,
    method: Method,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<RequestBody>,
) -> Result<Response<Http1Body>, Http1Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let body_bytes = body
        .as_ref()
        .and_then(|body| body.metadata().exact_length());
    let has_body = body.is_some();
    let span = debug_span!(
        "http1.request.prepare",
        method = %method,
        protocol = "http/1.1",
        body_bytes = field::Empty,
        has_body,
        outcome = field::Empty,
        error_kind = field::Empty,
    );
    if let Some(body_bytes) = body_bytes {
        span.record("body_bytes", body_bytes);
    }
    let outcome = OperationOutcome::new(&span);
    let prepared = {
        let _entered = span.enter();
        PreparedRequest::new_body(method, target, headers, body)
    };
    match &prepared {
        Ok(_) => outcome.finish("ok"),
        Err(error) => outcome.finish_with_error_kind("error", error.trace_kind()),
    }
    let prepared = prepared?;
    send_prepared_request(stream, prepared).await
}

/// Sends one pull-driven HTTP/1.1 body followed by exact ordered trailers.
///
/// Validation completes before the body is polled or the stream is touched.
pub async fn send_request_body_with_trailers<T>(
    stream: T,
    method: Method,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<RequestBody>,
    trailers: Vec<RequestHeader>,
) -> Result<Response<Http1Body>, Http1Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let prepared =
        PreparedRequest::new_body_with_trailers(method, target, headers, body, trailers)?;
    send_prepared_request(stream, prepared).await
}

/// Sends one HTTP/1.1 request with an absolute-form target over an
/// already-connected forward-proxy stream.
///
/// The `Host` field must match the target authority. Validation completes
/// before the supplied stream is touched.
pub async fn send_forward_request<T>(
    stream: T,
    method: Method,
    target: AbsoluteForm,
    headers: Vec<RequestHeader>,
    body: Option<Bytes>,
) -> Result<Response<Http1Body>, Http1Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let body_bytes = body.as_ref().map_or(0, Bytes::len);
    let has_body = body.is_some();
    let span = debug_span!(
        "http1.request.prepare",
        method = %method,
        protocol = "http/1.1",
        body_bytes,
        has_body,
        outcome = field::Empty,
        error_kind = field::Empty,
    );
    let outcome = OperationOutcome::new(&span);
    let prepared = {
        let _entered = span.enter();
        PreparedRequest::new_forward(method, target, headers, body)
    };
    match &prepared {
        Ok(_) => outcome.finish("ok"),
        Err(error) => outcome.finish_with_error_kind("error", error.trace_kind()),
    }
    let prepared = prepared?;
    send_prepared_request(stream, prepared).await
}

/// Sends one pull-driven HTTP/1.1 body with an absolute-form proxy target.
///
/// Validation completes before the supplied stream or request body is touched.
pub async fn send_forward_request_body<T>(
    stream: T,
    method: Method,
    target: AbsoluteForm,
    headers: Vec<RequestHeader>,
    body: Option<RequestBody>,
) -> Result<Response<Http1Body>, Http1Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let body_bytes = body
        .as_ref()
        .and_then(|body| body.metadata().exact_length());
    let has_body = body.is_some();
    let span = debug_span!(
        "http1.request.prepare",
        method = %method,
        protocol = "http/1.1",
        body_bytes = field::Empty,
        has_body,
        outcome = field::Empty,
        error_kind = field::Empty,
    );
    if let Some(body_bytes) = body_bytes {
        span.record("body_bytes", body_bytes);
    }
    let outcome = OperationOutcome::new(&span);
    let prepared = {
        let _entered = span.enter();
        PreparedRequest::new_forward_body(method, target, headers, body)
    };
    match &prepared {
        Ok(_) => outcome.finish("ok"),
        Err(error) => outcome.finish_with_error_kind("error", error.trace_kind()),
    }
    let prepared = prepared?;
    send_prepared_request(stream, prepared).await
}

/// Sends an absolute-form body followed by exact ordered trailers.
///
/// Validation completes before the body is polled or the stream is touched.
pub async fn send_forward_request_body_with_trailers<T>(
    stream: T,
    method: Method,
    target: AbsoluteForm,
    headers: Vec<RequestHeader>,
    body: Option<RequestBody>,
    trailers: Vec<RequestHeader>,
) -> Result<Response<Http1Body>, Http1Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let prepared =
        PreparedRequest::new_forward_body_with_trailers(method, target, headers, body, trailers)?;
    send_prepared_request(stream, prepared).await
}

/// Validates an empty-body HTTP/1.1 GET without performing I/O.
pub fn validate_get(target: &OriginForm, headers: &[RequestHeader]) -> Result<(), Http1Error> {
    validate_request(&Method::GET, target, headers, None)
}

/// Validates an HTTP/1.1 request without performing I/O.
pub fn validate_request(
    method: &Method,
    target: &OriginForm,
    headers: &[RequestHeader],
    body: Option<&Bytes>,
) -> Result<(), Http1Error> {
    validate_request_body(
        method,
        target,
        headers,
        Some(RequestBody::from_bytes(body.cloned().unwrap_or_default()).metadata()),
    )
}

/// Validates an HTTP/1.1 request and body framing metadata without performing I/O.
pub fn validate_request_body(
    method: &Method,
    target: &OriginForm,
    headers: &[RequestHeader],
    body: Option<RequestBodyMetadata>,
) -> Result<(), Http1Error> {
    PreparedRequest::validate(method.clone(), target.clone(), headers.to_vec(), body)
}

/// Validates an HTTP/1.1 request, body framing, and exact ordered trailers.
pub fn validate_request_body_with_trailers(
    method: &Method,
    target: &OriginForm,
    headers: &[RequestHeader],
    body: Option<RequestBodyMetadata>,
    trailers: &[RequestHeader],
) -> Result<(), Http1Error> {
    PreparedRequest::validate_with_trailers(
        method.clone(),
        target.clone(),
        headers.to_vec(),
        body,
        trailers.to_vec(),
    )
}

/// Validates an HTTP/1.1 absolute-form request without performing I/O.
pub fn validate_forward_request(
    method: &Method,
    target: &AbsoluteForm,
    headers: &[RequestHeader],
    body: Option<&Bytes>,
) -> Result<(), Http1Error> {
    validate_forward_request_body(
        method,
        target,
        headers,
        Some(RequestBody::from_bytes(body.cloned().unwrap_or_default()).metadata()),
    )
}

/// Validates an absolute-form request and body framing metadata without I/O.
pub fn validate_forward_request_body(
    method: &Method,
    target: &AbsoluteForm,
    headers: &[RequestHeader],
    body: Option<RequestBodyMetadata>,
) -> Result<(), Http1Error> {
    PreparedRequest::validate_forward(method.clone(), target.clone(), headers.to_vec(), body)
}

/// Validates an absolute-form request, body framing, and ordered trailers.
pub fn validate_forward_request_body_with_trailers(
    method: &Method,
    target: &AbsoluteForm,
    headers: &[RequestHeader],
    body: Option<RequestBodyMetadata>,
    trailers: &[RequestHeader],
) -> Result<(), Http1Error> {
    PreparedRequest::validate_forward_with_trailers(
        method.clone(),
        target.clone(),
        headers.to_vec(),
        body,
        trailers.to_vec(),
    )
}

async fn send_prepared_request<T>(
    stream: T,
    prepared: PreparedRequest,
) -> Result<Response<Http1Body>, Http1Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    Http1Connection::connect(stream)
        .await?
        .send_prepared_request(prepared)
        .await
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
            let outcome = if std::thread::panicking() {
                "panicked"
            } else {
                "cancelled"
            };
            self.span.record("outcome", outcome);
        }
    }
}

#[cfg(test)]
mod tests;

mod body;
mod connection;
mod driver;
mod limits;
mod request;
mod response_head;
mod tls;
mod upgrade;

pub use tls::{Http1TlsConnector, Http1TlsError, TlsError, TlsErrorKind};
