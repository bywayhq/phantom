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
    HeaderMap, HeaderValue, Method, Request, Response, Version,
    header::{CONTENT_LENGTH, HOST, HeaderName, TRANSFER_ENCODING},
};
use http_body_util::Empty;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, Span, debug, debug_span, field};
use wreq_proto::{
    conn::http1,
    ext::{OnPreserveHeaderCallback, on_preserve_header},
};

use body::DriverTask;

pub use crate::request::{OriginForm, RequestHeader};
pub use body::Http1Body;

const MAX_REQUEST_HEADERS: usize = 100;
const MAX_REQUEST_HEADER_BYTES: usize = 32 * 1024;

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
    let outcome = ResponseHeadOutcome::new(&span);
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

struct PreparedGet {
    request: Request<Empty<Bytes>>,
}

impl PreparedGet {
    fn new(target: OriginForm, headers: Vec<RequestHeader>) -> Result<Self, Http1Error> {
        let headers = ValidatedHeaders::new(headers)?;
        let mut request = Request::new(Empty::<Bytes>::new());
        *request.method_mut() = Method::GET;
        *request.uri_mut() = target.into_uri();
        *request.version_mut() = Version::HTTP_11;

        headers.populate(request.headers_mut());
        on_preserve_header(&mut request, headers.order);
        Ok(Self { request })
    }
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
    let outcome = ResponseHeadOutcome::new(&span);
    let result = async {
        debug!("HTTP/1 transaction started");
        let (mut sender, connection) = http1::Builder::default()
            .handshake::<_, Empty<Bytes>>(stream)
            .await?;
        let driver = DriverTask::spawn(connection);

        sender.ready().await?;
        let response = sender
            .try_send_request(prepared.request)
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

pub(super) struct ResponseHeadOutcome {
    span: Span,
    recorded: bool,
}

impl ResponseHeadOutcome {
    fn new(span: &Span) -> Self {
        Self {
            span: span.clone(),
            recorded: false,
        }
    }

    pub(super) fn finish(mut self, outcome: &'static str) {
        self.span.record("outcome", outcome);
        self.recorded = true;
    }

    fn finish_with_error_kind(mut self, outcome: &'static str, error_kind: &'static str) {
        self.span.record("outcome", outcome);
        self.span.record("error_kind", error_kind);
        self.recorded = true;
    }
}

impl Drop for ResponseHeadOutcome {
    fn drop(&mut self) {
        if !self.recorded {
            self.span.record("outcome", "cancelled");
        }
    }
}

struct ValidatedHeaders {
    semantic: Vec<(HeaderName, HeaderValue)>,
    order: OrderedHeaders,
}

impl ValidatedHeaders {
    fn new(headers: Vec<RequestHeader>) -> Result<Self, Http1Error> {
        if headers.len() > MAX_REQUEST_HEADERS {
            return Err(Http1Error::TooManyHeaders {
                count: headers.len(),
                maximum: MAX_REQUEST_HEADERS,
            });
        }

        let mut total_bytes = 0usize;
        let mut host_count = 0usize;
        let mut semantic = Vec::with_capacity(headers.len());
        let mut ordered = Vec::with_capacity(headers.len());

        for (index, header) in headers.into_iter().enumerate() {
            total_bytes = total_bytes
                .checked_add(header.name().len())
                .and_then(|size| size.checked_add(header.value().len()))
                .ok_or(Http1Error::HeadersTooLarge {
                    bytes: usize::MAX,
                    maximum: MAX_REQUEST_HEADER_BYTES,
                })?;
            if total_bytes > MAX_REQUEST_HEADER_BYTES {
                return Err(Http1Error::HeadersTooLarge {
                    bytes: total_bytes,
                    maximum: MAX_REQUEST_HEADER_BYTES,
                });
            }

            let name = HeaderName::from_bytes(header.name().as_bytes())
                .map_err(|_| Http1Error::InvalidHeaderName { index })?;
            if !header
                .name()
                .as_bytes()
                .eq_ignore_ascii_case(name.as_str().as_bytes())
            {
                return Err(Http1Error::InvalidHeaderName { index });
            }
            let value = HeaderValue::from_bytes(header.value()).map_err(|_| {
                Http1Error::InvalidHeaderValue {
                    index,
                    name: header.name().into(),
                }
            })?;

            if name == HOST {
                host_count += 1;
                if host_count > 1 {
                    return Err(Http1Error::MultipleHost);
                }
            } else if name == CONTENT_LENGTH || name == TRANSFER_ENCODING {
                return Err(Http1Error::RequestFramingHeader {
                    name: header.name().into(),
                });
            }

            ordered.push((header.name().as_bytes().into(), value.clone()));
            semantic.push((name, value));
        }

        if host_count == 0 {
            return Err(Http1Error::MissingHost);
        }

        Ok(Self {
            semantic,
            order: OrderedHeaders(ordered),
        })
    }

    fn populate(&self, target: &mut HeaderMap) {
        for (name, value) in &self.semantic {
            target.append(name, value.clone());
        }
    }
}

// This Vec is the sole authority for wire order and spelling. `semantic` in
// `ValidatedHeaders` must contain the same fields and values so wreq-proto sees
// accurate HTTP semantics while this callback controls serialization. Request
// bodies or middleware must add a regression proving that the two views remain
// aligned before extending this seam.
#[derive(Clone)]
struct OrderedHeaders(Vec<(Box<[u8]>, HeaderValue)>);

impl OnPreserveHeaderCallback for OrderedHeaders {
    fn call(&self, _headers: &mut HeaderMap) {}

    fn call_visit(
        &self,
        _headers: &mut HeaderMap,
        destination: &mut dyn FnMut(&dyn AsRef<[u8]>, &HeaderValue),
    ) {
        for (name, value) in &self.0 {
            destination(name, value);
        }
    }
}

#[cfg(test)]
mod tests;

mod body;
mod tls;

pub use tls::{Http1TlsConnector, Http1TlsError, TlsError, TlsErrorKind};
