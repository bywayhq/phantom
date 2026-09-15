//! A one-shot HTTP/1.1 client transaction.
//!
//! This module deliberately owns no connection pool or TLS setup. Callers
//! supply an already-connected byte stream. Completing or dropping the body
//! schedules cancellation of the protocol task; destruction of the underlying
//! stream is eventual.

use std::{
    error::Error as StdError,
    fmt,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{
    HeaderMap, HeaderValue, Method, Request, Response, Uri, Version,
    header::{CONTENT_LENGTH, HOST, HeaderName, TRANSFER_ENCODING},
};
use http_body::{Body, Frame, SizeHint};
use http_body_util::Empty;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    task::JoinHandle,
};
use wreq_proto::{
    body::Incoming,
    conn::http1,
    ext::{OnPreserveHeaderCallback, on_preserve_header},
};

const MAX_REQUEST_HEADERS: usize = 100;
const MAX_REQUEST_HEADER_BYTES: usize = 32 * 1024;

/// An HTTP origin-form request target such as `/search?q=rust`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginForm(Uri);

impl OriginForm {
    /// Parses an origin-form request target.
    pub fn parse(value: &str) -> Result<Self, Http1Error> {
        let uri = value
            .parse::<Uri>()
            .map_err(|_| Http1Error::InvalidOriginForm)?;
        let is_origin_form = value.starts_with('/')
            && uri.scheme().is_none()
            && uri.authority().is_none()
            && uri
                .path_and_query()
                .is_some_and(|path_and_query| path_and_query.as_str() == value);

        if is_origin_form {
            Ok(Self(uri))
        } else {
            Err(Http1Error::InvalidOriginForm)
        }
    }
}

/// A request header whose spelling and position are preserved on the wire.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestHeader {
    name: Box<str>,
    value: Box<[u8]>,
}

impl RequestHeader {
    /// Creates a header to be validated when the request is sent.
    ///
    /// Construction is intentionally infallible so validation of the complete
    /// ordered header list happens once, before the supplied stream is touched.
    #[must_use]
    pub fn new(name: impl Into<Box<str>>, value: impl AsRef<[u8]>) -> Self {
        Self {
            name: name.into(),
            value: value.as_ref().into(),
        }
    }

    /// Returns the exact field-name spelling that will be written.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the field value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Error returned by a one-shot HTTP/1.1 transaction.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http1Error {
    /// The request target was not valid HTTP origin-form.
    InvalidOriginForm,
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
            Self::InvalidOriginForm => formatter.write_str(
                "request target must be HTTP origin-form beginning with `/` and contain no authority or fragment",
            ),
            Self::TooManyHeaders { count, maximum } => {
                write!(formatter, "request has {count} headers; maximum is {maximum}")
            }
            Self::HeadersTooLarge { bytes, maximum } => write!(
                formatter,
                "request field names and values total {bytes} bytes; maximum is {maximum}"
            ),
            Self::InvalidHeaderName { index } => {
                write!(formatter, "request header at index {index} has an invalid field name")
            }
            Self::InvalidHeaderValue { index, name } => write!(
                formatter,
                "request header {name:?} at index {index} has an invalid field value"
            ),
            Self::MissingHost => formatter.write_str("request must contain exactly one Host header"),
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

/// Streaming response body for a one-shot HTTP/1.1 transaction.
///
/// Dropping this body schedules cancellation of the protocol driver. Once the
/// runtime observes that cancellation, dropping the driver tears down its byte
/// stream. `Drop` does not wait for teardown to finish.
#[must_use = "response bodies must be read or deliberately dropped"]
pub struct Http1Body {
    incoming: Incoming,
    driver: DriverTask,
    finished: bool,
}

impl fmt::Debug for Http1Body {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Http1Body")
            .field("finished", &self.finished)
            .finish_non_exhaustive()
    }
}

impl Body for Http1Body {
    type Data = Bytes;
    type Error = Http1Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.incoming).poll_frame(context) {
            Poll::Ready(Some(Ok(frame))) => {
                if self.incoming.is_end_stream() {
                    self.finished = true;
                    self.driver.cancel();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.finished = true;
                self.driver.cancel();
                Poll::Ready(Some(Err(Http1Error::Protocol(error))))
            }
            Poll::Ready(None) => {
                self.finished = true;
                self.driver.cancel();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished || self.incoming.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.incoming.size_hint()
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
    let headers = ValidatedHeaders::new(headers)?;
    let mut request = Request::builder()
        .method(Method::GET)
        .uri(target.0)
        .version(Version::HTTP_11)
        .body(Empty::<Bytes>::new())
        .map_err(|_| Http1Error::InvalidOriginForm)?;

    headers.populate(request.headers_mut());
    on_preserve_header(&mut request, headers.order);

    let (mut sender, connection) = http1::Builder::default()
        .handshake::<_, Empty<Bytes>>(stream)
        .await?;
    let driver = DriverTask::spawn(connection);

    sender.ready().await?;
    let response = sender
        .try_send_request(request)
        .await
        .map_err(|error| Http1Error::Protocol(error.into_error()))?;
    drop(sender);

    if response.headers().contains_key(TRANSFER_ENCODING)
        && response.headers().contains_key(CONTENT_LENGTH)
    {
        return Err(Http1Error::AmbiguousResponseFraming);
    }

    let (parts, incoming) = response.into_parts();
    let finished = incoming.is_end_stream();
    let mut driver = driver;
    if finished {
        driver.cancel();
    }
    Ok(Response::from_parts(
        parts,
        Http1Body {
            incoming,
            driver,
            finished,
        },
    ))
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
                .checked_add(header.name.len())
                .and_then(|size| size.checked_add(header.value.len()))
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

            let name = HeaderName::from_bytes(header.name.as_bytes())
                .map_err(|_| Http1Error::InvalidHeaderName { index })?;
            if !header
                .name
                .as_bytes()
                .eq_ignore_ascii_case(name.as_str().as_bytes())
            {
                return Err(Http1Error::InvalidHeaderName { index });
            }
            let value = HeaderValue::from_bytes(&header.value).map_err(|_| {
                Http1Error::InvalidHeaderValue {
                    index,
                    name: header.name.clone(),
                }
            })?;

            if name == HOST {
                host_count += 1;
                if host_count > 1 {
                    return Err(Http1Error::MultipleHost);
                }
            } else if name == CONTENT_LENGTH || name == TRANSFER_ENCODING {
                return Err(Http1Error::RequestFramingHeader { name: header.name });
            }

            ordered.push((header.name.as_bytes().into(), value.clone()));
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

/// Owns the connection driver and schedules its cancellation when dropped.
///
/// Cancellation is observed asynchronously by Tokio. Only then is the
/// connection future, and therefore its underlying stream, dropped.
struct DriverTask {
    handle: Option<JoinHandle<Result<(), wreq_proto::Error>>>,
}

impl DriverTask {
    // Aborting the task only schedules cancellation. The runtime later drops
    // the connection future and its stream; callers must not infer synchronous
    // transport teardown from this guard's `Drop`.
    fn spawn<T>(connection: http1::Connection<T, Empty<Bytes>>) -> Self
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        Self {
            handle: Some(tokio::spawn(connection)),
        }
    }

    fn cancel(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

impl Drop for DriverTask {
    fn drop(&mut self) {
        self.cancel();
    }
}

#[cfg(test)]
mod tests;
