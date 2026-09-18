//! HTTP/1.1 request preparation and ordered field serialization.

use std::{
    collections::HashSet,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::{
    HeaderMap, HeaderValue, Method, Request, Version,
    header::{
        AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
        CONTENT_TYPE, HOST, HeaderName, MAX_FORWARDS, SET_COOKIE, TE, TRAILER, TRANSFER_ENCODING,
        UPGRADE,
    },
};
use http_body::{Body, Frame, SizeHint};
use http_body_util::Empty;
use wreq_proto::ext::{
    OnPreserveHeaderCallback, OnPreserveTrailerCallback, on_preserve_header, on_preserve_trailer,
};

use super::{AbsoluteForm, Http1Error, OriginForm, RequestHeader};
use crate::request::{RequestBody, RequestBodyMetadata};

pub(super) const MAX_REQUEST_HEADERS: usize = 100;
pub(super) const MAX_REQUEST_HEADER_BYTES: usize = 32 * 1024;
pub(super) const MAX_REQUEST_TRAILERS: usize = 100;
pub(super) const MAX_REQUEST_TRAILER_BYTES: usize = 32 * 1024;

pub(super) struct PreparedRequest {
    request: Request<Http1RequestBody>,
    allows_reuse: bool,
    body_len: Option<u64>,
    has_body: bool,
}

impl PreparedRequest {
    pub(super) fn validate(
        method: Method,
        _target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<RequestBodyMetadata>,
    ) -> Result<(), Http1Error> {
        Self::validate_with_trailers(method, _target, headers, body, Vec::new())
    }

    pub(super) fn validate_with_trailers(
        method: Method,
        _target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<RequestBodyMetadata>,
        trailers: Vec<RequestHeader>,
    ) -> Result<(), Http1Error> {
        Self::validate_uri(method, headers, body, trailers, None)
    }

    pub(super) fn validate_forward(
        method: Method,
        target: AbsoluteForm,
        headers: Vec<RequestHeader>,
        body: Option<RequestBodyMetadata>,
    ) -> Result<(), Http1Error> {
        Self::validate_forward_with_trailers(method, target, headers, body, Vec::new())
    }

    pub(super) fn validate_forward_with_trailers(
        method: Method,
        target: AbsoluteForm,
        headers: Vec<RequestHeader>,
        body: Option<RequestBodyMetadata>,
        trailers: Vec<RequestHeader>,
    ) -> Result<(), Http1Error> {
        Self::validate_uri(method, headers, body, trailers, Some(target.authority()))
    }

    fn validate_uri(
        method: Method,
        headers: Vec<RequestHeader>,
        body: Option<RequestBodyMetadata>,
        trailers: Vec<RequestHeader>,
        expected_host: Option<&str>,
    ) -> Result<(), Http1Error> {
        if method == Method::CONNECT {
            return Err(Http1Error::ConnectUnsupported);
        }
        let trailers = ValidatedTrailers::new(trailers)?;
        ValidatedHeaders::new(headers, body, expected_host, trailers.as_ref()).map(drop)
    }

    pub(super) fn new(
        method: Method,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Self, Http1Error> {
        Self::new_with_trailers(method, target, headers, body, Vec::new())
    }

    pub(super) fn new_with_trailers(
        method: Method,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
        trailers: Vec<RequestHeader>,
    ) -> Result<Self, Http1Error> {
        let has_body = body.is_some();
        let body = RequestBody::from_bytes(body.unwrap_or_default());
        let metadata = body.metadata();
        Self::from_uri(
            method,
            target.into_uri(),
            headers,
            body,
            has_body,
            Some(metadata),
            trailers,
            None,
        )
    }

    pub(super) fn new_body(
        method: Method,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<RequestBody>,
    ) -> Result<Self, Http1Error> {
        Self::new_body_with_trailers(method, target, headers, body, Vec::new())
    }

    pub(super) fn new_body_with_trailers(
        method: Method,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<RequestBody>,
        trailers: Vec<RequestHeader>,
    ) -> Result<Self, Http1Error> {
        let has_body = body.is_some();
        let metadata = body.as_ref().map(RequestBody::metadata);
        let body = body.unwrap_or_else(|| RequestBody::from_bytes(Bytes::new()));
        Self::from_uri(
            method,
            target.into_uri(),
            headers,
            body,
            has_body,
            metadata,
            trailers,
            None,
        )
    }

    pub(super) fn new_forward(
        method: Method,
        target: AbsoluteForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Self, Http1Error> {
        Self::new_forward_with_trailers(method, target, headers, body, Vec::new())
    }

    pub(super) fn new_forward_with_trailers(
        method: Method,
        target: AbsoluteForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
        trailers: Vec<RequestHeader>,
    ) -> Result<Self, Http1Error> {
        let has_body = body.is_some();
        let body = RequestBody::from_bytes(body.unwrap_or_default());
        let metadata = body.metadata();
        let authority = target.authority().to_owned();
        Self::from_uri(
            method,
            target.into_uri(),
            headers,
            body,
            has_body,
            Some(metadata),
            trailers,
            Some(&authority),
        )
    }

    pub(super) fn new_forward_body(
        method: Method,
        target: AbsoluteForm,
        headers: Vec<RequestHeader>,
        body: Option<RequestBody>,
    ) -> Result<Self, Http1Error> {
        Self::new_forward_body_with_trailers(method, target, headers, body, Vec::new())
    }

    pub(super) fn new_forward_body_with_trailers(
        method: Method,
        target: AbsoluteForm,
        headers: Vec<RequestHeader>,
        body: Option<RequestBody>,
        trailers: Vec<RequestHeader>,
    ) -> Result<Self, Http1Error> {
        let has_body = body.is_some();
        let metadata = body.as_ref().map(RequestBody::metadata);
        let body = body.unwrap_or_else(|| RequestBody::from_bytes(Bytes::new()));
        let authority = target.authority().to_owned();
        Self::from_uri(
            method,
            target.into_uri(),
            headers,
            body,
            has_body,
            metadata,
            trailers,
            Some(&authority),
        )
    }

    fn from_uri(
        method: Method,
        target: http::Uri,
        headers: Vec<RequestHeader>,
        body: RequestBody,
        has_body: bool,
        metadata: Option<RequestBodyMetadata>,
        trailers: Vec<RequestHeader>,
        expected_host: Option<&str>,
    ) -> Result<Self, Http1Error> {
        if method == Method::CONNECT {
            return Err(Http1Error::ConnectUnsupported);
        }
        let body_len = metadata.and_then(RequestBodyMetadata::exact_length);
        let trailers = ValidatedTrailers::new(trailers)?;
        let headers = ValidatedHeaders::new(headers, metadata, expected_host, trailers.as_ref())?;
        let mut request = Request::new(Http1RequestBody::new(body, trailers.is_some()));
        *request.method_mut() = method;
        *request.uri_mut() = target;
        *request.version_mut() = Version::HTTP_11;

        headers.populate(request.headers_mut());
        let allows_reuse = headers.allows_reuse();
        on_preserve_header(&mut request, headers.order);
        if let Some(trailers) = trailers {
            on_preserve_trailer(&mut request, trailers);
        }
        Ok(Self {
            request,
            allows_reuse,
            body_len,
            has_body,
        })
    }

    pub(super) fn method(&self) -> &Method {
        self.request.method()
    }

    pub(super) fn into_request(self) -> Request<Http1RequestBody> {
        self.request
    }

    pub(super) const fn allows_reuse(&self) -> bool {
        self.allows_reuse
    }

    pub(super) const fn body_len(&self) -> Option<u64> {
        self.body_len
    }

    pub(super) const fn has_body(&self) -> bool {
        self.has_body
    }
}

pub(super) struct PreparedGet {
    request: Request<Empty<Bytes>>,
}

impl PreparedGet {
    pub(super) fn new(target: OriginForm, headers: Vec<RequestHeader>) -> Result<Self, Http1Error> {
        let headers = ValidatedHeaders::new(headers, None, None, None)?;
        let mut request = Request::new(Empty::<Bytes>::new());
        *request.method_mut() = Method::GET;
        *request.uri_mut() = target.into_uri();
        *request.version_mut() = Version::HTTP_11;

        headers.populate(request.headers_mut());
        on_preserve_header(&mut request, headers.order);
        Ok(Self { request })
    }

    pub(super) fn into_request(self) -> Request<Empty<Bytes>> {
        self.request
    }
}

pub(super) struct Http1RequestBody {
    inner: RequestBody,
    trailer_marker_pending: bool,
}

impl Http1RequestBody {
    fn new(inner: RequestBody, trailer_marker_pending: bool) -> Self {
        Self {
            inner,
            trailer_marker_pending,
        }
    }
}

impl Body for Http1RequestBody {
    type Data = Bytes;
    type Error = crate::request::RequestBodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(context) {
            Poll::Ready(None) if self.trailer_marker_pending => {
                self.trailer_marker_pending = false;
                Poll::Ready(Some(Ok(Frame::trailers(HeaderMap::new()))))
            }
            result => result,
        }
    }

    fn is_end_stream(&self) -> bool {
        !self.trailer_marker_pending && self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

fn header_has_token(value: &HeaderValue, token: &str) -> bool {
    value.as_bytes().split(|byte| *byte == b',').any(|value| {
        let start = value
            .iter()
            .position(|byte| !matches!(byte, b' ' | b'\t'))
            .unwrap_or(value.len());
        let end = value
            .iter()
            .rposition(|byte| !matches!(byte, b' ' | b'\t'))
            .map_or(start, |index| index + 1);
        value[start..end].eq_ignore_ascii_case(token.as_bytes())
    })
}

struct ValidatedHeaders {
    semantic: Vec<(HeaderName, HeaderValue)>,
    order: OrderedHeaders,
}

impl ValidatedHeaders {
    fn new(
        headers: Vec<RequestHeader>,
        body: Option<RequestBodyMetadata>,
        expected_host: Option<&str>,
        trailers: Option<&ValidatedTrailers>,
    ) -> Result<Self, Http1Error> {
        if headers.len() > MAX_REQUEST_HEADERS {
            return Err(Http1Error::TooManyHeaders {
                count: headers.len(),
                maximum: MAX_REQUEST_HEADERS,
            });
        }

        let mut total_bytes = 0usize;
        let mut host_count = 0usize;
        let mut content_length_index = None;
        let mut trailer_declaration_index = None;
        let mut declared_trailers = Vec::new();
        let expected_content_length = match body {
            None => Some(String::from("0")),
            Some(metadata) => metadata.exact_length().map(|length| length.to_string()),
        };
        let has_trailers = trailers.is_some();
        let unknown_body = body.is_some_and(|metadata| metadata.exact_length().is_none());
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
            let mut value = HeaderValue::from_bytes(header.value()).map_err(|_| {
                Http1Error::InvalidHeaderValue {
                    index,
                    name: header.name().into(),
                }
            })?;
            value.set_sensitive(header.is_sensitive());

            if name == HOST {
                host_count += 1;
                if host_count > 1 {
                    return Err(Http1Error::MultipleHost);
                }
                if expected_host.is_some_and(|expected| {
                    !value.as_bytes().eq_ignore_ascii_case(expected.as_bytes())
                }) {
                    return Err(Http1Error::MismatchedHost { index });
                }
            } else if name == TRANSFER_ENCODING {
                return Err(Http1Error::RequestFramingHeader {
                    name: header.name().into(),
                });
            } else if name == CONTENT_LENGTH {
                if has_trailers {
                    return Err(Http1Error::RequestTrailersWithContentLength { index });
                }
                let Some(expected) = expected_content_length.as_ref() else {
                    return Err(Http1Error::RequestFramingHeader {
                        name: header.name().into(),
                    });
                };
                if content_length_index.is_some() {
                    return Err(Http1Error::DuplicateContentLength { index });
                }
                content_length_index = Some(index);
                if value.as_bytes() != expected.as_bytes() {
                    return Err(Http1Error::InvalidContentLength { index });
                }
            } else if name == TRAILER {
                trailer_declaration_index.get_or_insert(index);
                for token in value.as_bytes().split(|byte| *byte == b',') {
                    let token = trim_ascii_whitespace(token);
                    let declared = HeaderName::from_bytes(token)
                        .map_err(|_| Http1Error::InvalidTrailerDeclaration { index })?;
                    if !declared_trailers.contains(&declared) {
                        declared_trailers.push(declared);
                    }
                }
            } else if name == CONNECTION
                && ["host", "content-length", "transfer-encoding", "trailer"]
                    .into_iter()
                    .any(|token| header_has_token(&value, token))
            {
                return Err(Http1Error::ConnectionNominatesCriticalField { index });
            }

            ordered.push((header.name().as_bytes().into(), value.clone()));
            semantic.push((name, value));
        }

        if host_count == 0 {
            return Err(Http1Error::MissingHost);
        }

        match (trailer_declaration_index, trailers) {
            (Some(index), Some(trailers)) if declared_trailers != trailers.declared_names => {
                return Err(Http1Error::InvalidTrailerDeclaration { index });
            }
            (Some(index), None) => {
                return Err(Http1Error::InvalidTrailerDeclaration { index });
            }
            _ => {}
        }

        if unknown_body || has_trailers {
            append_generated_header(
                &mut semantic,
                &mut ordered,
                &mut total_bytes,
                TRANSFER_ENCODING,
                b"Transfer-Encoding",
                HeaderValue::from_static("chunked"),
            )?;
        } else if let Some(length) =
            expected_content_length.filter(|length| length != "0" && content_length_index.is_none())
        {
            let value =
                HeaderValue::from_str(&length).map_err(|_| Http1Error::InvalidContentLength {
                    index: semantic.len(),
                })?;
            append_generated_header(
                &mut semantic,
                &mut ordered,
                &mut total_bytes,
                CONTENT_LENGTH,
                b"Content-Length",
                value,
            )?;
        }

        if let Some(trailers) = trailers.filter(|_| trailer_declaration_index.is_none()) {
            append_generated_header(
                &mut semantic,
                &mut ordered,
                &mut total_bytes,
                TRAILER,
                b"Trailer",
                HeaderValue::from_bytes(trailers.declaration.as_bytes()).map_err(|_| {
                    Http1Error::InvalidTrailerDeclaration {
                        index: semantic.len(),
                    }
                })?,
            )?;
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

    fn allows_reuse(&self) -> bool {
        !self
            .semantic
            .iter()
            .filter(|(name, _)| name == CONNECTION)
            .any(|(_, value)| header_has_token(value, "close"))
    }
}

fn trim_ascii_whitespace(value: &[u8]) -> &[u8] {
    let start = value
        .iter()
        .position(|byte| !matches!(byte, b' ' | b'\t'))
        .unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|byte| !matches!(byte, b' ' | b'\t'))
        .map_or(start, |index| index + 1);
    &value[start..end]
}

#[derive(Clone)]
struct ValidatedTrailers {
    ordered: Vec<(Box<[u8]>, HeaderValue)>,
    declared_names: Vec<HeaderName>,
    declaration: String,
}

impl ValidatedTrailers {
    fn new(trailers: Vec<RequestHeader>) -> Result<Option<Self>, Http1Error> {
        if trailers.is_empty() {
            return Ok(None);
        }
        if trailers.len() > MAX_REQUEST_TRAILERS {
            return Err(Http1Error::TooManyTrailers {
                count: trailers.len(),
                maximum: MAX_REQUEST_TRAILERS,
            });
        }

        let mut total_bytes = 0usize;
        let mut ordered = Vec::with_capacity(trailers.len());
        let mut declared_names = Vec::new();
        let mut seen = HashSet::new();
        let mut declaration_names = Vec::new();
        for (index, trailer) in trailers.into_iter().enumerate() {
            total_bytes = total_bytes
                .checked_add(trailer.name().len())
                .and_then(|size| size.checked_add(trailer.value().len()))
                .ok_or(Http1Error::TrailersTooLarge {
                    bytes: usize::MAX,
                    maximum: MAX_REQUEST_TRAILER_BYTES,
                })?;
            if total_bytes > MAX_REQUEST_TRAILER_BYTES {
                return Err(Http1Error::TrailersTooLarge {
                    bytes: total_bytes,
                    maximum: MAX_REQUEST_TRAILER_BYTES,
                });
            }
            let name = HeaderName::from_bytes(trailer.name().as_bytes())
                .map_err(|_| Http1Error::InvalidTrailerName { index })?;
            if !trailer
                .name()
                .as_bytes()
                .eq_ignore_ascii_case(name.as_str().as_bytes())
            {
                return Err(Http1Error::InvalidTrailerName { index });
            }
            if is_forbidden_trailer(&name) {
                return Err(Http1Error::ForbiddenTrailer {
                    index,
                    name: trailer.name().into(),
                });
            }
            let mut value = HeaderValue::from_bytes(trailer.value()).map_err(|_| {
                Http1Error::InvalidTrailerValue {
                    index,
                    name: trailer.name().into(),
                }
            })?;
            value.set_sensitive(trailer.is_sensitive());
            if seen.insert(name.clone()) {
                declared_names.push(name);
                declaration_names.push(trailer.name().to_owned());
            }
            ordered.push((trailer.name().as_bytes().into(), value));
        }

        Ok(Some(Self {
            ordered,
            declared_names,
            declaration: declaration_names.join(", "),
        }))
    }
}

fn is_forbidden_trailer(name: &HeaderName) -> bool {
    matches!(
        *name,
        AUTHORIZATION
            | CACHE_CONTROL
            | CONTENT_ENCODING
            | CONTENT_LENGTH
            | CONTENT_RANGE
            | CONTENT_TYPE
            | HOST
            | MAX_FORWARDS
            | SET_COOKIE
            | TRAILER
            | TRANSFER_ENCODING
            | TE
            | CONNECTION
            | UPGRADE
    ) || matches!(name.as_str(), "keep-alive" | "proxy-connection")
}

impl OnPreserveTrailerCallback for ValidatedTrailers {
    fn call_visit(&self, destination: &mut dyn FnMut(&dyn AsRef<[u8]>, &HeaderValue)) {
        for (name, value) in &self.ordered {
            destination(name, value);
        }
    }
}

fn append_generated_header(
    semantic: &mut Vec<(HeaderName, HeaderValue)>,
    ordered: &mut Vec<(Box<[u8]>, HeaderValue)>,
    total_bytes: &mut usize,
    name: HeaderName,
    wire_name: &'static [u8],
    value: HeaderValue,
) -> Result<(), Http1Error> {
    if semantic.len() == MAX_REQUEST_HEADERS {
        return Err(Http1Error::TooManyHeaders {
            count: semantic.len() + 1,
            maximum: MAX_REQUEST_HEADERS,
        });
    }
    *total_bytes = total_bytes
        .checked_add(wire_name.len() + value.len())
        .ok_or(Http1Error::HeadersTooLarge {
            bytes: usize::MAX,
            maximum: MAX_REQUEST_HEADER_BYTES,
        })?;
    if *total_bytes > MAX_REQUEST_HEADER_BYTES {
        return Err(Http1Error::HeadersTooLarge {
            bytes: *total_bytes,
            maximum: MAX_REQUEST_HEADER_BYTES,
        });
    }
    ordered.push((Box::from(wire_name), value.clone()));
    semantic.push((name, value));
    Ok(())
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
