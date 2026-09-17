//! HTTP/1.1 request preparation and ordered header serialization.

use bytes::Bytes;
use http::{
    HeaderMap, HeaderValue, Method, Request, Version,
    header::{CONNECTION, CONTENT_LENGTH, HOST, HeaderName, TRANSFER_ENCODING},
};
use http_body_util::{Empty, Full};
use wreq_proto::ext::{OnPreserveHeaderCallback, on_preserve_header};

use super::{AbsoluteForm, Http1Error, OriginForm, RequestHeader};

pub(super) const MAX_REQUEST_HEADERS: usize = 100;
pub(super) const MAX_REQUEST_HEADER_BYTES: usize = 32 * 1024;

pub(super) struct PreparedRequest {
    request: Request<Full<Bytes>>,
    allows_reuse: bool,
    body_len: usize,
    has_body: bool,
}

impl PreparedRequest {
    pub(super) fn new(
        method: Method,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Self, Http1Error> {
        Self::from_uri(method, target.into_uri(), headers, body, None)
    }

    pub(super) fn new_forward(
        method: Method,
        target: AbsoluteForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Self, Http1Error> {
        let authority = target.authority().to_owned();
        Self::from_uri(method, target.into_uri(), headers, body, Some(&authority))
    }

    fn from_uri(
        method: Method,
        target: http::Uri,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
        expected_host: Option<&str>,
    ) -> Result<Self, Http1Error> {
        if method == Method::CONNECT {
            return Err(Http1Error::ConnectUnsupported);
        }

        let has_body = body.is_some();
        let body = body.unwrap_or_default();
        let body_len = body.len();
        let headers = ValidatedHeaders::new(headers, Some(body.len()), expected_host)?;
        let mut request = Request::new(Full::new(body));
        *request.method_mut() = method;
        *request.uri_mut() = target;
        *request.version_mut() = Version::HTTP_11;

        headers.populate(request.headers_mut());
        let allows_reuse = headers.allows_reuse();
        on_preserve_header(&mut request, headers.order);
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

    pub(super) fn into_request(self) -> Request<Full<Bytes>> {
        self.request
    }

    pub(super) const fn allows_reuse(&self) -> bool {
        self.allows_reuse
    }

    pub(super) const fn body_len(&self) -> usize {
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
        let headers = ValidatedHeaders::new(headers, None, None)?;
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
        body_len: Option<usize>,
        expected_host: Option<&str>,
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
        let expected_content_length = body_len.map(|length| length.to_string());
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
            } else if name == CONNECTION
                && ["host", "content-length", "transfer-encoding"]
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

        if let Some(length) =
            body_len.filter(|length| *length > 0 && content_length_index.is_none())
        {
            let value = HeaderValue::from_str(&length.to_string()).map_err(|_| {
                Http1Error::InvalidContentLength {
                    index: semantic.len(),
                }
            })?;
            total_bytes = total_bytes
                .checked_add(CONTENT_LENGTH.as_str().len() + value.len())
                .ok_or(Http1Error::HeadersTooLarge {
                    bytes: usize::MAX,
                    maximum: MAX_REQUEST_HEADER_BYTES,
                })?;
            if semantic.len() == MAX_REQUEST_HEADERS {
                return Err(Http1Error::TooManyHeaders {
                    count: semantic.len() + 1,
                    maximum: MAX_REQUEST_HEADERS,
                });
            }
            if total_bytes > MAX_REQUEST_HEADER_BYTES {
                return Err(Http1Error::HeadersTooLarge {
                    bytes: total_bytes,
                    maximum: MAX_REQUEST_HEADER_BYTES,
                });
            }
            ordered.push((Box::from(b"Content-Length".as_slice()), value.clone()));
            semantic.push((CONTENT_LENGTH, value));
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
