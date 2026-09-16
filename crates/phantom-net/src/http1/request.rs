//! HTTP/1.1 request preparation and ordered header serialization.

use bytes::Bytes;
use http::{
    HeaderMap, HeaderValue, Method, Request, Version,
    header::{CONNECTION, CONTENT_LENGTH, HOST, HeaderName, TRANSFER_ENCODING},
};
use http_body_util::Empty;
use wreq_proto::ext::{OnPreserveHeaderCallback, on_preserve_header};

use super::{Http1Error, OriginForm, RequestHeader};

pub(super) const MAX_REQUEST_HEADERS: usize = 100;
pub(super) const MAX_REQUEST_HEADER_BYTES: usize = 32 * 1024;

pub(super) struct PreparedGet {
    request: Request<Empty<Bytes>>,
    allows_reuse: bool,
}

impl PreparedGet {
    pub(super) fn new(target: OriginForm, headers: Vec<RequestHeader>) -> Result<Self, Http1Error> {
        let headers = ValidatedHeaders::new(headers)?;
        let mut request = Request::new(Empty::<Bytes>::new());
        *request.method_mut() = Method::GET;
        *request.uri_mut() = target.into_uri();
        *request.version_mut() = Version::HTTP_11;

        headers.populate(request.headers_mut());
        let allows_reuse = !headers
            .semantic
            .iter()
            .filter(|(name, _)| name == CONNECTION)
            .any(|(_, value)| header_has_token(value, "close"));
        on_preserve_header(&mut request, headers.order);
        Ok(Self {
            request,
            allows_reuse,
        })
    }

    pub(super) fn into_request(self) -> Request<Empty<Bytes>> {
        self.request
    }

    pub(super) const fn allows_reuse(&self) -> bool {
        self.allows_reuse
    }
}

fn header_has_token(value: &HeaderValue, token: &str) -> bool {
    value.to_str().is_ok_and(|value| {
        value
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case(token))
    })
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
