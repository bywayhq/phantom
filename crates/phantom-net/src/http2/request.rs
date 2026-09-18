//! Request construction and HTTP/2 field validation.

use ::http2::ext::OrderedHeaders;
use http::{
    HeaderMap, HeaderValue, Method, Request, Uri, Version,
    header::{
        AUTHORIZATION, CACHE_CONTROL, CONNECTION, CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_RANGE,
        CONTENT_TYPE, HOST, HeaderName, MAX_FORWARDS, PROXY_AUTHORIZATION, SET_COOKIE, TE, TRAILER,
        TRANSFER_ENCODING, UPGRADE,
    },
    uri::Authority,
};

use super::{Http2Error, OriginForm, RequestBodyMetadata, RequestHeader};

pub(super) const MAX_REQUEST_HEADERS: usize = 100;
pub(super) const MAX_REQUEST_HEADER_BYTES: usize = 32 * 1024;

pub(super) struct PreparedRequestTrailers {
    semantic: HeaderMap,
    ordered: OrderedHeaders,
}

impl PreparedRequestTrailers {
    pub(super) fn new(trailers: Vec<RequestHeader>) -> Result<Option<Self>, Http2Error> {
        if trailers.is_empty() {
            return Ok(None);
        }
        if trailers.len() > MAX_REQUEST_HEADERS {
            return Err(Http2Error::TooManyTrailers {
                count: trailers.len(),
                maximum: MAX_REQUEST_HEADERS,
            });
        }

        let mut total_bytes = 0usize;
        let mut semantic = HeaderMap::new();
        let mut ordered = Vec::with_capacity(trailers.len());
        for (index, trailer) in trailers.into_iter().enumerate() {
            total_bytes = total_bytes
                .checked_add(trailer.name().len())
                .and_then(|size| size.checked_add(trailer.value().len()))
                .ok_or(Http2Error::TrailersTooLarge {
                    bytes: usize::MAX,
                    maximum: MAX_REQUEST_HEADER_BYTES,
                })?;
            if total_bytes > MAX_REQUEST_HEADER_BYTES {
                return Err(Http2Error::TrailersTooLarge {
                    bytes: total_bytes,
                    maximum: MAX_REQUEST_HEADER_BYTES,
                });
            }
            if !trailer
                .name()
                .bytes()
                .all(|byte| !byte.is_ascii_uppercase())
            {
                return Err(Http2Error::InvalidTrailerName { index });
            }
            let name = HeaderName::from_bytes(trailer.name().as_bytes())
                .map_err(|_| Http2Error::InvalidTrailerName { index })?;
            if is_forbidden_trailer(&name) {
                return Err(Http2Error::ForbiddenTrailer {
                    name: trailer.name().into(),
                });
            }
            let mut value = HeaderValue::from_bytes(trailer.value()).map_err(|_| {
                Http2Error::InvalidTrailerValue {
                    index,
                    name: trailer.name().into(),
                }
            })?;
            value.set_sensitive(trailer.is_sensitive());
            semantic
                .try_append(name.clone(), value.clone())
                .map_err(|_| Http2Error::HeaderMapCapacity)?;
            ordered.push((name, value));
        }

        Ok(Some(Self {
            semantic,
            ordered: OrderedHeaders::new(ordered),
        }))
    }

    pub(super) fn into_parts(self) -> (HeaderMap, OrderedHeaders) {
        (self.semantic, self.ordered)
    }
}

#[cfg(test)]
pub(super) fn prepare_get(
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
) -> Result<Request<()>, Http2Error> {
    prepare_request(Method::GET, authority, target, headers, None)
}

pub(super) fn prepare_request(
    method: Method,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
    body: Option<RequestBodyMetadata>,
) -> Result<Request<()>, Http2Error> {
    if method == Method::CONNECT {
        return Err(Http2Error::ConnectUnsupported);
    }
    if authority.as_bytes().contains(&b'@') {
        return Err(Http2Error::AuthorityContainsUserinfo);
    }
    let authority = authority
        .parse::<Authority>()
        .map_err(Http2Error::InvalidAuthority)?;
    let uri = Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(target.into_path_and_query())
        .build()
        .map_err(Http2Error::InvalidRequestUri)?;
    let headers = ValidatedHeaders::new(headers, body)?;

    let mut request = Request::new(());
    *request.method_mut() = method;
    *request.uri_mut() = uri;
    *request.version_mut() = Version::HTTP_2;
    headers.populate(request.headers_mut())?;
    request
        .extensions_mut()
        .insert(OrderedHeaders::new(headers.ordered));
    Ok(request)
}

struct ValidatedHeaders {
    ordered: Vec<(HeaderName, HeaderValue)>,
}

impl ValidatedHeaders {
    fn new(
        headers: Vec<RequestHeader>,
        body: Option<RequestBodyMetadata>,
    ) -> Result<Self, Http2Error> {
        if headers.len() > MAX_REQUEST_HEADERS {
            return Err(Http2Error::TooManyHeaders {
                count: headers.len(),
                maximum: MAX_REQUEST_HEADERS,
            });
        }

        let mut total_bytes = 0usize;
        let mut ordered = Vec::with_capacity(headers.len());
        let mut content_length_index = None;
        let exact_length = body.and_then(RequestBodyMetadata::exact_length);
        let expected_content_length = exact_length.unwrap_or(0).to_string();
        for (index, header) in headers.into_iter().enumerate() {
            total_bytes = total_bytes
                .checked_add(header.name().len())
                .and_then(|size| size.checked_add(header.value().len()))
                .ok_or(Http2Error::HeadersTooLarge {
                    bytes: usize::MAX,
                    maximum: MAX_REQUEST_HEADER_BYTES,
                })?;
            if total_bytes > MAX_REQUEST_HEADER_BYTES {
                return Err(Http2Error::HeadersTooLarge {
                    bytes: total_bytes,
                    maximum: MAX_REQUEST_HEADER_BYTES,
                });
            }

            if !header.name().bytes().all(|byte| !byte.is_ascii_uppercase()) {
                return Err(Http2Error::InvalidHeaderName { index });
            }
            let name = HeaderName::from_bytes(header.name().as_bytes())
                .map_err(|_| Http2Error::InvalidHeaderName { index })?;
            let mut value = HeaderValue::from_bytes(header.value()).map_err(|_| {
                Http2Error::InvalidHeaderValue {
                    index,
                    name: header.name().into(),
                }
            })?;
            value.set_sensitive(header.is_sensitive());

            if name == TE {
                if value.as_bytes() != b"trailers" {
                    return Err(Http2Error::InvalidTe);
                }
            } else if name == CONTENT_LENGTH {
                if content_length_index.is_some() {
                    return Err(Http2Error::DuplicateContentLength { index });
                }
                content_length_index = Some(index);
                if body.is_some() && exact_length.is_none() {
                    return Err(Http2Error::ContentLengthRequiresExactBody { index });
                }
                if value.as_bytes() != expected_content_length.as_bytes() {
                    return Err(Http2Error::InvalidContentLength { index });
                }
            } else if is_forbidden_header(&name) {
                return Err(Http2Error::ForbiddenHeader {
                    name: header.name().into(),
                });
            }

            ordered.push((name, value));
        }

        if exact_length.is_some_and(|length| length > 0) && content_length_index.is_none() {
            let count = ordered.len() + 1;
            if count > MAX_REQUEST_HEADERS {
                return Err(Http2Error::TooManyHeaders {
                    count,
                    maximum: MAX_REQUEST_HEADERS,
                });
            }
            total_bytes = total_bytes
                .checked_add(CONTENT_LENGTH.as_str().len())
                .and_then(|size| size.checked_add(expected_content_length.len()))
                .ok_or(Http2Error::HeadersTooLarge {
                    bytes: usize::MAX,
                    maximum: MAX_REQUEST_HEADER_BYTES,
                })?;
            if total_bytes > MAX_REQUEST_HEADER_BYTES {
                return Err(Http2Error::HeadersTooLarge {
                    bytes: total_bytes,
                    maximum: MAX_REQUEST_HEADER_BYTES,
                });
            }
            let value = HeaderValue::from_bytes(expected_content_length.as_bytes())
                .map_err(|_| Http2Error::InvalidContentLength { index: count - 1 })?;
            ordered.push((CONTENT_LENGTH, value));
        }

        Ok(Self { ordered })
    }

    fn populate(&self, target: &mut HeaderMap) -> Result<(), Http2Error> {
        for (name, value) in &self.ordered {
            target
                .try_append(name, value.clone())
                .map_err(|_| Http2Error::HeaderMapCapacity)?;
        }
        Ok(())
    }
}

fn is_forbidden_header(name: &HeaderName) -> bool {
    name == HOST
        || name == CONNECTION
        || name == TRANSFER_ENCODING
        || name == UPGRADE
        || name == TRAILER
        || name.as_str() == "keep-alive"
        || name.as_str() == "proxy-connection"
}

fn is_forbidden_trailer(name: &HeaderName) -> bool {
    name == HOST
        || name == AUTHORIZATION
        || name == CACHE_CONTROL
        || name == CONNECTION
        || name == CONTENT_ENCODING
        || name == CONTENT_LENGTH
        || name == CONTENT_RANGE
        || name == CONTENT_TYPE
        || name == MAX_FORWARDS
        || name == PROXY_AUTHORIZATION
        || name == SET_COOKIE
        || name == TE
        || name == TRANSFER_ENCODING
        || name == UPGRADE
        || name == TRAILER
        || name.as_str() == "keep-alive"
        || name.as_str() == "proxy-connection"
}
