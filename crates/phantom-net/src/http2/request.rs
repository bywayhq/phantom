//! Request construction and HTTP/2 field validation.

use ::http2::ext::OrderedHeaders;
use http::{
    HeaderMap, HeaderValue, Method, Request, Uri, Version,
    header::{
        CONNECTION, CONTENT_LENGTH, HOST, HeaderName, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
    },
    uri::Authority,
};

use super::{Http2Error, OriginForm, RequestHeader};

pub(super) const MAX_REQUEST_HEADERS: usize = 100;
pub(super) const MAX_REQUEST_HEADER_BYTES: usize = 32 * 1024;

pub(super) fn prepare_get(
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
) -> Result<Request<()>, Http2Error> {
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
    let headers = ValidatedHeaders::new(headers)?;

    let mut request = Request::new(());
    *request.method_mut() = Method::GET;
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
    fn new(headers: Vec<RequestHeader>) -> Result<Self, Http2Error> {
        if headers.len() > MAX_REQUEST_HEADERS {
            return Err(Http2Error::TooManyHeaders {
                count: headers.len(),
                maximum: MAX_REQUEST_HEADERS,
            });
        }

        let mut total_bytes = 0usize;
        let mut ordered = Vec::with_capacity(headers.len());
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
            let value = HeaderValue::from_bytes(header.value()).map_err(|_| {
                Http2Error::InvalidHeaderValue {
                    index,
                    name: header.name().into(),
                }
            })?;

            if name == TE {
                if value.as_bytes() != b"trailers" {
                    return Err(Http2Error::InvalidTe);
                }
            } else if name == CONTENT_LENGTH {
                if value.as_bytes() != b"0" {
                    return Err(Http2Error::InvalidContentLength { index });
                }
            } else if is_forbidden_header(&name) {
                return Err(Http2Error::ForbiddenHeader {
                    name: header.name().into(),
                });
            }

            ordered.push((name, value));
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
