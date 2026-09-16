//! HTTP/3 request construction and field validation.

use h3::ext::{OrderedHeaders, RequestPseudoHeader, RequestPseudoHeaderOrder};
use http::{
    HeaderMap, HeaderValue, Method, Request, Uri, Version,
    header::{
        CONNECTION, CONTENT_LENGTH, HOST, HeaderName, TE, TRAILER, TRANSFER_ENCODING, UPGRADE,
    },
    uri::{Authority, Scheme},
};
use phantom_profile::{Http3PseudoHeader, Http3RequestSettings};

use super::{Http3Error, Http3ErrorKind, OriginForm, RequestHeader};

pub(super) const MAX_REQUEST_HEADERS: usize = 100;
pub(super) const MAX_REQUEST_HEADER_BYTES: usize = 32 * 1024;

pub(super) fn prepare_get(
    request_settings: &Http3RequestSettings,
    authority: &str,
    target: OriginForm,
    headers: Vec<RequestHeader>,
) -> Result<Request<()>, Http3Error> {
    if authority.as_bytes().contains(&b'@') {
        return Err(invalid("HTTP/3 request authority contains userinfo"));
    }
    let authority = authority
        .parse::<Authority>()
        .map_err(|_| invalid("HTTP/3 request authority is invalid"))?;
    let uri = Uri::builder()
        .scheme("https")
        .authority(authority)
        .path_and_query(target.into_path_and_query())
        .build()
        .map_err(|_| invalid("HTTP/3 request URI is invalid"))?;
    let headers = ValidatedHeaders::new(headers)?;

    let mut request = Request::new(());
    *request.method_mut() = Method::GET;
    *request.uri_mut() = uri;
    *request.version_mut() = Version::HTTP_3;
    headers.populate(request.headers_mut())?;
    request
        .extensions_mut()
        .insert(OrderedHeaders::new(headers.ordered));
    request
        .extensions_mut()
        .insert(pseudo_header_order(request_settings)?);
    Ok(request)
}

pub(super) fn prepare_request(request: Request<()>) -> Result<Request<()>, Http3Error> {
    validate_request(&request)?;
    validate_ordered_headers(&request)?;
    validate_pseudo_header_order(&request)?;
    Ok(request)
}

fn validate_request(request: &Request<()>) -> Result<(), Http3Error> {
    let uri = request.uri();
    if uri.scheme() != Some(&Scheme::HTTPS) || uri.authority().is_none() {
        return Err(invalid("HTTP/3 requests require an absolute HTTPS URI"));
    }
    if uri
        .authority()
        .is_some_and(|authority| authority.as_str().contains('@'))
    {
        return Err(invalid("HTTP/3 request authority contains userinfo"));
    }
    if request.method() == Method::CONNECT
        || request.extensions().get::<h3::ext::Protocol>().is_some()
    {
        return Err(invalid(
            "HTTP/3 extension requests are not supported by the direct request path",
        ));
    }

    validate_semantic_headers(request.headers())
}

fn validate_semantic_headers(headers: &HeaderMap) -> Result<(), Http3Error> {
    if headers.len() > MAX_REQUEST_HEADERS {
        return Err(invalid("HTTP/3 request has too many headers"));
    }
    let mut bytes = 0usize;
    for (name, value) in headers {
        bytes = bytes
            .checked_add(name.as_str().len())
            .and_then(|size| size.checked_add(value.as_bytes().len()))
            .ok_or_else(|| invalid("HTTP/3 request headers are too large"))?;
        if bytes > MAX_REQUEST_HEADER_BYTES {
            return Err(invalid("HTTP/3 request headers are too large"));
        }

        validate_field(name, value)?;
    }
    Ok(())
}

fn validate_ordered_headers(request: &Request<()>) -> Result<(), Http3Error> {
    let Some(ordered) = request.extensions().get::<OrderedHeaders>() else {
        return Ok(());
    };
    let mut reconstructed = HeaderMap::new();
    for (name, value) in ordered.as_slice() {
        reconstructed
            .try_append(name, value.clone())
            .map_err(|_| invalid("HTTP/3 ordered headers exceed HeaderMap capacity"))?;
    }
    if !header_maps_agree(&reconstructed, request.headers()) {
        return Err(invalid(
            "HTTP/3 ordered headers disagree with semantic headers",
        ));
    }
    Ok(())
}

fn pseudo_header_order(
    settings: &Http3RequestSettings,
) -> Result<RequestPseudoHeaderOrder, Http3Error> {
    settings.validate().map_err(|error| {
        Http3Error::with_source(
            Http3ErrorKind::Configuration,
            "HTTP/3 request profile settings are invalid",
            error,
        )
    })?;
    let mut order = Vec::with_capacity(settings.pseudo_header_order.len());
    for header in &settings.pseudo_header_order {
        order.push(match header {
            Http3PseudoHeader::Method => RequestPseudoHeader::Method,
            Http3PseudoHeader::Authority => RequestPseudoHeader::Authority,
            Http3PseudoHeader::Scheme => RequestPseudoHeader::Scheme,
            Http3PseudoHeader::Path => RequestPseudoHeader::Path,
            _ => {
                return Err(Http3Error::without_source(
                    Http3ErrorKind::Configuration,
                    "HTTP/3 profile contains an unsupported pseudo-header",
                ));
            }
        });
    }
    Ok(RequestPseudoHeaderOrder::new(order))
}

fn validate_pseudo_header_order(request: &Request<()>) -> Result<(), Http3Error> {
    let Some(order) = request.extensions().get::<RequestPseudoHeaderOrder>() else {
        return Ok(());
    };
    let expected = [
        RequestPseudoHeader::Method,
        RequestPseudoHeader::Authority,
        RequestPseudoHeader::Scheme,
        RequestPseudoHeader::Path,
    ];
    if order.as_slice().len() != expected.len()
        || expected.iter().any(|header| {
            order
                .as_slice()
                .iter()
                .filter(|item| *item == header)
                .count()
                != 1
        })
    {
        return Err(invalid("HTTP/3 request pseudo-header order is invalid"));
    }
    Ok(())
}

fn header_maps_agree(left: &HeaderMap, right: &HeaderMap) -> bool {
    left.len() == right.len()
        && right.keys().all(|name| {
            let left = left.get_all(name).iter().collect::<Vec<_>>();
            let right = right.get_all(name).iter().collect::<Vec<_>>();
            left.len() == right.len()
                && left.into_iter().zip(right).all(|(left, right)| {
                    left.as_bytes() == right.as_bytes()
                        && left.is_sensitive() == right.is_sensitive()
                })
        })
}

struct ValidatedHeaders {
    ordered: Vec<(HeaderName, HeaderValue)>,
}

impl ValidatedHeaders {
    fn new(headers: Vec<RequestHeader>) -> Result<Self, Http3Error> {
        if headers.len() > MAX_REQUEST_HEADERS {
            return Err(invalid("HTTP/3 request has too many headers"));
        }

        let mut total_bytes = 0usize;
        let mut ordered = Vec::with_capacity(headers.len());
        for header in headers {
            total_bytes = total_bytes
                .checked_add(header.name().len())
                .and_then(|size| size.checked_add(header.value().len()))
                .ok_or_else(|| invalid("HTTP/3 request headers are too large"))?;
            if total_bytes > MAX_REQUEST_HEADER_BYTES {
                return Err(invalid("HTTP/3 request headers are too large"));
            }
            if !header.name().bytes().all(|byte| !byte.is_ascii_uppercase()) {
                return Err(invalid("HTTP/3 request header names must be lowercase"));
            }
            let name = HeaderName::from_bytes(header.name().as_bytes())
                .map_err(|_| invalid("HTTP/3 request header name is invalid"))?;
            let value = HeaderValue::from_bytes(header.value())
                .map_err(|_| invalid("HTTP/3 request header value is invalid"))?;
            validate_field(&name, &value)?;
            ordered.push((name, value));
        }
        Ok(Self { ordered })
    }

    fn populate(&self, target: &mut HeaderMap) -> Result<(), Http3Error> {
        for (name, value) in &self.ordered {
            target
                .try_append(name, value.clone())
                .map_err(|_| invalid("HTTP/3 request headers exceed HeaderMap capacity"))?;
        }
        Ok(())
    }
}

fn validate_field(name: &HeaderName, value: &HeaderValue) -> Result<(), Http3Error> {
    if name == TE {
        if value.as_bytes() != b"trailers" {
            return Err(invalid("HTTP/3 TE header must contain only `trailers`"));
        }
    } else if name == CONTENT_LENGTH {
        if value.as_bytes() != b"0" {
            return Err(invalid(
                "HTTP/3 empty request requires a zero content length",
            ));
        }
    } else if name == HOST
        || name == CONNECTION
        || name == TRANSFER_ENCODING
        || name == UPGRADE
        || name == TRAILER
        || name.as_str() == "keep-alive"
        || name.as_str() == "proxy-connection"
    {
        return Err(invalid("HTTP/3 request contains a forbidden header"));
    }
    Ok(())
}

const fn invalid(message: &'static str) -> Http3Error {
    Http3Error::without_source(Http3ErrorKind::Request, message)
}
