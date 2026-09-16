use http::{
    Request,
    header::{CONNECTION, CONTENT_LENGTH, HOST, TE, TRAILER, TRANSFER_ENCODING, UPGRADE},
    uri::Scheme,
};

use super::{Http3Error, Http3ErrorKind};

const MAX_REQUEST_HEADERS: usize = 100;
const MAX_REQUEST_HEADER_BYTES: usize = 32 * 1024;

pub(super) fn validate_request(request: &Request<()>) -> Result<(), Http3Error> {
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

    let headers = request.headers();
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
    }
    Ok(())
}

const fn invalid(message: &'static str) -> Http3Error {
    Http3Error::without_source(Http3ErrorKind::Request, message)
}
