//! Import one bounded HTTP/1.1 message into the ordinary request path.

use std::{error::Error, fmt};

use bytes::Bytes;
use http::{Method, Uri, header::HeaderValue, uri::Authority};
use phantom_net::request::OriginForm;

use crate::{
    Client, HttpProtocol, RequestBuilder, RequestError, RequestHeader,
    authority::{Endpoint, parse_absolute_uri},
};

// Import bounds include the request line and field delimiters, unlike the
// transport's 32 KiB field-name/value budget. Templates still apply its limits.
const MAXIMUM_HEAD_BYTES: usize = 32 * 1024;
const MAXIMUM_HEADERS: usize = 100;

/// The category of a raw HTTP/1.1 request import failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RawRequestErrorKind {
    /// The complete supplied message exceeds the caller's byte limit.
    InputTooLarge,
    /// The request line and header section exceed 32 KiB.
    HeadTooLarge,
    /// The message contains more than 100 fields, including `Host`.
    TooManyHeaders,
    /// The request line, CRLF delimiters, or a field is malformed or incomplete.
    InvalidSyntax,
    /// The message version is not HTTP/1.1.
    UnsupportedVersion,
    /// The destination is not an absolute HTTP(S) URI without user information.
    InvalidDestination,
    /// The method or target uses CONNECT, absolute form, or asterisk form.
    UnsupportedTarget,
    /// The origin-form target differs from the supplied destination's path/query.
    TargetMismatch,
    /// `Host` is absent, repeated, or not a valid authority.
    InvalidHost,
    /// `Host` differs from the supplied destination's canonical authority.
    HostMismatch,
    /// Transfer coding, trailers, upgrades, or proxy authorization are unsupported.
    UnsupportedHeader,
    /// `Content-Length` is repeated or is not a canonical decimal integer.
    InvalidContentLength,
    /// The remaining bytes differ from the declared length, or lack a length.
    BodyLengthMismatch,
    /// The existing request builder rejected the request configuration.
    Request,
}

/// An import failure that never retains request bytes or header contents.
///
/// [`Self::kind`] identifies parsing and framing errors. For a failure from
/// the ordinary request builder, [`Error::source`] returns its [`RequestError`].
pub struct RawRequestError {
    kind: RawRequestErrorKind,
    source: Option<RequestError>,
}

impl RawRequestError {
    const fn new(kind: RawRequestErrorKind) -> Self {
        Self { kind, source: None }
    }

    fn request(source: RequestError) -> Self {
        Self {
            kind: RawRequestErrorKind::Request,
            source: Some(source),
        }
    }

    /// Returns the failure category without any request contents.
    #[must_use]
    pub const fn kind(&self) -> RawRequestErrorKind {
        self.kind
    }
}

impl fmt::Debug for RawRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RawRequestError")
            .field("kind", &self.kind)
            .field(
                "request_kind",
                &self.source.as_ref().map(RequestError::kind),
            )
            .finish()
    }
}

impl fmt::Display for RawRequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "raw HTTP/1.1 request import failed ({:?})",
            self.kind
        )
    }
}

impl Error for RawRequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_ref().map(|error| error as &dyn Error)
    }
}

pub(crate) fn import(
    client: &Client,
    absolute_uri: &str,
    raw: &[u8],
    maximum_bytes: usize,
) -> Result<RequestBuilder, RawRequestError> {
    use RawRequestErrorKind as Kind;

    if raw.len() > maximum_bytes {
        return Err(RawRequestError::new(Kind::InputTooLarge));
    }
    let head_end = head_end(raw)?;
    let head = &raw[..head_end];
    let mut storage = [httparse::EMPTY_HEADER; MAXIMUM_HEADERS];
    let mut parsed = httparse::Request::new(&mut storage);
    match parsed.parse(head) {
        Ok(httparse::Status::Complete(length)) if length == head.len() => {}
        Err(httparse::Error::TooManyHeaders) => {
            return Err(RawRequestError::new(Kind::TooManyHeaders));
        }
        Err(httparse::Error::Version) => {
            return Err(RawRequestError::new(Kind::UnsupportedVersion));
        }
        _ => return Err(RawRequestError::new(Kind::InvalidSyntax)),
    }
    if parsed.version != Some(1) {
        return Err(RawRequestError::new(Kind::UnsupportedVersion));
    }
    let method = parsed
        .method
        .and_then(|method| Method::from_bytes(method.as_bytes()).ok())
        .ok_or_else(|| RawRequestError::new(Kind::InvalidSyntax))?;
    let target = parsed
        .path
        .filter(|target| OriginForm::parse(target).is_ok())
        .ok_or_else(|| RawRequestError::new(Kind::UnsupportedTarget))?;
    if method == Method::CONNECT {
        return Err(RawRequestError::new(Kind::UnsupportedTarget));
    }
    let (uri, endpoint) = destination(absolute_uri)?;
    if uri.path_and_query().map_or("/", |value| value.as_str()) != target {
        return Err(RawRequestError::new(Kind::TargetMismatch));
    }
    let body = &raw[head_end..];
    validate_fields(parsed.headers, &uri, &endpoint, body.len())?;

    let headers = parsed
        .headers
        .iter()
        .filter(|header| !header.name.eq_ignore_ascii_case("host"))
        .map(|header| RequestHeader::new(header.name, header.value).sensitive())
        .collect();
    let builder = client
        .request(HttpProtocol::Http1, method, absolute_uri)
        .map_err(RawRequestError::request)?
        .headers(headers);
    if body.is_empty() {
        Ok(builder)
    } else {
        Ok(builder.body(Bytes::copy_from_slice(body)))
    }
}

fn head_end(raw: &[u8]) -> Result<usize, RawRequestError> {
    use RawRequestErrorKind as Kind;

    let scan = &raw[..raw.len().min(MAXIMUM_HEAD_BYTES)];
    let end = scan
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .map(|offset| offset + 4)
        .ok_or_else(|| {
            RawRequestError::new(if raw.len() > MAXIMUM_HEAD_BYTES {
                Kind::HeadTooLarge
            } else {
                Kind::InvalidSyntax
            })
        })?;
    // httparse intentionally accepts bare LF and leading empty lines. Import
    // only the strict RFC 9112 section 2.1 CRLF message representation.
    if raw.starts_with(b"\r\n")
        || raw[..end].iter().enumerate().any(|(index, byte)| {
            (*byte == b'\r' && raw.get(index + 1) != Some(&b'\n'))
                || (*byte == b'\n' && (index == 0 || raw[index - 1] != b'\r'))
        })
    {
        return Err(RawRequestError::new(Kind::InvalidSyntax));
    }
    Ok(end)
}

fn destination(value: &str) -> Result<(Uri, Endpoint), RawRequestError> {
    let invalid = || RawRequestError::new(RawRequestErrorKind::InvalidDestination);
    if value.len() > MAXIMUM_HEAD_BYTES {
        return Err(invalid());
    }
    let uri = parse_absolute_uri(value).map_err(|_| invalid())?;
    let default_port = match uri.scheme_str() {
        Some("http") => 80,
        Some("https") => 443,
        _ => return Err(invalid()),
    };
    let endpoint = Endpoint::new(uri.authority().cloned().ok_or_else(invalid)?, default_port)
        .map_err(|_| invalid())?;
    Ok((uri, endpoint))
}

fn validate_fields(
    fields: &[httparse::Header<'_>],
    uri: &Uri,
    endpoint: &Endpoint,
    body_length: usize,
) -> Result<(), RawRequestError> {
    use RawRequestErrorKind as Kind;

    let mut host = None;
    let mut length = None;
    for field in fields {
        HeaderValue::from_bytes(field.value)
            .map_err(|_| RawRequestError::new(Kind::InvalidSyntax))?;
        if field.name.eq_ignore_ascii_case("host") {
            if host.replace(field.value).is_some() {
                return Err(RawRequestError::new(Kind::InvalidHost));
            }
        } else if field.name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(RawRequestError::new(Kind::InvalidContentLength));
            }
            let text = std::str::from_utf8(field.value)
                .map_err(|_| RawRequestError::new(Kind::InvalidContentLength))?;
            let parsed = text
                .parse::<usize>()
                .map_err(|_| RawRequestError::new(Kind::InvalidContentLength))?;
            if text.is_empty()
                || !text.bytes().all(|byte| byte.is_ascii_digit())
                || (text.len() > 1 && text.starts_with('0'))
            {
                return Err(RawRequestError::new(Kind::InvalidContentLength));
            }
            length = Some(parsed);
        } else if [
            "transfer-encoding",
            "trailer",
            "upgrade",
            "proxy-authorization",
        ]
        .iter()
        .any(|name| field.name.eq_ignore_ascii_case(name))
            || (field.name.eq_ignore_ascii_case("connection")
                && field
                    .value
                    .split(|byte| *byte == b',')
                    .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"upgrade")))
        {
            return Err(RawRequestError::new(Kind::UnsupportedHeader));
        }
    }
    validate_host(
        host.ok_or_else(|| RawRequestError::new(Kind::InvalidHost))?,
        uri,
        endpoint,
    )?;
    if length.unwrap_or(0) != body_length {
        return Err(RawRequestError::new(Kind::BodyLengthMismatch));
    }
    Ok(())
}

fn validate_host(value: &[u8], uri: &Uri, endpoint: &Endpoint) -> Result<(), RawRequestError> {
    let invalid = || RawRequestError::new(RawRequestErrorKind::InvalidHost);
    let value = std::str::from_utf8(value).map_err(|_| invalid())?;
    let _: Authority = value.parse().map_err(|_| invalid())?;
    let scheme = uri.scheme_str().ok_or_else(invalid)?;
    let (_, supplied) = destination(&format!("{scheme}://{value}/")).map_err(|_| invalid())?;
    // Compare canonical authority spelling, not only effective endpoints:
    // RFC 9110 section 7.2 requires Host to match URI authority, including an
    // explicitly written default port. Neither input supplies a replacement.
    if !supplied
        .authority()
        .as_str()
        .eq_ignore_ascii_case(endpoint.authority().as_str())
    {
        return Err(RawRequestError::new(RawRequestErrorKind::HostMismatch));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
