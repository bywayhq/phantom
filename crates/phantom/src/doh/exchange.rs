use std::{io, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderMap, Method, header};
use phantom_net::dns::wire::{DnsWireErrorKind, DnsWireQuery, DnsWireResult, MAX_MESSAGE_BYTES};
use tokio::time::Instant;

use super::{DohMethod, Endpoint, HttpsEndpoint, Transport};
use crate::{Bytes, ContentDecoding, HttpProtocol, RequestHeader};

#[cfg(test)]
mod tests;

pub(super) struct Exchange {
    pub(super) answer: DnsWireResult,
    started: Instant,
    received: Instant,
    age: u64,
}

impl Exchange {
    pub(super) fn expiry(&self, ttl: u32) -> Instant {
        let remaining = Duration::from_secs(u64::from(ttl))
            .saturating_sub(Duration::from_secs(self.age))
            .saturating_sub(self.received.saturating_duration_since(self.started));
        self.received
            .checked_add(remaining)
            .unwrap_or(self.received)
    }
}

pub(super) async fn send(endpoint: &Endpoint, query: &DnsWireQuery) -> io::Result<Exchange> {
    match &endpoint.transport {
        Transport::Https(endpoint) => send_https(endpoint, query).await,
        Transport::Tls(transport) => {
            let started = Instant::now();
            let answer = transport.exchange(query).await?;
            Ok(Exchange {
                answer,
                started,
                received: Instant::now(),
                age: 0,
            })
        }
    }
}

async fn send_https(endpoint: &HttpsEndpoint, query: &DnsWireQuery) -> io::Result<Exchange> {
    let started = Instant::now();
    let method = match endpoint.configuration.method {
        DohMethod::Get => Method::GET,
        DohMethod::Post => Method::POST,
    };
    let mut request = endpoint
        .client
        .request_with_protocol(HttpProtocol::Http2, method, endpoint.url.as_str())
        .map_err(io::Error::other)?
        .without_header_hooks()
        .content_decoding(ContentDecoding::none());
    let mut headers = vec![RequestHeader::new("accept", "application/dns-message")];
    if endpoint.configuration.chromium_headers {
        // Chromium 154.0.8037.58 net/dns/dns_http_attempt.cc sends these
        // minimal fields instead of navigation headers and credentials.
        headers.push(RequestHeader::new("accept-language", "*"));
        headers.push(RequestHeader::new("user-agent", "Chrome"));
    }
    headers.push(RequestHeader::new("accept-encoding", "identity"));
    match endpoint.configuration.method {
        DohMethod::Get => {
            let encoded = URL_SAFE_NO_PAD.encode(query.as_bytes());
            request = request
                .query_pairs([("dns", encoded.as_str())])
                .map_err(io::Error::other)?;
        }
        DohMethod::Post => {
            headers.push(RequestHeader::new(
                "content-type",
                "application/dns-message",
            ));
            request = request.body(Bytes::copy_from_slice(query.as_bytes()));
        }
    }
    let response = request
        .headers(headers)
        .send()
        .await
        .map_err(io::Error::other)?;
    if !response.status().is_success()
        || (endpoint.configuration.chromium_headers && response.status() != http::StatusCode::OK)
    {
        return Err(io::Error::other(format!(
            "DNS-over-HTTPS rejected HTTP status {}",
            response.status()
        )));
    }
    validate_content_type(response.headers())?;
    validate_content_encoding(response.headers())?;
    let age = response_age(response.headers())?;
    let body = response
        .into_body()
        .collect_with_limit(MAX_MESSAGE_BYTES)
        .await
        .map_err(io::Error::other)?;
    let answer = query.parse_response(&body).map_err(|error| {
        let kind = if error.kind() == DnsWireErrorKind::Server {
            io::ErrorKind::Other
        } else {
            io::ErrorKind::InvalidData
        };
        io::Error::new(kind, error)
    })?;
    Ok(Exchange {
        answer,
        started,
        received: Instant::now(),
        age,
    })
}

fn validate_content_type(headers: &HeaderMap) -> io::Result<()> {
    let mut values = headers.get_all(header::CONTENT_TYPE).iter();
    let value = values
        .next()
        .ok_or_else(|| invalid_response("missing DNS message Content-Type"))?;
    // Content-Type is a single-valued field, not an HTTP list. Refuse
    // duplicate instances rather than selecting one conflicting interpretation.
    if values.next().is_some() {
        return Err(invalid_response("duplicate DNS message Content-Type"));
    }
    let bytes = value.as_bytes();
    let mut position = 0;
    skip_ows(bytes, &mut position);
    let kind = token(bytes, &mut position)
        .ok_or_else(|| invalid_response("malformed DNS message Content-Type"))?;
    if bytes.get(position) != Some(&b'/') {
        return Err(invalid_response("malformed DNS message Content-Type"));
    }
    position += 1;
    let subtype = token(bytes, &mut position)
        .ok_or_else(|| invalid_response("malformed DNS message Content-Type"))?;
    if !kind.eq_ignore_ascii_case(b"application") || !subtype.eq_ignore_ascii_case(b"dns-message") {
        return Err(invalid_response("unsupported DNS message Content-Type"));
    }
    skip_ows(bytes, &mut position);
    while position < bytes.len() {
        if bytes[position] != b';' {
            return Err(invalid_response("malformed DNS message media parameter"));
        }
        position += 1;
        skip_ows(bytes, &mut position);
        token(bytes, &mut position)
            .ok_or_else(|| invalid_response("malformed DNS message media parameter"))?;
        if bytes.get(position) != Some(&b'=') {
            return Err(invalid_response("malformed DNS message media parameter"));
        }
        position += 1;
        if bytes.get(position) == Some(&b'"') {
            quoted_value(bytes, &mut position)?;
        } else {
            token(bytes, &mut position)
                .ok_or_else(|| invalid_response("malformed DNS message media parameter"))?;
        }
        skip_ows(bytes, &mut position);
    }
    Ok(())
}

fn validate_content_encoding(headers: &HeaderMap) -> io::Result<()> {
    for value in headers.get_all(header::CONTENT_ENCODING) {
        let value = value
            .to_str()
            .map_err(|_| invalid_response("malformed DNS response content coding"))?;
        if !value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case("identity")
        {
            return Err(invalid_response("encoded DNS response is unsupported"));
        }
    }
    Ok(())
}

fn response_age(headers: &HeaderMap) -> io::Result<u64> {
    let mut age = None;
    for value in headers.get_all(header::AGE) {
        let bytes = value.as_bytes();
        let mut start = 0;
        skip_ows(bytes, &mut start);
        let mut end = bytes.len();
        while end > start && matches!(bytes[end - 1], b' ' | b'\t') {
            end -= 1;
        }
        let digits = &bytes[start..end];
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
            return Err(invalid_response("malformed DNS response Age"));
        }
        // RFC 9111 delta-seconds overflow must expire data, not wrap to zero.
        let parsed = digits.iter().fold(0_u64, |age, digit| {
            age.saturating_mul(10)
                .saturating_add(u64::from(digit - b'0'))
        });
        if age.is_some_and(|previous| previous != parsed) {
            return Err(invalid_response("conflicting DNS response Age"));
        }
        age = Some(parsed);
    }
    Ok(age.unwrap_or(0))
}

fn token<'a>(bytes: &'a [u8], position: &mut usize) -> Option<&'a [u8]> {
    let start = *position;
    while bytes
        .get(*position)
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
    {
        *position += 1;
    }
    (*position > start).then_some(&bytes[start..*position])
}

fn skip_ows(bytes: &[u8], position: &mut usize) {
    while bytes
        .get(*position)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        *position += 1;
    }
}

fn quoted_value(bytes: &[u8], position: &mut usize) -> io::Result<()> {
    *position += 1;
    while let Some(byte) = bytes.get(*position) {
        *position += 1;
        match byte {
            b'"' => return Ok(()),
            b'\\' => {
                let escaped = bytes
                    .get(*position)
                    .ok_or_else(|| invalid_response("incomplete DNS media parameter"))?;
                if !matches!(escaped, b'\t' | b' '..=b'~' | 0x80..=0xff) {
                    return Err(invalid_response("malformed DNS media parameter escape"));
                }
                *position += 1;
            }
            b'\t' | b' ' | b'!' | b'#'..=b'[' | b']'..=b'~' | 0x80..=0xff => {}
            _ => return Err(invalid_response("malformed DNS media parameter")),
        }
    }
    Err(invalid_response("incomplete DNS media parameter"))
}

fn invalid_response(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
