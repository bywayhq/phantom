//! RFC 9298 CONNECT-UDP requests to an HTTPS proxy over HTTP/1.1 Upgrade
//! (section 3.2) or HTTP/2 extended CONNECT (section 3.4).
//!
//! Both legs carry the Capsule Protocol on the request's byte stream
//! (RFC 9297 section 3.2). HTTP/3 legs live in `http3::connect_udp`.

use bytes::Bytes;
use http::{
    HeaderMap, HeaderValue, StatusCode,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HeaderName, TRANSFER_ENCODING},
    uri::Authority,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tracing::Span;

use super::{
    HttpBasicCredentials, HttpConnectError, HttpsProxyConnector, HttpsProxyProtocol, TunnelStream,
    authentication::{has_valid_basic_challenge, validate_basic_proxy_challenge},
    http_connect::{
        MAX_CONNECT_HEADERS, MAX_INFORMATIONAL_RESPONSES, append_field, extend_bounded,
        read_response_head,
    },
    https_connect::HttpsProxyTunnel,
};
use crate::{
    http2::{Http2ExtendedConnectOutcome, Http2TlsError, prepare_connect_udp},
    request::{OriginForm, RequestHeader},
};

/// Upgrade token and `:protocol` value for UDP proxying (RFC 9298 section 3).
const CONNECT_UDP: &str = "connect-udp";

/// A validated CONNECT-UDP request for one HTTP/1.1 or HTTP/2 proxy leg.
///
/// With credentials, both the anonymous first request and the one
/// challenge-response retry are fully built before any proxy I/O.
pub(crate) struct PreparedConnectUdp {
    anonymous: PreparedLeg,
    authenticated: Option<PreparedLeg>,
}

enum PreparedLeg {
    Http1(Vec<u8>),
    Http2(http::Request<()>),
}

impl PreparedConnectUdp {
    /// Builds the request for `protocol` with generated fields first, the
    /// caller's ordered fields next, and `Proxy-Authorization` last on the
    /// authenticated form.
    pub(crate) fn new(
        protocol: HttpsProxyProtocol,
        authority: &str,
        path: &OriginForm,
        headers: &[RequestHeader],
        credentials: Option<&HttpBasicCredentials>,
    ) -> Result<Self, HttpConnectError> {
        validate_fields(authority, headers, credentials.is_some())?;
        let path_text = path.clone().into_path_and_query();
        let build = |authorization: Option<&[u8]>| match protocol {
            HttpsProxyProtocol::Http2 => {
                http2_request(authority, path.clone(), headers, authorization)
                    .map(PreparedLeg::Http2)
            }
            _ => http1_head(authority, path_text.as_str(), headers, authorization)
                .map(PreparedLeg::Http1),
        };
        Ok(Self {
            anonymous: build(None)?,
            authenticated: credentials
                .map(|credentials| build(Some(credentials.authorization())))
                .transpose()?,
        })
    }
}

/// Rejects fields that would repeat or contradict generated ones.
fn validate_fields(
    authority: &str,
    headers: &[RequestHeader],
    generates_authorization: bool,
) -> Result<(), HttpConnectError> {
    if authority.as_bytes().contains(&b'@') || authority.parse::<Authority>().is_err() {
        return Err(HttpConnectError::InvalidAuthority);
    }
    if headers.len() > MAX_CONNECT_HEADERS {
        return Err(HttpConnectError::TooManyHeaders {
            count: headers.len(),
            maximum: MAX_CONNECT_HEADERS,
        });
    }
    for (index, header) in headers.iter().enumerate() {
        let name = header.name();
        if name.eq_ignore_ascii_case("host") {
            return Err(HttpConnectError::AuthorityHeader);
        }
        if ["connection", "upgrade", "capsule-protocol"]
            .iter()
            .any(|generated| name.eq_ignore_ascii_case(generated))
        {
            return Err(HttpConnectError::ConnectUdpGeneratedHeader { index });
        }
        if name.eq_ignore_ascii_case("content-length")
            || name.eq_ignore_ascii_case("transfer-encoding")
        {
            return Err(HttpConnectError::RequestFramingHeader);
        }
        if generates_authorization && name.eq_ignore_ascii_case("proxy-authorization") {
            return Err(HttpConnectError::ProxyAuthorizationHeader);
        }
    }
    Ok(())
}

/// Encodes the RFC 9298 section 3.2 request head: `GET` in origin form with
/// `Host`, `Connection: Upgrade`, `Upgrade: connect-udp`, and
/// `Capsule-Protocol: ?1` (RFC 9298 figure 3).
fn http1_head(
    authority: &str,
    path: &str,
    headers: &[RequestHeader],
    authorization: Option<&[u8]>,
) -> Result<Vec<u8>, HttpConnectError> {
    let mut bytes = Vec::with_capacity(256);
    extend_bounded(&mut bytes, b"GET ")?;
    extend_bounded(&mut bytes, path.as_bytes())?;
    extend_bounded(&mut bytes, b" HTTP/1.1\r\n")?;
    append_field(&mut bytes, b"Host", authority.as_bytes())?;
    append_field(&mut bytes, b"Connection", b"Upgrade")?;
    append_field(&mut bytes, b"Upgrade", CONNECT_UDP.as_bytes())?;
    append_field(&mut bytes, b"Capsule-Protocol", b"?1")?;
    for (index, header) in headers.iter().enumerate() {
        let name = HeaderName::from_bytes(header.name().as_bytes())
            .map_err(|_| HttpConnectError::InvalidHeaderName { index })?;
        if !header
            .name()
            .as_bytes()
            .eq_ignore_ascii_case(name.as_str().as_bytes())
        {
            return Err(HttpConnectError::InvalidHeaderName { index });
        }
        HeaderValue::from_bytes(header.value())
            .map_err(|_| HttpConnectError::InvalidHeaderValue { index })?;
        append_field(&mut bytes, header.name().as_bytes(), header.value())?;
    }
    if let Some(value) = authorization {
        append_field(&mut bytes, b"Proxy-Authorization", value)?;
    }
    extend_bounded(&mut bytes, b"\r\n")?;
    Ok(bytes)
}

/// Builds the RFC 9298 section 3.4 extended CONNECT request (figure 5). The
/// generated authorization field is never indexed by HPACK.
fn http2_request(
    authority: &str,
    path: OriginForm,
    headers: &[RequestHeader],
    authorization: Option<&[u8]>,
) -> Result<http::Request<()>, HttpConnectError> {
    let mut fields = Vec::with_capacity(headers.len() + 2);
    fields.push(RequestHeader::new("capsule-protocol", "?1"));
    fields.extend(headers.iter().cloned());
    if let Some(value) = authorization {
        fields.push(RequestHeader::new("proxy-authorization", value).sensitive());
    }
    prepare_connect_udp(authority, path, fields)
        .map_err(|error| HttpConnectError::ProxyHttp2(Box::new(Http2TlsError::Http2(error))))
}

enum LegOutcome {
    Tunnel(HttpsProxyTunnel),
    Retry,
}

impl HttpsProxyConnector {
    /// Validates that this connector can speak `protocol` for CONNECT-UDP
    /// before any proxy I/O. HTTP/2 requires an `h2` offer, HTTP/2 settings,
    /// and an explicit extended CONNECT pseudo-header order.
    pub(crate) fn validate_connect_udp_protocol(
        &self,
        protocol: HttpsProxyProtocol,
    ) -> Result<(), HttpConnectError> {
        match protocol {
            HttpsProxyProtocol::Http2 => self.http2_extended_builder().map(drop),
            _ => Ok(()),
        }
    }

    /// Opens one CONNECT-UDP request stream to the proxy.
    ///
    /// Each attempt uses a fresh proxy connection whose ALPN selection must
    /// match the leg exactly. With credentials, a 407 carrying a valid Basic
    /// challenge causes exactly one authenticated retry on a new connection;
    /// a second 407 is [`HttpConnectError::AuthenticationRejected`]. Statuses
    /// and attempt counts are recorded on `span`.
    pub(crate) async fn connect_udp_tunnel(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        request: PreparedConnectUdp,
        span: &Span,
    ) -> Result<HttpsProxyTunnel, HttpConnectError> {
        let PreparedConnectUdp {
            anonymous,
            authenticated,
        } = request;
        let Some(authenticated) = authenticated else {
            return match self
                .connect_udp_leg(
                    proxy_host,
                    proxy_port,
                    proxy_server_name,
                    anonymous,
                    false,
                    span,
                )
                .await?
            {
                LegOutcome::Tunnel(tunnel) => Ok(tunnel),
                LegOutcome::Retry => Err(HttpConnectError::InvalidResponse),
            };
        };
        record_attempts(span, false);
        match self
            .connect_udp_leg(
                proxy_host,
                proxy_port,
                proxy_server_name,
                anonymous,
                true,
                span,
            )
            .await?
        {
            LegOutcome::Tunnel(tunnel) => Ok(tunnel),
            LegOutcome::Retry => {
                record_attempts(span, true);
                match self
                    .connect_udp_leg(
                        proxy_host,
                        proxy_port,
                        proxy_server_name,
                        authenticated,
                        false,
                        span,
                    )
                    .await
                {
                    Ok(LegOutcome::Tunnel(tunnel)) => Ok(tunnel),
                    Ok(LegOutcome::Retry) => Err(HttpConnectError::InvalidResponse),
                    Err(HttpConnectError::Rejected { status: 407 }) => {
                        Err(HttpConnectError::AuthenticationRejected)
                    }
                    Err(error) => Err(error),
                }
            }
        }
    }

    async fn connect_udp_leg(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        request: PreparedLeg,
        inspect_challenge: bool,
        span: &Span,
    ) -> Result<LegOutcome, HttpConnectError> {
        match request {
            PreparedLeg::Http1(head) => {
                let stream = self
                    .connect_http1_proxy(proxy_host, proxy_port, proxy_server_name)
                    .await?;
                Ok(
                    match http1_exchange(stream, &head, inspect_challenge, span).await? {
                        Http1Outcome::Upgraded(stream) => {
                            LegOutcome::Tunnel(HttpsProxyTunnel::http1(stream))
                        }
                        Http1Outcome::Retry => LegOutcome::Retry,
                    },
                )
            }
            PreparedLeg::Http2(request) => {
                // The connection lease moves into the accepted stream, so the
                // tunnel owns its dedicated proxy connection.
                let connection = self
                    .connect_http2_extended_proxy(proxy_host, proxy_port, proxy_server_name)
                    .await?;
                let outcome = connection
                    .send_connect_udp(request)
                    .await
                    .map_err(|error| {
                        HttpConnectError::ProxyHttp2(Box::new(Http2TlsError::Http2(error)))
                    })?;
                match outcome {
                    Http2ExtendedConnectOutcome::Accepted { response, stream } => {
                        span.record("status", response.status().as_u16());
                        if !starts_capsule_protocol(response.status(), response.headers()) {
                            return Err(HttpConnectError::InvalidResponse);
                        }
                        Ok(LegOutcome::Tunnel(HttpsProxyTunnel::http2(
                            stream.into_connect_stream(),
                        )))
                    }
                    Http2ExtendedConnectOutcome::Rejected(response) => {
                        let status = response.status().as_u16();
                        span.record("status", status);
                        if inspect_challenge && status == 407 {
                            validate_basic_proxy_challenge(response.headers())?;
                            return Ok(LegOutcome::Retry);
                        }
                        Err(HttpConnectError::Rejected { status })
                    }
                }
            }
        }
    }
}

/// Records whether the one challenge-driven authenticated retry happened.
fn record_attempts(span: &Span, retried: bool) {
    span.record("authentication_retry", retried);
    span.record("proxy_attempts", if retried { 2_u64 } else { 1_u64 });
}

/// RFC 9297 section 3.2: a response that starts the Capsule Protocol has no
/// content framing or type, and is never 204, 205, or 206.
fn starts_capsule_protocol(status: StatusCode, headers: &HeaderMap) -> bool {
    !matches!(status.as_u16(), 204..=206)
        && ![CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING]
            .iter()
            .any(|name| headers.contains_key(name))
}

enum Http1Outcome<S> {
    Upgraded(TunnelStream<S>),
    Retry,
}

/// Sends the Upgrade request and reads final responses until 101.
///
/// RFC 9298 section 3.3 requires 101 with `Connection: Upgrade` and a single
/// `Upgrade: connect-udp`; a 2xx or a malformed upgrade fails the attempt.
/// Bytes after the 101 head start the capsule stream (RFC 9297 section 3.2).
async fn http1_exchange<S>(
    mut stream: S,
    request: &[u8],
    inspect_challenge: bool,
    span: &Span,
) -> Result<Http1Outcome<S>, HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(request)
        .await
        .map_err(HttpConnectError::Write)?;
    stream.flush().await.map_err(HttpConnectError::Write)?;

    let mut response = Vec::with_capacity(1024);
    let mut informational_count = 0;
    loop {
        let head_end = read_response_head(&mut stream, &mut response).await?;
        let head = parse_upgrade_response(&response[..head_end], inspect_challenge)?;
        if head.status != 101 && (100..200).contains(&head.status) {
            informational_count += 1;
            if informational_count > MAX_INFORMATIONAL_RESPONSES {
                return Err(HttpConnectError::TooManyInformationalResponses {
                    maximum: MAX_INFORMATIONAL_RESPONSES,
                });
            }
            response.drain(..head_end);
            continue;
        }
        span.record("status", head.status);
        if head.status == 101 {
            if !head.valid_upgrade {
                return Err(HttpConnectError::InvalidResponse);
            }
            let prefix = Bytes::from(response).slice(head_end..);
            return Ok(Http1Outcome::Upgraded(TunnelStream::new(stream, prefix)));
        }
        if (200..300).contains(&head.status) {
            return Err(HttpConnectError::InvalidResponse);
        }
        if let Some(challenge) = head.challenge {
            challenge?;
            return Ok(Http1Outcome::Retry);
        }
        return Err(HttpConnectError::Rejected {
            status: head.status,
        });
    }
}

struct UpgradeResponse {
    status: u16,
    valid_upgrade: bool,
    challenge: Option<Result<(), HttpConnectError>>,
}

fn parse_upgrade_response(
    head: &[u8],
    inspect_challenge: bool,
) -> Result<UpgradeResponse, HttpConnectError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_CONNECT_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(head) {
        Ok(httparse::Status::Complete(length)) if length == head.len() => {}
        Ok(httparse::Status::Complete(_) | httparse::Status::Partial) | Err(_) => {
            return Err(HttpConnectError::InvalidResponse);
        }
    }
    let status = response.code.ok_or(HttpConnectError::InvalidResponse)?;
    let fields = response.headers;
    let valid_upgrade = status == 101 && {
        let connection_upgrade = fields
            .iter()
            .filter(|field| field.name.eq_ignore_ascii_case("connection"))
            .flat_map(|field| field.value.split(|byte| *byte == b','))
            .any(|token| token.trim_ascii().eq_ignore_ascii_case(b"upgrade"));
        let mut upgrades = fields
            .iter()
            .filter(|field| field.name.eq_ignore_ascii_case("upgrade"));
        let single_upgrade = upgrades.next().is_some_and(|field| {
            field
                .value
                .trim_ascii()
                .eq_ignore_ascii_case(CONNECT_UDP.as_bytes())
        }) && upgrades.next().is_none();
        let framed = fields.iter().any(|field| {
            ["content-length", "content-type", "transfer-encoding"]
                .iter()
                .any(|name| field.name.eq_ignore_ascii_case(name))
        });
        connection_upgrade && single_upgrade && !framed
    };
    let challenge = (inspect_challenge && status == 407).then(|| has_valid_basic_challenge(fields));
    Ok(UpgradeResponse {
        status,
        valid_upgrade,
        challenge,
    })
}

#[cfg(test)]
mod tests;
