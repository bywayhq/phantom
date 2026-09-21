use std::{fmt, future::Future};

use bytes::Bytes;
use http::{
    HeaderValue,
    header::{CONTENT_LENGTH, HOST, HeaderName, PROXY_AUTHORIZATION, TRANSFER_ENCODING},
    uri::Authority,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{Instrument, Span, debug_span, field};

use super::{
    HttpBasicCredentials, HttpConnectError, TunnelStream, authentication::has_valid_basic_challenge,
};
use crate::{
    direct::{DirectConnectError, connect_tcp},
    request::RequestHeader,
};

pub(super) const MAX_CONNECT_HEADERS: usize = 100;
pub(super) const MAX_CONNECT_HEAD_BYTES: usize = 32 * 1024;
pub(super) const MAX_INFORMATIONAL_RESPONSES: usize = 8;

/// One ordered field in an HTTP CONNECT request.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum HttpConnectHeader {
    /// Emits the current tunnel authority using the supplied field-name casing.
    Authority {
        /// Field-name spelling, which must be an ASCII case variant of `Host`.
        name: Box<str>,
    },
    /// Emits one literal field.
    Field(RequestHeader),
    /// Emits generated credentials at this position after a valid challenge.
    ProxyAuthorization {
        /// Field-name spelling, which must be an ASCII case variant of
        /// `Proxy-Authorization`.
        name: Box<str>,
    },
}

impl HttpConnectHeader {
    /// Creates the destination-dependent authority field.
    #[must_use]
    pub fn authority(name: impl Into<Box<str>>) -> Self {
        Self::Authority { name: name.into() }
    }

    /// Creates one literal ordered CONNECT field.
    #[must_use]
    pub fn field(header: RequestHeader) -> Self {
        Self::Field(header)
    }

    /// Creates the challenge-response authorization placeholder.
    #[must_use]
    pub fn proxy_authorization(name: impl Into<Box<str>>) -> Self {
        Self::ProxyAuthorization { name: name.into() }
    }

    /// Reports whether this is the generated authorization placeholder.
    #[must_use]
    pub fn is_proxy_authorization(&self) -> bool {
        matches!(self, Self::ProxyAuthorization { .. })
    }
}

impl fmt::Debug for HttpConnectHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority { name } => formatter
                .debug_struct("Authority")
                .field("name", name)
                .finish(),
            Self::Field(header) => formatter
                .debug_struct("Field")
                .field("name", &header.name())
                .field("value_bytes", &header.value().len())
                .finish(),
            Self::ProxyAuthorization { name } => formatter
                .debug_struct("ProxyAuthorization")
                .field("name", name)
                .finish(),
        }
    }
}

/// Establishes an HTTP CONNECT tunnel over an already-connected stream.
///
/// The authority and complete ordered field list are validated before the
/// supplied stream is touched. The field list must contain exactly one
/// [`HttpConnectHeader::Authority`] placeholder.
///
/// # Errors
///
/// Returns [`HttpConnectError`] for invalid input, I/O failure, malformed or
/// oversized proxy responses, and non-success proxy status.
pub async fn connect_http_tunnel<S>(
    stream: S,
    authority: &str,
    headers: &[HttpConnectHeader],
) -> Result<TunnelStream<S>, HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    trace_connect("supplied", async {
        let request = PreparedConnect::new(authority, headers)?;
        establish(stream, request).await
    })
    .await
}

/// Establishes a direct TCP connection to an HTTP proxy and opens a tunnel.
///
/// Request validation completes before DNS resolution or TCP I/O.
///
/// # Errors
///
/// Returns [`HttpConnectError`] for invalid input, runtime or connection
/// failure, proxy I/O failure, and rejection by the proxy.
///
pub async fn connect_http_tunnel_direct(
    proxy_host: &str,
    proxy_port: u16,
    authority: &str,
    headers: &[HttpConnectHeader],
) -> Result<TunnelStream<tokio::net::TcpStream>, HttpConnectError> {
    trace_connect("http", async {
        let request = PreparedConnect::new(authority, headers)?;
        let stream = connect_tcp(proxy_host, proxy_port)
            .await
            .map_err(|error| match error {
                DirectConnectError::RuntimeUnavailable => HttpConnectError::RuntimeUnavailable,
                DirectConnectError::Connect(error) => HttpConnectError::Connect(error),
            })?;
        establish(stream, request).await
    })
    .await
}

/// Opens a direct HTTP CONNECT tunnel with one challenge-driven Basic retry.
///
/// Both request forms are validated before DNS resolution or TCP I/O. The
/// first request omits the authorization placeholder. A valid Basic challenge
/// causes exactly one retry on a fresh connection to the same proxy.
///
/// # Errors
///
/// Returns [`HttpConnectError`] for invalid credentials or fields, connection
/// and I/O failures, unusable authentication challenges, and proxy rejection.
pub async fn connect_http_tunnel_direct_with_basic_auth(
    proxy_host: &str,
    proxy_port: u16,
    authority: &str,
    headers: &[HttpConnectHeader],
    credentials: &HttpBasicCredentials,
) -> Result<TunnelStream<tokio::net::TcpStream>, HttpConnectError> {
    trace_connect("http", async {
        let requests = PreparedBasicConnect::new(authority, headers, credentials)?;
        record_authentication_attempts(false);
        let stream = connect_proxy_tcp(proxy_host, proxy_port).await?;
        match establish_challenge(stream, requests.anonymous).await? {
            ChallengeOutcome::Tunnel(tunnel) => Ok(tunnel),
            ChallengeOutcome::Retry => {
                record_authentication_attempts(true);
                let stream = connect_proxy_tcp(proxy_host, proxy_port).await?;
                establish_authenticated(stream, requests.authenticated).await
            }
        }
    })
    .await
}

async fn connect_proxy_tcp(
    proxy_host: &str,
    proxy_port: u16,
) -> Result<tokio::net::TcpStream, HttpConnectError> {
    connect_tcp(proxy_host, proxy_port)
        .await
        .map_err(|error| match error {
            DirectConnectError::RuntimeUnavailable => HttpConnectError::RuntimeUnavailable,
            DirectConnectError::Connect(error) => HttpConnectError::Connect(error),
        })
}

pub(super) async fn establish<S>(
    stream: S,
    request: PreparedConnect,
) -> Result<TunnelStream<S>, HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match exchange(stream, request, false).await? {
        ExchangeOutcome::Tunnel(tunnel) => Ok(tunnel),
        ExchangeOutcome::Retry => Err(HttpConnectError::InvalidResponse),
    }
}

pub(super) async fn establish_challenge<S>(
    stream: S,
    request: PreparedConnect,
) -> Result<ChallengeOutcome<S>, HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match exchange(stream, request, true).await? {
        ExchangeOutcome::Tunnel(tunnel) => Ok(ChallengeOutcome::Tunnel(tunnel)),
        ExchangeOutcome::Retry => Ok(ChallengeOutcome::Retry),
    }
}

pub(super) async fn establish_authenticated<S>(
    stream: S,
    request: PreparedConnect,
) -> Result<TunnelStream<S>, HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match exchange(stream, request, false).await {
        Err(HttpConnectError::Rejected { status: 407 }) => {
            Err(HttpConnectError::AuthenticationRejected)
        }
        Ok(ExchangeOutcome::Tunnel(tunnel)) => Ok(tunnel),
        Ok(ExchangeOutcome::Retry) => Err(HttpConnectError::InvalidResponse),
        Err(error) => Err(error),
    }
}

async fn exchange<S>(
    mut stream: S,
    request: PreparedConnect,
    inspect_challenge: bool,
) -> Result<ExchangeOutcome<S>, HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    stream
        .write_all(&request.bytes)
        .await
        .map_err(HttpConnectError::Write)?;
    stream.flush().await.map_err(HttpConnectError::Write)?;

    let mut response = Vec::with_capacity(1024);
    let mut informational_count = 0;
    loop {
        let head_end = read_response_head(&mut stream, &mut response).await?;
        let parsed = parse_response(&response[..head_end], inspect_challenge)?;
        if parsed.status != 101 && (100..200).contains(&parsed.status) {
            informational_count += 1;
            if informational_count > MAX_INFORMATIONAL_RESPONSES {
                return Err(HttpConnectError::TooManyInformationalResponses {
                    maximum: MAX_INFORMATIONAL_RESPONSES,
                });
            }
            response.drain(..head_end);
            continue;
        }
        Span::current().record("status", parsed.status);
        if (200..300).contains(&parsed.status) {
            let prefix = Bytes::from(response).slice(head_end..);
            return Ok(ExchangeOutcome::Tunnel(TunnelStream::new(stream, prefix)));
        }
        if inspect_challenge && parsed.status == 407 {
            parsed
                .authentication
                .ok_or(HttpConnectError::InvalidResponse)??;
            return Ok(ExchangeOutcome::Retry);
        }
        return Err(HttpConnectError::Rejected {
            status: parsed.status,
        });
    }
}

pub(super) async fn read_response_head<S>(
    stream: &mut S,
    response: &mut Vec<u8>,
) -> Result<usize, HttpConnectError>
where
    S: AsyncRead + Unpin,
{
    loop {
        if let Some(end) = find_head_end(response) {
            return Ok(end);
        }
        if response.len() == MAX_CONNECT_HEAD_BYTES {
            return Err(HttpConnectError::ResponseHeadTooLarge {
                maximum: MAX_CONNECT_HEAD_BYTES,
            });
        }
        let remaining = MAX_CONNECT_HEAD_BYTES - response.len();
        let mut chunk = [0_u8; 4096];
        let read_limit = remaining.min(chunk.len());
        let read = stream
            .read(&mut chunk[..read_limit])
            .await
            .map_err(HttpConnectError::Read)?;
        if read == 0 {
            return Err(HttpConnectError::InvalidResponse);
        }
        response.extend_from_slice(&chunk[..read]);
    }
}

fn parse_response(
    head: &[u8],
    inspect_challenge: bool,
) -> Result<ParsedResponse, HttpConnectError> {
    let mut headers = [httparse::EMPTY_HEADER; MAX_CONNECT_HEADERS];
    let mut response = httparse::Response::new(&mut headers);
    match response.parse(head) {
        Ok(httparse::Status::Complete(length)) if length == head.len() => {}
        Ok(httparse::Status::Complete(_) | httparse::Status::Partial) | Err(_) => {
            return Err(HttpConnectError::InvalidResponse);
        }
    }
    let status = response.code.ok_or(HttpConnectError::InvalidResponse)?;
    let authentication =
        (inspect_challenge && status == 407).then(|| has_valid_basic_challenge(response.headers));
    Ok(ParsedResponse {
        status,
        authentication,
    })
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

pub(super) async fn trace_connect<F, T>(
    transport: &'static str,
    operation: F,
) -> Result<T, HttpConnectError>
where
    F: Future<Output = Result<T, HttpConnectError>>,
{
    let span = debug_span!(
        "proxy.http_connect",
        proxy_transport = transport,
        status = field::Empty,
        outcome = field::Empty,
        error_kind = field::Empty,
        authentication_retry = field::Empty,
        proxy_attempts = field::Empty,
    );
    let outcome = ConnectOutcome::new(&span);
    let result = operation.instrument(span.clone()).await;
    outcome.finish(&result);
    result
}

pub(super) fn record_authentication_attempts(retried: bool) {
    Span::current().record("authentication_retry", retried);
    Span::current().record("proxy_attempts", if retried { 2_u64 } else { 1_u64 });
}

struct ConnectOutcome {
    span: Span,
    recorded: bool,
}

impl ConnectOutcome {
    fn new(span: &Span) -> Self {
        Self {
            span: span.clone(),
            recorded: false,
        }
    }

    fn finish(mut self, result: &Result<impl Sized, HttpConnectError>) {
        match result {
            Ok(_) => {
                self.span.record("outcome", "ok");
            }
            Err(error) => {
                self.span.record("outcome", "error");
                self.span.record("error_kind", error.kind().trace_name());
            }
        }
        self.recorded = true;
    }
}

impl Drop for ConnectOutcome {
    fn drop(&mut self) {
        if !self.recorded {
            let outcome = if std::thread::panicking() {
                "panicked"
            } else {
                "cancelled"
            };
            self.span.record("outcome", outcome);
        }
    }
}

pub(super) struct PreparedConnect {
    bytes: Vec<u8>,
}

impl PreparedConnect {
    pub(super) fn new(
        authority: &str,
        headers: &[HttpConnectHeader],
    ) -> Result<Self, HttpConnectError> {
        Self::prepare(authority, headers, Authorization::Forbidden)
    }

    pub(super) fn prepare(
        authority: &str,
        headers: &[HttpConnectHeader],
        authorization: Authorization<'_>,
    ) -> Result<Self, HttpConnectError> {
        if authority.as_bytes().contains(&b'@') {
            return Err(HttpConnectError::InvalidAuthority);
        }
        let parsed = authority
            .parse::<Authority>()
            .map_err(|_| HttpConnectError::InvalidAuthority)?;
        if parsed.port_u16().is_none() || parsed.as_str() != authority {
            return Err(HttpConnectError::InvalidAuthority);
        }
        if headers.len() > MAX_CONNECT_HEADERS {
            return Err(HttpConnectError::TooManyHeaders {
                count: headers.len(),
                maximum: MAX_CONNECT_HEADERS,
            });
        }

        let mut bytes = Vec::with_capacity(256);
        extend_bounded(&mut bytes, b"CONNECT ")?;
        extend_bounded(&mut bytes, authority.as_bytes())?;
        extend_bounded(&mut bytes, b" HTTP/1.1\r\n")?;

        let mut authority_count = 0;
        for (index, header) in headers.iter().enumerate() {
            match header {
                HttpConnectHeader::Authority { name } => {
                    authority_count += 1;
                    if authority_count > 1 {
                        return Err(HttpConnectError::MultipleAuthorityHeaders);
                    }
                    let parsed = HeaderName::from_bytes(name.as_bytes())
                        .map_err(|_| HttpConnectError::InvalidHeaderName { index })?;
                    if parsed != HOST
                        || !name
                            .as_bytes()
                            .eq_ignore_ascii_case(parsed.as_str().as_bytes())
                    {
                        return Err(HttpConnectError::InvalidHeaderName { index });
                    }
                    append_field(&mut bytes, name.as_bytes(), authority.as_bytes())?;
                }
                HttpConnectHeader::Field(header) => {
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
                    if name == HOST {
                        return Err(HttpConnectError::AuthorityHeader);
                    }
                    if name == CONTENT_LENGTH || name == TRANSFER_ENCODING {
                        return Err(HttpConnectError::RequestFramingHeader);
                    }
                    if authorization.is_generated() && name == PROXY_AUTHORIZATION {
                        return Err(HttpConnectError::ProxyAuthorizationHeader);
                    }
                    append_field(&mut bytes, header.name().as_bytes(), header.value())?;
                }
                HttpConnectHeader::ProxyAuthorization { name } => {
                    let parsed = HeaderName::from_bytes(name.as_bytes())
                        .map_err(|_| HttpConnectError::InvalidHeaderName { index })?;
                    if parsed != PROXY_AUTHORIZATION
                        || !name
                            .as_bytes()
                            .eq_ignore_ascii_case(parsed.as_str().as_bytes())
                    {
                        return Err(HttpConnectError::InvalidHeaderName { index });
                    }
                    match authorization {
                        Authorization::Forbidden => {
                            return Err(HttpConnectError::ProxyAuthorizationPlaceholder);
                        }
                        Authorization::Omit => {}
                        Authorization::Emit(value) => {
                            append_field(&mut bytes, name.as_bytes(), value)?;
                        }
                    }
                }
            }
        }
        if authority_count == 0 {
            return Err(HttpConnectError::MissingAuthorityHeader);
        }
        extend_bounded(&mut bytes, b"\r\n")?;
        Ok(Self { bytes })
    }
}

pub(super) struct PreparedBasicConnect {
    pub(super) anonymous: PreparedConnect,
    pub(super) authenticated: PreparedConnect,
}

impl PreparedBasicConnect {
    pub(super) fn new(
        authority: &str,
        headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
    ) -> Result<Self, HttpConnectError> {
        let placeholders = headers
            .iter()
            .filter(|header| header.is_proxy_authorization())
            .count();
        match placeholders {
            0 => return Err(HttpConnectError::MissingProxyAuthorizationPlaceholder),
            1 => {}
            _ => return Err(HttpConnectError::MultipleProxyAuthorizationPlaceholders),
        }
        let anonymous = PreparedConnect::prepare(authority, headers, Authorization::Omit)?;
        let authenticated = PreparedConnect::prepare(
            authority,
            headers,
            Authorization::Emit(credentials.authorization()),
        )?;
        Ok(Self {
            anonymous,
            authenticated,
        })
    }
}

pub(super) enum ChallengeOutcome<S> {
    Tunnel(TunnelStream<S>),
    Retry,
}

enum ExchangeOutcome<S> {
    Tunnel(TunnelStream<S>),
    Retry,
}

struct ParsedResponse {
    status: u16,
    authentication: Option<Result<(), HttpConnectError>>,
}

#[derive(Clone, Copy)]
pub(super) enum Authorization<'a> {
    Forbidden,
    Omit,
    Emit(&'a [u8]),
}

impl Authorization<'_> {
    fn is_generated(self) -> bool {
        !matches!(self, Self::Forbidden)
    }
}

pub(super) fn append_field(
    target: &mut Vec<u8>,
    name: &[u8],
    value: &[u8],
) -> Result<(), HttpConnectError> {
    extend_bounded(target, name)?;
    extend_bounded(target, b": ")?;
    extend_bounded(target, value)?;
    extend_bounded(target, b"\r\n")
}

pub(super) fn extend_bounded(target: &mut Vec<u8>, bytes: &[u8]) -> Result<(), HttpConnectError> {
    let attempted =
        target
            .len()
            .checked_add(bytes.len())
            .ok_or(HttpConnectError::RequestHeadTooLarge {
                bytes: usize::MAX,
                maximum: MAX_CONNECT_HEAD_BYTES,
            })?;
    if attempted > MAX_CONNECT_HEAD_BYTES {
        return Err(HttpConnectError::RequestHeadTooLarge {
            bytes: attempted,
            maximum: MAX_CONNECT_HEAD_BYTES,
        });
    }
    target.extend_from_slice(bytes);
    Ok(())
}
