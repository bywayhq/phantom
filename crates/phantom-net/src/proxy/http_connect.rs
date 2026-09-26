use std::{
    fmt,
    future::Future,
    pin::{Pin, pin},
    sync::{Mutex, PoisonError},
};

use bytes::Bytes;
use http::{
    HeaderValue,
    header::{CONTENT_LENGTH, HOST, HeaderName, PROXY_AUTHORIZATION, TRANSFER_ENCODING},
    uri::Authority,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{Instrument, Span, debug_span, field};

use super::{
    AuthAttempt, AuthStep, BasicAuthPlan, HttpBasicCredentials, HttpConnectError,
    ProxyCredentialCache, ProxyScheme, TunnelStream,
    authentication::has_valid_basic_challenge,
    challenged_connection::{self, ChallengeBody},
};
use crate::{
    direct::{Dialer, DirectConnectError, connect_tcp},
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
    trace_connect(
        "supplied",
        pin!(async {
            let request = PreparedConnect::new(authority, headers)?;
            establish(stream, request).await
        }),
    )
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
    http_connect_tunnel(
        Dialer::default(),
        proxy_host,
        proxy_port,
        authority,
        headers,
    )
    .await
}

/// Opens a direct HTTP CONNECT tunnel on a proxy socket from `dialer`.
pub(crate) async fn http_connect_tunnel(
    dialer: Dialer<'_>,
    proxy_host: &str,
    proxy_port: u16,
    authority: &str,
    headers: &[HttpConnectHeader],
) -> Result<TunnelStream<tokio::net::TcpStream>, HttpConnectError> {
    trace_connect(
        "http",
        pin!(async {
            let request = PreparedConnect::new(authority, headers)?;
            let stream = connect_proxy_tcp(dialer, proxy_host, proxy_port).await?;
            establish(stream, request).await
        }),
    )
    .await
}

/// Opens a direct HTTP CONNECT tunnel with one challenge-driven Basic retry.
///
/// Both request forms are validated before DNS resolution or TCP I/O. The
/// first request omits the authorization placeholder. A valid Basic challenge
/// causes exactly one retry to the same proxy. The retry uses the challenged
/// connection when the `407` keeps it open and its body ends within
/// [`MAX_CHALLENGE_BODY_BYTES`](super::MAX_CHALLENGE_BODY_BYTES), and a new
/// connection otherwise.
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
    http_connect_tunnel_with_basic_auth(
        Dialer::default(),
        None,
        proxy_host,
        proxy_port,
        authority,
        headers,
        credentials,
    )
    .await
}

/// Opens a direct Basic-authenticated CONNECT tunnel on sockets from `dialer`.
///
/// Every proxy connection, including the authenticated retry, uses `dialer`.
/// With `cache`, a proxy that accepted `credentials` before receives them on
/// the first CONNECT.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn http_connect_tunnel_with_basic_auth(
    dialer: Dialer<'_>,
    cache: Option<&ProxyCredentialCache>,
    proxy_host: &str,
    proxy_port: u16,
    authority: &str,
    headers: &[HttpConnectHeader],
    credentials: &HttpBasicCredentials,
) -> Result<TunnelStream<tokio::net::TcpStream>, HttpConnectError> {
    trace_connect(
        "http",
        pin!(async {
            let requests = PreparedBasicConnect::new(authority, headers, credentials)?;
            let plan = BasicAuthPlan::new(
                cache,
                ProxyScheme::Http,
                proxy_host,
                proxy_port,
                credentials,
            );
            basic_auth_exchange(&plan, &requests, || {
                connect_proxy_tcp(dialer, proxy_host, proxy_port)
            })
            .await
        }),
    )
    .await
}

/// Runs one challenge-driven CONNECT exchange on connections from `connect`.
///
/// The retry after a `407` reuses the challenged connection when the
/// response allows it. When the proxy closes that connection before it
/// answers the retry, the retry is sent once more on a new connection, as
/// Chromium's `HttpProxyConnectJob` does.
pub(super) async fn basic_auth_exchange<S, C, F>(
    plan: &BasicAuthPlan<'_>,
    requests: &PreparedBasicConnect,
    connect: C,
) -> Result<TunnelStream<S>, HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    C: Fn() -> F,
    F: Future<Output = Result<S, HttpConnectError>>,
{
    let challenged = Mutex::new(None);
    plan.run(
        |attempt| {
            let connect = &connect;
            let challenged = &challenged;
            async move {
                record_authentication_attempts(attempt, plan.preemptive());
                if attempt.is_retry() {
                    // Boxed: only a `407` leads here, and the replay would
                    // otherwise enlarge every proxy connection's future.
                    return Box::pin(async {
                        let held = challenged
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .take();
                        if let Some(stream) = held {
                            match replay_on_challenged(stream, &requests.authenticated).await {
                                Replay::Answered(result) => return result.map(AuthStep::Done),
                                Replay::Closed => {}
                            }
                        }
                        let stream = connect().await?;
                        establish_authenticated(stream, &requests.authenticated)
                            .await
                            .map(AuthStep::Done)
                    })
                    .await;
                }
                let stream = connect().await?;
                let request = if attempt.sends_credentials() {
                    &requests.authenticated
                } else {
                    &requests.anonymous
                };
                Ok(match establish_challenge(stream, request).await? {
                    ChallengeOutcome::Tunnel(tunnel) => AuthStep::Done(tunnel),
                    ChallengeOutcome::Retry(reusable) => {
                        *challenged.lock().unwrap_or_else(PoisonError::into_inner) = reusable;
                        AuthStep::Challenged
                    }
                })
            }
        },
        HttpConnectError::is_challenge_failure,
        || HttpConnectError::AuthenticationRejected,
    )
    .await
}

async fn connect_proxy_tcp(
    dialer: Dialer<'_>,
    proxy_host: &str,
    proxy_port: u16,
) -> Result<tokio::net::TcpStream, HttpConnectError> {
    connect_tcp(proxy_host, proxy_port, dialer)
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
    match exchange(stream, &request, false).await? {
        ExchangeOutcome::Tunnel(tunnel) => Ok(tunnel),
        ExchangeOutcome::Retry(_) => Err(HttpConnectError::InvalidResponse),
    }
}

pub(super) async fn establish_challenge<S>(
    stream: S,
    request: &PreparedConnect,
) -> Result<ChallengeOutcome<S>, HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    match exchange(stream, request, true).await? {
        ExchangeOutcome::Tunnel(tunnel) => Ok(ChallengeOutcome::Tunnel(tunnel)),
        ExchangeOutcome::Retry(reusable) => Ok(ChallengeOutcome::Retry(reusable)),
    }
}

pub(super) async fn establish_authenticated<S>(
    stream: S,
    request: &PreparedConnect,
) -> Result<TunnelStream<S>, HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    authenticated_outcome(exchange(stream, request, false).await)
}

fn authenticated_outcome<S>(
    outcome: Result<ExchangeOutcome<S>, HttpConnectError>,
) -> Result<TunnelStream<S>, HttpConnectError> {
    match outcome {
        Err(HttpConnectError::Rejected { status: 407 }) => {
            Err(HttpConnectError::AuthenticationRejected)
        }
        Ok(ExchangeOutcome::Tunnel(tunnel)) => Ok(tunnel),
        Ok(ExchangeOutcome::Retry(_)) => Err(HttpConnectError::InvalidResponse),
        Err(error) => Err(error),
    }
}

/// Outcome of the credentialed CONNECT on the connection that was challenged.
enum Replay<S> {
    /// The proxy answered, or failed in a way a new connection cannot fix.
    Answered(Result<TunnelStream<S>, HttpConnectError>),
    /// The proxy closed the connection before any response byte.
    Closed,
}

async fn replay_on_challenged<S>(mut stream: S, request: &PreparedConnect) -> Replay<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let written = async {
        stream.write_all(&request.bytes).await?;
        stream.flush().await
    }
    .await;
    match written {
        Ok(()) => {}
        Err(error) if challenged_connection::is_connection_close(&error) => return Replay::Closed,
        Err(error) => return Replay::Answered(Err(HttpConnectError::Write(error))),
    }
    let mut chunk = [0_u8; 4096];
    let read = match stream.read(&mut chunk).await {
        Ok(0) => return Replay::Closed,
        Err(error) if challenged_connection::is_connection_close(&error) => return Replay::Closed,
        Err(error) => return Replay::Answered(Err(HttpConnectError::Read(error))),
        Ok(read) => read,
    };
    let mut response = Vec::with_capacity(1024);
    response.extend_from_slice(&chunk[..read]);
    Replay::Answered(authenticated_outcome(
        read_outcome(stream, false, response).await,
    ))
}

async fn exchange<S>(
    mut stream: S,
    request: &PreparedConnect,
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
    read_outcome(stream, inspect_challenge, Vec::with_capacity(1024)).await
}

/// Reads the final CONNECT response, starting with bytes already read into
/// `response`.
async fn read_outcome<S>(
    mut stream: S,
    inspect_challenge: bool,
    mut response: Vec<u8>,
) -> Result<ExchangeOutcome<S>, HttpConnectError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
            let reusable = match parsed.challenge_body {
                Some(body) => {
                    challenged_connection::drain(&mut stream, body, &response[head_end..]).await
                }
                None => false,
            };
            return Ok(ExchangeOutcome::Retry(reusable.then_some(stream)));
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
    let challenged = inspect_challenge && status == 407;
    let authentication = challenged.then(|| has_valid_basic_challenge(response.headers));
    let challenge_body = if challenged {
        ChallengeBody::from_head(
            response.version.ok_or(HttpConnectError::InvalidResponse)?,
            response.headers,
        )
    } else {
        None
    };
    Ok(ParsedResponse {
        status,
        authentication,
        challenge_body,
    })
}

fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)
}

/// Runs `operation` in the CONNECT span and records its outcome.
///
/// The caller pins `operation` in its own future: an async function holds a
/// future it takes by value twice, as the argument and as the awaited value,
/// and this wrapper encloses a whole proxy connection setup.
pub(super) async fn trace_connect<F, T>(
    transport: &'static str,
    operation: Pin<&mut F>,
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
        authentication_preemptive = field::Empty,
        authentication_retry = field::Empty,
        proxy_attempts = field::Empty,
    );
    let outcome = ConnectOutcome::new(&span);
    let result = operation.instrument(span.clone()).await;
    outcome.finish(&result);
    result
}

pub(super) fn record_authentication_attempts(attempt: AuthAttempt, preemptive: bool) {
    let retried = attempt.is_retry();
    Span::current().record("authentication_preemptive", preemptive);
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
    /// A valid challenge, with the connection when the replay may reuse it.
    Retry(Option<S>),
}

enum ExchangeOutcome<S> {
    Tunnel(TunnelStream<S>),
    Retry(Option<S>),
}

struct ParsedResponse {
    status: u16,
    authentication: Option<Result<(), HttpConnectError>>,
    /// How a `407` body ends, when the connection outlives it.
    challenge_body: Option<ChallengeBody>,
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
