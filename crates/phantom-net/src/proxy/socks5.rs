use std::{error::Error as StdError, fmt, future::Future};

use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};

use tokio_socks::{IntoTargetAddr, TargetAddr, tcp::Socks5Stream};
use tracing::{Instrument, Span, debug_span, field};

use crate::{
    address_cache::resolve,
    direct::{Dialer, DirectConnectError, connect_tcp, poll_tokio_io},
};

/// Stable category of SOCKS5 tunnel failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Socks5ErrorKind {
    /// The remote target cannot be encoded as a SOCKS5 address.
    InvalidTarget,
    /// Username/password credentials cannot be encoded for RFC 1929.
    InvalidAuthentication,
    /// The request was polled outside a Tokio runtime.
    RuntimeUnavailable,
    /// Connecting to the proxy failed.
    Connect,
    /// Resolving the target locally failed or returned no addresses.
    Resolve,
    /// SOCKS5 method selection or response parsing failed.
    Negotiation,
    /// The proxy rejected authentication or offered no supported method.
    Authentication,
    /// The proxy returned a failure reply for the requested SOCKS5 command.
    Rejected,
}

/// Error returned before a SOCKS5 tunnel is established.
#[derive(Debug)]
pub struct Socks5Error {
    kind: Socks5ErrorKind,
    source: Option<Socks5ErrorSource>,
}

#[derive(Debug)]
enum Socks5ErrorSource {
    Io(std::io::Error),
    Protocol(tokio_socks::Error),
}

impl Socks5Error {
    /// Returns the stable failure category.
    #[must_use]
    pub fn kind(&self) -> Socks5ErrorKind {
        self.kind
    }

    pub(super) const fn without_source(kind: Socks5ErrorKind) -> Self {
        Self { kind, source: None }
    }

    pub(super) fn io(kind: Socks5ErrorKind, source: std::io::Error) -> Self {
        Self {
            kind,
            source: Some(Socks5ErrorSource::Io(source)),
        }
    }

    fn connect(source: std::io::Error) -> Self {
        Self {
            kind: Socks5ErrorKind::Connect,
            source: Some(Socks5ErrorSource::Io(source)),
        }
    }

    fn resolve(source: std::io::Error) -> Self {
        Self {
            kind: Socks5ErrorKind::Resolve,
            source: Some(Socks5ErrorSource::Io(source)),
        }
    }

    fn invalid_target(source: tokio_socks::Error) -> Self {
        Self {
            kind: Socks5ErrorKind::InvalidTarget,
            source: Some(Socks5ErrorSource::Protocol(source)),
        }
    }

    pub(super) const fn invalid_authentication() -> Self {
        Self::without_source(Socks5ErrorKind::InvalidAuthentication)
    }

    fn negotiation(source: tokio_socks::Error) -> Self {
        let kind = match &source {
            tokio_socks::Error::GeneralSocksServerFailure
            | tokio_socks::Error::ConnectionNotAllowedByRuleset
            | tokio_socks::Error::NetworkUnreachable
            | tokio_socks::Error::HostUnreachable
            | tokio_socks::Error::ConnectionRefused
            | tokio_socks::Error::TtlExpired
            | tokio_socks::Error::CommandNotSupported
            | tokio_socks::Error::AddressTypeNotSupported
            | tokio_socks::Error::UnknownError => Socks5ErrorKind::Rejected,
            tokio_socks::Error::InvalidAuthValues(_) => Socks5ErrorKind::InvalidAuthentication,
            tokio_socks::Error::NoAcceptableAuthMethods
            | tokio_socks::Error::UnknownAuthMethod
            | tokio_socks::Error::PasswordAuthFailure(_)
            | tokio_socks::Error::AuthorizationRequired
            | tokio_socks::Error::IdentdAuthFailure
            | tokio_socks::Error::InvalidUserIdAuthFailure => Socks5ErrorKind::Authentication,
            _ => Socks5ErrorKind::Negotiation,
        };
        Self {
            kind,
            source: Some(Socks5ErrorSource::Protocol(source)),
        }
    }
}

impl fmt::Display for Socks5Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            Socks5ErrorKind::InvalidTarget => "invalid SOCKS5 target",
            Socks5ErrorKind::InvalidAuthentication => "invalid SOCKS5 authentication credentials",
            Socks5ErrorKind::RuntimeUnavailable => "SOCKS5 proxy requires a Tokio runtime",
            Socks5ErrorKind::Connect => "SOCKS5 proxy TCP connection failed",
            Socks5ErrorKind::Resolve => "SOCKS5 target DNS resolution failed",
            Socks5ErrorKind::Negotiation => "SOCKS5 negotiation failed",
            Socks5ErrorKind::Authentication => "SOCKS5 proxy authentication failed",
            Socks5ErrorKind::Rejected => "SOCKS5 proxy rejected the requested command",
        })
    }
}

impl StdError for Socks5Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self.source.as_ref()? {
            Socks5ErrorSource::Io(source) => Some(source),
            Socks5ErrorSource::Protocol(source) => Some(source),
        }
    }
}

impl Socks5ErrorKind {
    const fn trace_name(self) -> &'static str {
        match self {
            Self::InvalidTarget => "invalid_target",
            Self::InvalidAuthentication => "invalid_authentication",
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::Connect => "connect_error",
            Self::Resolve => "resolve_error",
            Self::Negotiation => "negotiation_error",
            Self::Authentication => "authentication_error",
            Self::Rejected => "rejected",
        }
    }
}

/// Authentication offered during SOCKS5 method negotiation.
///
/// Debug output intentionally omits credential values.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub enum Socks5Auth<'a> {
    /// Offer only the SOCKS5 no-authentication method.
    None,
    /// Offer no-authentication and RFC 1929 username/password authentication.
    UsernamePassword {
        /// RFC 1929 username, encoded as UTF-8 bytes on the wire.
        username: &'a str,
        /// RFC 1929 password, encoded as UTF-8 bytes on the wire.
        password: &'a str,
    },
}

impl fmt::Debug for Socks5Auth<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::None => "None",
            Self::UsernamePassword { .. } => "UsernamePassword(<redacted>)",
        })
    }
}

impl Socks5Auth<'_> {
    pub(crate) fn validate(self) -> Result<Self, Socks5Error> {
        if let Self::UsernamePassword { username, password } = self {
            let username_valid = (1..=255).contains(&username.len());
            let password_valid = (1..=255).contains(&password.len());
            if !username_valid || !password_valid {
                return Err(Socks5Error::invalid_authentication());
            }
        }
        Ok(self)
    }
}

/// Establishes a no-auth SOCKS5 CONNECT tunnel with proxy-owned target DNS.
///
/// Only the proxy endpoint is resolved locally. Domain targets are sent to the
/// proxy as SOCKS5 `DOMAIN` addresses. Target validation completes before proxy
/// DNS resolution or TCP I/O, and proxy failure never opens a direct target
/// connection.
///
/// # Errors
///
/// Returns [`Socks5Error`] for an invalid target, missing Tokio runtime, proxy
/// TCP failure, malformed negotiation, or a rejected CONNECT request.
pub async fn connect_socks5_tunnel_direct(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
) -> Result<tokio::net::TcpStream, Socks5Error> {
    connect_socks5_tunnel_direct_with_auth(
        proxy_host,
        proxy_port,
        target_host,
        target_port,
        Socks5Auth::None,
    )
    .await
}

/// Establishes a SOCKS5 CONNECT tunnel with proxy-owned target DNS.
///
/// Authentication and target validation complete before proxy DNS resolution
/// or TCP I/O. Credential values are not included in errors or trace fields.
///
/// # Errors
///
/// Returns [`Socks5Error`] for invalid authentication or target values, a
/// missing Tokio runtime, proxy TCP failure, malformed negotiation,
/// authentication failure, or a rejected CONNECT request.
pub async fn connect_socks5_tunnel_direct_with_auth(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    auth: Socks5Auth<'_>,
) -> Result<tokio::net::TcpStream, Socks5Error> {
    socks5_tunnel_remote_dns(
        Dialer::default(),
        proxy_host,
        proxy_port,
        target_host,
        target_port,
        auth,
    )
    .await
}

/// Opens a SOCKS5 CONNECT tunnel with proxy-owned DNS on a socket from
/// `dialer`; the target is never resolved locally.
pub(crate) async fn socks5_tunnel_remote_dns(
    dialer: Dialer<'_>,
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    auth: Socks5Auth<'_>,
) -> Result<tokio::net::TcpStream, Socks5Error> {
    trace_connect("remote", async {
        let auth = auth.validate()?;
        let target = prepare_target(target_host, target_port)?;
        let stream = connect_proxy(dialer, proxy_host, proxy_port).await?;
        establish(stream, target, auth).await
    })
    .await
}

/// Establishes a no-auth SOCKS5 CONNECT tunnel with locally resolved target DNS.
///
/// The target is resolved before connecting to the proxy, and the selected IP
/// address is sent as a SOCKS5 `IPV4` or `IPV6` target. Proxy failure never
/// opens a direct target connection.
///
/// # Errors
///
/// Returns [`Socks5Error`] for a missing Tokio runtime, target DNS failure,
/// proxy TCP failure, malformed negotiation, or a rejected CONNECT request.
pub async fn connect_socks5_tunnel_local(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
) -> Result<tokio::net::TcpStream, Socks5Error> {
    connect_socks5_tunnel_local_with_auth(
        proxy_host,
        proxy_port,
        target_host,
        target_port,
        Socks5Auth::None,
    )
    .await
}

/// Establishes a SOCKS5 CONNECT tunnel with locally resolved target DNS.
///
/// Authentication is validated before target DNS resolution or TCP I/O.
/// Credential values are not included in errors or trace fields.
///
/// # Errors
///
/// Returns [`Socks5Error`] for invalid authentication, a missing Tokio runtime,
/// target DNS failure, proxy TCP failure, malformed negotiation,
/// authentication failure, or a rejected CONNECT request.
pub async fn connect_socks5_tunnel_local_with_auth(
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    auth: Socks5Auth<'_>,
) -> Result<tokio::net::TcpStream, Socks5Error> {
    socks5_tunnel_local_dns(
        Dialer::default(),
        proxy_host,
        proxy_port,
        target_host,
        target_port,
        auth,
    )
    .await
}

/// Opens a SOCKS5 CONNECT tunnel with local target DNS on sockets from
/// `dialer`, resolving the target through the dialer's address cache.
pub(crate) async fn socks5_tunnel_local_dns(
    dialer: Dialer<'_>,
    proxy_host: &str,
    proxy_port: u16,
    target_host: &str,
    target_port: u16,
    auth: Socks5Auth<'_>,
) -> Result<tokio::net::TcpStream, Socks5Error> {
    trace_connect("local", async {
        let auth = auth.validate()?;
        if target_host.is_empty() {
            return Err(Socks5Error::without_source(Socks5ErrorKind::InvalidTarget));
        }
        tokio::runtime::Handle::try_current()
            .map_err(|_| Socks5Error::without_source(Socks5ErrorKind::RuntimeUnavailable))?;
        let targets = poll_tokio_io(|| resolve(dialer.addresses, target_host, target_port))
            .await
            .map_err(|_| Socks5Error::without_source(Socks5ErrorKind::RuntimeUnavailable))?
            .map_err(Socks5Error::resolve)?;
        let mut ordered = Vec::new();
        for target in targets {
            if !ordered.contains(&target) {
                ordered.push(target);
            }
        }
        connect_local_to_addresses_with_auth(dialer, proxy_host, proxy_port, ordered, auth).await
    })
    .await
}

#[cfg(test)]
pub(super) async fn connect_socks5_tunnel<S>(
    stream: S,
    target_host: &str,
    target_port: u16,
) -> Result<S, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    connect_socks5_tunnel_with_auth(stream, target_host, target_port, Socks5Auth::None).await
}

#[cfg(test)]
pub(super) async fn connect_socks5_tunnel_with_auth<S>(
    stream: S,
    target_host: &str,
    target_port: u16,
    auth: Socks5Auth<'_>,
) -> Result<S, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    trace_connect("remote", async {
        let auth = auth.validate()?;
        let target = prepare_target(target_host, target_port)?;
        establish(stream, target, auth).await
    })
    .await
}

fn prepare_target(host: &str, port: u16) -> Result<TargetAddr<'_>, Socks5Error> {
    if host.is_empty() {
        return Err(Socks5Error::without_source(Socks5ErrorKind::InvalidTarget));
    }
    (host, port)
        .into_target_addr()
        .map_err(Socks5Error::invalid_target)
}

async fn establish<S>(
    stream: S,
    target: TargetAddr<'_>,
    auth: Socks5Auth<'_>,
) -> Result<S, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let stream = match auth {
        Socks5Auth::None => Socks5Stream::connect_with_socket(stream, target).await,
        Socks5Auth::UsernamePassword { username, password } => {
            Socks5Stream::connect_with_password_and_socket(stream, target, username, password).await
        }
    };
    stream
        .map(Socks5Stream::into_inner)
        .map_err(Socks5Error::negotiation)
}

#[cfg(test)]
pub(super) async fn connect_local_to_addresses(
    proxy_host: &str,
    proxy_port: u16,
    targets: impl IntoIterator<Item = SocketAddr>,
) -> Result<tokio::net::TcpStream, Socks5Error> {
    connect_local_to_addresses_with_auth(
        Dialer::default(),
        proxy_host,
        proxy_port,
        targets,
        Socks5Auth::None,
    )
    .await
}

pub(super) async fn connect_local_to_addresses_with_auth(
    dialer: Dialer<'_>,
    proxy_host: &str,
    proxy_port: u16,
    targets: impl IntoIterator<Item = SocketAddr>,
    auth: Socks5Auth<'_>,
) -> Result<tokio::net::TcpStream, Socks5Error> {
    let auth = auth.validate()?;
    let mut last_rejection = None;
    for target in targets {
        let stream = connect_proxy(dialer, proxy_host, proxy_port).await?;
        match establish(stream, TargetAddr::Ip(target), auth).await {
            Ok(stream) => return Ok(stream),
            Err(error) if error.is_target_specific_rejection() => {
                last_rejection = Some(error);
            }
            Err(error) => return Err(error),
        }
    }
    Err(last_rejection.unwrap_or_else(|| Socks5Error::without_source(Socks5ErrorKind::Resolve)))
}

impl Socks5Error {
    fn is_target_specific_rejection(&self) -> bool {
        matches!(
            self.source,
            Some(Socks5ErrorSource::Protocol(
                tokio_socks::Error::NetworkUnreachable
                    | tokio_socks::Error::HostUnreachable
                    | tokio_socks::Error::ConnectionRefused
                    | tokio_socks::Error::TtlExpired
                    | tokio_socks::Error::AddressTypeNotSupported
            ))
        )
    }
}

pub(super) async fn connect_proxy(
    dialer: Dialer<'_>,
    proxy_host: &str,
    proxy_port: u16,
) -> Result<tokio::net::TcpStream, Socks5Error> {
    connect_tcp(proxy_host, proxy_port, dialer)
        .await
        .map_err(|error| match error {
            DirectConnectError::RuntimeUnavailable => {
                Socks5Error::without_source(Socks5ErrorKind::RuntimeUnavailable)
            }
            DirectConnectError::Connect(error) => Socks5Error::connect(error),
        })
}

pub(super) async fn trace_connect<F, S>(dns: &'static str, operation: F) -> Result<S, Socks5Error>
where
    F: Future<Output = Result<S, Socks5Error>>,
{
    let span = debug_span!(
        "proxy.socks5",
        proxy_scheme = "socks5",
        dns,
        outcome = field::Empty,
        error_kind = field::Empty,
    );
    let outcome = ConnectOutcome::new(&span);
    let result = operation.instrument(span.clone()).await;
    outcome.finish(&result);
    result
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

    fn finish(mut self, result: &Result<impl Sized, Socks5Error>) {
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
