use std::{error::Error as StdError, fmt, future::Future};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio_socks::{IntoTargetAddr, TargetAddr, tcp::Socks5Stream};
use tracing::{Instrument, Span, debug_span, field};

use crate::direct::{DirectConnectError, connect_tcp};

/// Stable category of SOCKS5 tunnel failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Socks5ErrorKind {
    /// The remote target cannot be encoded as a SOCKS5 address.
    InvalidTarget,
    /// The request was polled outside a Tokio runtime.
    RuntimeUnavailable,
    /// Connecting to the proxy failed.
    Connect,
    /// SOCKS5 method selection or response parsing failed.
    Negotiation,
    /// The proxy returned a SOCKS5 CONNECT failure reply.
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

    const fn without_source(kind: Socks5ErrorKind) -> Self {
        Self { kind, source: None }
    }

    fn connect(source: std::io::Error) -> Self {
        Self {
            kind: Socks5ErrorKind::Connect,
            source: Some(Socks5ErrorSource::Io(source)),
        }
    }

    fn invalid_target(source: tokio_socks::Error) -> Self {
        Self {
            kind: Socks5ErrorKind::InvalidTarget,
            source: Some(Socks5ErrorSource::Protocol(source)),
        }
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
            Socks5ErrorKind::RuntimeUnavailable => "SOCKS5 proxy requires a Tokio runtime",
            Socks5ErrorKind::Connect => "SOCKS5 proxy TCP connection failed",
            Socks5ErrorKind::Negotiation => "SOCKS5 negotiation failed",
            Socks5ErrorKind::Rejected => "SOCKS5 proxy rejected CONNECT",
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
            Self::RuntimeUnavailable => "runtime_unavailable",
            Self::Connect => "connect_error",
            Self::Negotiation => "negotiation_error",
            Self::Rejected => "rejected",
        }
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
    trace_connect(async {
        let target = prepare_target(target_host, target_port)?;
        let stream = connect_tcp(proxy_host, proxy_port)
            .await
            .map_err(|error| match error {
                DirectConnectError::RuntimeUnavailable => {
                    Socks5Error::without_source(Socks5ErrorKind::RuntimeUnavailable)
                }
                DirectConnectError::Connect(error) => Socks5Error::connect(error),
            })?;
        establish(stream, target).await
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
    trace_connect(async {
        let target = prepare_target(target_host, target_port)?;
        establish(stream, target).await
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

async fn establish<S>(stream: S, target: TargetAddr<'_>) -> Result<S, Socks5Error>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    Socks5Stream::connect_with_socket(stream, target)
        .await
        .map(Socks5Stream::into_inner)
        .map_err(Socks5Error::negotiation)
}

async fn trace_connect<F, S>(operation: F) -> Result<S, Socks5Error>
where
    F: Future<Output = Result<S, Socks5Error>>,
{
    let span = debug_span!(
        "proxy.socks5",
        proxy_scheme = "socks5",
        dns = "remote",
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
