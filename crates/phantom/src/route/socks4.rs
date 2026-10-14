use std::{error::Error, fmt};

use phantom_net::proxy::{Socks4Error, Socks4UserId};

use super::ProxyConfigSource;
use crate::authority::{Endpoint, ParseUriError, parse_absolute_uri};

/// Where SOCKS4 target names are resolved.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Socks4DnsMode {
    /// Resolve locally, using the first IPv4 answer.
    Local,
    /// Send domain names to the SOCKS4a proxy.
    Remote,
}

/// A SOCKS4 or SOCKS4a TCP proxy.
///
/// `socks4://` resolves targets locally and selects the first IPv4 answer.
/// `socks4a://` sends domain names to the proxy without a local lookup.
/// Both accept IPv4 targets. IPv6 targets and HTTP/3 fail before proxy I/O.
/// The proxy endpoint itself may use IPv6.
///
/// URI user information, paths and queries are rejected. Configure the
/// optional identification string with [`Self::with_user_id`]. SOCKS4 has
/// no password negotiation. A rejection never triggers a direct connection
/// or a change of protocol or route.
///
/// ```
/// use phantom::{Route, Socks4Proxy};
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let proxy = Socks4Proxy::new("socks4a://127.0.0.1:1080")?
///     .with_user_id("user")?;
/// let route = Route::socks4(proxy);
/// # drop(route);
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Eq, PartialEq)]
pub struct Socks4Proxy {
    endpoint: Endpoint,
    dns_mode: Socks4DnsMode,
    user_id: Box<str>,
}

impl Socks4Proxy {
    /// Parses a `socks4` or `socks4a` proxy URI; omitted ports use 1080.
    ///
    /// Host names are normalized to ASCII. Invalid schemes, authorities,
    /// paths and queries return a typed configuration error.
    pub fn new(uri: &str) -> Result<Self, Socks4ProxyConfigError> {
        let uri = parse_absolute_uri(uri).map_err(|error| match error {
            ParseUriError::Syntax(source) => Socks4ProxyConfigError {
                kind: Socks4ProxyConfigErrorKind::InvalidUri,
                source: Some(ProxyConfigSource::Uri(source)),
            },
            ParseUriError::Authority(source) => Socks4ProxyConfigError {
                kind: Socks4ProxyConfigErrorKind::InvalidAuthority,
                source: Some(ProxyConfigSource::Authority(source)),
            },
            ParseUriError::Fragment => {
                Socks4ProxyConfigError::new(Socks4ProxyConfigErrorKind::UnexpectedPath)
            }
        })?;
        let dns_mode = match uri.scheme_str() {
            Some("socks4") => Socks4DnsMode::Local,
            Some("socks4a") => Socks4DnsMode::Remote,
            _ => {
                return Err(Socks4ProxyConfigError::new(
                    Socks4ProxyConfigErrorKind::UnsupportedScheme,
                ));
            }
        };
        let authority = uri.authority().cloned().ok_or_else(|| {
            Socks4ProxyConfigError::new(Socks4ProxyConfigErrorKind::InvalidAuthority)
        })?;
        if !matches!(
            uri.path_and_query().map(|value| value.as_str()),
            None | Some("/")
        ) {
            return Err(Socks4ProxyConfigError::new(
                Socks4ProxyConfigErrorKind::UnexpectedPath,
            ));
        }
        let endpoint = Endpoint::new(authority, 1080).map_err(|source| Socks4ProxyConfigError {
            kind: Socks4ProxyConfigErrorKind::InvalidAuthority,
            source: Some(ProxyConfigSource::Authority(source)),
        })?;
        Ok(Self {
            endpoint,
            dns_mode,
            user_id: "".into(),
        })
    }

    /// Sets a UTF-8 identification string, copied into this route.
    ///
    /// Empty is allowed. Embedded NUL and more than 255 bytes fail. The bound
    /// limits resource use; SOCKS4 itself has no user-ID length field.
    /// Values appear on the proxy connection but never in debug output.
    pub fn with_user_id(mut self, value: impl AsRef<str>) -> Result<Self, Socks4ProxyConfigError> {
        let value = value.as_ref();
        Socks4UserId::new(value)
            .map_err(|_| Socks4ProxyConfigError::new(Socks4ProxyConfigErrorKind::InvalidUserId))?;
        self.user_id = value.into();
        Ok(self)
    }

    /// Returns where target domain names are resolved.
    #[must_use]
    pub const fn dns_mode(&self) -> Socks4DnsMode {
        self.dns_mode
    }

    pub(crate) fn tcp_route<'a>(
        &'a self,
        endpoint: phantom_net::route::Endpoint<'a>,
    ) -> Result<phantom_net::route::TcpRoute<'a>, Socks4Error> {
        use phantom_net::route::{Endpoint, Socks4Target, TcpRoute};
        Ok(TcpRoute::Socks4 {
            proxy: Endpoint {
                host: self.endpoint.host(),
                port: self.endpoint.port(),
            },
            target: match self.dns_mode {
                Socks4DnsMode::Local => Socks4Target::LocalDns(endpoint),
                Socks4DnsMode::Remote => Socks4Target::RemoteDns(endpoint),
            },
            user_id: Socks4UserId::new(&self.user_id)?,
        })
    }
}

impl fmt::Debug for Socks4Proxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Socks4Proxy")
            .field("authority", self.endpoint.authority())
            .field("dns", &self.dns_mode)
            .field("user_id", &"<redacted>")
            .finish()
    }
}

/// Stable category of SOCKS4 configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Socks4ProxyConfigErrorKind {
    /// The URI cannot be parsed.
    InvalidUri,
    /// The scheme is neither `socks4` nor `socks4a`.
    UnsupportedScheme,
    /// The proxy authority is missing or invalid, including URI user information.
    InvalidAuthority,
    /// The URI contains a path, query or fragment.
    UnexpectedPath,
    /// The user ID exceeds 255 bytes or contains a NUL.
    InvalidUserId,
}

/// Failure to construct a SOCKS4 proxy; identification values are omitted.
#[derive(Debug)]
pub struct Socks4ProxyConfigError {
    kind: Socks4ProxyConfigErrorKind,
    source: Option<ProxyConfigSource>,
}

impl Socks4ProxyConfigError {
    fn new(kind: Socks4ProxyConfigErrorKind) -> Self {
        Self { kind, source: None }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> Socks4ProxyConfigErrorKind {
        self.kind
    }
}

impl fmt::Display for Socks4ProxyConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self.kind {
            Socks4ProxyConfigErrorKind::InvalidUri => "invalid SOCKS4 proxy URI",
            Socks4ProxyConfigErrorKind::UnsupportedScheme => {
                "SOCKS4 proxy URI must use socks4 or socks4a"
            }
            Socks4ProxyConfigErrorKind::InvalidAuthority => "invalid SOCKS4 proxy authority",
            Socks4ProxyConfigErrorKind::UnexpectedPath => {
                "SOCKS4 proxy URI must not contain a path, query or fragment"
            }
            Socks4ProxyConfigErrorKind::InvalidUserId => {
                "SOCKS4 user ID must be NUL-free and at most 255 bytes"
            }
        })
    }
}

impl Error for Socks4ProxyConfigError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.source.as_ref().map(ProxyConfigSource::as_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_dns_modes_and_ipv6_proxy_endpoints() -> Result<(), Box<dyn Error>> {
        let local = Socks4Proxy::new("socks4://proxy.example")?;
        let remote = Socks4Proxy::new("socks4a://[::1]:1081")?;
        assert_eq!(local.dns_mode(), Socks4DnsMode::Local);
        assert_eq!(local.endpoint.port(), 1080);
        assert_eq!(remote.dns_mode(), Socks4DnsMode::Remote);
        assert_eq!(remote.endpoint.host(), "::1");
        assert_eq!(remote.endpoint.port(), 1081);
        let route = crate::Route::socks4(remote);
        assert!(route.carries_origin_tls_for_alpn());
        assert!(!route.carries_quic_alternative());
        Ok(())
    }

    #[test]
    fn rejects_uri_credentials_and_invalid_user_id_without_leaking() -> Result<(), Box<dyn Error>> {
        for uri in [
            "socks4a://user:secret@proxy.example",
            "socks4://proxy.example/path",
            "socks4a://proxy.example/?query",
            "socks5://proxy.example",
        ] {
            assert!(Socks4Proxy::new(uri).is_err());
        }
        for value in ["secret\0user".to_owned(), "secret-user".repeat(30)] {
            let error = Socks4Proxy::new("socks4a://proxy.example")?
                .with_user_id(value)
                .err()
                .ok_or("operation unexpectedly succeeded")?;
            assert_eq!(error.kind(), Socks4ProxyConfigErrorKind::InvalidUserId);
            assert!(!format!("{error:?} {error}").contains("secret"));
        }
        let empty = Socks4Proxy::new("socks4a://proxy.example")?.with_user_id("")?;
        let configured = empty.clone().with_user_id("secret-user")?;
        assert_ne!(empty, configured);
        assert!(!format!("{configured:?}").contains("secret-user"));
        Ok(())
    }
}
