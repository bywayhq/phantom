use std::{error::Error as StdError, fmt};

use http::Uri;

use crate::authority::Endpoint;

/// SOCKS5 proxy configuration with proxy-owned origin DNS resolution.
///
/// This slice accepts only `socks5h://` URIs so DNS ownership is explicit.
/// Credentials, paths, and queries are rejected.
#[derive(Clone, Eq, PartialEq)]
pub struct Socks5Proxy {
    endpoint: Endpoint,
}

impl Socks5Proxy {
    /// Parses a remote-DNS SOCKS5 proxy URI.
    ///
    /// Port 1080 is used when omitted. Unicode hostnames must be normalized to
    /// an ASCII A-label by the caller.
    ///
    /// # Errors
    ///
    /// Returns [`Socks5ProxyConfigError`] when the URI is malformed or uses an
    /// unsupported shape.
    pub fn new(uri: &str) -> Result<Self, Socks5ProxyConfigError> {
        let uri = uri
            .parse::<Uri>()
            .map_err(Socks5ProxyConfigError::invalid_uri)?;
        if uri.scheme_str() != Some("socks5h") {
            return Err(Socks5ProxyConfigError::unsupported_scheme());
        }
        let authority = uri
            .authority()
            .cloned()
            .ok_or_else(Socks5ProxyConfigError::invalid_authority)?;
        if !matches!(
            uri.path_and_query().map(|value| value.as_str()),
            None | Some("/")
        ) {
            return Err(Socks5ProxyConfigError::unexpected_path());
        }
        let endpoint = Endpoint::new(authority, 1080)
            .map_err(|error| Socks5ProxyConfigError::authority(error.message()))?;
        Ok(Self { endpoint })
    }

    pub(crate) fn host(&self) -> &str {
        self.endpoint.host()
    }

    pub(crate) fn port(&self) -> u16 {
        self.endpoint.port()
    }
}

impl fmt::Debug for Socks5Proxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Socks5Proxy")
            .field("authority", self.endpoint.authority())
            .field("dns", &"remote")
            .finish()
    }
}

/// Stable category of SOCKS5 proxy-configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Socks5ProxyConfigErrorKind {
    /// The proxy URI is syntactically invalid.
    InvalidUri,
    /// The proxy URI scheme is not `socks5h`.
    UnsupportedScheme,
    /// The proxy URI authority is missing or invalid.
    InvalidAuthority,
    /// The proxy URI contains a path or query.
    UnexpectedPath,
}

/// Error returned while constructing a [`Socks5Proxy`].
#[derive(Debug)]
pub struct Socks5ProxyConfigError {
    kind: Socks5ProxyConfigErrorKind,
    message: &'static str,
    source: Option<http::uri::InvalidUri>,
}

impl Socks5ProxyConfigError {
    fn invalid_uri(source: http::uri::InvalidUri) -> Self {
        Self {
            kind: Socks5ProxyConfigErrorKind::InvalidUri,
            message: "invalid SOCKS5 proxy URI",
            source: Some(source),
        }
    }

    fn unsupported_scheme() -> Self {
        Self::without_source(
            Socks5ProxyConfigErrorKind::UnsupportedScheme,
            "remote-DNS SOCKS5 proxy URI must use the socks5h scheme",
        )
    }

    fn invalid_authority() -> Self {
        Self::without_source(
            Socks5ProxyConfigErrorKind::InvalidAuthority,
            "SOCKS5 proxy URI must include an authority",
        )
    }

    fn authority(message: &'static str) -> Self {
        Self::without_source(Socks5ProxyConfigErrorKind::InvalidAuthority, message)
    }

    fn unexpected_path() -> Self {
        Self::without_source(
            Socks5ProxyConfigErrorKind::UnexpectedPath,
            "SOCKS5 proxy URI must not contain a path or query",
        )
    }

    fn without_source(kind: Socks5ProxyConfigErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            source: None,
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> Socks5ProxyConfigErrorKind {
        self.kind
    }
}

impl fmt::Display for Socks5ProxyConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl StdError for Socks5ProxyConfigError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::{Socks5Proxy, Socks5ProxyConfigErrorKind};

    #[test]
    fn parses_domain_ipv4_and_bracketed_ipv6_endpoints() -> Result<(), Box<dyn std::error::Error>> {
        let domain = Socks5Proxy::new("socks5h://proxy.example")?;
        let ipv4 = Socks5Proxy::new("socks5h://127.0.0.1:8080")?;
        let ipv6 = Socks5Proxy::new("socks5h://[::1]:1081")?;

        assert_eq!(domain.endpoint.host(), "proxy.example");
        assert_eq!(domain.endpoint.port(), 1080);
        assert_eq!(ipv4.endpoint.host(), "127.0.0.1");
        assert_eq!(ipv4.endpoint.port(), 8080);
        assert_eq!(ipv6.endpoint.host(), "::1");
        assert_eq!(ipv6.endpoint.port(), 1081);
        Ok(())
    }

    #[test]
    fn rejects_credentials_paths_queries_and_other_schemes() -> Result<(), &'static str> {
        for (uri, kind) in [
            (
                "socks5://proxy.example",
                Socks5ProxyConfigErrorKind::UnsupportedScheme,
            ),
            (
                "socks5h://proxy.example/path",
                Socks5ProxyConfigErrorKind::UnexpectedPath,
            ),
            (
                "socks5h://proxy.example/?x=1",
                Socks5ProxyConfigErrorKind::UnexpectedPath,
            ),
            (
                "socks5h://user:secret@proxy.example",
                Socks5ProxyConfigErrorKind::InvalidAuthority,
            ),
        ] {
            let error = match Socks5Proxy::new(uri) {
                Ok(_) => return Err("invalid SOCKS5 proxy URI was accepted"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), kind, "{uri}");
        }
        Ok(())
    }
}
