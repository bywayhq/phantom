use std::{error::Error as StdError, fmt};

use phantom_net::{proxy::HttpConnectHeader, request::RequestHeader};

use crate::authority::{Endpoint, ParseUriError, parse_absolute_uri};

mod socks5;

pub use socks5::{Socks5DnsMode, Socks5Proxy, Socks5ProxyConfigError, Socks5ProxyConfigErrorKind};

/// Route used to establish one origin connection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Route {
    /// Connect directly to the origin.
    #[default]
    Direct,
    /// Tunnel TCP through an HTTP proxy using CONNECT.
    HttpConnect(HttpProxy),
    /// Tunnel TCP through a SOCKS5 proxy with explicit DNS ownership.
    Socks5(Socks5Proxy),
}

impl Route {
    /// Returns a direct route.
    #[must_use]
    pub const fn direct() -> Self {
        Self::Direct
    }

    /// Returns an HTTP CONNECT route.
    #[must_use]
    pub fn http_connect(proxy: HttpProxy) -> Self {
        Self::HttpConnect(proxy)
    }

    /// Returns a SOCKS5 route using the proxy's configured DNS mode.
    #[must_use]
    pub fn socks5(proxy: Socks5Proxy) -> Self {
        Self::Socks5(proxy)
    }

    pub(crate) const fn trace_name(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::HttpConnect(proxy) => proxy.trace_name(),
            Self::Socks5(proxy) => match proxy.dns_mode() {
                Socks5DnsMode::Local => "socks5_local_dns",
                Socks5DnsMode::Remote => "socks5_remote_dns",
            },
        }
    }

    pub(crate) const fn as_http_proxy(&self) -> Option<&HttpProxy> {
        match self {
            Self::HttpConnect(proxy) => Some(proxy),
            Self::Direct | Self::Socks5(_) => None,
        }
    }
}

/// HTTP proxy configuration for CONNECT tunnels.
#[derive(Clone, Eq, PartialEq)]
pub struct HttpProxy {
    transport: HttpProxyTransport,
    endpoint: Endpoint,
    connect_headers: Vec<HttpConnectHeader>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HttpProxyTransport {
    Plaintext,
    Tls,
}

impl HttpProxy {
    /// Parses an HTTP or HTTPS proxy URI.
    ///
    /// The URI must use `http` or `https`, contain only an authority and
    /// optional `/`, and must not contain credentials. The default port is 80
    /// for HTTP and 443 for HTTPS. Unicode hostnames are normalized to their
    /// canonical ASCII form.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyConfigError`] when the URI is malformed or uses an
    /// unsupported shape.
    pub fn new(uri: &str) -> Result<Self, ProxyConfigError> {
        let uri = parse_absolute_uri(uri).map_err(|error| match error {
            ParseUriError::Syntax(error) => ProxyConfigError::invalid_uri(error),
            ParseUriError::Authority(error) => ProxyConfigError::authority(error.message()),
        })?;
        let (transport, default_port) = match uri.scheme_str() {
            Some("http") => (HttpProxyTransport::Plaintext, 80),
            Some("https") => (HttpProxyTransport::Tls, 443),
            _ => return Err(ProxyConfigError::unsupported_scheme()),
        };
        let authority = uri
            .authority()
            .cloned()
            .ok_or_else(ProxyConfigError::invalid_authority)?;
        if !matches!(
            uri.path_and_query().map(|value| value.as_str()),
            None | Some("/")
        ) {
            return Err(ProxyConfigError::unexpected_path());
        }
        let endpoint = Endpoint::new(authority, default_port)
            .map_err(|error| ProxyConfigError::authority(error.message()))?;
        Ok(Self {
            transport,
            endpoint,
            connect_headers: vec![HttpConnectHeader::authority("Host")],
        })
    }

    /// Appends one ordered field to the CONNECT request.
    ///
    /// A literal `Host` or request-framing field is rejected before proxy I/O;
    /// use [`HttpConnectHeader::Authority`] to control `Host` placement.
    #[must_use]
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.connect_headers.push(HttpConnectHeader::field(header));
        self
    }

    /// Replaces the literal CONNECT fields after the default leading `Host`.
    #[must_use]
    pub fn headers(mut self, headers: Vec<RequestHeader>) -> Self {
        self.connect_headers = std::iter::once(HttpConnectHeader::authority("Host"))
            .chain(headers.into_iter().map(HttpConnectHeader::field))
            .collect();
        self
    }

    /// Replaces the complete CONNECT field sequence.
    ///
    /// The sequence must contain exactly one
    /// [`HttpConnectHeader::Authority`] placeholder. Validation happens before
    /// proxy I/O when a request is sent.
    #[must_use]
    pub fn connect_headers(mut self, headers: Vec<HttpConnectHeader>) -> Self {
        self.connect_headers = headers;
        self
    }

    pub(crate) fn host(&self) -> &str {
        self.endpoint.host()
    }

    pub(crate) fn port(&self) -> u16 {
        self.endpoint.port()
    }

    pub(crate) const fn uses_tls(&self) -> bool {
        matches!(self.transport, HttpProxyTransport::Tls)
    }

    const fn trace_name(&self) -> &'static str {
        match self.transport {
            HttpProxyTransport::Plaintext => "http_connect",
            HttpProxyTransport::Tls => "https_connect",
        }
    }

    pub(crate) fn ordered_connect_headers(&self) -> &[HttpConnectHeader] {
        &self.connect_headers
    }
}

impl fmt::Debug for HttpProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpProxy")
            .field(
                "scheme",
                &match self.transport {
                    HttpProxyTransport::Plaintext => "http",
                    HttpProxyTransport::Tls => "https",
                },
            )
            .field("authority", self.endpoint.authority())
            .field("connect_header_count", &self.connect_headers.len())
            .finish_non_exhaustive()
    }
}

/// Stable category of proxy-configuration failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ProxyConfigErrorKind {
    /// The proxy URI is syntactically invalid.
    InvalidUri,
    /// The proxy URI scheme is unsupported.
    UnsupportedScheme,
    /// The proxy URI authority is missing or invalid.
    InvalidAuthority,
    /// The proxy URI contains a path or query.
    UnexpectedPath,
}

/// Error returned while constructing an [`HttpProxy`].
#[derive(Debug)]
pub struct ProxyConfigError {
    kind: ProxyConfigErrorKind,
    message: &'static str,
    source: Option<http::uri::InvalidUri>,
}

impl ProxyConfigError {
    fn invalid_uri(source: http::uri::InvalidUri) -> Self {
        Self {
            kind: ProxyConfigErrorKind::InvalidUri,
            message: "invalid HTTP proxy URI",
            source: Some(source),
        }
    }

    fn unsupported_scheme() -> Self {
        Self::without_source(
            ProxyConfigErrorKind::UnsupportedScheme,
            "HTTP CONNECT proxy URI must use the http or https scheme",
        )
    }

    fn invalid_authority() -> Self {
        Self::without_source(
            ProxyConfigErrorKind::InvalidAuthority,
            "HTTP proxy URI must include an authority",
        )
    }

    fn authority(message: &'static str) -> Self {
        Self::without_source(ProxyConfigErrorKind::InvalidAuthority, message)
    }

    fn unexpected_path() -> Self {
        Self::without_source(
            ProxyConfigErrorKind::UnexpectedPath,
            "HTTP proxy URI must not contain a path or query",
        )
    }

    fn without_source(kind: ProxyConfigErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            source: None,
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub fn kind(&self) -> ProxyConfigErrorKind {
        self.kind
    }
}

impl fmt::Display for ProxyConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)
    }
}

impl StdError for ProxyConfigError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_ref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}

#[cfg(test)]
mod tests {
    use super::{HttpProxy, ProxyConfigErrorKind};

    #[test]
    fn parses_domain_ipv4_and_bracketed_ipv6_endpoints() -> Result<(), Box<dyn std::error::Error>> {
        let domain = HttpProxy::new("http://proxy.example")?;
        let secure = HttpProxy::new("https://proxy.example")?;
        let ipv4 = HttpProxy::new("http://127.0.0.1:8080")?;
        let ipv6 = HttpProxy::new("http://[::1]:3128")?;

        assert_eq!(domain.endpoint.host(), "proxy.example");
        assert_eq!(domain.endpoint.port(), 80);
        assert_eq!(secure.endpoint.port(), 443);
        assert_eq!(ipv4.endpoint.host(), "127.0.0.1");
        assert_eq!(ipv4.endpoint.port(), 8080);
        assert_eq!(ipv6.endpoint.host(), "::1");
        assert_eq!(ipv6.endpoint.port(), 3128);
        Ok(())
    }

    #[test]
    fn canonicalizes_unicode_proxy_hosts() -> Result<(), Box<dyn std::error::Error>> {
        let proxy = HttpProxy::new("https://BÜCHER.Example:8443")?;

        assert_eq!(proxy.endpoint.host(), "xn--bcher-kva.example");
        assert_eq!(
            proxy.endpoint.authority().as_str(),
            "xn--bcher-kva.example:8443"
        );
        Ok(())
    }

    #[test]
    fn proxy_transport_is_part_of_route_identity_and_tracing()
    -> Result<(), Box<dyn std::error::Error>> {
        let plaintext = HttpProxy::new("http://proxy.example:8080")?;
        let secure = HttpProxy::new("https://proxy.example:8080")?;

        assert_ne!(plaintext, secure);
        assert!(!plaintext.uses_tls());
        assert!(secure.uses_tls());
        assert_eq!(plaintext.trace_name(), "http_connect");
        assert_eq!(secure.trace_name(), "https_connect");
        Ok(())
    }

    #[test]
    fn rejects_credentials_paths_queries_and_other_schemes() -> Result<(), &'static str> {
        for (uri, kind) in [
            (
                "socks5://proxy.example",
                ProxyConfigErrorKind::UnsupportedScheme,
            ),
            (
                "http://proxy.example/path",
                ProxyConfigErrorKind::UnexpectedPath,
            ),
            (
                "http://proxy.example/?x=1",
                ProxyConfigErrorKind::UnexpectedPath,
            ),
            (
                "http://user:secret@proxy.example",
                ProxyConfigErrorKind::InvalidAuthority,
            ),
            (
                "http://\u{200d}.example",
                ProxyConfigErrorKind::InvalidAuthority,
            ),
        ] {
            let error = match HttpProxy::new(uri) {
                Ok(_) => return Err("invalid proxy URI was accepted"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), kind, "{uri}");
        }
        Ok(())
    }
}
