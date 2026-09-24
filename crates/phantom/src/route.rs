use std::{error::Error as StdError, fmt};

use phantom_net::{
    proxy::{HttpBasicCredentials, HttpConnectHeader, HttpsProxyConnector, HttpsProxyProtocol},
    request::RequestHeader,
};

use crate::authority::{Endpoint, ParseUriError, parse_absolute_uri};

mod connect_udp;
mod socks5;

pub use connect_udp::{
    ConnectUdpProxy, ConnectUdpProxyConfigError, ConnectUdpProxyConfigErrorKind,
};
pub use socks5::{Socks5DnsMode, Socks5Proxy, Socks5ProxyConfigError, Socks5ProxyConfigErrorKind};

/// Route used to establish one origin connection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Route {
    /// Connect directly to the origin.
    #[default]
    Direct,
    /// Route through an HTTP proxy using forwarding or CONNECT as required.
    HttpProxy(HttpProxy),
    /// Tunnel TCP through a SOCKS5 proxy with explicit DNS ownership.
    Socks5(Socks5Proxy),
    /// Tunnel exact HTTP/3 through an RFC 9298 CONNECT-UDP (MASQUE) proxy.
    ConnectUdp(ConnectUdpProxy),
}

impl Route {
    /// Returns a direct route.
    #[must_use]
    pub const fn direct() -> Self {
        Self::Direct
    }

    /// Returns an HTTP proxy route using the established CONNECT-oriented constructor.
    ///
    /// Prefer [`Self::http_proxy`] when the route may also carry plaintext
    /// HTTP/1.1 forwarding.
    #[must_use]
    pub fn http_connect(proxy: HttpProxy) -> Self {
        Self::HttpProxy(proxy)
    }

    /// Returns an HTTP proxy route.
    ///
    /// Plaintext HTTP/1.1 uses absolute-form forwarding. HTTPS protocols use
    /// CONNECT tunneling.
    #[must_use]
    pub fn http_proxy(proxy: HttpProxy) -> Self {
        Self::HttpProxy(proxy)
    }

    /// Returns a SOCKS5 route using the proxy's configured DNS mode.
    #[must_use]
    pub fn socks5(proxy: Socks5Proxy) -> Self {
        Self::Socks5(proxy)
    }

    /// Returns a CONNECT-UDP route for exact HTTP/3 requests.
    ///
    /// The proxy leg may be HTTP/3, HTTP/2, or HTTP/1.1; see
    /// [`ConnectUdpProxy`]. Every other request protocol, negotiated
    /// requests, and WebSocket reject this route before I/O.
    #[must_use]
    pub fn connect_udp(proxy: ConnectUdpProxy) -> Self {
        Self::ConnectUdp(proxy)
    }

    pub(crate) const fn trace_name(&self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::HttpProxy(proxy) => proxy.trace_name(),
            Self::Socks5(proxy) => match proxy.dns_mode() {
                Socks5DnsMode::Local => "socks5_local_dns",
                Socks5DnsMode::Remote => "socks5_remote_dns",
            },
            Self::ConnectUdp(proxy) => proxy.trace_name(),
        }
    }

    pub(crate) fn request_trace_name(&self, scheme: Option<&str>) -> &'static str {
        match (scheme, self) {
            (Some("http"), Self::HttpProxy(proxy)) if proxy.uses_tls() => "https_forward",
            (Some("http"), Self::HttpProxy(_)) => "http_forward",
            _ => self.trace_name(),
        }
    }

    /// Returns whether a negotiated `https://` request may use this route.
    ///
    /// Negotiation needs one TLS stream to the origin whose ALPN selects H1 or
    /// H2, and the Alt-Svc upgrade that rides on it needs a UDP path to the
    /// advertised alternative authority over the same route. Only a route that
    /// carries both qualifies:
    ///
    /// - [`Route::Direct`] carries both.
    /// - [`Route::Socks5`] carries both: RFC 1928 CONNECT for the origin TLS
    ///   stream and UDP ASSOCIATE for QUIC to the alternative.
    /// - [`Route::HttpProxy`] carries only TCP. An RFC 9110 section 9.3.6
    ///   CONNECT tunnel cannot carry QUIC, so a learned `h3` alternative would
    ///   never be reachable and would have to fall back to the proxy's TCP
    ///   leg, which Phantom does not do.
    /// - [`Route::ConnectUdp`] carries only QUIC, so it has no TLS stream for
    ///   ALPN to select a protocol on.
    pub(crate) const fn carries_negotiated_https(&self) -> bool {
        match self {
            Self::Direct | Self::Socks5(_) => true,
            Self::HttpProxy(_) | Self::ConnectUdp(_) => false,
        }
    }

    pub(crate) const fn as_http_proxy(&self) -> Option<&HttpProxy> {
        match self {
            Self::HttpProxy(proxy) => Some(proxy),
            Self::Direct | Self::Socks5(_) | Self::ConnectUdp(_) => None,
        }
    }
}

/// HTTP proxy configuration for forwarding and CONNECT tunneling.
#[derive(Clone, Eq, PartialEq)]
pub struct HttpProxy {
    transport: HttpProxyTransport,
    protocol: HttpsProxyProtocol,
    endpoint: Endpoint,
    connect_headers: Vec<HttpConnectHeader>,
    credentials: Option<HttpBasicCredentials>,
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
        let (transport, endpoint) = parse_http_proxy_uri(uri)?;
        Ok(Self {
            transport,
            protocol: HttpsProxyProtocol::Http1,
            endpoint,
            connect_headers: vec![HttpConnectHeader::authority("Host")],
            credentials: None,
        })
    }

    /// Configures challenge-driven HTTP Basic proxy authentication.
    ///
    /// The first proxy request omits credentials. Phantom sends them only
    /// after a valid Basic proxy challenge and retries once on a fresh proxy
    /// connection. URI credentials remain unsupported.
    ///
    /// Basic credentials sent to a plaintext `http://` proxy have no transport
    /// confidentiality. Use an `https://` proxy for sensitive credentials.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyConfigError`] when the username is empty or contains a
    /// colon, either value contains non-ASCII or control characters, or the
    /// encoded credential field exceeds its bounded size. The complete
    /// CONNECT head is validated when the request is prepared for sending.
    pub fn with_basic_auth(
        mut self,
        username: impl AsRef<str>,
        password: impl AsRef<str>,
    ) -> Result<Self, ProxyConfigError> {
        let credentials = HttpBasicCredentials::new(username, password)
            .map_err(|_| ProxyConfigError::invalid_credentials())?;
        if !self
            .connect_headers
            .iter()
            .any(HttpConnectHeader::is_proxy_authorization)
        {
            self.connect_headers
                .push(HttpConnectHeader::proxy_authorization(
                    "Proxy-Authorization",
                ));
        }
        self.credentials = Some(credentials);
        Ok(self)
    }

    /// Speaks HTTP/2 to this HTTPS proxy instead of HTTP/1.1.
    ///
    /// Each tunnel opens one dedicated proxy connection whose TLS handshake
    /// must select `h2`; a proxy that selects `http/1.1` or no protocol fails
    /// with a proxy error instead of falling back. The proxy connection uses
    /// the client profile's TLS offer and HTTP/2 settings, and sends an
    /// RFC 9113 CONNECT with only `:method` and `:authority` pseudo-headers.
    /// The ordered CONNECT fields keep their order after those pseudo-headers,
    /// with names in HTTP/2 lowercase form; the authority placeholder becomes
    /// `:authority`, and connection-specific fields are rejected before I/O.
    ///
    /// Plaintext `http://` origins cannot be forwarded in this mode and fail
    /// before proxy I/O. HTTPS origins may use HTTP/1.1 or HTTP/2 inside the
    /// tunnel.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyConfigError`] for an `http://` proxy, because Phantom
    /// does not speak cleartext HTTP/2 (h2c) to proxies.
    pub fn with_http2_transport(mut self) -> Result<Self, ProxyConfigError> {
        if self.transport != HttpProxyTransport::Tls {
            return Err(ProxyConfigError::unsupported_transport());
        }
        self.protocol = HttpsProxyProtocol::Http2;
        Ok(self)
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
            .chain(
                self.credentials
                    .is_some()
                    .then(|| HttpConnectHeader::proxy_authorization("Proxy-Authorization")),
            )
            .collect();
        self
    }

    /// Replaces the complete CONNECT field sequence.
    ///
    /// The sequence must contain exactly one
    /// [`HttpConnectHeader::Authority`] placeholder. When Basic credentials are
    /// configured, it must also contain exactly one
    /// [`HttpConnectHeader::proxy_authorization`] placeholder. Validation
    /// happens before proxy I/O when a request is sent.
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
        match (self.transport, self.protocol) {
            (HttpProxyTransport::Plaintext, _) => "http_connect",
            (HttpProxyTransport::Tls, HttpsProxyProtocol::Http2) => "https_h2_connect",
            (HttpProxyTransport::Tls, _) => "https_connect",
        }
    }

    /// Applies this route's proxy protocol to a client-owned TLS connector.
    pub(crate) fn https_connector(&self, base: &HttpsProxyConnector) -> HttpsProxyConnector {
        base.clone().with_protocol(self.protocol)
    }

    pub(crate) fn ordered_connect_headers(&self) -> &[HttpConnectHeader] {
        &self.connect_headers
    }

    pub(crate) fn basic_credentials(&self) -> Option<&HttpBasicCredentials> {
        self.credentials.as_ref()
    }
}

fn parse_http_proxy_uri(value: &str) -> Result<(HttpProxyTransport, Endpoint), ProxyConfigError> {
    let uri = parse_absolute_uri(value).map_err(|error| match error {
        ParseUriError::Syntax(error) => ProxyConfigError::invalid_uri(error),
        ParseUriError::Authority(error) => ProxyConfigError::authority(error.message()),
        ParseUriError::Fragment => ProxyConfigError::unexpected_path(),
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
    Ok((transport, endpoint))
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
            .field(
                "proxy_protocol",
                &match self.protocol {
                    HttpsProxyProtocol::Http2 => "h2",
                    _ => "http/1.1",
                },
            )
            .field("authority", self.endpoint.authority())
            .field("connect_header_count", &self.connect_headers.len())
            .field("credentials_configured", &self.credentials.is_some())
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
    /// The HTTP Basic username or password is invalid.
    InvalidCredentials,
    /// The requested proxy protocol cannot be used with the proxy scheme.
    UnsupportedTransport,
}

/// Error returned while constructing an HTTP proxy route.
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
            "HTTP proxy URI must use the http or https scheme",
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

    fn invalid_credentials() -> Self {
        Self::without_source(
            ProxyConfigErrorKind::InvalidCredentials,
            "HTTP Basic proxy credentials must fit the credential-field bound, use ASCII without control characters, and have a nonempty username without a colon",
        )
    }

    fn unsupported_transport() -> Self {
        Self::without_source(
            ProxyConfigErrorKind::UnsupportedTransport,
            "HTTP/2 proxy transport requires an https proxy; cleartext h2c is unsupported",
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
    use phantom_net::proxy::HttpConnectHeader;

    use super::{HttpProxy, ProxyConfigErrorKind, Route};

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
    fn plaintext_proxy_rejects_h2_transport_configuration() -> Result<(), Box<dyn std::error::Error>>
    {
        let error = match HttpProxy::new("http://proxy.example:8080")?.with_http2_transport() {
            Ok(_) => return Err("plaintext proxy accepted HTTP/2 transport".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ProxyConfigErrorKind::UnsupportedTransport);

        let default = HttpProxy::new("https://proxy.example:8443")?;
        let http2 = default.clone().with_http2_transport()?;
        assert_ne!(default, http2, "proxy protocol must separate pool routes");
        assert_eq!(default.trace_name(), "https_connect");
        assert_eq!(http2.trace_name(), "https_h2_connect");
        assert!(format!("{http2:?}").contains("proxy_protocol: \"h2\""));
        Ok(())
    }

    #[test]
    fn connect_constructor_maps_to_the_generic_proxy_route()
    -> Result<(), Box<dyn std::error::Error>> {
        let proxy = HttpProxy::new("http://proxy.example:8080")?;

        assert_eq!(
            Route::http_proxy(proxy.clone()),
            Route::http_connect(proxy.clone())
        );
        assert_eq!(
            Route::http_proxy(HttpProxy::new("http://proxy.example")?)
                .request_trace_name(Some("http")),
            "http_forward"
        );
        assert_eq!(
            Route::http_proxy(HttpProxy::new("https://proxy.example")?)
                .request_trace_name(Some("http")),
            "https_forward"
        );
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

    #[test]
    fn basic_credentials_are_validated_redacted_and_part_of_route_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let first =
            HttpProxy::new("http://proxy.example")?.with_basic_auth("alice", "first secret")?;
        let matching =
            HttpProxy::new("http://proxy.example")?.with_basic_auth("alice", "first secret")?;
        let other =
            HttpProxy::new("http://proxy.example")?.with_basic_auth("alice", "second secret")?;

        assert_eq!(first, matching);
        assert_ne!(first, other);
        assert_eq!(
            first
                .connect_headers
                .iter()
                .filter(|header| header.is_proxy_authorization())
                .count(),
            1
        );
        let debug = format!("{first:?}");
        assert!(debug.contains("credentials_configured: true"));
        assert!(!debug.contains("alice"));
        assert!(!debug.contains("first secret"));
        Ok(())
    }

    #[test]
    fn basic_credentials_reject_ambiguous_or_unsafe_values() -> Result<(), &'static str> {
        for (username, password) in [
            ("", "secret"),
            ("user:name", "secret"),
            ("user", "line\nfeed"),
            ("usér", "secret"),
            ("user", "sécret"),
        ] {
            let result = HttpProxy::new("http://proxy.example")
                .map_err(|_| "valid proxy URI was rejected")?
                .with_basic_auth(username, password);
            let error = match result {
                Ok(_) => return Err("invalid credentials were accepted"),
                Err(error) => error,
            };
            assert_eq!(error.kind(), ProxyConfigErrorKind::InvalidCredentials);
            assert!(!format!("{error:?}").contains(password));
        }

        let oversized = "p".repeat(32 * 1024);
        let result = HttpProxy::new("http://proxy.example")
            .map_err(|_| "valid proxy URI was rejected")?
            .with_basic_auth("user", &oversized);
        let error = match result {
            Ok(_) => return Err("oversized credentials were accepted"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), ProxyConfigErrorKind::InvalidCredentials);
        Ok(())
    }

    #[test]
    fn replacing_literal_fields_preserves_the_auth_placeholder()
    -> Result<(), Box<dyn std::error::Error>> {
        let proxy = HttpProxy::new("http://proxy.example")?
            .with_basic_auth("user", "secret")?
            .headers(Vec::new());

        assert!(matches!(
            proxy.connect_headers.as_slice(),
            [HttpConnectHeader::Authority { .. }, auth] if auth.is_proxy_authorization()
        ));
        Ok(())
    }
}
