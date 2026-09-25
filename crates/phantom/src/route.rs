use std::{error::Error as StdError, fmt, sync::Arc};

use phantom_net::{
    proxy::{HttpBasicCredentials, HttpConnectHeader, HttpsProxyConnector, HttpsProxyProtocol},
    request::RequestHeader,
};
use phantom_profile::{ProxyConnectField, ProxyConnectTemplate};

use crate::authority::{Endpoint, ParseUriError, parse_absolute_uri};

mod connect_udp;
mod socks5;

pub use connect_udp::{
    ConnectUdpProxy, ConnectUdpProxyConfigError, ConnectUdpProxyConfigErrorKind,
};
pub use socks5::{Socks5DnsMode, Socks5Proxy, Socks5ProxyConfigError, Socks5ProxyConfigErrorKind};

/// Route used to establish one origin connection.
///
/// The default is [`Route::Direct`]. Set a client-wide route with
/// [`ClientBuilder::route`](crate::ClientBuilder::route) and override it for
/// one request with [`RequestBuilder::route`](crate::RequestBuilder::route).
///
/// The route you set is the route Phantom uses. When a proxy cannot be
/// reached, rejects the request, or cannot carry the request's scheme and
/// protocol, the request fails with a typed error; Phantom never retries it
/// directly or through another route. An unsupported combination of scheme,
/// protocol, and route fails before any proxy or origin I/O. Each pooled
/// connection belongs to one route, so requests on different routes never
/// share a connection.
///
/// # Examples
///
/// ```no_run
/// use phantom::profile::{chromium, ClientProfile};
/// use phantom::{Client, HttpProtocol, Route, Socks5Proxy};
///
/// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let profile = ClientProfile::new(chromium::v154_tls())
///     .with_http2(chromium::v154_http2());
/// let proxy = Socks5Proxy::new("socks5h://127.0.0.1:1080")?;
/// let client = Client::builder(profile).route(Route::socks5(proxy)).build()?;
///
/// // This request skips the proxy.
/// let response = client
///     .get(HttpProtocol::Http2, "https://example.com/")?
///     .route(Route::direct())
///     .send()
///     .await?;
/// # drop(response);
/// # Ok(())
/// # }
/// ```
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

    /// Returns an HTTP proxy route; an older name for [`Self::http_proxy`].
    ///
    /// Both constructors return the same route, which uses CONNECT for HTTPS
    /// and WebSocket origins and forwarding for plaintext requests. Prefer
    /// [`Self::http_proxy`].
    #[must_use]
    pub fn http_connect(proxy: HttpProxy) -> Self {
        Self::HttpProxy(proxy)
    }

    /// Returns an HTTP proxy route.
    ///
    /// Plaintext `http://` requests are forwarded: as HTTP/1.1 absolute-form
    /// requests in the proxy's default mode, and as HTTP/2 requests with
    /// `:scheme` `http` with [`HttpProxy::with_http2_transport`]. Exact
    /// HTTP/1.1, exact HTTP/2, and negotiated HTTPS requests, and `ws://` and
    /// `wss://` WebSockets, use CONNECT tunneling.
    /// Exact HTTP/3 rejects this route before I/O, because a CONNECT tunnel
    /// carries only TCP; for the same reason, negotiated requests on this
    /// route never learn an Alt-Svc HTTP/3 alternative.
    #[must_use]
    pub fn http_proxy(proxy: HttpProxy) -> Self {
        Self::HttpProxy(proxy)
    }

    /// Returns a SOCKS5 route using the proxy's configured DNS mode.
    ///
    /// HTTP/1.1, HTTP/2, and negotiated requests use an RFC 1928 CONNECT
    /// tunnel; an `http://` request stays plaintext inside it. Exact HTTP/3 and an Alt-Svc upgrade to HTTP/3 use UDP
    /// ASSOCIATE.
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
            (Some("http"), Self::HttpProxy(proxy)) if proxy.uses_http2() => "https_h2_forward",
            (Some("http"), Self::HttpProxy(proxy)) if proxy.uses_tls() => "https_forward",
            (Some("http"), Self::HttpProxy(_)) => "http_forward",
            _ => self.trace_name(),
        }
    }

    /// Returns whether a negotiated `https://` request may use this route.
    ///
    /// Negotiation needs one TLS stream to the origin whose ALPN selects H1 or
    /// H2:
    ///
    /// - [`Route::Direct`] opens that stream itself.
    /// - [`Route::Socks5`] carries it in an RFC 1928 CONNECT.
    /// - [`Route::HttpProxy`] carries it in an RFC 9110 section 9.3.6 CONNECT
    ///   tunnel, as a browser behind a proxy does.
    /// - [`Route::ConnectUdp`] carries only QUIC, so it has no TLS stream for
    ///   ALPN to select a protocol on.
    ///
    /// Whether the same route can also reach an HTTP/3 alternative is a
    /// separate question; see [`Self::carries_quic_alternative`].
    pub(crate) const fn carries_origin_tls_for_alpn(&self) -> bool {
        match self {
            Self::Direct | Self::Socks5(_) | Self::HttpProxy(_) => true,
            Self::ConnectUdp(_) => false,
        }
    }

    /// Returns whether a negotiated request on this route may learn and dial
    /// an Alt-Svc `h3` alternative.
    ///
    /// The upgrade needs a UDP path to the advertised alternative authority
    /// over the same route that carried the advertisement:
    ///
    /// - [`Route::Direct`] sends QUIC itself.
    /// - [`Route::Socks5`] sends QUIC through RFC 1928 UDP ASSOCIATE.
    /// - [`Route::HttpProxy`] carries only TCP. A CONNECT tunnel cannot carry
    ///   QUIC, so a learned alternative could never be dialed, and Phantom
    ///   does not move the request to another route instead.
    /// - [`Route::ConnectUdp`] never makes negotiated requests; see
    ///   [`Self::carries_origin_tls_for_alpn`].
    pub(crate) const fn carries_quic_alternative(&self) -> bool {
        match self {
            Self::Direct | Self::Socks5(_) => true,
            Self::HttpProxy(_) | Self::ConnectUdp(_) => false,
        }
    }

    /// Returns whether an `http://` request on this route is forwarded as an
    /// HTTP/2 request, because the route is an HTTP proxy in HTTP/2 mode.
    ///
    /// Browsers that negotiate `h2` with a TLS proxy send a plaintext origin's
    /// request on that session with `:scheme` `http`, so HTTP/1.1
    /// absolute-form forwarding is not available on such a route.
    pub(crate) const fn forwards_plaintext_over_http2(&self) -> bool {
        matches!(self, Self::HttpProxy(proxy) if proxy.uses_http2())
    }

    /// Returns whether this route forwards a request for `uri` through an
    /// HTTP proxy instead of tunneling it: an `http://` request on an HTTP
    /// proxy route, in absolute form on HTTP/1.1 or with `:scheme` `http`
    /// on an HTTP/2 proxy connection.
    pub(crate) fn forwards(&self, uri: &http::Uri) -> bool {
        uri.scheme_str() == Some("http") && matches!(self, Self::HttpProxy(_))
    }

    /// Returns this route with the profile's CONNECT fields, for an HTTP
    /// proxy whose CONNECT fields the caller has not set.
    ///
    /// `request_value` returns the value the request that opens the tunnel
    /// sends in a field of the given name.
    pub(crate) fn with_profile_connect(
        &self,
        template: Option<&ProxyConnectTemplate>,
        request_value: impl Fn(&str) -> Option<Vec<u8>>,
    ) -> Option<Self> {
        match (self, template) {
            (Self::HttpProxy(proxy), Some(template)) => proxy
                .with_profile_connect(template, request_value)
                .map(Self::HttpProxy),
            _ => None,
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
///
/// A new proxy speaks HTTP/1.1, sends no credentials, and sends a CONNECT
/// request whose only field is a leading `Host`, unless the client profile
/// has CONNECT fields
/// ([`ClientProfile::with_proxy_connect`](crate::profile::ClientProfile::with_proxy_connect)).
/// Fields set with [`Self::header`], [`Self::headers`], or
/// [`Self::connect_headers`] replace the profile's. The scheme, protocol,
/// CONNECT fields you set, and credentials are all part of the route, so
/// proxies that differ in any of them never share a pooled connection. The
/// profile's fields are not: a tunnel opened for one request serves later
/// requests on the same route, as a browser's does.
///
/// # Examples
///
/// ```
/// use phantom::{HttpProxy, Route};
///
/// # fn run() -> Result<(), Box<dyn std::error::Error>> {
/// let proxy = HttpProxy::new("https://proxy.example:8443")?
///     .with_basic_auth("proxy-user", "proxy-password")?;
/// let route = Route::http_proxy(proxy);
/// # drop(route);
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct HttpProxy {
    transport: HttpProxyTransport,
    protocol: HttpsProxyProtocol,
    endpoint: Endpoint,
    connect_headers: Vec<HttpConnectHeader>,
    /// Whether the caller set the CONNECT fields, which then win over the
    /// profile's.
    connect_headers_set: bool,
    /// The profile's CONNECT fields for one request, which replace
    /// `connect_headers` on the wire and are not part of route identity.
    profile_connect_headers: Option<Arc<[HttpConnectHeader]>>,
    credentials: Option<HttpBasicCredentials>,
}

impl PartialEq for HttpProxy {
    fn eq(&self, other: &Self) -> bool {
        self.transport == other.transport
            && self.protocol == other.protocol
            && self.endpoint == other.endpoint
            && self.connect_headers == other.connect_headers
            && self.connect_headers_set == other.connect_headers_set
            && self.credentials == other.credentials
    }
}

impl Eq for HttpProxy {}

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
    /// Returns [`ProxyConfigError`] with kind:
    ///
    /// - [`ProxyConfigErrorKind::InvalidUri`] when the URI does not parse;
    /// - [`ProxyConfigErrorKind::UnsupportedScheme`] for a scheme other than
    ///   `http` or `https`;
    /// - [`ProxyConfigErrorKind::InvalidAuthority`] when the authority is
    ///   missing, contains user information, or has an invalid host or port;
    /// - [`ProxyConfigErrorKind::UnexpectedPath`] for a path other than `/`, a
    ///   query, or a fragment.
    pub fn new(uri: &str) -> Result<Self, ProxyConfigError> {
        let (transport, endpoint) = parse_http_proxy_uri(uri)?;
        Ok(Self {
            transport,
            protocol: HttpsProxyProtocol::Http1,
            endpoint,
            connect_headers: vec![HttpConnectHeader::authority("Host")],
            connect_headers_set: false,
            profile_connect_headers: None,
            credentials: None,
        })
    }

    /// Configures challenge-driven HTTP Basic proxy authentication.
    ///
    /// The first request to the proxy omits credentials. After a valid Basic
    /// proxy challenge, Phantom retries once with them: on a fresh proxy
    /// connection for a CONNECT tunnel or HTTP/1.1 forwarding, and on the same
    /// connection for HTTP/2 forwarding. Once the proxy accepts them, the
    /// client sends them on the first attempt of later tunnels and forwarded
    /// requests through this proxy; see
    /// [`ClientBuilder::preemptive_proxy_authentication`](crate::ClientBuilder::preemptive_proxy_authentication).
    /// URI credentials remain unsupported.
    ///
    /// Basic credentials sent to a plaintext `http://` proxy have no transport
    /// confidentiality. Use an `https://` proxy for sensitive credentials.
    ///
    /// # Errors
    ///
    /// Returns [`ProxyConfigError`] with kind
    /// [`ProxyConfigErrorKind::InvalidCredentials`] when the username is empty
    /// or contains a colon, either value contains non-ASCII or control
    /// characters, or the encoded credential field exceeds its bounded size.
    /// The complete CONNECT head is validated when the request is prepared for
    /// sending.
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
    /// An `http://` request with exact HTTP/2 or negotiated protocol
    /// selection is forwarded as an HTTP/2 request with `:scheme` `http` and
    /// the origin in `:authority`, on one proxy connection per origin that
    /// later requests reuse. Exact HTTP/1.1 `http://` requests fail before
    /// proxy I/O with [`RequestErrorKind::UnsupportedRoute`]. HTTPS origins
    /// may use HTTP/1.1 or HTTP/2 inside the tunnel.
    ///
    /// [`RequestErrorKind::UnsupportedRoute`]: crate::RequestErrorKind::UnsupportedRoute
    ///
    /// # Errors
    ///
    /// Returns [`ProxyConfigError`] with kind
    /// [`ProxyConfigErrorKind::UnsupportedTransport`] for an `http://` proxy,
    /// because Phantom does not speak cleartext HTTP/2 (h2c) to proxies.
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
    /// use [`HttpConnectHeader::Authority`] to control `Host` placement. The
    /// route's CONNECT fields then replace the profile's.
    #[must_use]
    pub fn header(mut self, header: RequestHeader) -> Self {
        self.connect_headers.push(HttpConnectHeader::field(header));
        self.connect_headers_set = true;
        self
    }

    /// Replaces the literal CONNECT fields after the default leading `Host`.
    ///
    /// When Basic credentials are configured, the `Proxy-Authorization`
    /// placeholder stays last. As with [`Self::header`], a literal `Host` or
    /// request-framing field is rejected before proxy I/O, and the route's
    /// CONNECT fields replace the profile's.
    #[must_use]
    pub fn headers(mut self, headers: Vec<RequestHeader>) -> Self {
        self.connect_headers_set = true;
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
    /// happens before proxy I/O when a request is sent. The sequence
    /// replaces the profile's CONNECT fields.
    #[must_use]
    pub fn connect_headers(mut self, headers: Vec<HttpConnectHeader>) -> Self {
        self.connect_headers = headers;
        self.connect_headers_set = true;
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

    pub(crate) const fn uses_http2(&self) -> bool {
        matches!(self.protocol, HttpsProxyProtocol::Http2)
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
        self.profile_connect_headers
            .as_deref()
            .unwrap_or(&self.connect_headers)
    }

    /// Returns this proxy with `template`'s fields for its transport, or
    /// `None` when the caller set the CONNECT fields.
    ///
    /// The HTTP/2 list starts with the authority placeholder, which HTTP/2
    /// sends as `:authority`. A [`ProxyConnectField::FromRequest`] entry takes
    /// `request_value` for its name and is left out when that is `None`; the
    /// credentials placeholder is left out without credentials.
    fn with_profile_connect(
        &self,
        template: &ProxyConnectTemplate,
        request_value: impl Fn(&str) -> Option<Vec<u8>>,
    ) -> Option<Self> {
        if self.connect_headers_set {
            return None;
        }
        let (fields, authority) = if self.uses_http2() {
            (
                &template.http2_fields,
                Some(HttpConnectHeader::authority("host")),
            )
        } else {
            (&template.http1_fields, None)
        };
        let mut headers: Vec<HttpConnectHeader> = authority.into_iter().collect();
        for field in fields {
            match field {
                ProxyConnectField::Authority { name } => {
                    headers.push(HttpConnectHeader::authority(&**name));
                }
                ProxyConnectField::Literal { name, value } => {
                    headers.push(HttpConnectHeader::field(RequestHeader::new(
                        &**name,
                        value.as_bytes(),
                    )));
                }
                ProxyConnectField::FromRequest { name } => {
                    if let Some(value) = request_value(name) {
                        headers.push(HttpConnectHeader::field(RequestHeader::new(&**name, value)));
                    }
                }
                ProxyConnectField::ProxyAuthorization { name } if self.credentials.is_some() => {
                    headers.push(HttpConnectHeader::proxy_authorization(&**name));
                }
                _ => {}
            }
        }
        let mut proxy = self.clone();
        proxy.profile_connect_headers = Some(headers.into());
        Some(proxy)
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

    use super::{ConnectUdpProxy, HttpProxy, ProxyConfigErrorKind, Route, Socks5Proxy};

    #[test]
    fn negotiation_and_quic_alternatives_are_separate_route_capabilities()
    -> Result<(), Box<dyn std::error::Error>> {
        // Direct and SOCKS5 carry an origin TLS stream for ALPN and a UDP path
        // to an advertised alternative.
        assert!(Route::direct().carries_origin_tls_for_alpn());
        assert!(Route::direct().carries_quic_alternative());
        for uri in [
            "socks5://proxy.example:1080",
            "socks5h://proxy.example:1080",
        ] {
            let route = Route::socks5(Socks5Proxy::new(uri)?);
            assert!(route.carries_origin_tls_for_alpn(), "{uri}");
            assert!(route.carries_quic_alternative(), "{uri}");
        }

        // An HTTP proxy tunnels the origin TLS stream, whatever its transport
        // or protocol, but a CONNECT tunnel can never reach an `h3`
        // alternative.
        for proxy in [
            HttpProxy::new("http://proxy.example:8080")?,
            HttpProxy::new("https://proxy.example:8443")?,
            HttpProxy::new("https://proxy.example:8443")?.with_http2_transport()?,
        ] {
            let route = Route::http_proxy(proxy);
            assert!(route.carries_origin_tls_for_alpn(), "{route:?}");
            assert!(!route.carries_quic_alternative(), "{route:?}");
        }

        // CONNECT-UDP carries only QUIC, so ALPN has no stream to select on.
        let route = Route::connect_udp(ConnectUdpProxy::new(
            "https://proxy.example/.well-known/masque/udp/{target_host}/{target_port}/",
        )?);
        assert!(!route.carries_origin_tls_for_alpn());
        assert!(!route.carries_quic_alternative());
        Ok(())
    }

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
    fn profile_connect_fields_apply_only_without_route_fields_and_keep_route_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let template = phantom_profile::chromium::v154_proxy_connect();
        let user_agent = |name: &str| {
            name.eq_ignore_ascii_case("user-agent")
                .then(|| b"agent".to_vec())
        };
        let proxy = HttpProxy::new("http://proxy.example")?;
        let profiled = proxy
            .with_profile_connect(&template, user_agent)
            .ok_or("default fields were not replaced")?;
        assert_eq!(profiled, proxy, "profile fields are not route identity");
        let names: Vec<String> = profiled
            .ordered_connect_headers()
            .iter()
            .map(|header| format!("{header:?}"))
            .collect();
        assert_eq!(names.len(), 3, "{names:?}");
        assert!(names[1].contains("Proxy-Connection") && names[2].contains("User-Agent"));

        let credentials = proxy.clone().with_basic_auth("user", "secret")?;
        let profiled = credentials
            .with_profile_connect(&template, user_agent)
            .ok_or("default fields were not replaced")?;
        assert!(
            profiled
                .ordered_connect_headers()
                .last()
                .is_some_and(HttpConnectHeader::is_proxy_authorization)
        );

        for configured in [
            proxy
                .clone()
                .header(phantom_net::request::RequestHeader::new("X-Route", "1")),
            proxy.clone().headers(Vec::new()),
            proxy.connect_headers(vec![HttpConnectHeader::authority("Host")]),
        ] {
            assert!(
                configured
                    .with_profile_connect(&template, user_agent)
                    .is_none()
            );
        }
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
