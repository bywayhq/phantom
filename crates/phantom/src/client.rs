use std::{fmt, num::NonZeroUsize, sync::Arc};

use http::Method;
use phantom_net::{
    ServerAuthentication, http1::Http1TlsConnector, http1_or_2::Http1Or2TlsConnector,
    http2::Http2TlsConnector, http3::Http3Connector, proxy::HttpsProxyConnector,
};
#[cfg(feature = "cookies")]
use phantom_profile::CookiePlacement;
#[cfg(feature = "websocket")]
use phantom_profile::WebSocketSettings;
use phantom_profile::{ClientHintSettings, ClientProfile, TcpSettings};

#[cfg(feature = "cookies")]
use crate::CookieJar;
use crate::{
    BuildError, RedirectPolicy, RequestBuilder, RequestTimeouts, RetryPolicy, Route, Session,
    SessionBuilder,
    session::{ClientOptions, ClientState, http3_pool::ConnectUdpConnectors},
};
#[cfg(feature = "websocket")]
use crate::{WebSocketError, WebSocketRequestBuilder};

/// HTTP protocol selected for one request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum HttpProtocol {
    /// HTTP/1.1 over TLS, direct plaintext TCP, or plaintext forwarding to an
    /// HTTP proxy.
    Http1,
    /// HTTP/2 over TLS.
    Http2,
    /// HTTP/3 over QUIC.
    Http3,
}

impl HttpProtocol {
    pub(crate) const fn trace_name(self) -> &'static str {
        match self {
            Self::Http1 => "http/1.1",
            Self::Http2 => "h2",
            Self::Http3 => "h3",
        }
    }
}

/// Cloneable owner of transport configuration and bounded cross-request state.
///
/// Clones share connection pools, cookies when enabled, redirect policy, TLS
/// sessions, negotiated client-hint state, and optional Alt-Svc state.
/// Independently built clients share none of that mutable state. Settings
/// are fixed when [`ClientBuilder::build`] returns; a request can override
/// only its route, timeouts, and retry policy, and can opt into content
/// decoding.
///
/// # Examples
///
/// ```no_run
/// use phantom::profile::{chromium, ClientProfile};
/// use phantom::{Client, HttpProtocol};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let profile = ClientProfile::new(chromium::v154_tls()).with_http2(chromium::v154_http2());
/// let client = Client::builder(profile).build()?;
///
/// let response = client
///     .get(HttpProtocol::Http2, "https://example.com/")?
///     .send()
///     .await?;
/// let body = response.into_body().collect_with_limit(1 << 20).await?;
/// println!("{} bytes", body.len());
/// # Ok(())
/// # }
/// ```
#[derive(Clone)]
pub struct Client {
    pub(crate) inner: Arc<ClientInner>,
    pub(crate) state: Arc<ClientState>,
}

#[derive(Debug)]
pub(crate) struct ClientInner {
    pub(crate) http1: Option<Http1TlsConnector>,
    pub(crate) http1_or_2: Option<Http1Or2TlsConnector>,
    pub(crate) http2: Option<Http2TlsConnector>,
    pub(crate) http3: Option<Http3Connector>,
    /// Proxy-leg connectors for CONNECT-UDP proxies, using proxy trust.
    pub(crate) connect_udp_proxy: Option<ConnectUdpConnectors>,
    pub(crate) https_proxy: Option<HttpsProxyConnector>,
    pub(crate) client_hints: Option<ClientHintSettings>,
    /// The profile's HTTP/1.1 connection bound per origin and route.
    pub(crate) http1_connections_per_origin: NonZeroUsize,
    /// Profile position of the jar's `Cookie` field.
    #[cfg(feature = "cookies")]
    pub(crate) cookie_placement: CookiePlacement,
    pub(crate) route: Route,
    /// Profile WebSocket templates and connection policy.
    #[cfg(feature = "websocket")]
    pub(crate) websocket: Option<WebSocketSettings>,
    /// HTTP/1.1 connector with the policy's Upgrade-connection ALPN offer.
    #[cfg(feature = "websocket")]
    pub(crate) websocket_http1: Option<Http1TlsConnector>,
}

impl Client {
    /// Starts a client builder for one owned wire profile.
    ///
    /// Until a builder method changes it, the client uses a direct route,
    /// verifies servers against the bundled public roots, and has no
    /// timeouts, redirects, retries, cookie jar, or Alt-Svc learning.
    #[must_use]
    pub fn builder(profile: ClientProfile) -> ClientBuilder {
        ClientBuilder {
            profile,
            additional_roots: Vec::new(),
            server_authentication: ServerAuthentication::default(),
            proxy_additional_roots: Vec::new(),
            proxy_server_authentication: ServerAuthentication::default(),
            route: Route::Direct,
            options: ClientOptions::default(),
        }
    }

    /// Starts one empty-body GET using exactly `protocol`.
    ///
    /// The request never falls back to another protocol.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::RequestError`] before any I/O, with kind:
    ///
    /// - [`ProtocolUnavailable`](crate::RequestErrorKind::ProtocolUnavailable)
    ///   when the profile does not configure `protocol`;
    /// - [`InvalidUri`](crate::RequestErrorKind::InvalidUri) when `uri` does
    ///   not parse;
    /// - [`UnsupportedScheme`](crate::RequestErrorKind::UnsupportedScheme)
    ///   when the scheme is neither `http` nor `https`;
    /// - [`InvalidAuthority`](crate::RequestErrorKind::InvalidAuthority) when
    ///   the authority is missing or invalid; or
    /// - [`InvalidTarget`](crate::RequestErrorKind::InvalidTarget) when `uri`
    ///   has a fragment or its path and query are not a valid request target.
    ///
    /// [`RequestBuilder::send`] checks the scheme against the protocol and
    /// route, also before I/O: `http://` works only with
    /// [`HttpProtocol::Http1`] on a direct or HTTP proxy route.
    pub fn get(
        &self,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<RequestBuilder, crate::RequestError> {
        self.request(protocol, Method::GET, uri)
    }

    /// Starts one request using exactly `protocol`.
    ///
    /// The request never falls back to another protocol.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::RequestError`] before any I/O, with kind:
    ///
    /// - [`ProtocolUnavailable`](crate::RequestErrorKind::ProtocolUnavailable)
    ///   when the profile does not configure `protocol`;
    /// - [`InvalidUri`](crate::RequestErrorKind::InvalidUri) when `uri` does
    ///   not parse;
    /// - [`UnsupportedScheme`](crate::RequestErrorKind::UnsupportedScheme)
    ///   when the scheme is neither `http` nor `https`;
    /// - [`InvalidAuthority`](crate::RequestErrorKind::InvalidAuthority) when
    ///   the authority is missing or invalid; or
    /// - [`InvalidTarget`](crate::RequestErrorKind::InvalidTarget) when `uri`
    ///   has a fragment or its path and query are not a valid request target.
    ///
    /// [`RequestBuilder::send`] checks the scheme against the protocol and
    /// route, also before I/O: `http://` works only with
    /// [`HttpProtocol::Http1`] on a direct or HTTP proxy route.
    pub fn request(
        &self,
        protocol: HttpProtocol,
        method: Method,
        uri: &str,
    ) -> Result<RequestBuilder, crate::RequestError> {
        RequestBuilder::new_client(self.clone(), protocol, method, uri)
    }

    /// Starts one GET that selects HTTP/2, HTTP/1.1, or a learned H3 alternative.
    ///
    /// Negotiated requests run on direct, SOCKS5, and HTTP proxy routes; an
    /// HTTP proxy carries each connection in one CONNECT tunnel. The client
    /// opens at most one current TCP/TLS generation per origin and route, and
    /// reuses the ALPN-selected protocol while that generation is eligible.
    /// Exact `h2` selects HTTP/2; exact `http/1.1` or absent ALPN selects
    /// HTTP/1.1. It does not race. An opt-in [`RetryPolicy`] may retry a TCP
    /// or proxy connect failure before TLS starts; TLS and ALPN failures are
    /// terminal.
    /// When bounded Alt-Svc learning is enabled, a fresh `h3` advertisement
    /// from an earlier negotiated response selects HTTP/3 without changing the
    /// origin identity or the route. Alternatives are learned only on direct
    /// and SOCKS5 routes, because a CONNECT tunnel cannot carry QUIC; over an
    /// HTTP proxy, negotiated requests stay on HTTP/2 or HTTP/1.1. A
    /// CONNECT-UDP route, configured or per request, fails
    /// [`RequestBuilder::send`] with
    /// [`RequestErrorKind::UnsupportedRoute`](crate::RequestErrorKind::UnsupportedRoute)
    /// before I/O. [`crate::ResponseInfo::protocol`] reports the selected
    /// protocol. Client cookies and learned client hints apply. Negotiated
    /// generations are isolated from the exact-protocol pools.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::RequestError`] before any I/O, with kind:
    ///
    /// - [`ProtocolUnavailable`](crate::RequestErrorKind::ProtocolUnavailable)
    ///   when the profile lacks HTTP/2 settings or does not offer `http/1.1`
    ///   in its TLS ALPN list;
    /// - [`InvalidUri`](crate::RequestErrorKind::InvalidUri) when `uri` does
    ///   not parse;
    /// - [`UnsupportedScheme`](crate::RequestErrorKind::UnsupportedScheme)
    ///   when the scheme is neither `http` nor `https`;
    /// - [`InvalidAuthority`](crate::RequestErrorKind::InvalidAuthority) when
    ///   the authority is missing or invalid; or
    /// - [`InvalidTarget`](crate::RequestErrorKind::InvalidTarget) when `uri`
    ///   has a fragment or its path and query are not a valid request target.
    ///
    /// [`RequestBuilder::send`] rejects an `http://` URI and an unsupported
    /// route, also before I/O.
    pub fn get_negotiated(&self, uri: &str) -> Result<RequestBuilder, crate::RequestError> {
        self.request_negotiated(Method::GET, uri)
    }

    /// Starts one request that selects HTTP/2, HTTP/1.1, or a learned H3 alternative.
    ///
    /// This has the same route and pooled-generation selection contract as
    /// [`Self::get_negotiated`]. The request must be representable by both
    /// HTTP versions so validation can finish before network I/O.
    ///
    /// # Errors
    ///
    /// Returns a [`crate::RequestError`] before any I/O, with kind:
    ///
    /// - [`ProtocolUnavailable`](crate::RequestErrorKind::ProtocolUnavailable)
    ///   when the profile lacks HTTP/2 settings or does not offer `http/1.1`
    ///   in its TLS ALPN list;
    /// - [`InvalidUri`](crate::RequestErrorKind::InvalidUri) when `uri` does
    ///   not parse;
    /// - [`UnsupportedScheme`](crate::RequestErrorKind::UnsupportedScheme)
    ///   when the scheme is neither `http` nor `https`;
    /// - [`InvalidAuthority`](crate::RequestErrorKind::InvalidAuthority) when
    ///   the authority is missing or invalid; or
    /// - [`InvalidTarget`](crate::RequestErrorKind::InvalidTarget) when `uri`
    ///   has a fragment or its path and query are not a valid request target.
    ///
    /// [`RequestBuilder::send`] rejects an `http://` URI and an unsupported
    /// route, also before I/O.
    pub fn request_negotiated(
        &self,
        method: Method,
        uri: &str,
    ) -> Result<RequestBuilder, crate::RequestError> {
        RequestBuilder::new_client_negotiated(self.clone(), method, uri)
    }

    /// Starts one ordered WebSocket opening handshake over HTTP/1.1.
    ///
    /// The connect uses this client's profile, route, trust roots, and cookie
    /// jar, but not its timeouts, retry, or redirect policy.
    ///
    /// # Errors
    ///
    /// Returns a [`WebSocketError`] before any I/O, with kind
    /// [`ProtocolUnavailable`](crate::WebSocketErrorKind::ProtocolUnavailable)
    /// when the profile cannot use the selected protocol;
    /// [`InvalidUri`](crate::WebSocketErrorKind::InvalidUri),
    /// [`UnsupportedScheme`](crate::WebSocketErrorKind::UnsupportedScheme), or
    /// [`InvalidAuthority`](crate::WebSocketErrorKind::InvalidAuthority) when
    /// `uri` is not a valid `ws://` or `wss://` URI; or
    /// [`InvalidRequest`](crate::WebSocketErrorKind::InvalidRequest) when
    /// `uri` has a fragment or an invalid target, or the profile's WebSocket
    /// field template cannot be used.
    #[cfg(feature = "websocket")]
    pub fn websocket(&self, uri: &str) -> Result<WebSocketRequestBuilder, WebSocketError> {
        WebSocketRequestBuilder::new_client(self.clone(), uri)
    }

    /// Starts one ordered WebSocket opening handshake using exactly `protocol`.
    ///
    /// HTTP/2 uses RFC 8441 extended CONNECT and supports `wss://` only, over
    /// direct, HTTP CONNECT, or SOCKS5 routes. It requires an explicit
    /// extended-CONNECT pseudo-header order in the HTTP/2 profile and never
    /// falls back to HTTP/1.1. HTTP/3 is rejected when the builder is created.
    /// Client timeouts, retry, and redirect policy do not apply.
    ///
    /// # Errors
    ///
    /// Returns a [`WebSocketError`] before any I/O, with kind
    /// [`ProtocolUnavailable`](crate::WebSocketErrorKind::ProtocolUnavailable)
    /// when the profile cannot use the selected protocol;
    /// [`InvalidUri`](crate::WebSocketErrorKind::InvalidUri),
    /// [`UnsupportedScheme`](crate::WebSocketErrorKind::UnsupportedScheme), or
    /// [`InvalidAuthority`](crate::WebSocketErrorKind::InvalidAuthority) when
    /// `uri` is not a valid `ws://` or `wss://` URI; or
    /// [`InvalidRequest`](crate::WebSocketErrorKind::InvalidRequest) when
    /// `uri` has a fragment or an invalid target, or the profile's WebSocket
    /// field template cannot be used.
    #[cfg(feature = "websocket")]
    pub fn websocket_with_protocol(
        &self,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<WebSocketRequestBuilder, WebSocketError> {
        WebSocketRequestBuilder::new_client_with_protocol(self.clone(), protocol, uri)
    }

    /// Starts one WebSocket whose connection follows the profile's policy.
    ///
    /// `ws://` uses an HTTP/1.1 Upgrade. For `wss://`, a pooled HTTP/2
    /// session to the same origin and route whose peer enabled extended
    /// CONNECT carries the WebSocket as a new stream. Without such a session,
    /// the profile's [`WebSocketConnectionPolicy`] decides between a new
    /// HTTP/1.1 Upgrade connection with its own ALPN offer and a new HTTP/2
    /// connection. The choice is made once, before any WebSocket bytes are
    /// sent; a failed or rejected opening never retries on another
    /// connection or protocol. Client timeouts, retry, and redirect policy do
    /// not apply.
    ///
    /// [`WebSocketConnectionPolicy`]: crate::profile::WebSocketConnectionPolicy
    ///
    /// # Errors
    ///
    /// Returns a [`WebSocketError`] before any I/O, with kind
    /// [`ProtocolUnavailable`](crate::WebSocketErrorKind::ProtocolUnavailable)
    /// when the profile has no WebSocket settings;
    /// [`InvalidUri`](crate::WebSocketErrorKind::InvalidUri),
    /// [`UnsupportedScheme`](crate::WebSocketErrorKind::UnsupportedScheme), or
    /// [`InvalidAuthority`](crate::WebSocketErrorKind::InvalidAuthority) when
    /// `uri` is not a valid `ws://` or `wss://` URI; or
    /// [`InvalidRequest`](crate::WebSocketErrorKind::InvalidRequest) when
    /// `uri` has a fragment or an invalid target, or the profile's WebSocket
    /// field template cannot be used.
    #[cfg(feature = "websocket")]
    pub fn websocket_with_profile_policy(
        &self,
        uri: &str,
    ) -> Result<WebSocketRequestBuilder, WebSocketError> {
        WebSocketRequestBuilder::new_client_with_profile_policy(self.clone(), uri)
    }

    /// Creates an isolated compatibility client with default bounded state.
    #[must_use]
    #[doc(hidden)]
    pub fn session(&self) -> Session {
        // Default options enable no Alt-Svc store, so they need no validation.
        Client {
            inner: Arc::clone(&self.inner),
            state: ClientOptions::default().build(&self.inner),
        }
    }

    /// Starts a compatibility builder for isolated state over this transport.
    #[must_use]
    #[doc(hidden)]
    pub fn session_builder(&self) -> SessionBuilder {
        SessionBuilder::new(self.clone())
    }
}

/// Builds an immutable [`Client`].
///
/// Each method states the value used when it is not called. Pool bounds take
/// any nonzero value. Settings are validated only by [`Self::build`].
///
/// # Examples
///
/// ```
/// use std::{num::NonZeroUsize, time::Duration};
///
/// use phantom::profile::{chromium, ClientProfile};
/// use phantom::{Client, RequestTimeouts};
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let profile = ClientProfile::new(chromium::v154_tls()).with_http2(chromium::v154_http2());
/// let client = Client::builder(profile)
///     .request_timeouts(RequestTimeouts::new().total(Duration::from_secs(30)))
///     .max_retained_http2_connections(NonZeroUsize::new(8).expect("eight is nonzero"))
///     .build()?;
/// # drop(client);
/// # Ok(())
/// # }
/// ```
pub struct ClientBuilder {
    profile: ClientProfile,
    additional_roots: Vec<Box<[u8]>>,
    server_authentication: ServerAuthentication,
    proxy_additional_roots: Vec<Box<[u8]>>,
    proxy_server_authentication: ServerAuthentication,
    route: Route,
    options: ClientOptions,
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientBuilder")
            .field("http2_configured", &self.profile.http2().is_some())
            .field(
                "negotiated_http1_or_2_configured",
                &(self.profile.http2().is_some()
                    && self
                        .profile
                        .tls()
                        .alpn_protocols
                        .iter()
                        .any(|protocol| protocol.as_ref() == b"http/1.1")),
            )
            .field("http3_configured", &self.profile.http3().is_some())
            .field(
                "client_hints_configured",
                &self.profile.client_hints().is_some(),
            )
            .field("additional_root_count", &self.additional_roots.len())
            .field("server_authentication", &self.server_authentication)
            .field(
                "proxy_additional_root_count",
                &self.proxy_additional_roots.len(),
            )
            .field(
                "proxy_server_authentication",
                &self.proxy_server_authentication,
            )
            .field("route", &self.route)
            .field("redirect_policy", &self.options.redirect_policy)
            .field("retry_policy", &self.options.retry_policy)
            .field("request_timeouts", &self.options.request_timeouts)
            .field(
                "max_retained_http1_connections",
                &self.options.max_retained_http1_connections,
            )
            .field(
                "max_concurrent_http1_requests_per_origin",
                &self.options.max_concurrent_http1_requests_per_origin,
            )
            .field(
                "max_pending_http1_requests_per_origin",
                &self.options.max_pending_http1_requests_per_origin,
            )
            .field(
                "max_retained_http2_connections",
                &self.options.max_retained_http2_connections,
            )
            .field(
                "max_concurrent_http2_requests_per_origin",
                &self.options.max_concurrent_http2_requests_per_origin,
            )
            .field(
                "max_pending_http2_requests_per_origin",
                &self.options.max_pending_http2_requests_per_origin,
            )
            .field(
                "max_retained_http3_connections",
                &self.options.max_retained_http3_connections,
            )
            .field(
                "max_concurrent_http3_requests_per_origin",
                &self.options.max_concurrent_http3_requests_per_origin,
            )
            .field(
                "max_pending_http3_requests_per_origin",
                &self.options.max_pending_http3_requests_per_origin,
            )
            .field(
                "max_client_hint_origins",
                &self.options.max_client_hint_origins,
            )
            .field("max_alt_svc_origins", &self.options.max_alt_svc_origins)
            .field("alt_svc_policy", &self.options.alt_svc_policy)
            .field("cookies_enabled", &{
                #[cfg(feature = "cookies")]
                {
                    self.options.cookie_jar.is_some()
                }
                #[cfg(not(feature = "cookies"))]
                {
                    false
                }
            })
            .finish_non_exhaustive()
    }
}

impl ClientBuilder {
    /// Adds a DER-encoded certificate to the bundled public trust roots.
    ///
    /// By default only the bundled public roots are trusted. Certificate and
    /// hostname verification remain enabled. The added roots apply to origin
    /// TLS on HTTP/1.1, HTTP/2, and HTTP/3; proxies use
    /// [`Self::add_proxy_root_certificate_der`]. A certificate that cannot be
    /// loaded fails [`Self::build`] with
    /// [`BuildErrorKind::TrustStore`](crate::BuildErrorKind::TrustStore).
    #[must_use]
    pub fn add_root_certificate_der(mut self, certificate: impl Into<Box<[u8]>>) -> Self {
        self.additional_roots.push(certificate.into());
        self
    }

    /// Sets how TLS servers are authenticated.
    ///
    /// The default is [`ServerAuthentication::WebPki`]. Disabling
    /// authentication is explicit and is supported for HTTP/1.1 and HTTP/2.
    /// [`Self::build`] fails with
    /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy)
    /// when disabled authentication is combined with additional roots or a
    /// profile that configures HTTP/3.
    #[must_use]
    pub fn server_authentication(mut self, policy: ServerAuthentication) -> Self {
        self.server_authentication = policy;
        self
    }

    /// Adds a DER-encoded certificate to the HTTPS-proxy trust roots.
    ///
    /// By default only the bundled public roots are trusted. Proxy trust is
    /// independent from origin trust. Certificate and hostname verification
    /// remain enabled for the proxy. The roots also authenticate the outer
    /// HTTP/3 connection of a [`Route::ConnectUdp`] route. A certificate that
    /// cannot be loaded fails [`Self::build`] with
    /// [`BuildErrorKind::TrustStore`](crate::BuildErrorKind::TrustStore).
    #[must_use]
    pub fn add_proxy_root_certificate_der(mut self, certificate: impl Into<Box<[u8]>>) -> Self {
        self.proxy_additional_roots.push(certificate.into());
        self
    }

    /// Sets how an HTTPS proxy authenticates its TLS certificate.
    ///
    /// The default is [`ServerAuthentication::WebPki`]. This policy applies
    /// only to the outer proxy connection. Origin TLS uses
    /// [`Self::server_authentication`] and its own trust roots.
    /// [`Self::build`] fails with
    /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy)
    /// when disabled proxy authentication is combined with proxy roots or a
    /// [`Route::ConnectUdp`] route, whose outer connection is HTTP/3.
    #[must_use]
    pub fn proxy_server_authentication(mut self, policy: ServerAuthentication) -> Self {
        self.proxy_server_authentication = policy;
        self
    }

    /// Sets the default route for requests made by this client.
    ///
    /// The default is [`Route::Direct`]. [`RequestBuilder::route`] overrides
    /// it for one request.
    #[must_use]
    pub fn route(mut self, route: Route) -> Self {
        self.route = route;
        self
    }

    /// Sets the finite policy for following redirect responses.
    ///
    /// The default is [`RedirectPolicy::none`], which returns a 3xx response
    /// without following it. Redirect following is HTTPS-only: while a
    /// limited policy is set, `http://` requests fail before I/O, and a
    /// redirect to a non-`https://` target fails; both fail with
    /// [`RequestErrorKind::Redirect`](crate::RequestErrorKind::Redirect).
    #[must_use]
    pub fn redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.options.redirect_policy = policy;
        self
    }

    /// Sets the policy for retrying connection-establishment failures.
    ///
    /// The default is [`RetryPolicy::none`]. Connection retries apply only to
    /// connection setup before dispatch: exact-protocol acquisition and
    /// negotiated H1/H2 TCP setup before ALPN selection.
    /// [`RequestBuilder::retry_policy`] replaces the policy for one request. A
    /// delay or `Retry-After` limit the runtime clock cannot represent fails
    /// [`Self::build`] with
    /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
    #[must_use]
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.options.retry_policy = policy;
        self
    }

    /// Sets the default phase and whole-operation limits for ordinary requests.
    ///
    /// The default is [`RequestTimeouts::new`], which sets no limit.
    /// [`RequestBuilder::timeouts`] replaces this policy for one request.
    /// Every timeout is disabled unless explicitly present in `timeouts`. A
    /// duration the runtime clock cannot represent fails [`Self::build`] with
    /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
    #[must_use]
    pub fn request_timeouts(mut self, timeouts: RequestTimeouts) -> Self {
        self.options.request_timeouts = timeouts;
        self
    }

    /// Sets the maximum number of HTTP/1.1 pool entries retained for reuse.
    ///
    /// The default is 32. Each entry holds one pool key's connection state;
    /// when the limit is reached, the least recently used entry is evicted.
    /// The negotiated H1/H2 pool uses the lower of the configured H1 and H2
    /// retention limits so neither maximum is exceeded.
    #[must_use]
    pub fn max_retained_http1_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_retained_http1_connections = maximum;
        self
    }

    /// Sets the local active-request bound for each HTTP/1.1 pool key.
    ///
    /// Each active HTTP/1.1 request holds its own connection, so this is also
    /// the most connections open at once to the pool key, idle ones included.
    /// It replaces the profile's [`Http1Settings`] bound. Without either, the
    /// bound is one connection.
    ///
    /// [`Http1Settings`]: crate::profile::Http1Settings
    #[must_use]
    pub fn max_concurrent_http1_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_concurrent_http1_requests_per_origin = Some(maximum);
        self
    }

    /// Sets the number of requests allowed to wait per HTTP/1.1 pool key.
    ///
    /// The default is 100. A pool key is the origin plus the complete route.
    /// A request beyond the limit fails with
    /// [`RequestErrorKind::Capacity`](crate::RequestErrorKind::Capacity).
    #[must_use]
    pub fn max_pending_http1_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_pending_http1_requests_per_origin = maximum;
        self
    }

    /// Sets the maximum number of HTTP/2 pool entries retained for reuse.
    ///
    /// The default is 32. When the limit is reached, the least recently used
    /// entry is evicted. The negotiated H1/H2 pool uses the lower of the
    /// configured H1 and H2 retention limits so neither maximum is exceeded.
    #[must_use]
    pub fn max_retained_http2_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_retained_http2_connections = maximum;
        self
    }

    /// Sets the local active-request bound for each HTTP/2 pool key.
    ///
    /// The default is 100. The peer's stream limit also caps active requests.
    #[must_use]
    pub fn max_concurrent_http2_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_concurrent_http2_requests_per_origin = maximum;
        self
    }

    /// Sets the number of requests allowed to wait per HTTP/2 pool key.
    ///
    /// The default is 100. A request beyond the limit fails with
    /// [`RequestErrorKind::Capacity`](crate::RequestErrorKind::Capacity).
    #[must_use]
    pub fn max_pending_http2_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_pending_http2_requests_per_origin = maximum;
        self
    }

    /// Sets the maximum number of HTTP/3 pool entries retained for reuse.
    ///
    /// The default is 32. When the limit is reached, the least recently used
    /// entry is evicted. One entry keeps connections for up to four transport
    /// locations, so exact H3 and Alt-Svc H3 do not replace each other.
    #[must_use]
    pub fn max_retained_http3_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_retained_http3_connections = maximum;
        self
    }

    /// Sets the local active-request bound for each HTTP/3 pool key.
    ///
    /// The default is 100. The peer's stream limit also caps active requests.
    #[must_use]
    pub fn max_concurrent_http3_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_concurrent_http3_requests_per_origin = maximum;
        self
    }

    /// Sets the number of requests allowed to wait per HTTP/3 pool key.
    ///
    /// The default is 100. A request beyond the limit fails with
    /// [`RequestErrorKind::Capacity`](crate::RequestErrorKind::Capacity).
    #[must_use]
    pub fn max_pending_http3_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_pending_http3_requests_per_origin = maximum;
        self
    }

    /// Sets the number of origins that may retain `Accept-CH` state.
    ///
    /// The default is 64.
    #[must_use]
    pub fn max_client_hint_origins(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_client_hint_origins = maximum;
        self
    }

    /// Enables bounded, in-memory Alt-Svc learning for negotiated HTTPS requests.
    ///
    /// Alt-Svc learning is disabled by default. `maximum_origins` bounds
    /// stored origin-and-route pairs: one origin learned over N routes
    /// occupies N entries. [`Self::build`] fails with
    /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy)
    /// unless the profile configures HTTP/2, offers `http/1.1` in its TLS ALPN
    /// list, and configures HTTP/3.
    ///
    /// A fresh `h3` alternative is used by a later negotiated request without
    /// changing its origin identity or its route. Alternative setup failure is
    /// terminal for that request and never falls back implicitly to H1 or H2.
    ///
    /// The store is keyed by origin and route, so an alternative learned on
    /// one route is only ever dialed over that route. Learning runs only on
    /// direct and SOCKS5 routes. An HTTP proxy route makes negotiated requests
    /// but stores no advertisement, because its CONNECT tunnel cannot carry
    /// QUIC; see [`Route`](crate::Route).
    #[must_use]
    pub fn alt_svc(mut self, maximum_origins: NonZeroUsize) -> Self {
        self.options.max_alt_svc_origins = Some(maximum_origins);
        self
    }

    /// Selects how negotiated requests use a learned HTTP/3 alternative.
    ///
    /// The default is [`AltSvcPolicy::sequential`](crate::AltSvcPolicy::sequential).
    /// A racing policy requires [`ClientBuilder::alt_svc`]; building without
    /// it, or with an origin delay the runtime clock cannot represent, fails
    /// with [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
    #[must_use]
    pub fn alt_svc_policy(mut self, policy: crate::AltSvcPolicy) -> Self {
        self.options.alt_svc_policy = policy;
        self
    }

    /// Enables a bounded in-memory cookie jar owned by the client.
    ///
    /// By default the client has no cookie jar. This jar uses the default
    /// [`CookieLimits`](crate::CookieLimits).
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookies(mut self) -> Self {
        self.options.cookie_jar = Some(CookieJar::default());
        self
    }

    /// Enables cookie handling with a caller-created jar.
    ///
    /// By default the client has no cookie jar. Use this to set other
    /// [`CookieLimits`](crate::CookieLimits).
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookie_jar(mut self, jar: CookieJar) -> Self {
        self.options.cookie_jar = Some(jar);
        self
    }

    /// Validates the profile and builds reusable protocol connectors.
    ///
    /// # Errors
    ///
    /// Returns a [`BuildError`] whose [`BuildError::kind`] is:
    ///
    /// - [`InvalidProfile`](crate::BuildErrorKind::InvalidProfile) when the
    ///   TLS, TCP, client-hint, WebSocket, HTTP/2, or HTTP/3 settings are
    ///   invalid, or this host cannot apply the TCP settings;
    /// - [`InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy) when a
    ///   timeout, retry delay, or Alt-Svc race delay exceeds the runtime clock
    ///   range; disabled authentication is combined with added roots, HTTP/3,
    ///   or a CONNECT-UDP route; Alt-Svc is enabled without negotiated H1/H2
    ///   and HTTP/3; a racing Alt-Svc policy has no store; or the profile's
    ///   WebSocket connection policy needs HTTP/2 settings it lacks;
    /// - [`TrustStore`](crate::BuildErrorKind::TrustStore) when an added
    ///   origin or proxy root cannot be loaded;
    /// - [`ProtocolConfiguration`](crate::BuildErrorKind::ProtocolConfiguration)
    ///   when a protocol connector cannot represent the profile, such as an
    ///   HTTPS proxy route whose TLS ALPN list lacks `http/1.1`; or
    /// - [`NoSupportedProtocol`](crate::BuildErrorKind::NoSupportedProtocol)
    ///   when the profile enables no HTTP protocol Phantom implements.
    pub fn build(self) -> Result<Client, BuildError> {
        if !self.options.request_timeouts.validate() {
            return Err(BuildError::invalid_policy(
                "request timeout exceeds the runtime clock range",
            ));
        }
        if !self.options.retry_policy.validate() {
            return Err(BuildError::invalid_policy(
                "retry delay or Retry-After limit exceeds the runtime clock range",
            ));
        }
        self.profile
            .tls()
            .validate()
            .map_err(BuildError::invalid_tls_profile)?;
        if let Some(tcp) = self.profile.tcp() {
            tcp.validate().map_err(BuildError::invalid_tcp_profile)?;
            phantom_net::tcp::check_host_support(tcp)
                .map_err(BuildError::unsupported_tcp_profile)?;
        }
        if let Some(client_hints) = self.profile.client_hints() {
            client_hints
                .validate()
                .map_err(BuildError::invalid_client_hint_profile)?;
        }
        if let Some(websocket) = self.profile.websocket() {
            websocket
                .validate()
                .map_err(BuildError::invalid_websocket_profile)?;
        }

        let authentication_disabled = match self.server_authentication {
            ServerAuthentication::WebPki => false,
            ServerAuthentication::Disabled => true,
            _ => {
                return Err(BuildError::invalid_policy(
                    "unsupported server-authentication policy",
                ));
            }
        };
        if authentication_disabled {
            if !self.additional_roots.is_empty() {
                return Err(BuildError::invalid_policy(
                    "disabled server authentication cannot be combined with additional roots",
                ));
            }
            if self.profile.http3().is_some() {
                return Err(BuildError::invalid_policy(
                    "disabled server authentication is not supported for HTTP/3",
                ));
            }
        }

        let proxy_authentication_disabled = match self.proxy_server_authentication {
            ServerAuthentication::WebPki => false,
            ServerAuthentication::Disabled => true,
            _ => {
                return Err(BuildError::invalid_policy(
                    "unsupported proxy server-authentication policy",
                ));
            }
        };
        if proxy_authentication_disabled && !self.proxy_additional_roots.is_empty() {
            return Err(BuildError::invalid_policy(
                "disabled proxy server authentication cannot be combined with proxy roots",
            ));
        }

        let roots = || self.additional_roots.iter().map(AsRef::as_ref);
        let tcp = self.profile.tcp();
        let supports_http1 = self
            .profile
            .tls()
            .alpn_protocols
            .iter()
            .any(|protocol| protocol.as_ref() == b"http/1.1");
        let http1 = supports_http1
            .then(|| {
                if authentication_disabled {
                    Http1TlsConnector::new_with_server_authentication(
                        self.profile.tls(),
                        self.server_authentication,
                    )
                } else {
                    Http1TlsConnector::new_with_additional_roots(self.profile.tls(), roots())
                }
                .map(|connector| with_tcp(connector, tcp, Http1TlsConnector::with_tcp_settings))
            })
            .transpose()
            .map_err(BuildError::http1)?;
        let http2 = self
            .profile
            .http2()
            .map(|settings| {
                if authentication_disabled {
                    Http2TlsConnector::new_with_server_authentication(
                        self.profile.tls(),
                        settings,
                        self.server_authentication,
                    )
                } else {
                    Http2TlsConnector::new_with_additional_roots(
                        self.profile.tls(),
                        settings,
                        roots(),
                    )
                }
                .map(|connector| with_tcp(connector, tcp, Http2TlsConnector::with_tcp_settings))
            })
            .transpose()
            .map_err(BuildError::http2)?;
        let http1_or_2 = http2
            .as_ref()
            .filter(|_| supports_http1)
            .map(Http1Or2TlsConnector::from_http2)
            .transpose()
            .map_err(BuildError::http1_or_2)?;
        let http3 = self
            .profile
            .http3()
            .map(|settings| {
                Http3Connector::new_with_additional_roots(
                    settings.tls(),
                    settings.quic_transport(),
                    settings.http3(),
                    settings.request(),
                    roots(),
                )
                .map(|connector| with_tcp(connector, tcp, Http3Connector::with_tcp_settings))
            })
            .transpose()
            .map_err(BuildError::http3)?;
        // CONNECT-UDP's outer connection authenticates the proxy with proxy
        // trust roots; HTTP/3 cannot disable verification.
        let connect_udp_http3 = self
            .profile
            .http3()
            .filter(|_| !proxy_authentication_disabled)
            .map(|settings| {
                Http3Connector::new_with_additional_roots(
                    settings.tls(),
                    settings.quic_transport(),
                    settings.http3(),
                    settings.request(),
                    self.proxy_additional_roots.iter().map(AsRef::as_ref),
                )
            })
            .transpose()
            .map_err(BuildError::http3)?;
        if proxy_authentication_disabled && matches!(self.route, Route::ConnectUdp(_)) {
            return Err(BuildError::invalid_policy(
                "disabled proxy server authentication is not supported for CONNECT-UDP",
            ));
        }
        self.options
            .validate_protocols(http1_or_2.is_some(), http3.is_some())?;
        let secure_proxy_requested = self
            .route
            .as_http_proxy()
            .is_some_and(|proxy| proxy.uses_tls())
            || matches!(&self.route, Route::ConnectUdp(proxy) if proxy.tcp_protocol().is_some())
            || !self.proxy_additional_roots.is_empty()
            || proxy_authentication_disabled;
        let https_proxy = (supports_http1 || secure_proxy_requested)
            .then(|| {
                if proxy_authentication_disabled {
                    HttpsProxyConnector::new_with_server_authentication(
                        self.profile.tls(),
                        self.proxy_server_authentication,
                    )
                } else {
                    HttpsProxyConnector::new_with_additional_roots(
                        self.profile.tls(),
                        self.proxy_additional_roots.iter().map(AsRef::as_ref),
                    )
                }
                .map(|connector| match self.profile.http2() {
                    Some(settings) => connector.with_http2_settings(settings),
                    None => connector,
                })
                .map(|connector| with_tcp(connector, tcp, HttpsProxyConnector::with_tcp_settings))
            })
            .transpose()
            .map_err(BuildError::https_proxy)?;
        // HTTP/1.1 and HTTP/2 CONNECT-UDP legs share the HTTPS-proxy TLS
        // configuration; like the HTTP/3 leg, they require proxy verification.
        let connect_udp_tcp = https_proxy
            .clone()
            .filter(|_| !proxy_authentication_disabled);
        let connect_udp_proxy =
            (connect_udp_http3.is_some() || connect_udp_tcp.is_some()).then(|| {
                ConnectUdpConnectors {
                    http3: connect_udp_http3,
                    tcp: connect_udp_tcp,
                }
            });
        let client_hints = self.profile.client_hints().cloned();

        if http1.is_none() && http2.is_none() && http3.is_none() {
            return Err(BuildError::no_supported_protocol());
        }
        #[cfg(feature = "websocket")]
        let websocket_http1 = self
            .profile
            .websocket()
            .map(|websocket| {
                validate_websocket_policy(websocket, self.profile.http2())?;
                let tls = websocket.connection.http1_tls_settings(self.profile.tls());
                if authentication_disabled {
                    Http1TlsConnector::new_with_server_authentication(
                        &tls,
                        self.server_authentication,
                    )
                } else {
                    Http1TlsConnector::new_with_additional_roots(&tls, roots())
                }
                .map(|connector| with_tcp(connector, tcp, Http1TlsConnector::with_tcp_settings))
                .map_err(BuildError::http1)
            })
            .transpose()?;

        let inner = Arc::new(ClientInner {
            http1,
            http1_or_2,
            http2,
            http3,
            connect_udp_proxy,
            https_proxy,
            client_hints,
            http1_connections_per_origin: self
                .profile
                .http1()
                .map_or(NonZeroUsize::MIN, |http1| http1.max_connections_per_origin),
            #[cfg(feature = "cookies")]
            cookie_placement: self.profile.cookie_placement().clone(),
            route: self.route,
            #[cfg(feature = "websocket")]
            websocket: self.profile.websocket().cloned(),
            #[cfg(feature = "websocket")]
            websocket_http1,
        });
        let state = self.options.build(&inner);
        Ok(Client { inner, state })
    }
}

/// Applies the profile's TCP socket options, when it has any, to a connector.
fn with_tcp<C>(connector: C, tcp: Option<&TcpSettings>, apply: fn(C, &TcpSettings) -> C) -> C {
    match tcp {
        Some(settings) => apply(connector, settings),
        None => connector,
    }
}

/// Rejects a WebSocket policy that its HTTP/2 profile cannot carry out.
#[cfg(feature = "websocket")]
fn validate_websocket_policy(
    websocket: &WebSocketSettings,
    http2: Option<&phantom_profile::Http2Settings>,
) -> Result<(), BuildError> {
    match http2 {
        Some(http2) if http2.extended_connect_pseudo_header_order.is_none() => {
            Err(BuildError::invalid_policy(
                "a WebSocket connection policy needs an extended CONNECT pseudo-header order in the HTTP/2 profile",
            ))
        }
        None if websocket.connection.without_http2_session
            == phantom_profile::WebSocketNewConnection::Http2ExtendedConnect =>
        {
            Err(BuildError::invalid_policy(
                "a WebSocket connection policy that opens HTTP/2 needs an HTTP/2 profile",
            ))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use std::time::Duration;

    use phantom_profile::{ClientProfile, Http3ClientSettings, TcpKeepalive, chromium};

    use super::{Client, HttpProtocol};
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::BuildError;
    use crate::{BuildErrorKind, HttpProxy, Route, ServerAuthentication};

    #[test]
    fn protocol_trace_names_match_negotiated_tokens() {
        assert_eq!(HttpProtocol::Http1.trace_name(), "http/1.1");
        assert_eq!(HttpProtocol::Http2.trace_name(), "h2");
        assert_eq!(HttpProtocol::Http3.trace_name(), "h3");
    }

    #[test]
    fn profile_tcp_settings_reach_every_tcp_connector() -> Result<(), Box<dyn std::error::Error>> {
        let tcp = chromium::v154_tcp();
        let http3 = Http3ClientSettings::new(
            chromium::v154_http3_tls(),
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        );
        let profile = ClientProfile::new(chromium::v154_tls())
            .with_tcp(tcp)
            .with_http2(chromium::v154_http2())
            .with_http3(http3);
        #[cfg(feature = "websocket")]
        let profile = profile.with_websocket(chromium::v154_websocket());
        let route = Route::http_connect(HttpProxy::new("https://proxy.example")?);
        let client = Client::builder(profile).route(route).build()?;
        let inner = &client.inner;

        let expected = Some(&tcp);
        assert_eq!(
            inner.http1.as_ref().and_then(|c| c.tcp_settings()),
            expected
        );
        assert_eq!(
            inner.http2.as_ref().and_then(|c| c.tcp_settings()),
            expected
        );
        assert_eq!(
            inner.http1_or_2.as_ref().and_then(|c| c.tcp_settings()),
            expected
        );
        assert_eq!(
            inner.http3.as_ref().and_then(|c| c.tcp_settings()),
            expected
        );
        assert_eq!(
            inner.https_proxy.as_ref().and_then(|c| c.tcp_settings()),
            expected
        );
        #[cfg(feature = "websocket")]
        assert_eq!(
            inner
                .websocket_http1
                .as_ref()
                .and_then(|c| c.tcp_settings()),
            expected
        );
        Ok(())
    }

    #[test]
    fn invalid_tcp_profile_has_invalid_profile_category() -> Result<(), &'static str> {
        let mut tcp = chromium::v154_tcp();
        tcp.keepalive = Some(TcpKeepalive {
            idle: Duration::ZERO,
            interval: None,
        });
        let profile = ClientProfile::new(chromium::v154_tls()).with_tcp(tcp);
        let error = Client::builder(profile)
            .build()
            .err()
            .ok_or("a zero keepalive idle time was accepted")?;

        assert_eq!(error.kind(), BuildErrorKind::InvalidProfile);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn keepalive_without_interval_is_an_invalid_profile_on_windows() -> Result<(), &'static str> {
        let mut tcp = chromium::v154_tcp();
        tcp.keepalive = Some(TcpKeepalive {
            idle: Duration::from_secs(45),
            interval: None,
        });
        let profile = ClientProfile::new(chromium::v154_tls()).with_tcp(tcp);
        let error = Client::builder(profile)
            .build()
            .err()
            .ok_or("Windows accepted a keepalive it cannot apply")?;

        assert_eq!(error.kind(), BuildErrorKind::InvalidProfile);
        Ok(())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn idle_only_keepalive_builds_where_the_host_supports_it() -> Result<(), BuildError> {
        let mut tcp = chromium::v154_tcp();
        tcp.keepalive = Some(TcpKeepalive {
            idle: Duration::from_secs(45),
            interval: None,
        });
        let profile = ClientProfile::new(chromium::v154_tls()).with_tcp(tcp);

        Client::builder(profile).build().map(drop)
    }

    #[test]
    fn invalid_proxy_root_has_trust_store_category() -> Result<(), &'static str> {
        let profile = ClientProfile::new(chromium::v154_tls());
        let error = Client::builder(profile)
            .add_proxy_root_certificate_der(b"not-a-certificate".as_slice())
            .build()
            .err()
            .ok_or("invalid HTTPS-proxy trust root was accepted")?;

        assert_eq!(error.kind(), BuildErrorKind::TrustStore);
        Ok(())
    }

    #[test]
    fn disabled_proxy_authentication_rejects_proxy_roots() -> Result<(), &'static str> {
        let profile = ClientProfile::new(chromium::v154_tls());
        let error = Client::builder(profile)
            .proxy_server_authentication(ServerAuthentication::Disabled)
            .add_proxy_root_certificate_der(b"unused".as_slice())
            .build()
            .err()
            .ok_or("disabled HTTPS-proxy authentication accepted trust roots")?;

        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
        Ok(())
    }

    #[test]
    fn https_proxy_requires_http1_in_the_tls_recipe() -> Result<(), &'static str> {
        let mut tls = chromium::v154_tls();
        tls.alpn_protocols = vec![Box::from(&b"h2"[..])];
        let profile = ClientProfile::new(tls).with_http2(chromium::v154_http2());
        let route = Route::http_connect(
            HttpProxy::new("https://proxy.example")
                .map_err(|_| "valid HTTPS proxy route was rejected")?,
        );
        let error = Client::builder(profile)
            .route(route)
            .build()
            .err()
            .ok_or("HTTPS proxy accepted TLS settings without HTTP/1.1 ALPN")?;

        assert_eq!(error.kind(), BuildErrorKind::ProtocolConfiguration);
        Ok(())
    }

    #[test]
    fn alt_svc_requires_negotiated_http1_or_2_and_http3() -> Result<(), &'static str> {
        let capacity = NonZeroUsize::MIN;
        let without_http3 =
            ClientProfile::new(chromium::v154_tls()).with_http2(chromium::v154_http2());
        let error = Client::builder(without_http3)
            .alt_svc(capacity)
            .build()
            .err()
            .ok_or("Alt-Svc was accepted without HTTP/3")?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);

        let http3 = Http3ClientSettings::new(
            chromium::v154_http3_tls(),
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        );
        let without_negotiation = ClientProfile::new(chromium::v154_http3_tls()).with_http3(http3);
        let error = Client::builder(without_negotiation)
            .alt_svc(capacity)
            .build()
            .err()
            .ok_or("Alt-Svc was accepted without negotiated HTTP/1.1 and HTTP/2")?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
        Ok(())
    }
}
