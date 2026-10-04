use std::{fmt, net::IpAddr, num::NonZeroUsize, sync::Arc, time::Duration};

use http::Method;
use phantom_net::{
    ClientCertificate, ServerAuthentication, SourceBinding,
    host_resolver::{AddressResolver, HostResolver},
    http1::Http1TlsConnector,
    http1_or_2::Http1Or2TlsConnector,
    http2::Http2TlsConnector,
    http3::Http3Connector,
    proxy::{Http2ProxyPool, HttpsProxyConnector, ProxyCredentialCache},
};
#[cfg(feature = "cookies")]
use phantom_profile::CookiePlacement;
#[cfg(feature = "websocket")]
use phantom_profile::WebSocketSettings;
use phantom_profile::quic::{QuicTransportParameterKind, QuicTransportSettings};
use phantom_profile::{
    ClientHintSettings, ClientProfile, DnsCacheSettings, Http2ProxyConnections,
    ProxyConnectTemplate, TcpSettings, UdpSettings,
};

use crate::{
    BuildError, RequestBuilder, Route,
    session::{ClientOptions, ClientState, http3_pool::ConnectUdpConnectors},
};
#[cfg(feature = "websocket")]
use crate::{WebSocketError, WebSocketRequestBuilder};

/// HTTP protocol selected for one request.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum HttpProtocol {
    /// HTTP/1.1 over TLS, plaintext TCP (direct or in a SOCKS5 tunnel), or
    /// plaintext forwarding to an HTTP proxy.
    Http1,
    /// HTTP/2 over TLS, or forwarding of `http://` requests to an HTTP proxy
    /// that speaks HTTP/2.
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
/// sessions, negotiated client-hint state, optional Alt-Svc state, and the
/// address cache. Host overrides and the address resolver are settings.
/// Independently built clients share none of that mutable state. Settings
/// are fixed when [`ClientBuilder::build`] returns; a request can override
/// only its route, timeouts, and retry policy, and can opt into content
/// decoding.
///
/// A connection belongs to the Tokio runtime that opened it, because its
/// driver runs there. A request on another runtime opens a connection of its
/// own, so a client may outlive a runtime or serve several. The per-origin
/// request limits span runtimes, and connections opened on a runtime that was
/// dropped stay pooled until the pool evicts them. A request left pending on
/// a runtime that is alive but no longer driven holds its per-origin slot
/// until it is dropped, and
/// [`RequestTimeouts::pool_admission`](crate::RequestTimeouts::pool_admission)
/// bounds how long other requests wait for one.
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

/// Transport configuration shared by a client and its clones.
///
/// Cloning is shallow: TLS contexts, the HTTP/3 connectors, and the key log
/// stay shared.
#[derive(Clone, Debug)]
pub(crate) struct ClientInner {
    pub(crate) http1: Option<Http1TlsConnector>,
    pub(crate) http1_or_2: Option<Http1Or2TlsConnector>,
    pub(crate) http2: Option<Http2TlsConnector>,
    pub(crate) http3: Option<Arc<Http3Connector>>,
    /// Proxy-leg connectors for CONNECT-UDP proxies, using proxy trust.
    pub(crate) connect_udp_proxy: Option<Arc<ConnectUdpConnectors>>,
    /// Opens CONNECT tunnels through an HTTPS proxy, sharing HTTP/2 proxy
    /// connections from the client's pool.
    pub(crate) https_proxy: Option<HttpsProxyConnector>,
    /// `https_proxy` for `http://` requests forwarded over HTTP/2, with the
    /// pool the profile's [`Http2ProxyConnections`] gives them.
    pub(crate) forward_https_proxy: Option<HttpsProxyConnector>,
    /// `https_proxy` for WebSocket tunnels, with the pool the profile's
    /// [`Http2ProxyConnections`] gives them.
    #[cfg(feature = "websocket")]
    pub(crate) websocket_https_proxy: Option<HttpsProxyConnector>,
    /// Which HTTP/2 proxy requests share a connection.
    pub(crate) http2_proxy_connections: Http2ProxyConnections,
    /// HTTP/2 connections each proxy route may open; one unless the caller
    /// opted into more.
    pub(crate) http2_proxy_connections_per_route: NonZeroUsize,
    /// How many times per redirect hop a request is sent again after its
    /// HTTP/2 connection's PING failed; see
    /// [`phantom_profile::Http2Settings::ping_failure_retries`].
    pub(crate) http2_ping_failure_retries: u8,
    /// Proxies that accepted Basic credentials, shared with the connectors.
    pub(crate) proxy_credentials: Option<ProxyCredentialCache>,
    /// Host overrides, the address resolver, and the address cache, shared
    /// with the connectors. `None` when the client asks the operating system
    /// for every connection.
    pub(crate) host_resolver: Option<HostResolver>,
    pub(crate) client_hints: Option<ClientHintSettings>,
    /// The profile's HTTP/1.1 connection bound per origin and route.
    pub(crate) http1_connections_per_origin: NonZeroUsize,
    /// How long the profile reuses an idle HTTP/1.1 connection.
    pub(crate) http1_used_idle_timeout: Option<Duration>,
    /// The idle limit the profile also enforces on a timer between requests.
    pub(crate) http1_idle_timer: Option<Duration>,
    /// Profile position of the jar's `Cookie` field.
    #[cfg(feature = "cookies")]
    pub(crate) cookie_placement: CookiePlacement,
    pub(crate) route: Route,
    /// Profile CONNECT fields for HTTP proxy routes that set none.
    pub(crate) proxy_connect: Option<Arc<ProxyConnectTemplate>>,
    /// Profile WebSocket templates and connection policy.
    #[cfg(feature = "websocket")]
    pub(crate) websocket: Option<WebSocketSettings>,
    /// HTTP/1.1 connector with the policy's Upgrade-connection ALPN offer.
    #[cfg(feature = "websocket")]
    pub(crate) websocket_http1: Option<Http1TlsConnector>,
    #[cfg(feature = "diagnostics")]
    pub(crate) key_log: Option<Arc<crate::KeyLog>>,
}

impl ClientInner {
    /// Gives the HTTPS proxy connectors new HTTP/2 connection pools: one for
    /// every purpose, or one per purpose, as the profile says.
    ///
    /// Call it after every other change to `https_proxy`, whose clones it
    /// makes.
    fn bind_http2_proxy_pools(&mut self) {
        let Some(base) = self.https_proxy.take() else {
            return;
        };
        let per_route = self.http2_proxy_connections_per_route;
        let new_pool = || Http2ProxyPool::with_max_connections_per_route(per_route);
        let tunnels = new_pool();
        let separate = self.http2_proxy_connections == Http2ProxyConnections::ByPurpose;
        let own_pool = || {
            if separate {
                new_pool()
            } else {
                tunnels.clone()
            }
        };
        self.forward_https_proxy = Some(base.clone().with_http2_proxy_pool(own_pool()));
        #[cfg(feature = "websocket")]
        {
            self.websocket_https_proxy = Some(base.clone().with_http2_proxy_pool(own_pool()));
        }
        self.https_proxy = Some(base.with_http2_proxy_pool(tunnels));
    }

    /// Gives every connector that resolves host names the same resolver.
    fn bind_host_resolver(&mut self, resolver: HostResolver) {
        let bind = |connector: Http1TlsConnector| connector.with_host_resolver(resolver.clone());
        self.http1 = self.http1.take().map(bind);
        self.http1_or_2 = self
            .http1_or_2
            .take()
            .map(|connector| connector.with_host_resolver(resolver.clone()));
        self.http2 = self
            .http2
            .take()
            .map(|connector| connector.with_host_resolver(resolver.clone()));
        self.http3 = self
            .http3
            .take()
            .map(|connector| Arc::new(connector.with_host_resolver(resolver.clone())));
        self.https_proxy = self
            .https_proxy
            .take()
            .map(|connector| connector.with_host_resolver(resolver.clone()));
        self.connect_udp_proxy = self.connect_udp_proxy.take().map(|connectors| {
            Arc::new(ConnectUdpConnectors {
                http3: connectors
                    .http3
                    .as_ref()
                    .map(|connector| connector.with_host_resolver(resolver.clone())),
                tcp: connectors
                    .tcp
                    .clone()
                    .map(|connector| connector.with_host_resolver(resolver.clone())),
            })
        });
        #[cfg(feature = "websocket")]
        {
            self.websocket_http1 = self.websocket_http1.take().map(bind);
        }
        self.host_resolver = Some(resolver);
    }

    /// Gives every connector that can open an authenticated proxy tunnel the
    /// same record.
    fn bind_proxy_credentials(&mut self, cache: &ProxyCredentialCache) {
        let bind =
            |connector: Http1TlsConnector| connector.with_proxy_credential_cache(cache.clone());
        self.http1 = self.http1.take().map(bind);
        self.http1_or_2 = self
            .http1_or_2
            .take()
            .map(|connector| connector.with_proxy_credential_cache(cache.clone()));
        self.http2 = self
            .http2
            .take()
            .map(|connector| connector.with_proxy_credential_cache(cache.clone()));
        self.https_proxy = self
            .https_proxy
            .take()
            .map(|connector| connector.with_proxy_credential_cache(cache.clone()));
        #[cfg(feature = "websocket")]
        {
            self.websocket_http1 = self.websocket_http1.take().map(bind);
        }
    }
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
            preemptive_proxy_authentication: true,
            http2_proxy_connections_per_route: NonZeroUsize::MIN,
            dns_cache: None,
            host_overrides: Vec::new(),
            address_resolver: None,
            source_binding: SourceBinding::new(),
            client_certificate: None,
            #[cfg(feature = "diagnostics")]
            key_log_capacity: None,
            #[cfg(feature = "diagnostics")]
            qlog_dir: None,
        }
    }

    /// Returns the queued TLS secrets when [`ClientBuilder::key_log`]
    /// enabled key logging.
    ///
    /// Clones of this client share one key log.
    #[cfg(feature = "diagnostics")]
    #[must_use]
    pub fn key_log(&self) -> Option<&crate::KeyLog> {
        self.inner.key_log.as_deref()
    }

    /// Starts one empty-body GET using exactly `protocol`.
    ///
    /// The request never falls back to another protocol, except an exact
    /// HTTP/3 request under
    /// [`RetryPolicy::with_http2_fallback`](crate::RetryPolicy::with_http2_fallback).
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
    /// [`HttpProtocol::Http1`] on a direct, HTTP proxy, or SOCKS5 route.
    pub fn get(
        &self,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<RequestBuilder, crate::RequestError> {
        self.request(protocol, Method::GET, uri)
    }

    /// Starts one request using exactly `protocol`.
    ///
    /// The request never falls back to another protocol, except an exact
    /// HTTP/3 request under
    /// [`RetryPolicy::with_http2_fallback`](crate::RetryPolicy::with_http2_fallback).
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
    /// [`HttpProtocol::Http1`] on a direct, HTTP proxy, or SOCKS5 route.
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
    /// HTTP/1.1. It does not race. An opt-in
    /// [`RetryPolicy`](crate::RetryPolicy) may retry a TCP or proxy connect
    /// failure before TLS starts; TLS and ALPN failures are terminal.
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
    /// An `http://` origin has no TLS stream for ALPN, so the request is sent
    /// as exact HTTP/1.1 over the route, as a browser sends it, reports
    /// [`HttpProtocol::Http1`], and learns no Alt-Svc alternative.
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
    /// [`RequestBuilder::send`] rejects an unsupported route, also before I/O.
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
    /// [`RequestBuilder::send`] rejects an unsupported route, also before I/O.
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
    preemptive_proxy_authentication: bool,
    http2_proxy_connections_per_route: NonZeroUsize,
    /// The caller's address cache choice: `None` keeps the profile's, and
    /// `Some(None)` turns caching off.
    dns_cache: Option<Option<DnsCacheSettings>>,
    /// Host names as the caller wrote them, answered with fixed addresses;
    /// a later entry for the same name wins.
    host_overrides: Vec<(Box<str>, Vec<IpAddr>)>,
    address_resolver: Option<AddressResolver>,
    /// Local addresses and interface for every outgoing socket; empty by
    /// default.
    source_binding: SourceBinding,
    client_certificate: Option<ClientCertificate>,
    #[cfg(feature = "diagnostics")]
    key_log_capacity: Option<NonZeroUsize>,
    #[cfg(feature = "diagnostics")]
    qlog_dir: Option<std::path::PathBuf>,
}

impl fmt::Debug for ClientBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("ClientBuilder");
        debug
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
            .field(
                "preemptive_proxy_authentication",
                &self.preemptive_proxy_authentication,
            )
            .field(
                "max_http2_proxy_connections_per_route",
                &self.http2_proxy_connections_per_route,
            )
            .field("dns_cache", &self.dns_cache_settings())
            .field("host_overrides", &self.host_overrides.len())
            .field("address_resolver", &self.address_resolver.is_some())
            .field("source_binding", &self.source_binding)
            .field("client_certificate", &self.client_certificate.is_some());
        self.options.debug_fields(&mut debug);
        debug.finish_non_exhaustive()
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
    /// authentication takes the `danger-disable-verification` feature and is
    /// supported for HTTP/1.1 and HTTP/2. [`Self::build`] fails with
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

    /// Queues the TLS secrets of this client's connections for an NSS key log.
    ///
    /// The key log holds the TLS 1.3 traffic secrets of every TCP and QUIC
    /// handshake the client makes, to origins and to proxies. Anyone who holds
    /// them can decrypt a capture of those connections. Use it only to debug
    /// your own connections, for example to read a packet capture in
    /// Wireshark.
    ///
    /// Up to `capacity` lines wait in a queue until
    /// [`KeyLog::write_pending`](crate::KeyLog::write_pending) drains it.
    /// Handshakes never wait for the queue: a line that does not fit is
    /// dropped and counted. Each TLS 1.3 handshake adds five lines, or six
    /// when it offers early data (`CLIENT_EARLY_TRAFFIC_SECRET`). TLS 1.2
    /// handshakes are not logged.
    #[cfg(feature = "diagnostics")]
    #[must_use]
    pub fn key_log(mut self, capacity: NonZeroUsize) -> Self {
        self.key_log_capacity = Some(capacity);
        self
    }

    /// Writes a qlog file for each new QUIC connection into `dir`.
    ///
    /// Each file holds one connection's QUIC events as JSON-SEQ, without
    /// request fields or payloads, and is named
    /// `phantom-<process>-<milliseconds>-<counter>.sqlog`. The directory must
    /// exist. The file is created synchronously while the connection is set
    /// up, and a connection whose file cannot be created fails before its
    /// handshake with
    /// [`RequestErrorKind::Http3`](crate::RequestErrorKind::Http3). Writes are
    /// buffered, so the file is complete only after the connection closes.
    #[cfg(feature = "diagnostics")]
    #[must_use]
    pub fn qlog_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.qlog_dir = Some(dir.into());
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

    /// Sets whether Basic proxy credentials are sent before a challenge to a
    /// proxy that already accepted them.
    ///
    /// Enabled by default, as Chrome, Edge, and Firefox do. After an HTTP or
    /// HTTPS proxy configured with [`HttpProxy::with_basic_auth`] answers a
    /// `407` and accepts the credentials on the retry, this client remembers
    /// the proxy's scheme, host, and port with those credentials. Later
    /// CONNECT tunnels (including WebSocket tunnels) and forwarded `http://`
    /// requests to that proxy send `Proxy-Authorization` on the first
    /// attempt. A `407` to such a request forgets the proxy and allows the
    /// usual single retry. The record holds at most
    /// [`MAX_PROXY_CREDENTIAL_ENTRIES`] proxy and credential pairs and is
    /// never consulted for a route whose credentials differ. Clones of this
    /// client share it; a separately built client has its own.
    ///
    /// When disabled, every tunnel and forwarded request starts without
    /// credentials and waits for a `407`. CONNECT-UDP routes always start
    /// without credentials.
    ///
    /// [`HttpProxy::with_basic_auth`]: crate::HttpProxy::with_basic_auth
    /// [`MAX_PROXY_CREDENTIAL_ENTRIES`]: phantom_net::proxy::MAX_PROXY_CREDENTIAL_ENTRIES
    #[must_use]
    pub fn preemptive_proxy_authentication(mut self, enabled: bool) -> Self {
        self.preemptive_proxy_authentication = enabled;
        self
    }

    /// Lets each route through an HTTP/2 proxy open up to `maximum`
    /// connections to it instead of one.
    ///
    /// Off by default: like Chrome and Firefox, a client keeps one HTTP/2
    /// connection per proxy route and puts every CONNECT tunnel on it, and a
    /// tunnel past the proxy's `SETTINGS_MAX_CONCURRENT_STREAMS` waits until
    /// another stream on it ends. With a larger `maximum`, a route opens
    /// another connection once each connection carries
    /// [`MAX_TUNNELS_PER_HTTP2_PROXY_CONNECTION`] tunnels, or the proxy's
    /// stream limit when that is lower, so a tunnel does not wait behind
    /// long-lived tunnels. The trade-off: the proxy can see more connections
    /// than a browser opens. The profile's CONNECT recipe still decides which
    /// requests share each route's connections.
    ///
    /// [`Self::build`] fails with
    /// [`InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy) when `maximum`
    /// exceeds [`HTTP2_PROXY_CONNECTIONS_PER_ROUTE_CEILING`].
    ///
    /// [`MAX_TUNNELS_PER_HTTP2_PROXY_CONNECTION`]: phantom_net::proxy::MAX_TUNNELS_PER_HTTP2_PROXY_CONNECTION
    /// [`HTTP2_PROXY_CONNECTIONS_PER_ROUTE_CEILING`]: phantom_net::proxy::HTTP2_PROXY_CONNECTIONS_PER_ROUTE_CEILING
    #[must_use]
    pub fn max_http2_proxy_connections_per_route(mut self, maximum: NonZeroUsize) -> Self {
        self.http2_proxy_connections_per_route = maximum;
        self
    }

    /// Caches the addresses this client resolves with `settings` in place of
    /// the profile's.
    ///
    /// By default the client uses the profile's [`DnsCacheSettings`], set
    /// with [`ClientProfile::with_dns_cache`], and resolves the host of every
    /// new connection when the profile has none. The cache covers each name
    /// the client resolves itself: origin hosts on a direct route, proxy
    /// hosts, and the target of a local-DNS `socks5://` route. A target a
    /// proxy resolves, through `socks5h://`, an HTTP proxy, or CONNECT-UDP,
    /// is never resolved or cached locally, and neither is a name with an
    /// override from [`resolve`](Self::resolve). Concurrent connections to
    /// one host share one lookup, and the resolver's address order is kept
    /// for address selection. A system lookup runs on the blocking pool of the
    /// runtime that started it, as `tokio::net::lookup_host` does, so the
    /// number in flight is bounded by that pool, and a request on one runtime
    /// never waits on another runtime that has stopped being driven. A
    /// lookup through a [`dns_resolver`](Self::dns_resolver) runs as a task on
    /// the runtime that started it instead.
    ///
    /// Clones of this client share the cache; a separately built client has
    /// its own. The client does not watch for network changes as browsers do;
    /// [`Client::clear_dns_cache`] forgets every answer.
    #[must_use]
    pub fn dns_cache(mut self, settings: DnsCacheSettings) -> Self {
        self.dns_cache = Some(Some(settings));
        self
    }

    /// Resolves the host of every new connection, even when the profile
    /// caches addresses.
    #[must_use]
    pub fn no_dns_cache(mut self) -> Self {
        self.dns_cache = Some(None);
        self
    }

    /// Connects to `addresses` whenever this client resolves `host` itself,
    /// without asking the address resolver or the address cache.
    ///
    /// The override applies wherever the client resolves a name locally: the
    /// origin host on a direct route, proxy hosts, and the target of a
    /// local-DNS `socks5://` route. A target that a proxy resolves, through
    /// `socks5h://`, an HTTP proxy, or CONNECT-UDP, is sent to the proxy by
    /// name and never uses the override. The port always comes from the
    /// request or proxy URL. The TLS server name, certificate check, `Host`
    /// or `:authority`, cookies, and pool keys all keep using `host`.
    ///
    /// `host` is normalized as a URL host is, so it matches the host of a
    /// request URL however either is written: ASCII case is folded and a
    /// Unicode name becomes its IDNA A-label form (`bücher.example` and
    /// `xn--bcher-kva.example` are one name). A trailing dot is kept, so
    /// `example.com.` is another name. Connections try `addresses` in the
    /// given order, raced as the profile's TCP settings describe; an empty
    /// list makes `host` fail to resolve. Calling this again for the same
    /// name replaces its addresses. HTTPS DNS record lookups, with the
    /// `https-records` feature, still query the record for `host`, and an
    /// overridden name counts as resolved at once, so a profile that uses
    /// ECH from HTTPS records waits only the 5 ms minimum for the record.
    ///
    /// [`build`](Self::build) fails with
    /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy)
    /// when `host` is not a valid domain name. That includes every form of
    /// IP address a URL accepts, such as `127.1`, `[::1]`, or full-width
    /// digits, because the client always uses an IP address as written.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr};
    ///
    /// use phantom::profile::{chromium, ClientProfile};
    /// use phantom::Client;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let profile = ClientProfile::new(chromium::v154_tls()).with_http2(chromium::v154_http2());
    /// // Send example.com traffic to a staging server, keeping SNI and Host.
    /// let client = Client::builder(profile)
    ///     .resolve("example.com", [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))])
    ///     .build()?;
    /// # drop(client);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn resolve(mut self, host: &str, addresses: impl IntoIterator<Item = IpAddr>) -> Self {
        self.host_overrides
            .push((host.into(), addresses.into_iter().collect()));
        self
    }

    /// Resolves the host names this client resolves itself through
    /// `resolver` instead of the operating system.
    ///
    /// The resolver answers the same names the operating system would:
    /// origin hosts on a direct route, proxy hosts, and the target of a
    /// local-DNS `socks5://` route, except names that have an override from
    /// [`resolve`](Self::resolve). With an address cache, from the profile or
    /// [`dns_cache`](Self::dns_cache), each name is asked for once per cache
    /// lifetime, and concurrent connections share that lookup; without one,
    /// every new connection asks. Clones of the client share the resolver.
    ///
    /// A resolver error fails the request with the kind a failed system
    /// lookup gets on the same path:
    /// [`Resolve`](crate::RequestErrorKind::Resolve) for an HTTP/3 origin, a
    /// local-DNS SOCKS5 target, or a CONNECT-UDP proxy host;
    /// [`Proxy`](crate::RequestErrorKind::Proxy) for another proxy host; and
    /// [`Connect`](crate::RequestErrorKind::Connect) for a TCP origin.
    /// Without an address cache, the resolver's `io::Error` is in the
    /// error's source chain. With one, the chain holds a new `io::Error` with
    /// the same kind and message, because one stored failure can answer
    /// several requests.
    ///
    /// With the `https-records` feature,
    /// `AddressResolver::system_nameservers` sends Phantom's own A and AAAA
    /// queries, as Chromium's built-in DNS client does, and reports each
    /// answer's record TTL, which the address cache honors through
    /// [`DnsCacheSettings::min_record_ttl`]. The client opens that
    /// resolver's query sockets with the profile's
    /// [`UdpSettings`](crate::profile::UdpSettings), so the Chromium-family
    /// recipes set `SO_RANDOMIZE_PORT` on them on Windows.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::io;
    /// use std::net::{IpAddr, Ipv4Addr};
    ///
    /// use phantom::profile::{chromium, ClientProfile};
    /// use phantom::{AddressResolver, Client};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let resolver = AddressResolver::from_fn(|host: String| async move {
    ///     // Look `host` up with a DNS library of your choice.
    ///     match host.as_str() {
    ///         "example.com" => Ok(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10))]),
    ///         _ => Err(io::Error::new(io::ErrorKind::NotFound, "unknown host")),
    ///     }
    /// });
    /// let profile = ClientProfile::new(chromium::v154_tls()).with_http2(chromium::v154_http2());
    /// let client = Client::builder(profile).dns_resolver(resolver).build()?;
    /// # drop(client);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn dns_resolver(mut self, resolver: AddressResolver) -> Self {
        self.address_resolver = Some(resolver);
        self
    }

    /// Sends this client's connections from `address`.
    ///
    /// Off by default: the operating system picks each socket's source
    /// address. The address binds every TCP socket and QUIC UDP socket of
    /// its family that the client opens, to origins and to proxies, and the
    /// UDP socket of a SOCKS5 association. Call this once for an IPv4 and
    /// once for an IPv6 address to bind both families; a later address of
    /// the same family replaces the earlier one.
    ///
    /// When only one family has an address, connections use only the
    /// resolved addresses of that family, as curl does with `--interface` and
    /// an address: a host with both kinds of address is reached over the
    /// bound family, and one with none of it fails with
    /// [`Connect`](crate::RequestErrorKind::Connect) for an origin, over TCP
    /// or QUIC, or [`Proxy`](crate::RequestErrorKind::Proxy) for a proxy,
    /// with an [`std::io::ErrorKind::AddrNotAvailable`] error in the source
    /// chain. No connection falls
    /// back to an unbound socket. An address that no local interface holds
    /// fails each connection the same way when its socket binds. Name
    /// resolution is not bound, and no field of the TLS, HTTP/2, or HTTP/3
    /// fingerprint changes.
    ///
    /// [`build`](Self::build) fails with
    /// [`InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy) when `address`
    /// is unspecified, multicast, or the IPv4 broadcast address.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    ///
    /// use phantom::profile::{chromium, ClientProfile};
    /// use phantom::Client;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let profile = ClientProfile::new(chromium::v154_tls()).with_http2(chromium::v154_http2());
    /// let client = Client::builder(profile)
    ///     .local_address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)))
    ///     .local_address(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 10)))
    ///     .build()?;
    /// # drop(client);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn local_address(mut self, address: IpAddr) -> Self {
        self.source_binding = self.source_binding.with_address(address);
        self
    }

    /// Binds every socket this client opens to the network interface `name`.
    ///
    /// Off by default. The binding covers the same sockets as
    /// [`local_address`](Self::local_address), with `SO_BINDTODEVICE`, and
    /// leaves the source address to the operating system unless
    /// `local_address` also sets one. It is available on Linux and Android.
    /// [`build`](Self::build) fails with
    /// [`InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy) on other
    /// platforms, and when `name` is empty, holds a NUL byte, or is longer
    /// than 15 bytes. Linux kernels before 5.7 let only a process with
    /// `CAP_NET_RAW` bind a socket to an interface; there each connection
    /// fails when its socket binds.
    #[must_use]
    pub fn interface(mut self, name: &str) -> Self {
        self.source_binding = self.source_binding.with_interface(name);
        self
    }

    /// Presents `certificate` to every origin that requests TLS client
    /// authentication, over TCP and QUIC.
    ///
    /// Off by default: without a certificate, a server's
    /// `CertificateRequest` gets an empty `Certificate` message, as a
    /// browser sends when no certificate is chosen. With one, the ClientHello
    /// does not change, and the certificate and its chain leave the client
    /// only in answer to a `CertificateRequest`. One certificate serves every
    /// origin; there is no per-origin selection. Proxies, including the
    /// outer connection of a CONNECT-UDP route, never receive it.
    ///
    /// BoringSSL signs the `CertificateVerify` only with a scheme from the
    /// profile's `signature_schemes`, so [`build`](Self::build) fails with
    /// [`InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy) when the TLS
    /// or HTTP/3 TLS settings have no scheme for the key; see
    /// [`ClientCertificate::check_signature_schemes`]. The Chromium recipes
    /// sign with RSA, P-256, and P-384 keys, and the Firefox recipe also with
    /// P-521 keys.
    ///
    /// A server that rejects the certificate, or its absence, fails the
    /// request. Over TLS 1.2 the handshake fails, with
    /// [`Tls`](crate::RequestErrorKind::Tls). Over TLS 1.3 and QUIC the
    /// client finishes its handshake before the server checks the
    /// certificate, so the server's alert can instead fail the first read,
    /// with the kind of the request's protocol, such as
    /// [`Http1`](crate::RequestErrorKind::Http1).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use phantom::profile::{chromium, ClientProfile};
    /// use phantom::{Client, ClientCertificate};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let certificate = ClientCertificate::from_pem(
    ///     &std::fs::read("client-chain.pem")?,
    ///     &std::fs::read("client-key.pem")?,
    /// )?;
    /// let profile = ClientProfile::new(chromium::v154_tls()).with_http2(chromium::v154_http2());
    /// let client = Client::builder(profile)
    ///     .client_certificate(certificate)
    ///     .build()?;
    /// # drop(client);
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn client_certificate(mut self, certificate: ClientCertificate) -> Self {
        self.client_certificate = Some(certificate);
        self
    }

    /// Returns the host resolver the client will share with its connectors,
    /// or `None` when it asks the operating system for every connection.
    fn host_resolver(&self) -> Result<Option<HostResolver>, BuildError> {
        let dns_cache = self.dns_cache_settings().copied();
        if self.host_overrides.is_empty() && self.address_resolver.is_none() && dns_cache.is_none()
        {
            return Ok(None);
        }
        let mut resolver = HostResolver::new();
        if let Some(address_resolver) = &self.address_resolver {
            let address_resolver = match self.profile.udp() {
                Some(udp) => address_resolver.clone().with_udp_settings(*udp),
                None => address_resolver.clone(),
            };
            resolver = resolver.with_resolver(address_resolver);
        }
        if let Some(settings) = dns_cache {
            resolver = resolver.with_cache(settings);
        }
        for (host, addresses) in &self.host_overrides {
            // The same parser canonicalizes request and proxy hosts, so the
            // key matches the name a connector resolves.
            let Ok(url::Host::Domain(host)) = url::Host::parse(host) else {
                return Err(BuildError::invalid_policy(
                    "a host override must name a valid domain, not an IP address",
                ));
            };
            resolver = resolver.with_override(&host, addresses.iter().copied());
        }
        Ok(Some(resolver))
    }

    /// Returns the address cache settings the client will use, if any.
    fn dns_cache_settings(&self) -> Option<&DnsCacheSettings> {
        match &self.dns_cache {
            Some(choice) => choice.as_ref(),
            None => self.profile.dns_cache(),
        }
    }

    /// Sets the finite policy for following redirect responses.
    ///
    /// The default is [`RedirectPolicy::none`](crate::RedirectPolicy::none),
    /// which returns a 3xx response without following it. Redirects are
    /// followed to `http://` and `https://` targets. A target with another
    /// scheme fails with
    /// [`RequestErrorKind::Redirect`](crate::RequestErrorKind::Redirect), and a
    /// hop the request's protocol selection or route cannot carry fails with
    /// that combination's typed error before the hop is sent.
    #[must_use]
    pub fn redirect_policy(mut self, policy: crate::RedirectPolicy) -> Self {
        self.options.redirect_policy = policy;
        self
    }

    /// Sets the policy for retrying connection-establishment failures.
    ///
    /// The default is [`RetryPolicy::none`](crate::RetryPolicy::none).
    /// Connection retries apply only to connection setup before dispatch:
    /// exact-protocol acquisition and negotiated H1/H2 TCP setup before ALPN
    /// selection.
    /// [`RequestBuilder::retry_policy`](crate::RequestBuilder::retry_policy)
    /// replaces the policy for one request. A delay or `Retry-After` limit
    /// the runtime clock cannot represent fails [`Self::build`] with
    /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
    #[must_use]
    pub fn retry_policy(mut self, policy: crate::RetryPolicy) -> Self {
        self.options.retry_policy = policy;
        self
    }

    /// Sets the default phase and whole-operation limits for ordinary requests.
    ///
    /// The default is [`RequestTimeouts::new`](crate::RequestTimeouts::new),
    /// which sets no limit.
    /// [`RequestBuilder::timeouts`](crate::RequestBuilder::timeouts) replaces
    /// this policy for one request. Every timeout is disabled unless
    /// explicitly present in `timeouts`. A duration the runtime clock cannot
    /// represent fails [`Self::build`] with
    /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
    #[must_use]
    pub fn request_timeouts(mut self, timeouts: crate::RequestTimeouts) -> Self {
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
    pub fn max_retained_http1_connections(mut self, maximum: std::num::NonZeroUsize) -> Self {
        self.options.max_retained_http1_connections = maximum;
        self
    }

    /// Sets the local active-request bound for each HTTP/1.1 pool key.
    ///
    /// Each active HTTP/1.1 request holds its own connection, so this is also
    /// the most connections open at once to the pool key, idle ones included.
    /// Negotiated requests use the same bound for connections that selected
    /// HTTP/1.1 or are still in their TLS handshake. It replaces the
    /// profile's [`Http1Settings`] bound. Without either, the bound is one
    /// connection.
    ///
    /// [`Http1Settings`]: crate::profile::Http1Settings
    #[must_use]
    pub fn max_concurrent_http1_requests_per_origin(
        mut self,
        maximum: std::num::NonZeroUsize,
    ) -> Self {
        self.options.max_concurrent_http1_requests_per_origin = Some(maximum);
        self
    }

    /// Sets the number of requests allowed to wait per HTTP/1.1 pool key.
    ///
    /// The default is 100. A pool key is the origin plus the complete route.
    /// A request beyond the limit fails with
    /// [`RequestErrorKind::Capacity`](crate::RequestErrorKind::Capacity).
    #[must_use]
    pub fn max_pending_http1_requests_per_origin(
        mut self,
        maximum: std::num::NonZeroUsize,
    ) -> Self {
        self.options.max_pending_http1_requests_per_origin = maximum;
        self
    }

    /// Sets the maximum number of HTTP/2 pool entries retained for reuse.
    ///
    /// The default is 32. When the limit is reached, the least recently used
    /// entry is evicted. The negotiated H1/H2 pool uses the lower of the
    /// configured H1 and H2 retention limits so neither maximum is exceeded.
    #[must_use]
    pub fn max_retained_http2_connections(mut self, maximum: std::num::NonZeroUsize) -> Self {
        self.options.max_retained_http2_connections = maximum;
        self
    }

    /// Sets the local active-request bound for each HTTP/2 pool key.
    ///
    /// The default is 100. The peer's stream limit also caps active requests.
    /// The bound covers all of a pool key's connections when
    /// [`Self::max_http2_connections_per_origin`] allows more than one.
    #[must_use]
    pub fn max_concurrent_http2_requests_per_origin(
        mut self,
        maximum: std::num::NonZeroUsize,
    ) -> Self {
        self.options.max_concurrent_http2_requests_per_origin = maximum;
        self
    }

    /// Sets the number of requests allowed to wait per HTTP/2 pool key.
    ///
    /// The default is 100. A request beyond the limit fails with
    /// [`RequestErrorKind::Capacity`](crate::RequestErrorKind::Capacity).
    #[must_use]
    pub fn max_pending_http2_requests_per_origin(
        mut self,
        maximum: std::num::NonZeroUsize,
    ) -> Self {
        self.options.max_pending_http2_requests_per_origin = maximum;
        self
    }

    /// Lets each HTTP/2 pool key open up to `maximum` connections.
    ///
    /// The default is 1, as Chrome, Edge, and Firefox keep one HTTP/2
    /// connection per origin. With a higher limit, a request opens another
    /// connection only when every connection to the pool key has as many
    /// streams in flight as it can carry: the lower of
    /// [`Self::max_concurrent_http2_requests_per_origin`] and the peer's
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`. Each connection makes its own TCP
    /// and TLS handshake and sends the profile's full HTTP/2 preface. A new
    /// stream goes to the connection with the fewest streams in flight. At
    /// the limit, the least-loaded connection takes the stream and holds it
    /// until the peer allows it.
    ///
    /// This applies to exact HTTP/2 requests and to negotiated requests
    /// whose connections select HTTP/2. The active and waiting bounds stay
    /// per pool key, across all its connections, so a connection count
    /// above one helps only when the peer's stream limit is below
    /// [`Self::max_concurrent_http2_requests_per_origin`]. A server can see
    /// several simultaneous connections from one client, which no browser
    /// opens to one origin.
    #[must_use]
    pub fn max_http2_connections_per_origin(mut self, maximum: std::num::NonZeroUsize) -> Self {
        self.options.max_http2_connections_per_origin = maximum;
        self
    }

    /// Bounds how long a negotiated request waits for another request's TLS
    /// handshake to an origin that selected HTTP/2 before.
    ///
    /// By default the request waits until that handshake finishes, as
    /// Firefox 157 does, so a stalled handshake stalls every request queued
    /// behind it. Chromium 154 waits at most 300 ms. After `limit`, the
    /// request opens a connection of its own; if both select HTTP/2, the one
    /// that finishes second closes and its requests join the first, unless
    /// [`Self::max_http2_connections_per_origin`] allows both. The server
    /// sees a second TLS handshake that a Firefox profile would not make.
    ///
    /// A `limit` the runtime clock cannot represent fails [`Self::build`]
    /// with [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
    #[must_use]
    pub fn negotiated_setup_wait_limit(mut self, limit: std::time::Duration) -> Self {
        self.options.negotiated_setup_wait_limit = Some(limit);
        self
    }

    /// Sets the maximum number of HTTP/3 pool entries retained for reuse.
    ///
    /// The default is 32. When the limit is reached, the least recently used
    /// entry is evicted. One entry keeps connections for up to four transport
    /// locations, so exact H3 and Alt-Svc H3 do not replace each other, and
    /// up to [`Self::max_http3_connections_per_origin`] to each location.
    #[must_use]
    pub fn max_retained_http3_connections(mut self, maximum: std::num::NonZeroUsize) -> Self {
        self.options.max_retained_http3_connections = maximum;
        self
    }

    /// Sets the local active-request bound for each HTTP/3 pool key.
    ///
    /// The default is 100. The peer's stream limit also caps active requests.
    /// The bound covers all of a pool key's connections when
    /// [`Self::max_http3_connections_per_origin`] allows more than one.
    #[must_use]
    pub fn max_concurrent_http3_requests_per_origin(
        mut self,
        maximum: std::num::NonZeroUsize,
    ) -> Self {
        self.options.max_concurrent_http3_requests_per_origin = maximum;
        self
    }

    /// Sets the number of requests allowed to wait per HTTP/3 pool key.
    ///
    /// The default is 100. A request beyond the limit fails with
    /// [`RequestErrorKind::Capacity`](crate::RequestErrorKind::Capacity).
    #[must_use]
    pub fn max_pending_http3_requests_per_origin(
        mut self,
        maximum: std::num::NonZeroUsize,
    ) -> Self {
        self.options.max_pending_http3_requests_per_origin = maximum;
        self
    }

    /// Lets each HTTP/3 pool key open up to `maximum` QUIC connections to
    /// one transport location.
    ///
    /// The default is 1, as Chrome, Edge, and Firefox keep one HTTP/3
    /// connection per origin. With a higher limit, a request opens another
    /// connection only when every connection to the location has as many
    /// streams in flight as it can carry: the lower of
    /// [`Self::max_concurrent_http3_requests_per_origin`] and the server's
    /// `initial_max_streams_bidi` transport parameter. An absent or zero
    /// parameter counts as one stream, and later `MAX_STREAMS` credit is
    /// not counted: a server that grants more than its initial limit gets
    /// more connections than it needs. A new stream goes to the connection
    /// with the fewest streams in flight. At the limit, the
    /// least-loaded connection takes the stream, and QUIC holds it until
    /// the server grants stream credit.
    ///
    /// One request at a time opens a connection to a location; requests
    /// that arrive meanwhile wait for it and share it while it has room.
    /// Each new connection makes its own QUIC handshake with the profile's
    /// settings. It presents a session ticket when the pool entry holds
    /// one and offers early data as the client would on any resumed
    /// connection. On a CONNECT-UDP route, each connection has its own
    /// proxy tunnel. A connection that is draining after the server's
    /// GOAWAY takes no new request and does not count toward the limit.
    ///
    /// The limit applies to exact HTTP/3 requests and to negotiated
    /// requests that use an Alt-Svc or HTTPS-record alternative; an origin
    /// and its alternative are separate locations, each with its own
    /// limit. The active and waiting bounds stay per pool key, across all
    /// its connections, so a limit above one helps only when the server's
    /// stream limit is below
    /// [`Self::max_concurrent_http3_requests_per_origin`]. A server can see
    /// several simultaneous QUIC connections from one client, which no
    /// browser opens to one origin.
    ///
    /// [`Self::build`] fails with
    /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy)
    /// when `maximum` is above 8.
    #[must_use]
    pub fn max_http3_connections_per_origin(mut self, maximum: std::num::NonZeroUsize) -> Self {
        self.options.max_http3_connections_per_origin = maximum;
        self
    }

    /// Sets the number of origins that may retain `Accept-CH` state.
    ///
    /// The default is 64.
    #[must_use]
    pub fn max_client_hint_origins(mut self, maximum: std::num::NonZeroUsize) -> Self {
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
    /// A later negotiated request uses the first fresh `h3` alternative the
    /// field listed that is not broken, up to eight per origin, without
    /// changing its origin identity or its route. Alternative setup failure is
    /// terminal for that request and never falls back implicitly to H1 or H2.
    ///
    /// The store is keyed by origin and route, so an alternative learned on
    /// one route is only ever dialed over that route. Learning runs only on
    /// direct and SOCKS5 routes. An HTTP proxy route makes negotiated requests
    /// but stores no advertisement, because its CONNECT tunnel cannot carry
    /// QUIC; see [`Route`](crate::Route).
    #[must_use]
    pub fn alt_svc(mut self, maximum_origins: std::num::NonZeroUsize) -> Self {
        self.options.max_alt_svc_origins = Some(maximum_origins);
        self
    }

    /// Selects how negotiated requests use a learned HTTP/3 alternative.
    ///
    /// The default is [`AltSvcPolicy::sequential`](crate::AltSvcPolicy::sequential).
    /// A racing policy requires [`Self::alt_svc`]; building without
    /// it, or with an origin delay the runtime clock cannot represent, fails
    /// with [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
    #[must_use]
    pub fn alt_svc_policy(mut self, policy: crate::AltSvcPolicy) -> Self {
        self.options.alt_svc_policy = policy;
        self
    }

    /// Sets whether a resumed HTTP/3 connection offers early (0-RTT) data,
    /// overriding the profile.
    ///
    /// Without this call the profile decides. A client offers early data
    /// when its HTTP/3 QUIC settings set `early_data`, as the Chrome 154
    /// and Edge 154 recipes do, because the captured browsers offer it on
    /// every resumed connection. `false` turns it off for such a profile; `true`
    /// turns it on for a profile that leaves it unset.
    ///
    /// # Replay
    ///
    /// Early data is replayable. An attacker who records a connection's first
    /// flight can deliver it to the server again, and the server may process
    /// each copy (RFC 8446, section 8; RFC 9001, section 9.2).
    ///
    /// Only a request that is safe to replay goes out as early data: a safe
    /// method (`GET`, `HEAD`, `OPTIONS`, or `TRACE`) with no body and no
    /// trailers, the rule Chromium applies to a request of default
    /// idempotency. It is sent on a new connection that presents a ticket
    /// permitting early data; a request that finds a pooled connection uses
    /// it as usual. Any other request that opens a new connection offers
    /// early data in its ClientHello, as the captured browsers do, but is
    /// sent only after the handshake. Under a profile with dynamic QPACK
    /// encoding, as in the Chrome 154 recipe, the connection encodes early
    /// requests with the server's SETTINGS remembered with the ticket, as
    /// Chromium does, and closes with `H3_SETTINGS_ERROR` if the server's own
    /// SETTINGS then lower a remembered limit. If the server rejects the
    /// early data, it processed none of it, and Phantom sends the request
    /// again after a handshake over the same route and protocol.
    ///
    /// Building with `true` fails with
    /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy)
    /// unless the profile has HTTP/3 settings whose TLS settings enable
    /// `session_tickets`, because early data needs a resumed session.
    #[must_use]
    pub fn http3_early_data(mut self, enabled: bool) -> Self {
        self.options.http3_early_data = Some(enabled);
        self
    }

    /// Lets HTTPS DNS records (RFC 9460) advertise HTTP/3 for negotiated
    /// requests, as a learned Alt-Svc advertisement does. Off by default.
    ///
    /// When no Alt-Svc alternative is stored for a direct-route request, the
    /// client looks up the origin's HTTPS records with `resolver`. If a usable
    /// ServiceMode record lists `h3` for the origin's own host and port, the
    /// request uses HTTP/3 at that location under the
    /// [`AltSvcPolicy`](crate::AltSvcPolicy), without an `Alt-Used` field.
    ///
    /// The lookup does not hold back the request. While it is in flight, a
    /// sequential client sends the request to the origin, and a racing
    /// client starts origin setup at once and alternative setup when the
    /// lookup advertises `h3`. A failed lookup counts as no advertisement.
    ///
    /// A profile that sets
    /// [`TlsSettings::ech_from_https_records`](crate::profile::TlsSettings::ech_from_https_records),
    /// as the Chrome 154, Edge 154, Brave 154, and Opera 136 recipes do, also
    /// uses the records for Encrypted Client Hello on every direct TLS
    /// connection over TCP: those of negotiated and exact-protocol HTTP/1.1
    /// and HTTP/2 requests and of `wss://` WebSocket openings. Each such connection
    /// starts the origin's lookup when none is cached, and its TLS handshake
    /// waits for it at most 20% of the address resolution time, clamped to
    /// 5-50 ms, then offers the record's `ech`. An HTTP/3 profile that sets
    /// the field does the same on a direct QUIC connection to the origin's
    /// own host and port, which starts once the lookup ends within that
    /// bound; a rejected QUIC connection is not repeated. Exact HTTP/3
    /// requests, and negotiated ones under
    /// [`AltSvcPolicy::sequential`](crate::AltSvcPolicy::sequential), then
    /// keep failing on the stale configuration until the cached record
    /// expires; set `ech_from_https_records = false` on the profile's
    /// HTTP/3 TLS settings to send ECH GREASE instead.
    ///
    /// Results are cached per origin for the records' TTL, capped at one day,
    /// or 60 seconds when there is no TTL, as after a failed lookup. The
    /// cache holds at most the `maximum_origins` given to
    /// [`Self::alt_svc`], which this requires; building without it
    /// fails with
    /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
    /// Concurrent requests for one origin share one lookup. Proxy routes never
    /// query. The client opens the resolver's query sockets with the
    /// profile's [`UdpSettings`](crate::profile::UdpSettings), so the
    /// Chromium-family recipes set `SO_RANDOMIZE_PORT` on them on Windows.
    ///
    /// Requires the `https-records` feature.
    #[cfg(feature = "https-records")]
    #[must_use]
    pub fn https_record_discovery(mut self, resolver: crate::dns::HttpsRecordResolver) -> Self {
        self.options.https_record_resolver = Some(resolver);
        self
    }

    /// Enables a bounded in-memory cookie jar owned by the client.
    ///
    /// By default the client has no cookie jar. This jar uses the default
    /// [`CookieLimits`](crate::CookieLimits).
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookies(mut self) -> Self {
        self.options.cookie_jar = Some(crate::CookieJar::default());
        self
    }

    /// Enables cookie handling with a caller-created jar.
    ///
    /// By default the client has no cookie jar. Use this to set other
    /// [`CookieLimits`](crate::CookieLimits).
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookie_jar(mut self, jar: crate::CookieJar) -> Self {
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
    ///   TLS, TCP, HTTP/1.1, client-hint, WebSocket, HTTP/2, or HTTP/3
    ///   settings are invalid, or this host cannot apply the TCP settings;
    /// - [`InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy) when a
    ///   timeout, retry delay, negotiated setup wait limit, or Alt-Svc race
    ///   delay or setup limit exceeds the runtime clock range;
    ///   `max_http3_connections_per_origin` or
    ///   `max_http2_proxy_connections_per_route` is above its ceiling; disabled
    ///   authentication is combined with added roots, HTTP/3, or a
    ///   CONNECT-UDP route; Alt-Svc is enabled without negotiated H1/H2
    ///   and HTTP/3; a racing Alt-Svc policy has no store; or the profile's
    ///   WebSocket connection policy needs HTTP/2 settings it lacks;
    /// - [`TrustStore`](crate::BuildErrorKind::TrustStore) when an added
    ///   origin or proxy root cannot be loaded;
    /// - [`ProtocolConfiguration`](crate::BuildErrorKind::ProtocolConfiguration)
    ///   when a protocol connector cannot represent the profile, such as an
    ///   HTTPS proxy route whose TLS ALPN list lacks `http/1.1`, or when
    ///   BoringSSL's random number generator fails while drawing the order
    ///   of a
    ///   [`TrustAnchorIds::PerClient`](crate::profile::TrustAnchorIds::PerClient)
    ///   list; or
    /// - [`NoSupportedProtocol`](crate::BuildErrorKind::NoSupportedProtocol)
    ///   when the profile enables no HTTP protocol Phantom implements.
    pub fn build(mut self) -> Result<Client, BuildError> {
        if self.http2_proxy_connections_per_route.get()
            > phantom_net::proxy::HTTP2_PROXY_CONNECTIONS_PER_ROUTE_CEILING
        {
            return Err(BuildError::invalid_policy(
                "max_http2_proxy_connections_per_route exceeds HTTP2_PROXY_CONNECTIONS_PER_ROUTE_CEILING",
            ));
        }
        self.options.validate_policies()?;
        #[cfg(feature = "https-records")]
        if let Some(udp) = self.profile.udp() {
            self.options.https_record_resolver = self
                .options
                .https_record_resolver
                .take()
                .map(|resolver| resolver.with_udp_settings(*udp));
        }
        self.source_binding
            .validate()
            .map_err(BuildError::invalid_source_binding)?;
        if let Some(certificate) = &self.client_certificate {
            let http3_tls = self.profile.http3().map(|settings| settings.tls());
            for tls in std::iter::once(self.profile.tls()).chain(http3_tls) {
                certificate
                    .check_signature_schemes(&tls.signature_schemes)
                    .map_err(BuildError::client_certificate)?;
            }
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
        if let Some(http1) = self.profile.http1() {
            http1
                .validate()
                .map_err(BuildError::invalid_http1_profile)?;
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
        if let Some(proxy_connect) = self.profile.proxy_connect() {
            proxy_connect
                .validate()
                .map_err(BuildError::invalid_proxy_connect_profile)?;
        }

        let authentication_disabled = !self.server_authentication.verifies();
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

        let proxy_authentication_disabled = !self.proxy_server_authentication.verifies();
        if proxy_authentication_disabled && !self.proxy_additional_roots.is_empty() {
            return Err(BuildError::invalid_policy(
                "disabled proxy server authentication cannot be combined with proxy roots",
            ));
        }

        // One draw for the client, before any connector is built, so that
        // all of its connectors share it.
        phantom_net::draw_per_client(&mut self.profile).map_err(BuildError::per_client_draw)?;
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
                .map(|connector| self.bind_http1(connector))
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
                .map(|connector| self.bind_http2(connector))
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
                .map(|connector| with_udp(connector, self.profile.udp()))
                .map(|connector| self.with_qlog(connector))
                .map(|connector| {
                    let connector = self.bind_http3(connector);
                    match &self.client_certificate {
                        Some(certificate) => connector.with_client_certificate(certificate),
                        None => connector,
                    }
                })
            })
            .transpose()
            .map_err(BuildError::http3)?;
        let http3_session_tickets = self
            .profile
            .http3()
            .is_some_and(|settings| settings.tls().session_tickets);
        // CONNECT-UDP's outer connection authenticates the proxy with proxy
        // trust roots; HTTP/3 cannot disable verification.
        let connect_udp_http3 = self
            .profile
            .http3()
            .filter(|_| !proxy_authentication_disabled)
            .map(|settings| {
                Http3Connector::new_with_additional_roots(
                    settings.tls(),
                    &connect_udp_proxy_quic(settings.quic_transport()),
                    settings.http3(),
                    settings.request(),
                    self.proxy_additional_roots.iter().map(AsRef::as_ref),
                )
                .map(|connector| with_udp(connector, self.profile.udp()))
                .map(|connector| self.with_qlog(connector))
                .map(|connector| self.bind_http3(connector))
            })
            .transpose()
            .map_err(BuildError::http3)?;
        if proxy_authentication_disabled && matches!(self.route, Route::ConnectUdp(_)) {
            return Err(BuildError::invalid_policy(
                "disabled proxy server authentication is not supported for CONNECT-UDP",
            ));
        }
        self.options.validate_transport(
            http1_or_2.is_some(),
            http3.is_some(),
            http3_session_tickets,
        )?;
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
                .map(|connector| match self.profile.proxy_connect() {
                    Some(template) => {
                        connector.with_http2_rejected_connect(template.http2_rejected)
                    }
                    None => connector,
                })
                .map(|connector| with_tcp(connector, tcp, HttpsProxyConnector::with_tcp_settings))
                .map(|connector| self.bind_https_proxy(connector))
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
                .map(|connector| self.bind_http1(connector))
                .map_err(BuildError::http1)
            })
            .transpose()?;

        #[cfg(feature = "diagnostics")]
        let key_log = self.key_log_capacity.map(|capacity| {
            let (sender, receiver) = phantom_net::nss_key_log_channel(capacity);
            // The HTTP/1.1-or-HTTP/2 and CONNECT-UDP TCP connectors share
            // these connectors' TLS contexts.
            http1.iter().for_each(|c| c.attach_key_log(&sender));
            http2.iter().for_each(|c| c.attach_key_log(&sender));
            http3.iter().for_each(|c| c.attach_key_log(&sender));
            https_proxy.iter().for_each(|c| c.attach_key_log(&sender));
            if let Some(connector) = connect_udp_proxy
                .as_ref()
                .and_then(|connectors| connectors.http3.as_ref())
            {
                connector.attach_key_log(&sender);
            }
            #[cfg(feature = "websocket")]
            websocket_http1
                .iter()
                .for_each(|c| c.attach_key_log(&sender));
            Arc::new(crate::KeyLog::new(receiver))
        });

        let host_resolver = self.host_resolver()?;
        let mut inner = ClientInner {
            http1,
            http1_or_2,
            http2,
            http3: http3.map(Arc::new),
            connect_udp_proxy: connect_udp_proxy.map(Arc::new),
            https_proxy,
            forward_https_proxy: None,
            #[cfg(feature = "websocket")]
            websocket_https_proxy: None,
            http2_proxy_connections: self
                .profile
                .proxy_connect()
                .map(|template| template.http2_connections)
                .unwrap_or_default(),
            http2_proxy_connections_per_route: self.http2_proxy_connections_per_route,
            http2_ping_failure_retries: self
                .profile
                .http2()
                .map_or(0, |settings| settings.ping_failure_retries),
            proxy_credentials: None,
            host_resolver: None,
            client_hints,
            http1_connections_per_origin: self
                .profile
                .http1()
                .map_or(NonZeroUsize::MIN, |http1| http1.max_connections_per_origin),
            http1_used_idle_timeout: self
                .profile
                .http1()
                .and_then(|http1| http1.idle_timeout.checked_on_request()),
            http1_idle_timer: self
                .profile
                .http1()
                .and_then(|http1| http1.idle_timeout.closed_on_timer()),
            #[cfg(feature = "cookies")]
            cookie_placement: self.profile.cookie_placement().clone(),
            route: self.route,
            proxy_connect: self.profile.proxy_connect().cloned().map(Arc::new),
            #[cfg(feature = "websocket")]
            websocket: self.profile.websocket().cloned(),
            #[cfg(feature = "websocket")]
            websocket_http1,
            #[cfg(feature = "diagnostics")]
            key_log,
        };
        if self.preemptive_proxy_authentication {
            let cache = ProxyCredentialCache::new();
            inner.bind_proxy_credentials(&cache);
            inner.proxy_credentials = Some(cache);
        }
        if let Some(resolver) = host_resolver {
            inner.bind_host_resolver(resolver);
        }
        inner.bind_http2_proxy_pools();
        Ok(self.options.into_client(Arc::new(inner)))
    }
}

impl ClientBuilder {
    /// Whether the caller asked for a source address or interface.
    fn binds_sources(&self) -> bool {
        self.source_binding != SourceBinding::new()
    }

    /// Applies the source binding and client certificate, when set, to an
    /// HTTP/1.1 origin connector.
    fn bind_http1(&self, mut connector: Http1TlsConnector) -> Http1TlsConnector {
        if self.binds_sources() {
            connector = connector.with_source_binding(self.source_binding.clone());
        }
        match &self.client_certificate {
            Some(certificate) => connector.with_client_certificate(certificate),
            None => connector,
        }
    }

    /// Applies the source binding and client certificate, when set, to an
    /// HTTP/2 origin connector.
    fn bind_http2(&self, mut connector: Http2TlsConnector) -> Http2TlsConnector {
        if self.binds_sources() {
            connector = connector.with_source_binding(self.source_binding.clone());
        }
        match &self.client_certificate {
            Some(certificate) => connector.with_client_certificate(certificate),
            None => connector,
        }
    }

    /// Applies the source binding, when set, to an HTTP/3 connector.
    fn bind_http3(&self, connector: Http3Connector) -> Http3Connector {
        if self.binds_sources() {
            connector.with_source_binding(self.source_binding.clone())
        } else {
            connector
        }
    }

    /// Applies the source binding, when set, to an HTTPS proxy connector.
    fn bind_https_proxy(&self, connector: HttpsProxyConnector) -> HttpsProxyConnector {
        if self.binds_sources() {
            connector.with_source_binding(self.source_binding.clone())
        } else {
            connector
        }
    }

    /// Applies the qlog directory, when one is set, to an HTTP/3 connector.
    fn with_qlog(&self, connector: Http3Connector) -> Http3Connector {
        #[cfg(feature = "diagnostics")]
        if let Some(dir) = &self.qlog_dir {
            return connector.with_qlog_dir(dir.clone());
        }
        connector
    }
}

/// Applies the profile's TCP socket options, when it has any, to a connector.
fn with_tcp<C>(connector: C, tcp: Option<&TcpSettings>, apply: fn(C, &TcpSettings) -> C) -> C {
    match tcp {
        Some(settings) => apply(connector, settings),
        None => connector,
    }
}

/// Applies the profile's UDP socket options, when it has them, to the UDP
/// sockets of an HTTP/3 connector.
fn with_udp(connector: Http3Connector, udp: Option<&UdpSettings>) -> Http3Connector {
    match udp {
        Some(settings) => connector.with_udp_settings(settings),
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

/// QUIC settings for the outer connection to a CONNECT-UDP proxy.
///
/// No capture shows a browser's resumed CONNECT-UDP proxy connection, so the
/// outer connection offers no early data and sends no `initial_rtt_us`,
/// whatever the profile sets. Everything else follows the profile.
fn connect_udp_proxy_quic(settings: &QuicTransportSettings) -> QuicTransportSettings {
    let mut quic = settings.clone();
    quic.early_data = false;
    quic.wire_parameters
        .retain(|parameter| parameter.kind != QuicTransportParameterKind::InitialRtt);
    quic
}

#[cfg(test)]
mod dns_cache_tests;

#[cfg(test)]
mod option_tests;

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use std::time::Duration;

    use phantom_profile::{
        ClientProfile, Http1IdleTimeout, Http3ClientSettings, TcpKeepalive, TcpKeepalivePolicy,
        chromium, firefox,
    };

    use super::{Client, HttpProtocol};
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use crate::BuildError;
    use crate::{BuildErrorKind, HttpProxy, Route};

    #[test]
    fn connect_udp_proxy_connection_omits_resumption_additions() {
        use phantom_profile::quic::QuicTransportParameterKind;

        let recipe = chromium::v154_quic();
        let outer = super::connect_udp_proxy_quic(&recipe);
        assert!(recipe.early_data);
        assert!(!outer.early_data);
        let without_rtt: Vec<_> = recipe
            .wire_parameters
            .iter()
            .filter(|parameter| parameter.kind != QuicTransportParameterKind::InitialRtt)
            .cloned()
            .collect();
        assert_eq!(without_rtt.len() + 1, recipe.wire_parameters.len());
        assert_eq!(outer.wire_parameters, without_rtt);
        assert_eq!(outer.parameter_order, recipe.parameter_order);
    }

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
        let route = Route::http_proxy(HttpProxy::new("https://proxy.example")?);
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
    fn profile_udp_settings_reach_every_http3_connector() -> Result<(), Box<dyn std::error::Error>>
    {
        let udp = chromium::v154_udp();
        let http3 = Http3ClientSettings::new(
            chromium::v154_http3_tls(),
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        );
        let profile = ClientProfile::new(chromium::v154_tls())
            .with_udp(udp)
            .with_http3(http3.clone());
        let route = Route::http_proxy(HttpProxy::new("https://proxy.example")?);
        let client = Client::builder(profile).route(route).build()?;
        let inner = &client.inner;

        let expected = Some(&udp);
        assert_eq!(
            inner.http3.as_ref().and_then(|c| c.udp_settings()),
            expected
        );
        let connect_udp = inner
            .connect_udp_proxy
            .as_ref()
            .ok_or("no CONNECT-UDP connectors")?;
        assert_eq!(
            connect_udp.http3.as_ref().and_then(|c| c.udp_settings()),
            expected
        );

        let without = ClientProfile::new(chromium::v154_tls()).with_http3(http3);
        let client = Client::builder(without).build()?;
        assert_eq!(
            client.inner.http3.as_ref().and_then(|c| c.udp_settings()),
            None
        );
        Ok(())
    }

    #[test]
    fn source_binding_reaches_every_connector() -> Result<(), Box<dyn std::error::Error>> {
        use std::net::{IpAddr, Ipv4Addr};

        let http3 = Http3ClientSettings::new(
            chromium::v154_http3_tls(),
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        );
        let profile = ClientProfile::new(chromium::v154_tls())
            .with_http2(chromium::v154_http2())
            .with_http3(http3);
        #[cfg(feature = "websocket")]
        let profile = profile.with_websocket(chromium::v154_websocket());
        let route = Route::http_proxy(HttpProxy::new("https://proxy.example")?);
        let address = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let client = Client::builder(profile)
            .route(route)
            // A host override rebinds every connector to a host resolver.
            .resolve("example.com", [address])
            .local_address(address)
            .build()?;
        let inner = &client.inner;

        let expected = phantom_net::SourceBinding::new().with_address(address);
        let expected = Some(&expected);
        assert_eq!(
            inner.http1.as_ref().and_then(|c| c.source_binding()),
            expected
        );
        assert_eq!(
            inner.http2.as_ref().and_then(|c| c.source_binding()),
            expected
        );
        assert_eq!(
            inner.http1_or_2.as_ref().and_then(|c| c.source_binding()),
            expected
        );
        assert_eq!(
            inner.http3.as_ref().and_then(|c| c.source_binding()),
            expected
        );
        for proxy in [
            &inner.https_proxy,
            &inner.forward_https_proxy,
            #[cfg(feature = "websocket")]
            &inner.websocket_https_proxy,
        ] {
            assert_eq!(proxy.as_ref().and_then(|c| c.source_binding()), expected);
        }
        let connect_udp = inner
            .connect_udp_proxy
            .as_ref()
            .ok_or("no CONNECT-UDP connectors")?;
        assert_eq!(
            connect_udp.http3.as_ref().and_then(|c| c.source_binding()),
            expected
        );
        assert_eq!(
            connect_udp.tcp.as_ref().and_then(|c| c.source_binding()),
            expected
        );
        #[cfg(feature = "websocket")]
        assert_eq!(
            inner
                .websocket_http1
                .as_ref()
                .and_then(|c| c.source_binding()),
            expected
        );

        let unbound = Client::builder(ClientProfile::new(chromium::v154_tls())).build()?;
        assert_eq!(
            unbound
                .inner
                .http1
                .as_ref()
                .and_then(|c| c.source_binding()),
            None
        );
        Ok(())
    }

    #[test]
    fn invalid_tcp_profile_has_invalid_profile_category() -> Result<(), &'static str> {
        let mut tcp = chromium::v154_tcp();
        tcp.keepalive = TcpKeepalivePolicy::Fixed(TcpKeepalive {
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

    #[test]
    fn a_timer_idle_limit_beyond_firefox_range_is_an_invalid_profile() -> Result<(), &'static str> {
        let mut http1 = firefox::v157_http1();
        http1.idle_timeout = Http1IdleTimeout::ClosedOnTimer(Duration::MAX);
        let profile = ClientProfile::new(firefox::v157_tls()).with_http1(http1);
        let error = Client::builder(profile)
            .build()
            .err()
            .ok_or("an idle limit of Duration::MAX was accepted")?;

        assert_eq!(error.kind(), BuildErrorKind::InvalidProfile);
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn keepalive_without_interval_is_an_invalid_profile_on_windows() -> Result<(), &'static str> {
        let mut tcp = chromium::v154_tcp();
        tcp.keepalive = TcpKeepalivePolicy::Fixed(TcpKeepalive {
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
        tcp.keepalive = TcpKeepalivePolicy::Fixed(TcpKeepalive {
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

    #[cfg(feature = "danger-disable-verification")]
    #[test]
    fn disabled_proxy_authentication_rejects_proxy_roots() -> Result<(), &'static str> {
        let profile = ClientProfile::new(chromium::v154_tls());
        let error = Client::builder(profile)
            .proxy_server_authentication(crate::ServerAuthentication::DangerDisabled)
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
        let route = Route::http_proxy(
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
