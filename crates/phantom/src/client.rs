use std::{fmt, num::NonZeroUsize, sync::Arc};

use http::Method;
use phantom_net::{
    ServerAuthentication, http1::Http1TlsConnector, http1_or_2::Http1Or2TlsConnector,
    http2::Http2TlsConnector, http3::Http3Connector, proxy::HttpsProxyConnector,
};
use phantom_profile::{ClientHintSettings, ClientProfile};

#[cfg(feature = "cookies")]
use crate::CookieJar;
use crate::{
    BuildError, RedirectPolicy, RequestBuilder, RequestTimeouts, RetryPolicy, Route, Session,
    SessionBuilder,
    session::{ClientOptions, ClientState},
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
/// Independently built clients share none of that mutable state.
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
    /// Outer HTTP/3 connector for CONNECT-UDP proxies, using proxy trust.
    pub(crate) connect_udp_proxy: Option<Http3Connector>,
    pub(crate) https_proxy: Option<HttpsProxyConnector>,
    pub(crate) client_hints: Option<ClientHintSettings>,
    pub(crate) route: Route,
}

impl Client {
    /// Starts a client builder for one owned wire profile.
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
    /// # Errors
    ///
    /// Returns [`crate::RequestError`] when the protocol is absent from the
    /// profile or the URI, authority, or request target is invalid.
    pub fn get(
        &self,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<RequestBuilder, crate::RequestError> {
        self.request(protocol, Method::GET, uri)
    }

    /// Starts one request using exactly `protocol`.
    ///
    /// # Errors
    ///
    /// Returns [`crate::RequestError`] when the protocol is absent from the
    /// profile or the URI, authority, or request target is invalid.
    pub fn request(
        &self,
        protocol: HttpProtocol,
        method: Method,
        uri: &str,
    ) -> Result<RequestBuilder, crate::RequestError> {
        RequestBuilder::new_client(self.clone(), protocol, method, uri)
    }

    /// Starts one direct GET that selects HTTP/2, HTTP/1.1, or a learned H3 alternative.
    ///
    /// The client opens at most one current direct TCP/TLS generation per
    /// origin and reuses the ALPN-selected protocol while that generation is
    /// eligible. Exact `h2` selects HTTP/2; exact `http/1.1` or absent ALPN
    /// selects HTTP/1.1.
    /// It does not race. An opt-in [`RetryPolicy`] may retry a direct TCP
    /// connect failure before TLS starts; TLS and ALPN failures are terminal.
    /// When bounded Alt-Svc
    /// learning is enabled, a fresh `h3` advertisement from an earlier
    /// negotiated response selects HTTP/3 without changing the origin identity.
    /// Any non-direct configured or per-request route is rejected before I/O.
    /// [`crate::ResponseInfo::protocol`]
    /// reports the selected protocol. Client cookies and learned client hints
    /// apply. Negotiated generations are isolated from the exact-protocol
    /// pools.
    ///
    /// # Errors
    ///
    /// Returns [`crate::RequestError`] when the profile cannot negotiate H1/H2,
    /// a selected H3 alternative is unavailable, or the URI, authority, or
    /// request target is invalid.
    pub fn get_negotiated(&self, uri: &str) -> Result<RequestBuilder, crate::RequestError> {
        self.request_negotiated(Method::GET, uri)
    }

    /// Starts one direct request that selects HTTP/2, HTTP/1.1, or a learned H3 alternative.
    ///
    /// This has the same pooled-generation selection contract as
    /// [`Self::get_negotiated`]. The request must be representable by both HTTP
    /// versions so validation can finish before network I/O.
    ///
    /// # Errors
    ///
    /// Returns [`crate::RequestError`] when the profile cannot negotiate H1/H2,
    /// a selected H3 alternative is unavailable, or the URI, authority, or
    /// request target is invalid.
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
    #[cfg(feature = "websocket")]
    pub fn websocket(&self, uri: &str) -> Result<WebSocketRequestBuilder, WebSocketError> {
        WebSocketRequestBuilder::new_client(self.clone(), uri)
    }

    /// Starts one ordered WebSocket opening handshake using exactly `protocol`.
    ///
    /// HTTP/2 uses RFC 8441 extended CONNECT and currently supports direct
    /// `wss://` only. It requires an explicit extended-CONNECT pseudo-header
    /// order in the HTTP/2 profile and never falls back to HTTP/1.1.
    #[cfg(feature = "websocket")]
    pub fn websocket_with_protocol(
        &self,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<WebSocketRequestBuilder, WebSocketError> {
        WebSocketRequestBuilder::new_client_with_protocol(self.clone(), protocol, uri)
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
    /// Certificate and hostname verification remain enabled.
    #[must_use]
    pub fn add_root_certificate_der(mut self, certificate: impl Into<Box<[u8]>>) -> Self {
        self.additional_roots.push(certificate.into());
        self
    }

    /// Sets how TLS servers are authenticated.
    ///
    /// The default is [`ServerAuthentication::WebPki`]. Disabling
    /// authentication is explicit and is supported for HTTP/1.1 and HTTP/2;
    /// it cannot be combined with additional roots or HTTP/3.
    #[must_use]
    pub fn server_authentication(mut self, policy: ServerAuthentication) -> Self {
        self.server_authentication = policy;
        self
    }

    /// Adds a DER-encoded certificate to the HTTPS-proxy trust roots.
    ///
    /// Proxy trust is independent from origin trust. Certificate and hostname
    /// verification remain enabled for the proxy. The roots also authenticate
    /// the outer HTTP/3 connection of a [`Route::ConnectUdp`] route.
    #[must_use]
    pub fn add_proxy_root_certificate_der(mut self, certificate: impl Into<Box<[u8]>>) -> Self {
        self.proxy_additional_roots.push(certificate.into());
        self
    }

    /// Sets how an HTTPS proxy authenticates its TLS certificate.
    ///
    /// This policy applies only to the outer proxy connection. Origin TLS uses
    /// [`Self::server_authentication`] and its own trust roots. Disabled proxy
    /// authentication is not supported for [`Route::ConnectUdp`], whose outer
    /// connection is HTTP/3.
    #[must_use]
    pub fn proxy_server_authentication(mut self, policy: ServerAuthentication) -> Self {
        self.proxy_server_authentication = policy;
        self
    }

    /// Sets the default route for requests made by this client.
    #[must_use]
    pub fn route(mut self, route: Route) -> Self {
        self.route = route;
        self
    }

    /// Sets the finite policy for following redirect responses.
    ///
    /// Redirect following is HTTPS-only: while a policy is set, `http://`
    /// requests fail before I/O, and a redirect to a non-`https://` target
    /// fails with [`RequestErrorKind::Redirect`](crate::RequestErrorKind::Redirect).
    #[must_use]
    pub fn redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.options.redirect_policy = policy;
        self
    }

    /// Sets the policy for retrying connection-establishment failures.
    ///
    /// Connection retries are disabled by default and apply only to
    /// connection setup before dispatch: exact-protocol acquisition and
    /// negotiated H1/H2 TCP setup before ALPN selection.
    #[must_use]
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.options.retry_policy = policy;
        self
    }

    /// Sets the default phase and whole-operation limits for ordinary requests.
    ///
    /// Individual [`RequestBuilder`] values may replace this policy. Every
    /// timeout is disabled unless explicitly present in `timeouts`.
    #[must_use]
    pub fn request_timeouts(mut self, timeouts: RequestTimeouts) -> Self {
        self.options.request_timeouts = timeouts;
        self
    }

    /// Sets the maximum number of HTTP/1.1 connections retained for reuse.
    ///
    /// The direct negotiated H1/H2 pool uses the lower of the configured H1
    /// and H2 retention limits so neither maximum is exceeded.
    #[must_use]
    pub fn max_retained_http1_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_retained_http1_connections = maximum;
        self
    }

    /// Sets the number of sequential requests allowed to wait per HTTP/1.1 pool key.
    #[must_use]
    pub fn max_pending_http1_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_pending_http1_requests_per_origin = maximum;
        self
    }

    /// Sets the maximum number of HTTP/2 connections retained for reuse.
    ///
    /// The direct negotiated H1/H2 pool uses the lower of the configured H1
    /// and H2 retention limits so neither maximum is exceeded.
    #[must_use]
    pub fn max_retained_http2_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_retained_http2_connections = maximum;
        self
    }

    /// Sets the local active-request bound for each HTTP/2 pool key.
    #[must_use]
    pub fn max_concurrent_http2_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_concurrent_http2_requests_per_origin = maximum;
        self
    }

    /// Sets the number of requests allowed to wait per HTTP/2 pool key.
    #[must_use]
    pub fn max_pending_http2_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_pending_http2_requests_per_origin = maximum;
        self
    }

    /// Sets the maximum number of HTTP/3 connections retained for reuse.
    #[must_use]
    pub fn max_retained_http3_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_retained_http3_connections = maximum;
        self
    }

    /// Sets the local active-request bound for each HTTP/3 pool key.
    #[must_use]
    pub fn max_concurrent_http3_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_concurrent_http3_requests_per_origin = maximum;
        self
    }

    /// Sets the number of requests allowed to wait per HTTP/3 pool key.
    #[must_use]
    pub fn max_pending_http3_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_pending_http3_requests_per_origin = maximum;
        self
    }

    /// Sets the number of origins that may retain `Accept-CH` state.
    #[must_use]
    pub fn max_client_hint_origins(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_client_hint_origins = maximum;
        self
    }

    /// Enables bounded, in-memory Alt-Svc learning for negotiated HTTPS requests.
    ///
    /// A fresh `h3` alternative is used by a later negotiated request without
    /// changing its origin identity. Alternative setup failure is terminal for
    /// that request and never falls back implicitly to H1 or H2.
    #[must_use]
    pub fn alt_svc(mut self, maximum_origins: NonZeroUsize) -> Self {
        self.options.max_alt_svc_origins = Some(maximum_origins);
        self
    }

    /// Enables a bounded in-memory cookie jar owned by the client.
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookies(mut self) -> Self {
        self.options.cookie_jar = Some(CookieJar::default());
        self
    }

    /// Enables cookie handling with a caller-created jar.
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
    /// Returns [`BuildError`] when the profile is invalid, a trust root cannot
    /// be loaded, a protocol connector cannot represent the profile, or the
    /// profile enables no supported protocol. Use [`BuildError::kind`] for the
    /// stable category.
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
        if let Some(client_hints) = self.profile.client_hints() {
            client_hints
                .validate()
                .map_err(BuildError::invalid_client_hint_profile)?;
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
            })
            .transpose()
            .map_err(BuildError::http3)?;
        // CONNECT-UDP's outer connection authenticates the proxy with proxy
        // trust roots; HTTP/3 cannot disable verification.
        let connect_udp_proxy = self
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
            })
            .transpose()
            .map_err(BuildError::https_proxy)?;
        let client_hints = self.profile.client_hints().cloned();

        if http1.is_none() && http2.is_none() && http3.is_none() {
            return Err(BuildError::no_supported_protocol());
        }

        let inner = Arc::new(ClientInner {
            http1,
            http1_or_2,
            http2,
            http3,
            connect_udp_proxy,
            https_proxy,
            client_hints,
            route: self.route,
        });
        let state = self.options.build(&inner);
        Ok(Client { inner, state })
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use phantom_profile::{ClientProfile, Http3ClientSettings, chromium};

    use super::{Client, HttpProtocol};
    use crate::{BuildErrorKind, HttpProxy, Route, ServerAuthentication};

    #[test]
    fn protocol_trace_names_match_negotiated_tokens() {
        assert_eq!(HttpProtocol::Http1.trace_name(), "http/1.1");
        assert_eq!(HttpProtocol::Http2.trace_name(), "h2");
        assert_eq!(HttpProtocol::Http3.trace_name(), "h3");
    }

    #[test]
    fn invalid_proxy_root_has_trust_store_category() -> Result<(), &'static str> {
        let profile = ClientProfile::new(chromium::v152_tls());
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
        let profile = ClientProfile::new(chromium::v152_tls());
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
        let mut tls = chromium::v152_tls();
        tls.alpn_protocols = vec![Box::from(&b"h2"[..])];
        let profile = ClientProfile::new(tls).with_http2(chromium::v152_http2());
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
            ClientProfile::new(chromium::v152_tls()).with_http2(chromium::v152_http2());
        let error = Client::builder(without_http3)
            .alt_svc(capacity)
            .build()
            .err()
            .ok_or("Alt-Svc was accepted without HTTP/3")?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);

        let http3 = Http3ClientSettings::new(
            chromium::v152_http3_tls(),
            chromium::v152_quic(),
            chromium::v152_http3(),
            chromium::v152_http3_request(),
        );
        let without_negotiation = ClientProfile::new(chromium::v152_http3_tls()).with_http3(http3);
        let error = Client::builder(without_negotiation)
            .alt_svc(capacity)
            .build()
            .err()
            .ok_or("Alt-Svc was accepted without negotiated HTTP/1.1 and HTTP/2")?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
        Ok(())
    }
}
