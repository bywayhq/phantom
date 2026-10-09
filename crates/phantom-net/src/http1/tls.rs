//! HTTP/1.1 connections and one-shot requests over TLS or a forward proxy.

use std::{
    future::Future,
    pin::{Pin, pin},
};

use bytes::Bytes;
use http::{Method, Response};
use phantom_profile::{TcpSettings, TlsSettings};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, Span, debug, debug_span, field};

use super::{
    Http1Body, Http1Connection, Http1Error, Http1UpgradeOutcome, OperationOutcome, PreparedGet,
    PreparedRequest, RequestHeader, connection::early_data_error, send_prepared_upgrade,
};
use crate::{
    connection_leg::{self, ConnectionLegError},
    direct::{Dialer, DirectConnectError, connect_tcp, connect_tcp_keeping_slower},
    host_resolver::HostResolver,
    proxy::ProxyCredentialCache,
    route::{
        DirectTlsSetup, Http1Route, Http1Target, OriginRoute, ProxyTransport, Socks5Target,
        TcpRoute,
    },
    source_binding::SourceBinding,
    tcp::{SlowerAttempt, SlowerConnection, SlowerKeepalive, TcpKeepaliveSource},
    tls::{ClientCertificate, ServerAuthentication, TlsConnector, TlsStream, trace_alpn},
};

pub use crate::tls::{EchFailure, TlsError, TlsErrorKind};
pub use error::Http1TlsError;

/// A reusable connector for profiled HTTP/1.1 TLS and proxy-forwarded requests.
#[derive(Clone, Debug)]
pub struct Http1TlsConnector {
    tls: TlsConnector,
    tcp: Option<TcpSettings>,
    source: Option<SourceBinding>,
    host_resolver: Option<HostResolver>,
    proxy_credentials: Option<ProxyCredentialCache>,
}

impl Http1TlsConnector {
    /// Builds a connector from validated TLS settings and bundled public roots.
    pub fn new(settings: &TlsSettings) -> Result<Self, Http1TlsError> {
        require_http1_alpn(settings)?;
        TlsConnector::new(settings)
            .map(|tls| Self {
                tls,
                tcp: None,
                source: None,
                host_resolver: None,
                proxy_credentials: None,
            })
            .map_err(Into::into)
    }

    /// Builds a connector with bundled public roots and additional DER certificates.
    ///
    /// Additional roots extend verification for private authorities; they do
    /// not disable certificate or hostname verification.
    pub fn new_with_additional_roots<'a>(
        settings: &TlsSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, Http1TlsError> {
        require_http1_alpn(settings)?;
        TlsConnector::new_with_additional_roots(settings, roots)
            .map(|tls| Self {
                tls,
                tcp: None,
                source: None,
                host_resolver: None,
                proxy_credentials: None,
            })
            .map_err(Into::into)
    }

    /// Builds a connector with an explicit server-authentication policy.
    ///
    /// A policy that does not verify the server, which the
    /// `danger-disable-verification` feature provides, accepts any server
    /// certificate but continues to send Server Name Indication.
    pub fn new_with_server_authentication(
        settings: &TlsSettings,
        server_authentication: ServerAuthentication,
    ) -> Result<Self, Http1TlsError> {
        require_http1_alpn(settings)?;
        TlsConnector::new_with_server_authentication(settings, server_authentication)
            .map(|tls| Self {
                tls,
                tcp: None,
                source: None,
                host_resolver: None,
                proxy_credentials: None,
            })
            .map_err(Into::into)
    }

    #[cfg(test)]
    fn new_with_roots<'a>(
        settings: &TlsSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, Http1TlsError> {
        require_http1_alpn(settings)?;
        TlsConnector::new_with_roots(settings, roots)
            .map(|tls| Self {
                tls,
                tcp: None,
                source: None,
                host_resolver: None,
                proxy_credentials: None,
            })
            .map_err(Into::into)
    }

    /// Returns a connector clone with a fresh isolated TLS session cache.
    ///
    /// Clones of the returned connector share that cache. Separate calls create
    /// separate caches, and cached sessions remain bound to their TLS hostname.
    #[must_use]
    pub fn with_isolated_session_cache(&self) -> Self {
        Self {
            tls: self.tls.with_isolated_session_cache(),
            tcp: self.tcp,
            source: self.source.clone(),
            host_resolver: self.host_resolver.clone(),
            proxy_credentials: self.proxy_credentials.clone(),
        }
    }

    /// Returns a clone, sharing this connector's TLS context and session
    /// cache, that offers `protocols` by ALPN.
    ///
    /// The ALPS offer is kept only while its protocol stays in `protocols`,
    /// as [`WebSocketConnectionPolicy::http1_tls_settings`] derives it, so a
    /// connection from the clone sends the ClientHello of a connector built
    /// from those settings. It can resume the TLS sessions this connector's
    /// connections were issued, as Chrome 154 keys its session cache without
    /// ALPN.
    ///
    /// [`WebSocketConnectionPolicy::http1_tls_settings`]: phantom_profile::WebSocketConnectionPolicy::http1_tls_settings
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError::MissingHttp1Alpn`] when `protocols` lacks
    /// `http/1.1`, and [`Http1TlsError::Tls`] when the list cannot be encoded.
    pub fn with_alpn_protocols(&self, protocols: &[Box<[u8]>]) -> Result<Self, Http1TlsError> {
        if !protocols
            .iter()
            .any(|protocol| protocol.as_ref() == b"http/1.1")
        {
            return Err(Http1TlsError::MissingHttp1Alpn);
        }
        Ok(Self {
            tls: self.tls.with_alpn_protocols(protocols)?,
            tcp: self.tcp,
            source: self.source.clone(),
            host_resolver: self.host_resolver.clone(),
            proxy_credentials: self.proxy_credentials.clone(),
        })
    }

    /// An HTTP/1.1 connector over `tls`, which must offer `http/1.1`, with
    /// the connection settings of another connector.
    pub(crate) fn from_parts(
        tls: TlsConnector,
        tcp: Option<TcpSettings>,
        source: Option<SourceBinding>,
        host_resolver: Option<HostResolver>,
        proxy_credentials: Option<ProxyCredentialCache>,
    ) -> Self {
        Self {
            tls,
            tcp,
            source,
            host_resolver,
            proxy_credentials,
        }
    }

    /// Applies TCP socket options to every TCP connection this connector opens.
    ///
    /// The options cover direct origin connections and connections to HTTP
    /// and SOCKS5 proxies. An HTTPS proxy connection uses the options of the
    /// [`HttpsProxyConnector`] passed with it.
    /// The settings are checked before any DNS or socket I/O. Invalid
    /// settings fail each connection attempt with
    /// [`std::io::ErrorKind::InvalidInput`], and settings this host cannot
    /// apply exactly (see [`crate::tcp::check_host_support`]) with
    /// [`std::io::ErrorKind::Unsupported`].
    #[must_use]
    pub fn with_tcp_settings(mut self, settings: &TcpSettings) -> Self {
        self.tcp = Some(*settings);
        self
    }

    /// Sends Basic credentials on the first CONNECT to a plaintext proxy
    /// that accepted them before, as recorded in `cache`.
    ///
    /// Without a cache, every challenge-driven exchange starts without
    /// credentials. An HTTPS proxy uses the cache of the
    /// [`HttpsProxyConnector`] passed with it. Clones of this connector share
    /// `cache`.
    #[must_use]
    pub fn with_proxy_credential_cache(mut self, cache: ProxyCredentialCache) -> Self {
        self.proxy_credentials = Some(cache);
        self
    }

    /// Returns the TCP socket options applied to new connections, if any.
    #[must_use]
    pub fn tcp_settings(&self) -> Option<&TcpSettings> {
        self.tcp.as_ref()
    }

    /// Binds every TCP socket this connector opens as `binding` says.
    ///
    /// The binding covers direct origin connections and connections to HTTP
    /// and SOCKS5 proxies. An HTTPS proxy connection uses the binding of the
    /// [`HttpsProxyConnector`] passed with it. An invalid binding fails each
    /// connection attempt with [`std::io::ErrorKind::InvalidInput`] before
    /// any DNS or socket I/O; see [`SourceBinding::validate`].
    #[must_use]
    pub fn with_source_binding(mut self, binding: SourceBinding) -> Self {
        self.source = Some(binding);
        self
    }

    /// Returns the source binding applied to new connections, if any.
    #[must_use]
    pub fn source_binding(&self) -> Option<&SourceBinding> {
        self.source.as_ref()
    }

    /// Presents `certificate` on every TLS connection to an origin whose
    /// server requests client authentication.
    ///
    /// The ClientHello does not change. A proxy connection never presents
    /// it. The connector gets an empty TLS session cache of its own, so a
    /// session authenticated with the certificate is resumed only by
    /// connectors that present it.
    #[must_use]
    pub fn with_client_certificate(mut self, certificate: &ClientCertificate) -> Self {
        self.tls = self.tls.with_client_certificate(certificate);
        self
    }

    /// Resolves host names through `resolver` instead of asking the operating
    /// system for every connection.
    ///
    /// The resolver covers direct origin hosts, HTTP and SOCKS5 proxy hosts,
    /// and the target of a local-DNS SOCKS5 route. An HTTPS proxy host is
    /// resolved through the [`HttpsProxyConnector`] passed with it. A target
    /// that a proxy resolves is never looked up locally. Clones of this
    /// connector share `resolver`.
    #[must_use]
    pub fn with_host_resolver(mut self, resolver: HostResolver) -> Self {
        self.host_resolver = Some(resolver);
        self
    }

    /// Returns the host resolver new connections resolve through, if any.
    #[must_use]
    pub fn host_resolver(&self) -> Option<&HostResolver> {
        self.host_resolver.as_ref()
    }

    fn dialer(&self) -> Dialer<'_> {
        Dialer {
            tcp: self.tcp,
            udp: None,
            source: self.source.as_ref(),
            resolver: self.host_resolver.as_ref(),
        }
    }

    /// Returns whether the TLS settings offer Encrypted Client Hello from
    /// HTTPS records on direct connections
    /// ([`TlsSettings::ech_from_https_records`]).
    #[must_use]
    pub fn ech_from_https_records(&self) -> bool {
        self.tls.ech_from_https_records()
    }

    /// Returns the ALPN protocols the TLS settings offer, in order.
    #[must_use]
    pub fn alpn_protocols(&self) -> Vec<Box<[u8]>> {
        self.tls.alpn_protocols()
    }

    /// Queues the TLS secrets of this connector's connections to `sender`.
    ///
    /// Clones share the TLS context and its key log. The first sender
    /// attached is kept.
    #[cfg(feature = "keylog")]
    pub fn attach_key_log(&self, sender: &crate::NssKeyLogSender) {
        self.tls.key_log().attach(sender);
    }

    /// Opens one HTTP/1.1 connection over the selected origin or proxy transport.
    ///
    /// Direct TLS openings offer early data. Tunnels and caller-owned streams
    /// use ordinary TLS. A direct route can retain its slower address attempt.
    ///
    /// # Errors
    ///
    /// Returns an input, route, TLS, ALPN, or HTTP/1.1 setup error.
    pub async fn connect(
        &self,
        route: Http1Route<'_>,
    ) -> Result<(Http1Connection, Option<SlowerConnection<Http1Connection>>), Http1TlsError> {
        let span = connection_span(&route);
        let server_name = match &route {
            Http1Route::Origin(OriginRoute::Tls { server_name, .. }) => Some(*server_name),
            _ => None,
        };
        let mut slower = None;
        let connection = self
            .trace_connect(
                span,
                pin!(async {
                    validate_route(&route, true)?;
                    self.open_connection(route, true, &mut slower).await
                }),
            )
            .await?;
        let slower = slower.map(|attempt| match server_name {
            Some(server_name) => self.slower_tls(attempt, server_name),
            None => slower_plaintext(attempt),
        });
        Ok((connection, slower))
    }

    /// Sends one request over an explicit origin or forwarding route.
    ///
    /// Origin routes require an origin-form target. Forwarding requires an
    /// absolute-form target. Every TLS handshake is ordinary TLS. Request and
    /// route validation finish before lookup polling or connection I/O.
    ///
    /// # Errors
    ///
    /// Returns an input, request, route, TLS, ALPN, or HTTP/1.1 error.
    pub async fn send(
        &self,
        route: Http1Route<'_>,
        method: Method,
        target: Http1Target,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(
            &trace_method,
            body_bytes,
            pin!(async {
                validate_route(&route, false)?;
                let prepared = match (&route, target) {
                    (Http1Route::Origin(_), Http1Target::Origin(target)) => {
                        PreparedRequest::new(method, target, headers, body)?
                    }
                    (Http1Route::Forward(_), Http1Target::Absolute(target)) => {
                        PreparedRequest::new_forward(method, target, headers, body)?
                    }
                    _ => return Err(invalid_route("request target does not match its route")),
                };
                let connection = if matches!(route, Http1Route::Forward(_)) {
                    self.connect(route).await?.0
                } else {
                    self.open_connection(route, false, &mut None).await?
                };
                self.send_prepared_request(&connection, prepared).await
            }),
        )
        .await
    }

    /// Opens one Upgrade GET over an explicit origin or forwarding route.
    ///
    /// Origin routes require an origin-form target. Forwarding requires an
    /// absolute-form target. Direct TLS openings offer early data. Retaining
    /// a slower connection is rejected before lookup polling or I/O.
    ///
    /// # Errors
    ///
    /// Returns an input, request, route, TLS, ALPN, or HTTP/1.1 exchange error.
    pub async fn upgrade(
        &self,
        route: Http1Route<'_>,
        target: Http1Target,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        let span = upgrade_span(&route);
        self.trace_upgrade(
            span,
            pin!(async {
                validate_route(&route, false)?;
                let prepared = match (&route, target) {
                    (Http1Route::Origin(_), Http1Target::Origin(target)) => {
                        PreparedGet::new(target, headers)?
                    }
                    (Http1Route::Forward(_), Http1Target::Absolute(target)) => {
                        PreparedGet::new_forward(target, headers)?
                    }
                    _ => return Err(invalid_route("Upgrade target does not match its route")),
                };
                match route {
                    Http1Route::Forward(ProxyTransport::Tcp(endpoint)) => {
                        let stream = connect_tcp(endpoint.host, endpoint.port, self.dialer())
                            .await
                            .map_err(forward_connect_error)?;
                        send_plaintext_tunnel_upgrade(stream, prepared).await
                    }
                    Http1Route::Forward(ProxyTransport::Tls {
                        endpoint,
                        server_name,
                        connector,
                    }) => {
                        let stream = connector
                            .connect_forward(endpoint.host, endpoint.port, server_name)
                            .await?;
                        send_plaintext_tunnel_upgrade(stream, prepared).await
                    }
                    Http1Route::Origin(OriginRoute::Plaintext { tcp, .. }) => {
                        let stream = connection_leg::connect(
                            tcp,
                            self.dialer(),
                            self.proxy_credentials.as_ref(),
                        )
                        .await?;
                        send_plaintext_tunnel_upgrade(stream, prepared).await
                    }
                    Http1Route::Origin(OriginRoute::Tls {
                        tcp,
                        server_name,
                        setup,
                    }) => match (tcp, setup) {
                        #[cfg(feature = "https-records")]
                        (TcpRoute::Direct(endpoint), DirectTlsSetup::Ech(ech)) => {
                            let stream = crate::direct::connect_tls_with_ech(
                                &self.tls,
                                self.dialer(),
                                endpoint.host,
                                endpoint.port,
                                server_name,
                                ech,
                                true,
                            )
                            .await?;
                            upgrade_over_tls(stream, prepared).await
                        }
                        (tcp, DirectTlsSetup::Default) => {
                            let direct = matches!(tcp, TcpRoute::Direct(_));
                            let stream = connection_leg::connect(
                                tcp,
                                self.dialer(),
                                self.proxy_credentials.as_ref(),
                            )
                            .await?;
                            let stream = if direct {
                                self.tls
                                    .connect_offering_early_data(server_name, stream)
                                    .await?
                            } else {
                                self.tls.connect(server_name, stream).await?
                            };
                            upgrade_over_tls(stream, prepared).await
                        }
                        _ => Err(invalid_route("Upgrade cannot retain a slower connection")),
                    },
                }
            }),
        )
        .await
    }

    /// Opens the transport and finishes protocol setup within the caller's span.
    async fn open_connection(
        &self,
        route: Http1Route<'_>,
        offer_early_data: bool,
        slower: &mut Option<SlowerAttempt>,
    ) -> Result<Http1Connection, Http1TlsError> {
        match route {
            Http1Route::Forward(ProxyTransport::Tcp(endpoint)) => {
                let stream = connect_tcp(endpoint.host, endpoint.port, self.dialer())
                    .await
                    .map_err(forward_connect_error)?;
                connect_plaintext(stream).await.map_err(Into::into)
            }
            Http1Route::Forward(ProxyTransport::Tls {
                endpoint,
                server_name,
                connector,
            }) => {
                let stream = connector
                    .connect_forward(endpoint.host, endpoint.port, server_name)
                    .await?;
                connect_plaintext(stream).await.map_err(Into::into)
            }
            Http1Route::Origin(OriginRoute::Plaintext {
                tcp: TcpRoute::Direct(endpoint),
                family,
            }) => {
                let (stream, attempt) =
                    connect_tcp_keeping_slower(endpoint.host, endpoint.port, self.dialer(), family)
                        .await
                        .map_err(Http1TlsError::from_direct)?;
                *slower = attempt;
                connect_plaintext(stream).await.map_err(Into::into)
            }
            Http1Route::Origin(OriginRoute::Plaintext { tcp, .. }) => {
                let stream =
                    connection_leg::connect(tcp, self.dialer(), self.proxy_credentials.as_ref())
                        .await?;
                connect_plaintext(stream).await.map_err(Into::into)
            }
            Http1Route::Origin(OriginRoute::Tls {
                tcp,
                server_name,
                setup,
            }) => match (tcp, setup) {
                (TcpRoute::Direct(endpoint), DirectTlsSetup::KeepSlower(family)) => {
                    let (stream, attempt) = connect_tcp_keeping_slower(
                        endpoint.host,
                        endpoint.port,
                        self.dialer(),
                        Some(family),
                    )
                    .await
                    .map_err(Http1TlsError::from_direct)?;
                    *slower = attempt;
                    let handshake = async {
                        let stream = self
                            .tls
                            .connect_offering_early_data(server_name, stream)
                            .await?;
                        connect_over_tls(stream).await
                    };
                    match slower.as_mut() {
                        Some(attempt) => attempt.alongside(handshake).await,
                        None => handshake.await,
                    }
                }
                #[cfg(feature = "https-records")]
                (TcpRoute::Direct(endpoint), DirectTlsSetup::Ech(ech)) => {
                    let stream = crate::direct::connect_tls_with_ech(
                        &self.tls,
                        self.dialer(),
                        endpoint.host,
                        endpoint.port,
                        server_name,
                        ech,
                        offer_early_data,
                    )
                    .await?;
                    connect_over_tls(stream).await
                }
                (tcp, DirectTlsSetup::Default) => {
                    let direct = matches!(tcp, TcpRoute::Direct(_));
                    let stream = connection_leg::connect(
                        tcp,
                        self.dialer(),
                        self.proxy_credentials.as_ref(),
                    )
                    .await?;
                    let stream = if direct && offer_early_data {
                        self.tls
                            .connect_offering_early_data(server_name, stream)
                            .await?
                    } else {
                        self.tls.connect(server_name, stream).await?
                    };
                    connect_over_tls(stream).await
                }
                _ => Err(invalid_route("direct TLS setup requires a direct route")),
            },
        }
    }

    /// Finishes the TLS handshake of a slower attempt's connection.
    ///
    /// The handshake is the one a request's connection makes, early data
    /// offered as the cached session allows, as Firefox sets
    /// `SSL_ENABLE_0RTT_DATA` for every socket from one process default
    /// (`security/manager/ssl/nsNSSComponent.cpp:866-867` at tag
    /// `FIREFOX_157_0_RELEASE`). No request is written, so no early data is
    /// sent, as Firefox's null transaction declines it
    /// (`netwerk/protocol/http/nsAHttpTransaction.h:215-217`,
    /// `netwerk/protocol/http/TlsHandshaker.cpp:305-320`).
    pub(crate) fn slower_tls(
        &self,
        attempt: SlowerAttempt,
        server_name: &str,
    ) -> SlowerConnection<Http1Connection> {
        let tls = self.tls.clone();
        let server_name = server_name.to_owned();
        SlowerConnection::new(attempt.progress(), async move {
            let stream = attempt
                .connect()
                .await
                .ok()?
                .into_stream(SlowerKeepalive::BeforeTls);
            let stream = tls
                .connect_offering_early_data(&server_name, stream)
                .await
                .inspect_err(|error| debug!(error = %error, "slower connection handshake failed"))
                .ok()?;
            let connection = connect_over_tls(stream).await.ok()?;
            connection.early_data_answered().await;
            if !connection.is_reusable() {
                return None;
            }
            connection.report_idle();
            Some(connection)
        })
    }

    /// Runs `operation` in the connection span and records its outcome.
    ///
    /// The caller pins `operation` in its own future: an async function holds
    /// a future it takes by value twice, as the argument and as the awaited
    /// value, and these wrappers enclose whole connection setups.
    ///
    /// A cancelled operation is dropped by its caller after this wrapper's
    /// future, so outside the span and after the span records cancellation.
    async fn trace_connect<F>(
        &self,
        span: Span,
        operation: Pin<&mut F>,
    ) -> Result<Http1Connection, Http1TlsError>
    where
        F: Future<Output = Result<Http1Connection, Http1TlsError>>,
    {
        let outcome_guard = OperationOutcome::new(&span);
        let result = operation.instrument(span.clone()).await;
        outcome_guard.finish(connection_outcome(&result));
        result
    }

    async fn send_prepared_request(
        &self,
        connection: &Http1Connection,
        prepared: PreparedRequest,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        debug!("HTTP/1 request prepared");
        let response = connection.send_prepared_request(prepared).await?;
        Span::current().record("status", response.status().as_u16());
        Ok(response)
    }

    /// Takes `operation` pinned, for the reason [`Self::trace_connect`] gives,
    /// and drops a cancelled one in the same order.
    async fn trace_response_head<F>(
        &self,
        method: &Method,
        body_bytes: usize,
        operation: Pin<&mut F>,
    ) -> Result<Response<Http1Body>, Http1TlsError>
    where
        F: Future<Output = Result<Response<Http1Body>, Http1TlsError>>,
    {
        let span = debug_span!(
            "http1.tls.response_head",
            method = %method,
            body_bytes,
            transport = "tls",
            negotiated_alpn = field::Empty,
            status = field::Empty,
            outcome = field::Empty,
        );
        let outcome_guard = OperationOutcome::new(&span);
        let result = operation.instrument(span.clone()).await;
        let outcome = match &result {
            Ok(_) => "ok",
            Err(Http1TlsError::RuntimeUnavailable) => "runtime_unavailable",
            Err(Http1TlsError::Connect(_)) => "connect_error",
            Err(
                Http1TlsError::ForwardProxyConnect(_)
                | Http1TlsError::Proxy(_)
                | Http1TlsError::Socks5Proxy(_),
            ) => "proxy_error",
            Err(Http1TlsError::Tls(_)) => "tls_error",
            Err(Http1TlsError::Http1(
                Http1Error::Protocol(_)
                | Http1Error::ReusedConnectionClosed(_)
                | Http1Error::ConnectionClosed,
            )) => "http_protocol_error",
            Err(Http1TlsError::Http1(
                Http1Error::AmbiguousResponseFraming
                | Http1Error::UnexpectedUpgrade
                | Http1Error::TooManyResponseHeaders { .. }
                | Http1Error::ResponseHeadTooLarge { .. }
                | Http1Error::ChunkSizeLineTooLarge { .. },
            )) => "invalid_response",
            Err(Http1TlsError::Http1(Http1Error::MissingResponseHeaderOrder)) => {
                "http_protocol_error"
            }
            Err(Http1TlsError::Http1(_)) => "http_preparation_error",
            Err(Http1TlsError::UnsupportedAlpn { .. }) => "unsupported_alpn",
            Err(Http1TlsError::MissingHttp1Alpn) => "invalid_configuration",
        };
        outcome_guard.finish(outcome);
        result
    }

    /// Takes `operation` pinned, for the reason [`Self::trace_connect`] gives,
    /// and drops a cancelled one in the same order.
    async fn trace_upgrade<F>(
        &self,
        span: Span,
        operation: Pin<&mut F>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError>
    where
        F: Future<Output = Result<Http1UpgradeOutcome, Http1TlsError>>,
    {
        let outcome_guard = OperationOutcome::new(&span);
        let result = operation.instrument(span.clone()).await;
        outcome_guard.finish(upgrade_outcome(&result));
        result
    }
}

fn invalid_route(message: &'static str) -> Http1TlsError {
    Http1TlsError::Connect(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

fn validate_route(route: &Http1Route<'_>, slower: bool) -> Result<(), Http1TlsError> {
    if let Http1Route::Origin(origin) = route {
        origin
            .validate(true, slower)
            .map_err(Http1TlsError::Connect)?;
    }
    Ok(())
}

fn forward_connect_error(error: DirectConnectError) -> Http1TlsError {
    match error {
        DirectConnectError::RuntimeUnavailable => Http1TlsError::RuntimeUnavailable,
        DirectConnectError::Connect(error) => Http1TlsError::ForwardProxyConnect(error),
    }
}

fn plaintext_route(tcp: &TcpRoute<'_>) -> &'static str {
    match tcp {
        TcpRoute::Socks5 {
            target: Socks5Target::LocalDns(_),
            ..
        } => "socks5_local_dns",
        TcpRoute::Socks5 { .. } => "socks5_remote_dns",
        TcpRoute::HttpConnect(route) => match route.proxy {
            ProxyTransport::Tcp(_) => "http_connect",
            ProxyTransport::Tls { .. } => "https_connect",
        },
        _ => "direct",
    }
}

fn connection_span(route: &Http1Route<'_>) -> Span {
    match route {
        Http1Route::Origin(OriginRoute::Tls { .. }) => debug_span!(
            "http1.tls.connect",
            transport = "tls",
            negotiated_alpn = field::Empty,
            outcome = field::Empty,
        ),
        Http1Route::Origin(OriginRoute::Plaintext { tcp, .. }) => {
            let route = plaintext_route(tcp);
            if route == "direct" {
                debug_span!(
                    "http1.direct.connect",
                    transport = "tcp",
                    route,
                    outcome = field::Empty
                )
            } else {
                debug_span!(
                    "http1.proxy.connect",
                    transport = "tcp",
                    proxy_kind = route,
                    outcome = field::Empty
                )
            }
        }
        Http1Route::Forward(proxy) => {
            let transport = match proxy {
                ProxyTransport::Tcp(_) => "tcp",
                _ => "tls",
            };
            debug_span!(
                "http1.proxy.connect",
                transport,
                proxy_kind = "forward",
                outcome = field::Empty
            )
        }
    }
}

fn upgrade_span(route: &Http1Route<'_>) -> Span {
    match route {
        Http1Route::Origin(OriginRoute::Tls { .. }) => debug_span!(
            "http1.tls.upgrade_response_head",
            method = "GET",
            transport = "tls",
            negotiated_alpn = field::Empty,
            status = field::Empty,
            outcome = field::Empty,
        ),
        Http1Route::Forward(proxy) => {
            let transport = match proxy {
                ProxyTransport::Tcp(_) => "tcp",
                _ => "tls",
            };
            debug_span!(
                "http1.proxy.forward.upgrade_response_head",
                method = "GET",
                transport,
                route = "forward_proxy",
                status = field::Empty,
                outcome = field::Empty
            )
        }
        Http1Route::Origin(OriginRoute::Plaintext { tcp, .. }) => {
            let route = plaintext_route(tcp);
            match tcp {
                TcpRoute::Socks5 { .. } => debug_span!(
                    "http1.proxy.socks5.upgrade_response_head",
                    method = "GET",
                    transport = "tcp",
                    route,
                    status = field::Empty,
                    outcome = field::Empty
                ),
                TcpRoute::HttpConnect(_) => debug_span!(
                    "http1.proxy.connect.upgrade_response_head",
                    method = "GET",
                    transport = "tcp",
                    route,
                    status = field::Empty,
                    outcome = field::Empty
                ),
                _ => debug_span!(
                    "http1.direct.upgrade_response_head",
                    method = "GET",
                    transport = "tcp",
                    route,
                    status = field::Empty,
                    outcome = field::Empty
                ),
            }
        }
    }
}

/// Sends a prepared plaintext Upgrade on an established connection and
/// records the response status on the current span.
async fn send_plaintext_tunnel_upgrade<S>(
    stream: S,
    prepared: PreparedGet,
) -> Result<Http1UpgradeOutcome, Http1TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + TcpKeepaliveSource + 'static,
{
    debug!("HTTP/1 plaintext Upgrade request prepared");
    let outcome = send_profiled_upgrade(stream, prepared).await?;
    let status = match &outcome {
        Http1UpgradeOutcome::Upgraded(response) => response.status(),
        Http1UpgradeOutcome::Rejected(response) => response.status(),
    };
    Span::current().record("status", status.as_u16());
    Ok(outcome)
}

fn upgrade_outcome(result: &Result<Http1UpgradeOutcome, Http1TlsError>) -> &'static str {
    match result {
        Ok(Http1UpgradeOutcome::Upgraded(_)) => "upgraded",
        Ok(Http1UpgradeOutcome::Rejected(_)) => "rejected",
        Err(Http1TlsError::RuntimeUnavailable) => "runtime_unavailable",
        Err(Http1TlsError::Connect(_)) => "connect_error",
        Err(
            Http1TlsError::ForwardProxyConnect(_)
            | Http1TlsError::Proxy(_)
            | Http1TlsError::Socks5Proxy(_),
        ) => "proxy_error",
        Err(Http1TlsError::Tls(_)) => "tls_error",
        Err(Http1TlsError::Http1(
            Http1Error::Protocol(_)
            | Http1Error::ReusedConnectionClosed(_)
            | Http1Error::ConnectionClosed,
        )) => "http_protocol_error",
        Err(Http1TlsError::Http1(
            Http1Error::AmbiguousResponseFraming
            | Http1Error::UnexpectedUpgrade
            | Http1Error::TooManyResponseHeaders { .. }
            | Http1Error::ResponseHeadTooLarge { .. }
            | Http1Error::ChunkSizeLineTooLarge { .. },
        )) => "invalid_response",
        Err(Http1TlsError::Http1(Http1Error::MissingResponseHeaderOrder)) => "http_protocol_error",
        Err(Http1TlsError::Http1(_)) => "http_preparation_error",
        Err(Http1TlsError::UnsupportedAlpn { .. }) => "unsupported_alpn",
        Err(Http1TlsError::MissingHttp1Alpn) => "invalid_configuration",
    }
}

fn connection_outcome<T>(result: &Result<T, Http1TlsError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(Http1TlsError::RuntimeUnavailable) => "runtime_unavailable",
        Err(Http1TlsError::Connect(_)) => "connect_error",
        Err(
            Http1TlsError::ForwardProxyConnect(_)
            | Http1TlsError::Proxy(_)
            | Http1TlsError::Socks5Proxy(_),
        ) => "proxy_error",
        Err(Http1TlsError::Tls(_)) => "tls_error",
        Err(Http1TlsError::Http1(_)) => "http_protocol_error",
        Err(Http1TlsError::UnsupportedAlpn { .. }) => "unsupported_alpn",
        Err(Http1TlsError::MissingHttp1Alpn) => "invalid_configuration",
    }
}

impl From<ConnectionLegError> for Http1TlsError {
    fn from(error: ConnectionLegError) -> Self {
        match error {
            ConnectionLegError::Direct(DirectConnectError::RuntimeUnavailable) => {
                Self::RuntimeUnavailable
            }
            ConnectionLegError::Direct(DirectConnectError::Connect(error)) => Self::Connect(error),
            ConnectionLegError::HttpProxy(error) => Self::Proxy(error),
            ConnectionLegError::Socks5(error) => Self::Socks5Proxy(error),
        }
    }
}

impl Http1TlsError {
    fn from_direct(error: DirectConnectError) -> Self {
        match error {
            DirectConnectError::RuntimeUnavailable => Self::RuntimeUnavailable,
            DirectConnectError::Connect(error) => Self::Connect(error),
        }
    }
}

/// Starts HTTP/1.1 over an established TLS stream on a profile connection.
async fn connect_over_tls<S>(stream: TlsStream<S>) -> Result<Http1Connection, Http1TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + TcpKeepaliveSource + 'static,
{
    require_http1_selected(&stream)?;
    let keepalive = stream.tcp_keepalive();
    let early_data = stream.early_data_wait();
    Http1Connection::connect_with_early_data(stream, early_data, keepalive)
        .await
        .map_err(Into::into)
}

/// Starts plaintext HTTP/1.1 on a slower attempt's connection once it
/// connects, with no keepalive until its first request.
pub(crate) fn slower_plaintext(attempt: SlowerAttempt) -> SlowerConnection<Http1Connection> {
    SlowerConnection::new(attempt.progress(), async move {
        let stream = attempt
            .connect()
            .await
            .ok()?
            .into_stream(SlowerKeepalive::OnFirstRequest);
        connect_plaintext(stream).await.ok()
    })
}

/// Starts plaintext HTTP/1.1 on a profile connection.
async fn connect_plaintext<S>(stream: S) -> Result<Http1Connection, Http1Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + TcpKeepaliveSource + 'static,
{
    let keepalive = stream.tcp_keepalive();
    Http1Connection::connect_with_early_data(stream, None, keepalive).await
}

/// Sends a prepared Upgrade GET on a profile connection, which switches its
/// keepalive schedule when the server switches protocols.
async fn send_profiled_upgrade<S>(
    stream: S,
    prepared: PreparedGet,
) -> Result<Http1UpgradeOutcome, Http1Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + TcpKeepaliveSource + 'static,
{
    let keepalive = stream.tcp_keepalive();
    send_prepared_upgrade(stream, prepared, keepalive).await
}

/// Sends a prepared Upgrade GET over an established TLS stream.
///
/// On a stream whose handshake returned to send early data, the GET travels
/// in it. When the handshake then fails, this reports the error a fresh
/// connection reports.
async fn upgrade_over_tls<S>(
    stream: TlsStream<S>,
    prepared: PreparedGet,
) -> Result<Http1UpgradeOutcome, Http1TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + TcpKeepaliveSource + 'static,
{
    require_http1_selected(&stream)?;
    let early_data = stream.early_data_wait();
    let outcome = send_profiled_upgrade(stream, prepared)
        .await
        .map_err(|error| {
            early_data
                .as_ref()
                .and_then(early_data_error)
                .unwrap_or_else(|| error.into())
        })?;
    let status = match &outcome {
        Http1UpgradeOutcome::Upgraded(response) => response.status(),
        Http1UpgradeOutcome::Rejected(response) => response.status(),
    };
    Span::current().record("status", status.as_u16());
    Ok(outcome)
}

/// Rejects a selected ALPN protocol other than `http/1.1` before any HTTP
/// byte is written. No selection is accepted: HTTP/1.1 is the TLS default.
fn require_http1_selected<S>(stream: &TlsStream<S>) -> Result<(), Http1TlsError> {
    let negotiated_alpn = stream.negotiated_alpn();
    Span::current().record("negotiated_alpn", trace_alpn(negotiated_alpn));
    if let Some(selected) = negotiated_alpn
        && selected != b"http/1.1"
    {
        debug!("TLS selected an unsupported HTTP/1 ALPN protocol");
        return Err(Http1TlsError::UnsupportedAlpn {
            selected: selected.into(),
        });
    }
    Ok(())
}

fn require_http1_alpn(settings: &TlsSettings) -> Result<(), Http1TlsError> {
    settings
        .alpn_protocols
        .iter()
        .any(|protocol| protocol.as_ref() == b"http/1.1")
        .then_some(())
        .ok_or(Http1TlsError::MissingHttp1Alpn)
}

mod error;

#[cfg(test)]
mod tests;
