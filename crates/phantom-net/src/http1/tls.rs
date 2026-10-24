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
    Http1Body, Http1Connection, Http1Error, Http1UpgradeOpening, Http1UpgradeOutcome,
    OperationOutcome, PreparedGet, PreparedRequest, RequestHeader, connection::early_data_error,
    proxy_opening::Http1ProxyOpening, send_prepared_upgrade,
};
use crate::{
    SourceBinding,
    connection_leg::{self, ConnectionLegError},
    direct::{Dialer, DirectConnectError, connect_tcp, connect_tcp_keeping_slower},
    host_resolver::HostResolver,
    proxy::{
        ProxyCredentialCache,
        http1_opening::{self, ProxyBinding, ProxyStream},
    },
    route::{
        DirectTlsSetup, Http1Route, Http1Target, HttpConnectRoute, OriginRoute, ProxyTransport,
        Socks5Target, TcpRoute,
    },
    tcp::{SlowerAttempt, SlowerConnection, SlowerKeepalive, TcpKeepaliveSource},
    tls::{ClientCertificate, ServerAuthentication, TlsConnector, TlsStream, trace_alpn},
};

use crate::tls::{EchFailure, TlsError};
pub use error::{Http1TlsError, Http1TlsErrorKind};

/// A reusable connector for profiled HTTP/1.1 TLS and proxy-forwarded requests.
///
/// # Examples
///
/// ```no_run
/// use phantom_net::{
///     http1::Http1TlsConnector,
///     request::{OriginForm, RequestHeader},
///     route::{DirectTlsSetup, Endpoint, Http1Route, OriginRoute, TcpRoute},
/// };
/// use phantom_profile::browser::chrome;
///
/// # async fn request() -> Result<(), Box<dyn std::error::Error>> {
/// let connector = Http1TlsConnector::new(&chrome::v154_tcp_tls())?
///     .with_alpn_protocols(&[Box::from(&b"http/1.1"[..])])?;
/// let route = Http1Route::Origin(OriginRoute::Tls {
///     tcp: TcpRoute::Direct(Endpoint { host: "example.com", port: 443 }),
///     server_name: "example.com",
///     setup: DirectTlsSetup::Default,
/// });
/// let (connection, _slower) = connector.connect(route).await?;
/// let _response = connection.send_get(
///     OriginForm::parse("/")?,
///     vec![RequestHeader::new("Host", "example.com")],
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Http1TlsConnector {
    tls: TlsConnector,
    write_strategy: super::Http1WriteStrategy,
    tcp: Option<TcpSettings>,
    source: Option<SourceBinding>,
    host_resolver: Option<HostResolver>,
    tcp_connector: Option<crate::TcpConnector>,
    proxy_credentials: Option<ProxyCredentialCache>,
}

impl Http1TlsConnector {
    /// Builds a connector with bundled roots, additional roots and leaf pins.
    ///
    /// Pins supplement certificate-chain and hostname verification. They apply
    /// to every TLS origin opened by this connector, including proxy tunnels.
    ///
    /// # Errors
    /// Returns the configuration and trust-store errors from [`Self::new`].
    pub fn new_with_spki_pins<'a>(
        settings: &TlsSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
        pins: &crate::ServerSpkiPins,
    ) -> Result<Self, Http1TlsError> {
        require_http1_alpn(settings)?;
        let tls = TlsConnector::new_with_spki_pins(settings, roots, pins)?;
        Ok(Self::from_parts(tls, None, None, None, None, None))
    }

    /// Opens a quiet SOCKS origin and returns its already-started backup.
    ///
    /// Adopt the backup before finishing origin TLS on the winner. Neither
    /// opening sends origin TLS or a request until its claimant finishes it.
    /// Only Backup policies enter this operation. SOCKS origin TLS never offers
    /// early data.
    ///
    /// # Errors
    ///
    /// Rejects other routes or direct-only setup before I/O, and returns the
    /// existing SOCKS connection errors without a route fallback.
    pub async fn open_socks_retaining(
        &self,
        origin: OriginRoute<'_>,
        family: &crate::tcp::AddressFamilyMemory,
    ) -> Result<
        (
            super::Http1SocksOpening,
            Option<SlowerConnection<super::Http1SocksOpening>>,
        ),
        Http1TlsError,
    > {
        crate::destination_policy::check_route(self.host_resolver.as_ref(), false)
            .map_err(Http1TlsError::Connect)?;
        if self.tcp_connector.is_some() {
            return Err(Http1TlsError::from_direct(DirectConnectError::Connect(
                crate::tcp_connector::unsupported(),
            )));
        }

        origin
            .validate(true, false)
            .map_err(Http1TlsError::Connect)?;
        let (tcp, name) = match origin {
            OriginRoute::Plaintext { tcp, family: None } => (tcp, None),
            OriginRoute::Tls {
                tcp,
                server_name,
                setup: DirectTlsSetup::Default,
            } => (tcp, Some(Box::<str>::from(server_name))),
            _ => return Err(invalid_route("quiet SOCKS requires ordinary origin setup")),
        };
        if !matches!(tcp, TcpRoute::Socks4 { .. } | TcpRoute::Socks5 { .. }) {
            return Err(invalid_route("quiet SOCKS requires a SOCKS route"));
        }
        let Some(phantom_profile::TcpAddressSelection::Backup(backup)) =
            self.tcp.map(|s| s.address_selection)
        else {
            return Err(invalid_route("quiet SOCKS requires a backup policy"));
        };
        let (stream, slower) =
            crate::proxy::socks_connection::connect_retaining(self.dialer(), tcp, family, backup)
                .await
                .map_err(|e| Http1TlsError::from(e.into_leg()))?;
        let slower = slower.map(|attempt| {
            let connector = self.clone();
            let name = name.clone();
            SlowerConnection::new(attempt.progress(), async move {
                Some(super::Http1SocksOpening::new(
                    attempt.finish().await?,
                    connector,
                    name,
                ))
            })
        });
        Ok((
            super::Http1SocksOpening::new(stream, self.clone(), name),
            slower,
        ))
    }

    pub(super) async fn finish_socks_opening(
        &self,
        stream: crate::tcp::ProfileTcpStream,
        server_name: Option<&str>,
    ) -> Result<Http1Connection, Http1TlsError> {
        match server_name {
            Some(name) => {
                if let Some(keepalive) = stream.tcp_keepalive() {
                    keepalive.request_dispatched();
                }
                connect_over_tls(self.write_strategy, self.tls.connect(name, stream).await?).await
            }
            None => connect_plaintext(self.write_strategy, stream)
                .await
                .map_err(Into::into),
        }
    }

    pub(crate) async fn finish_socks_upgrade(
        &self,
        stream: crate::tcp::ProfileTcpStream,
        server_name: Option<&str>,
        target: crate::request::OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOpening, Http1TlsError> {
        let prepared = PreparedGet::new(target, headers)?;
        let span = debug_span!("http1_upgrade", route = "socks");
        let outcome = OperationOutcome::new(&span);
        let result = async {
            match server_name {
                Some(name) => {
                    let stream = self.tls.connect(name, stream).await?;
                    require_http1_selected(&stream)?;
                    Ok(super::upgrade_opening::OpeningStream::Tls(stream))
                }
                None => Ok(super::upgrade_opening::OpeningStream::Plaintext(stream)),
            }
        }
        .instrument(span.clone())
        .await;
        let classified = connection_outcome(&result);
        match result {
            Ok(stream) => Ok(Http1UpgradeOpening::new(
                self.write_strategy,
                stream,
                prepared,
                span,
                outcome,
            )),
            Err(error) => {
                outcome.finish(classified);
                Err(error)
            }
        }
    }

    /// Opens an exact HTTP/1 origin over SOCKS, keeping a completed backup.
    ///
    /// Backup profiles race complete SOCKS connections, including authentication.
    /// The retained connection finishes ordinary origin TLS without a request.
    /// Family memory describes a locally known target, never the proxy or a
    /// remote DNS answer. Other address policies use the existing connector path.
    /// Direct early-data settings do not change SOCKS retention. Origin TLS
    /// over SOCKS never offers early data. ECH and direct-only setup remain
    /// unsupported here.
    ///
    /// # Errors
    ///
    /// Rejects other routes or setup policies before I/O. Otherwise returns the
    /// existing typed SOCKS, TLS and HTTP/1 setup errors without route fallback.
    pub async fn connect_socks_retaining(
        &self,
        origin: OriginRoute<'_>,
        family: &crate::tcp::AddressFamilyMemory,
    ) -> Result<(Http1Connection, Option<SlowerConnection<Http1Connection>>), Http1TlsError> {
        crate::destination_policy::check_route(self.host_resolver.as_ref(), false)
            .map_err(Http1TlsError::Connect)?;
        if self.tcp_connector.is_some() {
            return Err(Http1TlsError::from_direct(DirectConnectError::Connect(
                crate::tcp_connector::unsupported(),
            )));
        }

        origin
            .validate(true, false)
            .map_err(Http1TlsError::Connect)?;
        let route = Http1Route::Origin(origin);
        let span = connection_span(&route);
        let Http1Route::Origin(origin) = route else {
            return Err(invalid_route("retained SOCKS requires an origin"));
        };
        let (tcp, name) = match &origin {
            OriginRoute::Plaintext { tcp, family: None } => (tcp, None),
            OriginRoute::Tls {
                tcp,
                server_name,
                setup: DirectTlsSetup::Default,
            } => (tcp, Some(*server_name)),
            _ => {
                return Err(invalid_route(
                    "retained SOCKS requires ordinary origin setup",
                ));
            }
        };
        if !matches!(tcp, TcpRoute::Socks4 { .. } | TcpRoute::Socks5 { .. }) {
            return Err(invalid_route(
                "retained SOCKS requires a SOCKS4 or SOCKS5 route",
            ));
        }
        let backup = match self.tcp.map(|s| s.address_selection) {
            Some(phantom_profile::TcpAddressSelection::Backup(backup)) => backup,
            _ => return self.connect(Http1Route::Origin(origin)).await,
        };
        let tcp = match origin {
            OriginRoute::Plaintext { tcp, .. } | OriginRoute::Tls { tcp, .. } => tcp,
        };
        let opening =
            crate::proxy::socks_connection::connect_retaining(self.dialer(), tcp, family, backup);
        let mut slower = None;
        let connection = self
            .trace_connect(
                span,
                pin!(async {
                    let (stream, pending) = opening
                        .await
                        .map_err(|e| Http1TlsError::from(e.into_leg()))?;
                    slower = pending;
                    let primary = async {
                        match name {
                            None => connect_plaintext(self.write_strategy, stream)
                                .await
                                .map_err(Into::into),
                            Some(name) => {
                                if let Some(keepalive) = stream.tcp_keepalive() {
                                    keepalive.request_dispatched();
                                }
                                let tls = self.tls.connect(name, stream).await?;
                                connect_over_tls(self.write_strategy, tls).await
                            }
                        }
                    };
                    let connection = match slower.as_mut() {
                        Some(slower) => slower.alongside(primary).await?,
                        None => primary.await?,
                    };
                    Ok(connection)
                }),
            )
            .await?;
        let slower = slower.map(|slower| {
            let progress = slower.progress();
            let connector = self.clone();
            let name = name.map(str::to_owned);
            SlowerConnection::new(progress, async move {
                let stream = slower.finish().await?;
                let connection = match name {
                    None => connect_plaintext(connector.write_strategy, stream)
                        .await
                        .ok()?,
                    Some(name) => {
                        if let Some(keepalive) = stream.tcp_keepalive() {
                            keepalive.request_dispatched();
                        }
                        let stream = connector.tls.connect(&name, stream).await.ok()?;
                        connect_over_tls(connector.write_strategy, stream)
                            .await
                            .ok()?
                    }
                };
                if !connection.is_reusable() {
                    return None;
                }
                connection.report_idle();
                Some(connection)
            })
        });
        Ok((connection, slower))
    }

    /// Opens the physical HTTPS forwarding socket and retains its slower attempt.
    ///
    /// Only an outer HTTP/1 proxy is accepted. Adopt the spare before calling
    /// [`Http1ProxyOpening::finish_forward`] on the primary. The spare may finish
    /// outer TLS, but sends no CONNECT, origin TLS or request until claimed.
    ///
    /// # Errors
    ///
    /// Rejects other transports/proxy protocols before I/O and returns the
    /// existing proxy connection errors.
    pub async fn open_https_forward_retaining(
        &self,
        transport: ProxyTransport<'_>,
        family: &crate::tcp::AddressFamilyMemory,
    ) -> Result<
        (
            Http1ProxyOpening,
            Option<SlowerConnection<Http1ProxyOpening>>,
        ),
        Http1TlsError,
    > {
        crate::destination_policy::check_route(self.host_resolver.as_ref(), false)
            .map_err(Http1TlsError::Connect)?;
        if self.tcp_connector.is_some() {
            return Err(Http1TlsError::from_direct(DirectConnectError::Connect(
                crate::tcp_connector::unsupported(),
            )));
        }

        let binding = ProxyBinding::forward(transport)?;
        let slower_binding = ProxyBinding::forward(transport)?;
        let ProxyTransport::Tls {
            endpoint,
            connector,
            ..
        } = transport
        else {
            return Err(invalid_route(
                "retained HTTPS forwarding requires proxy TLS",
            ));
        };
        let (stream, slower) = connector
            .open_http1_proxy_retaining(endpoint.host, endpoint.port, family)
            .await?;
        Ok((
            Http1ProxyOpening::new(stream, self.clone(), binding),
            slower.map(|attempt| self.slower_proxy_opening(attempt, slower_binding)),
        ))
    }

    /// Opens plaintext HTTP/1.1 to a proxy and retains its slower TCP attempt.
    ///
    /// Both connections remain quiet until a caller sends a forward request.
    /// The caller owns their route and credential partition and supplies each
    /// request's current ordered headers. Adopt the spare before sending.
    ///
    /// # Errors
    ///
    /// Returns the same runtime, proxy connection and HTTP/1 setup errors as
    /// [`Self::connect`] on a plaintext forwarding route.
    pub async fn connect_forward_retaining(
        &self,
        proxy: crate::route::Endpoint<'_>,
        family: &crate::tcp::AddressFamilyMemory,
    ) -> Result<(Http1Connection, Option<SlowerConnection<Http1Connection>>), Http1TlsError> {
        crate::destination_policy::check_route(self.host_resolver.as_ref(), false)
            .map_err(Http1TlsError::Connect)?;
        if self.tcp_connector.is_some() {
            return Err(Http1TlsError::from_direct(DirectConnectError::Connect(
                crate::tcp_connector::unsupported(),
            )));
        }

        let span = connection_span(&Http1Route::Forward(ProxyTransport::Tcp(proxy)));
        let mut slower = None;
        let connection = self
            .trace_connect(
                span,
                pin!(async {
                    let (stream, attempt) = connect_tcp_keeping_slower(
                        proxy.host,
                        proxy.port,
                        self.dialer(),
                        Some(family),
                    )
                    .await
                    .map_err(forward_connect_error)?;
                    slower = attempt;
                    connect_plaintext(self.write_strategy, stream)
                        .await
                        .map_err(Into::into)
                }),
            )
            .await?;
        Ok((
            connection,
            slower.map(|attempt| slower_plaintext(attempt, self.write_strategy)),
        ))
    }

    /// Opens a proxy TCP socket without sending CONNECT or origin TLS.
    ///
    /// Retain the returned slower opening before finishing the primary. Both
    /// use this connector's origin TLS context and immutable route binding.
    ///
    /// # Errors
    ///
    /// Rejects an H2 proxy or invalid CONNECT fields before I/O,
    /// and returns TCP connection errors through the HTTP proxy error category.
    pub async fn open_http_connect_retaining(
        &self,
        route: HttpConnectRoute<'_>,
        origin_server_name: &str,
        family: &crate::tcp::AddressFamilyMemory,
    ) -> Result<
        (
            Http1ProxyOpening,
            Option<SlowerConnection<Http1ProxyOpening>>,
        ),
        Http1TlsError,
    > {
        crate::destination_policy::check_route(self.host_resolver.as_ref(), false)
            .map_err(Http1TlsError::Connect)?;
        if self.tcp_connector.is_some() {
            return Err(Http1TlsError::from_direct(DirectConnectError::Connect(
                crate::tcp_connector::unsupported(),
            )));
        }

        let opened =
            http1_opening::open_connect(route, origin_server_name, self.dialer(), family).await?;
        let slower = opened
            .slower
            .map(|(attempt, binding)| self.slower_proxy_opening(attempt, binding));
        Ok((
            Http1ProxyOpening::new(opened.stream, self.clone(), opened.binding),
            slower,
        ))
    }

    pub(crate) async fn finish_proxy_upgrade(
        &self,
        stream: ProxyStream,
        binding: ProxyBinding,
        route: HttpConnectRoute<'_>,
        target: crate::request::OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOpening, Http1TlsError> {
        binding.validate_connect(route)?;
        let prepared = PreparedGet::new(target, headers)?;
        let span = upgrade_span(&Http1Route::Origin(OriginRoute::Tls {
            tcp: TcpRoute::HttpConnect(route),
            server_name: binding.server_name()?,
            setup: DirectTlsSetup::Default,
        }));
        let outcome = OperationOutcome::new(&span);
        let result = async {
            let (leg, server_name) = binding
                .finish_connect(
                    stream,
                    route,
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
            let stream = self.tls.connect(&server_name, leg).await?;
            require_http1_selected(&stream)?;
            Ok::<_, Http1TlsError>(stream)
        }
        .instrument(span.clone())
        .await;
        let classified = connection_outcome(&result);
        match result {
            Ok(stream) => Ok(Http1UpgradeOpening::new(
                self.write_strategy,
                super::upgrade_opening::OpeningStream::ProxyTls(stream),
                prepared,
                span,
                outcome,
            )),
            Err(error) => {
                outcome.finish(classified);
                Err(error)
            }
        }
    }

    fn slower_proxy_opening(
        &self,
        attempt: SlowerAttempt,
        binding: ProxyBinding,
    ) -> SlowerConnection<Http1ProxyOpening> {
        let connector = self.clone();
        SlowerConnection::new(attempt.progress(), async move {
            let stream = attempt
                .connect()
                .await
                .ok()?
                .into_stream(SlowerKeepalive::OnFirstRequest);
            Http1ProxyOpening::new(stream, connector, binding)
                .complete_proxy_tls()
                .await
                .ok()
        })
    }

    #[allow(
        clippy::manual_async_fn,
        reason = "Keep the explicit Send proof boundary for the pinned nightly compiler."
    )]
    pub(super) fn finish_proxy_opening(
        &self,
        stream: ProxyStream,
        binding: ProxyBinding,
        route: HttpConnectRoute<'_>,
    ) -> impl Future<Output = Result<Http1Connection, Http1TlsError>> + Send {
        // Keep the Send proof for this nested setup at its owning connector.
        async move {
            let span = connection_span(&Http1Route::Origin(OriginRoute::Tls {
                tcp: TcpRoute::HttpConnect(route),
                server_name: binding.server_name()?,
                setup: DirectTlsSetup::Default,
            }));
            self.trace_connect(
                span,
                pin!(async {
                    let (leg, server_name) = binding
                        .finish_connect(
                            stream,
                            route,
                            self.dialer(),
                            self.proxy_credentials.as_ref(),
                        )
                        .await?;
                    let stream = self.tls.connect(&server_name, leg).await?;
                    connect_over_tls(self.write_strategy, stream).await
                }),
            )
            .await
        }
    }

    /// Builds a connector from validated TLS settings and bundled public roots.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when TLS cannot offer HTTP/1.1 or the
    /// TLS settings are invalid or unsupported.
    pub fn new(settings: &TlsSettings) -> Result<Self, Http1TlsError> {
        require_http1_alpn(settings)?;
        TlsConnector::new(settings)
            .map(|tls| Self {
                tls,
                tcp: None,
                source: None,
                host_resolver: None,
                tcp_connector: None,
                proxy_credentials: None,
                write_strategy: super::Http1WriteStrategy::Automatic,
            })
            .map_err(Into::into)
    }

    /// Builds a connector with bundled public roots and additional DER certificates.
    ///
    /// For a direct connection example, see [`Self`].
    ///
    /// Additional roots extend verification for private authorities; they do
    /// not disable certificate or hostname verification.
    ///
    /// # Errors
    ///
    /// Returns the configuration errors from [`Self::new`]. Additional DER
    /// certificates can also fail to parse or enter the trust store.
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
                tcp_connector: None,
                proxy_credentials: None,
                write_strategy: super::Http1WriteStrategy::Automatic,
            })
            .map_err(Into::into)
    }

    /// Builds a connector with an explicit server-authentication policy.
    ///
    /// For a direct connection example, see [`Self`].
    ///
    /// A policy that does not verify the server, which the
    /// `danger-disable-verification` feature provides, accepts any server
    /// certificate but continues to send Server Name Indication.
    ///
    /// # Errors
    ///
    /// Returns the configuration errors from [`Self::new`]. The selected
    /// authentication policy also governs trust-store setup.
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
                tcp_connector: None,
                proxy_credentials: None,
                write_strategy: super::Http1WriteStrategy::Automatic,
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
                tcp_connector: None,
                proxy_credentials: None,
                write_strategy: super::Http1WriteStrategy::Automatic,
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
            tcp_connector: self.tcp_connector.clone(),
            proxy_credentials: self.proxy_credentials.clone(),
            write_strategy: self.write_strategy,
        }
    }

    /// Returns a weak control for this connector's isolated TLS ticket cache.
    #[must_use]
    pub fn session_ticket_cache(&self) -> Option<crate::SessionTicketCache> {
        self.tls.session_ticket_cache()
    }

    /// Attaches a consuming ticket store from the same immutable TLS configuration.
    ///
    /// Keeps this connector's DNS, TCP and proxy settings. The caller must
    /// separately match the cache's origin and route before attaching it.
    ///
    /// # Errors
    /// Rejects disabled tickets or a cache from a different profile or certificate.
    pub fn with_session_ticket_cache(
        &self,
        owner: &crate::SessionTicketCacheOwner,
    ) -> Result<Self, crate::TlsError> {
        let mut connector = self.clone();
        connector.tls = self.tls.with_session_ticket_cache(owner)?;
        Ok(connector)
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
            tcp_connector: self.tcp_connector.clone(),
            proxy_credentials: self.proxy_credentials.clone(),
            write_strategy: self.write_strategy,
        })
    }

    /// An HTTP/1.1 connector over `tls`, which must offer `http/1.1`, with
    /// the connection settings of another connector.
    pub(crate) fn from_parts(
        tls: TlsConnector,
        tcp: Option<TcpSettings>,
        source: Option<SourceBinding>,
        host_resolver: Option<HostResolver>,
        tcp_connector: Option<crate::TcpConnector>,
        proxy_credentials: Option<ProxyCredentialCache>,
    ) -> Self {
        Self {
            tls,
            tcp,
            source,
            host_resolver,
            tcp_connector,
            proxy_credentials,
            write_strategy: super::Http1WriteStrategy::Automatic,
        }
    }

    /// Selects request-write buffering for new HTTP/1.1 connections.
    ///
    /// Includes forwarded requests and Upgrade openings. Proxy CONNECT and
    /// SOCKS negotiation keep their existing writes. The default is Automatic.
    #[must_use]
    pub fn with_write_strategy(mut self, strategy: super::Http1WriteStrategy) -> Self {
        self.write_strategy = strategy;
        self
    }

    pub(super) const fn write_strategy(&self) -> super::Http1WriteStrategy {
        self.write_strategy
    }

    /// Applies TCP socket options to every TCP connection this connector opens.
    ///
    /// The options cover direct origin connections and connections to HTTP
    /// and SOCKS5 proxies. An HTTPS proxy connection uses the options of the
    /// [`crate::proxy::HttpsProxyConnector`] passed with it.
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
    /// [`crate::proxy::HttpsProxyConnector`] passed with it. Clones of this connector share
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
    /// [`crate::proxy::HttpsProxyConnector`] passed with it. An invalid binding fails each
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

    /// Uses caller-opened streams for direct origin connections.
    ///
    /// See [`crate::TcpConnector`] for supported routes, identity and socket
    /// ownership. Connection futures retain their caller's cancellation scope.
    #[must_use]
    pub fn with_tcp_connector(mut self, connector: crate::TcpConnector) -> Self {
        self.tcp_connector = Some(connector);
        self
    }

    /// Resolves host names through `resolver` instead of asking the operating
    /// system for every connection.
    ///
    /// The resolver covers direct origin hosts, HTTP and SOCKS5 proxy hosts,
    /// and the target of a local-DNS SOCKS5 route. An HTTPS proxy host is
    /// resolved through the [`crate::proxy::HttpsProxyConnector`] passed with it. A target
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
    /// ([`TlsSettings::ech`]).
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
        #[cfg(feature = "https-records")]
        let mut selected_ech = None;
        let connection = self
            .trace_connect(
                span,
                pin!(async {
                    validate_route(&route, true)?;
                    self.open_connection(
                        route,
                        true,
                        &mut slower,
                        #[cfg(feature = "https-records")]
                        &mut selected_ech,
                    )
                    .await
                }),
            )
            .await?;
        let slower = slower.map(|attempt| match server_name {
            Some(server_name) => {
                #[cfg(feature = "https-records")]
                if let Some(selected) = selected_ech {
                    return self.slower_tls_with_ech(attempt, server_name, selected);
                }
                self.slower_tls(attempt, server_name)
            }
            None => slower_plaintext(attempt, self.write_strategy),
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
                    self.open_connection(
                        route,
                        false,
                        &mut None,
                        #[cfg(feature = "https-records")]
                        &mut None,
                    )
                    .await?
                };
                self.send_prepared_request(&connection, prepared).await
            }),
        )
        .await
    }

    /// Connects a direct origin before sending its prepared Upgrade GET.
    ///
    /// The returned opening sends no application bytes until `send` is called.
    /// A retaining route returns its slower attempt separately, so its owner
    /// can keep that connection while waiting for the Upgrade response.
    ///
    /// # Errors
    ///
    /// Rejects invalid request fields and non-direct routes before lookup or I/O.
    /// Returns connection, TLS and ALPN failures without sending the GET.
    pub async fn open_upgrade(
        &self,
        route: OriginRoute<'_>,
        target: crate::request::OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<
        (
            Http1UpgradeOpening,
            Option<SlowerConnection<Http1Connection>>,
        ),
        Http1TlsError,
    > {
        let route = Http1Route::Origin(route);
        validate_route(&route, true)?;
        let prepared = PreparedGet::new(target, headers)?;
        let span = upgrade_span(&route);
        let outcome = OperationOutcome::new(&span);
        let result = async {
            let route = self.prepare_route(route).await?;

            match route {
                Http1Route::Origin(OriginRoute::Plaintext {
                    tcp: TcpRoute::Connected(stream),
                    family: None,
                }) => Ok((
                    super::upgrade_opening::OpeningStream::Connected(
                        crate::connection_leg::ConnectionLeg::Connected(stream),
                    ),
                    None,
                )),
                Http1Route::Origin(OriginRoute::Tls {
                    tcp: TcpRoute::Connected(stream),
                    server_name,
                    setup: DirectTlsSetup::Default,
                }) => {
                    let stream = self
                        .tls
                        .connect_offering_early_data(
                            server_name,
                            crate::connection_leg::ConnectionLeg::Connected(stream),
                        )
                        .await?;
                    require_http1_selected(&stream)?;
                    Ok((
                        super::upgrade_opening::OpeningStream::ProxyTls(stream),
                        None,
                    ))
                }

                Http1Route::Origin(OriginRoute::Plaintext {
                    tcp: TcpRoute::Direct(endpoint),
                    family,
                }) => {
                    let (stream, slower) = connect_tcp_keeping_slower(
                        endpoint.host,
                        endpoint.port,
                        self.dialer(),
                        family,
                    )
                    .await
                    .map_err(Http1TlsError::from_direct)?;
                    Ok((
                        super::upgrade_opening::OpeningStream::Plaintext(stream),
                        slower.map(|attempt| slower_plaintext(attempt, self.write_strategy)),
                    ))
                }
                Http1Route::Origin(OriginRoute::Tls {
                    tcp: TcpRoute::Direct(endpoint),
                    server_name,
                    setup,
                }) => {
                    #[cfg(feature = "https-records")]
                    let mut selected_ech = None;
                    let (stream, slower) = match setup {
                        #[cfg(feature = "https-records")]
                        DirectTlsSetup::EchRetry(_) => {
                            return Err(invalid_route("ECH recovery requires an ordinary request"));
                        }
                        #[cfg(feature = "https-records")]
                        DirectTlsSetup::EchKeepingSlower { lookup, family } => {
                            let (stream, slower, selected) =
                                crate::direct::connect_tls_with_ech_retaining(
                                    &self.tls,
                                    self.dialer(),
                                    endpoint,
                                    server_name,
                                    lookup,
                                    crate::direct::EchEarlyData::WithoutEch,
                                    Some(family),
                                )
                                .await?;
                            selected_ech = Some(selected);
                            (stream, slower)
                        }
                        #[cfg(feature = "https-records")]
                        DirectTlsSetup::Ech(lookup) => (
                            crate::direct::connect_tls_with_ech(
                                &self.tls,
                                self.dialer(),
                                endpoint.host,
                                endpoint.port,
                                server_name,
                                lookup,
                                crate::direct::EchEarlyData::WithoutEch,
                            )
                            .await?,
                            None,
                        ),
                        DirectTlsSetup::Default => {
                            let stream = connect_tcp(endpoint.host, endpoint.port, self.dialer())
                                .await
                                .map_err(Http1TlsError::from_direct)?;
                            (
                                self.tls
                                    .connect_offering_early_data(server_name, stream)
                                    .await?,
                                None,
                            )
                        }
                        DirectTlsSetup::KeepSlower(family) => {
                            let (stream, mut slower) = connect_tcp_keeping_slower(
                                endpoint.host,
                                endpoint.port,
                                self.dialer(),
                                Some(family),
                            )
                            .await
                            .map_err(Http1TlsError::from_direct)?;
                            let handshake =
                                self.tls.connect_offering_early_data(server_name, stream);
                            let stream = match slower.as_mut() {
                                Some(attempt) => attempt.alongside(handshake).await,
                                None => handshake.await,
                            }?;
                            (stream, slower)
                        }
                    };
                    require_http1_selected(&stream)?;
                    let slower = slower.map(|attempt| {
                        #[cfg(feature = "https-records")]
                        if let Some(selected) = selected_ech {
                            return self.slower_tls_with_ech(attempt, server_name, selected);
                        }
                        self.slower_tls(attempt, server_name)
                    });
                    Ok((super::upgrade_opening::OpeningStream::Tls(stream), slower))
                }
                _ => Err(invalid_route(
                    "connected Upgrade opening requires a direct origin",
                )),
            }
        }
        .instrument(span.clone())
        .await;
        let classified = connection_outcome(&result);
        match result {
            Ok((stream, slower)) => Ok((
                Http1UpgradeOpening::new(self.write_strategy, stream, prepared, span, outcome),
                slower,
            )),
            Err(error) => {
                outcome.finish(classified);
                Err(error)
            }
        }
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
                let route = self.prepare_route(route).await?;
                match route {
                    Http1Route::Forward(ProxyTransport::Tcp(endpoint)) => {
                        let stream = connect_tcp(endpoint.host, endpoint.port, self.dialer())
                            .await
                            .map_err(forward_connect_error)?;
                        send_plaintext_tunnel_upgrade(self.write_strategy, stream, prepared).await
                    }
                    Http1Route::Forward(ProxyTransport::Tls {
                        endpoint,
                        server_name,
                        connector,
                    }) => {
                        let stream = connector
                            .connect_forward(endpoint.host, endpoint.port, server_name)
                            .await?;
                        send_plaintext_tunnel_upgrade(self.write_strategy, stream, prepared).await
                    }
                    Http1Route::Origin(OriginRoute::Plaintext { tcp, .. }) => {
                        let stream = connection_leg::connect(
                            tcp,
                            self.dialer(),
                            self.proxy_credentials.as_ref(),
                        )
                        .await?;
                        send_plaintext_tunnel_upgrade(self.write_strategy, stream, prepared).await
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
                                crate::direct::EchEarlyData::WithoutEch,
                            )
                            .await?;
                            upgrade_over_tls(self.write_strategy, stream, prepared).await
                        }
                        (tcp, DirectTlsSetup::Default) => {
                            let direct = matches!(tcp, TcpRoute::Direct(_));
                            let stream = connection_leg::connect(
                                tcp,
                                self.dialer(),
                                self.proxy_credentials.as_ref(),
                            )
                            .await?;
                            let stream = if direct || self.tcp_connector.is_some() {
                                self.tls
                                    .connect_offering_early_data(server_name, stream)
                                    .await?
                            } else {
                                self.tls.connect(server_name, stream).await?
                            };
                            upgrade_over_tls(self.write_strategy, stream, prepared).await
                        }
                        _ => Err(invalid_route("Upgrade cannot retain a slower connection")),
                    },
                }
            }),
        )
        .await
    }

    async fn prepare_route<'a>(
        &self,
        route: Http1Route<'a>,
    ) -> Result<Http1Route<'a>, Http1TlsError> {
        let direct = matches!(
            &route,
            Http1Route::Origin(OriginRoute::Plaintext {
                tcp: TcpRoute::Direct(_),
                ..
            }) | Http1Route::Origin(OriginRoute::Tls {
                tcp: TcpRoute::Direct(_),
                ..
            })
        );
        crate::destination_policy::check_route(self.host_resolver.as_ref(), direct)
            .map_err(Http1TlsError::Connect)?;
        let route = if let Some(connector) = &self.tcp_connector {
            connector
                .check_socket_policy(self.source.as_ref(), self.host_resolver.as_ref())
                .map_err(|error| Http1TlsError::from_direct(DirectConnectError::Connect(error)))?;
            match route {
                Http1Route::Origin(origin) => Http1Route::Origin(
                    connector
                        .prepare(origin)
                        .await
                        .map_err(Http1TlsError::Connect)?,
                ),
                Http1Route::Forward(_) => {
                    return Err(Http1TlsError::Connect(crate::tcp_connector::unsupported()));
                }
            }
        } else {
            route
        };
        Ok(route)
    }

    /// Opens the transport and finishes protocol setup within the caller's span.
    async fn open_connection(
        &self,
        route: Http1Route<'_>,
        offer_early_data: bool,
        slower: &mut Option<SlowerAttempt>,
        #[cfg(feature = "https-records")] selected_ech: &mut Option<crate::direct::SelectedEch>,
    ) -> Result<Http1Connection, Http1TlsError> {
        let route = self.prepare_route(route).await?;
        match route {
            Http1Route::Forward(ProxyTransport::Tcp(endpoint)) => {
                let stream = connect_tcp(endpoint.host, endpoint.port, self.dialer())
                    .await
                    .map_err(forward_connect_error)?;
                connect_plaintext(self.write_strategy, stream)
                    .await
                    .map_err(Into::into)
            }
            Http1Route::Forward(ProxyTransport::Tls {
                endpoint,
                server_name,
                connector,
            }) => {
                let stream = connector
                    .connect_forward(endpoint.host, endpoint.port, server_name)
                    .await?;
                connect_plaintext(self.write_strategy, stream)
                    .await
                    .map_err(Into::into)
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
                connect_plaintext(self.write_strategy, stream)
                    .await
                    .map_err(Into::into)
            }
            Http1Route::Origin(OriginRoute::Plaintext { tcp, .. }) => {
                let stream =
                    connection_leg::connect(tcp, self.dialer(), self.proxy_credentials.as_ref())
                        .await?;
                connect_plaintext(self.write_strategy, stream)
                    .await
                    .map_err(Into::into)
            }
            Http1Route::Origin(OriginRoute::Tls {
                tcp,
                server_name,
                setup,
            }) => {
                // Keep TLS setup off plaintext poll frames and end its Send proof here.
                let operation: Pin<Box<dyn Future<Output = _> + Send + '_>> =
                    Box::pin(self.open_tls_connection(
                        tcp,
                        server_name,
                        setup,
                        offer_early_data,
                        slower,
                        #[cfg(feature = "https-records")]
                        selected_ech,
                    ));
                operation.await
            }
        }
    }

    async fn open_tls_connection(
        &self,
        tcp: TcpRoute<'_>,
        server_name: &str,
        setup: DirectTlsSetup<'_>,
        offer_early_data: bool,
        slower: &mut Option<SlowerAttempt>,
        #[cfg(feature = "https-records")] selected_ech: &mut Option<crate::direct::SelectedEch>,
    ) -> Result<Http1Connection, Http1TlsError> {
        match (tcp, setup) {
            #[cfg(feature = "https-records")]
            (TcpRoute::Direct(_), DirectTlsSetup::EchRetry(retry)) => {
                let stream =
                    crate::direct::retry_ech(&self.tls, self.dialer(), server_name, retry).await?;
                connect_over_tls(self.write_strategy, stream).await
            }
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
                    connect_over_tls(self.write_strategy, stream).await
                };
                match slower.as_mut() {
                    Some(attempt) => attempt.alongside(handshake).await,
                    None => handshake.await,
                }
            }
            #[cfg(feature = "https-records")]
            (TcpRoute::Direct(endpoint), DirectTlsSetup::EchKeepingSlower { lookup, family }) => {
                let (stream, attempt, selected) = crate::direct::connect_tls_with_ech_retaining(
                    &self.tls,
                    self.dialer(),
                    endpoint,
                    server_name,
                    lookup,
                    if offer_early_data {
                        crate::direct::EchEarlyData::Allowed
                    } else {
                        crate::direct::EchEarlyData::Disabled
                    },
                    Some(family),
                )
                .await?;
                *slower = attempt;
                *selected_ech = Some(selected);
                let protocol = connect_over_tls(self.write_strategy, stream);
                match slower.as_mut() {
                    Some(attempt) => attempt.alongside(protocol).await,
                    None => protocol.await,
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
                    if offer_early_data {
                        crate::direct::EchEarlyData::Allowed
                    } else {
                        crate::direct::EchEarlyData::Disabled
                    },
                )
                .await?;
                connect_over_tls(self.write_strategy, stream).await
            }
            (tcp, DirectTlsSetup::Default) => {
                let direct = matches!(tcp, TcpRoute::Direct(_));
                let stream =
                    connection_leg::connect(tcp, self.dialer(), self.proxy_credentials.as_ref())
                        .await?;
                let stream = if (direct || self.tcp_connector.is_some()) && offer_early_data {
                    self.tls
                        .connect_offering_early_data(server_name, stream)
                        .await?
                } else {
                    self.tls.connect(server_name, stream).await?
                };
                connect_over_tls(self.write_strategy, stream).await
            }
            _ => Err(invalid_route("direct TLS setup requires a direct route")),
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
        self.slower_tls_setup(
            attempt,
            server_name,
            #[cfg(feature = "https-records")]
            None,
        )
    }

    #[cfg(feature = "https-records")]
    pub(crate) fn slower_tls_with_ech(
        &self,
        attempt: SlowerAttempt,
        server_name: &str,
        selected: crate::direct::SelectedEch,
    ) -> SlowerConnection<Http1Connection> {
        self.slower_tls_setup(attempt, server_name, Some(selected))
    }

    fn slower_tls_setup(
        &self,
        attempt: SlowerAttempt,
        server_name: &str,
        #[cfg(feature = "https-records")] selected: Option<crate::direct::SelectedEch>,
    ) -> SlowerConnection<Http1Connection> {
        let tls = self.tls.clone();
        let strategy = self.write_strategy;
        #[cfg(feature = "https-records")]
        let (tcp, source, resolver) = (self.tcp, self.source.clone(), self.host_resolver.clone());
        let server_name = server_name.to_owned();
        SlowerConnection::new(attempt.progress(), async move {
            let stream = attempt
                .connect()
                .await
                .ok()?
                .into_stream(SlowerKeepalive::BeforeTls);
            let handshake = async {
                #[cfg(feature = "https-records")]
                if let Some(selected) = selected {
                    return selected
                        .connect(
                            &tls,
                            Dialer {
                                tcp,
                                udp: None,
                                source: source.as_ref(),
                                resolver: resolver.as_ref(),
                            },
                            &server_name,
                            stream,
                        )
                        .await
                        .map_err(Http1TlsError::from);
                }
                tls.connect_offering_early_data(&server_name, stream)
                    .await
                    .map_err(Http1TlsError::from)
            };
            let stream = handshake
                .await
                .inspect_err(|error| debug!(error = %error, "slower connection handshake failed"))
                .ok()?;
            let connection = connect_over_tls(strategy, stream).await.ok()?;
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
                | Http1TlsError::Socks4Proxy(_)
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
        TcpRoute::Socks4 {
            target: crate::route::Socks4Target::LocalDns(_),
            ..
        } => "socks4_local_dns",
        TcpRoute::Socks4 { .. } => "socks4_remote_dns",
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
                TcpRoute::Socks4 { .. } => debug_span!(
                    "http1.proxy.socks4.upgrade_response_head",
                    method = "GET",
                    transport = "tcp",
                    route,
                    status = field::Empty,
                    outcome = field::Empty
                ),
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
pub(super) async fn send_plaintext_tunnel_upgrade<S>(
    strategy: super::Http1WriteStrategy,
    stream: S,
    prepared: PreparedGet,
) -> Result<Http1UpgradeOutcome, Http1TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + TcpKeepaliveSource + 'static,
{
    debug!("HTTP/1 plaintext Upgrade request prepared");
    let outcome = send_profiled_upgrade(stream, prepared, strategy).await?;
    let status = match &outcome {
        Http1UpgradeOutcome::Upgraded(response) => response.status(),
        Http1UpgradeOutcome::Rejected(response) => response.status(),
    };
    Span::current().record("status", status.as_u16());
    Ok(outcome)
}

pub(super) fn upgrade_outcome(result: &Result<Http1UpgradeOutcome, Http1TlsError>) -> &'static str {
    match result {
        Ok(Http1UpgradeOutcome::Upgraded(_)) => "upgraded",
        Ok(Http1UpgradeOutcome::Rejected(_)) => "rejected",
        Err(Http1TlsError::RuntimeUnavailable) => "runtime_unavailable",
        Err(Http1TlsError::Connect(_)) => "connect_error",
        Err(
            Http1TlsError::ForwardProxyConnect(_)
            | Http1TlsError::Proxy(_)
            | Http1TlsError::Socks4Proxy(_)
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
            | Http1TlsError::Socks4Proxy(_)
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
            ConnectionLegError::Socks4(error) => Self::Socks4Proxy(error),
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
async fn connect_over_tls<S>(
    strategy: super::Http1WriteStrategy,
    stream: TlsStream<S>,
) -> Result<Http1Connection, Http1TlsError>
where
    S: AsyncRead
        + AsyncWrite
        + Unpin
        + Send
        + TcpKeepaliveSource
        + crate::connection_diagnostics::ConnectionMetadataSource
        + 'static,
{
    use crate::connection_diagnostics::ConnectionMetadataSource;
    require_http1_selected(&stream)?;
    let keepalive = stream.tcp_keepalive();
    let early_data = stream.early_data_wait();
    let metadata = stream.connection_metadata();
    Http1Connection::connect_with_early_data(stream, early_data, keepalive, strategy)
        .await
        .map(|connection| connection.with_connection_metadata(metadata))
        .map_err(Into::into)
}

/// Starts plaintext HTTP/1.1 on a slower attempt's connection once it
/// connects, with no keepalive until its first request.
pub(crate) fn slower_plaintext(
    attempt: SlowerAttempt,
    strategy: super::Http1WriteStrategy,
) -> SlowerConnection<Http1Connection> {
    SlowerConnection::new(attempt.progress(), async move {
        let stream = attempt
            .connect()
            .await
            .ok()?
            .into_stream(SlowerKeepalive::OnFirstRequest);
        connect_plaintext(strategy, stream).await.ok()
    })
}

/// Starts plaintext HTTP/1.1 on a profile connection.
pub(super) async fn connect_plaintext<S>(
    strategy: super::Http1WriteStrategy,
    stream: S,
) -> Result<Http1Connection, Http1Error>
where
    S: AsyncRead
        + AsyncWrite
        + Unpin
        + Send
        + TcpKeepaliveSource
        + crate::connection_diagnostics::ConnectionMetadataSource
        + 'static,
{
    let keepalive = stream.tcp_keepalive();
    let metadata = stream.connection_metadata();
    Http1Connection::connect_with_early_data(stream, None, keepalive, strategy)
        .await
        .map(|connection| connection.with_connection_metadata(metadata))
}

/// Sends a prepared Upgrade GET on a profile connection, which switches its
/// keepalive schedule when the server switches protocols.
async fn send_profiled_upgrade<S>(
    stream: S,
    prepared: PreparedGet,
    strategy: super::Http1WriteStrategy,
) -> Result<Http1UpgradeOutcome, Http1Error>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + TcpKeepaliveSource + 'static,
{
    let keepalive = stream.tcp_keepalive();
    send_prepared_upgrade(stream, prepared, keepalive, strategy).await
}

/// Sends a prepared Upgrade GET over an established TLS stream.
///
/// On a stream whose handshake returned to send early data, the GET travels
/// in it. When the handshake then fails, this reports the error a fresh
/// connection reports.
pub(super) async fn upgrade_over_tls<S>(
    strategy: super::Http1WriteStrategy,
    stream: TlsStream<S>,
    prepared: PreparedGet,
) -> Result<Http1UpgradeOutcome, Http1TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + TcpKeepaliveSource + 'static,
{
    require_http1_selected(&stream)?;
    let early_data = stream.early_data_wait();
    let outcome = send_profiled_upgrade(stream, prepared, strategy)
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
