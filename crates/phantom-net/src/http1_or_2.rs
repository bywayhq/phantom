//! One-handshake HTTP/1.1 or HTTP/2 selection over TLS ALPN.

use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    pin::{Pin, pin},
};

use phantom_profile::{Http2Settings, TcpSettings, TlsSettings};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, Span, debug, debug_span, field};

use crate::{
    SourceBinding,
    connection_leg::{self, ConnectionLegError},
    direct::{Dialer, DirectConnectError, connect_tcp_keeping_slower},
    host_resolver::HostResolver,
    http1::{Http1Connection, Http1Error, Http1TlsConnector, Http1TlsError},
    http2::{
        Http2Builder, Http2Connection, Http2TlsConnector, Http2TlsError, connect_selected,
        translate_settings, validate_http2,
    },
    proxy::http1_opening::{self, ProxyBinding, ProxyStream},
    proxy::{HttpConnectError, ProxyCredentialCache, Socks4Error, Socks5Error},
    route::{DirectTlsSetup, OriginRoute, TcpRoute},
    tcp::{SlowerAttempt, SlowerConnection, SlowerKeepalive, TcpKeepaliveSource},
    tls::{ClientCertificate, TlsConnector, TlsError, trace_alpn},
};

use crate::tls::EchFailure;

pub use proxy_opening::Http1Or2ProxyOpening;
pub use socks_opening::Http1Or2SocksOpening;
mod proxy_opening;
mod socks_opening;

/// An established connection selected from one TLS ALPN negotiation.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http1Or2Connection {
    /// HTTP/1.1 was selected, or the peer did not negotiate ALPN.
    Http1(Http1Connection),
    /// The peer selected exact `h2`.
    Http2(Http2Connection),
}

/// Stable category of HTTP/1.1-or-HTTP/2 connection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http1Or2TlsErrorKind {
    /// The request lacks a Tokio runtime with network I/O enabled.
    RuntimeUnavailable,
    /// Establishing the direct TCP connection failed.
    Connect,
    /// The HTTP proxy leg or its CONNECT request failed before origin TLS.
    HttpProxy,
    /// The SOCKS4 proxy leg failed.
    Socks4Proxy,
    /// The SOCKS5 proxy leg failed before TLS.
    Socks5Proxy,
    /// TLS setup or negotiation failed before an HTTP protocol was selected.
    Tls,
    /// HTTP/1.1 setup failed after ALPN selection.
    Http1,
    /// HTTP/2 or ALPS setup failed after ALPN selection.
    Http2,
    /// TLS selected an unsupported ALPN protocol.
    UnsupportedAlpn,
    /// The configured profile cannot negotiate both HTTP/1.1 and HTTP/2.
    InvalidConfiguration,
}

/// Error returned while selecting HTTP/1.1 or HTTP/2 over one TLS connection.
#[derive(Debug)]
#[non_exhaustive]
pub enum Http1Or2TlsError {
    /// The network operation was polled without a Tokio I/O runtime.
    RuntimeUnavailable,
    /// Establishing the direct TCP connection failed.
    Connect(std::io::Error),
    /// The HTTP proxy connection, its TLS, authentication, or CONNECT request
    /// failed.
    Proxy(HttpConnectError),
    /// The SOCKS4 proxy negotiation or CONNECT request failed.
    Socks4Proxy(Socks4Error),
    /// The SOCKS5 proxy negotiation or CONNECT request failed.
    Socks5Proxy(Socks5Error),
    /// TLS connector setup or handshake failed.
    Tls(TlsError),
    /// HTTP/1.1 connection setup failed after selection.
    Http1(Http1Error),
    /// HTTP/2 or ALPS setup failed after selection.
    Http2(Http2TlsError),
    /// The peer selected an ALPN protocol other than `h2` or `http/1.1`.
    UnsupportedAlpn {
        /// Exact ALPN bytes selected by the peer.
        selected: Box<[u8]>,
    },
    /// The TLS settings do not offer `http/1.1`.
    MissingHttp1Alpn,
    /// The TLS settings do not offer `h2`.
    MissingHttp2Alpn,
}

impl From<ConnectionLegError> for Http1Or2TlsError {
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

impl Http1Or2TlsError {
    /// Returns why a connection that offered Encrypted Client Hello failed,
    /// when that is the cause.
    #[must_use]
    pub fn ech_failure(&self) -> Option<EchFailure> {
        match self {
            Self::Tls(error) => error.ech_failure(),
            _ => None,
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub fn kind(&self) -> Http1Or2TlsErrorKind {
        match self {
            Self::RuntimeUnavailable => Http1Or2TlsErrorKind::RuntimeUnavailable,
            Self::Connect(_) => Http1Or2TlsErrorKind::Connect,
            Self::Proxy(_) => Http1Or2TlsErrorKind::HttpProxy,
            Self::Socks4Proxy(_) => Http1Or2TlsErrorKind::Socks4Proxy,
            Self::Socks5Proxy(_) => Http1Or2TlsErrorKind::Socks5Proxy,
            Self::Tls(_) => Http1Or2TlsErrorKind::Tls,
            Self::Http1(_) => Http1Or2TlsErrorKind::Http1,
            Self::Http2(_) => Http1Or2TlsErrorKind::Http2,
            Self::UnsupportedAlpn { .. } => Http1Or2TlsErrorKind::UnsupportedAlpn,
            Self::MissingHttp1Alpn | Self::MissingHttp2Alpn => {
                Http1Or2TlsErrorKind::InvalidConfiguration
            }
        }
    }
}

impl fmt::Display for Http1Or2TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeUnavailable => formatter
                .write_str("negotiated HTTP/1.1 or HTTP/2 requests require a Tokio runtime"),
            Self::Connect(_) => formatter.write_str("TCP connection failed"),
            Self::Proxy(_) => formatter.write_str("HTTP proxy failed"),
            Self::Socks4Proxy(_) => formatter.write_str("SOCKS4 proxy failed"),
            Self::Socks5Proxy(_) => formatter.write_str("SOCKS5 proxy failed"),
            Self::Tls(_) => formatter.write_str("TLS connection failed"),
            Self::Http1(_) => formatter.write_str("HTTP/1.1 connection failed"),
            Self::Http2(_) => formatter.write_str("HTTP/2 connection failed"),
            Self::UnsupportedAlpn { selected } => write!(
                formatter,
                "TLS selected {} ALPN, which is unsupported by HTTP/1.1-or-HTTP/2 negotiation",
                trace_alpn(Some(selected))
            ),
            Self::MissingHttp1Alpn => {
                formatter.write_str("TLS settings do not offer the required `http/1.1` ALPN")
            }
            Self::MissingHttp2Alpn => {
                formatter.write_str("TLS settings do not offer the required `h2` ALPN")
            }
        }
    }
}

impl StdError for Http1Or2TlsError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Connect(error) => Some(error),
            Self::Proxy(error) => Some(error),
            Self::Socks4Proxy(error) => Some(error),
            Self::Socks5Proxy(error) => Some(error),
            Self::Tls(error) => Some(error),
            Self::Http1(error) => Some(error),
            Self::Http2(error) => Some(error),
            Self::RuntimeUnavailable
            | Self::UnsupportedAlpn { .. }
            | Self::MissingHttp1Alpn
            | Self::MissingHttp2Alpn => None,
        }
    }
}

impl Http1Or2TlsError {
    fn from_direct(error: DirectConnectError) -> Self {
        match error {
            DirectConnectError::RuntimeUnavailable => Self::RuntimeUnavailable,
            DirectConnectError::Connect(error) => Self::Connect(error),
        }
    }
}

#[cfg(feature = "https-records")]
impl From<crate::direct::DirectTlsError> for Http1Or2TlsError {
    fn from(error: crate::direct::DirectTlsError) -> Self {
        match error {
            crate::direct::DirectTlsError::Direct(error) => Self::from_direct(error),
            crate::direct::DirectTlsError::Tls(error) => Self::Tls(error),
        }
    }
}

impl From<HttpConnectError> for Http1Or2TlsError {
    fn from(error: HttpConnectError) -> Self {
        Self::Proxy(error)
    }
}

impl From<Socks4Error> for Http1Or2TlsError {
    fn from(error: Socks4Error) -> Self {
        Self::Socks4Proxy(error)
    }
}

impl From<Socks5Error> for Http1Or2TlsError {
    fn from(error: Socks5Error) -> Self {
        Self::Socks5Proxy(error)
    }
}

impl From<TlsError> for Http1Or2TlsError {
    fn from(error: TlsError) -> Self {
        match error.into_speculative_proxy_error() {
            Ok(error) => Self::Proxy(error),
            Err(error) => Self::Tls(error),
        }
    }
}

impl From<Http1Error> for Http1Or2TlsError {
    fn from(error: Http1Error) -> Self {
        Self::Http1(error)
    }
}

impl From<Http2TlsError> for Http1Or2TlsError {
    fn from(error: Http2TlsError) -> Self {
        Self::Http2(error)
    }
}

/// A reusable connector that selects HTTP/1.1 or HTTP/2 from one TLS handshake.
#[derive(Clone, Debug)]
pub struct Http1Or2TlsConnector {
    tls: TlsConnector,
    http2: Http2Settings,
    http1_write_strategy: crate::http1::Http1WriteStrategy,
    tcp: Option<TcpSettings>,
    source: Option<SourceBinding>,
    host_resolver: Option<HostResolver>,
    tcp_connector: Option<crate::TcpConnector>,
    proxy_credentials: Option<ProxyCredentialCache>,
}

impl Http1Or2TlsConnector {
    /// Opens a quiet complete SOCKS tunnel and its already-started backup.
    ///
    /// Adopt the backup before the winner starts origin TLS. Only Backup
    /// policies are supported; no route is substituted. SOCKS origin TLS never
    /// offers early data.
    ///
    /// # Errors
    ///
    /// Rejects other routes and direct-only setup before I/O, and returns the
    /// existing typed SOCKS setup errors.
    pub async fn open_socks_retaining(
        &self,
        origin: OriginRoute<'_>,
        family: &crate::tcp::AddressFamilyMemory,
    ) -> Result<
        (
            Http1Or2SocksOpening,
            Option<SlowerConnection<Http1Or2SocksOpening>>,
        ),
        Http1Or2TlsError,
    > {
        crate::destination_policy::check_route(self.host_resolver.as_ref(), false)
            .map_err(|error| Http1Or2TlsError::from_direct(DirectConnectError::Connect(error)))?;
        if self.tcp_connector.is_some() {
            return Err(Http1Or2TlsError::from_direct(DirectConnectError::Connect(
                crate::tcp_connector::unsupported(),
            )));
        }

        origin
            .validate(false, true)
            .map_err(|e| Http1Or2TlsError::from_direct(DirectConnectError::Connect(e)))?;
        let OriginRoute::Tls {
            tcp,
            server_name,
            setup: DirectTlsSetup::Default,
        } = origin
        else {
            return Err(quiet_socks_invalid_route(
                "quiet SOCKS requires ordinary origin TLS",
            ));
        };
        if !matches!(tcp, TcpRoute::Socks4 { .. } | TcpRoute::Socks5 { .. }) {
            return Err(quiet_socks_invalid_route(
                "quiet SOCKS requires a SOCKS route",
            ));
        }
        let Some(phantom_profile::TcpAddressSelection::Backup(backup)) =
            self.tcp.map(|s| s.address_selection)
        else {
            return Err(quiet_socks_invalid_route(
                "quiet SOCKS requires a backup policy",
            ));
        };
        translate_settings(&self.http2).map_err(Http2TlsError::from)?;
        let name = Box::<str>::from(server_name);
        let (stream, slower) =
            crate::proxy::socks_connection::connect_retaining(self.dialer(), tcp, family, backup)
                .await
                .map_err(|e| Http1Or2TlsError::from(e.into_leg()))?;
        let slower = slower.map(|attempt| {
            let connector = self.clone();
            let name = name.clone();
            SlowerConnection::new(attempt.progress(), async move {
                Some(Http1Or2SocksOpening::new(
                    attempt.finish().await?,
                    connector,
                    name,
                ))
            })
        });
        Ok((
            Http1Or2SocksOpening::new(stream, self.clone(), name),
            slower,
        ))
    }

    pub(super) async fn finish_socks_opening(
        &self,
        stream: crate::tcp::ProfileTcpStream,
        server_name: &str,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError> {
        let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
        let stream = self.tls.connect(server_name, stream).await?;
        select_connection(stream, client, self.http1_write_strategy).await
    }

    /// Opens origin TLS over SOCKS, retaining an eligible complete backup.
    ///
    /// Backup address policies race complete SOCKS negotiations. HTTP/1.1 can
    /// keep an unfinished backup; HTTP/2 cancels it unless SOCKS negotiation
    /// already completed. Retained connections send no application request.
    /// Target family memory never records the proxy's address family.
    ///
    /// Non-backup policies keep the existing single-opening path. Origin TLS
    /// over SOCKS never offers early data. ECH and other direct-only setup
    /// policies are rejected before I/O.
    ///
    /// # Errors
    ///
    /// Returns the existing route, SOCKS, TLS, ALPN or protocol setup error.
    pub async fn connect_socks_retaining(
        &self,
        origin: OriginRoute<'_>,
        family: &crate::tcp::AddressFamilyMemory,
    ) -> Result<
        (
            Http1Or2Connection,
            Option<SlowerConnection<Http1Or2Connection>>,
        ),
        Http1Or2TlsError,
    > {
        crate::destination_policy::check_route(self.host_resolver.as_ref(), false)
            .map_err(|error| Http1Or2TlsError::from_direct(DirectConnectError::Connect(error)))?;
        if self.tcp_connector.is_some() {
            return Err(Http1Or2TlsError::from_direct(DirectConnectError::Connect(
                crate::tcp_connector::unsupported(),
            )));
        }

        origin
            .validate(false, true)
            .map_err(|error| Http1Or2TlsError::from_direct(DirectConnectError::Connect(error)))?;
        let OriginRoute::Tls {
            tcp,
            server_name,
            setup: DirectTlsSetup::Default,
        } = &origin
        else {
            return Err(Http1Or2TlsError::from_direct(DirectConnectError::Connect(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "retained SOCKS requires ordinary origin TLS",
                ),
            )));
        };
        if !matches!(tcp, TcpRoute::Socks4 { .. } | TcpRoute::Socks5 { .. }) {
            return Err(Http1Or2TlsError::from_direct(DirectConnectError::Connect(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "retained SOCKS requires a SOCKS4 or SOCKS5 route",
                ),
            )));
        }
        let backup = match self.tcp.map(|settings| settings.address_selection) {
            Some(phantom_profile::TcpAddressSelection::Backup(backup)) => backup,
            _ => return self.connect(origin).await,
        };
        let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
        let server_name = *server_name;
        let tcp = match origin {
            OriginRoute::Plaintext { tcp, .. } | OriginRoute::Tls { tcp, .. } => tcp,
        };
        let opening =
            crate::proxy::socks_connection::connect_retaining(self.dialer(), tcp, family, backup);
        let mut slower = None;
        let connection = self
            .trace_connect(pin!(async {
                let (stream, pending) = opening
                    .await
                    .map_err(|error| Http1Or2TlsError::from(error.into_leg()))?;
                slower = pending;
                let handshake = async {
                    let stream = self.tls.connect(server_name, stream).await?;
                    select_connection(stream, client, self.http1_write_strategy).await
                };
                match slower.as_mut() {
                    Some(attempt) => attempt.alongside(handshake).await,
                    None => handshake.await,
                }
            }))
            .await?;
        let slower = slower
            .filter(|attempt| {
                !matches!(connection, Http1Or2Connection::Http2(_))
                    || attempt.progress().has_connected()
            })
            .map(|attempt| {
                let progress = attempt.progress();
                let connector = self.clone();
                let server_name = server_name.to_owned();
                SlowerConnection::new(progress, async move {
                    let client = translate_settings(&connector.http2).ok()?;
                    let stream = attempt.finish().await?;
                    let stream = connector.tls.connect(&server_name, stream).await.ok()?;
                    match select_connection(stream, client, connector.http1_write_strategy)
                        .await
                        .ok()?
                    {
                        Http1Or2Connection::Http1(connection) => {
                            if !connection.is_reusable() {
                                return None;
                            }
                            connection.report_idle();
                            Some(Http1Or2Connection::Http1(connection))
                        }
                        Http1Or2Connection::Http2(connection) => connection
                            .is_reusable()
                            .then_some(Http1Or2Connection::Http2(connection)),
                    }
                })
            });
        Ok((connection, slower))
    }

    /// Opens a quiet CONNECT proxy socket and retains its slower backup.
    ///
    /// Adopt the backup before finishing the primary. Both retain this origin
    /// connector and the original proxy TLS and credential-cache context.
    /// Only TCP or HTTPS with outer HTTP/1 is supported here.
    ///
    /// # Errors
    ///
    /// Rejects invalid settings, CONNECT fields or outer protocol before I/O,
    /// and returns the existing proxy connection errors.
    pub async fn open_http_connect_retaining(
        &self,
        route: crate::route::HttpConnectRoute<'_>,
        origin_server_name: &str,
        family: &crate::tcp::AddressFamilyMemory,
    ) -> Result<
        (
            Http1Or2ProxyOpening,
            Option<SlowerConnection<Http1Or2ProxyOpening>>,
        ),
        Http1Or2TlsError,
    > {
        crate::destination_policy::check_route(self.host_resolver.as_ref(), false)
            .map_err(|error| Http1Or2TlsError::from_direct(DirectConnectError::Connect(error)))?;
        if self.tcp_connector.is_some() {
            return Err(Http1Or2TlsError::from_direct(DirectConnectError::Connect(
                crate::tcp_connector::unsupported(),
            )));
        }

        translate_settings(&self.http2).map_err(Http2TlsError::from)?;
        let opened =
            http1_opening::open_connect(route, origin_server_name, self.dialer(), family).await?;
        let slower = opened.slower.map(|(attempt, binding)| {
            let connector = self.clone();
            SlowerConnection::new(attempt.progress(), async move {
                let stream = attempt
                    .connect()
                    .await
                    .ok()?
                    .into_stream(SlowerKeepalive::OnFirstRequest);
                Http1Or2ProxyOpening::new(stream, connector, binding)
                    .complete_proxy_tls()
                    .await
                    .ok()
            })
        });
        Ok((
            Http1Or2ProxyOpening::new(opened.stream, self.clone(), opened.binding),
            slower,
        ))
    }

    pub(super) async fn finish_proxy_opening(
        &self,
        stream: ProxyStream,
        binding: ProxyBinding,
        route: crate::route::HttpConnectRoute<'_>,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError> {
        self.trace_connect(pin!(async {
            let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
            let (leg, server_name) = binding
                .finish_connect(
                    stream,
                    route,
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
            let stream = self.tls.connect(&server_name, leg).await?;
            select_connection(stream, client, self.http1_write_strategy).await
        }))
        .await
    }

    /// Builds a connector using bundled public roots.
    ///
    /// Both `h2` and `http/1.1` must be present in the TLS ALPN offer.
    ///
    /// # Errors
    ///
    /// Returns [`Http1Or2TlsError`] for missing protocol offers, invalid HTTP/2
    /// settings, or invalid or unsupported TLS settings.
    pub fn new(tls: &TlsSettings, http2: &Http2Settings) -> Result<Self, Http1Or2TlsError> {
        validate_settings(tls, http2)?;
        Ok(Self {
            tls: TlsConnector::new(tls)?,
            http2: http2.clone(),
            http1_write_strategy: crate::http1::Http1WriteStrategy::Automatic,
            tcp: None,
            source: None,
            host_resolver: None,
            tcp_connector: None,
            proxy_credentials: None,
        })
    }

    /// Builds a connector with bundled roots plus additional DER certificates.
    ///
    /// # Errors
    ///
    /// Returns the configuration errors from [`Self::new`]. Additional DER
    /// certificates can also fail to parse or enter the trust store.
    pub fn new_with_additional_roots<'a>(
        tls: &TlsSettings,
        http2: &Http2Settings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, Http1Or2TlsError> {
        validate_settings(tls, http2)?;
        Ok(Self {
            tls: TlsConnector::new_with_additional_roots(tls, roots)?,
            http2: http2.clone(),
            http1_write_strategy: crate::http1::Http1WriteStrategy::Automatic,
            tcp: None,
            source: None,
            host_resolver: None,
            tcp_connector: None,
            proxy_credentials: None,
        })
    }

    /// Reuses an HTTP/2 connector's validated TLS context and settings.
    ///
    /// The connector must also offer `http/1.1`. Reusing it avoids rebuilding
    /// the trust store when exact and negotiated request APIs coexist.
    ///
    /// # Errors
    ///
    /// Returns [`Http1Or2TlsError::MissingHttp1Alpn`] when the connector cannot
    /// negotiate HTTP/1.1.
    pub fn from_http2(connector: &Http2TlsConnector) -> Result<Self, Http1Or2TlsError> {
        if !connector.tls_connector().offers_alpn(b"http/1.1") {
            return Err(Http1Or2TlsError::MissingHttp1Alpn);
        }

        Ok(Self {
            tls: connector.tls_connector().clone(),
            http2: connector.settings().clone(),
            http1_write_strategy: crate::http1::Http1WriteStrategy::Automatic,
            tcp: connector.tcp_settings().copied(),
            source: connector.source_binding().cloned(),
            host_resolver: connector.host_resolver().cloned(),
            tcp_connector: connector.tcp_connector.clone(),
            proxy_credentials: connector.proxy_credential_cache().cloned(),
        })
    }

    /// Returns whether a direct connection offers TLS early data when its
    /// cached session permits it ([`TlsSettings::tcp_early_data`]).
    #[must_use]
    pub const fn offers_early_data(&self) -> bool {
        self.tls.offers_early_data()
    }

    /// Removes every TLS session this connector holds for `server_name`.
    ///
    /// Firefox removes every resumption token for a peer before it restarts
    /// requests whose early data the server rejected under another ALPN
    /// protocol (`MaybeRemoveSSLToken` and `nsHttpTransaction::Restart`,
    /// `netwerk/protocol/http/nsHttpTransaction.cpp:1390-1403` and
    /// `:1993-1999` at tag `FIREFOX_157_0_RELEASE`, under
    /// `network.http.remove_resumption_token_when_early_data_failed`, true by
    /// default), so the restarted connection makes a full handshake.
    pub fn forget_session_tickets(&self, server_name: &str) {
        self.tls.forget_sessions(server_name);
    }

    /// Returns a clone, sharing this connector's TLS session cache, whose
    /// connections never offer TLS early data
    /// ([`TlsSettings::tcp_early_data`]).
    ///
    /// Firefox restarts the requests of a connection whose early data the
    /// server rejected before selecting another ALPN protocol, and they do not
    /// try early data again (`nsHttpTransaction::Close`,
    /// `netwerk/protocol/http/nsHttpTransaction.cpp:1546-1579` at tag
    /// `FIREFOX_157_0_RELEASE`); a connection from this clone carries them,
    /// after [`Self::forget_session_tickets`] has removed the peer's tickets.
    #[must_use]
    pub fn without_early_data(&self) -> Self {
        Self {
            tls: self.tls.without_early_data(),
            http2: self.http2.clone(),
            http1_write_strategy: self.http1_write_strategy,
            tcp: self.tcp,
            source: self.source.clone(),
            host_resolver: self.host_resolver.clone(),
            tcp_connector: self.tcp_connector.clone(),
            proxy_credentials: self.proxy_credentials.clone(),
        }
    }

    /// Returns an HTTP/2 connector that shares this connector's TLS context,
    /// session cache, HTTP/2 settings, and connection settings.
    ///
    /// A connection from it sends the same ClientHello as this connector's
    /// and can resume the TLS sessions this connector's connections were
    /// issued, so an HTTP/2 WebSocket opening resumes the tickets of the
    /// origin's negotiated requests.
    #[must_use]
    pub fn http2_connector(&self) -> Http2TlsConnector {
        Http2TlsConnector::from_parts(
            self.tls.clone(),
            self.http2.clone(),
            self.tcp,
            self.source.clone(),
            self.host_resolver.clone(),
            self.tcp_connector.clone(),
            self.proxy_credentials.clone(),
        )
    }

    /// Returns an HTTP/1.1 connector, sharing this connector's TLS context
    /// and session cache, that offers `protocols` by ALPN.
    ///
    /// The ALPS offer is kept only while its protocol stays in `protocols`,
    /// as [`WebSocketConnectionPolicy::http1_tls_settings`] derives it. A
    /// connection from it can resume the TLS sessions this connector's
    /// connections were issued, as Chrome 154 keys its session cache without
    /// ALPN.
    ///
    /// [`WebSocketConnectionPolicy::http1_tls_settings`]: phantom_profile::WebSocketConnectionPolicy::http1_tls_settings
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError::MissingHttp1Alpn`] when `protocols` lacks
    /// `http/1.1`, and [`Http1TlsError::Tls`] when the list cannot be encoded.
    pub fn http1_connector(
        &self,
        protocols: &[Box<[u8]>],
    ) -> Result<Http1TlsConnector, Http1TlsError> {
        Http1TlsConnector::from_parts(
            self.tls.clone(),
            self.tcp,
            self.source.clone(),
            self.host_resolver.clone(),
            self.tcp_connector.clone(),
            self.proxy_credentials.clone(),
        )
        .with_write_strategy(self.http1_write_strategy)
        .with_alpn_protocols(protocols)
    }

    /// Returns a clone with a fresh isolated TLS session cache.
    #[must_use]
    pub fn with_isolated_session_cache(&self) -> Self {
        Self {
            tls: self.tls.with_isolated_session_cache(),
            http2: self.http2.clone(),
            http1_write_strategy: self.http1_write_strategy,
            tcp: self.tcp,
            source: self.source.clone(),
            host_resolver: self.host_resolver.clone(),
            tcp_connector: self.tcp_connector.clone(),
            proxy_credentials: self.proxy_credentials.clone(),
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

    /// Selects request-write buffering when TLS selects HTTP/1.1.
    ///
    /// Derived HTTP/1 Upgrade connectors keep this choice. HTTP/2 and proxy
    /// negotiation are unaffected. The default is Automatic.
    #[must_use]
    pub fn with_http1_write_strategy(mut self, strategy: crate::http1::Http1WriteStrategy) -> Self {
        self.http1_write_strategy = strategy;
        self
    }

    /// Applies TCP socket options to every direct TCP connection this
    /// connector opens.
    ///
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

    /// Opens one origin TLS connection and selects HTTP/1.1 or HTTP/2.
    ///
    /// Direct openings offer early data. Tunnels and caller-owned streams use
    /// ordinary TLS. A direct route can retain its slower address attempt.
    /// Plaintext origins are rejected before lookup polling or connection I/O.
    ///
    /// # Errors
    ///
    /// Returns an input, route, TLS, ALPN, ALPS, or protocol setup error.
    pub async fn connect(
        &self,
        route: OriginRoute<'_>,
    ) -> Result<
        (
            Http1Or2Connection,
            Option<SlowerConnection<Http1Or2Connection>>,
        ),
        Http1Or2TlsError,
    > {
        crate::destination_policy::check_origin(self.host_resolver.as_ref(), &route)
            .map_err(|error| Http1Or2TlsError::from_direct(DirectConnectError::Connect(error)))?;
        let server_name = match &route {
            OriginRoute::Tls { server_name, .. } => *server_name,
            OriginRoute::Plaintext { .. } => "",
        };
        let mut slower = None;
        #[cfg(feature = "https-records")]
        let mut selected_ech = None;
        let connection = self
            .trace_connect(pin!(async {
                route.validate(false, true).map_err(|error| {
                    Http1Or2TlsError::from_direct(DirectConnectError::Connect(error))
                })?;
                let route = match &self.tcp_connector {
                    Some(connector) => {
                        connector
                            .check_socket_policy(self.source.as_ref(), self.host_resolver.as_ref())
                            .map_err(|error| {
                                Http1Or2TlsError::from_direct(DirectConnectError::Connect(error))
                            })?;
                        connector.prepare(route).await.map_err(|error| {
                            Http1Or2TlsError::from_direct(DirectConnectError::Connect(error))
                        })?
                    }
                    None => route,
                };
                let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
                let OriginRoute::Tls {
                    tcp,
                    server_name,
                    setup,
                } = route
                else {
                    return Err(Http1Or2TlsError::from_direct(DirectConnectError::Connect(
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "negotiation requires origin TLS",
                        ),
                    )));
                };
                match (tcp, setup) {
                    (TcpRoute::Direct(endpoint), DirectTlsSetup::KeepSlower(family)) => {
                        let (stream, attempt) = connect_tcp_keeping_slower(
                            endpoint.host,
                            endpoint.port,
                            self.dialer(),
                            Some(family),
                        )
                        .await
                        .map_err(Http1Or2TlsError::from_direct)?;
                        slower = attempt;
                        let handshake = async {
                            let stream = self
                                .tls
                                .connect_offering_early_data(server_name, stream)
                                .await?;
                            select_connection(stream, client, self.http1_write_strategy).await
                        };
                        match slower.as_mut() {
                            Some(attempt) => attempt.alongside(handshake).await,
                            None => handshake.await,
                        }
                    }
                    #[cfg(feature = "https-records")]
                    (
                        TcpRoute::Direct(endpoint),
                        DirectTlsSetup::EchKeepingSlower { lookup, family },
                    ) => {
                        let (stream, attempt, selected) =
                            crate::direct::connect_tls_with_ech_retaining(
                                &self.tls,
                                self.dialer(),
                                endpoint,
                                server_name,
                                lookup,
                                crate::direct::EchEarlyData::Allowed,
                                Some(family),
                            )
                            .await?;
                        slower = attempt;
                        selected_ech = Some(selected);
                        let protocol = select_connection(stream, client, self.http1_write_strategy);
                        match slower.as_mut() {
                            Some(attempt) => attempt.alongside(protocol).await,
                            None => protocol.await,
                        }
                    }
                    #[cfg(feature = "https-records")]
                    (TcpRoute::Direct(_), DirectTlsSetup::EchRetry(retry)) => {
                        let stream =
                            crate::direct::retry_ech(&self.tls, self.dialer(), server_name, retry)
                                .await?;
                        select_connection(stream, client, self.http1_write_strategy).await
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
                            crate::direct::EchEarlyData::Allowed,
                        )
                        .await?;
                        select_connection(stream, client, self.http1_write_strategy).await
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
                        select_connection(stream, client, self.http1_write_strategy).await
                    }
                    _ => Err(Http1Or2TlsError::from_direct(DirectConnectError::Connect(
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidInput,
                            "direct TLS setup requires a direct route",
                        ),
                    ))),
                }
            }))
            .await?;
        let slower = slower
            .filter(|attempt| keeps_slower(&connection, attempt))
            .map(|attempt| {
                #[cfg(feature = "https-records")]
                if let Some(selected) = selected_ech {
                    return self.slower_connection_with_ech(attempt, server_name, selected);
                }
                self.slower_connection(attempt, server_name)
            });
        Ok((connection, slower))
    }

    /// Finishes the TLS handshake and protocol setup of a slower attempt's
    /// connection.
    ///
    /// The handshake is the one a request's connection makes, early data
    /// offered as the cached session allows. Firefox sets
    /// `SSL_ENABLE_0RTT_DATA` for every socket from one process default
    /// (`security/manager/ssl/nsNSSComponent.cpp:866-867` at tag
    /// `FIREFOX_157_0_RELEASE`). Its null transaction declines HTTP/1 early
    /// data, so nothing is written before the handshake ends
    /// (`netwerk/protocol/http/nsAHttpTransaction.h:215-217`,
    /// `netwerk/protocol/http/TlsHandshaker.cpp:305-320`), as no request is
    /// written here, and an early `h2` selection starts the HTTP/2 session as
    /// early data whatever the transaction (`TlsHandshaker.cpp:321-330`,
    /// `netwerk/protocol/http/nsHttpConnection.cpp:272-305`), as
    /// [`select_connection`] does for any connection.
    pub(crate) fn slower_connection(
        &self,
        attempt: SlowerAttempt,
        server_name: &str,
    ) -> SlowerConnection<Http1Or2Connection> {
        self.slower_connection_setup(
            attempt,
            server_name,
            #[cfg(feature = "https-records")]
            None,
        )
    }

    #[cfg(feature = "https-records")]
    pub(crate) fn slower_connection_with_ech(
        &self,
        attempt: SlowerAttempt,
        server_name: &str,
        selected: crate::direct::SelectedEch,
    ) -> SlowerConnection<Http1Or2Connection> {
        self.slower_connection_setup(attempt, server_name, Some(selected))
    }

    fn slower_connection_setup(
        &self,
        attempt: SlowerAttempt,
        server_name: &str,
        #[cfg(feature = "https-records")] selected: Option<crate::direct::SelectedEch>,
    ) -> SlowerConnection<Http1Or2Connection> {
        let tls = self.tls.clone();
        let strategy = self.http1_write_strategy;
        #[cfg(feature = "https-records")]
        let (tcp, source, resolver) = (self.tcp, self.source.clone(), self.host_resolver.clone());
        let http2 = self.http2.clone();
        let server_name = server_name.to_owned();
        SlowerConnection::new(attempt.progress(), async move {
            let client = translate_settings(&http2).ok()?;
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
                        .map_err(Http1Or2TlsError::from);
                }
                tls.connect_offering_early_data(&server_name, stream)
                    .await
                    .map_err(Http1Or2TlsError::from)
            };
            let stream = handshake
                .await
                .inspect_err(|error| debug!(error = %error, "slower connection handshake failed"))
                .ok()?;
            match select_connection(stream, client, strategy).await.ok()? {
                Http1Or2Connection::Http1(connection) => {
                    connection.early_data_answered().await;
                    if !connection.is_reusable() {
                        return None;
                    }
                    connection.report_idle();
                    Some(Http1Or2Connection::Http1(connection))
                }
                Http1Or2Connection::Http2(connection) => {
                    connection.early_data_answered().await;
                    connection
                        .is_reusable()
                        .then_some(Http1Or2Connection::Http2(connection))
                }
            }
        })
    }

    /// Runs `operation` in the connection span and records its outcome.
    ///
    /// The caller pins `operation` in its own future: an async function holds
    /// a future it takes by value twice, as the argument and as the awaited
    /// value, and this wrapper encloses a whole connection setup.
    ///
    /// A cancelled operation is dropped by its caller after this wrapper's
    /// future, so outside the span and after the span records cancellation.
    async fn trace_connect<F>(
        &self,
        operation: Pin<&mut F>,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError>
    where
        F: Future<Output = Result<Http1Or2Connection, Http1Or2TlsError>>,
    {
        let span = debug_span!(
            "http1_or_2.tls.connect",
            transport = "tls",
            negotiated_alpn = field::Empty,
            selected_protocol = field::Empty,
            outcome = field::Empty,
        );
        let outcome = ConnectOutcome::new(&span);
        let result = operation.instrument(span.clone()).await;
        outcome.finish(&result);
        result
    }
}

/// Whether the slower attempt of a backup connection is kept once the first
/// connection is set up: not when that connection selected HTTP/2 before the
/// attempt connected.
pub(crate) fn keeps_slower(first: &Http1Or2Connection, attempt: &SlowerAttempt) -> bool {
    !matches!(first, Http1Or2Connection::Http2(_)) || attempt.has_connected()
}

/// Starts the protocol TLS selected and reports it to the connection's
/// keepalive schedule, when there is one: HTTP/2 turns keepalive off, and
/// HTTP/1.1 reports each request.
async fn select_connection<S>(
    stream: crate::tls::TlsStream<S>,
    client: Http2Builder,
    strategy: crate::http1::Http1WriteStrategy,
) -> Result<Http1Or2Connection, Http1Or2TlsError>
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
    let metadata = stream.connection_metadata();
    let keepalive = stream.tcp_keepalive();
    let negotiated = stream.negotiated_alpn();
    Span::current().record("negotiated_alpn", trace_alpn(negotiated));
    match negotiated {
        Some(b"h2") => {
            Span::current().record("selected_protocol", "h2");
            debug!("TLS selected HTTP/2");
            if let Some(keepalive) = &keepalive {
                keepalive.http2_negotiated();
            }
            connect_selected(stream, client)
                .await
                .map(Http1Or2Connection::Http2)
                .map_err(Into::into)
        }
        Some(b"http/1.1") | None => {
            Span::current().record("selected_protocol", "http/1.1");
            debug!("TLS selected HTTP/1.1");
            let early_data = stream.early_data_wait();
            Http1Connection::connect_with_early_data(stream, early_data, keepalive, strategy)
                .await
                .map(|connection| connection.with_connection_metadata(metadata))
                .map(Http1Or2Connection::Http1)
                .map_err(Into::into)
        }
        Some(selected) => Err(Http1Or2TlsError::UnsupportedAlpn {
            selected: selected.into(),
        }),
    }
}

fn validate_settings(tls: &TlsSettings, http2: &Http2Settings) -> Result<(), Http1Or2TlsError> {
    require_alpn(tls, b"http/1.1", Http1Or2TlsError::MissingHttp1Alpn)?;
    require_alpn(tls, b"h2", Http1Or2TlsError::MissingHttp2Alpn)?;
    validate_http2(http2)?;
    Ok(())
}

fn require_alpn(
    settings: &TlsSettings,
    required: &[u8],
    error: Http1Or2TlsError,
) -> Result<(), Http1Or2TlsError> {
    settings
        .alpn_protocols
        .iter()
        .any(|protocol| protocol.as_ref() == required)
        .then_some(())
        .ok_or(error)
}

struct ConnectOutcome {
    span: Span,
    recorded: bool,
}

impl ConnectOutcome {
    fn new(span: &Span) -> Self {
        Self {
            span: span.clone(),
            recorded: false,
        }
    }

    fn finish(mut self, result: &Result<Http1Or2Connection, Http1Or2TlsError>) {
        let outcome = match result {
            Ok(_) => "ok",
            Err(Http1Or2TlsError::RuntimeUnavailable) => "runtime_unavailable",
            Err(Http1Or2TlsError::Connect(_)) => "connect_error",
            Err(
                Http1Or2TlsError::Proxy(_)
                | Http1Or2TlsError::Socks4Proxy(_)
                | Http1Or2TlsError::Socks5Proxy(_),
            ) => "proxy_error",
            Err(Http1Or2TlsError::Tls(_)) => "tls_error",
            Err(Http1Or2TlsError::Http1(_)) => "http1_error",
            Err(Http1Or2TlsError::Http2(_)) => "http2_error",
            Err(Http1Or2TlsError::UnsupportedAlpn { .. }) => "unsupported_alpn",
            Err(Http1Or2TlsError::MissingHttp1Alpn | Http1Or2TlsError::MissingHttp2Alpn) => {
                "invalid_configuration"
            }
        };
        self.span.record("outcome", outcome);
        self.recorded = true;
    }
}

impl Drop for ConnectOutcome {
    fn drop(&mut self) {
        if !self.recorded {
            let outcome = if std::thread::panicking() {
                "panicked"
            } else {
                "cancelled"
            };
            self.span.record("outcome", outcome);
        }
    }
}

fn quiet_socks_invalid_route(message: &'static str) -> Http1Or2TlsError {
    Http1Or2TlsError::from_direct(DirectConnectError::Connect(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    )))
}

#[cfg(test)]
mod tests;
