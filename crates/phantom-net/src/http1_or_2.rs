//! One-handshake HTTP/1.1 or HTTP/2 selection over TLS ALPN.

use std::{error::Error as StdError, fmt, future::Future};

use phantom_profile::{Http2Settings, TcpSettings, TlsSettings};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, Span, debug, debug_span, field};

use crate::{
    direct::{Dialer, DirectConnectError, connect_tcp},
    host_resolver::HostResolver,
    http1::{Http1Connection, Http1Error},
    http2::{
        Http2Connection, Http2TlsConnector, Http2TlsError, connect_selected, translate_settings,
        validate_http2,
    },
    proxy::{
        HttpBasicCredentials, HttpConnectError, HttpConnectHeader, HttpsProxyConnector,
        ProxyCredentialCache, Socks5Auth, Socks5Error, http_connect_tunnel,
        http_connect_tunnel_with_basic_auth, socks5_tunnel_local_dns, socks5_tunnel_remote_dns,
    },
    tls::{TlsConnector, TlsError, trace_alpn},
};

pub use crate::tls::EchFailure;

/// An established connection selected from one TLS ALPN negotiation.
#[derive(Debug)]
pub enum Http1Or2Connection {
    /// HTTP/1.1 was selected, or the peer did not negotiate ALPN.
    Http1(Http1Connection),
    /// The peer selected exact `h2`.
    Http2(Http2Connection),
}

/// Stable category of HTTP/1.1-or-HTTP/2 connection failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Http1Or2TlsErrorKind {
    /// The request lacks a Tokio runtime with network I/O enabled.
    RuntimeUnavailable,
    /// Establishing the direct TCP connection failed.
    Connect,
    /// The HTTP proxy leg or its CONNECT request failed before origin TLS.
    HttpProxy,
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
pub enum Http1Or2TlsError {
    /// The network operation was polled without a Tokio I/O runtime.
    RuntimeUnavailable,
    /// Establishing the direct TCP connection failed.
    Connect(std::io::Error),
    /// The HTTP proxy connection, its TLS, authentication, or CONNECT request
    /// failed.
    Proxy(HttpConnectError),
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
            Self::Connect(error) => write!(formatter, "TCP connection failed: {error}"),
            Self::Proxy(error) => write!(formatter, "HTTP proxy failed: {error}"),
            Self::Socks5Proxy(error) => write!(formatter, "SOCKS5 proxy failed: {error}"),
            Self::Tls(error) => write!(formatter, "TLS connection failed: {error}"),
            Self::Http1(error) => write!(formatter, "HTTP/1.1 connection failed: {error}"),
            Self::Http2(error) => write!(formatter, "HTTP/2 connection failed: {error}"),
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

impl From<HttpConnectError> for Http1Or2TlsError {
    fn from(error: HttpConnectError) -> Self {
        Self::Proxy(error)
    }
}

impl From<Socks5Error> for Http1Or2TlsError {
    fn from(error: Socks5Error) -> Self {
        Self::Socks5Proxy(error)
    }
}

impl From<TlsError> for Http1Or2TlsError {
    fn from(error: TlsError) -> Self {
        Self::Tls(error)
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
    tcp: Option<TcpSettings>,
    host_resolver: Option<HostResolver>,
    proxy_credentials: Option<ProxyCredentialCache>,
}

impl Http1Or2TlsConnector {
    /// Builds a connector using bundled public roots.
    ///
    /// Both `h2` and `http/1.1` must be present in the TLS ALPN offer.
    pub fn new(tls: &TlsSettings, http2: &Http2Settings) -> Result<Self, Http1Or2TlsError> {
        validate_settings(tls, http2)?;
        Ok(Self {
            tls: TlsConnector::new(tls)?,
            http2: http2.clone(),
            tcp: None,
            host_resolver: None,
            proxy_credentials: None,
        })
    }

    /// Builds a connector with bundled roots plus additional DER certificates.
    pub fn new_with_additional_roots<'a>(
        tls: &TlsSettings,
        http2: &Http2Settings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, Http1Or2TlsError> {
        validate_settings(tls, http2)?;
        Ok(Self {
            tls: TlsConnector::new_with_additional_roots(tls, roots)?,
            http2: http2.clone(),
            tcp: None,
            host_resolver: None,
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
            tcp: connector.tcp_settings().copied(),
            host_resolver: connector.host_resolver().cloned(),
            proxy_credentials: connector.proxy_credential_cache().cloned(),
        })
    }

    /// Returns a clone with a fresh isolated TLS session cache.
    #[must_use]
    pub fn with_isolated_session_cache(&self) -> Self {
        Self {
            tls: self.tls.with_isolated_session_cache(),
            http2: self.http2.clone(),
            tcp: self.tcp,
            host_resolver: self.host_resolver.clone(),
            proxy_credentials: self.proxy_credentials.clone(),
        }
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

    /// Opens one direct TCP connection and selects HTTP/1.1 or HTTP/2 over
    /// TLS, offering Encrypted Client Hello with the `ECHConfigList` that
    /// `ech` yields, as Chrome 154 does for an origin's HTTPS record.
    ///
    /// The host is resolved first; the TCP connect then runs while `ech`
    /// finishes. The ClientHello waits for `ech` at most 20% of the address
    /// resolution time, clamped to 5-50 ms, counted from when the addresses
    /// arrived; `ech` still pending then counts as `None`. With `None` the
    /// handshake is the one [`Self::connect_direct`] makes.
    ///
    /// A list the TLS client rejects fails with
    /// [`EchFailure::InvalidConfigList`] before any TLS byte is sent. When
    /// the server rejects ECH and authenticates as the public name, this
    /// connects once more to the same address, offering the server's retry
    /// configurations, or ECH GREASE and the true server name when it sent
    /// none. A second rejection fails with [`EchFailure::Rejected`].
    ///
    /// # Errors
    ///
    /// Returns [`Http1Or2TlsError`] for runtime, connection, TLS, ECH, ALPN,
    /// ALPS, or protocol setup failures.
    #[cfg(feature = "https-records")]
    pub async fn connect_direct_with_ech(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        ech: impl Future<Output = Option<crate::dns::EchConfigList>>,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
            let (stream, list) =
                crate::direct::connect_tcp_with_lookup(host, port, self.dialer(), ech)
                    .await
                    .map_err(Http1Or2TlsError::from_direct)?;
            if let Some(Err(error)) = list.as_ref().map(crate::dns::EchConfigList::parse) {
                return Err(Http1Or2TlsError::Tls(TlsError::invalid_ech_config_list(
                    error,
                )));
            }
            let address = stream.peer_addr().map_err(Http1Or2TlsError::Connect)?;
            let offered = list.as_ref().map(crate::dns::EchConfigList::as_bytes);
            let stream = match self
                .tls
                .connect_with_ech(server_name, stream, offered)
                .await
            {
                Ok(stream) => stream,
                Err(mut error) if error.ech_failure() == Some(EchFailure::Rejected) => {
                    let retry_configs = error.take_ech_retry_configs();
                    debug!(
                        retry_configs = retry_configs.is_some(),
                        "server rejected ECH; connecting once more"
                    );
                    let stream = crate::direct::connect_tcp_address(address, self.tcp)
                        .await
                        .map_err(Http1Or2TlsError::from_direct)?;
                    self.tls
                        .connect_with_ech(server_name, stream, retry_configs.as_deref())
                        .await?
                }
                Err(error) => return Err(error.into()),
            };
            select_connection(stream, client).await
        })
        .await
    }

    /// Selects HTTP/1.1 or HTTP/2 over an already-connected stream.
    ///
    /// This performs exactly one TLS handshake. `h2` enters HTTP/2;
    /// `http/1.1` or absent ALPN enters HTTP/1.1. No protocol retry or fallback
    /// is attempted after selection.
    ///
    /// # Errors
    ///
    /// Returns [`Http1Or2TlsError`] for TLS, ALPN, ALPS, or protocol setup
    /// failures.
    pub async fn connect<S>(
        &self,
        stream: S,
        server_name: &str,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.trace_connect(async {
            let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
            let stream = self.tls.connect(server_name, stream).await?;
            select_connection(stream, client).await
        })
        .await
    }

    /// Opens one direct TCP connection and selects HTTP/1.1 or HTTP/2 over TLS.
    ///
    /// HTTP/2 settings are prepared before DNS resolution or network I/O.
    ///
    /// # Errors
    ///
    /// Returns [`Http1Or2TlsError`] for runtime, connection, TLS, ALPN, ALPS,
    /// or protocol setup failures.
    pub async fn connect_direct(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
            let stream = connect_tcp(host, port, self.dialer())
                .await
                .map_err(Http1Or2TlsError::from_direct)?;
            let stream = self.tls.connect(server_name, stream).await?;
            select_connection(stream, client).await
        })
        .await
    }

    /// Tunnels through a plaintext HTTP proxy with one HTTP/1.1 CONNECT, then
    /// selects HTTP/1.1 or HTTP/2 over origin TLS.
    ///
    /// The CONNECT request is validated before DNS resolution or TCP I/O, and
    /// the proxy leg uses this connector's TCP settings. `server_name` controls
    /// origin certificate verification and SNI. The origin TLS handshake runs
    /// once inside the tunnel. Proxy or negotiation failure never falls back
    /// to a direct connection, another ALPN offer, or another HTTP protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Http1Or2TlsError`] for runtime, proxy, TLS, ALPN, ALPS, or
    /// protocol setup failures.
    pub async fn connect_http_connect(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        server_name: &str,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
            let stream = http_connect_tunnel(
                self.dialer(),
                proxy_host,
                proxy_port,
                connect_authority,
                connect_headers,
            )
            .await?;
            let stream = self.tls.connect(server_name, stream).await?;
            select_connection(stream, client).await
        })
        .await
    }

    /// Tunnels through a plaintext HTTP proxy using challenge-driven Basic
    /// authentication, then selects HTTP/1.1 or HTTP/2 over origin TLS.
    ///
    /// The first CONNECT omits credentials. After a valid Basic challenge the
    /// CONNECT is sent once more, with credentials, on a fresh proxy
    /// connection. Otherwise this behaves as [`Self::connect_http_connect`].
    ///
    /// # Errors
    ///
    /// Returns [`Http1Or2TlsError`] for runtime, proxy, authentication, TLS,
    /// ALPN, ALPS, or protocol setup failures.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_http_connect_with_basic_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
        server_name: &str,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
            let stream = http_connect_tunnel_with_basic_auth(
                self.dialer(),
                self.proxy_credentials.as_ref(),
                proxy_host,
                proxy_port,
                connect_authority,
                connect_headers,
                credentials,
            )
            .await?;
            let stream = self.tls.connect(server_name, stream).await?;
            select_connection(stream, client).await
        })
        .await
    }

    /// Tunnels through an HTTPS proxy with `proxy_connector`, then selects
    /// HTTP/1.1 or HTTP/2 over origin TLS inside the tunnel.
    ///
    /// The proxy connector owns the proxy TLS offer, trust roots, proxy
    /// protocol, and proxy-leg TCP settings. The origin handshake uses this
    /// connector's TLS settings and `server_name`, once. Failure never falls
    /// back to a direct connection, another ALPN offer, or another HTTP
    /// protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Http1Or2TlsError`] for runtime, proxy, TLS, ALPN, ALPS, or
    /// protocol setup failures.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_https_connect(
        &self,
        proxy_connector: &HttpsProxyConnector,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        server_name: &str,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
            let stream = proxy_connector
                .connect_tunnel(
                    proxy_host,
                    proxy_port,
                    proxy_server_name,
                    connect_authority,
                    connect_headers,
                )
                .await?;
            let stream = self.tls.connect(server_name, stream).await?;
            select_connection(stream, client).await
        })
        .await
    }

    /// Tunnels through an HTTPS proxy using challenge-driven Basic
    /// authentication, then selects HTTP/1.1 or HTTP/2 over origin TLS.
    ///
    /// Otherwise this behaves as [`Self::connect_https_connect`].
    ///
    /// # Errors
    ///
    /// Returns [`Http1Or2TlsError`] for runtime, proxy, authentication, TLS,
    /// ALPN, ALPS, or protocol setup failures.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_https_connect_with_basic_auth(
        &self,
        proxy_connector: &HttpsProxyConnector,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
        server_name: &str,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
            let stream = proxy_connector
                .connect_tunnel_with_basic_auth(
                    proxy_host,
                    proxy_port,
                    proxy_server_name,
                    connect_authority,
                    connect_headers,
                    credentials,
                )
                .await?;
            let stream = self.tls.connect(server_name, stream).await?;
            select_connection(stream, client).await
        })
        .await
    }

    /// Tunnels through a SOCKS5 proxy that resolves the target, then selects
    /// HTTP/1.1 or HTTP/2 over TLS.
    ///
    /// The target host is sent to the proxy as a SOCKS5 `DOMAIN` address and
    /// is never resolved locally. `server_name` still controls certificate
    /// verification and SNI, so the origin keeps its own identity. Proxy
    /// failure never falls back to a direct connection or another HTTP
    /// protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Http1Or2TlsError`] for runtime, proxy, TLS, ALPN, ALPS, or
    /// protocol setup failures.
    pub async fn connect_socks5_remote_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        server_name: &str,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
            let stream = socks5_tunnel_remote_dns(
                self.dialer(),
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            let stream = self.tls.connect(server_name, stream).await?;
            select_connection(stream, client).await
        })
        .await
    }

    /// Tunnels through a SOCKS5 proxy to a locally resolved target, then
    /// selects HTTP/1.1 or HTTP/2 over TLS.
    ///
    /// The target is resolved locally and the selected address is sent as a
    /// SOCKS5 `IPV4` or `IPV6` target. `server_name` still controls
    /// certificate verification and SNI. Proxy failure never falls back to a
    /// direct connection or another HTTP protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Http1Or2TlsError`] for runtime, resolution, proxy, TLS, ALPN,
    /// ALPS, or protocol setup failures.
    pub async fn connect_socks5_local_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        server_name: &str,
    ) -> Result<Http1Or2Connection, Http1Or2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2).map_err(Http2TlsError::from)?;
            let stream = socks5_tunnel_local_dns(
                self.dialer(),
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            let stream = self.tls.connect(server_name, stream).await?;
            select_connection(stream, client).await
        })
        .await
    }

    async fn trace_connect<F>(&self, operation: F) -> Result<Http1Or2Connection, Http1Or2TlsError>
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

async fn select_connection<S>(
    stream: crate::tls::TlsStream<S>,
    client: ::http2::client::Builder,
) -> Result<Http1Or2Connection, Http1Or2TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let negotiated = stream.negotiated_alpn();
    Span::current().record("negotiated_alpn", trace_alpn(negotiated));
    match negotiated {
        Some(b"h2") => {
            Span::current().record("selected_protocol", "h2");
            debug!("TLS selected HTTP/2");
            connect_selected(stream, client)
                .await
                .map(Http1Or2Connection::Http2)
                .map_err(Into::into)
        }
        Some(b"http/1.1") | None => {
            Span::current().record("selected_protocol", "http/1.1");
            debug!("TLS selected HTTP/1.1");
            Http1Connection::connect(stream)
                .await
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
            Err(Http1Or2TlsError::Proxy(_) | Http1Or2TlsError::Socks5Proxy(_)) => "proxy_error",
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

#[cfg(test)]
mod tests;
