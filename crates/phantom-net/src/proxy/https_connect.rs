use std::{
    fmt,
    future::Future,
    io,
    pin::Pin,
    sync::{Mutex, PoisonError},
    task::{Context, Poll},
};

use phantom_profile::{Http2RejectedConnect, Http2Settings, TcpSettings, TlsSettings};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{
    AuthStep, BasicAuthPlan, HttpBasicCredentials, HttpConnectError, HttpConnectHeader,
    ProxyCredentialCache, ProxyScheme, TunnelStream,
    http_connect::{
        PreparedBasicConnect, PreparedConnect, basic_auth_exchange, establish,
        record_authentication_attempts, trace_connect,
    },
    http2_connect::{
        self, Http2ChallengeOutcome, Http2Replay, PreparedBasicHttp2Connect, PreparedHttp2Connect,
    },
    http2_pool::{ConnectionSettingsId, Http2ProxyPool, PooledConnection, RouteKey},
};
use crate::{
    direct::{Dialer, DirectConnectError, connect_tcp},
    host_resolver::HostResolver,
    http2::{
        Http2Builder, Http2ConnectStream, Http2Connection, Http2RejectedStream, Http2TlsError,
        connect_selected, connect_selected_extended, translate_extended_connect_settings,
        translate_settings, validate_http2,
    },
    tls::{ServerAuthentication, TlsConnector, TlsStream},
};

/// Application protocol spoken to an HTTPS proxy after its TLS handshake.
///
/// The proxy-facing ClientHello offers the TLS settings' ALPN list unchanged
/// in every mode. The selected protocol must match this value exactly; any
/// other selection is an [`HttpConnectError::UnsupportedAlpn`] error and never
/// switches protocols.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum HttpsProxyProtocol {
    /// HTTP/1.1 CONNECT and absolute-form forwarding.
    ///
    /// The proxy must select `http/1.1` or omit ALPN.
    #[default]
    Http1,
    /// RFC 9113 section 8.5 CONNECT, and HTTP/2 forwarding of plaintext
    /// `http://` requests.
    ///
    /// Each tunnel is a stream of a connection from the connector's
    /// [`Http2ProxyPool`], or of its own connection when none is attached.
    /// The proxy must select `h2`. HTTP/1.1 absolute-form forwarding is not
    /// available in this mode.
    Http2,
}

/// Reusable TLS configuration for forwarding or CONNECT through an HTTPS proxy.
///
/// The default [`HttpsProxyProtocol::Http1`] mode supports HTTP/1.1 forwarding
/// and CONNECT. [`HttpsProxyProtocol::Http2`] supports CONNECT and HTTP/2
/// forwarding through [`Self::connect_forward_http2`].
#[derive(Clone, Debug)]
pub struct HttpsProxyConnector {
    tls: TlsConnector,
    offers_h2: bool,
    http2: Option<Http2Settings>,
    http2_rejected: Http2RejectedConnect,
    protocol: HttpsProxyProtocol,
    tcp: Option<TcpSettings>,
    host_resolver: Option<HostResolver>,
    proxy_credentials: Option<ProxyCredentialCache>,
    http2_pool: Option<Http2ProxyPool>,
    /// Replaced whenever a setting that shapes a proxy connection changes,
    /// so a shared pool keeps connections opened with other settings apart.
    connection_settings: ConnectionSettingsId,
}

impl HttpsProxyConnector {
    /// Builds a connector from TLS settings and bundled public roots.
    pub fn new(settings: &TlsSettings) -> Result<Self, HttpConnectError> {
        require_http1_alpn(settings)?;
        TlsConnector::new(settings)
            .map(|tls| Self::from_tls(tls, settings))
            .map_err(HttpConnectError::ProxyTls)
    }

    /// Builds a connector with bundled public roots and additional DER certificates.
    pub fn new_with_additional_roots<'a>(
        settings: &TlsSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, HttpConnectError> {
        require_http1_alpn(settings)?;
        TlsConnector::new_with_additional_roots(settings, roots)
            .map(|tls| Self::from_tls(tls, settings))
            .map_err(HttpConnectError::ProxyTls)
    }

    /// Builds a connector with an explicit server-authentication policy.
    pub fn new_with_server_authentication(
        settings: &TlsSettings,
        server_authentication: ServerAuthentication,
    ) -> Result<Self, HttpConnectError> {
        require_http1_alpn(settings)?;
        TlsConnector::new_with_server_authentication(settings, server_authentication)
            .map(|tls| Self::from_tls(tls, settings))
            .map_err(HttpConnectError::ProxyTls)
    }

    fn from_tls(tls: TlsConnector, settings: &TlsSettings) -> Self {
        Self {
            tls,
            offers_h2: settings
                .alpn_protocols
                .iter()
                .any(|protocol| protocol.as_ref() == b"h2"),
            http2: None,
            http2_rejected: Http2RejectedConnect::default(),
            protocol: HttpsProxyProtocol::Http1,
            tcp: None,
            host_resolver: None,
            proxy_credentials: None,
            http2_pool: None,
            connection_settings: ConnectionSettingsId::default(),
        }
    }

    /// Supplies the HTTP/2 SETTINGS, priority, and pseudo-header order used
    /// when this connector speaks HTTP/2 to the proxy.
    ///
    /// The settings are validated before proxy I/O when an HTTP/2 tunnel is
    /// opened. They have no effect in [`HttpsProxyProtocol::Http1`] mode.
    #[must_use]
    pub fn with_http2_settings(mut self, settings: &Http2Settings) -> Self {
        self.http2 = Some(settings.clone());
        self.connection_settings = ConnectionSettingsId::default();
        self
    }

    /// Chooses what an HTTP/2 CONNECT sends on a stream the proxy rejected,
    /// such as a challenged one, before the replay on the same connection.
    ///
    /// The default, [`Http2RejectedConnect::EndStream`], is what Chrome 154
    /// and Edge 154 send. It has no effect in [`HttpsProxyProtocol::Http1`]
    /// mode.
    #[must_use]
    pub fn with_http2_rejected_connect(mut self, rejected: Http2RejectedConnect) -> Self {
        self.http2_rejected = rejected;
        self
    }

    /// Applies TCP socket options to every connection this connector opens
    /// to an HTTPS proxy.
    ///
    /// The settings are checked before any DNS or socket I/O. Invalid
    /// settings fail each connection attempt with
    /// [`std::io::ErrorKind::InvalidInput`], and settings this host cannot
    /// apply exactly (see [`crate::tcp::check_host_support`]) with
    /// [`std::io::ErrorKind::Unsupported`].
    #[must_use]
    pub fn with_tcp_settings(mut self, settings: &TcpSettings) -> Self {
        self.tcp = Some(*settings);
        self.connection_settings = ConnectionSettingsId::default();
        self
    }

    /// Sends Basic credentials on the first CONNECT to a proxy that accepted
    /// them before, as recorded in `cache`.
    ///
    /// Without a cache, every challenge-driven exchange starts without
    /// credentials. Clones of this connector share `cache`.
    #[must_use]
    pub fn with_proxy_credential_cache(mut self, cache: ProxyCredentialCache) -> Self {
        self.proxy_credentials = Some(cache);
        self
    }

    /// Opens HTTP/2 tunnels as streams of connections from `pool`, as
    /// browsers do, instead of one connection per tunnel.
    ///
    /// A tunnel shares a connection only with tunnels to the same proxy
    /// host, port, and server name, for the same Basic credentials or none,
    /// from a connector with the same TLS, TCP, HTTP/2, and name-resolution
    /// settings: changing one of those on a clone keeps its connections
    /// apart. [`Self::connect_forward_http2_with_credentials`] draws from the
    /// same pool. Clones of this connector, including
    /// [`Self::with_isolated_session_cache`], share `pool`. It has no effect
    /// in [`HttpsProxyProtocol::Http1`] mode.
    #[must_use]
    pub fn with_http2_proxy_pool(mut self, pool: Http2ProxyPool) -> Self {
        self.http2_pool = Some(pool);
        self
    }

    /// Returns the TCP socket options applied to proxy connections, if any.
    #[must_use]
    pub fn tcp_settings(&self) -> Option<&TcpSettings> {
        self.tcp.as_ref()
    }

    /// Resolves host names through `resolver` instead of asking the operating
    /// system for every connection.
    ///
    /// The resolver covers the HTTPS proxy's host. A target that a proxy
    /// resolves is never looked up locally. Clones of this connector share
    /// `resolver`.
    #[must_use]
    pub fn with_host_resolver(mut self, resolver: HostResolver) -> Self {
        self.host_resolver = Some(resolver);
        self.connection_settings = ConnectionSettingsId::default();
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

    /// Queues the TLS secrets of this connector's connections to `sender`.
    ///
    /// Clones share the TLS context and its key log. The first sender
    /// attached is kept.
    #[cfg(feature = "keylog")]
    pub fn attach_key_log(&self, sender: &crate::NssKeyLogSender) {
        self.tls.key_log().attach(sender);
    }

    /// Selects the application protocol spoken to the proxy.
    ///
    /// Configuration conflicts, such as HTTP/2 without an `h2` ALPN offer or
    /// HTTP/2 settings, are reported before proxy I/O.
    #[must_use]
    pub fn with_protocol(mut self, protocol: HttpsProxyProtocol) -> Self {
        self.protocol = protocol;
        self
    }

    /// Returns the application protocol spoken to the proxy.
    #[must_use]
    pub fn protocol(&self) -> HttpsProxyProtocol {
        self.protocol
    }

    /// Returns a connector clone with a fresh isolated TLS session cache.
    ///
    /// The clone keeps this connector's [`Http2ProxyPool`], so its HTTP/2
    /// tunnels may use a connection this connector opened.
    #[must_use]
    pub fn with_isolated_session_cache(&self) -> Self {
        Self {
            tls: self.tls.with_isolated_session_cache(),
            offers_h2: self.offers_h2,
            http2: self.http2.clone(),
            http2_rejected: self.http2_rejected,
            protocol: self.protocol,
            tcp: self.tcp,
            host_resolver: self.host_resolver.clone(),
            proxy_credentials: self.proxy_credentials.clone(),
            http2_pool: self.http2_pool.clone(),
            connection_settings: self.connection_settings.clone(),
        }
    }

    pub(crate) async fn connect_forward(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
    ) -> Result<TlsStream<tokio::net::TcpStream>, HttpConnectError> {
        if self.protocol != HttpsProxyProtocol::Http1 {
            return Err(HttpConnectError::ForwardingRequiresHttp1);
        }
        self.connect_http1_proxy(proxy_host, proxy_port, proxy_server_name)
            .await
    }

    /// Returns an HTTP/2 connection to the proxy for forwarding plaintext
    /// `http://` requests that carry no proxy credentials.
    ///
    /// The same as [`Self::connect_forward_http2_with_credentials`] without
    /// credentials.
    ///
    /// # Errors
    ///
    /// As for [`Self::connect_forward_http2_with_credentials`].
    pub async fn connect_forward_http2(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
    ) -> Result<Http2Connection, HttpConnectError> {
        self.connect_forward_http2_with_credentials(proxy_host, proxy_port, proxy_server_name, None)
            .await
    }

    /// Returns an HTTP/2 connection to the proxy for forwarding plaintext
    /// `http://` requests that carry `credentials`.
    ///
    /// The connection uses this connector's TLS offer and HTTP/2 settings, so
    /// its SETTINGS, priority, pseudo-header order, and HPACK choices are the
    /// profile's. Send requests on it with
    /// [`Http2Connection::send_forward_request_body_with_trailers`]. The proxy
    /// must select `h2`; any other ALPN result is an error, never a switch to
    /// HTTP/1.1.
    ///
    /// This call sends no credentials. With an [`Http2ProxyPool`] attached,
    /// `credentials` choose which pooled connection is returned, one that
    /// tunnels and other forwarding for the same credentials may also use.
    /// The caller must send exactly these credentials, or none when it passes
    /// `None`, on every request it forwards on the connection, so that a
    /// connection never carries another route's credentials. Without a pool,
    /// every call opens a connection.
    ///
    /// # Errors
    ///
    /// Returns [`HttpConnectError::ForwardingRequiresHttp2`] in
    /// [`HttpsProxyProtocol::Http1`] mode and a configuration error for a
    /// missing `h2` offer or HTTP/2 settings, all before proxy I/O; otherwise
    /// a connect, TLS, ALPN, or HTTP/2 setup error.
    pub async fn connect_forward_http2_with_credentials(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        credentials: Option<&HttpBasicCredentials>,
    ) -> Result<Http2Connection, HttpConnectError> {
        if self.protocol != HttpsProxyProtocol::Http2 {
            return Err(HttpConnectError::ForwardingRequiresHttp2);
        }
        self.http2_builder()?;
        let target = ProxyTarget {
            host: proxy_host,
            port: proxy_port,
            server_name: proxy_server_name,
            credentials,
        };
        // The pool counts tunnels only; forwarded requests are short.
        Ok(self.http2_connection(&target).await?.into_connection())
    }

    pub(crate) async fn connect_tunnel(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        authority: &str,
        headers: &[HttpConnectHeader],
    ) -> Result<HttpsProxyTunnel, HttpConnectError> {
        match self.protocol {
            HttpsProxyProtocol::Http1 => trace_connect("https", async {
                let request = PreparedConnect::new(authority, headers)?;
                let stream = self
                    .connect_http1_proxy(proxy_host, proxy_port, proxy_server_name)
                    .await?;
                establish(stream, request).await
            })
            .await
            .map(HttpsProxyTunnel::http1),
            HttpsProxyProtocol::Http2 => trace_connect("https_h2", async {
                let request = &PreparedHttp2Connect::new(authority, headers)?;
                self.http2_builder()?;
                let target = ProxyTarget {
                    host: proxy_host,
                    port: proxy_port,
                    server_name: proxy_server_name,
                    credentials: None,
                };
                let rejected = self.http2_rejected;
                let (mut stream, connection) = self
                    .on_http2_connection(&target, |connection| async move {
                        http2_connect::establish(&connection, request, rejected).await
                    })
                    .await?;
                connection.attach(&mut stream);
                Ok(stream)
            })
            .await
            .map(HttpsProxyTunnel::http2),
        }
    }

    pub(crate) async fn connect_tunnel_with_basic_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        authority: &str,
        headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
    ) -> Result<HttpsProxyTunnel, HttpConnectError> {
        let plan = BasicAuthPlan::new(
            self.proxy_credentials.as_ref(),
            ProxyScheme::Https,
            proxy_host,
            proxy_port,
            credentials,
        );
        match self.protocol {
            HttpsProxyProtocol::Http1 => trace_connect("https", async {
                let requests = PreparedBasicConnect::new(authority, headers, credentials)?;
                basic_auth_exchange(&plan, &requests, || {
                    self.connect_http1_proxy(proxy_host, proxy_port, proxy_server_name)
                })
                .await
            })
            .await
            .map(HttpsProxyTunnel::http1),
            HttpsProxyProtocol::Http2 => trace_connect("https_h2", async {
                let requests = PreparedBasicHttp2Connect::new(authority, headers, credentials)?;
                self.http2_builder()?;
                let target = ProxyTarget {
                    host: proxy_host,
                    port: proxy_port,
                    server_name: proxy_server_name,
                    credentials: Some(credentials),
                };
                self.http2_basic_auth_exchange(&plan, &requests, &target)
                    .await
            })
            .await
            .map(HttpsProxyTunnel::http2),
        }
    }

    /// Runs one challenge-driven HTTP/2 CONNECT exchange.
    ///
    /// The replay after a `407` is a new stream on the challenged connection,
    /// and moves to another connection only when the proxy closed or refused
    /// it before processing the replay.
    async fn http2_basic_auth_exchange(
        &self,
        plan: &BasicAuthPlan<'_>,
        requests: &PreparedBasicHttp2Connect,
        target: &ProxyTarget<'_>,
    ) -> Result<Http2ConnectStream, HttpConnectError> {
        let rejected = self.http2_rejected;
        // The connection that carried a `407`, and its challenged stream when
        // the profile leaves it open.
        let challenged = Mutex::new(None::<(TunnelConnection, Option<Http2RejectedStream>)>);
        plan.run(
            |attempt| {
                let challenged = &challenged;
                async move {
                    record_authentication_attempts(attempt, plan.preemptive());
                    let authenticated = &requests.authenticated;
                    if attempt.is_retry() {
                        let kept = challenged
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner)
                            .take();
                        if let Some((connection, held)) = kept {
                            match http2_connect::replay_on_challenged(
                                connection.connection(),
                                authenticated,
                                rejected,
                            )
                            .await
                            {
                                Http2Replay::Answered(result) => {
                                    return result.map(|mut stream| {
                                        if let Some(held) = held {
                                            stream.hold_rejected_stream(held);
                                        }
                                        connection.attach(&mut stream);
                                        AuthStep::Done(stream)
                                    });
                                }
                                // The proxy closed or refused this connection,
                                // so no later tunnel is handed it.
                                Http2Replay::Unprocessed => connection.retire(),
                            }
                        }
                        // The replay's last send: unlike a first attempt, it
                        // is not sent again when this connection also leaves
                        // it unprocessed.
                        let connection = self.http2_connection(target).await?;
                        let mut stream = http2_connect::establish_authenticated(
                            connection.connection(),
                            authenticated,
                            rejected,
                        )
                        .await?;
                        connection.attach(&mut stream);
                        return Ok(AuthStep::Done(stream));
                    }
                    let request = if attempt.sends_credentials() {
                        authenticated
                    } else {
                        &requests.anonymous
                    };
                    let (outcome, connection) = self
                        .on_http2_connection(target, |connection| async move {
                            http2_connect::establish_challenge(&connection, request, rejected).await
                        })
                        .await?;
                    Ok(match outcome {
                        Http2ChallengeOutcome::Tunnel(mut stream) => {
                            connection.attach(&mut stream);
                            AuthStep::Done(stream)
                        }
                        Http2ChallengeOutcome::Retry(held) => {
                            *challenged.lock().unwrap_or_else(PoisonError::into_inner) =
                                Some((connection, held));
                            AuthStep::Challenged
                        }
                    })
                }
            },
            HttpConnectError::is_challenge_failure,
            || HttpConnectError::AuthenticationRejected,
        )
        .await
    }

    /// Returns the connection one HTTP/2 tunnel or forwarding caller uses: a
    /// pooled one when a pool is attached, otherwise a new one.
    async fn http2_connection(
        &self,
        target: &ProxyTarget<'_>,
    ) -> Result<TunnelConnection, HttpConnectError> {
        let open = || self.connect_http2_proxy(target.host, target.port, target.server_name);
        match &self.http2_pool {
            Some(pool) => {
                let key = RouteKey::new(
                    &self.connection_settings,
                    target.host,
                    target.port,
                    target.server_name,
                    target.credentials,
                );
                pool.acquire(key, open).await.map(TunnelConnection::Pooled)
            }
            None => open().await.map(TunnelConnection::Dedicated),
        }
    }

    /// Runs one CONNECT exchange on the connection
    /// [`Self::http2_connection`] returns.
    ///
    /// When the proxy did not process the CONNECT on a connection that had
    /// carried streams before, such as after a `GOAWAY` that crossed it, the
    /// connection is retired and the exchange runs once more on another.
    async fn on_http2_connection<T, F, Fut>(
        &self,
        target: &ProxyTarget<'_>,
        exchange: F,
    ) -> Result<(T, TunnelConnection), HttpConnectError>
    where
        F: Fn(Http2Connection) -> Fut,
        Fut: Future<Output = Result<T, HttpConnectError>>,
    {
        let connection = self.http2_connection(target).await?;
        match exchange(connection.connection().clone()).await {
            Err(HttpConnectError::ProxyHttp2(error))
                if connection.is_reused() && http2_connect::is_unprocessed(&error) =>
            {
                connection.retire();
                drop(connection);
                let connection = self.http2_connection(target).await?;
                let value = exchange(connection.connection().clone()).await?;
                Ok((value, connection))
            }
            result => result.map(|value| (value, connection)),
        }
    }

    async fn connect_proxy_tls(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
    ) -> Result<TlsStream<tokio::net::TcpStream>, HttpConnectError> {
        let stream = connect_tcp(proxy_host, proxy_port, self.dialer())
            .await
            .map_err(|error| match error {
                DirectConnectError::RuntimeUnavailable => HttpConnectError::RuntimeUnavailable,
                DirectConnectError::Connect(error) => HttpConnectError::Connect(error),
            })?;
        self.tls
            .connect(proxy_server_name, stream)
            .await
            .map_err(HttpConnectError::ProxyTls)
    }

    pub(super) async fn connect_http1_proxy(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
    ) -> Result<TlsStream<tokio::net::TcpStream>, HttpConnectError> {
        let stream = self
            .connect_proxy_tls(proxy_host, proxy_port, proxy_server_name)
            .await?;
        if let Some(selected) = stream.negotiated_alpn()
            && selected != b"http/1.1"
        {
            return Err(HttpConnectError::UnsupportedAlpn {
                selected: selected.into(),
            });
        }
        Ok(stream)
    }

    /// Opens one HTTP/2 connection to the proxy.
    ///
    /// Every tunnel stream on it holds a lease, so it stays open while any
    /// tunnel on it is open, and while a pool or forwarding caller holds it.
    async fn connect_http2_proxy(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
    ) -> Result<Http2Connection, HttpConnectError> {
        let client = self.http2_builder()?;
        let stream = self
            .connect_proxy_tls(proxy_host, proxy_port, proxy_server_name)
            .await?;
        match stream.negotiated_alpn() {
            Some(b"h2") => {}
            Some(selected) => {
                return Err(HttpConnectError::UnsupportedAlpn {
                    selected: selected.into(),
                });
            }
            None => return Err(HttpConnectError::MissingNegotiatedAlpn),
        }
        connect_selected(stream, client)
            .await
            .map_err(|error| HttpConnectError::ProxyHttp2(Box::new(error)))
    }

    /// Opens one dedicated HTTP/2 connection to the proxy for exact extended
    /// CONNECT, using the profile's extended CONNECT pseudo-header order.
    pub(super) async fn connect_http2_extended_proxy(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
    ) -> Result<Http2Connection, HttpConnectError> {
        let client = self.http2_extended_builder()?;
        let stream = self
            .connect_proxy_tls(proxy_host, proxy_port, proxy_server_name)
            .await?;
        match stream.negotiated_alpn() {
            Some(b"h2") => {}
            Some(selected) => {
                return Err(HttpConnectError::UnsupportedAlpn {
                    selected: selected.into(),
                });
            }
            None => return Err(HttpConnectError::MissingNegotiatedAlpn),
        }
        connect_selected_extended(stream, client)
            .await
            .map_err(|error| HttpConnectError::ProxyHttp2(Box::new(error)))
    }

    /// Validates HTTP/2 extended CONNECT support before proxy I/O.
    pub(super) fn http2_extended_builder(&self) -> Result<Http2Builder, HttpConnectError> {
        if !self.offers_h2 {
            return Err(HttpConnectError::MissingH2Alpn);
        }
        let settings = self
            .http2
            .as_ref()
            .ok_or(HttpConnectError::MissingHttp2Settings)?;
        validate_http2(settings)
            .and_then(|()| {
                translate_extended_connect_settings(settings).map_err(Http2TlsError::Http2)
            })
            .map_err(|error| HttpConnectError::ProxyHttp2(Box::new(error)))
    }

    fn http2_builder(&self) -> Result<Http2Builder, HttpConnectError> {
        if !self.offers_h2 {
            return Err(HttpConnectError::MissingH2Alpn);
        }
        let settings = self
            .http2
            .as_ref()
            .ok_or(HttpConnectError::MissingHttp2Settings)?;
        validate_http2(settings)
            .and_then(|()| translate_settings(settings).map_err(Http2TlsError::Http2))
            .map_err(|error| HttpConnectError::ProxyHttp2(Box::new(error)))
    }
}

/// The proxy endpoint and route credentials that choose a pooled connection.
struct ProxyTarget<'a> {
    host: &'a str,
    port: u16,
    server_name: &'a str,
    credentials: Option<&'a HttpBasicCredentials>,
}

/// The HTTP/2 proxy connection one tunnel uses.
enum TunnelConnection {
    /// A connection opened for this tunnel alone.
    Dedicated(Http2Connection),
    /// A connection from the connector's pool, counted for this tunnel.
    Pooled(PooledConnection),
}

impl TunnelConnection {
    fn connection(&self) -> &Http2Connection {
        match self {
            Self::Dedicated(connection) => connection,
            Self::Pooled(pooled) => &pooled.connection,
        }
    }

    fn is_reused(&self) -> bool {
        matches!(self, Self::Pooled(pooled) if pooled.reused)
    }

    /// Stops a pool from handing this connection to later tunnels.
    fn retire(&self) {
        if let Self::Pooled(pooled) = self {
            pooled.retire();
        }
    }

    /// Counts `stream` against its pooled connection until the stream ends.
    fn attach(self, stream: &mut Http2ConnectStream) {
        if let Self::Pooled(pooled) = self {
            let (_, tunnel) = pooled.into_tunnel();
            stream.retain_until_stream_complete(tunnel);
        }
    }

    fn into_connection(self) -> Http2Connection {
        match self {
            Self::Dedicated(connection) => connection,
            Self::Pooled(pooled) => pooled.into_tunnel().0,
        }
    }
}

/// Byte stream carried by an HTTPS proxy tunnel in either proxy protocol.
pub(crate) struct HttpsProxyTunnel {
    inner: TunnelInner,
}

enum TunnelInner {
    Http1(TunnelStream<TlsStream<tokio::net::TcpStream>>),
    Http2(Box<Http2ConnectStream>),
}

impl HttpsProxyTunnel {
    pub(super) fn http1(stream: TunnelStream<TlsStream<tokio::net::TcpStream>>) -> Self {
        Self {
            inner: TunnelInner::Http1(stream),
        }
    }

    pub(super) fn http2(stream: Http2ConnectStream) -> Self {
        Self {
            inner: TunnelInner::Http2(Box::new(stream)),
        }
    }
}

impl fmt::Debug for HttpsProxyTunnel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.inner {
            TunnelInner::Http1(stream) => formatter.debug_tuple("Http1").field(stream).finish(),
            TunnelInner::Http2(stream) => formatter.debug_tuple("Http2").field(stream).finish(),
        }
    }
}

impl AsyncRead for HttpsProxyTunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            TunnelInner::Http1(stream) => Pin::new(stream).poll_read(context, buffer),
            TunnelInner::Http2(stream) => Pin::new(stream.as_mut()).poll_read(context, buffer),
        }
    }
}

impl AsyncWrite for HttpsProxyTunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            TunnelInner::Http1(stream) => Pin::new(stream).poll_write(context, bytes),
            TunnelInner::Http2(stream) => Pin::new(stream.as_mut()).poll_write(context, bytes),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            TunnelInner::Http1(stream) => Pin::new(stream).poll_flush(context),
            TunnelInner::Http2(stream) => Pin::new(stream.as_mut()).poll_flush(context),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        match &mut self.get_mut().inner {
            TunnelInner::Http1(stream) => Pin::new(stream).poll_shutdown(context),
            TunnelInner::Http2(stream) => Pin::new(stream.as_mut()).poll_shutdown(context),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        match &mut self.get_mut().inner {
            TunnelInner::Http1(stream) => Pin::new(stream).poll_write_vectored(context, buffers),
            TunnelInner::Http2(stream) => {
                Pin::new(stream.as_mut()).poll_write_vectored(context, buffers)
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        match &self.inner {
            TunnelInner::Http1(stream) => stream.is_write_vectored(),
            TunnelInner::Http2(stream) => stream.is_write_vectored(),
        }
    }
}

fn require_http1_alpn(settings: &TlsSettings) -> Result<(), HttpConnectError> {
    settings
        .alpn_protocols
        .iter()
        .any(|protocol| protocol.as_ref() == b"http/1.1")
        .then_some(())
        .ok_or(HttpConnectError::MissingHttp1Alpn)
}
