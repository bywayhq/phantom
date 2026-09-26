//! HTTP/2 connections and one-shot requests over the crate's TLS transport.

use std::{error::Error as StdError, fmt, future::Future};

use bytes::Bytes;
use http::{Method, Response};
use phantom_profile::{Http2Settings, TcpSettings, TlsSettings};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, Span, debug, debug_span, field};

use super::{
    Http2Body, Http2Builder, Http2Connection, Http2Error, Http2ExtendedConnectOutcome,
    OperationOutcome, OriginForm, PreparedRequest, RequestHeader, alps,
    translate_extended_connect_settings, translate_settings, validate_extended_connect,
};
use crate::{
    direct::{Dialer, DirectConnectError, connect_tcp},
    host_resolver::HostResolver,
    proxy::{
        HttpBasicCredentials, HttpConnectError, HttpConnectHeader, HttpsProxyConnector,
        ProxyCredentialCache, Socks5Auth, Socks5Error, http_connect_tunnel,
        http_connect_tunnel_with_basic_auth, socks5_tunnel_local_dns, socks5_tunnel_remote_dns,
    },
    tls::{ServerAuthentication, TlsConnector, TlsStream, trace_alpn},
};

pub use crate::tls::{EchFailure, TlsError, TlsErrorKind};

/// Reusable TLS and HTTP/2 settings for connections and one-shot requests.
#[derive(Clone, Debug)]
pub struct Http2TlsConnector {
    tls: TlsConnector,
    http2: Http2Settings,
    tcp: Option<TcpSettings>,
    host_resolver: Option<HostResolver>,
    proxy_credentials: Option<ProxyCredentialCache>,
}

impl Http2TlsConnector {
    /// Builds a connector from validated TLS and HTTP/2 settings.
    pub fn new(tls: &TlsSettings, http2: &Http2Settings) -> Result<Self, Http2TlsError> {
        require_h2_alpn(tls)?;
        validate_http2(http2)?;
        TlsConnector::new(tls)
            .map(|tls| Self {
                tls,
                http2: http2.clone(),
                tcp: None,
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
        tls: &TlsSettings,
        http2: &Http2Settings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, Http2TlsError> {
        require_h2_alpn(tls)?;
        validate_http2(http2)?;
        TlsConnector::new_with_additional_roots(tls, roots)
            .map(|tls| Self {
                tls,
                http2: http2.clone(),
                tcp: None,
                host_resolver: None,
                proxy_credentials: None,
            })
            .map_err(Into::into)
    }

    /// Builds a connector with an explicit server-authentication policy.
    ///
    /// [`ServerAuthentication::Disabled`] accepts unauthenticated server
    /// certificates but continues to send Server Name Indication.
    pub fn new_with_server_authentication(
        tls: &TlsSettings,
        http2: &Http2Settings,
        server_authentication: ServerAuthentication,
    ) -> Result<Self, Http2TlsError> {
        require_h2_alpn(tls)?;
        validate_http2(http2)?;
        TlsConnector::new_with_server_authentication(tls, server_authentication)
            .map(|tls| Self {
                tls,
                http2: http2.clone(),
                tcp: None,
                host_resolver: None,
                proxy_credentials: None,
            })
            .map_err(Into::into)
    }

    #[cfg(test)]
    fn new_with_roots<'a>(
        tls: &TlsSettings,
        http2: &Http2Settings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, Http2TlsError> {
        require_h2_alpn(tls)?;
        validate_http2(http2)?;
        TlsConnector::new_with_roots(tls, roots)
            .map(|tls| Self {
                tls,
                http2: http2.clone(),
                tcp: None,
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
            http2: self.http2.clone(),
            tcp: self.tcp,
            host_resolver: self.host_resolver.clone(),
            proxy_credentials: self.proxy_credentials.clone(),
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

    pub(crate) fn proxy_credential_cache(&self) -> Option<&ProxyCredentialCache> {
        self.proxy_credentials.as_ref()
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

    /// Queues the TLS secrets of this connector's connections to `sender`.
    ///
    /// Clones share the TLS context and its key log. The first sender
    /// attached is kept.
    #[cfg(feature = "keylog")]
    pub fn attach_key_log(&self, sender: &crate::NssKeyLogSender) {
        self.tls.key_log().attach(sender);
    }

    pub(crate) fn tls_connector(&self) -> &TlsConnector {
        &self.tls
    }

    pub(crate) fn settings(&self) -> &Http2Settings {
        &self.http2
    }

    /// Establishes HTTP/2 over TLS on an already-connected byte stream.
    ///
    /// Missing ALPN and every selected protocol other than exact `h2` are
    /// rejected before the HTTP/2 connection preface is written.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] when TLS negotiation, ALPS decoding, or the
    /// HTTP/2 handshake fails.
    pub async fn connect<S>(
        &self,
        stream: S,
        server_name: &str,
    ) -> Result<Http2Connection, Http2TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.trace_connect(async {
            let client = translate_settings(&self.http2)?;
            self.connect_prepared(stream, server_name, client).await
        })
        .await
    }

    /// Establishes HTTP/2 over a new direct TCP and TLS connection.
    ///
    /// This method never falls back to another HTTP protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] when connection setup, TLS negotiation, ALPS
    /// decoding, or the HTTP/2 handshake fails.
    ///
    pub async fn connect_direct(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
    ) -> Result<Http2Connection, Http2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2)?;
            let stream =
                connect_tcp(host, port, self.dialer())
                    .await
                    .map_err(|error| match error {
                        DirectConnectError::RuntimeUnavailable => Http2TlsError::RuntimeUnavailable,
                        DirectConnectError::Connect(error) => Http2TlsError::Connect(error),
                    })?;
            self.connect_prepared(stream, server_name, client).await
        })
        .await
    }

    /// Establishes HTTP/2 over a new direct TCP and TLS connection that
    /// offers Encrypted Client Hello with the `ECHConfigList` that `ech`
    /// yields, as Chrome 154 does for an origin's HTTPS record.
    ///
    /// The bounded wait for `ech`, the check of the list, and the one retry
    /// after a rejection are those of
    /// [`Http1Or2TlsConnector::connect_direct_with_ech`](crate::http1_or_2::Http1Or2TlsConnector::connect_direct_with_ech).
    /// With `None` the handshake is the one [`Self::connect_direct`] makes.
    /// This method never falls back to another HTTP protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] when connection setup, TLS negotiation, ECH,
    /// ALPS decoding, or the HTTP/2 handshake fails.
    #[cfg(feature = "https-records")]
    pub async fn connect_direct_with_ech(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        ech: impl Future<Output = Option<crate::dns::EchConfigList>>,
    ) -> Result<Http2Connection, Http2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2)?;
            let stream = crate::direct::connect_tls_with_ech(
                &self.tls,
                self.dialer(),
                host,
                port,
                server_name,
                ech,
            )
            .await?;
            connect_over_tls(stream, client, false).await
        })
        .await
    }

    /// Opens one direct WebSocket extended CONNECT stream over exact HTTP/2.
    ///
    /// Settings and the complete ordered request fields are validated before
    /// DNS or TCP I/O. The connection is configured with the profile's
    /// dedicated five-field pseudo-header order and never falls back to H1.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] when the profile has no extended CONNECT
    /// order, request validation fails, connection setup fails, the peer does
    /// not advertise support, or the HTTP/2 stream fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_extended_connect_direct(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http2ExtendedConnectOutcome, Http2TlsError> {
        let client = self.prepare_extended_connect(authority, &target, &headers)?;
        let stream = connect_tcp(host, port, self.dialer())
            .await
            .map_err(|error| match error {
                DirectConnectError::RuntimeUnavailable => Http2TlsError::RuntimeUnavailable,
                DirectConnectError::Connect(error) => Http2TlsError::Connect(error),
            })?;
        self.send_prepared_extended_connect(stream, server_name, client, authority, target, headers)
            .await
    }

    /// Opens one direct WebSocket extended CONNECT stream over exact HTTP/2
    /// on a connection that offers Encrypted Client Hello with the
    /// `ECHConfigList` that `ech` yields.
    ///
    /// The connection is set up as [`Self::connect_direct_with_ech`] sets it
    /// up, and the stream is opened as [`Self::send_extended_connect_direct`]
    /// opens it. Settings and the complete ordered request fields are
    /// validated before DNS or TCP I/O.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] as [`Self::send_extended_connect_direct`]
    /// does, or an ECH failure from the handshake.
    #[cfg(feature = "https-records")]
    #[allow(clippy::too_many_arguments)]
    pub async fn send_extended_connect_direct_with_ech(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        ech: impl Future<Output = Option<crate::dns::EchConfigList>>,
    ) -> Result<Http2ExtendedConnectOutcome, Http2TlsError> {
        let client = self.prepare_extended_connect(authority, &target, &headers)?;
        let stream = crate::direct::connect_tls_with_ech(
            &self.tls,
            self.dialer(),
            host,
            port,
            server_name,
            ech,
        )
        .await?;
        let connection = connect_over_tls(stream, client, true).await?;
        connection
            .send_extended_connect_with_settings(&self.http2, authority, target, headers)
            .await
            .map_err(Into::into)
    }

    /// Opens one WebSocket extended CONNECT stream through a plaintext HTTP
    /// CONNECT proxy.
    ///
    /// Extended CONNECT and proxy CONNECT validation complete before proxy
    /// DNS or TCP I/O. Proxy failure never falls back to a direct connection
    /// or another HTTP protocol, and the origin must still advertise
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL` before CONNECT HEADERS are sent.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] as [`Self::send_extended_connect_direct`]
    /// does, or a proxy error when the tunnel cannot be established.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_extended_connect_http_connect(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http2ExtendedConnectOutcome, Http2TlsError> {
        let client = self.prepare_extended_connect(authority, &target, &headers)?;
        let stream = http_connect_tunnel(
            self.dialer(),
            proxy_host,
            proxy_port,
            connect_authority,
            connect_headers,
        )
        .await?;
        self.send_prepared_extended_connect(stream, server_name, client, authority, target, headers)
            .await
    }

    /// Opens one WebSocket extended CONNECT stream through a plaintext proxy
    /// using challenge-driven Basic authentication.
    ///
    /// The anonymous CONNECT may be replayed once, with credentials, on a
    /// fresh proxy connection after a strict Basic `407` challenge.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] as [`Self::send_extended_connect_http_connect`]
    /// does.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_extended_connect_http_connect_with_basic_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http2ExtendedConnectOutcome, Http2TlsError> {
        let client = self.prepare_extended_connect(authority, &target, &headers)?;
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
        self.send_prepared_extended_connect(stream, server_name, client, authority, target, headers)
            .await
    }

    /// Opens one WebSocket extended CONNECT stream through an HTTPS proxy.
    ///
    /// The proxy connector's protocol selects HTTP/1.1 or HTTP/2 CONNECT to
    /// the proxy; the origin leg is always exact HTTP/2 over its own TLS
    /// session inside the tunnel.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] as [`Self::send_extended_connect_http_connect`]
    /// does.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_extended_connect_https_connect(
        &self,
        proxy_connector: &HttpsProxyConnector,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http2ExtendedConnectOutcome, Http2TlsError> {
        let client = self.prepare_extended_connect(authority, &target, &headers)?;
        let stream = proxy_connector
            .connect_tunnel(
                proxy_host,
                proxy_port,
                proxy_server_name,
                connect_authority,
                connect_headers,
            )
            .await?;
        self.send_prepared_extended_connect(stream, server_name, client, authority, target, headers)
            .await
    }

    /// Opens one WebSocket extended CONNECT stream through an HTTPS proxy
    /// using challenge-driven Basic authentication.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] as [`Self::send_extended_connect_http_connect`]
    /// does.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_extended_connect_https_connect_with_basic_auth(
        &self,
        proxy_connector: &HttpsProxyConnector,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http2ExtendedConnectOutcome, Http2TlsError> {
        let client = self.prepare_extended_connect(authority, &target, &headers)?;
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
        self.send_prepared_extended_connect(stream, server_name, client, authority, target, headers)
            .await
    }

    /// Opens one WebSocket extended CONNECT stream through a SOCKS5 proxy
    /// that resolves the target name.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] as [`Self::send_extended_connect_direct`]
    /// does, or a SOCKS5 error when the tunnel cannot be established.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_extended_connect_socks5_remote_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http2ExtendedConnectOutcome, Http2TlsError> {
        let client = self.prepare_extended_connect(authority, &target, &headers)?;
        let stream = socks5_tunnel_remote_dns(
            self.dialer(),
            proxy_host,
            proxy_port,
            target_host,
            target_port,
            auth,
        )
        .await?;
        self.send_prepared_extended_connect(stream, server_name, client, authority, target, headers)
            .await
    }

    /// Opens one WebSocket extended CONNECT stream through a SOCKS5 proxy
    /// after resolving the target locally.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] as [`Self::send_extended_connect_direct`]
    /// does, or a SOCKS5 error when the tunnel cannot be established.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_extended_connect_socks5_local_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http2ExtendedConnectOutcome, Http2TlsError> {
        let client = self.prepare_extended_connect(authority, &target, &headers)?;
        let stream = socks5_tunnel_local_dns(
            self.dialer(),
            proxy_host,
            proxy_port,
            target_host,
            target_port,
            auth,
        )
        .await?;
        self.send_prepared_extended_connect(stream, server_name, client, authority, target, headers)
            .await
    }

    /// Establishes HTTP/2 through a plaintext HTTP CONNECT proxy.
    ///
    /// The CONNECT request is validated before DNS resolution or TCP I/O.
    /// Proxy failure never falls back to a direct connection or another HTTP
    /// protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] when proxy negotiation, TLS negotiation, ALPS
    /// decoding, or the HTTP/2 handshake fails.
    ///
    pub async fn connect_http_connect(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        server_name: &str,
    ) -> Result<Http2Connection, Http2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2)?;
            let stream = http_connect_tunnel(
                self.dialer(),
                proxy_host,
                proxy_port,
                connect_authority,
                connect_headers,
            )
            .await?;
            self.connect_prepared(stream, server_name, client).await
        })
        .await
    }

    /// Establishes HTTP/2 through a plaintext proxy using challenge-driven Basic authentication.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_http_connect_with_basic_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
        server_name: &str,
    ) -> Result<Http2Connection, Http2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2)?;
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
            self.connect_prepared(stream, server_name, client).await
        })
        .await
    }

    /// Establishes HTTP/2 origin TLS through an HTTP/1.1 CONNECT tunnel to an
    /// HTTPS proxy.
    ///
    /// CONNECT validation finishes before the proxy TCP connection begins.
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
    ) -> Result<Http2Connection, Http2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2)?;
            let stream = proxy_connector
                .connect_tunnel(
                    proxy_host,
                    proxy_port,
                    proxy_server_name,
                    connect_authority,
                    connect_headers,
                )
                .await?;
            self.connect_prepared(stream, server_name, client).await
        })
        .await
    }

    /// Establishes HTTP/2 through an HTTPS proxy using challenge-driven Basic authentication.
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
    ) -> Result<Http2Connection, Http2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2)?;
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
            self.connect_prepared(stream, server_name, client).await
        })
        .await
    }

    /// Establishes HTTP/2 through a SOCKS5 proxy using remote DNS.
    ///
    /// Proxy failure never falls back to a direct connection or another HTTP
    /// protocol.
    pub async fn connect_socks5_remote(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        server_name: &str,
    ) -> Result<Http2Connection, Http2TlsError> {
        self.connect_socks5_remote_with_auth(
            proxy_host,
            proxy_port,
            Socks5Auth::None,
            target_host,
            target_port,
            server_name,
        )
        .await
    }

    /// Establishes HTTP/2 through a remote-DNS proxy with configured credentials.
    ///
    /// Proxy failure never falls back to a direct connection or another HTTP
    /// protocol.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_socks5_remote_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        server_name: &str,
    ) -> Result<Http2Connection, Http2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2)?;
            let stream = socks5_tunnel_remote_dns(
                self.dialer(),
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            self.connect_prepared(stream, server_name, client).await
        })
        .await
    }

    /// Establishes HTTP/2 through a SOCKS5 proxy using local DNS.
    ///
    /// Proxy failure never falls back to a direct connection or another HTTP
    /// protocol.
    pub async fn connect_socks5_local(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        server_name: &str,
    ) -> Result<Http2Connection, Http2TlsError> {
        self.connect_socks5_local_with_auth(
            proxy_host,
            proxy_port,
            Socks5Auth::None,
            target_host,
            target_port,
            server_name,
        )
        .await
    }

    /// Establishes HTTP/2 through a local-DNS proxy with configured credentials.
    ///
    /// Proxy failure never falls back to a direct connection or another HTTP
    /// protocol.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_socks5_local_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        server_name: &str,
    ) -> Result<Http2Connection, Http2TlsError> {
        self.trace_connect(async {
            let client = translate_settings(&self.http2)?;
            let stream = socks5_tunnel_local_dns(
                self.dialer(),
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            self.connect_prepared(stream, server_name, client).await
        })
        .await
    }

    /// Sends one empty-body HTTP/2 GET after an exact `h2` TLS negotiation.
    ///
    /// `server_name` controls certificate verification and SNI; `authority`
    /// becomes the HTTP `:authority` value and may include a port. Request
    /// preparation completes before the supplied stream is touched. Missing
    /// ALPN and every selected protocol other than exact `h2` are rejected
    /// before the HTTP/2 connection preface is written.
    pub async fn send_get<S>(
        &self,
        stream: S,
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http2Body>, Http2TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.send_request(
            stream,
            server_name,
            Method::GET,
            authority,
            target,
            headers,
            None,
        )
        .await
    }

    /// Sends one HTTP/2 request after an exact `h2` TLS negotiation.
    ///
    /// Request preparation completes before the supplied stream is touched.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request<S>(
        &self,
        stream: S,
        server_name: &str,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http2Body>, Http2TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared =
                PreparedRequest::new(&self.http2, method, authority, target, headers, body)?;
            self.send_prepared_request(stream, server_name, prepared)
                .await
        })
        .await
    }

    /// Sends one empty-body GET over a new direct TCP and TLS connection.
    ///
    /// The complete request is validated before DNS resolution or TCP I/O.
    /// This method never falls back to another HTTP protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] when request preparation, connection setup,
    /// TLS negotiation, or HTTP/2 processing fails.
    ///
    pub async fn send_get_direct(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        self.send_request_direct(
            host,
            port,
            server_name,
            Method::GET,
            authority,
            target,
            headers,
            None,
        )
        .await
    }

    /// Sends one request over a new direct TCP and TLS connection.
    ///
    /// The complete request is validated before DNS resolution or TCP I/O.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request_direct(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared =
                PreparedRequest::new(&self.http2, method, authority, target, headers, body)?;
            let stream =
                connect_tcp(host, port, self.dialer())
                    .await
                    .map_err(|error| match error {
                        DirectConnectError::RuntimeUnavailable => Http2TlsError::RuntimeUnavailable,
                        DirectConnectError::Connect(error) => Http2TlsError::Connect(error),
                    })?;
            self.send_prepared_request(stream, server_name, prepared)
                .await
        })
        .await
    }

    /// Sends one empty-body GET through a plaintext HTTP CONNECT proxy.
    ///
    /// The origin request and CONNECT request are validated before DNS
    /// resolution or TCP I/O. Proxy failure never falls back to a direct
    /// connection or another HTTP protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] when request preparation, proxy negotiation,
    /// TLS negotiation, or HTTP/2 processing fails.
    ///
    #[allow(clippy::too_many_arguments)]
    pub async fn send_get_http_connect(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        self.send_request_http_connect(
            proxy_host,
            proxy_port,
            connect_authority,
            connect_headers,
            server_name,
            Method::GET,
            authority,
            target,
            headers,
            None,
        )
        .await
    }

    /// Sends one request through a plaintext HTTP CONNECT proxy.
    ///
    /// Origin and CONNECT requests are validated before proxy or origin I/O.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request_http_connect(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        server_name: &str,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared =
                PreparedRequest::new(&self.http2, method, authority, target, headers, body)?;
            let stream = http_connect_tunnel(
                self.dialer(),
                proxy_host,
                proxy_port,
                connect_authority,
                connect_headers,
            )
            .await?;
            self.send_prepared_request(stream, server_name, prepared)
                .await
        })
        .await
    }

    /// Sends one request through a plaintext proxy using challenge-driven Basic authentication.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request_http_connect_with_basic_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
        server_name: &str,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared =
                PreparedRequest::new(&self.http2, method, authority, target, headers, body)?;
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
            self.send_prepared_request(stream, server_name, prepared)
                .await
        })
        .await
    }

    /// Sends one HTTP/2 request through an HTTP/1.1 CONNECT tunnel to an HTTPS
    /// proxy.
    ///
    /// Origin and CONNECT requests are validated before proxy or origin I/O.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request_https_connect(
        &self,
        proxy_connector: &HttpsProxyConnector,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        server_name: &str,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared =
                PreparedRequest::new(&self.http2, method, authority, target, headers, body)?;
            let stream = proxy_connector
                .connect_tunnel(
                    proxy_host,
                    proxy_port,
                    proxy_server_name,
                    connect_authority,
                    connect_headers,
                )
                .await?;
            self.send_prepared_request(stream, server_name, prepared)
                .await
        })
        .await
    }

    /// Sends one request through an HTTPS proxy using challenge-driven Basic authentication.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request_https_connect_with_basic_auth(
        &self,
        proxy_connector: &HttpsProxyConnector,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
        server_name: &str,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared =
                PreparedRequest::new(&self.http2, method, authority, target, headers, body)?;
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
            self.send_prepared_request(stream, server_name, prepared)
                .await
        })
        .await
    }

    /// Sends one empty-body GET through a SOCKS5 proxy using remote DNS.
    ///
    /// Origin request validation completes before proxy I/O. Proxy failure
    /// never falls back to a direct connection.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_get_socks5_remote(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        self.send_request_socks5_remote(
            proxy_host,
            proxy_port,
            target_host,
            target_port,
            server_name,
            Method::GET,
            authority,
            target,
            headers,
            None,
        )
        .await
    }

    /// Sends one request through a SOCKS5 proxy using remote DNS.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request_socks5_remote(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        server_name: &str,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        self.send_request_socks5_remote_with_auth(
            proxy_host,
            proxy_port,
            Socks5Auth::None,
            target_host,
            target_port,
            server_name,
            method,
            authority,
            target,
            headers,
            body,
        )
        .await
    }

    /// Sends one request through a remote-DNS proxy with configured credentials.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request_socks5_remote_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        server_name: &str,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared =
                PreparedRequest::new(&self.http2, method, authority, target, headers, body)?;
            let stream = socks5_tunnel_remote_dns(
                self.dialer(),
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            self.send_prepared_request(stream, server_name, prepared)
                .await
        })
        .await
    }

    /// Sends one empty-body GET through a SOCKS5 proxy using local DNS.
    ///
    /// Origin request validation completes before target DNS or proxy I/O.
    /// Proxy failure never falls back to a direct connection.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_get_socks5_local(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        self.send_request_socks5_local(
            proxy_host,
            proxy_port,
            target_host,
            target_port,
            server_name,
            Method::GET,
            authority,
            target,
            headers,
            None,
        )
        .await
    }

    /// Sends one request through a SOCKS5 proxy using local DNS.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request_socks5_local(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        server_name: &str,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        self.send_request_socks5_local_with_auth(
            proxy_host,
            proxy_port,
            Socks5Auth::None,
            target_host,
            target_port,
            server_name,
            method,
            authority,
            target,
            headers,
            body,
        )
        .await
    }

    /// Sends one request through a local-DNS proxy with configured credentials.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request_socks5_local_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        server_name: &str,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared =
                PreparedRequest::new(&self.http2, method, authority, target, headers, body)?;
            let stream = socks5_tunnel_local_dns(
                self.dialer(),
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            self.send_prepared_request(stream, server_name, prepared)
                .await
        })
        .await
    }

    async fn send_prepared_request<S>(
        &self,
        stream: S,
        server_name: &str,
        prepared: PreparedRequest,
    ) -> Result<Response<Http2Body>, Http2TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!("HTTP/2 request prepared");
        let connection = self
            .connect_prepared(stream, server_name, prepared.client)
            .await?;
        let response = connection
            .send_prepared_request(prepared.request, prepared.body, prepared.trailers)
            .await?;
        Span::current().record("status", response.status().as_u16());
        Ok(response)
    }

    /// Validates settings and the extended CONNECT request before any I/O.
    fn prepare_extended_connect(
        &self,
        authority: &str,
        target: &OriginForm,
        headers: &[RequestHeader],
    ) -> Result<Http2Builder, Http2TlsError> {
        self.http2.validate().map_err(Http2Error::InvalidSettings)?;
        let client = translate_extended_connect_settings(&self.http2)?;
        validate_extended_connect(authority, target, headers)?;
        Ok(client)
    }

    async fn send_prepared_extended_connect<S>(
        &self,
        stream: S,
        server_name: &str,
        client: Http2Builder,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http2ExtendedConnectOutcome, Http2TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let connection = self
            .connect_prepared_extended(stream, server_name, client)
            .await?;
        connection
            .send_extended_connect_with_settings(&self.http2, authority, target, headers)
            .await
            .map_err(Into::into)
    }

    /// Opens one WebSocket extended CONNECT stream on an established connection.
    ///
    /// The connector's HTTP/2 profile supplies the stream's extended CONNECT
    /// pseudo-header order and priority. The connection may be one opened for
    /// ordinary requests with the same profile; its other streams keep their
    /// own shape. This never opens a connection or falls back to HTTP/1.1.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] when the profile has no extended CONNECT
    /// order, request validation fails, the peer does not advertise support,
    /// or the HTTP/2 stream fails.
    pub async fn send_extended_connect_on(
        &self,
        connection: &Http2Connection,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http2ExtendedConnectOutcome, Http2TlsError> {
        connection
            .send_extended_connect_with_settings(&self.http2, authority, target, headers)
            .await
            .map_err(Into::into)
    }

    async fn connect_prepared<S>(
        &self,
        stream: S,
        server_name: &str,
        client: Http2Builder,
    ) -> Result<Http2Connection, Http2TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.connect_prepared_kind(stream, server_name, client, false)
            .await
    }

    async fn connect_prepared_extended<S>(
        &self,
        stream: S,
        server_name: &str,
        client: Http2Builder,
    ) -> Result<Http2Connection, Http2TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.connect_prepared_kind(stream, server_name, client, true)
            .await
    }

    async fn connect_prepared_kind<S>(
        &self,
        stream: S,
        server_name: &str,
        client: Http2Builder,
        extended_connect: bool,
    ) -> Result<Http2Connection, Http2TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let stream = self.tls.connect(server_name, stream).await?;
        connect_over_tls(stream, client, extended_connect).await
    }

    async fn trace_connect<F>(&self, operation: F) -> Result<Http2Connection, Http2TlsError>
    where
        F: Future<Output = Result<Http2Connection, Http2TlsError>>,
    {
        let span = debug_span!(
            "http2.tls.connect",
            transport = "tls",
            negotiated_alpn = field::Empty,
            outcome = field::Empty,
        );
        let outcome_guard = OperationOutcome::new(&span);
        let result = operation.instrument(span.clone()).await;
        outcome_guard.finish(connection_outcome(&result));
        result
    }

    async fn trace_response_head<F>(
        &self,
        method: &Method,
        body_bytes: usize,
        operation: F,
    ) -> Result<Response<Http2Body>, Http2TlsError>
    where
        F: Future<Output = Result<Response<Http2Body>, Http2TlsError>>,
    {
        let span = debug_span!(
            "http2.tls.response_head",
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
            Err(Http2TlsError::RuntimeUnavailable) => "runtime_unavailable",
            Err(Http2TlsError::Connect(_)) => "connect_error",
            Err(Http2TlsError::Proxy(_) | Http2TlsError::Socks5Proxy(_)) => "proxy_error",
            Err(Http2TlsError::Tls(_)) => "tls_error",
            Err(Http2TlsError::Http2(Http2Error::Protocol(_))) => "http_protocol_error",
            Err(Http2TlsError::Http2(_)) => "http_preparation_error",
            Err(Http2TlsError::MissingNegotiatedAlpn | Http2TlsError::UnsupportedAlpn { .. }) => {
                "unsupported_alpn"
            }
            Err(Http2TlsError::InvalidPeerApplicationSettings { .. }) => "invalid_peer_alps",
            Err(Http2TlsError::MissingHttp2Alpn) => "invalid_configuration",
        };
        outcome_guard.finish(outcome);
        result
    }
}

pub(crate) async fn connect_selected<S>(
    stream: TlsStream<S>,
    client: Http2Builder,
) -> Result<Http2Connection, Http2TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    connect_selected_kind(stream, client, false).await
}

/// Establishes HTTP/2 on a TLS stream that selected `h2`, for exact extended
/// CONNECT requests built with the profile's extended CONNECT order.
pub(crate) async fn connect_selected_extended<S>(
    stream: TlsStream<S>,
    client: Http2Builder,
) -> Result<Http2Connection, Http2TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    connect_selected_kind(stream, client, true).await
}

async fn connect_selected_kind<S>(
    stream: TlsStream<S>,
    mut client: Http2Builder,
    extended_connect: bool,
) -> Result<Http2Connection, Http2TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let peer_settings = alps::decode(stream.peer_application_settings()).map_err(|error| {
        debug!(
            frame_index = error.frame_index,
            offset = error.offset,
            reason = error.reason(),
            "TLS peer supplied invalid HTTP/2 application settings"
        );
        Http2TlsError::InvalidPeerApplicationSettings {
            frame_index: error.frame_index,
            offset: error.offset,
            reason: error.reason(),
        }
    })?;
    debug!(
        alps_frame_count = peer_settings.frame_count(),
        accept_ch_entry_count = peer_settings.accept_ch_entry_count(),
        ignored_accept_ch_entry_count = peer_settings.ignored_accept_ch_entry_count(),
        malformed_accept_ch_frame_count = peer_settings.malformed_accept_ch_frame_count(),
        "HTTP/2 peer application settings decoded"
    );
    let (initial_settings, accept_ch) = peer_settings.into_parts();
    if let Some(settings) = initial_settings {
        client.client.initial_peer_settings(settings);
    }

    if extended_connect {
        Http2Connection::connect_extended_with_builder_and_accept_ch(stream, client, accept_ch)
            .await
            .map_err(Into::into)
    } else {
        Http2Connection::connect_with_builder_and_accept_ch(stream, client, accept_ch)
            .await
            .map_err(Into::into)
    }
}

fn connection_outcome(result: &Result<Http2Connection, Http2TlsError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(Http2TlsError::RuntimeUnavailable) => "runtime_unavailable",
        Err(Http2TlsError::Connect(_)) => "connect_error",
        Err(Http2TlsError::Proxy(_) | Http2TlsError::Socks5Proxy(_)) => "proxy_error",
        Err(Http2TlsError::Tls(_)) => "tls_error",
        Err(Http2TlsError::Http2(Http2Error::Protocol(_))) => "http_protocol_error",
        Err(Http2TlsError::Http2(_)) => "http_preparation_error",
        Err(Http2TlsError::MissingNegotiatedAlpn | Http2TlsError::UnsupportedAlpn { .. }) => {
            "unsupported_alpn"
        }
        Err(Http2TlsError::InvalidPeerApplicationSettings { .. }) => "invalid_peer_alps",
        Err(Http2TlsError::MissingHttp2Alpn) => "invalid_configuration",
    }
}

/// Starts HTTP/2 over an established TLS stream that selected exact `h2`.
///
/// Missing ALPN and every other selected protocol are rejected before the
/// connection preface is written.
async fn connect_over_tls<S>(
    stream: TlsStream<S>,
    client: Http2Builder,
    extended_connect: bool,
) -> Result<Http2Connection, Http2TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let negotiated = stream.negotiated_alpn();
    Span::current().record("negotiated_alpn", trace_alpn(negotiated));
    match negotiated {
        Some(b"h2") => {}
        None => {
            debug!("TLS completed without the required HTTP/2 ALPN protocol");
            return Err(Http2TlsError::MissingNegotiatedAlpn);
        }
        Some(selected) => {
            debug!("TLS selected an unsupported HTTP/2 ALPN protocol");
            return Err(Http2TlsError::UnsupportedAlpn {
                selected: selected.into(),
            });
        }
    }

    connect_selected_kind(stream, client, extended_connect).await
}

/// Error returned while establishing HTTP/2 over TLS or opening a request.
#[derive(Debug)]
pub enum Http2TlsError {
    /// The network request was polled outside a Tokio runtime.
    RuntimeUnavailable,
    /// Establishing the direct TCP connection failed.
    Connect(std::io::Error),
    /// HTTP CONNECT proxy negotiation failed.
    Proxy(HttpConnectError),
    /// SOCKS5 proxy negotiation failed.
    Socks5Proxy(Socks5Error),
    /// TLS connector setup or handshake failed.
    Tls(TlsError),
    /// HTTP/2 request preparation or protocol setup failed.
    Http2(Http2Error),
    /// The peer completed TLS without selecting an ALPN protocol.
    MissingNegotiatedAlpn,
    /// The peer selected a protocol other than exact `h2`.
    UnsupportedAlpn {
        /// Exact ALPN protocol bytes selected by the peer.
        selected: Box<[u8]>,
    },
    /// The peer's negotiated HTTP/2 ALPS value was malformed or invalid.
    InvalidPeerApplicationSettings {
        /// Zero-based frame position at which decoding failed.
        frame_index: usize,
        /// Byte offset of that frame within the ALPS value.
        offset: usize,
        /// Protocol reason without including any peer-supplied bytes.
        reason: &'static str,
    },
    /// The TLS settings cannot offer exact `h2`.
    MissingHttp2Alpn,
}

impl fmt::Display for Http2TlsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeUnavailable => {
                formatter.write_str("HTTP/2 network requests require a Tokio runtime")
            }
            Self::Connect(error) => write!(formatter, "TCP connection failed: {error}"),
            Self::Proxy(error) => write!(formatter, "HTTP proxy failed: {error}"),
            Self::Socks5Proxy(error) => write!(formatter, "SOCKS5 proxy failed: {error}"),
            Self::Tls(error) => write!(formatter, "TLS connection failed: {error}"),
            Self::Http2(error) => write!(formatter, "HTTP/2 request failed: {error}"),
            Self::MissingNegotiatedAlpn => {
                formatter.write_str("TLS completed without negotiating the required `h2` ALPN")
            }
            Self::UnsupportedAlpn { selected } => write!(
                formatter,
                "TLS selected {} ALPN, which is unsupported by the HTTP/2 transport",
                trace_alpn(Some(selected))
            ),
            Self::InvalidPeerApplicationSettings {
                frame_index,
                offset,
                reason,
            } => write!(
                formatter,
                "invalid HTTP/2 peer application settings at frame {frame_index}, byte {offset}: {reason}"
            ),
            Self::MissingHttp2Alpn => {
                formatter.write_str("HTTP/2 TLS settings must include the exact `h2` ALPN protocol")
            }
        }
    }
}

impl StdError for Http2TlsError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Connect(error) => Some(error),
            Self::Proxy(error) => Some(error),
            Self::Socks5Proxy(error) => Some(error),
            Self::Tls(error) => Some(error),
            Self::Http2(error) => Some(error),
            Self::RuntimeUnavailable
            | Self::MissingNegotiatedAlpn
            | Self::UnsupportedAlpn { .. }
            | Self::InvalidPeerApplicationSettings { .. }
            | Self::MissingHttp2Alpn => None,
        }
    }
}

impl Http2TlsError {
    /// Returns why a connection that offered Encrypted Client Hello failed,
    /// when that is the cause.
    #[must_use]
    pub fn ech_failure(&self) -> Option<EchFailure> {
        match self {
            Self::Tls(error) => error.ech_failure(),
            _ => None,
        }
    }
}

impl From<TlsError> for Http2TlsError {
    fn from(error: TlsError) -> Self {
        Self::Tls(error)
    }
}

#[cfg(feature = "https-records")]
impl From<crate::direct::DirectTlsError> for Http2TlsError {
    fn from(error: crate::direct::DirectTlsError) -> Self {
        use crate::direct::DirectTlsError;

        match error {
            DirectTlsError::Direct(DirectConnectError::RuntimeUnavailable) => {
                Self::RuntimeUnavailable
            }
            DirectTlsError::Direct(DirectConnectError::Connect(error)) => Self::Connect(error),
            DirectTlsError::Tls(error) => Self::Tls(error),
        }
    }
}

impl From<HttpConnectError> for Http2TlsError {
    fn from(error: HttpConnectError) -> Self {
        Self::Proxy(error)
    }
}

impl From<Socks5Error> for Http2TlsError {
    fn from(error: Socks5Error) -> Self {
        Self::Socks5Proxy(error)
    }
}

impl From<Http2Error> for Http2TlsError {
    fn from(error: Http2Error) -> Self {
        Self::Http2(error)
    }
}

fn require_h2_alpn(settings: &TlsSettings) -> Result<(), Http2TlsError> {
    settings
        .alpn_protocols
        .iter()
        .any(|protocol| protocol.as_ref() == b"h2")
        .then_some(())
        .ok_or(Http2TlsError::MissingHttp2Alpn)
}

pub(crate) fn validate_http2(settings: &Http2Settings) -> Result<(), Http2TlsError> {
    settings.validate().map_err(Http2Error::InvalidSettings)?;
    translate_settings(settings)?;
    Ok(())
}

#[cfg(test)]
mod tests;
