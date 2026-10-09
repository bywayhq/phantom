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
    AbsoluteForm, Http1Body, Http1Connection, Http1Error, Http1UpgradeOutcome, OperationOutcome,
    OriginForm, PreparedGet, PreparedRequest, RequestHeader, connection::early_data_error,
    send_prepared_upgrade,
};
use crate::{
    connection_leg::{self, ConnectionLegError},
    direct::{Dialer, DirectConnectError, connect_tcp, connect_tcp_keeping_slower},
    host_resolver::HostResolver,
    proxy::{
        HttpBasicCredentials, HttpConnectHeader, HttpsProxyConnector, ProxyCredentialCache,
        Socks5Auth,
    },
    route::{Endpoint, HttpConnectRoute, ProxyTransport, Socks5Target, TcpRoute},
    source_binding::SourceBinding,
    tcp::{
        AddressFamilyMemory, ForeignStream, SlowerAttempt, SlowerConnection, SlowerKeepalive,
        TcpKeepaliveSource,
    },
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

    /// Sends one empty-body HTTP/1.1 GET over a connected byte stream.
    ///
    /// The target and complete ordered header list are prepared before the
    /// supplied stream is touched. A server-selected ALPN protocol other than
    /// `http/1.1` is rejected before any HTTP bytes are written. No negotiated
    /// ALPN is accepted because HTTP/1.1 remains the TLS default when ALPN is
    /// absent.
    pub async fn send_get<S>(
        &self,
        stream: S,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http1Body>, Http1TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.send_request(stream, server_name, Method::GET, target, headers, None)
            .await
    }

    /// Sends one HTTP/1.1 request over a connected byte stream.
    ///
    /// The request is validated before the stream is touched. TLS and ALPN
    /// behavior is identical to [`Self::send_get`].
    pub async fn send_request<S>(
        &self,
        stream: S,
        server_name: &str,
        method: Method,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http1Body>, Http1TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(
            &trace_method,
            body_bytes,
            pin!(async {
                let prepared = PreparedRequest::new(method, target, headers, body)?;
                let connection = self
                    .connect_prepared(ForeignStream(stream), server_name)
                    .await?;
                self.send_prepared_request(&connection, prepared).await
            }),
        )
        .await
    }

    /// Sends one empty-body GET over a new direct TCP and TLS connection.
    ///
    /// The complete request is validated before DNS resolution or TCP I/O.
    /// This method never falls back to another HTTP protocol.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when request preparation, connection setup,
    /// TLS negotiation, or HTTP/1 processing fails.
    ///
    pub async fn send_get_direct(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        self.send_request_direct(host, port, server_name, Method::GET, target, headers, None)
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
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(
            &trace_method,
            body_bytes,
            pin!(async {
                let prepared = PreparedRequest::new(method, target, headers, body)?;
                let stream = connect_tcp(host, port, self.dialer())
                    .await
                    .map_err(|error| match error {
                        DirectConnectError::RuntimeUnavailable => Http1TlsError::RuntimeUnavailable,
                        DirectConnectError::Connect(error) => Http1TlsError::Connect(error),
                    })?;
                let connection = self.connect_prepared(stream, server_name).await?;
                self.send_prepared_request(&connection, prepared).await
            }),
        )
        .await
    }

    /// Sends one absolute-form HTTP/1.1 request to a plaintext forward proxy.
    ///
    /// Request validation completes before DNS resolution or proxy I/O. The
    /// proxy connection is plaintext and no direct-origin fallback is used.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request_forward_proxy(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        method: Method,
        target: AbsoluteForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(
            &trace_method,
            body_bytes,
            pin!(async {
                let prepared = PreparedRequest::new_forward(method, target, headers, body)?;
                let connection = self.connect_forward_proxy(proxy_host, proxy_port).await?;
                self.send_prepared_request(&connection, prepared).await
            }),
        )
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
    /// Returns [`Http1TlsError`] when request preparation, proxy negotiation,
    /// TLS negotiation, or HTTP/1 processing fails.
    ///
    #[allow(clippy::too_many_arguments)]
    pub async fn send_get_http_connect(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        self.send_request_http_connect(
            proxy_host,
            proxy_port,
            connect_authority,
            connect_headers,
            server_name,
            Method::GET,
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
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(
            &trace_method,
            body_bytes,
            pin!(async {
                let prepared = PreparedRequest::new(method, target, headers, body)?;
                let stream = connection_leg::connect(
                    TcpRoute::HttpConnect(HttpConnectRoute {
                        proxy: ProxyTransport::Tcp(Endpoint {
                            host: proxy_host,
                            port: proxy_port,
                        }),
                        authority: connect_authority,
                        headers: connect_headers,
                        credentials: None,
                    }),
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
                let connection = self.connect_prepared(stream, server_name).await?;
                self.send_prepared_request(&connection, prepared).await
            }),
        )
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
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(
            &trace_method,
            body_bytes,
            pin!(async {
                let prepared = PreparedRequest::new(method, target, headers, body)?;
                let stream = connection_leg::connect(
                    TcpRoute::HttpConnect(HttpConnectRoute {
                        proxy: ProxyTransport::Tcp(Endpoint {
                            host: proxy_host,
                            port: proxy_port,
                        }),
                        authority: connect_authority,
                        headers: connect_headers,
                        credentials: Some(credentials),
                    }),
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
                let connection = self.connect_prepared(stream, server_name).await?;
                self.send_prepared_request(&connection, prepared).await
            }),
        )
        .await
    }

    /// Sends one request through an HTTP/1.1 CONNECT tunnel to an HTTPS proxy.
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
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(
            &trace_method,
            body_bytes,
            pin!(async {
                let prepared = PreparedRequest::new(method, target, headers, body)?;
                let stream = connection_leg::connect(
                    TcpRoute::HttpConnect(HttpConnectRoute {
                        proxy: ProxyTransport::Tls {
                            endpoint: Endpoint {
                                host: proxy_host,
                                port: proxy_port,
                            },
                            server_name: proxy_server_name,
                            connector: proxy_connector,
                        },
                        authority: connect_authority,
                        headers: connect_headers,
                        credentials: None,
                    }),
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
                let connection = self.connect_prepared(stream, server_name).await?;
                self.send_prepared_request(&connection, prepared).await
            }),
        )
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
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(
            &trace_method,
            body_bytes,
            pin!(async {
                let prepared = PreparedRequest::new(method, target, headers, body)?;
                let stream = connection_leg::connect(
                    TcpRoute::HttpConnect(HttpConnectRoute {
                        proxy: ProxyTransport::Tls {
                            endpoint: Endpoint {
                                host: proxy_host,
                                port: proxy_port,
                            },
                            server_name: proxy_server_name,
                            connector: proxy_connector,
                        },
                        authority: connect_authority,
                        headers: connect_headers,
                        credentials: Some(credentials),
                    }),
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
                let connection = self.connect_prepared(stream, server_name).await?;
                self.send_prepared_request(&connection, prepared).await
            }),
        )
        .await
    }

    /// Sends one empty-body GET through a SOCKS5 proxy using remote DNS.
    ///
    /// The origin request is validated before the proxy connection starts.
    /// Proxy failure never falls back to a direct connection.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_get_socks5_remote(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        self.send_request_socks5_remote(
            proxy_host,
            proxy_port,
            target_host,
            target_port,
            server_name,
            Method::GET,
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
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        self.send_request_socks5_remote_with_auth(
            proxy_host,
            proxy_port,
            Socks5Auth::None,
            target_host,
            target_port,
            server_name,
            method,
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
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(
            &trace_method,
            body_bytes,
            pin!(async {
                let prepared = PreparedRequest::new(method, target, headers, body)?;
                let stream = connection_leg::connect(
                    TcpRoute::Socks5 {
                        proxy: Endpoint {
                            host: proxy_host,
                            port: proxy_port,
                        },
                        target: Socks5Target::RemoteDns(Endpoint {
                            host: target_host,
                            port: target_port,
                        }),
                        auth: auth,
                    },
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
                let connection = self.connect_prepared(stream, server_name).await?;
                self.send_prepared_request(&connection, prepared).await
            }),
        )
        .await
    }

    /// Sends one empty-body GET through a SOCKS5 proxy using local DNS.
    ///
    /// The origin request is validated before DNS or proxy I/O. Proxy failure
    /// never falls back to a direct connection.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_get_socks5_local(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        self.send_request_socks5_local(
            proxy_host,
            proxy_port,
            target_host,
            target_port,
            server_name,
            Method::GET,
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
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        self.send_request_socks5_local_with_auth(
            proxy_host,
            proxy_port,
            Socks5Auth::None,
            target_host,
            target_port,
            server_name,
            method,
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
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(
            &trace_method,
            body_bytes,
            pin!(async {
                let prepared = PreparedRequest::new(method, target, headers, body)?;
                let stream = connection_leg::connect(
                    TcpRoute::Socks5 {
                        proxy: Endpoint {
                            host: proxy_host,
                            port: proxy_port,
                        },
                        target: Socks5Target::LocalDns(Endpoint {
                            host: target_host,
                            port: target_port,
                        }),
                        auth: auth,
                    },
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
                let connection = self.connect_prepared(stream, server_name).await?;
                self.send_prepared_request(&connection, prepared).await
            }),
        )
        .await
    }

    /// Establishes HTTP/1.1 over TLS on an already-connected byte stream.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when TLS negotiation, ALPN selection, or the
    /// HTTP/1.1 handshake fails.
    pub async fn connect<S>(
        &self,
        stream: S,
        server_name: &str,
    ) -> Result<Http1Connection, Http1TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.trace_connect(pin!(
            self.connect_prepared(ForeignStream(stream), server_name)
        ))
        .await
    }

    /// Opens a connection through `route` using this connector's origin TLS.
    ///
    /// Direct connections offer early data; tunneled connections perform the
    /// ordinary origin handshake. Proxy TLS uses the route's proxy connector.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] for route setup, TLS, or protocol failures.
    pub async fn connect_via(
        &self,
        route: TcpRoute<'_>,
        server_name: &str,
    ) -> Result<Http1Connection, Http1TlsError> {
        self.trace_connect(pin!(async {
            let direct = matches!(route, TcpRoute::Direct(_));
            let stream =
                connection_leg::connect(route, self.dialer(), self.proxy_credentials.as_ref())
                    .await?;
            let stream = if direct {
                self.tls
                    .connect_offering_early_data(server_name, stream)
                    .await?
            } else {
                self.tls.connect(server_name, stream).await?
            };
            connect_over_tls(stream).await
        }))
        .await
    }

    /// Opens one direct TLS connection as [`Self::connect_via`] does and,
    /// when the TCP settings select a
    /// [`TcpBackupConnection`](phantom_profile::TcpBackupConnection), uses
    /// and updates `family`, the origin's address family, and returns the
    /// slower attempt when the backup started and that attempt is still
    /// connecting.
    ///
    /// The slower attempt keeps connecting while the first connection's
    /// handshake runs. Once the returned [`SlowerConnection`] is polled, it
    /// makes the same TLS handshake with no request, waits for the server to
    /// answer any early data, and comes back idle, its keepalive started
    /// before the handshake. A failure of the first connection closes it.
    ///
    /// This is a seam for the facade's pools, not supported API.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when TCP setup, TLS negotiation, ALPN
    /// selection, or the HTTP/1.1 handshake of the first connection fails.
    #[doc(hidden)]
    pub async fn connect_direct_keeping_slower(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        family: &AddressFamilyMemory,
    ) -> Result<(Http1Connection, Option<SlowerConnection<Http1Connection>>), Http1TlsError> {
        let mut slower = None;
        let connection = self
            .trace_connect(pin!(async {
                let (stream, attempt) =
                    connect_tcp_keeping_slower(host, port, self.dialer(), Some(family))
                        .await
                        .map_err(Http1TlsError::from_direct)?;
                slower = attempt;
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
            }))
            .await?;
        let slower = slower.map(|attempt| self.slower_tls(attempt, server_name));
        Ok((connection, slower))
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

    /// Opens one direct TLS connection for sequential HTTP/1.1 requests,
    /// offering Encrypted Client Hello with the `ECHConfigList` that `ech`
    /// yields, as Chrome 154 does for an origin's HTTPS record.
    ///
    /// The bounded wait for `ech`, the check of the list, and the one retry
    /// after a rejection are those of
    /// [`Http1Or2TlsConnector::connect_direct_with_ech`](crate::http1_or_2::Http1Or2TlsConnector::connect_direct_with_ech).
    /// With `None` the handshake is the one [`Self::connect_via`] makes.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when TCP setup, TLS negotiation, ECH, ALPN
    /// selection, or the HTTP/1.1 handshake fails.
    #[cfg(feature = "https-records")]
    pub async fn connect_direct_with_ech(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        ech: impl Future<Output = Option<crate::dns::EchConfigList>>,
    ) -> Result<Http1Connection, Http1TlsError> {
        self.trace_connect(pin!(async {
            let stream = crate::direct::connect_tls_with_ech(
                &self.tls,
                self.dialer(),
                host,
                port,
                server_name,
                ech,
                true,
            )
            .await?;
            connect_over_tls(stream).await
        }))
        .await
    }

    /// Opens one direct plaintext TCP connection for sequential HTTP/1.1 requests.
    ///
    /// This method performs no TLS handshake and never routes through a proxy.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when the Tokio runtime is unavailable, TCP
    /// setup fails, or the HTTP/1.1 handshake fails.
    pub async fn connect_plaintext_direct(
        &self,
        host: &str,
        port: u16,
    ) -> Result<Http1Connection, Http1TlsError> {
        self.connect_plaintext_direct_with(host, port, None)
            .await
            .map(|(connection, _)| connection)
    }

    /// Opens one direct plaintext TCP connection as
    /// [`Self::connect_plaintext_direct`] does and, when the TCP settings
    /// select a
    /// [`TcpBackupConnection`](phantom_profile::TcpBackupConnection), uses
    /// and updates `family`, the origin's address family, and returns the
    /// slower attempt when the backup started and that attempt is still
    /// connecting.
    ///
    /// Once the returned [`SlowerConnection`] is polled and connects, it
    /// comes back idle with no keepalive set until its first request.
    ///
    /// This is a seam for the facade's pools, not supported API.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when the Tokio runtime is unavailable, TCP
    /// setup fails, or the HTTP/1.1 handshake fails.
    #[doc(hidden)]
    pub async fn connect_plaintext_direct_keeping_slower(
        &self,
        host: &str,
        port: u16,
        family: &AddressFamilyMemory,
    ) -> Result<(Http1Connection, Option<SlowerConnection<Http1Connection>>), Http1TlsError> {
        self.connect_plaintext_direct_with(host, port, Some(family))
            .await
    }

    async fn connect_plaintext_direct_with(
        &self,
        host: &str,
        port: u16,
        family: Option<&AddressFamilyMemory>,
    ) -> Result<(Http1Connection, Option<SlowerConnection<Http1Connection>>), Http1TlsError> {
        let span = debug_span!(
            "http1.direct.connect",
            transport = "tcp",
            route = "direct",
            outcome = field::Empty,
        );
        let outcome = OperationOutcome::new(&span);
        let result = async {
            let (stream, slower) = connect_tcp_keeping_slower(host, port, self.dialer(), family)
                .await
                .map_err(Http1TlsError::from_direct)?;
            let connection = connect_plaintext(stream).await?;
            Ok((connection, slower.map(slower_plaintext)))
        }
        .instrument(span.clone())
        .await;
        outcome.finish(connection_outcome(&result));
        result
    }

    /// Opens one plaintext HTTP/1.1 connection through a remote-DNS SOCKS5 proxy.
    ///
    /// The configured authentication applies only to the SOCKS5 negotiation.
    /// The tunnel stays plaintext: this method performs no origin TLS
    /// handshake. Proxy failure never falls back to a direct connection.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when the Tokio runtime is unavailable, proxy
    /// authentication or negotiation fails, or the HTTP/1.1 handshake fails.
    pub async fn connect_plaintext_socks5_remote_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
    ) -> Result<Http1Connection, Http1TlsError> {
        self.trace_plaintext_socks5_connect(
            "socks5_remote_dns",
            pin!(async {
                let stream = connection_leg::connect(
                    TcpRoute::Socks5 {
                        proxy: Endpoint {
                            host: proxy_host,
                            port: proxy_port,
                        },
                        target: Socks5Target::RemoteDns(Endpoint {
                            host: target_host,
                            port: target_port,
                        }),
                        auth: auth,
                    },
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
                connect_plaintext(stream).await.map_err(Into::into)
            }),
        )
        .await
    }

    /// Opens one plaintext HTTP/1.1 connection through a local-DNS SOCKS5 proxy.
    ///
    /// The configured authentication applies only to the SOCKS5 negotiation.
    /// The tunnel stays plaintext: this method performs no origin TLS
    /// handshake. Proxy failure never falls back to a direct connection.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when the Tokio runtime is unavailable, target
    /// resolution fails, proxy authentication or negotiation fails, or the
    /// HTTP/1.1 handshake fails.
    pub async fn connect_plaintext_socks5_local_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
    ) -> Result<Http1Connection, Http1TlsError> {
        self.trace_plaintext_socks5_connect(
            "socks5_local_dns",
            pin!(async {
                let stream = connection_leg::connect(
                    TcpRoute::Socks5 {
                        proxy: Endpoint {
                            host: proxy_host,
                            port: proxy_port,
                        },
                        target: Socks5Target::LocalDns(Endpoint {
                            host: target_host,
                            port: target_port,
                        }),
                        auth: auth,
                    },
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
                connect_plaintext(stream).await.map_err(Into::into)
            }),
        )
        .await
    }

    /// Opens one plaintext HTTP/1.1 connection to a forward proxy.
    ///
    /// This method performs no TLS handshake and never connects directly to
    /// the origin.
    pub async fn connect_forward_proxy(
        &self,
        proxy_host: &str,
        proxy_port: u16,
    ) -> Result<Http1Connection, Http1TlsError> {
        let span = debug_span!(
            "http1.proxy.connect",
            transport = "tcp",
            proxy_kind = "forward",
            outcome = field::Empty,
        );
        let outcome = OperationOutcome::new(&span);
        let result = async {
            let stream = connect_tcp(proxy_host, proxy_port, self.dialer())
                .await
                .map_err(|error| match error {
                    DirectConnectError::RuntimeUnavailable => Http1TlsError::RuntimeUnavailable,
                    DirectConnectError::Connect(error) => Http1TlsError::ForwardProxyConnect(error),
                })?;
            connect_plaintext(stream).await.map_err(Into::into)
        }
        .instrument(span.clone())
        .await;
        outcome.finish(connection_outcome(&result));
        result
    }

    /// Opens one HTTP/1.1 connection to a forward proxy over TLS.
    ///
    /// The proxy connector's independent authentication policy applies to the
    /// TLS handshake. TLS terminates at the proxy. This method does not issue
    /// CONNECT, perform origin TLS, connect directly to the origin, or fall back
    /// to another route.
    pub async fn connect_https_forward_proxy(
        &self,
        proxy_connector: &HttpsProxyConnector,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
    ) -> Result<Http1Connection, Http1TlsError> {
        let span = debug_span!(
            "http1.proxy.connect",
            transport = "tls",
            proxy_kind = "forward",
            outcome = field::Empty,
        );
        let outcome = OperationOutcome::new(&span);
        let result = async {
            let stream = proxy_connector
                .connect_forward(proxy_host, proxy_port, proxy_server_name)
                .await?;
            connect_plaintext(stream).await.map_err(Into::into)
        }
        .instrument(span.clone())
        .await;
        outcome.finish(connection_outcome(&result));
        result
    }

    /// Sends one HTTP/1.1 Upgrade GET over a new direct TCP and TLS connection.
    ///
    /// A `101 Switching Protocols` response yields the upgraded byte stream.
    /// Any other status remains an ordinary streaming HTTP response. The
    /// complete request is validated before DNS resolution or TCP I/O.
    ///
    /// The handshake offers early data as [`Self::connect_via`] does, and
    /// the GET, which is replay safe, travels in it: Firefox 157 sends a
    /// WebSocket opening as early data on a resumed connection
    /// (`TlsHandshaker::Check0RttEnabled` and `nsHttpTransaction::Do0RTT`,
    /// `netwerk/protocol/http/TlsHandshaker.cpp:304-320` and
    /// `nsHttpTransaction.cpp:3383-3392` at tag `FIREFOX_157_0_RELEASE`).
    /// After a rejection the GET goes out again on the same connection. A
    /// handshake that then fails returns the [`Http1TlsError::Tls`] a fresh
    /// connection returns, and a server that rejects the early data and
    /// selects another ALPN protocol returns
    /// [`Http1TlsError::UnsupportedAlpn`], as a fresh connection that selects
    /// it does.
    pub async fn upgrade_get_direct(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_upgrade(pin!(async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream =
                connect_tcp(host, port, self.dialer())
                    .await
                    .map_err(|error| match error {
                        DirectConnectError::RuntimeUnavailable => Http1TlsError::RuntimeUnavailable,
                        DirectConnectError::Connect(error) => Http1TlsError::Connect(error),
                    })?;
            debug!("HTTP/1 Upgrade request prepared");
            let stream = self
                .tls
                .connect_offering_early_data(server_name, stream)
                .await?;
            upgrade_over_tls(stream, prepared).await
        }))
        .await
    }

    /// Sends one HTTP/1.1 Upgrade GET over a new direct TCP and TLS
    /// connection that offers Encrypted Client Hello with the
    /// `ECHConfigList` that `ech` yields, as Chrome 154 does when it opens a
    /// `wss://` connection to an origin with an HTTPS record.
    ///
    /// The connection is set up as [`Self::connect_direct_with_ech`] sets it
    /// up, and the request is sent as [`Self::upgrade_get_direct`] sends it.
    /// The complete request is validated before DNS resolution or TCP I/O.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when request validation, TCP setup, TLS
    /// negotiation, ECH, ALPN selection, or the HTTP/1.1 exchange fails.
    #[cfg(feature = "https-records")]
    pub async fn upgrade_get_direct_with_ech(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        ech: impl Future<Output = Option<crate::dns::EchConfigList>>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_upgrade(pin!(async {
            let prepared = PreparedGet::new(target, headers)?;
            debug!("HTTP/1 Upgrade request prepared");
            let stream = crate::direct::connect_tls_with_ech(
                &self.tls,
                self.dialer(),
                host,
                port,
                server_name,
                ech,
                true,
            )
            .await?;
            upgrade_over_tls(stream, prepared).await
        }))
        .await
    }

    /// Sends one HTTP/1.1 Upgrade GET over a new direct plaintext TCP connection.
    ///
    /// A `101 Switching Protocols` response yields the upgraded byte stream.
    /// Any other status remains an ordinary streaming HTTP response. The
    /// complete request is validated before DNS resolution or TCP I/O. This
    /// method performs no TLS handshake and never routes through a proxy.
    pub async fn upgrade_get_plaintext_direct(
        &self,
        host: &str,
        port: u16,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        let span = debug_span!(
            "http1.direct.upgrade_response_head",
            method = "GET",
            transport = "tcp",
            route = "direct",
            status = field::Empty,
            outcome = field::Empty,
        );
        let outcome_guard = OperationOutcome::new(&span);
        let result = async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream =
                connect_tcp(host, port, self.dialer())
                    .await
                    .map_err(|error| match error {
                        DirectConnectError::RuntimeUnavailable => Http1TlsError::RuntimeUnavailable,
                        DirectConnectError::Connect(error) => Http1TlsError::Connect(error),
                    })?;
            debug!("HTTP/1 plaintext Upgrade request prepared");
            let outcome = send_profiled_upgrade(stream, prepared).await?;
            let status = match &outcome {
                Http1UpgradeOutcome::Upgraded(response) => response.status(),
                Http1UpgradeOutcome::Rejected(response) => response.status(),
            };
            Span::current().record("status", status.as_u16());
            Ok(outcome)
        }
        .instrument(span.clone())
        .await;
        outcome_guard.finish(upgrade_outcome(&result));
        result
    }

    /// Sends one absolute-form HTTP/1.1 Upgrade GET to a plaintext forward proxy.
    ///
    /// A `101 Switching Protocols` response yields the upgraded proxy byte
    /// stream. Request validation completes before DNS resolution or proxy I/O.
    /// This method does not issue CONNECT, negotiate origin TLS, connect directly
    /// to the origin, or fall back to another route.
    pub async fn upgrade_get_forward_proxy(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target: AbsoluteForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        let span = debug_span!(
            "http1.proxy.forward.upgrade_response_head",
            method = "GET",
            transport = "tcp",
            route = "forward_proxy",
            status = field::Empty,
            outcome = field::Empty,
        );
        let outcome_guard = OperationOutcome::new(&span);
        let result = async {
            let prepared = PreparedGet::new_forward(target, headers)?;
            let stream = connect_tcp(proxy_host, proxy_port, self.dialer())
                .await
                .map_err(|error| match error {
                    DirectConnectError::RuntimeUnavailable => Http1TlsError::RuntimeUnavailable,
                    DirectConnectError::Connect(error) => Http1TlsError::ForwardProxyConnect(error),
                })?;
            debug!("HTTP/1 plaintext forward-proxy Upgrade request prepared");
            let outcome = send_profiled_upgrade(stream, prepared).await?;
            let status = match &outcome {
                Http1UpgradeOutcome::Upgraded(response) => response.status(),
                Http1UpgradeOutcome::Rejected(response) => response.status(),
            };
            Span::current().record("status", status.as_u16());
            Ok(outcome)
        }
        .instrument(span.clone())
        .await;
        outcome_guard.finish(upgrade_outcome(&result));
        result
    }

    /// Sends one absolute-form HTTP/1.1 Upgrade GET to a forward proxy over TLS.
    ///
    /// TLS terminates at the proxy and uses the proxy connector's authentication
    /// policy. A `101 Switching Protocols` response yields the upgraded proxy byte
    /// stream. This method does not issue CONNECT, negotiate origin TLS, connect
    /// directly to the origin, or fall back to another route.
    pub async fn upgrade_get_https_forward_proxy(
        &self,
        proxy_connector: &HttpsProxyConnector,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        target: AbsoluteForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        let span = debug_span!(
            "http1.proxy.forward.upgrade_response_head",
            method = "GET",
            transport = "tls",
            route = "forward_proxy",
            status = field::Empty,
            outcome = field::Empty,
        );
        let outcome_guard = OperationOutcome::new(&span);
        let result = async {
            let prepared = PreparedGet::new_forward(target, headers)?;
            let stream = proxy_connector
                .connect_forward(proxy_host, proxy_port, proxy_server_name)
                .await?;
            debug!("HTTP/1 HTTPS forward-proxy Upgrade request prepared");
            let outcome = send_profiled_upgrade(stream, prepared).await?;
            let status = match &outcome {
                Http1UpgradeOutcome::Upgraded(response) => response.status(),
                Http1UpgradeOutcome::Rejected(response) => response.status(),
            };
            Span::current().record("status", status.as_u16());
            Ok(outcome)
        }
        .instrument(span.clone())
        .await;
        outcome_guard.finish(upgrade_outcome(&result));
        result
    }

    /// Sends one HTTP/1.1 Upgrade GET through a plaintext HTTP CONNECT proxy.
    ///
    /// Origin and proxy requests are validated before proxy or origin I/O.
    /// Proxy failure never falls back to a direct connection.
    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_get_http_connect(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_upgrade(pin!(async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = connection_leg::connect(
                TcpRoute::HttpConnect(HttpConnectRoute {
                    proxy: ProxyTransport::Tcp(Endpoint {
                        host: proxy_host,
                        port: proxy_port,
                    }),
                    authority: connect_authority,
                    headers: connect_headers,
                    credentials: None,
                }),
                self.dialer(),
                self.proxy_credentials.as_ref(),
            )
            .await?;
            self.send_prepared_upgrade(stream, server_name, prepared)
                .await
        }))
        .await
    }

    /// Sends an Upgrade GET through a plaintext proxy using challenge-driven Basic authentication.
    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_get_http_connect_with_basic_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_upgrade(pin!(async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = connection_leg::connect(
                TcpRoute::HttpConnect(HttpConnectRoute {
                    proxy: ProxyTransport::Tcp(Endpoint {
                        host: proxy_host,
                        port: proxy_port,
                    }),
                    authority: connect_authority,
                    headers: connect_headers,
                    credentials: Some(credentials),
                }),
                self.dialer(),
                self.proxy_credentials.as_ref(),
            )
            .await?;
            self.send_prepared_upgrade(stream, server_name, prepared)
                .await
        }))
        .await
    }

    /// Sends one HTTP/1.1 Upgrade GET through an HTTPS proxy using CONNECT.
    ///
    /// Origin and CONNECT requests are validated before proxy or origin I/O.
    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_get_https_connect(
        &self,
        proxy_connector: &HttpsProxyConnector,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_upgrade(pin!(async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = connection_leg::connect(
                TcpRoute::HttpConnect(HttpConnectRoute {
                    proxy: ProxyTransport::Tls {
                        endpoint: Endpoint {
                            host: proxy_host,
                            port: proxy_port,
                        },
                        server_name: proxy_server_name,
                        connector: proxy_connector,
                    },
                    authority: connect_authority,
                    headers: connect_headers,
                    credentials: None,
                }),
                self.dialer(),
                self.proxy_credentials.as_ref(),
            )
            .await?;
            self.send_prepared_upgrade(stream, server_name, prepared)
                .await
        }))
        .await
    }

    /// Sends an Upgrade GET through an HTTPS proxy using challenge-driven Basic authentication.
    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_get_https_connect_with_basic_auth(
        &self,
        proxy_connector: &HttpsProxyConnector,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_upgrade(pin!(async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = connection_leg::connect(
                TcpRoute::HttpConnect(HttpConnectRoute {
                    proxy: ProxyTransport::Tls {
                        endpoint: Endpoint {
                            host: proxy_host,
                            port: proxy_port,
                        },
                        server_name: proxy_server_name,
                        connector: proxy_connector,
                    },
                    authority: connect_authority,
                    headers: connect_headers,
                    credentials: Some(credentials),
                }),
                self.dialer(),
                self.proxy_credentials.as_ref(),
            )
            .await?;
            self.send_prepared_upgrade(stream, server_name, prepared)
                .await
        }))
        .await
    }

    /// Sends one plaintext HTTP/1.1 Upgrade GET through a CONNECT tunnel on a
    /// plaintext HTTP proxy.
    ///
    /// The origin-form Upgrade is sent inside the tunnel exactly as on a direct
    /// connection. Origin and CONNECT requests are validated before proxy I/O.
    /// This method performs no origin TLS handshake, never sends an
    /// absolute-form request, and never falls back to a direct connection.
    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_get_plaintext_http_connect(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_plaintext_tunnel_upgrade(
            "http_connect",
            pin!(async {
                let prepared = PreparedGet::new(target, headers)?;
                let stream = connection_leg::connect(
                    TcpRoute::HttpConnect(HttpConnectRoute {
                        proxy: ProxyTransport::Tcp(Endpoint {
                            host: proxy_host,
                            port: proxy_port,
                        }),
                        authority: connect_authority,
                        headers: connect_headers,
                        credentials: None,
                    }),
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
                send_plaintext_tunnel_upgrade(stream, prepared).await
            }),
        )
        .await
    }

    /// Sends a plaintext Upgrade GET through a CONNECT tunnel on a plaintext
    /// HTTP proxy, using challenge-driven Basic authentication for CONNECT.
    ///
    /// Credentials go only to the proxy on the CONNECT request, never on the
    /// Upgrade inside the tunnel.
    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_get_plaintext_http_connect_with_basic_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_plaintext_tunnel_upgrade(
            "http_connect",
            pin!(async {
                let prepared = PreparedGet::new(target, headers)?;
                let stream = connection_leg::connect(
                    TcpRoute::HttpConnect(HttpConnectRoute {
                        proxy: ProxyTransport::Tcp(Endpoint {
                            host: proxy_host,
                            port: proxy_port,
                        }),
                        authority: connect_authority,
                        headers: connect_headers,
                        credentials: Some(credentials),
                    }),
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
                send_plaintext_tunnel_upgrade(stream, prepared).await
            }),
        )
        .await
    }

    /// Sends one plaintext HTTP/1.1 Upgrade GET through a CONNECT tunnel on
    /// an HTTPS proxy.
    ///
    /// The proxy connector's protocol selects an HTTP/1.1 CONNECT tunnel or an
    /// RFC 9113 section 8.5 CONNECT stream on an HTTP/2 connection, shared
    /// when the connector has an [`Http2ProxyPool`](crate::proxy::Http2ProxyPool).
    /// The origin-form Upgrade is sent inside it exactly as on a direct
    /// connection, with no origin TLS handshake. Origin and CONNECT requests
    /// are validated before proxy I/O.
    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_get_plaintext_https_connect(
        &self,
        proxy_connector: &HttpsProxyConnector,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_plaintext_tunnel_upgrade(
            "https_connect",
            pin!(async {
                let prepared = PreparedGet::new(target, headers)?;
                let stream = connection_leg::connect(
                    TcpRoute::HttpConnect(HttpConnectRoute {
                        proxy: ProxyTransport::Tls {
                            endpoint: Endpoint {
                                host: proxy_host,
                                port: proxy_port,
                            },
                            server_name: proxy_server_name,
                            connector: proxy_connector,
                        },
                        authority: connect_authority,
                        headers: connect_headers,
                        credentials: None,
                    }),
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
                send_plaintext_tunnel_upgrade(stream, prepared).await
            }),
        )
        .await
    }

    /// Sends a plaintext Upgrade GET through a CONNECT tunnel on an HTTPS
    /// proxy, using challenge-driven Basic authentication for CONNECT.
    ///
    /// Credentials go only to the proxy on the CONNECT request, never on the
    /// Upgrade inside the tunnel.
    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_get_plaintext_https_connect_with_basic_auth(
        &self,
        proxy_connector: &HttpsProxyConnector,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_plaintext_tunnel_upgrade(
            "https_connect",
            pin!(async {
                let prepared = PreparedGet::new(target, headers)?;
                let stream = connection_leg::connect(
                    TcpRoute::HttpConnect(HttpConnectRoute {
                        proxy: ProxyTransport::Tls {
                            endpoint: Endpoint {
                                host: proxy_host,
                                port: proxy_port,
                            },
                            server_name: proxy_server_name,
                            connector: proxy_connector,
                        },
                        authority: connect_authority,
                        headers: connect_headers,
                        credentials: Some(credentials),
                    }),
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
                send_plaintext_tunnel_upgrade(stream, prepared).await
            }),
        )
        .await
    }

    /// Sends one plaintext HTTP/1.1 Upgrade GET through a remote-DNS SOCKS5 proxy.
    ///
    /// The origin request is validated before proxy I/O. The established tunnel
    /// remains plaintext: this method performs no origin TLS handshake. Proxy
    /// failure never falls back to a direct connection.
    pub async fn upgrade_get_plaintext_socks5_remote(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.upgrade_get_plaintext_socks5_remote_with_auth(
            proxy_host,
            proxy_port,
            Socks5Auth::None,
            target_host,
            target_port,
            target,
            headers,
        )
        .await
    }

    /// Sends one plaintext Upgrade GET through a remote-DNS SOCKS5 proxy.
    ///
    /// The configured authentication is applied only to the SOCKS5 negotiation.
    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_get_plaintext_socks5_remote_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_plaintext_socks5_upgrade(
            "socks5_remote_dns",
            pin!(async {
                let prepared = PreparedGet::new(target, headers)?;
                let stream = connection_leg::connect(
                    TcpRoute::Socks5 {
                        proxy: Endpoint {
                            host: proxy_host,
                            port: proxy_port,
                        },
                        target: Socks5Target::RemoteDns(Endpoint {
                            host: target_host,
                            port: target_port,
                        }),
                        auth: auth,
                    },
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
                debug!("HTTP/1 plaintext SOCKS5 Upgrade request prepared");
                let outcome = send_profiled_upgrade(stream, prepared).await?;
                let status = match &outcome {
                    Http1UpgradeOutcome::Upgraded(response) => response.status(),
                    Http1UpgradeOutcome::Rejected(response) => response.status(),
                };
                Span::current().record("status", status.as_u16());
                Ok(outcome)
            }),
        )
        .await
    }

    /// Sends one plaintext HTTP/1.1 Upgrade GET through a local-DNS SOCKS5 proxy.
    ///
    /// The origin request is validated before target DNS resolution or proxy
    /// I/O. The established tunnel remains plaintext: this method performs no
    /// origin TLS handshake. Proxy failure never falls back to a direct
    /// connection.
    pub async fn upgrade_get_plaintext_socks5_local(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.upgrade_get_plaintext_socks5_local_with_auth(
            proxy_host,
            proxy_port,
            Socks5Auth::None,
            target_host,
            target_port,
            target,
            headers,
        )
        .await
    }

    /// Sends one plaintext Upgrade GET through a local-DNS SOCKS5 proxy.
    ///
    /// The configured authentication is applied only to the SOCKS5 negotiation.
    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_get_plaintext_socks5_local_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_plaintext_socks5_upgrade(
            "socks5_local_dns",
            pin!(async {
                let prepared = PreparedGet::new(target, headers)?;
                let stream = connection_leg::connect(
                    TcpRoute::Socks5 {
                        proxy: Endpoint {
                            host: proxy_host,
                            port: proxy_port,
                        },
                        target: Socks5Target::LocalDns(Endpoint {
                            host: target_host,
                            port: target_port,
                        }),
                        auth: auth,
                    },
                    self.dialer(),
                    self.proxy_credentials.as_ref(),
                )
                .await?;
                debug!("HTTP/1 plaintext SOCKS5 Upgrade request prepared");
                let outcome = send_profiled_upgrade(stream, prepared).await?;
                let status = match &outcome {
                    Http1UpgradeOutcome::Upgraded(response) => response.status(),
                    Http1UpgradeOutcome::Rejected(response) => response.status(),
                };
                Span::current().record("status", status.as_u16());
                Ok(outcome)
            }),
        )
        .await
    }

    /// Sends one HTTP/1.1 Upgrade GET through a remote-DNS SOCKS5 proxy.
    ///
    /// The origin request is validated before proxy I/O. Proxy failure never
    /// falls back to a direct connection.
    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_get_socks5_remote(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.upgrade_get_socks5_remote_with_auth(
            proxy_host,
            proxy_port,
            Socks5Auth::None,
            target_host,
            target_port,
            server_name,
            target,
            headers,
        )
        .await
    }

    /// Sends one Upgrade GET through a remote-DNS proxy with configured credentials.
    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_get_socks5_remote_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_upgrade(pin!(async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = connection_leg::connect(
                TcpRoute::Socks5 {
                    proxy: Endpoint {
                        host: proxy_host,
                        port: proxy_port,
                    },
                    target: Socks5Target::RemoteDns(Endpoint {
                        host: target_host,
                        port: target_port,
                    }),
                    auth: auth,
                },
                self.dialer(),
                self.proxy_credentials.as_ref(),
            )
            .await?;
            self.send_prepared_upgrade(stream, server_name, prepared)
                .await
        }))
        .await
    }

    /// Sends one HTTP/1.1 Upgrade GET through a local-DNS SOCKS5 proxy.
    ///
    /// The origin request is validated before DNS or proxy I/O. Proxy failure
    /// never falls back to a direct connection.
    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_get_socks5_local(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.upgrade_get_socks5_local_with_auth(
            proxy_host,
            proxy_port,
            Socks5Auth::None,
            target_host,
            target_port,
            server_name,
            target,
            headers,
        )
        .await
    }

    /// Sends one Upgrade GET through a local-DNS proxy with configured credentials.
    #[allow(clippy::too_many_arguments)]
    pub async fn upgrade_get_socks5_local_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_upgrade(pin!(async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = connection_leg::connect(
                TcpRoute::Socks5 {
                    proxy: Endpoint {
                        host: proxy_host,
                        port: proxy_port,
                    },
                    target: Socks5Target::LocalDns(Endpoint {
                        host: target_host,
                        port: target_port,
                    }),
                    auth: auth,
                },
                self.dialer(),
                self.proxy_credentials.as_ref(),
            )
            .await?;
            self.send_prepared_upgrade(stream, server_name, prepared)
                .await
        }))
        .await
    }

    async fn connect_prepared<S>(
        &self,
        stream: S,
        server_name: &str,
    ) -> Result<Http1Connection, Http1TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + TcpKeepaliveSource + 'static,
    {
        let stream = self.tls.connect(server_name, stream).await?;
        connect_over_tls(stream).await
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
        operation: Pin<&mut F>,
    ) -> Result<Http1Connection, Http1TlsError>
    where
        F: Future<Output = Result<Http1Connection, Http1TlsError>>,
    {
        let span = debug_span!(
            "http1.tls.connect",
            transport = "tls",
            negotiated_alpn = field::Empty,
            outcome = field::Empty,
        );
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

    async fn send_prepared_upgrade<S>(
        &self,
        stream: S,
        server_name: &str,
        prepared: PreparedGet,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + TcpKeepaliveSource + 'static,
    {
        debug!("HTTP/1 Upgrade request prepared");

        let stream = self.tls.connect(server_name, stream).await?;
        upgrade_over_tls(stream, prepared).await
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
        operation: Pin<&mut F>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError>
    where
        F: Future<Output = Result<Http1UpgradeOutcome, Http1TlsError>>,
    {
        let span = debug_span!(
            "http1.tls.upgrade_response_head",
            method = "GET",
            transport = "tls",
            negotiated_alpn = field::Empty,
            status = field::Empty,
            outcome = field::Empty,
        );
        let outcome_guard = OperationOutcome::new(&span);
        let result = operation.instrument(span.clone()).await;
        outcome_guard.finish(upgrade_outcome(&result));
        result
    }

    /// Takes `operation` pinned, for the reason [`Self::trace_connect`] gives,
    /// and drops a cancelled one in the same order.
    async fn trace_plaintext_socks5_connect<F>(
        &self,
        route: &'static str,
        operation: Pin<&mut F>,
    ) -> Result<Http1Connection, Http1TlsError>
    where
        F: Future<Output = Result<Http1Connection, Http1TlsError>>,
    {
        let span = debug_span!(
            "http1.proxy.connect",
            transport = "tcp",
            proxy_kind = route,
            outcome = field::Empty,
        );
        let outcome_guard = OperationOutcome::new(&span);
        let result = operation.instrument(span.clone()).await;
        outcome_guard.finish(connection_outcome(&result));
        result
    }

    /// Takes `operation` pinned, for the reason [`Self::trace_connect`] gives,
    /// and drops a cancelled one in the same order.
    async fn trace_plaintext_tunnel_upgrade<F>(
        &self,
        route: &'static str,
        operation: Pin<&mut F>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError>
    where
        F: Future<Output = Result<Http1UpgradeOutcome, Http1TlsError>>,
    {
        let span = debug_span!(
            "http1.proxy.connect.upgrade_response_head",
            method = "GET",
            transport = "tcp",
            route,
            status = field::Empty,
            outcome = field::Empty,
        );
        let outcome_guard = OperationOutcome::new(&span);
        let result = operation.instrument(span.clone()).await;
        outcome_guard.finish(upgrade_outcome(&result));
        result
    }

    /// Takes `operation` pinned, for the reason [`Self::trace_connect`] gives,
    /// and drops a cancelled one in the same order.
    async fn trace_plaintext_socks5_upgrade<F>(
        &self,
        route: &'static str,
        operation: Pin<&mut F>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError>
    where
        F: Future<Output = Result<Http1UpgradeOutcome, Http1TlsError>>,
    {
        let span = debug_span!(
            "http1.proxy.socks5.upgrade_response_head",
            method = "GET",
            transport = "tcp",
            route,
            status = field::Empty,
            outcome = field::Empty,
        );
        let outcome_guard = OperationOutcome::new(&span);
        let result = operation.instrument(span.clone()).await;
        outcome_guard.finish(upgrade_outcome(&result));
        result
    }
}

/// Sends a prepared plaintext Upgrade on an established proxy tunnel and
/// records the response status on the current span.
async fn send_plaintext_tunnel_upgrade<S>(
    stream: S,
    prepared: PreparedGet,
) -> Result<Http1UpgradeOutcome, Http1TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + TcpKeepaliveSource + 'static,
{
    debug!("HTTP/1 plaintext Upgrade request prepared for a CONNECT tunnel");
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
