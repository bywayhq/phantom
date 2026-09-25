//! HTTP/1.1 connections and one-shot requests over TLS or a forward proxy.

use std::future::Future;

use bytes::Bytes;
use http::{Method, Response};
use phantom_profile::{TcpSettings, TlsSettings};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, Span, debug, debug_span, field};

use super::{
    AbsoluteForm, Http1Body, Http1Connection, Http1Error, Http1UpgradeOutcome, OperationOutcome,
    OriginForm, PreparedGet, PreparedRequest, RequestHeader, send_prepared_upgrade,
};
use crate::{
    direct::{DirectConnectError, connect_tcp},
    proxy::{
        HttpBasicCredentials, HttpConnectHeader, HttpsProxyConnector, ProxyCredentialCache,
        Socks5Auth, http_connect_tunnel, http_connect_tunnel_with_basic_auth,
        socks5_tunnel_local_dns, socks5_tunnel_remote_dns,
    },
    tls::{TlsConnector, trace_alpn},
};

pub use crate::tls::{ServerAuthentication, TlsError, TlsErrorKind};
pub use error::Http1TlsError;

/// A reusable connector for profiled HTTP/1.1 TLS and proxy-forwarded requests.
#[derive(Clone, Debug)]
pub struct Http1TlsConnector {
    tls: TlsConnector,
    tcp: Option<TcpSettings>,
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
                proxy_credentials: None,
            })
            .map_err(Into::into)
    }

    /// Builds a connector with an explicit server-authentication policy.
    ///
    /// [`ServerAuthentication::Disabled`] accepts unauthenticated server
    /// certificates but continues to send Server Name Indication.
    pub fn new_with_server_authentication(
        settings: &TlsSettings,
        server_authentication: ServerAuthentication,
    ) -> Result<Self, Http1TlsError> {
        require_http1_alpn(settings)?;
        TlsConnector::new_with_server_authentication(settings, server_authentication)
            .map(|tls| Self {
                tls,
                tcp: None,
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

    /// Returns the TCP socket options applied to new connections, if any.
    #[must_use]
    pub fn tcp_settings(&self) -> Option<&TcpSettings> {
        self.tcp.as_ref()
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
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared = PreparedRequest::new(method, target, headers, body)?;
            let connection = self.connect_prepared(stream, server_name).await?;
            self.send_prepared_request(&connection, prepared).await
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
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared = PreparedRequest::new(method, target, headers, body)?;
            let stream = connect_tcp(host, port, self.tcp)
                .await
                .map_err(|error| match error {
                    DirectConnectError::RuntimeUnavailable => Http1TlsError::RuntimeUnavailable,
                    DirectConnectError::Connect(error) => Http1TlsError::Connect(error),
                })?;
            let connection = self.connect_prepared(stream, server_name).await?;
            self.send_prepared_request(&connection, prepared).await
        })
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
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared = PreparedRequest::new_forward(method, target, headers, body)?;
            let connection = self.connect_forward_proxy(proxy_host, proxy_port).await?;
            self.send_prepared_request(&connection, prepared).await
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
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared = PreparedRequest::new(method, target, headers, body)?;
            let stream = http_connect_tunnel(
                self.tcp,
                proxy_host,
                proxy_port,
                connect_authority,
                connect_headers,
            )
            .await?;
            let connection = self.connect_prepared(stream, server_name).await?;
            self.send_prepared_request(&connection, prepared).await
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
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared = PreparedRequest::new(method, target, headers, body)?;
            let stream = http_connect_tunnel_with_basic_auth(
                self.tcp,
                self.proxy_credentials.as_ref(),
                proxy_host,
                proxy_port,
                connect_authority,
                connect_headers,
                credentials,
            )
            .await?;
            let connection = self.connect_prepared(stream, server_name).await?;
            self.send_prepared_request(&connection, prepared).await
        })
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
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared = PreparedRequest::new(method, target, headers, body)?;
            let stream = proxy_connector
                .connect_tunnel(
                    proxy_host,
                    proxy_port,
                    proxy_server_name,
                    connect_authority,
                    connect_headers,
                )
                .await?;
            let connection = self.connect_prepared(stream, server_name).await?;
            self.send_prepared_request(&connection, prepared).await
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
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http1Body>, Http1TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared = PreparedRequest::new(method, target, headers, body)?;
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
            let connection = self.connect_prepared(stream, server_name).await?;
            self.send_prepared_request(&connection, prepared).await
        })
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
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared = PreparedRequest::new(method, target, headers, body)?;
            let stream = socks5_tunnel_remote_dns(
                self.tcp,
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            let connection = self.connect_prepared(stream, server_name).await?;
            self.send_prepared_request(&connection, prepared).await
        })
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
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared = PreparedRequest::new(method, target, headers, body)?;
            let stream = socks5_tunnel_local_dns(
                self.tcp,
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            let connection = self.connect_prepared(stream, server_name).await?;
            self.send_prepared_request(&connection, prepared).await
        })
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
        self.trace_connect(self.connect_prepared(stream, server_name))
            .await
    }

    /// Opens one direct TLS connection for sequential HTTP/1.1 requests.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when TCP setup, TLS negotiation, ALPN
    /// selection, or the HTTP/1.1 handshake fails.
    pub async fn connect_direct(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
    ) -> Result<Http1Connection, Http1TlsError> {
        self.trace_connect(async {
            let stream = connect_tcp(host, port, self.tcp)
                .await
                .map_err(|error| match error {
                    DirectConnectError::RuntimeUnavailable => Http1TlsError::RuntimeUnavailable,
                    DirectConnectError::Connect(error) => Http1TlsError::Connect(error),
                })?;
            self.connect_prepared(stream, server_name).await
        })
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
        let span = debug_span!(
            "http1.direct.connect",
            transport = "tcp",
            route = "direct",
            outcome = field::Empty,
        );
        let outcome = OperationOutcome::new(&span);
        let result = async {
            let stream = connect_tcp(host, port, self.tcp)
                .await
                .map_err(|error| match error {
                    DirectConnectError::RuntimeUnavailable => Http1TlsError::RuntimeUnavailable,
                    DirectConnectError::Connect(error) => Http1TlsError::Connect(error),
                })?;
            Http1Connection::connect(stream).await.map_err(Into::into)
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
        self.trace_plaintext_socks5_connect("socks5_remote_dns", async {
            let stream = socks5_tunnel_remote_dns(
                self.tcp,
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            Http1Connection::connect(stream).await.map_err(Into::into)
        })
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
        self.trace_plaintext_socks5_connect("socks5_local_dns", async {
            let stream = socks5_tunnel_local_dns(
                self.tcp,
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            Http1Connection::connect(stream).await.map_err(Into::into)
        })
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
            let stream = connect_tcp(proxy_host, proxy_port, self.tcp)
                .await
                .map_err(|error| match error {
                    DirectConnectError::RuntimeUnavailable => Http1TlsError::RuntimeUnavailable,
                    DirectConnectError::Connect(error) => Http1TlsError::ForwardProxyConnect(error),
                })?;
            Http1Connection::connect(stream).await.map_err(Into::into)
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
            Http1Connection::connect(stream).await.map_err(Into::into)
        }
        .instrument(span.clone())
        .await;
        outcome.finish(connection_outcome(&result));
        result
    }

    /// Opens one HTTP CONNECT tunnel and establishes HTTP/1.1 over TLS.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when proxy negotiation, TLS negotiation, ALPN
    /// selection, or the HTTP/1.1 handshake fails.
    pub async fn connect_http_connect(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        server_name: &str,
    ) -> Result<Http1Connection, Http1TlsError> {
        self.trace_connect(async {
            let stream = http_connect_tunnel(
                self.tcp,
                proxy_host,
                proxy_port,
                connect_authority,
                connect_headers,
            )
            .await?;
            self.connect_prepared(stream, server_name).await
        })
        .await
    }

    /// Opens a plaintext proxy tunnel using challenge-driven Basic authentication.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_http_connect_with_basic_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        connect_authority: &str,
        connect_headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
        server_name: &str,
    ) -> Result<Http1Connection, Http1TlsError> {
        self.trace_connect(async {
            let stream = http_connect_tunnel_with_basic_auth(
                self.tcp,
                self.proxy_credentials.as_ref(),
                proxy_host,
                proxy_port,
                connect_authority,
                connect_headers,
                credentials,
            )
            .await?;
            self.connect_prepared(stream, server_name).await
        })
        .await
    }

    /// Opens an HTTP/1.1 CONNECT tunnel through an HTTPS proxy and establishes
    /// HTTP/1.1 over origin TLS.
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
    ) -> Result<Http1Connection, Http1TlsError> {
        self.trace_connect(async {
            let stream = proxy_connector
                .connect_tunnel(
                    proxy_host,
                    proxy_port,
                    proxy_server_name,
                    connect_authority,
                    connect_headers,
                )
                .await?;
            self.connect_prepared(stream, server_name).await
        })
        .await
    }

    /// Opens an HTTPS proxy tunnel using challenge-driven Basic authentication.
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
    ) -> Result<Http1Connection, Http1TlsError> {
        self.trace_connect(async {
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
            self.connect_prepared(stream, server_name).await
        })
        .await
    }

    /// Opens one remote-DNS SOCKS5 tunnel and establishes HTTP/1.1 over TLS.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when proxy negotiation, TLS negotiation, ALPN
    /// selection, or the HTTP/1.1 handshake fails.
    pub async fn connect_socks5_remote(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        server_name: &str,
    ) -> Result<Http1Connection, Http1TlsError> {
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

    /// Opens a remote-DNS tunnel with configured credentials and establishes HTTP/1.1.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when proxy authentication or negotiation, TLS
    /// negotiation, ALPN selection, or the HTTP/1.1 handshake fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_socks5_remote_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        server_name: &str,
    ) -> Result<Http1Connection, Http1TlsError> {
        self.trace_connect(async {
            let stream = socks5_tunnel_remote_dns(
                self.tcp,
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            self.connect_prepared(stream, server_name).await
        })
        .await
    }

    /// Opens one local-DNS SOCKS5 tunnel and establishes HTTP/1.1 over TLS.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when target resolution, proxy negotiation,
    /// TLS negotiation, ALPN selection, or the HTTP/1.1 handshake fails.
    pub async fn connect_socks5_local(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        server_name: &str,
    ) -> Result<Http1Connection, Http1TlsError> {
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

    /// Opens a local-DNS tunnel with configured credentials and establishes HTTP/1.1.
    ///
    /// # Errors
    ///
    /// Returns [`Http1TlsError`] when target resolution, proxy authentication
    /// or negotiation, TLS negotiation, ALPN selection, or the HTTP/1.1
    /// handshake fails.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_socks5_local_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        server_name: &str,
    ) -> Result<Http1Connection, Http1TlsError> {
        self.trace_connect(async {
            let stream = socks5_tunnel_local_dns(
                self.tcp,
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            self.connect_prepared(stream, server_name).await
        })
        .await
    }

    /// Sends one HTTP/1.1 Upgrade GET over a new direct TCP and TLS connection.
    ///
    /// A `101 Switching Protocols` response yields the upgraded byte stream.
    /// Any other status remains an ordinary streaming HTTP response. The
    /// complete request is validated before DNS resolution or TCP I/O.
    pub async fn upgrade_get_direct(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http1UpgradeOutcome, Http1TlsError> {
        self.trace_upgrade(async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = connect_tcp(host, port, self.tcp)
                .await
                .map_err(|error| match error {
                    DirectConnectError::RuntimeUnavailable => Http1TlsError::RuntimeUnavailable,
                    DirectConnectError::Connect(error) => Http1TlsError::Connect(error),
                })?;
            self.send_prepared_upgrade(stream, server_name, prepared)
                .await
        })
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
            let stream = connect_tcp(host, port, self.tcp)
                .await
                .map_err(|error| match error {
                    DirectConnectError::RuntimeUnavailable => Http1TlsError::RuntimeUnavailable,
                    DirectConnectError::Connect(error) => Http1TlsError::Connect(error),
                })?;
            debug!("HTTP/1 plaintext Upgrade request prepared");
            let outcome = send_prepared_upgrade(stream, prepared).await?;
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
            let stream = connect_tcp(proxy_host, proxy_port, self.tcp)
                .await
                .map_err(|error| match error {
                    DirectConnectError::RuntimeUnavailable => Http1TlsError::RuntimeUnavailable,
                    DirectConnectError::Connect(error) => Http1TlsError::ForwardProxyConnect(error),
                })?;
            debug!("HTTP/1 plaintext forward-proxy Upgrade request prepared");
            let outcome = send_prepared_upgrade(stream, prepared).await?;
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
            let outcome = send_prepared_upgrade(stream, prepared).await?;
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
        self.trace_upgrade(async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = http_connect_tunnel(
                self.tcp,
                proxy_host,
                proxy_port,
                connect_authority,
                connect_headers,
            )
            .await?;
            self.send_prepared_upgrade(stream, server_name, prepared)
                .await
        })
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
        self.trace_upgrade(async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = http_connect_tunnel_with_basic_auth(
                self.tcp,
                self.proxy_credentials.as_ref(),
                proxy_host,
                proxy_port,
                connect_authority,
                connect_headers,
                credentials,
            )
            .await?;
            self.send_prepared_upgrade(stream, server_name, prepared)
                .await
        })
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
        self.trace_upgrade(async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = proxy_connector
                .connect_tunnel(
                    proxy_host,
                    proxy_port,
                    proxy_server_name,
                    connect_authority,
                    connect_headers,
                )
                .await?;
            self.send_prepared_upgrade(stream, server_name, prepared)
                .await
        })
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
        self.trace_upgrade(async {
            let prepared = PreparedGet::new(target, headers)?;
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
            self.send_prepared_upgrade(stream, server_name, prepared)
                .await
        })
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
        self.trace_plaintext_tunnel_upgrade("http_connect", async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = http_connect_tunnel(
                self.tcp,
                proxy_host,
                proxy_port,
                connect_authority,
                connect_headers,
            )
            .await?;
            send_plaintext_tunnel_upgrade(stream, prepared).await
        })
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
        self.trace_plaintext_tunnel_upgrade("http_connect", async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = http_connect_tunnel_with_basic_auth(
                self.tcp,
                self.proxy_credentials.as_ref(),
                proxy_host,
                proxy_port,
                connect_authority,
                connect_headers,
                credentials,
            )
            .await?;
            send_plaintext_tunnel_upgrade(stream, prepared).await
        })
        .await
    }

    /// Sends one plaintext HTTP/1.1 Upgrade GET through a CONNECT tunnel on
    /// an HTTPS proxy.
    ///
    /// The proxy connector's protocol selects an HTTP/1.1 CONNECT tunnel or an
    /// RFC 9113 section 8.5 CONNECT stream on a dedicated HTTP/2 connection.
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
        self.trace_plaintext_tunnel_upgrade("https_connect", async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = proxy_connector
                .connect_tunnel(
                    proxy_host,
                    proxy_port,
                    proxy_server_name,
                    connect_authority,
                    connect_headers,
                )
                .await?;
            send_plaintext_tunnel_upgrade(stream, prepared).await
        })
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
        self.trace_plaintext_tunnel_upgrade("https_connect", async {
            let prepared = PreparedGet::new(target, headers)?;
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
            send_plaintext_tunnel_upgrade(stream, prepared).await
        })
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
        self.trace_plaintext_socks5_upgrade("socks5_remote_dns", async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = socks5_tunnel_remote_dns(
                self.tcp,
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            debug!("HTTP/1 plaintext SOCKS5 Upgrade request prepared");
            let outcome = send_prepared_upgrade(stream, prepared).await?;
            let status = match &outcome {
                Http1UpgradeOutcome::Upgraded(response) => response.status(),
                Http1UpgradeOutcome::Rejected(response) => response.status(),
            };
            Span::current().record("status", status.as_u16());
            Ok(outcome)
        })
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
        self.trace_plaintext_socks5_upgrade("socks5_local_dns", async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = socks5_tunnel_local_dns(
                self.tcp,
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            debug!("HTTP/1 plaintext SOCKS5 Upgrade request prepared");
            let outcome = send_prepared_upgrade(stream, prepared).await?;
            let status = match &outcome {
                Http1UpgradeOutcome::Upgraded(response) => response.status(),
                Http1UpgradeOutcome::Rejected(response) => response.status(),
            };
            Span::current().record("status", status.as_u16());
            Ok(outcome)
        })
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
        self.trace_upgrade(async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = socks5_tunnel_remote_dns(
                self.tcp,
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            self.send_prepared_upgrade(stream, server_name, prepared)
                .await
        })
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
        self.trace_upgrade(async {
            let prepared = PreparedGet::new(target, headers)?;
            let stream = socks5_tunnel_local_dns(
                self.tcp,
                proxy_host,
                proxy_port,
                target_host,
                target_port,
                auth,
            )
            .await?;
            self.send_prepared_upgrade(stream, server_name, prepared)
                .await
        })
        .await
    }

    async fn connect_prepared<S>(
        &self,
        stream: S,
        server_name: &str,
    ) -> Result<Http1Connection, Http1TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let stream = self.tls.connect(server_name, stream).await?;
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

        Http1Connection::connect(stream).await.map_err(Into::into)
    }

    async fn trace_connect<F>(&self, operation: F) -> Result<Http1Connection, Http1TlsError>
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
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        debug!("HTTP/1 Upgrade request prepared");

        let stream = self.tls.connect(server_name, stream).await?;
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

        let outcome = send_prepared_upgrade(stream, prepared).await?;
        let status = match &outcome {
            Http1UpgradeOutcome::Upgraded(response) => response.status(),
            Http1UpgradeOutcome::Rejected(response) => response.status(),
        };
        Span::current().record("status", status.as_u16());
        Ok(outcome)
    }

    async fn trace_response_head<F>(
        &self,
        method: &Method,
        body_bytes: usize,
        operation: F,
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

    async fn trace_upgrade<F>(&self, operation: F) -> Result<Http1UpgradeOutcome, Http1TlsError>
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

    async fn trace_plaintext_socks5_connect<F>(
        &self,
        route: &'static str,
        operation: F,
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

    async fn trace_plaintext_tunnel_upgrade<F>(
        &self,
        route: &'static str,
        operation: F,
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

    async fn trace_plaintext_socks5_upgrade<F>(
        &self,
        route: &'static str,
        operation: F,
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
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    debug!("HTTP/1 plaintext Upgrade request prepared for a CONNECT tunnel");
    let outcome = send_prepared_upgrade(stream, prepared).await?;
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

fn connection_outcome(result: &Result<Http1Connection, Http1TlsError>) -> &'static str {
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
