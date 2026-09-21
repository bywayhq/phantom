use std::{
    fmt, io,
    pin::Pin,
    task::{Context, Poll},
};

use phantom_profile::{Http2Settings, TlsSettings};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{
    HttpBasicCredentials, HttpConnectError, HttpConnectHeader, TunnelStream,
    http_connect::{
        ChallengeOutcome, PreparedBasicConnect, PreparedConnect, establish,
        establish_authenticated, establish_challenge, record_authentication_attempts,
        trace_connect,
    },
    http2_connect::{self, Http2ChallengeOutcome, PreparedBasicHttp2Connect, PreparedHttp2Connect},
};
use crate::{
    direct::{DirectConnectError, connect_tcp},
    http2::{
        Http2ConnectStream, Http2Connection, Http2TlsError, connect_selected, translate_settings,
        validate_http2,
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
    /// RFC 9113 section 8.5 CONNECT on a dedicated HTTP/2 connection per
    /// tunnel.
    ///
    /// The proxy must select `h2`. Plaintext absolute-form forwarding is not
    /// available in this mode.
    Http2,
}

/// Reusable TLS configuration for forwarding or CONNECT through an HTTPS proxy.
///
/// The default [`HttpsProxyProtocol::Http1`] mode supports HTTP/1.1 forwarding
/// and CONNECT. [`HttpsProxyProtocol::Http2`] supports CONNECT only.
#[derive(Clone, Debug)]
pub struct HttpsProxyConnector {
    tls: TlsConnector,
    offers_h2: bool,
    http2: Option<Http2Settings>,
    protocol: HttpsProxyProtocol,
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
            protocol: HttpsProxyProtocol::Http1,
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
        self
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
    #[must_use]
    pub fn with_isolated_session_cache(&self) -> Self {
        Self {
            tls: self.tls.with_isolated_session_cache(),
            offers_h2: self.offers_h2,
            http2: self.http2.clone(),
            protocol: self.protocol,
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
                let request = PreparedHttp2Connect::new(authority, headers)?;
                self.http2_builder()?;
                let connection = self
                    .connect_http2_proxy(proxy_host, proxy_port, proxy_server_name)
                    .await?;
                http2_connect::establish(&connection, &request).await
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
        match self.protocol {
            HttpsProxyProtocol::Http1 => trace_connect("https", async {
                let requests = PreparedBasicConnect::new(authority, headers, credentials)?;
                record_authentication_attempts(false);
                let stream = self
                    .connect_http1_proxy(proxy_host, proxy_port, proxy_server_name)
                    .await?;
                match establish_challenge(stream, requests.anonymous).await? {
                    ChallengeOutcome::Tunnel(tunnel) => Ok(tunnel),
                    ChallengeOutcome::Retry => {
                        record_authentication_attempts(true);
                        let stream = self
                            .connect_http1_proxy(proxy_host, proxy_port, proxy_server_name)
                            .await?;
                        establish_authenticated(stream, requests.authenticated).await
                    }
                }
            })
            .await
            .map(HttpsProxyTunnel::http1),
            HttpsProxyProtocol::Http2 => trace_connect("https_h2", async {
                let requests = PreparedBasicHttp2Connect::new(authority, headers, credentials)?;
                self.http2_builder()?;
                record_authentication_attempts(false);
                let connection = self
                    .connect_http2_proxy(proxy_host, proxy_port, proxy_server_name)
                    .await?;
                match http2_connect::establish_challenge(&connection, &requests.anonymous).await? {
                    Http2ChallengeOutcome::Tunnel(stream) => Ok(stream),
                    Http2ChallengeOutcome::Retry => {
                        // The challenged connection is not reused: each tunnel
                        // owns one proxy connection, matching HTTP/1.1.
                        drop(connection);
                        record_authentication_attempts(true);
                        let connection = self
                            .connect_http2_proxy(proxy_host, proxy_port, proxy_server_name)
                            .await?;
                        http2_connect::establish_authenticated(&connection, &requests.authenticated)
                            .await
                    }
                }
            })
            .await
            .map(HttpsProxyTunnel::http2),
        }
    }

    async fn connect_proxy_tls(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
    ) -> Result<TlsStream<tokio::net::TcpStream>, HttpConnectError> {
        let stream = connect_tcp(proxy_host, proxy_port)
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

    async fn connect_http1_proxy(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
    ) -> Result<TlsStream<tokio::net::TcpStream>, HttpConnectError> {
        let stream = self
            .connect_proxy_tls(proxy_host, proxy_port, proxy_server_name)
            .await?;
        if let Some(selected) = stream.negotiated_alpn() {
            if selected != b"http/1.1" {
                return Err(HttpConnectError::UnsupportedAlpn {
                    selected: selected.into(),
                });
            }
        }
        Ok(stream)
    }

    /// Opens one dedicated HTTP/2 connection to the proxy.
    ///
    /// The connection is never shared between tunnels, so its lifetime is
    /// bounded by the one tunnel stream that holds it.
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

    fn http2_builder(&self) -> Result<::http2::client::Builder, HttpConnectError> {
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

/// Byte stream carried by an HTTPS proxy tunnel in either proxy protocol.
pub(crate) struct HttpsProxyTunnel {
    inner: TunnelInner,
}

enum TunnelInner {
    Http1(TunnelStream<TlsStream<tokio::net::TcpStream>>),
    Http2(Box<Http2ConnectStream>),
}

impl HttpsProxyTunnel {
    fn http1(stream: TunnelStream<TlsStream<tokio::net::TcpStream>>) -> Self {
        Self {
            inner: TunnelInner::Http1(stream),
        }
    }

    fn http2(stream: Http2ConnectStream) -> Self {
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
