use phantom_profile::TlsSettings;

use super::{
    HttpBasicCredentials, HttpConnectError, HttpConnectHeader, TunnelStream,
    http_connect::{
        ChallengeOutcome, PreparedBasicConnect, PreparedConnect, establish,
        establish_authenticated, establish_challenge, record_authentication_attempts,
        trace_connect,
    },
};
use crate::{
    direct::{DirectConnectError, connect_tcp},
    tls::{ServerAuthentication, TlsConnector, TlsStream},
};

/// Reusable TLS configuration for HTTP/1.1 CONNECT through an HTTPS proxy.
#[derive(Clone, Debug)]
pub struct HttpsProxyConnector {
    tls: TlsConnector,
}

impl HttpsProxyConnector {
    /// Builds a connector from TLS settings and bundled public roots.
    pub fn new(settings: &TlsSettings) -> Result<Self, HttpConnectError> {
        require_http1_alpn(settings)?;
        TlsConnector::new(settings)
            .map(|tls| Self { tls })
            .map_err(HttpConnectError::ProxyTls)
    }

    /// Builds a connector with bundled public roots and additional DER certificates.
    pub fn new_with_additional_roots<'a>(
        settings: &TlsSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, HttpConnectError> {
        require_http1_alpn(settings)?;
        TlsConnector::new_with_additional_roots(settings, roots)
            .map(|tls| Self { tls })
            .map_err(HttpConnectError::ProxyTls)
    }

    /// Builds a connector with an explicit server-authentication policy.
    pub fn new_with_server_authentication(
        settings: &TlsSettings,
        server_authentication: ServerAuthentication,
    ) -> Result<Self, HttpConnectError> {
        require_http1_alpn(settings)?;
        TlsConnector::new_with_server_authentication(settings, server_authentication)
            .map(|tls| Self { tls })
            .map_err(HttpConnectError::ProxyTls)
    }

    /// Returns a connector clone with a fresh isolated TLS session cache.
    #[must_use]
    pub fn with_isolated_session_cache(&self) -> Self {
        Self {
            tls: self.tls.with_isolated_session_cache(),
        }
    }

    pub(crate) async fn connect_forward(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
    ) -> Result<TlsStream<tokio::net::TcpStream>, HttpConnectError> {
        self.connect_proxy(proxy_host, proxy_port, proxy_server_name)
            .await
    }

    pub(crate) async fn connect_tunnel(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        authority: &str,
        headers: &[HttpConnectHeader],
    ) -> Result<TunnelStream<TlsStream<tokio::net::TcpStream>>, HttpConnectError> {
        trace_connect("https", async {
            let request = PreparedConnect::new(authority, headers)?;
            let stream =
                connect_tcp(proxy_host, proxy_port)
                    .await
                    .map_err(|error| match error {
                        DirectConnectError::RuntimeUnavailable => {
                            HttpConnectError::RuntimeUnavailable
                        }
                        DirectConnectError::Connect(error) => HttpConnectError::Connect(error),
                    })?;
            let stream = self
                .tls
                .connect(proxy_server_name, stream)
                .await
                .map_err(HttpConnectError::ProxyTls)?;
            if let Some(selected) = stream.negotiated_alpn() {
                if selected != b"http/1.1" {
                    return Err(HttpConnectError::UnsupportedAlpn {
                        selected: selected.into(),
                    });
                }
            }
            establish(stream, request).await
        })
        .await
    }

    pub(crate) async fn connect_tunnel_with_basic_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        proxy_server_name: &str,
        authority: &str,
        headers: &[HttpConnectHeader],
        credentials: &HttpBasicCredentials,
    ) -> Result<TunnelStream<TlsStream<tokio::net::TcpStream>>, HttpConnectError> {
        trace_connect("https", async {
            let requests = PreparedBasicConnect::new(authority, headers, credentials)?;
            record_authentication_attempts(false);
            let stream = self
                .connect_proxy(proxy_host, proxy_port, proxy_server_name)
                .await?;
            match establish_challenge(stream, requests.anonymous).await? {
                ChallengeOutcome::Tunnel(tunnel) => Ok(tunnel),
                ChallengeOutcome::Retry => {
                    record_authentication_attempts(true);
                    let stream = self
                        .connect_proxy(proxy_host, proxy_port, proxy_server_name)
                        .await?;
                    establish_authenticated(stream, requests.authenticated).await
                }
            }
        })
        .await
    }

    async fn connect_proxy(
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
        let stream = self
            .tls
            .connect(proxy_server_name, stream)
            .await
            .map_err(HttpConnectError::ProxyTls)?;
        if let Some(selected) = stream.negotiated_alpn() {
            if selected != b"http/1.1" {
                return Err(HttpConnectError::UnsupportedAlpn {
                    selected: selected.into(),
                });
            }
        }
        Ok(stream)
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
