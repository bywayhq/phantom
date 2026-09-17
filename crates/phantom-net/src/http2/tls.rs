//! HTTP/2 connections and one-shot requests over the crate's TLS transport.

use std::{error::Error as StdError, fmt, future::Future};

use bytes::Bytes;
use http::{Method, Response};
use phantom_profile::{Http2Settings, TlsSettings};
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{Instrument, Span, debug, debug_span, field};

use super::{
    Http2Body, Http2Connection, Http2Error, OperationOutcome, OriginForm, PreparedRequest,
    RequestHeader, alps, translate_settings,
};
use crate::{
    direct::{DirectConnectError, connect_tcp},
    proxy::{
        HttpConnectError, HttpConnectHeader, Socks5Error, connect_http_tunnel_direct,
        connect_socks5_tunnel_direct, connect_socks5_tunnel_local,
    },
    tls::{TlsConnector, trace_alpn},
};

pub use crate::tls::{TlsError, TlsErrorKind};

/// Reusable TLS and HTTP/2 settings for connections and one-shot requests.
#[derive(Clone, Debug)]
pub struct Http2TlsConnector {
    tls: TlsConnector,
    http2: Http2Settings,
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
        }
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
            let stream = connect_tcp(host, port).await.map_err(|error| match error {
                DirectConnectError::RuntimeUnavailable => Http2TlsError::RuntimeUnavailable,
                DirectConnectError::Connect(error) => Http2TlsError::Connect(error),
            })?;
            self.connect_prepared(stream, server_name, client).await
        })
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
            let stream = connect_http_tunnel_direct(
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
        self.trace_connect(async {
            let client = translate_settings(&self.http2)?;
            let stream =
                connect_socks5_tunnel_direct(proxy_host, proxy_port, target_host, target_port)
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
        self.trace_connect(async {
            let client = translate_settings(&self.http2)?;
            let stream =
                connect_socks5_tunnel_local(proxy_host, proxy_port, target_host, target_port)
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
            let stream = connect_tcp(host, port).await.map_err(|error| match error {
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
            let stream = connect_http_tunnel_direct(
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
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared =
                PreparedRequest::new(&self.http2, method, authority, target, headers, body)?;
            let stream =
                connect_socks5_tunnel_direct(proxy_host, proxy_port, target_host, target_port)
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
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(&trace_method, body_bytes, async {
            let prepared =
                PreparedRequest::new(&self.http2, method, authority, target, headers, body)?;
            let stream =
                connect_socks5_tunnel_local(proxy_host, proxy_port, target_host, target_port)
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
            .send_prepared_request(prepared.request, prepared.body)
            .await?;
        Span::current().record("status", response.status().as_u16());
        Ok(response)
    }

    async fn connect_prepared<S>(
        &self,
        stream: S,
        server_name: &str,
        mut client: ::http2::client::Builder,
    ) -> Result<Http2Connection, Http2TlsError>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let stream = self.tls.connect(server_name, stream).await?;
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
            client.initial_peer_settings(settings);
        }

        Http2Connection::connect_with_builder_and_accept_ch(stream, client, accept_ch)
            .await
            .map_err(Into::into)
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

/// Error returned while establishing HTTP/2 over TLS or opening a request.
#[derive(Debug)]
#[non_exhaustive]
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

impl From<TlsError> for Http2TlsError {
    fn from(error: TlsError) -> Self {
        Self::Tls(error)
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

fn validate_http2(settings: &Http2Settings) -> Result<(), Http2TlsError> {
    settings.validate().map_err(Http2Error::InvalidSettings)?;
    translate_settings(settings)?;
    Ok(())
}

#[cfg(test)]
mod tests;
