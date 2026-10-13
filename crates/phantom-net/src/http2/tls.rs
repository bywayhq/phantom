//! HTTP/2 connections and one-shot requests over the crate's TLS transport.

use std::{
    error::Error as StdError,
    fmt,
    future::Future,
    pin::{Pin, pin},
};

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
    SourceBinding,
    connection_leg::{self, ConnectionLegError},
    direct::{Dialer, DirectConnectError},
    host_resolver::HostResolver,
    proxy::{HttpConnectError, HttpsProxyConnector, ProxyCredentialCache, Socks5Error},
    route::{DirectTlsSetup, Http2Route, OriginRoute, ProxyTransport, TcpRoute},
    tcp::{TcpKeepaliveControl, TcpKeepaliveSource},
    tls::{ClientCertificate, ServerAuthentication, TlsConnector, TlsStream, trace_alpn},
};

use crate::tls::{EchFailure, TlsError};

/// Reusable TLS and HTTP/2 settings for connections and one-shot requests.
///
/// # Examples
///
/// ```no_run
/// use phantom_net::{
///     http2::Http2TlsConnector,
///     request::{OriginForm, RequestHeader},
///     route::{DirectTlsSetup, Endpoint, Http2Route, OriginRoute, TcpRoute},
/// };
/// use phantom_profile::browser::chrome;
///
/// # async fn request() -> Result<(), Box<dyn std::error::Error>> {
/// let connector = Http2TlsConnector::new(&chrome::v154_tcp_tls(), &chrome::v154_http2())?;
/// let route = Http2Route::Origin(OriginRoute::Tls {
///     tcp: TcpRoute::Direct(Endpoint { host: "example.com", port: 443 }),
///     server_name: "example.com",
///     setup: DirectTlsSetup::Default,
/// });
/// let connection = connector.connect(route).await?;
/// let _response = connection.send_get(
///     "example.com",
///     OriginForm::parse("/")?,
///     vec![RequestHeader::new("accept", "*/*")],
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Debug)]
pub struct Http2TlsConnector {
    tls: TlsConnector,
    http2: Http2Settings,
    tcp: Option<TcpSettings>,
    source: Option<SourceBinding>,
    host_resolver: Option<HostResolver>,
    proxy_credentials: Option<ProxyCredentialCache>,
}

impl Http2TlsConnector {
    /// Builds a connector from validated TLS and HTTP/2 settings.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] when TLS cannot offer HTTP/2 or the
    /// TLS settings are invalid or unsupported. Invalid HTTP/2 settings also fail.
    pub fn new(tls: &TlsSettings, http2: &Http2Settings) -> Result<Self, Http2TlsError> {
        require_h2_alpn(tls)?;
        validate_http2(http2)?;
        TlsConnector::new(tls)
            .map(|tls| Self {
                tls,
                http2: http2.clone(),
                tcp: None,
                source: None,
                host_resolver: None,
                proxy_credentials: None,
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
                source: None,
                host_resolver: None,
                proxy_credentials: None,
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
                source: None,
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
            http2: self.http2.clone(),
            tcp: self.tcp,
            source: self.source.clone(),
            host_resolver: self.host_resolver.clone(),
            proxy_credentials: self.proxy_credentials.clone(),
        }
    }

    /// Applies TCP socket options to every TCP connection this connector opens.
    ///
    /// The options cover direct origin connections and connections to HTTP
    /// and SOCKS5 proxies. An HTTPS proxy connection uses the options of the
    /// [`HttpsProxyConnector`](crate::proxy::HttpsProxyConnector) passed with it.
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
    /// [`HttpsProxyConnector`](crate::proxy::HttpsProxyConnector) passed with it. Clones of this connector share
    /// `cache`.
    #[must_use]
    pub fn with_proxy_credential_cache(mut self, cache: ProxyCredentialCache) -> Self {
        self.proxy_credentials = Some(cache);
        self
    }

    pub(crate) fn proxy_credential_cache(&self) -> Option<&ProxyCredentialCache> {
        self.proxy_credentials.as_ref()
    }

    /// An HTTP/2 connector over `tls`, which must offer `h2`, with the
    /// validated `http2` settings and the connection settings of another
    /// connector.
    pub(crate) fn from_parts(
        tls: TlsConnector,
        http2: Http2Settings,
        tcp: Option<TcpSettings>,
        source: Option<SourceBinding>,
        host_resolver: Option<HostResolver>,
        proxy_credentials: Option<ProxyCredentialCache>,
    ) -> Self {
        Self {
            tls,
            http2,
            tcp,
            source,
            host_resolver,
            proxy_credentials,
        }
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
    /// [`HttpsProxyConnector`](crate::proxy::HttpsProxyConnector) passed with it. An invalid binding fails each
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
    /// resolved through the [`HttpsProxyConnector`](crate::proxy::HttpsProxyConnector) passed with it. A target
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

    pub(crate) fn tls_connector(&self) -> &TlsConnector {
        &self.tls
    }

    pub(crate) fn settings(&self) -> &Http2Settings {
        &self.http2
    }

    /// Opens an exact HTTP/2 origin or TLS forward-proxy connection.
    ///
    /// Direct origin connections offer early data. Other origin routes use
    /// an ordinary TLS handshake. ECH follows the direct setup policy's
    /// bounded lookup wait and retry after rejection.
    ///
    /// A forwarding route uses its proxy connector's TLS and HTTP/2 settings.
    /// Its credentials select a pool partition and are not sent by this call.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] for invalid routes or settings, connection
    /// setup, TLS, ALPS, or HTTP/2 failures. Plaintext origins, plaintext
    /// forwarding proxies, and retaining a slower attempt fail before I/O.
    pub async fn connect(&self, route: Http2Route<'_>) -> Result<Http2Connection, Http2TlsError> {
        match route {
            Http2Route::Origin(origin) => {
                self.trace_connect(pin!(async {
                    origin
                        .validate(false, false)
                        .map_err(Http2TlsError::Connect)?;
                    let client = translate_settings(&self.http2)?;
                    self.connect_origin(origin, client, true, false).await
                }))
                .await
            }
            Http2Route::Forward { proxy, credentials } => {
                let ProxyTransport::Tls {
                    endpoint,
                    server_name,
                    connector,
                } = proxy
                else {
                    return Err(HttpConnectError::ForwardingRequiresHttp2.into());
                };
                connector
                    .connect_forward_http2_with_credentials(
                        endpoint.host,
                        endpoint.port,
                        server_name,
                        credentials,
                    )
                    .await
                    .map_err(Into::into)
            }
        }
    }

    /// Sends one request through an HTTP/2 origin or TLS forwarding route.
    ///
    /// Request, settings, and route validation finish before I/O. Origin
    /// routes use an ordinary TLS handshake, including direct connections.
    /// Forwarding uses the proxy connector's profile and `:scheme=http`.
    /// Credentials select its pool partition. Supply any authorization
    /// header explicitly in `headers`.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] for request validation, unsupported route
    /// setup, TLS negotiation, or HTTP/2 failures.
    pub async fn send(
        &self,
        route: Http2Route<'_>,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http2Body>, Http2TlsError> {
        let trace_method = method.clone();
        let body_bytes = body.as_ref().map_or(0, Bytes::len);
        self.trace_response_head(
            &trace_method,
            body_bytes,
            pin!(async {
                let settings = match &route {
                    Http2Route::Origin(origin) => {
                        origin
                            .validate(false, false)
                            .map_err(Http2TlsError::Connect)?;
                        &self.http2
                    }
                    Http2Route::Forward { proxy, .. } => {
                        forward_connector(proxy)?.forward_http2_settings()?
                    }
                };
                let mut prepared =
                    PreparedRequest::new(settings, method, authority, target, headers, body)?;
                if matches!(&route, Http2Route::Forward { .. }) {
                    let mut parts = prepared.request.uri().clone().into_parts();
                    parts.scheme = Some(http::uri::Scheme::HTTP);
                    *prepared.request.uri_mut() = http::Uri::from_parts(parts)
                        .map_err(|error| Http2Error::InvalidRequestUri(error.into()))?;
                }
                debug!("HTTP/2 request prepared");
                let connection = match route {
                    Http2Route::Origin(origin) => {
                        self.connect_origin(origin, prepared.client, false, false)
                            .await?
                    }
                    Http2Route::Forward { proxy, credentials } => {
                        let ProxyTransport::Tls {
                            endpoint,
                            server_name,
                            connector,
                        } = proxy
                        else {
                            return Err(HttpConnectError::ForwardingRequiresHttp2.into());
                        };
                        connector
                            .connect_forward_http2_with_credentials(
                                endpoint.host,
                                endpoint.port,
                                server_name,
                                credentials,
                            )
                            .await?
                    }
                };
                let response = connection
                    .send_prepared_request(prepared.request, prepared.body, prepared.trailers)
                    .await?;
                Span::current().record("status", response.status().as_u16());
                Ok(response)
            }),
        )
        .await
    }

    /// Opens one WebSocket extended CONNECT stream over an origin route.
    ///
    /// Settings and ordered headers are validated before I/O. Direct routes
    /// offer early data. Their connection preface and SETTINGS travel in it,
    /// while CONNECT waits for the server's answer. Firefox 157 starts its
    /// HTTP/2 session in early data and holds the WebSocket transaction until
    /// the session is established (`nsHttpConnection::Start0RTTSpdy` and
    /// `nsHttpConnection::MoveTransactionsToSpdy`,
    /// `netwerk/protocol/http/nsHttpConnection.cpp:203-221` and `272-305` at
    /// tag `FIREFOX_157_0_RELEASE`). A rejected early-data preface and SETTINGS
    /// are sent again on the same connection. Proxy routes use ordinary TLS.
    ///
    /// # Errors
    ///
    /// Returns [`Http2TlsError`] for invalid settings, headers or routes,
    /// connection setup, unsupported peer extended CONNECT, or stream errors.
    /// Forwarding routes are rejected before I/O. This never changes protocol.
    pub async fn extended_connect(
        &self,
        route: Http2Route<'_>,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http2ExtendedConnectOutcome, Http2TlsError> {
        let client = self.prepare_extended_connect(authority, &target, &headers)?;
        let Http2Route::Origin(origin) = route else {
            return Err(invalid_route("extended CONNECT requires an origin route"));
        };
        origin
            .validate(false, false)
            .map_err(Http2TlsError::Connect)?;
        let connection = self.connect_origin(origin, client, true, true).await?;
        connection
            .send_extended_connect_with_settings(&self.http2, authority, target, headers)
            .await
            .map_err(|error| {
                connection
                    .early_data_failure()
                    .unwrap_or_else(|| error.into())
            })
    }

    async fn connect_origin(
        &self,
        origin: OriginRoute<'_>,
        client: Http2Builder,
        early_data: bool,
        extended_connect: bool,
    ) -> Result<Http2Connection, Http2TlsError> {
        origin
            .validate(false, false)
            .map_err(Http2TlsError::Connect)?;
        let OriginRoute::Tls {
            tcp,
            server_name,
            setup,
        } = origin
        else {
            return Err(invalid_route("HTTP/2 origins require TLS"));
        };
        match setup {
            DirectTlsSetup::Default => {
                let direct = matches!(&tcp, TcpRoute::Direct(_));
                let stream =
                    connection_leg::connect(tcp, self.dialer(), self.proxy_credentials.as_ref())
                        .await?;
                let stream = if early_data && direct {
                    self.tls
                        .connect_offering_early_data(server_name, stream)
                        .await?
                } else {
                    self.tls.connect(server_name, stream).await?
                };
                let keepalive = stream.tcp_keepalive();
                connect_over_tls(stream, client, extended_connect, keepalive).await
            }
            #[cfg(feature = "https-records")]
            DirectTlsSetup::Ech(ech) => {
                let TcpRoute::Direct(endpoint) = tcp else {
                    return Err(invalid_route("ECH requires a direct TCP route"));
                };
                let stream = crate::direct::connect_tls_with_ech(
                    &self.tls,
                    self.dialer(),
                    endpoint.host,
                    endpoint.port,
                    server_name,
                    ech,
                    early_data,
                )
                .await?;
                let keepalive = stream.tcp_keepalive();
                connect_over_tls(stream, client, extended_connect, keepalive).await
            }
            DirectTlsSetup::KeepSlower(_) => {
                Err(invalid_route("HTTP/2 cannot retain a slower connection"))
            }
        }
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
    ) -> Result<Http2Connection, Http2TlsError>
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

    /// Takes `operation` pinned, for the reason [`Self::trace_connect`] gives,
    /// and drops a cancelled one in the same order.
    async fn trace_response_head<F>(
        &self,
        method: &Method,
        body_bytes: usize,
        operation: Pin<&mut F>,
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

fn invalid_route(message: &'static str) -> Http2TlsError {
    Http2TlsError::Connect(std::io::Error::new(
        std::io::ErrorKind::InvalidInput,
        message,
    ))
}

fn forward_connector<'a>(
    proxy: &ProxyTransport<'a>,
) -> Result<&'a HttpsProxyConnector, Http2TlsError> {
    match proxy {
        ProxyTransport::Tls { connector, .. } => Ok(connector),
        ProxyTransport::Tcp(_) => Err(HttpConnectError::ForwardingRequiresHttp2.into()),
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
    let early_data = stream.early_data_wait();
    if early_data.is_some() {
        return Http2Connection::connect_with_early_data(
            stream,
            client,
            accept_ch,
            extended_connect,
            early_data,
        )
        .await
        .map_err(Into::into);
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
///
/// HTTP/2 turns off `keepalive`, when there is one.
async fn connect_over_tls<S>(
    stream: TlsStream<S>,
    client: Http2Builder,
    extended_connect: bool,
    keepalive: Option<TcpKeepaliveControl>,
) -> Result<Http2Connection, Http2TlsError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let negotiated = stream.negotiated_alpn();
    Span::current().record("negotiated_alpn", trace_alpn(negotiated));
    match negotiated {
        Some(b"h2") => {
            if let Some(keepalive) = &keepalive {
                keepalive.http2_negotiated();
            }
        }
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

/// Stable category of HTTP/2 TLS or proxy setup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http2TlsErrorKind {
    /// The operation requires a Tokio runtime.
    RuntimeUnavailable,
    /// Opening the direct TCP connection failed.
    Connect,
    /// Opening or negotiating the HTTP proxy connection failed.
    HttpProxy,
    /// SOCKS5 connection setup failed.
    Socks5Proxy,
    /// TLS setup or the handshake failed.
    Tls,
    /// HTTP/2 preparation or protocol setup failed.
    Http2,
    /// The peer selected no protocol or a protocol other than HTTP/2.
    UnsupportedAlpn,
    /// The peer sent invalid HTTP/2 application settings.
    PeerApplicationSettings,
    /// The TLS profile cannot negotiate HTTP/2.
    InvalidConfiguration,
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
            Self::Connect(_) => formatter.write_str("TCP connection failed"),
            Self::Proxy(_) => formatter.write_str("HTTP proxy failed"),
            Self::Socks5Proxy(_) => formatter.write_str("SOCKS5 proxy failed"),
            Self::Tls(_) => formatter.write_str("TLS connection failed"),
            Self::Http2(_) => formatter.write_str("HTTP/2 request failed"),
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

impl From<ConnectionLegError> for Http2TlsError {
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

impl Http2TlsError {
    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> Http2TlsErrorKind {
        match self {
            Self::RuntimeUnavailable => Http2TlsErrorKind::RuntimeUnavailable,
            Self::Connect(_) => Http2TlsErrorKind::Connect,
            Self::Proxy(_) => Http2TlsErrorKind::HttpProxy,
            Self::Socks5Proxy(_) => Http2TlsErrorKind::Socks5Proxy,
            Self::Tls(_) => Http2TlsErrorKind::Tls,
            Self::Http2(_) => Http2TlsErrorKind::Http2,
            Self::MissingNegotiatedAlpn | Self::UnsupportedAlpn { .. } => {
                Http2TlsErrorKind::UnsupportedAlpn
            }
            Self::InvalidPeerApplicationSettings { .. } => {
                Http2TlsErrorKind::PeerApplicationSettings
            }
            Self::MissingHttp2Alpn => Http2TlsErrorKind::InvalidConfiguration,
        }
    }

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
