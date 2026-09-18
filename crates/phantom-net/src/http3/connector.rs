//! Profiled direct HTTP/3 connector.

use std::{error::Error as StdError, fmt, sync::Arc};

use bytes::Bytes;
use http::{Method, Response};
use phantom_profile::{
    Http3RequestSettings, Http3Settings, TlsSettings, quic::QuicTransportSettings,
};
use phantom_quic_btls::{
    InvalidServerName, QuicClientConfig, QuicTlsProfileErrorKind, QuicTransportProfileError,
    StatelessResetKey,
};

#[cfg(test)]
use super::request::PreparedRequest;
use super::{
    Http3Body, Http3Connection, Http3Error, Http3ErrorKind, OriginForm, RequestHeader,
    connect_bound, prepare_traced_request, prepare_traced_request_body_with_trailers, settings,
};
use crate::{
    direct::{RuntimeUnavailable, poll_tokio_io},
    request::{RequestBody, RequestBodyMetadata},
    tls::{TlsConnector, TlsError, TlsErrorKind},
};

type BoxError = Box<dyn StdError + Send + Sync>;

/// Reusable validated configuration for direct HTTP/3 requests and connections.
#[derive(Debug)]
pub struct Http3Connector {
    crypto: Arc<QuicClientConfig>,
    settings: Http3Settings,
    request_settings: Http3RequestSettings,
    identity: Arc<()>,
}

impl Http3Connector {
    /// Builds a connector using Phantom's bundled public trust roots.
    pub fn new(
        tls: &TlsSettings,
        quic: &QuicTransportSettings,
        settings: &Http3Settings,
        request_settings: &Http3RequestSettings,
    ) -> Result<Self, Http3ConnectorError> {
        Self::build(tls, quic, settings, request_settings, std::iter::empty())
    }

    /// Builds a connector with bundled public roots and additional DER certificates.
    ///
    /// Additional roots extend verification for private authorities; they do
    /// not disable certificate or hostname verification.
    pub fn new_with_additional_roots<'a>(
        tls: &TlsSettings,
        quic: &QuicTransportSettings,
        settings: &Http3Settings,
        request_settings: &Http3RequestSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, Http3ConnectorError> {
        Self::build(tls, quic, settings, request_settings, roots)
    }

    fn build<'a>(
        tls: &TlsSettings,
        quic: &QuicTransportSettings,
        settings: &Http3Settings,
        request_settings: &Http3RequestSettings,
        roots: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, Http3ConnectorError> {
        settings
            .validate()
            .map_err(Http3ConnectorError::invalid_profile)?;
        request_settings
            .validate()
            .map_err(Http3ConnectorError::invalid_profile)?;
        quic.validate()
            .map_err(Http3ConnectorError::invalid_profile)?;
        QuicClientConfig::validate_tls_profile(tls).map_err(Http3ConnectorError::quic_tls)?;

        let context = TlsConnector::new_with_additional_roots(tls, roots)
            .map_err(Http3ConnectorError::tls)?
            .into_context();
        let crypto = QuicClientConfig::with_transport_profile(context, quic.clone())
            .map_err(Http3ConnectorError::invalid_quic_profile)?
            .with_tls_profile(tls)
            .map_err(Http3ConnectorError::quic_tls)?;
        let crypto = Arc::new(crypto);
        validate_quic_runtime(&crypto)?;
        if settings.receives_datagrams() && !crypto.receives_datagrams() {
            return Err(Http3ConnectorError::without_source(
                Http3ConnectorErrorKind::InvalidProfile,
                "HTTP/3 Datagram support requires QUIC DATAGRAM receive support",
            ));
        }
        settings::validate_for_connector(settings, &crypto)
            .map_err(Http3ConnectorError::configuration)?;

        Ok(Self {
            crypto,
            settings: settings.clone(),
            request_settings: request_settings.clone(),
            identity: Arc::new(()),
        })
    }

    #[cfg(test)]
    pub(super) fn test_crypto(&self) -> Arc<QuicClientConfig> {
        Arc::clone(&self.crypto)
    }

    /// Sends one empty-body GET over a newly resolved direct QUIC connection.
    ///
    /// The complete request is prepared before the Tokio runtime is checked or
    /// DNS is resolved. This method never falls back to TCP or another HTTP
    /// protocol.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_get_direct(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http3Body>, Http3ConnectorError> {
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

    /// Sends one profiled request over a newly resolved direct connection.
    ///
    /// Address fallback completes before the request is dispatched exactly once.
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
    ) -> Result<Response<Http3Body>, Http3ConnectorError> {
        let request = prepare_traced_request(
            &self.request_settings,
            method,
            authority,
            target,
            headers,
            body,
        )
        .map_err(Http3ConnectorError::transaction)?;
        QuicClientConfig::validate_server_name(server_name)
            .map_err(Http3ConnectorError::invalid_server_name)?;
        tokio::runtime::Handle::try_current()
            .map_err(|_| Http3ConnectorError::runtime_unavailable())?;
        poll_tokio_io(|| async {
            let addresses = tokio::net::lookup_host((host, port))
                .await
                .map_err(Http3ConnectorError::resolve)?
                .collect::<Vec<_>>();
            let connection = self.connect_to_addresses(addresses, server_name).await?;
            connection
                .send_prepared_request(request)
                .await
                .map_err(Http3ConnectorError::transaction)
        })
        .await
        .map_err(|RuntimeUnavailable| Http3ConnectorError::runtime_unavailable())?
    }

    /// Opens one reusable direct HTTP/3 connection.
    ///
    /// The server name is validated before Tokio runtime checks or DNS I/O.
    /// This method never falls back to TCP or another HTTP protocol.
    pub async fn connect_direct(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
    ) -> Result<Http3Connection, Http3ConnectorError> {
        QuicClientConfig::validate_server_name(server_name)
            .map_err(Http3ConnectorError::invalid_server_name)?;
        tokio::runtime::Handle::try_current()
            .map_err(|_| Http3ConnectorError::runtime_unavailable())?;
        poll_tokio_io(|| async {
            let addresses = tokio::net::lookup_host((host, port))
                .await
                .map_err(Http3ConnectorError::resolve)?
                .collect::<Vec<_>>();
            self.connect_to_addresses(addresses, server_name).await
        })
        .await
        .map_err(|RuntimeUnavailable| Http3ConnectorError::runtime_unavailable())?
    }

    /// Sends one empty-body GET over a connection opened by this connector.
    ///
    /// The complete request and connector affinity are validated before a new
    /// request stream opens.
    pub async fn send_get_on(
        &self,
        connection: &Http3Connection,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Response<Http3Body>, Http3ConnectorError> {
        self.send_request_on(connection, Method::GET, authority, target, headers, None)
            .await
    }

    /// Sends one profiled request over a connection opened by this connector.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request_on(
        &self,
        connection: &Http3Connection,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<Bytes>,
    ) -> Result<Response<Http3Body>, Http3ConnectorError> {
        self.send_request_body_on(
            connection,
            method,
            authority,
            target,
            headers,
            body.map(RequestBody::from_bytes),
        )
        .await
    }

    /// Sends one profiled request body over a connection opened by this connector.
    ///
    /// The body is pulled only as HTTP/3 flow control accepts each preceding
    /// DATA frame. Request trailers are rejected by [`RequestBody`].
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request_body_on(
        &self,
        connection: &Http3Connection,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<RequestBody>,
    ) -> Result<Response<Http3Body>, Http3ConnectorError> {
        self.send_request_body_with_trailers_on(
            connection,
            method,
            authority,
            target,
            headers,
            body,
            Vec::new(),
        )
        .await
    }

    /// Sends one profiled request body followed by exact ordered static trailers.
    ///
    /// Trailer fields are validated before a stream opens or the body is polled.
    /// Body-produced trailers remain unsupported.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_request_body_with_trailers_on(
        &self,
        connection: &Http3Connection,
        method: Method,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
        body: Option<RequestBody>,
        trailers: Vec<RequestHeader>,
    ) -> Result<Response<Http3Body>, Http3ConnectorError> {
        let request = prepare_traced_request_body_with_trailers(
            &self.request_settings,
            method,
            authority,
            target,
            headers,
            body,
            trailers,
        )
        .map_err(Http3ConnectorError::transaction)?;
        if !connection.belongs_to(&self.identity) {
            return Err(Http3ConnectorError::connection_mismatch());
        }
        connection
            .send_prepared_request(request)
            .await
            .map_err(Http3ConnectorError::transaction)
    }

    /// Returns whether an originating connection is currently reusable.
    ///
    /// This is a health snapshot for pool selection, not a reservation of peer
    /// stream capacity. A later send can still fail and is never replayed.
    pub async fn can_reuse(&self, connection: &Http3Connection) -> bool {
        connection.belongs_to(&self.identity) && connection.is_reusable().await
    }

    /// Validates an empty-body GET without opening a connection or stream.
    pub fn validate_get(
        &self,
        authority: &str,
        target: &OriginForm,
        headers: &[RequestHeader],
    ) -> Result<(), Http3ConnectorError> {
        self.validate_request(Method::GET, authority, target, headers, None)
    }

    /// Validates one profiled request without opening a connection or stream.
    pub fn validate_request(
        &self,
        method: Method,
        authority: &str,
        target: &OriginForm,
        headers: &[RequestHeader],
        body: Option<&Bytes>,
    ) -> Result<(), Http3ConnectorError> {
        self.validate_request_body(
            method,
            authority,
            target,
            headers,
            body.map(|body| RequestBody::from_bytes(body.clone()).metadata()),
        )
    }

    /// Validates one profiled request and body framing without polling a body.
    pub fn validate_request_body(
        &self,
        method: Method,
        authority: &str,
        target: &OriginForm,
        headers: &[RequestHeader],
        body: Option<RequestBodyMetadata>,
    ) -> Result<(), Http3ConnectorError> {
        super::request::validate_profiled_request_body(
            &self.request_settings,
            method,
            authority,
            target.clone(),
            headers.to_vec(),
            body,
        )
        .map_err(Http3ConnectorError::transaction)
    }

    /// Validates one profiled request, body framing, and static trailers.
    ///
    /// This does not open a connection, stream, or poll the request body.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_request_body_with_trailers(
        &self,
        method: Method,
        authority: &str,
        target: &OriginForm,
        headers: &[RequestHeader],
        body: Option<RequestBodyMetadata>,
        trailers: &[RequestHeader],
    ) -> Result<(), Http3ConnectorError> {
        super::request::validate_profiled_request_body_with_trailers(
            &self.request_settings,
            method,
            authority,
            target.clone(),
            headers.to_vec(),
            body,
            trailers.to_vec(),
        )
        .map_err(Http3ConnectorError::transaction)
    }

    #[cfg(test)]
    pub(super) async fn send_prepared_to_addresses(
        &self,
        addresses: Vec<std::net::SocketAddr>,
        server_name: &str,
        request: PreparedRequest,
    ) -> Result<Response<Http3Body>, Http3ConnectorError> {
        let connection = self.connect_to_addresses(addresses, server_name).await?;
        connection
            .send_prepared_request(request)
            .await
            .map_err(Http3ConnectorError::transaction)
    }

    async fn connect_to_addresses(
        &self,
        addresses: Vec<std::net::SocketAddr>,
        server_name: &str,
    ) -> Result<Http3Connection, Http3ConnectorError> {
        let mut addresses = addresses.into_iter();
        let mut remote = addresses
            .next()
            .ok_or_else(Http3ConnectorError::no_address)?;
        loop {
            match connect_bound(
                remote,
                server_name,
                Arc::clone(&self.crypto),
                &self.settings,
                Arc::clone(&self.identity),
            )
            .await
            {
                Ok(connection) => return Ok(connection),
                Err(error) if should_try_next_address(&error) => {
                    let Some(next) = addresses.next() else {
                        return Err(Http3ConnectorError::transaction(error));
                    };
                    remote = next;
                }
                Err(error) => return Err(Http3ConnectorError::transaction(error)),
            }
        }
    }
}

fn should_try_next_address(error: &Http3Error) -> bool {
    matches!(
        error.kind(),
        Http3ErrorKind::Endpoint | Http3ErrorKind::Connect | Http3ErrorKind::Connection
    )
}

fn validate_quic_runtime(crypto: &Arc<QuicClientConfig>) -> Result<(), Http3ConnectorError> {
    let reset_key = StatelessResetKey::from_bytes(&[0; StatelessResetKey::KEY_LEN])
        .map_err(Http3ConnectorError::local_configuration)?;
    let mut endpoint = quinn::EndpointConfig::new(Arc::new(reset_key));
    let mut transport = quinn::TransportConfig::default();
    crypto
        .configure_transport(&mut endpoint, &mut transport)
        .map_err(Http3ConnectorError::quic_runtime)
}

/// Stable category of a direct HTTP/3 connector failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http3ConnectorErrorKind {
    /// Supplied profile values are internally inconsistent.
    InvalidProfile,
    /// A configured trust root could not be loaded.
    TrustStore,
    /// The backend cannot represent otherwise valid profile values.
    ProtocolConfiguration,
    /// No current Tokio runtime with network I/O enabled was available.
    RuntimeUnavailable,
    /// DNS resolution failed or returned no addresses.
    Resolve,
    /// The request cannot be represented by the current HTTP/3 path.
    Request,
    /// The local UDP or QUIC endpoint could not be initialized.
    Endpoint,
    /// The remote QUIC connection could not be started.
    Connect,
    /// QUIC failed while establishing or driving the connection.
    Connection,
    /// The TLS handshake did not produce the required HTTP/3 state.
    Handshake,
    /// The HTTP/3 connection or request stream failed.
    Protocol,
    /// A local driver or entropy source failed.
    Local,
}

/// Error returned while constructing or using [`Http3Connector`].
#[derive(Debug)]
pub struct Http3ConnectorError {
    kind: Http3ConnectorErrorKind,
    message: &'static str,
    source: Option<BoxError>,
}

impl Http3ConnectorError {
    fn invalid_profile(source: impl StdError + Send + Sync + 'static) -> Self {
        Self::with_source(
            Http3ConnectorErrorKind::InvalidProfile,
            "invalid HTTP/3 client profile",
            source,
        )
    }

    fn invalid_quic_profile(source: QuicTransportProfileError) -> Self {
        Self::invalid_profile(source)
    }

    fn quic_tls(source: phantom_quic_btls::QuicTlsProfileError) -> Self {
        let kind = match source.kind() {
            QuicTlsProfileErrorKind::InvalidProfile => Http3ConnectorErrorKind::InvalidProfile,
            QuicTlsProfileErrorKind::UnsupportedSetting => {
                Http3ConnectorErrorKind::ProtocolConfiguration
            }
            _ => Http3ConnectorErrorKind::ProtocolConfiguration,
        };
        Self::with_source(kind, "failed to configure HTTP/3 TLS", source)
    }

    fn tls(source: TlsError) -> Self {
        let kind = match source.kind() {
            TlsErrorKind::InvalidConfiguration => Http3ConnectorErrorKind::InvalidProfile,
            TlsErrorKind::TrustStore => Http3ConnectorErrorKind::TrustStore,
            TlsErrorKind::BackendConfiguration | TlsErrorKind::UnsupportedSetting => {
                Http3ConnectorErrorKind::ProtocolConfiguration
            }
            TlsErrorKind::Handshake => Http3ConnectorErrorKind::Handshake,
        };
        Self::with_source(kind, "failed to configure HTTP/3 TLS", source)
    }

    fn configuration(source: Http3Error) -> Self {
        Self::with_source(
            Http3ConnectorErrorKind::ProtocolConfiguration,
            "failed to configure HTTP/3",
            source,
        )
    }

    fn quic_runtime(source: QuicTransportProfileError) -> Self {
        Self::with_source(
            Http3ConnectorErrorKind::ProtocolConfiguration,
            "QUIC transport profile is incompatible with the runtime",
            source,
        )
    }

    fn local_configuration(source: impl StdError + Send + Sync + 'static) -> Self {
        Self::with_source(
            Http3ConnectorErrorKind::ProtocolConfiguration,
            "failed to validate QUIC endpoint configuration",
            source,
        )
    }

    const fn runtime_unavailable() -> Self {
        Self::without_source(
            Http3ConnectorErrorKind::RuntimeUnavailable,
            "HTTP/3 network requests require a Tokio runtime with network I/O enabled",
        )
    }

    const fn connection_mismatch() -> Self {
        Self::without_source(
            Http3ConnectorErrorKind::Request,
            "HTTP/3 connection belongs to a different connector",
        )
    }

    fn resolve(source: std::io::Error) -> Self {
        Self::with_source(
            Http3ConnectorErrorKind::Resolve,
            "failed to resolve HTTP/3 origin",
            source,
        )
    }

    fn invalid_server_name(source: InvalidServerName) -> Self {
        Self::with_source(
            Http3ConnectorErrorKind::Request,
            "invalid HTTP/3 server name",
            source,
        )
    }

    const fn no_address() -> Self {
        Self::without_source(
            Http3ConnectorErrorKind::Resolve,
            "HTTP/3 origin resolved to no addresses",
        )
    }

    fn transaction(source: Http3Error) -> Self {
        let kind = match source.kind() {
            Http3ErrorKind::Request => Http3ConnectorErrorKind::Request,
            Http3ErrorKind::Configuration => Http3ConnectorErrorKind::ProtocolConfiguration,
            Http3ErrorKind::RuntimeUnavailable => Http3ConnectorErrorKind::RuntimeUnavailable,
            Http3ErrorKind::Endpoint => Http3ConnectorErrorKind::Endpoint,
            Http3ErrorKind::Connect => Http3ConnectorErrorKind::Connect,
            Http3ErrorKind::Connection => Http3ConnectorErrorKind::Connection,
            Http3ErrorKind::Handshake => Http3ConnectorErrorKind::Handshake,
            Http3ErrorKind::Protocol => Http3ConnectorErrorKind::Protocol,
            Http3ErrorKind::Local => Http3ConnectorErrorKind::Local,
        };
        Self::with_source(kind, "HTTP/3 request failed", source)
    }

    const fn without_source(kind: Http3ConnectorErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            source: None,
        }
    }

    fn with_source(
        kind: Http3ConnectorErrorKind,
        message: &'static str,
        source: impl StdError + Send + Sync + 'static,
    ) -> Self {
        Self {
            kind,
            message,
            source: Some(Box::new(source)),
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> Http3ConnectorErrorKind {
        self.kind
    }
}

impl fmt::Display for Http3ConnectorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.message)?;
        if let Some(source) = &self.source {
            write!(formatter, ": {source}")?;
        }
        Ok(())
    }
}

impl StdError for Http3ConnectorError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source
            .as_deref()
            .map(|source| source as &(dyn StdError + 'static))
    }
}
