//! Profiled direct HTTP/3 connector.

use std::{error::Error as StdError, fmt, sync::Arc};

use bytes::Bytes;
use http::{Method, Response};
use phantom_profile::{
    Http3RequestSettings, Http3Settings, TcpSettings, TlsSettings, quic::QuicTransportSettings,
};
use tracing::Instrument;

use phantom_quic_btls::{
    InvalidServerName, QuicClientConfig, QuicTlsProfileErrorKind, QuicTransportProfileError,
    StatelessResetKey,
};

#[cfg(test)]
use super::request::PreparedRequest;
use super::{
    ConnectUdpError, ConnectUdpErrorKind, Http3Body, Http3Connection, Http3Error, Http3ErrorKind,
    Http3ExtendedConnectOutcome, Http3ExtendedProtocol, OriginForm, RequestHeader, connect_bound,
    connect_bound_with_socket,
    connect_udp::{self, OpenOutcome},
    prepare_traced_request, prepare_traced_request_body_with_trailers, settings,
};
use crate::{
    direct::{Dialer, RuntimeUnavailable, poll_tokio_io},
    host_resolver::{HostResolver, resolve},
    proxy::{
        HttpBasicCredentials, HttpsProxyConnector, HttpsProxyProtocol, PreparedConnectUdp,
        Socks5Auth, Socks5Error, associate_socks5_udp_local_with_auth,
        associate_socks5_udp_remote_with_auth, prepare_socks5_udp_remote_target,
    },
    request::{RequestBody, RequestBodyMetadata},
    tls::{EchFailure, TlsConnector, TlsError, TlsErrorKind},
};

type BoxError = Box<dyn StdError + Send + Sync>;

/// Reusable validated configuration for direct HTTP/3 requests and connections.
#[derive(Debug)]
pub struct Http3Connector {
    crypto: Arc<QuicClientConfig>,
    ech_from_https_records: bool,
    settings: Http3Settings,
    request_settings: Http3RequestSettings,
    max_datagram_frame_size: Option<u64>,
    max_udp_payload_size: u64,
    identity: Arc<()>,
    tcp: Option<TcpSettings>,
    host_resolver: Option<HostResolver>,
    #[cfg(feature = "keylog")]
    key_log: crate::tls::key_log::KeyLogSlot,
    /// Directory that receives one qlog file per new QUIC connection.
    #[cfg(feature = "qlog")]
    qlog_dir: Option<Arc<std::path::Path>>,
    #[cfg(test)]
    early_peer_alps: Option<Arc<[u8]>>,
    #[cfg(test)]
    remembered_settings: Option<Arc<[u8]>>,
    #[cfg(test)]
    restart_hold: Option<Arc<tokio::sync::Semaphore>>,
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

        let mut resumption_error = None;
        let tls_connector = TlsConnector::new_quic_with_additional_roots(tls, roots, |builder| {
            if let Err(error) = QuicClientConfig::enable_session_resumption(builder) {
                resumption_error = Some(error);
            }
        })
        .map_err(Http3ConnectorError::tls)?;
        if let Some(error) = resumption_error {
            return Err(Http3ConnectorError::quic_tls(error));
        }
        #[cfg(feature = "keylog")]
        let key_log = tls_connector.key_log().clone();
        let context = tls_connector.into_context();
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
            ech_from_https_records: tls.ech_from_https_records,
            settings: settings.clone(),
            request_settings: request_settings.clone(),
            max_datagram_frame_size: quic.max_datagram_frame_size,
            max_udp_payload_size: quic.max_udp_payload_size,
            identity: Arc::new(()),
            tcp: None,
            host_resolver: None,
            #[cfg(feature = "keylog")]
            key_log,
            #[cfg(feature = "qlog")]
            qlog_dir: None,
            #[cfg(test)]
            early_peer_alps: None,
            #[cfg(test)]
            remembered_settings: None,
            #[cfg(test)]
            restart_hold: None,
        })
    }

    /// Returns a connector clone with a fresh, empty QUIC ticket cache.
    ///
    /// When the TLS profile enables `session_tickets`, connections opened by
    /// the clone retain the TLS 1.3 tickets their peers issue and present one
    /// on a later connection to the same verified server name, resuming the
    /// session. Tickets never leave the clone: give each origin and route its
    /// own clone, as Phantom's client pool does, so a ticket learned through
    /// one proxy is never presented directly or through another route. The
    /// clone keeps this connector's identity, so connections it opens remain
    /// usable with this connector. A connector not produced by this method
    /// never resumes. A resumed connection offers early data when the QUIC
    /// profile sets `early_data` or after [`Self::with_early_data`], and
    /// advertises `initial_rtt_us` when the profile lists that parameter and
    /// an earlier connection from the clone measured a round-trip time to the
    /// same server.
    #[must_use]
    pub fn with_isolated_session_cache(&self) -> Self {
        self.with_crypto(self.crypto.with_isolated_session_cache())
    }

    /// Returns whether connections from this connector resume sessions.
    #[must_use]
    pub fn resumes_sessions(&self) -> bool {
        self.crypto.resumes_sessions()
    }

    /// Returns a clone that stores new tickets in this connector's cache but
    /// never presents one.
    ///
    /// Use it to repeat a connection attempt with a full handshake after an
    /// attempt that presented a ticket failed its handshake. The clone keeps
    /// this connector's identity, profile, and ticket cache.
    #[must_use]
    pub fn without_ticket_offers(&self) -> Self {
        self.with_crypto(self.crypto.without_ticket_offers())
    }

    /// Returns a clone that sends early (0-RTT) data on resumed connections.
    ///
    /// A connector sends early data from the start when its QUIC profile sets
    /// `early_data`, as the Chrome 154 recipe does; [`Self::without_early_data`]
    /// turns it off.
    ///
    /// # Replay
    ///
    /// Early data is replayable. An attacker who records a connection's first
    /// flight can deliver it to the server again, and the server may process
    /// each copy (RFC 8446, section 8; RFC 9001, section 9.2).
    ///
    /// A connection from the clone sends early data only when it presents a
    /// ticket that permits it, which needs [`Self::with_isolated_session_cache`]
    /// and a profile with `session_tickets`. Such a connection is returned
    /// before its handshake completes. Only a replay-safe request, a safe
    /// method (`GET`, `HEAD`, `OPTIONS`, or `TRACE`) with no body and no
    /// trailers, is sent before the handshake; every other request, including
    /// extended CONNECT and CONNECT-UDP, waits for it. If the server rejects
    /// the early data, the requests sent early fail with
    /// [`Http3Unprocessed::EarlyDataRejected`](super::Http3Unprocessed): the
    /// server processed none of them. The connection then starts HTTP/3 again
    /// after the handshake, without the SETTINGS remembered with the ticket,
    /// and carries later requests, including those sent again.
    ///
    /// The clone shares this connector's ticket cache and identity.
    #[must_use]
    pub fn with_early_data(&self) -> Self {
        self.with_crypto(self.crypto.with_early_data())
    }

    /// Returns a clone that never sends early data, sharing the ticket cache
    /// and identity.
    #[must_use]
    pub fn without_early_data(&self) -> Self {
        self.with_crypto(self.crypto.without_early_data())
    }

    /// Returns whether resumed connections from this connector may send early
    /// (0-RTT) data.
    #[must_use]
    pub fn sends_early_data(&self) -> bool {
        self.crypto.sends_early_data()
    }

    /// Waits until the server has answered `connection`'s early data.
    ///
    /// The result follows [`Http3Connection::early_data_settled`]: `Ok` for a
    /// connection that sent none, whose early data was accepted, or that
    /// started HTTP/3 again after a rejection, and otherwise the error that
    /// stops the connection from carrying a request.
    pub async fn early_data_settled_on(
        &self,
        connection: &Http3Connection,
    ) -> Result<(), Http3ConnectorError> {
        connection
            .early_data_settled()
            .await
            .map_err(Http3ConnectorError::transaction)
    }

    /// Returns whether a request waits for the peer's HTTP/3 SETTINGS before
    /// its HEADERS are encoded, as under dynamic QPACK encoding.
    ///
    /// A connection that sent early data and
    /// [started from remembered SETTINGS](Http3Connection::started_from_remembered_settings)
    /// already has them, so its requests do not wait. On any other connection
    /// that sent early data, the SETTINGS arrive with the server's first
    /// flight, which also completes the handshake, so such a request never
    /// leaves in 0-RTT packets.
    #[must_use]
    pub fn requests_wait_for_peer_settings(&self) -> bool {
        self.settings.qpack_encoding == phantom_profile::Http3QpackEncoding::Dynamic
    }

    fn with_crypto(&self, crypto: QuicClientConfig) -> Self {
        self.with_shared_crypto(Arc::new(crypto))
    }

    fn with_shared_crypto(&self, crypto: Arc<QuicClientConfig>) -> Self {
        Self {
            crypto,
            ech_from_https_records: self.ech_from_https_records,
            settings: self.settings.clone(),
            request_settings: self.request_settings.clone(),
            max_datagram_frame_size: self.max_datagram_frame_size,
            max_udp_payload_size: self.max_udp_payload_size,
            identity: Arc::clone(&self.identity),
            tcp: self.tcp,
            host_resolver: self.host_resolver.clone(),
            #[cfg(feature = "keylog")]
            key_log: self.key_log.clone(),
            #[cfg(feature = "qlog")]
            qlog_dir: self.qlog_dir.clone(),
            #[cfg(test)]
            early_peer_alps: self.early_peer_alps.clone(),
            #[cfg(test)]
            remembered_settings: self.remembered_settings.clone(),
            #[cfg(test)]
            restart_hold: self.restart_hold.clone(),
        }
    }

    /// Returns whether the TLS settings offer Encrypted Client Hello from
    /// HTTPS records on direct connections
    /// ([`TlsSettings::ech_from_https_records`]).
    #[must_use]
    pub const fn ech_from_https_records(&self) -> bool {
        self.ech_from_https_records
    }

    /// Returns whether a connection to `server_name` would present a ticket.
    #[must_use]
    pub fn has_ticket_for(&self, server_name: &str) -> bool {
        self.crypto.has_ticket_for(server_name)
    }

    /// Applies TCP socket options to the TCP control connection of each
    /// SOCKS5 UDP association this connector opens.
    ///
    /// QUIC itself runs over UDP, so direct connections are unaffected. The
    /// settings are checked before any DNS or socket I/O; invalid settings, or
    /// settings this host cannot apply exactly (see
    /// [`crate::tcp::check_host_support`]), fail the association's proxy
    /// connection.
    #[must_use]
    pub fn with_tcp_settings(mut self, settings: &TcpSettings) -> Self {
        self.tcp = Some(*settings);
        self
    }

    /// Returns the TCP socket options applied to SOCKS5 control connections.
    #[must_use]
    pub fn tcp_settings(&self) -> Option<&TcpSettings> {
        self.tcp.as_ref()
    }

    /// Returns a clone that resolves host names through `resolver` instead of
    /// asking the operating system for every connection.
    ///
    /// The resolver covers the origin host of a direct connection, the host
    /// of a SOCKS5 or CONNECT-UDP proxy, and the target of a local-DNS SOCKS5
    /// route. A target that a proxy resolves is never looked up locally. The
    /// clone shares this connector's ticket cache and identity, and its own
    /// clones share `resolver`.
    ///
    /// Unlike the TCP connectors' `with_host_resolver`, this borrows `self`,
    /// like [`Self::with_early_data`] and the other clone-returning methods
    /// here: an `Http3Connector` is not `Clone`, and callers often hold it in
    /// an `Arc`, so a consuming method could not rebind a shared connector.
    #[must_use]
    pub fn with_host_resolver(&self, resolver: HostResolver) -> Self {
        let mut connector = self.with_shared_crypto(Arc::clone(&self.crypto));
        connector.host_resolver = Some(resolver);
        connector
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
        self.key_log.attach(sender);
    }

    /// Writes a qlog file for each QUIC connection this connector opens into
    /// `dir`, which must exist.
    ///
    /// Each file holds one connection's QUIC events as JSON-SEQ, without
    /// request fields or payloads. A connection whose file cannot be created
    /// fails with a configuration error.
    #[cfg(feature = "qlog")]
    #[must_use]
    pub fn with_qlog_dir(mut self, dir: impl Into<std::path::PathBuf>) -> Self {
        self.qlog_dir = Some(Arc::from(dir.into()));
        self
    }

    // Without `qlog`, every remaining field is named, so the update is empty.
    #[cfg_attr(not(feature = "qlog"), expect(clippy::needless_update))]
    fn diagnostics(&self) -> super::ConnectionDiagnostics {
        super::ConnectionDiagnostics {
            #[cfg(feature = "qlog")]
            qlog_dir: self.qlog_dir.clone(),
            #[cfg(test)]
            early_peer_alps: self.early_peer_alps.clone(),
            #[cfg(test)]
            remembered_settings: self.remembered_settings.clone(),
            #[cfg(test)]
            restart_hold: self.restart_hold.clone(),
            ..super::ConnectionDiagnostics::default()
        }
    }

    /// Makes each early-data connection read `alps` as its peer's ALPS when
    /// its handshake completes, in place of what the handshake carried.
    #[cfg(test)]
    pub(super) fn with_test_early_peer_alps(mut self, alps: &[u8]) -> Self {
        self.early_peer_alps = Some(Arc::from(alps));
        self
    }

    /// Makes each connection whose early data is rejected take a permit from
    /// `hold` after its new HTTP/3 session is built and before the answer
    /// is published.
    #[cfg(test)]
    pub(super) fn with_test_restart_hold(mut self, hold: Arc<tokio::sync::Semaphore>) -> Self {
        self.restart_hold = Some(hold);
        self
    }

    /// Makes each connection that starts from remembered SETTINGS read
    /// `payload` in place of the state stored with its ticket.
    #[cfg(test)]
    pub(super) fn with_test_remembered_settings(mut self, payload: &[u8]) -> Self {
        self.remembered_settings = Some(Arc::from(payload));
        self
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
            let addresses = resolve(self.host_resolver.as_ref(), host, port)
                .await
                .map_err(Http3ConnectorError::resolve)?;
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
            let addresses = resolve(self.host_resolver.as_ref(), host, port)
                .await
                .map_err(Http3ConnectorError::resolve)?;
            self.connect_to_addresses(addresses, server_name).await
        })
        .await
        .map_err(|RuntimeUnavailable| Http3ConnectorError::runtime_unavailable())?
    }

    /// Opens one reusable direct HTTP/3 connection that offers Encrypted
    /// Client Hello with the `ECHConfigList` that `ech` yields, as Chrome 154's
    /// QUIC client does with the `ech` value of an origin's HTTPS record.
    ///
    /// The host is resolved first. The connection then waits for `ech` at
    /// most 20% of the address resolution time, clamped to 5-50 ms, and not
    /// at all when the client's address cache supplied the addresses; `ech`
    /// still pending then counts as `None`. Chromium likewise starts a QUIC
    /// session only once host resolution, including the HTTPS record within
    /// the same bound, has finished. With `None` the connection is the one
    /// [`Self::connect_direct`] makes.
    ///
    /// A list the TLS client rejects fails with
    /// [`EchFailure::InvalidConfigList`] before any packet is sent. When the
    /// server rejects ECH and authenticates as the public name, the
    /// connection fails with [`EchFailure::Rejected`] after closing with the
    /// TLS `ech_required` alert. It is not repeated, with the server's retry
    /// configurations or at another address: Chrome 154 does not repeat a
    /// rejected QUIC connection, and its request is served over TCP instead.
    ///
    /// # Errors
    ///
    /// Returns [`Http3ConnectorError`] for server-name, runtime, resolution,
    /// ECH, connection, and handshake failures.
    #[cfg(feature = "https-records")]
    pub async fn connect_direct_with_ech(
        &self,
        host: &str,
        port: u16,
        server_name: &str,
        ech: impl std::future::Future<Output = Option<crate::dns::EchConfigList>>,
    ) -> Result<Http3Connection, Http3ConnectorError> {
        use phantom_quic_btls::{EchOffer, EchOutcome};

        QuicClientConfig::validate_server_name(server_name)
            .map_err(Http3ConnectorError::invalid_server_name)?;
        tokio::runtime::Handle::try_current()
            .map_err(|_| Http3ConnectorError::runtime_unavailable())?;
        poll_tokio_io(|| async {
            let started = std::time::Instant::now();
            let (addresses, stored) =
                crate::host_resolver::resolve_noting_cache(self.host_resolver.as_ref(), host, port)
                    .await
                    .map_err(Http3ConnectorError::resolve)?;
            if addresses.is_empty() {
                return Err(Http3ConnectorError::no_address());
            }
            let extra_time = if stored {
                std::time::Duration::ZERO
            } else {
                crate::direct::https_record_extra_time(started.elapsed())
            };
            let deadline = crate::shutdown_timer::after(extra_time).map_err(|_| {
                Http3ConnectorError::without_source(
                    Http3ConnectorErrorKind::Local,
                    "could not schedule the HTTPS record deadline",
                )
            })?;
            let list = tokio::select! {
                biased;
                list = ech => list,
                _ = deadline => None,
            };
            let offer = match list {
                Some(list) => {
                    list.parse()
                        .map_err(Http3ConnectorError::invalid_ech_config_list)?;
                    Some(EchOffer::new(list.as_bytes()))
                }
                None => None,
            };
            let crypto = match &offer {
                Some(offer) => Arc::new(self.crypto.with_ech(offer)),
                None => Arc::clone(&self.crypto),
            };
            tracing::debug!(
                ech_offered = offer.is_some(),
                "QUIC connection may offer ECH"
            );
            let result = self
                .connect_to_addresses_with_crypto(addresses, server_name, crypto, None)
                .await
                .map_err(Http3ConnectorError::transaction);
            match (result, offer.as_ref().and_then(EchOffer::outcome)) {
                (Err(error), Some(EchOutcome::Rejected { retry_configs })) => {
                    tracing::debug!(
                        retry_configs = retry_configs.is_some(),
                        "server rejected ECH over QUIC; not retrying"
                    );
                    Err(error.with_ech(EchFailure::Rejected))
                }
                (Err(error), Some(EchOutcome::InvalidConfigList)) => {
                    Err(error.with_ech(EchFailure::InvalidConfigList))
                }
                (result, _) => result,
            }
        })
        .await
        .map_err(|RuntimeUnavailable| Http3ConnectorError::runtime_unavailable())?
    }

    /// Opens one reusable HTTP/3 connection through a SOCKS5 UDP association.
    ///
    /// Domain targets remain domain names for proxy-owned resolution. This
    /// method never resolves the target locally or falls back to a direct route
    /// or another protocol.
    pub async fn connect_socks5_remote(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        server_name: &str,
    ) -> Result<Http3Connection, Http3ConnectorError> {
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

    /// Opens one reusable HTTP/3 connection through an authenticated SOCKS5 UDP association.
    ///
    /// The server name, authentication, and remote target are validated before
    /// the Tokio runtime is checked or proxy I/O begins. The target is sent to
    /// the proxy without local DNS resolution. Proxy and QUIC failures are
    /// terminal for this connection attempt.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_socks5_remote_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        server_name: &str,
    ) -> Result<Http3Connection, Http3ConnectorError> {
        QuicClientConfig::validate_server_name(server_name)
            .map_err(Http3ConnectorError::invalid_server_name)?;
        let auth = auth.validate().map_err(Http3ConnectorError::proxy)?;
        let target = prepare_socks5_udp_remote_target(target_host, target_port)
            .map_err(Http3ConnectorError::proxy)?;
        tokio::runtime::Handle::try_current()
            .map_err(|_| Http3ConnectorError::runtime_unavailable())?;
        poll_tokio_io(|| async {
            let association = associate_socks5_udp_remote_with_auth(
                self.dialer(),
                proxy_host,
                proxy_port,
                target,
                auth,
            )
            .await
            .map_err(Http3ConnectorError::proxy)?;
            let (socket, logical_remote) = association.into_parts();
            connect_bound_with_socket(
                logical_remote,
                server_name,
                Arc::clone(&self.crypto),
                &self.settings,
                Arc::clone(&self.identity),
                socket,
                self.diagnostics(),
            )
            .await
            .map_err(Http3ConnectorError::transaction)
        })
        .await
        .map_err(|RuntimeUnavailable| Http3ConnectorError::runtime_unavailable())?
    }

    /// Opens one reusable HTTP/3 connection through a SOCKS5 UDP association.
    ///
    /// The target is resolved locally, and each resolved address receives a
    /// fresh UDP association attempt. The proxy never receives a domain target,
    /// and failure never falls back to a direct route or another protocol.
    pub async fn connect_socks5_local(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        server_name: &str,
    ) -> Result<Http3Connection, Http3ConnectorError> {
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

    /// Opens one reusable HTTP/3 connection through an authenticated SOCKS5 UDP association.
    ///
    /// The server name, connector profile, and authentication are validated
    /// before target DNS or proxy I/O. Target DNS remains local. A pre-handshake
    /// QUIC failure advances to the next resolved address using a new
    /// association; proxy failures and all other failures are terminal.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_socks5_local_with_auth(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        target_host: &str,
        target_port: u16,
        server_name: &str,
    ) -> Result<Http3Connection, Http3ConnectorError> {
        QuicClientConfig::validate_server_name(server_name)
            .map_err(Http3ConnectorError::invalid_server_name)?;
        let auth = auth.validate().map_err(Http3ConnectorError::proxy)?;
        tokio::runtime::Handle::try_current()
            .map_err(|_| Http3ConnectorError::runtime_unavailable())?;
        poll_tokio_io(|| async {
            let addresses = resolve(self.host_resolver.as_ref(), target_host, target_port)
                .await
                .map_err(Http3ConnectorError::resolve)?;
            self.connect_socks5_to_addresses(proxy_host, proxy_port, auth, addresses, server_name)
                .await
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

    /// Sends one profiled request body followed by exact ordered trailers.
    ///
    /// Static trailer fields and a streaming body's declared trailer-name plan
    /// are validated before a stream opens or the body is polled. They cannot
    /// be combined on one request.
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

    /// Opens one RFC 9220 extended CONNECT stream on a connection opened by
    /// this connector.
    ///
    /// The request fields, profile pseudo-header order, and connector affinity
    /// are validated before the connection is touched. The request is sent
    /// only after the peer's SETTINGS enable extended CONNECT; otherwise this
    /// returns [`Http3ErrorKind::ExtendedConnectUnavailable`] without opening a
    /// stream or trying another protocol.
    pub async fn send_extended_connect_on(
        &self,
        connection: &Http3Connection,
        protocol: Http3ExtendedProtocol,
        authority: &str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<Http3ExtendedConnectOutcome, Http3ConnectorError> {
        let request = super::request::prepare_extended_connect(
            &self.request_settings,
            protocol.wire_value(),
            authority,
            target,
            headers,
        )
        .map_err(Http3ConnectorError::transaction)?;
        if !connection.belongs_to(&self.identity) {
            return Err(Http3ConnectorError::connection_mismatch());
        }
        connection
            .send_extended_connect(protocol, request)
            .await
            .map_err(Http3ConnectorError::transaction)
    }

    /// Opens one reusable HTTP/3 connection through an RFC 9298 CONNECT-UDP proxy.
    ///
    /// `proxy` opens a fresh outer HTTP/3 connection to `proxy_host` with its
    /// own trust roots and server name; this connector owns the inner QUIC
    /// connection, origin trust, and `server_name`. The outer connection
    /// carries exactly one CONNECT-UDP request for `path` with `:authority`
    /// set to `proxy_authority`, a generated `capsule-protocol: ?1` field,
    /// and `headers` in order.
    ///
    /// The server names, request, and outer profile are validated before the
    /// runtime is checked or any I/O starts. The outer profile must send
    /// `SETTINGS_H3_DATAGRAM = 1` and accept a full 1200-byte inner Initial in
    /// one HTTP Datagram; the outer connection assumes a 1252-byte UDP path
    /// MTU. Failures are [`Http3ConnectorErrorKind::Proxy`] errors whose
    /// source is a [`ConnectUdpError`] until the tunnel is open; inner QUIC
    /// failures keep their ordinary kinds. Nothing falls back to a direct
    /// route, another proxy protocol, DATAGRAM capsules, or another HTTP
    /// version.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_connect_udp(
        &self,
        proxy: &Http3Connector,
        proxy_host: &str,
        proxy_port: u16,
        proxy_authority: &str,
        path: OriginForm,
        headers: Vec<RequestHeader>,
        server_name: &str,
    ) -> Result<Http3Connection, Http3ConnectorError> {
        self.connect_connect_udp_with_basic_auth(
            proxy,
            proxy_host,
            proxy_port,
            proxy_authority,
            path,
            headers,
            None,
            server_name,
        )
        .await
    }

    /// Opens one CONNECT-UDP connection over HTTP/3 with optional
    /// challenge-driven HTTP Basic proxy authentication.
    ///
    /// This behaves like [`Self::connect_connect_udp`]. With `credentials`,
    /// the first request omits them; a 407 carrying a valid Basic challenge
    /// is retried exactly once on a fresh outer connection with a
    /// never-indexed `proxy-authorization` field after `headers`. A second
    /// 407 is [`ConnectUdpErrorKind::Authentication`]. Both request forms are
    /// validated before I/O.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_connect_udp_with_basic_auth(
        &self,
        proxy: &Http3Connector,
        proxy_host: &str,
        proxy_port: u16,
        proxy_authority: &str,
        path: OriginForm,
        headers: Vec<RequestHeader>,
        credentials: Option<&HttpBasicCredentials>,
        server_name: &str,
    ) -> Result<Http3Connection, Http3ConnectorError> {
        QuicClientConfig::validate_server_name(server_name)
            .map_err(Http3ConnectorError::invalid_server_name)?;
        let (anonymous, authenticated) = proxy
            .prepare_connect_udp_requests(proxy_host, proxy_authority, path, headers, credentials)
            .map_err(Http3ConnectorError::connect_udp)?;
        tokio::runtime::Handle::try_current()
            .map_err(|_| Http3ConnectorError::runtime_unavailable())?;
        poll_tokio_io(|| async {
            let span = connect_udp::span("h3");
            let tunnel = async {
                let addresses = resolve(self.host_resolver.as_ref(), proxy_host, proxy_port)
                    .await
                    .map_err(|error| {
                        ConnectUdpError::with_source(
                            ConnectUdpErrorKind::Resolve,
                            "failed to resolve CONNECT-UDP proxy",
                            error,
                        )
                    })?;
                if addresses.is_empty() {
                    return Err(ConnectUdpError::new(
                        ConnectUdpErrorKind::Resolve,
                        "CONNECT-UDP proxy resolved to no addresses",
                    ));
                }
                let inspect_challenge = authenticated.is_some();
                if inspect_challenge {
                    connect_udp::record_attempts(&span, false);
                }
                let outer = proxy
                    .connect_to_addresses_with_mtu(
                        addresses.clone(),
                        proxy_host,
                        Some(connect_udp::OUTER_PATH_MTU),
                    )
                    .await
                    .map_err(ConnectUdpError::outer)?;
                let retry =
                    match connect_udp::open(outer, anonymous, span.clone(), inspect_challenge)
                        .await?
                    {
                        OpenOutcome::Tunnel(socket, logical_remote) => {
                            return Ok((socket, logical_remote));
                        }
                        OpenOutcome::Retry => authenticated,
                    };
                let Some(authenticated) = retry else {
                    return Err(ConnectUdpError::new(
                        ConnectUdpErrorKind::Protocol,
                        "CONNECT-UDP proxy challenged a request without credentials",
                    ));
                };
                connect_udp::record_attempts(&span, true);
                // The challenged outer connection is not reused: each tunnel
                // owns one proxy connection, matching HTTP/1.1 and HTTP/2.
                let outer = proxy
                    .connect_to_addresses_with_mtu(
                        addresses,
                        proxy_host,
                        Some(connect_udp::OUTER_PATH_MTU),
                    )
                    .await
                    .map_err(ConnectUdpError::outer)?;
                match connect_udp::open(outer, authenticated, span.clone(), false).await {
                    Ok(OpenOutcome::Tunnel(socket, logical_remote)) => Ok((socket, logical_remote)),
                    Ok(OpenOutcome::Retry) => Err(ConnectUdpError::new(
                        ConnectUdpErrorKind::Protocol,
                        "CONNECT-UDP proxy challenged the authenticated retry",
                    )),
                    Err(error)
                        if error.status()
                            == Some(http::StatusCode::PROXY_AUTHENTICATION_REQUIRED) =>
                    {
                        Err(ConnectUdpError::authentication_rejected())
                    }
                    Err(error) => Err(error),
                }
            }
            .instrument(span.clone())
            .await;
            connect_udp::record_setup_outcome(&span, &tunnel.as_ref().map(drop));
            let (socket, logical_remote) = tunnel.map_err(Http3ConnectorError::connect_udp)?;
            connect_bound_with_socket(
                logical_remote,
                server_name,
                Arc::clone(&self.crypto),
                &self.settings,
                Arc::clone(&self.identity),
                socket,
                self.diagnostics(),
            )
            .await
            .map_err(Http3ConnectorError::transaction)
        })
        .await
        .map_err(|RuntimeUnavailable| Http3ConnectorError::runtime_unavailable())?
    }

    /// Opens one reusable HTTP/3 connection through a CONNECT-UDP proxy
    /// reached over TLS with HTTP/1.1 Upgrade or HTTP/2 extended CONNECT.
    ///
    /// `protocol` selects the proxy leg. [`HttpsProxyProtocol::Http1`] sends
    /// RFC 9298 section 3.2 `GET` with `Upgrade: connect-udp` and requires a
    /// 101 response; the proxy must select `http/1.1` or omit ALPN.
    /// [`HttpsProxyProtocol::Http2`] sends RFC 9298 section 3.4 extended
    /// CONNECT after the proxy enables `SETTINGS_ENABLE_CONNECT_PROTOCOL`;
    /// the proxy must select `h2`, and the connector's HTTP/2 settings must
    /// carry an extended CONNECT pseudo-header order. Any other ALPN
    /// selection is [`ConnectUdpErrorKind::UnsupportedProtocol`].
    ///
    /// Generated `Host` (HTTP/1.1), `Connection`, `Upgrade`, and
    /// `Capsule-Protocol: ?1` fields precede `headers`. UDP payloads travel
    /// in DATAGRAM capsules on the request stream (RFC 9297 section 3.5), so
    /// the inner connection has no outer datagram-size limit beyond the
    /// 65 527-byte Context ID zero bound. Basic `credentials` follow the
    /// same one-retry challenge flow as
    /// [`Self::connect_connect_udp_with_basic_auth`], each attempt on a fresh
    /// proxy connection. The request and leg configuration are validated
    /// before I/O. Nothing falls back to another leg, route, or protocol.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_connect_udp_over_tcp(
        &self,
        proxy: &HttpsProxyConnector,
        protocol: HttpsProxyProtocol,
        proxy_host: &str,
        proxy_port: u16,
        proxy_authority: &str,
        path: OriginForm,
        headers: Vec<RequestHeader>,
        credentials: Option<&HttpBasicCredentials>,
        server_name: &str,
    ) -> Result<Http3Connection, Http3ConnectorError> {
        QuicClientConfig::validate_server_name(server_name)
            .map_err(Http3ConnectorError::invalid_server_name)?;
        let request = prepare_connect_udp_over_tcp(
            proxy,
            protocol,
            proxy_authority,
            &path,
            &headers,
            credentials,
        )
        .map_err(Http3ConnectorError::connect_udp)?;
        tokio::runtime::Handle::try_current()
            .map_err(|_| Http3ConnectorError::runtime_unavailable())?;
        poll_tokio_io(|| async {
            let span = connect_udp::span(match protocol {
                HttpsProxyProtocol::Http2 => "h2",
                _ => "http/1.1",
            });
            let tunnel = async {
                let stream = proxy
                    .connect_udp_tunnel(proxy_host, proxy_port, proxy_host, request, &span)
                    .await
                    .map_err(ConnectUdpError::proxy_leg)?;
                connect_udp::open_stream(stream, span.clone())
            }
            .instrument(span.clone())
            .await;
            connect_udp::record_setup_outcome(&span, &tunnel.as_ref().map(drop));
            let (socket, logical_remote) = tunnel.map_err(Http3ConnectorError::connect_udp)?;
            connect_bound_with_socket(
                logical_remote,
                server_name,
                Arc::clone(&self.crypto),
                &self.settings,
                Arc::clone(&self.identity),
                socket,
                self.diagnostics(),
            )
            .await
            .map_err(Http3ConnectorError::transaction)
        })
        .await
        .map_err(|RuntimeUnavailable| Http3ConnectorError::runtime_unavailable())?
    }

    /// Validates a CONNECT-UDP request and this connector as its outer
    /// profile without opening a connection.
    pub fn validate_connect_udp(
        &self,
        proxy_host: &str,
        proxy_authority: &str,
        path: &OriginForm,
        headers: &[RequestHeader],
    ) -> Result<(), Http3ConnectorError> {
        self.validate_connect_udp_with_basic_auth(proxy_host, proxy_authority, path, headers, None)
    }

    /// Validates both forms of an optionally authenticated HTTP/3
    /// CONNECT-UDP request and this connector as its outer profile.
    pub fn validate_connect_udp_with_basic_auth(
        &self,
        proxy_host: &str,
        proxy_authority: &str,
        path: &OriginForm,
        headers: &[RequestHeader],
        credentials: Option<&HttpBasicCredentials>,
    ) -> Result<(), Http3ConnectorError> {
        self.prepare_connect_udp_requests(
            proxy_host,
            proxy_authority,
            path.clone(),
            headers.to_vec(),
            credentials,
        )
        .map(drop)
        .map_err(Http3ConnectorError::connect_udp)
    }

    /// Validates a CONNECT-UDP request for an HTTP/1.1 or HTTP/2 proxy leg
    /// and the leg's configuration without opening a connection.
    pub fn validate_connect_udp_over_tcp(
        proxy: &HttpsProxyConnector,
        protocol: HttpsProxyProtocol,
        proxy_authority: &str,
        path: &OriginForm,
        headers: &[RequestHeader],
        credentials: Option<&HttpBasicCredentials>,
    ) -> Result<(), Http3ConnectorError> {
        prepare_connect_udp_over_tcp(proxy, protocol, proxy_authority, path, headers, credentials)
            .map(drop)
            .map_err(Http3ConnectorError::connect_udp)
    }

    /// Prepares the anonymous request and, with credentials, the
    /// challenge-response form that appends `proxy-authorization`.
    fn prepare_connect_udp_requests(
        &self,
        proxy_host: &str,
        proxy_authority: &str,
        path: OriginForm,
        headers: Vec<RequestHeader>,
        credentials: Option<&HttpBasicCredentials>,
    ) -> Result<(http::Request<()>, Option<http::Request<()>>), ConnectUdpError> {
        let Some(credentials) = credentials else {
            let request = self.prepare_connect_udp(proxy_host, proxy_authority, path, headers)?;
            return Ok((request, None));
        };
        if headers
            .iter()
            .any(|header| header.name().eq_ignore_ascii_case("proxy-authorization"))
        {
            return Err(ConnectUdpError::new(
                ConnectUdpErrorKind::InvalidRequest,
                "CONNECT-UDP fields must not repeat the generated proxy-authorization field",
            ));
        }
        let mut authenticated_headers = headers.clone();
        authenticated_headers.push(
            RequestHeader::new("proxy-authorization", credentials.authorization()).sensitive(),
        );
        let anonymous =
            self.prepare_connect_udp(proxy_host, proxy_authority, path.clone(), headers)?;
        let authenticated =
            self.prepare_connect_udp(proxy_host, proxy_authority, path, authenticated_headers)?;
        Ok((anonymous, Some(authenticated)))
    }

    fn prepare_connect_udp(
        &self,
        proxy_host: &str,
        proxy_authority: &str,
        path: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> Result<http::Request<()>, ConnectUdpError> {
        QuicClientConfig::validate_server_name(proxy_host).map_err(|error| {
            ConnectUdpError::with_source(
                ConnectUdpErrorKind::InvalidRequest,
                "invalid CONNECT-UDP proxy server name",
                error,
            )
        })?;
        connect_udp::validate_outer_profile(&connect_udp::OuterProfile {
            receives_http_datagrams: self.settings.receives_datagrams(),
            max_datagram_frame_size: self.max_datagram_frame_size,
            max_udp_payload_size: self.max_udp_payload_size,
        })?;
        super::request::prepare_connect_udp(&self.request_settings, proxy_authority, path, headers)
            .map_err(ConnectUdpError::outer)
    }

    /// Validates one extended CONNECT request without opening a connection or stream.
    pub fn validate_extended_connect(
        &self,
        protocol: Http3ExtendedProtocol,
        authority: &str,
        target: &OriginForm,
        headers: &[RequestHeader],
    ) -> Result<(), Http3ConnectorError> {
        super::request::prepare_extended_connect(
            &self.request_settings,
            protocol.wire_value(),
            authority,
            target.clone(),
            headers.to_vec(),
        )
        .map(drop)
        .map_err(Http3ConnectorError::transaction)
    }

    /// Returns whether an originating connection is currently reusable.
    ///
    /// This is a health snapshot for pool selection, not a reservation of peer
    /// stream capacity. A later send can still fail and is never replayed.
    /// The check never waits behind a request that is still opening its
    /// stream, for example while the peer withholds SETTINGS or stream credit.
    pub async fn can_reuse(&self, connection: &Http3Connection) -> bool {
        connection.belongs_to(&self.identity) && connection.is_reusable()
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

    /// Validates one profiled request, a body-produced trailer plan, and static trailers.
    ///
    /// This does not open a connection, stream, or poll the request body.
    #[allow(clippy::too_many_arguments)]
    pub fn validate_request_body_source_with_trailers(
        &self,
        method: Method,
        authority: &str,
        target: &OriginForm,
        headers: &[RequestHeader],
        body: Option<&RequestBody>,
        trailers: &[RequestHeader],
    ) -> Result<(), Http3ConnectorError> {
        super::request::validate_profiled_request_body_source_with_trailers(
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
        if addresses.is_empty() {
            return Err(Http3ConnectorError::no_address());
        }
        self.connect_to_addresses_with_mtu(addresses, server_name, None)
            .await
            .map_err(Http3ConnectorError::transaction)
    }

    /// Tries each resolved address in order; `None` addresses is a resolve failure.
    pub(super) async fn connect_to_addresses_with_mtu(
        &self,
        addresses: Vec<std::net::SocketAddr>,
        server_name: &str,
        path_mtu: Option<u16>,
    ) -> Result<Http3Connection, Http3Error> {
        self.connect_to_addresses_with_crypto(
            addresses,
            server_name,
            Arc::clone(&self.crypto),
            path_mtu,
        )
        .await
    }

    /// Tries each resolved address in order with `crypto`, which may carry a
    /// per-connection ECH offer. A handshake failure, ECH rejection included,
    /// ends the attempt at the address it reached.
    async fn connect_to_addresses_with_crypto(
        &self,
        addresses: Vec<std::net::SocketAddr>,
        server_name: &str,
        crypto: Arc<QuicClientConfig>,
        path_mtu: Option<u16>,
    ) -> Result<Http3Connection, Http3Error> {
        let mut addresses = addresses.into_iter();
        let Some(mut remote) = addresses.next() else {
            return Err(Http3Error::without_source(
                Http3ErrorKind::Connect,
                "HTTP/3 host resolved to no addresses",
            ));
        };
        loop {
            match connect_bound(
                remote,
                server_name,
                Arc::clone(&crypto),
                &self.settings,
                Arc::clone(&self.identity),
                path_mtu,
                self.diagnostics(),
            )
            .await
            {
                Ok(connection) => return Ok(connection),
                Err(error) if should_try_next_address(&error) => {
                    let Some(next) = addresses.next() else {
                        return Err(error);
                    };
                    remote = next;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn connect_socks5_to_addresses(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        auth: Socks5Auth<'_>,
        addresses: Vec<std::net::SocketAddr>,
        server_name: &str,
    ) -> Result<Http3Connection, Http3ConnectorError> {
        let mut addresses = addresses.into_iter();
        let mut remote = addresses
            .next()
            .ok_or_else(Http3ConnectorError::no_address)?;
        loop {
            let association = associate_socks5_udp_local_with_auth(
                self.dialer(),
                proxy_host,
                proxy_port,
                remote,
                auth,
            )
            .await
            .map_err(Http3ConnectorError::proxy)?;
            let (socket, logical_remote) = association.into_parts();
            match connect_bound_with_socket(
                logical_remote,
                server_name,
                Arc::clone(&self.crypto),
                &self.settings,
                Arc::clone(&self.identity),
                socket,
                self.diagnostics(),
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

/// Validates an HTTP/1.1 or HTTP/2 CONNECT-UDP leg and builds its request.
fn prepare_connect_udp_over_tcp(
    proxy: &HttpsProxyConnector,
    protocol: HttpsProxyProtocol,
    proxy_authority: &str,
    path: &OriginForm,
    headers: &[RequestHeader],
    credentials: Option<&HttpBasicCredentials>,
) -> Result<PreparedConnectUdp, ConnectUdpError> {
    let request = PreparedConnectUdp::new(protocol, proxy_authority, path, headers, credentials)
        .map_err(ConnectUdpError::proxy_leg_request)?;
    proxy
        .validate_connect_udp_protocol(protocol)
        .map_err(ConnectUdpError::proxy_leg_configuration)?;
    Ok(request)
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

/// Stable category of an HTTP/3 connector failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
    /// Connecting to or negotiating with the configured proxy failed.
    Proxy,
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
    /// The peer did not enable HTTP/3 extended CONNECT.
    ExtendedConnectUnavailable,
}

/// Error returned while constructing or using [`Http3Connector`].
#[derive(Debug)]
pub struct Http3ConnectorError {
    kind: Http3ConnectorErrorKind,
    message: &'static str,
    source: Option<BoxError>,
    ech: Option<EchFailure>,
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

    fn proxy(source: Socks5Error) -> Self {
        Self::with_source(
            Http3ConnectorErrorKind::Proxy,
            "HTTP/3 SOCKS5 proxy setup failed",
            source,
        )
    }

    fn connect_udp(source: ConnectUdpError) -> Self {
        Self::with_source(
            Http3ConnectorErrorKind::Proxy,
            "HTTP/3 CONNECT-UDP proxy setup failed",
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
            Http3ErrorKind::ExtendedConnectUnavailable => {
                Http3ConnectorErrorKind::ExtendedConnectUnavailable
            }
        };
        Self::with_source(kind, "HTTP/3 request failed", source)
    }

    const fn without_source(kind: Http3ConnectorErrorKind, message: &'static str) -> Self {
        Self {
            kind,
            message,
            source: None,
            ech: None,
        }
    }

    #[cfg(feature = "https-records")]
    fn invalid_ech_config_list(source: crate::dns::EchConfigListError) -> Self {
        Self::with_source(
            Http3ConnectorErrorKind::Handshake,
            "the ECHConfigList does not parse",
            source,
        )
        .with_ech(EchFailure::InvalidConfigList)
    }

    #[cfg(feature = "https-records")]
    const fn with_ech(mut self, failure: EchFailure) -> Self {
        self.ech = Some(failure);
        self
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
            ech: None,
        }
    }

    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> Http3ConnectorErrorKind {
        self.kind
    }

    /// Returns why a connection that offered Encrypted Client Hello failed,
    /// when that offer is the reason.
    ///
    /// Only [`Http3Connector::connect_direct_with_ech`] sets it; the
    /// handshake case has kind [`Http3ConnectorErrorKind::Handshake`].
    #[must_use]
    pub const fn ech_failure(&self) -> Option<EchFailure> {
        self.ech
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

#[cfg(test)]
mod socks5_tests {
    use std::{
        error::Error,
        future::Future,
        task::{Context, Poll, Waker},
    };

    use phantom_profile::chromium;

    use super::{Http3Connector, Http3ConnectorError, Http3ConnectorErrorKind};
    use crate::proxy::{Socks5Auth, Socks5Error, Socks5ErrorKind};

    #[test]
    fn invalid_socks5_auth_precedes_runtime_dns_and_proxy_io() -> Result<(), Box<dyn Error>> {
        let connector = connector()?;
        let request = connector.connect_socks5_local_with_auth(
            "does-not-resolve.invalid",
            1080,
            Socks5Auth::UsernamePassword {
                username: "",
                password: "password",
            },
            "does-not-resolve.invalid",
            443,
            "example.test",
        );
        let mut request = std::pin::pin!(request);
        let mut context = Context::from_waker(Waker::noop());
        let result = match request.as_mut().poll(&mut context) {
            Poll::Ready(result) => result,
            Poll::Pending => return Err("invalid authentication reached runtime or I/O".into()),
        };
        let error = result.err().ok_or("invalid authentication was accepted")?;
        assert_eq!(error.kind(), Http3ConnectorErrorKind::Proxy);
        let source = error
            .source()
            .and_then(|source| source.downcast_ref::<Socks5Error>())
            .ok_or("proxy connector error omitted its SOCKS5 source")?;
        assert_eq!(source.kind(), Socks5ErrorKind::InvalidAuthentication);
        Ok(())
    }

    #[test]
    fn invalid_server_name_precedes_socks5_auth_validation() -> Result<(), Box<dyn Error>> {
        let connector = connector()?;
        let request = connector.connect_socks5_local_with_auth(
            "does-not-resolve.invalid",
            1080,
            Socks5Auth::UsernamePassword {
                username: "",
                password: "password",
            },
            "does-not-resolve.invalid",
            443,
            "absolute.example.",
        );
        let mut request = std::pin::pin!(request);
        let mut context = Context::from_waker(Waker::noop());
        let result = match request.as_mut().poll(&mut context) {
            Poll::Ready(result) => result,
            Poll::Pending => return Err("invalid server name reached runtime or I/O".into()),
        };
        let error = result.err().ok_or("invalid server name was accepted")?;
        assert_eq!(error.kind(), Http3ConnectorErrorKind::Request);
        Ok(())
    }

    #[test]
    fn invalid_remote_socks5_auth_precedes_target_validation() -> Result<(), Box<dyn Error>> {
        let connector = connector()?;
        let request = connector.connect_socks5_remote_with_auth(
            "does-not-resolve.invalid",
            1080,
            Socks5Auth::UsernamePassword {
                username: "",
                password: "password",
            },
            "invalid target",
            0,
            "example.test",
        );
        let mut request = std::pin::pin!(request);
        let mut context = Context::from_waker(Waker::noop());
        let result = match request.as_mut().poll(&mut context) {
            Poll::Ready(result) => result,
            Poll::Pending => return Err("invalid authentication reached runtime or I/O".into()),
        };
        let error = result.err().ok_or("invalid authentication was accepted")?;
        assert_eq!(error.kind(), Http3ConnectorErrorKind::Proxy);
        let source = error
            .source()
            .and_then(|source| source.downcast_ref::<Socks5Error>())
            .ok_or("proxy connector error omitted its SOCKS5 source")?;
        assert_eq!(source.kind(), Socks5ErrorKind::InvalidAuthentication);
        Ok(())
    }

    #[test]
    fn invalid_remote_socks5_target_precedes_runtime_and_proxy_io() -> Result<(), Box<dyn Error>> {
        let connector = connector()?;
        let request = connector.connect_socks5_remote(
            "does-not-resolve.invalid",
            1080,
            "invalid target",
            443,
            "example.test",
        );
        let mut request = std::pin::pin!(request);
        let mut context = Context::from_waker(Waker::noop());
        let result = match request.as_mut().poll(&mut context) {
            Poll::Ready(result) => result,
            Poll::Pending => return Err("invalid target reached runtime or proxy I/O".into()),
        };
        let error = result.err().ok_or("invalid remote target was accepted")?;
        assert_eq!(error.kind(), Http3ConnectorErrorKind::Proxy);
        let source = error
            .source()
            .and_then(|source| source.downcast_ref::<Socks5Error>())
            .ok_or("proxy connector error omitted its SOCKS5 source")?;
        assert_eq!(source.kind(), Socks5ErrorKind::InvalidTarget);
        Ok(())
    }

    fn connector() -> Result<Http3Connector, Http3ConnectorError> {
        Http3Connector::new(
            &chromium::v154_http3_tls(),
            &chromium::v154_quic(),
            &chromium::v154_http3(),
            &chromium::v154_http3_request(),
        )
    }
}
