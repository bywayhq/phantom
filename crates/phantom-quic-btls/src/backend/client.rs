use std::any::Any;
use std::collections::VecDeque;
use std::fmt;
use std::io::Cursor;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};

use btls::ex_data::Index;
use btls::ssl::{KeyShare, SslContext, SslContextBuilder};
use phantom_profile::{AlpsSettings, CipherSuite, NamedGroup, TlsSettings, TlsVersion};
use quinn_proto::crypto::{self, ExportKeyingMaterialError, KeyPair, Keys};
use quinn_proto::{
    ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
    transport_parameters::TransportParameters,
};
use rustls_pki_types::DnsName;

use super::callback_state::{EncryptionLevel, HandshakeChunk, SecretPair};
use super::client_session::{ClientSession, ClientSessionError};
use super::quic_callbacks::enable_session_delivery;
#[cfg(test)]
use crate::key_schedule::TestDerivationFailure;
use crate::key_schedule::{PacketKeyPair, TrafficKeySchedule, TrafficKeys};
use crate::resumption::SessionCache;
use crate::transport_parameters::{QuicTransportProfileError, TransportParameterProfile};
use crate::{EndpointSide, QuicVersion, derive_initial_keys, verify_retry_integrity};
use phantom_profile::quic::QuicTransportSettings;
use quinn_proto::{EndpointConfig, TransportConfig};

const QUIC_VERSION_1: u32 = 0x0000_0001;
const H3_PROTOCOL: &[u8] = b"h3";

/// Marks a context whose builder passed through
/// [`QuicClientConfig::enable_session_resumption`].
struct SessionDeliveryEnabled;

fn session_delivery_index() -> Option<Index<SslContext, SessionDeliveryEnabled>> {
    static INDEX: OnceLock<Option<Index<SslContext, SessionDeliveryEnabled>>> = OnceLock::new();
    *INDEX.get_or_init(|| SslContext::new_ex_index().ok())
}

/// Immutable BoringSSL configuration for Quinn client sessions.
///
/// The supplied context must enable peer verification and contain the trust
/// roots and fingerprint settings used by every session created from it.
/// Session-specific QUIC requirements are applied to each owned `SSL`.
///
/// A configuration resumes sessions only when its TLS profile enables
/// `session_tickets` and it was produced by
/// [`Self::with_isolated_session_cache`]; see that method for the isolation
/// contract.
pub struct QuicClientConfig {
    context: SslContext,
    transport_profile: Option<TransportParameterProfile>,
    tls_profile: ClientTlsProfile,
    sessions: Option<SessionCache>,
    offer_tickets: bool,
    #[cfg(test)]
    derivation_failure: Option<TestDerivationFailure>,
}

impl QuicClientConfig {
    /// Wraps an already configured BoringSSL context.
    #[must_use]
    pub const fn new(context: SslContext) -> Self {
        Self {
            context,
            transport_profile: None,
            tls_profile: ClientTlsProfile {
                key_shares: None,
                ech_grease: false,
                ech_grease_payload_length: None,
                ech_grease_aeads: Vec::new(),
                alps: None,
                session_tickets: false,
            },
            sessions: None,
            offer_tickets: true,
            #[cfg(test)]
            derivation_failure: None,
        }
    }

    /// Wraps a BoringSSL context and applies a validated QUIC transport profile.
    pub fn with_transport_profile(
        context: SslContext,
        settings: QuicTransportSettings,
    ) -> Result<Self, QuicTransportProfileError> {
        Ok(Self {
            context,
            transport_profile: Some(TransportParameterProfile::new(settings)?),
            tls_profile: ClientTlsProfile::default(),
            sessions: None,
            offer_tickets: true,
            #[cfg(test)]
            derivation_failure: None,
        })
    }

    /// Prepares a context builder so QUIC sessions can retain tickets.
    ///
    /// This enables BoringSSL's client session callback, with its internal
    /// cache off, and marks the context. Call it on the builder of every
    /// context whose TLS profile sets `session_tickets`. It changes nothing
    /// in a ClientHello that offers no ticket.
    pub fn enable_session_resumption(
        builder: &mut SslContextBuilder,
    ) -> Result<(), QuicTlsProfileError> {
        let index = session_delivery_index().ok_or_else(|| {
            QuicTlsProfileError::unsupported(
                "session_tickets",
                "BoringSSL could not allocate the session-delivery marker",
            )
        })?;
        enable_session_delivery(builder);
        builder.set_ex_data(index, SessionDeliveryEnabled);
        Ok(())
    }

    /// Applies TLS controls that BoringSSL owns per QUIC session.
    ///
    /// The QUIC path requires TLS 1.3, exact `h3` ALPN, and at most an empty
    /// local H3 ALPS value. Profiles must state those constraints explicitly;
    /// this method never rewrites them.
    ///
    /// `session_tickets` enables TLS 1.3 session resumption. It requires a
    /// context prepared with [`Self::enable_session_resumption`], and it takes
    /// effect only on configurations derived with
    /// [`Self::with_isolated_session_cache`].
    pub fn with_tls_profile(mut self, settings: &TlsSettings) -> Result<Self, QuicTlsProfileError> {
        let profile = ClientTlsProfile::new(settings)?;
        if profile.session_tickets
            && session_delivery_index().is_none_or(|index| self.context.ex_data(index).is_none())
        {
            return Err(QuicTlsProfileError::invalid(
                "session_tickets",
                "QUIC session tickets require a context prepared for session resumption",
            ));
        }
        self.tls_profile = profile;
        Ok(self)
    }

    /// Returns a clone with a fresh, empty ticket cache of its own.
    ///
    /// Tickets learned through the returned configuration are presented only
    /// by it, and only for the verified server name whose handshake received
    /// them. Give each connection pool key, meaning each origin and route, its
    /// own clone, so a ticket learned through one route is never presented
    /// directly or through another. The clone shares the immutable BoringSSL
    /// context. Without `session_tickets` the clone has no cache and never
    /// resumes.
    #[must_use]
    pub fn with_isolated_session_cache(&self) -> Self {
        Self {
            context: self.context.clone(),
            transport_profile: self.transport_profile.clone(),
            tls_profile: self.tls_profile.clone(),
            sessions: self.tls_profile.session_tickets.then(SessionCache::default),
            offer_tickets: true,
            #[cfg(test)]
            derivation_failure: self.derivation_failure,
        }
    }

    /// Returns a clone that stores new tickets in this configuration's cache
    /// but never presents one.
    ///
    /// Use it to repeat a connection attempt with a full handshake after an
    /// attempt that presented a ticket failed its handshake: nothing about
    /// the connection's identity, protocol, or route changes.
    #[must_use]
    pub fn without_ticket_offers(&self) -> Self {
        Self {
            context: self.context.clone(),
            transport_profile: self.transport_profile.clone(),
            tls_profile: self.tls_profile.clone(),
            sessions: self.sessions.clone(),
            offer_tickets: false,
            #[cfg(test)]
            derivation_failure: self.derivation_failure,
        }
    }

    /// Returns whether a connection to `server_name` would present a ticket.
    ///
    /// The answer can change before the connection starts, because another
    /// connection may consume the ticket first.
    #[must_use]
    pub fn has_ticket_for(&self, server_name: &str) -> bool {
        self.offer_tickets
            && self
                .sessions
                .as_ref()
                .is_some_and(|sessions| sessions.contains(server_name))
    }

    /// Returns whether connections from this configuration retain and
    /// present session tickets.
    #[must_use]
    pub const fn resumes_sessions(&self) -> bool {
        self.sessions.is_some()
    }

    #[cfg(test)]
    pub(crate) const fn session_cache(&self) -> Option<&SessionCache> {
        self.sessions.as_ref()
    }

    /// Validates TLS controls without constructing a QUIC session.
    pub fn validate_tls_profile(settings: &TlsSettings) -> Result<(), QuicTlsProfileError> {
        ClientTlsProfile::new(settings).map(|_| ())
    }

    /// Validates a DNS name or IP literal before endpoint construction.
    pub fn validate_server_name(server_name: &str) -> Result<(), InvalidServerName> {
        validate_server_name_inner(server_name)
    }

    #[cfg(test)]
    pub(crate) fn with_test_derivation_failure(mut self, failure: TestDerivationFailure) -> Self {
        self.derivation_failure = Some(failure);
        self
    }

    /// Applies this profile's semantic settings to Quinn.
    ///
    /// The stock configuration created by [`Self::new`] leaves both values unchanged.
    pub fn configure_transport(
        &self,
        endpoint: &mut EndpointConfig,
        transport: &mut TransportConfig,
    ) -> Result<(), QuicTransportProfileError> {
        if let Some(profile) = &self.transport_profile {
            profile.configure_quinn(endpoint, transport)?;
        }
        Ok(())
    }

    /// Returns whether the configured QUIC transport accepts DATAGRAM frames.
    #[must_use]
    pub fn receives_datagrams(&self) -> bool {
        self.transport_profile
            .as_ref()
            .is_none_or(TransportParameterProfile::receives_datagrams)
    }
}

impl fmt::Debug for QuicClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QuicClientConfig")
    }
}

/// A server name that cannot be used for QUIC certificate verification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidServerName;

impl fmt::Display for InvalidServerName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("invalid QUIC server name")
    }
}

impl std::error::Error for InvalidServerName {}

/// Negotiated information made available by Quinn once ALPN is selected.
#[derive(Clone, Eq, PartialEq)]
pub struct HandshakeData {
    protocol: Vec<u8>,
    peer_application_settings: Option<Vec<u8>>,
    session_resumed: bool,
}

impl HandshakeData {
    /// Returns the negotiated ALPN protocol.
    #[must_use]
    pub fn protocol(&self) -> &[u8] {
        &self.protocol
    }

    /// Returns application settings received from the peer through ALPS.
    ///
    /// `None` means ALPS was not negotiated. An empty slice means it was
    /// negotiated with an empty settings value.
    #[must_use]
    pub fn peer_application_settings(&self) -> Option<&[u8]> {
        self.peer_application_settings.as_deref()
    }

    /// Returns whether the handshake resumed a session from a ticket.
    ///
    /// A resumed handshake authenticates the peer through the ticket, which
    /// an earlier verified handshake for the same server name received.
    #[must_use]
    pub const fn session_resumed(&self) -> bool {
        self.session_resumed
    }
}

impl fmt::Debug for HandshakeData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandshakeData")
            .field("protocol", &self.protocol)
            .field(
                "peer_application_settings_len",
                &self.peer_application_settings.as_ref().map(Vec::len),
            )
            .field("session_resumed", &self.session_resumed)
            .finish()
    }
}

/// Verified peer certificate chain, encoded as leaf-first DER certificates.
#[derive(Clone, Eq, PartialEq)]
pub struct PeerIdentity {
    certificates: Vec<Vec<u8>>,
}

impl PeerIdentity {
    /// Returns the leaf-first DER certificate chain.
    #[must_use]
    pub fn certificates(&self) -> &[Vec<u8>] {
        &self.certificates
    }
}

impl fmt::Debug for PeerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerIdentity")
            .field("certificate_count", &self.certificates.len())
            .finish()
    }
}

impl crypto::ClientConfig for QuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        server_name: &str,
        params: &TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, ConnectError> {
        let version = interpret_version(version)?;
        validate_server_name_inner(server_name)
            .map_err(|_| ConnectError::InvalidServerName(server_name.into()))?;

        let encoded_parameters = if let Some(profile) = &self.transport_profile {
            profile.encode(params, version).map_err(|error| {
                let message = error.to_string();
                if error.is_entropy_failure() {
                    ConnectError::TransportParameterEncoding(message)
                } else {
                    ConnectError::InvalidTransportParameters(message)
                }
            })?
        } else {
            let mut encoded = Vec::new();
            params.write(&mut encoded);
            encoded
        };
        let offered = self
            .sessions
            .as_ref()
            .filter(|_| self.offer_tickets)
            .and_then(|sessions| sessions.take(server_name));
        let mut backend = ClientSession::new_with_profile(
            &self.context,
            server_name,
            &encoded_parameters,
            &self.tls_profile,
            offered.as_deref(),
        )
        .map_err(|error| map_start_error(server_name, error))?;
        backend
            .start_handshake()
            .map_err(|error| map_start_error(server_name, error))?;

        let mut state = SessionState::new(version, backend);
        state.ticket_sink = self.sessions.clone().map(|sessions| TicketSink {
            sessions,
            server_name: server_name.into(),
        });
        #[cfg(test)]
        if let Some(failure) = self.derivation_failure {
            state.derivation_failure = Some(failure);
        }
        state
            .collect_backend_state()
            .map_err(|_| ConnectError::EndpointStopping)?;
        Ok(Box::new(QuicSession {
            state: Mutex::new(state),
        }))
    }
}

#[derive(Clone, Default)]
pub(super) struct ClientTlsProfile {
    key_shares: Option<Box<[KeyShare]>>,
    ech_grease: bool,
    ech_grease_payload_length: Option<u16>,
    ech_grease_aeads: Vec<u16>,
    alps: Option<AlpsSettings>,
    session_tickets: bool,
}

impl fmt::Debug for ClientTlsProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientTlsProfile")
            .field("key_shares", &self.key_shares)
            .field("ech_grease", &self.ech_grease)
            .field("ech_grease_payload_length", &self.ech_grease_payload_length)
            .field("ech_grease_aeads", &self.ech_grease_aeads)
            .field(
                "alps",
                &self.alps.as_ref().map(|value| value.settings.len()),
            )
            .field("session_tickets", &self.session_tickets)
            .finish()
    }
}

impl ClientTlsProfile {
    fn new(settings: &TlsSettings) -> Result<Self, QuicTlsProfileError> {
        settings
            .validate()
            .map_err(|error| QuicTlsProfileError::invalid(error.field(), error.to_string()))?;
        if settings.min_version != TlsVersion::Tls13 || settings.max_version != TlsVersion::Tls13 {
            return Err(QuicTlsProfileError::invalid(
                "version range",
                "QUIC requires an explicit TLS 1.3-only profile",
            ));
        }
        if settings.alpn_protocols.len() != 1 || settings.alpn_protocols[0].as_ref() != b"h3" {
            return Err(QuicTlsProfileError::invalid(
                "alpn_protocols",
                "QUIC requires the exact `h3` ALPN protocol",
            ));
        }
        if settings
            .alps
            .as_ref()
            .is_some_and(|alps| !alps.settings.is_empty())
        {
            return Err(QuicTlsProfileError::unsupported(
                "alps.settings",
                "nonempty local HTTP/3 ALPS requires correlated H3 SETTINGS",
            ));
        }
        if settings
            .cipher_suites
            .iter()
            .any(|suite| !is_tls13_cipher_suite(*suite))
        {
            return Err(QuicTlsProfileError::invalid(
                "cipher_suites",
                "QUIC TLS profiles must contain only TLS 1.3 cipher suites",
            ));
        }

        let key_shares = settings
            .key_shares
            .iter()
            .copied()
            .map(key_share)
            .collect::<Result<Vec<_>, _>>()?
            .into_boxed_slice();
        Ok(Self {
            key_shares: Some(key_shares),
            ech_grease: settings.ech_grease,
            ech_grease_payload_length: settings.ech_grease_payload_length,
            ech_grease_aeads: settings
                .ech_grease_aeads
                .iter()
                .map(|aead| aead.hpke_id())
                .collect(),
            alps: settings.alps.clone(),
            session_tickets: settings.session_tickets,
        })
    }

    pub(super) fn key_shares(&self) -> Option<&[KeyShare]> {
        self.key_shares.as_deref()
    }

    pub(super) const fn ech_grease(&self) -> bool {
        self.ech_grease
    }

    pub(super) const fn ech_grease_payload_length(&self) -> Option<u16> {
        self.ech_grease_payload_length
    }

    pub(super) fn ech_grease_aeads(&self) -> &[u16] {
        &self.ech_grease_aeads
    }

    pub(super) const fn alps(&self) -> Option<&AlpsSettings> {
        self.alps.as_ref()
    }
}

const fn is_tls13_cipher_suite(suite: CipherSuite) -> bool {
    matches!(
        suite,
        CipherSuite::Aes128GcmSha256
            | CipherSuite::Aes256GcmSha384
            | CipherSuite::Chacha20Poly1305Sha256
    )
}

fn key_share(group: NamedGroup) -> Result<KeyShare, QuicTlsProfileError> {
    match group {
        NamedGroup::X25519MlKem768 => Ok(KeyShare::X25519_MLKEM768),
        NamedGroup::X25519 => Ok(KeyShare::X25519),
        NamedGroup::Secp256r1 => Ok(KeyShare::P256),
        NamedGroup::Secp384r1 => Ok(KeyShare::P384),
        NamedGroup::Secp521r1 => Ok(KeyShare::P521),
        NamedGroup::Ffdhe2048 => Ok(KeyShare::FFDHE2048),
        NamedGroup::Ffdhe3072 => Ok(KeyShare::FFDHE3072),
        _ => Err(QuicTlsProfileError::unsupported(
            "key_shares",
            "profile contains a key share unsupported by the BoringSSL QUIC adapter",
        )),
    }
}

/// Failure while applying TLS controls to QUIC sessions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QuicTlsProfileError {
    kind: QuicTlsProfileErrorKind,
    field: &'static str,
    message: Box<str>,
}

impl QuicTlsProfileError {
    fn invalid(field: &'static str, message: impl Into<Box<str>>) -> Self {
        Self {
            kind: QuicTlsProfileErrorKind::InvalidProfile,
            field,
            message: message.into(),
        }
    }

    fn unsupported(field: &'static str, message: impl Into<Box<str>>) -> Self {
        Self {
            kind: QuicTlsProfileErrorKind::UnsupportedSetting,
            field,
            message: message.into(),
        }
    }

    /// Returns the broad failure category.
    #[must_use]
    pub const fn kind(&self) -> QuicTlsProfileErrorKind {
        self.kind
    }

    /// Returns the incompatible profile field.
    #[must_use]
    pub const fn field(&self) -> &'static str {
        self.field
    }
}

impl fmt::Display for QuicTlsProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "QUIC TLS profile {}: {}",
            self.field, self.message
        )
    }
}

impl std::error::Error for QuicTlsProfileError {}

/// Category of a QUIC TLS profile failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuicTlsProfileErrorKind {
    /// The profile contradicts mandatory QUIC TLS behavior.
    InvalidProfile,
    /// The adapter cannot represent one supplied TLS control.
    UnsupportedSetting,
}

struct QuicSession {
    state: Mutex<SessionState>,
}

impl QuicSession {
    fn lock(&self) -> MutexGuard<'_, SessionState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl fmt::Debug for QuicSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QuicSession")
    }
}

struct SessionState {
    version: QuicVersion,
    backend: ClientSession,
    outbound: OutboundHandshake,
    handshake_keys: Option<Keys>,
    application_keys: Option<Keys>,
    application_schedule: Option<TrafficKeySchedule>,
    handshake_data: Option<HandshakeData>,
    handshake_data_announced: bool,
    peer_identity: Option<PeerIdentity>,
    peer_transport_parameters: Option<Vec<u8>>,
    ticket_sink: Option<TicketSink>,
    #[cfg(test)]
    derivation_failure: Option<TestDerivationFailure>,
}

/// Where an authenticated connection stores the tickets its peer issues.
struct TicketSink {
    sessions: SessionCache,
    server_name: Box<str>,
}

impl SessionState {
    fn new(version: QuicVersion, backend: ClientSession) -> Self {
        Self {
            version,
            backend,
            outbound: OutboundHandshake::default(),
            handshake_keys: None,
            application_keys: None,
            application_schedule: None,
            handshake_data: None,
            handshake_data_announced: false,
            peer_identity: None,
            peer_transport_parameters: None,
            ticket_sink: None,
            #[cfg(test)]
            derivation_failure: None,
        }
    }

    fn collect_backend_state(&mut self) -> Result<(), AdapterError> {
        for chunk in self.backend.drain_output()? {
            self.outbound.stage(chunk);
        }

        if self.handshake_keys.is_none()
            && let Some(pair) = self.backend.take_secret_pair(EncryptionLevel::Handshake)?
        {
            self.handshake_keys = Some(keys_from_pair(pair)?.0);
        }
        if self.application_keys.is_none()
            && let Some(pair) = self
                .backend
                .take_secret_pair(EncryptionLevel::Application)?
        {
            #[cfg(test)]
            let derived = keys_from_pair_with_failure(pair, self.derivation_failure);
            #[cfg(not(test))]
            let derived = keys_from_pair(pair);
            let (keys, schedule) = derived?;
            self.application_keys = Some(keys);
            self.application_schedule = Some(schedule);
        }

        if self.handshake_data.is_none()
            && !self.backend.is_handshaking()
            && let Some(protocol) = self.backend.selected_protocol()?
        {
            if protocol != H3_PROTOCOL {
                return Err(AdapterError::Backend(ClientSessionError::AlpnNotNegotiated));
            }
            self.handshake_data = Some(HandshakeData {
                protocol,
                peer_application_settings: self.backend.peer_application_settings()?,
                session_resumed: self.backend.session_reused(),
            });
        }
        if self.peer_transport_parameters.is_none() {
            self.peer_transport_parameters = self.backend.peer_transport_parameters()?;
        }
        if !self.backend.is_handshaking() && self.peer_identity.is_none() {
            self.peer_identity = Some(PeerIdentity {
                certificates: self.backend.peer_identity()?,
            });
        }
        let issued = self.backend.take_new_sessions();
        if let Some(sink) = &self.ticket_sink {
            for session in issued {
                sink.sessions.insert(&sink.server_name, session);
            }
        }
        Ok(())
    }

    fn write_handshake(&mut self, destination: &mut Vec<u8>) -> Option<Keys> {
        self.outbound.write(
            destination,
            &mut self.handshake_keys,
            &mut self.application_keys,
        )
    }
}

struct OutboundHandshake {
    queues: [VecDeque<Vec<u8>>; 3],
    level: EncryptionLevel,
}

impl Default for OutboundHandshake {
    fn default() -> Self {
        Self {
            queues: std::array::from_fn(|_| VecDeque::new()),
            level: EncryptionLevel::Initial,
        }
    }
}

impl OutboundHandshake {
    fn stage(&mut self, chunk: HandshakeChunk) {
        self.queues[level_index(chunk.level)].push_back(chunk.bytes);
    }

    fn write(
        &mut self,
        destination: &mut Vec<u8>,
        handshake_keys: &mut Option<Keys>,
        application_keys: &mut Option<Keys>,
    ) -> Option<Keys> {
        let queue = &mut self.queues[level_index(self.level)];
        while let Some(chunk) = queue.pop_front() {
            destination.extend_from_slice(&chunk);
        }

        let keys = match self.level {
            EncryptionLevel::Initial => handshake_keys.take(),
            EncryptionLevel::Handshake => application_keys.take(),
            EncryptionLevel::Application => None,
        };
        if keys.is_some() {
            self.level = match self.level {
                EncryptionLevel::Initial => EncryptionLevel::Handshake,
                EncryptionLevel::Handshake | EncryptionLevel::Application => {
                    EncryptionLevel::Application
                }
            };
        }
        keys
    }
}

impl crypto::Session for QuicSession {
    fn initial_keys(
        &self,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<Keys, crypto::CryptoError> {
        let state = self.lock();
        let side = match side {
            Side::Client => EndpointSide::Client,
            Side::Server => EndpointSide::Server,
        };
        derive_initial_keys(state.version, dst_cid, side)
            .map(initial_keys_into_quinn)
            .map_err(|_| crypto::CryptoError)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.lock()
            .handshake_data
            .clone()
            .map(|data| Box::new(data) as Box<dyn Any>)
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        self.lock()
            .peer_identity
            .clone()
            .map(|identity| Box::new(identity) as Box<dyn Any>)
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        Some(false)
    }

    fn is_handshaking(&self) -> bool {
        self.lock().backend.is_handshaking()
    }

    fn read_handshake(&mut self, buffer: &[u8]) -> Result<bool, TransportError> {
        let mut state = self.lock();
        state
            .backend
            .provide_handshake_data(buffer)
            .map_err(|error| map_session_error(&state.backend, error))?;
        state
            .collect_backend_state()
            .map_err(|error| error.into_transport(&state.backend))?;

        if state.handshake_data.is_some() && !state.handshake_data_announced {
            state.handshake_data_announced = true;
            return Ok(true);
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        let state = self.lock();
        decode_peer_transport_parameters(
            state.peer_transport_parameters.as_deref(),
            state.backend.is_handshaking(),
        )
    }

    fn write_handshake(&mut self, buffer: &mut Vec<u8>) -> Option<Keys> {
        self.lock().write_handshake(buffer)
    }

    fn next_1rtt_keys(
        &mut self,
    ) -> Result<Option<KeyPair<Box<dyn crypto::PacketKey>>>, TransportError> {
        let mut state = self.lock();
        let Some(schedule) = state.application_schedule.as_mut() else {
            return Ok(None);
        };
        schedule
            .next_packet_keys()
            .map(packet_pair_into_quinn)
            .map(Some)
            .map_err(|_| {
                transport_error(
                    TransportErrorCode::INTERNAL_ERROR,
                    "1-RTT key update failed",
                )
            })
    }

    fn is_valid_retry(
        &self,
        original_destination_connection_id: &ConnectionId,
        header: &[u8],
        payload: &[u8],
    ) -> bool {
        let state = self.lock();
        let Some(capacity) = header.len().checked_add(payload.len()) else {
            return false;
        };
        let mut packet = Vec::new();
        if packet.try_reserve_exact(capacity).is_err() {
            return false;
        }
        packet.extend_from_slice(header);
        packet.extend_from_slice(payload);
        verify_retry_integrity(state.version, original_destination_connection_id, &packet)
            .unwrap_or(false)
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        self.lock()
            .backend
            .export_keying_material(output, label, context)
            .map_err(|_| ExportKeyingMaterialError)
    }
}

enum AdapterError {
    Backend(ClientSessionError),
    Crypto,
}

impl AdapterError {
    fn into_transport(self, backend: &ClientSession) -> TransportError {
        match self {
            Self::Backend(error) => map_session_error(backend, error),
            Self::Crypto => transport_error(
                TransportErrorCode::INTERNAL_ERROR,
                "QUIC traffic key derivation failed",
            ),
        }
    }
}

impl From<ClientSessionError> for AdapterError {
    fn from(error: ClientSessionError) -> Self {
        Self::Backend(error)
    }
}

fn keys_from_pair(pair: SecretPair) -> Result<(Keys, TrafficKeySchedule), AdapterError> {
    let schedule =
        TrafficKeySchedule::from_local_remote(pair.cipher_suite, pair.local, pair.remote)
            .map_err(|_| AdapterError::Crypto)?;
    keys_from_schedule(schedule)
}

#[cfg(test)]
fn keys_from_pair_with_failure(
    pair: SecretPair,
    failure: Option<TestDerivationFailure>,
) -> Result<(Keys, TrafficKeySchedule), AdapterError> {
    let schedule =
        TrafficKeySchedule::from_local_remote(pair.cipher_suite, pair.local, pair.remote)
            .map_err(|_| AdapterError::Crypto)?;
    if let Some(failure) = failure {
        schedule.inject_derivation_failure(failure);
    }
    keys_from_schedule(schedule)
}

fn keys_from_schedule(
    schedule: TrafficKeySchedule,
) -> Result<(Keys, TrafficKeySchedule), AdapterError> {
    let keys = schedule.keys().map_err(|_| AdapterError::Crypto)?;
    Ok((traffic_keys_into_quinn(keys), schedule))
}

fn initial_keys_into_quinn(keys: crate::InitialKeys) -> Keys {
    let (local, remote) = keys.into_parts();
    let (local_header, local_packet) = local.into_parts();
    let (remote_header, remote_packet) = remote.into_parts();
    Keys {
        header: KeyPair {
            local: Box::new(local_header),
            remote: Box::new(remote_header),
        },
        packet: KeyPair {
            local: Box::new(local_packet),
            remote: Box::new(remote_packet),
        },
    }
}

fn traffic_keys_into_quinn(keys: TrafficKeys) -> Keys {
    let (local_header, local_packet) = keys.local.into_parts();
    let (remote_header, remote_packet) = keys.remote.into_parts();
    Keys {
        header: KeyPair {
            local: Box::new(local_header),
            remote: Box::new(remote_header),
        },
        packet: KeyPair {
            local: Box::new(local_packet),
            remote: Box::new(remote_packet),
        },
    }
}

fn packet_pair_into_quinn(keys: PacketKeyPair) -> KeyPair<Box<dyn crypto::PacketKey>> {
    KeyPair {
        local: Box::new(keys.local),
        remote: Box::new(keys.remote),
    }
}

fn interpret_version(version: u32) -> Result<QuicVersion, ConnectError> {
    match version {
        QUIC_VERSION_1 => Ok(QuicVersion::V1),
        _ => Err(ConnectError::UnsupportedVersion),
    }
}

fn validate_server_name_inner(server_name: &str) -> Result<(), InvalidServerName> {
    let valid_ip = server_name.parse::<IpAddr>().is_ok();
    let invalid = !valid_ip
        && (server_name.ends_with('.')
            || server_name.contains('_')
            || DnsName::try_from(server_name).is_err());
    if invalid {
        Err(InvalidServerName)
    } else {
        Ok(())
    }
}

fn level_index(level: EncryptionLevel) -> usize {
    match level {
        EncryptionLevel::Initial => 0,
        EncryptionLevel::Handshake => 1,
        EncryptionLevel::Application => 2,
    }
}

fn decode_peer_transport_parameters(
    parameters: Option<&[u8]>,
    handshaking: bool,
) -> Result<Option<TransportParameters>, TransportError> {
    match parameters {
        Some(parameters) => TransportParameters::read(Side::Client, &mut Cursor::new(parameters))
            .map(Some)
            .map_err(Into::into),
        None if handshaking => Ok(None),
        None => Err(transport_error(
            TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            "peer omitted QUIC transport parameters",
        )),
    }
}

fn map_start_error(server_name: &str, error: ClientSessionError) -> ConnectError {
    match error {
        ClientSessionError::InvalidServerName => {
            ConnectError::InvalidServerName(server_name.into())
        }
        _ => ConnectError::EndpointStopping,
    }
}

fn map_session_error(backend: &ClientSession, error: ClientSessionError) -> TransportError {
    if let Ok(alerts) = backend.drain_alerts()
        && let Some(alert) = alerts.first()
    {
        return transport_error(
            TransportErrorCode::crypto(alert.description),
            "TLS peer or verification alert",
        );
    }

    match error {
        ClientSessionError::BackendFailure(_)
        | ClientSessionError::CallbackInstall(_)
        | ClientSessionError::Callback(_)
        | ClientSessionError::AllocationFailed
        | ClientSessionError::ExportBeforeHandshake
        | ClientSessionError::PeerApplicationSettingsBeforeHandshake => transport_error(
            TransportErrorCode::INTERNAL_ERROR,
            "local TLS provider failure",
        ),
        ClientSessionError::InvalidPeerTransportParameters => transport_error(
            TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
            "invalid peer QUIC transport parameters",
        ),
        _ => transport_error(
            TransportErrorCode::PROTOCOL_VIOLATION,
            "TLS handshake failed",
        ),
    }
}

fn transport_error(code: TransportErrorCode, reason: &'static str) -> TransportError {
    TransportError {
        code,
        frame: None,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests;
