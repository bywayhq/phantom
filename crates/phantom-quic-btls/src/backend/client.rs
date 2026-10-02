use std::any::Any;
use std::collections::VecDeque;
use std::fmt;
use std::io::Cursor;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use btls::pkey::{PKey, Private};
use btls::ssl::{KeyShare, SslContext, SslContextBuilder};
use btls::x509::X509;
use phantom_profile::{
    AlpsSettings, CipherSuite, EchGreasePayloadLength, NamedGroup, TlsSettings, TlsVersion,
    TrustAnchorIds,
};
use quinn_proto::crypto::{self, ExportKeyingMaterialError, KeyPair, Keys};
use quinn_proto::{
    ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
    transport_parameters::TransportParameters,
};
use rustls_pki_types::DnsName;

use super::callback_state::{EncryptionLevel, HandshakeChunk, SecretPair};
use super::client_session::{ClientSession, ClientSessionError};
use super::quic_callbacks::{SessionDelivery, enable_session_delivery, session_delivery};
use crate::ech::{EchOffer, EchOutcome};
#[cfg(test)]
use crate::key_schedule::TestDerivationFailure;
use crate::key_schedule::{
    CipherSuite as QuicCipherSuite, PacketKeyPair, TrafficKeySchedule, TrafficKeys, TrafficSecret,
    derive_version_keys,
};
use crate::resumption::{ApplicationState, ResumptionTicket, SessionCache};
use crate::transport_parameters::{QuicTransportProfileError, TransportParameterProfile};
use crate::{EndpointSide, QuicVersion, derive_initial_keys, verify_retry_integrity};
use phantom_profile::quic::QuicTransportSettings;
use quinn_proto::{EndpointConfig, TransportConfig};

const H3_PROTOCOL: &[u8] = b"h3";

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
    early_data: bool,
    application_state: Option<ApplicationState>,
    ech: Option<EchOffer>,
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
                ech_grease_payload: EchGreasePayload::BackendDefault,
                ech_grease_aeads: Vec::new(),
                per_connection_trust_anchors: None,
                alps: None,
                session_tickets: false,
                client_certificate: None,
            },
            sessions: None,
            offer_tickets: true,
            early_data: false,
            application_state: None,
            ech: None,
            #[cfg(test)]
            derivation_failure: None,
        }
    }

    /// Wraps a BoringSSL context and applies a validated QUIC transport profile.
    ///
    /// The configuration offers early data on resumption when the profile
    /// sets `early_data`, as if [`Self::with_early_data`] had been called.
    pub fn with_transport_profile(
        context: SslContext,
        settings: QuicTransportSettings,
    ) -> Result<Self, QuicTransportProfileError> {
        let transport_profile = TransportParameterProfile::new(settings)?;
        Ok(Self {
            context,
            early_data: transport_profile.early_data(),
            transport_profile: Some(transport_profile),
            tls_profile: ClientTlsProfile::default(),
            sessions: None,
            offer_tickets: true,
            application_state: None,
            ech: None,
            #[cfg(test)]
            derivation_failure: None,
        })
    }

    /// Prepares a context builder so QUIC sessions can retain tickets.
    ///
    /// This enables BoringSSL's client session callback, with its internal
    /// cache off. Call it on the builder of every context whose TLS profile
    /// sets `session_tickets`. It changes nothing in a ClientHello that
    /// offers no ticket.
    ///
    /// A context has a single new-session callback. When the builder already
    /// has one that this crate did not install, for example from
    /// `SslContextBuilder::set_new_session_callback`, this returns an error
    /// of kind [`QuicTlsProfileErrorKind::ContextConflict`] and leaves the
    /// builder unchanged. Calling it again on a prepared builder succeeds.
    pub fn enable_session_resumption(
        builder: &mut SslContextBuilder,
    ) -> Result<(), QuicTlsProfileError> {
        enable_session_delivery(builder).map_err(|_| foreign_session_callback())
    }

    /// Applies TLS controls that BoringSSL owns per QUIC session.
    ///
    /// The QUIC path requires TLS 1.3, exact `h3` ALPN, and at most an empty
    /// local H3 ALPS value. Profiles must state those constraints explicitly;
    /// this method never rewrites them.
    ///
    /// `session_tickets` enables TLS 1.3 session resumption. It requires a
    /// context prepared with [`Self::enable_session_resumption`] whose
    /// new-session callback was not replaced afterwards, and it takes
    /// effect only on configurations derived with
    /// [`Self::with_isolated_session_cache`]. Without `session_tickets` no
    /// connection resumes, so this also clears the early-data offer that a
    /// transport profile's `early_data` set.
    ///
    /// A `requested_trust_anchor_ids` list drawn per connection gets a new
    /// order, drawn uniformly from its orders, in every session's
    /// ClientHello. A fixed or per-client list is a context setting, which
    /// this method leaves to the context.
    pub fn with_tls_profile(mut self, settings: &TlsSettings) -> Result<Self, QuicTlsProfileError> {
        let profile = ClientTlsProfile::new(settings)?;
        if profile.session_tickets {
            match session_delivery(&self.context) {
                SessionDelivery::Quic => {}
                SessionDelivery::Off => {
                    return Err(QuicTlsProfileError::invalid(
                        "session_tickets",
                        "QUIC session tickets require a context prepared for session resumption",
                    ));
                }
                SessionDelivery::Foreign => return Err(foreign_session_callback()),
            }
        }
        if !profile.session_tickets {
            self.early_data = false;
        }
        let client_certificate = self.tls_profile.client_certificate.take();
        self.tls_profile = ClientTlsProfile {
            client_certificate,
            ..profile
        };
        Ok(self)
    }

    /// Returns a clone that presents `certificate` when a server requests
    /// client authentication.
    ///
    /// Nothing in the ClientHello changes: BoringSSL sends the certificate
    /// only in answer to a `CertificateRequest`. The clone has an empty
    /// ticket cache of its own when this configuration has one, so a session
    /// authenticated with the certificate is never resumed without it, or
    /// the reverse.
    #[must_use]
    pub fn with_client_certificate(&self, certificate: &QuicClientCertificate) -> Self {
        let sessions = self.sessions.as_ref().map(|_| SessionCache::default());
        let mut config = self.clone_with_sessions(sessions);
        config.tls_profile.client_certificate = Some(Arc::clone(&certificate.inner));
        config
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
            early_data: self.early_data,
            application_state: None,
            ech: None,
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
            early_data: self.early_data,
            application_state: self.application_state.clone(),
            ech: self.ech.clone(),
            #[cfg(test)]
            derivation_failure: self.derivation_failure,
        }
    }

    /// Returns a clone that sends early (0-RTT) data when it resumes.
    ///
    /// # Replay
    ///
    /// Early data is replayable. An attacker who records the first flight can
    /// deliver it to the server again, and the server may process each copy
    /// (RFC 8446, section 8, and RFC 9001, section 9.2). Send only requests
    /// whose repetition is harmless.
    ///
    /// The clone shares this configuration's ticket cache. A connection offers
    /// 0-RTT only when it presents a ticket that permits early data and whose
    /// issuer's transport parameters were retained; otherwise it performs an
    /// ordinary resumed or full handshake. When the server rejects 0-RTT, the
    /// handshake still completes and Quinn reports the rejection through
    /// `early_data_accepted`.
    #[must_use]
    pub fn with_early_data(&self) -> Self {
        let mut config = self.clone_with_sessions(self.sessions.clone());
        config.early_data = true;
        config
    }

    /// Returns a clone that never sends early data, sharing the ticket cache.
    #[must_use]
    pub fn without_early_data(&self) -> Self {
        let mut config = self.clone_with_sessions(self.sessions.clone());
        config.early_data = false;
        config
    }

    /// Returns whether this configuration offers early (0-RTT) data.
    ///
    /// A connection sends early data only when it also presents a ticket,
    /// which needs a configuration from [`Self::with_isolated_session_cache`].
    #[must_use]
    pub const fn sends_early_data(&self) -> bool {
        self.early_data
    }

    fn clone_with_sessions(&self, sessions: Option<SessionCache>) -> Self {
        Self {
            context: self.context.clone(),
            transport_profile: self.transport_profile.clone(),
            tls_profile: self.tls_profile.clone(),
            sessions,
            offer_tickets: self.offer_tickets,
            early_data: self.early_data,
            application_state: self.application_state.clone(),
            ech: self.ech.clone(),
            #[cfg(test)]
            derivation_failure: self.derivation_failure,
        }
    }

    /// Returns a clone whose connection exchanges application state with
    /// the ticket cache through `state`.
    ///
    /// The clone shares this configuration's ticket cache. Use it for one
    /// connection, with a new [`ApplicationState`] each time. The connection
    /// holds the tickets it receives until [`ApplicationState::store`]
    /// records the state to keep with them. It offers early data only with a
    /// ticket stored with application state, and [`ApplicationState::remembered`]
    /// then returns that state. HTTP/3 keeps the server's SETTINGS this way
    /// (RFC 9114, section 7.2.4.2).
    #[must_use]
    pub fn with_application_state(&self, state: &ApplicationState) -> Self {
        let mut config = self.clone_with_sessions(self.sessions.clone());
        config.application_state = Some(state.clone());
        config
    }

    /// Returns a clone whose connection offers Encrypted Client Hello with
    /// the `ECHConfigList` of `offer` and records the result there.
    ///
    /// The clone shares this configuration's ticket cache. Use it for one
    /// connection, with a new [`EchOffer`] each time. The ClientHello keeps
    /// every field of the TLS profile. BoringSSL encrypts it under the first
    /// configuration in the list it supports and sends an outer ClientHello
    /// that names the configuration's public name, as Chromium's QUIC client
    /// does with the `ech` value of an HTTPS record. When the server rejects
    /// the offer, BoringSSL checks its certificate against the public name,
    /// records [`EchOutcome::Rejected`], and fails the handshake with the
    /// `ech_required` alert.
    #[must_use]
    pub fn with_ech(&self, offer: &EchOffer) -> Self {
        let mut config = self.clone_with_sessions(self.sessions.clone());
        config.ech = Some(offer.clone());
        config
    }

    /// Records the round-trip time a connection to `server_name` measured.
    ///
    /// A later connection from a configuration that shares this ticket cache,
    /// and that presents a ticket for the same name, advertises the most
    /// recent value as `initial_rtt_us` when its transport profile includes
    /// that parameter. Without a ticket cache this does nothing. Record only a
    /// measurement taken after the handshake produced an RTT sample.
    pub fn record_round_trip_time(&self, server_name: &str, rtt: Duration) {
        if let Some(sessions) = &self.sessions {
            sessions.record_round_trip_time(server_name, rtt);
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

    /// Applies the profile's initial path MTU for a peer at `remote`, whose
    /// address family sets the IP header size.
    ///
    /// Call it after [`Self::configure_transport`] on the transport of an
    /// endpoint that connects to `remote`.
    pub fn configure_path(
        &self,
        transport: &mut TransportConfig,
        remote: IpAddr,
    ) -> Result<(), QuicTransportProfileError> {
        if let Some(profile) = &self.transport_profile {
            profile.configure_path(transport, remote)?;
        }
        Ok(())
    }

    /// Applies this profile's per-connection settings to a Quinn client configuration.
    ///
    /// Sets the length of the first Initial's Destination Connection ID when the profile sets
    /// one. A connection that will present a session ticket starts in the QUIC version of the
    /// connection that received that ticket, when the profile lists that version as available;
    /// otherwise the connection starts in QUIC v1.
    pub fn configure_client(&self, config: &mut quinn_proto::ClientConfig, server_name: &str) {
        let Some(profile) = &self.transport_profile else {
            return;
        };
        if let Some(provider) = profile.initial_destination_connection_id() {
            config.initial_dst_cid_provider(provider);
        }
        let resumed_version = self
            .sessions
            .as_ref()
            .filter(|_| self.offer_tickets)
            .and_then(|sessions| sessions.version(server_name))
            .filter(|version| profile.lists_version(*version));
        config.version(resumed_version.unwrap_or(QuicVersion::V1).wire());
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
    ech_accepted: bool,
    peer_initial_max_streams_bidi: Option<u64>,
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

    /// Returns whether the server accepted the Encrypted Client Hello
    /// offered through [`QuicClientConfig::with_ech`].
    #[must_use]
    pub const fn ech_accepted(&self) -> bool {
        self.ech_accepted
    }

    /// Returns the peer's `initial_max_streams_bidi` transport parameter
    /// (RFC 9000, section 18.2): how many request streams the server lets
    /// the client open before it grants more with `MAX_STREAMS` frames.
    ///
    /// `None` means the parameters could not be read when the handshake
    /// completed.
    #[must_use]
    pub const fn peer_initial_max_streams_bidi(&self) -> Option<u64> {
        self.peer_initial_max_streams_bidi
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
            .field("ech_accepted", &self.ech_accepted)
            .field(
                "peer_initial_max_streams_bidi",
                &self.peer_initial_max_streams_bidi,
            )
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

        let offered = self
            .sessions
            .as_ref()
            .filter(|_| self.offer_tickets)
            .and_then(|sessions| {
                let ticket = sessions.take_for_version(server_name, version)?;
                Some((ticket, sessions.round_trip_time(server_name)))
            });
        // Only a connection that presents a ticket advertises a round-trip
        // time, as in every resumed Chromium connection in the captures.
        let initial_rtt = offered.as_ref().and_then(|(_, rtt)| *rtt);
        let encoded_parameters = if let Some(profile) = &self.transport_profile {
            profile
                .encode(params, version, initial_rtt)
                .map_err(|error| {
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
        let (session, remembered, remembered_state) =
            offered.map_or((None, None, None), |(ticket, _)| {
                (
                    Some(ticket.session),
                    ticket.peer_transport_parameters,
                    ticket.application_state,
                )
            });
        // Early data needs the issuer's transport parameters and, for a
        // connection that keeps application state, the state stored with the
        // ticket, as a Chromium client needs both.
        let early_data = self.early_data
            && remembered.is_some()
            && (self.application_state.is_none() || remembered_state.is_some());
        let mut backend = ClientSession::new_with_profile(
            &self.context,
            server_name,
            &encoded_parameters,
            &self.tls_profile,
            session.as_deref(),
            early_data,
            self.ech.as_ref().map(EchOffer::config_list),
        )
        .map_err(|error| {
            if error == ClientSessionError::InvalidEchConfigList
                && let Some(offer) = &self.ech
            {
                offer.record(EchOutcome::InvalidConfigList);
            }
            map_start_error(server_name, error)
        })?;
        backend
            .start_handshake()
            .map_err(|error| map_start_error(server_name, error))?;

        let mut state = SessionState::new(version, backend);
        state.ech = self.ech.clone();
        state.remembered_transport_parameters = remembered.filter(|_| early_data);
        state.ticket_sink = self.sessions.clone().map(|sessions| TicketSink {
            sessions,
            server_name: server_name.into(),
        });
        if let Some(application_state) = &self.application_state {
            let generation = application_state.start(
                self.sessions
                    .clone()
                    .map(|sessions| (sessions, Box::from(server_name))),
                remembered_state.filter(|_| early_data),
            );
            state.application_state = Some((application_state.clone(), generation));
        }
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

/// How a [`ClientTlsProfile`] sizes the GREASE ECH payload, from
/// [`EchGreasePayloadLength`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum EchGreasePayload {
    #[default]
    BackendDefault,
    Exact(u16),
    FromClientHello {
        maximum_name_length: u8,
    },
}

#[derive(Clone, Default)]
pub(super) struct ClientTlsProfile {
    key_shares: Option<Box<[KeyShare]>>,
    ech_grease: bool,
    ech_grease_payload: EchGreasePayload,
    ech_grease_aeads: Vec<u16>,
    /// A trust anchor ID list whose order each session draws; fixed and
    /// per-client lists belong to the context.
    per_connection_trust_anchors: Option<Arc<TrustAnchorIds>>,
    alps: Option<AlpsSettings>,
    session_tickets: bool,
    client_certificate: Option<Arc<ClientCertificate>>,
}

/// A client certificate chain and the private key of its first
/// certificate, for [`QuicClientConfig::with_client_certificate`].
///
/// Cloning is cheap: clones share the parsed certificates and key.
#[derive(Clone)]
pub struct QuicClientCertificate {
    inner: Arc<ClientCertificate>,
}

impl QuicClientCertificate {
    /// Parses a DER certificate chain, the client certificate first, and a
    /// DER private key: a PKCS #8 `PrivateKeyInfo`, or an RSA or EC key in
    /// its traditional encoding.
    ///
    /// # Errors
    ///
    /// Returns a [`QuicTlsProfileError`] of kind
    /// [`QuicTlsProfileErrorKind::InvalidProfile`] for the field
    /// `client_certificate` when the chain is empty, a certificate or the key
    /// does not parse, or the key does not belong to the first certificate.
    pub fn from_der<'a>(
        certificate_chain: impl IntoIterator<Item = &'a [u8]>,
        private_key: &[u8],
    ) -> Result<Self, QuicTlsProfileError> {
        let invalid = |message: &str| QuicTlsProfileError::invalid("client_certificate", message);
        let mut chain = certificate_chain
            .into_iter()
            .map(X509::from_der)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid("a certificate is not valid DER"))?
            .into_iter();
        let certificate = chain
            .next()
            .ok_or_else(|| invalid("the certificate chain holds no certificate"))?;
        let private_key = PKey::private_key_from_der(private_key)
            .map_err(|_| invalid("the private key is not a DER private key"))?;
        let matches = certificate
            .public_key()
            .is_ok_and(|public_key| public_key.public_eq(&private_key));
        if !matches {
            return Err(invalid(
                "the private key does not match the first certificate",
            ));
        }
        Ok(Self {
            inner: Arc::new(ClientCertificate {
                certificate,
                chain: chain.collect(),
                private_key,
            }),
        })
    }
}

impl fmt::Debug for QuicClientCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("QuicClientCertificate")
            .field("intermediate_count", &self.inner.chain.len())
            .finish_non_exhaustive()
    }
}

/// A certificate, its intermediates, and its private key, which a client
/// presents only when the server sends a `CertificateRequest`.
pub(super) struct ClientCertificate {
    pub(super) certificate: X509,
    pub(super) chain: Box<[X509]>,
    pub(super) private_key: PKey<Private>,
}

impl fmt::Debug for ClientTlsProfile {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientTlsProfile")
            .field("key_shares", &self.key_shares)
            .field("ech_grease", &self.ech_grease)
            .field("ech_grease_payload", &self.ech_grease_payload)
            .field("ech_grease_aeads", &self.ech_grease_aeads)
            .field(
                "per_connection_trust_anchors",
                &self.per_connection_trust_anchors.is_some(),
            )
            .field(
                "alps",
                &self.alps.as_ref().map(|value| value.settings.len()),
            )
            .field("session_tickets", &self.session_tickets)
            .field("client_certificate", &self.client_certificate.is_some())
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
        let ech_grease_payload = match settings.ech_grease_payload_length {
            EchGreasePayloadLength::BackendDefault => EchGreasePayload::BackendDefault,
            EchGreasePayloadLength::Exact(length) => EchGreasePayload::Exact(length),
            EchGreasePayloadLength::FromClientHello {
                maximum_name_length,
            } => EchGreasePayload::FromClientHello {
                maximum_name_length,
            },
            _ => {
                return Err(QuicTlsProfileError::unsupported(
                    "ech_grease_payload_length",
                    "this ECH GREASE payload length policy is not supported",
                ));
            }
        };
        let per_connection_trust_anchors = match &settings.requested_trust_anchor_ids {
            None | Some(TrustAnchorIds::Fixed(_) | TrustAnchorIds::PerClient(_)) => None,
            Some(ids @ TrustAnchorIds::PerConnection(_)) => Some(Arc::new(ids.clone())),
            Some(_) => {
                return Err(QuicTlsProfileError::unsupported(
                    "requested_trust_anchor_ids",
                    "this trust anchor ID order policy is not supported",
                ));
            }
        };
        Ok(Self {
            key_shares: Some(key_shares),
            ech_grease: settings.ech_grease,
            ech_grease_payload,
            ech_grease_aeads: settings
                .ech_grease_aeads
                .iter()
                .map(|aead| aead.hpke_id())
                .collect(),
            per_connection_trust_anchors,
            alps: settings.alps.clone(),
            session_tickets: settings.session_tickets,
            client_certificate: None,
        })
    }

    pub(super) fn client_certificate(&self) -> Option<&ClientCertificate> {
        self.client_certificate.as_deref()
    }

    pub(super) fn key_shares(&self) -> Option<&[KeyShare]> {
        self.key_shares.as_deref()
    }

    pub(super) const fn ech_grease(&self) -> bool {
        self.ech_grease
    }

    pub(super) const fn ech_grease_payload(&self) -> EchGreasePayload {
        self.ech_grease_payload
    }

    pub(super) fn ech_grease_aeads(&self) -> &[u16] {
        &self.ech_grease_aeads
    }

    pub(super) fn per_connection_trust_anchors(&self) -> Option<&TrustAnchorIds> {
        self.per_connection_trust_anchors.as_deref()
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

    fn conflict(field: &'static str, message: impl Into<Box<str>>) -> Self {
        Self {
            kind: QuicTlsProfileErrorKind::ContextConflict,
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
    /// The BoringSSL context already uses a setting the adapter must own,
    /// such as a new-session callback installed by other code.
    ContextConflict,
}

fn foreign_session_callback() -> QuicTlsProfileError {
    QuicTlsProfileError::conflict(
        "session_tickets",
        "the context's new-session callback belongs to other code",
    )
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
    /// Holds received tickets until their application state is known, with
    /// this connection's generation on the handle.
    application_state: Option<(ApplicationState, u64)>,
    /// The client's 0-RTT write secret, present only while offering early data.
    early_secret: Option<(u16, TrafficSecret)>,
    /// Set once a server moved the connection to another version, which withdraws early
    /// data whatever BoringSSL reports.
    version_switched: bool,
    /// The ticket issuer's transport parameters, applied to 0-RTT data until
    /// the server's current parameters arrive.
    remembered_transport_parameters: Option<Box<[u8]>>,
    /// Receives the result of this connection's Encrypted Client Hello offer.
    ech: Option<EchOffer>,
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
            application_state: None,
            early_secret: None,
            version_switched: false,
            remembered_transport_parameters: None,
            ech: None,
            #[cfg(test)]
            derivation_failure: None,
        }
    }

    fn collect_backend_state(&mut self) -> Result<(), AdapterError> {
        for chunk in self.backend.drain_output()? {
            self.outbound.stage(chunk);
        }
        if self.early_secret.is_none()
            && !self.version_switched
            && let Some(secret) = self.backend.take_early_secret()
        {
            self.early_secret = Some(secret);
        }

        if self.handshake_keys.is_none()
            && let Some(pair) = self.backend.take_secret_pair(EncryptionLevel::Handshake)?
        {
            self.handshake_keys = Some(keys_from_pair(pair, self.version)?.0);
        }
        if self.application_keys.is_none()
            && let Some(pair) = self
                .backend
                .take_secret_pair(EncryptionLevel::Application)?
        {
            #[cfg(test)]
            let derived = keys_from_pair_with_failure(pair, self.version, self.derivation_failure);
            #[cfg(not(test))]
            let derived = keys_from_pair(pair, self.version);
            let (keys, schedule) = derived?;
            self.application_keys = Some(keys);
            self.application_schedule = Some(schedule);
        }

        if self.peer_transport_parameters.is_none() {
            self.peer_transport_parameters = self.backend.peer_transport_parameters()?;
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
                ech_accepted: self.backend.ech_accepted(),
                peer_initial_max_streams_bidi: self
                    .peer_transport_parameters
                    .as_deref()
                    .and_then(crate::transport_parameters::initial_max_streams_bidi),
            });
            if self.backend.ech_accepted()
                && let Some(offer) = &self.ech
            {
                offer.record(EchOutcome::Accepted);
            }
        }
        if !self.backend.is_handshaking() && self.peer_identity.is_none() {
            self.peer_identity = Some(PeerIdentity {
                certificates: self.backend.peer_identity()?,
            });
        }
        let issued = self.backend.take_new_sessions();
        if let Some(sink) = &self.ticket_sink {
            for session in issued {
                let ticket = ResumptionTicket {
                    session,
                    version: self.version,
                    peer_transport_parameters: self
                        .peer_transport_parameters
                        .as_deref()
                        .map(Box::from),
                    application_state: None,
                };
                match &self.application_state {
                    Some((application_state, generation)) => {
                        application_state.receive(*generation, ticket);
                    }
                    None => sink.sessions.insert(&sink.server_name, ticket),
                }
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

pub(super) struct OutboundHandshake {
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
    /// Whether keys beyond the Initial level were handed to Quinn.
    pub(super) fn level_advanced(&self) -> bool {
        self.level != EncryptionLevel::Initial
    }

    pub(super) fn stage(&mut self, chunk: HandshakeChunk) {
        self.queues[level_index(chunk.level)].push_back(chunk.bytes);
    }

    pub(super) fn write(
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
        let state = self.lock();
        let (suite, secret) = state.early_secret.as_ref()?;
        let suite = QuicCipherSuite::from_id(*suite).ok()?;
        let (header, packet) = derive_version_keys(suite, secret.as_slice(), state.version)
            .ok()?
            .into_parts();
        Some((Box::new(header), Box::new(packet)))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        // BoringSSL may report that the server accepted early data sent in the start
        // version, but Quinn dropped it when the version changed.
        let state = self.lock();
        Some(!state.version_switched && state.backend.early_data_accepted())
    }

    fn is_handshaking(&self) -> bool {
        self.lock().backend.is_handshaking()
    }

    fn read_handshake(&mut self, buffer: &[u8]) -> Result<bool, TransportError> {
        let mut state = self.lock();
        if let Err(error) = state.backend.provide_handshake_data(buffer) {
            if let ClientSessionError::EchRejected { retry_configs } = &error
                && let Some(offer) = &state.ech
            {
                offer.record(EchOutcome::Rejected {
                    retry_configs: retry_configs.as_deref().map(Box::from),
                });
            }
            return Err(map_session_error(&state.backend, error));
        }
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
        let handshaking = state.backend.is_handshaking();
        // Quinn asks before the server's first flight when it enables 0-RTT;
        // the ticket issuer's parameters bound that data (RFC 9000, 7.4.1).
        let remembered = state
            .remembered_transport_parameters
            .as_deref()
            .filter(|_| handshaking && state.early_secret.is_some());
        decode_peer_transport_parameters(
            state.peer_transport_parameters.as_deref().or(remembered),
            handshaking,
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

    fn initial_keys_for_version(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Option<Keys> {
        let version = QuicVersion::from_wire(version)?;
        let side = match side {
            Side::Client => EndpointSide::Client,
            Side::Server => EndpointSide::Server,
        };
        derive_initial_keys(version, dst_cid, side)
            .ok()
            .map(initial_keys_into_quinn)
    }

    /// Adopts a version a server chose by compatible version negotiation (RFC 9368).
    ///
    /// BoringSSL hands out traffic secrets, and this session turns them into packet keys with
    /// the labels of its version, so a switch is sound only before the first handshake secret.
    /// The 0-RTT secret of the start version is dropped: its keys cannot protect packets of the
    /// new version, and Quinn treats the early data as rejected.
    fn switch_version(&mut self, version: u32) -> bool {
        let mut state = self.lock();
        let Some(version) = QuicVersion::from_wire(version) else {
            return false;
        };
        if state.handshake_keys.is_some()
            || state.application_keys.is_some()
            || state.outbound.level_advanced()
        {
            return false;
        }
        state.version = version;
        state.early_secret = None;
        state.version_switched = true;
        true
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

pub(super) enum AdapterError {
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

pub(super) fn keys_from_pair(
    pair: SecretPair,
    version: QuicVersion,
) -> Result<(Keys, TrafficKeySchedule), AdapterError> {
    let schedule =
        TrafficKeySchedule::from_local_remote(pair.cipher_suite, pair.local, pair.remote)
            .map_err(|_| AdapterError::Crypto)?
            .with_version(version);
    keys_from_schedule(schedule)
}

#[cfg(test)]
fn keys_from_pair_with_failure(
    pair: SecretPair,
    version: QuicVersion,
    failure: Option<TestDerivationFailure>,
) -> Result<(Keys, TrafficKeySchedule), AdapterError> {
    let schedule =
        TrafficKeySchedule::from_local_remote(pair.cipher_suite, pair.local, pair.remote)
            .map_err(|_| AdapterError::Crypto)?
            .with_version(version);
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

pub(super) fn initial_keys_into_quinn(keys: crate::InitialKeys) -> Keys {
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

pub(super) fn packet_pair_into_quinn(keys: PacketKeyPair) -> KeyPair<Box<dyn crypto::PacketKey>> {
    KeyPair {
        local: Box::new(keys.local),
        remote: Box::new(keys.remote),
    }
}

fn interpret_version(version: u32) -> Result<QuicVersion, ConnectError> {
    QuicVersion::from_wire(version).ok_or(ConnectError::UnsupportedVersion)
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

pub(super) fn transport_error(code: TransportErrorCode, reason: &'static str) -> TransportError {
    TransportError {
        code,
        frame: None,
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests;
