use std::any::Any;
use std::collections::VecDeque;
use std::fmt;
use std::io::Cursor;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use btls::ssl::SslContext;
use quinn_proto::crypto::{self, ExportKeyingMaterialError, KeyPair, Keys};
use quinn_proto::{
    ConnectError, ConnectionId, Side, TransportError, TransportErrorCode,
    transport_parameters::TransportParameters,
};

use super::callback_state::{EncryptionLevel, HandshakeChunk, SecretPair};
use super::client_session::{ClientSession, ClientSessionError};
use crate::key_schedule::{PacketKeyPair, TrafficKeySchedule, TrafficKeys};
use crate::{EndpointSide, QuicVersion, derive_initial_keys, verify_retry_integrity};

const QUIC_VERSION_1: u32 = 0x0000_0001;
const H3_PROTOCOL: &[u8] = b"h3";

/// Immutable BoringSSL configuration for Quinn client sessions.
///
/// The supplied context must enable peer verification and contain the trust
/// roots and fingerprint settings used by every session created from it.
/// Session-specific QUIC requirements are applied to each owned `SSL`.
pub struct QuicClientConfig {
    context: SslContext,
}

impl QuicClientConfig {
    /// Wraps an already configured BoringSSL context.
    #[must_use]
    pub const fn new(context: SslContext) -> Self {
        Self { context }
    }
}

impl fmt::Debug for QuicClientConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QuicClientConfig")
    }
}

/// Negotiated information made available by Quinn once ALPN is selected.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HandshakeData {
    protocol: Vec<u8>,
}

impl HandshakeData {
    /// Returns the negotiated ALPN protocol.
    #[must_use]
    pub fn protocol(&self) -> &[u8] {
        &self.protocol
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
        validate_dns_name(server_name)?;

        let mut encoded_parameters = Vec::new();
        params.write(&mut encoded_parameters);
        let mut backend = ClientSession::new(&self.context, server_name, &encoded_parameters)
            .map_err(|error| map_start_error(server_name, error))?;
        backend
            .start_handshake()
            .map_err(|error| map_start_error(server_name, error))?;

        let mut state = SessionState::new(version, backend);
        state
            .collect_backend_state()
            .map_err(|_| ConnectError::EndpointStopping)?;
        Ok(Box::new(QuicSession {
            state: Mutex::new(state),
        }))
    }
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
        }
    }

    fn collect_backend_state(&mut self) -> Result<(), AdapterError> {
        for chunk in self.backend.drain_output()? {
            self.outbound.stage(chunk);
        }

        if self.handshake_keys.is_none() {
            if let Some(pair) = self.backend.take_secret_pair(EncryptionLevel::Handshake)? {
                self.handshake_keys = Some(keys_from_pair(pair)?.0);
            }
        }
        if self.application_keys.is_none() {
            if let Some(pair) = self
                .backend
                .take_secret_pair(EncryptionLevel::Application)?
            {
                let (keys, schedule) = keys_from_pair(pair)?;
                self.application_keys = Some(keys);
                self.application_schedule = Some(schedule);
            }
        }

        if self.handshake_data.is_none() {
            if let Some(protocol) = self.backend.selected_protocol()? {
                if protocol != H3_PROTOCOL {
                    return Err(AdapterError::Backend(ClientSessionError::AlpnNotNegotiated));
                }
                self.handshake_data = Some(HandshakeData { protocol });
            }
        }
        if self.peer_transport_parameters.is_none() {
            self.peer_transport_parameters = self.backend.peer_transport_parameters()?;
        }
        if !self.backend.is_handshaking() && self.peer_identity.is_none() {
            self.peer_identity = Some(PeerIdentity {
                certificates: self.backend.peer_identity()?,
            });
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

fn validate_dns_name(server_name: &str) -> Result<(), ConnectError> {
    let invalid = server_name.is_empty()
        || server_name.len() > 253
        || !server_name.is_ascii()
        || server_name.parse::<IpAddr>().is_ok()
        || server_name.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if invalid {
        Err(ConnectError::InvalidServerName(server_name.into()))
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
    if let Ok(alerts) = backend.drain_alerts() {
        if let Some(alert) = alerts.first() {
            return transport_error(
                TransportErrorCode::crypto(alert.description),
                "TLS peer or verification alert",
            );
        }
    }

    match error {
        ClientSessionError::BackendFailure(_)
        | ClientSessionError::CallbackInstall(_)
        | ClientSessionError::Callback(_)
        | ClientSessionError::AllocationFailed
        | ClientSessionError::ExportBeforeHandshake => transport_error(
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
