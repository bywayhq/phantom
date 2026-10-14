//! A BoringSSL QUIC server for Phantom's loopback tests and capture tools.
//!
//! It exists so a test or a capture can terminate QUIC with the same TLS
//! library the client uses, including Encrypted Client Hello keys, which
//! Quinn's rustls provider cannot hold. Early data is opt-in. It offers no
//! client authentication and no Retry validation of its own.

use std::any::Any;
use std::fmt;
use std::io::Cursor;
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::{Arc, Mutex, MutexGuard};

use btls::ssl::{NameType, SslContext, SslRef};
use btls_sys as ffi;
use foreign_types::ForeignTypeRef;
use quinn_proto::crypto::{self, ExportKeyingMaterialError, KeyPair, Keys, UnsupportedVersion};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectionId, Side, TransportError, TransportErrorCode};

use super::callback_state::{CallbackState, EncryptionLevel, FlightLimits};
use super::client::{
    OutboundHandshake, initial_keys_into_quinn, keys_from_pair, packet_pair_into_quinn,
    transport_error,
};
use super::client_session::{OwnedSsl, encryption_level, raw_level};
use super::drain_error_queue;
use super::quic_callbacks::install_server_on_ssl;
use crate::key_schedule::{CipherSuite, TrafficKeySchedule, TrafficSecret, derive_version_keys};
use crate::transport_parameters::server_early_data_context;
use crate::{CryptoError, EndpointSide, QuicVersion, derive_initial_keys, retry_integrity_tag};

/// Largest ClientHello the server keeps for [`ServerHandshakeData`].
const MAX_CLIENT_HELLO: usize = 64 * 1024;
const MAX_TRANSPORT_PARAMETERS: usize = u16::MAX as usize;
const MAX_APPLICATION_CONTEXT: usize = u16::MAX as usize;

/// Quinn server crypto backed by a BoringSSL context.
///
/// The context supplies the certificate, private key, ALPN selection, and,
/// through `SslContextBuilder::set_ech_keys`, any Encrypted Client Hello
/// keys. Each connection is TLS 1.3 only and sends Quinn's transport
/// parameters. Requires the `server` feature.
#[derive(Clone)]
pub struct QuicServerConfig {
    context: SslContext,
    application_state: Option<Arc<[u8]>>,
}

impl QuicServerConfig {
    /// Wraps a configured BoringSSL server context.
    #[must_use]
    pub const fn new(context: SslContext) -> Self {
        Self {
            context,
            application_state: None,
        }
    }

    /// Enables early data for this server's loopback tests or capture tools.
    ///
    /// `application_state` must contain 1..=65535 bytes that identify the
    /// application settings used for early requests, such as the server's
    /// HTTP/3 SETTINGS. This is combined with the connection's QUIC version
    /// and rememberable transport parameters. A different context rejects
    /// early data while still allowing ordinary ticket resumption.
    ///
    /// Early data is replayable. The server application must only process
    /// operations it can safely receive more than once (RFC 9001 section 9.2).
    /// Clones share the BoringSSL context and its ticket keys.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidEarlyDataContextLength`] for an empty or
    /// oversized application context.
    pub fn with_early_data(mut self, application_state: &[u8]) -> Result<Self, CryptoError> {
        if application_state.is_empty() || application_state.len() > MAX_APPLICATION_CONTEXT {
            return Err(CryptoError::InvalidEarlyDataContextLength {
                actual: application_state.len(),
                minimum: 1,
                maximum: MAX_APPLICATION_CONTEXT,
            });
        }
        self.application_state = Some(Arc::from(application_state));
        Ok(self)
    }
}

impl fmt::Debug for QuicServerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QuicServerConfig")
    }
}

impl crypto::ServerConfig for QuicServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<Keys, UnsupportedVersion> {
        let version = supported_version(version).ok_or(UnsupportedVersion)?;
        derive_initial_keys(version, dst_cid, EndpointSide::Server)
            .map(initial_keys_into_quinn)
            .map_err(|_| UnsupportedVersion)
    }

    fn retry_tag(&self, version: u32, orig_dst_cid: &ConnectionId, packet: &[u8]) -> [u8; 16] {
        // Quinn calls this only for a version `initial_keys` accepted. A tag
        // that cannot be computed is left zero, so the client drops the Retry.
        let version = supported_version(version).unwrap_or_default();
        retry_integrity_tag(version, orig_dst_cid, packet).unwrap_or([0; 16])
    }

    fn start_session(
        self: Arc<Self>,
        version: u32,
        params: &TransportParameters,
    ) -> Box<dyn crypto::Session> {
        let version = supported_version(version).unwrap_or_default();
        let mut encoded = Vec::new();
        params.write(&mut encoded);
        let early_context = self
            .application_state
            .as_deref()
            .map(|state| server_early_data_context(&encoded, state, version))
            .transpose();
        let session = match early_context {
            Ok(context) => ServerSession::new(&self.context, &encoded, context.as_deref()),
            Err(_) => Err("server early-data context"),
        };
        Box::new(QuicServerSession {
            state: Mutex::new(ServerState::new(version, session)),
        })
    }
}

fn supported_version(version: u32) -> Option<QuicVersion> {
    QuicVersion::from_wire(version)
}

/// What the server learned from a client's ClientHello.
///
/// Quinn returns it from `Connection::handshake_data` on the server once
/// ALPN is selected, before the handshake completes, so it is available for
/// a connection the client later abandons.
#[derive(Clone, Eq, PartialEq)]
pub struct ServerHandshakeData {
    protocol: Vec<u8>,
    server_name: Option<String>,
    ech_accepted: bool,
    client_hello: Vec<u8>,
    session_resumed: bool,
    early_data_accepted: Option<bool>,
}

impl ServerHandshakeData {
    /// Returns the selected ALPN protocol.
    #[must_use]
    pub fn protocol(&self) -> &[u8] {
        &self.protocol
    }

    /// Returns the server name the handshake uses: the inner ClientHello's
    /// when Encrypted Client Hello was accepted, the outer one's otherwise.
    #[must_use]
    pub fn server_name(&self) -> Option<&str> {
        self.server_name.as_deref()
    }

    /// Returns whether the server decrypted an Encrypted Client Hello.
    #[must_use]
    pub const fn ech_accepted(&self) -> bool {
        self.ech_accepted
    }

    /// Returns whether the handshake resumed a session from a ticket.
    ///
    /// It is `false` until the handshake completes; read it from the
    /// established connection.
    #[must_use]
    pub const fn session_resumed(&self) -> bool {
        self.session_resumed
    }

    /// Returns whether the completed handshake accepted early data.
    ///
    /// Returns `None` until the client's Finished completes the handshake.
    /// Read it from the established connection, not an earlier data snapshot.
    #[must_use]
    pub const fn early_data_accepted(&self) -> Option<bool> {
        self.early_data_accepted
    }

    /// Returns the ClientHello message as the client sent it in its Initial
    /// packets: the outer ClientHello when it offered ECH.
    #[must_use]
    pub fn client_hello(&self) -> &[u8] {
        &self.client_hello
    }
}

impl fmt::Debug for ServerHandshakeData {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServerHandshakeData")
            .field("protocol", &self.protocol)
            .field("server_name", &self.server_name)
            .field("ech_accepted", &self.ech_accepted)
            .field("client_hello_len", &self.client_hello.len())
            .field("session_resumed", &self.session_resumed)
            .field("early_data_accepted", &self.early_data_accepted)
            .finish()
    }
}

struct QuicServerSession {
    state: Mutex<ServerState>,
}

impl QuicServerSession {
    fn lock(&self) -> MutexGuard<'_, ServerState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

struct ServerState {
    version: QuicVersion,
    session: Result<ServerSession, &'static str>,
    outbound: OutboundHandshake,
    handshake_keys: Option<Keys>,
    application_keys: Option<Keys>,
    application_schedule: Option<TrafficKeySchedule>,
    client_hello: Vec<u8>,
    handshake_data: Option<ServerHandshakeData>,
    handshake_data_announced: bool,
    peer_transport_parameters: Option<Vec<u8>>,
    early_secret: Option<(u16, TrafficSecret)>,
}

impl ServerState {
    fn new(version: QuicVersion, session: Result<ServerSession, &'static str>) -> Self {
        Self {
            version,
            session,
            outbound: OutboundHandshake::default(),
            handshake_keys: None,
            application_keys: None,
            application_schedule: None,
            client_hello: Vec::new(),
            handshake_data: None,
            handshake_data_announced: false,
            peer_transport_parameters: None,
            early_secret: None,
        }
    }

    fn read(&mut self, data: &[u8]) -> Result<(), TransportError> {
        let session = self
            .session
            .as_mut()
            .map_err(|operation| transport_error(TransportErrorCode::INTERNAL_ERROR, operation))?;
        if session.read_level()? == EncryptionLevel::Initial
            && self.client_hello.len() + data.len() <= MAX_CLIENT_HELLO
        {
            self.client_hello.extend_from_slice(data);
        }
        session.provide(data)?;
        self.collect()
    }

    fn collect(&mut self) -> Result<(), TransportError> {
        let Ok(session) = &self.session else {
            return Ok(());
        };
        for chunk in session.callbacks.drain_handshake().map_err(internal)? {
            self.outbound.stage(chunk);
        }
        if self.early_secret.is_none() {
            self.early_secret = session.callbacks.take_early_secret();
        }
        if self.handshake_keys.is_none()
            && let Some(pair) = session
                .callbacks
                .take_secret_pair(EncryptionLevel::Handshake)
        {
            self.handshake_keys = Some(
                keys_from_pair(pair, self.version)
                    .map_err(|_| key_failure())?
                    .0,
            );
        }
        if self.application_keys.is_none()
            && let Some(pair) = session
                .callbacks
                .take_secret_pair(EncryptionLevel::Application)
        {
            let (keys, schedule) = keys_from_pair(pair, self.version).map_err(|_| key_failure())?;
            self.application_keys = Some(keys);
            self.application_schedule = Some(schedule);
        }
        if self.handshake_data.is_none()
            && let Some(protocol) = session.selected_protocol()
        {
            self.handshake_data = Some(ServerHandshakeData {
                protocol,
                server_name: session.server_name(),
                ech_accepted: session.ech_accepted(),
                client_hello: self.client_hello.clone(),
                session_resumed: false,
                early_data_accepted: None,
            });
        }
        if session.handshake_complete
            && let Some(data) = &mut self.handshake_data
        {
            data.session_resumed = session.session_reused();
            data.early_data_accepted = Some(session.early_data_accepted());
        }
        if self.peer_transport_parameters.is_none() {
            self.peer_transport_parameters = session.peer_transport_parameters()?;
        }
        Ok(())
    }
}

impl fmt::Debug for QuicServerSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("QuicServerSession")
    }
}

impl crypto::Session for QuicServerSession {
    fn initial_keys(
        &self,
        dst_cid: &ConnectionId,
        side: Side,
    ) -> Result<Keys, crypto::CryptoError> {
        let side = match side {
            Side::Client => EndpointSide::Client,
            Side::Server => EndpointSide::Server,
        };
        derive_initial_keys(self.lock().version, dst_cid, side)
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
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        let state = self.lock();
        let (suite, secret) = state.early_secret.as_ref()?;
        let suite = CipherSuite::from_id(*suite).ok()?;
        let (header, packet) = derive_version_keys(suite, secret.as_slice(), state.version)
            .ok()?
            .into_parts();
        Some((Box::new(header), Box::new(packet)))
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        // A session that failed to start never completes a handshake.
        !matches!(&self.lock().session, Ok(session) if session.handshake_complete)
    }

    fn read_handshake(&mut self, buffer: &[u8]) -> Result<bool, TransportError> {
        let mut state = self.lock();
        state.read(buffer)?;
        if state.handshake_data.is_some() && !state.handshake_data_announced {
            state.handshake_data_announced = true;
            return Ok(true);
        }
        Ok(false)
    }

    fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
        let state = self.lock();
        state
            .peer_transport_parameters
            .as_deref()
            .map(|parameters| TransportParameters::read(Side::Server, &mut Cursor::new(parameters)))
            .transpose()
            .map_err(Into::into)
    }

    fn write_handshake(&mut self, buffer: &mut Vec<u8>) -> Option<Keys> {
        let state = &mut *self.lock();
        state.outbound.write(
            buffer,
            &mut state.handshake_keys,
            &mut state.application_keys,
        )
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
            .map_err(|_| key_failure())
    }

    fn is_valid_retry(
        &self,
        _original_destination_connection_id: &ConnectionId,
        _header: &[u8],
        _payload: &[u8],
    ) -> bool {
        false
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        match &self.lock().session {
            Ok(session) => session.export_keying_material(output, label, context),
            Err(_) => Err(ExportKeyingMaterialError),
        }
    }
}

/// One server-side BoringSSL QUIC handshake.
struct ServerSession {
    // SSL must drop before the external callback-state handle.
    ssl: OwnedSsl,
    callbacks: CallbackState,
    handshake_complete: bool,
}

impl ServerSession {
    fn new(
        context: &SslContext,
        transport_parameters: &[u8],
        early_context: Option<&[u8]>,
    ) -> Result<Self, &'static str> {
        if transport_parameters.len() > MAX_TRANSPORT_PARAMETERS {
            return Err("server transport parameters too long");
        }
        ffi::init();
        let context = NonNull::new(context.as_ptr()).ok_or("server context")?;
        // SAFETY: the safe context owner is live and SSL_new retains its own reference.
        let ssl = unsafe { OwnedSsl::new(context) }.map_err(|_| "server SSL allocation")?;
        let pointer = ssl.as_ptr();
        // SAFETY: `pointer` is live and uniquely owned.
        if unsafe { ffi::SSL_set_min_proto_version(pointer, ffi::TLS1_3_VERSION as u16) } != 1 {
            return Err(failure("server minimum TLS version"));
        }
        // SAFETY: `pointer` is live and uniquely owned.
        if unsafe { ffi::SSL_set_max_proto_version(pointer, ffi::TLS1_3_VERSION as u16) } != 1 {
            return Err(failure("server maximum TLS version"));
        }
        // SAFETY: the SSL is live, uniquely owned, and has not started a handshake.
        unsafe {
            ffi::SSL_set_early_data_enabled(pointer, i32::from(early_context.is_some()));
        }
        if let Some(context) = early_context {
            // SAFETY: the unstarted SSL is live and the setter copies these bytes.
            if unsafe {
                ffi::SSL_set_quic_early_data_context(pointer, context.as_ptr(), context.len())
            } != 1
            {
                return Err(failure("server early-data context"));
            }
        }
        // SAFETY: the parameters remain live for the copying setter call.
        if unsafe {
            ffi::SSL_set_quic_transport_params(
                pointer,
                transport_parameters.as_ptr(),
                transport_parameters.len(),
            )
        } != 1
        {
            return Err(failure("server transport parameters"));
        }
        // SAFETY: this uniquely owned SSL has not started a handshake.
        unsafe {
            ffi::SSL_set_accept_state(pointer);
        }
        // SAFETY: the SSL is live, unique, and has not started its handshake.
        let callbacks =
            unsafe { install_server_on_ssl(ssl.as_non_null(), FlightLimits::default()) }
                .map_err(|_| "server QUIC callbacks")?;
        Ok(Self {
            ssl,
            callbacks,
            handshake_complete: false,
        })
    }

    fn read_level(&self) -> Result<EncryptionLevel, TransportError> {
        // SAFETY: the SSL is live and configured with the QUIC method.
        let level = unsafe { ffi::SSL_quic_read_level(self.ssl.as_ptr()) };
        encryption_level(level).map_err(internal)
    }

    fn provide(&mut self, data: &[u8]) -> Result<(), TransportError> {
        if let Some(error) = self.callbacks.terminal_error() {
            return Err(internal(error));
        }
        if !data.is_empty() {
            let level = raw_level(self.read_level()?);
            // SAFETY: the SSL and input slice remain live for the copying call.
            if unsafe {
                ffi::SSL_provide_quic_data(self.ssl.as_ptr(), level, data.as_ptr(), data.len())
            } != 1
            {
                return Err(self.handshake_failure());
            }
        }
        if self.handshake_complete {
            // SAFETY: the SSL is live and its handshake completed.
            if unsafe { ffi::SSL_process_quic_post_handshake(self.ssl.as_ptr()) } != 1 {
                return Err(self.handshake_failure());
            }
            return Ok(());
        }
        // SAFETY: the SSL is live, unique, and configured for a QUIC server handshake.
        let result = unsafe { ffi::SSL_do_handshake(self.ssl.as_ptr()) };
        if result == 1 {
            // SAFETY: this live SSL's early-data state is read without mutation.
            let in_early_data = unsafe { ffi::SSL_in_early_data(self.ssl.as_ptr()) } != 0;
            // An accepting server returns 1 before the client's Finished.
            self.handshake_complete = !in_early_data;
            drain_error_queue();
            return Ok(());
        }
        // SAFETY: `result` is the immediately preceding SSL operation result.
        let ssl_error = unsafe { ffi::SSL_get_error(self.ssl.as_ptr(), result) };
        if result == -1 && ssl_error == ffi::SSL_ERROR_WANT_READ {
            drain_error_queue();
            return Ok(());
        }
        Err(self.handshake_failure())
    }

    fn handshake_failure(&self) -> TransportError {
        drain_error_queue();
        if let Some(error) = self.callbacks.terminal_error() {
            return internal(error);
        }
        match self
            .callbacks
            .drain_alerts()
            .ok()
            .and_then(|alerts| alerts.first().copied())
        {
            Some(alert) => transport_error(
                TransportErrorCode::crypto(alert.description),
                "TLS alert from the server handshake",
            ),
            None => transport_error(
                TransportErrorCode::PROTOCOL_VIOLATION,
                "TLS handshake failed",
            ),
        }
    }

    fn ssl_ref(&self) -> &SslRef {
        // SAFETY: the SSL remains live for the borrow of `self`, and every
        // mutating SSL call takes `&mut self`.
        unsafe { SslRef::from_ptr(self.ssl.as_ptr()) }
    }

    fn selected_protocol(&self) -> Option<Vec<u8>> {
        self.ssl_ref().selected_alpn_protocol().map(<[u8]>::to_vec)
    }

    fn server_name(&self) -> Option<String> {
        self.ssl_ref()
            .servername(NameType::HOST_NAME)
            .map(str::to_owned)
    }

    fn ech_accepted(&self) -> bool {
        self.ssl_ref().ech_accepted()
    }

    fn session_reused(&self) -> bool {
        // SAFETY: the SSL is live; the query reads handshake state only.
        unsafe { ffi::SSL_session_reused(self.ssl.as_ptr()) != 0 }
    }

    fn early_data_accepted(&self) -> bool {
        // SAFETY: the SSL is live; this query reads handshake state only.
        self.handshake_complete && unsafe { ffi::SSL_early_data_accepted(self.ssl.as_ptr()) } != 0
    }

    fn peer_transport_parameters(&self) -> Result<Option<Vec<u8>>, TransportError> {
        let mut parameters = ptr::null();
        let mut len = 0;
        // SAFETY: both outputs are valid and the SSL remains live for the copy below.
        unsafe {
            ffi::SSL_get_peer_quic_transport_params(self.ssl.as_ptr(), &mut parameters, &mut len);
        }
        if len == 0 {
            return Ok(None);
        }
        if parameters.is_null() || len > MAX_TRANSPORT_PARAMETERS {
            return Err(transport_error(
                TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                "invalid client QUIC transport parameters",
            ));
        }
        // SAFETY: BoringSSL owns `len` readable bytes for the lifetime of the SSL.
        Ok(Some(
            unsafe { slice::from_raw_parts(parameters, len) }.to_vec(),
        ))
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ExportKeyingMaterialError> {
        if !self.handshake_complete {
            return Err(ExportKeyingMaterialError);
        }
        // SAFETY: all slices are live for the call. `use_context` is set even
        // for an empty context so it remains distinct from an absent context.
        let status = unsafe {
            ffi::SSL_export_keying_material(
                self.ssl.as_ptr(),
                output.as_mut_ptr(),
                output.len(),
                label.as_ptr().cast(),
                label.len(),
                context.as_ptr(),
                context.len(),
                1,
            )
        };
        if status == 1 {
            Ok(())
        } else {
            drain_error_queue();
            Err(ExportKeyingMaterialError)
        }
    }
}

fn failure(operation: &'static str) -> &'static str {
    drain_error_queue();
    operation
}

/// Maps a local failure to `INTERNAL_ERROR` without exposing its details
/// on the wire.
fn internal(_error: impl fmt::Debug) -> TransportError {
    transport_error(
        TransportErrorCode::INTERNAL_ERROR,
        "local TLS provider failure",
    )
}

fn key_failure() -> TransportError {
    transport_error(
        TransportErrorCode::INTERNAL_ERROR,
        "QUIC traffic key derivation failed",
    )
}

#[cfg(test)]
mod tests;
