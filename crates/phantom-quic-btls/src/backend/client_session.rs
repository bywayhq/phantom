use std::collections::VecDeque;
use std::ffi::c_long;
use std::fmt;
use std::net::IpAddr;
use std::ptr::{self, NonNull};
use std::slice;

use btls::ssl::{SslContext, SslRef, SslSession, SslSessionRef};
use btls::x509::verify::X509CheckFlags;
use btls_sys as ffi;
use foreign_types::{ForeignType, ForeignTypeRef};

use super::drain_error_queue;
use super::quic_callbacks::{CallbackInstallError, install_on_ssl};
use super::{
    callback_state::{
        Alert, CallbackError, CallbackState, EncryptionLevel, FlightLimits, HandshakeChunk,
        SecretPair,
    },
    client::ClientTlsProfile,
};

const H3_ALPN: &[u8] = &[2, b'h', b'3'];
const H3_PROTOCOL: &[u8] = b"h3";
const MAX_TRANSPORT_PARAMETERS: usize = u16::MAX as usize;
const MAX_PEER_CERTIFICATES: usize = 32;
const MAX_CERTIFICATE_DER: usize = 1024 * 1024;
const MAX_PEER_CHAIN_DER: usize = 4 * 1024 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ClientSessionError {
    InvalidServerName,
    X509ContextRequired,
    MissingTransportParameters,
    TransportParametersTooLong {
        len: usize,
    },
    PeerVerificationDisabled,
    CallbackInstall(CallbackInstallError),
    Callback(CallbackError),
    BackendFailure(&'static str),
    TlsFailure {
        operation: &'static str,
        ssl_error: i32,
    },
    UnexpectedProtocolVersion {
        actual: i32,
    },
    PeerVerificationFailed,
    AlpnNotNegotiated,
    PeerApplicationSettingsBeforeHandshake,
    ResumptionAttempted,
    EarlyDataActive,
    InvalidPeerTransportParameters,
    MissingPeerIdentity,
    PeerIdentityTooLarge,
    ExportBeforeHandshake,
    AllocationFailed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HandshakeProgress {
    NeedsData,
    Complete,
}

struct OwnedSsl(NonNull<ffi::SSL>);

// SAFETY: `OwnedSsl` has one owner; moving it transfers all access to the SSL.
unsafe impl Send for OwnedSsl {}

impl OwnedSsl {
    unsafe fn new(context: NonNull<ffi::SSL_CTX>) -> Result<Self, ClientSessionError> {
        // SAFETY: the caller supplies a live context; SSL_new retains its own context reference.
        let ssl = unsafe { ffi::SSL_new(context.as_ptr()) };
        let Some(ssl) = NonNull::new(ssl) else {
            return Err(backend_failure("SSL allocation"));
        };
        Ok(Self(ssl))
    }

    const fn as_ptr(&self) -> *mut ffi::SSL {
        self.0.as_ptr()
    }
}

impl fmt::Debug for OwnedSsl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("OwnedSsl")
    }
}

impl Drop for OwnedSsl {
    fn drop(&mut self) {
        // SAFETY: this owner releases its unique SSL allocation exactly once.
        unsafe {
            ffi::SSL_free(self.0.as_ptr());
        }
    }
}

pub(super) struct ClientSession {
    // SSL must drop before the external callback-state handle.
    ssl: OwnedSsl,
    callbacks: CallbackState,
    handshake_complete: bool,
    offered_session: bool,
}

impl fmt::Debug for ClientSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientSession")
            .field("handshake_complete", &self.handshake_complete)
            .field("offered_session", &self.offered_session)
            .finish_non_exhaustive()
    }
}

impl ClientSession {
    /// Creates a client from a verification-configured BoringSSL context.
    ///
    #[cfg(test)]
    pub(super) fn new(
        context: &SslContext,
        server_name: &str,
        local_transport_parameters: &[u8],
    ) -> Result<Self, ClientSessionError> {
        Self::new_with_profile(
            context,
            server_name,
            local_transport_parameters,
            &ClientTlsProfile::default(),
            None,
        )
    }

    /// Creates a client that offers `session` for resumption when present.
    ///
    /// The caller must supply only a session that a handshake from `context`
    /// authenticated for `server_name`: BoringSSL does not bind a client
    /// session to a hostname, and a resumed handshake does not repeat
    /// certificate verification.
    pub(super) fn new_with_profile(
        context: &SslContext,
        server_name: &str,
        local_transport_parameters: &[u8],
        tls_profile: &ClientTlsProfile,
        session: Option<&SslSessionRef>,
    ) -> Result<Self, ClientSessionError> {
        if server_name.is_empty() {
            return Err(ClientSessionError::InvalidServerName);
        }
        if local_transport_parameters.is_empty() {
            return Err(ClientSessionError::MissingTransportParameters);
        }
        if local_transport_parameters.len() > MAX_TRANSPORT_PARAMETERS {
            return Err(ClientSessionError::TransportParametersTooLong {
                len: local_transport_parameters.len(),
            });
        }

        if !context.has_x509_support() {
            return Err(ClientSessionError::X509ContextRequired);
        }

        ffi::init();
        let context =
            NonNull::new(context.as_ptr()).ok_or(ClientSessionError::X509ContextRequired)?;
        // SAFETY: the safe context owner is live and SSL_new retains its own reference.
        let mut ssl = unsafe { OwnedSsl::new(context) }?;
        apply_tls_profile(&mut ssl, tls_profile)?;
        apply_server_name(&mut ssl, server_name)?;
        let pointer = ssl.as_ptr();

        // SAFETY: `pointer` is uniquely owned throughout construction.
        if unsafe { ffi::SSL_get_verify_mode(pointer) } & ffi::SSL_VERIFY_PEER == 0 {
            return Err(ClientSessionError::PeerVerificationDisabled);
        }
        // SAFETY: `pointer` is live and uniquely owned.
        if unsafe { ffi::SSL_set_min_proto_version(pointer, ffi::TLS1_3_VERSION as u16) } != 1 {
            return Err(backend_failure("minimum TLS version"));
        }
        // SAFETY: `pointer` is live and uniquely owned.
        if unsafe { ffi::SSL_set_max_proto_version(pointer, ffi::TLS1_3_VERSION as u16) } != 1 {
            return Err(backend_failure("maximum TLS version"));
        }
        // SAFETY: the option is applied to this uniquely owned SSL.
        let options = unsafe { ffi::SSL_set_options(pointer, ffi::SSL_OP_NO_TICKET as u32) };
        if options & ffi::SSL_OP_NO_TICKET as u32 == 0 {
            return Err(backend_failure("session ticket disable"));
        }
        // SAFETY: the SSL is live and has not started a handshake.
        unsafe {
            ffi::SSL_set_early_data_enabled(pointer, 0);
        }
        // SAFETY: ALPN bytes remain live for the copying setter call.
        if unsafe { ffi::SSL_set_alpn_protos(pointer, H3_ALPN.as_ptr(), H3_ALPN.len()) } != 0 {
            return Err(backend_failure("ALPN configuration"));
        }
        // SAFETY: transport parameters remain live for the copying setter call.
        if unsafe {
            ffi::SSL_set_quic_transport_params(
                pointer,
                local_transport_parameters.as_ptr(),
                local_transport_parameters.len(),
            )
        } != 1
        {
            return Err(backend_failure("local QUIC transport parameters"));
        }
        if let Some(session) = session {
            // SAFETY: the SSL is live, unique, and has not started a handshake;
            // the session is live for the call and SSL_set_session takes its own
            // reference. BoringSSL drops an expired or non-QUIC session at
            // ClientHello time and performs a full handshake instead.
            if unsafe { ffi::SSL_set_session(pointer, session.as_ptr()) } != 1 {
                return Err(backend_failure("session resumption"));
            }
        }
        // SAFETY: this uniquely owned SSL has not started a handshake.
        unsafe {
            ffi::SSL_set_connect_state(pointer);
        }
        // SAFETY: the SSL is live; QUIC sessions must not have BIOs.
        if unsafe { !ffi::SSL_get_rbio(pointer).is_null() || !ffi::SSL_get_wbio(pointer).is_null() }
        {
            return Err(ClientSessionError::BackendFailure("unexpected BIO"));
        }

        // SAFETY: the SSL is live, unique, and has not started its handshake.
        let callbacks = unsafe { install_on_ssl(ssl.0, FlightLimits::default()) }
            .map_err(ClientSessionError::CallbackInstall)?;
        Ok(Self {
            ssl,
            callbacks,
            handshake_complete: false,
            offered_session: session.is_some(),
        })
    }

    pub(super) fn start_handshake(&mut self) -> Result<HandshakeProgress, ClientSessionError> {
        self.drive_handshake()
    }

    pub(super) fn provide_handshake_data(
        &mut self,
        data: &[u8],
    ) -> Result<HandshakeProgress, ClientSessionError> {
        self.callback_error()?;
        let level = self.incoming_level()?;
        if !data.is_empty() {
            let raw_level = raw_level(level);
            // SAFETY: the SSL and input slice remain live for the copying call.
            if unsafe {
                ffi::SSL_provide_quic_data(self.ssl.as_ptr(), raw_level, data.as_ptr(), data.len())
            } != 1
            {
                return Err(self.operation_failure("provide QUIC handshake data", None));
            }
        }

        if self.handshake_complete {
            self.process_post_handshake()?;
            Ok(HandshakeProgress::Complete)
        } else {
            self.drive_handshake()
        }
    }

    fn incoming_level(&self) -> Result<EncryptionLevel, ClientSessionError> {
        // SAFETY: the SSL is live and configured with the QUIC method.
        let level = unsafe { ffi::SSL_quic_read_level(self.ssl.as_ptr()) };
        encryption_level(level).map_err(ClientSessionError::Callback)
    }

    pub(super) fn drain_output(&self) -> Result<Vec<HandshakeChunk>, ClientSessionError> {
        self.callbacks
            .drain_handshake()
            .map_err(ClientSessionError::Callback)
    }

    pub(super) fn drain_alerts(&self) -> Result<Vec<Alert>, ClientSessionError> {
        self.callbacks
            .drain_alerts()
            .map_err(ClientSessionError::Callback)
    }

    pub(super) fn take_secret_pair(
        &self,
        level: EncryptionLevel,
    ) -> Result<Option<SecretPair>, ClientSessionError> {
        self.callback_error()?;
        Ok(self.callbacks.take_secret_pair(level))
    }

    pub(super) fn selected_protocol(&self) -> Result<Option<Vec<u8>>, ClientSessionError> {
        self.callback_error()?;
        let mut protocol = ptr::null();
        let mut protocol_len = 0;
        // SAFETY: output pointers are valid and the selected ALPN remains SSL-owned.
        unsafe {
            ffi::SSL_get0_alpn_selected(self.ssl.as_ptr(), &mut protocol, &mut protocol_len);
        }
        if protocol_len == 0 {
            return Ok(None);
        }
        if protocol.is_null() {
            return Err(ClientSessionError::AlpnNotNegotiated);
        }
        // SAFETY: BoringSSL returned `protocol_len` readable SSL-owned bytes.
        let protocol = unsafe { slice::from_raw_parts(protocol, protocol_len as usize) };
        Ok(Some(protocol.to_vec()))
    }

    pub(super) fn peer_application_settings(&self) -> Result<Option<Vec<u8>>, ClientSessionError> {
        self.callback_error()?;
        if !self.handshake_complete {
            return Err(ClientSessionError::PeerApplicationSettingsBeforeHandshake);
        }
        // SAFETY: the SSL remains live and no mutable SSL operation overlaps this borrow.
        let ssl = unsafe { SslRef::from_ptr(self.ssl.as_ptr()) };
        let Some(settings) = ssl.peer_application_settings() else {
            return Ok(None);
        };
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(settings.len())
            .map_err(|_| ClientSessionError::AllocationFailed)?;
        owned.extend_from_slice(settings);
        Ok(Some(owned))
    }

    pub(super) fn peer_identity(&self) -> Result<Vec<Vec<u8>>, ClientSessionError> {
        self.callback_error()?;
        if !self.handshake_complete {
            return Err(ClientSessionError::MissingPeerIdentity);
        }
        // SAFETY: the SSL remains live and no mutable SSL operation overlaps this borrow.
        let ssl = unsafe { SslRef::from_ptr(self.ssl.as_ptr()) };
        let chain = ssl
            .peer_cert_chain()
            .ok_or(ClientSessionError::MissingPeerIdentity)?;
        if chain.is_empty() || chain.len() > MAX_PEER_CERTIFICATES {
            return Err(ClientSessionError::PeerIdentityTooLarge);
        }

        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(chain.len())
            .map_err(|_| ClientSessionError::AllocationFailed)?;
        let mut total = 0usize;
        for certificate in chain {
            let len = certificate
                .to_der()
                .map_err(|_| backend_failure("peer certificate encoding"))?;
            total = total
                .checked_add(len.len())
                .ok_or(ClientSessionError::PeerIdentityTooLarge)?;
            if len.len() > MAX_CERTIFICATE_DER || total > MAX_PEER_CHAIN_DER {
                return Err(ClientSessionError::PeerIdentityTooLarge);
            }
            encoded.push(len);
        }
        Ok(encoded)
    }

    pub(super) fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ClientSessionError> {
        self.callback_error()?;
        if !self.handshake_complete {
            return Err(ClientSessionError::ExportBeforeHandshake);
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
        if status != 1 {
            return Err(backend_failure("keying material export"));
        }
        Ok(())
    }

    pub(super) const fn is_handshaking(&self) -> bool {
        !self.handshake_complete
    }

    /// Returns whether the completed handshake resumed the offered session.
    pub(super) fn session_reused(&self) -> bool {
        // SAFETY: the SSL is live; the query reads handshake state only.
        self.handshake_complete && unsafe { ffi::SSL_session_reused(self.ssl.as_ptr()) } != 0
    }

    /// Removes the sessions issued since the previous call, oldest first.
    ///
    /// Tickets arrive only after the handshake completed and verified the
    /// peer, so a returned session is always authenticated.
    pub(super) fn take_new_sessions(&self) -> VecDeque<SslSession> {
        if self.handshake_complete {
            self.callbacks.take_sessions()
        } else {
            VecDeque::new()
        }
    }

    pub(super) fn peer_transport_parameters(&self) -> Result<Option<Vec<u8>>, ClientSessionError> {
        self.callback_error()?;
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
            return Err(ClientSessionError::InvalidPeerTransportParameters);
        }
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(len)
            .map_err(|_| ClientSessionError::AllocationFailed)?;
        // SAFETY: BoringSSL owns `len` readable bytes for the lifetime of the SSL.
        owned.extend_from_slice(unsafe { slice::from_raw_parts(parameters, len) });
        Ok(Some(owned))
    }

    fn drive_handshake(&mut self) -> Result<HandshakeProgress, ClientSessionError> {
        self.callback_error()?;
        if self.handshake_complete {
            return Ok(HandshakeProgress::Complete);
        }
        // SAFETY: the SSL is live, unique, and configured for a QUIC client handshake.
        let result = unsafe { ffi::SSL_do_handshake(self.ssl.as_ptr()) };
        if result == 1 {
            self.validate_completed_handshake()?;
            self.handshake_complete = true;
            return Ok(HandshakeProgress::Complete);
        }
        // SAFETY: `result` is the immediately preceding SSL operation result.
        let ssl_error = unsafe { ffi::SSL_get_error(self.ssl.as_ptr(), result) };
        if result == -1 && ssl_error == ffi::SSL_ERROR_WANT_READ {
            self.callback_error()?;
            drain_error_queue();
            Ok(HandshakeProgress::NeedsData)
        } else {
            Err(self.operation_failure("TLS handshake", Some(ssl_error)))
        }
    }

    fn process_post_handshake(&self) -> Result<(), ClientSessionError> {
        self.callback_error()?;
        // SAFETY: the SSL is live and its initial handshake completed.
        if unsafe { ffi::SSL_process_quic_post_handshake(self.ssl.as_ptr()) } != 1 {
            return Err(self.operation_failure("post-handshake processing", None));
        }
        self.callback_error()
    }

    fn validate_completed_handshake(&self) -> Result<(), ClientSessionError> {
        // SAFETY: the SSL is live and SSL_do_handshake returned success.
        let version = unsafe { ffi::SSL_version(self.ssl.as_ptr()) };
        if version != ffi::TLS1_3_VERSION {
            return Err(ClientSessionError::UnexpectedProtocolVersion { actual: version });
        }
        // SAFETY: the SSL is live and its handshake completed. A permissive
        // verification callback can allow completion while retaining a failure result.
        let verification = unsafe { ffi::SSL_get_verify_result(self.ssl.as_ptr()) };
        if verification != c_long::from(ffi::X509_V_OK) {
            return Err(ClientSessionError::PeerVerificationFailed);
        }
        // SAFETY: the SSL is live and its handshake completed.
        if unsafe { ffi::SSL_session_reused(self.ssl.as_ptr()) } != 0 && !self.offered_session {
            return Err(ClientSessionError::ResumptionAttempted);
        }
        // SAFETY: the SSL is live and its handshake completed.
        if unsafe { ffi::SSL_in_early_data(self.ssl.as_ptr()) } != 0 {
            return Err(ClientSessionError::EarlyDataActive);
        }
        let mut protocol = ptr::null();
        let mut protocol_len = 0;
        // SAFETY: output pointers are valid and the selected ALPN is SSL-owned.
        unsafe {
            ffi::SSL_get0_alpn_selected(self.ssl.as_ptr(), &mut protocol, &mut protocol_len);
        }
        if protocol.is_null() || protocol_len as usize != H3_PROTOCOL.len() {
            return Err(ClientSessionError::AlpnNotNegotiated);
        }
        // SAFETY: BoringSSL returned `protocol_len` readable SSL-owned bytes.
        if unsafe { slice::from_raw_parts(protocol, protocol_len as usize) } != H3_PROTOCOL {
            return Err(ClientSessionError::AlpnNotNegotiated);
        }
        Ok(())
    }

    fn callback_error(&self) -> Result<(), ClientSessionError> {
        match self.callbacks.terminal_error() {
            Some(error) => Err(ClientSessionError::Callback(error)),
            None => Ok(()),
        }
    }

    fn operation_failure(
        &self,
        operation: &'static str,
        ssl_error: Option<i32>,
    ) -> ClientSessionError {
        if let Some(error) = self.callbacks.terminal_error() {
            drain_error_queue();
            return ClientSessionError::Callback(error);
        }
        drain_error_queue();
        match ssl_error {
            Some(ssl_error) => ClientSessionError::TlsFailure {
                operation,
                ssl_error,
            },
            None => ClientSessionError::BackendFailure(operation),
        }
    }
}

fn apply_tls_profile(
    ssl: &mut OwnedSsl,
    profile: &ClientTlsProfile,
) -> Result<(), ClientSessionError> {
    // SAFETY: `ssl` uniquely owns a live allocation for this entire borrow.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl.as_ptr()) };
    if let Some(key_shares) = profile.key_shares() {
        ssl.set_client_key_shares(key_shares)
            .map_err(|_| backend_failure("client key shares"))?;
    }
    ssl.set_enable_ech_grease(profile.ech_grease());
    if let Some(payload_length) = profile.ech_grease_payload_length() {
        ssl.set_ech_grease_payload_length(usize::from(payload_length))
            .map_err(|_| backend_failure("ECH GREASE payload length"))?;
    }
    if !profile.ech_grease_aeads().is_empty() {
        ssl.set_ech_grease_aeads(profile.ech_grease_aeads())
            .map_err(|_| backend_failure("ECH GREASE AEADs"))?;
    }
    if let Some(alps) = profile.alps() {
        ssl.add_application_settings_with_payload(&alps.protocol, &alps.settings)
            .map_err(|_| backend_failure("ALPS configuration"))?;
        ssl.set_alps_use_new_codepoint(alps.use_new_codepoint);
    }
    Ok(())
}

fn apply_server_name(ssl: &mut OwnedSsl, server_name: &str) -> Result<(), ClientSessionError> {
    // SAFETY: `ssl` uniquely owns a live allocation for this entire borrow.
    let ssl = unsafe { SslRef::from_ptr_mut(ssl.as_ptr()) };
    let ip = server_name.parse::<IpAddr>().ok();
    if ip.is_none() {
        ssl.set_hostname(server_name)
            .map_err(|_| backend_failure("server name indication"))?;
    }

    let verification = ssl.param_mut();
    verification.set_hostflags(X509CheckFlags::NO_PARTIAL_WILDCARDS);
    match ip {
        Some(ip) => verification.set_ip(ip),
        None => verification.set_host(server_name),
    }
    .map_err(|_| backend_failure("verification server name"))
}

fn raw_level(level: EncryptionLevel) -> ffi::ssl_encryption_level_t {
    match level {
        EncryptionLevel::Initial => ffi::ssl_encryption_level_t::ssl_encryption_initial,
        EncryptionLevel::Handshake => ffi::ssl_encryption_level_t::ssl_encryption_handshake,
        EncryptionLevel::Application => ffi::ssl_encryption_level_t::ssl_encryption_application,
    }
}

fn encryption_level(level: ffi::ssl_encryption_level_t) -> Result<EncryptionLevel, CallbackError> {
    match level {
        ffi::ssl_encryption_level_t::ssl_encryption_initial => Ok(EncryptionLevel::Initial),
        ffi::ssl_encryption_level_t::ssl_encryption_handshake => Ok(EncryptionLevel::Handshake),
        ffi::ssl_encryption_level_t::ssl_encryption_application => Ok(EncryptionLevel::Application),
        _ => Err(CallbackError::UnsupportedEncryptionLevel {
            raw: i64::from(level.0),
        }),
    }
}

fn backend_failure(operation: &'static str) -> ClientSessionError {
    drain_error_queue();
    ClientSessionError::BackendFailure(operation)
}

#[cfg(test)]
mod tests;
