use std::ffi::{CString, c_int, c_uint, c_void};
use std::fmt::Debug;
#[cfg(feature = "keylog")]
use std::num::NonZeroUsize;
use std::ptr::{self, NonNull};
use std::slice;

use btls::ssl::{SslContext, SslMethod, SslVerifyMode};
use btls_sys as ffi;
use foreign_types::ForeignType;

use super::super::{
    ClientSession, ClientSessionError, H3_PROTOCOL, HandshakeProgress, OwnedSsl, encryption_level,
    raw_level,
};
use crate::backend::callback_state::{
    CallbackState, EncryptionLevel, FlightLimits, HandshakeChunk,
};
use crate::backend::drain_error_queue;
use crate::backend::quic_callbacks::install_on_ssl;
#[cfg(feature = "keylog")]
use crate::{NssKeyLogReceiver, configure_nss_key_log};

pub(super) const CLIENT_PARAMETERS: &[u8] = &[0x01, 0x01, 0x00];
pub(super) const SERVER_PARAMETERS: &[u8] =
    &[0x03, 0x02, 0x44, 0xb0, 0x0f, 0x01, 0x02, 0x00, 0x01, 0x01];
pub(super) const SERVER_NAME: &str = "foobar.com";

pub(super) fn test_ok<T, E: Debug>(result: Result<T, E>, operation: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{operation} failed: {error:?}"),
    }
}

pub(super) fn test_some<T>(value: Option<T>, operation: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{operation} returned no value"),
    }
}

pub(super) struct OwnedContext(pub(super) SslContext);

impl OwnedContext {
    pub(super) fn new() -> Self {
        let context = SslContext::builder(SslMethod::tls())
            .unwrap_or_else(|error| panic!("test context allocation failed: {error}"))
            .build();
        Self(context)
    }

    pub(super) fn as_context(&self) -> &SslContext {
        &self.0
    }

    pub(super) fn as_ptr(&self) -> *mut ffi::SSL_CTX {
        self.0.as_ptr()
    }
}

pub(super) struct RawServer {
    ssl: OwnedSsl,
    callbacks: CallbackState,
    handshake_complete: bool,
}

impl RawServer {
    pub(super) fn new(context: &OwnedContext) -> Result<Self, ClientSessionError> {
        // SAFETY: `context` is live for the call and SSL_new retains it.
        let ssl = unsafe {
            OwnedSsl::new(
                NonNull::new(context.as_ptr())
                    .ok_or(ClientSessionError::BackendFailure("test context pointer"))?,
            )
        }?;
        let pointer = ssl.as_ptr();
        // SAFETY: `pointer` is live and uniquely owned.
        if unsafe { ffi::SSL_set_min_proto_version(pointer, ffi::TLS1_3_VERSION as u16) } != 1 {
            return Err(ClientSessionError::BackendFailure("server minimum version"));
        }
        // SAFETY: `pointer` is live and uniquely owned.
        if unsafe { ffi::SSL_set_max_proto_version(pointer, ffi::TLS1_3_VERSION as u16) } != 1 {
            return Err(ClientSessionError::BackendFailure("server maximum version"));
        }
        // SAFETY: the SSL has not started a handshake.
        unsafe {
            ffi::SSL_set_early_data_enabled(pointer, 0);
        }
        // SAFETY: the parameters are copied by the setter.
        if unsafe {
            ffi::SSL_set_quic_transport_params(
                pointer,
                SERVER_PARAMETERS.as_ptr(),
                SERVER_PARAMETERS.len(),
            )
        } != 1
        {
            return Err(ClientSessionError::BackendFailure(
                "server transport parameters",
            ));
        }
        // SAFETY: the SSL is live and has not started a handshake.
        unsafe {
            ffi::SSL_set_accept_state(pointer);
        }
        // SAFETY: the SSL is live, unique, and has not started its handshake.
        let callbacks = unsafe { install_on_ssl(ssl.0, FlightLimits::default()) }
            .map_err(ClientSessionError::CallbackInstall)?;
        Ok(Self {
            ssl,
            callbacks,
            handshake_complete: false,
        })
    }

    pub(super) fn provide(&mut self, chunk: &HandshakeChunk) -> Result<(), ClientSessionError> {
        self.provide_bytes(chunk.level, &chunk.bytes)
    }

    pub(super) fn provide_current_level(&mut self, data: &[u8]) -> Result<(), ClientSessionError> {
        // SAFETY: the SSL is live and configured with the QUIC method.
        let level = unsafe { ffi::SSL_quic_read_level(self.ssl.as_ptr()) };
        let level = encryption_level(level).map_err(ClientSessionError::Callback)?;
        self.provide_bytes(level, data)
    }

    fn provide_bytes(
        &mut self,
        level: EncryptionLevel,
        data: &[u8],
    ) -> Result<(), ClientSessionError> {
        // SAFETY: the SSL and data remain live for the copying call.
        if unsafe {
            ffi::SSL_provide_quic_data(
                self.ssl.as_ptr(),
                raw_level(level),
                data.as_ptr(),
                data.len(),
            )
        } != 1
        {
            return Err(self.failure("server input", None));
        }
        Ok(())
    }

    pub(super) fn export(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> Result<(), ClientSessionError> {
        // SAFETY: the SSL and all borrowed buffers remain live for the call.
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
            Err(self.failure("server keying material export", None))
        }
    }

    pub(super) fn drive(&mut self) -> Result<HandshakeProgress, ClientSessionError> {
        if self.handshake_complete {
            return Ok(HandshakeProgress::Complete);
        }
        if let Some(error) = self.callbacks.terminal_error() {
            return Err(ClientSessionError::Callback(error));
        }
        // SAFETY: the SSL is a live QUIC server session.
        let result = unsafe { ffi::SSL_do_handshake(self.ssl.as_ptr()) };
        if result == 1 {
            self.handshake_complete = true;
            return Ok(HandshakeProgress::Complete);
        }
        // SAFETY: `result` is from the immediately preceding operation.
        let ssl_error = unsafe { ffi::SSL_get_error(self.ssl.as_ptr(), result) };
        if result == -1 && ssl_error == ffi::SSL_ERROR_WANT_READ {
            drain_error_queue();
            Ok(HandshakeProgress::NeedsData)
        } else {
            Err(self.failure("server handshake", Some(ssl_error)))
        }
    }

    pub(super) fn drain_output(&self) -> Result<Vec<HandshakeChunk>, ClientSessionError> {
        self.callbacks
            .drain_handshake()
            .map_err(ClientSessionError::Callback)
    }

    fn failure(&self, operation: &'static str, ssl_error: Option<i32>) -> ClientSessionError {
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

unsafe extern "C" fn select_h3(
    _ssl: *mut ffi::SSL,
    out: *mut *const u8,
    out_len: *mut u8,
    input: *const u8,
    input_len: c_uint,
    _argument: *mut c_void,
) -> c_int {
    if out.is_null() || out_len.is_null() || input.is_null() {
        return ffi::SSL_TLSEXT_ERR_NOACK;
    }
    // SAFETY: BoringSSL lends `input_len` bytes for this callback.
    let protocols = unsafe { slice::from_raw_parts(input, input_len as usize) };
    let mut offset = 0;
    while offset < protocols.len() {
        let len = usize::from(protocols[offset]);
        offset += 1;
        let Some(end) = offset.checked_add(len) else {
            return ffi::SSL_TLSEXT_ERR_NOACK;
        };
        if end > protocols.len() {
            return ffi::SSL_TLSEXT_ERR_NOACK;
        }
        if &protocols[offset..end] == H3_PROTOCOL {
            // SAFETY: outputs are non-null and H3_PROTOCOL has process lifetime.
            unsafe {
                *out = H3_PROTOCOL.as_ptr();
                *out_len = H3_PROTOCOL.len() as u8;
            }
            return ffi::SSL_TLSEXT_ERR_OK;
        }
        offset = end;
    }
    ffi::SSL_TLSEXT_ERR_NOACK
}

unsafe extern "C" fn select_h2(
    _ssl: *mut ffi::SSL,
    out: *mut *const u8,
    out_len: *mut u8,
    _input: *const u8,
    _input_len: c_uint,
    _argument: *mut c_void,
) -> c_int {
    const H2: &[u8] = b"h2";
    if out.is_null() || out_len.is_null() {
        return ffi::SSL_TLSEXT_ERR_NOACK;
    }
    // SAFETY: outputs are non-null and H2 has process lifetime.
    unsafe {
        *out = H2.as_ptr();
        *out_len = H2.len() as u8;
    }
    ffi::SSL_TLSEXT_ERR_OK
}

fn certificate_path(file: &str) -> CString {
    let path = CString::new(format!(
        "{}/../../vendor/btls/test/{file}",
        env!("CARGO_MANIFEST_DIR")
    ));
    test_ok(path, "test certificate path")
}

pub(super) fn client_context(verify_peer: bool) -> OwnedContext {
    let context = OwnedContext::new();
    if verify_peer {
        configure_client_verification(&context);
    }
    context
}

#[cfg(feature = "keylog")]
pub(super) fn client_context_with_key_log(
    capacity: NonZeroUsize,
) -> (OwnedContext, NssKeyLogReceiver) {
    let mut builder = SslContext::builder(SslMethod::tls())
        .unwrap_or_else(|error| panic!("test context allocation failed: {error}"));
    let receiver = configure_nss_key_log(&mut builder, capacity);
    let context = OwnedContext(builder.build());
    configure_client_verification(&context);
    (context, receiver)
}

fn configure_client_verification(context: &OwnedContext) {
    // SAFETY: the context is live and no SSL has been created from it.
    unsafe {
        ffi::SSL_CTX_set_verify(context.as_ptr(), ffi::SSL_VERIFY_PEER, None);
    }
    let root = certificate_path("root-ca.pem");
    // SAFETY: the path is NUL-terminated and remains live for the call.
    let status =
        unsafe { ffi::SSL_CTX_load_verify_locations(context.as_ptr(), root.as_ptr(), ptr::null()) };
    assert_eq!(status, 1);
}

pub(super) fn untrusted_client_context() -> OwnedContext {
    let context = OwnedContext::new();
    // SAFETY: the context is live and no SSL has been created from it.
    unsafe {
        ffi::SSL_CTX_set_verify(context.as_ptr(), ffi::SSL_VERIFY_PEER, None);
    }
    context
}

pub(super) fn permissive_untrusted_client_context() -> OwnedContext {
    let mut context = SslContext::builder(SslMethod::tls())
        .unwrap_or_else(|error| panic!("test context allocation failed: {error}"));
    context.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
    OwnedContext(context.build())
}

pub(super) fn server_context() -> OwnedContext {
    let context = OwnedContext::new();
    let certificate = certificate_path("cert.pem");
    let key = certificate_path("key.pem");
    // SAFETY: paths are NUL-terminated and remain live for each call.
    unsafe {
        assert_eq!(
            ffi::SSL_CTX_use_certificate_chain_file(context.as_ptr(), certificate.as_ptr()),
            1
        );
        assert_eq!(
            ffi::SSL_CTX_use_PrivateKey_file(context.as_ptr(), key.as_ptr(), ffi::SSL_FILETYPE_PEM,),
            1
        );
        assert_eq!(ffi::SSL_CTX_check_private_key(context.as_ptr()), 1);
        assert_eq!(ffi::SSL_CTX_set_num_tickets(context.as_ptr(), 1), 1);
        ffi::SSL_CTX_set_alpn_select_cb(context.as_ptr(), Some(select_h3), ptr::null_mut());
    }
    context
}

pub(super) fn server_context_with_wrong_alpn() -> OwnedContext {
    let context = server_context();
    // SAFETY: the context is live and the callback has process lifetime.
    unsafe {
        ffi::SSL_CTX_set_alpn_select_cb(context.as_ptr(), Some(select_h2), ptr::null_mut());
    }
    context
}

pub(super) fn session(context: &OwnedContext) -> ClientSession {
    let client = ClientSession::new(context.as_context(), SERVER_NAME, CLIENT_PARAMETERS);
    test_ok(client, "client session")
}
