use std::ffi::{CString, c_int, c_uint, c_void};
use std::fmt::Debug;
use std::ptr::{self, NonNull};
use std::slice;

use btls_sys as ffi;

use super::{
    ClientSession, ClientSessionError, H3_PROTOCOL, HandshakeProgress, OwnedSsl, encryption_level,
    raw_level,
};
use crate::backend::callback_state::{
    CallbackError, CallbackState, EncryptionLevel, FlightLimits, HandshakeChunk,
};
use crate::backend::drain_error_queue;
use crate::backend::quic_callbacks::install_on_ssl;

const CLIENT_PARAMETERS: &[u8] = &[0x01, 0x01, 0x00];
const SERVER_PARAMETERS: &[u8] = &[0x03, 0x02, 0x44, 0x00];
const SERVER_NAME: &str = "foobar.com";

fn test_ok<T, E: Debug>(result: Result<T, E>, operation: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{operation} failed: {error:?}"),
    }
}

fn test_some<T>(value: Option<T>, operation: &str) -> T {
    match value {
        Some(value) => value,
        None => panic!("{operation} returned no value"),
    }
}

fn assert_send<T: Send>() {}

struct OwnedContext(NonNull<ffi::SSL_CTX>);

impl OwnedContext {
    fn new() -> Self {
        ffi::init();
        // SAFETY: TLS_method has process lifetime and SSL_CTX_new retains its method.
        let context = unsafe { ffi::SSL_CTX_new(ffi::TLS_method()) };
        let Some(context) = NonNull::new(context) else {
            panic!("test context allocation failed");
        };
        Self(context)
    }

    const fn as_non_null(&self) -> NonNull<ffi::SSL_CTX> {
        self.0
    }

    const fn as_ptr(&self) -> *mut ffi::SSL_CTX {
        self.0.as_ptr()
    }
}

impl Drop for OwnedContext {
    fn drop(&mut self) {
        // SAFETY: this owner releases its context exactly once.
        unsafe {
            ffi::SSL_CTX_free(self.0.as_ptr());
        }
    }
}

struct RawServer {
    ssl: OwnedSsl,
    callbacks: CallbackState,
    handshake_complete: bool,
}

impl RawServer {
    fn new(context: &OwnedContext) -> Result<Self, ClientSessionError> {
        // SAFETY: `context` is live for the call and SSL_new retains it.
        let ssl = unsafe { OwnedSsl::new(context.as_non_null()) }?;
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

    fn provide(&mut self, chunk: &HandshakeChunk) -> Result<(), ClientSessionError> {
        // SAFETY: the SSL and chunk remain live for the copying call.
        if unsafe {
            ffi::SSL_provide_quic_data(
                self.ssl.as_ptr(),
                raw_level(chunk.level),
                chunk.bytes.as_ptr(),
                chunk.bytes.len(),
            )
        } != 1
        {
            return Err(self.failure("server input", None));
        }
        Ok(())
    }

    fn drive(&mut self) -> Result<HandshakeProgress, ClientSessionError> {
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

    fn drain_output(&self) -> Result<Vec<HandshakeChunk>, ClientSessionError> {
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

fn certificate_path(file: &str) -> CString {
    let path = CString::new(format!(
        "{}/../../vendor/btls/test/{file}",
        env!("CARGO_MANIFEST_DIR")
    ));
    test_ok(path, "test certificate path")
}

fn client_context(verify_peer: bool) -> OwnedContext {
    let context = OwnedContext::new();
    if verify_peer {
        // SAFETY: the context is live and no SSL has been created from it.
        unsafe {
            ffi::SSL_CTX_set_verify(context.as_ptr(), ffi::SSL_VERIFY_PEER, None);
        }
        let root = certificate_path("root-ca.pem");
        // SAFETY: the path is NUL-terminated and remains live for the call.
        let status = unsafe {
            ffi::SSL_CTX_load_verify_locations(context.as_ptr(), root.as_ptr(), ptr::null())
        };
        assert_eq!(status, 1);
    }
    context
}

fn server_context() -> OwnedContext {
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

fn session(context: &OwnedContext) -> ClientSession {
    // SAFETY: the context is live for construction and SSL retains it.
    let client =
        unsafe { ClientSession::new(context.as_non_null(), SERVER_NAME, CLIENT_PARAMETERS) };
    test_ok(client, "client session")
}

#[test]
fn initial_client_hello_is_flush_published_without_bio() {
    assert_send::<ClientSession>();
    let context = client_context(true);
    let mut client = session(&context);

    assert!(test_ok(client.drain_output(), "preflight output").is_empty());
    assert_eq!(
        test_ok(client.start_handshake(), "start handshake"),
        HandshakeProgress::NeedsData
    );
    assert!(client.callbacks.completed_flushes() > 0);
    let output = test_ok(client.drain_output(), "client hello");
    assert!(!output.is_empty());
    assert!(
        output
            .iter()
            .all(|chunk| chunk.level == EncryptionLevel::Initial)
    );
    assert_eq!(output[0].bytes.first(), Some(&1));
    // SAFETY: the owned SSL remains live for these read-only queries.
    assert!(unsafe { ffi::SSL_get_rbio(client.ssl.as_ptr()) }.is_null());
    // SAFETY: the owned SSL remains live for this read-only query.
    assert!(unsafe { ffi::SSL_get_wbio(client.ssl.as_ptr()) }.is_null());
}

#[test]
fn drop_releases_ssl_and_callback_owners() {
    let context = client_context(true);
    let client = session(&context);
    let retained = client.callbacks.clone();

    assert_eq!(retained.owner_count(), 3);
    drop(client);
    assert_eq!(retained.owner_count(), 1);
}

#[test]
fn disabled_peer_verification_is_rejected() {
    let context = client_context(false);
    // SAFETY: the context is live for construction.
    let result =
        unsafe { ClientSession::new(context.as_non_null(), SERVER_NAME, CLIENT_PARAMETERS) };
    let error = match result {
        Ok(_) => panic!("verification-disabled session was accepted"),
        Err(error) => error,
    };

    assert_eq!(error, ClientSessionError::PeerVerificationDisabled);
}

#[test]
fn callback_failure_is_reported_before_backend_failure() {
    let context = client_context(true);
    let mut client = session(&context);
    client
        .callbacks
        .record_terminal(CallbackError::CallbackPanicked);

    assert_eq!(
        client.start_handshake(),
        Err(ClientSessionError::Callback(
            CallbackError::CallbackPanicked
        ))
    );
}

#[test]
fn hostname_mismatch_is_reported_as_a_tls_failure() {
    let client_context = client_context(true);
    let server_context = server_context();
    // SAFETY: the context is live for construction and SSL retains it.
    let client = unsafe {
        ClientSession::new(
            client_context.as_non_null(),
            "wrong.example",
            CLIENT_PARAMETERS,
        )
    };
    let mut client = test_ok(client, "mismatched-host client session");
    let mut server = test_ok(RawServer::new(&server_context), "server session");

    assert_eq!(
        test_ok(client.start_handshake(), "client start"),
        HandshakeProgress::NeedsData
    );
    for chunk in test_ok(client.drain_output(), "client hello") {
        test_ok(server.provide(&chunk), "server input");
    }
    assert_eq!(
        test_ok(server.drive(), "server first flight"),
        HandshakeProgress::NeedsData
    );

    let mut failure = None;
    for chunk in test_ok(server.drain_output(), "server output") {
        assert_eq!(
            test_ok(client.incoming_level(), "client inferred input level"),
            chunk.level
        );
        match client.provide_handshake_data(&chunk.bytes) {
            Ok(_) => {}
            Err(error) => {
                failure = Some(error);
                break;
            }
        }
    }
    assert!(matches!(
        failure,
        Some(ClientSessionError::TlsFailure {
            operation: "TLS handshake",
            ..
        })
    ));
}

#[test]
fn fragmented_peer_input_completes_and_copies_transport_parameters() {
    let client_context = client_context(true);
    let server_context = server_context();
    let mut client = session(&client_context);
    let mut server = test_ok(RawServer::new(&server_context), "server session");

    assert_eq!(
        test_ok(client.start_handshake(), "client start"),
        HandshakeProgress::NeedsData
    );
    for chunk in test_ok(client.drain_output(), "client hello") {
        test_ok(server.provide(&chunk), "server input");
    }
    assert_eq!(
        test_ok(server.drive(), "server first flight"),
        HandshakeProgress::NeedsData
    );

    let server_flight = test_ok(server.drain_output(), "server output");
    assert!(!server_flight.is_empty());
    let mut fragments = 0;
    let mut client_progress = HandshakeProgress::NeedsData;
    for chunk in server_flight {
        let midpoint = chunk.bytes.len().div_ceil(2);
        for fragment in chunk.bytes.chunks(midpoint.max(1)) {
            fragments += 1;
            assert_eq!(
                test_ok(client.incoming_level(), "client inferred input level"),
                chunk.level
            );
            client_progress = test_ok(
                client.provide_handshake_data(fragment),
                "fragmented server input",
            );
        }
    }
    assert!(fragments > 1);
    assert_eq!(client_progress, HandshakeProgress::Complete);

    let copied = test_ok(client.peer_transport_parameters(), "peer parameters");
    let mut copied = test_some(copied, "server parameters");
    assert_eq!(copied, SERVER_PARAMETERS);
    copied[0] ^= 0xff;
    assert_eq!(
        test_ok(client.peer_transport_parameters(), "fresh copy"),
        Some(SERVER_PARAMETERS.to_vec())
    );

    let client_finish = test_ok(client.drain_output(), "client finish");
    assert!(!client_finish.is_empty());
    for chunk in client_finish {
        test_ok(server.provide(&chunk), "server finish input");
    }
    assert_eq!(
        test_ok(server.drive(), "server completion"),
        HandshakeProgress::Complete
    );

    let post_handshake = test_ok(server.drain_output(), "server post-handshake output");
    assert!(!post_handshake.is_empty());
    for chunk in post_handshake {
        assert_eq!(chunk.level, EncryptionLevel::Application);
        assert_eq!(
            test_ok(client.incoming_level(), "post-handshake input level"),
            EncryptionLevel::Application
        );
        assert_eq!(
            test_ok(
                client.provide_handshake_data(&chunk.bytes),
                "post-handshake server input"
            ),
            HandshakeProgress::Complete
        );
    }
}

#[test]
fn unsupported_read_levels_are_rejected() {
    for raw in [
        ffi::ssl_encryption_level_t::ssl_encryption_early_data,
        ffi::ssl_encryption_level_t(99),
    ] {
        assert_eq!(
            encryption_level(raw),
            Err(CallbackError::UnsupportedEncryptionLevel { raw: raw.0 })
        );
    }
}
