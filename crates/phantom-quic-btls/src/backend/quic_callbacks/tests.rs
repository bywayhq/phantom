use super::*;

struct TestSsl {
    context: NonNull<ffi::SSL_CTX>,
    ssl: Option<NonNull<ffi::SSL>>,
}

impl TestSsl {
    fn client() -> Self {
        ffi::init();
        // SAFETY: the returned context is uniquely owned by this test helper.
        let context = unsafe { ffi::SSL_CTX_new(ffi::TLS_method()) };
        let Some(context) = NonNull::new(context) else {
            panic!("SSL_CTX_new failed");
        };
        // SAFETY: `context` is live and uniquely borrowed here.
        let min_status = unsafe {
            ffi::SSL_CTX_set_min_proto_version(context.as_ptr(), ffi::TLS1_3_VERSION as u16)
        };
        // SAFETY: `context` is live and uniquely borrowed here.
        let max_status = unsafe {
            ffi::SSL_CTX_set_max_proto_version(context.as_ptr(), ffi::TLS1_3_VERSION as u16)
        };
        assert_eq!(min_status, 1);
        assert_eq!(max_status, 1);
        // SAFETY: `context` remains live for the SSL allocation.
        let ssl = unsafe { ffi::SSL_new(context.as_ptr()) };
        let Some(ssl) = NonNull::new(ssl) else {
            // SAFETY: the SSL allocation failed, so only the context needs release.
            unsafe {
                ffi::SSL_CTX_free(context.as_ptr());
            }
            panic!("SSL_new failed");
        };
        // SAFETY: the SSL handle is live and uniquely borrowed here.
        unsafe {
            ffi::SSL_set_connect_state(ssl.as_ptr());
        }
        Self {
            context,
            ssl: Some(ssl),
        }
    }

    fn ssl(&self) -> NonNull<ffi::SSL> {
        match self.ssl {
            Some(ssl) => ssl,
            None => panic!("SSL already freed"),
        }
    }

    fn free_ssl(&mut self) {
        if let Some(ssl) = self.ssl.take() {
            // SAFETY: the optional owner releases each SSL allocation once.
            unsafe {
                ffi::SSL_free(ssl.as_ptr());
            }
        }
    }
}

impl Drop for TestSsl {
    fn drop(&mut self) {
        self.free_ssl();
        // SAFETY: the helper owns one live context allocation.
        unsafe {
            ffi::SSL_CTX_free(self.context.as_ptr());
        }
    }
}

fn install(test_ssl: &TestSsl) -> CallbackState {
    // SAFETY: the test helper owns a live SSL before handshake start.
    match unsafe { install_on_ssl(test_ssl.ssl(), FlightLimits::default()) } {
        Ok(state) => state,
        Err(error) => panic!("callback installation failed: {error:?}"),
    }
}

#[test]
fn static_method_defines_every_callback() {
    assert!(QUIC_METHOD.set_read_secret.is_some());
    assert!(QUIC_METHOD.set_write_secret.is_some());
    assert!(QUIC_METHOD.add_handshake_data.is_some());
    assert!(QUIC_METHOD.flush_flight.is_some());
    assert!(QUIC_METHOD.send_alert.is_some());
}

#[test]
fn null_ssl_is_rejected_by_every_callback() {
    let initial = ffi::ssl_encryption_level_t::ssl_encryption_initial;
    // SAFETY: null inputs exercise callback rejection paths without dereference.
    unsafe {
        assert_eq!(
            set_read_secret(ptr::null_mut(), initial, ptr::null(), ptr::null(), 0),
            0
        );
        assert_eq!(
            set_write_secret(ptr::null_mut(), initial, ptr::null(), ptr::null(), 0),
            0
        );
        assert_eq!(
            add_handshake_data(ptr::null_mut(), initial, ptr::null(), 0),
            0
        );
        assert_eq!(flush_flight(ptr::null_mut()), 0);
        assert_eq!(send_alert(ptr::null_mut(), initial, 1), 0);
    }
}

#[test]
fn null_empty_handshake_data_is_published_only_after_flush() {
    let test_ssl = TestSsl::client();
    let state = install(&test_ssl);
    let initial = ffi::ssl_encryption_level_t::ssl_encryption_initial;

    // SAFETY: the SSL has installed callbacks and null is valid for an empty fragment.
    let status = unsafe { add_handshake_data(test_ssl.ssl().as_ptr(), initial, ptr::null(), 0) };
    assert_eq!(status, 1);
    assert!(
        state
            .drain_handshake()
            .is_ok_and(|chunks| chunks.is_empty())
    );
    // SAFETY: the SSL has installed callbacks.
    assert_eq!(unsafe { flush_flight(test_ssl.ssl().as_ptr()) }, 1);
    let chunks = match state.drain_handshake() {
        Ok(chunks) => chunks,
        Err(error) => panic!("unexpected callback error: {error:?}"),
    };
    assert_eq!(chunks.len(), 1);
    assert!(chunks[0].bytes.is_empty());
}

#[test]
fn null_nonempty_handshake_data_is_terminal() {
    let test_ssl = TestSsl::client();
    let state = install(&test_ssl);
    let initial = ffi::ssl_encryption_level_t::ssl_encryption_initial;

    // SAFETY: null with a nonzero length exercises validation without dereference.
    let status = unsafe { add_handshake_data(test_ssl.ssl().as_ptr(), initial, ptr::null(), 1) };
    assert_eq!(status, 0);

    assert_eq!(
        state.terminal_error(),
        Some(CallbackError::NullInput {
            input: "handshake data",
            len: 1,
        })
    );
}

#[test]
fn early_data_read_secret_is_rejected_before_pointer_access() {
    let test_ssl = TestSsl::client();
    let state = install(&test_ssl);
    let early = ffi::ssl_encryption_level_t::ssl_encryption_early_data;

    // SAFETY: invalid pointers are not read because a client never reads 0-RTT.
    let status =
        unsafe { set_read_secret(test_ssl.ssl().as_ptr(), early, ptr::null(), ptr::null(), 0) };
    assert_eq!(status, 0);

    assert_eq!(
        state.terminal_error(),
        Some(CallbackError::EarlyDataUnsupported)
    );
}

#[test]
fn early_data_write_secret_is_stored_once() {
    let test_ssl = TestSsl::client();
    let state = install(&test_ssl);
    let early = ffi::ssl_encryption_level_t::ssl_encryption_early_data;
    // SAFETY: the cipher descriptor has process lifetime.
    let cipher = unsafe { ffi::SSL_get_cipher_by_value(0x1301) };
    assert!(!cipher.is_null());
    let secret = [5; 32];

    // SAFETY: all callback inputs remain live for the call.
    let status = unsafe {
        set_write_secret(
            test_ssl.ssl().as_ptr(),
            early,
            cipher,
            secret.as_ptr(),
            secret.len(),
        )
    };
    assert_eq!(status, 1);
    assert_eq!(state.terminal_error(), None);

    // SAFETY: all callback inputs remain live for the call.
    let duplicate = unsafe {
        set_write_secret(
            test_ssl.ssl().as_ptr(),
            early,
            cipher,
            secret.as_ptr(),
            secret.len(),
        )
    };
    assert_eq!(duplicate, 0);
    assert_eq!(
        state.terminal_error(),
        Some(CallbackError::DuplicateEarlySecret)
    );
    let (suite, stored) = state
        .take_early_secret()
        .unwrap_or_else(|| panic!("the 0-RTT secret was not stored"));
    assert_eq!(suite, 0x1301);
    assert_eq!(stored.as_slice(), &secret);
    assert!(state.take_early_secret().is_none());
}

#[test]
fn invalid_secret_pointer_shapes_are_rejected_before_copy() {
    // SAFETY: the cipher descriptor has process lifetime.
    let cipher = unsafe { ffi::SSL_get_cipher_by_value(0x1301) };
    assert!(!cipher.is_null());
    let level = ffi::ssl_encryption_level_t::ssl_encryption_handshake;

    let null_ssl = TestSsl::client();
    let null_state = install(&null_ssl);
    // SAFETY: null exercises validation and is not dereferenced.
    let status =
        unsafe { set_read_secret(null_ssl.ssl().as_ptr(), level, cipher, ptr::null(), 32) };
    assert_eq!(status, 0);
    assert_eq!(
        null_state.terminal_error(),
        Some(CallbackError::NullInput {
            input: "secret",
            len: 32,
        })
    );

    let short_ssl = TestSsl::client();
    let short_state = install(&short_ssl);
    let invalid = NonNull::<u8>::dangling().as_ptr();
    // SAFETY: the invalid pointer is not read because the length is rejected first.
    let status = unsafe { set_read_secret(short_ssl.ssl().as_ptr(), level, cipher, invalid, 31) };
    assert_eq!(status, 0);
    assert_eq!(
        short_state.terminal_error(),
        Some(CallbackError::InvalidSecretLength {
            actual: 31,
            expected: 32,
        })
    );

    let cipher_ssl = TestSsl::client();
    let cipher_state = install(&cipher_ssl);
    let secret = [0; 32];
    // SAFETY: the secret is live and the null cipher is rejected before use.
    let status = unsafe {
        set_read_secret(
            cipher_ssl.ssl().as_ptr(),
            level,
            ptr::null(),
            secret.as_ptr(),
            secret.len(),
        )
    };
    assert_eq!(status, 0);
    assert_eq!(
        cipher_state.terminal_error(),
        Some(CallbackError::NullCipher)
    );
}

#[test]
fn unknown_level_is_rejected_before_pointer_access() {
    let test_ssl = TestSsl::client();
    let state = install(&test_ssl);
    let invalid_level = ffi::ssl_encryption_level_t(99);

    // SAFETY: the invalid pointer is not read because the level is rejected first.
    let status = unsafe {
        add_handshake_data(
            test_ssl.ssl().as_ptr(),
            invalid_level,
            NonNull::<u8>::dangling().as_ptr(),
            1,
        )
    };
    assert_eq!(status, 0);
    assert_eq!(
        state.terminal_error(),
        Some(CallbackError::UnsupportedEncryptionLevel { raw: 99 })
    );
}

#[test]
fn read_and_write_callbacks_map_remote_and_local_secrets() {
    let test_ssl = TestSsl::client();
    let state = install(&test_ssl);
    let level = ffi::ssl_encryption_level_t::ssl_encryption_application;
    // SAFETY: the cipher descriptor has process lifetime.
    let cipher = unsafe { ffi::SSL_get_cipher_by_value(0x1301) };
    assert!(!cipher.is_null());
    let local = [3; 32];
    let remote = [7; 32];

    // SAFETY: all callback inputs remain live for each call.
    let write_status = unsafe {
        set_write_secret(
            test_ssl.ssl().as_ptr(),
            level,
            cipher,
            local.as_ptr(),
            local.len(),
        )
    };
    assert_eq!(write_status, 1);
    // SAFETY: all callback inputs remain live for each call.
    let read_status = unsafe {
        set_read_secret(
            test_ssl.ssl().as_ptr(),
            level,
            cipher,
            remote.as_ptr(),
            remote.len(),
        )
    };
    assert_eq!(read_status, 1);

    assert!(state.secret_matches(EncryptionLevel::Application, SecretDirection::Local, &local));
    assert!(state.secret_matches(
        EncryptionLevel::Application,
        SecretDirection::Remote,
        &remote
    ));
}

#[test]
fn panic_is_contained_and_recorded() {
    let state = CallbackState::new(FlightLimits::default());

    let status = callback_outcome(&state, || panic!("callback test panic"));

    assert_eq!(status, 0);
    assert_eq!(
        state.terminal_error(),
        Some(CallbackError::CallbackPanicked)
    );
}

#[test]
fn ssl_destruction_releases_ex_data_owner() {
    let mut test_ssl = TestSsl::client();
    let state = install(&test_ssl);
    assert_eq!(state.owner_count(), 2);

    test_ssl.free_ssl();

    assert_eq!(state.owner_count(), 1);
}

#[test]
fn no_bio_client_handshake_publishes_client_hello_after_flush() {
    let test_ssl = TestSsl::client();
    let ssl = test_ssl.ssl();
    let state = install(&test_ssl);
    let transport_parameters = [0x01, 0x01, 0x00];
    let alpn = [2, b'h', b'3'];
    // SAFETY: pointers reference live storage for this call.
    let transport_status = unsafe {
        ffi::SSL_set_quic_transport_params(
            ssl.as_ptr(),
            transport_parameters.as_ptr(),
            transport_parameters.len(),
        )
    };
    assert_eq!(transport_status, 1);
    // SAFETY: pointers reference live storage for this call.
    let alpn_status = unsafe { ffi::SSL_set_alpn_protos(ssl.as_ptr(), alpn.as_ptr(), alpn.len()) };
    assert_eq!(alpn_status, 0);
    // SAFETY: the SSL handle is live.
    unsafe {
        assert!(ffi::SSL_get_rbio(ssl.as_ptr()).is_null());
        assert!(ffi::SSL_get_wbio(ssl.as_ptr()).is_null());
    }
    assert!(
        state
            .drain_handshake()
            .is_ok_and(|chunks| chunks.is_empty())
    );
    assert_eq!(state.completed_flushes(), 0);

    // SAFETY: the SSL handle is live, configured as a no-BIO QUIC client.
    let status = unsafe { ffi::SSL_do_handshake(ssl.as_ptr()) };
    // SAFETY: `status` is the immediately preceding result for this SSL.
    let error = unsafe { ffi::SSL_get_error(ssl.as_ptr(), status) };
    assert_eq!(
        error,
        ffi::SSL_ERROR_WANT_READ,
        "callback error: {:?}",
        state.terminal_error()
    );
    assert!(state.completed_flushes() > 0);
    let chunks = match state.drain_handshake() {
        Ok(chunks) => chunks,
        Err(error) => panic!("unexpected callback error: {error:?}"),
    };
    assert!(!chunks.is_empty());
    assert_eq!(chunks[0].level, EncryptionLevel::Initial);
    assert_eq!(chunks[0].bytes.first(), Some(&1));
}

/// Allocates an empty session owned by the caller.
fn new_session(test_ssl: &TestSsl) -> NonNull<ffi::SSL_SESSION> {
    // SAFETY: the context is live; the returned reference belongs to the caller.
    let session = unsafe { ffi::SSL_SESSION_new(test_ssl.context.as_ptr()) };
    match NonNull::new(session) {
        Some(session) => session,
        None => panic!("SSL_SESSION_new failed"),
    }
}

#[test]
fn session_callback_declines_without_taking_the_reference() {
    let test_ssl = TestSsl::client();
    let session = new_session(&test_ssl);

    // SAFETY: both handles are live. An SSL without callback state makes the
    // callback return 0, which leaves the reference with the caller.
    let status = unsafe { deliver_new_session(test_ssl.ssl().as_ptr(), session.as_ptr()) };
    assert_eq!(status, 0);
    // SAFETY: as above; a null SSL yields no callback state either.
    let status = unsafe { deliver_new_session(ptr::null_mut(), session.as_ptr()) };
    assert_eq!(status, 0);
    // SAFETY: a null session is rejected before the SSL is read.
    let status = unsafe { deliver_new_session(test_ssl.ssl().as_ptr(), ptr::null_mut()) };
    assert_eq!(status, 0);

    // SAFETY: the callback declined, so this test still owns the one
    // reference. Had the callback released it, AddressSanitizer would report
    // this use and the release after it.
    let session = unsafe { SslSession::from_ptr(session.as_ptr()) };
    assert!(session.time() > 0);
}

#[test]
fn session_callback_takes_the_reference_it_accepts() {
    let test_ssl = TestSsl::client();
    let state = install(&test_ssl);
    let session = new_session(&test_ssl);

    // SAFETY: both handles are live; returning 1 transfers the reference.
    let status = unsafe { deliver_new_session(test_ssl.ssl().as_ptr(), session.as_ptr()) };
    assert_eq!(status, 1);
    let delivered = state.take_sessions();
    assert_eq!(delivered.len(), 1);
    assert_eq!(delivered[0].as_ptr(), session.as_ptr());
}

fn context_builder() -> SslContextBuilder {
    match SslContextBuilder::new(btls::ssl::SslMethod::tls()) {
        Ok(builder) => builder,
        Err(error) => panic!("context allocation failed: {error}"),
    }
}

#[test]
fn session_delivery_reports_who_owns_the_callback_slot() {
    let mut builder = context_builder();
    assert_eq!(enable_session_delivery(&mut builder), Ok(()));
    // Preparing twice keeps the same callback.
    assert_eq!(enable_session_delivery(&mut builder), Ok(()));
    assert_eq!(session_delivery(&builder.build()), SessionDelivery::Quic);

    assert_eq!(
        session_delivery(&context_builder().build()),
        SessionDelivery::Off
    );

    let mut caching_off = context_builder();
    assert_eq!(enable_session_delivery(&mut caching_off), Ok(()));
    caching_off.set_session_cache_mode(SslSessionCacheMode::OFF);
    assert_eq!(session_delivery(&caching_off.build()), SessionDelivery::Off);
}

#[test]
fn session_delivery_refuses_a_foreign_callback_and_changes_nothing() {
    let mut builder = context_builder();
    builder.set_new_session_callback(|_, _| {});
    let mode = builder.set_session_cache_mode(SslSessionCacheMode::SERVER);
    assert_eq!(mode, SslSessionCacheMode::SERVER);

    assert_eq!(
        enable_session_delivery(&mut builder),
        Err(SessionDelivery::Foreign)
    );
    assert_eq!(
        builder.set_session_cache_mode(SslSessionCacheMode::SERVER),
        SslSessionCacheMode::SERVER
    );
    assert_eq!(session_delivery(&builder.build()), SessionDelivery::Foreign);

    // A callback installed over a prepared builder is foreign too.
    let mut replaced = context_builder();
    assert_eq!(enable_session_delivery(&mut replaced), Ok(()));
    replaced.set_new_session_callback(|_, _| {});
    assert_eq!(
        session_delivery(&replaced.build()),
        SessionDelivery::Foreign
    );
}
