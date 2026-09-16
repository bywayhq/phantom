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
    assert_eq!(
        unsafe { add_handshake_data(test_ssl.ssl().as_ptr(), initial, ptr::null(), 0) },
        1
    );
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
    assert_eq!(
        unsafe { add_handshake_data(test_ssl.ssl().as_ptr(), initial, ptr::null(), 1) },
        0
    );

    assert_eq!(
        state.terminal_error(),
        Some(CallbackError::NullInput {
            input: "handshake data",
            len: 1,
        })
    );
}

#[test]
fn early_data_secret_is_rejected_before_pointer_access() {
    let test_ssl = TestSsl::client();
    let state = install(&test_ssl);
    let early = ffi::ssl_encryption_level_t::ssl_encryption_early_data;

    // SAFETY: invalid pointers are not read because early data is rejected first.
    assert_eq!(
        unsafe { set_write_secret(test_ssl.ssl().as_ptr(), early, ptr::null(), ptr::null(), 0) },
        0
    );

    assert_eq!(
        state.terminal_error(),
        Some(CallbackError::EarlyDataUnsupported)
    );
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
    assert_eq!(
        unsafe { set_read_secret(null_ssl.ssl().as_ptr(), level, cipher, ptr::null(), 32,) },
        0
    );
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
    assert_eq!(
        unsafe { set_read_secret(short_ssl.ssl().as_ptr(), level, cipher, invalid, 31) },
        0
    );
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
    assert_eq!(
        unsafe {
            set_read_secret(
                cipher_ssl.ssl().as_ptr(),
                level,
                ptr::null(),
                secret.as_ptr(),
                secret.len(),
            )
        },
        0
    );
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
    assert_eq!(
        unsafe {
            add_handshake_data(
                test_ssl.ssl().as_ptr(),
                invalid_level,
                NonNull::<u8>::dangling().as_ptr(),
                1,
            )
        },
        0
    );
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
    assert_eq!(
        unsafe {
            set_write_secret(
                test_ssl.ssl().as_ptr(),
                level,
                cipher,
                local.as_ptr(),
                local.len(),
            )
        },
        1
    );
    // SAFETY: all callback inputs remain live for each call.
    assert_eq!(
        unsafe {
            set_read_secret(
                test_ssl.ssl().as_ptr(),
                level,
                cipher,
                remote.as_ptr(),
                remote.len(),
            )
        },
        1
    );

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
    assert_eq!(
        unsafe {
            ffi::SSL_set_quic_transport_params(
                ssl.as_ptr(),
                transport_parameters.as_ptr(),
                transport_parameters.len(),
            )
        },
        1
    );
    // SAFETY: pointers reference live storage for this call.
    assert_eq!(
        unsafe { ffi::SSL_set_alpn_protos(ssl.as_ptr(), alpn.as_ptr(), alpn.len()) },
        0
    );
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
