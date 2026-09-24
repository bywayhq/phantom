use std::alloc::{Layout, alloc};
use std::ffi::{c_int, c_long, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::OnceLock;

use btls::ssl::{SslContextBuilder, SslSession, SslSessionCacheMode};
use btls_sys as ffi;
use foreign_types::ForeignType;

use super::callback_state::{
    Alert, CallbackError, CallbackState, EncryptionLevel, FlightLimits, SecretDirection,
};
use super::drain_error_queue;
use crate::key_schedule::CipherSuite;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CallbackInstallError {
    ExDataIndexAllocation,
    StateAllocation,
    AlreadyInstalled,
    MethodInstallation,
    StateInstallation,
}

pub(super) static QUIC_METHOD: ffi::SSL_QUIC_METHOD = ffi::SSL_QUIC_METHOD {
    set_read_secret: Some(set_read_secret),
    set_write_secret: Some(set_write_secret),
    add_handshake_data: Some(add_handshake_data),
    flush_flight: Some(flush_flight),
    send_alert: Some(send_alert),
};

static CALLBACK_EX_INDEX: OnceLock<c_int> = OnceLock::new();

fn callback_ex_index() -> Result<c_int, CallbackInstallError> {
    let index = *CALLBACK_EX_INDEX.get_or_init(|| {
        ffi::init();
        // SAFETY: the callback matches `CRYPTO_EX_free` and the opaque arguments are unused.
        unsafe {
            ffi::SSL_get_ex_new_index(
                0,
                ptr::null_mut(),
                ptr::null_mut(),
                None,
                Some(free_callback_state),
            )
        }
    });
    if index < 0 {
        drain_error_queue();
        Err(CallbackInstallError::ExDataIndexAllocation)
    } else {
        Ok(index)
    }
}

fn allocate_state(state: CallbackState) -> Result<NonNull<CallbackState>, CallbackInstallError> {
    let layout = Layout::new::<CallbackState>();
    // SAFETY: the allocation is checked before it is initialized.
    let allocation = unsafe { alloc(layout).cast::<CallbackState>() };
    let Some(allocation) = NonNull::new(allocation) else {
        return Err(CallbackInstallError::StateAllocation);
    };
    // SAFETY: the allocation has the exact layout of `CallbackState` and is uninitialized.
    unsafe {
        allocation.as_ptr().write(state);
    }
    Ok(allocation)
}

unsafe fn release_uninstalled_state(state: NonNull<CallbackState>) {
    // SAFETY: `state` came from `allocate_state` and has not been transferred to SSL ex-data.
    unsafe {
        drop(Box::from_raw(state.as_ptr()));
    }
}

/// Installs callbacks before the first handshake operation.
///
/// # Safety
///
/// `ssl` must be a live, uniquely borrowed SSL handle.
/// `StateInstallation` requires the caller to discard `ssl`; its method remains attached.
pub(super) unsafe fn install_on_ssl(
    ssl: NonNull<ffi::SSL>,
    limits: FlightLimits,
) -> Result<CallbackState, CallbackInstallError> {
    // SAFETY: the caller upholds this function's contract.
    unsafe { install_method_on_ssl(ssl, limits, &QUIC_METHOD) }
}

/// Installs the loopback test server's callbacks; see [`TEST_SERVER_METHOD`].
///
/// # Safety
///
/// As for [`install_on_ssl`].
#[cfg(test)]
pub(super) unsafe fn install_test_server_on_ssl(
    ssl: NonNull<ffi::SSL>,
    limits: FlightLimits,
) -> Result<CallbackState, CallbackInstallError> {
    // SAFETY: the caller upholds this function's contract.
    unsafe { install_method_on_ssl(ssl, limits, &TEST_SERVER_METHOD) }
}

/// The client method, except that a 0-RTT read secret is discarded.
///
/// A BoringSSL server that accepts early data installs one; the loopback
/// test harness delivers no 0-RTT packets, so the server never needs it. The
/// client method keeps rejecting it, because a client never reads 0-RTT.
#[cfg(test)]
static TEST_SERVER_METHOD: ffi::SSL_QUIC_METHOD = ffi::SSL_QUIC_METHOD {
    set_read_secret: Some(test_server_read_secret),
    set_write_secret: Some(set_write_secret),
    add_handshake_data: Some(add_handshake_data),
    flush_flight: Some(flush_flight),
    send_alert: Some(send_alert),
};

#[cfg(test)]
unsafe extern "C" fn test_server_read_secret(
    ssl: *mut ffi::SSL,
    raw_level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    if raw_level == ffi::ssl_encryption_level_t::ssl_encryption_early_data {
        return 1;
    }
    // SAFETY: BoringSSL supplies the arguments of this callback unchanged.
    unsafe { set_read_secret(ssl, raw_level, cipher, secret, secret_len) }
}

/// # Safety
///
/// As for [`install_on_ssl`]; `method` must have process lifetime.
unsafe fn install_method_on_ssl(
    ssl: NonNull<ffi::SSL>,
    limits: FlightLimits,
    method: &'static ffi::SSL_QUIC_METHOD,
) -> Result<CallbackState, CallbackInstallError> {
    let index = callback_ex_index()?;
    // SAFETY: `ssl` is live by the caller contract and `index` is allocated for SSL objects.
    if unsafe { !ffi::SSL_get_ex_data(ssl.as_ptr(), index).is_null() } {
        return Err(CallbackInstallError::AlreadyInstalled);
    }

    let state = CallbackState::new(limits);
    let installed_state = allocate_state(state.clone())?;

    // SAFETY: `ssl` is live and `method` has process lifetime.
    if unsafe { ffi::SSL_set_quic_method(ssl.as_ptr(), method) } != 1 {
        // SAFETY: ownership was not transferred to SSL.
        unsafe {
            release_uninstalled_state(installed_state);
        }
        drain_error_queue();
        return Err(CallbackInstallError::MethodInstallation);
    }

    // SAFETY: `ssl` and `index` are valid. The allocation stays live until the ex-data destructor.
    if unsafe {
        ffi::SSL_set_ex_data(
            ssl.as_ptr(),
            index,
            installed_state.as_ptr().cast::<c_void>(),
        )
    } != 1
    {
        // SAFETY: ownership was not transferred on failure.
        unsafe {
            release_uninstalled_state(installed_state);
        }
        drain_error_queue();
        return Err(CallbackInstallError::StateInstallation);
    }

    Ok(state)
}

unsafe extern "C" fn free_callback_state(
    _parent: *mut c_void,
    state: *mut c_void,
    _ad: *mut ffi::CRYPTO_EX_DATA,
    _index: c_int,
    _argl: c_long,
    _argp: *mut c_void,
) {
    if state.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: successful installation transferred one allocation to this destructor.
        unsafe {
            drop(Box::from_raw(state.cast::<CallbackState>()));
        }
    }));
}

unsafe fn callback_state(ssl: *mut ffi::SSL) -> Option<NonNull<CallbackState>> {
    if ssl.is_null() {
        return None;
    }
    let index = *CALLBACK_EX_INDEX.get()?;
    if index < 0 {
        return None;
    }
    // SAFETY: `ssl` is live during a BoringSSL callback and `index` is an SSL ex-data index.
    let state = unsafe { ffi::SSL_get_ex_data(ssl, index) }.cast::<CallbackState>();
    if state.is_null() {
        None
    } else {
        NonNull::new(state)
    }
}

fn callback_outcome(
    state: &CallbackState,
    operation: impl FnOnce() -> Result<(), CallbackError>,
) -> c_int {
    if state.has_terminal_error() {
        return 0;
    }
    match catch_unwind(AssertUnwindSafe(operation)) {
        Ok(Ok(())) => 1,
        Ok(Err(error)) => {
            state.record_terminal(error);
            0
        }
        Err(_) => {
            state.record_terminal(CallbackError::CallbackPanicked);
            0
        }
    }
}

fn encryption_level(raw: ffi::ssl_encryption_level_t) -> Result<EncryptionLevel, CallbackError> {
    match raw {
        ffi::ssl_encryption_level_t::ssl_encryption_initial => Ok(EncryptionLevel::Initial),
        ffi::ssl_encryption_level_t::ssl_encryption_early_data => {
            Err(CallbackError::EarlyDataUnsupported)
        }
        ffi::ssl_encryption_level_t::ssl_encryption_handshake => Ok(EncryptionLevel::Handshake),
        ffi::ssl_encryption_level_t::ssl_encryption_application => Ok(EncryptionLevel::Application),
        _ => Err(CallbackError::UnsupportedEncryptionLevel {
            raw: i64::from(raw.0),
        }),
    }
}

fn validate_secret_len(cipher_suite: u16, actual: usize) -> Result<(), CallbackError> {
    let suite = CipherSuite::from_id(cipher_suite)
        .map_err(|_| CallbackError::UnsupportedCipherSuite { id: cipher_suite })?;
    let expected = suite.digest().output_len();
    if actual != expected {
        return Err(CallbackError::InvalidSecretLength { actual, expected });
    }
    Ok(())
}

unsafe fn with_callback_bytes<T>(
    pointer: *const u8,
    len: usize,
    input: &'static str,
    allow_null_empty: bool,
    operation: impl FnOnce(&[u8]) -> Result<T, CallbackError>,
) -> Result<T, CallbackError> {
    if pointer.is_null() {
        if len == 0 && allow_null_empty {
            return operation(&[]);
        }
        return Err(CallbackError::NullInput { input, len });
    }
    // SAFETY: BoringSSL lends the callback input for `len` bytes until callback return.
    operation(unsafe { slice::from_raw_parts(pointer, len) })
}

unsafe extern "C" fn set_read_secret(
    ssl: *mut ffi::SSL,
    raw_level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    // SAFETY: callback state is installed before the method is activated.
    let Some(state) = (unsafe { callback_state(ssl) }) else {
        return 0;
    };
    // SAFETY: SSL owns the state for the duration of this callback.
    let state = unsafe { state.as_ref() };
    callback_outcome(state, || {
        let level = encryption_level(raw_level)?;
        let cipher = NonNull::new(cipher.cast_mut()).ok_or(CallbackError::NullCipher)?;
        // SAFETY: BoringSSL lends a valid cipher descriptor for this callback.
        let cipher_suite = unsafe { ffi::SSL_CIPHER_get_protocol_id(cipher.as_ptr()) };
        validate_secret_len(cipher_suite, secret_len)?;
        // SAFETY: callback input remains live until the closure returns.
        unsafe {
            with_callback_bytes(secret, secret_len, "secret", false, |secret| {
                state.set_secret(level, SecretDirection::Remote, cipher_suite, secret)
            })
        }
    })
}

unsafe extern "C" fn set_write_secret(
    ssl: *mut ffi::SSL,
    raw_level: ffi::ssl_encryption_level_t,
    cipher: *const ffi::SSL_CIPHER,
    secret: *const u8,
    secret_len: usize,
) -> c_int {
    // SAFETY: callback state is installed before the method is activated.
    let Some(state) = (unsafe { callback_state(ssl) }) else {
        return 0;
    };
    // SAFETY: SSL owns the state for the duration of this callback.
    let state = unsafe { state.as_ref() };
    callback_outcome(state, || {
        // A client writes 0-RTT data only after offering a resumable session
        // with early data enabled, and never reads it.
        let level = if raw_level == ffi::ssl_encryption_level_t::ssl_encryption_early_data {
            None
        } else {
            Some(encryption_level(raw_level)?)
        };
        let cipher = NonNull::new(cipher.cast_mut()).ok_or(CallbackError::NullCipher)?;
        // SAFETY: BoringSSL lends a valid cipher descriptor for this callback.
        let cipher_suite = unsafe { ffi::SSL_CIPHER_get_protocol_id(cipher.as_ptr()) };
        validate_secret_len(cipher_suite, secret_len)?;
        // SAFETY: callback input remains live until the closure returns.
        unsafe {
            with_callback_bytes(secret, secret_len, "secret", false, |secret| match level {
                Some(level) => {
                    state.set_secret(level, SecretDirection::Local, cipher_suite, secret)
                }
                None => state.set_early_secret(cipher_suite, secret),
            })
        }
    })
}

unsafe extern "C" fn add_handshake_data(
    ssl: *mut ffi::SSL,
    raw_level: ffi::ssl_encryption_level_t,
    data: *const u8,
    len: usize,
) -> c_int {
    // SAFETY: callback state is installed before the method is activated.
    let Some(state) = (unsafe { callback_state(ssl) }) else {
        return 0;
    };
    // SAFETY: SSL owns the state for the duration of this callback.
    let state = unsafe { state.as_ref() };
    callback_outcome(state, || {
        let level = encryption_level(raw_level)?;
        // SAFETY: `ssl` is live for this callback and no state lock is held.
        let backend_limit = unsafe { ffi::SSL_quic_max_handshake_flight_len(ssl, raw_level) };
        state.validate_handshake_len(level, len, backend_limit)?;
        // SAFETY: BoringSSL permits null for an empty handshake fragment.
        unsafe {
            with_callback_bytes(data, len, "handshake data", true, |data| {
                state.append_handshake(level, data, backend_limit)
            })
        }
    })
}

unsafe extern "C" fn flush_flight(ssl: *mut ffi::SSL) -> c_int {
    // SAFETY: callback state is installed before the method is activated.
    let Some(state) = (unsafe { callback_state(ssl) }) else {
        return 0;
    };
    // SAFETY: SSL owns the state for the duration of this callback.
    let state = unsafe { state.as_ref() };
    callback_outcome(state, || state.flush())
}

unsafe extern "C" fn send_alert(
    ssl: *mut ffi::SSL,
    raw_level: ffi::ssl_encryption_level_t,
    description: u8,
) -> c_int {
    // SAFETY: callback state is installed before the method is activated.
    let Some(state) = (unsafe { callback_state(ssl) }) else {
        return 0;
    };
    // SAFETY: SSL owns the state for the duration of this callback.
    let state = unsafe { state.as_ref() };
    callback_outcome(state, || {
        state.push_alert(Alert {
            level: encryption_level(raw_level)?,
            description,
        })
    })
}

/// Routes each session a peer issues to the QUIC session that received it.
///
/// BoringSSL reports TLS 1.3 tickets only through the context-level
/// new-session callback, and only while client caching is enabled. The
/// internal cache stays off so no session outlives the connection that
/// received it except through [`crate::resumption::SessionCache`].
pub(super) fn enable_session_delivery(builder: &mut SslContextBuilder) {
    builder.set_session_cache_mode(SslSessionCacheMode::CLIENT | SslSessionCacheMode::NO_INTERNAL);
    // SAFETY: the builder uniquely owns its context, so no SSL can read the
    // callback slot concurrently, and `deliver_new_session` has process lifetime.
    unsafe {
        ffi::SSL_CTX_sess_set_new_cb(builder.as_ptr(), Some(deliver_new_session));
    }
}

unsafe extern "C" fn deliver_new_session(
    ssl: *mut ffi::SSL,
    session: *mut ffi::SSL_SESSION,
) -> c_int {
    if session.is_null() {
        return 0;
    }
    // SAFETY: `ssl` is live for this callback. An SSL without QUIC callback
    // state yields `None`, and returning 0 leaves the session with BoringSSL.
    let Some(state) = (unsafe { callback_state(ssl) }) else {
        return 0;
    };
    // SAFETY: SSL owns the state for the duration of this callback.
    let state = unsafe { state.as_ref() };
    // SAFETY: `session` is non-null, and returning 1 below tells BoringSSL
    // that this callback took its one reference, which the owner now releases.
    let session = unsafe { SslSession::from_ptr(session) };
    // A panic drops the moved session during unwinding, so ownership is
    // still discharged exactly once and 1 remains the correct result.
    let _ = catch_unwind(AssertUnwindSafe(|| state.push_session(session)));
    1
}

#[cfg(test)]
mod tests;
