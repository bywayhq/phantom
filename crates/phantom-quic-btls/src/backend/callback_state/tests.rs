use super::*;

const AES_128_GCM_SHA256: u16 = 0x1301;

fn success<T>(result: Result<T, CallbackError>) -> T {
    result.unwrap_or_else(|error| panic!("unexpected callback error: {error:?}"))
}

fn failure<T>(result: Result<T, CallbackError>) -> CallbackError {
    match result {
        Ok(_) => panic!("callback unexpectedly succeeded"),
        Err(error) => error,
    }
}

#[test]
fn complete_secret_pairs_are_extracted_once_in_both_callback_orders() {
    for first in [SecretDirection::Local, SecretDirection::Remote] {
        let state = CallbackState::new(FlightLimits::default());
        let second = match first {
            SecretDirection::Local => SecretDirection::Remote,
            SecretDirection::Remote => SecretDirection::Local,
        };

        success(state.set_secret(
            EncryptionLevel::Handshake,
            first,
            AES_128_GCM_SHA256,
            &[1; 32],
        ));
        assert!(state.take_secret_pair(EncryptionLevel::Handshake).is_none());
        success(state.set_secret(
            EncryptionLevel::Handshake,
            second,
            AES_128_GCM_SHA256,
            &[2; 32],
        ));

        assert_eq!(
            state.secret_len(EncryptionLevel::Handshake, SecretDirection::Local),
            Some(32)
        );
        assert_eq!(
            state.secret_len(EncryptionLevel::Handshake, SecretDirection::Remote),
            Some(32)
        );

        let pair = state
            .take_secret_pair(EncryptionLevel::Handshake)
            .unwrap_or_else(|| panic!("complete secret pair was not available"));
        assert_eq!(pair.cipher_suite, AES_128_GCM_SHA256);
        let (expected_local, expected_remote) = match first {
            SecretDirection::Local => ([1; 32], [2; 32]),
            SecretDirection::Remote => ([2; 32], [1; 32]),
        };
        assert_eq!(pair.local.as_slice(), expected_local);
        assert_eq!(pair.remote.as_slice(), expected_remote);
        assert_eq!(
            format!("{pair:?}"),
            "SecretPair { cipher_suite: 4865, local: \"[REDACTED]\", remote: \"[REDACTED]\" }"
        );
        assert!(state.take_secret_pair(EncryptionLevel::Handshake).is_none());

        let error = failure(state.set_secret(
            EncryptionLevel::Handshake,
            first,
            AES_128_GCM_SHA256,
            &[3; 32],
        ));
        assert_eq!(
            error,
            CallbackError::DuplicateSecret {
                level: EncryptionLevel::Handshake,
                direction: first,
            }
        );
    }
}

#[test]
fn handshake_and_application_secrets_are_independent() {
    let state = CallbackState::new(FlightLimits::default());

    for level in [EncryptionLevel::Handshake, EncryptionLevel::Application] {
        for direction in [SecretDirection::Local, SecretDirection::Remote] {
            success(state.set_secret(level, direction, AES_128_GCM_SHA256, &[7; 32]));
        }
    }

    assert!(state.terminal_error().is_none());
}

#[test]
fn duplicate_secret_is_rejected() {
    let state = CallbackState::new(FlightLimits::default());
    success(state.set_secret(
        EncryptionLevel::Application,
        SecretDirection::Local,
        AES_128_GCM_SHA256,
        &[1; 32],
    ));

    let error = failure(state.set_secret(
        EncryptionLevel::Application,
        SecretDirection::Local,
        AES_128_GCM_SHA256,
        &[1; 32],
    ));

    assert_eq!(
        error,
        CallbackError::DuplicateSecret {
            level: EncryptionLevel::Application,
            direction: SecretDirection::Local,
        }
    );
}

#[test]
fn flush_is_the_publication_boundary() {
    let state = CallbackState::new(FlightLimits::new(8, 8, 8));
    success(state.append_handshake(EncryptionLevel::Initial, b"hello", 8));

    assert!(success(state.drain_handshake()).is_empty());
    success(state.flush());
    assert_eq!(success(state.drain_handshake())[0].bytes, b"hello");
}

#[test]
fn handshake_output_is_bounded_by_the_lower_limit() {
    let state = CallbackState::new(FlightLimits::new(8, 8, 8));
    success(state.append_handshake(EncryptionLevel::Handshake, b"1234", 6));

    let error = failure(state.append_handshake(EncryptionLevel::Handshake, b"567", 6));

    assert_eq!(
        error,
        CallbackError::HandshakeDataTooLarge {
            level: EncryptionLevel::Handshake,
            attempted: 7,
            limit: 6,
        }
    );
}

#[test]
fn alerts_are_retained() {
    let state = CallbackState::new(FlightLimits::default());
    let alert = Alert {
        level: EncryptionLevel::Handshake,
        description: 42,
    };

    success(state.push_alert(alert));

    assert_eq!(success(state.drain_alerts()), vec![alert]);
}
