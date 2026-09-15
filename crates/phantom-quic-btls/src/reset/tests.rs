use std::sync::Arc;

use quinn_proto::crypto::HmacKey as _;

use super::StatelessResetKey;
use crate::CryptoError;

// RFC 4868 section 2.7.2.1, AUTH256-1:
// https://www.rfc-editor.org/rfc/rfc4868.html#section-2.7.2.1
const RFC_4868_AUTH256_1: [u8; 32] = [
    0x19, 0x8a, 0x60, 0x7e, 0xb4, 0x4b, 0xfb, 0xc6, 0x99, 0x03, 0xa0, 0xf1, 0xcf, 0x2b, 0xbd, 0xc5,
    0xba, 0x0a, 0xa3, 0xf3, 0xd9, 0xae, 0x3c, 0x1c, 0x7a, 0x3b, 0x16, 0x96, 0xa0, 0xb6, 0x8c, 0xf7,
];

#[test]
fn rfc_4868_hmac_sha256_known_answer_is_exact() {
    let key = StatelessResetKey::from_bytes(&[0x0b; 32])
        .unwrap_or_else(|error| panic!("RFC key construction failed: {error}"));
    let mut signature = [0; StatelessResetKey::SIGNATURE_LEN];

    key.sign(b"Hi There", &mut signature)
        .unwrap_or_else(|error| panic!("RFC signing failed: {error}"));

    assert_eq!(signature, RFC_4868_AUTH256_1);
    assert_eq!(key.verify(b"Hi There", &signature), Ok(()));
}

#[test]
fn verification_rejects_modified_data_signature_and_length() {
    let key = StatelessResetKey::from_bytes(&[0x0b; 32])
        .unwrap_or_else(|error| panic!("test key construction failed: {error}"));
    let mut wrong_signature = RFC_4868_AUTH256_1;
    wrong_signature[0] ^= 1;

    assert_eq!(
        key.verify(b"Hi There!", &RFC_4868_AUTH256_1),
        Err(CryptoError::SignatureMismatch)
    );
    assert_eq!(
        key.verify(b"Hi There", &wrong_signature),
        Err(CryptoError::SignatureMismatch)
    );
    assert_eq!(
        key.verify(b"Hi There", &wrong_signature[..31]),
        Err(CryptoError::InvalidSignatureLength {
            actual: 31,
            expected: 32,
        })
    );
}

#[test]
fn quinn_trait_signing_is_panic_free_and_fails_closed_for_wrong_bounds() {
    let key = StatelessResetKey::from_bytes(&[0x0b; 32])
        .unwrap_or_else(|error| panic!("test key construction failed: {error}"));
    let trait_key: &dyn quinn_proto::crypto::HmacKey = &key;

    let mut exact = [0; 32];
    trait_key.sign(b"Hi There", &mut exact);
    assert_eq!(exact, RFC_4868_AUTH256_1);
    assert!(trait_key.verify(b"Hi There", &exact).is_ok());

    let mut short = [0xab; 31];
    trait_key.sign(b"Hi There", &mut short);
    assert_eq!(short, [0; 31]);

    let mut long = [0xab; 33];
    trait_key.sign(b"Hi There", &mut long);
    assert_eq!(long, [0; 33]);

    let mut wrong = exact;
    wrong[31] ^= 1;
    assert!(trait_key.verify(b"Hi There", &wrong).is_err());
    assert!(trait_key.verify(b"Hi There", &exact[..31]).is_err());
}

#[test]
fn checked_signing_returns_typed_bounds_errors_and_clears_output() {
    let key = StatelessResetKey::from_bytes(&[0x0b; 32])
        .unwrap_or_else(|error| panic!("test key construction failed: {error}"));
    let mut output = [0xab; 31];

    assert_eq!(
        key.sign(b"Hi There", &mut output),
        Err(CryptoError::InvalidSignatureLength {
            actual: 31,
            expected: 32,
        })
    );
    assert_eq!(output, [0; 31]);
}

#[test]
fn generated_key_constructs_stock_quinn_endpoint_config_without_other_crypto_backends() {
    let key = Arc::new(
        StatelessResetKey::generate()
            .unwrap_or_else(|error| panic!("random key generation failed: {error}")),
    );
    assert_eq!(key.signature_len(), StatelessResetKey::SIGNATURE_LEN);

    let config = quinn_proto::EndpointConfig::new(key);
    let debug = format!("{config:?}");
    assert!(debug.starts_with("EndpointConfig"));
    assert!(!debug.contains("reset_key"));
}

#[test]
fn key_construction_and_debug_do_not_disclose_secret_material() {
    assert!(matches!(
        StatelessResetKey::from_bytes(&[0x5a; 31]),
        Err(CryptoError::InvalidKeyLength {
            actual: 31,
            expected: 32,
        })
    ));

    let key = StatelessResetKey::from_bytes(&[0x5a; 32])
        .unwrap_or_else(|error| panic!("test key construction failed: {error}"));
    assert_eq!(format!("{key:?}"), "StatelessResetKey([REDACTED])");
}
