//! `ECHConfigList` parsing.
//!
//! The harness drives `phantom_net::dns::EchConfigList::parse`, the parser
//! that checks an HTTPS record's `ech` value before a direct connection
//! offers it to the TLS client. It feeds the raw input and a structural seed
//! perturbed by the input. Every list that parses must hold at least one
//! configuration, and every configuration the client would use must have
//! version `0xfe0d`, a non-empty public key and public name, and at least one
//! cipher suite.

#[cfg(test)]
mod tests;

use phantom_net::dns::{EchConfig, EchConfigList, EchConfigListError};

use crate::seed;

/// A list of two configurations: one of version `0xfe0d` that the client
/// supports, with one non-mandatory extension, and one of an unknown version
/// that the parser keeps without reading.
#[rustfmt::skip]
pub const LIST: &[u8] = &[
    0x00, 0x4b,
    // ECHConfig 0xfe0d, 0x003f bytes of contents.
    0xfe, 0x0d, 0x00, 0x3f,
    // config_id 7, KEM X25519 HKDF-SHA256, 32-byte public key.
    0x07, 0x00, 0x20, 0x00, 0x20,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    // Two cipher suites: HKDF-SHA256 with AES-128-GCM and ChaCha20-Poly1305.
    0x00, 0x08, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x03,
    // maximum_name_length 0, public name "a.test".
    0x00, 0x06, b'a', b'.', b't', b'e', b's', b't',
    // One extension, type 0x0001, two bytes.
    0x00, 0x06, 0x00, 0x01, 0x00, 0x02, 0xaa, 0xbb,
    // An unknown version with four bytes of contents.
    0xfe, 0x0a, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
];

/// Parses `input` as an `ECHConfigList`.
///
/// # Errors
///
/// Returns the parser's error for a malformed list.
pub fn drive(input: &[u8]) -> Result<Box<[EchConfig]>, EchConfigListError> {
    EchConfigList::new(input).parse()
}

/// Runs the harness on one fuzz input.
pub fn exercise(input: &[u8]) {
    for bytes in [input.to_vec(), seed::perturb(LIST, input)] {
        if let Ok(configs) = drive(&bytes) {
            check(&configs);
        }
    }
}

fn check(configs: &[EchConfig]) {
    assert!(!configs.is_empty(), "a parsed list holds a configuration");
    for config in configs.iter().filter(|config| config.is_supported()) {
        assert_eq!(config.version(), 0xfe0d);
        assert!(!config.public_key().is_empty());
        assert!(config.public_name().is_some_and(|name| !name.is_empty()));
        assert!(!config.cipher_suites().is_empty());
    }
}
