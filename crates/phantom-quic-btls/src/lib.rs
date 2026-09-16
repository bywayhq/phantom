//! BoringSSL-backed QUIC cryptography primitives for Phantom.
//!
//! This crate is an internal adapter, not a general-purpose cryptography API.
//! Its checked concrete types are deliberately separate from Quinn's
//! infallible Quinn traits. The full QUIC session provider can adapt them once
//! it owns the protocol invariants required by those traits.

#![deny(unsafe_code)]

// Raw BoringSSL access is isolated here so safe protocol code cannot grow new
// unsafe operations without crossing an explicit, reviewable module boundary.
#[allow(unsafe_code, reason = "private BoringSSL FFI boundary")]
mod backend;
mod error;
mod header;
mod hkdf;
mod initial;
#[cfg(feature = "keylog")]
mod key_log;
mod key_schedule;
mod packet;
mod quinn;
mod reset;
mod retry;
mod secret;
mod transport_parameters;

#[cfg(test)]
mod suite_tests;
#[cfg(test)]
mod tests;

pub use backend::client::{
    HandshakeData, InvalidServerName, PeerIdentity, QuicClientConfig, QuicTlsProfileError,
    QuicTlsProfileErrorKind,
};
pub use error::{CryptoError, Result};
pub use header::HeaderProtectionKey;
pub use initial::{InitialKeys, derive_initial_keys};
#[cfg(feature = "keylog")]
pub use key_log::{NssKeyLogLine, NssKeyLogReceiver, configure_nss_key_log};
pub use key_schedule::{DirectionKeys, EndpointSide};
pub use packet::PacketProtectionKey;
pub use reset::StatelessResetKey;
pub use retry::{retry_integrity_tag, verify_retry_integrity};
pub use transport_parameters::QuicTransportProfileError;

/// The QUIC protocol version understood by this packet-crypto slice.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum QuicVersion {
    /// QUIC version 1, as specified by RFC 9000 and RFC 9001.
    #[default]
    V1,
}

impl QuicVersion {
    pub(crate) const fn initial_salt(self) -> &'static [u8; 20] {
        match self {
            Self::V1 => &[
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
            ],
        }
    }

    pub(crate) const fn retry_key(self) -> &'static [u8; 16] {
        match self {
            Self::V1 => &[
                0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68,
                0xc8, 0x4e,
            ],
        }
    }

    pub(crate) const fn retry_nonce(self) -> &'static [u8; 12] {
        match self {
            Self::V1 => &[
                0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
            ],
        }
    }
}
