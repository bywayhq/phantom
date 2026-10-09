//! BoringSSL-backed QUIC cryptography for Phantom.
//!
//! This crate is an internal adapter, not a general-purpose cryptography API.
//! [`QuicClientConfig`] implements Quinn's client crypto provider: it drives a
//! BoringSSL QUIC TLS 1.3 handshake from a typed TLS profile, applies the
//! profile's QUIC transport parameters, and derives packet, header, key-update,
//! Retry-integrity, and stateless-reset keys. Packet protection and Retry
//! helpers stay private. Their Quinn trait implementations fail closed when
//! a trait has no error channel. [`StatelessResetKey`] supplies Quinn's
//! endpoint reset key and has checked methods that return [`CryptoError`].
//! [`QuicClientConfig::with_ech`] offers Encrypted Client Hello on one
//! connection and reports the result through an [`EchOffer`].
//!
//! The optional `server` feature adds `QuicServerConfig`, a Quinn server
//! provider on a BoringSSL context, for Phantom's loopback tests and capture
//! tools; it can hold ECH keys and offers no 0-RTT.
//!
//! All `unsafe` code is confined to the private `backend` module, the
//! BoringSSL FFI boundary. The rest of the crate denies `unsafe_code`, and
//! every unsafe block in `backend` carries a `SAFETY` comment required by
//! `clippy::undocumented_unsafe_blocks`. The optional `keylog` feature emits
//! NSS key-log lines through a bounded queue. The `phantom-http` facade
//! exposes it as `ClientBuilder::key_log` behind its `diagnostics` feature.

#![deny(unsafe_code)]

// Raw BoringSSL access is isolated here so safe protocol code cannot grow new
// unsafe operations without crossing an explicit, reviewable module boundary.
#[allow(unsafe_code, reason = "private BoringSSL FFI boundary")]
mod backend;
mod ech;
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
mod resumption;
mod retry;
mod secret;
mod transport_parameters;

#[cfg(test)]
mod suite_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod version_2_tests;

pub use backend::client::{
    HandshakeData, InvalidServerName, PeerIdentity, QuicClientCertificate, QuicClientConfig,
    QuicTlsProfileError, QuicTlsProfileErrorKind,
};
#[cfg(feature = "server")]
pub use backend::server::{QuicServerConfig, ServerHandshakeData};
pub use ech::{EchOffer, EchOutcome};
pub use error::{CryptoError, Result};
pub(crate) use header::HeaderProtectionKey;
pub(crate) use initial::{InitialKeys, derive_initial_keys};
#[cfg(feature = "keylog")]
pub use key_log::{
    NssKeyLogLine, NssKeyLogReceiver, NssKeyLogSender, configure_nss_key_log, nss_key_log_channel,
};
pub(crate) use key_schedule::{DirectionKeys, EndpointSide};
pub(crate) use packet::PacketProtectionKey;
pub use reset::StatelessResetKey;
pub use resumption::ApplicationState;
#[cfg(any(test, feature = "server"))]
pub(crate) use retry::retry_integrity_tag;
pub(crate) use retry::verify_retry_integrity;
pub use transport_parameters::QuicTransportProfileError;

/// The QUIC protocol version understood by this packet-crypto slice.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub(crate) enum QuicVersion {
    /// QUIC version 1, as specified by RFC 9000 and RFC 9001.
    #[default]
    V1,
    /// QUIC version 2, as specified by RFC 9369.
    V2,
}

/// HKDF labels for packet protection and key updates (RFC 9001 section 5.1, RFC 9369
/// section 3.3.2).
pub(crate) struct PacketLabels {
    pub(crate) key: &'static [u8],
    pub(crate) iv: &'static [u8],
    pub(crate) hp: &'static [u8],
    pub(crate) ku: &'static [u8],
}

impl QuicVersion {
    /// Returns the version number on the wire.
    #[must_use]
    pub(crate) const fn wire(self) -> u32 {
        match self {
            Self::V1 => 0x0000_0001,
            Self::V2 => 0x6b33_43cf,
        }
    }

    /// Returns the version with wire number `version`, if this crate implements it.
    #[must_use]
    pub(crate) const fn from_wire(version: u32) -> Option<Self> {
        match version {
            0x0000_0001 => Some(Self::V1),
            0x6b33_43cf => Some(Self::V2),
            _ => None,
        }
    }

    pub(crate) const fn labels(self) -> PacketLabels {
        match self {
            Self::V1 => PacketLabels {
                key: b"quic key",
                iv: b"quic iv",
                hp: b"quic hp",
                ku: b"quic ku",
            },
            Self::V2 => PacketLabels {
                key: b"quicv2 key",
                iv: b"quicv2 iv",
                hp: b"quicv2 hp",
                ku: b"quicv2 ku",
            },
        }
    }

    pub(crate) const fn initial_salt(self) -> &'static [u8; 20] {
        match self {
            Self::V1 => &[
                0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8,
                0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
            ],
            // RFC 9369 section 3.3.1
            Self::V2 => &[
                0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26,
                0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9,
            ],
        }
    }

    pub(crate) const fn retry_key(self) -> &'static [u8; 16] {
        match self {
            Self::V1 => &[
                0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68,
                0xc8, 0x4e,
            ],
            // RFC 9369 section 3.3.3
            Self::V2 => &[
                0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2, 0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c,
                0xcc, 0x92,
            ],
        }
    }

    pub(crate) const fn retry_nonce(self) -> &'static [u8; 12] {
        match self {
            Self::V1 => &[
                0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
            ],
            Self::V2 => &[
                0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99, 0x90, 0xef, 0xb0, 0x4a,
            ],
        }
    }
}
