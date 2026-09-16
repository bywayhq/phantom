use std::fmt;

use zeroize::Zeroize;

use crate::backend::AeadContext;
use crate::secret::QUIC_NONCE_LEN;
use crate::secret::Secret;
use crate::{CryptoError, Result};

const TAG_LEN: usize = 16;

/// A QUIC packet-protection key and IV for a TLS 1.3 AEAD suite.
pub struct PacketProtectionKey {
    context: AeadContext,
    iv: Secret<QUIC_NONCE_LEN>,
    algorithm: PacketAlgorithm,
}

#[derive(Clone, Copy)]
enum PacketAlgorithm {
    AesGcm,
    ChaCha20Poly1305,
}

impl PacketProtectionKey {
    /// Builds a packet key from a 16-byte AES key and 12-byte QUIC IV.
    pub fn aes_128_gcm(key: &[u8], iv: &[u8]) -> Result<Self> {
        Self::new(AeadContext::aes_128_gcm(key)?, iv, PacketAlgorithm::AesGcm)
    }

    /// Builds a packet key from a 32-byte AES key and 12-byte QUIC IV.
    pub fn aes_256_gcm(key: &[u8], iv: &[u8]) -> Result<Self> {
        Self::new(AeadContext::aes_256_gcm(key)?, iv, PacketAlgorithm::AesGcm)
    }

    /// Builds a packet key from a 32-byte ChaCha20 key and 12-byte QUIC IV.
    pub fn chacha20_poly1305(key: &[u8], iv: &[u8]) -> Result<Self> {
        Self::new(
            AeadContext::chacha20_poly1305(key)?,
            iv,
            PacketAlgorithm::ChaCha20Poly1305,
        )
    }

    fn new(context: AeadContext, iv: &[u8], algorithm: PacketAlgorithm) -> Result<Self> {
        if iv.len() != QUIC_NONCE_LEN {
            return Err(CryptoError::InvalidNonceLength {
                actual: iv.len(),
                expected: QUIC_NONCE_LEN,
            });
        }
        Ok(Self {
            context,
            iv: Secret::copy_from_slice(iv)?,
            algorithm,
        })
    }

    /// Encrypts the payload in place and writes the authentication tag into
    /// the final 16 bytes of `packet`.
    ///
    /// `packet` must already reserve tag capacity, matching Quinn's packet-key
    /// contract. `header_len` separates associated data from plaintext.
    pub fn seal(&self, packet_number: u64, packet: &mut [u8], header_len: usize) -> Result<()> {
        let packet_len = packet.len();
        let payload =
            packet
                .get_mut(header_len..)
                .ok_or(CryptoError::InsufficientOutputCapacity {
                    actual: packet_len,
                    required: header_len,
                })?;
        let plaintext_len =
            payload
                .len()
                .checked_sub(TAG_LEN)
                .ok_or(CryptoError::InsufficientOutputCapacity {
                    actual: payload.len(),
                    required: TAG_LEN,
                })?;
        let (header, payload) = packet.split_at_mut(header_len);
        let mut nonce = self.nonce(packet_number);
        let result = self.context.seal(&nonce, payload, plaintext_len, header);
        nonce.zeroize();
        result.map(|_| ())
    }

    /// Authenticates and decrypts a packet payload in place.
    ///
    /// Returns the plaintext length. Bytes after that length are unspecified
    /// and should be truncated by the caller.
    pub fn open(
        &self,
        packet_number: u64,
        header: &[u8],
        payload_and_tag: &mut [u8],
    ) -> Result<usize> {
        if payload_and_tag.len() < TAG_LEN {
            return Err(CryptoError::InsufficientOutputCapacity {
                actual: payload_and_tag.len(),
                required: TAG_LEN,
            });
        }
        let mut nonce = self.nonce(packet_number);
        let result = self.context.open(&nonce, payload_and_tag, header);
        nonce.zeroize();
        result
    }

    /// Returns the authentication tag length in bytes.
    #[must_use]
    pub const fn tag_len(&self) -> usize {
        TAG_LEN
    }

    pub(crate) const fn confidentiality_limit(&self) -> u64 {
        // https://www.rfc-editor.org/rfc/rfc9001.html#section-6.6
        match self.algorithm {
            PacketAlgorithm::AesGcm => 1 << 23,
            // RFC 9001 section 6.6 says ChaCha20-Poly1305's limit is greater
            // than QUIC's 2^62 packet-number space and can be disregarded.
            PacketAlgorithm::ChaCha20Poly1305 => u64::MAX,
        }
    }

    pub(crate) const fn integrity_limit(&self) -> u64 {
        // https://www.rfc-editor.org/rfc/rfc9001.html#section-6.6
        match self.algorithm {
            // RFC 9001 section 6.6 applies the same conservative bound to
            // AES-128-GCM and AES-256-GCM.
            PacketAlgorithm::AesGcm => 1 << 52,
            PacketAlgorithm::ChaCha20Poly1305 => 1 << 36,
        }
    }

    fn nonce(&self, packet_number: u64) -> [u8; QUIC_NONCE_LEN] {
        let mut nonce = [0; QUIC_NONCE_LEN];
        nonce.copy_from_slice(self.iv.as_slice());
        for (byte, packet_byte) in nonce[QUIC_NONCE_LEN - 8..]
            .iter_mut()
            .zip(packet_number.to_be_bytes())
        {
            *byte ^= packet_byte;
        }
        nonce
    }
}

impl fmt::Debug for PacketProtectionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PacketProtectionKey([REDACTED])")
    }
}
