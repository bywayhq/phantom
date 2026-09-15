use std::fmt;

use zeroize::Zeroize;

use crate::backend::Aes128GcmContext;
use crate::secret::{AES_128_KEY_LEN, QUIC_NONCE_LEN, Secret};
use crate::{CryptoError, Result};

const TAG_LEN: usize = 16;

/// An AES-128-GCM QUIC packet-protection key and IV.
pub struct PacketProtectionKey {
    context: Aes128GcmContext,
    iv: Secret<QUIC_NONCE_LEN>,
}

impl PacketProtectionKey {
    /// Builds a packet key from a 16-byte AES key and 12-byte QUIC IV.
    pub fn aes_128_gcm(key: &[u8], iv: &[u8]) -> Result<Self> {
        if key.len() != AES_128_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                actual: key.len(),
                expected: AES_128_KEY_LEN,
            });
        }
        if iv.len() != QUIC_NONCE_LEN {
            return Err(CryptoError::InvalidNonceLength {
                actual: iv.len(),
                expected: QUIC_NONCE_LEN,
            });
        }
        Ok(Self {
            context: Aes128GcmContext::new(key)?,
            iv: Secret::copy_from_slice(iv)?,
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
