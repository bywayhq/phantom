use std::fmt;

use crate::backend::{AesHeaderCipher, ChaChaHeaderCipher};
use crate::secret::{AES_128_KEY_LEN, CHACHA20_KEY_LEN};
use crate::{CryptoError, Result};

const SAMPLE_LEN: usize = 16;
const SAMPLE_OFFSET_FROM_PACKET_NUMBER: usize = 4;

/// An AES-128 or ChaCha20 QUIC header-protection key.
pub struct HeaderProtectionKey {
    cipher: HeaderCipher,
}

enum HeaderCipher {
    // `AES_KEY` stores a large expanded schedule. Allocate it once when the
    // header key is built rather than inflating every enum value.
    Aes128(Box<AesHeaderCipher>),
    ChaCha20(ChaChaHeaderCipher),
}

impl HeaderProtectionKey {
    /// Builds an AES-128 header-protection key from exactly 16 key bytes.
    pub fn aes_128(key: &[u8]) -> Result<Self> {
        if key.len() != AES_128_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                actual: key.len(),
                expected: AES_128_KEY_LEN,
            });
        }
        Ok(Self {
            cipher: HeaderCipher::Aes128(Box::new(AesHeaderCipher::new(key)?)),
        })
    }

    /// Builds a ChaCha20 header-protection key from exactly 32 key bytes.
    pub fn chacha20(key: &[u8]) -> Result<Self> {
        if key.len() != CHACHA20_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                actual: key.len(),
                expected: CHACHA20_KEY_LEN,
            });
        }
        Ok(Self {
            cipher: HeaderCipher::ChaCha20(ChaChaHeaderCipher::new(key)?),
        })
    }

    /// Applies QUIC header protection in place.
    pub fn protect(&self, packet_number_offset: usize, packet: &mut [u8]) -> Result<()> {
        self.apply(packet_number_offset, packet, false)
    }

    /// Removes QUIC header protection in place.
    pub fn unprotect(&self, packet_number_offset: usize, packet: &mut [u8]) -> Result<()> {
        self.apply(packet_number_offset, packet, true)
    }

    /// Returns the required header-protection sample length.
    #[must_use]
    pub const fn sample_len(&self) -> usize {
        SAMPLE_LEN
    }

    fn apply(&self, packet_number_offset: usize, packet: &mut [u8], masked: bool) -> Result<()> {
        if packet_number_offset == 0 || packet_number_offset >= packet.len() {
            return Err(CryptoError::InvalidPacketNumberOffset {
                offset: packet_number_offset,
                packet_len: packet.len(),
            });
        }
        let sample_offset = packet_number_offset
            .checked_add(SAMPLE_OFFSET_FROM_PACKET_NUMBER)
            .ok_or(CryptoError::InvalidSampleBounds {
                offset: usize::MAX,
                required: SAMPLE_LEN,
                packet_len: packet.len(),
            })?;
        let sample_end =
            sample_offset
                .checked_add(SAMPLE_LEN)
                .ok_or(CryptoError::InvalidSampleBounds {
                    offset: sample_offset,
                    required: SAMPLE_LEN,
                    packet_len: packet.len(),
                })?;
        let sample =
            packet
                .get(sample_offset..sample_end)
                .ok_or(CryptoError::InvalidSampleBounds {
                    offset: sample_offset,
                    required: SAMPLE_LEN,
                    packet_len: packet.len(),
                })?;
        let mut sample_array = [0; SAMPLE_LEN];
        sample_array.copy_from_slice(sample);
        let mask = match &self.cipher {
            HeaderCipher::Aes128(cipher) => cipher.mask(&sample_array),
            HeaderCipher::ChaCha20(cipher) => cipher.mask(&sample_array),
        };
        sample_array.fill(0);

        const LONG_HEADER: u8 = 0x80;
        let first_mask = if packet[0] & LONG_HEADER == LONG_HEADER {
            0x0f
        } else {
            0x1f
        };
        let first_plain = if masked {
            packet[0] ^ (mask[0] & first_mask)
        } else {
            packet[0]
        };
        let packet_number_len = usize::from(first_plain & 0x03) + 1;
        let packet_number_end = packet_number_offset.checked_add(packet_number_len).ok_or(
            CryptoError::InvalidPacketNumberOffset {
                offset: packet_number_offset,
                packet_len: packet.len(),
            },
        )?;
        if packet_number_end > packet.len() {
            return Err(CryptoError::InvalidPacketNumberOffset {
                offset: packet_number_offset,
                packet_len: packet.len(),
            });
        }

        packet[0] ^= mask[0] & first_mask;
        for (byte, mask_byte) in packet[packet_number_offset..packet_number_end]
            .iter_mut()
            .zip(&mask[1..])
        {
            *byte ^= mask_byte;
        }
        Ok(())
    }
}

impl fmt::Debug for HeaderProtectionKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HeaderProtectionKey([REDACTED])")
    }
}
