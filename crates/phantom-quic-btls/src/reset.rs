//! Stateless-reset authentication for Quinn endpoint configuration.

use std::fmt;

use quinn_proto::crypto;
use zeroize::Zeroize;

use crate::backend;
use crate::secret::{SHA256_LEN, Secret};
use crate::{CryptoError, Result};

/// A BoringSSL-backed HMAC-SHA-256 key for QUIC stateless-reset tokens.
///
/// The fixed 256-bit key supplies the full security strength of HMAC-SHA-256.
/// Key material is redacted from formatting and zeroized when the key drops.
pub struct StatelessResetKey {
    key: Secret<SHA256_LEN>,
}

impl StatelessResetKey {
    /// Required key length in bytes.
    pub const KEY_LEN: usize = SHA256_LEN;

    /// HMAC-SHA-256 signature length in bytes.
    pub const SIGNATURE_LEN: usize = SHA256_LEN;

    /// Constructs a reset key from exactly 256 bits of caller-supplied key material.
    pub fn from_bytes(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Secret::copy_from_slice(key)?,
        })
    }

    /// Generates a reset key with BoringSSL's operating-system-seeded CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut key = Secret::zeroed();
        backend::random_bytes(key.as_mut_slice())?;
        Ok(Self { key })
    }

    /// Signs `data` into an exactly sized HMAC-SHA-256 output buffer.
    pub fn sign(&self, data: &[u8], signature_out: &mut [u8]) -> Result<()> {
        if signature_out.len() != Self::SIGNATURE_LEN {
            signature_out.fill(0);
            return Err(CryptoError::InvalidSignatureLength {
                actual: signature_out.len(),
                expected: Self::SIGNATURE_LEN,
            });
        }

        let actual = signature_out.len();
        let output = <&mut [u8; Self::SIGNATURE_LEN]>::try_from(signature_out).map_err(|_| {
            CryptoError::InvalidSignatureLength {
                actual,
                expected: Self::SIGNATURE_LEN,
            }
        })?;
        backend::hmac_sha256(self.key.as_slice(), data, output)
    }

    /// Verifies a complete HMAC-SHA-256 signature in constant time.
    pub fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        if signature.len() != Self::SIGNATURE_LEN {
            return Err(CryptoError::InvalidSignatureLength {
                actual: signature.len(),
                expected: Self::SIGNATURE_LEN,
            });
        }

        let mut expected = [0; Self::SIGNATURE_LEN];
        backend::hmac_sha256(self.key.as_slice(), data, &mut expected)?;
        let valid = backend::constant_time_eq(&expected, signature);
        expected.zeroize();
        if valid {
            Ok(())
        } else {
            Err(CryptoError::SignatureMismatch)
        }
    }
}

impl fmt::Debug for StatelessResetKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StatelessResetKey([REDACTED])")
    }
}

impl crypto::HmacKey for StatelessResetKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        if StatelessResetKey::sign(self, data, signature_out).is_err() {
            signature_out.fill(0);
        }
    }

    fn signature_len(&self) -> usize {
        Self::SIGNATURE_LEN
    }

    fn verify(
        &self,
        data: &[u8],
        signature: &[u8],
    ) -> std::result::Result<(), crypto::CryptoError> {
        StatelessResetKey::verify(self, data, signature).map_err(|_| crypto::CryptoError)
    }
}

#[cfg(test)]
mod tests;
