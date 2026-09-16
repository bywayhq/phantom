use std::fmt;

use zeroize::Zeroize;

use crate::{CryptoError, Result};

pub(crate) const SHA256_LEN: usize = 32;
pub(crate) const AES_128_KEY_LEN: usize = 16;
pub(crate) const AES_256_KEY_LEN: usize = 32;
pub(crate) const CHACHA20_KEY_LEN: usize = 32;
pub(crate) const QUIC_NONCE_LEN: usize = 12;

pub(crate) struct Secret<const N: usize>([u8; N]);

impl<const N: usize> Secret<N> {
    pub(crate) fn zeroed() -> Self {
        Self([0; N])
    }

    pub(crate) fn copy_from_slice(value: &[u8]) -> Result<Self> {
        if value.len() != N {
            return Err(CryptoError::InvalidKeyLength {
                actual: value.len(),
                expected: N,
            });
        }

        let mut bytes = [0; N];
        bytes.copy_from_slice(value);
        Ok(Self(bytes))
    }

    pub(crate) const fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}
