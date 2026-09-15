//! The complete FFI boundary for packet cryptography.

use std::ffi::c_uint;
use std::fmt;
use std::ptr::NonNull;

use btls_sys as ffi;

use crate::secret::{AES_128_KEY_LEN, QUIC_NONCE_LEN, SHA256_LEN};
use crate::{CryptoError, Result};

const AES_BLOCK_LEN: usize = 16;
const AES_GCM_TAG_LEN: usize = 16;

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    // SAFETY: both pointers reference readable slices of the same checked
    // length for the duration of the call. `CRYPTO_memcmp` does not write.
    unsafe { ffi::CRYPTO_memcmp(left.as_ptr().cast(), right.as_ptr().cast(), left.len()) == 0 }
}

pub(crate) fn hkdf_extract_sha256(salt: &[u8], ikm: &[u8], output: &mut [u8]) -> Result<()> {
    if output.len() != SHA256_LEN {
        return Err(CryptoError::InsufficientOutputCapacity {
            actual: output.len(),
            required: SHA256_LEN,
        });
    }

    ffi::init();
    let mut written = output.len();
    // SAFETY: all pointers come from live slices for the duration of the call;
    // `output` has SHA-256 digest capacity and cannot alias either input.
    let status = unsafe {
        ffi::HKDF_extract(
            output.as_mut_ptr(),
            &mut written,
            ffi::EVP_sha256(),
            ikm.as_ptr(),
            ikm.len(),
            salt.as_ptr(),
            salt.len(),
        )
    };
    if status != 1 || written != SHA256_LEN {
        output.fill(0);
        return Err(CryptoError::BackendFailure("HKDF extract"));
    }
    Ok(())
}

pub(crate) fn hkdf_expand_sha256(prk: &[u8], info: &[u8], output: &mut [u8]) -> Result<()> {
    ffi::init();
    // SAFETY: all pointers come from live, non-overlapping slices for the
    // duration of the call; BoringSSL writes exactly `output.len()` bytes.
    let status = unsafe {
        ffi::HKDF_expand(
            output.as_mut_ptr(),
            output.len(),
            ffi::EVP_sha256(),
            prk.as_ptr(),
            prk.len(),
            info.as_ptr(),
            info.len(),
        )
    };
    if status != 1 {
        output.fill(0);
        return Err(CryptoError::BackendFailure("HKDF expand"));
    }
    Ok(())
}

pub(crate) struct AesHeaderCipher(ffi::AES_KEY);

impl AesHeaderCipher {
    pub(crate) fn new(key: &[u8]) -> Result<Self> {
        if key.len() != AES_128_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                actual: key.len(),
                expected: AES_128_KEY_LEN,
            });
        }

        ffi::init();
        let mut expanded = std::mem::MaybeUninit::uninit();
        // SAFETY: the key is exactly 128 bits and `expanded` points to writable,
        // correctly aligned storage which is read only after success.
        let status = unsafe {
            ffi::AES_set_encrypt_key(
                key.as_ptr(),
                (AES_128_KEY_LEN * 8) as c_uint,
                expanded.as_mut_ptr(),
            )
        };
        if status != 0 {
            return Err(CryptoError::BackendFailure("AES key expansion"));
        }

        // SAFETY: `AES_set_encrypt_key` returned success and initialized the
        // complete `AES_KEY` value above.
        Ok(Self(unsafe { expanded.assume_init() }))
    }

    pub(crate) fn mask(&self, sample: &[u8; AES_BLOCK_LEN]) -> [u8; 5] {
        let mut encrypted = [0; AES_BLOCK_LEN];
        // SAFETY: input and output are distinct 16-byte arrays and `self.0`
        // remains initialized and immutably borrowed throughout the call.
        unsafe {
            ffi::AES_encrypt(sample.as_ptr(), encrypted.as_mut_ptr(), &self.0);
        }
        let mut mask = [0; 5];
        mask.copy_from_slice(&encrypted[..5]);
        encrypted.fill(0);
        mask
    }
}

impl fmt::Debug for AesHeaderCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AesHeaderCipher([REDACTED])")
    }
}

impl Drop for AesHeaderCipher {
    fn drop(&mut self) {
        // SAFETY: `self.0` is valid writable storage for exactly one `AES_KEY`;
        // cleansing happens only during drop after its last possible use.
        unsafe {
            ffi::OPENSSL_cleanse(
                std::ptr::addr_of_mut!(self.0).cast(),
                std::mem::size_of::<ffi::AES_KEY>(),
            );
        }
    }
}

// SAFETY: BoringSSL documents AES block encryption as read-only with respect
// to an initialized `AES_KEY`; the wrapper never exposes mutable access.
unsafe impl Send for AesHeaderCipher {}
// SAFETY: concurrent calls only read the fully initialized expanded key and
// write to caller-owned, non-overlapping output arrays.
unsafe impl Sync for AesHeaderCipher {}

pub(crate) struct Aes128GcmContext(NonNull<ffi::EVP_AEAD_CTX>);

impl Aes128GcmContext {
    pub(crate) fn new(key: &[u8]) -> Result<Self> {
        if key.len() != AES_128_KEY_LEN {
            return Err(CryptoError::InvalidKeyLength {
                actual: key.len(),
                expected: AES_128_KEY_LEN,
            });
        }

        ffi::init();
        // SAFETY: the algorithm pointer has static BoringSSL lifetime and the
        // key slice remains valid for the call. The returned allocation is
        // uniquely owned by this wrapper and freed in `Drop`.
        let pointer = unsafe {
            ffi::EVP_AEAD_CTX_new(
                ffi::EVP_aead_aes_128_gcm(),
                key.as_ptr(),
                key.len(),
                AES_GCM_TAG_LEN,
            )
        };
        NonNull::new(pointer)
            .map(Self)
            .ok_or(CryptoError::BackendFailure("AES-128-GCM initialization"))
    }

    pub(crate) fn seal(
        &self,
        nonce: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
        associated_data: &[u8],
    ) -> Result<usize> {
        validate_nonce(nonce)?;
        let required = plaintext_len.checked_add(AES_GCM_TAG_LEN).ok_or(
            CryptoError::InsufficientOutputCapacity {
                actual: buffer.len(),
                required: usize::MAX,
            },
        )?;
        if buffer.len() < required {
            return Err(CryptoError::InsufficientOutputCapacity {
                actual: buffer.len(),
                required,
            });
        }

        let mut written = 0;
        // SAFETY: the context is live; nonce length was checked; input aliases
        // output exactly as permitted by BoringSSL; `plaintext_len` is within
        // `buffer`, which has room for the full authentication tag; AAD is live.
        let status = unsafe {
            ffi::EVP_AEAD_CTX_seal(
                self.0.as_ptr(),
                buffer.as_mut_ptr(),
                &mut written,
                buffer.len(),
                nonce.as_ptr(),
                nonce.len(),
                buffer.as_ptr(),
                plaintext_len,
                associated_data.as_ptr(),
                associated_data.len(),
            )
        };
        if status != 1 || written != required {
            buffer.fill(0);
            return Err(CryptoError::BackendFailure("packet sealing"));
        }
        Ok(written)
    }

    pub(crate) fn open(
        &self,
        nonce: &[u8],
        buffer: &mut [u8],
        associated_data: &[u8],
    ) -> Result<usize> {
        validate_nonce(nonce)?;
        if buffer.len() < AES_GCM_TAG_LEN {
            return Err(CryptoError::InsufficientOutputCapacity {
                actual: buffer.len(),
                required: AES_GCM_TAG_LEN,
            });
        }

        let mut written = 0;
        // SAFETY: the context is live; nonce length was checked; input aliases
        // output exactly as permitted by BoringSSL; output capacity equals the
        // input length and AAD remains live for the duration of the call.
        let status = unsafe {
            ffi::EVP_AEAD_CTX_open(
                self.0.as_ptr(),
                buffer.as_mut_ptr(),
                &mut written,
                buffer.len(),
                nonce.as_ptr(),
                nonce.len(),
                buffer.as_ptr(),
                buffer.len(),
                associated_data.as_ptr(),
                associated_data.len(),
            )
        };
        if status != 1 {
            buffer.fill(0);
            return Err(CryptoError::AuthenticationFailed);
        }
        Ok(written)
    }
}

impl fmt::Debug for Aes128GcmContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Aes128GcmContext([REDACTED])")
    }
}

impl Drop for Aes128GcmContext {
    fn drop(&mut self) {
        // SAFETY: this wrapper uniquely owns the non-null context allocation;
        // `Drop` runs once and no references outlive `self`.
        unsafe {
            ffi::EVP_AEAD_CTX_free(self.0.as_ptr());
        }
    }
}

// SAFETY: the context is uniquely owned and BoringSSL documents all seal/open
// operations on one `EVP_AEAD_CTX` as safe to call concurrently.
unsafe impl Send for Aes128GcmContext {}
// SAFETY: shared operations do not mutate Rust-visible state, and BoringSSL's
// AEAD contract explicitly permits concurrent seal/open calls on one context.
unsafe impl Sync for Aes128GcmContext {}

fn validate_nonce(nonce: &[u8]) -> Result<()> {
    if nonce.len() != QUIC_NONCE_LEN {
        return Err(CryptoError::InvalidNonceLength {
            actual: nonce.len(),
            expected: QUIC_NONCE_LEN,
        });
    }
    Ok(())
}
