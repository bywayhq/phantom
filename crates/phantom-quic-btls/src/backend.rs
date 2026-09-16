//! The complete FFI boundary for QUIC cryptography primitives.

use std::ffi::{c_uint, c_void};
use std::fmt;
use std::ptr::NonNull;

use btls_sys as ffi;

use crate::secret::{
    AES_128_KEY_LEN, AES_256_KEY_LEN, CHACHA20_KEY_LEN, QUIC_NONCE_LEN, SHA256_LEN, Secret,
};
use crate::{CryptoError, Result};

const AES_BLOCK_LEN: usize = 16;
const AEAD_TAG_LEN: usize = 16;

#[allow(dead_code, reason = "private QUIC callback bridge")]
mod callback_state;
pub(super) mod client;
#[allow(dead_code, reason = "private BoringSSL QUIC client session")]
mod client_session;
#[allow(dead_code, reason = "private QUIC callback bridge")]
mod quic_callbacks;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HkdfDigest {
    Sha256,
    Sha384,
}

impl HkdfDigest {
    pub(crate) const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    fn evp_md(self) -> *const ffi::EVP_MD {
        // SAFETY: both functions return pointers to immutable, process-lifetime
        // digest descriptors owned by BoringSSL.
        unsafe {
            match self {
                Self::Sha256 => ffi::EVP_sha256(),
                Self::Sha384 => ffi::EVP_sha384(),
            }
        }
    }
}

pub(crate) fn random_bytes(output: &mut [u8]) -> Result<()> {
    ffi::init();
    // SAFETY: `output` is writable for exactly `output.len()` bytes and remains
    // exclusively borrowed for the duration of the call. BoringSSL's default
    // CSPRNG obtains its entropy from the operating system.
    let status = unsafe { ffi::RAND_bytes(output.as_mut_ptr(), output.len()) };
    if status != 1 {
        drain_error_queue();
        output.fill(0);
        return Err(CryptoError::BackendFailure("random key generation"));
    }
    Ok(())
}

pub(crate) fn hmac_sha256(key: &[u8], data: &[u8], output: &mut [u8; SHA256_LEN]) -> Result<()> {
    ffi::init();
    let mut written = 0;
    // SAFETY: key and data point to readable storage for their stated lengths;
    // output is a distinct writable SHA-256-sized array. BoringSSL documents
    // that `HMAC` writes at most the selected digest's output size.
    let result = unsafe {
        ffi::HMAC(
            ffi::EVP_sha256(),
            key.as_ptr().cast::<c_void>(),
            key.len(),
            data.as_ptr(),
            data.len(),
            output.as_mut_ptr(),
            &mut written,
        )
    };
    if result != output.as_mut_ptr() || written != SHA256_LEN as c_uint {
        drain_error_queue();
        output.fill(0);
        return Err(CryptoError::BackendFailure("HMAC-SHA-256 signing"));
    }
    Ok(())
}

pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    // SAFETY: both pointers reference readable slices of the same checked
    // length for the duration of the call. `CRYPTO_memcmp` does not write.
    unsafe { ffi::CRYPTO_memcmp(left.as_ptr().cast(), right.as_ptr().cast(), left.len()) == 0 }
}

fn drain_error_queue() {
    // SAFETY: `ERR_clear_error` only clears BoringSSL's current-thread error
    // queue and accepts no pointers. Queue contents are intentionally ignored.
    unsafe {
        ffi::ERR_clear_error();
    }
}

#[cfg(test)]
pub(crate) fn error_queue_is_empty() -> bool {
    // SAFETY: `ERR_peek_error` reads the current thread's queue without
    // removing entries and accepts no pointers.
    unsafe { ffi::ERR_peek_error() == 0 }
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
            HkdfDigest::Sha256.evp_md(),
            ikm.as_ptr(),
            ikm.len(),
            salt.as_ptr(),
            salt.len(),
        )
    };
    if status != 1 || written != SHA256_LEN {
        drain_error_queue();
        output.fill(0);
        return Err(CryptoError::BackendFailure("HKDF extract"));
    }
    Ok(())
}

pub(crate) fn hkdf_expand(
    digest: HkdfDigest,
    prk: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<()> {
    ffi::init();
    // SAFETY: all pointers come from live, non-overlapping slices for the
    // duration of the call; BoringSSL writes exactly `output.len()` bytes.
    let status = unsafe {
        ffi::HKDF_expand(
            output.as_mut_ptr(),
            output.len(),
            digest.evp_md(),
            prk.as_ptr(),
            prk.len(),
            info.as_ptr(),
            info.len(),
        )
    };
    if status != 1 {
        drain_error_queue();
        output.fill(0);
        return Err(CryptoError::BackendFailure("HKDF expand"));
    }
    Ok(())
}

pub(crate) struct AesHeaderCipher(ffi::AES_KEY);

impl AesHeaderCipher {
    pub(crate) fn new(key: &[u8]) -> Result<Self> {
        Self::expand(key, AES_128_KEY_LEN)
    }

    pub(crate) fn new_256(key: &[u8]) -> Result<Self> {
        Self::expand(key, AES_256_KEY_LEN)
    }

    fn expand(key: &[u8], expected_len: usize) -> Result<Self> {
        if key.len() != expected_len {
            return Err(CryptoError::InvalidKeyLength {
                actual: key.len(),
                expected: expected_len,
            });
        }

        ffi::init();
        let mut expanded = std::mem::MaybeUninit::uninit();
        // SAFETY: the key is exactly 128 or 256 bits and `expanded` points to
        // writable, correctly aligned storage which is read only after success.
        let status = unsafe {
            ffi::AES_set_encrypt_key(
                key.as_ptr(),
                (expected_len * 8) as c_uint,
                expanded.as_mut_ptr(),
            )
        };
        if status != 0 {
            drain_error_queue();
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

pub(crate) struct ChaChaHeaderCipher {
    key: Secret<CHACHA20_KEY_LEN>,
}

impl ChaChaHeaderCipher {
    pub(crate) fn new(key: &[u8]) -> Result<Self> {
        Ok(Self {
            key: Secret::copy_from_slice(key)?,
        })
    }

    pub(crate) fn mask(&self, sample: &[u8; AES_BLOCK_LEN]) -> [u8; 5] {
        let mut counter_bytes = [0; 4];
        counter_bytes.copy_from_slice(&sample[..4]);
        let counter = u32::from_le_bytes(counter_bytes);
        let nonce = &sample[4..];
        let zeros = [0; 5];
        let mut mask = [0; 5];
        // SAFETY: output and input are distinct five-byte arrays, the key is
        // exactly 32 bytes, and the sample suffix is exactly a 12-byte nonce.
        unsafe {
            ffi::CRYPTO_chacha_20(
                mask.as_mut_ptr(),
                zeros.as_ptr(),
                zeros.len(),
                self.key.as_slice().as_ptr(),
                nonce.as_ptr(),
                counter,
            );
        }
        mask
    }
}

impl fmt::Debug for ChaChaHeaderCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ChaChaHeaderCipher([REDACTED])")
    }
}

pub(crate) struct AeadContext(NonNull<ffi::EVP_AEAD_CTX>);

impl AeadContext {
    pub(crate) fn aes_128_gcm(key: &[u8]) -> Result<Self> {
        validate_key(key, AES_128_KEY_LEN)?;
        // SAFETY: the getter accepts no arguments and returns BoringSSL's
        // process-lifetime algorithm descriptor.
        let algorithm = unsafe { ffi::EVP_aead_aes_128_gcm() };
        Self::new(key, algorithm, "AES-128-GCM initialization")
    }

    pub(crate) fn aes_256_gcm(key: &[u8]) -> Result<Self> {
        validate_key(key, AES_256_KEY_LEN)?;
        // SAFETY: the getter accepts no arguments and returns BoringSSL's
        // process-lifetime algorithm descriptor.
        let algorithm = unsafe { ffi::EVP_aead_aes_256_gcm() };
        Self::new(key, algorithm, "AES-256-GCM initialization")
    }

    pub(crate) fn chacha20_poly1305(key: &[u8]) -> Result<Self> {
        validate_key(key, CHACHA20_KEY_LEN)?;
        // SAFETY: the getter accepts no arguments and returns BoringSSL's
        // process-lifetime algorithm descriptor.
        let algorithm = unsafe { ffi::EVP_aead_chacha20_poly1305() };
        Self::new(key, algorithm, "ChaCha20-Poly1305 initialization")
    }

    fn new(key: &[u8], algorithm: *const ffi::EVP_AEAD, operation: &'static str) -> Result<Self> {
        ffi::init();
        // SAFETY: the algorithm pointer has static BoringSSL lifetime and the
        // key slice remains valid for the call. The returned allocation is
        // uniquely owned by this wrapper and freed in `Drop`.
        let pointer =
            unsafe { ffi::EVP_AEAD_CTX_new(algorithm, key.as_ptr(), key.len(), AEAD_TAG_LEN) };
        match NonNull::new(pointer) {
            Some(pointer) => Ok(Self(pointer)),
            None => {
                drain_error_queue();
                Err(CryptoError::BackendFailure(operation))
            }
        }
    }

    pub(crate) fn seal(
        &self,
        nonce: &[u8],
        buffer: &mut [u8],
        plaintext_len: usize,
        associated_data: &[u8],
    ) -> Result<usize> {
        validate_nonce(nonce)?;
        let required = plaintext_len.checked_add(AEAD_TAG_LEN).ok_or(
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
            drain_error_queue();
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
        if buffer.len() < AEAD_TAG_LEN {
            return Err(CryptoError::InsufficientOutputCapacity {
                actual: buffer.len(),
                required: AEAD_TAG_LEN,
            });
        }
        let expected = buffer.len() - AEAD_TAG_LEN;

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
            drain_error_queue();
            buffer.fill(0);
            return Err(CryptoError::AuthenticationFailed);
        }
        if written != expected {
            drain_error_queue();
            buffer.fill(0);
            return Err(CryptoError::BackendFailure("packet opening"));
        }
        Ok(written)
    }
}

impl fmt::Debug for AeadContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AeadContext([REDACTED])")
    }
}

impl Drop for AeadContext {
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
unsafe impl Send for AeadContext {}
// SAFETY: shared operations do not mutate Rust-visible state, and BoringSSL's
// AEAD contract explicitly permits concurrent seal/open calls on one context.
unsafe impl Sync for AeadContext {}

fn validate_key(key: &[u8], expected: usize) -> Result<()> {
    if key.len() != expected {
        return Err(CryptoError::InvalidKeyLength {
            actual: key.len(),
            expected,
        });
    }
    Ok(())
}

fn validate_nonce(nonce: &[u8]) -> Result<()> {
    if nonce.len() != QUIC_NONCE_LEN {
        return Err(CryptoError::InvalidNonceLength {
            actual: nonce.len(),
            expected: QUIC_NONCE_LEN,
        });
    }
    Ok(())
}
