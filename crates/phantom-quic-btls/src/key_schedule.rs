#[cfg(test)]
use std::cell::Cell;
use std::fmt;

use crate::backend::HkdfDigest;
use crate::hkdf::expand_label;
use crate::secret::{
    AES_128_KEY_LEN, AES_256_KEY_LEN, CHACHA20_KEY_LEN, QUIC_NONCE_LEN, SHA256_LEN, Secret,
};
use crate::{CryptoError, HeaderProtectionKey, PacketProtectionKey, Result};

#[allow(dead_code, reason = "BoringSSL traffic-secret callback input")]
const TLS_AES_128_GCM_SHA256: u16 = 0x1301;
#[allow(dead_code, reason = "BoringSSL traffic-secret callback input")]
const TLS_AES_256_GCM_SHA384: u16 = 0x1302;
#[allow(dead_code, reason = "BoringSSL traffic-secret callback input")]
const TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;
#[allow(dead_code, reason = "SHA-384 QUIC traffic-secret storage")]
const SHA384_LEN: usize = 48;

/// Which endpoint owns the local half of a derived key pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointSide {
    /// The local endpoint initiated the connection.
    Client,
    /// The local endpoint accepted the connection.
    Server,
}

/// Packet and header keys for one direction of a QUIC packet space.
pub struct DirectionKeys {
    header: HeaderProtectionKey,
    packet: PacketProtectionKey,
}

impl DirectionKeys {
    /// Returns the header-protection key.
    #[must_use]
    pub const fn header(&self) -> &HeaderProtectionKey {
        &self.header
    }

    /// Returns the packet-protection key.
    #[must_use]
    pub const fn packet(&self) -> &PacketProtectionKey {
        &self.packet
    }

    pub(crate) fn into_parts(self) -> (HeaderProtectionKey, PacketProtectionKey) {
        (self.header, self.packet)
    }
}

impl fmt::Debug for DirectionKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DirectionKeys([REDACTED])")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code, reason = "BoringSSL traffic-secret callback input")]
pub(crate) enum CipherSuite {
    Aes128GcmSha256,
    Aes256GcmSha384,
    ChaCha20Poly1305Sha256,
}

impl CipherSuite {
    #[allow(dead_code, reason = "BoringSSL traffic-secret callback input")]
    pub(crate) fn from_id(id: u16) -> Result<Self> {
        match id {
            TLS_AES_128_GCM_SHA256 => Ok(Self::Aes128GcmSha256),
            TLS_AES_256_GCM_SHA384 => Ok(Self::Aes256GcmSha384),
            TLS_CHACHA20_POLY1305_SHA256 => Ok(Self::ChaCha20Poly1305Sha256),
            _ => Err(CryptoError::UnsupportedCipherSuite { id }),
        }
    }

    pub(crate) const fn digest(self) -> HkdfDigest {
        match self {
            Self::Aes128GcmSha256 | Self::ChaCha20Poly1305Sha256 => HkdfDigest::Sha256,
            Self::Aes256GcmSha384 => HkdfDigest::Sha384,
        }
    }

    const fn key_len(self) -> usize {
        match self {
            Self::Aes128GcmSha256 => AES_128_KEY_LEN,
            Self::Aes256GcmSha384 => AES_256_KEY_LEN,
            Self::ChaCha20Poly1305Sha256 => CHACHA20_KEY_LEN,
        }
    }

    fn packet_key(self, key: &[u8], iv: &[u8]) -> Result<PacketProtectionKey> {
        match self {
            Self::Aes128GcmSha256 => PacketProtectionKey::aes_128_gcm(key, iv),
            Self::Aes256GcmSha384 => PacketProtectionKey::aes_256_gcm(key, iv),
            Self::ChaCha20Poly1305Sha256 => PacketProtectionKey::chacha20_poly1305(key, iv),
        }
    }

    fn header_key(self, key: &[u8]) -> Result<HeaderProtectionKey> {
        match self {
            Self::Aes128GcmSha256 => HeaderProtectionKey::aes_128(key),
            Self::Aes256GcmSha384 => HeaderProtectionKey::aes_256(key),
            Self::ChaCha20Poly1305Sha256 => HeaderProtectionKey::chacha20(key),
        }
    }
}

struct KeyMaterial {
    key: Secret<AES_256_KEY_LEN>,
    key_len: usize,
    iv: Secret<QUIC_NONCE_LEN>,
    header: Secret<AES_256_KEY_LEN>,
}

impl KeyMaterial {
    fn derive(suite: CipherSuite, traffic_secret: &[u8]) -> Result<Self> {
        let expected = suite.digest().output_len();
        if traffic_secret.len() != expected {
            return Err(CryptoError::InvalidKeyLength {
                actual: traffic_secret.len(),
                expected,
            });
        }

        let key_len = suite.key_len();
        let mut key = Secret::<AES_256_KEY_LEN>::zeroed();
        expand_label(
            suite.digest(),
            traffic_secret,
            b"quic key",
            &[],
            &mut key.as_mut_slice()[..key_len],
        )?;
        let mut iv = Secret::<QUIC_NONCE_LEN>::zeroed();
        expand_label(
            suite.digest(),
            traffic_secret,
            b"quic iv",
            &[],
            iv.as_mut_slice(),
        )?;
        let mut header = Secret::<AES_256_KEY_LEN>::zeroed();
        expand_label(
            suite.digest(),
            traffic_secret,
            b"quic hp",
            &[],
            &mut header.as_mut_slice()[..key_len],
        )?;
        Ok(Self {
            key,
            key_len,
            iv,
            header,
        })
    }

    fn into_keys(self, suite: CipherSuite) -> Result<DirectionKeys> {
        Ok(DirectionKeys {
            header: suite.header_key(&self.header.as_slice()[..self.key_len])?,
            packet: suite.packet_key(&self.key.as_slice()[..self.key_len], self.iv.as_slice())?,
        })
    }

    #[allow(dead_code, reason = "QUIC 1-RTT key updates")]
    fn into_packet_key(self, suite: CipherSuite) -> Result<PacketProtectionKey> {
        suite.packet_key(&self.key.as_slice()[..self.key_len], self.iv.as_slice())
    }
}

pub(crate) fn derive_direction_keys(
    suite: CipherSuite,
    traffic_secret: &[u8],
) -> Result<DirectionKeys> {
    KeyMaterial::derive(suite, traffic_secret)?.into_keys(suite)
}

#[allow(dead_code, reason = "QUIC traffic-secret storage")]
pub(crate) enum TrafficSecret {
    Sha256(Secret<SHA256_LEN>),
    Sha384(Secret<SHA384_LEN>),
}

#[allow(dead_code, reason = "QUIC traffic-secret storage and updates")]
impl TrafficSecret {
    pub(crate) fn new(digest: HkdfDigest, value: &[u8]) -> Result<Self> {
        match digest {
            HkdfDigest::Sha256 => Ok(Self::Sha256(Secret::copy_from_slice(value)?)),
            HkdfDigest::Sha384 => Ok(Self::Sha384(Secret::copy_from_slice(value)?)),
        }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        match self {
            Self::Sha256(secret) => secret.as_slice(),
            Self::Sha384(secret) => secret.as_slice(),
        }
    }

    fn next(&self) -> Result<Self> {
        match self {
            Self::Sha256(secret) => {
                let mut next = Secret::<SHA256_LEN>::zeroed();
                expand_label(
                    HkdfDigest::Sha256,
                    secret.as_slice(),
                    b"quic ku",
                    &[],
                    next.as_mut_slice(),
                )?;
                Ok(Self::Sha256(next))
            }
            Self::Sha384(secret) => {
                let mut next = Secret::<SHA384_LEN>::zeroed();
                expand_label(
                    HkdfDigest::Sha384,
                    secret.as_slice(),
                    b"quic ku",
                    &[],
                    next.as_mut_slice(),
                )?;
                Ok(Self::Sha384(next))
            }
        }
    }
}

impl fmt::Debug for TrafficSecret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrafficSecret([REDACTED])")
    }
}

#[allow(dead_code, reason = "QUIC traffic-key installation")]
pub(crate) struct TrafficKeys {
    pub(crate) local: DirectionKeys,
    pub(crate) remote: DirectionKeys,
}

impl fmt::Debug for TrafficKeys {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrafficKeys([REDACTED])")
    }
}

#[allow(dead_code, reason = "QUIC traffic-key updates")]
pub(crate) struct PacketKeyPair {
    pub(crate) local: PacketProtectionKey,
    pub(crate) remote: PacketProtectionKey,
}

impl fmt::Debug for PacketKeyPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PacketKeyPair([REDACTED])")
    }
}

/// Owns the application traffic secrets needed for QUIC key updates.
#[allow(dead_code, reason = "QUIC traffic-key installation and updates")]
pub(crate) struct TrafficKeySchedule {
    suite: CipherSuite,
    local: TrafficSecret,
    remote: TrafficSecret,
    #[cfg(test)]
    derivation_failure: Cell<Option<TestDerivationFailure>>,
    #[cfg(test)]
    update_attempts: Cell<usize>,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TestDerivationStage {
    CurrentLocalKeys,
    CurrentRemoteKeys,
    NextLocalSecret,
    NextRemoteSecret,
    NextLocalPacketKey,
    NextRemotePacketKey,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TestDerivationFailure {
    stage: TestDerivationStage,
    update_attempt: usize,
}

#[cfg(test)]
impl TestDerivationFailure {
    pub(crate) const fn current(stage: TestDerivationStage) -> Self {
        Self {
            stage,
            update_attempt: 0,
        }
    }

    pub(crate) const fn update(stage: TestDerivationStage, attempt: usize) -> Self {
        Self {
            stage,
            update_attempt: attempt,
        }
    }
}

#[allow(dead_code, reason = "QUIC traffic-key installation and updates")]
impl TrafficKeySchedule {
    pub(crate) fn new(
        cipher_suite: u16,
        side: EndpointSide,
        client_secret: &[u8],
        server_secret: &[u8],
    ) -> Result<Self> {
        let suite = CipherSuite::from_id(cipher_suite)?;
        let client = TrafficSecret::new(suite.digest(), client_secret)?;
        let server = TrafficSecret::new(suite.digest(), server_secret)?;
        let (local, remote) = match side {
            EndpointSide::Client => (client, server),
            EndpointSide::Server => (server, client),
        };
        Ok(Self {
            suite,
            local,
            remote,
            #[cfg(test)]
            derivation_failure: Cell::new(None),
            #[cfg(test)]
            update_attempts: Cell::new(0),
        })
    }

    pub(crate) fn from_local_remote(
        cipher_suite: u16,
        local: TrafficSecret,
        remote: TrafficSecret,
    ) -> Result<Self> {
        let suite = CipherSuite::from_id(cipher_suite)?;
        let expected = suite.digest().output_len();
        if local.as_slice().len() != expected {
            return Err(CryptoError::InvalidKeyLength {
                actual: local.as_slice().len(),
                expected,
            });
        }
        if remote.as_slice().len() != expected {
            return Err(CryptoError::InvalidKeyLength {
                actual: remote.as_slice().len(),
                expected,
            });
        }
        Ok(Self {
            suite,
            local,
            remote,
            #[cfg(test)]
            derivation_failure: Cell::new(None),
            #[cfg(test)]
            update_attempts: Cell::new(0),
        })
    }

    pub(crate) fn keys(&self) -> Result<TrafficKeys> {
        #[cfg(test)]
        self.fail_derivation(TestDerivationStage::CurrentLocalKeys, 0)?;
        let local = derive_direction_keys(self.suite, self.local.as_slice())?;
        #[cfg(test)]
        self.fail_derivation(TestDerivationStage::CurrentRemoteKeys, 0)?;
        let remote = derive_direction_keys(self.suite, self.remote.as_slice())?;
        Ok(TrafficKeys { local, remote })
    }

    /// Advances both directions transactionally and returns the new packet keys.
    ///
    /// This operation remains fallible because HKDF and key construction can
    /// fail. It must not implement Quinn's infallible `next_1rtt_keys` boundary
    /// until the Session provider establishes explicit fail-closed propagation
    /// or precomputes a successful next pair before Quinn can request it.
    pub(crate) fn next_packet_keys(&mut self) -> Result<PacketKeyPair> {
        #[cfg(test)]
        let attempt = {
            let attempt = self.update_attempts.get() + 1;
            self.update_attempts.set(attempt);
            attempt
        };
        #[cfg(test)]
        self.fail_derivation(TestDerivationStage::NextLocalSecret, attempt)?;
        let next_local = self.local.next()?;
        #[cfg(test)]
        self.fail_derivation(TestDerivationStage::NextRemoteSecret, attempt)?;
        let next_remote = self.remote.next()?;
        #[cfg(test)]
        self.fail_derivation(TestDerivationStage::NextLocalPacketKey, attempt)?;
        let local =
            KeyMaterial::derive(self.suite, next_local.as_slice())?.into_packet_key(self.suite)?;
        #[cfg(test)]
        self.fail_derivation(TestDerivationStage::NextRemotePacketKey, attempt)?;
        let remote =
            KeyMaterial::derive(self.suite, next_remote.as_slice())?.into_packet_key(self.suite)?;
        self.local = next_local;
        self.remote = next_remote;
        Ok(PacketKeyPair { local, remote })
    }

    #[cfg(test)]
    pub(crate) fn inject_derivation_failure(&self, failure: TestDerivationFailure) {
        self.derivation_failure.set(Some(failure));
    }

    #[cfg(test)]
    fn fail_derivation(&self, stage: TestDerivationStage, update_attempt: usize) -> Result<()> {
        if self.derivation_failure.get()
            == Some(TestDerivationFailure {
                stage,
                update_attempt,
            })
        {
            self.derivation_failure.set(None);
            return Err(CryptoError::BackendFailure("injected key derivation"));
        }
        Ok(())
    }
}

impl fmt::Debug for TrafficKeySchedule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("TrafficKeySchedule([REDACTED])")
    }
}

#[cfg(test)]
mod tests;
