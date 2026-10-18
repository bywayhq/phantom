//! Built-in restrictions that retain native chain and hostname verification.

use std::{error::Error, fmt, ptr, sync::Arc};

use foreign_types::ForeignTypeRef;

use super::{
    CustomSessionVerifier, SessionVerifierProvenance, Ssl, SslContext, SslContextBuilder,
    SslContextRef, SslRef, SslVerifyMode,
};
use crate::{
    error::ErrorStack,
    ffi,
    sha::sha256,
    x509::{X509Ref, X509StoreContext, X509StoreContextRef, X509VerifyError},
};

/// An immutable OR set of SHA-256 hashes of leaf DER SubjectPublicKeyInfo.
///
/// Pins restrict normal certificate and hostname verification. They do not
/// replace roots or accept an otherwise invalid certificate. Sets are sorted
/// and deduplicated for policy binding. Debug output omits their values.
#[derive(Clone, Eq, PartialEq)]
pub struct SpkiPins(Arc<[[u8; 32]]>);

impl SpkiPins {
    /// Accepts one to 32 supplied digests, before removing duplicates.
    ///
    /// # Errors
    /// Returns an error for an empty or oversized input.
    pub fn new(mut digests: Vec<[u8; 32]>) -> Result<Self, SpkiPinConfigurationError> {
        if digests.is_empty() || digests.len() > 32 {
            return Err(SpkiPinConfigurationError::InvalidCount);
        }
        digests.sort_unstable();
        digests.dedup();
        Ok(Self(digests.into()))
    }

    /// Returns the canonical sorted, distinct digests for policy binding.
    #[must_use]
    pub fn sha256_digests(&self) -> &[[u8; 32]] {
        &self.0
    }
}

impl fmt::Debug for SpkiPins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpkiPins")
            .field("count", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// A pin set or native context that cannot install the built-in restriction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SpkiPinConfigurationError {
    /// Supply between one and 32 digests.
    InvalidCount,
    /// An arbitrary verifier is already installed on this context.
    CustomVerifier,
}

impl fmt::Display for SpkiPinConfigurationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidCount => "SPKI pins require one to 32 digests",
            Self::CustomVerifier => "SPKI pins cannot replace an arbitrary verifier",
        })
    }
}

impl Error for SpkiPinConfigurationError {}

/// Per-connection progress of the built-in leaf restriction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SpkiPinVerification {
    /// This context has no active built-in restriction.
    NotConfigured,
    /// Verification has not provided a result yet.
    Pending,
    /// The fresh leaf passed native verification and matched a configured pin.
    Matched,
    /// Resumption inherited authenticated proof under the same context and policy.
    Resumed,
    /// Native chain or hostname verification rejected the certificate.
    CertificateInvalid,
    /// The verified leaf matched no configured pin.
    Mismatch,
    /// Native verification or SPKI encoding failed internally.
    BackendFailure,
    /// ECH public-name authentication must complete as an ECH rejection.
    EchRejected,
}

impl SslContextBuilder {
    /// Restricts native client verification to the supplied leaf SPKI hashes.
    ///
    /// Installs PEER verification. The native-prepared store retains roots,
    /// purpose, hostname parameters and ECH public-name handling. Do not replace
    /// verification after installation. Native contexts must be immutable once
    /// shared. This restriction supports client verification only.
    ///
    /// Ordinary certificate verification does not rerun during resumption.
    /// Scoped sessions therefore require authenticated source proof before
    /// attachment. Portable session owners must bind these canonical pins and
    /// the selected peer identity into their complete policy descriptor.
    ///
    /// # Errors
    /// Returns an error without changing a context with an arbitrary verifier.
    ///
    /// # Panics
    /// Panics for a raw-public-key context, like native X509 verification setters.
    pub fn set_spki_pins(&mut self, pins: SpkiPins) -> Result<(), SpkiPinConfigurationError> {
        if !matches!(
            self.ctx
                .ex_data(SslContext::cached_ex_index::<SessionVerifierProvenance>()),
            Some(SessionVerifierProvenance::Default | SessionVerifierProvenance::SpkiPins)
        ) {
            return Err(SpkiPinConfigurationError::CustomVerifier);
        }
        self.set_verify(SslVerifyMode::PEER);
        let verifier_pins = pins.clone();
        self.set_cert_verify_callback(move |context| verify(context, &verifier_pins));
        let epoch = self.ctx.transfer_context_epoch();
        let _mutation = epoch.as_ref().map(|epoch| epoch.mutate());
        self.replace_ex_data(SslContext::cached_ex_index::<SpkiPins>(), pins);
        self.replace_ex_data(
            SslContext::cached_ex_index::<SessionVerifierProvenance>(),
            SessionVerifierProvenance::SpkiPins,
        );
        Ok(())
    }
}

impl SslContextRef {
    /// Returns pins only while the built-in restriction remains the verifier.
    #[must_use]
    pub fn spki_pins(&self) -> Option<&SpkiPins> {
        matches!(
            self.ex_data(SslContext::cached_ex_index::<SessionVerifierProvenance>()),
            Some(SessionVerifierProvenance::SpkiPins)
        )
        .then(|| self.ex_data(SslContext::cached_ex_index::<SpkiPins>()))
        .flatten()
    }
}

impl SslRef {
    /// Returns this connection's pin result, without sharing outcomes with peers.
    #[must_use]
    pub fn spki_pin_verification(&self) -> SpkiPinVerification {
        if self.ssl_context().spki_pins().is_none() {
            return SpkiPinVerification::NotConfigured;
        }
        if self.spki_resumption_authenticated() {
            return SpkiPinVerification::Resumed;
        }
        self.ex_data(Ssl::cached_ex_index::<SpkiPinVerification>())
            .copied()
            .unwrap_or(SpkiPinVerification::Pending)
    }

    pub(super) fn spki_pins_allow_session_publication(&self) -> bool {
        self.ssl_context().spki_pins().is_none()
            || matches!(
                self.spki_pin_verification(),
                SpkiPinVerification::Matched | SpkiPinVerification::Resumed
            )
    }
}

fn record(context: &mut X509StoreContextRef, result: SpkiPinVerification) -> bool {
    let Ok(index) = X509StoreContext::ssl_idx() else {
        return false;
    };
    let Some(ssl) = context.ex_data_mut(index) else {
        return false;
    };
    ssl.set_ex_data(Ssl::cached_ex_index::<SpkiPinVerification>(), result);
    true
}

fn reject(context: &mut X509StoreContextRef, result: SpkiPinVerification) -> bool {
    context.set_error(Err(X509VerifyError::APPLICATION_VERIFICATION));
    let _ = record(context, result);
    false
}

fn verify(context: &mut X509StoreContextRef, pins: &SpkiPins) -> bool {
    let ssl_index = match X509StoreContext::ssl_idx() {
        Ok(index) => index,
        Err(_) => return reject(context, SpkiPinVerification::BackendFailure),
    };
    let Some(ssl) = context.ex_data(ssl_index) else {
        return reject(context, SpkiPinVerification::BackendFailure);
    };
    if ssl.is_server()
        || !ssl.verify_mode().contains(SslVerifyMode::PEER)
        || ssl
            .ex_data(Ssl::cached_ex_index::<CustomSessionVerifier>())
            .is_some()
    {
        return reject(context, SpkiPinVerification::BackendFailure);
    }
    match context.verify_cert() {
        Ok(true) if context.verify_result().is_ok() => {}
        Ok(_) => {
            let _ = record(context, SpkiPinVerification::CertificateInvalid);
            return false;
        }
        Err(_) => return reject(context, SpkiPinVerification::BackendFailure),
    }
    if context
        .ex_data(ssl_index)
        .is_some_and(|ssl| ssl.get_ech_name_override().is_some())
    {
        // The public-name certificate authenticates retry configuration only.
        return record(context, SpkiPinVerification::EchRejected);
    }
    let digest = context.cert().and_then(|leaf| spki_sha256(leaf).ok());
    let Some(digest) = digest else {
        return reject(context, SpkiPinVerification::BackendFailure);
    };
    if !pins.0.iter().any(|pin| crate::memcmp::eq(pin, &digest)) {
        return reject(context, SpkiPinVerification::Mismatch);
    }
    record(context, SpkiPinVerification::Matched)
}

fn spki_sha256(certificate: &X509Ref) -> Result<[u8; 32], ErrorStack> {
    // SAFETY: the immutable certificate keeps the borrowed X509_PUBKEY alive.
    // The first encode measures its fixed DER length. The second receives that
    // much writable storage; it neither owns nor frees the borrowed key.
    unsafe {
        let key = crate::cvt_p(ffi::X509_get_X509_PUBKEY(certificate.as_ptr()))?;
        let length = crate::cvt_nz(ffi::i2d_X509_PUBKEY(key, ptr::null_mut()))?.get();
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| ErrorStack::get())?;
        bytes.resize(length, 0);
        let encoded = crate::cvt_nz(ffi::i2d_X509_PUBKEY(key, &mut bytes.as_mut_ptr()))?.get();
        if encoded != length {
            return Err(ErrorStack::get());
        }
        Ok(sha256(&bytes))
    }
}

#[cfg(test)]
mod tests;
