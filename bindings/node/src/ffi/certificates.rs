//! Parsed client identities and synchronous custody of certificate inputs.

use std::fmt;

use napi::{
    Env, Result,
    bindgen_prelude::{AsyncBlock, AsyncBlockBuilder, Buffer, Reference},
};
use napi_derive::napi;
use zeroize::Zeroizing;

use super::{
    buffer::{buffer_info, copy_buffer_info},
    options::ClientOptions,
};
use crate::error::failure;

/// Immutable parsed certificate/key owner; no key export or mutable access.
#[derive(Debug)]
#[napi]
pub struct NativeClientCertificate {
    inner: phantom::ClientCertificate,
}

/// One ordered native client identity mapping.
#[napi(object)]
pub struct ClientCertificateOrigin {
    /// HTTPS or WSS origin, validated by the core.
    pub origin: String,
    /// Authentic parsed native identity.
    pub certificate: Reference<NativeClientCertificate>,
}

impl fmt::Debug for ClientCertificateOrigin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientCertificateOrigin")
            .finish_non_exhaustive()
    }
}

pub(super) fn client_certificates(
    options: &mut ClientOptions,
) -> Result<crate::client_certificate::Certificates> {
    use crate::client_certificate::{MAXIMUM_BYTES, MAXIMUM_ORIGIN_BYTES, MAXIMUM_ORIGINS};
    let origins = options.client_certificates_for.take().unwrap_or_default();
    if origins.len() > MAXIMUM_ORIGINS {
        return Err(failure(
            "InvalidArgument",
            "clientCertificatesFor exceeds 256 origins",
        ));
    }
    let mut total = 0_usize;
    for pair in &origins {
        total = total.saturating_add(pair.origin.len());
        if pair.origin.len() > MAXIMUM_ORIGIN_BYTES || total > MAXIMUM_BYTES {
            return Err(failure(
                "InputLimit",
                "clientCertificatesFor exceeds its byte limit",
            ));
        }
    }
    Ok(crate::client_certificate::Certificates {
        default: options
            .client_certificate
            .take()
            .map(|certificate| certificate.inner.clone()),
        origins: origins
            .into_iter()
            .map(|pair| (pair.origin, pair.certificate.inner.clone()))
            .collect(),
    })
}

type CertificateInputs = (Vec<Vec<u8>>, Zeroizing<Vec<u8>>);

fn certificate_inputs(env: &Env, chain: Vec<Buffer>, key: Buffer) -> Result<CertificateInputs> {
    use crate::client_certificate::{MAXIMUM_BYTES, size};
    // Validate actual backing and all extents before allocating any byte copy.
    // These pointers stay in this synchronous Env call, with no JS or await.
    let key = buffer_info(env, key)?;
    let chain = chain
        .into_iter()
        .map(|value| buffer_info(env, value))
        .collect::<Result<Vec<_>>>()?;
    let total = chain
        .iter()
        .fold(key.1, |total, value| total.saturating_add(value.1));
    size(total)?;
    let key = Zeroizing::new(copy_buffer_info(key, MAXIMUM_BYTES)?);
    let chain = chain
        .into_iter()
        .map(|value| copy_buffer_info(value, MAXIMUM_BYTES))
        .collect::<Result<Vec<_>>>()?;
    Ok((chain, key))
}

/// Copies PEM inputs on their Env, then parses off the JavaScript thread.
#[napi]
pub fn client_certificate_pem(
    env: Env,
    chain: Buffer,
    key: Buffer,
) -> Result<AsyncBlock<NativeClientCertificate>> {
    let (chain, key) = certificate_inputs(&env, vec![chain], key)?;
    AsyncBlockBuilder::new(async move {
        crate::client_certificate::parse(chain, key, true)
            .await
            .map(|inner| NativeClientCertificate { inner })
    })
    .build(&env)
}

/// Parses an explicitly ordered DER chain and unencrypted DER private key.
#[napi]
pub fn client_certificate_der(
    env: Env,
    chain: Vec<Buffer>,
    key: Buffer,
) -> Result<AsyncBlock<NativeClientCertificate>> {
    if chain.is_empty() || chain.len() > crate::client_certificate::MAXIMUM_CERTIFICATES {
        return Err(crate::client_certificate::failure("invalid_chain_count"));
    }
    let (chain, key) = certificate_inputs(&env, chain, key)?;
    AsyncBlockBuilder::new(async move {
        crate::client_certificate::parse(chain, key, false)
            .await
            .map(|inner| NativeClientCertificate { inner })
    })
    .build(&env)
}
