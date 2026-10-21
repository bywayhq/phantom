//! Parsed native TLS identities; private keys are never exported.

use std::error::Error as _;

use napi::{Error, Result, Status};
use phantom::{BuildError, ClientCertificate, ClientCertificateError, ClientCertificateErrorKind};
use zeroize::Zeroizing;

pub(crate) const MAXIMUM_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAXIMUM_CERTIFICATES: usize = 256;
pub(crate) const MAXIMUM_ORIGINS: usize = 256;
pub(crate) const MAXIMUM_ORIGIN_BYTES: usize = 64 * 1024;

#[derive(Default)]
pub(crate) struct Certificates {
    pub(crate) default: Option<ClientCertificate>,
    pub(crate) origins: Vec<(String, ClientCertificate)>,
}

impl std::fmt::Debug for Certificates {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Certificates")
            .field("has_default", &self.default.is_some())
            .field("origin_count", &self.origins.len())
            .finish()
    }
}

pub(crate) fn failure(kind: &str) -> Error {
    Error::new(
        Status::GenericFailure,
        format!("PHANTOM_CERTIFICATE:{kind}:client certificate configuration failed"),
    )
}

pub(crate) fn core_error(error: &ClientCertificateError) -> Error {
    failure(match error.kind() {
        ClientCertificateErrorKind::Certificate => "certificate",
        ClientCertificateErrorKind::PrivateKey => "private_key",
        ClientCertificateErrorKind::KeyMismatch => "key_mismatch",
        ClientCertificateErrorKind::SignatureScheme => "signature_scheme",
        _ => "unsupported_certificate_error",
    })
}

pub(crate) fn build_error(error: BuildError) -> Error {
    if let Some(cause) = error.source().and_then(|cause| cause.downcast_ref()) {
        core_error(cause)
    } else {
        crate::error::failure(&format!("{:?}", error.kind()), &error.to_string())
    }
}

pub(crate) fn size(total: usize) -> Result<()> {
    if total > MAXIMUM_BYTES {
        return Err(failure("too_large"));
    }
    Ok(())
}

pub(crate) async fn parse(
    chain: Vec<Vec<u8>>,
    key: Zeroizing<Vec<u8>>,
    pem: bool,
) -> Result<ClientCertificate> {
    // Only bounded native-owned inputs enter CPU work. Cancellation drops an
    // unpublished result; it does not preempt the parser already running.
    tokio::task::spawn_blocking(move || {
        let result = if pem {
            ClientCertificate::from_pem(
                chain
                    .first()
                    .ok_or_else(|| failure("invalid_chain_count"))?,
                &key,
            )
        } else {
            ClientCertificate::from_der(chain.iter().map(Vec::as_slice), &key)
        };
        result.map_err(|error| core_error(&error))
    })
    .await
    .map_err(|_| failure("backend"))?
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parser_keeps_exact_categories_without_input_text() -> Result<()> {
        let chain = include_bytes!("../tests/fixtures/certificate.pem").to_vec();
        let key = include_bytes!("../tests/fixtures/key.pem").to_vec();
        let owner = parse(vec![chain.clone()], Zeroizing::new(key.clone()), true).await?;
        assert_eq!(
            format!("{owner:?}"),
            "ClientCertificate { intermediate_count: 0, .. }"
        );
        for (chain, key, kind) in [
            (b"private supplied input".to_vec(), key, "certificate"),
            (chain, b"private supplied input".to_vec(), "private_key"),
        ] {
            let error = parse(vec![chain], Zeroizing::new(key), true).await.err();
            assert!(error.is_some_and(|error| error.reason
                == format!("PHANTOM_CERTIFICATE:{kind}:client certificate configuration failed")));
        }
        assert!(size(MAXIMUM_BYTES).is_ok());
        assert!(size(MAXIMUM_BYTES + 1).is_err());
        Ok(())
    }
}
