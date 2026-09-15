//! Backend-neutral TLS profile settings.

use std::{error::Error, fmt};

/// A TLS protocol version accepted by a transport.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum TlsVersion {
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
}

/// A TLS cipher suite in wire preference order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CipherSuite {
    /// TLS_AES_128_GCM_SHA256.
    Aes128GcmSha256,
    /// TLS_AES_256_GCM_SHA384.
    Aes256GcmSha384,
    /// TLS_CHACHA20_POLY1305_SHA256.
    Chacha20Poly1305Sha256,
    /// TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256.
    EcdheEcdsaAes128GcmSha256,
    /// TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256.
    EcdheRsaAes128GcmSha256,
    /// TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384.
    EcdheEcdsaAes256GcmSha384,
    /// TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384.
    EcdheRsaAes256GcmSha384,
    /// TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
    EcdheEcdsaChacha20Poly1305Sha256,
    /// TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256.
    EcdheRsaChacha20Poly1305Sha256,
    /// TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.
    EcdheRsaAes128CbcSha,
    /// TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA.
    EcdheRsaAes256CbcSha,
    /// TLS_RSA_WITH_AES_128_GCM_SHA256.
    RsaAes128GcmSha256,
    /// TLS_RSA_WITH_AES_256_GCM_SHA384.
    RsaAes256GcmSha384,
    /// TLS_RSA_WITH_AES_128_CBC_SHA.
    RsaAes128CbcSha,
    /// TLS_RSA_WITH_AES_256_CBC_SHA.
    RsaAes256CbcSha,
}

/// A TLS supported group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum NamedGroup {
    /// Hybrid X25519 and ML-KEM-768.
    X25519MlKem768,
    /// X25519.
    X25519,
    /// NIST P-256.
    Secp256r1,
    /// NIST P-384.
    Secp384r1,
}

/// A TLS signature scheme in wire preference order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SignatureScheme {
    /// ML-DSA-44.
    MlDsa44,
    /// ML-DSA-65.
    MlDsa65,
    /// ML-DSA-87.
    MlDsa87,
    /// ECDSA P-256 with SHA-256.
    EcdsaSecp256r1Sha256,
    /// RSA-PSS with an RSAE key and SHA-256.
    RsaPssRsaeSha256,
    /// RSA PKCS#1 v1.5 with SHA-256.
    RsaPkcs1Sha256,
    /// ECDSA P-384 with SHA-384.
    EcdsaSecp384r1Sha384,
    /// RSA-PSS with an RSAE key and SHA-384.
    RsaPssRsaeSha384,
    /// RSA PKCS#1 v1.5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSA-PSS with an RSAE key and SHA-512.
    RsaPssRsaeSha512,
    /// RSA PKCS#1 v1.5 with SHA-512.
    RsaPkcs1Sha512,
}

/// A certificate compression algorithm advertised by the TLS client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CertificateCompression {
    /// Brotli certificate compression.
    Brotli,
}

/// ALPS configuration for one ALPN protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlpsSettings {
    /// ALPN protocol identifier receiving application settings.
    pub protocol: Box<[u8]>,
    /// Whether to use the final ALPS extension codepoint.
    pub use_new_codepoint: bool,
}

/// Ordered TLS settings independent of the concrete TLS backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsSettings {
    /// Smallest accepted TLS version.
    pub min_version: TlsVersion,
    /// Largest accepted TLS version.
    pub max_version: TlsVersion,
    /// Cipher suites in preference order.
    pub cipher_suites: Vec<CipherSuite>,
    /// Supported groups in preference order.
    pub groups: Vec<NamedGroup>,
    /// Initial TLS 1.3 key shares in wire order.
    pub key_shares: Vec<NamedGroup>,
    /// Signature schemes in preference order.
    pub signature_schemes: Vec<SignatureScheme>,
    /// ALPN protocol identifiers in preference order.
    pub alpn_protocols: Vec<Box<[u8]>>,
    /// Optional ALPS advertisement.
    pub alps: Option<AlpsSettings>,
    /// Certificate compression algorithms in preference order.
    pub certificate_compression: Vec<CertificateCompression>,
    /// Optional trust anchor IDs advertised to guide server certificate selection.
    ///
    /// Each ID is an opaque, non-empty byte string. `None` omits the TLS
    /// `trust_anchors` extension, while `Some(Vec::new())` emits the extension
    /// with an empty ID list. This setting does not change certificate
    /// verification.
    pub requested_trust_anchors: Option<Vec<Box<[u8]>>>,
    /// Whether ordinary TLS GREASE is enabled.
    pub grease: bool,
    /// Whether signature-algorithm GREASE is enabled.
    pub grease_signature_algorithms: bool,
    /// Whether eligible ClientHello extensions are randomized.
    pub permute_extensions: bool,
    /// Whether to emit a GREASE ECH extension without an ECH configuration.
    pub ech_grease: bool,
    /// Whether to request an OCSP staple.
    pub request_ocsp_staple: bool,
    /// Whether to request signed certificate timestamps.
    pub request_signed_certificate_timestamps: bool,
    /// Whether the client should be treated as having AES hardware.
    pub aes_hardware: bool,
}

impl TlsSettings {
    /// Validates settings that are independent of a particular TLS backend.
    pub fn validate(&self) -> Result<(), InvalidTlsSettings> {
        if self.min_version > self.max_version {
            return Err(InvalidTlsSettings::new(
                "version range",
                "minimum TLS version exceeds maximum TLS version",
            ));
        }
        if self.cipher_suites.is_empty() {
            return Err(InvalidTlsSettings::new(
                "cipher_suites",
                "at least one cipher suite is required",
            ));
        }
        if self.groups.is_empty() {
            return Err(InvalidTlsSettings::new(
                "groups",
                "at least one supported group is required",
            ));
        }
        if self.max_version == TlsVersion::Tls12 {
            if !self.key_shares.is_empty() {
                return Err(InvalidTlsSettings::new(
                    "key_shares",
                    "initial key shares require TLS 1.3 to be enabled",
                ));
            }
            if self.ech_grease {
                return Err(InvalidTlsSettings::new(
                    "ech_grease",
                    "ECH GREASE requires TLS 1.3 to be enabled",
                ));
            }
            if self.requested_trust_anchors.is_some() {
                return Err(InvalidTlsSettings::new(
                    "requested_trust_anchors",
                    "requested trust anchors require TLS 1.3 to be enabled",
                ));
            }
        } else {
            if self.key_shares.is_empty() {
                return Err(InvalidTlsSettings::new(
                    "key_shares",
                    "at least one initial key share is required when TLS 1.3 is enabled",
                ));
            }
            if let Some(group) = self
                .key_shares
                .iter()
                .find(|group| !self.groups.contains(group))
            {
                return Err(InvalidTlsSettings::new(
                    "key_shares",
                    format!("key share {group:?} is absent from supported groups"),
                ));
            }
        }
        if self.signature_schemes.is_empty() {
            return Err(InvalidTlsSettings::new(
                "signature_schemes",
                "at least one signature scheme is required",
            ));
        }
        validate_alpn(&self.alpn_protocols)?;

        if let Some(alps) = &self.alps {
            if self.max_version == TlsVersion::Tls12 {
                return Err(InvalidTlsSettings::new(
                    "alps",
                    "ALPS requires TLS 1.3 to be enabled",
                ));
            }
            if !self
                .alpn_protocols
                .iter()
                .any(|protocol| protocol.as_ref() == alps.protocol.as_ref())
            {
                return Err(InvalidTlsSettings::new(
                    "alps.protocol",
                    "ALPS protocol is absent from the ALPN protocol list",
                ));
            }
        }

        if self.certificate_compression.len() > 1 {
            return Err(InvalidTlsSettings::new(
                "certificate_compression",
                "Brotli certificate compression must not repeat",
            ));
        }

        if let Some(ids) = &self.requested_trust_anchors {
            validate_trust_anchor_ids(ids)?;
        }

        Ok(())
    }
}

/// Error returned when TLS profile settings are internally inconsistent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidTlsSettings {
    field: &'static str,
    message: Box<str>,
}

impl InvalidTlsSettings {
    fn new(field: &'static str, message: impl Into<Box<str>>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }

    /// Returns the invalid setting's field name.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }
}

impl fmt::Display for InvalidTlsSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid TLS {}: {}", self.field, self.message)
    }
}

impl Error for InvalidTlsSettings {}

fn validate_alpn(protocols: &[Box<[u8]>]) -> Result<(), InvalidTlsSettings> {
    if protocols.is_empty() {
        return Err(InvalidTlsSettings::new(
            "alpn_protocols",
            "at least one ALPN protocol is required",
        ));
    }

    let encoded_length = protocols.iter().try_fold(0usize, |length, protocol| {
        if protocol.is_empty() || protocol.len() > u8::MAX as usize {
            return Err(InvalidTlsSettings::new(
                "alpn_protocols",
                "each ALPN protocol must contain 1..=255 bytes",
            ));
        }
        length
            .checked_add(1 + protocol.len())
            .ok_or_else(|| InvalidTlsSettings::new("alpn_protocols", "encoded list is too large"))
    })?;
    if encoded_length > u16::MAX as usize {
        return Err(InvalidTlsSettings::new(
            "alpn_protocols",
            "encoded ALPN protocol list exceeds 65535 bytes",
        ));
    }

    Ok(())
}

fn validate_trust_anchor_ids(ids: &[Box<[u8]>]) -> Result<(), InvalidTlsSettings> {
    let encoded_length = ids.iter().try_fold(0usize, |length, id| {
        if id.is_empty() || id.len() > u8::MAX as usize {
            return Err(InvalidTlsSettings::new(
                "requested_trust_anchors",
                "each trust anchor ID must contain 1..=255 bytes",
            ));
        }
        length.checked_add(1 + id.len()).ok_or_else(|| {
            InvalidTlsSettings::new("requested_trust_anchors", "encoded ID list is too large")
        })
    })?;

    // The ID vector has its own u16 length inside the extension's u16-sized body.
    if encoded_length > u16::MAX as usize - size_of::<u16>() {
        return Err(InvalidTlsSettings::new(
            "requested_trust_anchors",
            "encoded trust anchor ID list exceeds 65533 bytes",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_settings() -> TlsSettings {
        TlsSettings {
            min_version: TlsVersion::Tls12,
            max_version: TlsVersion::Tls13,
            cipher_suites: vec![CipherSuite::Aes128GcmSha256],
            groups: vec![NamedGroup::X25519],
            key_shares: vec![NamedGroup::X25519],
            signature_schemes: vec![SignatureScheme::EcdsaSecp256r1Sha256],
            alpn_protocols: vec![Box::from(&b"http/1.1"[..])],
            alps: None,
            certificate_compression: Vec::new(),
            requested_trust_anchors: None,
            grease: false,
            grease_signature_algorithms: false,
            permute_extensions: false,
            ech_grease: false,
            request_ocsp_staple: false,
            request_signed_certificate_timestamps: false,
            aes_hardware: true,
        }
    }

    #[test]
    fn tls_12_does_not_require_key_shares() -> Result<(), Box<dyn Error>> {
        let mut settings = minimal_settings();
        settings.max_version = TlsVersion::Tls12;
        settings.key_shares.clear();

        settings.validate()?;
        Ok(())
    }

    #[test]
    fn tls_12_rejects_key_shares() {
        let mut settings = minimal_settings();
        settings.max_version = TlsVersion::Tls12;

        let error = settings.validate().err();
        assert_eq!(
            error.as_ref().map(InvalidTlsSettings::field),
            Some("key_shares")
        );
    }

    #[test]
    fn tls_12_rejects_ech_grease() {
        let mut settings = minimal_settings();
        settings.max_version = TlsVersion::Tls12;
        settings.key_shares.clear();
        settings.ech_grease = true;

        let error = settings.validate().err();
        assert_eq!(
            error.as_ref().map(InvalidTlsSettings::field),
            Some("ech_grease")
        );
    }

    #[test]
    fn tls_12_rejects_alps() {
        let mut settings = minimal_settings();
        settings.max_version = TlsVersion::Tls12;
        settings.key_shares.clear();
        settings.alps = Some(AlpsSettings {
            protocol: Box::from(&b"http/1.1"[..]),
            use_new_codepoint: true,
        });

        let error = settings.validate().err();
        assert_eq!(error.as_ref().map(InvalidTlsSettings::field), Some("alps"));
    }

    #[test]
    fn tls_12_rejects_requested_trust_anchors() {
        let mut settings = minimal_settings();
        settings.max_version = TlsVersion::Tls12;
        settings.key_shares.clear();
        settings.requested_trust_anchors = Some(Vec::new());

        let error = settings.validate().err();
        assert_eq!(
            error.as_ref().map(InvalidTlsSettings::field),
            Some("requested_trust_anchors")
        );
    }

    #[test]
    fn trust_anchor_ids_may_be_omitted_or_explicitly_empty() -> Result<(), Box<dyn Error>> {
        let mut settings = minimal_settings();
        settings.requested_trust_anchors = Some(Vec::new());

        settings.validate()?;
        settings.requested_trust_anchors = None;
        settings.validate()?;
        Ok(())
    }

    #[test]
    fn trust_anchor_ids_must_be_nonempty_and_fit_one_byte_lengths() {
        let invalid_ids = [Box::default(), vec![0; 256].into_boxed_slice()];

        for id in invalid_ids {
            let mut settings = minimal_settings();
            settings.requested_trust_anchors = Some(vec![id]);
            let error = settings.validate().err();
            assert_eq!(
                error.as_ref().map(InvalidTlsSettings::field),
                Some("requested_trust_anchors")
            );
        }
    }

    #[test]
    fn trust_anchor_id_list_must_fit_the_extension_body() -> Result<(), Box<dyn Error>> {
        let mut settings = minimal_settings();
        let mut ids = (0..u8::MAX)
            .map(|_| vec![0; u8::MAX as usize].into_boxed_slice())
            .collect::<Vec<_>>();
        ids.push(vec![0; 252].into_boxed_slice());
        settings.requested_trust_anchors = Some(ids);

        settings.validate()?;
        settings
            .requested_trust_anchors
            .as_mut()
            .expect("test configured IDs")
            .push(Box::from(&b"x"[..]));

        let error = settings.validate().err();
        assert_eq!(
            error.as_ref().map(InvalidTlsSettings::field),
            Some("requested_trust_anchors")
        );
        Ok(())
    }
}
