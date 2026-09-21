//! Backend-neutral TLS profile settings.

use std::{error::Error, fmt};

const ECH_GREASE_EXTENSION_OVERHEAD: u16 = 42;
const MAX_ECH_GREASE_PAYLOAD_LENGTH: u16 = u16::MAX - ECH_GREASE_EXTENSION_OVERHEAD;

/// A TLS protocol version accepted by a transport.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum TlsVersion {
    /// TLS 1.0.
    Tls10,
    /// TLS 1.1.
    Tls11,
    /// TLS 1.2.
    Tls12,
    /// TLS 1.3.
    Tls13,
}

impl TlsVersion {
    /// Returns the protocol identifier used by the TLS `supported_versions` extension.
    #[must_use]
    pub const fn protocol_id(self) -> u16 {
        match self {
            Self::Tls10 => 0x0301,
            Self::Tls11 => 0x0302,
            Self::Tls12 => 0x0303,
            Self::Tls13 => 0x0304,
        }
    }

    /// Converts a TLS protocol identifier into a known version.
    #[must_use]
    pub const fn from_protocol_id(value: u16) -> Option<Self> {
        match value {
            0x0301 => Some(Self::Tls10),
            0x0302 => Some(Self::Tls11),
            0x0303 => Some(Self::Tls12),
            0x0304 => Some(Self::Tls13),
            _ => None,
        }
    }
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
    /// TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA.
    EcdheEcdsaAes128CbcSha,
    /// TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA.
    EcdheEcdsaAes256CbcSha,
    /// TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA.
    EcdheEcdsa3DesEdeCbcSha,
    /// TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA.
    EcdheRsa3DesEdeCbcSha,
    /// TLS_RSA_WITH_AES_128_GCM_SHA256.
    RsaAes128GcmSha256,
    /// TLS_RSA_WITH_AES_256_GCM_SHA384.
    RsaAes256GcmSha384,
    /// TLS_RSA_WITH_AES_128_CBC_SHA.
    RsaAes128CbcSha,
    /// TLS_RSA_WITH_AES_256_CBC_SHA.
    RsaAes256CbcSha,
    /// TLS_RSA_WITH_3DES_EDE_CBC_SHA.
    Rsa3DesEdeCbcSha,
}

impl CipherSuite {
    /// Returns the cipher suite's IANA value.
    #[must_use]
    pub const fn iana_id(self) -> u16 {
        match self {
            Self::Aes128GcmSha256 => 0x1301,
            Self::Aes256GcmSha384 => 0x1302,
            Self::Chacha20Poly1305Sha256 => 0x1303,
            Self::EcdheEcdsaAes128GcmSha256 => 0xc02b,
            Self::EcdheRsaAes128GcmSha256 => 0xc02f,
            Self::EcdheEcdsaAes256GcmSha384 => 0xc02c,
            Self::EcdheRsaAes256GcmSha384 => 0xc030,
            Self::EcdheEcdsaChacha20Poly1305Sha256 => 0xcca9,
            Self::EcdheRsaChacha20Poly1305Sha256 => 0xcca8,
            Self::EcdheRsaAes128CbcSha => 0xc013,
            Self::EcdheRsaAes256CbcSha => 0xc014,
            Self::EcdheEcdsaAes128CbcSha => 0xc009,
            Self::EcdheEcdsaAes256CbcSha => 0xc00a,
            Self::EcdheEcdsa3DesEdeCbcSha => 0xc008,
            Self::EcdheRsa3DesEdeCbcSha => 0xc012,
            Self::RsaAes128GcmSha256 => 0x009c,
            Self::RsaAes256GcmSha384 => 0x009d,
            Self::RsaAes128CbcSha => 0x002f,
            Self::RsaAes256CbcSha => 0x0035,
            Self::Rsa3DesEdeCbcSha => 0x000a,
        }
    }

    /// Converts an IANA value into a known cipher suite.
    #[must_use]
    pub const fn from_iana_id(value: u16) -> Option<Self> {
        match value {
            0x1301 => Some(Self::Aes128GcmSha256),
            0x1302 => Some(Self::Aes256GcmSha384),
            0x1303 => Some(Self::Chacha20Poly1305Sha256),
            0xc02b => Some(Self::EcdheEcdsaAes128GcmSha256),
            0xc02f => Some(Self::EcdheRsaAes128GcmSha256),
            0xc02c => Some(Self::EcdheEcdsaAes256GcmSha384),
            0xc030 => Some(Self::EcdheRsaAes256GcmSha384),
            0xcca9 => Some(Self::EcdheEcdsaChacha20Poly1305Sha256),
            0xcca8 => Some(Self::EcdheRsaChacha20Poly1305Sha256),
            0xc013 => Some(Self::EcdheRsaAes128CbcSha),
            0xc014 => Some(Self::EcdheRsaAes256CbcSha),
            0xc009 => Some(Self::EcdheEcdsaAes128CbcSha),
            0xc00a => Some(Self::EcdheEcdsaAes256CbcSha),
            0xc008 => Some(Self::EcdheEcdsa3DesEdeCbcSha),
            0xc012 => Some(Self::EcdheRsa3DesEdeCbcSha),
            0x009c => Some(Self::RsaAes128GcmSha256),
            0x009d => Some(Self::RsaAes256GcmSha384),
            0x002f => Some(Self::RsaAes128CbcSha),
            0x0035 => Some(Self::RsaAes256CbcSha),
            0x000a => Some(Self::Rsa3DesEdeCbcSha),
            _ => None,
        }
    }
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
    /// NIST P-521.
    Secp521r1,
    /// RFC 7919 finite-field group with a 2048-bit modulus.
    Ffdhe2048,
    /// RFC 7919 finite-field group with a 3072-bit modulus.
    Ffdhe3072,
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
    /// ECDSA P-521 with SHA-512.
    EcdsaSecp521r1Sha512,
    /// RSA-PSS with an RSAE key and SHA-384.
    RsaPssRsaeSha384,
    /// RSA PKCS#1 v1.5 with SHA-384.
    RsaPkcs1Sha384,
    /// RSA-PSS with an RSAE key and SHA-512.
    RsaPssRsaeSha512,
    /// RSA PKCS#1 v1.5 with SHA-512.
    RsaPkcs1Sha512,
    /// Legacy ECDSA with SHA-1.
    EcdsaSha1,
    /// Legacy RSA PKCS#1 v1.5 with SHA-1.
    RsaPkcs1Sha1,
}

/// A certificate compression algorithm advertised by the TLS client.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CertificateCompression {
    /// Zlib certificate compression.
    Zlib,
    /// Brotli certificate compression.
    Brotli,
    /// Zstandard certificate compression.
    Zstd,
}

/// A known ClientHello extension whose relative wire position can be fixed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientHelloExtension {
    /// Server Name Indication.
    ServerName,
    /// Extended Master Secret.
    ExtendedMasterSecret,
    /// Secure renegotiation indication.
    RenegotiationInfo,
    /// Supported groups.
    SupportedGroups,
    /// Elliptic-curve point formats.
    EcPointFormats,
    /// Session ticket.
    SessionTicket,
    /// RFC 8449 protected-record receive limit.
    RecordSizeLimit,
    /// Application-Layer Protocol Negotiation.
    Alpn,
    /// Certificate status request.
    StatusRequest,
    /// Signed certificate timestamps.
    SignedCertificateTimestamp,
    /// TLS 1.3 key shares.
    KeyShare,
    /// Supported TLS versions.
    SupportedVersions,
    /// Handshake signature algorithms.
    SignatureAlgorithms,
    /// RFC 9345 delegated-credential signature algorithms.
    DelegatedCredential,
    /// TLS 1.3 pre-shared-key exchange modes.
    PskKeyExchangeModes,
    /// Certificate compression algorithms.
    CertificateCompression,
    /// Requested trust anchors.
    TrustAnchors,
    /// Final-codepoint Application-Layer Protocol Settings.
    ApplicationSettings,
    /// Legacy-codepoint Application-Layer Protocol Settings.
    ApplicationSettingsLegacy,
    /// Encrypted ClientHello or ECH GREASE.
    EncryptedClientHello,
}

/// Controls the ordering of known ClientHello extensions.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ClientHelloExtensionOrder {
    /// Keep the TLS backend's deterministic default order.
    BackendDefault,
    /// Randomize eligible extensions for each connection.
    Permuted,
    /// Keep listed extensions in this order before any unlisted extensions.
    ///
    /// The backend appends unlisted configurable extensions in random order;
    /// backend-managed extensions may follow them. Profiles should list every
    /// configurable extension whose relative position belongs to the captured
    /// fingerprint.
    Fixed(Vec<ClientHelloExtension>),
}

/// ALPS configuration for one ALPN protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AlpsSettings {
    /// ALPN protocol identifier receiving application settings.
    pub protocol: Box<[u8]>,
    /// Opaque application settings sent when ALPS is negotiated.
    pub settings: Box<[u8]>,
    /// Whether to use the final ALPS extension codepoint.
    pub use_new_codepoint: bool,
}

/// An HPKE AEAD that a GREASE ECH extension may advertise.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum EchGreaseAead {
    /// AES-128-GCM.
    Aes128Gcm,
    /// AES-256-GCM.
    Aes256Gcm,
    /// ChaCha20-Poly1305.
    ChaCha20Poly1305,
}

impl EchGreaseAead {
    /// Returns the RFC 9180 HPKE AEAD identifier carried in the ECH extension.
    #[must_use]
    pub const fn hpke_id(self) -> u16 {
        match self {
            Self::Aes128Gcm => 0x0001,
            Self::Aes256Gcm => 0x0002,
            Self::ChaCha20Poly1305 => 0x0003,
        }
    }
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
    /// Signature schemes advertised for server delegated credentials.
    ///
    /// An empty vector omits RFC 9345 extension 34. This ordered list controls
    /// only the ClientHello advertisement; it does not weaken certificate,
    /// hostname, delegated-credential authorization, or CertificateVerify
    /// checks. Legacy ECDSA-SHA1 may be advertised to reproduce an observed
    /// wire image, but it cannot be selected for TLS 1.3 authentication.
    pub delegated_credential_schemes: Vec<SignatureScheme>,
    /// ALPN protocol identifiers in preference order.
    pub alpn_protocols: Vec<Box<[u8]>>,
    /// Optional ALPS advertisement.
    pub alps: Option<AlpsSettings>,
    /// Certificate compression algorithms in preference order.
    pub certificate_compression: Vec<CertificateCompression>,
    /// Whether session-ticket support is enabled.
    ///
    /// Disabling this omits the TLS 1.2 `session_ticket` ClientHello extension
    /// and disables ticket resumption supported by the TLS backend.
    pub session_tickets: bool,
    /// Maximum protected TLS record plaintext the client accepts.
    ///
    /// `None` omits the RFC 8449 extension. Configured values use the wire
    /// range `64..=16385`; TLS 1.2 applies its protocol maximum of 16384.
    pub record_size_limit: Option<u16>,
    /// Optional trust anchor IDs advertised to guide server certificate selection.
    ///
    /// Each ID is an opaque, non-empty byte string. `None` omits the TLS
    /// `trust_anchors` extension, while `Some(Vec::new())` emits the extension
    /// with an empty ID list. This setting does not change certificate
    /// verification.
    pub requested_trust_anchor_ids: Option<Vec<Box<[u8]>>>,
    /// Whether ordinary TLS GREASE is enabled.
    pub grease: bool,
    /// Whether signature-algorithm GREASE is enabled.
    pub grease_signature_algorithms: bool,
    /// Ordering policy for known ClientHello extensions.
    pub extension_order: ClientHelloExtensionOrder,
    /// Whether to emit a GREASE ECH extension without an ECH configuration.
    pub ech_grease: bool,
    /// Optional exact nonzero byte length for the random GREASE ECH payload.
    ///
    /// `None` retains the TLS backend's randomized payload-length policy. A
    /// configured length requires [`Self::ech_grease`] and must leave room for
    /// the ECHClientHelloOuter framing in the TLS extension body.
    pub ech_grease_payload_length: Option<u16>,
    /// HPKE AEADs from which each connection's GREASE ECH extension draws one.
    ///
    /// Every connection selects one listed AEAD uniformly at random; a
    /// HelloRetryRequest keeps the first ClientHello's choice. An empty vector
    /// retains the TLS backend's policy, which advertises AES-128-GCM when
    /// [`Self::aes_hardware`] is set and ChaCha20-Poly1305 otherwise. A
    /// non-empty list requires [`Self::ech_grease`] and must not repeat an
    /// AEAD.
    pub ech_grease_aeads: Vec<EchGreaseAead>,
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
        if self
            .record_size_limit
            .is_some_and(|limit| !(64..=16_385).contains(&limit))
        {
            return Err(InvalidTlsSettings::new(
                "record_size_limit",
                "record size limit must be between 64 and 16385 bytes",
            ));
        }
        if self.ech_grease_payload_length.is_some() && !self.ech_grease {
            return Err(InvalidTlsSettings::new(
                "ech_grease_payload_length",
                "an exact ECH GREASE payload length requires ECH GREASE to be enabled",
            ));
        }
        if self.ech_grease_payload_length == Some(0) {
            return Err(InvalidTlsSettings::new(
                "ech_grease_payload_length",
                "an exact ECH GREASE payload length must be nonzero",
            ));
        }
        if self
            .ech_grease_payload_length
            .is_some_and(|length| length > MAX_ECH_GREASE_PAYLOAD_LENGTH)
        {
            return Err(InvalidTlsSettings::new(
                "ech_grease_payload_length",
                "ECH GREASE payload and framing exceed the TLS extension body limit",
            ));
        }
        if !self.ech_grease_aeads.is_empty() && !self.ech_grease {
            return Err(InvalidTlsSettings::new(
                "ech_grease_aeads",
                "ECH GREASE AEAD choices require ECH GREASE to be enabled",
            ));
        }
        for (index, aead) in self.ech_grease_aeads.iter().enumerate() {
            if self.ech_grease_aeads[..index].contains(aead) {
                return Err(InvalidTlsSettings::new(
                    "ech_grease_aeads",
                    "ECH GREASE AEAD choices must not repeat",
                ));
            }
        }
        if self.max_version < TlsVersion::Tls13 {
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
            if self.requested_trust_anchor_ids.is_some() {
                return Err(InvalidTlsSettings::new(
                    "requested_trust_anchor_ids",
                    "requested trust anchors require TLS 1.3 to be enabled",
                ));
            }
            if !self.certificate_compression.is_empty() {
                return Err(InvalidTlsSettings::new(
                    "certificate_compression",
                    "certificate compression requires TLS 1.3 to be enabled",
                ));
            }
            if !self.delegated_credential_schemes.is_empty() {
                return Err(InvalidTlsSettings::new(
                    "delegated_credential_schemes",
                    "delegated credentials require TLS 1.3 to be enabled",
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
        if self
            .delegated_credential_schemes
            .iter()
            .copied()
            .any(|scheme| !can_advertise_for_delegated_credentials(scheme))
        {
            return Err(InvalidTlsSettings::new(
                "delegated_credential_schemes",
                "delegated credential advertisement contains an unsupported or RSAE scheme",
            ));
        }
        validate_alpn(&self.alpn_protocols)?;

        if let Some(alps) = &self.alps {
            if self.max_version < TlsVersion::Tls13 {
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
            if alps.settings.len() > u16::MAX as usize {
                return Err(InvalidTlsSettings::new(
                    "alps.settings",
                    "ALPS application settings exceed the TLS vector limit",
                ));
            }
        }

        for (index, algorithm) in self.certificate_compression.iter().enumerate() {
            if self.certificate_compression[..index].contains(algorithm) {
                return Err(InvalidTlsSettings::new(
                    "certificate_compression",
                    "certificate compression algorithms must not repeat",
                ));
            }
        }

        if let ClientHelloExtensionOrder::Fixed(extensions) = &self.extension_order {
            if extensions.is_empty() {
                return Err(InvalidTlsSettings::new(
                    "extension_order",
                    "fixed extension order must contain at least one extension",
                ));
            }
            for (index, extension) in extensions.iter().enumerate() {
                if extensions[..index].contains(extension) {
                    return Err(InvalidTlsSettings::new(
                        "extension_order",
                        "fixed extension order must not contain duplicates",
                    ));
                }
            }
        }

        if let Some(ids) = &self.requested_trust_anchor_ids {
            validate_trust_anchor_ids(ids)?;
        }

        Ok(())
    }
}

fn can_advertise_for_delegated_credentials(scheme: SignatureScheme) -> bool {
    matches!(
        scheme,
        SignatureScheme::MlDsa44
            | SignatureScheme::MlDsa65
            | SignatureScheme::MlDsa87
            | SignatureScheme::EcdsaSecp256r1Sha256
            | SignatureScheme::EcdsaSecp384r1Sha384
            | SignatureScheme::EcdsaSecp521r1Sha512
            | SignatureScheme::EcdsaSha1
    )
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
                "requested_trust_anchor_ids",
                "each trust anchor ID must contain 1..=255 bytes",
            ));
        }
        length.checked_add(1 + id.len()).ok_or_else(|| {
            InvalidTlsSettings::new("requested_trust_anchor_ids", "encoded ID list is too large")
        })
    })?;

    // The ID vector has its own u16 length inside the extension's u16-sized body.
    if encoded_length > u16::MAX as usize - size_of::<u16>() {
        return Err(InvalidTlsSettings::new(
            "requested_trust_anchor_ids",
            "encoded trust anchor ID list exceeds 65533 bytes",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
