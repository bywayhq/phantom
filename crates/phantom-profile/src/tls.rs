//! Backend-neutral TLS profile settings.

use std::{error::Error, fmt, net::IpAddr, num::NonZeroU8};

const ECH_GREASE_EXTENSION_OVERHEAD: u16 = 42;
const MAX_ECH_GREASE_PAYLOAD_LENGTH: u16 = u16::MAX - ECH_GREASE_EXTENSION_OVERHEAD;
/// Matches the TCP session cache's total capacity in `phantom-net`.
const MAX_SESSION_TICKETS_PER_ORIGIN: u8 = 10;

/// A TLS protocol version accepted by a transport.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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

/// An inclusive range of accepted TLS versions.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct TlsVersionRange {
    min: TlsVersion,
    max: TlsVersion,
}

impl From<TlsVersion> for TlsVersionRange {
    fn from(version: TlsVersion) -> Self {
        Self::only(version)
    }
}

impl TryFrom<(TlsVersion, TlsVersion)> for TlsVersionRange {
    type Error = InvalidTlsSettings;

    fn try_from((min, max): (TlsVersion, TlsVersion)) -> Result<Self, Self::Error> {
        Self::new(min, max)
    }
}

impl TlsVersionRange {
    /// Accepts TLS 1.2 and TLS 1.3.
    pub const TLS12_TO_TLS13: Self = Self {
        min: TlsVersion::Tls12,
        max: TlsVersion::Tls13,
    };

    /// Creates a range with these inclusive endpoints.
    ///
    /// # Errors
    ///
    /// Returns an error when `min` exceeds `max`.
    pub fn new(min: TlsVersion, max: TlsVersion) -> Result<Self, InvalidTlsSettings> {
        if min > max {
            return Err(InvalidTlsSettings::new(
                crate::ValidationErrorKind::Inconsistent,
                "version range",
                "minimum TLS version exceeds maximum TLS version",
            ));
        }
        Ok(Self { min, max })
    }

    /// Accepts only this TLS version.
    #[must_use]
    pub const fn only(version: TlsVersion) -> Self {
        Self {
            min: version,
            max: version,
        }
    }

    /// Returns the smallest accepted version.
    #[must_use]
    pub const fn min(self) -> TlsVersion {
        self.min
    }

    /// Returns the largest accepted version.
    #[must_use]
    pub const fn max(self) -> TlsVersion {
        self.max
    }
}

/// Session-ticket support and the number kept per origin over TCP.
///
/// Enablement also controls QUIC resumption. QUIC keeps its own tickets and
/// ignores the TCP limit.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SessionTickets {
    tcp_per_origin: Option<NonZeroU8>,
}

impl TryFrom<u8> for SessionTickets {
    type Error = InvalidTlsSettings;

    /// Enables tickets with this TCP limit. Zero is an error, not disablement.
    fn try_from(tcp_per_origin: u8) -> Result<Self, Self::Error> {
        Self::enabled(tcp_per_origin)
    }
}

impl SessionTickets {
    /// Disables ticket resumption and omits the TLS 1.2 ticket extension.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            tcp_per_origin: None,
        }
    }

    /// Enables tickets, keeping at most `tcp_per_origin` for one TCP origin.
    ///
    /// # Errors
    ///
    /// Returns an error when the limit is outside `1..=10`.
    pub fn enabled(tcp_per_origin: u8) -> Result<Self, InvalidTlsSettings> {
        if !(1..=MAX_SESSION_TICKETS_PER_ORIGIN).contains(&tcp_per_origin) {
            return Err(InvalidTlsSettings::new(
                crate::ValidationErrorKind::OutOfRange,
                "session_tickets.tcp_per_origin",
                "session tickets per origin must be between 1 and 10",
            ));
        }
        Ok(Self {
            tcp_per_origin: NonZeroU8::new(tcp_per_origin),
        })
    }

    /// Returns whether ticket support is enabled.
    #[must_use]
    pub const fn is_enabled(self) -> bool {
        self.tcp_per_origin.is_some()
    }

    /// Returns the TCP limit, or `None` when tickets are disabled.
    ///
    /// A `phantom` client applies it per origin and route. An isolated
    /// `phantom-net` connector applies it per server name across ports.
    #[must_use]
    pub const fn tcp_per_origin_limit(self) -> Option<NonZeroU8> {
        self.tcp_per_origin
    }
}

// Built-in recipe limits are known at compile time. Public input uses `enabled`.
pub(crate) const TWO_SESSION_TICKETS: SessionTickets = SessionTickets {
    tcp_per_origin: NonZeroU8::new(2),
};
pub(crate) const TEN_SESSION_TICKETS: SessionTickets = SessionTickets {
    tcp_per_origin: NonZeroU8::new(10),
};

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

impl From<CipherSuite> for u16 {
    fn from(suite: CipherSuite) -> Self {
        suite.iana_id()
    }
}

impl TryFrom<u16> for CipherSuite {
    type Error = UnknownCipherSuite;

    /// Converts a supported IANA identifier into a cipher suite.
    ///
    /// # Errors
    ///
    /// Returns [`UnknownCipherSuite`] when this profile API does not name the ID.
    fn try_from(iana_id: u16) -> Result<Self, Self::Error> {
        Self::from_iana_id(iana_id).ok_or(UnknownCipherSuite { iana_id })
    }
}

/// A cipher-suite identifier this profile API does not name.
///
/// ```
/// use phantom_profile::CipherSuite;
///
/// let suite = CipherSuite::try_from(0x1301)?;
/// assert_eq!(u16::from(suite), 0x1301);
/// let unknown = CipherSuite::try_from(0xffff).unwrap_err();
/// assert_eq!(unknown.iana_id(), 0xffff);
/// # Ok::<(), phantom_profile::UnknownCipherSuite>(())
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct UnknownCipherSuite {
    iana_id: u16,
}

impl UnknownCipherSuite {
    /// Returns the unsupported IANA identifier.
    #[must_use]
    pub const fn iana_id(self) -> u16 {
        self.iana_id
    }
}

impl fmt::Display for UnknownCipherSuite {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "unknown TLS cipher suite 0x{:04x}", self.iana_id)
    }
}

impl Error for UnknownCipherSuite {}

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
    /// TLS 1.3 early-data indication.
    ///
    /// Sent only by a resumption that offers early data; see
    /// [`TlsSettings::tcp_early_data`].
    EarlyData,
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
    /// QUIC transport parameters, sent only by QUIC connections.
    QuicTransportParameters,
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
    /// Randomize the other extensions for each connection, then write the
    /// listed ones last, in this order.
    ///
    /// Only `padding` and `pre_shared_key` follow the listed extensions. With
    /// [`TlsSettings::grease`] set, the trailing GREASE extension is written
    /// just before them. A listed extension is written only when the
    /// connection sends it anyway, so a list may name an extension that only
    /// QUIC or only a resumption sends. The second ClientHello after a HelloRetryRequest
    /// keeps the first one's order. The list must not be empty or repeat an
    /// extension.
    PermutedWithTail(Vec<ClientHelloExtension>),
}

/// How the payload of a GREASE ECH extension is sized.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum EchGreasePayloadLength {
    /// Keep the TLS backend's policy, which draws a length per connection.
    #[default]
    BackendDefault,
    /// Send this exact nonzero number of payload bytes.
    ///
    /// The length must leave room for the ECHClientHelloOuter framing in the
    /// TLS extension body.
    Exact(u16),
    /// Size the payload from the ClientHello that carries it, as the NSS of
    /// Firefox 157 does.
    ///
    /// The payload is as long as the encrypted EncodedClientHelloInner that a
    /// real ECH offer of the same ClientHello would carry, padded for an
    /// ECHConfig whose `maximum_name_length` is this value. The length
    /// therefore grows with a session ticket. The padding subtracts the
    /// length of the URL host: the server name, or for an IP literal, which
    /// sends no server name, the address text (an IPv6 address without
    /// brackets). Firefox 157 uses 100.
    FromClientHello {
        /// The `maximum_name_length` the padding assumes.
        maximum_name_length: u8,
    },
}

impl EchGreasePayloadLength {
    /// Returns the host text that [`Self::FromClientHello`] pads by in place
    /// of the server name: `server_name` without brackets when it is an IP
    /// literal, which sends no server name, and `None` for a host name,
    /// which pads by the server name itself.
    ///
    /// Firefox 157 pads by `127.0.0.1` and by `::1` without brackets. An
    /// IPv4-mapped IPv6 address keeps the text it is given, such as
    /// `::ffff:127.0.0.1`; how Firefox writes such a host is not verified.
    #[must_use]
    pub fn ip_literal_host(server_name: &str) -> Option<&str> {
        let host = server_name
            .strip_prefix('[')
            .and_then(|host| host.strip_suffix(']'))
            .unwrap_or(server_name);
        host.parse::<IpAddr>().is_ok().then_some(host)
    }
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
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
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

/// Checked payload sizing and AEAD choices for ECH GREASE.
///
/// Each connection draws one listed AEAD uniformly. A HelloRetryRequest keeps
/// the first ClientHello's choice. An empty list keeps the backend's policy:
/// AES-128-GCM with AES hardware, and ChaCha20-Poly1305 otherwise.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct EchGreaseSettings {
    payload_length: EchGreasePayloadLength,
    aeads: Vec<EchGreaseAead>,
}

impl EchGreaseSettings {
    /// Checks payload sizing and AEAD choices.
    ///
    /// ```
    /// # fn main() -> Result<(), phantom_profile::InvalidTlsSettings> {
    /// use phantom_profile::{EchGreaseAead, EchGreasePayloadLength,
    ///     EchGreaseSettings, EchSettings, browser::chrome};
    /// let mut tls = chrome::v154_tcp_tls();
    /// let grease = EchGreaseSettings::new(
    ///     EchGreasePayloadLength::Exact(128), vec![EchGreaseAead::Aes128Gcm],
    /// )?;
    /// tls.ech = EchSettings::Grease(grease);
    /// tls.validate()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Exact lengths must be between 1 and 65_493 bytes, leaving room for ECH
    /// framing in the TLS extension body. AEAD choices must not repeat. An
    /// empty list and `BackendDefault` keep the backend's choices.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTlsSettings`] for an exact length outside that range
    /// or a repeated AEAD choice.
    pub fn new(
        payload_length: EchGreasePayloadLength,
        aeads: Vec<EchGreaseAead>,
    ) -> Result<Self, InvalidTlsSettings> {
        if let EchGreasePayloadLength::Exact(length) = payload_length {
            if length == 0 {
                return Err(InvalidTlsSettings::new(
                    crate::ValidationErrorKind::OutOfRange,
                    "ech_grease_payload_length",
                    "an exact ECH GREASE payload length must be nonzero",
                ));
            }
            if length > MAX_ECH_GREASE_PAYLOAD_LENGTH {
                return Err(InvalidTlsSettings::new(
                    crate::ValidationErrorKind::TooLarge,
                    "ech_grease_payload_length",
                    "ECH GREASE payload and framing exceed the TLS extension body limit",
                ));
            }
        }
        for (index, aead) in aeads.iter().enumerate() {
            if aeads[..index].contains(aead) {
                return Err(InvalidTlsSettings::new(
                    crate::ValidationErrorKind::Duplicate,
                    "ech_grease_aeads",
                    "ECH GREASE AEAD choices must not repeat",
                ));
            }
        }
        Ok(Self {
            payload_length,
            aeads,
        })
    }

    /// Keeps the backend's payload sizing and AEAD choices.
    #[must_use]
    pub const fn backend_default() -> Self {
        Self {
            payload_length: EchGreasePayloadLength::BackendDefault,
            aeads: Vec::new(),
        }
    }

    /// Returns the checked payload sizing policy.
    #[must_use]
    pub const fn payload_length(&self) -> EchGreasePayloadLength {
        self.payload_length
    }

    /// Returns the AEAD choices, or an empty slice for the backend's policy.
    #[must_use]
    pub fn aeads(&self) -> &[EchGreaseAead] {
        &self.aeads
    }
}

// The built-in recipe has a valid payload policy and two distinct AEADs.
pub(crate) fn firefox_ech_grease() -> EchGreaseSettings {
    EchGreaseSettings {
        payload_length: EchGreasePayloadLength::FromClientHello {
            maximum_name_length: 100,
        },
        aeads: vec![EchGreaseAead::Aes128Gcm, EchGreaseAead::ChaCha20Poly1305],
    }
}

/// How you offer Encrypted ClientHello (ECH).
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum EchSettings {
    /// Omits ECH and ECH GREASE.
    Disabled,
    /// Sends ECH GREASE without looking up ECH configurations.
    Grease(EchGreaseSettings),
    /// Uses an origin's HTTPS record when it has a usable ECH configuration.
    ///
    /// On a client configured to look up HTTPS records, direct TCP requests
    /// and secure WebSocket openings overlap the lookup with address resolution. They wait at most 5–50 ms after the address
    /// answers, select the first record compatible with their ALPN offer,
    /// and retry once after an authenticated ECH rejection.
    ///
    /// QUIC connections to the origin's own host and port use the first
    /// record listing `h3`, with the same wait bound. They do not retry an
    /// ECH rejection. A stale configuration keeps failing until the cached
    /// record expires. Choose `Grease` to stop using HTTPS records.
    ///
    /// The supplied GREASE settings apply when no usable configuration is
    /// available. Proxy routes and Alt-Svc alternatives at another location
    /// use GREASE without waiting for HTTPS records. Connector operations
    /// use records only when you supply an ECH lookup or configuration.
    HttpsRecords(EchGreaseSettings),
}

impl EchSettings {
    /// Returns GREASE settings when ECH is enabled.
    #[must_use]
    pub const fn grease(&self) -> Option<&EchGreaseSettings> {
        match self {
            Self::Disabled => None,
            Self::Grease(settings) | Self::HttpsRecords(settings) => Some(settings),
        }
    }

    /// Returns whether direct connections may use HTTPS record configurations.
    #[must_use]
    pub const fn uses_https_records(&self) -> bool {
        matches!(self, Self::HttpsRecords(_))
    }
}

/// One checked, ordered list of opaque trust anchor IDs.
///
/// IDs contain 1..=255 bytes. Their one-byte length prefixes and bytes fit
/// within 65533 bytes. An empty order explicitly advertises no IDs.
/// Repeated IDs and their positions are preserved.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TrustAnchorOrder {
    ids: Vec<Box<[u8]>>,
}

impl TrustAnchorOrder {
    /// Checks and stores IDs in the supplied order.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTlsSettings`] if an ID length or encoded list size
    /// exceeds its bounds.
    ///
    /// # Examples
    ///
    /// ```
    /// use phantom_profile::{TrustAnchorIds, TrustAnchorOrder};
    /// let order = TrustAnchorOrder::new(vec![Box::from(&b"anchor"[..])])?;
    /// let ids = TrustAnchorIds::Fixed(order);
    /// # Ok::<(), phantom_profile::InvalidTlsSettings>(())
    /// ```
    pub fn new(ids: Vec<Box<[u8]>>) -> Result<Self, InvalidTlsSettings> {
        validate_trust_anchor_ids(&ids)?;
        Ok(Self { ids })
    }

    /// Creates an explicit empty order.
    #[must_use]
    pub const fn empty() -> Self {
        Self { ids: Vec::new() }
    }

    /// Returns the IDs in their stored order, including duplicates.
    #[must_use]
    pub fn as_slice(&self) -> &[Box<[u8]>] {
        &self.ids
    }

    /// Copies known recipe IDs whose bounds have been checked in a constant.
    pub(crate) fn from_recipe(ids: Vec<Box<[u8]>>) -> Self {
        Self { ids }
    }

    /// Checks static recipe bounds without allocating or changing order.
    pub(crate) const fn valid_recipe_ids(ids: &[&[u8]]) -> bool {
        let mut encoded = 0;
        let mut index = 0;
        while index < ids.len() {
            let length = ids[index].len();
            if length == 0 || length > 255 || encoded > 65533 - (length + 1) {
                return false;
            }
            encoded += length + 1;
            index += 1;
        }
        true
    }
}

impl AsRef<[Box<[u8]>]> for TrustAnchorOrder {
    fn as_ref(&self) -> &[Box<[u8]>] {
        self.as_slice()
    }
}

impl TryFrom<Vec<Box<[u8]>>> for TrustAnchorOrder {
    type Error = InvalidTlsSettings;

    fn try_from(ids: Vec<Box<[u8]>>) -> Result<Self, Self::Error> {
        Self::new(ids)
    }
}

/// A nonempty list of checked candidate orders with the same ID multiset.
///
/// Candidate positions and repetitions are preserved. Repeating a candidate
/// gives it another slot in a draw. Repeated IDs must occur equally often in
/// every candidate.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct TrustAnchorOrders {
    orders: Vec<TrustAnchorOrder>,
}

impl TrustAnchorOrders {
    /// Checks a nonempty candidate list for matching ID multisets.
    ///
    /// The candidate list must contain an order. Each order may itself be
    /// empty. Stored orders are never sorted.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTlsSettings`] for an empty candidate list or different
    /// ID multisets.
    pub fn new(orders: Vec<TrustAnchorOrder>) -> Result<Self, InvalidTlsSettings> {
        let Some((first, rest)) = orders.split_first() else {
            return Err(InvalidTlsSettings::new(
                crate::ValidationErrorKind::Missing,
                "requested_trust_anchor_ids",
                "a drawn trust anchor ID order needs at least one order to draw from",
            ));
        };
        let sorted = |order: &TrustAnchorOrder| {
            let mut ids = order.as_slice().to_vec();
            ids.sort_unstable();
            ids
        };
        let expected = sorted(first);
        if rest.iter().any(|order| sorted(order) != expected) {
            return Err(InvalidTlsSettings::new(
                crate::ValidationErrorKind::Inconsistent,
                "requested_trust_anchor_ids",
                "every drawn trust anchor ID order must list the same IDs",
            ));
        }
        Ok(Self { orders })
    }

    /// Returns candidates in their stored order, including repeated slots.
    #[must_use]
    pub fn as_slice(&self) -> &[TrustAnchorOrder] {
        &self.orders
    }

    /// Stores known recipe permutations checked in a constant.
    pub(crate) fn from_recipe(orders: Vec<TrustAnchorOrder>) -> Self {
        Self { orders }
    }
}

impl AsRef<[TrustAnchorOrder]> for TrustAnchorOrders {
    fn as_ref(&self) -> &[TrustAnchorOrder] {
        self.as_slice()
    }
}

impl TryFrom<Vec<TrustAnchorOrder>> for TrustAnchorOrders {
    type Error = InvalidTlsSettings;

    fn try_from(orders: Vec<TrustAnchorOrder>) -> Result<Self, Self::Error> {
        Self::new(orders)
    }
}

/// The trust anchor IDs a ClientHello requests, and when their order is
/// chosen.
///
/// Every variant sends the same IDs on every connection; only the order can
/// change. Each ID is an opaque, non-empty byte string. In a drawn variant,
/// each listed order is equally likely, so listing an order twice makes it
/// twice as likely, and every order must list the same IDs.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum TrustAnchorIds {
    /// Sends these IDs in this order on every connection. An empty list
    /// sends the extension with no IDs.
    Fixed(TrustAnchorOrder),
    /// Draws one of these orders for each client and sends it on every
    /// connection that client opens.
    ///
    /// A `phantom` client draws once when it is built, for every connection
    /// it opens with these settings. A connector built from these settings
    /// without a client draws once when it is built.
    PerClient(TrustAnchorOrders),
    /// Draws one of these orders for each connection.
    PerConnection(TrustAnchorOrders),
}

impl TrustAnchorIds {
    /// Returns every order these settings can send: the one list of
    /// [`Self::Fixed`], or each listed order of a drawn variant.
    #[must_use]
    pub fn orders(&self) -> &[TrustAnchorOrder] {
        match self {
            Self::Fixed(ids) => std::slice::from_ref(ids),
            Self::PerClient(orders) | Self::PerConnection(orders) => orders.as_slice(),
        }
    }

    /// Returns the stored order selected by `random`.
    ///
    /// Checked configurations always have at least one candidate.
    ///
    /// `random` should be uniformly distributed over `u64`; the order at
    /// `random * count / 2^64` is selected, so each of `count` orders is
    /// chosen with probability `1 / count`, off by less than `count / 2^64`.
    /// [`Self::Fixed`] ignores `random`.
    #[must_use]
    pub fn select(&self, random: u64) -> Option<&TrustAnchorOrder> {
        let orders = self.orders();
        let count = u128::try_from(orders.len()).ok()?;
        let index = usize::try_from((u128::from(random) * count) >> u64::BITS).ok()?;
        orders.get(index)
    }
}

/// Which saved ticket a new TCP connection to an origin offers, and which
/// one is dropped when the origin is full.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SessionTicketOrder {
    /// Offers the newest ticket and drops the oldest, as Chrome 154 does.
    NewestFirst,
    /// Offers the tickets of the connection that stored its first ticket
    /// earliest, newest of them first, and drops the ticket it would offer
    /// next. This follows the usual Firefox 157 Windows capture order;
    /// tickets from different clock ticks or interleaved connections can
    /// differ.
    OldestConnectionFirst,
    /// Offers the ticket stored first and drops it first when full. This
    /// follows the macOS Firefox capture order and Firefox's Unix source
    /// when no tickets share a clock value. Android resumption is uncaptured.
    OldestFirst,
}

/// Ordered TLS settings independent of the concrete TLS backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsSettings {
    /// Inclusive range of accepted TLS versions.
    pub versions: TlsVersionRange,
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
    /// Session-ticket support and the TCP cache limit.
    ///
    /// A new connection presents the ticket [`Self::session_ticket_order`]
    /// selects, and each TLS 1.3 ticket is used at most once. When the origin
    /// reaches its TCP limit, storing a ticket evicts the one that order
    /// names. QUIC connections keep their own tickets under a separate bound.
    ///
    /// The `phantom` client keeps one cache per origin and route, so the
    /// bound applies per origin there; a `phantom-net` connector built with
    /// `with_isolated_session_cache` applies it per server name, across
    /// ports.
    pub session_tickets: SessionTickets,
    /// Which of an origin's TLS session tickets a new connection over TCP
    /// presents, and which one a full origin evicts.
    ///
    /// The Chromium-family recipes set [`SessionTicketOrder::NewestFirst`],
    /// `firefox::v157_tcp_tls` [`SessionTicketOrder::OldestConnectionFirst`], and
    /// `firefox::v156_android_tcp_tls` [`SessionTicketOrder::OldestFirst`].
    /// QUIC connections ignore it.
    pub session_ticket_order: SessionTicketOrder,
    /// Whether a ClientHello that offers a TLS 1.3 ticket over TCP keeps the
    /// empty `session_ticket` extension.
    ///
    /// The extension only carries TLS 1.2 tickets, so the fresh ClientHello
    /// is unchanged either way. Chrome keeps it on resumption; Firefox omits
    /// it.
    pub session_ticket_extension_when_resuming: bool,
    /// Whether a direct TCP connection that resumes with a TLS 1.3 ticket
    /// permitting early data offers `early_data` and sends replay-safe
    /// requests in it, as Firefox 157 does.
    ///
    /// A replay-safe request has a safe method (`GET`, `HEAD`, `OPTIONS`, or
    /// `TRACE`), no body, and no trailers. Other requests on the connection
    /// wait until the server answers the early data. If the server rejects
    /// it, the connection finishes the handshake and sends the same bytes
    /// again, unless the server then selects another ALPN protocol, which
    /// fails the connection. A direct WebSocket opening through the
    /// `phantom-net` connectors that resumes such a ticket offers it too: its
    /// HTTP/1.1 Upgrade GET travels in it, and over HTTP/2 the preface and
    /// SETTINGS do while the extended CONNECT waits for the answer. A
    /// `phantom` `Client` WebSocket opening shares the tickets of its
    /// origin's request pool, so it offers early data when it resumes one.
    /// Connections through a proxy never offer early data, as Firefox's never
    /// do. Phantom also never offers it on connections that offer Encrypted
    /// Client Hello from an HTTPS record, which Firefox does not exclude.
    /// QUIC connections follow
    /// [`crate::quic::QuicTransportSettings::early_data`] instead.
    /// Requires [`Self::session_tickets`] and TLS 1.3.
    pub tcp_early_data: bool,
    /// Maximum protected TLS record plaintext the client accepts.
    ///
    /// `None` omits the RFC 8449 extension. Configured values use the wire
    /// range `64..=16385`; TLS 1.2 applies its protocol maximum of 16384. A
    /// QUIC connection sends and negotiates the extension, but QUIC carries
    /// no TLS records, so no limit applies there.
    pub record_size_limit: Option<u16>,
    /// Whether a ClientHello whose minimum version is TLS 1.3 still sends an
    /// empty `extended_master_secret` and a `renegotiation_info` with an empty
    /// renegotiated connection, as NSS does.
    ///
    /// Both extensions only matter to TLS 1.2 and earlier. A ClientHello that
    /// also offers TLS 1.2 sends them either way, so this changes only a TLS
    /// 1.3-only offer, such as every QUIC ClientHello. With real ECH, only
    /// the outer ClientHello carries them.
    pub tls12_extensions_in_tls13_client_hello: bool,
    /// Optional trust anchor IDs advertised to guide server certificate
    /// selection, in a fixed order or in one drawn per client or per
    /// connection.
    ///
    /// `None` omits the TLS `trust_anchors` extension, while
    /// `Some(TrustAnchorIds::Fixed(TrustAnchorOrder::empty()))` emits an explicit
    /// empty ID list. This setting does not change certificate verification.
    pub requested_trust_anchor_ids: Option<TrustAnchorIds>,
    /// Whether ordinary TLS GREASE is enabled.
    pub grease: bool,
    /// Whether signature-algorithm GREASE is enabled.
    pub grease_signature_algorithms: bool,
    /// Ordering policy for known ClientHello extensions.
    pub extension_order: ClientHelloExtensionOrder,
    /// Whether you disable ECH, send GREASE, or use HTTPS records with GREASE
    /// when no usable configuration is available.
    pub ech: EchSettings,
    /// Whether to request an OCSP staple.
    pub request_ocsp_staple: bool,
    /// Whether to request signed certificate timestamps.
    pub request_signed_certificate_timestamps: bool,
    /// Whether the client should be treated as having AES hardware.
    pub aes_hardware: bool,
    /// Whether shutting down a TCP connection sends a TLS `close_notify`
    /// alert before the TCP FIN.
    ///
    /// Firefox 157 sent the alert when a page aborted an HTTP/1.1 response
    /// and on each connection it closed at exit; on its other closes it rests
    /// on NSS, whose `ssl_SecureClose` sends it. Chromium sends only the FIN,
    /// because `SSLClientSocketImpl::Disconnect` never calls `SSL_shutdown`.
    /// It applies wherever Phantom shuts a connection down, such as an HTTP/2
    /// connection that ends after `GOAWAY` or a PING timeout. A connection
    /// dropped without a shutdown sends neither an alert nor a FIN of its
    /// own; the operating system closes it. QUIC connections close with
    /// `CONNECTION_CLOSE` instead and ignore it.
    pub close_notify: bool,
}

impl TlsSettings {
    /// Validates settings that are independent of a particular TLS backend.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidTlsSettings`] for missing algorithms, invalid record
    /// or ALPN lengths, or inconsistent TLS-version and extension settings.
    /// It also rejects unsupported delegated-credential schemes, repeated
    /// compression algorithms, and empty or repeated fixed extension lists.
    /// The error identifies the setting that failed.
    pub fn validate(&self) -> Result<(), InvalidTlsSettings> {
        if self.cipher_suites.is_empty() {
            return Err(InvalidTlsSettings::new(
                crate::ValidationErrorKind::Missing,
                "cipher_suites",
                "at least one cipher suite is required",
            ));
        }
        if self.groups.is_empty() {
            return Err(InvalidTlsSettings::new(
                crate::ValidationErrorKind::Missing,
                "groups",
                "at least one supported group is required",
            ));
        }
        if self
            .record_size_limit
            .is_some_and(|limit| !(64..=16_385).contains(&limit))
        {
            return Err(InvalidTlsSettings::new(
                crate::ValidationErrorKind::OutOfRange,
                "record_size_limit",
                "record size limit must be between 64 and 16385 bytes",
            ));
        }
        if self.tcp_early_data && !self.session_tickets.is_enabled() {
            return Err(InvalidTlsSettings::new(
                crate::ValidationErrorKind::Inconsistent,
                "tcp_early_data",
                "early data over TCP requires session tickets",
            ));
        }
        if self.versions.max() < TlsVersion::Tls13 {
            if self.tcp_early_data {
                return Err(InvalidTlsSettings::new(
                    crate::ValidationErrorKind::Inconsistent,
                    "tcp_early_data",
                    "early data over TCP requires TLS 1.3 to be enabled",
                ));
            }
            if !self.key_shares.is_empty() {
                return Err(InvalidTlsSettings::new(
                    crate::ValidationErrorKind::Inconsistent,
                    "key_shares",
                    "initial key shares require TLS 1.3 to be enabled",
                ));
            }
            if self.ech.grease().is_some() {
                return Err(InvalidTlsSettings::new(
                    crate::ValidationErrorKind::Inconsistent,
                    "ech",
                    "ECH requires TLS 1.3 to be enabled",
                ));
            }
            if self.requested_trust_anchor_ids.is_some() {
                return Err(InvalidTlsSettings::new(
                    crate::ValidationErrorKind::Inconsistent,
                    "requested_trust_anchor_ids",
                    "requested trust anchors require TLS 1.3 to be enabled",
                ));
            }
            if !self.certificate_compression.is_empty() {
                return Err(InvalidTlsSettings::new(
                    crate::ValidationErrorKind::Inconsistent,
                    "certificate_compression",
                    "certificate compression requires TLS 1.3 to be enabled",
                ));
            }
            if !self.delegated_credential_schemes.is_empty() {
                return Err(InvalidTlsSettings::new(
                    crate::ValidationErrorKind::Inconsistent,
                    "delegated_credential_schemes",
                    "delegated credentials require TLS 1.3 to be enabled",
                ));
            }
        } else {
            if self.key_shares.is_empty() {
                return Err(InvalidTlsSettings::new(
                    crate::ValidationErrorKind::Missing,
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
                    crate::ValidationErrorKind::Inconsistent,
                    "key_shares",
                    format!("key share {group:?} is absent from supported groups"),
                ));
            }
        }
        if self.signature_schemes.is_empty() {
            return Err(InvalidTlsSettings::new(
                crate::ValidationErrorKind::Missing,
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
                crate::ValidationErrorKind::Unsupported,
                "delegated_credential_schemes",
                "delegated credential advertisement contains an unsupported or RSAE scheme",
            ));
        }
        validate_alpn(&self.alpn_protocols)?;

        if let Some(alps) = &self.alps {
            if self.versions.max() < TlsVersion::Tls13 {
                return Err(InvalidTlsSettings::new(
                    crate::ValidationErrorKind::Inconsistent,
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
                    crate::ValidationErrorKind::Inconsistent,
                    "alps.protocol",
                    "ALPS protocol is absent from the ALPN protocol list",
                ));
            }
            if alps.settings.len() > u16::MAX as usize {
                return Err(InvalidTlsSettings::new(
                    crate::ValidationErrorKind::TooLarge,
                    "alps.settings",
                    "ALPS application settings exceed the TLS vector limit",
                ));
            }
        }

        for (index, algorithm) in self.certificate_compression.iter().enumerate() {
            if self.certificate_compression[..index].contains(algorithm) {
                return Err(InvalidTlsSettings::new(
                    crate::ValidationErrorKind::Duplicate,
                    "certificate_compression",
                    "certificate compression algorithms must not repeat",
                ));
            }
        }

        if let ClientHelloExtensionOrder::Fixed(extensions)
        | ClientHelloExtensionOrder::PermutedWithTail(extensions) = &self.extension_order
        {
            if extensions.is_empty() {
                return Err(InvalidTlsSettings::new(
                    crate::ValidationErrorKind::Missing,
                    "extension_order",
                    "a fixed extension order or tail must contain at least one extension",
                ));
            }
            for (index, extension) in extensions.iter().enumerate() {
                if extensions[..index].contains(extension) {
                    return Err(InvalidTlsSettings::new(
                        crate::ValidationErrorKind::Duplicate,
                        "extension_order",
                        "a fixed extension order or tail must not contain duplicates",
                    ));
                }
            }
        }

        Ok(())
    }

    /// Makes the draws these settings take once per client: a
    /// [`TrustAnchorIds::PerClient`] list becomes the
    /// [`TrustAnchorIds::Fixed`] order that the number from `random`
    /// selects, as [`TrustAnchorIds::select`] describes.
    ///
    /// `random` is called once for each draw and not at all when there is
    /// nothing to draw. Other settings and lists drawn per connection are
    /// unchanged. Checked candidate orders already contain the same IDs.
    ///
    /// # Errors
    ///
    /// Returns the error from `random` and leaves the settings unchanged.
    pub fn draw_per_client<E>(&mut self, random: impl FnOnce() -> Result<u64, E>) -> Result<(), E> {
        let Some(ids @ TrustAnchorIds::PerClient(_)) = &self.requested_trust_anchor_ids else {
            return Ok(());
        };
        if let Some(order) = ids.select(random()?) {
            self.requested_trust_anchor_ids = Some(TrustAnchorIds::Fixed(order.clone()));
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
///
/// Use [`Self::kind`] for recovery and [`Self::field`] and [`Self::reason`]
/// for diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidTlsSettings {
    kind: crate::ValidationErrorKind,
    field: &'static str,
    message: Box<str>,
}

impl InvalidTlsSettings {
    /// Returns the stable recovery category.
    #[must_use]
    pub const fn kind(&self) -> crate::ValidationErrorKind {
        self.kind
    }

    fn new(
        kind: crate::ValidationErrorKind,
        field: &'static str,
        message: impl Into<Box<str>>,
    ) -> Self {
        Self {
            kind,
            field,
            message: message.into(),
        }
    }

    /// Returns the invalid setting's field name.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }

    /// Returns the reason the setting is invalid.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.message
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
            crate::ValidationErrorKind::Missing,
            "alpn_protocols",
            "at least one ALPN protocol is required",
        ));
    }

    let encoded_length = protocols.iter().try_fold(0usize, |length, protocol| {
        if protocol.is_empty() || protocol.len() > u8::MAX as usize {
            return Err(InvalidTlsSettings::new(
                crate::ValidationErrorKind::OutOfRange,
                "alpn_protocols",
                "each ALPN protocol must contain 1..=255 bytes",
            ));
        }
        length.checked_add(1 + protocol.len()).ok_or_else(|| {
            InvalidTlsSettings::new(
                crate::ValidationErrorKind::TooLarge,
                "alpn_protocols",
                "encoded list is too large",
            )
        })
    })?;
    if encoded_length > u16::MAX as usize {
        return Err(InvalidTlsSettings::new(
            crate::ValidationErrorKind::TooLarge,
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
                crate::ValidationErrorKind::OutOfRange,
                "requested_trust_anchor_ids",
                "each trust anchor ID must contain 1..=255 bytes",
            ));
        }
        length.checked_add(1 + id.len()).ok_or_else(|| {
            InvalidTlsSettings::new(
                crate::ValidationErrorKind::TooLarge,
                "requested_trust_anchor_ids",
                "encoded ID list is too large",
            )
        })
    })?;

    // The ID vector has its own u16 length inside the extension's u16-sized body.
    if encoded_length > u16::MAX as usize - size_of::<u16>() {
        return Err(InvalidTlsSettings::new(
            crate::ValidationErrorKind::TooLarge,
            "requested_trust_anchor_ids",
            "encoded trust anchor ID list exceeds 65533 bytes",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
