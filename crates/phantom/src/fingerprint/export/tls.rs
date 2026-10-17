//! tls settings in the custom-profile format.

use super::{Encode, Encoder, Result};
use phantom_profile::*;
use serde_json::Value;

tokens!(TlsVersion, Tls10, Tls11, Tls12, Tls13);
tokens!(
    CipherSuite,
    Aes128GcmSha256,
    Aes256GcmSha384,
    Chacha20Poly1305Sha256,
    EcdheEcdsaAes128GcmSha256,
    EcdheRsaAes128GcmSha256,
    EcdheEcdsaAes256GcmSha384,
    EcdheRsaAes256GcmSha384,
    EcdheEcdsaChacha20Poly1305Sha256,
    EcdheRsaChacha20Poly1305Sha256,
    EcdheRsaAes128CbcSha,
    EcdheRsaAes256CbcSha,
    EcdheEcdsaAes128CbcSha,
    EcdheEcdsaAes256CbcSha,
    EcdheEcdsa3DesEdeCbcSha,
    EcdheRsa3DesEdeCbcSha,
    RsaAes128GcmSha256,
    RsaAes256GcmSha384,
    RsaAes128CbcSha,
    RsaAes256CbcSha,
    Rsa3DesEdeCbcSha
);
tokens!(
    NamedGroup,
    X25519MlKem768,
    X25519,
    Secp256r1,
    Secp384r1,
    Secp521r1,
    Ffdhe2048,
    Ffdhe3072
);
tokens!(
    SignatureScheme,
    MlDsa44,
    MlDsa65,
    MlDsa87,
    EcdsaSecp256r1Sha256,
    RsaPssRsaeSha256,
    RsaPkcs1Sha256,
    EcdsaSecp384r1Sha384,
    EcdsaSecp521r1Sha512,
    RsaPssRsaeSha384,
    RsaPkcs1Sha384,
    RsaPssRsaeSha512,
    RsaPkcs1Sha512,
    EcdsaSha1,
    RsaPkcs1Sha1
);
tokens!(CertificateCompression, Zlib, Brotli, Zstd);
tokens!(
    ClientHelloExtension,
    ServerName,
    ExtendedMasterSecret,
    RenegotiationInfo,
    SupportedGroups,
    EcPointFormats,
    SessionTicket,
    RecordSizeLimit,
    Alpn,
    StatusRequest,
    SignedCertificateTimestamp,
    KeyShare,
    EarlyData,
    SupportedVersions,
    SignatureAlgorithms,
    DelegatedCredential,
    PskKeyExchangeModes,
    CertificateCompression,
    TrustAnchors,
    ApplicationSettings,
    ApplicationSettingsLegacy,
    EncryptedClientHello,
    QuicTransportParameters
);
tokens!(EchGreaseAead, Aes128Gcm, Aes256Gcm, ChaCha20Poly1305);
tokens!(
    SessionTicketOrder,
    NewestFirst,
    OldestConnectionFirst,
    OldestFirst
);
record!(AlpsSettings, protocol, settings, use_new_codepoint);
record!(
    TlsSettings,
    versions,
    cipher_suites,
    groups,
    key_shares,
    signature_schemes,
    delegated_credential_schemes,
    alpn_protocols,
    alps,
    certificate_compression,
    session_tickets,
    session_ticket_order,
    session_ticket_extension_when_resuming,
    tcp_early_data,
    record_size_limit,
    tls12_extensions_in_tls13_client_hello,
    requested_trust_anchor_ids,
    grease,
    grease_signature_algorithms,
    extension_order,
    ech,
    request_ocsp_staple,
    request_signed_certificate_timestamps,
    aes_hardware,
    close_notify
);

impl Encode for TlsVersionRange {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        object!(e, f, "min" => &self.min(), "max" => &self.max())
    }
}
impl Encode for SessionTickets {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        object!(e, f, "enabled" => &self.is_enabled(), "tcp_per_origin" => &self.tcp_per_origin_limit())
    }
}
impl Encode for ClientHelloExtensionOrder {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        let (kind, extensions): (&str, &[ClientHelloExtension]) = match self {
            Self::BackendDefault => ("BackendDefault", &[]),
            Self::Permuted => ("Permuted", &[]),
            Self::Fixed(values) => ("Fixed", values),
            Self::PermutedWithTail(values) => ("PermutedWithTail", values),
            _ => return Err(super::super::json::unsupported(f)),
        };
        object!(e, f, "kind" => kind, "extensions" => extensions)
    }
}
impl Encode for TrustAnchorOrder {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        self.as_slice().encode(e, f)
    }
}
impl Encode for TrustAnchorIds {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        let (kind, orders): (&str, &[TrustAnchorOrder]) = match self {
            Self::Fixed(order) => ("Fixed", std::slice::from_ref(order)),
            Self::PerClient(orders) => ("PerClient", orders.as_slice()),
            Self::PerConnection(orders) => ("PerConnection", orders.as_slice()),
            _ => return Err(super::super::json::unsupported(f)),
        };
        object!(e, f, "kind" => kind, "orders" => orders)
    }
}
impl Encode for EchSettings {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        let (kind, settings) = match self {
            Self::Disabled => ("Disabled", None),
            Self::Grease(settings) => ("Grease", Some(settings)),
            Self::HttpsRecords(settings) => ("HttpsRecords", Some(settings)),
            _ => return Err(super::super::json::unsupported(f)),
        };
        object!(e, f, "kind" => kind, "settings" => &settings)
    }
}
impl Encode for EchGreaseSettings {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        object!(e, f, "payload_length" => &self.payload_length(), "aeads" => self.aeads())
    }
}
impl Encode for EchGreasePayloadLength {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        let (kind, value) = match self {
            Self::BackendDefault => ("BackendDefault", None),
            Self::Exact(value) => ("Exact", Some(*value)),
            Self::FromClientHello {
                maximum_name_length,
            } => ("FromClientHello", Some(u16::from(*maximum_name_length))),
            _ => return Err(super::super::json::unsupported(f)),
        };
        object!(e, f, "kind" => kind, "value" => &value)
    }
}
