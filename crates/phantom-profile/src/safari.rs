//! Wire settings retained from Safari browser observations.

use crate::tls::{
    CertificateCompression, CipherSuite, ClientHelloExtension, ClientHelloExtensionOrder,
    NamedGroup, SignatureScheme, TlsSettings, TlsVersion,
};

/// Returns TLS settings captured from Safari 18.5 on macOS 15.5.
///
/// The fixed extension order covers the real extensions visible in the
/// retained ClientHello. GREASE and padding remain owned by the TLS backend.
/// The returned value is an ordinary owned [`TlsSettings`], so callers can
/// customize it before constructing a transport.
#[must_use]
pub fn v18_5_macos_tls() -> TlsSettings {
    TlsSettings {
        min_version: TlsVersion::Tls10,
        max_version: TlsVersion::Tls13,
        cipher_suites: vec![
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::Chacha20Poly1305Sha256,
            CipherSuite::EcdheEcdsaAes256GcmSha384,
            CipherSuite::EcdheEcdsaAes128GcmSha256,
            CipherSuite::EcdheEcdsaChacha20Poly1305Sha256,
            CipherSuite::EcdheRsaAes256GcmSha384,
            CipherSuite::EcdheRsaAes128GcmSha256,
            CipherSuite::EcdheRsaChacha20Poly1305Sha256,
            CipherSuite::EcdheEcdsaAes256CbcSha,
            CipherSuite::EcdheEcdsaAes128CbcSha,
            CipherSuite::EcdheRsaAes256CbcSha,
            CipherSuite::EcdheRsaAes128CbcSha,
            CipherSuite::RsaAes256GcmSha384,
            CipherSuite::RsaAes128GcmSha256,
            CipherSuite::RsaAes256CbcSha,
            CipherSuite::RsaAes128CbcSha,
            CipherSuite::EcdheEcdsa3DesEdeCbcSha,
            CipherSuite::EcdheRsa3DesEdeCbcSha,
            CipherSuite::Rsa3DesEdeCbcSha,
        ],
        groups: vec![
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
            NamedGroup::Secp384r1,
            NamedGroup::Secp521r1,
        ],
        key_shares: vec![NamedGroup::X25519],
        signature_schemes: vec![
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPkcs1Sha384,
            SignatureScheme::RsaPssRsaeSha512,
            SignatureScheme::RsaPkcs1Sha512,
            SignatureScheme::RsaPkcs1Sha1,
        ],
        alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
        alps: None,
        certificate_compression: vec![CertificateCompression::Zlib],
        session_tickets: false,
        record_size_limit: None,
        requested_trust_anchor_ids: None,
        grease: true,
        grease_signature_algorithms: false,
        extension_order: ClientHelloExtensionOrder::Fixed(vec![
            ClientHelloExtension::ServerName,
            ClientHelloExtension::ExtendedMasterSecret,
            ClientHelloExtension::RenegotiationInfo,
            ClientHelloExtension::SupportedGroups,
            ClientHelloExtension::EcPointFormats,
            ClientHelloExtension::Alpn,
            ClientHelloExtension::StatusRequest,
            ClientHelloExtension::SignatureAlgorithms,
            ClientHelloExtension::SignedCertificateTimestamp,
            ClientHelloExtension::KeyShare,
            ClientHelloExtension::PskKeyExchangeModes,
            ClientHelloExtension::SupportedVersions,
            ClientHelloExtension::CertificateCompression,
        ]),
        ech_grease: false,
        ech_grease_payload_length: None,
        request_ocsp_staple: true,
        request_signed_certificate_timestamps: true,
        aes_hardware: true,
    }
}

#[cfg(test)]
mod tests;
