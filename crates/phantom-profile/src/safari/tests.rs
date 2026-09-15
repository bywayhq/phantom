use super::v18_5_macos_tls;
use crate::tls::{
    CertificateCompression, CipherSuite, ClientHelloExtension, ClientHelloExtensionOrder,
    NamedGroup, SignatureScheme, TlsVersion,
};

#[test]
fn safari_18_5_macos_tls_settings_match_retained_vector() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = v18_5_macos_tls();
    settings.validate()?;

    assert_eq!(settings.min_version, TlsVersion::Tls10);
    assert_eq!(settings.max_version, TlsVersion::Tls13);
    assert_eq!(
        settings.cipher_suites,
        [
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
        ]
    );
    assert_eq!(
        settings.groups,
        [
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
            NamedGroup::Secp384r1,
            NamedGroup::Secp521r1,
        ]
    );
    assert_eq!(settings.key_shares, [NamedGroup::X25519]);
    assert_eq!(
        settings.signature_schemes,
        [
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
        ]
    );
    assert_eq!(
        settings
            .alpn_protocols
            .iter()
            .map(|protocol| protocol.as_ref())
            .collect::<Vec<&[u8]>>(),
        [b"h2".as_slice(), b"http/1.1".as_slice()]
    );
    assert!(settings.alps.is_none());
    assert_eq!(
        settings.certificate_compression,
        [CertificateCompression::Zlib]
    );
    assert!(!settings.session_tickets);
    assert!(settings.requested_trust_anchor_ids.is_none());
    assert!(settings.grease);
    assert!(!settings.grease_signature_algorithms);
    assert!(!settings.ech_grease);
    assert!(settings.request_ocsp_staple);
    assert!(settings.request_signed_certificate_timestamps);
    assert!(settings.aes_hardware);
    assert_eq!(
        settings.extension_order,
        ClientHelloExtensionOrder::Fixed(vec![
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
        ])
    );

    Ok(())
}
