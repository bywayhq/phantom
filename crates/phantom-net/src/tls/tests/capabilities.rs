//! Wire tests for browser-neutral TLS capabilities.

use phantom_profile::{
    CertificateCompression, CipherSuite, ClientHelloExtension, ClientHelloExtensionOrder,
    NamedGroup, SignatureScheme, TlsSettings, TlsVersion,
};

use super::{capture_client_hello_from, client_hello_fixture};
use crate::tls::test_support::TestResult;

const CERTIFICATE_COMPRESSION_EXTENSION: u16 = 27;
const DELEGATED_CREDENTIAL_EXTENSION: u16 = 34;
const RECORD_SIZE_LIMIT_EXTENSION: u16 = 28;
const SESSION_TICKET_EXTENSION: u16 = 35;

#[tokio::test]
async fn configured_capabilities_are_emitted_in_fixed_wire_order() -> TestResult<()> {
    let capture = capture_client_hello_from(&capability_settings()).await?;
    let summary = capture.summary()?;

    assert_eq!(
        summary.cipher_suites(),
        &[0x1301, 0xc009, 0xc00a, 0xc008, 0xc012, 0x000a]
    );
    assert_eq!(
        summary.supported_groups(),
        &[0x0019, 0x0100, 0x0101, 0x001d]
    );
    assert_eq!(summary.key_share_groups(), &[0x001d]);
    assert_eq!(
        summary.signature_algorithms(),
        &[0x0403, 0x0503, 0x0603, 0x0203, 0x0201]
    );
    assert_eq!(
        summary.supported_versions(),
        &[0x0304, 0x0303, 0x0302, 0x0301]
    );
    assert!(
        summary
            .extension_types()
            .contains(&SESSION_TICKET_EXTENSION)
    );
    assert_eq!(
        summary.extension_types(),
        &[
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0012, 0x0033, 0x002b,
            0x000d, 0x002d, 0x001b, 0x0015,
        ]
    );
    assert!(
        !summary
            .extension_types()
            .contains(&DELEGATED_CREDENTIAL_EXTENSION)
    );
    assert!(
        !summary
            .extension_types()
            .contains(&RECORD_SIZE_LIMIT_EXTENSION)
    );
    assert_eq!(
        client_hello_fixture::extension_payload(
            capture.handshake_bytes(),
            CERTIFICATE_COMPRESSION_EXTENSION
        )?,
        &[0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03]
    );
    Ok(())
}

#[tokio::test]
async fn disabled_session_tickets_omit_the_client_hello_extension() -> TestResult<()> {
    let mut settings = capability_settings();
    settings.session_tickets = false;

    let summary = capture_client_hello_from(&settings).await?.summary()?;
    assert!(
        !summary
            .extension_types()
            .contains(&SESSION_TICKET_EXTENSION)
    );
    Ok(())
}

fn capability_settings() -> TlsSettings {
    TlsSettings {
        min_version: TlsVersion::Tls10,
        max_version: TlsVersion::Tls13,
        cipher_suites: vec![
            CipherSuite::Aes128GcmSha256,
            CipherSuite::EcdheEcdsaAes128CbcSha,
            CipherSuite::EcdheEcdsaAes256CbcSha,
            CipherSuite::EcdheEcdsa3DesEdeCbcSha,
            CipherSuite::EcdheRsa3DesEdeCbcSha,
            CipherSuite::Rsa3DesEdeCbcSha,
        ],
        groups: vec![
            NamedGroup::Secp521r1,
            NamedGroup::Ffdhe2048,
            NamedGroup::Ffdhe3072,
            NamedGroup::X25519,
        ],
        key_shares: vec![NamedGroup::X25519],
        signature_schemes: vec![
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
            SignatureScheme::EcdsaSha1,
            SignatureScheme::RsaPkcs1Sha1,
        ],
        delegated_credential_schemes: Vec::new(),
        alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
        alps: None,
        certificate_compression: vec![
            CertificateCompression::Zlib,
            CertificateCompression::Brotli,
            CertificateCompression::Zstd,
        ],
        session_tickets: true,
        record_size_limit: None,
        requested_trust_anchor_ids: None,
        grease: false,
        grease_signature_algorithms: false,
        extension_order: ClientHelloExtensionOrder::Fixed(vec![
            ClientHelloExtension::ServerName,
            ClientHelloExtension::ExtendedMasterSecret,
            ClientHelloExtension::RenegotiationInfo,
            ClientHelloExtension::SupportedGroups,
            ClientHelloExtension::EcPointFormats,
            ClientHelloExtension::SessionTicket,
            ClientHelloExtension::Alpn,
            ClientHelloExtension::StatusRequest,
            ClientHelloExtension::SignedCertificateTimestamp,
            ClientHelloExtension::KeyShare,
            ClientHelloExtension::SupportedVersions,
            ClientHelloExtension::SignatureAlgorithms,
            ClientHelloExtension::PskKeyExchangeModes,
            ClientHelloExtension::CertificateCompression,
        ]),
        ech_grease: false,
        ech_grease_payload_length: None,
        ech_grease_aeads: Vec::new(),
        ech_from_https_records: false,
        request_ocsp_staple: true,
        request_signed_certificate_timestamps: true,
        aes_hardware: true,
    }
}
