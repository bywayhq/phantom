//! Wire tests for browser-neutral TLS capabilities.

use std::io;

use phantom_profile::{
    CertificateCompression, CipherSuite, ClientHelloExtension, ClientHelloExtensionOrder,
    NamedGroup, SignatureScheme, TlsSettings, TlsVersion,
};

use super::capture_client_hello_from;
use crate::tls::test_support::TestResult;

const DELEGATED_CREDENTIAL_EXTENSION: u16 = 34;
const RECORD_SIZE_LIMIT_EXTENSION: u16 = 28;
const CERTIFICATE_COMPRESSION_EXTENSION: u16 = 27;

#[tokio::test]
async fn configured_capabilities_are_emitted_in_fixed_wire_order() -> TestResult<()> {
    let capture = capture_client_hello_from(&capability_settings()).await?;
    let summary = capture.summary()?;

    assert_eq!(summary.cipher_suites(), &[0x1301, 0xc008, 0xc012, 0x000a]);
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
    assert_eq!(
        summary.extension_types(),
        &[
            0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0022, 0x0012, 0x0033,
            0x002b, 0x000d, 0x002d, 0x001c, 0x001b, 0x0015,
        ]
    );

    assert_eq!(
        extension_payload(capture.handshake_bytes(), DELEGATED_CREDENTIAL_EXTENSION)?,
        &[0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03]
    );
    assert_eq!(
        extension_payload(capture.handshake_bytes(), RECORD_SIZE_LIMIT_EXTENSION)?,
        &[0x40, 0x01]
    );
    assert_eq!(
        extension_payload(capture.handshake_bytes(), CERTIFICATE_COMPRESSION_EXTENSION)?,
        &[0x06, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03]
    );
    Ok(())
}

fn capability_settings() -> TlsSettings {
    TlsSettings {
        min_version: TlsVersion::Tls10,
        max_version: TlsVersion::Tls13,
        cipher_suites: vec![
            CipherSuite::Aes128GcmSha256,
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
        delegated_credential_signature_schemes: vec![
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
            SignatureScheme::EcdsaSha1,
        ],
        alpn_protocols: vec![Box::from(&b"h2"[..]), Box::from(&b"http/1.1"[..])],
        alps: None,
        certificate_compression: vec![
            CertificateCompression::Zlib,
            CertificateCompression::Brotli,
            CertificateCompression::Zstd,
        ],
        record_size_limit: Some(0x4001),
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
            ClientHelloExtension::DelegatedCredential,
            ClientHelloExtension::SignedCertificateTimestamp,
            ClientHelloExtension::KeyShare,
            ClientHelloExtension::SupportedVersions,
            ClientHelloExtension::SignatureAlgorithms,
            ClientHelloExtension::PskKeyExchangeModes,
            ClientHelloExtension::RecordSizeLimit,
            ClientHelloExtension::CertificateCompression,
            ClientHelloExtension::Padding,
        ]),
        ech_grease: false,
        request_ocsp_staple: true,
        request_signed_certificate_timestamps: true,
        aes_hardware: true,
    }
}

fn extension_payload(handshake: &[u8], expected_type: u16) -> io::Result<&[u8]> {
    let mut offset = 0;
    take(handshake, &mut offset, 4)?;
    take(handshake, &mut offset, 2 + 32)?;
    let session_id_length = usize::from(read_u8(handshake, &mut offset)?);
    take(handshake, &mut offset, session_id_length)?;
    let cipher_suites_length = usize::from(read_u16(handshake, &mut offset)?);
    take(handshake, &mut offset, cipher_suites_length)?;
    let compression_methods_length = usize::from(read_u8(handshake, &mut offset)?);
    take(handshake, &mut offset, compression_methods_length)?;
    let extensions_length = usize::from(read_u16(handshake, &mut offset)?);
    let extensions = take(handshake, &mut offset, extensions_length)?;

    let mut extension_offset = 0;
    while extension_offset < extensions.len() {
        let extension_type = read_u16(extensions, &mut extension_offset)?;
        let payload_length = usize::from(read_u16(extensions, &mut extension_offset)?);
        let payload = take(extensions, &mut extension_offset, payload_length)?;
        if extension_type == expected_type {
            return Ok(payload);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("ClientHello omitted extension 0x{expected_type:04x}"),
    ))
}

fn read_u8(bytes: &[u8], offset: &mut usize) -> io::Result<u8> {
    Ok(take(bytes, offset, 1)?[0])
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> io::Result<u16> {
    let bytes = take(bytes, offset, 2)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn take<'a>(bytes: &'a [u8], offset: &mut usize, length: usize) -> io::Result<&'a [u8]> {
    let end = offset
        .checked_add(length)
        .filter(|&end| end <= bytes.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "truncated ClientHello"))?;
    let value = &bytes[*offset..end];
    *offset = end;
    Ok(value)
}
