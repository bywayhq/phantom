use super::{v154_http2, v154_tls};
use crate::http2::{Http2Priority, Http2PseudoHeader, Http2Setting};
use crate::tls::{
    CertificateCompression, CipherSuite, ClientHelloExtension, ClientHelloExtensionOrder,
    NamedGroup, SignatureScheme, TlsVersion,
};

const LOCAL_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http2/firefox/154.0/macos-15.5/client-startup.txt"
));
const PEET_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http2/firefox/154.0/macos-15.5/peet-api-all.txt"
));
const PINGLY_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/http2/firefox/154.0/macos-15.5/pingly-api-all.txt"
));

#[test]
fn firefox_154_macos_tls_settings_match_retained_vector() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = v154_tls();
    settings.validate()?;

    assert_eq!(settings.min_version, TlsVersion::Tls12);
    assert_eq!(settings.max_version, TlsVersion::Tls13);
    assert_eq!(
        settings.cipher_suites,
        [
            CipherSuite::Aes128GcmSha256,
            CipherSuite::Chacha20Poly1305Sha256,
            CipherSuite::Aes256GcmSha384,
            CipherSuite::EcdheEcdsaAes128GcmSha256,
            CipherSuite::EcdheRsaAes128GcmSha256,
            CipherSuite::EcdheEcdsaChacha20Poly1305Sha256,
            CipherSuite::EcdheRsaChacha20Poly1305Sha256,
            CipherSuite::EcdheEcdsaAes256GcmSha384,
            CipherSuite::EcdheRsaAes256GcmSha384,
            CipherSuite::EcdheRsaAes128CbcSha,
            CipherSuite::EcdheRsaAes256CbcSha,
            CipherSuite::RsaAes128GcmSha256,
            CipherSuite::RsaAes256GcmSha384,
            CipherSuite::RsaAes128CbcSha,
            CipherSuite::RsaAes256CbcSha,
        ]
    );
    assert_eq!(
        settings.groups,
        [
            NamedGroup::X25519MlKem768,
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
            NamedGroup::Secp384r1,
            NamedGroup::Secp521r1,
            NamedGroup::Ffdhe2048,
            NamedGroup::Ffdhe3072,
        ]
    );
    assert_eq!(
        settings.key_shares,
        [
            NamedGroup::X25519MlKem768,
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
        ]
    );
    assert_eq!(
        settings.signature_schemes,
        [
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
            SignatureScheme::RsaPssRsaeSha256,
            SignatureScheme::RsaPssRsaeSha384,
            SignatureScheme::RsaPssRsaeSha512,
            SignatureScheme::RsaPkcs1Sha256,
            SignatureScheme::RsaPkcs1Sha384,
            SignatureScheme::RsaPkcs1Sha512,
            SignatureScheme::EcdsaSha1,
            SignatureScheme::RsaPkcs1Sha1,
        ]
    );
    assert_eq!(
        settings.delegated_credential_schemes,
        [
            SignatureScheme::EcdsaSecp256r1Sha256,
            SignatureScheme::EcdsaSecp384r1Sha384,
            SignatureScheme::EcdsaSecp521r1Sha512,
            SignatureScheme::EcdsaSha1,
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
        [
            CertificateCompression::Zlib,
            CertificateCompression::Brotli,
            CertificateCompression::Zstd,
        ]
    );
    assert!(settings.session_tickets);
    assert_eq!(settings.record_size_limit, Some(16_385));
    assert!(settings.requested_trust_anchor_ids.is_none());
    assert!(!settings.grease);
    assert!(!settings.grease_signature_algorithms);
    assert_eq!(
        settings.extension_order,
        ClientHelloExtensionOrder::Fixed(vec![
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
            ClientHelloExtension::EncryptedClientHello,
        ])
    );
    assert!(settings.ech_grease);
    assert_eq!(settings.ech_grease_payload_length, Some(239));
    assert!(settings.request_ocsp_staple);
    assert!(settings.request_signed_certificate_timestamps);
    assert!(settings.aes_hardware);

    Ok(())
}

#[test]
fn firefox_154_macos_http2_startup_matches_local_capture() -> Result<(), Box<dyn std::error::Error>>
{
    let settings = v154_http2();
    settings.validate()?;

    assert_eq!(
        settings.initial_settings,
        [
            Http2Setting::HeaderTableSize(65_536),
            Http2Setting::EnablePush(false),
            Http2Setting::InitialWindowSize(131_072),
            Http2Setting::MaxFrameSize(16_384),
        ]
    );
    assert_eq!(settings.initial_connection_window_size, 12_582_912);
    assert_eq!(
        fixture_value(LOCAL_FIXTURE, "initial_settings")?,
        "0x0001:65536,0x0002:0,0x0004:131072,0x0005:16384"
    );
    assert_eq!(
        fixture_value(LOCAL_FIXTURE, "connection_window_update")?,
        "12517377"
    );
    assert_eq!(
        settings.initial_connection_window_size - 65_535,
        fixture_value(LOCAL_FIXTURE, "connection_window_update")?.parse()?
    );

    Ok(())
}

#[test]
fn firefox_154_macos_request_shape_matches_supplemental_observations()
-> Result<(), Box<dyn std::error::Error>> {
    let settings = v154_http2();
    let expected_order = [
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Path,
        Http2PseudoHeader::Authority,
        Http2PseudoHeader::Scheme,
    ];
    let expected_priority = Http2Priority {
        dependency_stream_id: 0,
        weight: 42,
        exclusive: false,
    };

    assert_eq!(settings.pseudo_header_order, expected_order);
    assert_eq!(settings.headers_priority, Some(expected_priority));
    for fixture in [PEET_FIXTURE, PINGLY_FIXTURE] {
        assert_eq!(
            fixture_value(fixture, "pseudo_header_order")?,
            "method,path,authority,scheme"
        );
        assert_eq!(fixture_value(fixture, "headers_priority_dependency")?, "0");
        assert_eq!(fixture_value(fixture, "headers_priority_weight")?, "42");
        assert_eq!(
            fixture_value(fixture, "headers_priority_exclusive")?,
            "false"
        );
    }

    Ok(())
}

fn fixture_value<'a>(
    fixture: &'a str,
    expected_key: &str,
) -> Result<&'a str, Box<dyn std::error::Error>> {
    fixture
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once('=')?;
            (key == expected_key).then_some(value)
        })
        .ok_or_else(|| format!("fixture omitted {expected_key}").into())
}

#[test]
fn firefox_154_compatibility_aliases_return_the_renamed_recipes() {
    assert_eq!(super::v154_macos_tls(), super::v154_tls());
    assert_eq!(super::v154_macos_http2(), super::v154_http2());
}
