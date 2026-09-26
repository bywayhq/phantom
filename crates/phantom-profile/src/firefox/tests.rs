use super::{v156_http2, v156_tls};
use crate::http2::{
    Http2HpackSettings, Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings,
    Http2StreamSettings, session_capture::SessionCapture,
};
use crate::tls::{
    CertificateCompression, CipherSuite, ClientHelloExtension, ClientHelloExtensionOrder,
    EchGreaseAead, NamedGroup, SignatureScheme, TlsVersion,
};

const V156_SESSION_FIXTURE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../fixtures/websocket/firefox/156.0/windows-11-26200/accept.txt"
));

#[test]
fn firefox_156_tls_settings_match_retained_vector() -> Result<(), Box<dyn std::error::Error>> {
    let settings = v156_tls();
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
    // Firefox 156 no longer offers FFDHE-2048 or FFDHE-3072.
    assert_eq!(
        settings.groups,
        [
            NamedGroup::X25519MlKem768,
            NamedGroup::X25519,
            NamedGroup::Secp256r1,
            NamedGroup::Secp384r1,
            NamedGroup::Secp521r1,
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
    assert_eq!(settings.ech_grease_payload_length, Some(240));
    assert_eq!(
        settings.ech_grease_aeads,
        [EchGreaseAead::Aes128Gcm, EchGreaseAead::ChaCha20Poly1305]
    );
    assert!(settings.request_ocsp_staple);
    assert!(settings.request_signed_certificate_timestamps);
    assert!(settings.aes_hardware);

    Ok(())
}

#[test]
fn firefox_156_http2_recipe_matches_windows_session_capture()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(V156_SESSION_FIXTURE)?;
    assert_eq!(capture.value("client")?, "Mozilla Firefox");
    assert_eq!(capture.value("client_version")?, "156.0");
    assert_eq!(
        capture.value("operating_system")?,
        "Windows 11 Home 10.0.26200 x64"
    );
    assert_eq!(capture.value("scenario")?, "accept");

    let settings = v156_http2();
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
        settings.pseudo_header_order,
        [
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Path,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
        ]
    );
    assert_eq!(
        settings.headers_priority,
        Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 42,
            exclusive: false,
        })
    );
    // Firefox source states the limit; the capture servers all state 100.
    assert_eq!(
        settings.streams,
        Http2StreamSettings {
            first_stream_id: 3,
            assumed_max_concurrent_streams: Some(100),
        }
    );

    // Navigation HEADERS carry no extended CONNECT shape, and one block shows
    // only the static-name choice; the WebSocket recipe tests compare the whole
    // encoder identity with every captured CONNECT.
    let navigation = Http2Settings {
        extended_connect_pseudo_header_order: None,
        extended_connect_priority: None,
        hpack: Http2HpackSettings {
            static_name_index: settings.hpack.static_name_index,
            ..Http2HpackSettings::default()
        },
        // A capture shows the first stream ID but not the assumed limit.
        streams: Http2StreamSettings {
            assumed_max_concurrent_streams: None,
            ..settings.streams
        },
        ..settings
    };
    let observed = capture.navigation_settings()?;
    assert_eq!(observed.len(), 3);
    for run in observed {
        assert_eq!(run, navigation);
    }
    Ok(())
}

/// The macOS 15.5 arm64 page loads carry the same H2 settings as on Windows.
#[test]
fn firefox_156_macos_http2_session_capture_matches_the_recipe()
-> Result<(), Box<dyn std::error::Error>> {
    let capture = SessionCapture::parse(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/websocket/firefox/156.0/macos-15.5-arm64/accept.txt"
    )))?;
    assert_eq!(capture.value("client")?, "Mozilla Firefox");
    assert_eq!(
        capture.value("operating_system")?,
        "macOS 15.5 (24F74) arm64"
    );
    assert_eq!(capture.value("scenario")?, "accept");
    let settings = v156_http2();
    let navigation = Http2Settings {
        extended_connect_pseudo_header_order: None,
        extended_connect_priority: None,
        hpack: Http2HpackSettings {
            static_name_index: settings.hpack.static_name_index,
            ..Http2HpackSettings::default()
        },
        // A capture shows the first stream ID but not the assumed limit.
        streams: Http2StreamSettings {
            assumed_max_concurrent_streams: None,
            ..settings.streams
        },
        ..settings
    };
    let observed = capture.navigation_settings()?;
    assert_eq!(observed.len(), 3);
    for run in observed {
        assert_eq!(run, navigation);
    }
    Ok(())
}
