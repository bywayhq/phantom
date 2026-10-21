//! Source-qualified settings checked against independent peer execution bytes.

use phantom_profile::{
    ClientProfile, Http2PseudoHeader as P, Http2Setting, Http2TableSizeUpdates, NamedGroup as G,
    RequestField, SignatureScheme as S,
    catalog::{
        Browser, CatalogError, EvidenceKind, LayerSupport, ProfileIdentity, ProfileLayer,
        ProfilePlatform, RequestTemplateKind, profile,
    },
    client_hello::ClientHelloSummary,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const HELLOS: [&[u8]; 3] = [
    include_bytes!(
        "../fixtures/peers/curl-impersonate-2.2.3-safari2601/run-1/connection-0.hello.bin"
    ),
    include_bytes!(
        "../fixtures/peers/curl-impersonate-2.2.3-safari2601/run-2/connection-0.hello.bin"
    ),
    include_bytes!(
        "../fixtures/peers/curl-impersonate-2.2.3-safari2601/run-3/connection-0.hello.bin"
    ),
];

#[test]
fn peer_identity_does_not_invent_browser_build_or_capture_environment() -> TestResult {
    let definition = profile("curl-safari-26-macos")?;
    assert_eq!(
        definition.id().as_str(),
        "peer/curl-impersonate/safari2601/r1"
    );
    let metadata = definition.metadata();
    assert_eq!(metadata.browser(), Browser::Safari);
    assert_eq!(metadata.platform(), ProfilePlatform::Macos);
    assert_eq!(metadata.version(), "26.0.1");
    assert_eq!(metadata.build(), None);
    assert_eq!(metadata.platform_release(), None);
    assert_eq!(metadata.architecture(), None);
    assert_eq!(metadata.environment(), None);
    assert_eq!(
        metadata.identity(),
        ProfileIdentity::Peer {
            project: "curl-impersonate",
            source_revision: "6e8f87760a4dd96771e96fc9d55440dcd8845243",
            recipe: "safari2601",
            release: "26.0.1",
        }
    );

    for layer in definition.layers() {
        let configured = matches!(layer.layer(), ProfileLayer::TcpTls | ProfileLayer::Http2);
        assert_eq!(layer.support() == LayerSupport::Configured, configured);
        if configured {
            assert!(
                layer
                    .references()
                    .iter()
                    .any(|reference| reference.kind() == EvidenceKind::ExternalSource)
            );
            assert!(
                layer
                    .references()
                    .iter()
                    .any(|reference| reference.kind() == EvidenceKind::PeerCapture)
            );
            assert!(layer.references().iter().all(|reference| !matches!(
                reference.kind(),
                EvidenceKind::Source | EvidenceKind::Capture
            )));
        } else {
            assert_eq!(
                definition.instantiate(&[layer.layer()]),
                Err(CatalogError::UnavailableLayer {
                    profile: definition.id(),
                    layer: layer.layer(),
                })
            );
        }
    }
    Ok(())
}

#[test]
fn tls_settings_preserve_the_captured_cipher_and_duplicate_signature_order() -> TestResult {
    let settings = profile("curl-safari-26-macos")?.instantiate(&[ProfileLayer::TcpTls])?;
    let tls = settings.tls();
    tls.validate()?;
    assert_eq!(
        tls.groups,
        [
            G::X25519MlKem768,
            G::X25519,
            G::Secp256r1,
            G::Secp384r1,
            G::Secp521r1
        ]
    );
    assert_eq!(tls.key_shares, [G::X25519MlKem768, G::X25519]);
    assert_eq!(
        tls.signature_schemes,
        [
            S::EcdsaSecp256r1Sha256,
            S::RsaPssRsaeSha256,
            S::RsaPkcs1Sha256,
            S::EcdsaSecp384r1Sha384,
            S::RsaPssRsaeSha384,
            S::RsaPssRsaeSha384,
            S::RsaPkcs1Sha384,
            S::RsaPssRsaeSha512,
            S::RsaPkcs1Sha512,
            S::RsaPkcs1Sha1
        ]
    );
    assert!(!tls.session_tickets.is_enabled());
    assert!(tls.alps.is_none());
    assert!(tls.ech.grease().is_none());
    assert!(tls.requested_trust_anchor_ids.is_none());

    for bytes in HELLOS {
        let captured = ClientHelloSummary::from_handshake_bytes(bytes)?;
        let is_grease = |value: &u16| value & 0x0f0f == 0x0a0a && value >> 8 == value & 0xff;
        let ciphers: Vec<_> = captured
            .cipher_suites()
            .iter()
            .copied()
            .filter(|value| !is_grease(value))
            .collect();
        assert_eq!(
            tls.cipher_suites
                .iter()
                .map(|suite| suite.iana_id())
                .collect::<Vec<_>>(),
            ciphers
        );
        assert_eq!(
            captured.signature_algorithms(),
            [1027, 2052, 1025, 1283, 2053, 2053, 1281, 2054, 1537, 513]
        );
        assert_eq!(
            captured
                .supported_groups()
                .iter()
                .copied()
                .filter(|value| !is_grease(value))
                .collect::<Vec<_>>(),
            [4588, 29, 23, 24, 25]
        );
        assert_eq!(
            captured
                .key_share_groups()
                .iter()
                .copied()
                .filter(|value| !is_grease(value))
                .collect::<Vec<_>>(),
            [4588, 29]
        );
        assert_eq!(
            captured
                .alpn_protocols()
                .iter()
                .map(Vec::as_slice)
                .collect::<Vec<_>>(),
            tls.alpn_protocols
                .iter()
                .map(AsRef::as_ref)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            captured
                .extension_types()
                .iter()
                .copied()
                .filter(|value| !is_grease(value))
                .collect::<Vec<_>>(),
            [0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27]
        );
    }
    Ok(())
}

#[test]
fn http2_settings_keep_the_captured_preface_without_head_priority() -> TestResult {
    let settings = profile("curl-safari-26-macos")?.instantiate(&[ProfileLayer::Http2])?;
    let h2 = settings.http2().ok_or("missing HTTP/2")?;
    h2.validate()?;
    assert_eq!(
        h2.initial_settings,
        [
            Http2Setting::EnablePush(false),
            Http2Setting::MaxConcurrentStreams(100),
            Http2Setting::InitialWindowSize(2097152),
            Http2Setting::NoRfc7540Priorities(true)
        ]
    );
    assert_eq!(h2.initial_connection_window_size, 10485760);
    assert_eq!(
        h2.pseudo_header_order,
        [P::Method, P::Scheme, P::Authority, P::Path]
    );
    assert_eq!(h2.headers_priority, None);
    assert_eq!(
        h2.hpack.table_size_updates,
        Http2TableSizeUpdates::EverySetting
    );
    let client = include_bytes!(
        "../fixtures/peers/curl-impersonate-2.2.3-safari2601/run-1/connection-0.client.bin"
    );
    assert_eq!(
        client.get(..24),
        Some(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice())
    );
    assert_eq!(
        client.get(24..57),
        Some(
            [
                0, 0, 24, 4, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100, 0, 4, 0, 32, 0,
                0, 0, 9, 0, 0, 0, 1,
            ]
            .as_slice()
        )
    );
    assert_eq!(
        client.get(57..70),
        Some([0, 0, 4, 8, 0, 0, 0, 0, 0, 0, 159, 0, 1].as_slice())
    );
    Ok(())
}

#[test]
fn only_the_measured_navigation_template_is_supplied() -> TestResult {
    let definition = profile("curl-safari-26-macos")?;
    let template = definition.request_template(RequestTemplateKind::Navigation)?;
    template.validate()?;
    let expected = [
        ("sec-fetch-dest", "document"),
        (
            "user-agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0.1 Safari/605.1.15",
        ),
        (
            "accept",
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ),
        ("sec-fetch-site", "none"),
        ("sec-fetch-mode", "navigate"),
        ("accept-language", "en-US,en;q=0.9"),
        ("priority", "u=0, i"),
        ("accept-encoding", "gzip, deflate, br"),
    ];
    assert_eq!(
        template.http2_fields,
        expected.map(|(name, value)| RequestField::literal(name, value))
    );
    assert!(template.http1_fields.is_empty());
    assert!(template.http3_fields.is_none());
    assert_eq!(template.http2_priority, None);
    for kind in [
        RequestTemplateKind::Fetch,
        RequestTemplateKind::FetchNoStore,
        RequestTemplateKind::FetchUpload,
    ] {
        assert_eq!(
            definition.request_template(kind),
            Err(CatalogError::UnavailableTemplate {
                profile: definition.id(),
                kind
            })
        );
    }
    let original = definition.instantiate(&[])?;
    let mut tls = original.tls().clone();
    tls.cipher_suites.reverse();
    let custom =
        ClientProfile::new(tls).with_http2(original.http2().ok_or("missing HTTP/2")?.clone());
    assert_ne!(custom, original);
    assert_eq!(definition.instantiate(&[])?, original);
    Ok(())
}
