//! iOS preset selection against independently retained peer bytes.

use phantom_profile::{
    Http2CookieCrumbs, Http2HuffmanCoding, Http2Setting, Http2TableSizeUpdates, RequestField,
    catalog::{
        Browser, CatalogError, EvidenceKind, LayerSupport, ProfileIdentity, ProfileLayer,
        ProfilePlatform, RequestTemplateKind, profile,
    },
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn ios_identity_keeps_the_pinned_source_without_inventing_observations() -> TestResult {
    let definition = profile("safari-26-ios")?;
    assert!(std::ptr::eq(definition, profile("safari/26.0/ios/r1")?));
    let metadata = definition.metadata();
    assert_eq!(metadata.browser(), Browser::Safari);
    assert_eq!(metadata.platform(), ProfilePlatform::Ios);
    assert_eq!(metadata.version(), "26.0");
    assert_eq!(metadata.build(), None);
    assert_eq!(metadata.platform_release(), None);
    assert_eq!(metadata.architecture(), None);
    assert_eq!(metadata.environment(), None);
    assert_eq!(
        metadata.identity(),
        ProfileIdentity::Peer {
            project: "wreq-util",
            source_revision: "5715529002738f46eea86a7271f918f9374d3582",
            recipe: "safari-ios-26",
            release: "26.0",
        }
    );

    for layer in definition.layers() {
        let configured = matches!(layer.layer(), ProfileLayer::TcpTls | ProfileLayer::Http2);
        assert_eq!(layer.support() == LayerSupport::Configured, configured);
        if configured {
            assert_eq!(
                layer
                    .references()
                    .iter()
                    .map(|r| r.kind())
                    .collect::<Vec<_>>(),
                [EvidenceKind::ExternalSource, EvidenceKind::PeerCapture]
            );
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
fn ios_uses_the_observed_preface_and_its_own_hpack_policy() -> TestResult {
    let ios =
        profile("safari-26-ios")?.instantiate(&[ProfileLayer::TcpTls, ProfileLayer::Http2])?;
    let macos = profile("safari-26-macos")?.instantiate(&[])?;
    assert_eq!(ios.tls(), macos.tls());
    let h2 = ios.http2().ok_or("missing HTTP/2")?;
    h2.validate()?;
    assert_eq!(h2.hpack.huffman_coding, Http2HuffmanCoding::Always);
    assert_eq!(h2.hpack.cookie_crumbs, Http2CookieCrumbs::Whole);
    assert_eq!(
        h2.hpack.table_size_updates,
        Http2TableSizeUpdates::WhenChanged
    );
    assert_eq!(h2.initial_connection_window_size, 10485760);
    assert_eq!(h2.headers_priority, None);
    assert_eq!(
        h2.initial_settings,
        [
            Http2Setting::EnablePush(false),
            Http2Setting::MaxConcurrentStreams(100),
            Http2Setting::InitialWindowSize(2097152),
            Http2Setting::NoRfc7540Priorities(true),
        ]
    );

    for client in [
        include_bytes!(
            "../fixtures/peers/wreq-util-5715529-safari-ios-26/run-1/connection-0.client.bin"
        )
        .as_slice(),
        include_bytes!(
            "../fixtures/peers/wreq-util-5715529-safari-ios-26/run-2/connection-0.client.bin"
        )
        .as_slice(),
        include_bytes!(
            "../fixtures/peers/wreq-util-5715529-safari-ios-26/run-3/connection-0.client.bin"
        )
        .as_slice(),
    ] {
        assert_eq!(
            client.get(..24),
            Some(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice())
        );
        assert_eq!(
            client.get(24..57),
            Some(
                [
                    0, 0, 24, 4, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 3, 0, 0, 0, 100, 0, 4, 0, 32,
                    0, 0, 0, 9, 0, 0, 0, 1,
                ]
                .as_slice()
            )
        );
        let mut remaining = client.get(24..).ok_or("missing client preface")?;
        let mut windows = Vec::new();
        while !remaining.is_empty() {
            let head = remaining.get(..9).ok_or("truncated HTTP/2 frame")?;
            let length =
                usize::from(head[0]) << 16 | usize::from(head[1]) << 8 | usize::from(head[2]);
            let payload = remaining
                .get(9..9 + length)
                .ok_or("truncated HTTP/2 payload")?;
            if head[3] == 8 {
                assert_eq!(head.get(4..), Some([0, 0, 0, 0, 0].as_slice()));
                windows.push(payload);
            }
            remaining = remaining
                .get(9 + length..)
                .ok_or("truncated HTTP/2 frame")?;
        }
        assert_eq!(windows, [b"\x00\x9f\x00\x01".as_slice()]);
    }
    Ok(())
}

#[test]
fn ios_navigation_keeps_the_measured_fields_and_excludes_other_contexts() -> TestResult {
    let definition = profile("safari-26-ios")?;
    let template = definition.request_template(RequestTemplateKind::Navigation)?;
    template.validate()?;
    assert_eq!(
        template.http2_fields,
        [
            RequestField::literal("sec-fetch-dest", "document"),
            RequestField::literal(
                "user-agent",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 26_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Mobile/15E148 Safari/604.1"
            ),
            RequestField::literal(
                "accept",
                "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            ),
            RequestField::literal("sec-fetch-site", "none"),
            RequestField::literal("sec-fetch-mode", "navigate"),
            RequestField::literal("accept-language", "en-US,en;q=0.9"),
            RequestField::literal("priority", "u=0, i"),
            RequestField::literal("accept-encoding", "gzip, deflate, br"),
        ]
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
    Ok(())
}
