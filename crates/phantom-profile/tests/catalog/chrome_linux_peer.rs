//! Linux preset identity and the retained peer's supported layers.

use phantom_profile::{
    Http2IndexingLimit,
    catalog::{
        Browser, CatalogError, LayerSupport, ProfileIdentity, ProfileLayer, ProfilePlatform,
        profile,
    },
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn linux_preset_keeps_peer_identity_and_requires_only_observed_layers() -> TestResult {
    let definition = profile("chrome-155-linux")?;
    let metadata = definition.metadata();
    assert_eq!(metadata.browser(), Browser::Chrome);
    assert_eq!(metadata.platform(), ProfilePlatform::Linux);
    assert_eq!(metadata.build(), None);
    assert_eq!(metadata.platform_release(), None);
    assert_eq!(metadata.architecture(), None);
    assert_eq!(metadata.environment(), None);
    assert_eq!(
        metadata.identity(),
        ProfileIdentity::Peer {
            project: "httpcloak",
            source_revision: "3a426f92c44af452a249b388a16ae3720097e50a",
            recipe: "chrome-155-linux",
            release: "155.0.0.0",
        }
    );
    for layer in definition.layers() {
        let configured = matches!(
            layer.layer(),
            ProfileLayer::TcpTls | ProfileLayer::Http2 | ProfileLayer::CookiePlacement
        );
        assert_eq!(layer.support() == LayerSupport::Configured, configured);
        if configured {
            assert!(definition.instantiate(&[layer.layer()]).is_ok());
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
    let selected = definition.instantiate(&[])?;
    assert_eq!(
        selected
            .http2()
            .ok_or("missing HTTP/2")?
            .hpack
            .indexing_limit,
        Http2IndexingLimit::FullTable
    );
    assert!(selected.tcp().is_none());
    assert!(selected.http1().is_none());
    assert!(selected.http3().is_none());
    assert!(selected.client_hints().is_none());
    Ok(())
}
