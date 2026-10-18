//! macOS selection keeps platform-specific options and evidence boundaries.

use phantom_profile::{
    TcpKeepalivePolicy,
    browser::chrome,
    catalog::{
        CaptureEnvironment, CatalogError, EvidenceKind, LayerSupport, ProfileLayer,
        ProfilePlatform, RequestTemplateKind, profile,
    },
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn macos_selects_its_own_tcp_policy_and_reports_uncaptured_layers() -> TestResult {
    let definition = profile("chrome/154.0.8037.95/macos-15.5-arm64/r1")?;
    assert_eq!(definition.metadata().platform(), ProfilePlatform::Macos);
    assert_eq!(
        definition.metadata().environment(),
        CaptureEnvironment::Desktop
    );
    assert_eq!(definition.metadata().architecture(), Some("arm64"));
    let selected = definition.instantiate(&[ProfileLayer::Tcp, ProfileLayer::ClientHints])?;
    assert_eq!(selected, chrome::v154_macos());
    assert_eq!(selected.tcp(), Some(&chrome::v154_macos_tcp()));
    let tcp = selected.tcp().ok_or("macOS TCP settings missing")?;
    assert!(tcp.port_randomization.is_none());
    let TcpKeepalivePolicy::Fixed(keepalive) = &tcp.keepalive else {
        return Err("macOS should set only the keepalive idle time".into());
    };
    assert_eq!(keepalive.idle, std::time::Duration::from_secs(45));
    assert!(keepalive.interval.is_none());
    assert!(selected.udp().is_none());
    assert!(selected.dns_cache().is_none());

    for layer in [ProfileLayer::Udp, ProfileLayer::Dns] {
        assert_eq!(
            definition
                .evidence(layer)
                .ok_or("layer evidence missing")?
                .support(),
            LayerSupport::Unavailable
        );
        assert!(
            matches!(definition.instantiate(&[layer]), Err(CatalogError::UnavailableLayer { layer: missing, .. }) if missing == layer)
        );
    }
    let evidence = definition
        .evidence(ProfileLayer::Tcp)
        .ok_or("TCP evidence missing")?;
    assert!(evidence.verified_fields().is_empty());
    assert!(
        evidence
            .references()
            .iter()
            .any(|reference| reference.kind() == EvidenceKind::Source)
    );
    assert!(
        evidence
            .references()
            .iter()
            .all(|reference| reference.kind() != EvidenceKind::Capture)
    );
    assert!(
        definition
            .evidence(ProfileLayer::ProxyConnect)
            .ok_or("proxy evidence missing")?
            .verified_fields()
            .is_empty()
    );
    assert!(matches!(
        definition.request_template(RequestTemplateKind::FetchUpload),
        Err(CatalogError::UnavailableTemplate { .. })
    ));
    Ok(())
}
