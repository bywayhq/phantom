//! Historical composition keeps unavailable platform policies absent.

use phantom_profile::{
    ClientHint, ClientHintSettings, CookiePlacement,
    browser::edge,
    catalog::{CatalogError, LayerSupport, ProfileLayer, RequestTemplateKind, profile, profiles},
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ID: &str = "edge/153.0.4234.48/windows-11-26200/r1";

#[test]
fn second_edge_version_keeps_exact_selection_and_every_missing_layer_error() -> TestResult {
    let definition = profile(ID)?;
    assert_eq!(profiles().len(), 14);
    assert_eq!(definition.metadata().build(), Some("153.0.4234.48"));
    assert_eq!(definition.metadata().architecture(), None);
    assert_ne!(
        definition.id(),
        profile("edge/154.0.4258.48/windows-11-26200/r1")?.id()
    );
    let present = [
        ProfileLayer::TcpTls,
        ProfileLayer::Http2,
        ProfileLayer::QuicTls,
        ProfileLayer::QuicTransport,
        ProfileLayer::Http3,
        ProfileLayer::Http3Request,
        ProfileLayer::ClientHints,
    ];
    assert_eq!(definition.instantiate(&present)?, edge::v153_windows());
    for layer in [
        ProfileLayer::Tcp,
        ProfileLayer::Udp,
        ProfileLayer::Dns,
        ProfileLayer::Http1,
        ProfileLayer::WebSocket,
        ProfileLayer::ProxyConnect,
        ProfileLayer::CookiePlacement,
    ] {
        assert_eq!(
            definition.evidence(layer).map(|entry| entry.support()),
            Some(LayerSupport::Unavailable)
        );
        assert_eq!(
            definition.instantiate(&[layer]),
            Err(CatalogError::UnavailableLayer {
                profile: definition.id(),
                layer,
            })
        );
    }
    for id in [
        "edge/153.0.4234.49/windows-11-26200/r1",
        "edge/153.0.4234.48/windows-11-26200/r2",
        "edge/153.0.4234.48/macos-15.5-arm64/r1",
        "edge/latest/windows",
    ] {
        assert!(matches!(profile(id), Err(CatalogError::UnknownProfile)));
    }
    Ok(())
}

#[test]
fn historical_catalog_preserves_independent_hints_templates_and_owned_values() -> TestResult {
    let definition = profile(ID)?;
    let expected = edge::v153_windows();
    assert_eq!(expected.client_hints(), Some(&original_hints()));
    assert_eq!(definition.instantiate(&[])?, expected);
    let second = definition.instantiate(&[])?;
    let changed = definition
        .instantiate(&[])?
        .with_client_hints(ClientHintSettings::new(vec![]));
    assert_ne!(changed, second);
    assert_eq!(definition.instantiate(&[])?, second);
    for (kind, expected) in [
        (
            RequestTemplateKind::Navigation,
            edge::v153_windows_navigation_template(),
        ),
        (
            RequestTemplateKind::FetchNoStore,
            edge::v153_windows_fetch_no_store_template(),
        ),
    ] {
        let mut first = definition.request_template(kind)?;
        assert_eq!(first, expected);
        first.http1_fields.clear();
        assert_eq!(definition.request_template(kind)?, expected);
    }
    for kind in [RequestTemplateKind::Fetch, RequestTemplateKind::FetchUpload] {
        assert_eq!(
            definition.request_template(kind),
            Err(CatalogError::UnavailableTemplate {
                profile: definition.id(),
                kind,
            })
        );
    }
    Ok(())
}

#[test]
fn historical_edge_153_windows_does_not_claim_edge_154_socket_or_cache_policies() {
    let profile = edge::v153_windows();
    assert!(profile.tcp().is_none());
    assert!(profile.udp().is_none());
    assert!(profile.dns_cache().is_none());
    assert!(profile.http1().is_none());
    assert!(profile.websocket().is_none());
    assert!(profile.proxy_connect().is_none());
    assert!(profile.request_template().is_none());
    assert_eq!(profile.cookie_placement(), &CookiePlacement::last());
    assert!(profile.http2().is_some());
    assert!(profile.http3().is_some());
    assert!(profile.client_hints().is_some());
}

fn original_hints() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};
    use phantom_profile::ClientHintDelivery;

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?0", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""153.0.4234.48""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""x86""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Windows""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""19.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Microsoft Edge";v="153.0.4234.48", "Not_A Brand";v="8.0.0.0", "Chromium";v="153.0.8010.53""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Desktop""#, AcceptCh),
    ])
}
