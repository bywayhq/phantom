//! Exact catalog selection, evidence boundaries, and existing recipe parity.

use std::convert::Infallible;

use phantom_profile::{
    ClientProfile, browser,
    catalog::{
        Browser, CaptureEnvironment, CatalogError, EvidenceKind, LayerSupport, ProfileLayer,
        RequestTemplateKind, profile, profiles,
    },
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
type ProfileFactory = fn() -> ClientProfile;

#[test]
fn exact_lookup_never_replaces_a_missing_version_platform_or_revision() -> TestResult {
    for unknown in [
        "chrome/latest/windows",
        "chrome/154.0.8037.58/windows-11-26200/r1",
        "chrome/154.0.8037.97/macos-15.5-arm64/r1",
        "chrome/154.0.8037.97/windows-11-26200/r2",
        "Chrome/154.0.8037.97/windows-11-26200/r1",
        "",
    ] {
        assert!(matches!(
            profile(unknown),
            Err(CatalogError::UnknownProfile)
        ));
    }

    assert!(
        profiles()
            .windows(2)
            .all(|pair| pair[0].id() < pair[1].id())
    );
    for definition in profiles() {
        let selected = profile(definition.id().as_str())?;
        assert!(std::ptr::eq(selected, definition));
    }
    Ok(())
}

#[test]
fn catalog_preserves_the_composed_factories_stored_settings() -> TestResult {
    let factories: &[(&str, ProfileFactory)] = &[
        (
            "chrome/154.0.8037.95/macos-15.5-arm64/r1",
            browser::chrome::v154_macos,
        ),
        (
            "chrome/154.0.8037.97/windows-11-26200/r1",
            browser::chrome::v154_windows,
        ),
        (
            "chrome/154.0.8037.57/android-17-pixel7-emulator/r1",
            browser::chrome::v154_android,
        ),
        (
            "edge/154.0.4258.48/windows-11-26200/r1",
            browser::edge::v154_windows,
        ),
        (
            "edge/153.0.4234.49/android-17-pixel7-emulator/r1",
            browser::edge::v153_android,
        ),
        (
            "brave/154.1.96.59/windows-11-26200/r1",
            browser::brave::v154_windows,
        ),
        (
            "brave/153.1.95.104/android-17-pixel7-emulator/r1",
            browser::brave::v153_android,
        ),
        (
            "firefox/157.0/windows-11-26200/r1",
            browser::firefox::v157_windows,
        ),
        (
            "firefox/156.0.1/android-35-emulator/r1",
            browser::firefox::v156_android,
        ),
        (
            "opera/136.0.6008.52/windows-11-26200/r1",
            browser::opera::v136_windows,
        ),
        (
            "opera/102.1.5206.90382/android-17-pixel7-emulator/r1",
            browser::opera::v102_android,
        ),
    ];
    assert_eq!(profiles().len(), factories.len() + 1);

    for &(id, factory) in factories {
        let definition = profile(id)?;
        let selected = definition.instantiate(&[])?;
        assert_eq!(
            selected,
            factory(),
            "all stored settings, including order: {id}"
        );
        assert!(selected.request_template().is_none());

        for evidence in definition.layers() {
            let configured = match evidence.layer() {
                ProfileLayer::TcpTls => true,
                ProfileLayer::Tcp => selected.tcp().is_some(),
                ProfileLayer::Udp => selected.udp().is_some(),
                ProfileLayer::Dns => selected.dns_cache().is_some(),
                ProfileLayer::Http1 => selected.http1().is_some(),
                ProfileLayer::Http2 => selected.http2().is_some(),
                ProfileLayer::QuicTls
                | ProfileLayer::QuicTransport
                | ProfileLayer::Http3
                | ProfileLayer::Http3Request => selected.http3().is_some(),
                ProfileLayer::ClientHints => selected.client_hints().is_some(),
                ProfileLayer::WebSocket => selected.websocket().is_some(),
                ProfileLayer::ProxyConnect => selected.proxy_connect().is_some(),
                // Android factories leave generic cookie placement in place.
                ProfileLayer::CookiePlacement => {
                    definition.metadata().environment() == CaptureEnvironment::Desktop
                }
                _ => panic!("new layer needs an independent availability control"),
            };
            assert_eq!(
                evidence.support() == LayerSupport::Configured,
                configured,
                "metadata must describe the actual configured layer: {id} {:?}",
                evidence.layer()
            );
            assert_eq!(
                definition.instantiate(&[evidence.layer()]).is_ok(),
                configured
            );
        }
    }
    Ok(())
}

#[test]
fn intentional_absence_and_unavailable_support_remain_distinct() -> TestResult {
    let firefox = profile("firefox/157.0/windows-11-26200/r1")?;
    assert_eq!(
        firefox
            .evidence(ProfileLayer::ClientHints)
            .ok_or("missing hint metadata")?
            .support(),
        LayerSupport::IntentionallyAbsent
    );
    assert_eq!(
        firefox
            .evidence(ProfileLayer::Udp)
            .ok_or("missing UDP metadata")?
            .support(),
        LayerSupport::Unavailable
    );

    let android = profile("firefox/156.0.1/android-35-emulator/r1")?;
    assert_eq!(
        android.instantiate(&[ProfileLayer::Http2]),
        Err(CatalogError::UnavailableLayer {
            profile: android.id(),
            layer: ProfileLayer::Http2
        })
    );
    assert!(android.instantiate(&[ProfileLayer::TcpTls]).is_ok());
    Ok(())
}

#[test]
fn layer_evidence_preserves_different_builds_and_unknown_host_architecture() -> TestResult {
    let chrome = profile("chrome/154.0.8037.97/windows-11-26200/r1")?;
    assert_eq!(chrome.metadata().browser(), Browser::Chrome);
    assert_eq!(chrome.metadata().build(), "154.0.8037.97");
    assert_eq!(chrome.metadata().architecture(), None);

    let captured_build = |layer| -> TestResult<&'static str> {
        let reference = chrome
            .evidence(layer)
            .ok_or("missing layer")?
            .references()
            .iter()
            .find(|reference| reference.kind() == EvidenceKind::Capture)
            .ok_or("missing direct retained capture")?;
        Ok(reference.build())
    };
    assert_eq!(captured_build(ProfileLayer::TcpTls)?, "154.0.8037.58");
    assert_eq!(captured_build(ProfileLayer::ClientHints)?, "154.0.8037.97");
    Ok(())
}

#[test]
fn custom_settings_do_not_mutate_or_relabel_the_catalog_definition() -> TestResult {
    let android = profile("firefox/156.0.1/android-35-emulator/r1")?;
    let original = android.instantiate(&[])?;
    let custom = original.clone().with_http2(browser::chrome::v154_http2());
    assert!(custom.http2().is_some());
    assert_eq!(android.instantiate(&[]), Ok(original));
    assert_eq!(
        android
            .evidence(ProfileLayer::Http2)
            .ok_or("missing metadata")?
            .support(),
        LayerSupport::Unavailable
    );
    Ok(())
}

#[test]
fn catalog_leaves_opera_per_client_and_per_connection_draws_intact() -> TestResult {
    let opera = profile("opera/136.0.6008.52/windows-11-26200/r1")?;
    let mut selected = opera.instantiate(&[])?;
    let mut legacy = browser::opera::v136_windows();
    let mut selected_draws = 0;
    let mut legacy_draws = 0;
    selected.draw_per_client(|| {
        selected_draws += 1;
        Ok::<_, Infallible>(u64::MAX)
    })?;
    legacy.draw_per_client(|| {
        legacy_draws += 1;
        Ok::<_, Infallible>(u64::MAX)
    })?;

    assert_eq!(selected_draws, 1);
    assert_eq!(legacy_draws, 1);
    assert_eq!(selected, legacy);
    assert_ne!(opera.instantiate(&[])?, selected);
    Ok(())
}

#[test]
fn templates_require_an_explicit_supported_request_kind() -> TestResult {
    let chrome = profile("chrome/154.0.8037.97/windows-11-26200/r1")?;
    assert_eq!(
        chrome.request_template(RequestTemplateKind::Navigation),
        Ok(browser::chrome::v154_windows_navigation_template())
    );
    assert_eq!(
        chrome.request_template(RequestTemplateKind::FetchUpload),
        Ok(browser::chrome::v154_windows_fetch_upload_template())
    );

    let edge = profile("edge/154.0.4258.48/windows-11-26200/r1")?;
    assert_eq!(
        edge.request_template(RequestTemplateKind::Fetch),
        Err(CatalogError::UnavailableTemplate {
            profile: edge.id(),
            kind: RequestTemplateKind::Fetch
        })
    );
    Ok(())
}
