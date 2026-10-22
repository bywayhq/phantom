use super::super::{
    FingerprintImportErrorKind, ProfileRegistry, ProfileRegistryErrorKind, describe_profile,
    export_profile_json, import_profile_json,
};
use phantom_profile::{
    ClientProfile, CookiePlacement, SessionTicketOrder, TrustAnchorIds, TrustAnchorOrder,
    TrustAnchorOrders,
    browser::chrome,
    catalog::{self, RequestTemplateKind},
};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;

fn round_trip(profile: &ClientProfile) -> TestResult {
    let bytes = export_profile_json(profile)?;
    assert_eq!(import_profile_json(&bytes)?, *profile);
    assert_eq!(export_profile_json(profile)?, bytes);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes)?,
        describe_profile(profile)?
    );
    Ok(())
}

#[test]
fn every_catalog_profile_and_available_template_round_trips() -> TestResult {
    let mut base_count = 0;
    let mut template_count = 0;
    for definition in catalog::profiles() {
        let profile = definition.instantiate(&[])?;
        round_trip(&profile)?;
        base_count += 1;
        for kind in [
            RequestTemplateKind::Navigation,
            RequestTemplateKind::FetchNoStore,
            RequestTemplateKind::Fetch,
            RequestTemplateKind::FetchUpload,
            RequestTemplateKind::Script,
            RequestTemplateKind::Stylesheet,
            RequestTemplateKind::Image,
            RequestTemplateKind::Font,
        ] {
            if let Ok(template) = definition.request_template(kind) {
                round_trip(&profile.clone().with_request_template(template))?;
                template_count += 1;
            }
        }
    }
    assert_eq!(base_count, catalog::profiles().len());
    assert!(base_count > 0 && template_count > 0);
    Ok(())
}

#[test]
fn edited_export_retains_order_and_changes_only_selected_settings() -> TestResult {
    let profile = chrome::v154_windows();
    let mut document = describe_profile(&profile)?;
    let expected_settings = profile
        .http2()
        .ok_or("HTTP/2 absent")?
        .initial_settings
        .iter()
        .rev()
        .copied()
        .collect::<Vec<_>>();
    document["profile"]["http2"]["initial_settings"]
        .as_array_mut()
        .ok_or("settings absent")?
        .reverse();
    document["profile"]["tls"]["session_ticket_order"] = "OldestFirst".into();
    let mut expected_tls = profile.tls().clone();
    expected_tls.session_ticket_order = SessionTicketOrder::OldestFirst;
    let mut expected_http2 = profile.http2().ok_or("HTTP/2 absent")?.clone();
    expected_http2.initial_settings = expected_settings;
    let imported = import_profile_json(&serde_json::to_vec(&document)?)?;
    assert_eq!(imported.tls(), &expected_tls);
    assert_eq!(imported.http2(), Some(&expected_http2));
    let before = describe_profile(&profile)?;
    let after = describe_profile(&imported)?;
    for key in [
        "tcp",
        "udp",
        "dns_cache",
        "http1",
        "http3",
        "client_hints",
        "websocket",
        "proxy_connect",
        "cookie_placement",
        "request_template",
    ] {
        assert_eq!(before["profile"][key], after["profile"][key], "{key}");
    }
    round_trip(&imported)
}

#[test]
fn export_preserves_raw_bytes_subseconds_and_duplicate_draw_candidates() -> TestResult {
    let profile = chrome::v154_windows();
    let mut tls = profile.tls().clone();
    tls.alps = None;
    tls.alpn_protocols = vec![vec![0xff, 0x00, 0x80].into_boxed_slice()];
    let order = TrustAnchorOrder::new(vec![Box::from(&b"opaque\0id"[..])])?;
    tls.requested_trust_anchor_ids = Some(TrustAnchorIds::PerConnection(TrustAnchorOrders::new(
        vec![order.clone(), order.clone(), order],
    )?));
    let mut http2 = profile.http2().ok_or("HTTP/2 absent")?.clone();
    http2.ping_timeout = Some(std::time::Duration::new(7, 123_456_789));
    round_trip(&ClientProfile::new(tls).with_http2(http2))
}

#[test]
fn description_preserves_missing_layers_without_claiming_catalog_identity() -> TestResult {
    let profile = ClientProfile::new(chrome::v154_tcp_tls());
    let value = describe_profile(&profile)?;
    assert_eq!(value["format"], "phantom.custom-profile");
    assert_eq!(value.as_object().ok_or("document absent")?.len(), 3);
    assert!(value["profile"]["http3"].is_null());
    assert!(value["profile"]["request_template"].is_null());
    round_trip(&profile)
}

#[test]
fn invalid_export_has_a_typed_cause_and_omits_supplied_values() -> TestResult {
    let mut tls = chrome::v154_tcp_tls();
    tls.cipher_suites.clear();
    let error = export_profile_json(&ClientProfile::new(tls))
        .err()
        .ok_or("invalid TLS exported")?;
    assert_eq!(error.kind(), FingerprintImportErrorKind::InvalidSettings);
    assert_eq!(error.field(), "tls");
    assert!(error.source().and_then(Error::source).is_some());
    let oversized = ClientProfile::new(chrome::v154_tcp_tls())
        .with_cookie_placement(CookiePlacement::before_fields(["SECRET".repeat(12_000)]));
    let error = describe_profile(&oversized)
        .err()
        .ok_or("oversized value exported")?;
    assert_eq!(error.kind(), FingerprintImportErrorKind::TooLarge);
    assert_eq!(error.field(), "profile.cookie_placement.before[0]");
    assert!(!format!("{error} {error:?}").contains("SECRET"));
    Ok(())
}

#[test]
fn export_limits_encoded_size_including_json_escaping() -> TestResult {
    let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_cookie_placement(
        CookiePlacement::before_fields(vec!["\"".repeat(32_768); 260]),
    );
    let error = export_profile_json(&profile)
        .err()
        .ok_or("oversized document exported")?;
    assert_eq!(error.kind(), FingerprintImportErrorKind::TooLarge);
    assert_eq!(error.field(), "document");
    Ok(())
}

#[test]
fn registry_imports_owned_settings_lists_names_and_requires_explicit_replacement() -> TestResult {
    let profile = chrome::v154_windows();
    let mut registry = ProfileRegistry::new();
    assert!(registry.is_empty());
    let bytes = export_profile_json(&profile)?;
    registry.import_json("custom/z", &bytes)?;
    drop(bytes);
    registry.insert("custom/a", profile.clone())?;
    assert_eq!(
        registry.names().collect::<Vec<_>>(),
        ["custom/a", "custom/z"]
    );
    assert_eq!(registry.len(), 2);
    let duplicate = registry
        .insert("custom/z", ClientProfile::new(chrome::v154_tcp_tls()))
        .err()
        .ok_or("duplicate replaced")?;
    assert_eq!(duplicate.kind(), ProfileRegistryErrorKind::DuplicateName);
    assert_eq!(registry.get("custom/z"), Some(&profile));
    assert!(registry.get("Custom/z").is_none());
    assert!(registry.get(catalog::profiles()[0].id().as_str()).is_none());
    let snapshot = registry.clone();
    assert_eq!(registry.remove("custom/z"), Some(profile.clone()));
    assert_eq!(snapshot.get("custom/z"), Some(&profile));
    registry.insert("custom/z", ClientProfile::new(chrome::v154_tcp_tls()))?;
    Ok(())
}

#[test]
fn failed_registry_operations_leave_other_entries_unchanged() -> TestResult {
    let mut registry = ProfileRegistry::new();
    let profile = chrome::v154_windows();
    registry.insert("existing", profile.clone())?;
    for name in [
        "",
        "UPPER",
        "../bad",
        " space",
        "secret\nname",
        "é",
        &"x".repeat(129),
    ] {
        let error = registry
            .insert(name, profile.clone())
            .err()
            .ok_or("invalid name accepted")?;
        assert_eq!(error.kind(), ProfileRegistryErrorKind::InvalidName);
        assert!(!format!("{error:?}").contains("secret"));
    }
    let error = registry
        .import_json("new", br#"{"format":"ja3"}"#)
        .err()
        .ok_or("lossy input accepted")?;
    assert_eq!(error.kind(), ProfileRegistryErrorKind::InvalidProfile);
    assert!(error.source().is_some());
    let mut invalid_tls = chrome::v154_tcp_tls();
    invalid_tls.cipher_suites.clear();
    let error = registry
        .insert("invalid", ClientProfile::new(invalid_tls))
        .err()
        .ok_or("invalid profile inserted")?;
    assert_eq!(error.kind(), ProfileRegistryErrorKind::InvalidProfile);
    assert!(error.source().is_some());
    let boundary = "x".repeat(128);
    registry.insert(&boundary, profile.clone())?;
    assert_eq!(registry.remove(&boundary), Some(profile.clone()));
    assert_eq!(registry.len(), 1);
    assert_eq!(registry.get("existing"), Some(&profile));
    Ok(())
}

#[test]
fn full_table_indexing_round_trips_as_an_explicit_choice() -> TestResult {
    let mut http2 = chrome::v154_http2();
    http2.hpack.indexing_limit = phantom_profile::Http2IndexingLimit::FullTable;
    let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_http2(http2);
    let description = describe_profile(&profile)?;
    assert_eq!(
        description["profile"]["http2"]["hpack"]["indexing_limit"],
        "FullTable"
    );
    round_trip(&profile)
}

#[test]
fn editable_request_priority_keeps_its_mode_and_rejects_mixed_fields() -> TestResult {
    use phantom_profile::Http2RequestPriority;
    use serde_json::json;

    let profile =
        chrome::v154_windows().with_request_template(chrome::v154_windows_navigation_template());
    let mut document = describe_profile(&profile)?;
    let priority = &mut document["profile"]["request_template"]["http2_priority"];
    *priority = json!({"variant":"WeightBand", "weight":147, "exclusive":true});
    let imported = import_profile_json(&serde_json::to_vec(&document)?)?;
    assert_eq!(
        imported
            .request_template()
            .ok_or("missing template")?
            .http2_priority,
        Some(Http2RequestPriority::WeightBand {
            weight: 147,
            exclusive: true
        })
    );
    round_trip(&imported)?;

    document["profile"]["request_template"]["http2_priority"]["dependency_stream_id"] = 0.into();
    let error = import_profile_json(&serde_json::to_vec(&document)?)
        .err()
        .ok_or("weight band accepted a fixed dependency")?;
    assert_eq!(error.kind(), FingerprintImportErrorKind::UnsupportedSetting);
    assert_eq!(error.field(), "request_template.http2_priority");
    Ok(())
}
