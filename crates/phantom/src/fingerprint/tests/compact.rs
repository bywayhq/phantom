use std::error::Error;

use phantom_profile::{ClientProfile, browser::chrome};

use super::super::{
    FingerprintImportErrorKind as Kind, describe_profile, export_profile_json,
    import_akamai_profile, import_profile_json,
};

type TestResult = Result<(), Box<dyn Error>>;

const DESCRIPTION: &str = "6:131072;4:16777216;2:0;1:65536|16711681|0|m,p,a,s";

#[test]
fn akamai_import_replaces_only_described_fields_and_preserves_order() -> TestResult {
    let base = chrome::v154_windows();
    let original = base.clone();
    let result = import_akamai_profile(DESCRIPTION, &base)?;
    let before = describe_profile(&base)?;
    let after = describe_profile(result.profile())?;
    assert_eq!(base, original);
    assert_eq!(
        after["profile"]["http2"]["initial_settings"],
        serde_json::json!([
            {"kind":"MaxHeaderListSize", "value":131072},
            {"kind":"InitialWindowSize", "value":16777216},
            {"kind":"EnablePush", "value":false},
            {"kind":"HeaderTableSize", "value":65536},
        ])
    );
    assert_eq!(
        after["profile"]["http2"]["initial_connection_window_size"],
        16777216
    );
    assert_eq!(
        after["profile"]["http2"]["pseudo_header_order"],
        serde_json::json!(["Method", "Path", "Authority", "Scheme"])
    );
    let supplemented = result.supplemented_fields().collect::<Vec<_>>();
    for field in before["profile"]
        .as_object()
        .ok_or("profile absent")?
        .keys()
    {
        if field != "http2" {
            assert!(supplemented.contains(&field.as_str()));
            assert_eq!(before["profile"][field], after["profile"][field]);
        }
    }
    for field in before["profile"]["http2"]
        .as_object()
        .ok_or("HTTP/2 absent")?
        .keys()
    {
        let path = format!("http2.{field}");
        let observed = result.observed_fields().any(|value| value == path);
        assert_ne!(observed, supplemented.contains(&path.as_str()), "{path}");
        if !observed {
            assert_eq!(
                before["profile"]["http2"][field],
                after["profile"]["http2"][field]
            );
        }
    }
    assert_eq!(result.observed_fields().len(), 3);
    let debug = format!("{result:?}");
    assert!(!debug.contains("Aes128GcmSha256"));
    assert!(!debug.contains("16777216"));
    let bytes = export_profile_json(result.profile())?;
    assert_eq!(import_profile_json(&bytes)?, result.clone().into_profile());
    Ok(())
}

#[test]
fn akamai_windows_distinguish_no_initial_update_and_the_largest_target() -> TestResult {
    let base = chrome::v154_windows();
    for (increment, expected) in [(0, 65535), (32767, 98302), (2147418112_u32, 2147483647)] {
        let input = format!("4:65535|{increment}|0|m,a,s,p");
        let imported = import_akamai_profile(&input, &base)?;
        assert_eq!(
            imported
                .profile()
                .http2()
                .ok_or("HTTP/2 absent")?
                .initial_connection_window_size,
            expected
        );
    }
    for increment in [1, 1024, 32766] {
        let error = import_akamai_profile(&format!("4:65535|{increment}|0|m,a,s,p"), &base)
            .err()
            .ok_or("deferred update accepted")?;
        assert_eq!(error.kind(), Kind::UnsupportedSetting);
        assert_eq!(error.field(), "akamai.window_update");
    }
    for increment in ["2147418113", "4294967295", "4294967296", "-1", "+1", " 1"] {
        let error = import_akamai_profile(&format!("4:65535|{increment}|0|m,a,s,p"), &base)
            .err()
            .ok_or("invalid update accepted")?;
        assert_eq!(error.kind(), Kind::InvalidValue);
        assert_eq!(error.field(), "akamai.window_update");
    }
    Ok(())
}

#[test]
fn akamai_rejects_missing_supplements_and_conflicting_base_settings() -> TestResult {
    let base = ClientProfile::new(chrome::v154_tcp_tls());
    let error = import_akamai_profile(DESCRIPTION, &base)
        .err()
        .ok_or("HTTP/2 inferred")?;
    assert_eq!(error.kind(), Kind::MissingField);
    assert_eq!(error.field(), "http2");

    let mut http2 = chrome::v154_http2();
    http2.initial_stream_window_target = Some(8 * 1024 * 1024);
    let base = chrome::v154_windows().with_http2(http2);
    let error = import_akamai_profile(DESCRIPTION, &base)
        .err()
        .ok_or("conflict ignored")?;
    assert_eq!(error.kind(), Kind::InvalidSettings);
    assert!(error.source().is_some());
    Ok(())
}

#[test]
fn akamai_rejects_malformed_or_unsupported_descriptions_without_exposing_values() -> TestResult {
    let base = chrome::v154_windows();
    for (input, kind, field) in [
        ("", Kind::MalformedDescription, "akamai"),
        (
            "4:65535|0|0|m,a,s,p|extra",
            Kind::MalformedDescription,
            "akamai",
        ),
        (
            "00000000000000000000000000000000",
            Kind::LossyDescription,
            "akamai",
        ),
        (
            "4:65535|0|3:0:0:201|m,a,s,p",
            Kind::UnsupportedSetting,
            "akamai.priority",
        ),
        (
            "4:65535;unknown-secret:1|0|0|m,a,s,p",
            Kind::InvalidValue,
            "akamai.settings.id",
        ),
        (
            "7:0;4:65535|0|0|m,a,s,p",
            Kind::UnsupportedSetting,
            "akamai.settings.id",
        ),
        (
            "|0|0|m,a,s,p",
            Kind::UnsupportedSetting,
            "akamai.settings.initial_window_size",
        ),
        (
            "1:100|0|0|m,a,s,p",
            Kind::UnsupportedSetting,
            "akamai.settings.initial_window_size",
        ),
        (
            "4:65535;|0|0|m,a,s,p",
            Kind::MalformedDescription,
            "akamai.settings",
        ),
        (
            "2:2;4:65535|0|0|m,a,s,p",
            Kind::InvalidValue,
            "akamai.settings.value",
        ),
        (
            "8:2;4:65535|0|0|m,a,s,p",
            Kind::InvalidValue,
            "akamai.settings.value",
        ),
        (
            "9:2;4:65535|0|0|m,a,s,p",
            Kind::InvalidValue,
            "akamai.settings.value",
        ),
        (
            "4:+65535|0|0|m,a,s,p",
            Kind::InvalidValue,
            "akamai.settings.value",
        ),
        (
            "4:65535|0|0|m,a,s,unknown-secret",
            Kind::InvalidValue,
            "akamai.pseudo_headers",
        ),
        (
            "4:65535|0|0|m,a,s,p,m",
            Kind::InvalidValue,
            "akamai.pseudo_headers",
        ),
        ("4:65535|0|0|m,a,s,s", Kind::InvalidSettings, "http2"),
        ("4:65535;4:100|0|0|m,a,s,p", Kind::InvalidSettings, "http2"),
        ("4:2147483648|0|0|m,a,s,p", Kind::InvalidSettings, "http2"),
        ("4:65535;5:10|0|0|m,a,s,p", Kind::InvalidSettings, "http2"),
    ] {
        let error = import_akamai_profile(input, &base)
            .err()
            .ok_or("invalid input accepted")?;
        assert_eq!(error.kind(), kind, "{input}");
        assert_eq!(error.field(), field, "{input}");
        assert!(!format!("{error:?} {error}").contains("unknown-secret"));
    }
    Ok(())
}

#[test]
fn akamai_enforces_input_and_setting_count_bounds() -> TestResult {
    let base = chrome::v154_windows();
    for (input, field) in [
        ("x".repeat(32769), "akamai"),
        (
            format!("{}|0|0|m,a,s,p", vec!["4:65535"; 65].join(";")),
            "akamai.settings",
        ),
    ] {
        let error = import_akamai_profile(&input, &base)
            .err()
            .ok_or("unbounded input accepted")?;
        assert_eq!(error.kind(), Kind::TooLarge);
        assert_eq!(error.field(), field);
    }
    Ok(())
}
