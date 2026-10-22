use std::time::Duration;

use phantom_profile::browser::firefox;
use serde_json::json;

use super::super::{
    FingerprintImportErrorKind as Kind, describe_profile, export_profile_json, import_profile_json,
};
use super::profiles::{TestResult, import};

#[test]
fn edited_dns_grace_round_trips_without_changing_other_settings() -> TestResult {
    let profile = firefox::v157_windows();
    let mut document = describe_profile(&profile)?;
    document["profile"]["dns_cache"]["stale_grace"] = json!({"seconds": 12, "nanoseconds": 345});
    let mut settings = *profile.dns_cache().ok_or("missing DNS settings")?;
    settings.stale_grace = Duration::new(12, 345);
    let expected = profile.with_dns_cache(settings);

    let actual = import(&document)?;

    assert_eq!(actual, expected);
    assert_eq!(
        import_profile_json(&export_profile_json(&actual)?)?,
        expected
    );
    Ok(())
}

#[test]
fn dns_grace_requires_a_complete_duration() -> TestResult {
    let document = describe_profile(&firefox::v157_windows())?;
    for (invalid, kind, field) in [
        (json!(null), Kind::InvalidValue, "dns_cache.stale_grace"),
        (json!(600), Kind::InvalidValue, "dns_cache.stale_grace"),
        (
            json!({"seconds": 1}),
            Kind::MissingField,
            "dns_cache.stale_grace",
        ),
        (
            json!({"seconds": -1, "nanoseconds": 0}),
            Kind::InvalidValue,
            "document",
        ),
        (
            json!({"seconds": 1, "nanoseconds": 1_000_000_000}),
            Kind::InvalidValue,
            "dns_cache.stale_grace",
        ),
    ] {
        let mut value = document.clone();
        value["profile"]["dns_cache"]["stale_grace"] = invalid;

        let error = import_profile_json(&serde_json::to_vec(&value)?)
            .err()
            .ok_or("invalid grace duration was accepted")?;

        assert_eq!(error.kind(), kind);
        assert_eq!(error.field(), field);
    }
    let mut missing = document;
    missing["profile"]["dns_cache"]
        .as_object_mut()
        .ok_or("missing DNS settings")?
        .remove("stale_grace");
    let error = import_profile_json(&serde_json::to_vec(&missing)?)
        .err()
        .ok_or("missing grace duration was accepted")?;
    assert_eq!(error.kind(), Kind::MissingField);
    assert_eq!(error.field(), "dns_cache");
    Ok(())
}
