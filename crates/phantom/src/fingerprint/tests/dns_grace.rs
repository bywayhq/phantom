use std::time::Duration;

use phantom_profile::browser::firefox;
use serde_json::json;

use super::super::{describe_profile, export_profile_json, import_profile_json};
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
    for invalid in [
        json!(null),
        json!(600),
        json!({"seconds": 1}),
        json!({"seconds": -1, "nanoseconds": 0}),
        json!({"seconds": 1, "nanoseconds": 1_000_000_000}),
    ] {
        let mut value = document.clone();
        value["profile"]["dns_cache"]["stale_grace"] = invalid;

        let error = import_profile_json(&serde_json::to_vec(&value)?)
            .err()
            .ok_or("invalid grace duration was accepted")?;

        assert!(error.field().starts_with("dns_cache.stale_grace"));
    }
    let mut missing = document;
    missing["profile"]["dns_cache"]
        .as_object_mut()
        .ok_or("missing DNS settings")?
        .remove("stale_grace");
    assert!(import(&missing).is_err());
    Ok(())
}
