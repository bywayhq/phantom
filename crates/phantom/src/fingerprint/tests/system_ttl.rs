use super::profiles::{TestResult, document, import};
use phantom_profile::SystemDnsTtlPolicy;
use serde_json::json;

#[test]
fn system_ttl_policy_is_required_and_closed() -> TestResult {
    let mut value = document(0)?;
    let mut settings = phantom_profile::browser::chrome::v154_dns_cache();
    value["profile"]["dns_cache"] = json!({"address_failure_policy":{"kind":"Ignore","max_unusable_addresses":null},"max_entries":1000,"ttl":{"seconds":60,"nanoseconds":0},"min_record_ttl":{"seconds":60,"nanoseconds":0},"negative_ttl":null,"system_ttl":"Ignore"});
    for (name, policy) in [
        ("Ignore", SystemDnsTtlPolicy::Ignore),
        ("FirefoxWindows", SystemDnsTtlPolicy::FirefoxWindows),
    ] {
        value["profile"]["dns_cache"]["system_ttl"] = json!(name);
        settings.system_ttl = policy;
        assert_eq!(import(&value)?.dns_cache(), Some(&settings));
    }
    value["profile"]["dns_cache"]["system_ttl"] = json!("FuturePolicy");
    assert!(import(&value).is_err());
    value["profile"]["dns_cache"]["system_ttl"] = json!(null);
    assert!(import(&value).is_err());
    value["profile"]["dns_cache"]
        .as_object_mut()
        .ok_or("DNS settings absent")?
        .remove("system_ttl");
    assert!(import(&value).is_err());
    Ok(())
}
