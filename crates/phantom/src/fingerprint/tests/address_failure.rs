//! Closed failed-address policies retain native-size custom resource bounds.
use super::profiles::{TestResult, document, import};
use phantom_profile::{DnsAddressFailurePolicy, SystemDnsTtlPolicy, browser};
use serde_json::json;
use std::num::NonZeroUsize;

fn dns_document() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let mut value = document(0)?;
    value["profile"]["dns_cache"] = json!({
        "address_failure_policy":{"kind":"Ignore","max_unusable_addresses":null},
        "system_ttl":"Ignore", "max_entries":1000,
        "ttl":{"seconds":60,"nanoseconds":0},
        "min_record_ttl":{"seconds":60,"nanoseconds":0},"negative_ttl":null
    });
    Ok(value)
}

#[test]
fn address_failure_policies_preserve_cap_and_independent_system_ttl() -> TestResult {
    let mut value = dns_document()?;
    for (name, system_ttl) in [
        ("Ignore", SystemDnsTtlPolicy::Ignore),
        ("FirefoxWindows", SystemDnsTtlPolicy::FirefoxWindows),
    ] {
        value["profile"]["dns_cache"]["system_ttl"] = json!(name);
        let mut expected = browser::chrome::v154_dns_cache();
        expected.system_ttl = system_ttl;
        value["profile"]["dns_cache"]["address_failure_policy"] =
            json!({"kind":"Ignore","max_unusable_addresses":null});
        assert_eq!(import(&value)?.dns_cache(), Some(&expected));
        for cap in [1, 1600, usize::MAX] {
            value["profile"]["dns_cache"]["address_failure_policy"] =
                json!({"kind":"Record","max_unusable_addresses":cap});
            expected.address_failure_policy = DnsAddressFailurePolicy::Record {
                max_unusable_addresses: NonZeroUsize::new(cap).ok_or("zero test limit")?,
            };
            assert_eq!(import(&value)?.dns_cache(), Some(&expected));
        }
    }
    Ok(())
}

#[test]
fn address_failure_policy_requires_both_closed_fields_and_nonzero_native_cap() -> TestResult {
    let original = dns_document()?;
    for invalid in [
        json!(null),
        json!(true),
        json!("Ignore"),
        json!([]),
        json!({}),
        json!({"kind":"Ignore"}),
        json!({"max_unusable_addresses":1}),
        json!({"kind":null,"max_unusable_addresses":null}),
        json!({"kind":"Future","max_unusable_addresses":null}),
        json!({"kind":"Ignore","max_unusable_addresses":0}),
        json!({"kind":"Ignore","max_unusable_addresses":1}),
        json!({"kind":"Ignore","max_unusable_addresses":null,"extra":0}),
        json!({"kind":"Record","max_unusable_addresses":null}),
        json!({"kind":"Record","max_unusable_addresses":0}),
        json!({"kind":"Record","max_unusable_addresses":-1}),
        json!({"kind":"Record","max_unusable_addresses":true}),
        json!({"kind":"Record","max_unusable_addresses":"1"}),
        json!({"kind":"Record","max_unusable_addresses":1.0}),
        json!({"kind":"Record","max_unusable_addresses":1,"extra":0}),
    ] {
        let mut value = original.clone();
        value["profile"]["dns_cache"]["address_failure_policy"] = invalid;
        assert!(import(&value).is_err());
    }
    let mut missing = original.clone();
    missing["profile"]["dns_cache"]
        .as_object_mut()
        .ok_or("DNS record absent")?
        .remove("address_failure_policy");
    assert!(import(&missing).is_err());
    let mut record = original;
    record["profile"]["dns_cache"]["address_failure_policy"] =
        json!({"kind":"Record","max_unusable_addresses":1});
    assert!(import(&record).is_ok());
    let valid = serde_json::to_string(&record)?;
    let oversized = valid.replace(
        "\"max_unusable_addresses\":1",
        "\"max_unusable_addresses\":18446744073709551616",
    );
    assert_ne!(oversized, valid);
    assert!(super::super::import_profile_json(oversized.as_bytes()).is_err());
    if usize::BITS == 32 {
        record["profile"]["dns_cache"]["address_failure_policy"]["max_unusable_addresses"] =
            json!(u64::from(u32::MAX) + 1);
        assert!(import(&record).is_err());
    }
    Ok(())
}

#[test]
fn duplicate_policy_discriminants_and_caps_are_rejected() -> TestResult {
    let mut value = dns_document()?;
    value["profile"]["dns_cache"]["address_failure_policy"] =
        json!({"kind":"Record","max_unusable_addresses":1});
    let valid = serde_json::to_string(&value)?;
    assert!(import(&value).is_ok());
    for (field, duplicate) in [
        (
            "\"kind\":\"Record\"",
            "\"kind\":\"Record\",\"kind\":\"Record\"",
        ),
        (
            "\"max_unusable_addresses\":1",
            "\"max_unusable_addresses\":1,\"max_unusable_addresses\":1",
        ),
    ] {
        let invalid = valid.replace(field, duplicate);
        assert_ne!(invalid, valid);
        assert!(super::super::import_profile_json(invalid.as_bytes()).is_err());
    }
    Ok(())
}
