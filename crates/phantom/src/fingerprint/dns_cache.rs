//! Complete DNS cache description parsing.

use super::{
    Result,
    json::{self, Value},
};
use phantom_profile::{DnsAddressFailurePolicy, DnsCacheSettings, SystemDnsTtlPolicy};

pub(super) fn parse(v: &Value) -> Result<DnsCacheSettings> {
    v.record(
        &[
            "address_failure_policy",
            "max_entries",
            "ttl",
            "min_record_ttl",
            "negative_ttl",
            "system_ttl",
        ],
        "dns_cache",
    )?;
    let settings = DnsCacheSettings {
        address_failure_policy: address_failure_policy(
            v.member("address_failure_policy", "dns_cache.address_failure_policy")?,
        )?,
        system_ttl: match v
            .member("system_ttl", "dns_cache.system_ttl")?
            .text("dns_cache.system_ttl")?
        {
            "Ignore" => SystemDnsTtlPolicy::Ignore,
            "FirefoxWindows" => SystemDnsTtlPolicy::FirefoxWindows,
            _ => return Err(json::unsupported("dns_cache.system_ttl")),
        },
        max_entries: v
            .member("max_entries", "dns_cache.max_entries")?
            .nonzero_usize("dns_cache.max_entries")?,
        ttl: v
            .member("ttl", "dns_cache.ttl")?
            .duration("dns_cache.ttl")?,
        min_record_ttl: v
            .member("min_record_ttl", "dns_cache.min_record_ttl")?
            .duration("dns_cache.min_record_ttl")?,
        negative_ttl: v
            .member("negative_ttl", "dns_cache.negative_ttl")?
            .optional(|v| v.duration("dns_cache.negative_ttl"))?,
    };
    Ok(settings)
}

fn address_failure_policy(v: &Value) -> Result<DnsAddressFailurePolicy> {
    v.record(
        &["kind", "max_unusable_addresses"],
        "dns_cache.address_failure_policy",
    )?;
    let limit = v.member(
        "max_unusable_addresses",
        "dns_cache.address_failure_policy.max_unusable_addresses",
    )?;
    match v
        .member("kind", "dns_cache.address_failure_policy.kind")?
        .text("dns_cache.address_failure_policy.kind")?
    {
        "Ignore" => {
            limit.null("dns_cache.address_failure_policy.max_unusable_addresses")?;
            Ok(DnsAddressFailurePolicy::Ignore)
        }
        "Record" => Ok(DnsAddressFailurePolicy::Record {
            max_unusable_addresses: limit
                .nonzero_usize("dns_cache.address_failure_policy.max_unusable_addresses")?,
        }),
        _ => Err(json::unsupported("dns_cache.address_failure_policy.kind")),
    }
}
