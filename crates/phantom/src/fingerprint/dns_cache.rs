//! Complete DNS cache description parsing.

use super::{Result, json::Value};
use phantom_profile::DnsCacheSettings;

pub(super) fn parse(v: &Value) -> Result<DnsCacheSettings> {
    v.record(
        &["max_entries", "ttl", "min_record_ttl", "negative_ttl"],
        "dns_cache",
    )?;
    let settings = DnsCacheSettings {
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
