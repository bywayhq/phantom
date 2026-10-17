//! dns cache settings in the custom-profile format.

use super::{Encode, Encoder, Result};
use phantom_profile::*;
use serde_json::Value;

impl Encode for DnsAddressFailurePolicy {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        match self {
            Self::Ignore => {
                object!(e, f, "kind" => "Ignore", "max_unusable_addresses" => &Option::<u8>::None)
            }
            Self::Record {
                max_unusable_addresses,
            } => {
                object!(e, f, "kind" => "Record", "max_unusable_addresses" => max_unusable_addresses)
            }
        }
    }
}

impl Encode for SystemDnsTtlPolicy {
    fn encode(&self, e: &mut Encoder, f: &str) -> Result<Value> {
        match self {
            Self::Ignore => "Ignore".encode(e, f),
            Self::FirefoxWindows => "FirefoxWindows".encode(e, f),
        }
    }
}
record!(
    DnsCacheSettings,
    address_failure_policy,
    system_ttl,
    max_entries,
    ttl,
    min_record_ttl,
    negative_ttl
);
