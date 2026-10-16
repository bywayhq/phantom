use super::*;
use phantom_profile::{DnsAddressFailurePolicy, SystemDnsTtlPolicy};
use std::num::NonZeroUsize;

#[test]
fn address_failure_policy_and_cap_change_tcp_and_quic_cache_identity() -> TestResult {
    use super::super::descriptor::{TicketCacheLeg, TicketCacheProtocol};
    let origin = cache_endpoint("origin.example", 443)?;
    let source = phantom_net::SourceBinding::new();
    for protocol in [TicketCacheProtocol::Http1, TicketCacheProtocol::Http3] {
        let mut policies = Vec::new();
        let mut configured = Vec::new();
        for system_ttl in [
            SystemDnsTtlPolicy::Ignore,
            SystemDnsTtlPolicy::FirefoxWindows,
        ] {
            for failure_policy in [
                DnsAddressFailurePolicy::Ignore,
                DnsAddressFailurePolicy::Record {
                    max_unusable_addresses: NonZeroUsize::MIN,
                },
                DnsAddressFailurePolicy::Record {
                    max_unusable_addresses: NonZeroUsize::new(1600).ok_or("zero test limit")?,
                },
            ] {
                let mut dns = chrome::v154_dns_cache();
                dns.system_ttl = system_ttl;
                dns.address_failure_policy = failure_policy;
                let profile = chrome::v154_windows().with_dns_cache(dns);
                let encoded = profile::encode(&profile, None, None)?;
                for prior in &configured {
                    assert_ne!(prior, &encoded);
                }
                configured.push(encoded);
                let prepared = BindingPlan::capture(&profile)?
                    .complete(&profile)?
                    .with_client_context(client_context(&source))?;
                let current = prepared.prepare_cache_descriptor(
                    &origin,
                    "origin.example",
                    TicketCacheLeg::Origin,
                    protocol,
                    &crate::Route::Direct,
                )?;
                for prior in &policies {
                    assert!(prior != &current.policy);
                }
                policies.push(current.policy);
            }
        }
        assert_eq!(policies.len(), 6);
    }
    Ok(())
}
