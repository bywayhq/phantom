use std::time::Duration;

use crate::{chromium, firefox};

#[test]
fn chromium_154_keeps_1000_answers_for_60_seconds_and_no_failures() {
    // `kDefaultCacheSize`, `net/dns/resolve_context.cc:110`, and the system
    // resolver TTLs, `net/dns/host_resolver_manager_job.cc:55-58`, at
    // `154.0.8037.58`.
    let settings = chromium::v154_dns_cache();

    assert_eq!(settings.max_entries.get(), 1000);
    assert_eq!(settings.ttl, Duration::from_secs(60));
    assert_eq!(settings.negative_ttl, None);
}

#[test]
fn firefox_156_keeps_1600_answers_and_failures_for_60_seconds() {
    // `network.dnsCacheEntries` and `network.dnsCacheExpiration`,
    // `modules/libpref/init/StaticPrefList.yaml:15552-15565`, and
    // `NEGATIVE_RECORD_LIFETIME`, `netwerk/dns/nsHostResolver.cpp:67`, at
    // `FIREFOX_156_0_RELEASE`.
    let settings = firefox::v156_dns_cache();

    assert_eq!(settings.max_entries.get(), 1600);
    assert_eq!(settings.ttl, Duration::from_secs(60));
    assert_eq!(settings.negative_ttl, Some(Duration::from_secs(60)));
}
