//! Browser DNS lifetimes and resource limits.

use phantom_profile::{DnsCacheSettings, SystemDnsTtlPolicy, browser};
use std::{num::NonZeroUsize, time::Duration};

#[test]
fn browser_factories_preserve_every_stored_field() {
    assert_eq!(browser::chrome::v154_dns_cache(), chrome_original());
    assert_eq!(browser::firefox::v157_dns_cache(), firefox_original());
}

#[test]
fn composed_profiles_keep_address_cache_lifetimes() -> Result<(), Box<dyn std::error::Error>> {
    for profile in [
        browser::chrome::v154_windows(),
        browser::edge::v154_windows(),
        browser::brave::v154_windows(),
        browser::opera::v136_windows(),
    ] {
        assert_eq!(
            *profile.dns_cache().ok_or("lost DNS cache")?,
            chrome_original()
        );
    }
    assert_eq!(
        *browser::firefox::v157_windows()
            .dns_cache()
            .ok_or("Firefox lost DNS cache")?,
        firefox_original()
    );
    let mut custom = browser::chrome::v154_dns_cache();
    custom.negative_ttl = Some(Duration::ZERO);
    assert_ne!(custom, chrome_original());
    assert_eq!(browser::chrome::v154_dns_cache(), chrome_original());
    Ok(())
}
fn chrome_original() -> DnsCacheSettings {
    DnsCacheSettings {
        address_failure_policy: phantom_profile::DnsAddressFailurePolicy::Ignore,
        system_ttl: SystemDnsTtlPolicy::Ignore,
        max_entries: NonZeroUsize::new(1000).unwrap_or(NonZeroUsize::MIN),
        ttl: Duration::from_secs(60),
        min_record_ttl: Duration::from_secs(60),
        stale_grace: Duration::ZERO,
        negative_ttl: None,
    }
}

fn firefox_original() -> DnsCacheSettings {
    DnsCacheSettings {
        address_failure_policy: phantom_profile::DnsAddressFailurePolicy::Record {
            max_unusable_addresses: NonZeroUsize::new(1600).unwrap_or(NonZeroUsize::MIN),
        },
        system_ttl: SystemDnsTtlPolicy::FirefoxWindows,
        max_entries: NonZeroUsize::new(1600).unwrap_or(NonZeroUsize::MIN),
        ttl: Duration::from_secs(60),
        min_record_ttl: Duration::ZERO,
        stale_grace: Duration::from_secs(600),
        negative_ttl: Some(Duration::from_secs(60)),
    }
}
