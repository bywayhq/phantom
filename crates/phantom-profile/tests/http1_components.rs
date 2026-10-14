//! Independent http1 factory values frozen at 51cd42aeaf9274cc59650846df1eebd7f3cc4c4c.

use phantom_profile::{Http1IdleTimeout, Http1Settings, browser};
use std::{num::NonZeroUsize, time::Duration};

#[test]
fn browser_factories_preserve_every_stored_field() {
    assert_eq!(browser::chrome::v154_http1(), chrome_original());
    assert_eq!(browser::firefox::v157_http1(), firefox_original());
}

#[test]
fn composed_profiles_keep_the_http1_timer_policy() -> Result<(), Box<dyn std::error::Error>> {
    for profile in [
        browser::chrome::v154_windows(),
        browser::edge::v154_windows(),
        browser::brave::v154_windows(),
        browser::opera::v136_windows(),
    ] {
        assert_eq!(*profile.http1().ok_or("lost HTTP/1.1")?, chrome_original());
    }
    assert_eq!(
        *browser::firefox::v157_windows()
            .http1()
            .ok_or("Firefox lost HTTP/1.1")?,
        firefox_original()
    );
    Ok(())
}
fn chrome_original() -> Http1Settings {
    Http1Settings {
        max_connections_per_origin: NonZeroUsize::new(6).unwrap_or(NonZeroUsize::MIN),
        idle_timeout: Http1IdleTimeout::CheckedOnRequest(Duration::from_secs(300)),
    }
}

fn firefox_original() -> Http1Settings {
    Http1Settings {
        max_connections_per_origin: NonZeroUsize::new(6).unwrap_or(NonZeroUsize::MIN),
        idle_timeout: Http1IdleTimeout::ClosedOnTimer(Duration::from_secs(115)),
    }
}
