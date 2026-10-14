//! Independent udp factory values frozen at 51cd42aeaf9274cc59650846df1eebd7f3cc4c4c.

use phantom_profile::{UdpSettings, browser};

#[test]
fn browser_factories_preserve_every_stored_field() {
    assert_eq!(browser::chrome::v154_udp(), chrome_original());
}

#[test]
fn composed_profiles_keep_udp_port_randomization() -> Result<(), Box<dyn std::error::Error>> {
    for profile in [
        browser::chrome::v154_windows(),
        browser::edge::v154_windows(),
        browser::brave::v154_windows(),
        browser::opera::v136_windows(),
    ] {
        assert_eq!(*profile.udp().ok_or("lost UDP")?, chrome_original());
    }
    assert!(browser::firefox::v157_windows().udp().is_none());
    Ok(())
}
fn chrome_original() -> UdpSettings {
    UdpSettings {
        port_randomization: true,
    }
}
