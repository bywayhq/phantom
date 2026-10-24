//! Independent TCP factory values frozen at cba97f37b4ed65f3b8a83df4a0474f6d762db162.

use phantom_profile::{
    TcpAddressRacing, TcpAddressSelection, TcpBackupConnection, TcpKeepalive, TcpKeepalivePolicy,
    TcpKeepaliveSchedule, TcpPortRandomization, TcpSettings, browser,
};
use std::{num::NonZeroU32, time::Duration};

type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn browser_tcp_factories_preserve_every_stored_field() -> TestResult {
    for (actual, original) in [
        (browser::chrome::v154_tcp(), chrome_original()),
        (browser::firefox::v157_tcp(), firefox_original()),
    ] {
        actual.validate()?;
        original.validate()?;
        assert_eq!(actual, original);
    }
    Ok(())
}
#[test]
fn composed_profiles_preserve_tcp_policies_and_custom_ownership() -> TestResult {
    for profile in [
        browser::chrome::v154_windows(),
        browser::edge::v154_windows(),
        browser::brave::v154_windows(),
        browser::opera::v136_windows(),
    ] {
        assert_eq!(
            *profile.tcp().ok_or("composed profile lost TCP")?,
            chrome_original()
        );
    }
    assert_eq!(
        *browser::firefox::v157_windows_r2()
            .tcp()
            .ok_or("Firefox lost TCP")?,
        firefox_original()
    );
    let mut current = firefox_original();
    let TcpAddressSelection::Backup(ref mut backup) = current.address_selection else {
        return Err("Firefox backup policy absent".into());
    };
    backup.socks_proxy_dns_feedback =
        phantom_profile::SocksProxyDnsFeedback::InitialConnectFailures;
    assert_eq!(
        *browser::firefox::v157_windows()
            .tcp()
            .ok_or("current Firefox lost TCP")?,
        current
    );
    for mut custom in [browser::chrome::v154_tcp(), browser::firefox::v157_tcp()] {
        custom.nodelay = false;
        custom.keepalive = TcpKeepalivePolicy::Unchanged;
        assert_ne!(custom, browser::chrome::v154_tcp());
        assert_ne!(custom, browser::firefox::v157_tcp());
    }
    assert_eq!(browser::chrome::v154_tcp(), chrome_original());
    assert_eq!(browser::firefox::v157_tcp(), firefox_original());
    Ok(())
}
fn chrome_original() -> TcpSettings {
    const KEEPALIVE: Duration = Duration::from_secs(45);

    TcpSettings {
        nodelay: true,
        send_buffer_size: None,
        keepalive: TcpKeepalivePolicy::Fixed(TcpKeepalive {
            idle: KEEPALIVE,
            interval: Some(KEEPALIVE),
        }),
        address_selection: TcpAddressSelection::Racing(TcpAddressRacing {
            fallback_delay: Duration::from_millis(300),
        }),
        port_randomization: Some(TcpPortRandomization {
            minimum_windows_build: 22_621,
        }),
    }
}

fn firefox_original() -> TcpSettings {
    TcpSettings {
        nodelay: true,
        send_buffer_size: NonZeroU32::new(524_288),
        keepalive: TcpKeepalivePolicy::Schedule(TcpKeepaliveSchedule {
            short_lived_idle: Duration::from_secs(10),
            long_lived_idle: Duration::from_secs(600),
            minimum_interval: Duration::from_secs(1),
            short_lived_time: Duration::from_secs(60),
            probe_count: 10,
            set_interval: true,
            set_probe_count: false,
        }),
        address_selection: TcpAddressSelection::Backup(TcpBackupConnection {
            delay: Duration::from_millis(250),
            known_family_backup_timeout: Some(Duration::from_secs(5)),
            socks_proxy_dns_feedback: phantom_profile::SocksProxyDnsFeedback::AllConnectFailures,
        }),
        port_randomization: None,
    }
}

#[test]
fn platform_tcp_factories_keep_their_complete_source_policies() -> TestResult {
    let mut chrome_macos = chrome_original();
    chrome_macos.keepalive = TcpKeepalivePolicy::Fixed(TcpKeepalive {
        idle: Duration::from_secs(45),
        interval: None,
    });
    chrome_macos.port_randomization = None;
    let mut chrome_android = chrome_original();
    chrome_android.keepalive = TcpKeepalivePolicy::Unchanged;
    chrome_android.port_randomization = None;

    let mut firefox_macos = firefox_original();
    firefox_macos.send_buffer_size = None;
    firefox_macos.keepalive = TcpKeepalivePolicy::Schedule(TcpKeepaliveSchedule {
        short_lived_idle: Duration::from_secs(10),
        long_lived_idle: Duration::from_secs(600),
        minimum_interval: Duration::from_secs(1),
        short_lived_time: Duration::from_secs(60),
        probe_count: 8,
        set_interval: false,
        set_probe_count: false,
    });
    let mut firefox_linux = firefox_macos;
    firefox_linux.keepalive = TcpKeepalivePolicy::Schedule(TcpKeepaliveSchedule {
        short_lived_idle: Duration::from_secs(10),
        long_lived_idle: Duration::from_secs(600),
        minimum_interval: Duration::from_secs(1),
        short_lived_time: Duration::from_secs(60),
        probe_count: 4,
        set_interval: true,
        set_probe_count: true,
    });

    for (actual, expected) in [
        (browser::chrome::v154_macos_tcp(), chrome_macos),
        (browser::chrome::v154_android_tcp(), chrome_android),
        (browser::firefox::v157_macos_tcp(), firefox_macos),
        (browser::firefox::v157_linux_tcp(), firefox_linux),
        (browser::firefox::v156_android_tcp(), firefox_linux),
    ] {
        actual.validate()?;
        assert_eq!(actual, expected);
    }
    assert_eq!(browser::chrome::v154_android().tcp(), Some(&chrome_android));
    assert_eq!(browser::firefox::v156_android().tcp(), Some(&firefox_linux));
    Ok(())
}
