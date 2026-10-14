//! Independent proxy_connect values frozen at f2d6cb84bbd01d78d2b21062efac43c0f75fe9bd.

use phantom_profile::{
    Http2ProxyConnections, Http2RejectedConnect, ProxyConnectField, ProxyConnectTemplate, browser,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;
#[test]
fn browser_connect_factories_preserve_every_field_and_policy() -> TestResult {
    for (actual, original) in [
        (browser::chrome::v154_proxy_connect(), chrome_original()),
        (browser::firefox::v157_proxy_connect(), firefox_original()),
    ] {
        actual.validate()?;
        original.validate()?;
        assert_eq!(actual, original);
    }
    Ok(())
}
#[test]
fn composed_connect_profiles_and_custom_values_keep_ownership() -> TestResult {
    for profile in [
        browser::chrome::v154_windows(),
        browser::edge::v154_windows(),
        browser::brave::v154_windows(),
        browser::opera::v136_windows(),
    ] {
        assert_eq!(
            *profile.proxy_connect().ok_or("profile lost CONNECT")?,
            chrome_original()
        );
    }
    assert_eq!(
        *browser::firefox::v157_windows()
            .proxy_connect()
            .ok_or("Firefox lost CONNECT")?,
        firefox_original()
    );
    for mut custom in [
        browser::chrome::v154_proxy_connect(),
        browser::firefox::v157_proxy_connect(),
    ] {
        custom.http1_fields.clear();
        custom.http2_fields.clear();
        assert!(custom.validate().is_err());
    }
    assert_eq!(browser::chrome::v154_proxy_connect(), chrome_original());
    assert_eq!(browser::firefox::v157_proxy_connect(), firefox_original());
    let default = phantom_profile::ClientProfile::new(browser::chrome::v154_tcp_tls());
    assert_eq!(default.proxy_connect(), None);
    Ok(())
}
fn chrome_original() -> ProxyConnectTemplate {
    ProxyConnectTemplate {
        http1_fields: vec![
            ProxyConnectField::authority("Host"),
            ProxyConnectField::literal("Proxy-Connection", "keep-alive"),
            ProxyConnectField::from_request("User-Agent"),
            ProxyConnectField::proxy_authorization("Proxy-Authorization"),
        ],
        http2_fields: vec![
            ProxyConnectField::from_request("user-agent"),
            ProxyConnectField::proxy_authorization("proxy-authorization"),
        ],
        http2_rejected: Http2RejectedConnect::EndStream,
        http2_connections: Http2ProxyConnections::Shared,
    }
}

fn firefox_original() -> ProxyConnectTemplate {
    ProxyConnectTemplate {
        http1_fields: vec![
            ProxyConnectField::from_request("User-Agent"),
            ProxyConnectField::literal("Proxy-Connection", "keep-alive"),
            ProxyConnectField::literal("Connection", "keep-alive"),
            ProxyConnectField::authority("Host"),
            ProxyConnectField::proxy_authorization("Proxy-Authorization"),
        ],
        http2_fields: vec![
            ProxyConnectField::from_request("user-agent"),
            ProxyConnectField::proxy_authorization("proxy-authorization"),
        ],
        http2_rejected: Http2RejectedConnect::LeaveOpen,
        http2_connections: Http2ProxyConnections::ByPurpose,
    }
}
