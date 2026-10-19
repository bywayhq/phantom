//! Independent pre-migration constructor bodies; do not generate these controls.

use phantom_profile::{
    ClientProfile, Http3ClientSettings,
    browser::{brave, chrome, edge, firefox, opera},
};

#[test]
fn brave_v153_android_keeps_its_component_selection() {
    let expected = brave_v153_android();
    assert_eq!(brave::v153_android(), expected);
}

fn brave_v153_android() -> ClientProfile {
    ClientProfile::new(brave::v153_android_tcp_tls())
        .with_http2(brave::v153_android_http2())
        .with_http3(Http3ClientSettings::new(
            brave::v153_android_quic_tls(),
            brave::v153_android_quic(),
            brave::v153_android_http3(),
            brave::v153_android_http3_request(),
        ))
        .with_client_hints(brave::v153_android_client_hints())
        .with_websocket(brave::v153_android_websocket())
}

#[test]
fn brave_v154_windows_keeps_its_component_selection() {
    let expected = brave_v154_windows();
    assert_eq!(brave::v154_windows(), expected);
}

fn brave_v154_windows() -> ClientProfile {
    ClientProfile::new(brave::v154_tcp_tls())
        .with_tcp(chrome::v154_tcp())
        .with_udp(chrome::v154_udp())
        .with_dns_cache(chrome::v154_dns_cache())
        .with_http1(chrome::v154_http1())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            brave::v154_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
        .with_client_hints(brave::v154_windows_client_hints())
        .with_websocket(chrome::v154_websocket())
        .with_proxy_connect(chrome::v154_proxy_connect())
        .with_cookie_placement(chrome::v154_cookie_placement())
}

#[test]
fn chrome_v154_android_keeps_its_component_selection() {
    let expected = chrome_v154_android();
    assert_eq!(chrome::v154_android(), expected);
}

fn chrome_v154_android() -> ClientProfile {
    ClientProfile::new(chrome::v154_android_tcp_tls())
        .with_tcp(chrome::v154_android_tcp())
        .with_http2(chrome::v154_android_http2())
        .with_http3(Http3ClientSettings::new(
            chrome::v154_android_quic_tls(),
            chrome::v154_android_quic(),
            chrome::v154_android_http3(),
            chrome::v154_android_http3_request(),
        ))
        .with_client_hints(chrome::v154_android_client_hints())
        .with_websocket(chrome::v154_android_websocket())
}

#[test]
fn chrome_v154_macos_keeps_its_component_selection() {
    let expected = chrome_v154_macos();
    assert_eq!(chrome::v154_macos(), expected);
}

fn chrome_v154_macos() -> ClientProfile {
    ClientProfile::new(chrome::v154_tcp_tls())
        .with_tcp(chrome::v154_macos_tcp())
        .with_http1(chrome::v154_http1())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            chrome::v154_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
        .with_client_hints(chrome::v154_macos_client_hints())
        .with_websocket(chrome::v154_websocket())
        .with_proxy_connect(chrome::v154_proxy_connect())
        .with_cookie_placement(chrome::v154_cookie_placement())
}

#[test]
fn chrome_v154_windows_keeps_its_component_selection() {
    let expected = chrome_v154_windows();
    assert_eq!(chrome::v154_windows(), expected);
}

fn chrome_v154_windows() -> ClientProfile {
    ClientProfile::new(chrome::v154_tcp_tls())
        .with_tcp(chrome::v154_tcp())
        .with_udp(chrome::v154_udp())
        .with_dns_cache(chrome::v154_dns_cache())
        .with_http1(chrome::v154_http1())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            chrome::v154_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
        .with_client_hints(chrome::v154_windows_client_hints())
        .with_websocket(chrome::v154_websocket())
        .with_proxy_connect(chrome::v154_proxy_connect())
        .with_cookie_placement(chrome::v154_cookie_placement())
}

#[test]
fn edge_v153_android_keeps_its_component_selection() {
    let expected = edge_v153_android();
    assert_eq!(edge::v153_android(), expected);
}

fn edge_v153_android() -> ClientProfile {
    ClientProfile::new(edge::v153_android_tcp_tls())
        .with_http2(edge::v153_android_http2())
        .with_http3(Http3ClientSettings::new(
            edge::v153_android_quic_tls(),
            edge::v153_android_quic(),
            edge::v153_android_http3(),
            edge::v153_android_http3_request(),
        ))
        .with_client_hints(edge::v153_android_client_hints())
        .with_websocket(edge::v153_android_websocket())
}

#[test]
fn edge_v153_windows_keeps_its_component_selection() {
    let expected = edge_v153_windows();
    assert_eq!(edge::v153_windows(), expected);
}

fn edge_v153_windows() -> ClientProfile {
    ClientProfile::new(edge::v153_tcp_tls())
        .with_http2(edge::v153_http2())
        .with_http3(Http3ClientSettings::new(
            edge::v153_quic_tls(),
            edge::v153_quic(),
            edge::v153_http3(),
            edge::v153_http3_request(),
        ))
        .with_client_hints(edge::v153_windows_client_hints())
}

#[test]
fn edge_v154_windows_keeps_its_component_selection() {
    let expected = edge_v154_windows();
    assert_eq!(edge::v154_windows(), expected);
}

fn edge_v154_windows() -> ClientProfile {
    ClientProfile::new(edge::v154_tcp_tls())
        .with_tcp(chrome::v154_tcp())
        .with_udp(chrome::v154_udp())
        .with_dns_cache(chrome::v154_dns_cache())
        .with_http1(chrome::v154_http1())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            edge::v154_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
        .with_client_hints(edge::v154_windows_client_hints())
        .with_websocket(chrome::v154_websocket())
        .with_proxy_connect(chrome::v154_proxy_connect())
        .with_cookie_placement(chrome::v154_cookie_placement())
}

#[test]
fn firefox_v156_android_keeps_its_component_selection() {
    let expected = firefox_v156_android();
    assert_eq!(firefox::v156_android(), expected);
}

fn firefox_v156_android() -> ClientProfile {
    ClientProfile::new(firefox::v156_android_tcp_tls()).with_tcp(firefox::v156_android_tcp())
}

#[test]
fn firefox_v157_windows_keeps_its_component_selection() {
    let expected = firefox_v157_windows();
    assert_eq!(firefox::v157_windows(), expected);
}

fn firefox_v157_windows() -> ClientProfile {
    ClientProfile::new(firefox::v157_tcp_tls())
        .with_tcp(firefox::v157_tcp())
        .with_dns_cache(firefox::v157_dns_cache())
        .with_http1(firefox::v157_http1())
        .with_http2(firefox::v157_http2())
        .with_http3(Http3ClientSettings::new(
            firefox::v157_quic_tls(),
            firefox::v157_quic(),
            firefox::v157_http3(),
            firefox::v157_http3_request(),
        ))
        .with_websocket(firefox::v157_websocket())
        .with_proxy_connect(firefox::v157_proxy_connect())
        .with_cookie_placement(firefox::v157_cookie_placement())
}

#[test]
fn opera_v102_android_keeps_its_component_selection() {
    let expected = opera_v102_android();
    assert_eq!(opera::v102_android(), expected);
}

fn opera_v102_android() -> ClientProfile {
    ClientProfile::new(opera::v102_android_tcp_tls())
        .with_client_hints(opera::v102_android_client_hints())
}

#[test]
fn opera_v136_windows_keeps_its_component_selection() {
    let expected = opera_v136_windows();
    assert_eq!(opera::v136_windows(), expected);
}

fn opera_v136_windows() -> ClientProfile {
    ClientProfile::new(opera::v136_tcp_tls())
        .with_tcp(chrome::v154_tcp())
        .with_udp(chrome::v154_udp())
        .with_dns_cache(chrome::v154_dns_cache())
        .with_http1(chrome::v154_http1())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            opera::v136_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
        .with_client_hints(opera::v136_windows_client_hints())
        .with_websocket(chrome::v154_websocket())
        .with_proxy_connect(chrome::v154_proxy_connect())
        .with_cookie_placement(chrome::v154_cookie_placement())
}
