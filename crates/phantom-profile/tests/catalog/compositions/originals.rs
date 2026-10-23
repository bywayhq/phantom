// Independent pre-migration composition oracle, read from the ten original
// browser factory bodies. Component literal controls live in their layer tests.
use phantom_profile::{
    ClientProfile, Http3ClientSettings,
    browser::{brave, chrome, edge, firefox, opera},
};

pub(super) fn profiles() -> [(&'static str, ClientProfile); 10] {
    [
        ("chrome/154.0.8037.97/windows-11-26200/r1", chrome_windows()),
        (
            "chrome/154.0.8037.57/android-17-pixel7-emulator/r1",
            chrome_android(),
        ),
        ("edge/154.0.4258.48/windows-11-26200/r1", edge_windows()),
        (
            "edge/153.0.4234.49/android-17-pixel7-emulator/r1",
            edge_android(),
        ),
        ("brave/154.1.96.59/windows-11-26200/r1", brave_windows()),
        (
            "brave/153.1.95.104/android-17-pixel7-emulator/r1",
            brave_android(),
        ),
        ("firefox/157.0/windows-11-26200/r2", firefox_windows()),
        ("firefox/156.0.1/android-35-emulator/r1", firefox_android()),
        ("opera/136.0.6008.52/windows-11-26200/r1", opera_windows()),
        (
            "opera/102.1.5206.90382/android-17-pixel7-emulator/r1",
            opera_android(),
        ),
    ]
}

fn chrome_windows() -> ClientProfile {
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

fn chrome_android() -> ClientProfile {
    ClientProfile::new(chrome::v154_android_tcp_tls())
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

fn edge_windows() -> ClientProfile {
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

fn edge_android() -> ClientProfile {
    ClientProfile::new(edge::v153_android_tcp_tls())
        .with_http2(edge::v153_android_http2())
        .with_http3(Http3ClientSettings::new(
            edge::v153_android_quic_tls(),
            edge::v153_android_quic(),
            edge::v153_android_http3(),
            edge::v153_android_http3_request(),
        ))
        .with_client_hints(edge::v153_android_client_hints())
}

fn brave_windows() -> ClientProfile {
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

fn brave_android() -> ClientProfile {
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

fn firefox_windows() -> ClientProfile {
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

fn firefox_android() -> ClientProfile {
    ClientProfile::new(firefox::v156_android_tcp_tls())
}

fn opera_windows() -> ClientProfile {
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

fn opera_android() -> ClientProfile {
    ClientProfile::new(opera::v102_android_tcp_tls())
        .with_client_hints(opera::v102_android_client_hints())
}
