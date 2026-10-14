//! Wire settings retained from Opera browser observations.
//!
//! Opera 136.0.6008.52 on Windows 11 (build 26200) is built on Chromium
//! 152.0.7977.130, and Phantom carries no Chromium 152 recipe, so each Opera
//! capture is compared with the Chrome 154 recipes. Opera matches them on the
//! H2 startup, request pseudo-header order and priority, extended CONNECT
//! shape, WebSocket connection choice and opening fields, proxy CONNECT
//! fields, QUIC transport parameters, H3 SETTINGS and request order, and the
//! request fields other than `User-Agent`. Those captures are replayed
//! against [`chrome::v154_http2`], [`chrome::v154_websocket`],
//! [`chrome::v154_proxy_connect`], [`chrome::v154_quic`],
//! [`chrome::v154_http3`], and [`chrome::v154_http3_request`]. The
//! trust-anchor IDs and the client hints differ, so only the TLS offers and
//! client hints, and request templates with a caller `User-Agent`, have Opera
//! recipes here.
//!
//! The retained Opera cookie captures place `Cookie` and split it into crumbs
//! as Chrome 154 does over HTTP/1.1, HTTP/2, and HTTP/3, so they are replayed
//! against [`chrome::v154_cookie_placement`] with the H2 and H3 recipes.
//!
//! Opera's network-stack source is not public, and no wire capture shows socket
//! options or cache lifetimes. Frida hook logs of Opera 136's network service,
//! under `fixtures/socket-hooks/`, show the `TCP_NODELAY`, keepalive, and
//! `SO_RANDOMIZE_PORT` of [`chrome::v154_tcp`] on every origin socket, the
//! `SO_RANDOMIZE_PORT` of [`chrome::v154_udp`] on every UDP socket it
//! opens, its 300 ms IPv4 fallback, six connections to one origin as in
//! [`chrome::v154_http1`], and system-resolver answers kept for the 60 s of
//! [`chrome::v154_dns_cache`], as Chrome 154's logs do. Opera profiles
//! therefore use those recipes; Opera has no TCP, UDP, HTTP/1.1 connection,
//! or address cache recipe of its own.
//!
//! On macOS 15.5 arm64, Opera 136.0.6008.52 sends the Windows client hints
//! with macOS platform data, [`v136_macos_client_hints`], and the fields of the
//! Windows request templates.

//!
//! ## Android
//!
//! Wire settings retained from Opera for Android observations.
//!
//! Opera 102.1.5206.90382, built on Chromium 152.0.7977.82, as the Google
//! Play Store served it to two emulators: the `phantom-pixel7` Android 17
//! emulator, which reports a Pixel 7, for the TLS and client-hint captures,
//! and the earlier `phantom-api35-play` Android 15 emulator for the HTTP/1.1
//! request captures.
//!
//! Opera for Android reads no command-line file, so no capture can map a test
//! name, trust a test certificate, force QUIC, or route through a proxy: it
//! reaches only the device's own loopback. The retained captures therefore
//! cover the TCP ClientHello, sent to `https://localhost`, and client hints
//! and plaintext HTTP/1.1 requests to `http://127.0.0.1`. Only the TLS and
//! client-hint layers have recipes here. With no HTTP/2 or HTTP/3 capture,
//! there are no request templates, and no H2, QUIC, H3, or WebSocket recipe.
//!
//! There is no TCP, HTTP/1.1 connection, address-cache, proxy CONNECT, or
//! cookie-placement recipe, for the reasons given in [`crate::browser::opera`] and
//! [`crate::browser::chrome`].

use crate::{ClientProfile, Http3ClientSettings};

mod android;

pub use android::{
    v102_android_client_hints, v102_android_client_hints_for_model, v102_android_tcp_tls,
};

use crate::{
    browser::chrome, client_hints::ClientHintSettings, request_template::RequestTemplate,
    tls::TlsSettings,
};

/// Returns TLS settings captured from Opera 136.0.6008.52 on Windows 11.
///
/// Opera 136.0.6008.52 (Windows 11 build 26200) sends the Chrome 154 TCP
/// ClientHello, signature-algorithm GREASE included, in all 29 processes
/// whose ClientHellos are retained (20 startups and 9 resumption runs), with
/// one difference: its trust-anchor IDs extension carries 32 IDs in a
/// per-process order where Chrome 154 sends 28 in sorted order. This reuses
/// [`chrome::v154_tcp_tls`] with [`crate::TrustAnchorIds::PerClient`]: each client
/// draws one of the 29 processes' orders, 16 distinct, and keeps it on every
/// TCP connection, as a process does. The retained `client-hello.txt` is
/// replayed against the result. It keeps [`TlsSettings::ech`] on HTTPS
/// records: given an HTTPS record with `ech` from its DNS-over-HTTPS server,
/// Opera 136 sent the configuration, and after a rejection it retried once
/// with the server's retry configuration, as Chrome 154 does.
#[must_use]
pub fn v136_tcp_tls() -> TlsSettings {
    crate::tls::components::opera_136_tcp_tls()
}

/// Returns TLS settings for the Opera 136.0.6008.52 HTTP/3 offer on Windows 11.
///
/// The QUIC ClientHellos match [`chrome::v154_quic_tls`] except in the
/// trust-anchor IDs, which are the 32 IDs of [`v136_tcp_tls`] in an order
/// drawn per connection: 20 retained QUIC ClientHellos carry 19 orders. This
/// sends them with [`crate::TrustAnchorIds::PerConnection`], drawing one of those 20
/// ClientHellos' orders for each connection. It inherits that recipe's ticket
/// resumption, whose Chromium source basis was read at 154, not at Opera's
/// Chromium 152 base. It keeps [`TlsSettings::ech`], as [`v136_tcp_tls`]
/// does: Opera 136 sent an HTTPS record's `ech` over QUIC, and closed a
/// rejected QUIC connection with `ech_required` without retrying it there, as
/// Chrome 154 does.
#[must_use]
pub fn v136_quic_tls() -> TlsSettings {
    crate::tls::components::opera_136_quic_tls()
}

/// Returns client-hint fields observed from Opera 136 on Windows 11 x64.
///
/// Names, order, and delivery match the Chromium client-hint recipes. The
/// values carry Opera's brand list, which leads with Chromium and puts the
/// greased brand `"Not?A_Brand";v="24"` second, the exact 136.0.6008.52
/// build, the Chromium 152.0.7977.130 base it reports in the full version
/// list, and Windows platform data. Three headless runs of the retained
/// navigation capture agree. The returned value is owned and may be
/// customized before client creation.
#[must_use]
pub fn v136_windows_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::opera_windows_136_client_hints()
}

/// Returns client-hint fields observed from Opera 136 on macOS 15.5 arm64.
///
/// Names, order, delivery, the brand list, and the versions match
/// [`v136_windows_client_hints`]; three headless runs of the retained
/// navigation capture of Opera 136.0.6008.52 on macOS 15.5 (24F74) on Apple
/// silicon agree. Only the platform data differs: `sec-ch-ua-platform` is
/// `"macOS"`, `sec-ch-ua-platform-version` is `"15.5.0"`, and
/// `sec-ch-ua-arch` is `"arm"`, while `sec-ch-ua-bitness` stays `"64"` and
/// `sec-ch-ua-wow64` stays `?0`. The returned value is owned and may be
/// customized before client creation, for example to carry another macOS
/// version.
#[must_use]
pub fn v136_macos_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::opera_macos_136_client_hints()
}

/// Returns navigation request fields observed from Opera 136.0.6008.52 on Windows 11.
///
/// Opera sends the fields of [`chrome::v154_windows_navigation_template`]
/// in the same order and with the same values on HTTP/1.1, HTTP/2, and
/// HTTP/3, except `User-Agent` and the brand-bearing client hints, which come
/// from [`v136_windows_client_hints`]. `User-Agent` is a required caller slot:
/// every retained Opera capture ran headless and sent `HeadlessChrome`, and
/// no headful Opera capture backs a literal value. The retained proxy route
/// captures show the Chromium change for a URL that is not potentially
/// trustworthy: to `origin.phantom.test` Opera sends no `Sec-Fetch-*` field
/// and `Accept-Encoding: gzip, deflate`.
///
/// The template also matches the Opera 136.0.6008.52 captures on macOS 15.5
/// arm64 on HTTP/1.1, HTTP/2, and HTTP/3, with [`v136_macos_client_hints`],
/// so there is no separate macOS template.
#[must_use]
pub fn v136_windows_navigation_template() -> RequestTemplate {
    chrome::v154_navigation_template(None)
}

/// Returns same-origin no-store `fetch` request fields observed from Opera
/// 136.0.6008.52 on Windows 11.
///
/// The order and values match [`chrome::v154_windows_fetch_no_store_template`]
/// on HTTP/1.1 and HTTP/2, including the HTTP/2 HEADERS priority weight 220,
/// with `User-Agent` as a required caller slot for the reason given in
/// [`v136_windows_navigation_template`]. No capture backs this request kind on
/// HTTP/3, and none shows where hints requested through `Accept-CH` go on a
/// fetch. The macOS 15.5 arm64 captures match it as well.
#[must_use]
pub fn v136_windows_fetch_no_store_template() -> RequestTemplate {
    chrome::v154_fetch_no_store_template(None)
}

/// Returns the Windows connection profile for Opera 136.
///
/// Includes TCP, HTTP/1.1 policy, address cache, HTTP/2, HTTP/3, WebSocket,
/// proxy CONNECT fields, and cookie placement. UDP socket settings and
/// client hints are included.
/// No request template is selected. Choose one for your request kind.
#[must_use]
pub fn v136_windows() -> ClientProfile {
    ClientProfile::new(v136_tcp_tls())
        .with_tcp(chrome::v154_tcp())
        .with_udp(chrome::v154_udp())
        .with_dns_cache(chrome::v154_dns_cache())
        .with_http1(chrome::v154_http1())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            v136_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
        .with_client_hints(v136_windows_client_hints())
        .with_websocket(chrome::v154_websocket())
        .with_proxy_connect(chrome::v154_proxy_connect())
        .with_cookie_placement(chrome::v154_cookie_placement())
}

/// Returns the captured Android layers for Opera 102.
///
/// Supplies TCP TLS and client hints only.
/// TCP socket, UDP socket, HTTP/1.1 policy, address-cache, proxy CONNECT,
/// and cookie-placement recipes are absent. Their generic defaults remain.
/// No request template is selected. These captures came from emulators.
#[must_use]
pub fn v102_android() -> ClientProfile {
    ClientProfile::new(v102_android_tcp_tls()).with_client_hints(v102_android_client_hints())
}

#[cfg(test)]
mod tests;
