//! Wire settings retained from Chrome for Android observations.
//!
//! Google Chrome 153.0.8010.52 is the build the Google Play Store served to the
//! `phantom-api35-play` Android 15 (API 35) x86_64 emulator on the Windows 11
//! capture host. Google's release API listed 155.0.8059.16 as the stable
//! Android build at the time; Play's staged rollout had not reached the device.
//!
//! Where a layer equals the desktop Chrome recipe on every compared field, the
//! function here returns the [`chromium`] recipe, and a test replays the
//! Android capture against it. Values that carry the platform, such as client
//! hints and `User-Agent`, have their own data.
//!
//! There is no TCP, HTTP/1.1 connection, address-cache, proxy CONNECT, or
//! cookie-placement recipe. The emulator's network terminates the device's TCP
//! connections, so no socket option reaches a host listener, and the other
//! layers rest on Chromium source or on captures not taken on Android.

use crate::{
    chromium,
    client_hints::{ClientHint, ClientHintDelivery, ClientHintSettings},
    http2::Http2Settings,
    http3::{Http3RequestSettings, Http3Settings},
    quic::QuicTransportSettings,
    request_template::RequestTemplate,
    tls::TlsSettings,
    websocket::WebSocketSettings,
};

// Every fresh process of the retained Android TCP capture sent Chrome's 28
// trust-anchor IDs in this one order, which is not sorted: Chrome 153 predates
// Chromium commit `942bda4298c1`, which sorts the list.
const V153_ANDROID_TRUST_ANCHOR_IDS: &[&[u8]] = &[
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09],
    &[0x82, 0xdf, 0x13, 0x02, 0x0d],
    &[0x82, 0xdf, 0x13, 0x02, 0x0e],
    &[0x82, 0xdf, 0x13, 0x02, 0x01],
    &[0xd6, 0x79, 0x09, 0x06],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c],
    &[0xd6, 0x79, 0x09, 0x01],
    &[0xd6, 0x79, 0x09, 0x04],
    &[0xd6, 0x79, 0x09, 0x0c],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13],
    &[0x82, 0xdf, 0x13, 0x02, 0x13],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d],
    &[0xd6, 0x79, 0x09, 0x0f],
    &[0xd6, 0x79, 0x09, 0x05],
    &[0xd6, 0x79, 0x09, 0x0b],
    &[0xd6, 0x79, 0x09, 0x08],
    &[0x82, 0xdf, 0x13, 0x02, 0x06],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12],
    &[0x82, 0xdf, 0x13, 0x02, 0x12],
    &[0xd6, 0x79, 0x09, 0x0a],
    &[0xd6, 0x79, 0x09, 0x07],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08],
    &[0xd6, 0x79, 0x09, 0x0d],
    &[0x82, 0xdf, 0x13, 0x02, 0x14],
    &[0x82, 0xdf, 0x13, 0x02, 0x0f],
];

// The QUIC ClientHellos of the Android capture did not share one
// trust-anchor order between browser processes. This is the order they sent
// most often.
const V153_ANDROID_QUIC_TRUST_ANCHOR_IDS: &[&[u8]] = &[
    &[0xd6, 0x79, 0x09, 0x0a],
    &[0xd6, 0x79, 0x09, 0x0d],
    &[0x82, 0xdf, 0x13, 0x02, 0x01],
    &[0x82, 0xdf, 0x13, 0x02, 0x0e],
    &[0x82, 0xdf, 0x13, 0x02, 0x0f],
    &[0xd6, 0x79, 0x09, 0x07],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0b],
    &[0x82, 0xdf, 0x13, 0x02, 0x14],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x08],
    &[0x82, 0xdf, 0x13, 0x02, 0x0d],
    &[0xd6, 0x79, 0x09, 0x06],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x07],
    &[0xd6, 0x79, 0x09, 0x04],
    &[0xd6, 0x79, 0x09, 0x01],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x13],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x12],
    &[0xd6, 0x79, 0x09, 0x0f],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0d],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x09],
    &[0x82, 0xdf, 0x13, 0x02, 0x13],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0c],
    &[0xd6, 0x79, 0x09, 0x05],
    &[0xd6, 0x79, 0x09, 0x0c],
    &[0xd6, 0x79, 0x09, 0x0b],
    &[0x82, 0xdf, 0x13, 0x02, 0x06],
    &[0x82, 0xdf, 0x13, 0x02, 0x12],
    &[0xd6, 0x79, 0x09, 0x08],
    &[0x83, 0x9a, 0x64, 0x8c, 0x9b, 0x2d, 0x01, 0x0a],
];

/// The `User-Agent` Chrome 153 for Android sent on every captured request.
///
/// Chrome's reduced Android string: the platform is always `Android 10; K`
/// and the version is `153.0.0.0`, whatever the device and build.
pub(crate) const V153_ANDROID_USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 10; K) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Mobile Safari/537.36";

/// Returns client-hint fields observed from Chrome 153 for Android.
///
/// From the retained navigation capture of Chrome 153.0.8010.52 on the
/// Android 15 emulator, three fresh-profile runs that agree. Names, order,
/// and delivery equal [`chromium::v154_windows_client_hints`]: the three
/// default hints, then eight more after `Accept-CH`. The values carry
/// Chrome 153's brand list, `?1` for `sec-ch-ua-mobile`, the `"Android"`
/// platform at version `"15.0.0"`, an empty architecture and bitness, the
/// `"Mobile"` form factor, and the emulator's model,
/// `"sdk_gphone64_x86_64"`. A phone sends its own model and Android version;
/// replace those two values for another device. The returned value is owned
/// and may be customized before client creation.
#[must_use]
pub fn v153_android_client_hints() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Google Chrome";v="153", "Not_A Brand";v="8", "Chromium";v="153""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?1", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""153.0.8010.52""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Android""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""15.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""sdk_gphone64_x86_64""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Google Chrome";v="153.0.8010.52", "Not_A Brand";v="8.0.0.0", "Chromium";v="153.0.8010.52""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Mobile""#, AcceptCh),
    ])
}

/// Returns TLS settings captured from Chrome 153.0.8010.52 for Android.
///
/// Every fresh-process TCP ClientHello of the retained Android capture equals
/// [`chromium::v154_tls`] on the legacy version, cipher suites, extension
/// membership, supported groups, key shares, signature algorithms including
/// the three ML-DSA schemes, ALPN and ALPS, certificate compression, supported
/// versions, and ECH GREASE with HKDF-SHA256 and AES-128-GCM. GREASE, the
/// permuted extension order, and the ECH GREASE payload length vary per
/// connection, as on Windows.
///
/// The trust-anchor IDs are the same 28 identifiers in a different order.
/// Chrome 153 does not sort the list, and all 62 retained processes, over two
/// emulator boots, sent the order this recipe carries. The QUIC ClientHellos of the same build
/// used other orders; see [`v153_http3_tls`].
///
/// [`TlsSettings::ech_from_https_records`] is unset: no Android capture shows
/// Chrome using an HTTPS record's `ech`, because the capture cannot give the
/// device a DNS-over-HTTPS resolver.
#[must_use]
pub fn v153_tls() -> TlsSettings {
    let mut settings = chromium::v154_tls();
    settings.requested_trust_anchor_ids = Some(trust_anchor_ids(V153_ANDROID_TRUST_ANCHOR_IDS));
    settings.ech_from_https_records = false;
    settings
}

/// Returns HTTP/2 settings observed from Chrome 153.0.8010.52 for Android.
///
/// The initial SETTINGS, their order, the connection WINDOW_UPDATE, the
/// request pseudo-header order, the navigation and extended CONNECT HEADERS
/// priorities, and the HPACK choices of the retained Android captures equal
/// [`chromium::v154_http2`], so this returns that recipe. Its `cookie`
/// crumb rule comes from the desktop cookie captures; no Android capture
/// carries a cookie.
#[must_use]
pub fn v153_http2() -> Http2Settings {
    chromium::v154_http2()
}

/// Returns TLS settings for the Chrome 153.0.8010.52 for Android HTTP/3 offer.
///
/// The retained Android QUIC ClientHellos equal [`chromium::v154_http3_tls`]
/// on every compared field except the trust-anchor order: the same 28
/// identifiers, in an order that differed between captured browser processes
/// and from the TCP order of [`v153_tls`]. No fixed list reproduces a
/// per-process order, so this recipe carries the order sent most often,
/// as the retired Chrome 153 desktop recipe did.
/// [`TlsSettings::ech_from_https_records`] is unset, as in [`v153_tls`].
#[must_use]
pub fn v153_http3_tls() -> TlsSettings {
    let mut settings = chromium::v154_http3_tls();
    settings.requested_trust_anchor_ids =
        Some(trust_anchor_ids(V153_ANDROID_QUIC_TRUST_ANCHOR_IDS));
    settings.ech_from_https_records = false;
    settings
}

/// Returns QUIC transport settings observed from Chrome 153.0.8010.52 for
/// Android.
///
/// Every transport parameter of the retained Android QUIC startup capture,
/// with its id, length, and value widths, equals [`chromium::v154_quic`], and
/// the order varies per connection as on Windows, so this returns that
/// recipe.
#[must_use]
pub fn v153_quic() -> QuicTransportSettings {
    chromium::v154_quic()
}

/// Returns HTTP/3 settings observed from Chrome 153.0.8010.52 for Android.
///
/// The five SETTINGS, their order and widths, and the QPACK stream prefixes
/// of the retained Android capture equal [`chromium::v154_http3`]. Its
/// `cookie` crumb rule comes from the desktop cookie captures; no Android
/// capture carries a cookie.
#[must_use]
pub fn v153_http3() -> Http3Settings {
    chromium::v154_http3()
}

/// Returns HTTP/3 request ordering observed from Chrome 153.0.8010.52 for
/// Android.
///
/// The retained Android H3 request sends the pseudo-header fields in the
/// order of [`chromium::v154_http3_request`].
#[must_use]
pub fn v153_http3_request() -> Http3RequestSettings {
    chromium::v154_http3_request()
}

/// Returns WebSocket settings observed from Chrome 153.0.8010.52 for Android.
///
/// The retained Android WebSocket captures, three runs of each of nine
/// scenarios, equal [`chromium::v154_websocket`] on the connection choice,
/// the ALPN offer of a WebSocket's own connection, the refused-stream retry,
/// the compression offer, the empty-message compression, and the opening
/// fields of both protocols, so this returns that recipe.
#[must_use]
pub fn v153_websocket() -> WebSocketSettings {
    chromium::v154_websocket()
}

/// Returns navigation request fields observed from Chrome 153.0.8010.52 for
/// Android.
///
/// A navigation typed into the address bar. The retained Android captures
/// send the fields of [`chromium::v154_windows_navigation_template`] in the
/// same order, with the same values and HTTP/2 priority, except `User-Agent`,
/// which is Chrome's reduced Android string, and the client hints of
/// [`v153_android_client_hints`]. The HTTP/1.1 order comes from the
/// plaintext loopback page loads of the WebSocket and client-hint captures,
/// the HTTP/2 order from the WebSocket captures' page requests, and the
/// HTTP/3 order from the H3 startup capture.
///
/// A page that another app opens with a `VIEW` intent is not user-activated,
/// and Chrome then leaves out `Sec-Fetch-User`; this template models the
/// typed navigation only.
#[must_use]
pub fn v153_android_navigation_template() -> RequestTemplate {
    chromium::v154_navigation_template(Some(V153_ANDROID_USER_AGENT))
}

/// Returns same-origin no-store `fetch` request fields observed from Chrome
/// 153.0.8010.52 for Android.
///
/// The final report request of every retained Android WebSocket capture sends
/// the fields of [`chromium::v154_windows_fetch_no_store_template`] in the
/// same order and with the same values on HTTP/1.1 and HTTP/2, including the
/// HTTP/2 HEADERS priority weight 220, except `User-Agent`, which is Chrome's
/// reduced Android string, and the client hints of
/// [`v153_android_client_hints`]. No capture backs this request kind on
/// HTTP/3, and none shows where a hint requested through `Accept-CH` goes on
/// a fetch.
#[must_use]
pub fn v153_android_fetch_no_store_template() -> RequestTemplate {
    chromium::v154_fetch_no_store_template(Some(V153_ANDROID_USER_AGENT))
}

fn trust_anchor_ids(ids: &[&[u8]]) -> Vec<Box<[u8]>> {
    ids.iter().map(|id| Box::from(*id)).collect()
}

#[cfg(test)]
mod tests;
