//! Wire settings retained from Chrome for Android observations.
//!
//! Google Chrome 154.0.8037.57 is the build the Google Play Store served to the
//! `phantom-pixel7` Android 17 x86_64 emulator on the Windows 11 capture host.
//! A Magisk module sets the emulator's build properties to those of a Pixel 7
//! on build `CP3A.260905.009`: model, build fingerprint, and security patch
//! level. `docs/explanation/validation.md`, under "Chrome for Android 154
//! recipes", describes the emulator.
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

/// The `User-Agent` Chrome 154 for Android sent on every captured request.
///
/// Chrome's reduced Android string: the platform is always `Android 10; K`
/// and the version is `154.0.0.0`, whatever the device and build.
pub(crate) const V154_ANDROID_USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 10; K) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Mobile Safari/537.36";

/// The device model the Android captures report, as Android's `Build.MODEL`
/// gives it.
pub(crate) const CAPTURED_MODEL: &str = "Pixel 7";

/// Returns client-hint fields observed from Chrome 154 for Android on a
/// Pixel 7.
///
/// From the retained navigation capture of Chrome 154.0.8037.57, three
/// fresh-profile runs that agree. Names, order, and delivery equal
/// [`chromium::v154_windows_client_hints`]: the three default hints, then
/// eight more after `Accept-CH`. The values carry Chrome 154's brand list,
/// `?1` for `sec-ch-ua-mobile`, the `"Android"` platform at version
/// `"17.0.0"`, the `"Pixel 7"` model, an empty architecture and bitness, and
/// the `"Mobile"` form factor.
///
/// Google publishes Android 17 for the Pixel 7: its factory image list for
/// `panther` has 17.0.0 builds `CP2A.260605.012` (Jun 2026),
/// `CP2A.260705.006` (Jul 2026), and `CP3A.260905.009` (Sep 2026), the build
/// the capture emulator reports. `docs/explanation/validation.md` quotes the
/// list under "Chrome for Android 154 recipes".
///
/// For another phone, use [`v154_android_client_hints_for_model`].
#[must_use]
pub fn v154_android_client_hints() -> ClientHintSettings {
    v154_android_client_hints_for_model(CAPTURED_MODEL)
}

/// Returns the client hints of [`v154_android_client_hints`] with another
/// device model in `sec-ch-ua-model`.
///
/// Pass the model as Android's `Build.MODEL` reports it; it is sent as a
/// structured-field string. Only the Pixel 7 value is captured, and the
/// platform version stays Android 17's.
#[must_use]
pub fn v154_android_client_hints_for_model(model: &str) -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Chromium";v="154", "Google Chrome";v="154", "Not A(Brand";v="99""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?1", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""154.0.8037.57""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Android""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""17.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", model_value(model), AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Chromium";v="154.0.8037.57", "Google Chrome";v="154.0.8037.57", "Not A(Brand";v="99.0.0.0""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Mobile""#, AcceptCh),
    ])
}

/// Returns TLS settings captured from Chrome 154.0.8037.57 for Android.
///
/// The retained TCP ClientHello equals [`chromium::v154_tls`] on every
/// compared field, the 28 trust-anchor IDs in their sorted order included.
/// GREASE, the permuted extension order, and the ECH GREASE payload length
/// vary per connection, as on Windows.
///
/// [`TlsSettings::ech_from_https_records`] is unset: no Android capture shows
/// Chrome using an HTTPS record's `ech`, because the capture cannot give the
/// device a DNS-over-HTTPS resolver.
#[must_use]
pub fn v154_tls() -> TlsSettings {
    let mut settings = chromium::v154_tls();
    settings.ech_from_https_records = false;
    settings
}

/// Returns HTTP/2 settings observed from Chrome 154.0.8037.57 for Android.
///
/// The initial SETTINGS, their order, the connection WINDOW_UPDATE, the
/// request pseudo-header order, the navigation priority, and the HPACK
/// choices of the retained Android captures equal [`chromium::v154_http2`],
/// so this returns that recipe. Its `cookie` crumb rule comes from the
/// desktop cookie captures; no Android capture carries a cookie.
#[must_use]
pub fn v154_http2() -> Http2Settings {
    chromium::v154_http2()
}

/// Returns TLS settings for the Chrome 154.0.8037.57 for Android HTTP/3 offer.
///
/// The retained QUIC ClientHello equals [`chromium::v154_http3_tls`] on every
/// compared field, the sorted trust-anchor IDs included.
/// [`TlsSettings::ech_from_https_records`] is unset, as in [`v154_tls`].
#[must_use]
pub fn v154_http3_tls() -> TlsSettings {
    let mut settings = chromium::v154_http3_tls();
    settings.ech_from_https_records = false;
    settings
}

/// Returns QUIC transport settings observed from Chrome 154.0.8037.57 for
/// Android.
///
/// Every transport parameter of the retained Android QUIC startup capture,
/// with its id, length, and value widths, equals [`chromium::v154_quic`], and
/// the order varies per connection as on Windows, so this returns that
/// recipe.
#[must_use]
pub fn v154_quic() -> QuicTransportSettings {
    chromium::v154_quic()
}

/// Returns HTTP/3 settings observed from Chrome 154.0.8037.57 for Android.
///
/// The five SETTINGS, their order and widths, and the QPACK stream prefixes
/// of the retained Android capture equal [`chromium::v154_http3`]. Its
/// `cookie` crumb rule comes from the desktop cookie captures; no Android
/// capture carries a cookie.
#[must_use]
pub fn v154_http3() -> Http3Settings {
    chromium::v154_http3()
}

/// Returns HTTP/3 request ordering observed from Chrome 154.0.8037.57 for
/// Android.
///
/// The retained Android H3 request sends the pseudo-header fields in the
/// order of [`chromium::v154_http3_request`].
#[must_use]
pub fn v154_http3_request() -> Http3RequestSettings {
    chromium::v154_http3_request()
}

/// Returns WebSocket settings for Chrome 154.0.8037.57 for Android.
///
/// The retained Chrome 154 `accept` and `h1-accept` captures open their
/// WebSockets as [`chromium::v154_websocket`] does, and the nine-scenario
/// Chrome 153 for Android set matched that recipe on every compared field,
/// so this returns it.
#[must_use]
pub fn v154_websocket() -> WebSocketSettings {
    chromium::v154_websocket()
}

/// Returns navigation request fields observed from Chrome 154.0.8037.57 for
/// Android.
///
/// A navigation typed into the address bar. The retained Android captures
/// send the fields of [`chromium::v154_windows_navigation_template`] in the
/// same order, with the same values and HTTP/2 priority, except `User-Agent`,
/// which is Chrome's reduced Android string, and the client hints of
/// [`v154_android_client_hints`]. The HTTP/1.1 order comes from the plaintext
/// page loads of the WebSocket and client-hint captures and the HTTP/2 order
/// from the WebSocket captures' page requests. The HTTP/3 list is the
/// Chromium one: the Android H3 startup, opened by intent, sends it without
/// `Sec-Fetch-User` and with `Sec-Fetch-Site: cross-site`.
///
/// A page that another app opens with a `VIEW` intent is not user-activated,
/// and Chrome then leaves out `Sec-Fetch-User`; this template models the
/// typed navigation only.
#[must_use]
pub fn v154_android_navigation_template() -> RequestTemplate {
    chromium::v154_navigation_template(Some(V154_ANDROID_USER_AGENT))
}

/// Returns same-origin no-store `fetch` request fields observed from Chrome
/// 154.0.8037.57 for Android.
///
/// The final report request of every retained Android WebSocket capture sends
/// the fields of [`chromium::v154_windows_fetch_no_store_template`] in the
/// same order and with the same values on HTTP/1.1 and HTTP/2, including the
/// HTTP/2 HEADERS priority weight 220, except `User-Agent`, which is Chrome's
/// reduced Android string, and the client hints of
/// [`v154_android_client_hints`]. No capture backs this request kind on
/// HTTP/3, and none shows where a hint requested through `Accept-CH` goes on
/// a fetch.
#[must_use]
pub fn v154_android_fetch_no_store_template() -> RequestTemplate {
    chromium::v154_fetch_no_store_template(Some(V154_ANDROID_USER_AGENT))
}

/// Encodes a device model as the structured-field string `sec-ch-ua-model`
/// carries: in quotes, with each quote and backslash escaped.
pub(crate) fn model_value(model: &str) -> String {
    let mut value = String::with_capacity(model.len() + 2);
    value.push('"');
    for character in model.chars() {
        if matches!(character, '"' | '\\') {
            value.push('\\');
        }
        value.push(character);
    }
    value.push('"');
    value
}

#[cfg(test)]
mod tests;
