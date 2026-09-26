//! Wire settings retained from Brave for Android observations.
//!
//! Brave 1.95.104 (Chromium 153), as the Google Play Store served it to the
//! `phantom-api35-play` Android 15 emulator, recorded in fixtures as
//! `153.1.95.104` to match the desktop naming. Its captures equal the desktop
//! Brave recipes in [`brave`] on the TLS and QUIC ClientHellos and on every
//! request-field difference from Chrome, and the desktop Chromium recipes on
//! HTTP/2, QUIC transport parameters, HTTP/3, and WebSocket openings. Only
//! the client hints and `User-Agent` carry Android data.
//!
//! There is no TCP, HTTP/1.1 connection, address-cache, proxy CONNECT, or
//! cookie-placement recipe, for the reasons given in
//! [`crate::chrome_android`].

use crate::{
    brave, chrome_android, chromium,
    client_hints::{ClientHint, ClientHintDelivery, ClientHintSettings},
    http2::Http2Settings,
    http3::{Http3RequestSettings, Http3Settings},
    quic::QuicTransportSettings,
    request_template::RequestTemplate,
    tls::TlsSettings,
    websocket::WebSocketSettings,
};

/// Returns TLS settings captured from Brave 1.95.104 for Android.
///
/// Every fresh-process TCP ClientHello of the retained Android capture equals
/// the desktop Brave ClientHello of [`brave::v154_tls`], with no trust-anchor
/// IDs. [`TlsSettings::ech_from_https_records`] is unset: no Android capture
/// shows Brave using an HTTPS record's `ech`, because the device cannot be
/// given a DNS-over-HTTPS resolver.
#[must_use]
pub fn v153_tls() -> TlsSettings {
    let mut settings = brave::v154_tls();
    settings.ech_from_https_records = false;
    settings
}

/// Returns TLS settings for the Brave 1.95.104 for Android HTTP/3 offer.
///
/// The retained Android QUIC ClientHellos equal [`brave::v154_http3_tls`].
/// [`TlsSettings::ech_from_https_records`] is unset, as in [`v153_tls`].
#[must_use]
pub fn v153_http3_tls() -> TlsSettings {
    let mut settings = brave::v154_http3_tls();
    settings.ech_from_https_records = false;
    settings
}

/// Returns client-hint fields observed from Brave 1.95.104 for Android.
///
/// From the retained navigation capture, three fresh-profile runs that agree.
/// Names, order, and delivery equal [`brave::v154_windows_client_hints`]: no
/// `sec-ch-ua-full-version` and no `sec-ch-ua-form-factors`. The values carry
/// Brave's Chromium 153 brand list, `?1`, the `"Android"` platform at
/// `"15.0.0"`, and an empty model, architecture, and bitness; every version
/// in the full version list is reduced to `.0.0.0`.
#[must_use]
pub fn v153_android_client_hints() -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Brave";v="153", "Not_A Brand";v="8", "Chromium";v="153""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?1", Default),
        ClientHint::new("sec-ch-ua-arch", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Android""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""15.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Brave";v="153.0.0.0", "Not_A Brand";v="8.0.0.0", "Chromium";v="153.0.0.0""#,
            AcceptCh,
        ),
    ])
}

/// Returns HTTP/2 settings observed from Brave 1.95.104 for Android.
///
/// The raw startup is byte-identical to the desktop Chromium and Brave
/// captures, and the H2 request shape of the WebSocket captures equals
/// [`chromium::v154_http2`], so this returns that recipe.
#[must_use]
pub fn v153_http2() -> Http2Settings {
    chromium::v154_http2()
}

/// Returns QUIC transport settings observed from Brave 1.95.104 for Android.
///
/// The transport parameters of the retained Android capture equal
/// [`chromium::v154_quic`]; see that recipe for what varies per connection.
#[must_use]
pub fn v153_quic() -> QuicTransportSettings {
    chromium::v154_quic()
}

/// Returns HTTP/3 settings observed from Brave 1.95.104 for Android, equal to
/// [`chromium::v154_http3`].
#[must_use]
pub fn v153_http3() -> Http3Settings {
    chromium::v154_http3()
}

/// Returns HTTP/3 request ordering observed from Brave 1.95.104 for Android,
/// equal to [`chromium::v154_http3_request`].
#[must_use]
pub fn v153_http3_request() -> Http3RequestSettings {
    chromium::v154_http3_request()
}

/// Returns WebSocket settings observed from Brave 1.95.104 for Android.
///
/// The nine retained WebSocket scenarios equal [`chromium::v154_websocket`]
/// on every compared field.
#[must_use]
pub fn v153_websocket() -> WebSocketSettings {
    chromium::v154_websocket()
}

/// Returns navigation request fields observed from Brave 1.95.104 for
/// Android.
///
/// A navigation typed into the address bar. The captures show the desktop
/// Brave differences from Chrome: `Accept` without signed exchanges,
/// `Sec-GPC: 1` after `Accept`, and an `Accept-Language` whose `q` value
/// Brave draws per session (every value from `0.5` to `0.9` appears across
/// the runs, one per run), so `Accept-Language` is a required caller slot.
/// `User-Agent` is Chrome's reduced Android string, which Brave sent on every
/// captured request; unlike the desktop Brave captures, these ran with a
/// visible browser, so the value is literal.
#[must_use]
pub fn v153_android_navigation_template() -> RequestTemplate {
    brave::with_brave_fields(
        chromium::v154_navigation_template(Some(chrome_android::V153_ANDROID_USER_AGENT)),
        Some(brave::V154_NAVIGATION_ACCEPT),
    )
}

/// Returns same-origin no-store `fetch` request fields observed from Brave
/// 1.95.104 for Android: the Chromium fetch lists with `Sec-GPC: 1` after
/// `Accept`, a required caller `Accept-Language`, and the Android
/// `User-Agent`. No capture backs this request kind on HTTP/3.
#[must_use]
pub fn v153_android_fetch_no_store_template() -> RequestTemplate {
    brave::with_brave_fields(
        chromium::v154_fetch_no_store_template(Some(chrome_android::V153_ANDROID_USER_AGENT)),
        None,
    )
}

#[cfg(test)]
mod tests;
