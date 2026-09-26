//! Wire settings retained from Microsoft Edge for Android observations.
//!
//! Edge 153.0.4234.49 for Android, the arm64 build the Google Play Store
//! serves, captured on an arm64 Android 17 emulator that reports a Pixel 7
//! on build `CP3A.260905.009`. Edge for Android reads Chrome's command-line
//! file, so the Chrome for Android launches and tools apply unchanged.
//!
//! The TLS and QUIC ClientHellos equal desktop Edge 153's, which are the
//! Chromium offers without trust-anchor IDs, and the H2 startup, QUIC
//! transport parameters, H3 SETTINGS, and request field orders equal the
//! Chromium recipes. Only the client hints and `User-Agent` carry Edge for
//! Android data.
//!
//! There is no TCP, HTTP/1.1 connection, address-cache, proxy CONNECT,
//! WebSocket, or cookie-placement recipe: the emulator hides socket options,
//! as [`crate::chrome_android`] explains, and only the `accept` and
//! `h1-accept` WebSocket scenarios were captured, for their page and `fetch`
//! requests.

use crate::{
    chrome_android::{CAPTURED_MODEL, model_value},
    chromium,
    client_hints::{ClientHint, ClientHintDelivery, ClientHintSettings},
    edge,
    http2::Http2Settings,
    http3::{Http3RequestSettings, Http3Settings},
    quic::QuicTransportSettings,
    request_template::RequestTemplate,
    tls::TlsSettings,
};

/// The `User-Agent` Edge 153 for Android sent on every captured request:
/// Chrome's reduced Android string at Chromium 153 with an `EdgA` token.
pub(crate) const V153_ANDROID_USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 10; K) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Mobile Safari/537.36 EdgA/153.0.0.0";

/// Returns TLS settings captured from Edge 153.0.4234.49 for Android.
///
/// Three fresh-process TCP ClientHellos of the retained capture equal the
/// desktop Edge ClientHello of [`edge::v153_tls`]: the Chromium ClientHello
/// without trust-anchor IDs. [`TlsSettings::ech_from_https_records`] is
/// unset: no Android capture shows Edge using an HTTPS record's `ech`,
/// because the device cannot be given a DNS-over-HTTPS resolver.
#[must_use]
pub fn v153_tls() -> TlsSettings {
    let mut settings = edge::v153_tls();
    settings.ech_from_https_records = false;
    settings
}

/// Returns TLS settings for the Edge 153.0.4234.49 for Android HTTP/3 offer.
///
/// The retained QUIC ClientHello equals [`edge::v153_http3_tls`].
/// [`TlsSettings::ech_from_https_records`] is unset, as in [`v153_tls`].
#[must_use]
pub fn v153_http3_tls() -> TlsSettings {
    let mut settings = edge::v153_http3_tls();
    settings.ech_from_https_records = false;
    settings
}

/// Returns HTTP/2 settings observed from Edge 153.0.4234.49 for Android.
///
/// The raw startup is byte-identical to the Chrome 154 startup, and the page
/// requests of the WebSocket captures carry its pseudo-header order and
/// priority, so this returns [`chromium::v154_http2`].
#[must_use]
pub fn v153_http2() -> Http2Settings {
    chromium::v154_http2()
}

/// Returns QUIC transport settings observed from Edge 153.0.4234.49 for
/// Android, equal to [`chromium::v154_quic`].
#[must_use]
pub fn v153_quic() -> QuicTransportSettings {
    chromium::v154_quic()
}

/// Returns HTTP/3 settings observed from Edge 153.0.4234.49 for Android,
/// equal to [`chromium::v154_http3`].
#[must_use]
pub fn v153_http3() -> Http3Settings {
    chromium::v154_http3()
}

/// Returns HTTP/3 request ordering observed from Edge 153.0.4234.49 for
/// Android, equal to [`chromium::v154_http3_request`].
#[must_use]
pub fn v153_http3_request() -> Http3RequestSettings {
    chromium::v154_http3_request()
}

/// Returns client-hint fields observed from Edge 153 for Android on a
/// Pixel 7.
///
/// From the retained navigation capture, three fresh-profile runs that
/// agree. Names, order, and delivery equal the Chromium client-hint recipes.
/// The values carry desktop Edge 153's brand list and the Chromium
/// 153.0.8010.53 base in the full version list, the exact 153.0.4234.49
/// build, `?1`, the `"Android"` platform at `"17.0.0"`, the `"Pixel 7"`
/// model, an empty architecture and bitness, and the `"Mobile"` form factor.
///
/// Google publishes Android 17 for the Pixel 7: its factory image list for
/// `panther` has 17.0.0 builds `CP2A.260605.012` (Jun 2026),
/// `CP2A.260705.006` (Jul 2026), and `CP3A.260905.009` (Sep 2026), the build
/// the capture emulator reports. `docs/explanation/validation.md` quotes the
/// list under "Chrome for Android 154 recipes".
///
/// For another phone, use [`v153_android_client_hints_for_model`].
#[must_use]
pub fn v153_android_client_hints() -> ClientHintSettings {
    v153_android_client_hints_for_model(CAPTURED_MODEL)
}

/// Returns the client hints of [`v153_android_client_hints`] with another
/// device model in `sec-ch-ua-model`, as Android's `Build.MODEL` reports it.
/// Only the Pixel 7 value is captured.
#[must_use]
pub fn v153_android_client_hints_for_model(model: &str) -> ClientHintSettings {
    use ClientHintDelivery::{AcceptCh, Default};

    ClientHintSettings::new(vec![
        ClientHint::new(
            "sec-ch-ua",
            r#""Microsoft Edge";v="153", "Not_A Brand";v="8", "Chromium";v="153""#,
            Default,
        ),
        ClientHint::new("sec-ch-ua-mobile", "?1", Default),
        ClientHint::new("sec-ch-ua-full-version", r#""153.0.4234.49""#, AcceptCh),
        ClientHint::new("sec-ch-ua-arch", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-platform", r#""Android""#, Default),
        ClientHint::new("sec-ch-ua-platform-version", r#""17.0.0""#, AcceptCh),
        ClientHint::new("sec-ch-ua-model", model_value(model), AcceptCh),
        ClientHint::new("sec-ch-ua-bitness", r#""""#, AcceptCh),
        ClientHint::new("sec-ch-ua-wow64", "?0", AcceptCh),
        ClientHint::new(
            "sec-ch-ua-full-version-list",
            r#""Microsoft Edge";v="153.0.4234.49", "Not_A Brand";v="8.0.0.0", "Chromium";v="153.0.8010.53""#,
            AcceptCh,
        ),
        ClientHint::new("sec-ch-ua-form-factors", r#""Mobile""#, AcceptCh),
    ])
}

/// Returns navigation request fields observed from Edge 153.0.4234.49 for
/// Android.
///
/// A navigation typed into the address bar. The retained captures send the
/// fields of [`chromium::v154_windows_navigation_template`] in the same order
/// and with the same values and HTTP/2 priority, except `User-Agent`, which
/// is the literal Edge for Android string, and the client hints of
/// [`v153_android_client_hints`]. The captures ran with a visible browser,
/// so, unlike the headless desktop Edge captures, they back a literal
/// `User-Agent`. The HTTP/3 list is the Chromium one: the Android H3
/// startup, opened by intent, sends it without `Sec-Fetch-User` and with
/// `Sec-Fetch-Site: cross-site`.
#[must_use]
pub fn v153_android_navigation_template() -> RequestTemplate {
    chromium::v154_navigation_template(Some(V153_ANDROID_USER_AGENT))
}

/// Returns same-origin no-store `fetch` request fields observed from Edge
/// 153.0.4234.49 for Android: the Chromium fetch lists on HTTP/1.1 and
/// HTTP/2, including the HTTP/2 HEADERS priority weight 220, with the Edge
/// for Android `User-Agent`. No capture backs this request kind on HTTP/3.
#[must_use]
pub fn v153_android_fetch_no_store_template() -> RequestTemplate {
    chromium::v154_fetch_no_store_template(Some(V153_ANDROID_USER_AGENT))
}

#[cfg(test)]
mod tests;
