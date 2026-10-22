//! Brave 1.95.104 connection settings and request templates for Android.

use crate::{
    browser::brave,
    browser::chrome,
    client_hints::ClientHintSettings,
    http2::Http2Settings,
    http3::{Http3RequestSettings, Http3Settings},
    quic::QuicTransportSettings,
    request_template::RequestTemplate,
    tls::TlsSettings,
    websocket::WebSocketSettings,
};

/// The `User-Agent` Brave 1.95.104 for Android sent on every captured
/// request: Chrome's reduced Android string at Chromium 153.
pub(crate) const V153_ANDROID_USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 10; K) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Mobile Safari/537.36";

/// Returns Brave 1.95.104 TLS settings for Android.
///
/// Uses [`brave::v154_tcp_tls`]'s ClientHello settings. ECH uses GREASE
/// rather than HTTPS-record configurations.
#[must_use]
pub fn v153_android_tcp_tls() -> TlsSettings {
    crate::tls::components::brave_153_android_tcp_tls()
}

/// Returns Brave 1.95.104 TLS settings for HTTP/3 on Android.
///
/// Uses [`brave::v154_quic_tls`]'s ClientHello settings with ECH GREASE.
#[must_use]
pub fn v153_android_quic_tls() -> TlsSettings {
    crate::tls::components::brave_153_android_quic_tls()
}

/// Returns Brave 1.95.104 client hints for Android 17.
///
/// Uses [`brave::v154_windows_client_hints`]'s order with Chromium 153 brands,
/// reduced full versions and empty model, architecture and bitness values.
#[must_use]
pub fn v153_android_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::brave_android_153_client_hints()
}

/// Returns Brave 1.95.104 HTTP/2 settings for Android.
///
/// Uses [`chrome::v154_http2`].
#[must_use]
pub fn v153_android_http2() -> Http2Settings {
    chrome::v154_http2()
}

/// Returns Brave 1.95.104 QUIC settings for Android.
///
/// Uses [`chrome::v154_quic`].
#[must_use]
pub fn v153_android_quic() -> QuicTransportSettings {
    chrome::v154_quic()
}

/// Returns HTTP/3 settings observed from Brave 1.95.104 for Android, equal to
/// [`chrome::v154_http3`].
#[must_use]
pub fn v153_android_http3() -> Http3Settings {
    chrome::v154_http3()
}

/// Returns HTTP/3 request ordering observed from Brave 1.95.104 for Android,
/// equal to [`chrome::v154_http3_request`].
#[must_use]
pub fn v153_android_http3_request() -> Http3RequestSettings {
    chrome::v154_http3_request()
}

/// Returns Brave 1.95.104 WebSocket settings for Android.
///
/// Uses [`chrome::v154_websocket`].
#[must_use]
pub fn v153_android_websocket() -> WebSocketSettings {
    chrome::v154_websocket()
}

/// Returns Brave 1.95.104 Android address-bar navigation fields.
///
/// Uses Chromium ordering, omits signed exchanges from `Accept` and adds
/// `Sec-GPC: 1` after it. Includes the reduced Android user agent.
/// Supply `Accept-Language`; Brave chooses the secondary-language quality
/// from 0.5 through 0.9 once per session.
#[must_use]
pub fn v153_android_navigation_template() -> RequestTemplate {
    brave::with_brave_fields(
        chrome::v154_navigation_template(Some(V153_ANDROID_USER_AGENT)),
        Some(brave::V154_NAVIGATION_ACCEPT),
    )
}

/// Returns Brave 1.95.104 Android same-origin no-store GET fields.
///
/// Uses Chromium fetch ordering with `Sec-GPC: 1` after `Accept` and the
/// Android user agent. Supply `Accept-Language`. HTTP/3 is unavailable.
#[must_use]
pub fn v153_android_fetch_no_store_template() -> RequestTemplate {
    brave::with_brave_fields(
        chrome::v154_fetch_no_store_template(Some(V153_ANDROID_USER_AGENT)),
        None,
    )
}

#[cfg(test)]
mod tests;
