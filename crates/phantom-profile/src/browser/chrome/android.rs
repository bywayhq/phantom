//! Chrome 154.0.8037.57 connection settings and request templates for Android.
//!
//! Client hints use Pixel 7 / Android 17 values. HTTP/1.1 pool, address-cache,
//! proxy CONNECT and cookie-placement recipes are unavailable.

use crate::{
    browser::chrome,
    client_hints::ClientHintSettings,
    http2::Http2Settings,
    http3::{Http3RequestSettings, Http3Settings},
    quic::QuicTransportSettings,
    request_template::RequestTemplate,
    tcp::TcpSettings,
    tls::TlsSettings,
    websocket::WebSocketSettings,
};

/// Returns Chrome 154.0.8037.57 TCP settings for Android.
///
/// Enables `TCP_NODELAY` and a 300 ms address fallback delay. Leaves
/// keepalive disabled, with the send buffer and port selection unchanged.
#[must_use]
pub fn v154_android_tcp() -> TcpSettings {
    crate::catalog::tcp_components::chromium_154_android_tcp()
}

/// The `User-Agent` Chrome 154 for Android sent on every captured request.
///
/// Chrome's reduced Android string: the platform is always `Android 10; K`
/// and the version is `154.0.0.0`, whatever the device and build.
pub(crate) const V154_ANDROID_USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 10; K) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Mobile Safari/537.36";

/// Returns Chrome 154 client hints for a Pixel 7 on Android 17.
///
/// Uses [`chrome::v154_windows_client_hints`]'s field order with mobile
/// platform values. Use [`v154_android_client_hints_for_model`] for another
/// model.
#[must_use]
pub fn v154_android_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::chrome_android_154_client_hints()
}

/// Returns [`v154_android_client_hints`] with a custom `sec-ch-ua-model`.
///
/// Pass Android's `Build.MODEL` value. The platform version stays Android 17.
///
/// # Errors
///
/// Rejects characters outside printable ASCII (space through `~`). Quotes
/// and backslashes are escaped in the structured-field string.
pub fn v154_android_client_hints_for_model(
    model: &str,
) -> Result<ClientHintSettings, crate::InvalidClientHintSettings> {
    validate_model(model)?;
    Ok(crate::catalog::client_hints_components::chrome_android_154_client_hints_for_model(model))
}

/// Returns Chrome 154.0.8037.57 TLS settings for Android.
///
/// Uses [`chrome::v154_tcp_tls`]'s ClientHello settings, including sorted
/// trust-anchor IDs. ECH uses GREASE rather than HTTPS-record configurations.
#[must_use]
pub fn v154_android_tcp_tls() -> TlsSettings {
    crate::tls::components::chromium_154_android_tcp_tls()
}

/// Returns Chrome 154.0.8037.57 HTTP/2 settings for Android.
///
/// Uses [`chrome::v154_http2`], including its cookie-crumb policy.
#[must_use]
pub fn v154_android_http2() -> Http2Settings {
    chrome::v154_http2()
}

/// Returns Chrome 154.0.8037.57 TLS settings for HTTP/3 on Android.
///
/// Uses [`chrome::v154_quic_tls`]'s ClientHello settings. ECH uses GREASE
/// rather than HTTPS-record configurations.
#[must_use]
pub fn v154_android_quic_tls() -> TlsSettings {
    crate::tls::components::chromium_154_android_quic_tls()
}

/// Returns Chrome 154.0.8037.57 QUIC settings for Android.
///
/// Uses [`chrome::v154_quic`], including its per-connection parameter shuffle.
#[must_use]
pub fn v154_android_quic() -> QuicTransportSettings {
    chrome::v154_quic()
}

/// Returns Chrome 154.0.8037.57 HTTP/3 settings for Android.
///
/// Uses [`chrome::v154_http3`].
#[must_use]
pub fn v154_android_http3() -> Http3Settings {
    chrome::v154_http3()
}

/// Returns Chrome 154.0.8037.57 HTTP/3 request settings for Android.
///
/// Uses [`chrome::v154_http3_request`].
#[must_use]
pub fn v154_android_http3_request() -> Http3RequestSettings {
    chrome::v154_http3_request()
}

/// Returns Chrome 154.0.8037.57 WebSocket settings for Android.
///
/// Uses [`chrome::v154_websocket`].
#[must_use]
pub fn v154_android_websocket() -> WebSocketSettings {
    chrome::v154_websocket()
}

/// Returns Chrome 154.0.8037.57 Android address-bar navigation fields.
///
/// Uses [`chrome::v154_windows_navigation_template`]'s ordering and priority,
/// with the reduced Android user agent and [`v154_android_client_hints`].
/// This models typed navigation; another app's `VIEW` intent omits
/// `Sec-Fetch-User` and can change `Sec-Fetch-Site`.
#[must_use]
pub fn v154_android_navigation_template() -> RequestTemplate {
    chrome::v154_navigation_template(Some(V154_ANDROID_USER_AGENT))
}

/// Returns Chrome 154.0.8037.57 Android same-origin no-store GET fields.
///
/// Uses [`chrome::v154_windows_fetch_no_store_template`]'s ordering and
/// priority with the reduced Android user agent and mobile client hints.
/// HTTP/3 and requested client hints are unavailable.
#[must_use]
pub fn v154_android_fetch_no_store_template() -> RequestTemplate {
    chrome::v154_fetch_no_store_template(Some(V154_ANDROID_USER_AGENT))
}

pub(crate) fn validate_model(model: &str) -> Result<(), crate::InvalidClientHintSettings> {
    if model.bytes().all(|byte| matches!(byte, b' '..=b'~')) {
        Ok(())
    } else {
        Err(crate::InvalidClientHintSettings::new(
            crate::ValidationErrorKind::InvalidValue,
            "model",
            "device model must contain only printable ASCII",
        ))
    }
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
