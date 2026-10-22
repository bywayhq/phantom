//! Edge 153.0.4234.49 connection settings and request templates for Android.

use crate::{
    browser::chrome,
    client_hints::ClientHintSettings,
    http2::Http2Settings,
    http3::{Http3RequestSettings, Http3Settings},
    quic::QuicTransportSettings,
    request_template::RequestTemplate,
    tls::TlsSettings,
    websocket::WebSocketSettings,
};

/// The `User-Agent` Edge 153 for Android sent on every captured request:
/// Chrome's reduced Android string at Chromium 153 with an `EdgA` token.
pub(crate) const V153_ANDROID_USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 10; K) \
AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Mobile Safari/537.36 EdgA/153.0.0.0";

/// Returns Edge 153.0.4234.49 TLS settings for Android.
///
/// Uses [`crate::browser::edge::v154_tcp_tls`]'s ClientHello settings with
/// ECH GREASE rather than HTTPS-record configurations.
#[must_use]
pub fn v153_android_tcp_tls() -> TlsSettings {
    crate::tls::components::edge_153_android_tcp_tls()
}

/// Returns Edge 153.0.4234.49 TLS settings for HTTP/3 on Android.
///
/// Uses [`crate::browser::edge::v154_quic_tls`]'s ClientHello settings with
/// ECH GREASE.
#[must_use]
pub fn v153_android_quic_tls() -> TlsSettings {
    crate::tls::components::edge_153_android_quic_tls()
}

/// Returns Edge 153.0.4234.49 HTTP/2 settings for Android.
///
/// Uses [`chrome::v154_http2`].
#[must_use]
pub fn v153_android_http2() -> Http2Settings {
    chrome::v154_http2()
}

/// Returns QUIC transport settings observed from Edge 153.0.4234.49 for
/// Android, equal to [`chrome::v154_quic`].
#[must_use]
pub fn v153_android_quic() -> QuicTransportSettings {
    chrome::v154_quic()
}

/// Returns HTTP/3 settings observed from Edge 153.0.4234.49 for Android,
/// equal to [`chrome::v154_http3`].
#[must_use]
pub fn v153_android_http3() -> Http3Settings {
    chrome::v154_http3()
}

/// Returns HTTP/3 request ordering observed from Edge 153.0.4234.49 for
/// Android, equal to [`chrome::v154_http3_request`].
#[must_use]
pub fn v153_android_http3_request() -> Http3RequestSettings {
    chrome::v154_http3_request()
}

/// Returns Edge 153 client hints for a Pixel 7 on Android 17.
///
/// Uses Chromium field order with Edge 153.0.4234.49 brands and mobile
/// platform values. Use [`v153_android_client_hints_for_model`] for another
/// model.
#[must_use]
pub fn v153_android_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::edge_android_153_client_hints()
}

/// Returns [`v153_android_client_hints`] with a custom `sec-ch-ua-model`.
///
/// Pass Android's `Build.MODEL` value.
///
/// # Errors
///
/// Rejects characters outside printable ASCII (space through `~`). Quotes
/// and backslashes are escaped in the structured-field string.
pub fn v153_android_client_hints_for_model(
    model: &str,
) -> Result<ClientHintSettings, crate::InvalidClientHintSettings> {
    crate::browser::chrome::validate_model(model)?;
    Ok(crate::catalog::client_hints_components::edge_android_153_client_hints_for_model(model))
}

/// Returns Edge 153.0.4234.49 Android address-bar navigation fields.
///
/// Uses [`chrome::v154_windows_navigation_template`]'s ordering and priority
/// with the Edge Android user agent and [`v153_android_client_hints`].
/// This models typed navigation; another app's `VIEW` intent omits
/// `Sec-Fetch-User` and can change `Sec-Fetch-Site`.
#[must_use]
pub fn v153_android_navigation_template() -> RequestTemplate {
    chrome::v154_navigation_template(Some(V153_ANDROID_USER_AGENT))
}

/// Returns Edge 153.0.4234.49 Android same-origin no-store GET fields.
///
/// Uses Chromium ordering and HTTP/2 weight 220 with the Edge Android
/// user agent. HTTP/3 is unavailable.
#[must_use]
pub fn v153_android_fetch_no_store_template() -> RequestTemplate {
    chrome::v154_fetch_no_store_template(Some(V153_ANDROID_USER_AGENT))
}

/// Returns Edge 153 Android WebSocket settings.
///
/// Uses Chromium's compression, 240-second opening deadline, session
/// selection and refusal retries. Supply `User-Agent` and `Origin`.
/// Includes optional cookie and subprotocol slots. HTTP/3 and Android
/// buffer sizing are outside this recipe.
///
/// Connection policies follow Chromium 153.0.8010.53 at commit
/// `792bf6722e73a45aa9e47c163b9901bdc17f3230`.
#[must_use]
pub fn v153_android_websocket() -> WebSocketSettings {
    crate::catalog::websocket_components::edge_android_153_websocket()
}

#[cfg(test)]
mod tests;
