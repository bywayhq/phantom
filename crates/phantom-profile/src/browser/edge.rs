//! Microsoft Edge connection settings and request templates.
//!
//! Edge 154 uses Chromium connection settings with Edge TLS offers, client
//! hints and request fields. Windows and macOS client hints are available.
//!
//! Select `Fetch` from the `edge-154-windows` catalog profile for ordinary
//! same-origin GETs. Supply `User-Agent` and any cache validators.
//!
//! Android recipes target Edge 153.0.4234.49. See each recipe for its required
//! caller fields and supported protocols.

pub use crate::catalog::browser_profiles::edge::*;

mod android;
mod historical;

pub use historical::{
    v153_http2, v153_http3, v153_http3_request, v153_quic, v153_quic_tls, v153_tcp_tls,
    v153_windows_client_hints, v153_windows_fetch_no_store_template,
    v153_windows_navigation_template,
};

pub use android::{
    v153_android_client_hints, v153_android_client_hints_for_model,
    v153_android_fetch_no_store_template, v153_android_http2, v153_android_http3,
    v153_android_http3_request, v153_android_navigation_template, v153_android_quic,
    v153_android_quic_tls, v153_android_tcp_tls, v153_android_websocket,
};

use crate::{
    browser::chrome, client_hints::ClientHintSettings, request_template::RequestTemplate,
    tls::TlsSettings,
};

/// Returns Edge 154.0.4258.37 TLS settings for Windows 11.
///
/// Uses [`chrome::v154_tcp_tls`] without trust-anchor IDs. Keeps its
/// HTTPS-record ECH and session-ticket policies.
#[must_use]
pub fn v154_tcp_tls() -> TlsSettings {
    crate::tls::components::edge_154_tcp_tls()
}

/// Returns Edge 154.0.4258.37 TLS settings for HTTP/3.
///
/// Uses [`chrome::v154_quic_tls`] without trust-anchor IDs, including its
/// HTTPS-record ECH and session-ticket policies.
#[must_use]
pub fn v154_quic_tls() -> TlsSettings {
    crate::tls::components::edge_154_quic_tls()
}

/// Returns Edge 154.0.4258.48 client hints for Windows 11 x64.
///
/// Uses Chromium field order with Edge's brand list and full version.
#[must_use]
pub fn v154_windows_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::edge_windows_154_client_hints()
}

/// Returns Edge 154.0.4258.48 client hints for macOS 15.5 arm64.
///
/// Uses the Windows hint order with macOS platform values.
#[must_use]
pub fn v154_macos_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::edge_macos_154_client_hints()
}

/// Returns Edge 154 navigation fields for Windows and macOS.
///
/// Uses [`chrome::v154_windows_navigation_template`]'s ordering with Edge
/// client hints. Supply `User-Agent`. Language defaults to `en-US,en;q=0.9`;
/// override it for another language list. Use [`v154_macos_client_hints`]
/// on macOS.
#[must_use]
pub fn v154_windows_navigation_template() -> RequestTemplate {
    chrome::v154_navigation_template(None)
}

/// Returns Edge 154 same-origin no-store GET fields for Windows and macOS.
///
/// Uses [`chrome::v154_windows_fetch_no_store_template`]'s ordering and
/// HTTP/2 weight 220. Supply `User-Agent`. HTTP/3 and requested client hints
/// are unavailable.
#[must_use]
pub fn v154_windows_fetch_no_store_template() -> RequestTemplate {
    chrome::v154_fetch_no_store_template(None)
}

#[cfg(test)]
mod tests;
