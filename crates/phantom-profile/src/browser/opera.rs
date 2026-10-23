//! Opera connection settings and request templates.
//!
//! Opera 136 uses Chromium connection settings with Opera trust-anchor IDs,
//! client hints and request fields. Windows and macOS client hints are available.
//!
//! Select `Fetch` from the `opera-136-windows` catalog profile for ordinary
//! same-origin GETs and revalidation. Supply `User-Agent` and any cache
//! validators.
//!
//! Opera 102 Android provides TLS settings and client hints. Other Android
//! layers are unavailable.

pub use crate::catalog::browser_profiles::opera::*;

mod android;

pub use android::{
    v102_android_client_hints, v102_android_client_hints_for_model, v102_android_tcp_tls,
};

use crate::{
    browser::chrome, client_hints::ClientHintSettings, request_template::RequestTemplate,
    tls::TlsSettings,
};

/// Returns Opera 136.0.6008.52 TLS settings for Windows 11.
///
/// Uses [`chrome::v154_tcp_tls`] with 32 trust-anchor IDs. Each client draws
/// one recorded order and keeps it for every TCP connection. ECH uses HTTPS
/// records and can retry with the server's replacement configuration.
#[must_use]
pub fn v136_tcp_tls() -> TlsSettings {
    crate::tls::components::opera_136_tcp_tls()
}

/// Returns Opera 136.0.6008.52 TLS settings for HTTP/3.
///
/// Uses [`chrome::v154_quic_tls`] with 32 trust-anchor IDs. Each connection
/// draws one recorded order. Keeps the Chromium session-ticket and ECH
/// policies, including rejection handling described by [`chrome::v154_quic_tls`].
#[must_use]
pub fn v136_quic_tls() -> TlsSettings {
    crate::tls::components::opera_136_quic_tls()
}

/// Returns Opera 136.0.6008.52 client hints for Windows 11 x64.
///
/// Uses Chromium field order with Opera's brand list and full version.
#[must_use]
pub fn v136_windows_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::opera_windows_136_client_hints()
}

/// Returns Opera 136.0.6008.52 client hints for macOS 15.5 arm64.
///
/// Uses the Windows hint order with macOS platform values.
#[must_use]
pub fn v136_macos_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::opera_macos_136_client_hints()
}

/// Returns Opera 136.0.6008.52 navigation fields for Windows and macOS.
///
/// Uses [`chrome::v154_windows_navigation_template`]'s ordering with Opera
/// client hints. Supply `User-Agent`. Use [`v136_macos_client_hints`] on macOS.
#[must_use]
pub fn v136_windows_navigation_template() -> RequestTemplate {
    chrome::v154_navigation_template(None)
}

/// Returns Opera 136.0.6008.52 same-origin no-store GET fields.
///
/// Uses [`chrome::v154_windows_fetch_no_store_template`]'s ordering and
/// HTTP/2 weight 220. Supply `User-Agent`. HTTP/3 and requested client hints
/// are unavailable. On macOS, use [`v136_macos_client_hints`].
#[must_use]
pub fn v136_windows_fetch_no_store_template() -> RequestTemplate {
    chrome::v154_fetch_no_store_template(None)
}

#[cfg(test)]
mod tests;
