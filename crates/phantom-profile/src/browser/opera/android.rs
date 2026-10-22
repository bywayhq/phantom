//! Opera 102.1.5206.90382 TLS settings and client hints for Android.

use crate::{client_hints::ClientHintSettings, tls::TlsSettings};

/// Returns Opera 102.1.5206.90382 TLS settings for Android.
///
/// Uses [`crate::browser::chrome::v154_tcp_tls`]'s ClientHello settings
/// without trust-anchor IDs. ECH uses GREASE rather than HTTPS-record
/// configurations.
#[must_use]
pub fn v102_android_tcp_tls() -> TlsSettings {
    crate::tls::components::opera_102_android_tcp_tls()
}

/// Returns Opera 102.1.5206.90382 client hints for Android 17.
///
/// Includes OperaMobile, Opera 137 and Chromium 152 brands, a Pixel 7 model
/// and an empty form-factor value. Use [`v102_android_client_hints_for_model`]
/// for another model.
#[must_use]
pub fn v102_android_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::opera_android_102_client_hints()
}

/// Returns [`v102_android_client_hints`] with a custom `sec-ch-ua-model`.
///
/// Pass Android's `Build.MODEL` value.
///
/// # Errors
///
/// Rejects characters outside printable ASCII (space through `~`). Quotes
/// and backslashes are escaped in the structured-field string.
pub fn v102_android_client_hints_for_model(
    model: &str,
) -> Result<ClientHintSettings, crate::InvalidClientHintSettings> {
    crate::browser::chrome::validate_model(model)?;
    Ok(crate::catalog::client_hints_components::opera_android_102_client_hints_for_model(model))
}

#[cfg(test)]
mod tests;
