//! Wire settings retained from Opera for Android observations.
//!
//! Opera 102.1.5206.90382, built on Chromium 152.0.7977.82, as the Google
//! Play Store served it to two emulators: the `phantom-pixel7` Android 17
//! emulator, which reports a Pixel 7, for the TLS and client-hint captures,
//! and the earlier `phantom-api35-play` Android 15 emulator for the HTTP/1.1
//! request captures.
//!
//! Opera for Android reads no command-line file, so no capture can map a test
//! name, trust a test certificate, force QUIC, or route through a proxy: it
//! reaches only the device's own loopback. The retained captures therefore
//! cover the TCP ClientHello, sent to `https://localhost`, and client hints
//! and plaintext HTTP/1.1 requests to `http://127.0.0.1`. Only the TLS and
//! client-hint layers have recipes here. With no HTTP/2 or HTTP/3 capture,
//! there are no request templates, and no H2, QUIC, H3, or WebSocket recipe.
//!
//! There is no TCP, HTTP/1.1 connection, address-cache, proxy CONNECT, or
//! cookie-placement recipe, for the reasons given in [`crate::browser::opera`] and
//! [`crate::browser::chrome`].

use crate::{client_hints::ClientHintSettings, tls::TlsSettings};

/// Returns TLS settings captured from Opera 102.1.5206.90382 for Android.
///
/// The retained ClientHello, from a cleared profile, equals the
/// [`crate::browser::chrome::v154_tcp_tls`] ClientHello without the
/// trust-anchor IDs extension, signature-algorithm GREASE included. Desktop
/// Opera 136, on the same Chromium 152 base, sends 32 trust-anchor IDs
/// ([`crate::browser::opera::v136_tcp_tls`]); Opera for Android sends none.
/// The captures reached `localhost`, the only name Opera could resolve to the
/// listener, and a ClientHello to another name differs only in its server
/// name. [`TlsSettings::ech`] uses GREASE without HTTPS records: no Android
/// capture shows Opera using an HTTPS record's `ech`, though desktop Opera
/// 136 does.
#[must_use]
pub fn v102_android_tcp_tls() -> TlsSettings {
    crate::tls::components::opera_102_android_tcp_tls()
}

/// Returns client-hint fields observed from Opera 102.1.5206.90382 for
/// Android.
///
/// From the retained navigation capture, three fresh-profile runs that agree.
/// Names, order, and delivery equal the Chromium client-hint recipes. The
/// values carry Opera's four-brand list, which names `OperaMobile`, `Opera`
/// 137, and Chromium 152 and puts the greased brand last, `?1`, the
/// `"Android"` platform at version `"17"` (Opera sends no minor versions),
/// the `"Pixel 7"` model, and an empty `sec-ch-ua-form-factors`.
///
/// For another phone, use [`v102_android_client_hints_for_model`].
#[must_use]
pub fn v102_android_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::opera_android_102_client_hints()
}

/// Returns the client hints of [`v102_android_client_hints`] with another
/// device model in `sec-ch-ua-model`, as Android's `Build.MODEL` reports it.
/// Only the Pixel 7 value is captured.
///
/// # Errors
///
/// Returns an error if the model contains anything outside printable ASCII
/// (space through `~`). Quotes and backslashes are escaped in the hint value.
pub fn v102_android_client_hints_for_model(
    model: &str,
) -> Result<ClientHintSettings, crate::InvalidClientHintSettings> {
    crate::browser::chrome::validate_model(model)?;
    Ok(crate::catalog::client_hints_components::opera_android_102_client_hints_for_model(model))
}

#[cfg(test)]
mod tests;
