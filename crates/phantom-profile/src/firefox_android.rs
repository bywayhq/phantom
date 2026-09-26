//! Wire settings retained from Firefox for Android observations.
//!
//! Firefox 156.0.1 for Android, as the Google Play Store served it to the
//! `phantom-api35-play` Android 15 emulator. A release Firefox for Android
//! reads GeckoView's debug configuration when it is the device's debug app,
//! so a capture can set preferences such as `network.dns.localDomains`, but
//! it cannot place a certificate override in the app's private profile. No
//! capture can therefore complete a TLS handshake with a test certificate, and
//! only the TCP ClientHello is captured. It has a recipe here.
//!
//! There is no Firefox for Android H2, WebSocket, request template, TCP,
//! HTTP/1.1 connection, address-cache, proxy CONNECT, or cookie-placement
//! recipe: none of those layers was captured on Android.

use crate::{firefox, tls::TlsSettings};

/// Returns TLS settings captured from Firefox 156.0.1 for Android.
///
/// Twelve fresh-profile ClientHellos of the retained capture equal the
/// desktop [`firefox::v156_tls`] ClientHello: the same fixed extension order,
/// cipher suites, groups, key shares, signature algorithms, record size
/// limit, delegated-credential schemes, and a 240-byte ECH GREASE payload.
/// Firefox for Android also draws its ECH GREASE AEAD per connection: 5 of
/// the 12 used AES-128-GCM and 7 ChaCha20-Poly1305. This returns that recipe.
#[must_use]
pub fn v156_tls() -> TlsSettings {
    firefox::v156_tls()
}
