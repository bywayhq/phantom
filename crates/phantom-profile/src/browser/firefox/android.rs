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

use crate::{
    browser::firefox,
    tls::{SessionTicketOrder, TlsSettings},
};

/// Returns TLS settings captured from Firefox 156.0.1 for Android.
///
/// Twelve fresh-profile ClientHellos of the retained capture equal the
/// desktop Firefox 156.0.1 ClientHello, which desktop Firefox 157.0 still
/// sends and [`firefox::v157_tcp_tls`] reproduces: the same fixed extension order,
/// cipher suites, groups, key shares, signature algorithms, record size
/// limit, delegated-credential schemes, and a 240-byte ECH GREASE payload.
/// Firefox for Android also draws its ECH GREASE AEAD per connection: 5 of
/// the 12 used AES-128-GCM and 7 ChaCha20-Poly1305. This returns that recipe.
///
/// It sizes the ECH GREASE payload from the ClientHello as the desktop
/// recipe does. Only the fresh 240 bytes come from an Android capture: the
/// resumed and IP-literal lengths come from NSS source and the desktop
/// captures, since no Android capture resumed a session or reached an IP
/// literal.
///
/// It keeps the desktop recipe's early data over TCP
/// ([`TlsSettings::tcp_early_data`]) from source, not from a capture: no
/// Android capture resumed a session. At tag `FIREFOX_156_0_RELEASE`,
/// `security.tls.enable_0rtt_data` and
/// `network.http.remove_resumption_token_when_early_data_failed` default to
/// true on every platform (`modules/libpref/init/StaticPrefList.yaml:19097-19100`
/// and `:17033-17037`), and GeckoView's Android preferences
/// (`mobile/android/app/geckoview-prefs.js`) override neither.
///
/// It offers saved tickets [`SessionTicketOrder::OldestFirst`], where the
/// desktop recipe offers them
/// [`SessionTicketOrder::OldestConnectionFirst`]. Firefox offers the ticket
/// whose expiry, the time it received the ticket plus two days, is earliest.
/// Android's clock counts microseconds, as macOS's does, so tickets almost
/// never tie and the earliest goes first, as in the macOS capture. No
/// Android capture shows the order.
#[must_use]
pub fn v156_android_tcp_tls() -> TlsSettings {
    TlsSettings {
        session_ticket_order: SessionTicketOrder::OldestFirst,
        ..firefox::v157_tcp_tls()
    }
}
