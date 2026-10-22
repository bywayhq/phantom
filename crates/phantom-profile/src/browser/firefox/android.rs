//! Firefox 156.0.1 TCP and TLS settings for Android.

use crate::{tcp::TcpSettings, tls::TlsSettings};

/// Returns Firefox 156.0.1 TLS settings for Android.
///
/// Uses [`crate::browser::firefox::v157_tcp_tls`]'s ClientHello settings,
/// ECH GREASE sizing and direct TCP early-data policy. Offers the oldest
/// ticket first ([`crate::SessionTicketOrder::OldestFirst`]), following NSS
/// expiry ordering with Android's microsecond clock.
#[must_use]
pub fn v156_android_tcp_tls() -> TlsSettings {
    crate::tls::components::firefox_156_android_tcp_tls()
}

/// Returns Firefox 156.0.1 TCP settings for Android.
///
/// Keepalive sets idle time, the computed interval and four probes. The send
/// buffer stays unchanged. Address selection follows
/// [`crate::browser::firefox::v157_tcp`].
#[must_use]
pub fn v156_android_tcp() -> TcpSettings {
    crate::catalog::tcp_components::firefox_156_android_tcp()
}
