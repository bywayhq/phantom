//! Retained Windows layers for Edge 153.0.4234.48.
//!
//! Socket options, address-cache lifetimes, and HTTP/1.1 pool policy are
//! unavailable. ClientHello, HTTP/2 startup, QUIC parameters, HTTP/3 settings,
//! and request ordering reuse the equivalent Chromium components. Their
//! uncaptured connection policies remain inherited, rather than verified
//! Edge 153 behavior. TCP and QUIC ticket bounds also remain reused policies.

use crate::browser::chrome;
use crate::{
    ClientHintSettings, ClientProfile, Http2Settings, Http3ClientSettings, Http3RequestSettings,
    Http3Settings, QuicTransportSettings, RequestTemplate, TlsSettings,
};

/// Returns the captured Edge 153 TCP ClientHello settings.
///
/// The offer matches the Chromium component without trust-anchor IDs.
/// ECH and ticket policies reuse that component; a ClientHello alone does
/// not verify their complete lifecycles.
#[must_use]
pub fn v153_tcp_tls() -> TlsSettings {
    let mut settings = chrome::v154_tcp_tls();
    settings.requested_trust_anchor_ids = None;
    settings
}

/// Returns the captured Edge 153 QUIC ClientHello settings.
///
/// Ticket resumption policy reuses Chromium behavior. The retained Edge
/// captures verify initial offers, rather than the QUIC ticket lifecycle.
#[must_use]
pub fn v153_quic_tls() -> TlsSettings {
    let mut settings = chrome::v154_quic_tls();
    settings.requested_trust_anchor_ids = None;
    settings
}

/// Returns HTTP/2 settings whose startup matches the Edge 153 capture.
///
/// Uncaptured stream limits, PING timers, and idle policy reuse Chromium.
#[must_use]
pub fn v153_http2() -> Http2Settings {
    chrome::v154_http2()
}

/// Returns QUIC parameters matching the retained Edge 153 startup.
///
/// Parameter order reuses Chromium's per-connection shuffle. The retained
/// samples do not establish Edge's shuffle distribution or a fixed order.
#[must_use]
pub fn v153_quic() -> QuicTransportSettings {
    chrome::v154_quic()
}

/// Returns HTTP/3 SETTINGS matching the retained Edge 153 startup.
#[must_use]
pub fn v153_http3() -> Http3Settings {
    chrome::v154_http3()
}

/// Returns HTTP/3 request ordering matching the Edge 153 navigation.
///
/// Uncaptured cookie splitting, extended CONNECT, and alternative-service
/// field policies remain inherited.
#[must_use]
pub fn v153_http3_request() -> Http3RequestSettings {
    chrome::v154_http3_request()
}

/// Returns the Windows client hints captured from Edge 153.0.4234.48.
#[must_use]
pub fn v153_windows_client_hints() -> ClientHintSettings {
    crate::catalog::client_hints_components::edge_windows_153_client_hints()
}

/// Returns the captured Edge 153 Windows navigation field layout.
///
/// Supply `User-Agent`: the retained runs were headless. Requested-hint
/// placement and ordinary fields reuse the equivalent Chromium template.
#[must_use]
pub fn v153_windows_navigation_template() -> RequestTemplate {
    chrome::v154_navigation_template(None)
}

/// Returns the captured Edge 153 Windows no-store fetch field layout.
///
/// Supply `User-Agent` and `Referer`. HTTP/3 fetch fields are unavailable.
#[must_use]
pub fn v153_windows_fetch_no_store_template() -> RequestTemplate {
    chrome::v154_fetch_no_store_template(None)
}

/// Returns the available Windows layers for Edge 153.0.4234.48.
///
/// TCP and UDP socket settings, DNS caching, HTTP/1.1 pool policy, WebSocket
/// connection policy, proxy CONNECT, and cookie placement are not supplied.
/// Their generic defaults remain. Choose a request template separately.
#[must_use]
pub fn v153_windows() -> ClientProfile {
    ClientProfile::new(v153_tcp_tls())
        .with_http2(v153_http2())
        .with_http3(Http3ClientSettings::new(
            v153_quic_tls(),
            v153_quic(),
            v153_http3(),
            v153_http3_request(),
        ))
        .with_client_hints(v153_windows_client_hints())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_hints::navigation_capture::{NavigationCapture, profile_hints};

    #[test]
    fn historical_edge_153_windows_hints_match_all_retained_navigation_runs()
    -> Result<(), Box<dyn std::error::Error>> {
        let hints = v153_windows_client_hints();
        hints.validate()?;
        let capture = NavigationCapture::parse(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/client-hints/edge/153.0.4234.48/windows-11-26200/navigation.txt"
        )))?;
        assert_eq!(capture.value("client")?, "Microsoft Edge");
        assert_eq!(capture.value("client_version")?, "153.0.4234.48");
        assert_eq!(
            capture.value("operating_system")?,
            "Windows 11 Home 10.0.26200 x64"
        );
        capture.assert_runs_agree()?;
        assert_eq!(profile_hints(&hints), capture.hints()?);
        Ok(())
    }
}
