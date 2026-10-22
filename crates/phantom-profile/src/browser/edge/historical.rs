//! Edge 153.0.4234.48 settings for Windows.
//!
//! Uses Chromium TLS, HTTP/2 and HTTP/3 policies with Edge's ClientHello and
//! request fields. Socket options, address-cache and HTTP/1.1 pool settings
//! are unavailable.

use crate::browser::chrome;
use crate::{
    ClientHintSettings, Http2Settings, Http3RequestSettings, Http3Settings, QuicTransportSettings,
    RequestTemplate, TlsSettings,
};

/// Returns the captured Edge 153 TCP ClientHello settings.
///
/// The offer matches the Chromium component without trust-anchor IDs.
/// Uses the Chromium component's ECH and ticket policies.
#[must_use]
pub fn v153_tcp_tls() -> TlsSettings {
    let mut settings = chrome::v154_tcp_tls();
    settings.requested_trust_anchor_ids = None;
    settings
}

/// Returns the captured Edge 153 QUIC ClientHello settings.
///
/// Uses Chromium ticket resumption policy.
#[must_use]
pub fn v153_quic_tls() -> TlsSettings {
    let mut settings = chrome::v154_quic_tls();
    settings.requested_trust_anchor_ids = None;
    settings
}

/// Returns HTTP/2 settings whose startup matches the Edge 153 capture.
///
/// Uses Chromium stream limits, PING timers and idle policy.
#[must_use]
pub fn v153_http2() -> Http2Settings {
    chrome::v154_http2()
}

/// Returns QUIC parameters matching the retained Edge 153 startup.
///
/// Uses Chromium's per-connection parameter shuffle.
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
/// Uses Chromium cookie splitting and alternative-service field policies.
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
