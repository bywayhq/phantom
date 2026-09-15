//! Wire settings retained from Firefox browser observations.

use crate::http2::{Http2Priority, Http2PseudoHeader, Http2Setting, Http2Settings};

/// Returns HTTP/2 settings observed from Firefox 154.0 on macOS 15.5.
///
/// The initial SETTINGS and connection window come from the retained local raw
/// startup-frame capture. Pseudo-header order and request priority come from
/// matching supplemental Peet and Pingly observations; the local capture ends
/// before a request HEADERS frame. The returned value is an ordinary owned
/// [`Http2Settings`], so callers can customize it before constructing a
/// transport.
#[must_use]
pub fn v154_macos_http2() -> Http2Settings {
    Http2Settings {
        initial_settings: vec![
            Http2Setting::HeaderTableSize(65_536),
            Http2Setting::EnablePush(false),
            Http2Setting::InitialWindowSize(131_072),
            Http2Setting::MaxFrameSize(16_384),
        ],
        initial_connection_window_size: 12_582_912,
        pseudo_header_order: vec![
            Http2PseudoHeader::Method,
            Http2PseudoHeader::Path,
            Http2PseudoHeader::Authority,
            Http2PseudoHeader::Scheme,
        ],
        headers_priority: Some(Http2Priority {
            dependency_stream_id: 0,
            weight: 42,
            exclusive: false,
        }),
    }
}

#[cfg(test)]
mod tests;
