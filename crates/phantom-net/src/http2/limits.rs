//! Fixed HTTP/2 response receive limits.
//!
//! These limits are local decoder policy. None of them is advertised in
//! SETTINGS, so the initial SETTINGS frame remains exactly the profile's.

/// Unadvertised ceiling on one decoded response header list, in RFC 9113
/// section 6.5.2 units (name plus value plus 32 bytes per field).
///
/// Firefox rejects HTTP/2 response header blocks above its
/// `network.http.max_response_header_size` default of 393,216 bytes. Chromium
/// advertises and enforces `kSpdyMaxHeaderListSize` (262,144 bytes), which the
/// Chrome profile already sends, so the lower advertised value applies there.
/// Without this ceiling, profiles that omit `SETTINGS_MAX_HEADER_LIST_SIZE`
/// would accept 16 MiB lists.
pub(super) const MAX_RESPONSE_HEADER_LIST_BYTES: u32 = 393_216;
