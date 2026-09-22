//! Fixed HTTP/2 response receive limits.
//!
//! These limits are local decoder policy. None of them is advertised in
//! SETTINGS, so the initial SETTINGS frame remains exactly the profile's.

/// Unadvertised ceiling on one decoded response header list, in RFC 9113
/// section 6.5.2 units (name plus value plus 32 bytes per field).
///
/// The value is Firefox's `network.http.max_response_header_size` default of
/// 393,216 bytes, but Firefox measures differently. `Http2Session::RecvHeaders`
/// sums the encoded HPACK bytes of a HEADERS frame and its CONTINUATION frames,
/// excluding padding and priority, and fails the whole connection with
/// `GOAWAY(PROTOCOL_ERROR)` above the limit. `nsHttpTransaction::ProcessData`
/// separately fails the request once its decoded head, serialized as a status
/// line and `name: value\r\n` lines, exceeds it. Phantom resets only the
/// stream, and its 32-byte per-field overhead exceeds Firefox's 4 bytes, so a
/// list of many small fields can reach this ceiling before Firefox's. Sources
/// (mozilla-central `4d5216592535`):
/// <https://hg.mozilla.org/mozilla-central/file/4d5216592535badef64a33022512c562e3d4f946/netwerk/protocol/http/Http2Session.cpp#l1577>
/// and
/// <https://hg.mozilla.org/mozilla-central/file/4d5216592535badef64a33022512c562e3d4f946/netwerk/protocol/http/nsHttpTransaction.cpp#l2823>.
///
/// Chromium advertises and enforces `kSpdyMaxHeaderListSize` (262,144 bytes),
/// which the Chrome profile already sends, so the lower advertised value
/// applies there. Without this ceiling, profiles that omit
/// `SETTINGS_MAX_HEADER_LIST_SIZE` would accept 16 MiB lists.
pub(super) const MAX_RESPONSE_HEADER_LIST_BYTES: u32 = 393_216;

/// Interim responses accepted before one final response, matching the HTTP/1
/// and HTTP/3 transports and the HTTP CONNECT exchange bound.
///
/// The backend enforces it as each 1xx head arrives, before the response is
/// polled, so a burst cannot grow the stream's receive queue.
pub(super) const MAX_INFORMATIONAL_RESPONSES: usize = 8;
