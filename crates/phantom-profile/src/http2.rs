//! Backend-neutral HTTP/2 profile settings.

use std::{
    error::Error,
    fmt,
    time::{Duration, Instant},
};

const MAX_WINDOW_SIZE: u32 = (1 << 31) - 1;
const MAX_STREAM_ID: u32 = (1 << 31) - 1;
const INITIAL_CONNECTION_WINDOW_SIZE: u32 = 65_535;
const MIN_FRAME_SIZE: u32 = 1 << 14;
const MAX_FRAME_SIZE: u32 = (1 << 24) - 1;

/// One value in the initial HTTP/2 SETTINGS frame.
///
/// Values are stored in a [`Vec`] on [`Http2Settings`], so their position is
/// also their wire order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http2Setting {
    /// SETTINGS_HEADER_TABLE_SIZE.
    HeaderTableSize(u32),
    /// SETTINGS_ENABLE_PUSH.
    EnablePush(bool),
    /// SETTINGS_MAX_CONCURRENT_STREAMS.
    MaxConcurrentStreams(u32),
    /// SETTINGS_INITIAL_WINDOW_SIZE.
    InitialWindowSize(u32),
    /// SETTINGS_MAX_FRAME_SIZE.
    MaxFrameSize(u32),
    /// SETTINGS_MAX_HEADER_LIST_SIZE.
    MaxHeaderListSize(u32),
    /// SETTINGS_ENABLE_CONNECT_PROTOCOL.
    EnableConnectProtocol(bool),
    /// SETTINGS_NO_RFC7540_PRIORITIES.
    NoRfc7540Priorities(bool),
}

impl Http2Setting {
    fn kind(self) -> SettingKind {
        match self {
            Self::HeaderTableSize(_) => SettingKind::HeaderTableSize,
            Self::EnablePush(_) => SettingKind::EnablePush,
            Self::MaxConcurrentStreams(_) => SettingKind::MaxConcurrentStreams,
            Self::InitialWindowSize(_) => SettingKind::InitialWindowSize,
            Self::MaxFrameSize(_) => SettingKind::MaxFrameSize,
            Self::MaxHeaderListSize(_) => SettingKind::MaxHeaderListSize,
            Self::EnableConnectProtocol(_) => SettingKind::EnableConnectProtocol,
            Self::NoRfc7540Priorities(_) => SettingKind::NoRfc7540Priorities,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SettingKind {
    HeaderTableSize,
    EnablePush,
    MaxConcurrentStreams,
    InitialWindowSize,
    MaxFrameSize,
    MaxHeaderListSize,
    EnableConnectProtocol,
    NoRfc7540Priorities,
}

/// A request pseudo-header in its HPACK wire order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http2PseudoHeader {
    /// `:method`.
    Method,
    /// `:authority`.
    Authority,
    /// `:scheme`.
    Scheme,
    /// `:path`.
    Path,
    /// `:protocol`.
    ///
    /// This pseudo-header is present only on extended CONNECT requests.
    Protocol,
}

/// Which HPACK static entry names a field whose name has several entries.
///
/// RFC 7541 appendix A lists `:method`, `:path`, and `:scheme` twice, so a
/// field whose value matches neither entry can be named by either index. A
/// value that does match an entry is still sent as that entry's own index.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http2StaticNameIndex {
    /// `:method` 2, `:path` 4, and `:scheme` 6.
    #[default]
    Lowest,
    /// `:method` 3, `:path` 5, and `:scheme` 7.
    Highest,
}

/// When a literal HPACK name or value is Huffman-coded.
///
/// RFC 7541 section 5.2 leaves the choice to the encoder, and the flag is on
/// the wire for every literal string. The rules differ only when the coded
/// form is exactly as long as the raw one, which short values such as `13`,
/// `*/*`, and `CONNECT` all are.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http2HuffmanCoding {
    /// Code every literal string, whatever it costs.
    #[default]
    Always,
    /// Code only when the coded form is strictly shorter.
    WhenShorter,
    /// Code whenever the coded form is no longer than the raw one.
    WhenNotLonger,
    /// Code every literal string, and flag an empty one as coded.
    ///
    /// [`Self::Always`] sends an empty string raw, as the byte `0x00`; this
    /// rule sends `0x80`, a coded string of length zero (Firefox).
    AlwaysIncludingEmpty,
}

/// How the HPACK encoder sends each `cookie` field.
///
/// RFC 9113 section 8.2.3 lets a client split `cookie` into one field per
/// cookie, called crumbs, so that each can be indexed on its own. Browsers do,
/// and the split and each crumb's representation are on the wire. The rule
/// applies to every `cookie` field on the connection, whether the cookie jar
/// or the caller supplied it. While crumbs are sent, the rule alone chooses
/// each crumb's representation: `RequestHeader::sensitive` on a `cookie` field
/// then only hides its value from `Debug` output.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http2CookieCrumbs {
    /// Send each `cookie` field whole, as a literal that never enters the
    /// dynamic table: never-indexed when the field is sensitive, otherwise
    /// without indexing.
    #[default]
    Whole,
    /// Split at every `;` and insert each crumb into the dynamic table, then
    /// send it as an index on later requests.
    ///
    /// Spaces and tabs at both ends of the value are removed first, and one
    /// space after each `;` is skipped (Chromium).
    IndexAll,
    /// Split at every `"; "`. A crumb shorter than 20 bytes is a never-indexed
    /// literal; a longer one is inserted into the dynamic table (Firefox).
    NeverIndexShort,
}

/// Which ordinary fields the HPACK encoder keeps out of the dynamic table.
///
/// `:path`, and a `cookie` field sent whole, never enter the table under any
/// rule; this setting decides the other ordinary fields. A field marked
/// sensitive is always a never-indexed literal, even when a table entry
/// matches it, except a `cookie` field sent as crumbs, whose rule decides.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http2FieldIndexing {
    /// Keep `age`, `authorization`, `content-length`, `etag`,
    /// `if-modified-since`, `if-none-match`, `location`, and `set-cookie` out
    /// of the table, as the nghttp2 encoder does.
    #[default]
    Nghttp2,
    /// Let every ordinary field enter the table (Chromium).
    All,
    /// Send `authorization` as a never-indexed literal, and let every other
    /// ordinary field enter the table (Firefox).
    NeverIndexAuthorization,
}

/// Which table entry names a literal field whose name is in the table.
///
/// A literal can name its field with any static or dynamic entry that has the
/// same name, and the index is on the wire.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http2NameReference {
    /// The static entry when one has the name, otherwise the newest dynamic
    /// entry. A sensitive field whose name is in the dynamic table names the
    /// newest such entry instead, and a field kept out of the table names only
    /// a static entry.
    #[default]
    StaticUnlessSensitive,
    /// The static entry when one has the name, otherwise the newest dynamic
    /// entry (Chromium).
    StaticThenNewest,
    /// The oldest dynamic entry when one has the name, otherwise the static
    /// entry, which makes it the highest-numbered entry with the name
    /// (Firefox).
    OldestDynamic,
}

/// How a field kept out of the dynamic table is sent when a table entry
/// matches both its name and its value.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http2UnindexedMatch {
    /// As that entry's index, so `:path: /` is index 4 (Chromium).
    #[default]
    Index,
    /// As a literal without indexing that names the entry, so `:path: /` is a
    /// literal naming entry 4 (Firefox).
    Literal,
}

/// The largest field the HPACK encoder inserts into the dynamic table.
///
/// A field's size is its RFC 7541 section 4.1 entry size, name plus value plus
/// 32 bytes, compared with the table size the peer set.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http2IndexingLimit {
    /// A field larger than three quarters of the table is a literal without
    /// indexing.
    #[default]
    ThreeQuarters,
    /// A field larger than half the table, or any field when the table is
    /// under 128 bytes, is a literal without indexing (Firefox).
    Half,
    /// Every field that may enter the table is indexed incrementally, and
    /// older entries are evicted to make room. A field larger than the whole
    /// table empties it and is not inserted (Chromium).
    Unlimited,
}

/// When a field block starts with a dynamic-table size update after the peer
/// sends `SETTINGS_HEADER_TABLE_SIZE`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http2TableSizeUpdates {
    /// Only when the setting changes the table size (Chromium).
    #[default]
    WhenChanged,
    /// After every received setting, even one equal to the current size, so
    /// a peer that states the default 4,096 bytes is answered with an update
    /// to 4,096 (Firefox).
    EverySetting,
}

/// HPACK encoder choices that RFC 7541 leaves to the encoder.
///
/// A peer decodes the same fields whichever choice is made, so these describe
/// a client's wire fingerprint rather than its semantics. They belong to the
/// connection because an HPACK encoder holds them for its whole lifetime.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Http2HpackSettings {
    /// Pseudo-headers never inserted into the dynamic table.
    ///
    /// A listed pseudo-header whose name and value both match a static entry
    /// is still sent as that index. Otherwise it is sent as a literal without
    /// indexing, naming the static entry when one matches its name.
    pub literal_pseudo_headers: Vec<Http2PseudoHeader>,
    /// Which static entry names a field whose name has several entries.
    pub static_name_index: Http2StaticNameIndex,
    /// When a literal name or value is Huffman-coded.
    pub huffman_coding: Http2HuffmanCoding,
    /// How each `cookie` field is split and indexed.
    pub cookie_crumbs: Http2CookieCrumbs,
    /// Which ordinary fields are kept out of the dynamic table.
    pub field_indexing: Http2FieldIndexing,
    /// Which table entry names a literal field.
    pub name_reference: Http2NameReference,
    /// How a field kept out of the table is sent when an entry matches it.
    pub unindexed_match: Http2UnindexedMatch,
    /// The largest field inserted into the dynamic table.
    pub indexing_limit: Http2IndexingLimit,
    /// When a field block starts with a dynamic-table size update.
    pub table_size_updates: Http2TableSizeUpdates,
}

/// How a client numbers its streams and how many it opens at once.
///
/// None of these values is sent on the wire, but each shapes it: the first
/// value is the stream identifier of every connection's first request, the
/// second decides how many requests go out before the peer's SETTINGS arrive,
/// and the third bounds how many go out at once after the peer states a
/// limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2StreamSettings {
    /// Stream identifier of the first request on each connection.
    ///
    /// Later requests take the following odd identifiers. The value must be
    /// odd, as every client-initiated stream is. The default is 1.
    pub first_stream_id: u32,
    /// Concurrent streams the client opens before the peer states
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`.
    ///
    /// The limit holds until the peer states a value, including after an
    /// initial SETTINGS frame that omits the setting; a stated value then
    /// replaces it. `None`, the default, sets no limit before the peer's
    /// initial SETTINGS and lifts every limit when they omit the setting, as
    /// RFC 9113 section 5.1.2 allows. A value must be at least 1.
    pub assumed_max_concurrent_streams: Option<u32>,
    /// Largest `SETTINGS_MAX_CONCURRENT_STREAMS` from the peer that the
    /// client applies as stated.
    ///
    /// A larger stated value is lowered to this one before it limits the
    /// client's concurrent streams. When the peer's first SETTINGS omit the
    /// setting and no assumed limit holds, the limit is this value instead of
    /// none. It does not bound [`Self::assumed_max_concurrent_streams`].
    /// `None`, the default, applies every stated value unchanged. A value must
    /// be at least 1.
    pub max_concurrent_streams_cap: Option<u32>,
}

impl Default for Http2StreamSettings {
    fn default() -> Self {
        Self {
            first_stream_id: 1,
            assumed_max_concurrent_streams: None,
            max_concurrent_streams_cap: None,
        }
    }
}

/// Priority information carried by each outgoing request HEADERS frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http2Priority {
    /// Stream on which the request stream depends.
    pub dependency_stream_id: u32,
    /// RFC 7540 weight in the inclusive range 1..=256.
    pub weight: u16,
    /// Whether the request stream becomes the dependency's sole child.
    pub exclusive: bool,
}

/// Ordered HTTP/2 settings independent of the concrete HTTP/2 backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http2Settings {
    /// Values and wire order of the initial SETTINGS frame.
    ///
    /// The current transport backend requires exactly one
    /// [`Http2Setting::InitialWindowSize`] value.
    pub initial_settings: Vec<Http2Setting>,
    /// Target connection receive window after the initial WINDOW_UPDATE.
    ///
    /// HTTP/2 connections begin with 65,535 bytes, so this value must be in
    /// 65,535..=2,147,483,647. A larger target emits an initial WINDOW_UPDATE
    /// containing the difference.
    pub initial_connection_window_size: u32,
    /// Wire order of `:method`, `:authority`, `:scheme`, and `:path`.
    pub pseudo_header_order: Vec<Http2PseudoHeader>,
    /// Wire order of pseudo-headers on an extended CONNECT request.
    ///
    /// When configured, this must contain `:method`, `:authority`, `:scheme`,
    /// `:path`, and `:protocol` exactly once. `None` means that the profile
    /// does not claim an observed extended CONNECT pseudo-header order.
    pub extended_connect_pseudo_header_order: Option<Vec<Http2PseudoHeader>>,
    /// Optional priority fields carried by each request HEADERS frame.
    pub headers_priority: Option<Http2Priority>,
    /// Optional priority fields carried by extended CONNECT HEADERS frames.
    ///
    /// `None` means that extended CONNECT uses [`Self::headers_priority`].
    /// A value applies only to the extended CONNECT request, including one sent
    /// on a pooled connection opened for ordinary requests.
    pub extended_connect_priority: Option<Http2Priority>,
    /// HPACK encoder choices used for every field block on the connection.
    pub hpack: Http2HpackSettings,
    /// Stream numbering, the stream limit assumed before the peer states one,
    /// and the cap on a stated limit.
    pub streams: Http2StreamSettings,
    /// Read-idle time after which a PING follows the next request frame.
    ///
    /// When set, the client writes a PING right after a request's HEADERS, or
    /// after a DATA frame with a non-empty payload, once it has read nothing
    /// from the peer for longer than this; no other frame comes between them.
    /// It sends none while an earlier such PING awaits its ACK. The first PING's payload is the
    /// 64-bit big-endian value 1, and each later one carries the next value.
    /// `None` sends no such PING.
    pub preface_ping_after: Option<Duration>,
    /// How long a PING sent under [`Self::preface_ping_after`] may go
    /// unanswered with nothing read from the peer before the connection
    /// closes.
    ///
    /// The client sleeps for this long after the PING. If it read no frame
    /// meanwhile, the PING has failed; otherwise it sleeps again. The close
    /// therefore comes one to two periods after the last frame read, and
    /// only the ACK stops it. The client does not count the time while its
    /// writes are blocked. When the PING fails, the client sends `GOAWAY`
    /// with last stream ID 0, `PROTOCOL_ERROR`, and the debug data
    /// `Failed ping.`, then closes the connection, and every request still
    /// open on it fails. `None` keeps a connection whose PING is never
    /// answered. A value requires [`Self::preface_ping_after`].
    pub ping_timeout: Option<Duration>,
}

impl Http2Settings {
    /// Validates settings that are independent of a particular HTTP/2 backend.
    pub fn validate(&self) -> Result<(), InvalidHttp2Settings> {
        validate_initial_settings(&self.initial_settings)?;

        if !(INITIAL_CONNECTION_WINDOW_SIZE..=MAX_WINDOW_SIZE)
            .contains(&self.initial_connection_window_size)
        {
            return Err(InvalidHttp2Settings::new(
                "initial_connection_window_size",
                "connection window must be in 65535..=2147483647 bytes",
            ));
        }

        validate_pseudo_header_order(&self.pseudo_header_order)?;
        validate_literal_pseudo_headers(&self.hpack.literal_pseudo_headers)?;
        if let Some(order) = &self.extended_connect_pseudo_header_order {
            validate_extended_connect_pseudo_header_order(order)?;
        }

        validate_streams(self.streams)?;
        validate_ping_timeout(self.preface_ping_after, self.ping_timeout)?;

        if let Some(priority) = self.headers_priority {
            validate_priority(
                priority,
                "headers_priority.dependency_stream_id",
                "headers_priority.weight",
            )?;
        }
        if let Some(priority) = self.extended_connect_priority {
            validate_priority(
                priority,
                "extended_connect_priority.dependency_stream_id",
                "extended_connect_priority.weight",
            )?;
        }

        Ok(())
    }
}

fn validate_streams(streams: Http2StreamSettings) -> Result<(), InvalidHttp2Settings> {
    if streams.first_stream_id.is_multiple_of(2) || streams.first_stream_id > MAX_STREAM_ID {
        return Err(InvalidHttp2Settings::new(
            "streams.first_stream_id",
            "a client stream ID must be odd and use 31 bits",
        ));
    }
    if streams.assumed_max_concurrent_streams == Some(0) {
        return Err(InvalidHttp2Settings::new(
            "streams.assumed_max_concurrent_streams",
            "an assumed stream limit must be at least 1",
        ));
    }
    if streams.max_concurrent_streams_cap == Some(0) {
        return Err(InvalidHttp2Settings::new(
            "streams.max_concurrent_streams_cap",
            "a stream limit cap must be at least 1",
        ));
    }
    Ok(())
}

fn validate_ping_timeout(
    preface_ping_after: Option<Duration>,
    ping_timeout: Option<Duration>,
) -> Result<(), InvalidHttp2Settings> {
    let Some(timeout) = ping_timeout else {
        return Ok(());
    };
    if preface_ping_after.is_none() {
        return Err(InvalidHttp2Settings::new(
            "ping_timeout",
            "a PING timeout applies only to a preface PING; set preface_ping_after",
        ));
    }
    if timeout.is_zero() {
        return Err(InvalidHttp2Settings::new(
            "ping_timeout",
            "a PING timeout must be positive; None sets no limit",
        ));
    }
    if Instant::now().checked_add(timeout).is_none() {
        return Err(InvalidHttp2Settings::new(
            "ping_timeout",
            "the PING timeout exceeds the clock range",
        ));
    }
    Ok(())
}

fn validate_priority(
    priority: Http2Priority,
    dependency_field: &'static str,
    weight_field: &'static str,
) -> Result<(), InvalidHttp2Settings> {
    if priority.dependency_stream_id > MAX_STREAM_ID {
        return Err(InvalidHttp2Settings::new(
            dependency_field,
            "stream IDs use 31 bits",
        ));
    }
    if !(1..=256).contains(&priority.weight) {
        return Err(InvalidHttp2Settings::new(
            weight_field,
            "priority weight must be in 1..=256",
        ));
    }
    Ok(())
}

/// Error returned when HTTP/2 profile settings are internally inconsistent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidHttp2Settings {
    field: &'static str,
    message: Box<str>,
}

impl InvalidHttp2Settings {
    fn new(field: &'static str, message: impl Into<Box<str>>) -> Self {
        Self {
            field,
            message: message.into(),
        }
    }

    /// Returns the invalid setting's field name.
    #[must_use]
    pub fn field(&self) -> &'static str {
        self.field
    }
}

impl fmt::Display for InvalidHttp2Settings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid HTTP/2 {}: {}", self.field, self.message)
    }
}

impl Error for InvalidHttp2Settings {}

fn validate_initial_settings(settings: &[Http2Setting]) -> Result<(), InvalidHttp2Settings> {
    let mut kinds = Vec::with_capacity(settings.len());
    let mut has_initial_window_size = false;

    for setting in settings {
        let kind = setting.kind();
        if kinds.contains(&kind) {
            return Err(InvalidHttp2Settings::new(
                "initial_settings",
                format!("{kind:?} must not repeat"),
            ));
        }
        kinds.push(kind);

        match *setting {
            Http2Setting::InitialWindowSize(size) => {
                has_initial_window_size = true;
                if size > MAX_WINDOW_SIZE {
                    return Err(InvalidHttp2Settings::new(
                        "initial_settings.initial_window_size",
                        "stream window must not exceed 2147483647 bytes",
                    ));
                }
            }
            Http2Setting::MaxFrameSize(size)
                if !(MIN_FRAME_SIZE..=MAX_FRAME_SIZE).contains(&size) =>
            {
                return Err(InvalidHttp2Settings::new(
                    "initial_settings.max_frame_size",
                    "maximum frame size must be in 16384..=16777215",
                ));
            }
            _ => {}
        }
    }

    if !has_initial_window_size {
        return Err(InvalidHttp2Settings::new(
            "initial_settings",
            "exactly one InitialWindowSize setting is required by the current backend",
        ));
    }

    Ok(())
}

fn validate_pseudo_header_order(order: &[Http2PseudoHeader]) -> Result<(), InvalidHttp2Settings> {
    const REQUIRED_COUNT: usize = 4;
    if order.len() != REQUIRED_COUNT {
        return Err(InvalidHttp2Settings::new(
            "pseudo_header_order",
            "order must contain method, authority, scheme, and path exactly once",
        ));
    }

    let mut present = [false; REQUIRED_COUNT];
    for header in order {
        let index = match header {
            Http2PseudoHeader::Method => 0,
            Http2PseudoHeader::Authority => 1,
            Http2PseudoHeader::Scheme => 2,
            Http2PseudoHeader::Path => 3,
            Http2PseudoHeader::Protocol => {
                return Err(InvalidHttp2Settings::new(
                    "pseudo_header_order",
                    "ordinary requests must not contain protocol",
                ));
            }
        };
        if present[index] {
            return Err(InvalidHttp2Settings::new(
                "pseudo_header_order",
                "order must contain method, authority, scheme, and path exactly once",
            ));
        }
        present[index] = true;
    }

    Ok(())
}

fn validate_literal_pseudo_headers(
    headers: &[Http2PseudoHeader],
) -> Result<(), InvalidHttp2Settings> {
    const FIELD: &str = "hpack.literal_pseudo_headers";
    let mut seen = Vec::with_capacity(headers.len());
    for header in headers {
        if seen.contains(header) {
            return Err(InvalidHttp2Settings::new(
                FIELD,
                "each pseudo-header may be listed once",
            ));
        }
        seen.push(*header);
    }
    Ok(())
}

fn validate_extended_connect_pseudo_header_order(
    order: &[Http2PseudoHeader],
) -> Result<(), InvalidHttp2Settings> {
    const REQUIRED_COUNT: usize = 5;
    const FIELD: &str = "extended_connect_pseudo_header_order";
    if order.len() != REQUIRED_COUNT {
        return Err(InvalidHttp2Settings::new(
            FIELD,
            "order must contain method, authority, scheme, path, and protocol exactly once",
        ));
    }

    let mut present = [false; REQUIRED_COUNT];
    for header in order {
        let index = match header {
            Http2PseudoHeader::Method => 0,
            Http2PseudoHeader::Authority => 1,
            Http2PseudoHeader::Scheme => 2,
            Http2PseudoHeader::Path => 3,
            Http2PseudoHeader::Protocol => 4,
        };
        if present[index] {
            return Err(InvalidHttp2Settings::new(
                FIELD,
                "order must contain method, authority, scheme, path, and protocol exactly once",
            ));
        }
        present[index] = true;
    }

    Ok(())
}

#[cfg(test)]
pub(crate) mod session_capture;
#[cfg(test)]
mod tests;
