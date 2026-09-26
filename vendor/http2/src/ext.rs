//! Extensions specific to the HTTP/2 protocol.

use crate::frame::{PseudoId, PseudoOrder, StreamDependency};
use crate::hpack::BytesStr;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue};
use std::fmt;

/// Exact wire order for ordinary header fields.
///
/// Store this value in a request's extensions to control its field order.
/// Received requests and responses also carry this value in their extensions
/// with the order produced by HPACK decoding. Pseudo-headers are excluded.
/// Outgoing ordered fields must describe the same semantic multimap as the
/// request's [`HeaderMap`], including duplicate values and their per-name
/// order, or the request is rejected as malformed. Global field-name order is
/// intentionally ignored during that comparison because `HeaderMap` does not
/// preserve it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedHeaders {
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl OrderedHeaders {
    /// Creates an owned ordinary-header order.
    #[must_use]
    pub fn new(headers: Vec<(HeaderName, HeaderValue)>) -> Self {
        Self { headers }
    }

    /// Returns the ordered ordinary fields.
    #[must_use]
    pub fn as_slice(&self) -> &[(HeaderName, HeaderValue)] {
        &self.headers
    }

    pub(crate) fn agrees_with(&self, semantic: &HeaderMap) -> bool {
        let mut reconstructed = HeaderMap::new();
        for (name, value) in &self.headers {
            if reconstructed.try_append(name, value.clone()).is_err() {
                return false;
            }
        }
        reconstructed.eq(semantic)
    }

    pub(crate) fn into_inner(self) -> Vec<(HeaderName, HeaderValue)> {
        self.headers
    }
}

/// Per-request overrides for a client request's initial HEADERS frame.
///
/// Store this value in a request's extensions to replace the connection's
/// configured pseudo-header order or RFC 7540 stream dependency for that one
/// request. An unset value keeps the connection default. A peer that disabled
/// RFC 7540 priorities still suppresses the priority fields.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HeadersFrameOverrides {
    pseudo_order: Option<PseudoOrder>,
    stream_dependency: Option<StreamDependency>,
}

impl HeadersFrameOverrides {
    /// Creates overrides that keep every connection default.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the connection's pseudo-header order for this request.
    #[must_use]
    pub fn pseudo_order(mut self, order: PseudoOrder) -> Self {
        self.pseudo_order = Some(order);
        self
    }

    /// Replaces the connection's HEADERS stream dependency for this request.
    #[must_use]
    pub fn stream_dependency(mut self, dependency: StreamDependency) -> Self {
        self.stream_dependency = Some(dependency);
        self
    }

    pub(crate) fn into_parts(self) -> (Option<PseudoOrder>, Option<StreamDependency>) {
        (self.pseudo_order, self.stream_dependency)
    }
}

/// Which HPACK static entry names a field whose name has several entries.
///
/// The static table lists `:method`, `:path`, and `:scheme` twice, so a field
/// whose value matches neither entry can be named by either index. The choice
/// is visible on the wire and constant for a given encoder.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum StaticNameIndex {
    /// The lowest-numbered entry: `:method` 2, `:path` 4, `:scheme` 6.
    ///
    /// This is the upstream and nghttp2 choice.
    #[default]
    Lowest,
    /// The highest-numbered entry: `:method` 3, `:path` 5, `:scheme` 7.
    Highest,
}

/// When a literal HPACK string is Huffman-coded rather than sent raw.
///
/// RFC 7541 section 5.2 leaves the choice to the encoder, and the flag is
/// visible on the wire for every literal name and value.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HuffmanCoding {
    /// Always Huffman-code, whatever the result costs.
    ///
    /// This is the upstream choice.
    #[default]
    Always,
    /// Huffman-code only when the coded form is strictly shorter.
    WhenShorter,
    /// Huffman-code whenever the coded form is no longer than the raw one.
    WhenNotLonger,
    /// Always Huffman-code, and set the Huffman flag on an empty string too.
    ///
    /// `Always` sends an empty string raw, as the one byte `0x00`; this rule
    /// sends it as `0x80`, a coded string of length zero.
    AlwaysIncludingEmpty,
}

/// Which ordinary fields an HPACK encoder keeps out of the dynamic table.
///
/// A `cookie` field sent whole is always kept out, and `:path` always is, as
/// upstream does; this choice decides the other ordinary fields.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum FieldIndexing {
    /// Keep `age`, `authorization`, `content-length`, `etag`,
    /// `if-modified-since`, `if-none-match`, `location`, and `set-cookie` out
    /// of the table, as literals without indexing unless sensitive.
    ///
    /// This is the upstream choice, borrowed from nghttp2.
    #[default]
    Nghttp2,
    /// Let every ordinary field enter the table.
    All,
    /// Send `authorization` as a never-indexed literal and let every other
    /// ordinary field enter the table.
    NeverIndexAuthorization,
}

/// Which table entry names a literal field whose name is in the table.
///
/// A literal can name its field with any entry that has the same name, in the
/// static or the dynamic table. The index chosen is visible on the wire.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum NameReference {
    /// The static entry when one has the name, otherwise the newest dynamic
    /// entry, except that a sensitive field whose name is in the dynamic
    /// table names the newest such entry, and a field kept out of the table
    /// names only a static entry.
    ///
    /// This is the upstream choice.
    #[default]
    Upstream,
    /// The static entry when one has the name, otherwise the newest dynamic
    /// entry.
    StaticThenNewest,
    /// The oldest dynamic entry when one has the name, otherwise the static
    /// entry: the highest-numbered entry with the name.
    OldestDynamic,
}

/// How a field kept out of the dynamic table is sent when an entry matches
/// both its name and its value.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum UnindexedMatch {
    /// As that entry's index, so `:path: /` is sent as index 4.
    ///
    /// This is the upstream choice.
    #[default]
    Index,
    /// As a literal naming that entry, so `:path: /` is sent as a literal
    /// without indexing naming entry 4.
    Literal,
}

/// The largest field an HPACK encoder inserts into the dynamic table.
///
/// The size is the RFC 7541 section 4.1 entry size, name plus value plus 32
/// bytes, compared with the current maximum table size.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum IndexingLimit {
    /// A field larger than three quarters of the table is a literal without
    /// indexing.
    ///
    /// This is the upstream choice.
    #[default]
    ThreeQuarters,
    /// A field larger than half the table, or any field when the table is
    /// smaller than 128 bytes, is a literal without indexing.
    Half,
    /// Every field that may enter the table is sent with incremental
    /// indexing. One larger than the whole table empties it and is not
    /// inserted, as RFC 7541 section 4.4 requires.
    Unlimited,
}

/// When an HPACK encoder starts a field block with a dynamic-table size
/// update after the peer sends `SETTINGS_HEADER_TABLE_SIZE`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum SizeUpdates {
    /// Only when the setting changes the table size.
    ///
    /// This is the upstream choice.
    #[default]
    WhenChanged,
    /// After every received setting, even one equal to the current size.
    ///
    /// When the peer sent a smaller value before the last one, the smallest
    /// is announced first.
    EverySetting,
}

/// How an HPACK encoder sends each `cookie` field.
///
/// RFC 9113 section 8.2.3 lets a client split the `cookie` field into one
/// field per cookie, called crumbs, so that each crumb can be indexed on its
/// own. The split and each crumb's representation are visible on the wire.
///
/// When crumbs are sent, this choice alone decides each crumb's
/// representation: a `cookie` value marked sensitive is split and encoded
/// like any other.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum CookieCrumbs {
    /// Send each `cookie` field whole, as a literal that never enters the
    /// dynamic table.
    ///
    /// This is the upstream choice.
    #[default]
    Whole,
    /// Split at every `;` and index every crumb like any other field.
    ///
    /// Spaces and tabs at both ends of the value are removed first, and one
    /// space after each `;` is skipped. This is Chromium's
    /// `HpackEncoder::CookieToCrumbs` with its default indexing policy.
    IndexAll,
    /// Split at every `"; "`, send a crumb shorter than 20 bytes as a
    /// never-indexed literal, and index a longer one like any other field.
    ///
    /// This is Firefox's `Http2Compressor::EncodeHeaderBlock`.
    NeverIndexShort,
}

impl CookieCrumbs {
    /// Returns the crumbs of one `cookie` value in order, each with whether
    /// it must be sent as a never-indexed literal.
    pub(crate) fn split(self, value: &[u8]) -> Vec<(&[u8], bool)> {
        match self {
            CookieCrumbs::Whole => vec![(value, false)],
            CookieCrumbs::IndexAll => {
                let is_space = |byte: &u8| *byte == b' ' || *byte == b'\t';
                let start = value.iter().position(|byte| !is_space(byte));
                let value = match start {
                    None => &value[..0],
                    Some(start) => {
                        let end = value
                            .iter()
                            .rposition(|byte| !is_space(byte))
                            .map_or(start, |end| end + 1);
                        &value[start..end]
                    }
                };
                let mut crumbs = Vec::new();
                let mut rest = value;
                loop {
                    match rest.iter().position(|byte| *byte == b';') {
                        None => {
                            crumbs.push((rest, false));
                            return crumbs;
                        }
                        Some(end) => {
                            crumbs.push((&rest[..end], false));
                            rest = &rest[end + 1..];
                            if rest.first() == Some(&b' ') {
                                rest = &rest[1..];
                            }
                        }
                    }
                }
            }
            CookieCrumbs::NeverIndexShort => {
                let mut crumbs = Vec::new();
                let mut rest = value;
                loop {
                    let end = rest.windows(2).position(|pair| pair == b"; ");
                    let crumb = &rest[..end.unwrap_or(rest.len())];
                    crumbs.push((crumb, crumb.len() < 20));
                    match end {
                        None => return crumbs,
                        Some(end) => rest = &rest[end + 2..],
                    }
                }
            }
        }
    }
}

/// Connection-wide HPACK encoder choices that RFC 7541 leaves open.
///
/// Every encoder that RFC 7541 allows produces a block the peer decodes to the
/// same fields, so the choices below are part of a client's wire fingerprint
/// rather than its semantics. Each one defaults to the upstream behavior, so a
/// connection that sets nothing encodes byte-for-byte as before, with one
/// exception under every profile: a sensitive field that matches a table
/// entry is a never-indexed literal naming that entry, where upstream sent
/// the entry's index.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HpackEncoderProfile {
    literal_pseudo_headers: u8,
    static_name_index: StaticNameIndex,
    huffman_coding: HuffmanCoding,
    cookie_crumbs: CookieCrumbs,
    field_indexing: FieldIndexing,
    name_reference: NameReference,
    unindexed_match: UnindexedMatch,
    indexing_limit: IndexingLimit,
    size_updates: SizeUpdates,
}

impl HpackEncoderProfile {
    /// Creates a profile that keeps every upstream encoder choice.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Never inserts these pseudo-headers into the dynamic table.
    ///
    /// A listed pseudo-header whose name and value both match a static entry
    /// is still sent as that index; otherwise it is sent as a literal without
    /// indexing, naming the static entry when one matches. This is the same
    /// treatment upstream already gives `:path` and fields such as `cookie`.
    #[must_use]
    pub fn literal_pseudo_headers(mut self, ids: impl IntoIterator<Item = PseudoId>) -> Self {
        for id in ids {
            self.literal_pseudo_headers |= pseudo_bit(id);
        }
        self
    }

    /// Names a repeated static entry with this index.
    #[must_use]
    pub fn static_name_index(mut self, index: StaticNameIndex) -> Self {
        self.static_name_index = index;
        self
    }

    /// Huffman-codes literal names and values by this rule.
    #[must_use]
    pub fn huffman_coding(mut self, coding: HuffmanCoding) -> Self {
        self.huffman_coding = coding;
        self
    }

    /// Sends each `cookie` field by this rule.
    #[must_use]
    pub fn cookie_crumbs(mut self, crumbs: CookieCrumbs) -> Self {
        self.cookie_crumbs = crumbs;
        self
    }

    /// Keeps ordinary fields out of the dynamic table by this rule.
    #[must_use]
    pub fn field_indexing(mut self, indexing: FieldIndexing) -> Self {
        self.field_indexing = indexing;
        self
    }

    /// Names literal fields with table entries by this rule.
    #[must_use]
    pub fn name_reference(mut self, reference: NameReference) -> Self {
        self.name_reference = reference;
        self
    }

    /// Sends a field kept out of the table that matches an entry by this rule.
    #[must_use]
    pub fn unindexed_match(mut self, matched: UnindexedMatch) -> Self {
        self.unindexed_match = matched;
        self
    }

    /// Inserts fields into the dynamic table up to this size.
    #[must_use]
    pub fn indexing_limit(mut self, limit: IndexingLimit) -> Self {
        self.indexing_limit = limit;
        self
    }

    /// Announces the peer's table size setting by this rule.
    #[must_use]
    pub fn size_updates(mut self, updates: SizeUpdates) -> Self {
        self.size_updates = updates;
        self
    }

    pub(crate) fn is_literal_pseudo(self, id: PseudoId) -> bool {
        self.literal_pseudo_headers & pseudo_bit(id) != 0
    }

    pub(crate) fn static_name(self) -> StaticNameIndex {
        self.static_name_index
    }

    pub(crate) fn huffman(self) -> HuffmanCoding {
        self.huffman_coding
    }

    pub(crate) fn crumbs(self) -> CookieCrumbs {
        self.cookie_crumbs
    }

    pub(crate) fn fields(self) -> FieldIndexing {
        self.field_indexing
    }

    pub(crate) fn names(self) -> NameReference {
        self.name_reference
    }

    pub(crate) fn matched(self) -> UnindexedMatch {
        self.unindexed_match
    }

    pub(crate) fn limit(self) -> IndexingLimit {
        self.indexing_limit
    }

    pub(crate) fn updates(self) -> SizeUpdates {
        self.size_updates
    }
}

/// Returns the bit that represents `id` in a pseudo-header set.
fn pseudo_bit(id: PseudoId) -> u8 {
    match id {
        PseudoId::Method => 1 << 0,
        PseudoId::Scheme => 1 << 1,
        PseudoId::Authority => 1 << 2,
        PseudoId::Path => 1 << 3,
        PseudoId::Protocol => 1 << 4,
        PseudoId::Status => 1 << 5,
    }
}

/// One ALTSVC frame (RFC 7838 section 4) received by a client.
#[derive(Clone, Eq, PartialEq)]
pub struct AltSvc {
    origin: Option<Bytes>,
    field_value: Bytes,
}

impl AltSvc {
    pub(crate) fn from_frame(frame: crate::frame::AltSvc) -> Self {
        let origin = if frame.stream_id().is_zero() {
            Some(frame.origin().clone())
        } else {
            None
        };
        Self {
            origin,
            field_value: frame.field_value().clone(),
        }
    }

    /// Returns the `Origin` of a connection-scoped frame received on stream 0.
    ///
    /// A frame received on the response's own stream has no origin field;
    /// its origin is the request's origin.
    #[must_use]
    pub fn origin(&self) -> Option<&[u8]> {
        self.origin.as_deref()
    }

    /// Returns the frame's `Alt-Svc-Field-Value`, with `Alt-Svc` field syntax.
    #[must_use]
    pub fn field_value(&self) -> &[u8] {
        &self.field_value
    }
}

impl fmt::Debug for AltSvc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AltSvc")
            .field("connection_scoped", &self.origin.is_some())
            .field("field_value_len", &self.field_value.len())
            .finish()
    }
}

/// ALTSVC frames delivered with one client response, in arrival order.
///
/// A client attaches this value to a final response when the connection
/// received ALTSVC frames on stream 0, or on the response's stream before its
/// final HEADERS. Each queued frame is delivered with exactly one response.
/// Servers ignore ALTSVC frames and never attach this value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AltSvcFrames {
    frames: Vec<AltSvc>,
}

impl AltSvcFrames {
    pub(crate) fn new(frames: Vec<AltSvc>) -> Self {
        Self { frames }
    }

    /// Returns the received frames in arrival order.
    #[must_use]
    pub fn as_slice(&self) -> &[AltSvc] {
        &self.frames
    }
}

/// Represents the `:protocol` pseudo-header used by
/// the [Extended CONNECT Protocol].
///
/// [Extended CONNECT Protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    value: BytesStr,
}

impl Protocol {
    /// Converts a static string to a protocol name.
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            value: BytesStr::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    pub(crate) fn try_from(bytes: Bytes) -> Result<Self, std::str::Utf8Error> {
        Ok(Self {
            value: BytesStr::try_from(bytes)?,
        })
    }
}

impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            value: BytesStr::from(value),
        }
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}
