//! Backend-neutral HTTP/3 settings and wire ordering.

use std::{error::Error, fmt};

const MAX_VARINT: u64 = (1 << 62) - 1;
const MAX_QPACK_TABLE_CAPACITY: u64 = (1 << 30) - 1;

/// One entry in the initial HTTP/3 SETTINGS frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http3Setting {
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (`0x01`).
    QpackMaxTableCapacity(u64),
    /// SETTINGS_MAX_FIELD_SECTION_SIZE (`0x06`).
    MaxFieldSectionSize(u64),
    /// SETTINGS_QPACK_BLOCKED_STREAMS (`0x07`).
    QpackBlockedStreams(u64),
    /// SETTINGS_H3_DATAGRAM (`0x33`).
    H3Datagram(bool),
    /// One reserved setting generated from two independent random `u32` values.
    ///
    /// The identifier is `31 * N + 33`; the second value is sent directly.
    RandomizedGrease,
}

impl Http3Setting {
    fn kind(self) -> SettingKind {
        match self {
            Self::QpackMaxTableCapacity(_) => SettingKind::QpackMaxTableCapacity,
            Self::MaxFieldSectionSize(_) => SettingKind::MaxFieldSectionSize,
            Self::QpackBlockedStreams(_) => SettingKind::QpackBlockedStreams,
            Self::H3Datagram(_) => SettingKind::H3Datagram,
            Self::RandomizedGrease => SettingKind::RandomizedGrease,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SettingKind {
    QpackMaxTableCapacity,
    MaxFieldSectionSize,
    QpackBlockedStreams,
    H3Datagram,
    RandomizedGrease,
}

/// Ordering policy for the initial HTTP/3 SETTINGS frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http3SettingOrder {
    /// Preserve [`Http3Settings::initial_settings`] order.
    Fixed,
    /// Sort materialized settings by their numeric identifier.
    Ascending,
}

/// Outbound QPACK policy for request field sections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http3QpackEncoding {
    /// Encode requests without using the peer's dynamic table.
    Stateless,
    /// Wait for peer SETTINGS and use the connection-owned dynamic table.
    Dynamic,
}

/// Stream-type emission policy for the local QPACK decoder stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http3QpackDecoderStream {
    /// Write the decoder stream type when the HTTP/3 connection starts.
    Eager,
    /// Reserve the stream but write its type only when feedback is available.
    OnFeedback,
}

/// Opening order of the local QPACK encoder and decoder streams.
///
/// Both streams are opened after the control stream, so on QUIC the control
/// stream is client stream 2 and the QPACK streams are 6 and 10 in this order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http3QpackStreamOrder {
    /// Open the encoder stream (6) before the decoder stream (10).
    EncoderFirst,
    /// Open the decoder stream (6) before the encoder stream (10).
    DecoderFirst,
}

/// Stream-type emission policy for the local QPACK encoder stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http3QpackEncoderStream {
    /// Write the encoder stream type when the HTTP/3 connection starts.
    Eager,
    /// Reserve the stream but write its type only with the first request
    /// field section that is prepared while encoder instructions are queued.
    ///
    /// The type is then written with every queued instruction, such as the
    /// dynamic table capacity and that field section's own inserts, ahead of
    /// its HEADERS. A connection that sends no request, or never queues an
    /// instruction, never writes to the stream.
    OnFirstInstruction,
}

/// A request pseudo-header in its QPACK field-section order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http3PseudoHeader {
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

/// Ordered HTTP/3 settings independent of the concrete HTTP/3 backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http3Settings {
    /// Initial SETTINGS entries. Position is wire order when order is fixed.
    pub initial_settings: Vec<Http3Setting>,
    /// Ordering applied after per-connection settings are materialized.
    pub setting_order: Http3SettingOrder,
    /// QPACK policy for request field sections sent on this connection.
    pub qpack_encoding: Http3QpackEncoding,
    /// Controls when the local QPACK decoder stream becomes visible on the wire.
    pub qpack_decoder_stream: Http3QpackDecoderStream,
    /// Controls when the local QPACK encoder stream becomes visible on the wire.
    pub qpack_encoder_stream: Http3QpackEncoderStream,
    /// Opening order, and so stream identifiers, of the local QPACK streams.
    pub qpack_stream_order: Http3QpackStreamOrder,
}

impl Http3Settings {
    /// Validates settings independent of a concrete HTTP/3 backend.
    pub fn validate(&self) -> Result<(), InvalidHttp3Settings> {
        let mut kinds = Vec::with_capacity(self.initial_settings.len());

        for setting in &self.initial_settings {
            let kind = setting.kind();
            if kinds.contains(&kind) {
                return Err(InvalidHttp3Settings::new(
                    "initial_settings",
                    format!("{kind:?} must not repeat"),
                ));
            }
            kinds.push(kind);

            match *setting {
                Http3Setting::QpackMaxTableCapacity(value) if value > MAX_QPACK_TABLE_CAPACITY => {
                    return Err(InvalidHttp3Settings::new(
                        "initial_settings.qpack_max_table_capacity",
                        "QPACK table capacity must not exceed 1073741823 bytes",
                    ));
                }
                Http3Setting::MaxFieldSectionSize(value)
                | Http3Setting::QpackBlockedStreams(value)
                    if value > MAX_VARINT =>
                {
                    return Err(InvalidHttp3Settings::new(
                        "initial_settings",
                        "setting values must be smaller than 2^62",
                    ));
                }
                _ => {}
            }
        }

        Ok(())
    }

    /// Returns whether this profile advertises HTTP Datagram receive support.
    #[must_use]
    pub fn receives_datagrams(&self) -> bool {
        self.initial_settings
            .iter()
            .any(|setting| matches!(setting, Http3Setting::H3Datagram(true)))
    }
}

/// How each `cookie` request field is split before QPACK encoding.
///
/// RFC 9114 section 4.2.1 lets a client split `cookie` into one field per
/// cookie, called crumbs, so that each can be indexed on its own. The rule
/// applies to every `cookie` field, whether the cookie jar or the caller
/// supplied it.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http3CookieCrumbs {
    /// Send each `cookie` field whole, encoded like any other field.
    #[default]
    Whole,
    /// Split at every `;`, skipping one space after it, and encode each crumb
    /// like any other field (Chromium's `ValueSplittingHeaderList`).
    ///
    /// Under [`Http3QpackEncoding::Dynamic`] each crumb enters the dynamic
    /// table. Crumbs are never sent as never-indexed literals: marking the
    /// `cookie` field with `RequestHeader::sensitive` then only hides its
    /// value from `Debug` output.
    Split,
}

/// Ordered HTTP/3 request construction independent of the concrete backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http3RequestSettings {
    /// Wire order of `:method`, `:authority`, `:scheme`, and `:path`.
    pub pseudo_header_order: Vec<Http3PseudoHeader>,
    /// Wire order of pseudo-headers on an extended CONNECT request.
    ///
    /// When configured, this must contain `:method`, `:authority`, `:scheme`,
    /// `:path`, and `:protocol` exactly once. One order applies to every
    /// extended CONNECT protocol. `None` means that the profile does not claim
    /// an observed extended CONNECT pseudo-header order.
    pub extended_connect_pseudo_header_order: Option<Vec<Http3PseudoHeader>>,
    /// How each `cookie` field is split.
    pub cookie_crumbs: Http3CookieCrumbs,
}

impl Http3RequestSettings {
    /// Validates the request profile independently of a concrete backend.
    pub fn validate(&self) -> Result<(), InvalidHttp3RequestSettings> {
        validate_pseudo_header_order(&self.pseudo_header_order)?;
        if let Some(order) = &self.extended_connect_pseudo_header_order {
            validate_extended_connect_pseudo_header_order(order)?;
        }
        Ok(())
    }
}

fn validate_pseudo_header_order(
    order: &[Http3PseudoHeader],
) -> Result<(), InvalidHttp3RequestSettings> {
    const REQUIRED_COUNT: usize = 4;
    if order.len() != REQUIRED_COUNT {
        return Err(InvalidHttp3RequestSettings::new(
            "pseudo_header_order",
            "order must contain method, authority, scheme, and path exactly once",
        ));
    }

    let mut present = [false; REQUIRED_COUNT];
    for header in order {
        let index = match header {
            Http3PseudoHeader::Method => 0,
            Http3PseudoHeader::Authority => 1,
            Http3PseudoHeader::Scheme => 2,
            Http3PseudoHeader::Path => 3,
            Http3PseudoHeader::Protocol => {
                return Err(InvalidHttp3RequestSettings::new(
                    "pseudo_header_order",
                    "ordinary requests must not contain protocol",
                ));
            }
        };
        if present[index] {
            return Err(InvalidHttp3RequestSettings::new(
                "pseudo_header_order",
                "order must contain method, authority, scheme, and path exactly once",
            ));
        }
        present[index] = true;
    }

    Ok(())
}

fn validate_extended_connect_pseudo_header_order(
    order: &[Http3PseudoHeader],
) -> Result<(), InvalidHttp3RequestSettings> {
    const REQUIRED_COUNT: usize = 5;
    const FIELD: &str = "extended_connect_pseudo_header_order";
    const MESSAGE: &str =
        "order must contain method, authority, scheme, path, and protocol exactly once";
    if order.len() != REQUIRED_COUNT {
        return Err(InvalidHttp3RequestSettings::new(FIELD, MESSAGE));
    }

    let mut present = [false; REQUIRED_COUNT];
    for header in order {
        let index = match header {
            Http3PseudoHeader::Method => 0,
            Http3PseudoHeader::Authority => 1,
            Http3PseudoHeader::Scheme => 2,
            Http3PseudoHeader::Path => 3,
            Http3PseudoHeader::Protocol => 4,
        };
        if present[index] {
            return Err(InvalidHttp3RequestSettings::new(FIELD, MESSAGE));
        }
        present[index] = true;
    }

    Ok(())
}

/// Error returned when HTTP/3 request settings are inconsistent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidHttp3RequestSettings {
    field: &'static str,
    message: Box<str>,
}

impl InvalidHttp3RequestSettings {
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

    /// Returns the reason the setting is invalid.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for InvalidHttp3RequestSettings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "invalid HTTP/3 request {}: {}",
            self.field, self.message
        )
    }
}

impl Error for InvalidHttp3RequestSettings {}

/// Error returned when HTTP/3 profile settings are inconsistent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvalidHttp3Settings {
    field: &'static str,
    message: Box<str>,
}

impl InvalidHttp3Settings {
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

    /// Returns the reason the setting is invalid.
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for InvalidHttp3Settings {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid HTTP/3 {}: {}", self.field, self.message)
    }
}

impl Error for InvalidHttp3Settings {}

#[cfg(test)]
mod tests;
