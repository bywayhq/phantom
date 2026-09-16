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

/// Ordered HTTP/3 request construction independent of the concrete backend.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Http3RequestSettings {
    /// Wire order of `:method`, `:authority`, `:scheme`, and `:path`.
    pub pseudo_header_order: Vec<Http3PseudoHeader>,
}

impl Http3RequestSettings {
    /// Validates the request profile independently of a concrete backend.
    pub fn validate(&self) -> Result<(), InvalidHttp3RequestSettings> {
        validate_pseudo_header_order(&self.pseudo_header_order)
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
