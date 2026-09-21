//! Backend-neutral HTTP/2 profile settings.

use std::{error::Error, fmt};

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
        if let Some(order) = &self.extended_connect_pseudo_header_order {
            validate_extended_connect_pseudo_header_order(order)?;
        }

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
