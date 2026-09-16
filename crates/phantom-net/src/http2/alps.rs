//! Decoding of peer HTTP/2 settings carried by TLS ALPS.

use ::http2::frame::{Error as FrameError, Head, Settings};

const FRAME_HEADER_LEN: usize = 9;
const MAX_FRAME_PAYLOAD_LEN: usize = 16_384;
const SETTINGS_FRAME_TYPE: u8 = 0x4;
const SETTINGS_ACK: u8 = 0x1;

pub(super) enum PeerApplicationSettings {
    Absent,
    Negotiated {
        settings: Box<Settings>,
        frame_count: usize,
        settings_frame_count: usize,
    },
}

impl PeerApplicationSettings {
    pub(super) fn into_initial_settings(self) -> Option<Settings> {
        match self {
            Self::Absent => None,
            Self::Negotiated {
                settings,
                settings_frame_count,
                ..
            } if settings_frame_count != 0 => Some(*settings),
            Self::Negotiated { .. } => None,
        }
    }

    pub(super) fn frame_count(&self) -> Option<usize> {
        match self {
            Self::Absent => None,
            Self::Negotiated { frame_count, .. } => Some(*frame_count),
        }
    }

    #[cfg(test)]
    pub(super) fn settings_frame_count(&self) -> Option<usize> {
        match self {
            Self::Absent => None,
            Self::Negotiated {
                settings_frame_count,
                ..
            } => Some(*settings_frame_count),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DecodeError {
    pub(super) frame_index: usize,
    pub(super) offset: usize,
    kind: DecodeErrorKind,
}

impl DecodeError {
    pub(super) fn reason(self) -> &'static str {
        self.kind.reason()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DecodeErrorKind {
    TotalLength,
    TruncatedHeader,
    FrameSize,
    TruncatedPayload,
    CoreFrameType,
    SettingsStream,
    SettingsAck,
    SettingsLength,
    SettingValue,
    SettingTransition,
}

impl DecodeErrorKind {
    fn reason(self) -> &'static str {
        match self {
            Self::TotalLength => "ALPS value exceeds the TLS application-settings length limit",
            Self::TruncatedHeader => "ALPS ended inside an HTTP/2 frame header",
            Self::FrameSize => "ALPS HTTP/2 frame exceeds the initial frame-size limit",
            Self::TruncatedPayload => "ALPS ended inside an HTTP/2 frame payload",
            Self::CoreFrameType => "ALPS contains a known non-SETTINGS HTTP/2 frame",
            Self::SettingsStream => "ALPS SETTINGS frame has a nonzero stream identifier",
            Self::SettingsAck => "ALPS SETTINGS frame has the ACK flag",
            Self::SettingsLength => "ALPS SETTINGS payload length is not divisible by six",
            Self::SettingValue => "ALPS SETTINGS contains an invalid known value",
            Self::SettingTransition => {
                "ALPS SETTINGS contains a forbidden setting value transition"
            }
        }
    }
}

pub(super) fn decode(encoded: Option<&[u8]>) -> Result<PeerApplicationSettings, DecodeError> {
    let Some(encoded) = encoded else {
        return Ok(PeerApplicationSettings::Absent);
    };
    if encoded.len() > usize::from(u16::MAX) {
        return Err(error(0, 0, DecodeErrorKind::TotalLength));
    }

    let mut settings = Settings::default();
    let mut offset = 0;
    let mut frame_index = 0;
    let mut settings_frame_count = 0;
    while offset < encoded.len() {
        let remaining = encoded.len() - offset;
        if remaining < FRAME_HEADER_LEN {
            return Err(error(frame_index, offset, DecodeErrorKind::TruncatedHeader));
        }

        let payload_len = (usize::from(encoded[offset]) << 16)
            | (usize::from(encoded[offset + 1]) << 8)
            | usize::from(encoded[offset + 2]);
        if payload_len > MAX_FRAME_PAYLOAD_LEN {
            return Err(error(frame_index, offset, DecodeErrorKind::FrameSize));
        }
        let payload_start = offset
            .checked_add(FRAME_HEADER_LEN)
            .ok_or_else(|| error(frame_index, offset, DecodeErrorKind::TruncatedPayload))?;
        let payload_end = payload_start
            .checked_add(payload_len)
            .ok_or_else(|| error(frame_index, offset, DecodeErrorKind::TruncatedPayload))?;
        let payload = encoded
            .get(payload_start..payload_end)
            .ok_or_else(|| error(frame_index, offset, DecodeErrorKind::TruncatedPayload))?;

        let frame_type = encoded[offset + 3];
        if frame_type == SETTINGS_FRAME_TYPE {
            let head = Head::parse(&encoded[offset..payload_start]);
            if !head.stream_id().is_zero() {
                return Err(error(frame_index, offset, DecodeErrorKind::SettingsStream));
            }
            if head.flag() & SETTINGS_ACK != 0 {
                return Err(error(frame_index, offset, DecodeErrorKind::SettingsAck));
            }
            apply_settings(
                head,
                payload,
                &mut settings,
                settings_frame_count == 0,
                frame_index,
                offset,
            )?;
            settings_frame_count += 1;
        } else if frame_type <= 0x9 {
            return Err(error(frame_index, offset, DecodeErrorKind::CoreFrameType));
        }

        offset = payload_end;
        frame_index += 1;
    }

    Ok(PeerApplicationSettings::Negotiated {
        settings: Box::new(settings),
        frame_count: frame_index,
        settings_frame_count,
    })
}

fn apply_settings(
    head: Head,
    payload: &[u8],
    settings: &mut Settings,
    is_initial: bool,
    frame_index: usize,
    offset: usize,
) -> Result<(), DecodeError> {
    let decoded = Settings::load(head, payload).map_err(|parse_error| {
        let kind = match parse_error {
            FrameError::InvalidPayloadAckSettings => DecodeErrorKind::SettingsLength,
            _ => DecodeErrorKind::SettingValue,
        };
        error(frame_index, offset, kind)
    })?;
    validate_transitions(payload, settings, is_initial, frame_index, offset)?;
    merge_settings(settings, &decoded);
    Ok(())
}

fn validate_transitions(
    payload: &[u8],
    settings: &Settings,
    is_initial: bool,
    frame_index: usize,
    offset: usize,
) -> Result<(), DecodeError> {
    let mut enable_connect_protocol = settings
        .is_extended_connect_protocol_enabled()
        .unwrap_or(false);
    let mut no_rfc7540_priorities = settings.is_no_rfc7540_priorities().unwrap_or(false);
    for setting in payload.chunks_exact(6) {
        let id = u16::from_be_bytes([setting[0], setting[1]]);
        let value = u32::from_be_bytes([setting[2], setting[3], setting[4], setting[5]]);
        match id {
            0x2 if value != 0 => {
                return Err(error(frame_index, offset, DecodeErrorKind::SettingValue));
            }
            0x8 => {
                let value = value == 1;
                if enable_connect_protocol && !value {
                    return Err(error(
                        frame_index,
                        offset,
                        DecodeErrorKind::SettingTransition,
                    ));
                }
                enable_connect_protocol = value;
            }
            0x9 => {
                let value = value == 1;
                if !is_initial && value != no_rfc7540_priorities {
                    return Err(error(
                        frame_index,
                        offset,
                        DecodeErrorKind::SettingTransition,
                    ));
                }
                no_rfc7540_priorities = value;
            }
            _ => {}
        }
    }
    Ok(())
}

fn merge_settings(settings: &mut Settings, decoded: &Settings) {
    if let Some(value) = decoded.header_table_size() {
        settings.set_header_table_size(Some(value));
    }
    if let Some(value) = decoded.is_push_enabled() {
        settings.set_enable_push(value);
    }
    if let Some(value) = decoded.max_concurrent_streams() {
        settings.set_max_concurrent_streams(Some(value));
    }
    if let Some(value) = decoded.initial_window_size() {
        settings.set_initial_window_size(Some(value));
    }
    if let Some(value) = decoded.max_frame_size() {
        settings.set_max_frame_size(Some(value));
    }
    if let Some(value) = decoded.max_header_list_size() {
        settings.set_max_header_list_size(Some(value));
    }
    if let Some(value) = decoded.is_extended_connect_protocol_enabled() {
        settings.set_enable_connect_protocol(Some(u32::from(value)));
    }
    if let Some(value) = decoded.is_no_rfc7540_priorities() {
        settings.set_no_rfc7540_priorities(value);
    }
}

fn error(frame_index: usize, offset: usize, kind: DecodeErrorKind) -> DecodeError {
    DecodeError {
        frame_index,
        offset,
        kind,
    }
}

#[cfg(test)]
mod tests;
