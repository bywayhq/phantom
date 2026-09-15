//! HTTP/2 frame and SETTINGS decoding.

use std::{error::Error, fmt};

pub(super) const FRAME_HEADER_LENGTH: usize = 9;
pub(super) const SETTINGS_FRAME_TYPE: u8 = 0x04;
pub(super) const WINDOW_UPDATE_FRAME_TYPE: u8 = 0x08;
const SETTINGS_ACK_FLAG: u8 = 0x01;
const SETTING_LENGTH: usize = 6;
const SETTINGS_ENABLE_PUSH: u16 = 0x02;
const SETTINGS_INITIAL_WINDOW_SIZE: u16 = 0x04;
const SETTINGS_MAX_FRAME_SIZE: u16 = 0x05;
const MAX_FLOW_CONTROL_WINDOW: u32 = 0x7fff_ffff;
const MIN_MAX_FRAME_SIZE: u32 = 16_384;
const MAX_MAX_FRAME_SIZE: u32 = 0x00ff_ffff;
const WINDOW_UPDATE_PAYLOAD_LENGTH: usize = 4;

/// The decoded nine-byte HTTP/2 frame header.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    wire: [u8; FRAME_HEADER_LENGTH],
    payload_length: usize,
    frame_type: u8,
    flags: u8,
    reserved: bool,
    stream_id: u32,
}

impl FrameHeader {
    pub(super) fn decode(wire: [u8; FRAME_HEADER_LENGTH]) -> Self {
        let payload_length =
            (usize::from(wire[0]) << 16) | (usize::from(wire[1]) << 8) | usize::from(wire[2]);
        let raw_stream_id = u32::from_be_bytes([wire[5], wire[6], wire[7], wire[8]]);

        Self {
            wire,
            payload_length,
            frame_type: wire[3],
            flags: wire[4],
            reserved: raw_stream_id & (1 << 31) != 0,
            stream_id: raw_stream_id & 0x7fff_ffff,
        }
    }

    /// Returns the exact nine-byte frame header.
    #[must_use]
    pub fn wire_bytes(&self) -> &[u8; FRAME_HEADER_LENGTH] {
        &self.wire
    }

    /// Returns the 24-bit payload length.
    #[must_use]
    pub const fn payload_length(&self) -> usize {
        self.payload_length
    }

    /// Returns the frame type without interpreting unknown values.
    #[must_use]
    pub const fn frame_type(&self) -> u8 {
        self.frame_type
    }

    /// Returns the exact frame flags.
    #[must_use]
    pub const fn flags(&self) -> u8 {
        self.flags
    }

    /// Reports whether the reserved stream-identifier bit was set on the wire.
    #[must_use]
    pub const fn reserved_bit(&self) -> bool {
        self.reserved
    }

    /// Returns the normalized 31-bit stream identifier.
    #[must_use]
    pub const fn stream_id(&self) -> u32 {
        self.stream_id
    }
}

/// One HTTP/2 frame exactly as received from the input.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapturedFrame {
    pub(super) header: FrameHeader,
    pub(super) wire: Vec<u8>,
}

impl CapturedFrame {
    /// Returns the decoded frame header.
    #[must_use]
    pub const fn header(&self) -> &FrameHeader {
        &self.header
    }

    /// Returns the exact frame header and payload.
    #[must_use]
    pub fn wire_bytes(&self) -> &[u8] {
        &self.wire
    }

    /// Returns the exact frame payload.
    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.wire[FRAME_HEADER_LENGTH..]
    }

    /// Decodes this frame as SETTINGS, or returns `Ok(None)` for another type.
    ///
    /// Entries retain their wire order. HTTP/2 permits an identifier to occur
    /// more than once; the last value is effective, so duplicates are retained.
    pub fn settings(&self) -> Result<Option<SettingsFrame>, SettingsDecodeError> {
        if self.header.frame_type != SETTINGS_FRAME_TYPE {
            return Ok(None);
        }

        if self.header.stream_id != 0 {
            return Err(SettingsDecodeError::NonZeroStream {
                stream_id: self.header.stream_id,
            });
        }

        let ack = self.header.flags & SETTINGS_ACK_FLAG != 0;
        let payload = self.payload();
        if ack && !payload.is_empty() {
            return Err(SettingsDecodeError::AckWithPayload {
                length: payload.len(),
            });
        }
        if payload.len() % SETTING_LENGTH != 0 {
            return Err(SettingsDecodeError::InvalidPayloadLength {
                length: payload.len(),
            });
        }

        let entries = payload
            .chunks_exact(SETTING_LENGTH)
            .map(|entry| Setting {
                identifier: u16::from_be_bytes([entry[0], entry[1]]),
                value: u32::from_be_bytes([entry[2], entry[3], entry[4], entry[5]]),
            })
            .collect::<Vec<_>>();
        for entry in &entries {
            validate_setting(*entry)?;
        }

        Ok(Some(SettingsFrame { ack, entries }))
    }

    /// Decodes this frame as WINDOW_UPDATE, or returns `Ok(None)` for another type.
    pub fn window_update(&self) -> Result<Option<WindowUpdateFrame>, WindowUpdateDecodeError> {
        if self.header.frame_type != WINDOW_UPDATE_FRAME_TYPE {
            return Ok(None);
        }
        let payload = self.payload();
        if payload.len() != WINDOW_UPDATE_PAYLOAD_LENGTH {
            return Err(WindowUpdateDecodeError::InvalidPayloadLength {
                length: payload.len(),
            });
        }

        let raw_increment = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
        let increment = raw_increment & MAX_FLOW_CONTROL_WINDOW;
        if increment == 0 {
            return Err(WindowUpdateDecodeError::ZeroIncrement);
        }

        Ok(Some(WindowUpdateFrame {
            reserved: raw_increment & (1 << 31) != 0,
            increment,
        }))
    }
}

fn validate_setting(setting: Setting) -> Result<(), SettingsDecodeError> {
    match setting.identifier {
        SETTINGS_ENABLE_PUSH if setting.value > 1 => Err(SettingsDecodeError::InvalidEnablePush {
            value: setting.value,
        }),
        SETTINGS_INITIAL_WINDOW_SIZE if setting.value > MAX_FLOW_CONTROL_WINDOW => {
            Err(SettingsDecodeError::InitialWindowSizeTooLarge {
                value: setting.value,
                maximum: MAX_FLOW_CONTROL_WINDOW,
            })
        }
        SETTINGS_MAX_FRAME_SIZE
            if !(MIN_MAX_FRAME_SIZE..=MAX_MAX_FRAME_SIZE).contains(&setting.value) =>
        {
            Err(SettingsDecodeError::InvalidMaxFrameSize {
                value: setting.value,
                minimum: MIN_MAX_FRAME_SIZE,
                maximum: MAX_MAX_FRAME_SIZE,
            })
        }
        _ => Ok(()),
    }
}

/// One SETTINGS parameter, including unknown identifiers and values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Setting {
    identifier: u16,
    value: u32,
}

impl Setting {
    /// Returns the exact 16-bit setting identifier.
    #[must_use]
    pub const fn identifier(&self) -> u16 {
        self.identifier
    }

    /// Returns the exact 32-bit setting value.
    #[must_use]
    pub const fn value(&self) -> u32 {
        self.value
    }
}

/// A semantically decoded HTTP/2 SETTINGS frame.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SettingsFrame {
    ack: bool,
    entries: Vec<Setting>,
}

impl SettingsFrame {
    /// Reports whether this SETTINGS frame acknowledges peer settings.
    #[must_use]
    pub const fn is_acknowledgement(&self) -> bool {
        self.ack
    }

    /// Returns SETTINGS entries in their exact wire order.
    #[must_use]
    pub fn entries(&self) -> &[Setting] {
        &self.entries
    }
}

/// Failure returned while semantically decoding a SETTINGS frame.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SettingsDecodeError {
    /// SETTINGS is a connection-level frame and used a non-zero stream.
    NonZeroStream {
        /// Normalized stream identifier from the frame header.
        stream_id: u32,
    },
    /// An acknowledgement carried a payload, which HTTP/2 forbids.
    AckWithPayload {
        /// Invalid payload length.
        length: usize,
    },
    /// The payload cannot be divided into six-byte SETTINGS entries.
    InvalidPayloadLength {
        /// Invalid payload length.
        length: usize,
    },
    /// SETTINGS_ENABLE_PUSH used a value other than zero or one.
    InvalidEnablePush {
        /// Invalid setting value.
        value: u32,
    },
    /// SETTINGS_INITIAL_WINDOW_SIZE exceeded the maximum flow-control window.
    InitialWindowSizeTooLarge {
        /// Invalid setting value.
        value: u32,
        /// Largest valid setting value.
        maximum: u32,
    },
    /// SETTINGS_MAX_FRAME_SIZE was outside its permitted inclusive range.
    InvalidMaxFrameSize {
        /// Invalid setting value.
        value: u32,
        /// Smallest valid setting value.
        minimum: u32,
        /// Largest valid setting value.
        maximum: u32,
    },
}

impl fmt::Display for SettingsDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NonZeroStream { stream_id } => {
                write!(
                    formatter,
                    "SETTINGS frame used stream {stream_id}, not stream 0"
                )
            }
            Self::AckWithPayload { length } => write!(
                formatter,
                "SETTINGS acknowledgement has a {length}-byte payload, not an empty payload"
            ),
            Self::InvalidPayloadLength { length } => write!(
                formatter,
                "SETTINGS payload is {length} bytes, not a multiple of 6"
            ),
            Self::InvalidEnablePush { value } => write!(
                formatter,
                "SETTINGS_ENABLE_PUSH value is {value}, not 0 or 1"
            ),
            Self::InitialWindowSizeTooLarge { value, maximum } => write!(
                formatter,
                "SETTINGS_INITIAL_WINDOW_SIZE value is {value}; maximum is {maximum}"
            ),
            Self::InvalidMaxFrameSize {
                value,
                minimum,
                maximum,
            } => write!(
                formatter,
                "SETTINGS_MAX_FRAME_SIZE value is {value}; valid range is {minimum}..={maximum}"
            ),
        }
    }
}

impl Error for SettingsDecodeError {}

/// A semantically decoded HTTP/2 WINDOW_UPDATE frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WindowUpdateFrame {
    reserved: bool,
    increment: u32,
}

impl WindowUpdateFrame {
    /// Reports whether the reserved payload bit was set on the wire.
    #[must_use]
    pub const fn reserved_bit(&self) -> bool {
        self.reserved
    }

    /// Returns the normalized 31-bit flow-control window increment.
    #[must_use]
    pub const fn increment(&self) -> u32 {
        self.increment
    }
}

/// Failure returned while semantically decoding a WINDOW_UPDATE frame.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum WindowUpdateDecodeError {
    /// A WINDOW_UPDATE payload was not exactly four bytes.
    InvalidPayloadLength {
        /// Invalid payload length.
        length: usize,
    },
    /// The normalized 31-bit window increment was zero.
    ZeroIncrement,
}

impl fmt::Display for WindowUpdateDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPayloadLength { length } => write!(
                formatter,
                "WINDOW_UPDATE payload is {length} bytes, not 4 bytes"
            ),
            Self::ZeroIncrement => {
                formatter.write_str("WINDOW_UPDATE flow-control increment is zero")
            }
        }
    }
}

impl Error for WindowUpdateDecodeError {}
