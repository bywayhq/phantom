//! `gzip` content coding: exactly one RFC 1952 member.

use flate2::{Crc, Decompress};

use super::{StageError, Step, inflate::inflate, inflate::trailing_input};

const FIXED_HEADER_BYTES: usize = 10;
const FOOTER_BYTES: usize = 8;
const FLAG_HEADER_CRC: u8 = 0x02;
const FLAG_EXTRA: u8 = 0x04;
const FLAG_NAME: u8 = 0x08;
const FLAG_COMMENT: u8 = 0x10;
const RESERVED_FLAGS: u8 = 0xe0;

pub(super) struct GzipDecoder {
    state: GzipState,
    flags: u8,
    header_crc: Crc,
    body_crc: Crc,
    seen_input: bool,
}

enum GzipState {
    Fixed {
        bytes: [u8; FIXED_HEADER_BYTES],
        length: usize,
    },
    ExtraLength {
        bytes: [u8; 2],
        length: usize,
    },
    Extra {
        remaining: u16,
    },
    Name,
    Comment,
    HeaderCrc {
        bytes: [u8; 2],
        length: usize,
    },
    Body(Box<Decompress>),
    Footer {
        bytes: [u8; FOOTER_BYTES],
        length: usize,
    },
    Done,
}

impl GzipDecoder {
    pub(super) fn new() -> Self {
        Self {
            state: GzipState::Fixed {
                bytes: [0; FIXED_HEADER_BYTES],
                length: 0,
            },
            flags: 0,
            header_crc: Crc::new(),
            body_crc: Crc::new(),
            seen_input: false,
        }
    }

    pub(super) fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Step, StageError> {
        self.seen_input |= !input.is_empty();
        let mut consumed = 0;
        let mut produced = 0;
        loop {
            match &mut self.state {
                GzipState::Body(decompress) => {
                    if produced == output.len() {
                        return Ok(Step::new(consumed, produced));
                    }
                    let (body_consumed, body_produced, end) =
                        inflate(decompress, &input[consumed..], &mut output[produced..])?;
                    self.body_crc
                        .update(&output[produced..produced + body_produced]);
                    consumed += body_consumed;
                    produced += body_produced;
                    if !end {
                        return Ok(Step::new(consumed, produced));
                    }
                    self.state = GzipState::Footer {
                        bytes: [0; FOOTER_BYTES],
                        length: 0,
                    };
                }
                GzipState::Done => {
                    trailing_input(input.len() - consumed).map_err(|_| {
                        StageError::new("gzip response has bytes after its first member")
                    })?;
                    return Ok(Step::new(consumed, produced));
                }
                _ => {
                    let Some(&byte) = input.get(consumed) else {
                        return Ok(Step::new(consumed, produced));
                    };
                    consumed += 1;
                    self.header_byte(byte)?;
                }
            }
        }
    }

    pub(super) const fn is_complete(&self) -> bool {
        matches!(self.state, GzipState::Done) || !self.seen_input
    }

    /// Advances every non-body state by one byte.
    fn header_byte(&mut self, byte: u8) -> Result<(), StageError> {
        if !matches!(
            self.state,
            GzipState::HeaderCrc { .. } | GzipState::Footer { .. }
        ) {
            self.header_crc.update(&[byte]);
        }
        match &mut self.state {
            GzipState::Fixed { bytes, length } => {
                bytes[*length] = byte;
                *length += 1;
                if *length == FIXED_HEADER_BYTES {
                    let [id1, id2, method, flags, ..] = *bytes;
                    if id1 != 0x1f || id2 != 0x8b {
                        return Err(StageError::new("gzip response has an invalid magic number"));
                    }
                    if method != 8 {
                        return Err(StageError::new("gzip response uses an unknown method"));
                    }
                    if flags & RESERVED_FLAGS != 0 {
                        return Err(StageError::new("gzip response sets reserved flags"));
                    }
                    self.flags = flags;
                    self.state = GzipState::ExtraLength {
                        bytes: [0; 2],
                        length: 0,
                    };
                    self.skip_absent_optional_fields();
                }
            }
            GzipState::ExtraLength { bytes, length } => {
                bytes[*length] = byte;
                *length += 1;
                if *length == 2 {
                    let remaining = u16::from_le_bytes(*bytes);
                    self.state = GzipState::Extra { remaining };
                    self.skip_absent_optional_fields();
                }
            }
            GzipState::Extra { remaining } => {
                *remaining -= 1;
                self.skip_absent_optional_fields();
            }
            GzipState::Name => {
                if byte == 0 {
                    self.state = GzipState::Comment;
                    self.skip_absent_optional_fields();
                }
            }
            GzipState::Comment => {
                if byte == 0 {
                    self.state = GzipState::HeaderCrc {
                        bytes: [0; 2],
                        length: 0,
                    };
                    self.skip_absent_optional_fields();
                }
            }
            GzipState::HeaderCrc { bytes, length } => {
                bytes[*length] = byte;
                *length += 1;
                if *length == 2 {
                    // RFC 1952 §2.3.1: CRC16 is the low 16 bits of the header CRC32.
                    let expected = u16::from_le_bytes(*bytes);
                    if u32::from(expected) != self.header_crc.sum() & 0xffff {
                        return Err(StageError::new("gzip response has a header CRC mismatch"));
                    }
                    self.state = GzipState::Body(Box::new(Decompress::new(false)));
                }
            }
            GzipState::Footer { bytes, length } => {
                bytes[*length] = byte;
                *length += 1;
                if *length == FOOTER_BYTES {
                    let [c0, c1, c2, c3, s0, s1, s2, s3] = *bytes;
                    if u32::from_le_bytes([c0, c1, c2, c3]) != self.body_crc.sum() {
                        return Err(StageError::new("gzip response has a CRC32 mismatch"));
                    }
                    if u32::from_le_bytes([s0, s1, s2, s3]) != self.body_crc.amount() {
                        return Err(StageError::new("gzip response has an ISIZE mismatch"));
                    }
                    self.state = GzipState::Done;
                }
            }
            GzipState::Body(_) | GzipState::Done => {}
        }
        Ok(())
    }

    /// Moves past optional header fields whose flag is clear or whose content is empty.
    fn skip_absent_optional_fields(&mut self) {
        loop {
            self.state = match &self.state {
                GzipState::ExtraLength { length: 0, .. } if self.flags & FLAG_EXTRA == 0 => {
                    GzipState::Name
                }
                GzipState::Extra { remaining: 0 } => GzipState::Name,
                GzipState::Name if self.flags & FLAG_NAME == 0 => GzipState::Comment,
                GzipState::Comment if self.flags & FLAG_COMMENT == 0 => GzipState::HeaderCrc {
                    bytes: [0; 2],
                    length: 0,
                },
                GzipState::HeaderCrc { length: 0, .. } if self.flags & FLAG_HEADER_CRC == 0 => {
                    GzipState::Body(Box::new(Decompress::new(false)))
                }
                _ => return,
            };
        }
    }
}
