//! `deflate` content coding: a zlib stream (RFC 1950) or, when the first two
//! bytes are not a zlib header, a raw DEFLATE stream (RFC 1951).

use flate2::{Decompress, FlushDecompress, Status};

use super::{StageError, Step};

pub(super) struct DeflateDecoder {
    state: DeflateState,
}

enum DeflateState {
    Header {
        bytes: [u8; 2],
        length: usize,
    },
    Body {
        decompress: Box<Decompress>,
        header: [u8; 2],
        header_fed: usize,
    },
    Done,
}

impl DeflateDecoder {
    pub(super) const fn new() -> Self {
        Self {
            state: DeflateState::Header {
                bytes: [0; 2],
                length: 0,
            },
        }
    }

    pub(super) fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Step, StageError> {
        let mut consumed = 0;
        if let DeflateState::Header { bytes, length } = &mut self.state {
            let taken = input.len().min(bytes.len() - *length);
            bytes[*length..*length + taken].copy_from_slice(&input[..taken]);
            *length += taken;
            consumed += taken;
            if *length < bytes.len() {
                return Ok(Step::new(consumed, 0));
            }
            let header = *bytes;
            let zlib = is_zlib_header(header);
            if zlib && header[1] & 0x20 != 0 {
                return Err(StageError::new(
                    "deflate response requires an unsupported preset dictionary",
                ));
            }
            self.state = DeflateState::Body {
                decompress: Box::new(Decompress::new(zlib)),
                header,
                header_fed: 0,
            };
        }

        let DeflateState::Body {
            decompress,
            header,
            header_fed,
        } = &mut self.state
        else {
            return trailing_input(input.len() - consumed);
        };

        let mut produced = 0;
        let mut finished = false;
        if *header_fed < header.len() {
            let (header_consumed, header_produced, end) =
                inflate(decompress, &header[*header_fed..], output)?;
            *header_fed += header_consumed;
            produced += header_produced;
            finished = end;
        }
        if !finished && *header_fed == header.len() && produced < output.len() {
            let (body_consumed, body_produced, end) =
                inflate(decompress, &input[consumed..], &mut output[produced..])?;
            consumed += body_consumed;
            produced += body_produced;
            finished = end;
        }
        if finished {
            if *header_fed < header.len() || consumed < input.len() {
                return Err(StageError::new(
                    "deflate response has bytes after its stream",
                ));
            }
            self.state = DeflateState::Done;
        }
        Ok(Step::new(consumed, produced))
    }

    pub(super) const fn is_complete(&self) -> bool {
        matches!(
            self.state,
            DeflateState::Done | DeflateState::Header { length: 0, .. }
        )
    }
}

/// RFC 1950 §2.2: CM = 8, CINFO <= 7, and `CMF * 256 + FLG` is a multiple of 31.
pub(super) fn is_zlib_header([cmf, flg]: [u8; 2]) -> bool {
    cmf & 0x0f == 8 && cmf >> 4 <= 7 && (u16::from(cmf) << 8 | u16::from(flg)) % 31 == 0
}

/// Runs one bounded inflate step and returns `(consumed, produced, stream_end)`.
pub(super) fn inflate(
    decompress: &mut Decompress,
    input: &[u8],
    output: &mut [u8],
) -> Result<(usize, usize, bool), StageError> {
    let input_before = decompress.total_in();
    let output_before = decompress.total_out();
    let status = decompress
        .decompress(input, output, FlushDecompress::None)
        .map_err(|error| StageError::with_source("deflate stream is malformed", error))?;
    let consumed = step_length(decompress.total_in() - input_before, input.len())?;
    let produced = step_length(decompress.total_out() - output_before, output.len())?;
    Ok((consumed, produced, status == Status::StreamEnd))
}

fn step_length(delta: u64, bound: usize) -> Result<usize, StageError> {
    usize::try_from(delta)
        .ok()
        .filter(|length| *length <= bound)
        .ok_or_else(|| StageError::new("deflate engine reported an impossible step length"))
}

pub(super) fn trailing_input(remaining: usize) -> Result<Step, StageError> {
    if remaining == 0 {
        Ok(Step::new(0, 0))
    } else {
        Err(StageError::new(
            "response has bytes after its content-coded stream",
        ))
    }
}
