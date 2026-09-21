//! `zstd` content coding: RFC 8878 frames with the RFC 9659 window bound.

use zstd::stream::raw::{DParameter, Decoder, Operation};

use super::{StageError, Step};

/// RFC 9659 §3: decoders need not support windows larger than 8 MiB.
const MAXIMUM_WINDOW_LOG: u32 = 23;
const FRAME_MAGIC: u32 = 0xfd2f_b528;
/// RFC 8878 §3.1.2: skippable frame magic numbers are `0x184D2A5?`.
const SKIPPABLE_MAGIC_MASK: u32 = 0xffff_fff0;
const SKIPPABLE_MAGIC: u32 = 0x184d_2a50;

pub(super) struct ZstdDecoder {
    decoder: Decoder<'static>,
    magic: [u8; 4],
    magic_length: usize,
    magic_fed: usize,
    in_frame: bool,
}

impl ZstdDecoder {
    pub(super) fn new() -> Result<Self, StageError> {
        let mut decoder = Decoder::new()
            .map_err(|error| StageError::with_source("zstd decoder is unavailable", error))?;
        decoder
            .set_parameter(DParameter::WindowLogMax(MAXIMUM_WINDOW_LOG))
            .map_err(|error| StageError::with_source("zstd decoder is unavailable", error))?;
        Ok(Self {
            decoder,
            magic: [0; 4],
            magic_length: 0,
            magic_fed: 0,
            in_frame: false,
        })
    }

    pub(super) fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Step, StageError> {
        let mut consumed = 0;
        if !self.in_frame {
            // Each frame's magic number is inspected before libzstd sees it so
            // legacy pre-RFC 8878 frames are rejected rather than decoded.
            let taken = input.len().min(self.magic.len() - self.magic_length);
            self.magic[self.magic_length..self.magic_length + taken]
                .copy_from_slice(&input[..taken]);
            self.magic_length += taken;
            consumed += taken;
            if self.magic_length < self.magic.len() {
                return Ok(Step::new(consumed, 0));
            }
            let magic = u32::from_le_bytes(self.magic);
            if magic != FRAME_MAGIC && magic & SKIPPABLE_MAGIC_MASK != SKIPPABLE_MAGIC {
                return Err(StageError::new(
                    "zstd response contains a frame that is not RFC 8878",
                ));
            }
            self.in_frame = true;
            self.magic_fed = 0;
        }

        let mut produced = 0;
        if self.magic_fed < self.magic.len() {
            let magic = self.magic;
            let (fed, written, frame_end) = self.run(&magic[self.magic_fed..], output)?;
            self.magic_fed += fed;
            produced += written;
            if frame_end {
                return Err(StageError::new("zstd frame ended inside its magic number"));
            }
            if self.magic_fed < self.magic.len() {
                return Ok(Step::new(consumed, produced));
            }
        }
        if produced < output.len() {
            let (fed, written, frame_end) =
                self.run(&input[consumed..], &mut output[produced..])?;
            consumed += fed;
            produced += written;
            if frame_end {
                self.in_frame = false;
                self.magic_length = 0;
            }
        }
        Ok(Step::new(consumed, produced))
    }

    pub(super) const fn is_complete(&self) -> bool {
        !self.in_frame && self.magic_length == 0
    }

    /// Runs one bounded step; libzstd stops at each frame boundary and
    /// reports it with a zero input hint once the frame is fully flushed.
    fn run(&mut self, input: &[u8], output: &mut [u8]) -> Result<(usize, usize, bool), StageError> {
        let status = self
            .decoder
            .run_on_buffers(input, output)
            .map_err(|error| StageError::with_source("zstd stream is malformed", error))?;
        if status.bytes_read > input.len() || status.bytes_written > output.len() {
            return Err(StageError::new(
                "zstd engine reported an impossible step length",
            ));
        }
        Ok((
            status.bytes_read,
            status.bytes_written,
            status.remaining == 0,
        ))
    }
}
