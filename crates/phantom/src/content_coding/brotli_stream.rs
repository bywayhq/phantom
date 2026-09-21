//! `br` content coding: exactly one RFC 7932 stream.

use brotli::{BrotliDecompressStream, BrotliResult, BrotliState, HeapAlloc, HuffmanCode};

use super::{StageError, Step, inflate::trailing_input};

type State = BrotliState<HeapAlloc<u8>, HeapAlloc<u32>, HeapAlloc<HuffmanCode>>;

pub(super) struct BrotliDecoder {
    state: Option<Box<State>>,
    seen_input: bool,
}

impl BrotliDecoder {
    pub(super) fn new() -> Self {
        // `new_strict` rejects the non-RFC large-window extension, bounding the
        // window at the RFC 7932 maximum of 16 MiB.
        let state = State::new_strict(
            HeapAlloc::new(0),
            HeapAlloc::new(0),
            HeapAlloc::new(HuffmanCode { bits: 2, value: 1 }),
        );
        Self {
            state: Some(Box::new(state)),
            seen_input: false,
        }
    }

    pub(super) fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Step, StageError> {
        let Some(state) = self.state.as_mut() else {
            return trailing_input(input.len())
                .map_err(|_| StageError::new("brotli response has bytes after its stream"));
        };
        self.seen_input |= !input.is_empty();
        let mut available_in = input.len();
        let mut input_offset = 0;
        let mut available_out = output.len();
        let mut output_offset = 0;
        let mut total_out = 0;
        let result = BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            input,
            &mut available_out,
            &mut output_offset,
            output,
            &mut total_out,
            state,
        );
        if input_offset > input.len() || output_offset > output.len() {
            return Err(StageError::new(
                "brotli engine reported an impossible step length",
            ));
        }
        match result {
            BrotliResult::ResultSuccess => {
                if input_offset < input.len() {
                    return Err(StageError::new(
                        "brotli response has bytes after its stream",
                    ));
                }
                self.state = None;
            }
            BrotliResult::NeedsMoreInput | BrotliResult::NeedsMoreOutput => {}
            BrotliResult::ResultFailure => {
                return Err(StageError::new("brotli stream is malformed"));
            }
        }
        Ok(Step::new(input_offset, output_offset))
    }

    pub(super) const fn is_complete(&self) -> bool {
        self.state.is_none() || !self.seen_input
    }
}
