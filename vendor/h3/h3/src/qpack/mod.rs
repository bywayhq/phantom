pub use self::{
    decoder::{decode_stateless, Decoded, DecoderError},
    encoder::{encode_stateless, EncoderError},
    field::HeaderField,
};

pub(crate) use self::{
    decoder::Decoder,
    encoder::Encoder,
    state::{
        DecodeStatus, DecoderState, ReadAheadLease, RequestGuard, RuntimeError, Section,
        MAX_ENCODED_FIELD_SECTION_BYTES,
    },
};

mod block;
mod dynamic;
mod field;
mod parse_error;
mod state;
mod static_;
mod stream;
mod vas;

mod decoder;
mod encoder;

mod prefix_int;
mod prefix_string;

#[cfg(test)]
mod tests;

#[derive(Debug)]
pub enum Error {
    Encoder(EncoderError),
    Decoder(DecoderError),
}

impl std::error::Error for Error {}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Encoder(e) => write!(f, "Encoder {}", e),
            Error::Decoder(e) => write!(f, "Decoder {}", e),
        }
    }
}
