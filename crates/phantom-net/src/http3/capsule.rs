//! Incremental Capsule Protocol decoding (RFC 9297 section 3.2) for the data
//! stream of an accepted CONNECT-UDP request.

use bytes::Bytes;

use super::varint;

/// DATAGRAM capsule type (RFC 9297 section 3.5).
pub(super) const DATAGRAM: u64 = 0x00;
/// Largest accepted DATAGRAM capsule value: an eight-byte Context ID plus the
/// largest UDP payload a Context ID zero datagram may carry (RFC 9298
/// section 5). Larger capsules are rejected rather than buffered (RFC 9297
/// section 3.5).
pub(super) const MAX_DATAGRAM_CAPSULE_LEN: u64 = 8 + 65_527;
/// Capsule Type and Capsule Length are each at most an eight-byte varint.
const MAX_HEADER_LEN: usize = 16;

/// Failure to parse the Capsule Protocol; the data stream is malformed
/// (RFC 9297 section 3.3).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CapsuleError {
    /// The data stream ended inside a capsule.
    Truncated,
    /// A DATAGRAM capsule exceeded [`MAX_DATAGRAM_CAPSULE_LEN`].
    Oversized,
}

impl CapsuleError {
    pub(super) const fn message(self) -> &'static str {
        match self {
            Self::Truncated => "CONNECT-UDP data stream ended inside a capsule",
            Self::Oversized => "CONNECT-UDP DATAGRAM capsule exceeds the UDP payload bound",
        }
    }
}

/// Streaming decoder that yields DATAGRAM capsule values.
///
/// Unknown capsule types are skipped without buffering their values (RFC 9297
/// section 3.2), so memory stays bounded by one DATAGRAM capsule.
#[derive(Debug)]
pub(super) struct CapsuleDecoder {
    state: State,
}

#[derive(Debug)]
enum State {
    Header {
        bytes: [u8; MAX_HEADER_LEN],
        len: usize,
    },
    Datagram {
        value: Vec<u8>,
        remaining: usize,
    },
    Skip {
        remaining: u64,
    },
}

impl CapsuleDecoder {
    pub(super) const fn new() -> Self {
        Self {
            state: State::Header {
                bytes: [0; MAX_HEADER_LEN],
                len: 0,
            },
        }
    }

    /// Consumes `input`, passing each complete DATAGRAM capsule value to
    /// `on_datagram` in stream order.
    pub(super) fn feed(
        &mut self,
        mut input: &[u8],
        mut on_datagram: impl FnMut(Bytes),
    ) -> Result<(), CapsuleError> {
        while !input.is_empty() {
            match &mut self.state {
                State::Header { bytes, len } => {
                    let target = header_target(&bytes[..*len]);
                    let count = (target - *len).min(input.len());
                    bytes[*len..*len + count].copy_from_slice(&input[..count]);
                    *len += count;
                    input = &input[count..];
                    if let Some((capsule_type, length)) = parse_header(&bytes[..*len]) {
                        self.start_value(capsule_type, length, &mut on_datagram)?;
                    }
                }
                State::Datagram { value, remaining } => {
                    let count = (*remaining).min(input.len());
                    value.extend_from_slice(&input[..count]);
                    *remaining -= count;
                    input = &input[count..];
                    if *remaining == 0 {
                        let value = std::mem::take(value);
                        self.state = State::new_header();
                        on_datagram(Bytes::from(value));
                    }
                }
                State::Skip { remaining } => {
                    let count = usize::try_from(*remaining)
                        .unwrap_or(usize::MAX)
                        .min(input.len());
                    *remaining -= count as u64;
                    input = &input[count..];
                    if *remaining == 0 {
                        self.state = State::new_header();
                    }
                }
            }
        }
        Ok(())
    }

    /// Validates a clean end of the data stream (RFC 9297 section 3.3).
    pub(super) fn finish(&self) -> Result<(), CapsuleError> {
        match self.state {
            State::Header { len: 0, .. } => Ok(()),
            _ => Err(CapsuleError::Truncated),
        }
    }

    fn start_value(
        &mut self,
        capsule_type: u64,
        length: u64,
        on_datagram: &mut impl FnMut(Bytes),
    ) -> Result<(), CapsuleError> {
        self.state = if capsule_type == DATAGRAM {
            if length > MAX_DATAGRAM_CAPSULE_LEN {
                return Err(CapsuleError::Oversized);
            }
            if length == 0 {
                on_datagram(Bytes::new());
                State::new_header()
            } else {
                // Bounded by `MAX_DATAGRAM_CAPSULE_LEN`, so the cast is lossless.
                let length = length as usize;
                State::Datagram {
                    value: Vec::with_capacity(length),
                    remaining: length,
                }
            }
        } else if length == 0 {
            State::new_header()
        } else {
            State::Skip { remaining: length }
        };
        Ok(())
    }
}

impl State {
    const fn new_header() -> Self {
        Self::Header {
            bytes: [0; MAX_HEADER_LEN],
            len: 0,
        }
    }
}

/// Returns how many header bytes are needed to learn the next field width.
fn header_target(bytes: &[u8]) -> usize {
    let Some(first) = bytes.first() else {
        return 1;
    };
    let type_len = varint::width(*first);
    match bytes.get(type_len) {
        Some(length_first) => type_len + varint::width(*length_first),
        None => type_len + 1,
    }
}

fn parse_header(bytes: &[u8]) -> Option<(u64, u64)> {
    let (capsule_type, type_len) = varint::decode(bytes)?;
    let (length, length_len) = varint::decode(&bytes[type_len..])?;
    (type_len + length_len == bytes.len()).then_some((capsule_type, length))
}

/// Encodes one capsule (RFC 9297 section 3.2).
pub(super) fn encode(capsule_type: u64, value: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(MAX_HEADER_LEN + value.len());
    varint::encode(capsule_type, &mut output);
    varint::encode(value.len() as u64, &mut output);
    output.extend_from_slice(value);
    output
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::{CapsuleDecoder, CapsuleError, DATAGRAM, MAX_DATAGRAM_CAPSULE_LEN, State, encode};

    fn decode_all(input: &[u8], chunk: usize) -> Result<Vec<Bytes>, CapsuleError> {
        let mut decoder = CapsuleDecoder::new();
        let mut output = Vec::new();
        for part in input.chunks(chunk) {
            decoder.feed(part, |value| output.push(value))?;
        }
        decoder.finish()?;
        Ok(output)
    }

    #[test]
    fn datagram_capsules_round_trip_across_arbitrary_chunking() -> Result<(), CapsuleError> {
        let mut stream = encode(DATAGRAM, b"\x00first");
        stream.extend(encode(DATAGRAM, &[]));
        stream.extend(encode(DATAGRAM, &vec![7; 300]));
        for chunk in [1, 2, 3, 7, stream.len()] {
            let values = decode_all(&stream, chunk)?;
            assert_eq!(values.len(), 3, "chunk size {chunk}");
            assert_eq!(values[0], Bytes::from_static(b"\x00first"));
            assert!(values[1].is_empty());
            assert_eq!(values[2], Bytes::from(vec![7; 300]));
        }
        Ok(())
    }

    #[test]
    fn unknown_capsules_are_skipped_without_buffering() -> Result<(), CapsuleError> {
        let mut stream = encode(0x2a, &vec![9; 100_000]);
        stream.extend(encode(0x3f_ff_ff, &[]));
        stream.extend(encode(DATAGRAM, b"\x00payload"));
        let mut decoder = CapsuleDecoder::new();
        let mut values = Vec::new();
        decoder.feed(&stream[..50], |value| values.push(value))?;
        assert!(matches!(decoder.state, State::Skip { .. }));
        decoder.feed(&stream[50..], |value| values.push(value))?;
        decoder.finish()?;
        assert_eq!(values, [Bytes::from_static(b"\x00payload")]);
        Ok(())
    }

    #[test]
    fn stream_end_inside_a_capsule_is_truncated() {
        let stream = encode(DATAGRAM, b"\x00payload");
        for end in 1..stream.len() {
            assert_eq!(
                decode_all(&stream[..end], 1),
                Err(CapsuleError::Truncated),
                "end {end}"
            );
        }
        let unknown = encode(0x2a, b"abc");
        assert_eq!(decode_all(&unknown[..3], 1), Err(CapsuleError::Truncated));
    }

    #[test]
    fn oversized_datagram_capsule_is_rejected_before_buffering() {
        let mut header = Vec::new();
        super::varint::encode(DATAGRAM, &mut header);
        super::varint::encode(MAX_DATAGRAM_CAPSULE_LEN + 1, &mut header);
        let mut decoder = CapsuleDecoder::new();
        assert_eq!(decoder.feed(&header, |_| {}), Err(CapsuleError::Oversized));

        let largest = vec![0; MAX_DATAGRAM_CAPSULE_LEN as usize];
        assert_eq!(
            decode_all(&encode(DATAGRAM, &largest), 4096).map(|values| values.len()),
            Ok(1)
        );
    }
}
