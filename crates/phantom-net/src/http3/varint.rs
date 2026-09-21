//! QUIC variable-length integers (RFC 9000 section 16) for HTTP Datagram and
//! Capsule Protocol fields that the protocol engine does not expose.

/// Largest value representable by a QUIC variable-length integer.
pub(super) const MAX: u64 = (1 << 62) - 1;

/// Returns the encoded width selected by the first byte of a varint.
pub(super) const fn width(first: u8) -> usize {
    1 << (first >> 6)
}

/// Decodes one varint prefix, returning its value and encoded width.
///
/// Returns `None` when `input` is shorter than the width its first byte
/// declares. Non-minimal encodings are accepted (RFC 9000 section 16).
pub(super) fn decode(input: &[u8]) -> Option<(u64, usize)> {
    let first = *input.first()?;
    let width = width(first);
    let bytes = input.get(..width)?;
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, width))
}

/// Returns the minimal encoded width of `value`, or `None` above [`MAX`].
pub(super) const fn encoded_len(value: u64) -> Option<usize> {
    if value < 1 << 6 {
        Some(1)
    } else if value < 1 << 14 {
        Some(2)
    } else if value < 1 << 30 {
        Some(4)
    } else if value <= MAX {
        Some(8)
    } else {
        None
    }
}

/// Appends the minimal encoding of `value`; returns `false` above [`MAX`].
pub(super) fn encode(value: u64, output: &mut Vec<u8>) -> bool {
    match encoded_len(value) {
        Some(1) => output.push(value as u8),
        Some(2) => output.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes()),
        Some(4) => output.extend_from_slice(&((value as u32) | 0x8000_0000).to_be_bytes()),
        Some(_) => output.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes()),
        None => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{MAX, decode, encode, encoded_len};

    #[test]
    fn minimal_encodings_round_trip_at_each_width_boundary() {
        for value in [0, 63, 64, 16_383, 16_384, (1 << 30) - 1, 1 << 30, MAX] {
            let mut encoded = Vec::new();
            assert!(encode(value, &mut encoded));
            assert_eq!(Some(encoded.len()), encoded_len(value));
            assert_eq!(decode(&encoded), Some((value, encoded.len())));
        }
        assert!(!encode(MAX + 1, &mut Vec::new()));
    }

    #[test]
    fn truncated_and_non_minimal_inputs_follow_rfc_9000() {
        assert_eq!(decode(&[]), None);
        assert_eq!(decode(&[0x40]), None);
        assert_eq!(decode(&[0x40, 0x25]), Some((37, 2)));
        // RFC 9000 appendix A.1 sample values.
        assert_eq!(
            decode(&[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
            Some((151_288_809_941_952_652, 8))
        );
        assert_eq!(decode(&[0x9d, 0x7f, 0x3e, 0x7d]), Some((494_878_333, 4)));
    }
}
