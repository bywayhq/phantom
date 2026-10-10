use super::{Capture, TestResult, decode_hex, header_blocks, read_integer, skip_string};

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

#[test]
fn a_continuation_beyond_the_integer_width_returns_an_error() {
    let mut encoded = vec![0x7f];
    encoded.extend(std::iter::repeat_n(0x80, (usize::BITS / 7 + 1) as usize));
    encoded.push(0);

    assert!(read_integer(&encoded, &mut 0, 7).is_err());
}

#[test]
fn an_integer_value_beyond_usize_returns_an_error() {
    let mut encoded = vec![0x7f];
    append_base128(&mut encoded, usize::MAX);

    assert!(read_integer(&encoded, &mut 0, 7).is_err());
}

#[test]
fn a_string_length_beyond_the_remaining_block_returns_an_error() {
    let mut encoded = vec![0x7f];
    append_base128(&mut encoded, usize::MAX - 0x7f);

    assert!(skip_string(&encoded, &mut 0).is_err());
}

#[test]
fn a_priority_header_without_five_priority_bytes_returns_an_error() {
    let mut wire = PREFACE.to_vec();
    wire.extend_from_slice(&[0, 0, 4, 1, 0x24, 0, 0, 0, 1]);
    wire.extend_from_slice(&[0, 0, 0, 1]);

    assert!(header_blocks(&wire).is_err());
}

#[test]
fn a_partial_header_after_a_complete_frame_returns_an_error() {
    let mut wire = PREFACE.to_vec();
    wire.extend_from_slice(&[0, 0, 1, 1, 4, 0, 0, 0, 1, 0x82]);
    wire.extend_from_slice(&[0, 0, 1, 1]);

    assert!(header_blocks(&wire).is_err());
}

#[test]
fn signed_hexadecimal_is_not_a_capture_byte() {
    assert!(decode_hex("+1").is_err());
}

#[test]
fn an_unknown_huffman_flag_is_not_a_false_flag() {
    assert!(Capture::parse(&capture_with_flag("unknown")).is_err());
}

#[test]
fn literal_integer_and_string_lengths_are_preserved() -> TestResult<()> {
    let mut cursor = 0;
    assert_eq!(read_integer(&[0x7f, 0xba, 0x09], &mut cursor, 7)?, 1337);
    assert_eq!(cursor, 3);

    cursor = 0;
    assert!(skip_string(&[0x83, b'a', b'b', b'c'], &mut cursor)?);
    assert_eq!(cursor, 4);
    assert!(read_integer(&[0x7f, 0x80], &mut 0, 7).is_err());
    assert!(skip_string(&[0x03, b'a'], &mut 0).is_err());
    Ok(())
}

#[test]
fn complete_plain_and_priority_headers_preserve_literal_blocks() -> TestResult<()> {
    let mut wire = PREFACE.to_vec();
    wire.extend_from_slice(&[0, 0, 1, 1, 4, 0, 0, 0, 1, 0x82]);
    wire.extend_from_slice(&[0, 0, 6, 1, 0x24, 0, 0, 0, 3, 0, 0, 0, 1, 15, 0x84]);

    assert_eq!(header_blocks(&wire)?, [vec![0x82], vec![0x84]]);
    wire.pop();
    assert!(header_blocks(&wire).is_err());
    Ok(())
}

#[test]
fn literal_hex_and_declared_huffman_flags_are_preserved() -> TestResult<()> {
    assert_eq!(decode_hex("00aAFF")?, [0, 0xaa, 0xff]);
    assert!(decode_hex("aéa").is_err());

    for (flag, expected) in [("true", Some(true)), ("false", Some(false)), ("none", None)] {
        let capture = Capture::parse(&capture_with_flag(flag))?;
        assert_eq!(capture.requests.len(), 1);
        assert_eq!(capture.requests[0].len(), 1);
        let field = &capture.requests[0][0];
        assert_eq!(field.name, "cookie");
        assert_eq!(field.value, "k=v");
        assert_eq!(field.value_huffman, expected);
    }
    Ok(())
}

fn append_base128(encoded: &mut Vec<u8>, mut value: usize) {
    while value >= 128 {
        encoded.push((value % 128) as u8 | 0x80);
        value /= 128;
    }
    encoded.push(value as u8);
}

fn capture_with_flag(flag: &str) -> String {
    format!(
        "format=phantom-cookie-crumbs-v1\n\
         probe_cookie_count=0\n\
         run_0_request_count=1\n\
         run_0_request_0_field_count=1\n\
         run_0_request_0_field_0=repr:never-indexed,index:0,\
         name_hex:636f6f6b6965,value_hex:6b3d76,value_huffman:{flag}\n"
    )
}
