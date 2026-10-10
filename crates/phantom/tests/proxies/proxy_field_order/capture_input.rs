use super::{TestResult, decode_hex};

#[test]
fn even_byte_non_ascii_capture_input_returns_an_error() {
    // Four UTF-8 bytes: the original byte-pair slicing crosses the é boundary.
    assert!(decode_hex("aéa").is_err());
}

#[test]
fn signed_hexadecimal_is_not_a_capture_byte() {
    assert!(decode_hex("+1").is_err());
}

#[test]
fn valid_capture_hexadecimal_preserves_literal_bytes() -> TestResult<()> {
    assert_eq!(decode_hex("434f4e4e454354")?, "CONNECT");
    assert_eq!(decode_hex("")?, "");
    assert!(decode_hex("0").is_err());
    assert!(decode_hex("zz").is_err());
    Ok(())
}
