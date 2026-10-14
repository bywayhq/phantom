//! Resource and grammar controls at the JSON boundary.
use super::super::{FingerprintImportErrorKind as Kind, json};
use super::profiles::TestResult;

fn rejected(bytes: &[u8], kind: Kind) -> TestResult {
    let error = json::parse(bytes)
        .err()
        .ok_or("JSON unexpectedly accepted")?;
    assert_eq!(error.kind(), kind);
    Ok(())
}

#[test]
fn escaped_duplicate_keys_are_rejected_before_values_can_replace_each_other() -> TestResult {
    rejected(
        br#"{"profile":null,"\u0070rofile":{}}"#,
        Kind::DuplicateField,
    )?;
    rejected(
        br#"{"outer":{"secret":1,"secret":2}}"#,
        Kind::DuplicateField,
    )
}

#[test]
fn integer_grammar_rejects_floats_negative_and_nonfinite_forms() -> TestResult {
    for bytes in [b"-1".as_slice(), b"-0", b"1.0", b"1e2"] {
        rejected(bytes, Kind::InvalidValue)?;
    }
    for bytes in [b"NaN".as_slice(), b"Infinity", b"18446744073709551616"] {
        assert!(json::parse(bytes).is_err());
    }
    assert!(json::parse(b"18446744073709551615").is_ok());
    Ok(())
}

#[test]
fn malformed_utf8_syntax_and_trailing_documents_fail() -> TestResult {
    for bytes in [b"[1,]".as_slice(), b"{}{}", b"\"\xff\"", b"{\"a\":"] {
        rejected(bytes, Kind::MalformedJson)?;
    }
    Ok(())
}

#[test]
fn decoded_string_limit_applies_to_values_and_keys() -> TestResult {
    let value = format!("\"{}\"", "a".repeat(65536));
    assert!(json::parse(value.as_bytes()).is_ok());
    rejected(
        format!("\"{}\"", "a".repeat(65537)).as_bytes(),
        Kind::TooLarge,
    )?;
    rejected(
        format!("{{\"{}\":null}}", "a".repeat(65537)).as_bytes(),
        Kind::TooLarge,
    )?;
    rejected(
        format!("\"{}\"", "\\u0061".repeat(65537)).as_bytes(),
        Kind::TooLarge,
    )
}

#[test]
fn nesting_object_array_and_input_limits_fail_at_the_boundary() -> TestResult {
    assert!(json::parse(format!("{}0{}", "[".repeat(16), "]".repeat(16)).as_bytes()).is_ok());
    rejected(
        format!("{}0{}", "[".repeat(17), "]".repeat(17)).as_bytes(),
        Kind::TooLarge,
    )?;
    let object = (0..65)
        .map(|n| format!("\"k{n}\":null"))
        .collect::<Vec<_>>()
        .join(",");
    rejected(format!("{{{object}}}").as_bytes(), Kind::TooLarge)?;
    let array = format!("[{}0]", "0,".repeat(65535));
    rejected(array.as_bytes(), Kind::TooLarge)?;
    assert!(json::parse(format!("[{}0]", "0,".repeat(65534)).as_bytes()).is_ok());
    rejected(&vec![b' '; 16 * 1024 * 1024 + 1], Kind::TooLarge)
}

#[test]
fn aggregate_node_limit_bounds_many_legal_arrays() -> TestResult {
    let row = format!("[{}0]", "0,".repeat(65534));
    let document = format!("[{}]", vec![row; 17].join(","));
    rejected(document.as_bytes(), Kind::TooLarge)
}
