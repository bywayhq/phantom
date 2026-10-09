use std::{cell::Cell, error::Error};

use serde::{Serialize, Serializer, ser::SerializeSeq};

use super::super::{BodyBuffer, PreparedBodyErrorKind, PreparedRequestBody};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn json_keeps_serializer_bytes_and_exact_content_type_with_an_inclusive_limit() -> TestResult {
    let values = ["é", "line\nquote\"", "<>&"];
    let expected = "[\"é\",\"line\\nquote\\\"\",\"<>&\"]";
    let body = PreparedRequestBody::json(&values, expected.len())?;
    assert_eq!(body.bytes().as_ref(), expected.as_bytes());
    assert_eq!(body.content_type(), "application/json");
    assert_eq!(
        PreparedRequestBody::json(&values, expected.len() - 1)
            .err()
            .ok_or("JSON limit ignored")?
            .kind(),
        PreparedBodyErrorKind::TooLarge
    );
    assert_eq!(
        PreparedRequestBody::json(&(), 0)
            .err()
            .ok_or("zero JSON limit ignored")?
            .kind(),
        PreparedBodyErrorKind::TooLarge
    );
    Ok(())
}

struct Failing;

impl Serialize for Failing {
    fn serialize<S: Serializer>(&self, _serializer: S) -> Result<S::Ok, S::Error> {
        Err(serde::ser::Error::custom("serializer-value-marker"))
    }
}

#[test]
fn json_serializer_failure_preserves_its_typed_source_only() -> TestResult {
    let error = PreparedRequestBody::json(&Failing, 64)
        .err()
        .ok_or("serializer failure ignored")?;
    assert_eq!(error.kind(), PreparedBodyErrorKind::Json);
    let source = error
        .source()
        .and_then(|source| source.downcast_ref::<serde_json::Error>())
        .ok_or("typed JSON source missing")?;
    assert!(source.to_string().contains("serializer-value-marker"));
    assert!(!format!("{error} {error:?}").contains("serializer-value-marker"));
    Ok(())
}

struct Sequence<'a> {
    first: &'a str,
    visits: &'a Cell<usize>,
}

impl Serialize for Sequence<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(2))?;
        self.visits.set(1);
        sequence.serialize_element(self.first)?;
        self.visits.set(2);
        sequence.serialize_element("second")?;
        sequence.end()
    }
}

#[test]
fn json_output_failure_stops_serialization_and_has_no_misleading_json_source() -> TestResult {
    let visits = Cell::new(0);
    let value = Sequence {
        first: "this exceeds the output limit",
        visits: &visits,
    };
    let error = PreparedRequestBody::json(&value, 8)
        .err()
        .ok_or("output limit ignored")?;
    assert_eq!(visits.get(), 1);
    assert_eq!(error.kind(), PreparedBodyErrorKind::TooLarge);
    assert!(error.source().is_none());
    Ok(())
}

#[test]
fn json_writer_keeps_the_first_failure_and_refuses_later_writes() -> TestResult {
    use std::io::Write;

    let mut output = BodyBuffer::new(1);
    output.write_all(b"x")?;
    assert!(output.write_all(b"too large").is_err());
    assert!(output.write(b"").is_err());
    assert_eq!(output.failure, Some(PreparedBodyErrorKind::TooLarge));
    assert_eq!(output.bytes, b"x");
    Ok(())
}
