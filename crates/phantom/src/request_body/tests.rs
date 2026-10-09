use std::error::Error;

use super::{
    BodyBuffer, MAX_METADATA_BYTES, MAX_MULTIPART_PARTS, MultipartPart, PreparedBodyErrorKind,
    PreparedRequestBody,
};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn form_keeps_order_duplicates_empty_fields_and_utf8_without_normalizing_newlines() -> TestResult {
    let body = PreparedRequestBody::form(
        [
            ("tag", "first"),
            ("", ""),
            ("tag", "last"),
            ("text", "é +*~"),
            ("line", "\n\r\r\n"),
        ],
        256,
    )?;
    assert_eq!(
        body.bytes().as_ref(),
        b"tag=first&=&tag=last&text=%C3%A9+%2B*%7E&line=%0A%0D%0D%0A"
    );
    assert_eq!(
        body.content_type(),
        "application/x-www-form-urlencoded;charset=UTF-8"
    );
    let clone = body.clone();
    let (bytes, content_type) = body.into_parts();
    assert_eq!(&bytes, clone.bytes());
    assert_eq!(content_type.as_ref(), clone.content_type());
    assert_eq!(bytes.as_ptr(), clone.bytes().as_ptr());
    Ok(())
}

#[test]
fn form_limit_includes_escaping_separators_and_empty_fields() -> TestResult {
    let empty = PreparedRequestBody::form(std::iter::empty::<(&str, &str)>(), 0)?;
    assert!(empty.bytes().is_empty());
    assert_eq!(
        PreparedRequestBody::form([("", "")], 1)?.bytes(),
        b"=".as_slice()
    );
    for (pairs, maximum) in [
        (vec![("", "")], 0),
        (vec![("", "+")], 3),
        (vec![("", ""), ("", "")], 2),
        (vec![("", "é")], 6),
    ] {
        let error = PreparedRequestBody::form(pairs, maximum)
            .err()
            .ok_or("limit ignored")?;
        assert_eq!(error.kind(), PreparedBodyErrorKind::TooLarge);
        assert!(error.source().is_none());
    }
    assert_eq!(
        PreparedRequestBody::form([("", "+")], 4)?.bytes(),
        b"=%2B".as_slice()
    );
    Ok(())
}

#[test]
fn form_stops_consuming_input_at_the_first_output_limit() -> TestResult {
    let mut visits = 0;
    let pairs = std::iter::from_fn(|| {
        visits += 1;
        Some(("", ""))
    });
    assert_eq!(
        PreparedRequestBody::form(pairs, 1)
            .err()
            .ok_or("limit ignored")?
            .kind(),
        PreparedBodyErrorKind::TooLarge
    );
    assert_eq!(visits, 2);
    Ok(())
}

#[test]
fn multipart_keeps_duplicate_fields_order_binary_bytes_and_explicit_file_metadata() -> TestResult {
    let binary = [0, 255, b'\r', b'\n'];
    let parts = [
        MultipartPart::text("tag", "one\ntwo\rthree\r\nfour")?,
        MultipartPart::text("tag", "last")?,
        MultipartPart::bytes("file", &binary)?
            .with_filename("file.bin")?
            .with_content_type("application/custom")?,
    ];
    let body = PreparedRequestBody::multipart("boundary", parts, 1024)?;
    let mut expected = b"--boundary\r\nContent-Disposition: form-data; name=\"tag\"\r\n\r\none\r\ntwo\r\nthree\r\nfour\r\n--boundary\r\nContent-Disposition: form-data; name=\"tag\"\r\n\r\nlast\r\n--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"file.bin\"\r\nContent-Type: application/custom\r\n\r\n".to_vec();
    expected.extend_from_slice(&binary);
    expected.extend_from_slice(b"\r\n--boundary--\r\n");
    assert_eq!(body.bytes().as_ref(), expected);
    assert_eq!(
        body.content_type(),
        "multipart/form-data; boundary=boundary"
    );
    let size = body.bytes().len();
    assert_eq!(
        PreparedRequestBody::multipart("boundary", parts, size)?,
        body
    );
    assert_eq!(
        PreparedRequestBody::multipart("boundary", parts, size - 1)
            .err()
            .ok_or("multipart limit ignored")?
            .kind(),
        PreparedBodyErrorKind::TooLarge
    );
    Ok(())
}

#[test]
fn multipart_escapes_parameter_newlines_and_quotes_but_keeps_backslashes_and_utf8() -> TestResult {
    let part = MultipartPart::bytes("名\n\r\r\n\"\\", b"data")?.with_filename("文\n\r\r\n\"\\")?;
    let body = PreparedRequestBody::multipart("B", [part], 1024)?;
    let expected = concat!(
        "--B\r\nContent-Disposition: form-data; name=\"名%0D%0A%0D%0A%0D%0A%22\\\"; ",
        "filename=\"文%0A%0D%0D%0A%22\\\"\r\n",
        "Content-Type: application/octet-stream\r\n\r\ndata\r\n--B--\r\n"
    );
    assert_eq!(body.bytes().as_ref(), expected.as_bytes());
    assert!(!expected.contains("filename*="));
    Ok(())
}

#[test]
fn multipart_allows_empty_names_and_filenames_and_explicit_text_media_types() -> TestResult {
    let part = MultipartPart::text("", "\n")?
        .with_filename("")?
        .with_content_type("Text/Plain")?;
    let body = PreparedRequestBody::multipart("B", [part], 256)?;
    assert_eq!(body.bytes().as_ref(), b"--B\r\nContent-Disposition: form-data; name=\"\"; filename=\"\"\r\nContent-Type: Text/Plain\r\n\r\n\r\n\r\n--B--\r\n");
    Ok(())
}

#[test]
fn multipart_boundary_grammar_controls_content_type_quoting_without_changing_delimiters()
-> TestResult {
    for (boundary, content_type) in [
        ("a'_+-.", "multipart/form-data; boundary=a'_+-."),
        ("a():/=?", "multipart/form-data; boundary=\"a():/=?\""),
    ] {
        let body = PreparedRequestBody::multipart(boundary, [], 128)?;
        assert_eq!(body.content_type(), content_type);
        assert_eq!(
            body.bytes().as_ref(),
            format!("--{boundary}--\r\n").as_bytes()
        );
    }
    let maximum = "b".repeat(70);
    assert!(PreparedRequestBody::multipart(&maximum, [], 128).is_ok());
    for boundary in [
        "",
        "a b",
        "a\r\nInjected",
        "a;",
        "a\"",
        "a\\",
        "é",
        &"b".repeat(71),
    ] {
        let error = PreparedRequestBody::multipart(boundary, [], 128)
            .err()
            .ok_or("invalid boundary accepted")?;
        assert_eq!(error.kind(), PreparedBodyErrorKind::InvalidBoundary);
        assert!(error.source().is_none());
    }
    assert_eq!(
        PreparedRequestBody::multipart("B", [], 7)?.bytes().as_ref(),
        b"--B--\r\n"
    );
    assert_eq!(
        PreparedRequestBody::multipart("B", [], 6)
            .err()
            .ok_or("closing delimiter limit ignored")?
            .kind(),
        PreparedBodyErrorKind::TooLarge
    );
    Ok(())
}

#[test]
fn multipart_collision_check_also_rejects_normalized_and_non_line_delimiters() -> TestResult {
    for value in ["--B", "a\n--Btail", "a\r--B", "inside--Bvalue"] {
        let text = MultipartPart::text("field", value)?;
        let bytes = MultipartPart::bytes("field", value.as_bytes())?;
        for part in [text, bytes] {
            let error = PreparedRequestBody::multipart("B", [part], 1024)
                .err()
                .ok_or("boundary collision accepted")?;
            assert_eq!(error.kind(), PreparedBodyErrorKind::BoundaryCollision);
        }
    }
    assert!(PreparedRequestBody::multipart("B", [MultipartPart::text("--B", "B")?], 1024).is_ok());
    Ok(())
}

#[test]
fn multipart_metadata_rejects_controls_and_unchecked_part_header_syntax() -> TestResult {
    for value in ["bad\0name", "bad\tname", "bad\u{85}name"] {
        assert_eq!(
            MultipartPart::text(value, "data")
                .err()
                .ok_or("control name accepted")?
                .kind(),
            PreparedBodyErrorKind::InvalidName
        );
        assert_eq!(
            MultipartPart::bytes("field", b"data")?
                .with_filename(value)
                .err()
                .ok_or("control filename accepted")?
                .kind(),
            PreparedBodyErrorKind::InvalidFilename
        );
    }
    for value in [
        "",
        "text",
        "/plain",
        "text/",
        "text/plain; charset=x",
        "text /plain",
        "text/plain\r\nInjected: value",
        "text/plain/extra",
        "téxt/plain",
    ] {
        let error = MultipartPart::bytes("field", b"data")?
            .with_content_type(value)
            .err()
            .ok_or("invalid part type accepted")?;
        assert_eq!(error.kind(), PreparedBodyErrorKind::InvalidContentType);
        assert!(error.source().is_none());
    }
    Ok(())
}

#[test]
fn multipart_metadata_and_part_count_bounds_are_inclusive() -> TestResult {
    let name = "x".repeat(MAX_METADATA_BYTES);
    let part = MultipartPart::text(&name, "")?.with_filename(&name)?;
    let content_type = format!("x/{}", "x".repeat(MAX_METADATA_BYTES - 2));
    assert!(part.with_content_type(&content_type).is_ok());
    let too_long = format!("{name}x");
    assert_eq!(
        MultipartPart::text(&too_long, "")
            .err()
            .ok_or("name bound ignored")?
            .kind(),
        PreparedBodyErrorKind::TooLarge
    );
    assert_eq!(
        part.with_filename(&too_long)
            .err()
            .ok_or("filename bound ignored")?
            .kind(),
        PreparedBodyErrorKind::TooLarge
    );
    assert_eq!(
        part.with_content_type(&format!("{content_type}x"))
            .err()
            .ok_or("media type bound ignored")?
            .kind(),
        PreparedBodyErrorKind::TooLarge
    );
    let short = MultipartPart::text("field", "")?;
    assert!(
        PreparedRequestBody::multipart(
            "B",
            std::iter::repeat_n(short, MAX_MULTIPART_PARTS),
            1 << 20
        )
        .is_ok()
    );
    assert_eq!(
        PreparedRequestBody::multipart(
            "B",
            std::iter::repeat_n(short, MAX_MULTIPART_PARTS + 1),
            1 << 20
        )
        .err()
        .ok_or("part count bound ignored")?
        .kind(),
        PreparedBodyErrorKind::TooManyParts
    );
    Ok(())
}

#[test]
fn multipart_stops_consuming_parts_at_the_first_output_limit() -> TestResult {
    let part = MultipartPart::text("field", "")?;
    let mut visits = 0;
    let parts = std::iter::from_fn(|| {
        visits += 1;
        Some(part)
    });
    assert_eq!(
        PreparedRequestBody::multipart("B", parts, 0)
            .err()
            .ok_or("multipart limit ignored")?
            .kind(),
        PreparedBodyErrorKind::TooLarge
    );
    assert_eq!(visits, 1);
    Ok(())
}

#[test]
fn prepared_values_and_errors_omit_payloads_and_metadata_from_diagnostics() -> TestResult {
    let marker = "private-body-marker";
    let part = MultipartPart::bytes(marker, marker.as_bytes())?.with_filename(marker)?;
    let body = PreparedRequestBody::multipart("private-boundary-marker", [part], 512)?;
    for diagnostic in [format!("{part:?}"), format!("{body:?}")] {
        assert!(!diagnostic.contains(marker));
        assert!(!diagnostic.contains("private-boundary-marker"));
        assert!(!diagnostic.contains("application/octet-stream"));
    }
    let error = PreparedRequestBody::multipart("private boundary marker", [part], 512)
        .err()
        .ok_or("invalid boundary accepted")?;
    assert!(!format!("{error} {error:?}").contains("private"));
    Ok(())
}

#[test]
fn output_reservation_classifies_limits_and_allocation_failures_separately() -> TestResult {
    let mut bounded = BodyBuffer::new(4);
    bounded.append(b"data")?;
    assert_eq!(
        bounded.append(b"x").err().ok_or("limit ignored")?.kind(),
        PreparedBodyErrorKind::TooLarge
    );
    assert_eq!(bounded.bytes, b"data");
    assert!(bounded.bytes.capacity() <= 4);
    let mut allocation = BodyBuffer::new(usize::MAX);
    assert_eq!(
        allocation
            .reserve(usize::MAX)
            .err()
            .ok_or("impossible capacity accepted")?
            .kind(),
        PreparedBodyErrorKind::Allocation
    );
    assert!(allocation.bytes.is_empty());
    Ok(())
}

#[cfg(feature = "json")]
mod json;
