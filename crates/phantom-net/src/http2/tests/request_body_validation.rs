use bytes::Bytes;
use http::Method;

use super::{TestResult, target};
use crate::http2::{Http2Error, RequestHeader, validate_request};

#[test]
fn request_body_content_length_is_preserved_or_appended() -> TestResult<()> {
    let supplied = crate::http2::request::prepare_request(
        Method::POST,
        "example.test",
        target()?,
        vec![
            RequestHeader::new("x-before", "a"),
            RequestHeader::new("content-length", "3"),
            RequestHeader::new("x-after", "b"),
        ],
        3,
    )?;
    let supplied = supplied
        .extensions()
        .get::<::http2::ext::OrderedHeaders>()
        .ok_or("prepared request omitted ordered headers")?;
    assert_eq!(
        supplied
            .as_slice()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
            .collect::<Vec<_>>(),
        [
            ("x-before", b"a".as_slice()),
            ("content-length", b"3".as_slice()),
            ("x-after", b"b".as_slice()),
        ]
    );

    let appended = crate::http2::request::prepare_request(
        Method::POST,
        "example.test",
        target()?,
        vec![RequestHeader::new("x-only", "value")],
        3,
    )?;
    let appended = appended
        .extensions()
        .get::<::http2::ext::OrderedHeaders>()
        .ok_or("prepared request omitted ordered headers")?;
    assert_eq!(
        appended
            .as_slice()
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_bytes()))
            .collect::<Vec<_>>(),
        [
            ("x-only", b"value".as_slice()),
            ("content-length", b"3".as_slice()),
        ]
    );
    Ok(())
}

#[test]
fn request_body_rejects_noncanonical_or_duplicate_content_length() -> TestResult<()> {
    for value in ["2", "03", "+3", " 3"] {
        let error = match crate::http2::request::prepare_request(
            Method::POST,
            "example.test",
            target()?,
            vec![RequestHeader::new("content-length", value)],
            3,
        ) {
            Ok(_) => return Err("invalid content-length was accepted".into()),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            Http2Error::InvalidContentLength { index: 0 }
        ));
    }

    let error = match crate::http2::request::prepare_request(
        Method::POST,
        "example.test",
        target()?,
        vec![
            RequestHeader::new("content-length", "3"),
            RequestHeader::new("content-length", "3"),
        ],
        3,
    ) {
        Ok(_) => return Err("duplicate content-length was accepted".into()),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        Http2Error::DuplicateContentLength { index: 1 }
    ));
    Ok(())
}

#[test]
fn connect_is_rejected_by_the_origin_form_api() -> TestResult<()> {
    let body = Bytes::from_static(b"body");
    let result = validate_request(
        &Method::CONNECT,
        "example.test",
        &target()?,
        &[],
        Some(&body),
    );
    assert!(matches!(result, Err(Http2Error::ConnectUnsupported)));
    Ok(())
}
