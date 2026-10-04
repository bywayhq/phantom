use std::time::Duration;

use bytes::Bytes;
use http::Method;

use super::{TestResult, target};
use crate::http2::{Http2Error, RequestBody, RequestBodyMetadata, RequestHeader};

/// A field's name and value as prepared.
type Field = (String, Vec<u8>);

fn waiting_body(bytes: &'static [u8]) -> Option<RequestBodyMetadata> {
    Some(
        RequestBody::from_bytes(Bytes::from_static(bytes))
            .expect_continue(Duration::from_secs(1))
            .metadata(),
    )
}

fn ordered(
    headers: Vec<RequestHeader>,
    body: Option<RequestBodyMetadata>,
) -> TestResult<Result<Vec<Field>, Http2Error>> {
    let request = match crate::http2::request::prepare_request(
        Method::POST,
        "example.test",
        target()?,
        headers,
        body,
    ) {
        Ok(request) => request,
        Err(error) => return Ok(Err(error)),
    };
    Ok(Ok(request
        .extensions()
        .get::<::http2::ext::OrderedHeaders>()
        .map(|ordered| {
            ordered
                .as_slice()
                .iter()
                .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
                .collect()
        })
        .unwrap_or_default()))
}

#[test]
fn generated_expectation_follows_content_length() -> TestResult<()> {
    assert_eq!(
        ordered(
            vec![RequestHeader::new("x-before", "a")],
            waiting_body(b"abc")
        )??,
        [
            ("x-before".to_owned(), b"a".to_vec()),
            ("content-length".to_owned(), b"3".to_vec()),
            ("expect".to_owned(), b"100-continue".to_vec()),
        ]
    );
    Ok(())
}

#[test]
fn an_empty_body_or_no_wait_sends_no_expectation() -> TestResult<()> {
    for body in [
        waiting_body(b""),
        Some(RequestBody::from_bytes(Bytes::from_static(b"abc")).metadata()),
    ] {
        assert!(
            ordered(Vec::new(), body)??
                .iter()
                .all(|(name, _)| name != "expect")
        );
    }
    Ok(())
}

#[test]
fn a_caller_expectation_keeps_its_position_and_must_be_100_continue() -> TestResult<()> {
    assert_eq!(
        ordered(
            vec![
                RequestHeader::new("expect", "100-Continue"),
                RequestHeader::new("x-after", "b"),
            ],
            waiting_body(b"abc"),
        )??,
        [
            ("expect".to_owned(), b"100-Continue".to_vec()),
            ("x-after".to_owned(), b"b".to_vec()),
            ("content-length".to_owned(), b"3".to_vec()),
        ]
    );

    for (headers, invalid) in [
        (vec![RequestHeader::new("expect", "gzip")], 0),
        (
            vec![
                RequestHeader::new("expect", "100-continue"),
                RequestHeader::new("expect", "100-continue"),
            ],
            1,
        ),
    ] {
        let result = ordered(headers, waiting_body(b"abc"))?;
        assert!(
            matches!(
                result,
                Err(Http2Error::InvalidHeaderValue { index, .. }) if index == invalid
            ),
            "unexpected result: {result:?}"
        );
    }
    Ok(())
}
