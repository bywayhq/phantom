use std::{
    convert::Infallible,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http::Method;
use http_body::{Body, Frame, SizeHint};

use super::{TestResult, target};
use crate::http2::{Http2Error, RequestBody, RequestBodyMetadata, RequestHeader, validate_request};

fn exact_body(length: usize) -> Option<RequestBodyMetadata> {
    Some(RequestBody::from_bytes(Bytes::from(vec![0; length])).metadata())
}

struct UnknownBody;

impl Body for UnknownBody {
    type Data = Bytes;
    type Error = Infallible;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Poll::Pending
    }

    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

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
        exact_body(3),
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
        exact_body(3),
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
            exact_body(3),
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
        exact_body(3),
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
fn unknown_length_body_omits_and_rejects_content_length() -> TestResult<()> {
    let metadata = RequestBody::streaming(UnknownBody).metadata();
    let prepared = crate::http2::request::prepare_request(
        Method::POST,
        "example.test",
        target()?,
        vec![RequestHeader::new("x-only", "value")],
        Some(metadata),
    )?;
    assert!(prepared.headers().get("content-length").is_none());

    let result = crate::http2::request::prepare_request(
        Method::POST,
        "example.test",
        target()?,
        vec![RequestHeader::new("content-length", "3")],
        Some(metadata),
    );
    assert!(matches!(
        result,
        Err(Http2Error::ContentLengthRequiresExactBody { index: 0 })
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
