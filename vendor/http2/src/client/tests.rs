use std::{io::Cursor, ops::ControlFlow};

use bytes::{BufMut, BytesMut};
use http::{HeaderName, HeaderValue, Method, Request, Version};

use super::Peer;
use crate::{
    codec::{SendError, UserError},
    ext::OrderedHeaders,
    frame::{Headers, StreamId},
    hpack::{Decoder, Encoder, Header},
};

const A: HeaderName = HeaderName::from_static("x-a");
const B: HeaderName = HeaderName::from_static("x-b");

#[test]
fn ordered_headers_encode_interleaved_duplicates_exactly() {
    let mut request = request_with_headers();
    request.extensions_mut().insert(OrderedHeaders::new(vec![
        (A, HeaderValue::from_static("a1")),
        (B, HeaderValue::from_static("b1")),
        (A, HeaderValue::from_static("a2")),
    ]));

    let frame = convert(request).expect("matching ordered headers were rejected");
    assert_eq!(
        decode_ordinary_fields(frame),
        vec![
            (A, HeaderValue::from_static("a1")),
            (B, HeaderValue::from_static("b1")),
            (A, HeaderValue::from_static("a2")),
        ]
    );
}

#[test]
fn ordered_headers_reject_semantic_mismatch() {
    let mismatches = [
        vec![
            (A, HeaderValue::from_static("a1")),
            (B, HeaderValue::from_static("b1")),
        ],
        vec![
            (A, HeaderValue::from_static("a1")),
            (B, HeaderValue::from_static("b1")),
            (A, HeaderValue::from_static("a2")),
            (B, HeaderValue::from_static("extra")),
        ],
        vec![
            (A, HeaderValue::from_static("a1")),
            (B, HeaderValue::from_static("b1")),
            (A, HeaderValue::from_static("different")),
        ],
        vec![
            (A, HeaderValue::from_static("a2")),
            (B, HeaderValue::from_static("b1")),
            (A, HeaderValue::from_static("a1")),
        ],
    ];

    for ordered in mismatches {
        let mut request = request_with_headers();
        request
            .extensions_mut()
            .insert(OrderedHeaders::new(ordered));

        let error = match convert(request) {
            Ok(_) => panic!("mismatched ordered headers were accepted"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            SendError::User(UserError::MalformedHeaders)
        ));
        assert_eq!(error.to_string(), "malformed headers");
    }
}

#[test]
fn absent_ordered_headers_use_header_map_iteration() {
    let request = request_with_headers();
    let expected = request
        .headers()
        .iter()
        .map(|(name, value)| (name.clone(), value.clone()))
        .collect::<Vec<_>>();

    let frame = convert(request).expect("ordinary request was rejected");
    assert_eq!(decode_ordinary_fields(frame), expected);
}

fn request_with_headers() -> Request<()> {
    let mut request = Request::new(());
    *request.method_mut() = Method::GET;
    *request.uri_mut() = "https://example.test/resource"
        .parse()
        .expect("static request URI must parse");
    *request.version_mut() = Version::HTTP_2;
    request
        .headers_mut()
        .append(A, HeaderValue::from_static("a1"));
    request
        .headers_mut()
        .append(B, HeaderValue::from_static("b1"));
    request
        .headers_mut()
        .append(A, HeaderValue::from_static("a2"));
    request
}

fn convert(request: Request<()>) -> Result<Headers, SendError> {
    Peer::convert_send_message(StreamId::from(1), request, None, true, None, None)
}

fn decode_ordinary_fields(headers: Headers) -> Vec<(HeaderName, HeaderValue)> {
    let mut encoder = Encoder::default();
    let mut encoded = BytesMut::new();
    let continuation = headers.encode(&mut encoder, &mut (&mut encoded).limit(16 * 1024));
    assert!(continuation.is_none(), "test header block was fragmented");

    let mut payload = BytesMut::from(&encoded[9..]);
    let mut cursor = Cursor::new(&mut payload);
    let mut decoder = Decoder::new(4096);
    let mut fields = Vec::new();
    decoder
        .decode(&mut cursor, |header| {
            if let Header::Field { name, value } = header {
                fields.push((name, value));
            }
            ControlFlow::Continue(())
        })
        .expect("encoded header block must decode");
    fields
}
