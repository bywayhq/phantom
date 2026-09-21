use std::io::Write;

use bytes::Bytes;
use flate2::{
    Compression,
    write::{DeflateEncoder, GzEncoder, ZlibEncoder},
};
use http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use phantom_net::request::RequestHeader;
use zstd::stream::raw::CParameter;

use super::{
    AdvertisedContentCodings, ContentCoding, ContentDecoder, ContentDecoding, ContentDecodingPlan,
    DECODED_FRAME_BYTES, Pump,
    field::{ContentEncodingList, parse_accept_encoding, parse_content_encoding},
    plan,
};
use crate::{HttpProtocol, RequestError, RequestErrorKind};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PAYLOAD: &[u8] = b"phantom content coding payload, repeated enough to compress well. ";

fn payload(repetitions: usize) -> Vec<u8> {
    PAYLOAD.repeat(repetitions)
}

fn gzip(data: &[u8]) -> TestResult<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn zlib(data: &[u8]) -> TestResult<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn raw_deflate(data: &[u8]) -> TestResult<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn brotli(data: &[u8]) -> TestResult<Vec<u8>> {
    let mut output = Vec::new();
    brotli::BrotliCompress(
        &mut std::io::Cursor::new(data),
        &mut output,
        &brotli::enc::BrotliEncoderParams::default(),
    )?;
    Ok(output)
}

fn zstd(data: &[u8]) -> TestResult<Vec<u8>> {
    Ok(zstd::encode_all(data, 3)?)
}

struct Decoded {
    data: Vec<u8>,
    largest_frame: usize,
}

fn decode_chunks(
    codings: &[ContentCoding],
    chunks: impl IntoIterator<Item = Vec<u8>>,
    maximum: u64,
) -> Result<Decoded, RequestError> {
    let mut decoder = ContentDecoder::new(codings, maximum, HttpProtocol::Http1)?;
    let mut chunks = chunks.into_iter();
    let mut decoded = Decoded {
        data: Vec::new(),
        largest_frame: 0,
    };
    loop {
        match decoder.pump()? {
            Pump::Data(data) => {
                decoded.largest_frame = decoded.largest_frame.max(data.len());
                decoded.data.extend_from_slice(&data);
            }
            Pump::NeedInput => match chunks.next() {
                Some(chunk) => decoder.push(Bytes::from(chunk)),
                None => decoder.end_input(),
            },
            Pump::Finished => return Ok(decoded),
        }
    }
}

fn decode(codings: &[ContentCoding], encoded: &[u8]) -> Result<Vec<u8>, RequestError> {
    decode_chunks(codings, [encoded.to_vec()], u64::MAX).map(|decoded| decoded.data)
}

fn single_bytes(encoded: &[u8]) -> Vec<Vec<u8>> {
    encoded.iter().map(|byte| vec![*byte]).collect()
}

fn decoding_error_kind(result: Result<Vec<u8>, RequestError>) -> Option<RequestErrorKind> {
    result.err().map(|error| error.kind())
}

fn accept(values: &[&str]) -> Result<AdvertisedContentCodings, &'static str> {
    parse_accept_encoding(values.iter().map(|value| value.as_bytes()))
}

fn content(values: &[&str]) -> Result<ContentEncodingList, &'static str> {
    parse_content_encoding(values.iter().map(|value| value.as_bytes()))
}

#[test]
fn accept_encoding_advertises_explicit_codings_with_nonzero_quality() -> TestResult {
    let advertised = accept(&["gzip;q=0.5, br, zstd;q=1.000"])?;
    assert!(advertised.contains(ContentCoding::Gzip));
    assert!(advertised.contains(ContentCoding::Brotli));
    assert!(advertised.contains(ContentCoding::Zstd));
    assert!(!advertised.contains(ContentCoding::Deflate));
    Ok(())
}

#[test]
fn accept_encoding_zero_quality_withdraws_a_coding_despite_wildcard() -> TestResult {
    let advertised = accept(&["*, br;q=0"])?;
    assert!(advertised.contains(ContentCoding::Gzip));
    assert!(!advertised.contains(ContentCoding::Brotli));
    Ok(())
}

#[test]
fn accept_encoding_wildcard_advertises_only_supported_codings() -> TestResult {
    let advertised = accept(&["*;q=0.1"])?;
    for coding in ContentCoding::ALL {
        assert!(advertised.contains(coding));
    }
    assert_eq!(accept(&["*;q=0"])?, AdvertisedContentCodings::default());
    Ok(())
}

#[test]
fn accept_encoding_x_gzip_advertises_gzip() -> TestResult {
    assert!(accept(&["X-GZIP"])?.contains(ContentCoding::Gzip));
    Ok(())
}

#[test]
fn accept_encoding_combines_field_lines_in_order() -> TestResult {
    let advertised = accept(&["gzip", "", "deflate, identity"])?;
    assert!(advertised.contains(ContentCoding::Gzip));
    assert!(advertised.contains(ContentCoding::Deflate));
    assert_eq!(
        accept(&["gzip", "gzip;q=0"]),
        Err("Accept-Encoding repeats a member")
    );
    Ok(())
}

#[test]
fn accept_encoding_rejects_malformed_quality_and_unknown_parameters() {
    for value in [
        "gzip;q=2",
        "gzip;q=1.001",
        "gzip;q=0.0001",
        "gzip;q=",
        "gzip;level=1",
        "gzip;q=0.5;x=1",
        "g zip",
        "gzip;",
    ] {
        assert!(accept(&[value]).is_err(), "{value} was accepted");
    }
}

#[test]
fn accept_encoding_rejects_duplicate_members_for_one_coding() {
    assert!(accept(&["gzip, x-gzip"]).is_err());
    assert!(accept(&["*, *;q=0"]).is_err());
    assert!(accept(&["identity, identity"]).is_err());
}

#[test]
fn content_encoding_tokens_are_case_insensitive_and_trimmed() -> TestResult {
    assert_eq!(
        content(&[" GZip ,\tBR"])?,
        ContentEncodingList::Codings(vec![ContentCoding::Gzip, ContentCoding::Brotli])
    );
    Ok(())
}

#[test]
fn content_encoding_ignores_empty_list_elements() -> TestResult {
    assert_eq!(
        content(&[",, zstd ,", ""])?,
        ContentEncodingList::Codings(vec![ContentCoding::Zstd])
    );
    Ok(())
}

#[test]
fn content_encoding_identity_only_passes_through() -> TestResult {
    assert_eq!(
        content(&["identity", "IDENTITY"])?,
        ContentEncodingList::Identity
    );
    assert_eq!(content(&[])?, ContentEncodingList::Identity);
    Ok(())
}

#[test]
fn content_encoding_identity_mixed_with_a_coding_is_rejected() {
    assert!(content(&["identity, gzip"]).is_err());
}

#[test]
fn content_encoding_unknown_coding_is_rejected() {
    for value in ["compress", "dcb", "dcz", "gzip;q=1"] {
        assert!(content(&[value]).is_err(), "{value} was accepted");
    }
}

#[test]
fn content_encoding_more_than_three_codings_is_rejected() -> TestResult {
    assert!(content(&["gzip, br, zstd"]).is_ok());
    assert!(content(&["gzip, br", "zstd, deflate"]).is_err());
    Ok(())
}

#[test]
fn content_encoding_non_ascii_value_is_rejected() {
    let values: [&[u8]; 1] = [b"gzip\xff"];
    assert!(parse_content_encoding(values).is_err());
}

#[test]
fn gzip_decodes_across_single_byte_input_chunks() -> TestResult {
    let data = payload(200);
    let decoded = decode_chunks(
        &[ContentCoding::Gzip],
        single_bytes(&gzip(&data)?),
        u64::MAX,
    )?;
    assert_eq!(decoded.data, data);
    Ok(())
}

#[test]
fn gzip_parses_every_optional_header_field() -> TestResult {
    let data = payload(10);
    let mut encoder = flate2::GzBuilder::new()
        .extra(b"extra".to_vec())
        .filename("name.txt")
        .comment("comment")
        .operating_system(3)
        .write(Vec::new(), Compression::default());
    encoder.write_all(&data)?;
    let mut encoded = encoder.finish()?;
    // Set FHCRC and insert the header CRC16 before the compressed data.
    let header_end = 10 + 2 + 5 + b"name.txt\0".len() + b"comment\0".len();
    encoded[3] |= 0x02;
    let mut crc = flate2::Crc::new();
    crc.update(&encoded[..header_end]);
    let crc16 = u16::try_from(crc.sum() & 0xffff)?.to_le_bytes();
    encoded.splice(header_end..header_end, crc16);

    assert_eq!(decode(&[ContentCoding::Gzip], &encoded)?, data);

    encoded[header_end] ^= 0xff;
    assert_eq!(
        decoding_error_kind(decode(&[ContentCoding::Gzip], &encoded)),
        Some(RequestErrorKind::ContentDecoding)
    );
    Ok(())
}

#[test]
fn gzip_rejects_crc_and_isize_mismatch() -> TestResult {
    let encoded = gzip(&payload(4))?;
    let crc_offset = encoded.len() - 8;
    for offset in [crc_offset, crc_offset + 4] {
        let mut corrupted = encoded.clone();
        corrupted[offset] ^= 0x01;
        assert_eq!(
            decoding_error_kind(decode(&[ContentCoding::Gzip], &corrupted)),
            Some(RequestErrorKind::ContentDecoding)
        );
    }
    Ok(())
}

#[test]
fn gzip_rejects_truncated_footer() -> TestResult {
    let encoded = gzip(&payload(4))?;
    assert_eq!(
        decoding_error_kind(decode(
            &[ContentCoding::Gzip],
            &encoded[..encoded.len() - 1]
        )),
        Some(RequestErrorKind::ContentDecoding)
    );
    Ok(())
}

#[test]
fn gzip_rejects_bytes_after_the_first_member() -> TestResult {
    let mut encoded = gzip(b"first")?;
    encoded.extend(gzip(b"second")?);
    assert_eq!(
        decoding_error_kind(decode(&[ContentCoding::Gzip], &encoded)),
        Some(RequestErrorKind::ContentDecoding)
    );
    Ok(())
}

#[test]
fn deflate_accepts_zlib_wrapped_stream() -> TestResult {
    let data = payload(50);
    let decoded = decode_chunks(
        &[ContentCoding::Deflate],
        single_bytes(&zlib(&data)?),
        u64::MAX,
    )?;
    assert_eq!(decoded.data, data);
    Ok(())
}

#[test]
fn deflate_accepts_raw_stream() -> TestResult {
    let data = payload(50);
    let encoded = raw_deflate(&data)?;
    assert!(!super::inflate::is_zlib_header([encoded[0], encoded[1]]));
    assert_eq!(decode(&[ContentCoding::Deflate], &encoded)?, data);
    Ok(())
}

#[test]
fn deflate_rejects_adler32_mismatch() -> TestResult {
    let mut encoded = zlib(&payload(5))?;
    let last = encoded.len() - 1;
    encoded[last] ^= 0x01;
    assert_eq!(
        decoding_error_kind(decode(&[ContentCoding::Deflate], &encoded)),
        Some(RequestErrorKind::ContentDecoding)
    );
    Ok(())
}

#[test]
fn deflate_rejects_preset_dictionary() {
    // CMF 0x78 with FDICT set and a valid FCHECK: 0x78BB % 31 == 0.
    let encoded = [0x78, 0xbb, 0, 0, 0, 1, 0x03, 0x00];
    assert_eq!(
        decoding_error_kind(decode(&[ContentCoding::Deflate], &encoded)),
        Some(RequestErrorKind::ContentDecoding)
    );
}

#[test]
fn deflate_rejects_bytes_after_its_stream() -> TestResult {
    let mut encoded = zlib(b"body")?;
    encoded.push(0);
    assert_eq!(
        decoding_error_kind(decode(&[ContentCoding::Deflate], &encoded)),
        Some(RequestErrorKind::ContentDecoding)
    );
    Ok(())
}

#[test]
fn brotli_decodes_across_chunk_boundaries() -> TestResult {
    let data = payload(300);
    let encoded = brotli(&data)?;
    let chunks = encoded.chunks(7).map(<[u8]>::to_vec);
    assert_eq!(
        decode_chunks(&[ContentCoding::Brotli], chunks, u64::MAX)?.data,
        data
    );
    Ok(())
}

#[test]
fn brotli_rejects_trailing_bytes() -> TestResult {
    let mut encoded = brotli(b"body")?;
    encoded.push(0);
    assert_eq!(
        decoding_error_kind(decode(&[ContentCoding::Brotli], &encoded)),
        Some(RequestErrorKind::ContentDecoding)
    );
    Ok(())
}

#[test]
fn brotli_rejects_truncated_stream() -> TestResult {
    let encoded = brotli(&payload(100))?;
    assert_eq!(
        decoding_error_kind(decode(
            &[ContentCoding::Brotli],
            &encoded[..encoded.len() / 2]
        )),
        Some(RequestErrorKind::ContentDecoding)
    );
    Ok(())
}

#[test]
fn zstd_decodes_concatenated_and_skippable_frames() -> TestResult {
    let mut encoded = zstd(b"first ")?;
    // RFC 8878 §3.1.2 skippable frame: magic 0x184D2A5A, 3-byte user data.
    encoded.extend_from_slice(&[0x5a, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 1, 2, 3]);
    encoded.extend(zstd(b"second")?);
    assert_eq!(
        decode_chunks(&[ContentCoding::Zstd], single_bytes(&encoded), u64::MAX)?.data,
        b"first second"
    );
    Ok(())
}

#[test]
fn zstd_rejects_legacy_frame_magic() -> TestResult {
    let mut encoded = zstd(b"first")?;
    encoded.extend_from_slice(&[0x27, 0xb5, 0x2f, 0xfd, 0, 0, 0, 0]);
    assert_eq!(
        decoding_error_kind(decode(&[ContentCoding::Zstd], &encoded)),
        Some(RequestErrorKind::ContentDecoding)
    );
    Ok(())
}

#[test]
fn zstd_rejects_window_larger_than_eight_mebibytes() -> TestResult {
    let mut encoder = zstd::stream::raw::Encoder::new(3)?;
    encoder.set_parameter(CParameter::WindowLog(24))?;
    encoder.set_parameter(CParameter::ContentSizeFlag(false))?;
    let mut writer = zstd::stream::zio::Writer::new(Vec::new(), encoder);
    writer.write_all(&payload(1_000))?;
    writer.finish()?;
    let (encoded, _) = writer.into_inner();
    assert_eq!(
        decoding_error_kind(decode(&[ContentCoding::Zstd], &encoded)),
        Some(RequestErrorKind::ContentDecoding)
    );
    Ok(())
}

#[test]
fn zstd_rejects_truncated_frame() -> TestResult {
    let encoded = zstd(&payload(100))?;
    assert_eq!(
        decoding_error_kind(decode(
            &[ContentCoding::Zstd],
            &encoded[..encoded.len() - 2]
        )),
        Some(RequestErrorKind::ContentDecoding)
    );
    Ok(())
}

#[test]
fn stacked_gzip_then_br_decodes_in_reverse_application_order() -> TestResult {
    let data = payload(100);
    let encoded = brotli(&gzip(&data)?)?;
    // `Content-Encoding: gzip, br` lists gzip first because it was applied first.
    let decoded = decode_chunks(
        &[ContentCoding::Gzip, ContentCoding::Brotli],
        encoded.chunks(5).map(<[u8]>::to_vec),
        u64::MAX,
    )?;
    assert_eq!(decoded.data, data);
    Ok(())
}

#[test]
fn decoded_frames_never_exceed_frame_size() -> TestResult {
    let data = vec![b'a'; DECODED_FRAME_BYTES * 5 + 3];
    for (coding, encoded) in [
        (ContentCoding::Gzip, gzip(&data)?),
        (ContentCoding::Deflate, zlib(&data)?),
        (ContentCoding::Brotli, brotli(&data)?),
        (ContentCoding::Zstd, zstd(&data)?),
    ] {
        let decoded = decode_chunks(&[coding], [encoded], u64::MAX)?;
        assert_eq!(decoded.data, data, "{coding:?}");
        assert!(decoded.largest_frame <= DECODED_FRAME_BYTES, "{coding:?}");
    }
    Ok(())
}

#[test]
fn decoded_limit_is_inclusive() -> TestResult {
    let data = payload(10);
    let length = u64::try_from(data.len())?;
    let encoded = gzip(&data)?;
    assert_eq!(
        decode_chunks(&[ContentCoding::Gzip], [encoded.clone()], length)?.data,
        data
    );
    let Err(error) = decode_chunks(&[ContentCoding::Gzip], [encoded], length - 1) else {
        return Err("decoded stream beyond the cap was accepted".into());
    };
    assert_eq!(error.kind(), RequestErrorKind::ResponseBodyLimit);
    Ok(())
}

#[test]
fn high_ratio_stream_fails_at_limit_without_buffering_beyond_one_frame() -> TestResult {
    let data = vec![0_u8; 64 << 20];
    let encoded = zstd(&data)?;
    assert!(encoded.len() < 64 << 10);
    let mut decoder = ContentDecoder::new(&[ContentCoding::Zstd], 1 << 20, HttpProtocol::Http2)?;
    decoder.push(Bytes::from(encoded));
    decoder.end_input();
    let mut total = 0_usize;
    loop {
        match decoder.pump() {
            Ok(Pump::Data(data)) => {
                assert!(data.len() <= DECODED_FRAME_BYTES);
                total += data.len();
            }
            Ok(other) => return Err(format!("unexpected {other:?}").into()),
            Err(error) => {
                assert_eq!(error.kind(), RequestErrorKind::ResponseBodyLimit);
                assert_eq!(error.protocol(), Some(HttpProtocol::Http2));
                assert_eq!(total, 1 << 20);
                return Ok(());
            }
        }
    }
}

#[test]
fn empty_encoded_body_decodes_to_empty() -> TestResult {
    for coding in ContentCoding::ALL {
        assert!(decode(&[coding], &[])?.is_empty(), "{coding:?}");
    }
    Ok(())
}

fn content_encoding_headers(value: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_ENCODING, HeaderValue::from_static(value));
    headers
}

#[test]
fn plan_passes_through_bodyless_and_disabled_responses() -> TestResult {
    let headers = content_encoding_headers("compress");
    let advertised = AdvertisedContentCodings::default();
    let enabled = ContentDecoding::advertised(1);
    for (policy, method, status, empty) in [
        (ContentDecoding::none(), Method::GET, StatusCode::OK, false),
        (enabled, Method::HEAD, StatusCode::OK, false),
        (enabled, Method::GET, StatusCode::NO_CONTENT, false),
        (enabled, Method::GET, StatusCode::NOT_MODIFIED, false),
        (enabled, Method::GET, StatusCode::OK, true),
    ] {
        let decision = plan(
            policy,
            advertised,
            &method,
            status,
            &headers,
            empty,
            HttpProtocol::Http1,
        );
        assert!(matches!(decision, ContentDecodingPlan::Passthrough));
    }
    Ok(())
}

#[test]
fn plan_rejects_unadvertised_coding() -> TestResult {
    let headers = content_encoding_headers("br");
    let advertised = AdvertisedContentCodings::from_request_headers(&[RequestHeader::new(
        "Accept-Encoding",
        "gzip",
    )])?;
    let decision = plan(
        ContentDecoding::advertised(1),
        advertised,
        &Method::GET,
        StatusCode::OK,
        &headers,
        false,
        HttpProtocol::Http3,
    );
    let ContentDecodingPlan::Reject(error) = decision else {
        return Err("unadvertised coding was not rejected".into());
    };
    assert_eq!(error.kind(), RequestErrorKind::ContentDecoding);
    assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
    Ok(())
}
