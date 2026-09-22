//! Deterministic regressions for the HTTP/1.1 response harness.

use phantom_net::http1::Http1Error;

use super::{MAX_REQUESTS, VALID_RESPONSES, drive};

/// Read sizes that bracket the harness: one byte per read, a size that lands
/// mid-field, and a single whole-buffer read.
const CHUNKS: [usize; 3] = [1, 7, usize::MAX];

/// Response-head bytes the observer buffers before it reports the limit,
/// mirroring `MAX_RESPONSE_HEAD_BYTES` in `phantom-net`.
const MAX_RESPONSE_HEAD_BYTES: usize = 32 * 1024;

/// Fields the observer accepts before it reports the count limit, mirroring
/// `MAX_RESPONSE_HEADERS` in `phantom-net`.
const MAX_RESPONSE_HEADERS: usize = 100;

/// Builds a response whose head exceeds the observer's byte limit while
/// staying under its field-count limit, so the byte limit is what reports.
fn oversized_head() -> Vec<u8> {
    let value = "v".repeat(2 * 1024);
    let mut response = b"HTTP/1.1 200 OK\r\n".to_vec();
    let mut index = 0;
    while response.len() <= MAX_RESPONSE_HEAD_BYTES {
        response.extend_from_slice(format!("x-pad-{index}: {value}\r\n").as_bytes());
        index += 1;
    }
    assert!(
        index < MAX_RESPONSE_HEADERS,
        "the field count limit reports first"
    );
    response.extend_from_slice(b"\r\n");
    response
}

/// Builds a response with more fields than the observer accepts, each short
/// enough that the aggregate stays under its byte limit.
fn too_many_headers() -> Vec<u8> {
    let mut response = b"HTTP/1.1 200 OK\r\n".to_vec();
    for index in 0..=MAX_RESPONSE_HEADERS {
        response.extend_from_slice(format!("x-pad-{index}: v\r\n").as_bytes());
    }
    assert!(
        response.len() < MAX_RESPONSE_HEAD_BYTES,
        "the byte limit reports first"
    );
    response.extend_from_slice(b"\r\n");
    response
}

/// Every embedded seed must stay a response the production parser accepts, at
/// every read boundary. A seed that stopped parsing would leave the fuzz target
/// perturbing bytes that never reach the parser, and nothing would say so.
#[test]
fn structural_seeds_parse_at_every_read_boundary() {
    for (index, seed) in VALID_RESPONSES.iter().enumerate() {
        for chunk in CHUNKS {
            drive(&[seed], chunk).unwrap_or_else(|error| {
                panic!("seed {index} failed at chunk {chunk}: {error:?}");
            });
        }
    }
}

/// A reused connection must reach a second response head, which is what resets
/// the ordered-header observer between transactions. Reaching only end of
/// stream would exercise reuse after close instead.
#[test]
fn a_reused_connection_parses_a_second_response() {
    for (index, seed) in VALID_RESPONSES.iter().enumerate() {
        for chunk in CHUNKS {
            let scripted = vec![*seed; MAX_REQUESTS];
            drive(&scripted, chunk).unwrap_or_else(|error| {
                panic!("seed {index} failed on a reused connection at chunk {chunk}: {error:?}");
            });
        }
    }
}

/// The fuzz target's `-max_len` keeps every generated response below
/// `MAX_RESPONSE_HEAD_BYTES`, because the observer and the protocol engine both
/// reparse their buffered head on every read and a longer head with one-byte
/// reads costs quadratic time. The head-byte limit is therefore unreachable
/// under fuzzing and is pinned here instead.
#[test]
fn an_oversized_response_head_is_rejected() {
    for chunk in CHUNKS {
        let response = oversized_head();
        let error = drive(&[&response], chunk).expect_err("an oversized head must be rejected");
        assert!(
            matches!(error, Http1Error::ResponseHeadTooLarge { .. }),
            "unexpected error at chunk {chunk}: {error:?}"
        );
    }
}

/// The field-count limit is unreachable under the fuzz target's `-max_len` for
/// the same reason as the byte limit, so it is pinned here too.
#[test]
fn too_many_response_headers_are_rejected() {
    for chunk in CHUNKS {
        let response = too_many_headers();
        let error = drive(&[&response], chunk).expect_err("excess fields must be rejected");
        assert!(
            matches!(error, Http1Error::TooManyResponseHeaders { .. }),
            "unexpected error at chunk {chunk}: {error:?}"
        );
    }
}
