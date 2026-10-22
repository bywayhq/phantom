//! Production coding-field parsing and chained decoding under DATA partitions.

use phantom::{ContentDecoding, FuzzContentDecode, fuzz_content_decode};

use crate::seed;

const MAXIMUM_BYTES: usize = 64 * 1024;
const MAXIMUM_PUMPS: usize = 4096;
const ADVERTISED: &[&[u8]] = &[b"gzip, deflate, br, zstd"];

// Literal streams all decode to "hello". Gzip uses a stored DEFLATE block;
// zstd uses a raw last block. The final seed wraps that gzip member in zstd.
const GZIP: &[u8] =
    b"\x1f\x8b\x08\0\0\0\0\0\0\xff\x01\x05\0\xfa\xffhello\x86\xa6\x10\x36\x05\0\0\0";
const SEEDS: [(&[&[u8]], &[u8]); 6] = [
    (&[b"gzip"], GZIP),
    (&[b"deflate"], b"\x78\x9c\xcb\x48\xcd\xc9\xc9\x07\0\x06\x2c\x02\x15"),
    (&[b"deflate"], b"\x01\x05\0\xfa\xffhello"),
    (&[b"br"], b"\x0b\x02\x80hello\x03"),
    (&[b"zstd"], b"\x28\xb5\x2f\xfd\x20\x05\x29\0\0hello"),
    (
        &[b"gzip", b"zstd"],
        b"\x28\xb5\x2f\xfd\x20\x1c\xe1\0\0\x1f\x8b\x08\0\0\0\0\0\0\xff\x01\x05\0\xfa\xffhello\x86\xa6\x10\x36\x05\0\0\0",
    ),
];

/// Checks arbitrary fields/body and a separately perturbed literal coded stream.
///
/// Nine control bytes select field modes/lengths, cap, seed and two chunk sizes.
/// Header bytes precede the body; mutation offsets come only from body bytes.
pub fn exercise(input: &[u8]) {
    let input = &input[..input.len().min(MAXIMUM_BYTES)];
    let control = |index| input.get(index).copied().unwrap_or(0);
    let remaining = input.get(9..).unwrap_or_default();
    let (request, remaining) = remaining.split_at(usize::from(control(2)).min(remaining.len()));
    let (response, body) = remaining.split_at(usize::from(control(3)).min(remaining.len()));
    let request_values = match control(0) % 3 {
        0 => ADVERTISED.to_vec(),
        1 => vec![&b"*;q=0.5, gzip;q=0"[..]],
        _ => fields(request),
    };
    let response_values = match control(1) % 8 {
        0 => vec![&b"gzip"[..]],
        1 => vec![&b"deflate"[..]],
        2 => vec![&b"br"[..]],
        3 => vec![&b"zstd"[..]],
        4 => vec![&b"gzip"[..], &b"zstd"[..]],
        5 => vec![&b"identity"[..]],
        6 => vec![&b"unknown"[..]],
        _ => fields(response),
    };
    let maximum = if control(0) & 0x80 != 0 {
        MAXIMUM_BYTES as u64
    } else {
        u64::from(u16::from_le_bytes([control(4), control(5)]))
    };
    let policy = if control(0) & 0x40 != 0 {
        ContentDecoding::none()
    } else {
        ContentDecoding::advertised(maximum)
    };
    let chunks = [usize::from(control(7)) + 1, usize::from(control(8)) + 1];
    check_partitions(&request_values, &response_values, body, policy, &chunks);

    let (codings, encoded) = SEEDS[usize::from(control(6)) % SEEDS.len()];
    let structured = seed::perturb(encoded, body);
    check_partitions(
        ADVERTISED,
        codings,
        &structured,
        ContentDecoding::advertised(maximum),
        &chunks,
    );
}

fn fields(value: &[u8]) -> Vec<&[u8]> {
    value.split(|byte| *byte == 0).take(4).collect()
}

fn decode(
    request: &[&[u8]],
    response: &[&[u8]],
    body: &[u8],
    policy: ContentDecoding,
    chunks: &[usize],
) -> FuzzContentDecode {
    let outcome = fuzz_content_decode(request, response, body, chunks, policy, MAXIMUM_PUMPS)
        .unwrap_or_else(|error| {
            panic!("bounded content-coding harness rejected its input: {error}")
        });
    if let FuzzContentDecode::Complete {
        data,
        largest_frame,
    } = &outcome
    {
        assert!(*largest_frame <= 16 * 1024, "decoded frame exceeds 16 KiB");
        assert!(
            policy
                .maximum_decoded_bytes()
                .is_some_and(|maximum| data.len() as u64 <= maximum),
            "completed decoded body exceeds its inclusive cap"
        );
    }
    outcome
}

fn check_partitions(
    request: &[&[u8]],
    response: &[&[u8]],
    body: &[u8],
    policy: ContentDecoding,
    chunks: &[usize],
) {
    // Small streams get bytewise coverage; larger ones keep input work bounded.
    let fixed = if body.len() <= 1024 { 1 } else { 32 };
    let mut completed = None;
    let mut rejected = false;
    for partition in [&[MAXIMUM_BYTES][..], &[fixed], chunks] {
        match decode(request, response, body, policy, partition) {
            FuzzContentDecode::Complete { data, .. } => {
                assert!(
                    !rejected,
                    "chunking changed rejected data into a complete stream"
                );
                if let Some(previous) = &completed {
                    assert_eq!(&data, previous, "chunking changed completed decoded bytes");
                }
                completed = Some(data);
            }
            FuzzContentDecode::WorkLimit => {}
            _ => {
                assert!(
                    completed.is_none(),
                    "chunking rejected a complete decoded stream"
                );
                rejected = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use phantom::RequestErrorKind;

    use super::*;

    fn complete(response: &[&[u8]], body: &[u8], chunks: &[usize], maximum: u64) -> Vec<u8> {
        match decode(
            ADVERTISED,
            response,
            body,
            ContentDecoding::advertised(maximum),
            chunks,
        ) {
            FuzzContentDecode::Complete { data, .. } => data,
            other => panic!("literal content-coding stream did not complete: {other:?}"),
        }
    }

    #[test]
    fn literal_streams_decode_and_enforce_the_inclusive_cap_across_chunks() {
        for (response, encoded) in SEEDS {
            for chunks in [&[MAXIMUM_BYTES][..], &[1], &[2, 3, 7]] {
                assert_eq!(complete(response, encoded, chunks, 5), b"hello");
                for maximum in [0, 4] {
                    assert_eq!(
                        decode(
                            ADVERTISED,
                            response,
                            encoded,
                            ContentDecoding::advertised(maximum),
                            chunks
                        ),
                        FuzzContentDecode::Failed(RequestErrorKind::ResponseBodyLimit)
                    );
                }
            }
        }
    }

    #[test]
    fn every_nonempty_truncated_literal_stream_is_rejected_at_eof() {
        for (response, encoded) in SEEDS {
            for length in 1..encoded.len() {
                for chunks in [&[MAXIMUM_BYTES][..], &[1], &[2, 3]] {
                    assert_eq!(
                        decode(
                            ADVERTISED,
                            response,
                            &encoded[..length],
                            ContentDecoding::advertised(64),
                            chunks
                        ),
                        FuzzContentDecode::Failed(RequestErrorKind::ContentDecoding),
                        "truncated {response:?} at {length} bytes with {chunks:?} chunks"
                    );
                }
            }
        }
    }

    #[test]
    fn ordered_coding_fields_and_advertisement_rules_reach_the_production_plan() {
        let (_, stacked) = SEEDS[5];
        assert_eq!(complete(&[b"GZip", b"ZSTD"], stacked, &[1], 5), b"hello");
        for response in [
            &[&b"zstd"[..], &b"gzip"[..]][..],
            &[b"identity, gzip"],
            &[b"gzip, gzip, gzip, gzip"],
        ] {
            assert_eq!(
                decode(
                    ADVERTISED,
                    response,
                    stacked,
                    ContentDecoding::advertised(64),
                    &[1]
                ),
                FuzzContentDecode::Failed(RequestErrorKind::ContentDecoding)
            );
        }
        assert_eq!(
            decode(
                &[b"*;q=1", b"gzip;q=0"],
                &[b"gzip"],
                GZIP,
                ContentDecoding::advertised(5),
                &[1]
            ),
            FuzzContentDecode::Failed(RequestErrorKind::ContentDecoding)
        );
        assert_eq!(
            decode(
                &[b"gzip;q=2"],
                &[b"gzip"],
                GZIP,
                ContentDecoding::advertised(5),
                &[1]
            ),
            FuzzContentDecode::Failed(RequestErrorKind::InvalidHeader)
        );
        assert_eq!(
            decode(
                ADVERTISED,
                &[b"identity"],
                GZIP,
                ContentDecoding::advertised(0),
                &[1]
            ),
            FuzzContentDecode::Passthrough
        );
        assert_eq!(
            decode(
                ADVERTISED,
                &[b"gzip"],
                b"malformed",
                ContentDecoding::none(),
                &[1]
            ),
            FuzzContentDecode::Passthrough
        );
        assert_eq!(
            decode(
                ADVERTISED,
                &[b"gzip\r\n"],
                GZIP,
                ContentDecoding::advertised(5),
                &[1]
            ),
            FuzzContentDecode::InvalidResponseField
        );
    }

    #[test]
    fn a_short_work_budget_is_inconclusive_even_for_a_valid_stream() {
        for budget in [0, 1, 2] {
            assert_eq!(
                fuzz_content_decode(
                    ADVERTISED,
                    &[b"gzip"],
                    GZIP,
                    &[1],
                    ContentDecoding::advertised(5),
                    budget
                ),
                Ok(FuzzContentDecode::WorkLimit)
            );
        }
        assert_eq!(complete(&[b"gzip"], GZIP, &[1], 5), b"hello");
    }

    #[test]
    fn harness_bounds_reject_oversized_or_nonprogressing_arguments() {
        let policy = ContentDecoding::advertised(64);
        for chunks in [vec![], vec![0], vec![MAXIMUM_BYTES + 1], vec![1; 65]] {
            assert!(
                fuzz_content_decode(ADVERTISED, &[b"gzip"], GZIP, &chunks, policy, MAXIMUM_PUMPS)
                    .is_err()
            );
        }
        assert!(
            fuzz_content_decode(
                ADVERTISED,
                &[b"gzip"],
                &vec![0; MAXIMUM_BYTES + 1],
                &[1],
                policy,
                1
            )
            .is_err()
        );
        assert!(
            fuzz_content_decode(
                ADVERTISED,
                &[b"gzip"],
                GZIP,
                &[1],
                ContentDecoding::advertised(MAXIMUM_BYTES as u64 + 1),
                1
            )
            .is_err()
        );
        assert!(
            fuzz_content_decode(&[&b"gzip"[..]; 5], &[b"gzip"], GZIP, &[1], policy, 1).is_err()
        );
        assert!(fuzz_content_decode(ADVERTISED, &[&[b'x'; 1025]], GZIP, &[1], policy, 1).is_err());
        assert!(
            fuzz_content_decode(
                ADVERTISED,
                &[b"gzip"],
                GZIP,
                &[1],
                policy,
                MAXIMUM_PUMPS + 1
            )
            .is_err()
        );
        exercise(&vec![u8::MAX; MAXIMUM_BYTES]);
        exercise(&[]);
    }
}
