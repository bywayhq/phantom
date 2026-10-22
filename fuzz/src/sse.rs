//! Production SSE decoding under different DATA chunk boundaries.
//!
//! The optional `phantom/fuzzing` batch seam drives the same private decoder
//! as `SseStream`. This target compares emitted prefixes, the first error kind,
//! and retained reconnect state; it does not exercise HTTP or reconnect timing.

use std::time::Duration;

use phantom::{SseErrorKind, SseEvent, SseLimits, fuzz_sse_decode};

use crate::seed;

const MAXIMUM_BYTES: usize = 64 * 1024;
const SEEDS: [&[u8]; 5] = [
    b"\xef\xbb\xbf: heartbeat\rretry: 1500\r\nid: first\ndata: one\rdata: two\r\n\r\n",
    b"data: \xe2\x82\xac\ndata: \xff\n\n",
    b"id: kept\n\nid: ignored\0value\nevent: update\ndata: next\n\n",
    b"retry: 18446744073709551615\nretry: 18446744073709551616\ndata: max\n\n",
    b"id: kept\n\nretry: 9\nid: pending\ndata: incomplete\n",
];

type Trace = (
    Vec<SseEvent>,
    Option<SseErrorKind>,
    String,
    Option<Duration>,
);

/// Checks raw bytes and one perturbed structural seed against three partitions.
///
/// Seven control bytes select line/event limits, two cyclic chunk sizes, and a
/// seed. The remaining bytes are payload, including the seed mutation offset.
pub fn exercise(input: &[u8]) {
    let input = &input[..input.len().min(MAXIMUM_BYTES)];
    let control = |index| input.get(index).copied().unwrap_or(0);
    let limits = SseLimits::new(
        usize::from(u16::from_le_bytes([control(0), control(1)])) % 4097,
        usize::from(u16::from_le_bytes([control(2), control(3)])) % 4097,
    );
    let chunks = [usize::from(control(4)) + 1, usize::from(control(5)) + 1];
    let payload = input.get(7..).unwrap_or_default();
    check_partitions(payload, limits, &chunks);
    let structured = seed::perturb(SEEDS[usize::from(control(6)) % SEEDS.len()], payload);
    check_partitions(&structured, limits, &chunks);
}

fn decode(input: &[u8], limits: SseLimits, chunks: &[usize]) -> Trace {
    fuzz_sse_decode(input, chunks, limits)
        .unwrap_or_else(|error| panic!("bounded SSE harness rejected its input: {error}"))
}

fn check_partitions(input: &[u8], limits: SseLimits, chunks: &[usize]) {
    let whole = decode(input, limits, &[MAXIMUM_BYTES]);
    assert_eq!(whole, decode(input, limits, &[1]), "bytewise SSE partition");
    assert_eq!(whole, decode(input, limits, chunks), "cyclic SSE partition");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expected(data: &str, event: &str, id: &str) -> (String, String, String) {
        (data.to_owned(), event.to_owned(), id.to_owned())
    }

    fn fields(events: &[SseEvent]) -> Vec<(String, String, String)> {
        events
            .iter()
            .map(|event| expected(event.data(), event.event(), event.id()))
            .collect()
    }

    #[test]
    fn literal_seeds_keep_event_and_reconnect_semantics() {
        let cases = [
            (
                vec![expected("one\ntwo", "message", "first")],
                "first",
                Some(Duration::from_millis(1500)),
            ),
            (vec![expected("€\n�", "message", "")], "", None),
            (vec![expected("next", "update", "kept")], "kept", None),
            (
                vec![expected("max", "message", "")],
                "",
                Some(Duration::from_millis(u64::MAX)),
            ),
            (vec![], "kept", Some(Duration::from_millis(9))),
        ];
        for (seed, (events, id, retry)) in SEEDS.iter().zip(cases) {
            for chunks in [&[1][..], &[2, 3, 7], &[MAXIMUM_BYTES]] {
                let trace = decode(seed, SseLimits::new(256, 1024), chunks);
                assert_eq!(fields(&trace.0), events);
                assert_eq!(trace.1, None);
                assert_eq!(trace.2, id);
                assert_eq!(trace.3, retry);
            }
        }
    }

    #[test]
    fn encoded_limits_exclude_terminators_and_accept_the_exact_boundary() {
        // The literal line "data:x" is six encoded bytes; CRLF is excluded.
        for chunks in [&[1][..], &[2, 3], &[MAXIMUM_BYTES]] {
            let exact = decode(b"data:x\r\n\r\n", SseLimits::new(6, 6), chunks);
            assert_eq!(fields(&exact.0), [expected("x", "message", "")]);
            assert_eq!(exact.1, None);
            assert_eq!(
                decode(b"data:x\r\n\r\n", SseLimits::new(5, 6), chunks).1,
                Some(SseErrorKind::LineTooLong)
            );
            assert_eq!(
                decode(b"data:x\r\n\r\n", SseLimits::new(6, 5), chunks).1,
                Some(SseErrorKind::EventTooLarge)
            );
        }
    }

    #[test]
    fn comments_and_unknown_fields_consume_the_event_byte_limit() {
        // Four comment bytes plus three unknown-field bytes, excluding LF.
        let input = b":abc\nx:y\n\n";
        assert_eq!(decode(input, SseLimits::new(4, 7), &[1]).1, None);
        assert_eq!(
            decode(input, SseLimits::new(4, 6), &[1]).1,
            Some(SseErrorKind::EventTooLarge)
        );
    }

    #[test]
    fn zero_limits_allow_only_empty_lines() {
        let empty = decode(b"\r\n\n", SseLimits::new(0, 0), &[1]);
        assert!(empty.0.is_empty());
        assert_eq!(empty.1, None);
        assert_eq!(
            decode(b"x", SseLimits::new(0, 8), &[1]).1,
            Some(SseErrorKind::LineTooLong)
        );
        assert_eq!(
            decode(b":\n", SseLimits::new(8, 0), &[1]).1,
            Some(SseErrorKind::EventTooLarge)
        );
    }

    #[test]
    fn error_retains_the_dispatched_prefix_and_discards_pending_id() {
        let input = b"id:a\ndata:x\n\nid:b\nxxxxxxx";
        let trace = decode(input, SseLimits::new(6, 16), &[2, 3]);
        assert_eq!(fields(&trace.0), [expected("x", "message", "a")]);
        assert_eq!(trace.1, Some(SseErrorKind::LineTooLong));
        assert_eq!(trace.2, "a");
        check_partitions(input, SseLimits::new(6, 16), &[2, 3]);
    }

    #[test]
    fn adapter_rejects_unbounded_or_nonprogressing_harness_arguments() {
        let limits = SseLimits::new(MAXIMUM_BYTES, MAXIMUM_BYTES);
        assert!(fuzz_sse_decode(&vec![b'x'; MAXIMUM_BYTES + 1], &[1], limits).is_err());
        for chunks in [vec![], vec![0], vec![MAXIMUM_BYTES + 1], vec![1; 65]] {
            assert!(fuzz_sse_decode(b"", &chunks, limits).is_err());
        }
        for limits in [
            SseLimits::new(MAXIMUM_BYTES + 1, 1),
            SseLimits::new(1, MAXIMUM_BYTES + 1),
        ] {
            assert!(fuzz_sse_decode(b"", &[1], limits).is_err());
        }
        assert_eq!(
            decode(b"", SseLimits::new(0, 0), &[1]),
            (vec![], None, String::new(), None)
        );
    }

    #[test]
    fn maximum_input_and_adversarial_control_values_stay_within_the_adapter() {
        let trace = decode(&vec![b'\n'; MAXIMUM_BYTES], SseLimits::new(0, 0), &[1]);
        assert_eq!(trace, (vec![], None, String::new(), None));
        for byte in [0, b'\n', b'\r', 0xff] {
            exercise(&vec![byte; MAXIMUM_BYTES]);
        }
        exercise(&[]);
        exercise(&[0xff; 7]);
    }
}
