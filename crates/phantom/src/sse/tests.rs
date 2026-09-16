use std::{error::Error, time::Duration};

use bytes::Bytes;

use super::{SseErrorKind, SseEvent, SseLimits, decoder::Decoder};

#[test]
fn fragmented_input_follows_event_stream_field_semantics() -> TestResult<()> {
    let input = concat!(
        "\u{feff}: heartbeat\r",
        "retry: 1500\r\n",
        "id: first\n",
        "event: update\r",
        "data: one:two\n",
        "data: three\r\n",
        "\r",
        "id: ignored\0value\n",
        "data: next\n\n",
        "id:\n\n",
        "retry: 12ms\n",
        "event: discarded\n\n",
        "data: final\n\n",
    );
    let mut decoder = Decoder::new(SseLimits::default());
    let mut events = Vec::new();

    for byte in input.as_bytes() {
        decoder.replace_chunk(Bytes::copy_from_slice(std::slice::from_ref(byte)));
        if let Some(event) = decoder.decode_available()? {
            events.push(event);
        }
    }

    assert_eq!(
        events,
        [
            event("one:two\nthree", "update", "first"),
            event("next", "message", "first"),
            event("final", "message", ""),
        ]
    );
    assert_eq!(decoder.last_event_id, "");
    assert_eq!(decoder.retry_delay, Some(Duration::from_millis(1500)));
    Ok(())
}

#[test]
fn utf8_is_reassembled_across_fragments_and_invalid_input_is_replaced() -> TestResult<()> {
    let mut decoder = Decoder::new(SseLimits::default());
    let mut decoded = None;
    for chunk in [
        &b"data: \xe2"[..],
        &b"\x82"[..],
        &b"\xac\n"[..],
        &b"data: \xff\n\n"[..],
    ] {
        decoder.replace_chunk(Bytes::copy_from_slice(chunk));
        decoded = decoder.decode_available()?.or(decoded);
    }

    assert_eq!(decoded, Some(event("€\n�", "message", "")));
    Ok(())
}

#[test]
fn only_a_leading_bom_is_removed() -> TestResult<()> {
    let events = decode_all("\u{feff}data: first\n\n\u{feff}data: ignored\ndata: second\n\n")?;

    assert_eq!(
        events,
        [
            event("first", "message", ""),
            event("second", "message", "")
        ]
    );
    Ok(())
}

#[test]
fn end_of_body_discards_an_unterminated_event() -> TestResult<()> {
    let mut decoder = Decoder::new(SseLimits::default());
    decoder.replace_chunk(Bytes::from_static(b"id: uncommitted\ndata: incomplete\n"));

    assert_eq!(decoder.decode_available()?, None);
    decoder.discard_pending();
    assert!(decoder.data.is_empty());
    assert!(decoder.last_event_id.is_empty());
    assert!(decoder.id_buffer.is_empty());
    Ok(())
}

#[test]
fn line_and_event_limits_fail_at_the_configured_boundary() -> TestResult<()> {
    let mut line_limited = Decoder::new(SseLimits::new(4, 128));
    line_limited.replace_chunk(Bytes::from_static(b"datax"));
    let error = line_limited
        .decode_available()
        .err()
        .ok_or("oversized line was accepted")?;
    assert_eq!(error.kind(), SseErrorKind::LineTooLong);

    let mut event_limited = Decoder::new(SseLimits::new(64, 10));
    event_limited.replace_chunk(Bytes::from_static(b"data: one\ndata:x\n\n"));
    let error = event_limited
        .decode_available()
        .err()
        .ok_or("oversized event was accepted")?;
    assert_eq!(error.kind(), SseErrorKind::EventTooLarge);
    Ok(())
}

fn decode_all(input: &str) -> Result<Vec<SseEvent>, super::SseError> {
    let mut decoder = Decoder::new(SseLimits::default());
    decoder.replace_chunk(Bytes::copy_from_slice(input.as_bytes()));
    let mut events = Vec::new();
    while let Some(event) = decoder.decode_available()? {
        events.push(event);
    }
    Ok(events)
}

fn event(data: &str, event: &str, id: &str) -> SseEvent {
    SseEvent {
        data: data.to_owned(),
        event: event.to_owned(),
        id: id.to_owned(),
    }
}

type TestResult<T> = Result<T, Box<dyn Error>>;
