use std::time::Duration;

use phantom_net::request::RequestHeader;

use crate::{HttpProtocol, SseErrorKind};

use super::{SseHeader, default_headers, effective_retry, resolve_template, validate_template};

#[test]
fn default_headers_preserve_protocol_spelling_and_order() {
    for (protocol, expected_names) in [
        (HttpProtocol::Http1, ["Accept", "Cache-Control"]),
        (HttpProtocol::Http2, ["accept", "cache-control"]),
        (HttpProtocol::Http3, ["accept", "cache-control"]),
    ] {
        let headers = resolve_template(&default_headers(protocol), protocol, "");
        assert_eq!(names(&headers), expected_names);
        assert_eq!(headers[0].value(), b"text/event-stream");
        assert_eq!(headers[1].value(), b"no-cache");
    }
}

#[test]
fn placeholder_emits_the_committed_id_at_its_position_with_caller_spelling() {
    let template = vec![
        field("Accept", "text/event-stream"),
        SseHeader::last_event_id("last-EVENT-id"),
        field("Referer", "http://origin.test/"),
    ];

    let headers = resolve_template(&template, HttpProtocol::Http1, "é-☃");

    assert_eq!(names(&headers), ["Accept", "last-EVENT-id", "Referer"]);
    assert_eq!(headers[1].value(), "é-☃".as_bytes());
}

#[test]
fn empty_committed_id_omits_the_placeholder_field() {
    let template = vec![
        field("Accept", "text/event-stream"),
        SseHeader::last_event_id("Last-Event-ID"),
        field("Referer", "http://origin.test/"),
    ];

    let headers = resolve_template(&template, HttpProtocol::Http1, "");

    assert_eq!(names(&headers), ["Accept", "Referer"]);
}

#[test]
fn template_without_placeholder_appends_a_nonempty_id_last() {
    for (protocol, expected) in [
        (HttpProtocol::Http1, "Last-Event-ID"),
        (HttpProtocol::Http2, "last-event-id"),
        (HttpProtocol::Http3, "last-event-id"),
    ] {
        let headers = resolve_template(&default_headers(protocol), protocol, "7");
        assert_eq!(headers.len(), 3);
        assert_eq!(headers[2].name(), expected);
        assert_eq!(headers[2].value(), b"7");
        assert_eq!(
            resolve_template(&default_headers(protocol), protocol, "").len(),
            2
        );
    }
}

#[test]
fn template_validation_rejects_literal_repeated_and_misspelled_last_event_id() {
    let rejected = [
        (HttpProtocol::Http1, vec![field("last-event-id", "caller")]),
        (
            HttpProtocol::Http1,
            vec![
                SseHeader::last_event_id("Last-Event-ID"),
                SseHeader::last_event_id("Last-Event-ID"),
            ],
        ),
        (
            HttpProtocol::Http1,
            vec![SseHeader::last_event_id("Last-Event")],
        ),
        (
            HttpProtocol::Http1,
            vec![SseHeader::last_event_id("Last-Event-ID ")],
        ),
        (
            HttpProtocol::Http2,
            vec![SseHeader::last_event_id("Last-Event-ID")],
        ),
        (
            HttpProtocol::Http3,
            vec![SseHeader::last_event_id("Last-Event-ID")],
        ),
    ];
    for (protocol, template) in rejected {
        let error = validate_template(&template, protocol)
            .err()
            .unwrap_or_else(|| panic!("{protocol:?} accepted {template:?}"));
        assert_eq!(error.kind(), SseErrorKind::InvalidRequestHeader);
    }

    for (protocol, name) in [
        (HttpProtocol::Http1, "Last-Event-ID"),
        (HttpProtocol::Http1, "LAST-EVENT-ID"),
        (HttpProtocol::Http2, "last-event-id"),
        (HttpProtocol::Http3, "last-event-id"),
    ] {
        let template = vec![SseHeader::last_event_id(name)];
        assert!(
            validate_template(&template, protocol).is_ok(),
            "{name} rejected"
        );
    }
}

#[test]
fn minimum_retry_raises_only_shorter_delays() {
    let minimum = Some(Duration::from_millis(500));
    assert_eq!(effective_retry(Duration::ZERO, None), Duration::ZERO);
    assert_eq!(
        effective_retry(Duration::from_millis(100), minimum),
        Duration::from_millis(500)
    );
    assert_eq!(
        effective_retry(Duration::from_millis(750), minimum),
        Duration::from_millis(750)
    );
}

fn field(name: &str, value: &str) -> SseHeader {
    SseHeader::field(RequestHeader::new(name, value))
}

fn names(headers: &[RequestHeader]) -> Vec<&str> {
    headers.iter().map(RequestHeader::name).collect()
}
