use super::{AcceptCh, MAX_ACCEPT_CH_ENTRIES};

#[test]
fn keeps_first_value_for_canonical_ascii_origins() {
    let mut values = AcceptCh::default();
    values.insert(b"https://example.test", b"first");
    values.insert(b"https://example.test", b"later");

    assert_eq!(values.len(), 1);
    assert_eq!(values.ignored_len(), 0);
    assert_eq!(
        values.for_origin("https://example.test"),
        Some(b"first".as_slice())
    );
}

#[test]
fn ignores_noncanonical_and_non_utf8_origins() {
    let mut values = AcceptCh::default();
    for origin in [
        b"HTTPS://EXAMPLE.TEST".as_slice(),
        b"https://example.test:443".as_slice(),
        b"https://example.test/path".as_slice(),
        b"not an origin".as_slice(),
        b"\xff".as_slice(),
    ] {
        values.insert(origin, b"ignored");
    }

    assert_eq!(values.len(), 0);
    assert_eq!(values.ignored_len(), 5);
}

#[test]
fn bounds_distinct_peer_origins() {
    let mut values = AcceptCh::default();
    for index in 0..=MAX_ACCEPT_CH_ENTRIES {
        values.insert(
            format!("https://{index}.example.test").as_bytes(),
            b"Sec-CH-UA",
        );
    }
    values.insert(b"https://0.example.test", b"replacement");

    assert_eq!(values.len(), MAX_ACCEPT_CH_ENTRIES);
    assert_eq!(values.ignored_len(), 1);
    assert_eq!(
        values.for_origin("https://0.example.test"),
        Some(b"Sec-CH-UA".as_slice())
    );
}
