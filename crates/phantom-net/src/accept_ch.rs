//! Connection-scoped Client Hint preferences received through ALPS.

use std::collections::HashMap;

const MAX_ACCEPT_CH_ENTRIES: usize = 1_024;

#[derive(Default)]
pub(crate) struct AcceptCh {
    entries: HashMap<Box<str>, Box<[u8]>>,
    ignored_entries: usize,
}

impl AcceptCh {
    pub(crate) fn insert(&mut self, origin: &[u8], value: &[u8]) {
        let Ok(origin) = std::str::from_utf8(origin) else {
            self.ignored_entries += 1;
            return;
        };
        let Ok(url) = url::Url::parse(origin) else {
            self.ignored_entries += 1;
            return;
        };
        if url.origin().ascii_serialization() != origin {
            self.ignored_entries += 1;
            return;
        }
        if self.entries.contains_key(origin) {
            return;
        }
        if self.entries.len() == MAX_ACCEPT_CH_ENTRIES {
            self.ignored_entries += 1;
            return;
        }
        self.entries.insert(origin.into(), value.into());
    }

    pub(crate) fn for_origin(&self, origin: &str) -> Option<&[u8]> {
        self.entries.get(origin).map(AsRef::as_ref)
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn ignored_len(&self) -> usize {
        self.ignored_entries
    }
}

#[cfg(test)]
mod tests {
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
}
