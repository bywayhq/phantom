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
#[path = "accept_ch/tests.rs"]
mod tests;
