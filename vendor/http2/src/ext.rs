//! Extensions specific to the HTTP/2 protocol.

use crate::hpack::BytesStr;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue};
use std::fmt;

/// Exact wire order for ordinary header fields.
///
/// Store this value in a request's extensions to control its field order.
/// Received requests and responses also carry this value in their extensions
/// with the order produced by HPACK decoding. Pseudo-headers are excluded.
/// Outgoing ordered fields must describe the same semantic multimap as the
/// request's [`HeaderMap`], including duplicate values and their per-name
/// order, or the request is rejected as malformed. Global field-name order is
/// intentionally ignored during that comparison because `HeaderMap` does not
/// preserve it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrderedHeaders {
    headers: Vec<(HeaderName, HeaderValue)>,
}

impl OrderedHeaders {
    /// Creates an owned ordinary-header order.
    #[must_use]
    pub fn new(headers: Vec<(HeaderName, HeaderValue)>) -> Self {
        Self { headers }
    }

    /// Returns the ordered ordinary fields.
    #[must_use]
    pub fn as_slice(&self) -> &[(HeaderName, HeaderValue)] {
        &self.headers
    }

    pub(crate) fn agrees_with(&self, semantic: &HeaderMap) -> bool {
        let mut reconstructed = HeaderMap::new();
        for (name, value) in &self.headers {
            if reconstructed.try_append(name, value.clone()).is_err() {
                return false;
            }
        }
        reconstructed.eq(semantic)
    }

    pub(crate) fn into_inner(self) -> Vec<(HeaderName, HeaderValue)> {
        self.headers
    }
}

/// Represents the `:protocol` pseudo-header used by
/// the [Extended CONNECT Protocol].
///
/// [Extended CONNECT Protocol]: https://datatracker.ietf.org/doc/html/rfc8441#section-4
#[derive(Clone, Eq, PartialEq)]
pub struct Protocol {
    value: BytesStr,
}

impl Protocol {
    /// Converts a static string to a protocol name.
    pub const fn from_static(value: &'static str) -> Self {
        Self {
            value: BytesStr::from_static(value),
        }
    }

    /// Returns a str representation of the header.
    pub fn as_str(&self) -> &str {
        self.value.as_str()
    }

    pub(crate) fn try_from(bytes: Bytes) -> Result<Self, std::str::Utf8Error> {
        Ok(Self {
            value: BytesStr::try_from(bytes)?,
        })
    }
}

impl<'a> From<&'a str> for Protocol {
    fn from(value: &'a str) -> Self {
        Self {
            value: BytesStr::from(value),
        }
    }
}

impl AsRef<[u8]> for Protocol {
    fn as_ref(&self) -> &[u8] {
        self.value.as_ref()
    }
}

impl fmt::Debug for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.value.fmt(f)
    }
}
