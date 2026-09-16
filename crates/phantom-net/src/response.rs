//! Response metadata shared by HTTP protocol implementations.

use std::fmt;

use http::{HeaderName, HeaderValue};

/// One response field in its received position.
///
/// The field name retains the spelling observed on HTTP/1. HTTP/2 and HTTP/3
/// require lowercase field names on the wire, so their names are lowercase.
#[derive(Clone, Eq, PartialEq)]
pub struct ResponseHeader {
    name: Box<str>,
    value: Box<[u8]>,
    sensitive: bool,
}

impl fmt::Debug for ResponseHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseHeader")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .field("sensitive", &self.sensitive)
            .finish()
    }
}

impl ResponseHeader {
    pub(crate) fn from_parts(name: &str, value: &[u8], sensitive: bool) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
            sensitive,
        }
    }

    /// Returns the field-name spelling observed on the wire.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the field value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Returns whether the compression layer marked this field as sensitive.
    ///
    /// HTTP/1 has no equivalent wire marker and always returns `false`.
    #[must_use]
    pub fn is_sensitive(&self) -> bool {
        self.sensitive
    }
}

/// Response fields in their original global wire order.
///
/// Every successful Phantom transport response stores this value in its
/// [`http::Extensions`]. Unlike [`http::HeaderMap`], this representation
/// retains the positions of duplicate and interleaved field names. HTTP/1
/// field-name spelling is also retained exactly.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OrderedResponseHeaders {
    headers: Vec<ResponseHeader>,
}

impl OrderedResponseHeaders {
    pub(crate) fn new(headers: Vec<ResponseHeader>) -> Self {
        Self { headers }
    }

    pub(crate) fn from_normalized_fields(fields: &[(HeaderName, HeaderValue)]) -> Self {
        Self::new(
            fields
                .iter()
                .map(|(name, value)| {
                    ResponseHeader::from_parts(
                        name.as_str(),
                        value.as_bytes(),
                        value.is_sensitive(),
                    )
                })
                .collect(),
        )
    }

    /// Returns the fields in received order.
    #[must_use]
    pub fn as_slice(&self) -> &[ResponseHeader] {
        &self.headers
    }

    /// Returns an iterator over the fields in received order.
    pub fn iter(&self) -> impl ExactSizeIterator<Item = &ResponseHeader> {
        self.headers.iter()
    }

    /// Returns the number of received fields, including duplicates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.headers.len()
    }

    /// Returns whether the response contained no ordinary fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::{OrderedResponseHeaders, ResponseHeader};

    #[test]
    fn retains_interleaved_duplicates_and_spelling() {
        let headers = OrderedResponseHeaders::new(vec![
            ResponseHeader::from_parts("Set-Cookie", b"first=1", false),
            ResponseHeader::from_parts("X-MiXeD", b"middle", false),
            ResponseHeader::from_parts("set-cookie", b"second=2", false),
        ]);

        let observed = headers
            .iter()
            .map(|header| (header.name(), header.value(), header.is_sensitive()))
            .collect::<Vec<_>>();
        assert_eq!(
            observed,
            [
                ("Set-Cookie", b"first=1".as_slice(), false),
                ("X-MiXeD", b"middle".as_slice(), false),
                ("set-cookie", b"second=2".as_slice(), false),
            ]
        );
        let debug = format!("{headers:?}");
        assert!(!debug.contains("first=1"));
        assert!(!debug.contains("middle"));
    }
}
