//! Request syntax shared by HTTP protocol implementations.

use std::{error::Error as StdError, fmt};

use http::{Uri, uri::PathAndQuery};

/// An HTTP origin-form request target such as `/search?q=rust`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OriginForm(PathAndQuery);

impl OriginForm {
    /// Parses an origin-form request target.
    pub fn parse(value: &str) -> Result<Self, InvalidOriginForm> {
        let uri = value.parse::<Uri>().map_err(|_| InvalidOriginForm)?;
        let is_origin_form = value.starts_with('/')
            && uri.scheme().is_none()
            && uri.authority().is_none()
            && uri
                .path_and_query()
                .is_some_and(|path_and_query| path_and_query.as_str() == value);

        if !is_origin_form {
            return Err(InvalidOriginForm);
        }

        match uri.into_parts().path_and_query {
            Some(path_and_query) => Ok(Self(path_and_query)),
            None => Err(InvalidOriginForm),
        }
    }

    pub(crate) fn into_uri(self) -> Uri {
        self.0.into()
    }

    pub(crate) fn into_path_and_query(self) -> PathAndQuery {
        self.0
    }
}

/// Error returned when a request target is not valid HTTP origin-form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidOriginForm;

impl fmt::Display for InvalidOriginForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "request target must be HTTP origin-form beginning with `/` and contain no authority or fragment",
        )
    }
}

impl StdError for InvalidOriginForm {}

/// A request header retaining caller-supplied spelling, value, and position.
///
/// Each protocol validates this representation against its own wire rules.
/// HTTP/1 preserves the supplied field-name spelling; HTTP/2 requires lowercase
/// field names while preserving field order and duplicate positions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestHeader {
    name: Box<str>,
    value: Box<[u8]>,
}

impl RequestHeader {
    /// Creates a header to be validated when the request is sent.
    ///
    /// Construction is intentionally infallible so validation of the complete
    /// ordered header list happens once, before the supplied stream is touched.
    #[must_use]
    pub fn new(name: impl Into<Box<str>>, value: impl AsRef<[u8]>) -> Self {
        Self {
            name: name.into(),
            value: value.as_ref().into(),
        }
    }

    /// Returns the exact field-name spelling that will be written.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the field value bytes.
    #[must_use]
    pub fn value(&self) -> &[u8] {
        &self.value
    }
}

#[cfg(test)]
mod tests {
    use super::{InvalidOriginForm, OriginForm};

    #[test]
    fn accepts_only_origin_form_targets() -> Result<(), InvalidOriginForm> {
        let target = OriginForm::parse("/path?query=yes")?;
        assert_eq!(target.0.as_str(), "/path?query=yes");

        for value in ["", "*", "example.test/path", "https://example.test/path"] {
            assert!(OriginForm::parse(value).is_err(), "accepted {value:?}");
        }
        Ok(())
    }

    #[test]
    fn invalid_origin_form_error_is_specific_and_stable() -> Result<(), &'static str> {
        let error = match OriginForm::parse("https://example.test/path") {
            Ok(_) => return Err("absolute-form target was accepted"),
            Err(error) => error,
        };

        assert_eq!(error, InvalidOriginForm);
        assert_eq!(
            error.to_string(),
            "request target must be HTTP origin-form beginning with `/` and contain no authority or fragment"
        );
        Ok(())
    }
}
