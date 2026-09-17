//! Request syntax shared by HTTP protocol implementations.

use std::{error::Error as StdError, fmt};

use http::{
    Uri,
    uri::{Authority, PathAndQuery},
};

/// An HTTP absolute-form request target such as `http://example.test/search?q=rust`.
///
/// HTTP forward proxies receive this form instead of the origin-form used by
/// direct and tunneled requests.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AbsoluteForm {
    uri: Uri,
    authority: Authority,
}

impl AbsoluteForm {
    /// Parses an HTTP or HTTPS absolute-form request target.
    pub fn parse(value: &str) -> Result<Self, InvalidAbsoluteForm> {
        if value.contains('#') {
            return Err(InvalidAbsoluteForm);
        }
        value
            .parse::<Uri>()
            .map_err(|_| InvalidAbsoluteForm)
            .and_then(Self::from_uri)
    }

    /// Validates an already-parsed HTTP URI as absolute-form.
    pub fn from_uri(uri: Uri) -> Result<Self, InvalidAbsoluteForm> {
        if !matches!(uri.scheme_str(), Some("http" | "https"))
            || uri
                .path_and_query()
                .is_none_or(|target| target.as_str().contains('#'))
        {
            return Err(InvalidAbsoluteForm);
        }
        let authority = uri.authority().cloned().ok_or(InvalidAbsoluteForm)?;
        if authority.as_str().as_bytes().contains(&b'@') {
            return Err(InvalidAbsoluteForm);
        }
        Ok(Self { uri, authority })
    }

    pub(crate) fn authority(&self) -> &str {
        self.authority.as_str()
    }

    pub(crate) fn into_uri(self) -> Uri {
        self.uri
    }
}

/// Error returned when a request target is not valid HTTP absolute-form.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InvalidAbsoluteForm;

impl fmt::Display for InvalidAbsoluteForm {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "request target must be HTTP absolute-form with an http or https scheme and authority",
        )
    }
}

impl StdError for InvalidAbsoluteForm {}

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
/// HTTP/1 preserves the supplied field-name spelling; HTTP/2 and HTTP/3 require
/// lowercase field names while preserving field order and duplicate positions.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestHeader {
    name: Box<str>,
    value: Box<[u8]>,
    sensitive: bool,
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
            sensitive: false,
        }
    }

    /// Marks this field as sensitive for compression-layer encoding.
    ///
    /// HTTP/2 and HTTP/3 emit sensitive fields as never-indexed literals.
    /// HTTP/1 wire bytes are unchanged. Debug output redacts the value.
    #[must_use]
    pub fn sensitive(mut self) -> Self {
        self.sensitive = true;
        self
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

    /// Returns whether compression layers must never index this field.
    #[must_use]
    pub fn is_sensitive(&self) -> bool {
        self.sensitive
    }
}

impl fmt::Debug for RequestHeader {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("RequestHeader");
        debug.field("name", &self.name);
        if self.sensitive {
            debug.field("value", &"<redacted>");
        } else {
            debug.field("value", &self.value);
        }
        debug.field("sensitive", &self.sensitive).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{AbsoluteForm, InvalidAbsoluteForm, InvalidOriginForm, OriginForm, RequestHeader};

    #[test]
    fn accepts_only_http_absolute_form_targets() -> Result<(), InvalidAbsoluteForm> {
        let target = AbsoluteForm::parse("http://example.test/path?query=yes")?;
        assert_eq!(
            target.uri,
            "http://example.test/path?query=yes"
                .parse::<http::Uri>()
                .map_err(|_| InvalidAbsoluteForm)?
        );
        let root = AbsoluteForm::parse("http://example.test")?;
        assert_eq!(root.uri.path(), "/");

        for value in [
            "/path",
            "example.test/path",
            "ftp://example.test/path",
            "http:///path",
            "http://user@example.test/path",
            "http://example.test/path#fragment",
        ] {
            assert!(AbsoluteForm::parse(value).is_err(), "accepted {value:?}");
        }
        Ok(())
    }

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

    #[test]
    fn sensitive_header_debug_output_redacts_the_value() {
        let header = RequestHeader::new("cookie", "secret=value").sensitive();
        let debug = format!("{header:?}");

        assert!(header.is_sensitive());
        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("secret=value"));
    }
}
