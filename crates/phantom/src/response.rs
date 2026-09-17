use std::fmt;

use http::Uri;

/// Facade metadata attached to every successful ordinary response.
///
/// Retrieve this value through [`http::Response::extensions`].
#[derive(Clone, Eq, PartialEq)]
pub struct ResponseInfo {
    effective_uri: Uri,
    redirect_count: usize,
}

impl fmt::Debug for ResponseInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseInfo")
            .field("redirect_count", &self.redirect_count)
            .finish_non_exhaustive()
    }
}

impl ResponseInfo {
    pub(crate) fn new(effective_uri: Uri, redirect_count: usize) -> Self {
        Self {
            effective_uri,
            redirect_count,
        }
    }

    /// Returns the URL that produced this response.
    #[must_use]
    pub fn effective_uri(&self) -> &Uri {
        &self.effective_uri
    }

    /// Returns the number of redirects followed before this response.
    #[must_use]
    pub const fn redirects_followed(&self) -> usize {
        self.redirect_count
    }
}

#[cfg(test)]
mod tests {
    use super::ResponseInfo;

    #[test]
    fn debug_omits_the_effective_uri() -> Result<(), Box<dyn std::error::Error>> {
        let info = ResponseInfo::new("https://example.test/private?token=secret".parse()?, 2);
        let debug = format!("{info:?}");

        assert!(debug.contains("redirect_count: 2"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("secret"));
        Ok(())
    }
}
