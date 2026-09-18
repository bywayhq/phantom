use std::fmt;

use http::Uri;

use crate::HttpProtocol;

/// Facade metadata attached to every successful ordinary response.
///
/// Retrieve this value through [`http::Response::extensions`].
#[derive(Clone, Eq, PartialEq)]
pub struct ResponseInfo {
    effective_uri: Uri,
    redirect_count: usize,
    retries_performed: usize,
    protocol: HttpProtocol,
}

impl fmt::Debug for ResponseInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseInfo")
            .field("redirect_count", &self.redirect_count)
            .field("retries_performed", &self.retries_performed)
            .field("protocol", &self.protocol)
            .finish_non_exhaustive()
    }
}

impl ResponseInfo {
    pub(crate) fn new(
        effective_uri: Uri,
        redirect_count: usize,
        retries_performed: usize,
        protocol: HttpProtocol,
    ) -> Self {
        Self {
            effective_uri,
            redirect_count,
            retries_performed,
            protocol,
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

    /// Returns the number of connection-setup retries performed before this response.
    #[must_use]
    pub const fn retries_performed(&self) -> usize {
        self.retries_performed
    }

    /// Returns the HTTP protocol that produced this response.
    #[must_use]
    pub const fn protocol(&self) -> HttpProtocol {
        self.protocol
    }
}

#[cfg(test)]
mod tests {
    use super::ResponseInfo;
    use crate::HttpProtocol;

    #[test]
    fn debug_omits_the_effective_uri() -> Result<(), Box<dyn std::error::Error>> {
        let info = ResponseInfo::new(
            "https://example.test/private?token=secret".parse()?,
            2,
            3,
            HttpProtocol::Http2,
        );
        let debug = format!("{info:?}");

        assert!(debug.contains("redirect_count: 2"));
        assert!(debug.contains("retries_performed: 3"));
        assert!(debug.contains("protocol: Http2"));
        assert!(!debug.contains("private"));
        assert!(!debug.contains("secret"));
        Ok(())
    }
}
