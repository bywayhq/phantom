use std::fmt;

use http::Uri;

use crate::{ContentCoding, HttpProtocol};

/// Facade metadata attached to every successful ordinary response.
///
/// Retrieve this value through [`http::Response::extensions`].
#[derive(Clone, Eq, PartialEq)]
pub struct ResponseInfo {
    effective_uri: Uri,
    redirect_count: usize,
    retries_performed: usize,
    protocol: HttpProtocol,
    decoded_content_codings: Box<[ContentCoding]>,
}

impl fmt::Debug for ResponseInfo {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseInfo")
            .field("redirect_count", &self.redirect_count)
            .field("retries_performed", &self.retries_performed)
            .field("protocol", &self.protocol)
            .field("decoded_content_codings", &self.decoded_content_codings)
            .finish_non_exhaustive()
    }
}

impl ResponseInfo {
    pub(crate) fn new(
        effective_uri: Uri,
        redirect_count: usize,
        retries_performed: usize,
        protocol: HttpProtocol,
        decoded_content_codings: Box<[ContentCoding]>,
    ) -> Self {
        Self {
            effective_uri,
            redirect_count,
            retries_performed,
            protocol,
            decoded_content_codings,
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
    ///
    /// Each count is one repeated setup attempt under
    /// [`RetryPolicy::connection_failures`](crate::RetryPolicy::connection_failures),
    /// summed across every redirect hop and counted when the attempt starts.
    /// Redirects, status retries, reused-connection and `GOAWAY` replays,
    /// proxy-authentication replays, and `Critical-CH` retries are not counted.
    #[must_use]
    pub const fn retries_performed(&self) -> usize {
        self.retries_performed
    }

    /// Returns the HTTP protocol that produced this response.
    #[must_use]
    pub const fn protocol(&self) -> HttpProtocol {
        self.protocol
    }

    /// Returns the content codings the body decodes, in `Content-Encoding` order.
    ///
    /// Empty unless [`ContentDecoding::advertised`](crate::ContentDecoding::advertised)
    /// was set and the response used a supported, advertised coding chain.
    #[must_use]
    pub fn decoded_content_codings(&self) -> &[ContentCoding] {
        &self.decoded_content_codings
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
            Box::default(),
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
