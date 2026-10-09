use std::{error::Error as StdError, fmt, str::Utf8Error};

use bytes::Bytes;
use http::{Response, StatusCode, Uri};

use crate::{ContentCoding, HttpProtocol, RequestError, ResponseBody};

/// Returns an error for a 4xx or 5xx response without reading its body.
///
/// You can recover the complete response through [`StatusError::into_response`].
/// Other status codes pass through unchanged. This check is opt-in.
///
/// ```no_run
/// # async fn example(client: &phantom::Client) -> Result<(), Box<dyn std::error::Error>> {
/// let response = client.get(phantom::HttpProtocol::Http2, "https://example.com/")?
///     .send().await?;
/// let response = phantom::error_for_status(response)?;
/// let response = phantom::response_bytes(response, 1 << 20).await?;
/// println!("{}: {} bytes", response.status(), response.body().len());
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns [`StatusError`] for client and server error status codes.
pub fn error_for_status(
    response: Response<ResponseBody>,
) -> Result<Response<ResponseBody>, StatusError> {
    if response.status().is_client_error() || response.status().is_server_error() {
        Err(StatusError {
            response: Box::new(response),
        })
    } else {
        Ok(response)
    }
}

/// An HTTP error status with its complete, unread response.
///
/// Dropping this error drops the response body. Its formatting includes only
/// the status code, so headers, response metadata and the URL stay private.
pub struct StatusError {
    response: Box<Response<ResponseBody>>,
}

impl StatusError {
    /// Returns the HTTP status that failed the check.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.response.status()
    }

    /// Returns the original response, including its unread body.
    #[must_use]
    pub fn response(&self) -> &Response<ResponseBody> {
        &self.response
    }

    /// Returns the original response for metadata or body changes.
    pub fn response_mut(&mut self) -> &mut Response<ResponseBody> {
        &mut self.response
    }

    /// Recovers the complete response without reading its body.
    #[must_use]
    pub fn into_response(self) -> Response<ResponseBody> {
        *self.response
    }
}

impl fmt::Debug for StatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatusError")
            .field("status", &self.status())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for StatusError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "response has error status {}", self.status())
    }
}

impl StdError for StatusError {}

/// Collects at most `maximum_bytes` of response data while keeping its metadata.
///
/// The limit counts decoded bytes when you enabled content decoding. Status,
/// headers, version and extensions pass through unchanged, including on errors.
/// Trailers are consumed and discarded. This helper does not check the status.
/// Dropping its future cancels the read and drops the body.
///
/// # Errors
///
/// Returns [`ResponseReadErrorKind::Body`] for a body failure or an exceeded
/// limit. The error retains the response metadata and the original
/// [`RequestError`]. Partial body data is discarded.
pub async fn response_bytes(
    response: Response<ResponseBody>,
    maximum_bytes: usize,
) -> Result<Response<Bytes>, ResponseReadError> {
    let (parts, body) = response.into_parts();
    match body.collect_with_limit(maximum_bytes).await {
        Ok(bytes) => Ok(Response::from_parts(parts, bytes)),
        Err(error) => Err(ResponseReadError {
            response: Box::new(Response::from_parts(parts, ())),
            cause: ResponseReadCause::Body(error),
        }),
    }
}

/// Reads bounded response data as UTF-8 text while keeping its metadata.
///
/// Uses [`response_bytes`] with the same limit and cleanup behavior. It requires
/// valid UTF-8 and does not choose a charset from response headers.
///
/// # Errors
///
/// Returns a body error or [`ResponseReadErrorKind::Utf8`] for invalid UTF-8.
/// The error keeps the response metadata and discards the collected data.
pub async fn response_text(
    response: Response<ResponseBody>,
    maximum_bytes: usize,
) -> Result<Response<String>, ResponseReadError> {
    let response = response_bytes(response, maximum_bytes).await?;
    let (parts, bytes) = response.into_parts();
    match std::str::from_utf8(&bytes) {
        Ok(text) => Ok(Response::from_parts(parts, text.to_owned())),
        Err(error) => Err(ResponseReadError {
            response: Box::new(Response::from_parts(parts, ())),
            cause: ResponseReadCause::Utf8(error),
        }),
    }
}

/// Reads bounded response data as JSON while keeping its metadata.
///
/// Uses [`response_bytes`] with the same limit and cleanup behavior. You choose
/// the output type. This helper does not require a JSON `Content-Type` header.
/// The byte limit bounds input data, not memory allocated by deserialization.
///
/// ```no_run
/// # async fn example(response: phantom::Response<phantom::ResponseBody>) -> Result<(), Box<dyn std::error::Error>> {
/// let response = phantom::response_json::<Vec<String>>(response, 1 << 20).await?;
/// println!("{} entries", response.body().len());
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns a body error or [`ResponseReadErrorKind::Json`] for invalid JSON or
/// data that cannot be deserialized into `T`. The error keeps response metadata
/// and discards the collected data.
#[cfg(feature = "json")]
pub async fn response_json<T: serde::de::DeserializeOwned>(
    response: Response<ResponseBody>,
    maximum_bytes: usize,
) -> Result<Response<T>, ResponseReadError> {
    let response = response_bytes(response, maximum_bytes).await?;
    let (parts, bytes) = response.into_parts();
    match serde_json::from_slice(&bytes) {
        Ok(value) => Ok(Response::from_parts(parts, value)),
        Err(error) => Err(ResponseReadError {
            response: Box::new(Response::from_parts(parts, ())),
            cause: ResponseReadCause::Json(error),
        }),
    }
}

/// The reason a bounded response read failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResponseReadErrorKind {
    /// The body failed or exceeded the byte limit.
    Body,
    /// The collected bytes are not valid UTF-8.
    Utf8,
    /// The collected JSON could not be deserialized.
    #[cfg(feature = "json")]
    Json,
}

/// A response read failure with the original status, headers and metadata.
///
/// The body has been dropped. [`Self::response`] and [`Self::into_response`]
/// expose the unchanged response parts with a unit body. Formatting includes
/// only status and failure category. [`StdError::source`] returns the original
/// body, UTF-8 or JSON error for detailed inspection.
pub struct ResponseReadError {
    response: Box<Response<()>>,
    cause: ResponseReadCause,
}

enum ResponseReadCause {
    Body(RequestError),
    Utf8(Utf8Error),
    #[cfg(feature = "json")]
    Json(serde_json::Error),
}

impl ResponseReadError {
    /// Returns the stable failure category.
    #[must_use]
    pub const fn kind(&self) -> ResponseReadErrorKind {
        match &self.cause {
            ResponseReadCause::Body(_) => ResponseReadErrorKind::Body,
            ResponseReadCause::Utf8(_) => ResponseReadErrorKind::Utf8,
            #[cfg(feature = "json")]
            ResponseReadCause::Json(_) => ResponseReadErrorKind::Json,
        }
    }

    /// Returns the original body error, including its typed classification.
    #[must_use]
    pub const fn request_error(&self) -> Option<&RequestError> {
        match &self.cause {
            ResponseReadCause::Body(error) => Some(error),
            _ => None,
        }
    }

    /// Returns the original response metadata with a unit body.
    #[must_use]
    pub fn response(&self) -> &Response<()> {
        &self.response
    }

    /// Returns the original response metadata for changes.
    pub fn response_mut(&mut self) -> &mut Response<()> {
        &mut self.response
    }

    /// Recovers the original response metadata with a unit body.
    #[must_use]
    pub fn into_response(self) -> Response<()> {
        *self.response
    }
}

impl fmt::Debug for ResponseReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseReadError")
            .field("status", &self.response.status())
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for ResponseReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self.kind() {
            ResponseReadErrorKind::Body => "response body read failed",
            ResponseReadErrorKind::Utf8 => "response body is not valid UTF-8",
            #[cfg(feature = "json")]
            ResponseReadErrorKind::Json => "response body could not be read as JSON",
        };
        write!(formatter, "{message} (HTTP {})", self.response.status())
    }
}

impl StdError for ResponseReadError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        Some(match &self.cause {
            ResponseReadCause::Body(error) => error,
            ResponseReadCause::Utf8(error) => error,
            #[cfg(feature = "json")]
            ResponseReadCause::Json(error) => error,
        })
    }
}

/// The final URL, protocol and retry counts for an HTTP response.
///
/// You can retrieve it through [`http::Response::extensions`] on each
/// successful HTTP response.
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
    /// Counts retries under
    /// [`RetryPolicy::connection_failures`](crate::RetryPolicy::connection_failures)
    /// across all redirect hops. A retry counts when its setup attempt starts.
    /// Redirects, status retries, reused-connection and `GOAWAY` replays,
    /// proxy-authentication replays, `Critical-CH` retries, and the HTTP/2
    /// fallback are not counted.
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
