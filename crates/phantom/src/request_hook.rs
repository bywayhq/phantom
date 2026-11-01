//! Observe one logical HTTP request without taking ownership of its body.

use std::{error::Error, fmt, future::Future, pin::Pin, sync::Arc};

use http::{HeaderMap, Method, StatusCode, Uri, Version};

use crate::{RequestError, ResponseInfo};

pub(crate) use dispatch::{ActiveRequestHooks, SharedRequestHooks};

mod dispatch;

/// Synchronous callbacks around one call to [`crate::RequestBuilder::send`].
///
/// Client callbacks run first, then request callbacks. `on_request` runs when
/// `send` is first polled, before header hooks, validation and network I/O.
/// A completed `send` calls either `on_response` or `on_error` once. Redirects,
/// retries and protocol replays stay inside that logical request and do not
/// repeat these callbacks. Use [`crate::RequestDiagnostics`] for attempts.
///
/// Callbacks borrow metadata. They cannot mutate headers, consume bodies,
/// authorize a replay or turn an error into a response. Use
/// [`crate::HeaderHookContext`] to change initial caller headers.
///
/// A response callback observes the final response head, including HTTP error
/// statuses. Later body failures do not call `on_error`. Dropping an unfinished
/// send future does not call a terminal callback. Diagnostics track body
/// completion and cancellation separately. Invalid builder construction occurs
/// before `send` and has no callbacks. WebSocket openings have no callbacks;
/// each SSE HTTP request has its own callbacks.
///
/// Callbacks may run concurrently for different requests and share state across
/// client clones. Avoid blocking or network I/O in them. Panics propagate to the
/// caller; callbacks should handle their own reporting failures.
pub trait RequestHooks: Send + Sync {
    /// Observes the original method and resolved URI before request preparation.
    fn on_request(&self, _request: &RequestHookContext<'_>) {}

    /// Observes the final response head before `send` returns it to the caller.
    fn on_response(&self, _response: &ResponseHookContext<'_>) {}

    /// Observes the final send error, after its origin context has been attached.
    fn on_error(&self, _error: &RequestErrorHookContext<'_>) {}
}

impl<T: RequestHooks + ?Sized> RequestHooks for Arc<T> {
    fn on_request(&self, request: &RequestHookContext<'_>) {
        (**self).on_request(request);
    }

    fn on_response(&self, response: &ResponseHookContext<'_>) {
        (**self).on_response(response);
    }

    fn on_error(&self, error: &RequestErrorHookContext<'_>) {
        (**self).on_error(error);
    }
}

/// Awaited callbacks around one logical HTTP request.
///
/// These use the metadata and ordering of [`RequestHooks`]. Client callbacks
/// run before request callbacks, once per phase. Retries and redirects do not
/// repeat them. All awaited work shares the request's total deadline, including
/// the final response body. Synchronous callbacks must still avoid blocking.
///
/// A request callback failure prevents sending and enters the error phase.
/// A response callback failure drops the unread body and returns that failure
/// without entering the error phase. An error callback failure retains the
/// original error as primary; its source is [`RequestErrorHookFailure`].
/// Each phase stops at its first failure. Dropping `send` cancels its current
/// callback without starting another phase. Later body failures have no callback.
///
/// A pending callback at an exhausted deadline has no additional wait. As with
/// other timed operations, an immediately ready callback can finish then.
/// A closed client, invalid timeout or unavailable timer prevents callback
/// admission through that failed operation.
///
/// # Examples
///
/// ```no_run
/// use std::{future::Future, pin::Pin};
/// use phantom::{AsyncRequestHooks, RequestHookContext, RequestHookError};
///
/// struct Observer;
/// impl AsyncRequestHooks for Observer {
///     fn on_request<'a>(&'a self, request: &'a RequestHookContext<'_>)
///         -> Pin<Box<dyn Future<Output = Result<(), RequestHookError>> + Send + 'a>>
///     {
///         Box::pin(async move {
///             println!("method {}", request.method());
///             Ok(())
///         })
///     }
/// }
/// # fn configure(builder: phantom::ClientBuilder) {
/// let builder = builder.async_request_hooks(Observer);
/// # }
/// ```
pub trait AsyncRequestHooks: Send + Sync {
    /// Observes the original request before preparation or any HTTP attempt.
    fn on_request<'a>(
        &'a self,
        _request: &'a RequestHookContext<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<(), RequestHookError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    /// Observes the final response head while `send` retains the unread body.
    fn on_response<'a>(
        &'a self,
        _response: &'a ResponseHookContext<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<(), RequestHookError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }

    /// Observes the original terminal error, including its origin and source.
    fn on_error<'a>(
        &'a self,
        _error: &'a RequestErrorHookContext<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<(), RequestHookError>> + Send + 'a>> {
        Box::pin(async { Ok(()) })
    }
}

impl<T: AsyncRequestHooks + ?Sized> AsyncRequestHooks for Arc<T> {
    fn on_request<'a>(
        &'a self,
        request: &'a RequestHookContext<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<(), RequestHookError>> + Send + 'a>> {
        (**self).on_request(request)
    }

    fn on_response<'a>(
        &'a self,
        response: &'a ResponseHookContext<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<(), RequestHookError>> + Send + 'a>> {
        (**self).on_response(response)
    }

    fn on_error<'a>(
        &'a self,
        error: &'a RequestErrorHookContext<'_>,
    ) -> Pin<Box<dyn Future<Output = Result<(), RequestHookError>> + Send + 'a>> {
        (**self).on_error(error)
    }
}

/// A logical request callback failure with its original typed cause.
///
/// Formatting omits the cause. Inspect [`Error::source`] for details, which
/// may contain secrets.
pub struct RequestHookError(Box<dyn Error + Send + Sync>);

impl RequestHookError {
    /// Retains an error returned by your callback.
    #[must_use]
    pub fn new(source: impl Error + Send + Sync + 'static) -> Self {
        Self(Box::new(source))
    }
}

impl fmt::Debug for RequestHookError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestHookError { .. }")
    }
}

impl fmt::Display for RequestHookError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("request callback failed")
    }
}

impl Error for RequestHookError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.0.as_ref())
    }
}

/// An original request error together with a failure while observing it.
///
/// The outer [`RequestError`] keeps the original category, protocol, timeout
/// phase, origin and replay observation. Its source is this value. The normal
/// source chain follows [`Self::original_error`]; [`Self::hook_error`] retains
/// the callback failure or the timeout encountered while awaiting it.
pub struct RequestErrorHookFailure {
    original: RequestError,
    hook: RequestError,
}

impl RequestErrorHookFailure {
    pub(crate) fn new(original: RequestError, hook: RequestError) -> Self {
        Self { original, hook }
    }

    /// Returns the request failure that selected the error phase.
    #[must_use]
    pub fn original_error(&self) -> &RequestError {
        &self.original
    }

    /// Returns the callback failure, including its typed source, or its timeout.
    #[must_use]
    pub fn hook_error(&self) -> &RequestError {
        &self.hook
    }
}

impl fmt::Debug for RequestErrorHookFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestErrorHookFailure")
            .field("original_kind", &self.original.kind())
            .field("hook_kind", &self.hook.kind())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for RequestErrorHookFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("request and error callback failed")
    }
}

impl Error for RequestErrorHookFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.original)
    }
}

/// The original logical request, before redirects or method changes.
#[derive(Clone, Copy)]
pub struct RequestHookContext<'a> {
    method: &'a Method,
    uri: &'a Uri,
}

impl RequestHookContext<'_> {
    /// Returns the original request method.
    #[must_use]
    pub fn method(&self) -> &Method {
        self.method
    }

    /// Returns the resolved initial URI. It can contain secrets.
    #[must_use]
    pub fn uri(&self) -> &Uri {
        self.uri
    }
}

impl fmt::Debug for RequestHookContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestHookContext")
            .finish_non_exhaustive()
    }
}

/// Borrowed final response metadata. No request or response body is exposed.
pub struct ResponseHookContext<'a> {
    request: RequestHookContext<'a>,
    status: StatusCode,
    version: Version,
    headers: &'a HeaderMap,
    info: Option<&'a ResponseInfo>,
}

impl ResponseHookContext<'_> {
    /// Returns the original logical request.
    #[must_use]
    pub fn request(&self) -> &RequestHookContext<'_> {
        &self.request
    }

    /// Returns the final response status, including 4xx and 5xx responses.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// Returns the final HTTP version.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

    /// Returns response headers as exposed to the caller, after content decoding
    /// preparation. Values may contain secrets. This map does not retain wire order.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        self.headers
    }

    /// Returns final URI, protocol and redirect metadata when attached.
    #[must_use]
    pub fn info(&self) -> Option<&ResponseInfo> {
        self.info
    }
}

impl fmt::Debug for ResponseHookContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseHookContext")
            .field("status", &self.status())
            .field("version", &self.version())
            .field("header_count", &self.headers().len())
            .finish_non_exhaustive()
    }
}

/// The original request and the terminal error returned by `send`.
pub struct RequestErrorHookContext<'a> {
    request: RequestHookContext<'a>,
    error: &'a RequestError,
}

impl RequestErrorHookContext<'_> {
    /// Returns the original logical request.
    #[must_use]
    pub fn request(&self) -> &RequestHookContext<'_> {
        &self.request
    }

    /// Returns the error, including its typed source and origin context.
    /// Sources may contain secrets.
    #[must_use]
    pub fn error(&self) -> &RequestError {
        self.error
    }
}

impl fmt::Debug for RequestErrorHookContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestErrorHookContext")
            .field("kind", &self.error.kind())
            .finish_non_exhaustive()
    }
}
