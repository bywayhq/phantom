//! Observe one logical HTTP request without taking ownership of its body.

use std::{fmt, sync::Arc};

use http::{HeaderMap, Method, Response, StatusCode, Uri, Version};

use crate::{RequestError, ResponseBody, ResponseInfo};

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
    response: &'a Response<ResponseBody>,
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
        self.response.status()
    }

    /// Returns the final HTTP version.
    #[must_use]
    pub fn version(&self) -> Version {
        self.response.version()
    }

    /// Returns response headers as exposed to the caller, after content decoding
    /// preparation. Values may contain secrets. This map does not retain wire order.
    #[must_use]
    pub fn headers(&self) -> &HeaderMap {
        self.response.headers()
    }

    /// Returns final URI, protocol and redirect metadata when attached.
    #[must_use]
    pub fn info(&self) -> Option<&ResponseInfo> {
        self.response.extensions().get()
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

#[derive(Clone)]
pub(crate) struct SharedRequestHooks(Arc<dyn RequestHooks>);

impl SharedRequestHooks {
    pub(crate) fn new(hooks: impl RequestHooks + 'static) -> Self {
        Self(Arc::new(hooks))
    }
}

impl fmt::Debug for SharedRequestHooks {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RequestHooks { .. }")
    }
}

pub(crate) struct ActiveRequestHooks {
    method: Method,
    uri: Uri,
    client: Option<SharedRequestHooks>,
    request: Option<SharedRequestHooks>,
}

impl ActiveRequestHooks {
    pub(crate) fn start(
        method: &Method,
        uri: &Uri,
        client: Option<&SharedRequestHooks>,
        request: Option<&SharedRequestHooks>,
    ) -> Option<Box<Self>> {
        if client.is_none() && request.is_none() {
            return None;
        }
        let active = Box::new(Self {
            method: method.clone(),
            uri: uri.clone(),
            client: client.cloned(),
            request: request.cloned(),
        });
        let context = active.context();
        for hooks in active.callbacks() {
            hooks.on_request(&context);
        }
        Some(active)
    }

    pub(crate) fn finish(&self, result: &Result<Response<ResponseBody>, RequestError>) {
        for hooks in self.callbacks() {
            match result {
                Ok(response) => hooks.on_response(&ResponseHookContext {
                    request: self.context(),
                    response,
                }),
                Err(error) => hooks.on_error(&RequestErrorHookContext {
                    request: self.context(),
                    error,
                }),
            }
        }
    }

    fn context(&self) -> RequestHookContext<'_> {
        RequestHookContext {
            method: &self.method,
            uri: &self.uri,
        }
    }

    fn callbacks(&self) -> impl Iterator<Item = &dyn RequestHooks> {
        self.client
            .iter()
            .chain(self.request.iter())
            .map(|hooks| hooks.0.as_ref())
    }
}
