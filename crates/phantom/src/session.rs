use std::{fmt, num::NonZeroUsize, sync::Arc};

use http::Method;

#[cfg(feature = "sse")]
use crate::SseRequestBuilder;
use crate::{Client, HttpProtocol, RedirectPolicy, RequestBuilder, RequestError};
#[cfg(feature = "websocket")]
use crate::{WebSocketError, WebSocketRequestBuilder};

mod admission;
#[cfg(feature = "cookies")]
mod cookies;
mod http1_pool;
mod http2_pool;
mod http3_pool;

#[cfg(feature = "cookies")]
pub use cookies::{CookieError, CookieErrorKind, CookieJar, CookieLimits};

const DEFAULT_MAX_RETAINED_HTTP1_CONNECTIONS: NonZeroUsize = match NonZeroUsize::new(32) {
    Some(value) => value,
    None => NonZeroUsize::MIN,
};
const DEFAULT_MAX_RETAINED_HTTP2_CONNECTIONS: NonZeroUsize = match NonZeroUsize::new(32) {
    Some(value) => value,
    None => NonZeroUsize::MIN,
};
const DEFAULT_MAX_RETAINED_HTTP3_CONNECTIONS: NonZeroUsize = DEFAULT_MAX_RETAINED_HTTP2_CONNECTIONS;
const DEFAULT_MAX_PENDING_HTTP1_REQUESTS_PER_ORIGIN: NonZeroUsize = match NonZeroUsize::new(100) {
    Some(value) => value,
    None => NonZeroUsize::MIN,
};
const DEFAULT_MAX_CONCURRENT_HTTP2_REQUESTS_PER_ORIGIN: NonZeroUsize = match NonZeroUsize::new(100)
{
    Some(value) => value,
    None => NonZeroUsize::MIN,
};
const DEFAULT_MAX_PENDING_HTTP2_REQUESTS_PER_ORIGIN: NonZeroUsize =
    DEFAULT_MAX_CONCURRENT_HTTP2_REQUESTS_PER_ORIGIN;
const DEFAULT_MAX_CONCURRENT_HTTP3_REQUESTS_PER_ORIGIN: NonZeroUsize = match NonZeroUsize::new(100)
{
    Some(value) => value,
    None => NonZeroUsize::MIN,
};
const DEFAULT_MAX_PENDING_HTTP3_REQUESTS_PER_ORIGIN: NonZeroUsize =
    DEFAULT_MAX_CONCURRENT_HTTP3_REQUESTS_PER_ORIGIN;

/// Cloneable cross-request state for one immutable [`Client`].
///
/// Clones share the same connection pool. Separate sessions never share
/// mutable state, even when they originate from the same client.
#[derive(Clone)]
pub struct Session {
    pub(crate) client: Client,
    pub(crate) state: Arc<SessionState>,
}

pub(crate) struct SessionState {
    pub(crate) redirect_policy: RedirectPolicy,
    pub(crate) http1: http1_pool::Http1Pool,
    pub(crate) http2: http2_pool::Http2Pool,
    pub(crate) http3: http3_pool::Http3Pool,
    #[cfg(feature = "cookies")]
    pub(crate) cookies: Option<Arc<CookieJar>>,
}

impl Session {
    /// Starts one empty-body GET using exactly `protocol`.
    ///
    /// HTTP/1.1, HTTP/2, and direct HTTP/3 requests may reuse compatible
    /// connections owned by this session.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] when the protocol is absent from the profile
    /// or the URI, authority, or request target is invalid.
    pub fn get(&self, protocol: HttpProtocol, uri: &str) -> Result<RequestBuilder, RequestError> {
        self.request(protocol, Method::GET, uri)
    }

    /// Starts one request using exactly `protocol`.
    ///
    /// HTTP/1.1, HTTP/2, and direct HTTP/3 requests may reuse compatible
    /// connections owned by this session.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] when the protocol is absent from the profile
    /// or the URI, authority, or request target is invalid.
    pub fn request(
        &self,
        protocol: HttpProtocol,
        method: Method,
        uri: &str,
    ) -> Result<RequestBuilder, RequestError> {
        RequestBuilder::new_session(self.clone(), protocol, method, uri)
    }

    /// Starts a bounded server-sent event source using this session's state.
    ///
    /// Reconnects use exactly `protocol`, the same route, ordered caller fields,
    /// shared connection pools, redirect policy, and optional cookie jar.
    ///
    /// # Errors
    ///
    /// Returns [`RequestError`] when the protocol is absent from the profile
    /// or the URI, authority, or request target is invalid.
    #[cfg(feature = "sse")]
    pub fn event_source(
        &self,
        protocol: HttpProtocol,
        uri: &str,
    ) -> Result<SseRequestBuilder, RequestError> {
        SseRequestBuilder::new_session(self.clone(), protocol, uri)
    }

    /// Starts a secure WebSocket handshake with this session's route and cookies.
    #[cfg(feature = "websocket")]
    pub fn websocket(&self, uri: &str) -> Result<WebSocketRequestBuilder, WebSocketError> {
        WebSocketRequestBuilder::new_session(self.clone(), uri)
    }

    /// Returns this session's cookie jar when cookie handling was enabled.
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookie_jar(&self) -> Option<&CookieJar> {
        self.state.cookies.as_deref()
    }
}

impl fmt::Debug for Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Session")
            .field("redirect_policy", &self.state.redirect_policy)
            .field(
                "max_retained_http1_connections",
                &self.state.http1.capacity(),
            )
            .field(
                "max_pending_http1_requests_per_origin",
                &self.state.http1.max_pending(),
            )
            .field(
                "max_retained_http2_connections",
                &self.state.http2.capacity(),
            )
            .field(
                "max_concurrent_http2_requests_per_origin",
                &self.state.http2.max_active(),
            )
            .field(
                "max_pending_http2_requests_per_origin",
                &self.state.http2.max_pending(),
            )
            .field(
                "max_retained_http3_connections",
                &self.state.http3.capacity(),
            )
            .field(
                "max_concurrent_http3_requests_per_origin",
                &self.state.http3.max_active(),
            )
            .field(
                "max_pending_http3_requests_per_origin",
                &self.state.http3.max_pending(),
            )
            .field("cookies_enabled", &{
                #[cfg(feature = "cookies")]
                {
                    self.state.cookies.is_some()
                }
                #[cfg(not(feature = "cookies"))]
                {
                    false
                }
            })
            .finish_non_exhaustive()
    }
}

/// Builds one isolated [`Session`].
pub struct SessionBuilder {
    client: Client,
    redirect_policy: RedirectPolicy,
    max_retained_http1_connections: NonZeroUsize,
    max_pending_http1_requests_per_origin: NonZeroUsize,
    max_retained_http2_connections: NonZeroUsize,
    max_concurrent_http2_requests_per_origin: NonZeroUsize,
    max_pending_http2_requests_per_origin: NonZeroUsize,
    max_retained_http3_connections: NonZeroUsize,
    max_concurrent_http3_requests_per_origin: NonZeroUsize,
    max_pending_http3_requests_per_origin: NonZeroUsize,
    #[cfg(feature = "cookies")]
    cookie_jar: Option<CookieJar>,
}

impl SessionBuilder {
    pub(crate) fn new(client: Client) -> Self {
        Self {
            client,
            redirect_policy: RedirectPolicy::none(),
            max_retained_http1_connections: DEFAULT_MAX_RETAINED_HTTP1_CONNECTIONS,
            max_pending_http1_requests_per_origin: DEFAULT_MAX_PENDING_HTTP1_REQUESTS_PER_ORIGIN,
            max_retained_http2_connections: DEFAULT_MAX_RETAINED_HTTP2_CONNECTIONS,
            max_retained_http3_connections: DEFAULT_MAX_RETAINED_HTTP3_CONNECTIONS,
            max_concurrent_http2_requests_per_origin:
                DEFAULT_MAX_CONCURRENT_HTTP2_REQUESTS_PER_ORIGIN,
            max_pending_http2_requests_per_origin: DEFAULT_MAX_PENDING_HTTP2_REQUESTS_PER_ORIGIN,
            max_concurrent_http3_requests_per_origin:
                DEFAULT_MAX_CONCURRENT_HTTP3_REQUESTS_PER_ORIGIN,
            max_pending_http3_requests_per_origin: DEFAULT_MAX_PENDING_HTTP3_REQUESTS_PER_ORIGIN,
            #[cfg(feature = "cookies")]
            cookie_jar: None,
        }
    }

    /// Sets the policy for following redirect responses.
    ///
    /// Redirects are disabled unless a finite policy is supplied explicitly.
    #[must_use]
    pub fn redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.redirect_policy = policy;
        self
    }

    /// Sets the maximum number of HTTP/1.1 connections retained for reuse.
    #[must_use]
    pub fn max_retained_http1_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.max_retained_http1_connections = maximum;
        self
    }

    /// Sets the number of sequential requests allowed to wait for each HTTP/1.1 origin and route.
    #[must_use]
    pub fn max_pending_http1_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.max_pending_http1_requests_per_origin = maximum;
        self
    }

    /// Sets the maximum number of HTTP/2 connections retained for reuse.
    ///
    /// Evicting a connection from the pool does not cancel response bodies
    /// already using it. It prevents later requests from selecting it.
    #[must_use]
    pub fn max_retained_http2_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.max_retained_http2_connections = maximum;
        self
    }

    /// Sets the local active-request bound for each HTTP/2 origin and route.
    ///
    /// The bound spans a draining connection and its replacement. The peer's
    /// advertised concurrent-stream limit remains independently authoritative.
    #[must_use]
    pub fn max_concurrent_http2_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.max_concurrent_http2_requests_per_origin = maximum;
        self
    }

    /// Sets the number of requests allowed to wait for each HTTP/2 origin and route.
    #[must_use]
    pub fn max_pending_http2_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.max_pending_http2_requests_per_origin = maximum;
        self
    }

    /// Sets the maximum number of HTTP/3 connections retained for reuse.
    ///
    /// Eviction prevents later selection but does not cancel response bodies
    /// already using the connection.
    #[must_use]
    pub fn max_retained_http3_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.max_retained_http3_connections = maximum;
        self
    }

    /// Sets the local active-request bound for each retained HTTP/3 origin and route.
    ///
    /// The bound spans a draining connection and its replacement so a stale
    /// generation cannot temporarily double the origin's admitted work.
    #[must_use]
    pub fn max_concurrent_http3_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.max_concurrent_http3_requests_per_origin = maximum;
        self
    }

    /// Sets the number of requests allowed to wait for each HTTP/3 origin and route.
    #[must_use]
    pub fn max_pending_http3_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.max_pending_http3_requests_per_origin = maximum;
        self
    }

    /// Enables an isolated in-memory cookie jar with default bounds.
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookies(mut self) -> Self {
        self.cookie_jar = Some(CookieJar::default());
        self
    }

    /// Enables cookie handling with a caller-created jar.
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookie_jar(mut self, jar: CookieJar) -> Self {
        self.cookie_jar = Some(jar);
        self
    }

    /// Builds the session.
    #[must_use]
    pub fn build(self) -> Session {
        Session {
            client: self.client,
            state: Arc::new(SessionState {
                redirect_policy: self.redirect_policy,
                http1: http1_pool::Http1Pool::new(
                    self.max_retained_http1_connections,
                    self.max_pending_http1_requests_per_origin,
                ),
                http2: http2_pool::Http2Pool::new(
                    self.max_retained_http2_connections,
                    self.max_concurrent_http2_requests_per_origin,
                    self.max_pending_http2_requests_per_origin,
                ),
                http3: http3_pool::Http3Pool::new(
                    self.max_retained_http3_connections,
                    self.max_concurrent_http3_requests_per_origin,
                    self.max_pending_http3_requests_per_origin,
                ),
                #[cfg(feature = "cookies")]
                cookies: self.cookie_jar.map(Arc::new),
            }),
        }
    }
}

impl fmt::Debug for SessionBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionBuilder")
            .field("redirect_policy", &self.redirect_policy)
            .field(
                "max_retained_http1_connections",
                &self.max_retained_http1_connections,
            )
            .field(
                "max_pending_http1_requests_per_origin",
                &self.max_pending_http1_requests_per_origin,
            )
            .field(
                "max_retained_http2_connections",
                &self.max_retained_http2_connections,
            )
            .field(
                "max_concurrent_http2_requests_per_origin",
                &self.max_concurrent_http2_requests_per_origin,
            )
            .field(
                "max_pending_http2_requests_per_origin",
                &self.max_pending_http2_requests_per_origin,
            )
            .field(
                "max_retained_http3_connections",
                &self.max_retained_http3_connections,
            )
            .field(
                "max_concurrent_http3_requests_per_origin",
                &self.max_concurrent_http3_requests_per_origin,
            )
            .field(
                "max_pending_http3_requests_per_origin",
                &self.max_pending_http3_requests_per_origin,
            )
            .field("cookies_enabled", &{
                #[cfg(feature = "cookies")]
                {
                    self.cookie_jar.is_some()
                }
                #[cfg(not(feature = "cookies"))]
                {
                    false
                }
            })
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{Session, SessionBuilder};
    use crate::{RequestBuilder, ResponseBody};

    fn assert_send_sync_clone<T: Send + Sync + Clone>() {}
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn session_handles_are_send_sync_and_clone() {
        assert_send_sync_clone::<Session>();
        fn assert_send<T: Send>() {}
        assert_send::<SessionBuilder>();
        fn assert_send_static<T: Send + 'static>() {}
        assert_send_static::<RequestBuilder>();
        assert_send_sync::<ResponseBody>();
        #[cfg(feature = "cookies")]
        assert_send_sync::<super::CookieJar>();
    }
}
