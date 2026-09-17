use std::{fmt, num::NonZeroUsize, sync::Arc};

use crate::{Client, RedirectPolicy, RequestTimeouts, client::ClientInner};
#[cfg(feature = "sse")]
use crate::{HttpProtocol, RequestError, SseRequestBuilder};

mod admission;
pub(crate) mod client_hints;
#[cfg(feature = "cookies")]
mod cookies;
pub(crate) mod http1_or_2_pool;
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
const DEFAULT_MAX_CLIENT_HINT_ORIGINS: NonZeroUsize = match NonZeroUsize::new(64) {
    Some(value) => value,
    None => NonZeroUsize::MIN,
};

pub(crate) struct ClientOptions {
    pub(crate) redirect_policy: RedirectPolicy,
    pub(crate) request_timeouts: RequestTimeouts,
    pub(crate) max_retained_http1_connections: NonZeroUsize,
    pub(crate) max_pending_http1_requests_per_origin: NonZeroUsize,
    pub(crate) max_retained_http2_connections: NonZeroUsize,
    pub(crate) max_concurrent_http2_requests_per_origin: NonZeroUsize,
    pub(crate) max_pending_http2_requests_per_origin: NonZeroUsize,
    pub(crate) max_retained_http3_connections: NonZeroUsize,
    pub(crate) max_concurrent_http3_requests_per_origin: NonZeroUsize,
    pub(crate) max_pending_http3_requests_per_origin: NonZeroUsize,
    pub(crate) max_client_hint_origins: NonZeroUsize,
    #[cfg(feature = "cookies")]
    pub(crate) cookie_jar: Option<CookieJar>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            redirect_policy: RedirectPolicy::none(),
            request_timeouts: RequestTimeouts::default(),
            max_retained_http1_connections: DEFAULT_MAX_RETAINED_HTTP1_CONNECTIONS,
            max_pending_http1_requests_per_origin: DEFAULT_MAX_PENDING_HTTP1_REQUESTS_PER_ORIGIN,
            max_retained_http2_connections: DEFAULT_MAX_RETAINED_HTTP2_CONNECTIONS,
            max_concurrent_http2_requests_per_origin:
                DEFAULT_MAX_CONCURRENT_HTTP2_REQUESTS_PER_ORIGIN,
            max_pending_http2_requests_per_origin: DEFAULT_MAX_PENDING_HTTP2_REQUESTS_PER_ORIGIN,
            max_retained_http3_connections: DEFAULT_MAX_RETAINED_HTTP3_CONNECTIONS,
            max_concurrent_http3_requests_per_origin:
                DEFAULT_MAX_CONCURRENT_HTTP3_REQUESTS_PER_ORIGIN,
            max_pending_http3_requests_per_origin: DEFAULT_MAX_PENDING_HTTP3_REQUESTS_PER_ORIGIN,
            max_client_hint_origins: DEFAULT_MAX_CLIENT_HINT_ORIGINS,
            #[cfg(feature = "cookies")]
            cookie_jar: None,
        }
    }
}

/// Compatibility name for the pooled [`Client`] owner.
#[doc(hidden)]
pub type Session = Client;

pub(crate) struct ClientState {
    pub(crate) redirect_policy: RedirectPolicy,
    pub(crate) request_timeouts: RequestTimeouts,
    pub(crate) http1: http1_pool::Http1Pool,
    pub(crate) http1_or_2: http1_or_2_pool::Http1Or2Pool,
    pub(crate) http2: http2_pool::Http2Pool,
    pub(crate) http3: http3_pool::Http3Pool,
    client_hints: Option<client_hints::ClientHintStore>,
    #[cfg(feature = "cookies")]
    pub(crate) cookies: Option<Arc<CookieJar>>,
}

impl ClientOptions {
    pub(crate) fn build(self, inner: &ClientInner) -> Arc<ClientState> {
        Arc::new(ClientState {
            redirect_policy: self.redirect_policy,
            request_timeouts: self.request_timeouts,
            http1: http1_pool::Http1Pool::new(
                self.max_retained_http1_connections,
                self.max_pending_http1_requests_per_origin,
            ),
            http1_or_2: http1_or_2_pool::Http1Or2Pool::new(
                self.max_retained_http1_connections,
                self.max_pending_http1_requests_per_origin,
                self.max_retained_http2_connections,
                self.max_concurrent_http2_requests_per_origin,
                self.max_pending_http2_requests_per_origin,
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
            client_hints: inner
                .client_hints
                .is_some()
                .then(|| client_hints::ClientHintStore::new(self.max_client_hint_origins)),
            #[cfg(feature = "cookies")]
            cookies: self.cookie_jar.map(Arc::new),
        })
    }
}

impl Client {
    /// Returns the default timeout policy for ordinary requests.
    #[must_use]
    pub fn request_timeouts(&self) -> RequestTimeouts {
        self.state.request_timeouts
    }

    pub(crate) fn client_hint_context<'a>(
        &'a self,
        endpoint: &'a crate::authority::Endpoint,
        origin: &'a str,
        settings: &'a phantom_profile::ClientHintSettings,
    ) -> client_hints::ClientHintContext<'a> {
        client_hints::ClientHintContext::new(
            endpoint,
            origin,
            settings,
            self.state.client_hints.as_ref(),
        )
    }

    pub(crate) fn learn_client_hints_and_should_retry(
        &self,
        endpoint: &crate::authority::Endpoint,
        settings: &phantom_profile::ClientHintSettings,
        response: &http::HeaderMap,
        sent: &[phantom_net::request::RequestHeader],
    ) -> bool {
        self.state
            .client_hints
            .as_ref()
            .is_some_and(|client_hints| {
                client_hints.learn_and_should_retry(endpoint, settings, response, sent)
            })
    }

    /// Starts a bounded server-sent event source using this client's state.
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
        SseRequestBuilder::new_client(self.clone(), protocol, uri)
    }

    /// Returns this client's cookie jar when cookie handling was enabled.
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookie_jar(&self) -> Option<&CookieJar> {
        self.state.cookies.as_deref()
    }

    /// Clears all `Accept-CH` preferences learned by this client.
    pub fn clear_client_hints(&self) {
        if let Some(client_hints) = &self.state.client_hints {
            client_hints.clear();
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Client")
            .field("redirect_policy", &self.state.redirect_policy)
            .field("request_timeouts", &self.state.request_timeouts)
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
            .field("client_hints_enabled", &self.state.client_hints.is_some())
            .field(
                "max_client_hint_origins",
                &self
                    .state
                    .client_hints
                    .as_ref()
                    .map(client_hints::ClientHintStore::capacity),
            )
            .finish_non_exhaustive()
    }
}

/// Builds an isolated compatibility client from existing transport configuration.
#[doc(hidden)]
pub struct SessionBuilder {
    inner: Arc<ClientInner>,
    options: ClientOptions,
}

impl SessionBuilder {
    pub(crate) fn new(client: Client) -> Self {
        Self {
            inner: client.inner,
            options: ClientOptions::default(),
        }
    }

    /// Sets the policy for following redirect responses.
    ///
    /// Redirects are disabled unless a finite policy is supplied explicitly.
    #[must_use]
    pub fn redirect_policy(mut self, policy: RedirectPolicy) -> Self {
        self.options.redirect_policy = policy;
        self
    }

    /// Sets the maximum number of HTTP/1.1 connections retained for reuse.
    #[must_use]
    pub fn max_retained_http1_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_retained_http1_connections = maximum;
        self
    }

    /// Sets the number of sequential requests allowed to wait for each HTTP/1.1 origin and route.
    #[must_use]
    pub fn max_pending_http1_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_pending_http1_requests_per_origin = maximum;
        self
    }

    /// Sets the maximum number of HTTP/2 connections retained for reuse.
    ///
    /// Evicting a connection from the pool does not cancel response bodies
    /// already using it. It prevents later requests from selecting it.
    #[must_use]
    pub fn max_retained_http2_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_retained_http2_connections = maximum;
        self
    }

    /// Sets the local active-request bound for each HTTP/2 origin and route.
    ///
    /// The bound spans a draining connection and its replacement. The peer's
    /// advertised concurrent-stream limit remains independently authoritative.
    #[must_use]
    pub fn max_concurrent_http2_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_concurrent_http2_requests_per_origin = maximum;
        self
    }

    /// Sets the number of requests allowed to wait for each HTTP/2 origin and route.
    #[must_use]
    pub fn max_pending_http2_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_pending_http2_requests_per_origin = maximum;
        self
    }

    /// Sets the maximum number of HTTP/3 connections retained for reuse.
    ///
    /// Eviction prevents later selection but does not cancel response bodies
    /// already using the connection.
    #[must_use]
    pub fn max_retained_http3_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_retained_http3_connections = maximum;
        self
    }

    /// Sets the local active-request bound for each retained HTTP/3 origin and route.
    ///
    /// The bound spans a draining connection and its replacement so a stale
    /// generation cannot temporarily double the origin's admitted work.
    #[must_use]
    pub fn max_concurrent_http3_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_concurrent_http3_requests_per_origin = maximum;
        self
    }

    /// Sets the number of requests allowed to wait for each HTTP/3 origin and route.
    #[must_use]
    pub fn max_pending_http3_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_pending_http3_requests_per_origin = maximum;
        self
    }

    /// Sets the number of origins that may retain `Accept-CH` state.
    #[must_use]
    pub fn max_client_hint_origins(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_client_hint_origins = maximum;
        self
    }

    /// Enables an isolated in-memory cookie jar with default bounds.
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookies(mut self) -> Self {
        self.options.cookie_jar = Some(CookieJar::default());
        self
    }

    /// Enables cookie handling with a caller-created jar.
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookie_jar(mut self, jar: CookieJar) -> Self {
        self.options.cookie_jar = Some(jar);
        self
    }

    /// Builds the isolated client.
    #[must_use]
    pub fn build(self) -> Client {
        let state = self.options.build(&self.inner);
        Client {
            inner: self.inner,
            state,
        }
    }
}

impl fmt::Debug for SessionBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionBuilder")
            .field("redirect_policy", &self.options.redirect_policy)
            .field(
                "max_retained_http1_connections",
                &self.options.max_retained_http1_connections,
            )
            .field(
                "max_pending_http1_requests_per_origin",
                &self.options.max_pending_http1_requests_per_origin,
            )
            .field(
                "max_retained_http2_connections",
                &self.options.max_retained_http2_connections,
            )
            .field(
                "max_concurrent_http2_requests_per_origin",
                &self.options.max_concurrent_http2_requests_per_origin,
            )
            .field(
                "max_pending_http2_requests_per_origin",
                &self.options.max_pending_http2_requests_per_origin,
            )
            .field(
                "max_retained_http3_connections",
                &self.options.max_retained_http3_connections,
            )
            .field(
                "max_concurrent_http3_requests_per_origin",
                &self.options.max_concurrent_http3_requests_per_origin,
            )
            .field(
                "max_pending_http3_requests_per_origin",
                &self.options.max_pending_http3_requests_per_origin,
            )
            .field(
                "max_client_hint_origins",
                &self.options.max_client_hint_origins,
            )
            .field("cookies_enabled", &{
                #[cfg(feature = "cookies")]
                {
                    self.options.cookie_jar.is_some()
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
    use super::SessionBuilder;
    use crate::{Client, RequestBuilder, ResponseBody};

    fn assert_send_sync_clone<T: Send + Sync + Clone>() {}
    fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn client_handles_are_send_sync_and_clone() {
        assert_send_sync_clone::<Client>();
        fn assert_send<T: Send>() {}
        assert_send::<SessionBuilder>();
        fn assert_send_static<T: Send + 'static>() {}
        assert_send_static::<RequestBuilder>();
        assert_send_sync::<ResponseBody>();
        #[cfg(feature = "cookies")]
        assert_send_sync::<super::CookieJar>();
    }
}
