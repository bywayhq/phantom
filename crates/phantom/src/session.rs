use std::{fmt, num::NonZeroUsize, sync::Arc};

use crate::{
    BuildError, Client, RedirectPolicy, RequestTimeouts, RetryPolicy, client::ClientInner,
};
#[cfg(feature = "sse")]
use crate::{HttpProtocol, RequestError, SseRequestBuilder};

mod admission;
pub(crate) mod alt_svc;
pub(crate) mod client_hints;
#[cfg(feature = "cookies")]
mod cookies;
pub(crate) mod http1_or_2_pool;
pub(crate) mod http1_pool;
mod http2_pool;
pub(crate) mod http3_pool;

pub use alt_svc::{
    AltSvcSnapshot, AltSvcSnapshotEntry, AltSvcSnapshotError, AltSvcSnapshotErrorKind,
};
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
    pub(crate) retry_policy: RetryPolicy,
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
    pub(crate) max_alt_svc_origins: Option<NonZeroUsize>,
    #[cfg(feature = "cookies")]
    pub(crate) cookie_jar: Option<CookieJar>,
}

impl Default for ClientOptions {
    fn default() -> Self {
        Self {
            redirect_policy: RedirectPolicy::none(),
            retry_policy: RetryPolicy::none(),
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
            max_alt_svc_origins: None,
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
    pub(crate) retry_policy: RetryPolicy,
    pub(crate) request_timeouts: RequestTimeouts,
    pub(crate) http1: http1_pool::Http1Pool,
    pub(crate) http1_or_2: http1_or_2_pool::Http1Or2Pool,
    pub(crate) http2: http2_pool::Http2Pool,
    pub(crate) http3: http3_pool::Http3Pool,
    alt_svc: Option<alt_svc::AltSvcStore>,
    client_hints: Option<client_hints::ClientHintStore>,
    #[cfg(feature = "cookies")]
    pub(crate) cookies: Option<Arc<CookieJar>>,
}

impl ClientOptions {
    pub(crate) fn validate(&self, inner: &ClientInner) -> Result<(), BuildError> {
        self.validate_protocols(inner.http1_or_2.is_some(), inner.http3.is_some())
    }

    pub(crate) fn validate_protocols(
        &self,
        negotiated: bool,
        http3: bool,
    ) -> Result<(), BuildError> {
        if self.max_alt_svc_origins.is_some() && !(negotiated && http3) {
            return Err(BuildError::invalid_policy(
                "Alt-Svc requires negotiated HTTP/1.1+HTTP/2 and HTTP/3 profiles",
            ));
        }
        Ok(())
    }

    pub(crate) fn build(self, inner: &ClientInner) -> Arc<ClientState> {
        Arc::new(ClientState {
            redirect_policy: self.redirect_policy,
            retry_policy: self.retry_policy,
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
            alt_svc: self.max_alt_svc_origins.map(alt_svc::AltSvcStore::new),
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
    /// Returns the policy for retrying connection-establishment failures.
    #[must_use]
    pub fn retry_policy(&self) -> RetryPolicy {
        self.state.retry_policy
    }

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

    pub(crate) fn alt_svc_location(
        &self,
        endpoint: &crate::authority::Endpoint,
    ) -> Option<(Box<str>, u16, Box<str>, u64)> {
        self.state.alt_svc.as_ref()?.get(endpoint).map(|selection| {
            (
                Box::<str>::from(selection.location().host()),
                selection.location().port(),
                selection.location().authority(),
                selection.generation(),
            )
        })
    }

    pub(crate) fn alt_svc_enabled(&self) -> bool {
        self.state.alt_svc.is_some()
    }

    pub(crate) fn learn_alt_svc<B>(
        &self,
        endpoint: &crate::authority::Endpoint,
        response: &http::Response<B>,
    ) {
        let Some(store) = &self.state.alt_svc else {
            return;
        };
        // ALTSVC frames precede the response HEADERS on the wire, so they are
        // applied before the response's own Alt-Svc field.
        if let Some(frames) = response
            .extensions()
            .get::<phantom_net::http2::AltSvcFrames>()
        {
            store.learn_frames(endpoint, frames);
        }
        let Some(headers) = response
            .extensions()
            .get::<phantom_net::OrderedResponseHeaders>()
        else {
            return;
        };
        store.learn(endpoint, headers);
    }

    pub(crate) fn remove_alt_svc_if_current(
        &self,
        endpoint: &crate::authority::Endpoint,
        generation: u64,
    ) {
        if let Some(store) = &self.state.alt_svc {
            store.remove_if_current(endpoint, generation);
        }
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

    /// Clears all alternative services learned by this client.
    pub fn clear_alt_svc(&self) {
        if let Some(alt_svc) = &self.state.alt_svc {
            alt_svc.clear();
        }
    }

    /// Exports this client's unexpired Alt-Svc alternatives for caller-owned
    /// persistence, least recently used first.
    ///
    /// Returns `None` when the client was built without
    /// [`ClientBuilder::alt_svc`](crate::ClientBuilder::alt_svc). Expiry is
    /// the remaining lifetime as wall-clock time, rounded down to a second.
    /// Snapshots describe direct-route alternatives only.
    #[must_use]
    pub fn export_alt_svc(&self) -> Option<AltSvcSnapshot> {
        self.state
            .alt_svc
            .as_ref()
            .map(alt_svc::AltSvcStore::export)
    }

    /// Imports alternatives from a previously exported or caller-built snapshot.
    ///
    /// Every entry is revalidated first; one invalid entry rejects the whole
    /// snapshot without changing state. Expired entries are dropped, a later
    /// entry for the same origin wins, and lifetimes are clamped and never
    /// extended. Alternatives this client already holds take precedence and
    /// imported entries rank as least recently used, so capacity keeps held
    /// entries and then the most recently used snapshot entries. Every
    /// imported entry receives a fresh generation, like a learned one.
    ///
    /// # Errors
    ///
    /// Returns [`AltSvcSnapshotError`] with
    /// [`AltSvcSnapshotErrorKind::Disabled`] when Alt-Svc is not enabled,
    /// [`AltSvcSnapshotErrorKind::NoncanonicalOrigin`] for an origin that is
    /// not a canonical HTTPS origin serialization, or
    /// [`AltSvcSnapshotErrorKind::InvalidAlternative`] for a noncanonical
    /// host or zero port.
    pub fn import_alt_svc(&self, snapshot: &AltSvcSnapshot) -> Result<(), AltSvcSnapshotError> {
        self.state
            .alt_svc
            .as_ref()
            .ok_or_else(AltSvcSnapshotError::disabled)?
            .import(snapshot)
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Client")
            .field("redirect_policy", &self.state.redirect_policy)
            .field("retry_policy", &self.state.retry_policy)
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
            .field("alt_svc_enabled", &self.state.alt_svc.is_some())
            .field(
                "max_alt_svc_origins",
                &self
                    .state
                    .alt_svc
                    .as_ref()
                    .map(alt_svc::AltSvcStore::capacity),
            )
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

    /// Sets the policy for retrying connection-establishment failures.
    ///
    /// Connection retries are disabled by default and apply only to
    /// connection setup before dispatch: exact-protocol acquisition and
    /// negotiated H1/H2 TCP setup before ALPN selection.
    #[must_use]
    pub fn retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.options.retry_policy = policy;
        self
    }

    /// Sets the maximum number of HTTP/1.1 connections retained for reuse.
    ///
    /// The direct negotiated H1/H2 pool uses the lower of the configured H1
    /// and H2 retention limits so neither maximum is exceeded.
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
    /// The direct negotiated H1/H2 pool uses the lower of the configured H1
    /// and H2 retention limits so neither maximum is exceeded.
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

    /// Enables bounded, isolated Alt-Svc learning for negotiated HTTPS requests.
    #[must_use]
    pub fn alt_svc(mut self, maximum_origins: NonZeroUsize) -> Self {
        self.options.max_alt_svc_origins = Some(maximum_origins);
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
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] with [`BuildErrorKind::InvalidPolicy`] when
    /// Alt-Svc learning is enabled but the transport lacks negotiated
    /// HTTP/1.1+HTTP/2 or HTTP/3, matching [`ClientBuilder::build`].
    ///
    /// [`BuildErrorKind::InvalidPolicy`]: crate::BuildErrorKind::InvalidPolicy
    /// [`ClientBuilder::build`]: crate::ClientBuilder::build
    pub fn build(self) -> Result<Client, BuildError> {
        self.options.validate(&self.inner)?;
        let state = self.options.build(&self.inner);
        Ok(Client {
            inner: self.inner,
            state,
        })
    }
}

impl fmt::Debug for SessionBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionBuilder")
            .field("redirect_policy", &self.options.redirect_policy)
            .field("retry_policy", &self.options.retry_policy)
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
            .field("max_alt_svc_origins", &self.options.max_alt_svc_origins)
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
