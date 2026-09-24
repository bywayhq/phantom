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
    AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, AltSvcSnapshot, AltSvcSnapshotEntry,
    AltSvcSnapshotError, AltSvcSnapshotErrorKind,
};
#[cfg(feature = "cookies")]
pub use cookies::{
    CookieError, CookieErrorKind, CookieJar, CookieLimits, CookieSameSite, CookieSnapshot,
    CookieSnapshotEntry, CookieSnapshotError, CookieSnapshotErrorKind, CookieSourceScheme,
};

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
    /// Replaces the profile's HTTP/1.1 connection bound when set.
    pub(crate) max_concurrent_http1_requests_per_origin: Option<NonZeroUsize>,
    pub(crate) max_pending_http1_requests_per_origin: NonZeroUsize,
    pub(crate) max_retained_http2_connections: NonZeroUsize,
    pub(crate) max_concurrent_http2_requests_per_origin: NonZeroUsize,
    pub(crate) max_pending_http2_requests_per_origin: NonZeroUsize,
    pub(crate) max_retained_http3_connections: NonZeroUsize,
    pub(crate) max_concurrent_http3_requests_per_origin: NonZeroUsize,
    pub(crate) max_pending_http3_requests_per_origin: NonZeroUsize,
    pub(crate) max_client_hint_origins: NonZeroUsize,
    pub(crate) max_alt_svc_origins: Option<NonZeroUsize>,
    pub(crate) alt_svc_policy: AltSvcPolicy,
    pub(crate) http3_early_data: bool,
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
            max_concurrent_http1_requests_per_origin: None,
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
            alt_svc_policy: AltSvcPolicy::sequential(),
            http3_early_data: false,
            #[cfg(feature = "cookies")]
            cookie_jar: None,
        }
    }
}

/// A pooled HTTP/2 connection and the per-origin admission for one stream.
#[cfg(feature = "websocket")]
pub(crate) type PooledHttp2Session = (
    phantom_net::http2::Http2Connection,
    admission::AdmissionPermit,
);

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
    alt_svc_policy: AltSvcPolicy,
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
        if self.alt_svc_policy.race_settings().is_some() && self.max_alt_svc_origins.is_none() {
            return Err(BuildError::invalid_policy(
                "Alt-Svc racing requires an Alt-Svc store",
            ));
        }
        self.alt_svc_policy.validate()
    }

    pub(crate) fn build(self, inner: &ClientInner) -> Arc<ClientState> {
        Arc::new(ClientState {
            redirect_policy: self.redirect_policy,
            retry_policy: self.retry_policy,
            request_timeouts: self.request_timeouts,
            http1: http1_pool::Http1Pool::new(
                self.max_retained_http1_connections,
                self.max_concurrent_http1_requests_per_origin
                    .unwrap_or(inner.http1_connections_per_origin),
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
            alt_svc_policy: self.alt_svc_policy,
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
    /// Admits one stream on a pooled, reusable HTTP/2 session to the origin.
    ///
    /// Both pools are keyed by origin and route. The negotiated pool is
    /// consulted for the direct route only: a WebSocket reusing a negotiated
    /// session is browser behavior captured for direct connections, and no
    /// capture covers reusing a proxied negotiated session, so the exact
    /// HTTP/2 pool answers for every proxy route. Nothing is opened. The
    /// returned permit is that pool's per-origin HTTP/2 admission; holding it
    /// counts the stream against the origin's active bound until dropped.
    ///
    /// # Errors
    ///
    /// Returns a typed capacity error when the origin's waiting bound is full.
    #[cfg(feature = "websocket")]
    pub(crate) async fn admit_http2_session(
        &self,
        endpoint: &crate::authority::Endpoint,
        route: &crate::Route,
    ) -> Result<Option<PooledHttp2Session>, crate::RequestError> {
        // See the note above: deliberately the direct route only, even though
        // the negotiated pool can now hold proxied sessions.
        if matches!(route, crate::Route::Direct)
            && let Some(session) = self
                .state
                .http1_or_2
                .admit_current_http2_connection(endpoint, route)
                .await?
        {
            return Ok(Some(session));
        }
        self.state
            .http2
            .admit_current_connection(endpoint, route)
            .await
    }

    /// Returns the client's default retry policy.
    ///
    /// It covers connection-setup retries, reused-connection and
    /// unprocessed-request replays, and status retries.
    /// [`RequestBuilder::retry_policy`](crate::RequestBuilder::retry_policy)
    /// replaces it for one request.
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
        route: &crate::Route,
    ) -> Option<alt_svc::AlternativeTarget> {
        self.state
            .alt_svc
            .as_ref()?
            .get(endpoint, route)
            .map(|selection| alt_svc::AlternativeTarget::new(&selection))
    }

    /// Returns how negotiated requests use a learned alternative.
    pub(crate) fn alt_svc_policy(&self) -> AltSvcPolicy {
        self.state.alt_svc_policy
    }

    pub(crate) fn mark_alt_svc_broken(
        &self,
        endpoint: &crate::authority::Endpoint,
        route: &crate::Route,
        alternative: &alt_svc::AlternativeTarget,
        backoff: AltSvcBrokenBackoff,
    ) {
        if let Some(store) = &self.state.alt_svc {
            store.mark_broken(endpoint, route, alternative.location(), backoff);
        }
    }

    pub(crate) fn confirm_alt_svc(
        &self,
        endpoint: &crate::authority::Endpoint,
        route: &crate::Route,
        alternative: &alt_svc::AlternativeTarget,
    ) {
        if let Some(store) = &self.state.alt_svc {
            store.confirm(endpoint, route, alternative.location());
        }
    }

    pub(crate) fn alt_svc_enabled(&self) -> bool {
        self.state.alt_svc.is_some()
    }

    pub(crate) fn learn_alt_svc<B>(
        &self,
        endpoint: &crate::authority::Endpoint,
        route: &crate::Route,
        response: &http::Response<B>,
    ) {
        let Some(store) = &self.state.alt_svc else {
            return;
        };
        // A route without a UDP path could never dial an `h3` alternative, so
        // its advertisements are not stored.
        if !route.carries_quic_alternative() {
            return;
        }
        // ALTSVC frames precede the response HEADERS on the wire, so they are
        // applied before the response's own Alt-Svc field.
        if let Some(frames) = response
            .extensions()
            .get::<phantom_net::http2::AltSvcFrames>()
        {
            store.learn_frames(endpoint, route, frames);
        }
        let Some(headers) = response
            .extensions()
            .get::<phantom_net::OrderedResponseHeaders>()
        else {
            return;
        };
        store.learn(endpoint, route, headers);
    }

    pub(crate) fn remove_alt_svc_if_current(
        &self,
        endpoint: &crate::authority::Endpoint,
        route: &crate::Route,
        generation: u64,
    ) {
        if let Some(store) = &self.state.alt_svc {
            store.remove_if_current(endpoint, route, generation);
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
    ///
    /// Returns `None` unless the client was built with
    /// [`ClientBuilder::cookies`](crate::ClientBuilder::cookies) or
    /// [`ClientBuilder::cookie_jar`](crate::ClientBuilder::cookie_jar).
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn cookie_jar(&self) -> Option<&CookieJar> {
        self.state.cookies.as_deref()
    }

    /// Exports this client's unexpired cookies for caller-owned persistence,
    /// oldest first.
    ///
    /// Returns `None` when the client was built without a cookie jar. Each
    /// entry keeps every attribute, the partition key of a `Partitioned`
    /// cookie, and the scheme of the URL that set it. A persistent cookie's
    /// expiry is rounded down to a second; a session cookie has none and is
    /// exported too, so restoring one continues the session. Exporting does
    /// not count as a use for eviction.
    ///
    /// # Examples
    ///
    /// ```
    /// use phantom::{Client, profile::ClientProfile, profile::chromium};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let profile = || ClientProfile::new(chromium::v154_tls());
    /// let client = Client::builder(profile()).cookies().build()?;
    /// if let Some(jar) = client.cookie_jar() {
    ///     jar.set_cookie("https://example.com/", "sid=1; Secure; HttpOnly")?;
    /// }
    ///
    /// let snapshot = client.export_cookies().ok_or("cookies are enabled")?;
    /// let restored = Client::builder(profile()).cookies().build()?;
    /// restored.import_cookies(&snapshot)?;
    /// assert_eq!(
    ///     restored
    ///         .cookie_jar()
    ///         .map(|jar| jar.request_value("https://example.com/"))
    ///         .transpose()?
    ///         .flatten()
    ///         .as_deref(),
    ///     Some("sid=1")
    /// );
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "cookies")]
    #[must_use]
    pub fn export_cookies(&self) -> Option<CookieSnapshot> {
        self.state.cookies.as_deref().map(CookieJar::export)
    }

    /// Imports cookies from a previously exported or caller-built snapshot.
    ///
    /// Every entry is revalidated first as the `Set-Cookie` field a response
    /// from its source scheme and domain would send, under the same rules and
    /// byte limit that govern response cookies, and one invalid entry rejects
    /// the whole snapshot without changing state. An import can therefore
    /// store only a cookie a response could have stored.
    ///
    /// Expired entries are dropped, a later entry with the same name, domain,
    /// path, and host-only and partitioned flags wins, and expiry is rounded
    /// down to a second and never extended. Cookies the jar already holds
    /// take precedence, as does a held `Secure` cookie that an entry from an
    /// untrustworthy origin would overlay. Imported cookies rank as created
    /// and used before every held cookie. The jar's count limits admit
    /// imported cookies up to each limit instead of evicting, so capacity
    /// keeps every held cookie and then the newest snapshot entries.
    ///
    /// # Errors
    ///
    /// Returns [`CookieSnapshotError`] with
    /// [`CookieSnapshotErrorKind::Disabled`] when the client has no cookie
    /// jar, or with the category and index of the first entry that storage
    /// would refuse.
    #[cfg(feature = "cookies")]
    pub fn import_cookies(&self, snapshot: &CookieSnapshot) -> Result<(), CookieSnapshotError> {
        self.state
            .cookies
            .as_deref()
            .ok_or_else(CookieSnapshotError::disabled)?
            .import(snapshot)
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
    /// The store keys each alternative by origin and route; an export keeps
    /// the direct-route entries and omits every proxy-route one.
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
    /// imported entry receives a fresh generation, like a learned one, and
    /// belongs to the direct route, so no import can reach a proxy route.
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
                "max_concurrent_http1_requests_per_origin",
                &self.state.http1.max_active(),
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
            .field("alt_svc_policy", &self.state.alt_svc_policy)
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
    /// The negotiated H1/H2 pool uses the lower of the configured H1 and H2
    /// retention limits so neither maximum is exceeded.
    #[must_use]
    pub fn max_retained_http1_connections(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_retained_http1_connections = maximum;
        self
    }

    /// Sets the local active-request bound for each HTTP/1.1 origin and route.
    ///
    /// Each active HTTP/1.1 request holds its own connection, so this is also
    /// the most connections open at once to the pool key, idle ones included.
    /// It replaces the profile's HTTP/1.1 connection bound for the new client.
    #[must_use]
    pub fn max_concurrent_http1_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_concurrent_http1_requests_per_origin = Some(maximum);
        self
    }

    /// Sets the number of requests allowed to wait for each HTTP/1.1 origin and route.
    #[must_use]
    pub fn max_pending_http1_requests_per_origin(mut self, maximum: NonZeroUsize) -> Self {
        self.options.max_pending_http1_requests_per_origin = maximum;
        self
    }

    /// Sets the maximum number of HTTP/2 connections retained for reuse.
    ///
    /// Evicting a connection from the pool does not cancel response bodies
    /// already using it. It prevents later requests from selecting it.
    /// The negotiated H1/H2 pool uses the lower of the configured H1 and H2
    /// retention limits so neither maximum is exceeded.
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
                "max_concurrent_http1_requests_per_origin",
                &self.options.max_concurrent_http1_requests_per_origin,
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
            .field("alt_svc_policy", &self.options.alt_svc_policy)
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
