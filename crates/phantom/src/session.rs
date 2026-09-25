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
mod http2_connections;
pub(crate) mod http2_pool;
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
    /// HTTP/2 connections per pool key, exact and negotiated; 1 as browsers.
    pub(crate) max_http2_connections_per_origin: NonZeroUsize,
    /// Longest wait for another request's handshake to a key that selected
    /// HTTP/2 before; `None` waits for it to finish, as Firefox does.
    pub(crate) negotiated_setup_wait_limit: Option<std::time::Duration>,
    pub(crate) max_retained_http3_connections: NonZeroUsize,
    pub(crate) max_concurrent_http3_requests_per_origin: NonZeroUsize,
    pub(crate) max_pending_http3_requests_per_origin: NonZeroUsize,
    pub(crate) max_client_hint_origins: NonZeroUsize,
    pub(crate) max_alt_svc_origins: Option<NonZeroUsize>,
    pub(crate) alt_svc_policy: AltSvcPolicy,
    /// The caller's HTTP/3 early-data choice; `None` keeps the profile's.
    pub(crate) http3_early_data: Option<bool>,
    #[cfg(feature = "https-records")]
    pub(crate) https_record_resolver: Option<phantom_net::dns::HttpsRecordResolver>,
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
            max_http2_connections_per_origin: NonZeroUsize::MIN,
            negotiated_setup_wait_limit: None,
            max_retained_http3_connections: DEFAULT_MAX_RETAINED_HTTP3_CONNECTIONS,
            max_concurrent_http3_requests_per_origin:
                DEFAULT_MAX_CONCURRENT_HTTP3_REQUESTS_PER_ORIGIN,
            max_pending_http3_requests_per_origin: DEFAULT_MAX_PENDING_HTTP3_REQUESTS_PER_ORIGIN,
            max_client_hint_origins: DEFAULT_MAX_CLIENT_HINT_ORIGINS,
            max_alt_svc_origins: None,
            alt_svc_policy: AltSvcPolicy::sequential(),
            http3_early_data: None,
            #[cfg(feature = "https-records")]
            https_record_resolver: None,
            #[cfg(feature = "cookies")]
            cookie_jar: None,
        }
    }
}

/// Defines a setter for every [`ClientOptions`] field on a builder that
/// keeps them in a field named `options`.
///
/// [`ClientBuilder`](crate::ClientBuilder) and [`SessionBuilder`] both
/// expand it, so a per-client option reaches sessions with no second copy.
/// The documentation speaks of a client; for a session it is the client
/// that [`SessionBuilder::build`] returns.
macro_rules! client_option_setters {
    () => {
        /// Sets the finite policy for following redirect responses.
        ///
        /// The default is [`RedirectPolicy::none`](crate::RedirectPolicy::none),
        /// which returns a 3xx response without following it. Redirects are
        /// followed to `http://` and `https://` targets. A target with another
        /// scheme fails with
        /// [`RequestErrorKind::Redirect`](crate::RequestErrorKind::Redirect), and a
        /// hop the request's protocol selection or route cannot carry fails with
        /// that combination's typed error before the hop is sent.
        #[must_use]
        pub fn redirect_policy(mut self, policy: crate::RedirectPolicy) -> Self {
            self.options.redirect_policy = policy;
            self
        }

        /// Sets the policy for retrying connection-establishment failures.
        ///
        /// The default is [`RetryPolicy::none`](crate::RetryPolicy::none).
        /// Connection retries apply only to connection setup before dispatch:
        /// exact-protocol acquisition and negotiated H1/H2 TCP setup before ALPN
        /// selection.
        /// [`RequestBuilder::retry_policy`](crate::RequestBuilder::retry_policy)
        /// replaces the policy for one request. A delay or `Retry-After` limit
        /// the runtime clock cannot represent fails [`Self::build`] with
        /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
        #[must_use]
        pub fn retry_policy(mut self, policy: crate::RetryPolicy) -> Self {
            self.options.retry_policy = policy;
            self
        }

        /// Sets the default phase and whole-operation limits for ordinary requests.
        ///
        /// The default is [`RequestTimeouts::new`](crate::RequestTimeouts::new),
        /// which sets no limit.
        /// [`RequestBuilder::timeouts`](crate::RequestBuilder::timeouts) replaces
        /// this policy for one request. Every timeout is disabled unless
        /// explicitly present in `timeouts`. A duration the runtime clock cannot
        /// represent fails [`Self::build`] with
        /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
        #[must_use]
        pub fn request_timeouts(mut self, timeouts: crate::RequestTimeouts) -> Self {
            self.options.request_timeouts = timeouts;
            self
        }

        /// Sets the maximum number of HTTP/1.1 pool entries retained for reuse.
        ///
        /// The default is 32. Each entry holds one pool key's connection state;
        /// when the limit is reached, the least recently used entry is evicted.
        /// The negotiated H1/H2 pool uses the lower of the configured H1 and H2
        /// retention limits so neither maximum is exceeded.
        #[must_use]
        pub fn max_retained_http1_connections(mut self, maximum: std::num::NonZeroUsize) -> Self {
            self.options.max_retained_http1_connections = maximum;
            self
        }

        /// Sets the local active-request bound for each HTTP/1.1 pool key.
        ///
        /// Each active HTTP/1.1 request holds its own connection, so this is also
        /// the most connections open at once to the pool key, idle ones included.
        /// Negotiated requests use the same bound for connections that selected
        /// HTTP/1.1 or are still in their TLS handshake. It replaces the
        /// profile's [`Http1Settings`] bound. Without either, the bound is one
        /// connection.
        ///
        /// [`Http1Settings`]: crate::profile::Http1Settings
        #[must_use]
        pub fn max_concurrent_http1_requests_per_origin(
            mut self,
            maximum: std::num::NonZeroUsize,
        ) -> Self {
            self.options.max_concurrent_http1_requests_per_origin = Some(maximum);
            self
        }

        /// Sets the number of requests allowed to wait per HTTP/1.1 pool key.
        ///
        /// The default is 100. A pool key is the origin plus the complete route.
        /// A request beyond the limit fails with
        /// [`RequestErrorKind::Capacity`](crate::RequestErrorKind::Capacity).
        #[must_use]
        pub fn max_pending_http1_requests_per_origin(
            mut self,
            maximum: std::num::NonZeroUsize,
        ) -> Self {
            self.options.max_pending_http1_requests_per_origin = maximum;
            self
        }

        /// Sets the maximum number of HTTP/2 pool entries retained for reuse.
        ///
        /// The default is 32. When the limit is reached, the least recently used
        /// entry is evicted. The negotiated H1/H2 pool uses the lower of the
        /// configured H1 and H2 retention limits so neither maximum is exceeded.
        #[must_use]
        pub fn max_retained_http2_connections(mut self, maximum: std::num::NonZeroUsize) -> Self {
            self.options.max_retained_http2_connections = maximum;
            self
        }

        /// Sets the local active-request bound for each HTTP/2 pool key.
        ///
        /// The default is 100. The peer's stream limit also caps active requests.
        /// The bound covers all of a pool key's connections when
        /// [`Self::max_http2_connections_per_origin`] allows more than one.
        #[must_use]
        pub fn max_concurrent_http2_requests_per_origin(
            mut self,
            maximum: std::num::NonZeroUsize,
        ) -> Self {
            self.options.max_concurrent_http2_requests_per_origin = maximum;
            self
        }

        /// Sets the number of requests allowed to wait per HTTP/2 pool key.
        ///
        /// The default is 100. A request beyond the limit fails with
        /// [`RequestErrorKind::Capacity`](crate::RequestErrorKind::Capacity).
        #[must_use]
        pub fn max_pending_http2_requests_per_origin(
            mut self,
            maximum: std::num::NonZeroUsize,
        ) -> Self {
            self.options.max_pending_http2_requests_per_origin = maximum;
            self
        }

        /// Lets each HTTP/2 pool key open up to `maximum` connections.
        ///
        /// The default is 1, as Chrome, Edge, and Firefox keep one HTTP/2
        /// connection per origin. With a higher limit, a request opens another
        /// connection only when every connection to the pool key has as many
        /// streams in flight as it can carry: the lower of
        /// [`Self::max_concurrent_http2_requests_per_origin`] and the peer's
        /// `SETTINGS_MAX_CONCURRENT_STREAMS`. Each connection makes its own TCP
        /// and TLS handshake and sends the profile's full HTTP/2 preface. A new
        /// stream goes to the connection with the fewest streams in flight. At
        /// the limit, the least-loaded connection takes the stream and holds it
        /// until the peer allows it.
        ///
        /// This applies to exact HTTP/2 requests and to negotiated requests
        /// whose connections select HTTP/2. The active and waiting bounds stay
        /// per pool key, across all its connections, so a connection count
        /// above one helps only when the peer's stream limit is below
        /// [`Self::max_concurrent_http2_requests_per_origin`]. A server can see
        /// several simultaneous connections from one client, which no browser
        /// opens to one origin.
        #[must_use]
        pub fn max_http2_connections_per_origin(mut self, maximum: std::num::NonZeroUsize) -> Self {
            self.options.max_http2_connections_per_origin = maximum;
            self
        }

        /// Bounds how long a negotiated request waits for another request's TLS
        /// handshake to an origin that selected HTTP/2 before.
        ///
        /// By default the request waits until that handshake finishes, as
        /// Firefox 156 does, so a stalled handshake stalls every request queued
        /// behind it. Chromium 154 waits at most 300 ms. After `limit`, the
        /// request opens a connection of its own; if both select HTTP/2, the one
        /// that finishes second closes and its requests join the first, unless
        /// [`Self::max_http2_connections_per_origin`] allows both. The server
        /// sees a second TLS handshake that a Firefox profile would not make.
        ///
        /// A `limit` the runtime clock cannot represent fails [`Self::build`]
        /// with [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
        #[must_use]
        pub fn negotiated_setup_wait_limit(mut self, limit: std::time::Duration) -> Self {
            self.options.negotiated_setup_wait_limit = Some(limit);
            self
        }

        /// Sets the maximum number of HTTP/3 pool entries retained for reuse.
        ///
        /// The default is 32. When the limit is reached, the least recently used
        /// entry is evicted. One entry keeps connections for up to four transport
        /// locations, so exact H3 and Alt-Svc H3 do not replace each other.
        #[must_use]
        pub fn max_retained_http3_connections(mut self, maximum: std::num::NonZeroUsize) -> Self {
            self.options.max_retained_http3_connections = maximum;
            self
        }

        /// Sets the local active-request bound for each HTTP/3 pool key.
        ///
        /// The default is 100. The peer's stream limit also caps active requests.
        #[must_use]
        pub fn max_concurrent_http3_requests_per_origin(
            mut self,
            maximum: std::num::NonZeroUsize,
        ) -> Self {
            self.options.max_concurrent_http3_requests_per_origin = maximum;
            self
        }

        /// Sets the number of requests allowed to wait per HTTP/3 pool key.
        ///
        /// The default is 100. A request beyond the limit fails with
        /// [`RequestErrorKind::Capacity`](crate::RequestErrorKind::Capacity).
        #[must_use]
        pub fn max_pending_http3_requests_per_origin(
            mut self,
            maximum: std::num::NonZeroUsize,
        ) -> Self {
            self.options.max_pending_http3_requests_per_origin = maximum;
            self
        }

        /// Sets the number of origins that may retain `Accept-CH` state.
        ///
        /// The default is 64.
        #[must_use]
        pub fn max_client_hint_origins(mut self, maximum: std::num::NonZeroUsize) -> Self {
            self.options.max_client_hint_origins = maximum;
            self
        }

        /// Enables bounded, in-memory Alt-Svc learning for negotiated HTTPS requests.
        ///
        /// Alt-Svc learning is disabled by default. `maximum_origins` bounds
        /// stored origin-and-route pairs: one origin learned over N routes
        /// occupies N entries. [`Self::build`] fails with
        /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy)
        /// unless the profile configures HTTP/2, offers `http/1.1` in its TLS ALPN
        /// list, and configures HTTP/3.
        ///
        /// A fresh `h3` alternative is used by a later negotiated request without
        /// changing its origin identity or its route. Alternative setup failure is
        /// terminal for that request and never falls back implicitly to H1 or H2.
        ///
        /// The store is keyed by origin and route, so an alternative learned on
        /// one route is only ever dialed over that route. Learning runs only on
        /// direct and SOCKS5 routes. An HTTP proxy route makes negotiated requests
        /// but stores no advertisement, because its CONNECT tunnel cannot carry
        /// QUIC; see [`Route`](crate::Route).
        #[must_use]
        pub fn alt_svc(mut self, maximum_origins: std::num::NonZeroUsize) -> Self {
            self.options.max_alt_svc_origins = Some(maximum_origins);
            self
        }

        /// Selects how negotiated requests use a learned HTTP/3 alternative.
        ///
        /// The default is [`AltSvcPolicy::sequential`](crate::AltSvcPolicy::sequential).
        /// A racing policy requires [`Self::alt_svc`]; building without
        /// it, or with an origin delay the runtime clock cannot represent, fails
        /// with [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
        #[must_use]
        pub fn alt_svc_policy(mut self, policy: crate::AltSvcPolicy) -> Self {
            self.options.alt_svc_policy = policy;
            self
        }

        /// Sets whether a resumed HTTP/3 connection offers early (0-RTT) data,
        /// overriding the profile.
        ///
        /// Without this call the profile decides, and a session keeps the
        /// choice of the client it is built from. A client offers early data
        /// when its HTTP/3 QUIC settings set `early_data`, as the Chrome 154
        /// and Edge 153 recipes do, because the captured browsers offer it on
        /// every resumed connection. `false` turns it off for such a profile; `true`
        /// turns it on for a profile that leaves it unset.
        ///
        /// # Replay
        ///
        /// Early data is replayable. An attacker who records a connection's first
        /// flight can deliver it to the server again, and the server may process
        /// each copy (RFC 8446, section 8; RFC 9001, section 9.2).
        ///
        /// Only a request that is safe to replay goes out as early data: a safe
        /// method (`GET`, `HEAD`, `OPTIONS`, or `TRACE`) with no body and no
        /// trailers, the rule Chromium applies to a request of default
        /// idempotency. It is sent on a new connection that presents a ticket
        /// permitting early data; a request that finds a pooled connection uses
        /// it as usual. Any other request that opens a new connection offers
        /// early data in its ClientHello, as the captured browsers do, but is
        /// sent only after the handshake. Under a profile with dynamic QPACK
        /// encoding, as in the Chrome 154 recipe, the connection encodes early
        /// requests with the server's SETTINGS remembered with the ticket, as
        /// Chromium does, and closes with `H3_SETTINGS_ERROR` if the server's own
        /// SETTINGS then lower a remembered limit. If the server rejects the
        /// early data, it processed none of it, and Phantom sends the request
        /// again after a handshake over the same route and protocol.
        ///
        /// Building with `true` fails with
        /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy)
        /// unless the profile has HTTP/3 settings whose TLS settings enable
        /// `session_tickets`, because early data needs a resumed session.
        #[must_use]
        pub fn http3_early_data(mut self, enabled: bool) -> Self {
            self.options.http3_early_data = Some(enabled);
            self
        }

        /// Lets HTTPS DNS records (RFC 9460) advertise HTTP/3 for negotiated
        /// requests, as a learned Alt-Svc advertisement does. Off by default.
        ///
        /// When no Alt-Svc alternative is stored for a direct-route request, the
        /// client looks up the origin's HTTPS records with `resolver`. If a usable
        /// ServiceMode record lists `h3` for the origin's own host and port, the
        /// request uses HTTP/3 at that location under the
        /// [`AltSvcPolicy`](crate::AltSvcPolicy), without an `Alt-Used` field.
        ///
        /// The lookup does not hold back the request. While it is in flight, a
        /// sequential client sends the request to the origin, and a racing
        /// client starts origin setup at once and alternative setup when the
        /// lookup advertises `h3`. A failed lookup counts as no advertisement.
        ///
        /// A profile that sets
        /// [`TlsSettings::ech_from_https_records`](crate::profile::TlsSettings::ech_from_https_records),
        /// as the Chrome 154, Edge 153, and Brave 154 recipes do, also uses the
        /// records for Encrypted Client Hello on every direct TLS connection over
        /// TCP: those of negotiated and exact-protocol HTTP/1.1 and HTTP/2
        /// requests and of `wss://` WebSocket openings. Each such connection
        /// starts the origin's lookup when none is cached, and its TLS handshake
        /// waits for it at most 20% of the address resolution time, clamped to
        /// 5-50 ms, then offers the record's `ech`. An HTTP/3 profile that sets
        /// the field does the same on a direct QUIC connection to the origin's
        /// own host and port, which starts once the lookup ends within that
        /// bound; a rejected QUIC connection is not repeated. Exact HTTP/3
        /// requests, and negotiated ones under
        /// [`AltSvcPolicy::sequential`](crate::AltSvcPolicy::sequential), then
        /// keep failing on the stale configuration until the cached record
        /// expires; set `ech_from_https_records = false` on the profile's
        /// HTTP/3 TLS settings to send ECH GREASE instead.
        ///
        /// Results are cached per origin for the records' TTL, capped at one day,
        /// or 60 seconds when there is no TTL, as after a failed lookup. The
        /// cache holds at most the `maximum_origins` given to
        /// [`Self::alt_svc`], which this requires; building without it
        /// fails with
        /// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
        /// Concurrent requests for one origin share one lookup. Proxy routes never
        /// query.
        ///
        /// Requires the `https-records` feature.
        #[cfg(feature = "https-records")]
        #[must_use]
        pub fn https_record_discovery(mut self, resolver: crate::dns::HttpsRecordResolver) -> Self {
            self.options.https_record_resolver = Some(resolver);
            self
        }

        /// Enables a bounded in-memory cookie jar owned by the client.
        ///
        /// By default the client has no cookie jar. This jar uses the default
        /// [`CookieLimits`](crate::CookieLimits).
        #[cfg(feature = "cookies")]
        #[must_use]
        pub fn cookies(mut self) -> Self {
            self.options.cookie_jar = Some(crate::CookieJar::default());
            self
        }

        /// Enables cookie handling with a caller-created jar.
        ///
        /// By default the client has no cookie jar. Use this to set other
        /// [`CookieLimits`](crate::CookieLimits).
        #[cfg(feature = "cookies")]
        #[must_use]
        pub fn cookie_jar(mut self, jar: crate::CookieJar) -> Self {
            self.options.cookie_jar = Some(jar);
            self
        }
    };
}
pub(crate) use client_option_setters;

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
    #[cfg(feature = "https-records")]
    https_records: Option<alt_svc::HttpsRecordDiscovery>,
    client_hints: Option<client_hints::ClientHintStore>,
    #[cfg(feature = "cookies")]
    pub(crate) cookies: Option<Arc<CookieJar>>,
}

impl ClientOptions {
    /// Checks every option against the transport a client or session uses.
    pub(crate) fn validate(&self, inner: &ClientInner) -> Result<(), BuildError> {
        self.validate_policies()?;
        self.validate_transport(
            inner.http1_or_2.is_some(),
            inner.http3.is_some(),
            inner.http3_session_tickets,
        )
    }

    /// Checks the options that do not depend on the transport.
    pub(crate) fn validate_policies(&self) -> Result<(), BuildError> {
        if !self.request_timeouts.validate() {
            return Err(BuildError::invalid_policy(
                "request timeout exceeds the runtime clock range",
            ));
        }
        if !self.retry_policy.validate() {
            return Err(BuildError::invalid_policy(
                "retry delay or Retry-After limit exceeds the runtime clock range",
            ));
        }
        Ok(())
    }

    /// Checks the options that need a protocol or TLS feature of the
    /// transport.
    pub(crate) fn validate_transport(
        &self,
        negotiated: bool,
        http3: bool,
        http3_session_tickets: bool,
    ) -> Result<(), BuildError> {
        if self.http3_early_data == Some(true) && !(http3 && http3_session_tickets) {
            return Err(BuildError::invalid_policy(
                "HTTP/3 early data requires HTTP/3 TLS settings with session tickets",
            ));
        }
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
        #[cfg(feature = "https-records")]
        if self.https_record_resolver.is_some() && self.max_alt_svc_origins.is_none() {
            return Err(BuildError::invalid_policy(
                "HTTPS record discovery requires an Alt-Svc store",
            ));
        }
        if self
            .negotiated_setup_wait_limit
            .is_some_and(|limit| std::time::Instant::now().checked_add(limit).is_none())
        {
            return Err(BuildError::invalid_policy(
                "negotiated setup wait limit exceeds the runtime clock range",
            ));
        }
        self.alt_svc_policy.validate()
    }

    /// Builds a client over `inner` once [`Self::validate`] has accepted
    /// these options for it.
    ///
    /// An HTTP/3 early-data choice replaces the connector with a clone that
    /// shares its TLS context, key log, qlog directory, and host resolver.
    pub(crate) fn into_client(self, mut inner: Arc<ClientInner>) -> Client {
        if let Some(enabled) = self.http3_early_data {
            let transport = Arc::make_mut(&mut inner);
            transport.http3 = transport.http3.as_deref().map(|connector| {
                Arc::new(if enabled {
                    connector.with_early_data()
                } else {
                    connector.without_early_data()
                })
            });
        }
        let state = self.build(&inner);
        Client { inner, state }
    }

    /// Adds every option to a builder's `Debug` output.
    ///
    /// The pattern names every field, so a new option does not compile until
    /// it is printed here.
    pub(crate) fn debug_fields(&self, formatter: &mut fmt::DebugStruct<'_, '_>) {
        let Self {
            redirect_policy,
            retry_policy,
            request_timeouts,
            max_retained_http1_connections,
            max_concurrent_http1_requests_per_origin,
            max_pending_http1_requests_per_origin,
            max_retained_http2_connections,
            max_concurrent_http2_requests_per_origin,
            max_pending_http2_requests_per_origin,
            max_http2_connections_per_origin,
            negotiated_setup_wait_limit,
            max_retained_http3_connections,
            max_concurrent_http3_requests_per_origin,
            max_pending_http3_requests_per_origin,
            max_client_hint_origins,
            max_alt_svc_origins,
            alt_svc_policy,
            http3_early_data,
            #[cfg(feature = "https-records")]
            https_record_resolver,
            #[cfg(feature = "cookies")]
            cookie_jar,
        } = self;
        formatter
            .field("redirect_policy", redirect_policy)
            .field("retry_policy", retry_policy)
            .field("request_timeouts", request_timeouts)
            .field(
                "max_retained_http1_connections",
                max_retained_http1_connections,
            )
            .field(
                "max_concurrent_http1_requests_per_origin",
                max_concurrent_http1_requests_per_origin,
            )
            .field(
                "max_pending_http1_requests_per_origin",
                max_pending_http1_requests_per_origin,
            )
            .field(
                "max_retained_http2_connections",
                max_retained_http2_connections,
            )
            .field(
                "max_concurrent_http2_requests_per_origin",
                max_concurrent_http2_requests_per_origin,
            )
            .field(
                "max_pending_http2_requests_per_origin",
                max_pending_http2_requests_per_origin,
            )
            .field(
                "max_http2_connections_per_origin",
                max_http2_connections_per_origin,
            )
            .field("negotiated_setup_wait_limit", negotiated_setup_wait_limit)
            .field(
                "max_retained_http3_connections",
                max_retained_http3_connections,
            )
            .field(
                "max_concurrent_http3_requests_per_origin",
                max_concurrent_http3_requests_per_origin,
            )
            .field(
                "max_pending_http3_requests_per_origin",
                max_pending_http3_requests_per_origin,
            )
            .field("max_client_hint_origins", max_client_hint_origins)
            .field("max_alt_svc_origins", max_alt_svc_origins)
            .field("alt_svc_policy", alt_svc_policy)
            .field("http3_early_data", http3_early_data)
            .field("https_record_discovery", &{
                #[cfg(feature = "https-records")]
                {
                    https_record_resolver.is_some()
                }
                #[cfg(not(feature = "https-records"))]
                {
                    false
                }
            })
            .field("cookies_enabled", &{
                #[cfg(feature = "cookies")]
                {
                    cookie_jar.is_some()
                }
                #[cfg(not(feature = "cookies"))]
                {
                    false
                }
            });
    }

    fn build(self, inner: &ClientInner) -> Arc<ClientState> {
        #[cfg(feature = "https-records")]
        let https_records = self
            .https_record_resolver
            .zip(self.max_alt_svc_origins)
            .map(|(resolver, capacity)| alt_svc::HttpsRecordDiscovery::new(resolver, capacity));
        #[cfg_attr(not(feature = "https-records"), allow(unused_mut))]
        let mut http1_or_2 = http1_or_2_pool::Http1Or2Pool::new(
            self.max_retained_http1_connections,
            self.max_concurrent_http1_requests_per_origin
                .unwrap_or(inner.http1_connections_per_origin),
            self.max_pending_http1_requests_per_origin,
            self.max_retained_http2_connections,
            self.max_concurrent_http2_requests_per_origin,
            self.max_pending_http2_requests_per_origin,
        )
        .with_max_http2_connections(self.max_http2_connections_per_origin)
        .with_setup_wait_limit(self.negotiated_setup_wait_limit);
        #[cfg(feature = "https-records")]
        http1_or_2.set_https_records(https_records.clone());
        #[cfg_attr(not(feature = "https-records"), allow(unused_mut))]
        let mut http1 = http1_pool::Http1Pool::new(
            self.max_retained_http1_connections,
            self.max_concurrent_http1_requests_per_origin
                .unwrap_or(inner.http1_connections_per_origin),
            self.max_pending_http1_requests_per_origin,
        );
        #[cfg(feature = "https-records")]
        http1.set_https_records(https_records.clone());
        #[cfg_attr(not(feature = "https-records"), allow(unused_mut))]
        let mut http2 = http2_pool::Http2Pool::new(
            self.max_retained_http2_connections,
            self.max_concurrent_http2_requests_per_origin,
            self.max_pending_http2_requests_per_origin,
        )
        .with_max_connections(self.max_http2_connections_per_origin);
        #[cfg(feature = "https-records")]
        http2.set_https_records(https_records.clone());
        #[cfg_attr(not(feature = "https-records"), allow(unused_mut))]
        let mut http3 = http3_pool::Http3Pool::new(
            self.max_retained_http3_connections,
            self.max_concurrent_http3_requests_per_origin,
            self.max_pending_http3_requests_per_origin,
        );
        #[cfg(feature = "https-records")]
        http3.set_https_records(https_records.clone());
        Arc::new(ClientState {
            redirect_policy: self.redirect_policy,
            retry_policy: self.retry_policy,
            request_timeouts: self.request_timeouts,
            http1,
            http1_or_2,
            http2,
            http3,
            alt_svc: self.max_alt_svc_origins.map(alt_svc::AltSvcStore::new),
            alt_svc_policy: self.alt_svc_policy,
            #[cfg(feature = "https-records")]
            https_records,
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
        https: bool,
        settings: &phantom_profile::ClientHintSettings,
        response: &http::HeaderMap,
        sent: &[phantom_net::request::RequestHeader],
    ) -> bool {
        self.state
            .client_hints
            .as_ref()
            .is_some_and(|client_hints| {
                client_hints.learn_and_should_retry(endpoint, https, settings, response, sent)
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

    /// Records that a raced alternative that sent early data then failed its
    /// handshake, so later raced setups for the origin send no early data.
    pub(crate) fn mark_origin_quic_recently_broken(
        &self,
        endpoint: &crate::authority::Endpoint,
        route: &crate::Route,
    ) {
        if let Some(store) = &self.state.alt_svc {
            store.mark_origin_quic_recently_broken(endpoint, route);
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

    /// Returns the lookup of the `ech` value that a direct TLS connection to
    /// `endpoint` offering `alpn` waits for, when `offers_ech` says its
    /// profile takes ECH from HTTPS records and this client looks them up.
    ///
    /// The connection's ALPN offer picks the record, as in Chromium's
    /// `TcpConnectJob::FindServiceEndpoint`. Callers use it on the direct
    /// route only.
    #[cfg(all(feature = "https-records", feature = "websocket"))]
    pub(crate) fn direct_tcp_ech(
        &self,
        endpoint: &crate::authority::Endpoint,
        offers_ech: bool,
        alpn: impl FnOnce() -> Vec<Box<[u8]>>,
    ) -> Option<impl Future<Output = Option<phantom_net::dns::EchConfigList>> + Send + 'static>
    {
        let discovery = self.state.https_records.as_ref().filter(|_| offers_ech)?;
        Some(discovery.tcp_ech(endpoint, alpn()))
    }

    /// Returns the origin's own location as an HTTP/3 alternative, with what
    /// its HTTPS records say, when discovery applies to this request.
    ///
    /// Discovery runs on the direct route only. Like Chromium, which gives a
    /// proxied request no `DNS_ALPN_H3` job because "proxied connections
    /// perform DNS on the proxy", Phantom sends no HTTPS query for a request
    /// whose route is a proxy.
    #[cfg(feature = "https-records")]
    pub(crate) fn https_record_alternative(
        &self,
        endpoint: &crate::authority::Endpoint,
        route: &crate::Route,
    ) -> Option<(alt_svc::AlternativeTarget, alt_svc::Discovery)> {
        let discovery = self.state.https_records.as_ref()?;
        let store = self.state.alt_svc.as_ref()?;
        if !matches!(route, crate::Route::Direct) {
            return None;
        }
        let broken = store.is_broken(
            endpoint,
            route,
            alt_svc::AlternativeTarget::https_record(endpoint, false, false).location(),
        );
        let target = alt_svc::AlternativeTarget::https_record(
            endpoint,
            broken,
            store.origin_quic_recently_broken(endpoint, route),
        );
        if broken {
            return Some((target, alt_svc::Discovery::NotAdvertised));
        }
        Some((target, discovery.discover(endpoint)))
    }

    /// Stops using `alternative` after its connection failed or it answered
    /// `421`.
    ///
    /// A stored Alt-Svc advertisement is evicted, unless it was replaced
    /// meanwhile. An HTTPS record cannot be evicted from DNS, so its location
    /// is marked broken instead, for the racing policy's backoff or, under
    /// the sequential policy, for [`AltSvcBrokenBackoff::CHROMIUM_153`].
    pub(crate) fn invalidate_alternative(
        &self,
        endpoint: &crate::authority::Endpoint,
        route: &crate::Route,
        alternative: &alt_svc::AlternativeTarget,
    ) {
        match alternative.generation() {
            Some(generation) => self.remove_alt_svc_if_current(endpoint, route, generation),
            None => {
                let backoff = self.state.alt_svc_policy.race_settings().map_or(
                    AltSvcBrokenBackoff::CHROMIUM_153,
                    AltSvcRace::broken_backoff,
                );
                self.mark_alt_svc_broken(endpoint, route, alternative, backoff);
            }
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

    /// Forgets every host address this client and its clones resolved.
    ///
    /// Browsers flush their address caches when the network changes; Phantom
    /// does not watch the network, so call this after such a change. A
    /// lookup in flight still answers the connections waiting for it, but
    /// its answer is not kept. Does nothing when the client caches no
    /// addresses.
    pub fn clear_dns_cache(&self) {
        if let Some(cache) = self
            .inner
            .host_resolver
            .as_ref()
            .and_then(|resolver| resolver.cache())
        {
            cache.clear();
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
                "max_http2_connections_per_origin",
                &self.state.http2.max_connections(),
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
            .field("https_record_discovery_enabled", &{
                #[cfg(feature = "https-records")]
                {
                    self.state.https_records.is_some()
                }
                #[cfg(not(feature = "https-records"))]
                {
                    false
                }
            })
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
///
/// The client shares the parent's transport: its profile, route, trust roots
/// and server authentication, host overrides and address resolver, address
/// cache settings, proxy-authentication mode, key log, and qlog directory.
/// Pools, cookies, Alt-Svc and client-hint state, remembered proxy
/// credentials, and cached addresses start empty. Every
/// [`ClientBuilder`](crate::ClientBuilder) option that is not transport is a
/// method here with the same default, except
/// [`Self::http3_early_data`]: without it, the session keeps the parent's
/// choice.
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

    client_option_setters!();

    /// Builds the isolated client.
    ///
    /// # Errors
    ///
    /// Returns [`BuildError`] with [`BuildErrorKind::InvalidPolicy`] when an
    /// option is invalid or needs a protocol the transport lacks, as
    /// [`ClientBuilder::build`] does for the same option.
    ///
    /// [`BuildErrorKind::InvalidPolicy`]: crate::BuildErrorKind::InvalidPolicy
    /// [`ClientBuilder::build`]: crate::ClientBuilder::build
    pub fn build(self) -> Result<Client, BuildError> {
        self.options.validate(&self.inner)?;
        Ok(self
            .options
            .into_client(self.inner.with_fresh_session_state()))
    }
}

impl fmt::Debug for SessionBuilder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut debug = formatter.debug_struct("SessionBuilder");
        self.options.debug_fields(&mut debug);
        debug.finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
