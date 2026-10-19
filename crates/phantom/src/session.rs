use std::{fmt, num::NonZeroUsize, sync::Arc};

use crate::{
    BuildError, Client, RedirectPolicy, RequestTimeouts, RetryPolicy, client::ClientInner,
};
#[cfg(feature = "sse")]
use crate::{HttpProtocol, RequestError, SseRequestBuilder};

pub use alt_svc::{
    AltSvcBrokenBackoff, AltSvcOriginDelay, AltSvcPolicy, AltSvcRace, AltSvcRttDelay,
    AltSvcSnapshot, AltSvcSnapshotEntry, AltSvcSnapshotError, AltSvcSnapshotErrorKind,
};
#[cfg(feature = "cookies")]
pub use cookies::{
    CookieError, CookieErrorKind, CookieJar, CookieLimits, CookieSameSite, CookieSnapshot,
    CookieSnapshotEntry, CookieSnapshotError, CookieSnapshotErrorKind, CookieSourceScheme,
};

mod address_families;
mod admission;
pub(crate) mod alt_svc;
pub(crate) mod client_hints;
#[cfg(feature = "cookies")]
mod cookies;
pub(crate) mod http1_or_2_pool;
pub(crate) mod http1_pool;
mod http2_connections;
pub(crate) mod http2_pool;
mod http3_connections;
pub(crate) mod http3_pool;
pub(crate) mod lifecycle;
mod prune_timer;
mod retired_connections;
mod sharing;
#[cfg(feature = "session-snapshot")]
mod snapshot;
#[cfg(feature = "session-snapshot")]
mod storage;
mod stream_count;
mod tickets;

pub use sharing::SessionSharing;
#[cfg(feature = "session-snapshot")]
pub use snapshot::{SessionSnapshot, SessionSnapshotError, SessionSnapshotErrorKind};
#[cfg(feature = "session-snapshot")]
pub use storage::{SessionStorageError, SessionStorageErrorKind, SessionStore, SessionStoreFuture};
pub use tickets::{SessionTicketError, SessionTicketErrorKind, SessionTicketSnapshot};

pub(crate) use tickets::binding::encoding::Encoder as TicketBindingEncoder;
pub(crate) use tickets::binding::{
    BindingPlan, PreparationError, PreparedTicketPolicy, TicketClientContext,
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
/// The most HTTP/3 connections one transport location of a pool entry may
/// keep. At this ceiling, the default 32 retained entries of four locations
/// each pool at most 1,024 QUIC connections.
pub(crate) const HTTP3_CONNECTIONS_PER_ORIGIN_CEILING: usize = 8;
const DEFAULT_MAX_CLIENT_HINT_ORIGINS: NonZeroUsize = match NonZeroUsize::new(64) {
    Some(value) => value,
    None => NonZeroUsize::MIN,
};

/// A future boxed by [`box_send`].
pub(crate) type SendBox<'a, T> =
    std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Boxes `future` as a `Send` trait object.
///
/// The connector futures are deep: a request future nests the request path,
/// the pool, and the connector state machines, and proving the whole nest
/// `Send` exceeds the compiler's default recursion limit
/// (rust-lang/rust#159228), in this crate and in a caller that spawns a
/// request. A trait object ends that proof where it is created, so each
/// existing box on the request and connection setup paths uses this helper
/// instead of `Box::pin`.
pub(crate) fn box_send<'a, T>(
    future: impl std::future::Future<Output = T> + Send + 'a,
) -> SendBox<'a, T> {
    box_send_unscoped(phantom_net::request_diagnostics::Observation::scope(
        phantom_net::request_diagnostics::Observation::capture(),
        future,
    ))
}

/// Ends the `Send` proof without capturing the caller's observation scope.
pub(crate) fn box_send_unscoped<'a, T>(
    future: impl std::future::Future<Output = T> + Send + 'a,
) -> SendBox<'a, T> {
    Box::pin(future)
}

/// The runtime the calling task runs on, which every pool key includes.
///
/// A connection's driver runs on the runtime that opened it and stops being
/// polled once that runtime is dropped or no longer driven, as a
/// current-thread runtime is after `block_on` returns. Keying pools by
/// runtime keeps a client that outlives a runtime from sending on such a
/// connection, where the request would never be answered. Per-origin
/// admission and learned protocol state use the key without its runtime, so
/// they stay per origin across runtimes.
fn current_runtime() -> Option<tokio::runtime::Id> {
    tokio::runtime::Handle::try_current()
        .ok()
        .map(|runtime| runtime.id())
}

#[derive(Clone)]
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
    /// HTTP/3 connections per pool entry and transport location; 1 as
    /// browsers.
    pub(crate) max_http3_connections_per_origin: NonZeroUsize,
    pub(crate) max_client_hint_origins: NonZeroUsize,
    pub(crate) max_alt_svc_origins: Option<NonZeroUsize>,
    pub(crate) alt_svc_policy: AltSvcPolicy,
    #[cfg(feature = "https-records")]
    pub(crate) alt_svc_https_policy: crate::AltSvcHttpsPolicy,
    /// The caller's HTTP/3 early-data choice; `None` keeps the profile's.
    pub(crate) http3_early_data: Option<bool>,
    #[cfg(feature = "https-records")]
    pub(crate) https_record_resolver: Option<phantom_net::dns::HttpsRecordResolver>,
    #[cfg(feature = "cookies")]
    pub(crate) cookie_jar: Option<Arc<CookieJar>>,
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
            max_http3_connections_per_origin: NonZeroUsize::MIN,
            max_client_hint_origins: DEFAULT_MAX_CLIENT_HINT_ORIGINS,
            max_alt_svc_origins: None,
            alt_svc_policy: AltSvcPolicy::sequential(),
            #[cfg(feature = "https-records")]
            alt_svc_https_policy: crate::AltSvcHttpsPolicy::OriginOnly,
            http3_early_data: None,
            #[cfg(feature = "https-records")]
            https_record_resolver: None,
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

pub(crate) struct ClientState {
    options: ClientOptions,
    pub(crate) lifecycle: Arc<lifecycle::Lifecycle>,
    tickets: Arc<tickets::TicketOwner>,
    pub(crate) redirect_policy: RedirectPolicy,
    pub(crate) retry_policy: RetryPolicy,
    pub(crate) request_timeouts: RequestTimeouts,
    pub(crate) http1: http1_pool::Http1Pool,
    pub(crate) http1_or_2: http1_or_2_pool::Http1Or2Pool,
    pub(crate) http2: http2_pool::Http2Pool,
    pub(crate) http3: http3_pool::Http3Pool,
    alt_svc: Option<Arc<alt_svc::AltSvcStore>>,
    alt_svc_policy: AltSvcPolicy,
    pub(crate) rtt_history: Option<Arc<alt_svc::rtt_history::RttHistory>>,
    #[cfg(feature = "https-records")]
    https_records: Option<alt_svc::HttpsRecordDiscovery>,
    client_hints: Option<Arc<client_hints::ClientHintStore>>,
    #[cfg(feature = "cookies")]
    pub(crate) cookies: Option<Arc<CookieJar>>,
}

impl ClientOptions {
    /// Checks the options that do not depend on the transport.
    pub(crate) fn validate_policies(
        &self,
        profile_http1_bound: NonZeroUsize,
    ) -> Result<(), BuildError> {
        for (bound, message) in [
            (
                self.max_concurrent_http1_requests_per_origin
                    .unwrap_or(profile_http1_bound),
                "HTTP/1.1 active-request bound exceeds the semaphore limit",
            ),
            (
                self.max_pending_http1_requests_per_origin,
                "HTTP/1.1 pending-request bound exceeds the semaphore limit",
            ),
            (
                self.max_concurrent_http2_requests_per_origin,
                "HTTP/2 active-request bound exceeds the semaphore limit",
            ),
            (
                self.max_pending_http2_requests_per_origin,
                "HTTP/2 pending-request bound exceeds the semaphore limit",
            ),
            (
                self.max_concurrent_http3_requests_per_origin,
                "HTTP/3 active-request bound exceeds the semaphore limit",
            ),
            (
                self.max_pending_http3_requests_per_origin,
                "HTTP/3 pending-request bound exceeds the semaphore limit",
            ),
        ] {
            if bound.get() > tokio::sync::Semaphore::MAX_PERMITS {
                return Err(BuildError::invalid_policy(message));
            }
        }

        if !self.request_timeouts.validate() {
            return Err(BuildError::invalid_policy(
                "request timeout exceeds the runtime clock range",
            ));
        }
        if let Err(message) = self.retry_policy.validate() {
            return Err(BuildError::invalid_policy(message));
        }
        if self.max_http3_connections_per_origin.get() > HTTP3_CONNECTIONS_PER_ORIGIN_CEILING {
            return Err(BuildError::invalid_policy(
                "max_http3_connections_per_origin exceeds 8",
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

    #[cfg(feature = "https-records")]
    pub(crate) fn validate_alt_svc_https(&self, consumes_ech: bool) -> Result<(), BuildError> {
        self.alt_svc_https_policy.validate()?;
        if matches!(
            self.alt_svc_https_policy,
            crate::AltSvcHttpsPolicy::Destination { .. }
        ) && (self.max_alt_svc_origins.is_none()
            || self.https_record_resolver.is_none()
            || !consumes_ech)
        {
            return Err(BuildError::invalid_policy(
                "Alt-Svc destination lookup requires an Alt-Svc store, HTTPS discovery and HTTP/3 HTTPS-record ECH",
            ));
        }
        Ok(())
    }

    /// Applies an HTTP/3 early-data choice to `inner`'s HTTP/3 connector,
    /// once [`Self::validate_transport`] has accepted it.
    ///
    /// The choice replaces the connector with a clone that shares its TLS
    /// context, key log, qlog directory, and host resolver. Connectors
    /// cloned from it afterwards keep the choice.
    pub(crate) fn apply_http3_early_data(&self, inner: &mut ClientInner) {
        if let Some(enabled) = self.http3_early_data {
            inner.http3 = inner.http3.as_deref().map(|connector| {
                Arc::new(if enabled {
                    connector.with_early_data()
                } else {
                    connector.without_early_data()
                })
            });
        }
    }

    /// Builds a client over `inner` once [`Self::validate_policies`] and
    /// [`Self::validate_transport`] have accepted these options for it and
    /// [`Self::apply_http3_early_data`] has applied them to it.
    pub(crate) fn into_client(self, inner: Arc<ClientInner>) -> Client {
        let state = Arc::new(self.build(&inner));
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
            max_http3_connections_per_origin,
            max_client_hint_origins,
            max_alt_svc_origins,
            alt_svc_policy,
            #[cfg(feature = "https-records")]
            alt_svc_https_policy,
            http3_early_data,
            #[cfg(feature = "https-records")]
            https_record_resolver,
            #[cfg(feature = "cookies")]
            cookie_jar,
        } = self;
        #[cfg(feature = "https-records")]
        formatter.field("alt_svc_https_policy", alt_svc_https_policy);
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
            .field(
                "max_http3_connections_per_origin",
                max_http3_connections_per_origin,
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

    fn build(self, inner: &ClientInner) -> ClientState {
        self.build_with_tickets(inner, None)
    }

    fn build_with_tickets(
        self,
        inner: &ClientInner,
        shared_tickets: Option<Arc<tickets::TicketOwner>>,
    ) -> ClientState {
        let options = self.clone();
        #[cfg(feature = "https-records")]
        let https_records = self
            .https_record_resolver
            .zip(self.max_alt_svc_origins)
            .map(|(resolver, capacity)| alt_svc::HttpsRecordDiscovery::new(resolver, capacity));
        let tickets = shared_tickets.unwrap_or_else(|| {
            Arc::new(tickets::TicketOwner::with_preparation(
                inner.ticket_preparation.clone(),
            ))
        });
        // One timer prunes the H1 and H2 connections of every pool, as
        // Firefox's connection manager prunes all of its connections on one.
        let prune_timer = (inner.http1_idle_timer.is_some() || inner.http2_idle_timer.is_some())
            .then(|| prune_timer::PruneTimer::new(inner.http1_idle_timer));
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
        .with_setup_wait_limit(self.negotiated_setup_wait_limit)
        .with_http1_used_idle_timeout(inner.http1_used_idle_timeout)
        .with_prune_timer(prune_timer.clone())
        .with_ticket_owner(Arc::clone(&tickets));
        #[cfg(feature = "https-records")]
        http1_or_2.set_https_records(https_records.clone());
        #[cfg_attr(not(feature = "https-records"), allow(unused_mut))]
        let mut http1 = http1_pool::Http1Pool::new(
            self.max_retained_http1_connections,
            self.max_concurrent_http1_requests_per_origin
                .unwrap_or(inner.http1_connections_per_origin),
            self.max_pending_http1_requests_per_origin,
        )
        .with_used_idle_timeout(inner.http1_used_idle_timeout)
        .with_prune_timer(prune_timer.clone())
        .with_ticket_owner(Arc::clone(&tickets));
        #[cfg(feature = "https-records")]
        http1.set_https_records(https_records.clone());
        #[cfg_attr(not(feature = "https-records"), allow(unused_mut))]
        let mut http2 = http2_pool::Http2Pool::new(
            self.max_retained_http2_connections,
            self.max_concurrent_http2_requests_per_origin,
            self.max_pending_http2_requests_per_origin,
        )
        .with_max_connections(self.max_http2_connections_per_origin)
        .with_http1_used_idle_timeout(inner.http1_used_idle_timeout)
        .with_prune_timer(prune_timer)
        .with_ticket_owner(Arc::clone(&tickets));
        #[cfg(feature = "https-records")]
        http2.set_https_records(https_records.clone());
        let rtt_history =
            self.alt_svc_policy
                .race_settings()
                .and_then(|race| match race.origin_delay_policy() {
                    AltSvcOriginDelay::Fixed(_) => None,
                    AltSvcOriginDelay::Rtt(settings) => {
                        Some(alt_svc::rtt_history::RttHistory::new(settings))
                    }
                });
        let mut http3 = http3_pool::Http3Pool::new(
            self.max_retained_http3_connections,
            self.max_concurrent_http3_requests_per_origin,
            self.max_pending_http3_requests_per_origin,
        )
        .with_max_connections(self.max_http3_connections_per_origin)
        .with_ticket_owner(Arc::clone(&tickets));
        #[cfg(feature = "https-records")]
        http3.set_https_records(https_records.clone());
        #[cfg(feature = "https-records")]
        http3.set_alt_svc_https_policy(self.alt_svc_https_policy);
        http3.set_rtt_history(rtt_history.clone());
        ClientState {
            options,
            lifecycle: Arc::default(),
            tickets,
            redirect_policy: self.redirect_policy,
            retry_policy: self.retry_policy,
            request_timeouts: self.request_timeouts,
            http1,
            http1_or_2,
            http2,
            http3,
            alt_svc: self
                .max_alt_svc_origins
                .map(|capacity| Arc::new(alt_svc::AltSvcStore::new(capacity))),
            alt_svc_policy: self.alt_svc_policy,
            rtt_history,
            #[cfg(feature = "https-records")]
            https_records,
            client_hints: inner.client_hints.is_some().then(|| {
                Arc::new(client_hints::ClientHintStore::new(
                    self.max_client_hint_origins,
                ))
            }),
            #[cfg(feature = "cookies")]
            cookies: self.cookie_jar,
        }
    }
}

impl Client {
    /// Stops accepting work and waits for existing operations to finish.
    ///
    /// The first poll closes admission for this client and all its clones.
    /// Requests and WebSocket openings already in progress can finish, including
    /// their redirects and eligible replays. Later operations fail with
    /// [`crate::RequestErrorKind::ClientClosed`]. WebSocket openings report
    /// the corresponding `WebSocketErrorKind::ClientClosed` category.
    ///
    /// Read response bodies through EOF or drop them, including response bodies
    /// returned by a rejected WebSocket opening. Receive the end of established
    /// WebSockets or drop them. Shutdown waits for these owners, then releases
    /// retained origin and proxy connections. Driver cleanup is asynchronous;
    /// this does not join transport tasks or wait for peer acknowledgements.
    ///
    /// Cancelling this future leaves admission closed. A later call can finish
    /// waiting and connection cleanup. Use an external timeout to bound the wait;
    /// cancelling shutdown does not abort active work. Client state such as TLS
    /// tickets and cookies remains available for export.
    pub async fn shutdown(&self) {
        self.state.lifecycle.shutdown().await;
        self.refresh_connections().await;
    }

    /// Returns whether shutdown has closed admission for this client and clones.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.state.lifecycle.is_closed()
    }

    /// Replaces retained origin and proxy connections while active work finishes.
    ///
    /// After this returns, later pool lookups use fresh connections. Work that
    /// already obtained a pool owner can finish setup, authentication, requests,
    /// bodies, WebSockets and tunnels using it. Client clones share this change.
    /// TLS tickets, cookies, discovery, learned protocol state and request
    /// admission limits are retained.
    ///
    /// This visits retained routes and the default route. CONNECT-UDP pools
    /// shared with other clients are refreshed too. Previously evicted entries
    /// remain available only to their existing owners. Cancelling this future
    /// can leave some pools unvisited; it does not cancel active work.
    ///
    /// Shutdown of old transport drivers is asynchronous. This operation does
    /// not wait for active work to finish or report graceful drain completion.
    pub async fn refresh_connections(&self) {
        self.state.http1.refresh_connections().await;
        self.state.http1_or_2.refresh_connections().await;
        self.state.http2.refresh_connections().await;
        let mut pools = self.state.http3.refresh_connections().await;
        if let Some(default) = self.inner.default_connect_udp_pool()
            && !pools.iter().any(|pool| pool.shares_scope(default))
        {
            pools.push(default.clone());
        }
        let mut visited: Vec<phantom_net::proxy::ConnectUdpProxyPool> = Vec::new();
        for pool in pools {
            if !visited.iter().any(|prior| prior.shares_scope(&pool)) {
                pool.refresh_connections();
                visited.push(pool);
            }
        }
        self.inner.refresh_proxy_connections();
    }

    /// Releases idle origin and proxy connections retained by this client.
    ///
    /// Client clones share pools. Active requests, response bodies, WebSockets,
    /// tunnels and pending setup remain open. TLS tickets, cookies, discovery
    /// state and pool admission limits are retained. Later requests can open
    /// new connections and resume TLS sessions with retained tickets.
    ///
    /// This visits retained route entries and the configured default route.
    /// CONNECT-UDP route clones share an outer proxy pool, including when used
    /// by different clients; its idle connections are included. Previously
    /// evicted request routes cannot be visited. Concurrent activity can make
    /// an idle connection ineligible during this call.
    ///
    /// Shutdown of the underlying drivers is asynchronous. An outer proxy
    /// connection can become idle after its origin tunnel finishes shutting
    /// down and may need a later call. Cancelling this future can leave some
    /// pools unvisited; it does not cancel requests.
    pub async fn close_idle_connections(&self) {
        self.state.http1.close_idle_connections().await;
        self.state.http1_or_2.close_idle_connections().await;
        self.state.http2.close_idle_connections().await;
        let proxy_pools = self.state.http3.close_idle_connections().await;
        for pool in proxy_pools {
            pool.close_idle_connections();
        }
        self.inner.close_idle_proxy_connections();
    }

    /// Clears this client's retained TCP TLS and QUIC session tickets.
    ///
    /// This includes origin and TLS proxy caches, including caches whose pool
    /// entry was evicted while a connection or setup still uses it. Older
    /// handshakes cannot put their tickets back. Existing connections keep
    /// working, and native buffers belonging to those connections are retained
    /// until their connection ends. Returns the tickets removed from caches
    /// and pending library callbacks. Clones share the same ticket owner.
    ///
    /// # Errors
    ///
    /// Returns an allocation or registry error without removing tickets.
    pub fn clear_session_tickets(&self) -> Result<usize, crate::SessionTicketError> {
        self.state.tickets.clear()
    }

    /// Admits one stream on a pooled, reusable HTTP/2 session to the origin.
    ///
    /// Both pools are keyed by origin and route, proxy credentials included,
    /// and the negotiated pool is checked before the exact HTTP/2 pool. On a
    /// proxy route neither is checked unless `reuse_proxied` is set, as the
    /// profile's `WebSocketProxiedSession` decides: a reused session already
    /// carries its tunnel, so the stream sends no proxy CONNECT. Nothing is
    /// opened. The returned permit is that pool's per-origin HTTP/2
    /// admission; holding it counts the stream against the origin's active
    /// bound until dropped.
    ///
    /// # Errors
    ///
    /// Returns a typed capacity error when the origin's waiting bound is full.
    #[cfg(feature = "websocket")]
    pub(crate) async fn admit_http2_session(
        &self,
        endpoint: &crate::authority::Endpoint,
        route: &crate::Route,
        reuse_proxied: bool,
    ) -> Result<Option<PooledHttp2Session>, crate::RequestError> {
        if !reuse_proxied && !matches!(route, crate::Route::Direct) {
            return Ok(None);
        }
        if let Some(session) = self
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
            self.state.client_hints.as_deref(),
        )
    }

    pub(crate) fn learn_client_hints_and_should_retry(
        &self,
        endpoint: &crate::authority::Endpoint,
        https: bool,
        settings: &phantom_profile::ClientHintSettings,
        response: &http::HeaderMap,
        sent: &[phantom_net::request::RequestHeader],
        managed: &[&str],
    ) -> bool {
        self.state
            .client_hints
            .as_ref()
            .is_some_and(|client_hints| {
                client_hints.learn_and_should_retry_with_managed_headers(
                    endpoint, https, settings, response, sent, managed,
                )
            })
    }

    /// Returns up to `max` learned alternatives in field order that are not
    /// broken, or else the first one, marked broken; empty when none is
    /// learned.
    pub(crate) fn alt_svc_locations(
        &self,
        endpoint: &crate::authority::Endpoint,
        route: &crate::Route,
        max: usize,
    ) -> Vec<alt_svc::AlternativeTarget> {
        self.state.alt_svc.as_ref().map_or_else(Vec::new, |store| {
            store
                .get_up_to(endpoint, route, max)
                .iter()
                .map(alt_svc::AlternativeTarget::new)
                .collect()
        })
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
            if let Some(history) = &self.state.rtt_history {
                history.invalidate(endpoint, route, alternative.host(), alternative.port());
            }
        }
    }

    /// Returns whether `alternative` is in a broken period for `endpoint`
    /// and `route`.
    pub(crate) fn alt_svc_is_broken(
        &self,
        endpoint: &crate::authority::Endpoint,
        route: &crate::Route,
        alternative: &alt_svc::AlternativeTarget,
    ) -> bool {
        self.state
            .alt_svc
            .as_ref()
            .is_some_and(|store| store.is_broken(endpoint, route, alternative.location()))
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
    /// The alternative is removed from its stored Alt-Svc advertisement,
    /// unless the advertisement was replaced meanwhile, so the next request
    /// takes the next alternative the field listed; the advertisement goes
    /// once it lists none. An HTTPS record cannot be evicted from DNS, so its
    /// location is marked broken instead, for the racing policy's backoff or,
    /// under the sequential policy, for [`AltSvcBrokenBackoff::CHROMIUM_153`].
    pub(crate) fn invalidate_alternative(
        &self,
        endpoint: &crate::authority::Endpoint,
        route: &crate::Route,
        alternative: &alt_svc::AlternativeTarget,
    ) {
        if let Some(history) = &self.state.rtt_history {
            history.invalidate(endpoint, route, alternative.host(), alternative.port());
        }
        match alternative.generation() {
            Some(generation) => {
                if let Some(store) = &self.state.alt_svc {
                    store.remove_if_current(endpoint, route, generation, alternative.location());
                }
            }
            None => {
                let backoff = self.state.alt_svc_policy.race_settings().map_or(
                    AltSvcBrokenBackoff::CHROMIUM_153,
                    AltSvcRace::broken_backoff,
                );
                self.mark_alt_svc_broken(endpoint, route, alternative, backoff);
            }
        }
    }

    /// Returns the UDP settings of the HTTPS record lookups' query sockets.
    #[cfg(all(test, feature = "https-records"))]
    pub(crate) fn https_record_udp_settings(&self) -> Option<phantom_profile::UdpSettings> {
        self.state
            .https_records
            .as_ref()
            .and_then(|discovery| discovery.resolver().udp_settings())
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
    /// use phantom::{Client, profile::{ClientProfile, browser::chrome}};
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let profile = || ClientProfile::new(chrome::v154_tcp_tls());
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
    /// path, host-only flag, and schemeful partition site wins. Expiry is
    /// rounded down to a second and never extended. Cookies the jar already
    /// holds take precedence, as does a held `Secure` cookie that an entry from an
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

    /// Clears RTT samples and client-local QUIC success used by racing.
    ///
    /// A connection started before clearing cannot restore this history.
    /// Existing connections remain usable. Create a fresh client when its
    /// local network identity changes; this client has no network notifier.
    pub fn clear_alt_svc_racing_history(&self) {
        if let Some(history) = &self.state.rtt_history {
            history.clear();
        }
    }

    /// Clears learned alternatives and the client's RTT racing history.
    pub fn clear_alt_svc(&self) {
        self.clear_alt_svc_racing_history();
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
        self.state.alt_svc.as_ref().map(|store| store.export())
    }

    /// Imports alternatives from a previously exported or caller-built snapshot.
    ///
    /// Every entry is revalidated first; one invalid entry rejects the whole
    /// snapshot without changing state. Expired entries are dropped, the
    /// entries for one origin form its list of alternatives in snapshot
    /// order, up to eight, and lifetimes are clamped and never extended. An
    /// origin ranks where its last entry stands. Origins this client already
    /// holds take precedence and imported origins rank as least recently
    /// used, so capacity keeps held origins and then the most recently used
    /// snapshot origins. Every imported origin receives a fresh generation,
    /// like a learned advertisement, and belongs to the direct route, so no
    /// import can reach a proxy route.
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
            .field(
                "max_http3_connections_per_origin",
                &self.state.http3.max_connections(),
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
                &self.state.alt_svc.as_ref().map(|store| store.capacity()),
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
                    .map(|store| store.capacity()),
            )
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
