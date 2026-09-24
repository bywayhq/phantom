use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::{Arc, MutexGuard, OnceLock, PoisonError},
};

use http::Method;
use phantom_net::http1::{
    AbsoluteForm, Http1Connection, Http1TlsConnector, Http1TlsError, OriginForm, RequestHeader,
    validate_forward_request_body_source_with_trailers, validate_request_body_source_with_trailers,
};
use phantom_net::proxy::HttpsProxyConnector;
use phantom_net::request::RequestBody;
use tokio::sync::Mutex;
use tracing::debug;

use super::admission::{Admission, AdmissionPermit, AdmissionRegistry};
use crate::timeout::{TimeoutBudget, TimeoutPhase};
use crate::{
    HttpProtocol, RequestError, ResponseBody, Route,
    authority::Endpoint,
    retry::{ConnectionSetupRetryState, acquire_with_retries},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Http1ConnectionMode {
    TlsOrigin,
    PlaintextOrigin,
    Forward,
}

/// Exact HTTP/1.1 connections, grouped by origin and route.
///
/// Each pool key keeps up to `max_active` connections, idle ones included.
/// A request first passes the key's admission, which lets at most
/// `max_active` requests through and queues the rest in arrival order. It
/// then takes the most recently used idle connection, or opens one when none
/// is idle.
pub(crate) struct Http1Pool {
    capacity: NonZeroUsize,
    max_active: NonZeroUsize,
    max_pending: NonZeroUsize,
    state: Mutex<PoolState>,
}

impl Http1Pool {
    pub(super) fn new(
        capacity: NonZeroUsize,
        max_active: NonZeroUsize,
        max_pending: NonZeroUsize,
    ) -> Self {
        Self {
            capacity,
            max_active,
            max_pending,
            state: Mutex::new(PoolState::default()),
        }
    }

    pub(super) const fn capacity(&self) -> NonZeroUsize {
        self.capacity
    }

    pub(super) const fn max_active(&self) -> NonZeroUsize {
        self.max_active
    }

    pub(super) const fn max_pending(&self) -> NonZeroUsize {
        self.max_pending
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_request(
        &self,
        connector: &Http1TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        mode: Http1ConnectionMode,
        method: Method,
        target: OriginForm,
        absolute_target: AbsoluteForm,
        headers: Vec<RequestHeader>,
        trailers: Vec<RequestHeader>,
        body: Option<RequestBody>,
        forward_authorization: bool,
        fresh_connection: bool,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
    ) -> Result<http::Response<ResponseBody>, RequestError> {
        let mut authenticated_headers = None;
        let validation: Result<(), phantom_net::http1::Http1Error> = (|| {
            if mode != Http1ConnectionMode::Forward {
                return validate_request_body_source_with_trailers(
                    &method,
                    &target,
                    &headers,
                    body.as_ref(),
                    &trailers,
                );
            }
            validate_forward_request_body_source_with_trailers(
                &method,
                &absolute_target,
                &headers,
                body.as_ref(),
                &trailers,
            )?;
            if let Some(credentials) = route
                .as_http_proxy()
                .and_then(crate::HttpProxy::basic_credentials)
            {
                let mut candidate = headers.clone();
                candidate.push(credentials.proxy_authorization_header());
                validate_forward_request_body_source_with_trailers(
                    &method,
                    &absolute_target,
                    &candidate,
                    body.as_ref(),
                    &trailers,
                )?;
                authenticated_headers = Some(candidate);
            }
            Ok(())
        })();
        validation
            .map_err(Http1TlsError::from)
            .map_err(RequestError::http1)?;
        let headers = if forward_authorization {
            authenticated_headers
                .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http1))?
        } else {
            headers
        };
        if route.as_http_proxy().is_some_and(|proxy| proxy.uses_tls()) && https_proxy.is_none() {
            return Err(RequestError::unsupported_route(HttpProtocol::Http1));
        }
        let key = PoolKey::new(endpoint, route, mode);
        let entry = self.entry(key).await;
        let permit = timeout_budget
            .run(
                TimeoutPhase::PoolAdmission,
                Some(HttpProtocol::Http1),
                entry.admit(),
            )
            .await?;
        let mut lease =
            acquire_with_retries(HttpProtocol::Http1, timeout_budget, retries, || async {
                entry
                    .acquire(
                        connector,
                        https_proxy,
                        endpoint,
                        route,
                        mode,
                        forward_authorization || fresh_connection,
                    )
                    .await
            })
            .await?;
        let result = timeout_budget
            .run(
                TimeoutPhase::ResponseHead,
                Some(HttpProtocol::Http1),
                async {
                    Ok(if mode == Http1ConnectionMode::Forward {
                        lease
                            .connection
                            .send_forward_request_body_with_trailers(
                                method,
                                absolute_target,
                                headers,
                                body,
                                trailers,
                            )
                            .await
                    } else {
                        lease
                            .connection
                            .send_request_body_with_trailers(
                                method, target, headers, body, trailers,
                            )
                            .await
                    })
                },
            )
            .await;
        match result {
            Ok(Ok(response)) => {
                if mode == Http1ConnectionMode::Forward
                    && route
                        .as_http_proxy()
                        .and_then(crate::HttpProxy::basic_credentials)
                        .is_some()
                    && response.status() == http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
                {
                    // A zero-length 407 may already have released its transport
                    // lease as reusable. Retire the generation before exposing
                    // the response so an authentication retry must reconnect.
                    lease.retire();
                }
                let (parts, body) = response.into_parts();
                Ok(http::Response::from_parts(
                    parts,
                    ResponseBody::http1_with_guard(
                        body,
                        RequestGuard {
                            _lease: lease,
                            _permit: permit,
                        },
                    ),
                ))
            }
            Ok(Err(error)) => {
                // The lease drops before the permit, so the next admitted
                // request finds a reusable connection idle.
                drop(lease);
                drop(permit);
                Err(RequestError::http1(error.into()))
            }
            Err(error) => {
                lease.retire();
                drop(lease);
                drop(permit);
                Err(error)
            }
        }
    }

    async fn entry(&self, key: PoolKey) -> Arc<PoolEntry> {
        let mut state = self.state.lock().await;
        if let Some(position) = state
            .entries
            .iter()
            .position(|(candidate, _)| candidate == &key)
            && let Some((stored_key, entry)) = state.entries.remove(position)
        {
            state.entries.push_back((stored_key, Arc::clone(&entry)));
            return entry;
        }

        if state.entries.len() == self.capacity.get() {
            state.entries.pop_front();
            debug!(outcome = "evicted", "HTTP/1 pool entry evicted");
        }
        let admission = state
            .admissions
            .get(&key, self.max_active, self.max_pending);
        let entry = Arc::new(PoolEntry::new(admission, self.max_active));
        state.entries.push_back((key, Arc::clone(&entry)));
        entry
    }
}

#[derive(Default)]
struct PoolState {
    entries: VecDeque<(PoolKey, Arc<PoolEntry>)>,
    admissions: AdmissionRegistry<PoolKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PoolKey {
    host: Box<str>,
    port: u16,
    route: Route,
    mode: Http1ConnectionMode,
}

impl PoolKey {
    fn new(endpoint: &Endpoint, route: &Route, mode: Http1ConnectionMode) -> Self {
        Self {
            host: endpoint.host().to_ascii_lowercase().into(),
            port: endpoint.port(),
            route: route.clone(),
            mode,
        }
    }
}

struct PoolEntry {
    connections: Arc<EntryConnections>,
    admission: Arc<Admission>,
    connector: OnceLock<Http1TlsConnector>,
    https_proxy: OnceLock<HttpsProxyConnector>,
}

impl PoolEntry {
    fn new(admission: Arc<Admission>, max_connections: NonZeroUsize) -> Self {
        Self {
            connections: Arc::new(EntryConnections {
                max: max_connections,
                set: std::sync::Mutex::new(ConnectionSet::default()),
            }),
            admission,
            connector: OnceLock::new(),
            https_proxy: OnceLock::new(),
        }
    }

    async fn admit(&self) -> Result<AdmissionPermit, RequestError> {
        Arc::clone(&self.admission).admit(HttpProtocol::Http1).await
    }

    async fn acquire(
        &self,
        connector: &Http1TlsConnector,
        https_proxy: Option<&HttpsProxyConnector>,
        endpoint: &Endpoint,
        route: &Route,
        mode: Http1ConnectionMode,
        force_new_connection: bool,
    ) -> Result<ConnectionLease, RequestError> {
        let reservation = match self.connections.checkout(force_new_connection) {
            Checkout::Idle(lease) => {
                debug!(
                    outcome = "hit",
                    "HTTP/1 connection acquired from client pool"
                );
                return Ok(lease);
            }
            Checkout::Reserved(reservation) => reservation,
        };

        debug!(outcome = "connect", "HTTP/1 client pool opening connection");
        let connection = match mode {
            Http1ConnectionMode::Forward => {
                let Route::HttpProxy(proxy) = route else {
                    return Err(RequestError::unsupported_route(HttpProtocol::Http1));
                };
                if proxy.uses_tls() {
                    let base = https_proxy
                        .ok_or_else(|| RequestError::unsupported_route(HttpProtocol::Http1))?;
                    let proxy_connector = self
                        .https_proxy
                        .get_or_init(|| proxy.https_connector(&base.with_isolated_session_cache()));
                    connector
                        .connect_https_forward_proxy(
                            proxy_connector,
                            proxy.host(),
                            proxy.port(),
                            proxy.host(),
                        )
                        .await
                        .map_err(RequestError::http1_connection_setup)?
                } else {
                    connector
                        .connect_forward_proxy(proxy.host(), proxy.port())
                        .await
                        .map_err(RequestError::http1_connection_setup)?
                }
            }
            Http1ConnectionMode::PlaintextOrigin => {
                if !matches!(route, Route::Direct) {
                    return Err(RequestError::unsupported_route(HttpProtocol::Http1));
                }
                connector
                    .connect_plaintext_direct(endpoint.host(), endpoint.port())
                    .await
                    .map_err(RequestError::http1_connection_setup)?
            }
            Http1ConnectionMode::TlsOrigin => {
                let connector = self
                    .connector
                    .get_or_init(|| connector.with_isolated_session_cache());
                match route {
                    // Rejected before admission; never reinterpreted as TCP.
                    Route::ConnectUdp(_) => {
                        return Err(RequestError::unsupported_route(HttpProtocol::Http1));
                    }
                    Route::Direct => connector
                        .connect_direct(endpoint.host(), endpoint.port(), endpoint.host())
                        .await
                        .map_err(RequestError::http1_connection_setup)?,
                    Route::HttpProxy(proxy) => {
                        let connect_authority = endpoint.tunnel_authority();
                        if proxy.uses_tls() {
                            let base = https_proxy.ok_or_else(|| {
                                RequestError::unsupported_route(HttpProtocol::Http1)
                            })?;
                            let proxy_connector = self.https_proxy.get_or_init(|| {
                                proxy.https_connector(&base.with_isolated_session_cache())
                            });
                            if let Some(credentials) = proxy.basic_credentials() {
                                // Bound the challenge/retry state machine without
                                // adding allocation to unauthenticated connections.
                                Box::pin(connector.connect_https_connect_with_basic_auth(
                                    proxy_connector,
                                    proxy.host(),
                                    proxy.port(),
                                    proxy.host(),
                                    &connect_authority,
                                    proxy.ordered_connect_headers(),
                                    credentials,
                                    endpoint.host(),
                                ))
                                .await
                                .map_err(RequestError::http1_connection_setup)?
                            } else {
                                connector
                                    .connect_https_connect(
                                        proxy_connector,
                                        proxy.host(),
                                        proxy.port(),
                                        proxy.host(),
                                        &connect_authority,
                                        proxy.ordered_connect_headers(),
                                        endpoint.host(),
                                    )
                                    .await
                                    .map_err(RequestError::http1_connection_setup)?
                            }
                        } else {
                            if let Some(credentials) = proxy.basic_credentials() {
                                Box::pin(connector.connect_http_connect_with_basic_auth(
                                    proxy.host(),
                                    proxy.port(),
                                    &connect_authority,
                                    proxy.ordered_connect_headers(),
                                    credentials,
                                    endpoint.host(),
                                ))
                                .await
                                .map_err(RequestError::http1_connection_setup)?
                            } else {
                                connector
                                    .connect_http_connect(
                                        proxy.host(),
                                        proxy.port(),
                                        &connect_authority,
                                        proxy.ordered_connect_headers(),
                                        endpoint.host(),
                                    )
                                    .await
                                    .map_err(RequestError::http1_connection_setup)?
                            }
                        }
                    }
                    Route::Socks5(proxy) => match proxy.dns_mode() {
                        crate::Socks5DnsMode::Local => connector
                            .connect_socks5_local_with_auth(
                                proxy.host(),
                                proxy.port(),
                                proxy.auth(),
                                endpoint.host(),
                                endpoint.port(),
                                endpoint.host(),
                            )
                            .await
                            .map_err(RequestError::http1_connection_setup)?,
                        crate::Socks5DnsMode::Remote => connector
                            .connect_socks5_remote_with_auth(
                                proxy.host(),
                                proxy.port(),
                                proxy.auth(),
                                endpoint.host(),
                                endpoint.port(),
                                endpoint.host(),
                            )
                            .await
                            .map_err(RequestError::http1_connection_setup)?,
                    },
                }
            }
        };
        Ok(reservation.into_lease(connection))
    }
}

/// The connections of one pool key.
///
/// Admission lets at most `max` requests past it, and each holds at most one
/// lease, so a request that finds no idle connection always has room to open
/// one. A lease returns its connection before the request's admission permit
/// is released.
struct EntryConnections {
    max: NonZeroUsize,
    set: std::sync::Mutex<ConnectionSet>,
}

#[derive(Default)]
struct ConnectionSet {
    /// Connections with no request, least recently used first.
    idle: Vec<Http1Connection>,
    /// Connections leased to a request, and connections being opened.
    leased: usize,
}

impl ConnectionSet {
    fn open(&self) -> usize {
        self.idle.len() + self.leased
    }
}

enum Checkout {
    /// An idle connection that has carried an earlier request.
    Idle(ConnectionLease),
    /// A slot for a connection the caller opens.
    Reserved(Reservation),
}

impl EntryConnections {
    fn lock(&self) -> MutexGuard<'_, ConnectionSet> {
        self.set.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Leases the most recently used idle connection, or reserves a slot for a
    /// new connection when none is idle or `force_new_connection` is set.
    fn checkout(self: &Arc<Self>, force_new_connection: bool) -> Checkout {
        let mut set = self.lock();
        set.idle.retain(Http1Connection::is_reusable);
        let idle = if force_new_connection {
            if set.open() >= self.max.get() && !set.idle.is_empty() {
                // Proxy-authentication and reused-connection replays both need
                // a connection that has carried no earlier request. Close the
                // least recently used idle one to stay within the bound.
                set.idle.remove(0);
                debug!(
                    outcome = "authentication_retry",
                    "HTTP/1 pooled connection retired before a fresh-connection attempt"
                );
            }
            None
        } else {
            set.idle.pop()
        };
        set.leased += 1;
        let reservation = Reservation {
            connections: Arc::clone(self),
            released: false,
        };
        match idle {
            Some(connection) => Checkout::Idle(reservation.into_lease(connection)),
            None => Checkout::Reserved(reservation),
        }
    }

    /// Frees one leased slot, keeping `connection` idle when it is reusable.
    fn release(&self, connection: Option<Http1Connection>) {
        let mut set = self.lock();
        set.leased = set.leased.saturating_sub(1);
        match connection {
            Some(connection) if connection.is_reusable() => set.idle.push(connection),
            _ => debug!(
                outcome = "invalidated",
                "HTTP/1 pooled connection invalidated"
            ),
        }
    }

    #[cfg(test)]
    fn open(&self) -> usize {
        self.lock().open()
    }
}

/// A slot counted against the pool key's bound before its connection exists.
///
/// Dropping it, for example when connection setup fails or the request is
/// cancelled, frees the slot.
struct Reservation {
    connections: Arc<EntryConnections>,
    released: bool,
}

impl Reservation {
    fn into_lease(self, connection: Http1Connection) -> ConnectionLease {
        ConnectionLease {
            reservation: self,
            connection,
            retired: false,
        }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        if !self.released {
            self.connections.release(None);
        }
    }
}

/// One request's hold on a pool-key connection.
///
/// Dropping it returns a still-reusable connection to the idle list unless it
/// was retired.
struct ConnectionLease {
    reservation: Reservation,
    connection: Http1Connection,
    retired: bool,
}

impl ConnectionLease {
    /// Keeps this connection from serving another request.
    fn retire(&mut self) {
        self.retired = true;
    }
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        let connection = (!self.retired).then(|| self.connection.clone());
        self.reservation.connections.release(connection);
        self.reservation.released = true;
    }
}

/// Held by a response body until it completes or is dropped.
///
/// Fields drop in declaration order, so the connection returns to the idle
/// list before the admission permit lets the next request in.
struct RequestGuard {
    _lease: ConnectionLease,
    _permit: AdmissionPermit,
}

#[cfg(test)]
mod tests;
