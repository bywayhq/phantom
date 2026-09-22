use std::{
    collections::VecDeque,
    num::NonZeroUsize,
    sync::{Arc, OnceLock},
};

use http::{Method, Response};
use phantom_net::{
    http1::{
        Http1Connection,
        validate_request_body_source_with_trailers as validate_http1_request_body_source_with_trailers,
    },
    http1_or_2::{Http1Or2Connection, Http1Or2TlsConnector},
    http2::{
        Http2Connection, Http2Error, Http2ProtocolErrorKind,
        validate_request_body_source_with_trailers as validate_http2_request_body_source_with_trailers,
    },
    request::{OriginForm, RequestBody, RequestHeader},
};
use phantom_profile::Http2Priority;
use tokio::sync::Mutex;
use tracing::{Span, debug};

use super::{
    admission::{Admission, AdmissionPermit, AdmissionRegistry},
    client_hints::ClientHintContext,
    http2_pool::{is_graceful_goaway, send_on},
};
use crate::{
    HttpProtocol, RequestError, ResponseBody,
    authority::Endpoint,
    error::is_unprocessed_http2,
    retry::{ConnectionSetupRetryState, acquire_unselected_with_retries},
    timeout::{TimeoutBudget, TimeoutPhase},
};

pub(crate) struct Http1Or2Pool {
    capacity: NonZeroUsize,
    max_http1_pending: NonZeroUsize,
    max_http2_active: NonZeroUsize,
    max_http2_pending: NonZeroUsize,
    state: Mutex<PoolState>,
}

impl Http1Or2Pool {
    pub(super) fn new(
        http1_capacity: NonZeroUsize,
        max_http1_pending: NonZeroUsize,
        http2_capacity: NonZeroUsize,
        max_http2_active: NonZeroUsize,
        max_http2_pending: NonZeroUsize,
    ) -> Self {
        Self {
            capacity: http1_capacity.min(http2_capacity),
            max_http1_pending,
            max_http2_active,
            max_http2_pending,
            state: Mutex::new(PoolState::default()),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn send_request(
        &self,
        connector: &Http1Or2TlsConnector,
        endpoint: &Endpoint,
        request_span: &Span,
        method: Method,
        target: OriginForm,
        http1_headers: Vec<RequestHeader>,
        http2_headers: Vec<RequestHeader>,
        trailers: Vec<RequestHeader>,
        client_hints: Option<ClientHintContext<'_>>,
        body: Option<RequestBody>,
        http2_priority: Option<Http2Priority>,
        fresh_http1_connection: bool,
        leased: Option<NegotiatedLease>,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
    ) -> Result<NegotiatedResponse, RequestError> {
        let (http1_wire_headers, http1_sent_headers) = validate_request(
            endpoint,
            &method,
            &target,
            http1_headers,
            &http2_headers,
            &trailers,
            client_hints,
            body.as_ref(),
        )?;

        // A raced connection was admitted by this pool for this endpoint.
        let mut leased = leased;
        let entry = match &leased {
            Some(leased) => Arc::clone(&leased.entry),
            None => self.entry(PoolKey::new(endpoint)).await,
        };
        // Same eligibility as the exact HTTP/2 pool: only a bodyless GET
        // without trailers may repeat after GOAWAY(NO_ERROR).
        let graceful_goaway_replayable =
            method == Method::GET && body.is_none() && trailers.is_empty();
        let request = NegotiatedRequest {
            method,
            authority: endpoint.authority().as_str(),
            target,
            http1_wire_headers,
            http1_sent_headers,
            http2_headers,
            http2_priority,
            trailers,
            client_hints,
        };
        let retire_unprocessed = retries.replays_unprocessed_requests();
        let mut retried_graceful_goaway = false;
        let mut fresh_http1_connection = fresh_http1_connection;

        loop {
            let (lease, permit) = match leased.take() {
                Some(leased) => (leased.lease, leased.permit),
                None => {
                    let selection = timeout_budget
                        .run(
                            TimeoutPhase::PoolAdmission,
                            None,
                            entry.admit_before_selection(),
                        )
                        .await?;
                    entry
                        .acquire_selected(
                            connector,
                            endpoint,
                            request_span,
                            selection,
                            std::mem::take(&mut fresh_http1_connection),
                            timeout_budget,
                            retries,
                        )
                        .await?
                }
            };
            if !graceful_goaway_replayable || retried_graceful_goaway {
                return entry
                    .dispatch_on_lease(
                        lease,
                        permit,
                        request,
                        body,
                        retire_unprocessed,
                        timeout_budget,
                    )
                    .await
                    .map_err(RequestError::from);
            }
            match entry
                .dispatch_on_lease(
                    lease,
                    permit,
                    request.clone(),
                    None,
                    retire_unprocessed,
                    timeout_budget,
                )
                .await
            {
                Ok(response) => return Ok(response),
                Err(DispatchFailure::Request(error)) => return Err(error),
                Err(DispatchFailure::GracefulGoaway(_)) => {
                    // The protocol admission was released with the refused
                    // stream; the replacement is admitted and negotiated anew.
                    retried_graceful_goaway = true;
                    debug!(
                        retry = 1,
                        reason = "graceful_goaway",
                        "retrying negotiated request on a replacement connection"
                    );
                }
            }
        }
    }

    /// Admits one request and acquires its ALPN-selected connection without
    /// dispatching; the lease holds the selected protocol's admission.
    pub(crate) async fn acquire_lease(
        &self,
        connector: &Http1Or2TlsConnector,
        endpoint: &Endpoint,
        request_span: &Span,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
    ) -> Result<NegotiatedLease, RequestError> {
        let entry = self.entry(PoolKey::new(endpoint)).await;
        let selection = timeout_budget
            .run(
                TimeoutPhase::PoolAdmission,
                None,
                entry.admit_before_selection(),
            )
            .await?;
        let (lease, permit) = entry
            .acquire_selected(
                connector,
                endpoint,
                request_span,
                selection,
                false,
                timeout_budget,
                retries,
            )
            .await?;
        Ok(NegotiatedLease {
            entry,
            lease,
            permit,
        })
    }

    /// Bounds requests that hold no protocol-specific admission yet.
    ///
    /// ALPN has not chosen H1 or H2 at this point, so the bound takes the
    /// larger active and waiting limit of the two protocols (H1 always has
    /// one active exchange). Every request that the selected protocol could
    /// run or queue is therefore admitted, while waiters for the connection
    /// lock and setup retry delays remain bounded by configured limits.
    fn selection_limits(&self) -> (NonZeroUsize, NonZeroUsize) {
        (
            self.max_http2_active,
            self.max_http1_pending.max(self.max_http2_pending),
        )
    }

    /// Admits one stream on the current reusable HTTP/2 generation for this
    /// origin.
    ///
    /// This neither opens a connection nor creates a pool entry, and it does
    /// not change eviction order. An HTTP/1.1 generation yields `None`. When
    /// an HTTP/2 generation exists, the returned permit is the HTTP/2
    /// admission a negotiated request holds once ALPN selected HTTP/2: it
    /// waits at the active bound and fails with a typed capacity error when
    /// the waiting bound is full. The generation is checked again after
    /// admission because it may have been retired while the caller waited.
    #[cfg(feature = "websocket")]
    pub(crate) async fn admit_current_http2_connection(
        &self,
        endpoint: &Endpoint,
    ) -> Result<Option<(Http2Connection, AdmissionPermit)>, RequestError> {
        let key = PoolKey::new(endpoint);
        let entry = {
            let state = self.state.lock().await;
            state
                .entries
                .iter()
                .find(|(candidate, _)| candidate == &key)
                .map(|(_, entry)| Arc::clone(entry))
        };
        let Some(entry) = entry else {
            return Ok(None);
        };
        if entry.current_reusable_http2().await.is_none() {
            return Ok(None);
        }
        let permit = entry.admit(HttpProtocol::Http2).await?;
        Ok(entry
            .current_reusable_http2()
            .await
            .map(|connection| (connection, permit)))
    }

    /// Returns whether the origin's current generation is a reusable HTTP/2
    /// connection.
    ///
    /// This neither opens a connection, creates a pool entry, admits a
    /// request, nor changes eviction order. An entry whose connection is
    /// being set up, or an HTTP/1.1 generation, counts as unavailable.
    pub(crate) async fn has_available_http2(&self, endpoint: &Endpoint) -> bool {
        let key = PoolKey::new(endpoint);
        let entry = {
            let state = self.state.lock().await;
            state
                .entries
                .iter()
                .find(|(candidate, _)| candidate == &key)
                .map(|(_, entry)| Arc::clone(entry))
        };
        let Some(entry) = entry else {
            return false;
        };
        // The connection lock is held across setup, so it is not awaited.
        let Ok(current) = entry.current.try_lock() else {
            return false;
        };
        matches!(
            current.as_ref().map(|slot| &slot.connection),
            Some(PooledConnection::Http2(connection)) if connection.is_reusable()
        )
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
            debug!(outcome = "evicted", "negotiated HTTP pool entry evicted");
        }
        let http1_admission =
            state
                .http1_admissions
                .get(&key, NonZeroUsize::MIN, self.max_http1_pending);
        let http2_admission =
            state
                .http2_admissions
                .get(&key, self.max_http2_active, self.max_http2_pending);
        let (selection_active, selection_pending) = self.selection_limits();
        let selection_admission =
            state
                .selection_admissions
                .get(&key, selection_active, selection_pending);
        let entry = Arc::new(PoolEntry::new(
            selection_admission,
            http1_admission,
            http2_admission,
        ));
        state.entries.push_back((key, Arc::clone(&entry)));
        entry
    }
}

#[derive(Default)]
struct PoolState {
    entries: VecDeque<(PoolKey, Arc<PoolEntry>)>,
    selection_admissions: AdmissionRegistry<PoolKey>,
    http1_admissions: AdmissionRegistry<PoolKey>,
    http2_admissions: AdmissionRegistry<PoolKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PoolKey {
    host: Box<str>,
    port: u16,
}

impl PoolKey {
    fn new(endpoint: &Endpoint) -> Self {
        Self {
            host: endpoint.host().to_ascii_lowercase().into(),
            port: endpoint.port(),
        }
    }
}

struct PoolEntry {
    current: Mutex<Option<ConnectionSlot>>,
    selection_admission: Arc<Admission>,
    http1_admission: Arc<Admission>,
    http2_admission: Arc<Admission>,
    connector: OnceLock<Http1Or2TlsConnector>,
}

impl PoolEntry {
    fn new(
        selection_admission: Arc<Admission>,
        http1_admission: Arc<Admission>,
        http2_admission: Arc<Admission>,
    ) -> Self {
        Self {
            current: Mutex::new(None),
            selection_admission,
            http1_admission,
            http2_admission,
            connector: OnceLock::new(),
        }
    }

    #[cfg(feature = "websocket")]
    async fn current_reusable_http2(&self) -> Option<Http2Connection> {
        let current = self.current.lock().await;
        match current.as_ref().map(|slot| &slot.connection) {
            Some(PooledConnection::Http2(connection)) if connection.is_reusable() => {
                Some(connection.clone())
            }
            _ => None,
        }
    }

    /// Phase one: bounded admission before ALPN selects a protocol.
    async fn admit_before_selection(&self) -> Result<AdmissionPermit, RequestError> {
        Arc::clone(&self.selection_admission)
            .admit_unselected()
            .await
    }

    async fn admit(&self, protocol: HttpProtocol) -> Result<AdmissionPermit, RequestError> {
        match protocol {
            HttpProtocol::Http1 => Arc::clone(&self.http1_admission).admit(protocol).await,
            HttpProtocol::Http2 => Arc::clone(&self.http2_admission).admit(protocol).await,
            HttpProtocol::Http3 => Err(RequestError::unsupported_protocol(protocol)),
        }
    }

    /// Phase two: acquires a selected-protocol lease and converts admission.
    ///
    /// `selection` stays held across setup retry delays and until the selected
    /// protocol admits the request, so the request is always counted by one
    /// bounded admission. The connection lock is released before any delay.
    /// `fresh_http1` retires a current H1 generation once before acquiring.
    #[allow(clippy::too_many_arguments)]
    async fn acquire_selected(
        &self,
        connector: &Http1Or2TlsConnector,
        endpoint: &Endpoint,
        request_span: &Span,
        selection: AdmissionPermit,
        fresh_http1: bool,
        timeout_budget: TimeoutBudget,
        retries: &mut ConnectionSetupRetryState,
    ) -> Result<(ConnectionLease, AdmissionPermit), RequestError> {
        if fresh_http1 {
            self.retire_http1().await;
        }
        loop {
            let lease = acquire_unselected_with_retries(timeout_budget, retries, || {
                self.acquire(connector, endpoint)
            })
            .await?;
            let protocol = lease.protocol();
            request_span.record("selected_protocol", protocol.trace_name());
            let permit = timeout_budget
                .run(
                    TimeoutPhase::PoolAdmission,
                    Some(protocol),
                    self.admit(protocol),
                )
                .await?;
            if self.is_current_and_reusable(&lease).await {
                drop(selection);
                return Ok((lease, permit));
            }
            drop(permit);
            self.invalidate(&lease.token).await;
        }
    }

    /// Phase three: dispatches the request on its admitted lease.
    ///
    /// `retire_unprocessed` retires an H2 connection that refused the stream,
    /// so an unprocessed replay uses another connection.
    async fn dispatch_on_lease(
        &self,
        lease: ConnectionLease,
        permit: AdmissionPermit,
        request: NegotiatedRequest<'_>,
        body: Option<RequestBody>,
        retire_unprocessed: bool,
        timeout_budget: TimeoutBudget,
    ) -> Result<NegotiatedResponse, DispatchFailure> {
        let NegotiatedRequest {
            method,
            authority,
            target,
            http1_wire_headers,
            http1_sent_headers,
            http2_headers,
            http2_priority,
            trailers,
            client_hints,
        } = request;
        let ConnectionLease { connection, token } = lease;

        match connection {
            PooledConnection::Http1(connection) => {
                let result = timeout_budget
                    .run(
                        TimeoutPhase::ResponseHead,
                        Some(HttpProtocol::Http1),
                        async {
                            Ok::<_, RequestError>(
                                connection
                                    .send_request_body_with_trailers(
                                        method,
                                        target,
                                        http1_wire_headers,
                                        body,
                                        trailers,
                                    )
                                    .await,
                            )
                        },
                    )
                    .await;
                match result {
                    Ok(Ok(response)) => {
                        let (parts, body) = response.into_parts();
                        Ok((
                            Response::from_parts(
                                parts,
                                ResponseBody::http1_with_guard(body, permit),
                            ),
                            HttpProtocol::Http1,
                            http1_sent_headers,
                        ))
                    }
                    Ok(Err(error)) => {
                        drop(permit);
                        if !connection.is_reusable() {
                            self.invalidate(&token).await;
                        }
                        Err(RequestError::http1(error.into()).into())
                    }
                    Err(error) => {
                        drop(permit);
                        self.invalidate(&token).await;
                        Err(error.into())
                    }
                }
            }
            PooledConnection::Http2(connection) => {
                let sent_headers = prepare_headers(
                    client_hints,
                    http2_headers,
                    client_hints
                        .and_then(|context| connection.accept_ch_for_origin(context.origin())),
                )?;
                let result = timeout_budget
                    .run(
                        TimeoutPhase::ResponseHead,
                        Some(HttpProtocol::Http2),
                        async {
                            Ok::<_, RequestError>(
                                send_on(
                                    &connection,
                                    method,
                                    authority,
                                    target,
                                    sent_headers.clone(),
                                    body,
                                    trailers,
                                    http2_priority,
                                )
                                .await,
                            )
                        },
                    )
                    .await;
                match result {
                    Ok(Ok(response)) => {
                        let (parts, body) = response.into_parts();
                        Ok((
                            Response::from_parts(
                                parts,
                                ResponseBody::http2_with_guard(body, permit),
                            ),
                            HttpProtocol::Http2,
                            sent_headers,
                        ))
                    }
                    Ok(Err(error)) => {
                        drop(permit);
                        if invalidates_http2_connection(&error)
                            || (retire_unprocessed && is_unprocessed_http2(&error))
                        {
                            self.invalidate(&token).await;
                        }
                        if is_graceful_goaway(&error) {
                            return Err(DispatchFailure::GracefulGoaway(error));
                        }
                        Err(RequestError::http2_stream(error).into())
                    }
                    Err(error) => {
                        drop(permit);
                        Err(error.into())
                    }
                }
            }
        }
    }

    async fn acquire(
        &self,
        connector: &Http1Or2TlsConnector,
        endpoint: &Endpoint,
    ) -> Result<ConnectionLease, RequestError> {
        let mut current = self.current.lock().await;
        if let Some(slot) = current.as_ref() {
            debug!(
                protocol = slot.connection.protocol().trace_name(),
                outcome = "generation",
                "negotiated HTTP pool found current generation"
            );
            return Ok(slot.lease());
        }

        debug!(
            outcome = "connect",
            "negotiated HTTP pool opening connection"
        );
        let connector = self
            .connector
            .get_or_init(|| connector.with_isolated_session_cache());
        let connection = connector
            .connect_direct(endpoint.host(), endpoint.port(), endpoint.host())
            .await
            .map_err(RequestError::http1_or_2_connection_setup)?;
        let slot = ConnectionSlot {
            connection: connection.into(),
            token: Arc::new(()),
        };
        let lease = slot.lease();
        *current = Some(slot);
        Ok(lease)
    }

    /// Retires a current H1 generation so the next acquisition connects anew.
    ///
    /// A current H2 generation is kept: it is not the reused H1 connection
    /// that failed, and the replacement is chosen by ALPN either way.
    async fn retire_http1(&self) {
        let mut current = self.current.lock().await;
        if current
            .as_ref()
            .is_some_and(|slot| matches!(slot.connection, PooledConnection::Http1(_)))
        {
            current.take();
            debug!(
                outcome = "retired",
                "negotiated HTTP/1 generation retired before a fresh-connection attempt"
            );
        }
    }

    async fn is_current_and_reusable(&self, lease: &ConnectionLease) -> bool {
        let current = self.current.lock().await;
        current.as_ref().is_some_and(|slot| {
            Arc::ptr_eq(&slot.token, &lease.token) && slot.connection.is_reusable()
        })
    }

    async fn invalidate(&self, token: &Arc<()>) {
        let mut current = self.current.lock().await;
        if current
            .as_ref()
            .is_some_and(|slot| Arc::ptr_eq(&slot.token, token))
        {
            current.take();
            debug!(
                outcome = "invalidated",
                "negotiated HTTP generation invalidated"
            );
        }
    }
}

/// A negotiated connection admitted for one request and not yet dispatched.
pub(crate) struct NegotiatedLease {
    entry: Arc<PoolEntry>,
    lease: ConnectionLease,
    permit: AdmissionPermit,
}

/// Checks one negotiated request's H1 and H2 representations before any I/O
/// and returns the H1 wire fields (with `Host`) and the H1 fields as sent.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_request(
    endpoint: &Endpoint,
    method: &Method,
    target: &OriginForm,
    http1_headers: Vec<RequestHeader>,
    http2_headers: &[RequestHeader],
    trailers: &[RequestHeader],
    client_hints: Option<ClientHintContext<'_>>,
    body: Option<&RequestBody>,
) -> Result<(Vec<RequestHeader>, Vec<RequestHeader>), RequestError> {
    let http1_sent_headers = prepare_headers(client_hints, http1_headers, None)?;
    let http2_validation_headers = prepare_headers(client_hints, http2_headers.to_vec(), None)?;
    let mut http1_wire_headers = Vec::with_capacity(http1_sent_headers.len() + 1);
    http1_wire_headers.push(RequestHeader::new(
        "Host",
        endpoint.authority().as_str().as_bytes(),
    ));
    http1_wire_headers.extend(http1_sent_headers.clone());
    validate_http1_request_body_source_with_trailers(
        method,
        target,
        &http1_wire_headers,
        body,
        trailers,
    )
    .map_err(RequestError::negotiated_http1_validation)?;
    validate_http2_request_body_source_with_trailers(
        method,
        endpoint.authority().as_str(),
        target,
        &http2_validation_headers,
        body,
        trailers,
    )
    .map_err(RequestError::negotiated_http2_validation)?;
    Ok((http1_wire_headers, http1_sent_headers))
}

/// One negotiated request, without its body, prepared for either protocol.
#[derive(Clone)]
struct NegotiatedRequest<'a> {
    method: Method,
    authority: &'a str,
    target: OriginForm,
    http1_wire_headers: Vec<RequestHeader>,
    http1_sent_headers: Vec<RequestHeader>,
    http2_headers: Vec<RequestHeader>,
    http2_priority: Option<Http2Priority>,
    trailers: Vec<RequestHeader>,
    client_hints: Option<ClientHintContext<'a>>,
}

type NegotiatedResponse = (Response<ResponseBody>, HttpProtocol, Vec<RequestHeader>);

enum DispatchFailure {
    /// The peer refused the stream with `GOAWAY(NO_ERROR)` before processing it.
    GracefulGoaway(Http2Error),
    Request(RequestError),
}

impl From<RequestError> for DispatchFailure {
    fn from(error: RequestError) -> Self {
        Self::Request(error)
    }
}

impl From<DispatchFailure> for RequestError {
    fn from(failure: DispatchFailure) -> Self {
        match failure {
            DispatchFailure::GracefulGoaway(error) => Self::http2_stream(error),
            DispatchFailure::Request(error) => error,
        }
    }
}

enum PooledConnection {
    Http1(Http1Connection),
    Http2(Http2Connection),
}

impl PooledConnection {
    fn protocol(&self) -> HttpProtocol {
        match self {
            Self::Http1(_) => HttpProtocol::Http1,
            Self::Http2(_) => HttpProtocol::Http2,
        }
    }

    fn is_reusable(&self) -> bool {
        match self {
            Self::Http1(connection) => connection.is_reusable(),
            Self::Http2(connection) => connection.is_reusable(),
        }
    }

    fn clone_connection(&self) -> Self {
        match self {
            Self::Http1(connection) => Self::Http1(connection.clone()),
            Self::Http2(connection) => Self::Http2(connection.clone()),
        }
    }
}

impl From<Http1Or2Connection> for PooledConnection {
    fn from(connection: Http1Or2Connection) -> Self {
        match connection {
            Http1Or2Connection::Http1(connection) => Self::Http1(connection),
            Http1Or2Connection::Http2(connection) => Self::Http2(connection),
        }
    }
}

struct ConnectionSlot {
    connection: PooledConnection,
    token: Arc<()>,
}

impl ConnectionSlot {
    fn lease(&self) -> ConnectionLease {
        ConnectionLease {
            connection: self.connection.clone_connection(),
            token: Arc::clone(&self.token),
        }
    }
}

struct ConnectionLease {
    connection: PooledConnection,
    token: Arc<()>,
}

impl ConnectionLease {
    fn protocol(&self) -> HttpProtocol {
        self.connection.protocol()
    }
}

fn prepare_headers(
    client_hints: Option<ClientHintContext<'_>>,
    headers: Vec<RequestHeader>,
    connection_accept_ch: Option<&[u8]>,
) -> Result<Vec<RequestHeader>, RequestError> {
    match client_hints {
        Some(context) => context.prepare(headers, connection_accept_ch),
        None => Ok(headers),
    }
}

fn invalidates_http2_connection(error: &Http2Error) -> bool {
    matches!(
        error,
        Http2Error::Protocol(error)
            if error.kind() != Http2ProtocolErrorKind::StreamReset
    )
}

#[cfg(test)]
mod tests {
    use std::{num::NonZeroUsize, sync::Arc};

    use super::{Http1Or2Pool, PoolKey};
    use crate::authority::Endpoint;

    #[tokio::test]
    async fn pre_selection_admission_survives_lru_eviction()
    -> Result<(), Box<dyn std::error::Error>> {
        let one = NonZeroUsize::MIN;
        let pool = Http1Or2Pool::new(one, one, one, one, one);
        let first = Endpoint::new("first.test:443".parse()?, 443)?;
        let second = Endpoint::new("second.test:443".parse()?, 443)?;

        let first_entry = pool.entry(PoolKey::new(&first)).await;
        let permit = first_entry.admit_before_selection().await?;
        pool.entry(PoolKey::new(&second)).await;
        drop(first_entry);
        let replacement = pool.entry(PoolKey::new(&first)).await;

        // A held permit keeps the original instance, so the recreated entry
        // counts against the same semaphore instead of a fresh one.
        assert!(Arc::ptr_eq(
            permit.admission(),
            &replacement.selection_admission
        ));
        assert_eq!(replacement.selection_admission.available_active(), 0);
        drop(permit);
        assert_eq!(replacement.selection_admission.available_active(), 1);
        Ok(())
    }
}
