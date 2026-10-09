use std::{error::Error as StdError, fmt, future::Future, num::NonZeroUsize, time::Duration};

use http::{HeaderMap, StatusCode};
use tracing::Span;

use crate::{
    HttpProtocol, RequestError,
    timeout::{TimeoutBudget, TimeoutPhase},
};

mod retry_after;

/// Choose which connection failures and response statuses to retry.
///
/// The default is [`RetryPolicy::none`]. Set a policy for a
/// client with [`ClientBuilder::retry_policy`](crate::ClientBuilder::retry_policy).
/// [`RequestBuilder::retry_policy`](crate::RequestBuilder::retry_policy)
/// replaces the whole policy for one request. Retries and replays keep the
/// route and protocol selection rule. With
/// [`with_http2_fallback`](Self::with_http2_fallback), an exact HTTP/3 request
/// can try HTTP/2 after its connection setup fails.
///
/// An eligible connection-setup retry occurs inside the selected H1, H2, or H3
/// pool. In the negotiated H1/H2 pool, it occurs before ALPN selection.
/// The origin request and body have not been sent, so no method or body
/// needs replaying. Connection-setup retries do not cover TLS, ALPN,
/// proxy negotiation, timeouts, HTTP responses, or protocol failures.
///
/// [`with_reused_connection_replay`](Self::with_reused_connection_replay)
/// separately opts into replaying an idempotent HTTP/1.1 request whose reused
/// keep-alive connection closed before any response byte, and an idempotent
/// HTTP/2 request that reached a connection already closed after an
/// unanswered PING.
/// [`with_unprocessed_replay`](Self::with_unprocessed_replay) separately opts
/// into replaying an HTTP/2 or HTTP/3 request that the peer reported as not
/// processed. [`with_status_retry`](Self::with_status_retry) separately opts
/// into repeating idempotent requests that received a caller-listed status.
/// [`with_max_retries`](Self::with_max_retries) caps all these caller-enabled
/// classes together across redirects. Their individual limits still apply.
/// The replay and status-retry classes never resend a one-shot streaming
/// body. Such a request returns the original error or response.
///
/// Some replays run independently of this policy and do not consume its
/// budgets. All but the last repeat a request the server did not process:
///
/// - The negotiated and exact HTTP/2 pools send a bodyless GET without
///   trailers once more if refused by `GOAWAY(NO_ERROR)`. It uses a replacement
///   connection, once per dispatch to the pool.
/// - When an HTTP/2 or HTTP/3 connection's ALPS `ACCEPT_CH` names a client
///   hint that a page load, or a request without a template, lacks, the pool
///   sends nothing of the request. The attempt builds it again with the hint
///   and sends it. Any method and body may restart because nothing was sent.
///   Each restart adds at least one
///   hint, so an attempt restarts at most once per hint the profile sends on
///   request. The origin attempt of an Alt-Svc race starts with none.
/// - When a server rejects TLS early data, the connection that sent it sends
///   the same bytes again once its handshake completes. The TCP stream or the
///   HTTP/3 pool owns the resend. The handshake answers early data once, so
///   the resend happens at most once per connection.
/// - When a server rejects a negotiated request's early data over TCP and
///   then selects another ALPN protocol, the connection fails before the
///   server processes anything. The negotiated pool removes the origin's TLS
///   tickets and sends the request once on a new connection that offers no
///   early data. A request that is not replay safe
///   waits for the server's answer before its body is used, so its body is
///   sent only on that new connection.
/// - When an HTTP/2 connection closes itself over an unanswered PING before
///   a request's response head, the request is sent again at once on another
///   connection, up to
///   [`Http2Settings::ping_failure_retries`](crate::profile::Http2Settings::ping_failure_retries)
///   times per redirect hop, whatever its method, as Chromium resends after
///   `ERR_HTTP2_PING_FAILED`. The server may have processed it.
///
/// Safe `Critical-CH` replays and proxy authentication exchanges also run
/// independently of this policy. Address attempts, background discovery and
/// connector-managed ECH retries do not consume the shared caller cap.
///
/// A delay or `Retry-After` limit must be small enough to add to the runtime
/// clock. A client policy that exceeds it makes
/// [`ClientBuilder::build`](crate::ClientBuilder::build) fail with
/// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
/// A per-request policy that exceeds it makes
/// [`RequestBuilder::send`](crate::RequestBuilder::send) fail with
/// [`RequestErrorKind::InvalidTimeout`](crate::RequestErrorKind::InvalidTimeout).
///
/// # Examples
///
/// ```
/// use std::{num::NonZeroUsize, time::Duration};
///
/// use phantom::RetryPolicy;
///
/// let policy = RetryPolicy::connection_failures(NonZeroUsize::MIN, Duration::from_millis(200))
///     .with_reused_connection_replay(true);
/// assert_eq!(policy.max_connection_failures(), Some(NonZeroUsize::MIN));
/// assert!(policy.reused_connection_replay());
/// assert_eq!(RetryPolicy::default(), RetryPolicy::none());
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetryPolicy {
    maximum_retries: Option<usize>,
    maximum_connection_failures: Option<NonZeroUsize>,
    delay: Duration,
    reused_connection_replay: bool,
    unprocessed_replays: Option<NonZeroUsize>,
    status_retry: Option<StatusRetry>,
    http2_fallback: bool,
}

impl RetryPolicy {
    /// Disables connection-setup retries, reused-connection replay,
    /// unprocessed-request replay, status retries, and the HTTP/2 fallback.
    #[must_use]
    pub const fn none() -> Self {
        Self {
            maximum_retries: None,
            maximum_connection_failures: None,
            delay: Duration::ZERO,
            reused_connection_replay: false,
            unprocessed_replays: None,
            status_retry: None,
            http2_fallback: false,
        }
    }

    /// Retries at most `maximum` eligible connection-establishment failures.
    ///
    /// Each retry waits for `delay` before starting another connection attempt.
    /// The complete request's total timeout continues through this delay. One
    /// budget of `maximum` covers every redirect hop of a request. The other
    /// retry classes start disabled. Chain their methods to enable them.
    #[must_use]
    pub const fn connection_failures(maximum: NonZeroUsize, delay: Duration) -> Self {
        Self {
            maximum_retries: None,
            maximum_connection_failures: Some(maximum),
            delay,
            reused_connection_replay: false,
            unprocessed_replays: None,
            status_retry: None,
            http2_fallback: false,
        }
    }

    /// Sets whether a request is replayed after its reused HTTP/1.1
    /// connection closes before any response byte.
    ///
    /// When enabled, exact and negotiated HTTP/1.1 requests can be sent again
    /// on a fresh connection over the same route. All these conditions apply:
    ///
    /// - The request was written to a connection that had delivered a response.
    /// - It closed or reset before any byte of the new response arrived.
    /// - The method is idempotent (RFC 9110, section 9.2.2).
    /// - The body can be replayed: absent, owned bytes, or buffered within
    ///   its limit with no source failure.
    ///
    /// A one-shot body, fresh connection or failure after any response byte
    /// returns the original error. At most one replay occurs per redirect
    /// hop. It has no delay and does not consume the connection-setup budget.
    ///
    /// The same replay covers an HTTP/2 request that reached a pooled
    /// connection after the connection closed itself over an unanswered PING
    /// ([`Http2Settings::ping_timeout`](crate::profile::Http2Settings::ping_timeout)),
    /// so that none of the request was sent. A request already sent when the
    /// PING failed is resent only under the profile's
    /// [`Http2Settings::ping_failure_retries`](crate::profile::Http2Settings::ping_failure_retries).
    #[must_use]
    pub const fn with_reused_connection_replay(self, enabled: bool) -> Self {
        Self {
            reused_connection_replay: enabled,
            ..self
        }
    }

    /// Replays, at most `maximum` times per request, an HTTP/2 or HTTP/3
    /// request that the peer reported as not processed. `None` disables it.
    ///
    /// This is caller policy, never browser or profile behavior. A replay
    /// starts only after one of these peer signals, observed before any
    /// response head:
    ///
    /// - HTTP/2 `RST_STREAM(REFUSED_STREAM)` received for the request stream
    ///   (RFC 9113, section 8.7);
    /// - an HTTP/2 `GOAWAY`, with any error code, whose last-stream-id is
    ///   below the request's stream, or that arrived before the stream opened
    ///   (RFC 9113, sections 6.8 and 8.7);
    /// - an HTTP/3 request stream reset or stopped with `H3_REQUEST_REJECTED`
    ///   (RFC 9114, section 4.1.1);
    /// - an HTTP/3 `GOAWAY` received before the request opened its stream,
    ///   so the request was never sent (RFC 9114, section 5.2).
    ///
    /// Because the server did not act on the request, any method may be
    /// replayed. The body must be absent, owned bytes or buffered within its
    /// limit with no source failure. A one-shot streaming body returns the
    /// original error without opening another connection.
    /// A replay is sent at once, without a delay, on a fresh or different
    /// connection with the same route and protocol, or the same negotiated
    /// selection rule. On an Alt-Svc alternative it stays on that
    /// alternative. The class budget is shared by every redirect hop. Each
    /// replay also consumes the shared [`Self::with_max_retries`] cap.
    /// HTTP/2 streams at or below a `GOAWAY`
    /// last-stream-id, HTTP/3 streams already open when a `GOAWAY` arrives,
    /// and any failure after a response head may have been processed and
    /// return the original error.
    ///
    /// Without this policy, only the built-in replays listed on
    /// [`RetryPolicy`] remain, such as a bodyless HTTP/2 GET refused by
    /// `GOAWAY(NO_ERROR)`, retried once on a replacement connection.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::num::NonZeroUsize;
    ///
    /// use phantom::RetryPolicy;
    ///
    /// let policy = RetryPolicy::none().with_unprocessed_replay(NonZeroUsize::new(2));
    /// assert_eq!(policy.unprocessed_replay(), NonZeroUsize::new(2));
    /// assert_eq!(RetryPolicy::default().unprocessed_replay(), None);
    /// ```
    #[must_use]
    pub const fn with_unprocessed_replay(self, maximum: Option<NonZeroUsize>) -> Self {
        Self {
            unprocessed_replays: maximum,
            ..self
        }
    }

    /// Repeats idempotent requests whose response has a status listed by
    /// `status_retry`.
    ///
    /// This is caller policy, never browser or profile behavior. A response is
    /// retried only when its status is listed, the method is idempotent (RFC
    /// 9110, section 9.2.2), the request body can be replayed, and the
    /// request-scoped budget, shared by every redirect hop, is not exhausted.
    /// Otherwise the response is returned unchanged. Each intermediate response
    /// updates cookies, client hints, and Alt-Svc exactly as a returned
    /// response would, and its body is then dropped without being read. The
    /// retry waits for the [`StatusRetry`] delay; a delay that cannot finish
    /// before the request's total deadline returns the response immediately.
    /// A retry keeps the route, the exact protocol or negotiated
    /// selection rule, and any Alt-Svc alternative in use.
    #[must_use]
    pub const fn with_status_retry(self, status_retry: StatusRetry) -> Self {
        Self {
            status_retry: Some(status_retry),
            ..self
        }
    }

    /// Sets whether failed exact HTTP/3 setup falls back to HTTP/2.
    ///
    /// This is the only retry policy that changes protocol. You enable it
    /// separately from browser settings. It starts after any
    /// connection-setup retries, only when no QUIC connection could carry the
    /// request: the connection attempt failed or was refused, the QUIC or TLS
    /// handshake failed, the attempt did not finish within the connect
    /// timeout, or a handshake that sent early data failed before the request
    /// was written. A request that could fall back limits each QUIC attempt
    /// to 4 seconds, the same limit as a raced Alt-Svc alternative. Chromium
    /// limits handshake inactivity instead and lets a responsive handshake
    /// run longer. A slow responsive handshake can therefore fall back here
    /// while Chromium keeps waiting. A name-resolution failure, a SOCKS5
    /// proxy failure, rejected Encrypted Client Hello, a full pool, or a
    /// failure after writing the request returns the HTTP/3 error.
    /// So does a request to an alternative pinned with
    /// [`RequestBuilder::alt_svc_alternative`](crate::RequestBuilder::alt_svc_alternative),
    /// and a replay-safe request sent as early data on a resumed connection,
    /// which leaves before its handshake completes. Turn early data off with
    /// [`ClientBuilder::http3_early_data`](crate::ClientBuilder::http3_early_data)
    /// for such a request to fall back too.
    ///
    /// The request then goes once, at once, as an exact HTTP/2 request on the
    /// same route: the profile's TLS ClientHello over TCP, its
    /// [`Http2Settings`](crate::profile::Http2Settings), and a template's
    /// HTTP/2 field list. The rest of the redirect hop stays on HTTP/2, and
    /// the next hop tries HTTP/3 again. Nothing is remembered between
    /// requests, so each one tries QUIC first. Any method may fall back
    /// because the server processed none of the request. The body must be
    /// absent, owned, or buffered within its limit, and a one-shot streaming
    /// body returns the HTTP/3 error. If the HTTP/2 attempt fails too, its
    /// error is returned.
    /// [`ResponseInfo::protocol`](crate::ResponseInfo::protocol) reports the
    /// protocol that answered.
    ///
    /// The client needs an HTTP/2 profile, and the route must carry TCP: an
    /// exact HTTP/3 request with this policy on a client without one, or on
    /// a CONNECT-UDP route, fails before any I/O.
    ///
    /// # Examples
    ///
    /// ```
    /// use phantom::RetryPolicy;
    ///
    /// let policy = RetryPolicy::none().with_http2_fallback(true);
    /// assert!(policy.http2_fallback());
    /// assert!(!RetryPolicy::default().http2_fallback());
    /// ```
    #[must_use]
    pub const fn with_http2_fallback(self, enabled: bool) -> Self {
        Self {
            http2_fallback: enabled,
            ..self
        }
    }

    /// Caps all caller-enabled retries across every redirect hop.
    ///
    /// `None` adds no shared cap. `Some(0)` disables caller retries without
    /// changing which classes are enabled. The cap covers connection setup,
    /// reused connections, peer-unprocessed requests, listed statuses and
    /// the explicit HTTP/3-to-HTTP/2 fallback. Each class keeps its own bounds.
    /// A delay never grants permission to retry.
    ///
    /// Redirects and the automatic replays listed on [`RetryPolicy`] do not
    /// consume this cap. Those replays keep their existing safety checks.
    #[must_use]
    pub const fn with_max_retries(self, maximum: Option<usize>) -> Self {
        Self {
            maximum_retries: maximum,
            ..self
        }
    }

    /// Returns the shared cap for caller-enabled retries.
    #[must_use]
    pub const fn max_retries(self) -> Option<usize> {
        self.maximum_retries
    }

    /// Returns the maximum number of connection failures that may be retried.
    #[must_use]
    pub const fn max_connection_failures(self) -> Option<NonZeroUsize> {
        self.maximum_connection_failures
    }

    /// Returns the delay before each connection retry.
    #[must_use]
    pub const fn delay(self) -> Duration {
        self.delay
    }

    /// Returns whether reused-connection replay is enabled.
    #[must_use]
    pub const fn reused_connection_replay(self) -> bool {
        self.reused_connection_replay
    }

    /// Returns the maximum unprocessed-request replays per request, when
    /// enabled.
    #[must_use]
    pub const fn unprocessed_replay(self) -> Option<NonZeroUsize> {
        self.unprocessed_replays
    }

    /// Returns the status-retry policy, when enabled.
    #[must_use]
    pub const fn status_retry(self) -> Option<StatusRetry> {
        self.status_retry
    }

    /// Returns whether an exact HTTP/3 request falls back to HTTP/2 when its
    /// connection cannot be set up.
    #[must_use]
    pub const fn http2_fallback(self) -> bool {
        self.http2_fallback
    }

    pub(crate) fn validate(self) -> bool {
        let now = std::time::Instant::now();
        (self.maximum_connection_failures.is_none() || now.checked_add(self.delay).is_some())
            && self.status_retry.is_none_or(|status_retry| {
                now.checked_add(status_retry.delay).is_some()
                    && status_retry
                        .retry_after_limit
                        .is_none_or(|limit| now.checked_add(limit).is_some())
            })
    }
}

/// Statuses a [`StatusRetry`] may list, in bit order.
///
/// Each reports a condition that a later identical request can clear: 408
/// (RFC 9110, section 15.5.9), 425 (RFC 8470, section 5.2), 429 (RFC 6585,
/// section 4), and the transient server statuses 500, 502, 503, and 504.
/// `421 Misdirected Request` is excluded: repeating it on the same route and
/// connection target cannot succeed.
const RETRYABLE_STATUSES: [StatusCode; 7] = [
    StatusCode::REQUEST_TIMEOUT,
    StatusCode::TOO_EARLY,
    StatusCode::TOO_MANY_REQUESTS,
    StatusCode::INTERNAL_SERVER_ERROR,
    StatusCode::BAD_GATEWAY,
    StatusCode::SERVICE_UNAVAILABLE,
    StatusCode::GATEWAY_TIMEOUT,
];

/// Opt-in caller policy that repeats requests after retryable statuses.
///
/// Attach it with [`RetryPolicy::with_status_retry`]. Only `408`, `425`,
/// `429`, `500`, `502`, `503`, and `504` may be listed. Every retry waits for
/// the constant delay unless [`honor_retry_after`](Self::honor_retry_after)
/// is set and the response carries a valid `Retry-After` field.
///
/// # Examples
///
/// ```
/// use std::{num::NonZeroUsize, time::Duration};
///
/// use http::StatusCode;
/// use phantom::{RetryPolicy, StatusRetry};
///
/// # fn main() -> Result<(), phantom::StatusRetryError> {
/// let status_retry = StatusRetry::new(
///     &[StatusCode::SERVICE_UNAVAILABLE, StatusCode::TOO_MANY_REQUESTS],
///     NonZeroUsize::MIN.saturating_add(1),
///     Duration::from_millis(250),
/// )?
/// .honor_retry_after(Duration::from_secs(5));
/// let policy = RetryPolicy::none().with_status_retry(status_retry);
/// assert!(policy.status_retry().is_some());
///
/// let misdirected = [StatusCode::MISDIRECTED_REQUEST];
/// assert!(StatusRetry::new(&misdirected, NonZeroUsize::MIN, Duration::ZERO).is_err());
/// # Ok(())
/// # }
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusRetry {
    statuses: u8,
    maximum: NonZeroUsize,
    delay: Duration,
    retry_after_limit: Option<Duration>,
}

impl StatusRetry {
    /// Retries at most `maximum` responses per request whose status is in
    /// `statuses`, waiting `delay` before each retry.
    ///
    /// `Retry-After` is ignored until [`Self::honor_retry_after`] is set. The
    /// `maximum` budget is shared by every redirect hop of a request.
    ///
    /// # Errors
    ///
    /// Returns [`StatusRetryError`] when `statuses` is empty or lists a status
    /// outside the retryable set, including `421 Misdirected Request`.
    pub fn new(
        statuses: &[StatusCode],
        maximum: NonZeroUsize,
        delay: Duration,
    ) -> Result<Self, StatusRetryError> {
        let mut bits = 0_u8;
        for status in statuses {
            let index = retryable_index(*status).ok_or(StatusRetryError {
                status: Some(*status),
            })?;
            bits |= 1 << index;
        }
        if bits == 0 {
            return Err(StatusRetryError { status: None });
        }
        Ok(Self {
            statuses: bits,
            maximum,
            delay,
            retry_after_limit: None,
        })
    }

    /// Uses a valid `Retry-After` field (RFC 9110, section 10.2.3) instead of
    /// the constant delay, up to `maximum_delay`.
    ///
    /// Accepts seconds (`delta-seconds`) or a date in IMF-fixdate `HTTP-date`
    /// format. A date becomes a delay against the system clock. A requested
    /// delay above `maximum_delay` returns the response without waiting or
    /// retrying. A missing, repeated, obsolete-format, or malformed field
    /// falls back to the constant delay.
    #[must_use]
    pub const fn honor_retry_after(self, maximum_delay: Duration) -> Self {
        Self {
            retry_after_limit: Some(maximum_delay),
            ..self
        }
    }

    /// Returns whether `status` is listed for retry.
    #[must_use]
    pub fn retries(self, status: StatusCode) -> bool {
        retryable_index(status).is_some_and(|index| self.statuses & (1 << index) != 0)
    }

    /// Returns the maximum number of status retries per request.
    #[must_use]
    pub const fn max_retries(self) -> NonZeroUsize {
        self.maximum
    }

    /// Returns the constant delay before each status retry.
    #[must_use]
    pub const fn delay(self) -> Duration {
        self.delay
    }

    /// Returns the largest honored `Retry-After` delay, when enabled.
    #[must_use]
    pub const fn retry_after_limit(self) -> Option<Duration> {
        self.retry_after_limit
    }

    /// Returns the delay before retrying `status`, or `None` to return it.
    fn delay_for(self, status: StatusCode, headers: &HeaderMap) -> Option<Duration> {
        if !self.retries(status) {
            return None;
        }
        let Some(limit) = self.retry_after_limit else {
            return Some(self.delay);
        };
        match retry_after::requested_delay(headers, std::time::SystemTime::now()) {
            Some(requested) if requested > limit => None,
            Some(requested) => Some(requested),
            None => Some(self.delay),
        }
    }
}

fn retryable_index(status: StatusCode) -> Option<usize> {
    RETRYABLE_STATUSES
        .iter()
        .position(|retryable| *retryable == status)
}

/// A [`StatusRetry`] status list that cannot be used.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusRetryError {
    status: Option<StatusCode>,
}

impl StatusRetryError {
    /// Returns the rejected status, or `None` when the list was empty.
    #[must_use]
    pub const fn status(self) -> Option<StatusCode> {
        self.status
    }
}

impl fmt::Display for StatusRetryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.status {
            Some(status) => write!(
                formatter,
                "status {} is not retryable; only 408, 425, 429, 500, 502, 503, and 504 are",
                status.as_u16()
            ),
            None => formatter.write_str("status retry requires at least one status"),
        }
    }
}

impl StdError for StatusRetryError {}

/// Request-scoped retry accounting that spans every redirect hop.
pub(crate) struct ConnectionSetupRetryState {
    policy: RetryPolicy,
    caller_retries: usize,
    performed: usize,
    reused_connection_replays: usize,
    unprocessed_replays: usize,
    status_retries: usize,
    http2_fallbacks: usize,
    request_span: Span,
}

impl ConnectionSetupRetryState {
    pub(crate) fn new(policy: RetryPolicy, request_span: Span) -> Self {
        Self {
            policy,
            caller_retries: 0,
            performed: 0,
            reused_connection_replays: 0,
            unprocessed_replays: 0,
            status_retries: 0,
            http2_fallbacks: 0,
            request_span,
        }
    }

    pub(crate) fn caller_retry_available(&self) -> bool {
        self.policy
            .maximum_retries
            .is_none_or(|maximum| self.caller_retries < maximum)
    }

    fn record_caller_retry(&mut self) {
        self.caller_retries = self.caller_retries.saturating_add(1);
    }

    /// Returns setup state for an Alt-Svc alternative: no setup retries, so a
    /// setup failure removes the alternative from its advertisement, while
    /// the pool still retires
    /// a connection that refused a request when unprocessed replay is on.
    /// Replays are counted by the request's own state, not by this one.
    pub(crate) fn for_alternative_setup(&self) -> Self {
        Self::new(
            RetryPolicy::none().with_unprocessed_replay(self.policy.unprocessed_replays),
            self.request_span.clone(),
        )
    }

    /// Returns whether unprocessed-request replay is enabled, so a pool
    /// should stop reusing a connection that refused a request.
    pub(crate) const fn replays_unprocessed_requests(&self) -> bool {
        self.policy.unprocessed_replays.is_some()
    }

    /// Returns whether the request-scoped unprocessed-replay budget has room.
    pub(crate) fn unprocessed_replay_available(&self) -> bool {
        self.caller_retry_available()
            && self
                .policy
                .unprocessed_replays
                .is_some_and(|maximum| self.unprocessed_replays < maximum.get())
    }

    /// Counts one unprocessed replay against its class and shared budgets.
    pub(crate) fn record_unprocessed_replay(&mut self, protocol: Option<HttpProtocol>) {
        self.record_caller_retry();
        self.unprocessed_replays += 1;
        self.request_span.record(
            "unprocessed_replays",
            u64::try_from(self.unprocessed_replays).unwrap_or(u64::MAX),
        );
        tracing::debug!(
            replay = self.unprocessed_replays,
            protocol = protocol.map(HttpProtocol::trace_name),
            reason = "unprocessed",
            "replaying request the peer did not process on another connection"
        );
    }

    /// Returns the delay before retrying a response with this status and
    /// fields, when the policy, listed statuses, `Retry-After` limit, and
    /// remaining request-scoped budget permit it.
    ///
    /// Consumes no budget; [`Self::record_status_retry`] does.
    pub(crate) fn status_retry_delay(
        &self,
        status: StatusCode,
        headers: &HeaderMap,
    ) -> Option<Duration> {
        let status_retry = self.policy.status_retry?;
        if !self.caller_retry_available() || self.status_retries >= status_retry.maximum.get() {
            return None;
        }
        status_retry.delay_for(status, headers)
    }

    /// Counts one status retry against its class and shared budgets.
    pub(crate) fn record_status_retry(&mut self, status: StatusCode, delay: Duration) {
        self.record_caller_retry();
        self.status_retries += 1;
        self.request_span.record(
            "status_retries",
            u64::try_from(self.status_retries).unwrap_or(u64::MAX),
        );
        tracing::debug!(
            retry = self.status_retries,
            status = status.as_u16(),
            delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
            reason = "status",
            "waiting to retry request after a retryable status"
        );
    }

    /// Returns whether an exact HTTP/3 request falls back to HTTP/2 when its
    /// connection cannot be set up.
    pub(crate) const fn falls_back_to_http2(&self) -> bool {
        self.policy.http2_fallback
    }

    /// Returns whether an earlier hop of the request fell back to HTTP/2.
    pub(crate) const fn has_fallen_back_to_http2(&self) -> bool {
        self.http2_fallbacks > 0
    }

    /// Counts one HTTP/3-to-HTTP/2 fallback against the shared budget.
    pub(crate) fn record_http2_fallback(&mut self, error: &RequestError) {
        self.record_caller_retry();
        self.http2_fallbacks += 1;
        self.request_span.record(
            "http2_fallbacks",
            u64::try_from(self.http2_fallbacks).unwrap_or(u64::MAX),
        );
        tracing::debug!(
            fallback = self.http2_fallbacks,
            error_kind = ?error.kind(),
            reason = "http3_setup_failed",
            "sending exact HTTP/3 request over HTTP/2"
        );
    }

    /// Returns connection-setup retries only; replays are counted separately.
    pub(crate) const fn performed(&self) -> usize {
        self.performed
    }

    pub(crate) const fn replays_reused_connections(&self) -> bool {
        self.policy.reused_connection_replay
    }

    /// Counts one reused-connection replay without touching the setup budget.
    pub(crate) fn record_reused_connection_replay(&mut self) {
        self.record_caller_retry();
        self.reused_connection_replays += 1;
        self.request_span.record(
            "reused_connection_replays",
            u64::try_from(self.reused_connection_replays).unwrap_or(u64::MAX),
        );
        tracing::debug!(
            replay = self.reused_connection_replays,
            reason = "reused_connection_closed",
            "replaying request on a fresh HTTP/1.1 connection"
        );
    }

    pub(crate) async fn retry_after(
        &mut self,
        error: &RequestError,
        protocol: Option<HttpProtocol>,
        timeout_budget: TimeoutBudget,
    ) -> Result<bool, RequestError> {
        let Some(maximum) = self.policy.maximum_connection_failures else {
            return Ok(false);
        };
        if !self.caller_retry_available()
            || !error.is_retryable_connection_setup()
            || self.performed >= maximum.get()
        {
            return Ok(false);
        }

        self.request_span.record("retry_reason", "connection_setup");
        tracing::debug!(
            retry = self.performed + 1,
            reason = "connection_setup",
            "waiting to retry request connection setup"
        );
        timeout_budget.delay(self.policy.delay, protocol).await?;
        self.record_caller_retry();
        self.performed += 1;
        self.request_span.record(
            "retries_performed",
            u64::try_from(self.performed).unwrap_or(u64::MAX),
        );
        Ok(true)
    }
}

pub(crate) async fn acquire_with_retries<Output, Attempt, AttemptFuture>(
    protocol: HttpProtocol,
    timeout_budget: TimeoutBudget,
    retries: &mut ConnectionSetupRetryState,
    attempt: Attempt,
) -> Result<Output, RequestError>
where
    Attempt: FnMut() -> AttemptFuture,
    AttemptFuture: Future<Output = Result<Output, RequestError>>,
{
    acquire_with_retries_for(Some(protocol), timeout_budget, retries, attempt).await
}

async fn acquire_with_retries_for<Output, Attempt, AttemptFuture>(
    protocol: Option<HttpProtocol>,
    timeout_budget: TimeoutBudget,
    retries: &mut ConnectionSetupRetryState,
    mut attempt: Attempt,
) -> Result<Output, RequestError>
where
    Attempt: FnMut() -> AttemptFuture,
    AttemptFuture: Future<Output = Result<Output, RequestError>>,
{
    loop {
        // Connector futures include bounded proxy-authentication state machines.
        // Keep that backend-specific future off this request future's stack.
        let attempt = Box::pin(attempt());
        let result = timeout_budget
            .run(TimeoutPhase::Connect, protocol, attempt)
            .await;
        match result {
            Ok(output) => return Ok(output),
            Err(error)
                if retries
                    .retry_after(&error, protocol, timeout_budget)
                    .await? => {}
            Err(error) => return Err(error),
        }
    }
}

#[cfg(test)]
mod tests;
