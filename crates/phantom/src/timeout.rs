use std::{
    future::{Future, poll_fn},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::time::{Instant, Sleep};

use crate::{HttpProtocol, RequestError};

/// Set time limits for one HTTP request.
///
/// Every limit is disabled by default. Each phase limit restarts for a
/// redirect, connection retry or internal replay. The total deadline covers
/// all attempts, retry delays and the final response body. An expired limit
/// returns
/// [`RequestErrorKind::Timeout`](crate::RequestErrorKind::Timeout) and names
/// its [`TimeoutPhase`]. A duration outside the runtime clock's range makes
/// [`ClientBuilder::build`](crate::ClientBuilder::build) return
/// [`BuildErrorKind::InvalidPolicy`](crate::BuildErrorKind::InvalidPolicy).
/// A per-request limit outside that range returns
/// [`RequestErrorKind::InvalidTimeout`](crate::RequestErrorKind::InvalidTimeout).
/// Enable the Tokio runtime's timers when you set a limit. Without them,
/// the request returns
/// [`RequestErrorKind::RuntimeUnavailable`](crate::RequestErrorKind::RuntimeUnavailable).
///
/// # Examples
///
/// ```
/// use std::time::Duration;
///
/// use phantom::RequestTimeouts;
///
/// let timeouts = RequestTimeouts::new()
///     .connect(Duration::from_secs(10))
///     .total(Duration::from_secs(60));
/// assert_eq!(timeouts.connect_duration(), Some(Duration::from_secs(10)));
/// assert_eq!(timeouts.read_idle_duration(), None);
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequestTimeouts {
    pool_admission: Option<Duration>,
    connect: Option<Duration>,
    response_head: Option<Duration>,
    read_idle: Option<Duration>,
    total: Option<Duration>,
}

impl RequestTimeouts {
    /// Creates a policy with every timeout disabled.
    ///
    /// This equals [`RequestTimeouts::default`].
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pool_admission: None,
            connect: None,
            response_head: None,
            read_idle: None,
            total: None,
        }
    }

    /// Limits how long a request waits for space in a connection or stream pool.
    ///
    /// Default: no limit.
    #[must_use]
    pub const fn pool_admission(mut self, timeout: Duration) -> Self {
        self.pool_admission = Some(timeout);
        self
    }

    /// Limits connection setup, including DNS, proxy negotiation and TLS.
    /// Protocol setup counts toward the same limit.
    ///
    /// A TCP connection that offers TLS early data
    /// ([`TlsSettings::tcp_early_data`](crate::profile::TlsSettings::tcp_early_data))
    /// is ready after sending its ClientHello. The server's answer completes
    /// the handshake later. A request sent as early data waits for that
    /// answer within its [`response_head`](Self::response_head) limit.
    ///
    /// A negotiated request that cannot safely be replayed waits for the
    /// answer before sending. That wait shares the connect limit of the
    /// attempt that opened the connection or waited for another request to
    /// open it. Pool admission and earlier attempts do not use that limit.
    /// A reused connection starts a new connect limit for the wait.
    /// A connection received from an Alt-Svc race does the same.
    /// Exact HTTP/1.1 and HTTP/2 requests wait within their response-head limit.
    ///
    /// Default: no limit.
    #[must_use]
    pub const fn connect(mut self, timeout: Duration) -> Self {
        self.connect = Some(timeout);
        self
    }

    /// Limits sending the request and waiting for the final response headers.
    ///
    /// This phase includes sending the request body, whether owned or
    /// streamed, as well as waiting for response headers. Default: no limit.
    #[must_use]
    pub const fn response_head(mut self, timeout: Duration) -> Self {
        self.response_head = Some(timeout);
        self
    }

    /// Limits inactivity between response-body frames.
    ///
    /// The timer restarts after each response-body frame. Default: no limit.
    #[must_use]
    pub const fn read_idle(mut self, timeout: Duration) -> Self {
        self.read_idle = Some(timeout);
        self
    }

    /// Limits the complete operation across redirects, replays, and body reads.
    ///
    /// The deadline is fixed when the request starts and still applies while
    /// the response body is read. Default: no limit.
    #[must_use]
    pub const fn total(mut self, timeout: Duration) -> Self {
        self.total = Some(timeout);
        self
    }

    /// Returns the pool-admission limit.
    #[must_use]
    pub const fn pool_admission_duration(self) -> Option<Duration> {
        self.pool_admission
    }

    /// Returns the connection-establishment limit.
    #[must_use]
    pub const fn connect_duration(self) -> Option<Duration> {
        self.connect
    }

    /// Returns the response-head limit.
    #[must_use]
    pub const fn response_head_duration(self) -> Option<Duration> {
        self.response_head
    }

    /// Returns the response-body inactivity limit.
    #[must_use]
    pub const fn read_idle_duration(self) -> Option<Duration> {
        self.read_idle
    }

    /// Returns the whole-operation limit.
    #[must_use]
    pub const fn total_duration(self) -> Option<Duration> {
        self.total
    }

    pub(crate) fn validate(self) -> bool {
        let now = std::time::Instant::now();
        [
            self.pool_admission,
            self.connect,
            self.response_head,
            self.read_idle,
            self.total,
        ]
        .into_iter()
        .flatten()
        .all(|duration| now.checked_add(duration).is_some())
    }
}

/// Choose whether one request inherits, disables, or replaces a client limit.
///
/// A zero duration is a finite limit. It does not disable the timer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum TimeoutOverride {
    /// Uses the corresponding client limit.
    #[default]
    Inherit,
    /// Disables the corresponding limit for this request.
    Disabled,
    /// Replaces the corresponding limit with this duration.
    Limit(Duration),
}

impl TimeoutOverride {
    const fn resolve(self, inherited: Option<Duration>) -> Option<Duration> {
        match self {
            Self::Inherit => inherited,
            Self::Disabled => None,
            Self::Limit(duration) => Some(duration),
        }
    }
}

/// Override individual client time limits for one request.
///
/// Each field inherits its client limit by default. Use [`Self::disabled`]
/// to disable every limit, or set individual fields to [`TimeoutOverride::Disabled`].
/// The resolved total deadline still covers every redirect, retry and body read.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use phantom::{RequestTimeoutOverrides, RequestTimeouts, TimeoutOverride};
///
/// let defaults = RequestTimeouts::new().connect(Duration::from_secs(10));
/// let overrides = RequestTimeoutOverrides::new()
///     .total(TimeoutOverride::Limit(Duration::from_secs(60)));
/// assert_eq!(overrides.resolve(defaults).connect_duration(), Some(Duration::from_secs(10)));
/// ```
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RequestTimeoutOverrides {
    pool_admission: TimeoutOverride,
    connect: TimeoutOverride,
    response_head: TimeoutOverride,
    read_idle: TimeoutOverride,
    total: TimeoutOverride,
}

impl RequestTimeoutOverrides {
    /// Inherits every client limit.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            pool_admission: TimeoutOverride::Inherit,
            connect: TimeoutOverride::Inherit,
            response_head: TimeoutOverride::Inherit,
            read_idle: TimeoutOverride::Inherit,
            total: TimeoutOverride::Inherit,
        }
    }

    /// Disables every limit for this request.
    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            pool_admission: TimeoutOverride::Disabled,
            connect: TimeoutOverride::Disabled,
            response_head: TimeoutOverride::Disabled,
            read_idle: TimeoutOverride::Disabled,
            total: TimeoutOverride::Disabled,
        }
    }

    /// Sets the pool-admission override.
    #[must_use]
    pub const fn pool_admission(mut self, timeout: TimeoutOverride) -> Self {
        self.pool_admission = timeout;
        self
    }

    /// Returns the pool-admission override.
    #[must_use]
    pub const fn pool_admission_override(self) -> TimeoutOverride {
        self.pool_admission
    }

    /// Sets the connection setup override.
    #[must_use]
    pub const fn connect(mut self, timeout: TimeoutOverride) -> Self {
        self.connect = timeout;
        self
    }

    /// Returns the connection setup override.
    #[must_use]
    pub const fn connect_override(self) -> TimeoutOverride {
        self.connect
    }

    /// Sets the response-head override.
    #[must_use]
    pub const fn response_head(mut self, timeout: TimeoutOverride) -> Self {
        self.response_head = timeout;
        self
    }

    /// Returns the response-head override.
    #[must_use]
    pub const fn response_head_override(self) -> TimeoutOverride {
        self.response_head
    }

    /// Sets the body read-idle override.
    #[must_use]
    pub const fn read_idle(mut self, timeout: TimeoutOverride) -> Self {
        self.read_idle = timeout;
        self
    }

    /// Returns the body read-idle override.
    #[must_use]
    pub const fn read_idle_override(self) -> TimeoutOverride {
        self.read_idle
    }

    /// Sets the total operation override.
    #[must_use]
    pub const fn total(mut self, timeout: TimeoutOverride) -> Self {
        self.total = timeout;
        self
    }

    /// Returns the total operation override.
    #[must_use]
    pub const fn total_override(self) -> TimeoutOverride {
        self.total
    }

    /// Resolves each field against its corresponding client limit.
    #[must_use]
    pub const fn resolve(self, defaults: RequestTimeouts) -> RequestTimeouts {
        RequestTimeouts {
            pool_admission: self.pool_admission.resolve(defaults.pool_admission),
            connect: self.connect.resolve(defaults.connect),
            response_head: self.response_head.resolve(defaults.response_head),
            read_idle: self.read_idle.resolve(defaults.read_idle),
            total: self.total.resolve(defaults.total),
        }
    }
}

/// The request phase that reached its time limit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TimeoutPhase {
    /// Waiting for space in a connection or stream pool.
    PoolAdmission,
    /// DNS, proxy, transport, TLS, or protocol connection setup.
    Connect,
    /// Sending the request and waiting for the final response headers.
    ResponseHead,
    /// Waiting for the next response-body frame after read inactivity.
    ReadIdle,
    /// The absolute whole-operation deadline.
    Total,
    /// A WebSocket opening handshake, from the start of the connect until
    /// the accepting response is validated.
    ///
    /// This deadline covers name resolution, proxy setup, TLS, the opening
    /// request and its response. Chromium's handshake timer covers the same
    /// steps. Firefox starts its timer after resolving the host.
    /// `WebSocketRequestBuilder::handshake_timeout` sets it, with the
    /// `websocket` feature.
    WebSocketHandshake,
}

impl TimeoutPhase {
    pub(crate) const fn trace_name(self) -> &'static str {
        match self {
            Self::PoolAdmission => "pool_admission",
            Self::Connect => "connect",
            Self::ResponseHead => "response_head",
            Self::ReadIdle => "read_idle",
            Self::Total => "total",
            Self::WebSocketHandshake => "websocket_handshake",
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct TimeoutBudget {
    policy: RequestTimeouts,
    total_deadline: Option<Instant>,
}

impl TimeoutBudget {
    pub(crate) fn new(policy: RequestTimeouts) -> Result<Self, RequestError> {
        if !policy.validate() {
            return Err(RequestError::invalid_timeout());
        }
        let total_deadline = policy
            .total
            .map(|duration| {
                Instant::now()
                    .checked_add(duration)
                    .ok_or_else(RequestError::invalid_timeout)
            })
            .transpose()?;
        Ok(Self {
            policy,
            total_deadline,
        })
    }

    /// Runs `operation` within `phase`'s deadline and the total deadline.
    ///
    /// The phase deadline starts when this is called, not when the returned
    /// future is first polled.
    pub(crate) fn run<Output, Operation>(
        self,
        phase: TimeoutPhase,
        protocol: Option<HttpProtocol>,
        operation: Operation,
    ) -> impl Future<Output = Result<Output, RequestError>>
    where
        Operation: Future<Output = Result<Output, RequestError>>,
    {
        run_until(self.deadline(phase), protocol, operation)
    }

    pub(crate) fn phase(
        self,
        phase: TimeoutPhase,
        protocol: Option<HttpProtocol>,
    ) -> Result<PhaseTimeout, RequestError> {
        Ok(PhaseTimeout {
            deadline: self.deadline(phase)?,
            protocol,
        })
    }

    pub(crate) fn response_body(
        self,
        protocol: HttpProtocol,
    ) -> Result<Option<ResponseTimeouts>, RequestError> {
        if self.policy.read_idle.is_none() && self.total_deadline.is_none() {
            return Ok(None);
        }
        ResponseTimeouts::new(self.policy.read_idle, self.total_deadline, protocol).map(Some)
    }

    /// Returns the longest wait for one response-body frame, if any.
    pub(crate) const fn read_idle(self) -> Option<Duration> {
        self.policy.read_idle
    }

    /// Returns the time left before the total deadline, or `None` when the
    /// operation has no total limit. An expired deadline returns zero.
    pub(crate) fn remaining_total(self) -> Option<Duration> {
        self.total_deadline
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    pub(crate) async fn delay(
        self,
        duration: Duration,
        protocol: Option<HttpProtocol>,
    ) -> Result<(), RequestError> {
        let now = Instant::now();
        if self.total_deadline.is_some_and(|deadline| deadline <= now) {
            return Err(RequestError::timeout(TimeoutPhase::Total, protocol));
        }
        if duration.is_zero() {
            return Ok(());
        }
        let delay_deadline = now
            .checked_add(duration)
            .ok_or_else(RequestError::invalid_timeout)?;
        let (deadline, total_expires_first) = match self.total_deadline {
            Some(total_deadline) if total_deadline <= delay_deadline => (total_deadline, true),
            Some(_) | None => (delay_deadline, false),
        };
        let mut timer = DeadlineTimer::new(deadline)?;
        poll_fn(|context| timer.poll_expired(context)).await?;
        if total_expires_first {
            return Err(RequestError::timeout(TimeoutPhase::Total, protocol));
        }
        Ok(())
    }

    fn deadline(self, phase: TimeoutPhase) -> Result<Option<Deadline>, RequestError> {
        let duration = match phase {
            TimeoutPhase::PoolAdmission => self.policy.pool_admission,
            TimeoutPhase::Connect => self.policy.connect,
            TimeoutPhase::ResponseHead => self.policy.response_head,
            TimeoutPhase::ReadIdle | TimeoutPhase::Total | TimeoutPhase::WebSocketHandshake => None,
        };
        let phase_deadline = duration
            .map(|duration| {
                Instant::now()
                    .checked_add(duration)
                    .ok_or_else(RequestError::invalid_timeout)
            })
            .transpose()?;
        Ok(match (phase_deadline, self.total_deadline) {
            (None, None) => None,
            (Some(at), None) => Some(Deadline { at, phase }),
            (None, Some(at)) => Some(Deadline {
                at,
                phase: TimeoutPhase::Total,
            }),
            (Some(phase_at), Some(total_at)) if total_at <= phase_at => Some(Deadline {
                at: total_at,
                phase: TimeoutPhase::Total,
            }),
            (Some(at), Some(_)) => Some(Deadline { at, phase }),
        })
    }
}

#[derive(Clone, Copy)]
pub(crate) struct PhaseTimeout {
    deadline: Option<Deadline>,
    protocol: Option<HttpProtocol>,
}

impl PhaseTimeout {
    pub(crate) fn run<Output, Operation>(
        self,
        operation: Operation,
    ) -> impl Future<Output = Result<Output, RequestError>>
    where
        Operation: Future<Output = Result<Output, RequestError>>,
    {
        run_until(Ok(self.deadline), self.protocol, operation)
    }
}

/// Runs `operation` until `deadline`, when there is one.
///
/// The `run` methods return this future instead of awaiting it: an async
/// function holds a future it takes and awaits twice, as the argument and as
/// the awaited value, so each async layer between a request and its
/// operation would add another copy of the operation to the request's
/// future.
async fn run_until<Output, Operation>(
    deadline: Result<Option<Deadline>, RequestError>,
    protocol: Option<HttpProtocol>,
    operation: Operation,
) -> Result<Output, RequestError>
where
    Operation: Future<Output = Result<Output, RequestError>>,
{
    let Some(deadline) = deadline? else {
        return operation.await;
    };
    let mut timer = DeadlineTimer::new(deadline.at)?;
    let mut operation = std::pin::pin!(operation);
    poll_fn(|context| {
        if let Poll::Ready(result) = operation.as_mut().poll(context) {
            return Poll::Ready(result);
        }
        match timer.poll_expired(context) {
            Poll::Ready(Ok(())) => {
                tracing::debug!(
                    timeout_phase = deadline.phase.trace_name(),
                    protocol = protocol.map(HttpProtocol::trace_name),
                    "request phase timed out"
                );
                Poll::Ready(Err(RequestError::timeout(deadline.phase, protocol)))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    })
    .await
}

#[derive(Clone, Copy)]
struct Deadline {
    at: Instant,
    phase: TimeoutPhase,
}

pub(crate) struct ResponseTimeouts {
    idle_duration: Option<Duration>,
    idle: Option<DeadlineTimer>,
    total: Option<DeadlineTimer>,
    protocol: HttpProtocol,
}

impl ResponseTimeouts {
    fn new(
        idle_duration: Option<Duration>,
        total_deadline: Option<Instant>,
        protocol: HttpProtocol,
    ) -> Result<Self, RequestError> {
        let idle = idle_duration
            .map(|duration| {
                let deadline = Instant::now()
                    .checked_add(duration)
                    .ok_or_else(RequestError::invalid_timeout)?;
                DeadlineTimer::new(deadline)
            })
            .transpose()?;
        let total = total_deadline.map(DeadlineTimer::new).transpose()?;
        Ok(Self {
            idle_duration,
            idle,
            total,
            protocol,
        })
    }

    pub(crate) fn poll_expired(&mut self, context: &mut Context<'_>) -> Poll<RequestError> {
        if let Poll::Ready(error) = self.poll_total_expired(context) {
            return Poll::Ready(error);
        }
        if let Some(timer) = self.idle.as_mut() {
            match timer.poll_expired(context) {
                Poll::Ready(Ok(())) => {
                    return Poll::Ready(RequestError::timeout(
                        TimeoutPhase::ReadIdle,
                        Some(self.protocol),
                    ));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(error),
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }

    pub(crate) fn poll_total_expired(&mut self, context: &mut Context<'_>) -> Poll<RequestError> {
        if let Some(timer) = self.total.as_mut() {
            match timer.poll_expired(context) {
                Poll::Ready(Ok(())) => {
                    return Poll::Ready(RequestError::timeout(
                        TimeoutPhase::Total,
                        Some(self.protocol),
                    ));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(error),
                Poll::Pending => {}
            }
        }
        Poll::Pending
    }

    pub(crate) fn record_activity(&mut self) -> Result<(), RequestError> {
        let Some(duration) = self.idle_duration else {
            return Ok(());
        };
        let deadline = Instant::now()
            .checked_add(duration)
            .ok_or_else(RequestError::invalid_timeout)?;
        if let Some(timer) = self.idle.as_mut() {
            timer.reset(deadline);
        }
        Ok(())
    }
}

/// Waits until `deadline`, or fails when the current runtime cannot time it.
#[cfg(any(feature = "sse", feature = "websocket"))]
pub(crate) async fn sleep_until(deadline: Instant) -> Result<(), RequestError> {
    let mut timer = DeadlineTimer::new(deadline)?;
    poll_fn(|context| timer.poll_expired(context)).await
}

/// Runs `future` for at most `limit`: `Ok(None)` when the limit passes first.
///
/// Unlike `tokio::time::timeout`, a runtime without its time driver is an
/// error instead of a panic. The future is polled before the timer, so one
/// that is ready at the limit still wins.
pub(crate) async fn within<F: Future>(
    limit: Duration,
    future: F,
) -> Result<Option<F::Output>, RequestError> {
    let deadline = Instant::now()
        .checked_add(limit)
        .ok_or_else(RequestError::invalid_timeout)?;
    let mut timer = DeadlineTimer::new(deadline)?;
    let mut future = std::pin::pin!(future);
    poll_fn(|context| {
        if let Poll::Ready(output) = future.as_mut().poll(context) {
            return Poll::Ready(Ok(Some(output)));
        }
        timer
            .poll_expired(context)
            .map(|expired| expired.map(|()| None))
    })
    .await
}

pub(crate) struct DeadlineTimer {
    sleep: Pin<Box<Sleep>>,
}

impl DeadlineTimer {
    pub(crate) fn new(deadline: Instant) -> Result<Self, RequestError> {
        // Tokio panics when a timer is created outside any runtime, so a
        // missing runtime is reported before one is constructed. A runtime
        // without its time driver has no query API and is detected after
        // the panic Tokio raises for it.
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(RequestError::runtime_timer_unavailable());
        }
        let sleep = match catch_unwind(AssertUnwindSafe(|| tokio::time::sleep_until(deadline))) {
            Ok(sleep) => sleep,
            Err(_) if time_driver_missing() => {
                return Err(RequestError::runtime_timer_unavailable());
            }
            Err(payload) => resume_unwind(payload),
        };
        Ok(Self {
            sleep: Box::pin(sleep),
        })
    }

    pub(crate) fn poll_expired(
        &mut self,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), RequestError>> {
        match catch_unwind(AssertUnwindSafe(|| self.sleep.as_mut().poll(context))) {
            Ok(Poll::Ready(())) => Poll::Ready(Ok(())),
            Ok(Poll::Pending) => Poll::Pending,
            Err(_) if time_driver_missing() => {
                Poll::Ready(Err(RequestError::runtime_timer_unavailable()))
            }
            Err(payload) => resume_unwind(payload),
        }
    }

    fn reset(&mut self, deadline: Instant) {
        self.sleep.as_mut().reset(deadline);
    }
}

/// Whether the current context has no runtime with a time driver.
///
/// Called after a timer operation panicked. Tokio has no query for its time
/// driver, and creating a timer without one panics, so creating a probe timer
/// that panics as well attributes the first panic to the missing driver
/// without relying on the wording of Tokio's panic message. A panic the probe
/// does not repeat belongs to someone else and keeps unwinding.
fn time_driver_missing() -> bool {
    tokio::runtime::Handle::try_current().is_err()
        || catch_unwind(|| drop(tokio::time::sleep_until(Instant::now()))).is_err()
}

#[cfg(test)]
mod tests {
    use std::{future::pending, time::Duration};

    use super::{
        RequestTimeoutOverrides, RequestTimeouts, TimeoutBudget, TimeoutOverride, TimeoutPhase,
    };
    use crate::RequestErrorKind;

    #[test]
    fn each_override_resolves_without_changing_other_phases() {
        let duration = Duration::from_secs(7);
        let defaults = RequestTimeouts::new()
            .pool_admission(duration)
            .connect(duration)
            .response_head(duration)
            .read_idle(duration)
            .total(duration);
        let setters: [fn(RequestTimeoutOverrides, TimeoutOverride) -> RequestTimeoutOverrides; 5] = [
            RequestTimeoutOverrides::pool_admission,
            RequestTimeoutOverrides::connect,
            RequestTimeoutOverrides::response_head,
            RequestTimeoutOverrides::read_idle,
            RequestTimeoutOverrides::total,
        ];
        let getters: [fn(RequestTimeouts) -> Option<Duration>; 5] = [
            RequestTimeouts::pool_admission_duration,
            RequestTimeouts::connect_duration,
            RequestTimeouts::response_head_duration,
            RequestTimeouts::read_idle_duration,
            RequestTimeouts::total_duration,
        ];
        for (index, setter) in setters.into_iter().enumerate() {
            for (value, expected) in [
                (TimeoutOverride::Inherit, Some(duration)),
                (TimeoutOverride::Disabled, None),
                (
                    TimeoutOverride::Limit(Duration::from_secs(2)),
                    Some(Duration::from_secs(2)),
                ),
                (TimeoutOverride::Limit(Duration::ZERO), Some(Duration::ZERO)),
            ] {
                let resolved = setter(RequestTimeoutOverrides::new(), value).resolve(defaults);
                for (phase, getter) in getters.into_iter().enumerate() {
                    assert_eq!(
                        getter(resolved),
                        if phase == index {
                            expected
                        } else {
                            Some(duration)
                        }
                    );
                }
            }
        }
        assert_eq!(
            RequestTimeoutOverrides::default().resolve(defaults),
            defaults
        );
        assert_eq!(
            RequestTimeoutOverrides::disabled().resolve(defaults),
            RequestTimeouts::new()
        );
        assert_eq!(
            RequestTimeoutOverrides::new().resolve(RequestTimeouts::new()),
            RequestTimeouts::new()
        );
    }

    #[test]
    fn missing_time_driver_is_detected_without_reading_a_panic_message()
    -> Result<(), Box<dyn std::error::Error>> {
        assert!(super::time_driver_missing());
        let without_time = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;
        assert!(without_time.block_on(async { super::time_driver_missing() }));
        let with_time = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()?;
        assert!(!with_time.block_on(async { super::time_driver_missing() }));
        Ok(())
    }

    #[test]
    fn limit_on_a_runtime_without_a_time_driver_is_runtime_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()?;

        let result = runtime.block_on(super::within(Duration::from_secs(1), pending::<()>()));

        let error = result
            .err()
            .ok_or("a limit without a time driver did not fail")?;
        assert_eq!(error.kind(), RequestErrorKind::RuntimeUnavailable);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn within_returns_none_once_the_limit_passes() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            super::within(Duration::from_secs(1), async { 7 }).await?,
            Some(7)
        );
        assert_eq!(
            super::within(Duration::from_secs(1), pending::<()>()).await?,
            None
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn ready_operation_wins_when_deadline_is_also_ready()
    -> Result<(), Box<dyn std::error::Error>> {
        let budget = TimeoutBudget::new(RequestTimeouts::new().total(Duration::ZERO))?;

        let value = budget
            .run(TimeoutPhase::ResponseHead, None, async { Ok(7_u8) })
            .await?;

        assert_eq!(value, 7);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn remaining_total_counts_down_to_zero() -> Result<(), Box<dyn std::error::Error>> {
        let unlimited = TimeoutBudget::new(RequestTimeouts::new())?;
        assert_eq!(unlimited.remaining_total(), None);
        let budget = TimeoutBudget::new(RequestTimeouts::new().total(Duration::from_secs(5)))?;
        assert_eq!(budget.remaining_total(), Some(Duration::from_secs(5)));

        tokio::time::advance(Duration::from_secs(2)).await;
        assert_eq!(budget.remaining_total(), Some(Duration::from_secs(3)));
        tokio::time::advance(Duration::from_secs(4)).await;
        assert_eq!(budget.remaining_total(), Some(Duration::ZERO));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn total_deadline_wins_a_phase_deadline_tie() -> Result<(), Box<dyn std::error::Error>> {
        let budget = TimeoutBudget::new(
            RequestTimeouts::new()
                .response_head(Duration::ZERO)
                .total(Duration::ZERO),
        )?;

        let result = budget
            .run(TimeoutPhase::ResponseHead, None, async {
                pending::<()>().await;
                Ok(())
            })
            .await;
        let error = result.err().ok_or("pending operation did not time out")?;

        assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn phase_deadline_before_the_total_names_the_phase_and_starts_at_the_call()
    -> Result<(), Box<dyn std::error::Error>> {
        let budget = TimeoutBudget::new(
            RequestTimeouts::new()
                .connect(Duration::from_secs(1))
                .total(Duration::from_secs(10)),
        )?;
        let started = tokio::time::Instant::now();

        let operation = budget.run(TimeoutPhase::Connect, None, async {
            pending::<()>().await;
            Ok(())
        });
        tokio::time::advance(Duration::from_millis(400)).await;
        let error = operation
            .await
            .err()
            .ok_or("pending operation did not time out")?;

        assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Connect));
        assert_eq!(started.elapsed(), Duration::from_secs(1));
        Ok(())
    }
}
