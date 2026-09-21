use std::{
    any::Any,
    future::{Future, poll_fn},
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use tokio::time::{Instant, Sleep};

use crate::{HttpProtocol, RequestError};

const TOKIO_TIME_DISABLED_PANIC: &str = "A Tokio 1.x context was found, but timers are disabled. Call `enable_time` on the runtime builder to enable timers.";

/// Time limits for one ordinary HTTP request operation.
///
/// Every limit is disabled by default. Phase limits restart for each redirect,
/// connection retry, or bounded internal replay. The total limit is one
/// absolute deadline shared by every attempt, retry delay, and the final
/// response body.
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

    /// Limits how long a request may wait for local pool admission.
    #[must_use]
    pub const fn pool_admission(mut self, timeout: Duration) -> Self {
        self.pool_admission = Some(timeout);
        self
    }

    /// Limits connection establishment, including DNS, proxy, TLS, and protocol setup.
    #[must_use]
    pub const fn connect(mut self, timeout: Duration) -> Self {
        self.connect = Some(timeout);
        self
    }

    /// Limits dispatch through receipt of the final response head.
    ///
    /// This phase includes sending the request body, whether owned or
    /// streamed, as well as waiting for response headers.
    #[must_use]
    pub const fn response_head(mut self, timeout: Duration) -> Self {
        self.response_head = Some(timeout);
        self
    }

    /// Limits inactivity between response-body frames.
    #[must_use]
    pub const fn read_idle(mut self, timeout: Duration) -> Self {
        self.read_idle = Some(timeout);
        self
    }

    /// Limits the complete operation across redirects, replays, and body reads.
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

/// Named request phase that exhausted its configured time budget.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TimeoutPhase {
    /// Waiting for local connection or stream admission.
    PoolAdmission,
    /// DNS, proxy, transport, TLS, or protocol connection setup.
    Connect,
    /// Request dispatch through the final response head.
    ResponseHead,
    /// Waiting for the next response-body frame after read inactivity.
    ReadIdle,
    /// The absolute whole-operation deadline.
    Total,
}

impl TimeoutPhase {
    pub(crate) const fn trace_name(self) -> &'static str {
        match self {
            Self::PoolAdmission => "pool_admission",
            Self::Connect => "connect",
            Self::ResponseHead => "response_head",
            Self::ReadIdle => "read_idle",
            Self::Total => "total",
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

    pub(crate) async fn run<Output, Operation>(
        self,
        phase: TimeoutPhase,
        protocol: Option<HttpProtocol>,
        operation: Operation,
    ) -> Result<Output, RequestError>
    where
        Operation: Future<Output = Result<Output, RequestError>>,
    {
        self.phase(phase, protocol)?.run(operation).await
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
            TimeoutPhase::ReadIdle | TimeoutPhase::Total => None,
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
    pub(crate) async fn run<Output, Operation>(
        self,
        operation: Operation,
    ) -> Result<Output, RequestError>
    where
        Operation: Future<Output = Result<Output, RequestError>>,
    {
        let Some(deadline) = self.deadline else {
            return operation.await;
        };
        let mut operation = Box::pin(operation);
        let mut timer = DeadlineTimer::new(deadline.at)?;
        poll_fn(|context| {
            if let Poll::Ready(result) = operation.as_mut().poll(context) {
                return Poll::Ready(result);
            }
            match timer.poll_expired(context) {
                Poll::Ready(Ok(())) => {
                    tracing::debug!(
                        timeout_phase = deadline.phase.trace_name(),
                        protocol = self.protocol.map(HttpProtocol::trace_name),
                        "request phase timed out"
                    );
                    return Poll::Ready(Err(RequestError::timeout(deadline.phase, self.protocol)));
                }
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => {}
            }
            Poll::Pending
        })
        .await
    }
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
#[cfg(feature = "sse")]
pub(crate) async fn sleep_until(deadline: Instant) -> Result<(), RequestError> {
    let mut timer = DeadlineTimer::new(deadline)?;
    poll_fn(|context| timer.poll_expired(context)).await
}

pub(crate) struct DeadlineTimer {
    sleep: Pin<Box<Sleep>>,
}

impl DeadlineTimer {
    pub(crate) fn new(deadline: Instant) -> Result<Self, RequestError> {
        // Tokio panics when a timer is created outside any runtime, so a
        // missing runtime is reported before one is constructed. A runtime
        // without its time driver has no query API and is detected from the
        // panic Tokio raises for it.
        if tokio::runtime::Handle::try_current().is_err() {
            return Err(RequestError::runtime_timer_unavailable());
        }
        let sleep = match catch_unwind(AssertUnwindSafe(|| tokio::time::sleep_until(deadline))) {
            Ok(sleep) => sleep,
            Err(payload) if is_time_disabled_panic(payload.as_ref()) => {
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
            Err(payload) if is_time_disabled_panic(payload.as_ref()) => {
                Poll::Ready(Err(RequestError::runtime_timer_unavailable()))
            }
            Err(payload) => resume_unwind(payload),
        }
    }

    fn reset(&mut self, deadline: Instant) {
        self.sleep.as_mut().reset(deadline);
    }
}

fn is_time_disabled_panic(payload: &(dyn Any + Send)) -> bool {
    payload
        .downcast_ref::<&str>()
        .is_some_and(|message| *message == TOKIO_TIME_DISABLED_PANIC)
        || payload
            .downcast_ref::<String>()
            .is_some_and(|message| message == TOKIO_TIME_DISABLED_PANIC)
}

#[cfg(test)]
mod tests {
    use std::{future::pending, time::Duration};

    use super::{RequestTimeouts, TimeoutBudget, TimeoutPhase};

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
}
