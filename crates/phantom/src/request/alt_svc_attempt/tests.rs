use std::{
    future::{Future, pending},
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::Duration,
};

use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore},
    time::{Instant, sleep, sleep_until},
};

use super::{Candidate, RaceOutcome, race_setup};
use crate::{
    HttpProtocol, RequestError, RequestErrorKind, RequestTimeouts, TimeoutPhase,
    timeout::TimeoutBudget,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const ORIGIN_DELAY: Duration = Duration::from_millis(300);

/// Records when a candidate starts, and sets `dropped` when it is cancelled.
struct Probe {
    started: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}

impl Probe {
    fn new() -> Self {
        Self {
            started: Arc::new(AtomicUsize::new(0)),
            dropped: Arc::new(AtomicBool::new(false)),
        }
    }

    fn guard(&self) -> DropFlag {
        self.started.fetch_add(1, Ordering::SeqCst);
        DropFlag(Arc::clone(&self.dropped))
    }

    fn starts(&self) -> usize {
        self.started.load(Ordering::SeqCst)
    }

    fn was_dropped(&self) -> bool {
        self.dropped.load(Ordering::SeqCst)
    }
}

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

fn budget(timeouts: RequestTimeouts) -> TestResult<TimeoutBudget> {
    Ok(TimeoutBudget::new(timeouts)?)
}

/// A setup that holds one permit from `admission` and then waits forever,
/// like a QUIC handshake to a blackholed alternative.
async fn blackholed(
    probe: DropFlag,
    admission: Arc<Semaphore>,
) -> Result<OwnedSemaphorePermit, RequestError> {
    let permit = admission
        .acquire_owned()
        .await
        .map_err(|_| RequestError::capacity(HttpProtocol::Http3))?;
    let _probe = probe;
    let _permit = permit;
    pending().await
}

fn poll_once<F: Future + Unpin>(future: &mut F) -> Poll<F::Output> {
    Pin::new(future).poll(&mut Context::from_waker(Waker::noop()))
}

#[tokio::test(start_paused = true)]
async fn origin_starts_after_configured_delay_and_returns_unfinished_alternative() -> TestResult {
    // The origin starts exactly at the configured delay and wins; the
    // unfinished alternative is handed back so its later failure can mark it
    // broken, which `tests/alt_svc_race.rs` proves through the public client.
    let alternative = Probe::new();
    let origin_started_at = Arc::new(std::sync::Mutex::new(None));
    let started = Instant::now();
    let admission = Arc::new(Semaphore::new(1));
    let outcome = race_setup(
        Box::pin(blackholed(alternative.guard(), Arc::clone(&admission))),
        || {
            let origin_started_at = Arc::clone(&origin_started_at);
            async move {
                if let Ok(mut slot) = origin_started_at.lock() {
                    *slot = Some(Instant::now());
                }
                sleep(Duration::from_millis(5)).await;
                Ok::<_, RequestError>("origin")
            }
        },
        ORIGIN_DELAY,
        budget(RequestTimeouts::new())?,
    )
    .await?;

    let origin_started_at = origin_started_at
        .lock()
        .map_err(|_| "poisoned")?
        .ok_or("origin never started")?;
    assert_eq!(origin_started_at - started, ORIGIN_DELAY);
    match outcome {
        RaceOutcome::Origin {
            leased,
            loser: Candidate::Pending(setup),
        } => {
            assert_eq!(leased, "origin");
            assert!(!alternative.was_dropped());
            assert_eq!(admission.available_permits(), 0);
            drop(setup);
            assert!(alternative.was_dropped());
            assert_eq!(admission.available_permits(), 1);
        }
        _ => return Err("the origin must win against a blackholed alternative".into()),
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn alternative_failure_starts_origin_at_once_and_is_reported() -> TestResult {
    let started = Instant::now();
    let origin_started_at = Arc::new(std::sync::Mutex::new(None));
    let outcome = race_setup(
        Box::pin(async {
            sleep(Duration::from_millis(20)).await;
            Err::<(), _>(RequestError::timeout(
                TimeoutPhase::Connect,
                Some(HttpProtocol::Http3),
            ))
        }),
        || {
            let origin_started_at = Arc::clone(&origin_started_at);
            async move {
                if let Ok(mut slot) = origin_started_at.lock() {
                    *slot = Some(Instant::now());
                }
                Ok::<_, RequestError>(())
            }
        },
        ORIGIN_DELAY,
        budget(RequestTimeouts::new())?,
    )
    .await?;

    let origin_started_at = origin_started_at
        .lock()
        .map_err(|_| "poisoned")?
        .ok_or("origin never started")?;
    assert_eq!(origin_started_at - started, Duration::from_millis(20));
    match outcome {
        RaceOutcome::Origin {
            loser: Candidate::Failed(error),
            ..
        } => assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Connect)),
        _ => return Err("the failed alternative must be reported".into()),
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn alternative_that_finishes_first_wins_and_cancels_origin() -> TestResult {
    let origin = Probe::new();
    let outcome = race_setup(
        Box::pin(async {
            sleep(ORIGIN_DELAY + Duration::from_millis(10)).await;
            Ok::<_, RequestError>("alternative")
        }),
        || {
            let guard = origin.guard();
            async move {
                let _guard = guard;
                pending::<Result<&str, RequestError>>().await
            }
        },
        ORIGIN_DELAY,
        budget(RequestTimeouts::new())?,
    )
    .await?;

    assert!(matches!(outcome, RaceOutcome::Alternative("alternative")));
    assert_eq!(origin.starts(), 1);
    assert!(origin.was_dropped());
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn origin_failure_waits_for_the_alternative() -> TestResult {
    let outcome = race_setup(
        Box::pin(async {
            sleep(Duration::from_secs(1)).await;
            Ok::<_, RequestError>("alternative")
        }),
        || async { Err::<&str, _>(RequestError::capacity(HttpProtocol::Http2)) },
        Duration::ZERO,
        budget(RequestTimeouts::new())?,
    )
    .await?;

    assert!(matches!(outcome, RaceOutcome::Alternative("alternative")));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn both_failures_return_the_origin_error() -> TestResult {
    let result = race_setup(
        Box::pin(async { Err::<(), _>(RequestError::capacity(HttpProtocol::Http3)) }),
        || async { Err::<(), _>(RequestError::unselected_capacity()) },
        ORIGIN_DELAY,
        budget(RequestTimeouts::new())?,
    )
    .await;

    let Err(error) = result else {
        return Err("both candidates failed".into());
    };
    assert_eq!(error.kind(), RequestErrorKind::Capacity);
    assert_eq!(error.protocol(), None);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn race_observes_total_and_connect_deadlines() -> TestResult {
    // Each candidate runs its setup under the connect phase, as the pools do.
    let timeouts = RequestTimeouts::new().connect(Duration::from_secs(1));
    let connect_budget = budget(timeouts)?;
    let started = Instant::now();
    let result = race_setup(
        Box::pin(connect_budget.run(
            TimeoutPhase::Connect,
            Some(HttpProtocol::Http3),
            pending::<Result<(), RequestError>>(),
        )),
        || {
            connect_budget.run(
                TimeoutPhase::Connect,
                None,
                pending::<Result<(), RequestError>>(),
            )
        },
        Duration::from_secs(10),
        connect_budget,
    )
    .await;
    let Err(error) = result else {
        return Err("both connect deadlines expire".into());
    };
    // The alternative's deadline starts the origin at once; the origin then
    // has its own full connect phase.
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Connect));
    assert_eq!(error.protocol(), None);
    assert_eq!(Instant::now() - started, Duration::from_secs(2));

    // A total deadline ends the race even while the origin delay is pending.
    let total_budget = budget(RequestTimeouts::new().total(Duration::from_millis(250)))?;
    let started = Instant::now();
    let result = race_setup(
        Box::pin(pending::<Result<(), RequestError>>()),
        || async { Ok::<_, RequestError>(()) },
        Duration::from_secs(10),
        total_budget,
    )
    .await;
    let Err(error) = result else {
        return Err("the total deadline expires before the origin starts".into());
    };
    assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Total));
    assert_eq!(Instant::now() - started, Duration::from_millis(250));
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn race_holds_at_most_two_setup_permits() -> TestResult {
    // One admission per candidate pool, as in the H3 and negotiated pools.
    let http3 = Arc::new(Semaphore::new(4));
    let negotiated = Arc::new(Semaphore::new(4));
    let alternative = Probe::new();
    let origin = Probe::new();
    let mut race = Box::pin(race_setup(
        Box::pin(blackholed(alternative.guard(), Arc::clone(&http3))),
        || {
            let guard = origin.guard();
            let negotiated = Arc::clone(&negotiated);
            async move {
                let _guard = guard;
                let _permit = negotiated
                    .acquire_owned()
                    .await
                    .map_err(|_| RequestError::unselected_capacity())?;
                pending::<Result<(), RequestError>>().await
            }
        },
        ORIGIN_DELAY,
        budget(RequestTimeouts::new())?,
    ));

    assert!(poll_once(&mut race).is_pending());
    assert_eq!((alternative.starts(), origin.starts()), (1, 0));
    assert_eq!(
        http3.available_permits() + negotiated.available_permits(),
        7
    );
    sleep_until(Instant::now() + ORIGIN_DELAY).await;
    assert!(poll_once(&mut race).is_pending());
    sleep(Duration::from_secs(1)).await;
    assert!(poll_once(&mut race).is_pending());
    assert_eq!((alternative.starts(), origin.starts()), (1, 1));
    assert_eq!(http3.available_permits(), 3);
    assert_eq!(negotiated.available_permits(), 3);
    drop(race);
    assert_eq!(http3.available_permits(), 4);
    assert_eq!(negotiated.available_permits(), 4);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn cancelling_raced_request_cancels_both_attempts() -> TestResult {
    let alternative = Probe::new();
    let origin = Probe::new();
    let admission = Arc::new(Semaphore::new(1));
    let mut race = Box::pin(race_setup(
        Box::pin(blackholed(alternative.guard(), Arc::clone(&admission))),
        || {
            let guard = origin.guard();
            async move {
                let _guard = guard;
                pending::<Result<(), RequestError>>().await
            }
        },
        ORIGIN_DELAY,
        budget(RequestTimeouts::new())?,
    ));
    assert!(poll_once(&mut race).is_pending());
    sleep(ORIGIN_DELAY).await;
    assert!(poll_once(&mut race).is_pending());
    assert_eq!((alternative.starts(), origin.starts()), (1, 1));
    assert!(!alternative.was_dropped() && !origin.was_dropped());

    drop(race);

    assert!(alternative.was_dropped());
    assert!(origin.was_dropped());
    assert_eq!(admission.available_permits(), 1);
    Ok(())
}

#[test]
fn the_retry_rule_needs_a_race_that_allowed_early_data_and_a_replayable_body() {
    use super::races_again;

    // The first race allowed early data; its retry allows none.
    assert!(races_again(true, true));
    assert!(!races_again(false, true));
    // A one-shot streaming body cannot be sent again.
    assert!(!races_again(true, false));
}

#[test]
fn the_orphan_rule_confirms_only_after_a_completed_handshake() {
    use super::confirms_orphan;

    assert!(confirms_orphan(false));
    assert!(!confirms_orphan(true));
}
