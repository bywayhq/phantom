//! Client-owned, setup-only validation of advertised HTTP/3 alternatives.

use std::{
    future::{Future, poll_fn},
    sync::{
        Arc, Mutex, MutexGuard, PoisonError, Weak,
        atomic::{AtomicBool, Ordering},
    },
    task::Poll,
    time::Instant,
};

use phantom_net::http3::Http3Connector;
use tokio::{
    runtime::{Handle, Id},
    sync::{Mutex as AsyncMutex, OwnedMutexGuard},
    task::{JoinError, JoinSet},
};
use tracing::debug;

use super::{AltSvcValidationCandidate, AltSvcValidationPublication};
use crate::{
    RequestErrorKind, RequestTimeouts, Route,
    authority::Endpoint,
    session::http3_pool::{ConnectUdpConnectors, Http3Pool, Http3TransportTarget},
    timeout::{DeadlineTimer, TimeoutBudget},
};

const MAX_VALIDATIONS: usize = 32;

/// The setup dependencies retained independently of the advertising request.
pub(crate) struct AltSvcValidationJob {
    pub(crate) pool: Arc<Http3Pool>,
    pub(crate) connector: Arc<Http3Connector>,
    pub(crate) connect_udp_proxy: Option<Arc<ConnectUdpConnectors>>,
    pub(crate) endpoint: Endpoint,
    pub(crate) route: Route,
    pub(crate) candidate: AltSvcValidationCandidate,
    pub(crate) timeouts: RequestTimeouts,
}

#[derive(Default)]
pub(crate) struct AltSvcValidationJobs {
    control: Arc<Control>,
    tasks: Arc<Mutex<TaskSets>>,
    cleanup_turn: Arc<AsyncMutex<()>>,
}

#[derive(Default)]
struct TaskSets {
    active: JoinSet<()>,
    retired: Vec<JoinSet<()>>,
}

#[derive(Default)]
struct Control {
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    closed: bool,
    epoch: Arc<()>,
    refreshes: Vec<Weak<()>>,
    pending: Vec<Reservation>,
}

struct Reservation {
    token: Arc<()>,
    runtime: Id,
    publication: AltSvcValidationPublication,
    claim: Weak<ValidationClaim>,
}

/// Shared across runtimes so one cancelled waiter cannot abandon another setup.
struct ValidationClaim {
    control: Weak<Control>,
    publication: AltSvcValidationPublication,
    completed: AtomicBool,
}

struct JobGuard {
    control: Weak<Control>,
    token: Arc<()>,
    epoch: ValidationEpoch,
    claim: Arc<ValidationClaim>,
}

/// Fences final pool publication against client close and refresh.
pub(crate) struct ValidationEpoch {
    control: Arc<Control>,
    epoch: Arc<()>,
}

/// Holds the current owner epoch only for synchronous publication.
#[must_use]
pub(crate) struct ValidationPermit<'a> {
    _state: MutexGuard<'a, State>,
}

/// Keeps enqueue blocked throughout pool refresh, including cancellation cleanup.
#[must_use = "keep this guard until pool refresh completes"]
pub(crate) struct AltSvcValidationRefresh {
    _refresh: Arc<()>,
    registry: Weak<Mutex<TaskSets>>,
    cleanup_turn: Arc<AsyncMutex<()>>,
    turn: Option<OwnedMutexGuard<()>>,
    tasks: Vec<JoinSet<()>>,
}

impl AltSvcValidationJobs {
    /// Starts at most one setup for this mapping on the current runtime.
    ///
    /// Rejected work is not queued. The owner retains at most 32 in-flight
    /// setups across runtimes, and a task never retains the owning client.
    pub(crate) fn start(&self, job: AltSvcValidationJob) -> bool {
        let Some(publication) = job.candidate.target().validation_publication().cloned() else {
            return false;
        };
        let runtime = match Handle::try_current() {
            Ok(runtime) => runtime,
            Err(_) => {
                self.control.reject(&publication);
                return false;
            }
        };
        let mut tasks = self.lock_tasks();
        let errors = tasks.reap();
        let started = if let Some(guard) = self.control.reserve(&publication, runtime.id()) {
            // Capture the guard before spawning: aborting an unpolled task
            // must release its reservation and unfinished mapping too.
            tasks.active.spawn_on(run(job, guard), &runtime);
            true
        } else {
            false
        };
        drop(tasks);
        for error in errors {
            observe_join(Err(error));
        }
        started
    }

    /// Permanently closes validation admission and requests task cancellation.
    pub(crate) fn close(&self) {
        let mut tasks = self.lock_tasks();
        let mut state = self.control.lock();
        state.closed = true;
        state.epoch = Arc::new(());
        drop(state);
        tasks.abort_all();
    }

    /// Closes admission, cancels setups, and observes their terminal outcomes.
    pub(crate) async fn shutdown(&self) {
        self.close();
        let mut refresh = AltSvcValidationRefresh {
            _refresh: Arc::new(()),
            registry: Arc::downgrade(&self.tasks),
            cleanup_turn: Arc::clone(&self.cleanup_turn),
            turn: None,
            tasks: Vec::new(),
        };
        refresh.observe_cancelled().await;
    }

    /// Blocks enqueue until the returned guard is dropped after pool refresh.
    ///
    /// Call `observe_cancelled` before refreshing the pool. If the enclosing
    /// refresh is cancelled, dropping the guard aborts retained tasks and
    /// releases the enqueue block.
    pub(crate) fn begin_refresh(&self) -> AltSvcValidationRefresh {
        let refresh = Arc::new(());
        {
            let mut tasks = self.lock_tasks();
            let mut state = self.control.lock();
            state
                .refreshes
                .retain(|refresh| refresh.strong_count() != 0);
            state.refreshes.push(Arc::downgrade(&refresh));
            state.epoch = Arc::new(());
            drop(state);
            tasks.abort_all();
        }
        AltSvcValidationRefresh {
            _refresh: refresh,
            registry: Arc::downgrade(&self.tasks),
            cleanup_turn: Arc::clone(&self.cleanup_turn),
            turn: None,
            tasks: Vec::new(),
        }
    }
}

impl Drop for AltSvcValidationJobs {
    fn drop(&mut self) {
        self.close();
    }
}

impl AltSvcValidationRefresh {
    /// Observes cancelled setups while keeping enqueue blocked.
    ///
    /// The cleanup turn stays owned until this guard is dropped after pool
    /// refresh, so concurrent refresh and shutdown callers cannot bypass it.
    pub(crate) async fn observe_cancelled(&mut self) {
        if self.turn.is_none() {
            self.turn = Some(Arc::clone(&self.cleanup_turn).lock_owned().await);
            if let Some(registry) = self.registry.upgrade() {
                self.tasks.extend(
                    registry
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .take_all(),
                );
            }
        }
        for tasks in &mut self.tasks {
            observe_cancelled(tasks).await;
        }
    }
}

impl Drop for AltSvcValidationRefresh {
    fn drop(&mut self) {
        for tasks in &mut self.tasks {
            tasks.abort_all();
        }
        if let Some(registry) = self.registry.upgrade() {
            let mut registry = registry.lock().unwrap_or_else(PoisonError::into_inner);
            registry
                .retired
                .extend(self.tasks.drain(..).filter(|tasks| !tasks.is_empty()));
        }
        // If the owner is gone, dropping its final sets aborts remaining work.
        drop(self.turn.take());
    }
}

impl AltSvcValidationJobs {
    fn lock_tasks(&self) -> MutexGuard<'_, TaskSets> {
        self.tasks.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl TaskSets {
    fn reap(&mut self) -> Vec<JoinError> {
        let mut errors = reap(&mut self.active);
        for tasks in &mut self.retired {
            errors.extend(reap(tasks));
        }
        self.retired.retain(|tasks| !tasks.is_empty());
        errors
    }

    fn abort_all(&mut self) {
        self.active.abort_all();
        for tasks in &mut self.retired {
            tasks.abort_all();
        }
    }

    fn take_all(&mut self) -> Vec<JoinSet<()>> {
        let mut sets = std::mem::take(&mut self.retired);
        if !self.active.is_empty() {
            sets.push(std::mem::take(&mut self.active));
        }
        sets
    }

    #[cfg(test)]
    fn is_empty(&self) -> bool {
        self.active.is_empty() && self.retired.iter().all(JoinSet::is_empty)
    }
}

impl Control {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn reject(&self, publication: &AltSvcValidationPublication) {
        let state = self.lock();
        let owned = state.pending.iter().any(|entry| {
            entry.claim.strong_count() != 0 && entry.publication.same_mapping(publication)
        });
        if !owned {
            publication.abandon();
        }
    }

    fn reserve(
        self: &Arc<Self>,
        publication: &AltSvcValidationPublication,
        runtime: Id,
    ) -> Option<JobGuard> {
        let mut state = self.lock();
        state
            .pending
            .retain(|entry| entry.claim.strong_count() != 0);
        state
            .refreshes
            .retain(|refresh| refresh.strong_count() != 0);
        let existing = state.pending.iter().find_map(|entry| {
            if entry.publication.same_mapping(publication) {
                entry.claim.upgrade()
            } else {
                None
            }
        });
        let duplicate = state.pending.iter().any(|entry| {
            entry.runtime == runtime
                && entry.claim.strong_count() != 0
                && entry.publication.same_mapping(publication)
        });
        if state.closed
            || !state.refreshes.is_empty()
            || state.pending.len() >= MAX_VALIDATIONS
            || duplicate
            || !publication.is_current()
        {
            if existing.is_none() {
                publication.abandon();
            }
            drop(state);
            return None;
        }

        let claim = existing.unwrap_or_else(|| {
            Arc::new(ValidationClaim {
                control: Arc::downgrade(self),
                publication: publication.clone(),
                completed: AtomicBool::new(false),
            })
        });
        let token = Arc::new(());
        state.pending.push(Reservation {
            token: Arc::clone(&token),
            runtime,
            publication: publication.clone(),
            claim: Arc::downgrade(&claim),
        });
        Some(JobGuard {
            control: Arc::downgrade(self),
            token,
            epoch: ValidationEpoch {
                control: Arc::clone(self),
                epoch: Arc::clone(&state.epoch),
            },
            claim,
        })
    }
}

impl ValidationEpoch {
    /// Locks a live owner epoch for final mapping registration and pool insert.
    ///
    /// Never hold the permit during I/O, callbacks, tracing or an await.
    /// Pool publication takes the pool lock first, then this permit, then
    /// the mapping store lock. Owner operations never take a pool lock.
    pub(crate) fn lock_current(&self) -> Option<ValidationPermit<'_>> {
        let state = self.control.lock();
        if state.closed
            || !Arc::ptr_eq(&self.epoch, &state.epoch)
            || state
                .refreshes
                .iter()
                .any(|refresh| refresh.strong_count() != 0)
        {
            return None;
        }
        Some(ValidationPermit { _state: state })
    }
}

impl JobGuard {
    fn complete(&self) {
        self.claim.completed.store(true, Ordering::Relaxed);
    }
}

impl Drop for JobGuard {
    fn drop(&mut self) {
        if let Some(control) = self.control.upgrade() {
            control
                .lock()
                .pending
                .retain(|entry| !Arc::ptr_eq(&entry.token, &self.token));
        }
    }
}

impl Drop for ValidationClaim {
    fn drop(&mut self) {
        if self.completed.load(Ordering::Relaxed) {
            return;
        }
        let Some(control) = self.control.upgrade() else {
            self.publication.abandon();
            return;
        };
        let state = control.lock();
        // Another admission may take ownership between the last reservation's
        // removal and this claim's drop. Do not shorten its live mapping.
        if !state.pending.iter().any(|entry| {
            entry.claim.strong_count() != 0 && entry.publication.same_mapping(&self.publication)
        }) {
            self.publication.abandon();
        }
    }
}

async fn run(job: AltSvcValidationJob, guard: JobGuard) {
    let budget = match TimeoutBudget::new(job.timeouts) {
        Ok(budget) => budget,
        Err(error) => {
            debug!(outcome = "invalid_timeout", error_kind = ?error.kind(), "Alt-Svc validation stopped");
            return;
        }
    };
    if job.candidate.expires_at() <= Instant::now() {
        return;
    }
    if guard.epoch.lock_current().is_none() || !guard.claim.publication.is_current() {
        return;
    }
    let mut expiry = match DeadlineTimer::new(tokio::time::Instant::from_std(
        job.candidate.expires_at(),
    )) {
        Ok(expiry) => expiry,
        Err(error) => {
            debug!(outcome = "timer_unavailable", error_kind = ?error.kind(), "Alt-Svc validation stopped");
            return;
        }
    };
    let setup = job.pool.warmup(
        &job.connector,
        job.connect_udp_proxy.as_deref(),
        &job.endpoint,
        &job.route,
        Http3TransportTarget::for_alternative(job.candidate.target()),
        budget,
        Some(&guard.epoch),
    );
    let mut setup = std::pin::pin!(setup);
    let result = poll_fn(|context| {
        match expiry.poll_expired(context) {
            Poll::Ready(Ok(())) => return Poll::Ready(Ok(None)),
            Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
            Poll::Pending => {}
        }
        setup.as_mut().poll(context).map(|result| Ok(Some(result)))
    })
    .await;
    match result {
        Ok(Some(Ok(true))) => {
            guard.complete();
            debug!(outcome = "validated", "Alt-Svc validation finished");
        }
        Ok(Some(Err(error))) => {
            // A completed failed transaction keeps the advertised expiry;
            // only unfinished/cancelled work uses the abandonment retry rule.
            if error.kind() != RequestErrorKind::RuntimeUnavailable {
                guard.complete();
            }
            debug!(outcome = "failed", error_kind = ?error.kind(), "Alt-Svc validation finished");
        }
        Ok(None) => {
            debug!(outcome = "expired", "Alt-Svc validation stopped");
        }
        Ok(Some(Ok(false))) => {
            debug!(outcome = "retired", "Alt-Svc validation stopped");
        }
        Err(error) => {
            debug!(outcome = "timer_unavailable", error_kind = ?error.kind(), "Alt-Svc validation stopped");
        }
    }
}

async fn observe_cancelled(tasks: &mut JoinSet<()>) {
    tasks.abort_all();
    while let Some(result) = tasks.join_next().await {
        observe_join(result);
    }
}

fn reap(tasks: &mut JoinSet<()>) -> Vec<JoinError> {
    let mut errors = Vec::new();
    while let Some(result) = tasks.try_join_next() {
        if let Err(error) = result {
            errors.push(error);
        }
    }
    errors
}

fn observe_join(result: Result<(), JoinError>) {
    if let Err(error) = result {
        debug!(
            cancelled = error.is_cancelled(),
            panicked = error.is_panic(),
            "Alt-Svc validation task ended"
        );
    }
}

#[cfg(test)]
mod tests;
