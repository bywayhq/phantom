//! Read-idle expiry of one route's pooled connections.

use std::{sync::Arc, time::Duration};

use tokio::{task::AbortHandle, time::Instant};
use tracing::debug;

use super::{RouteConnections, RouteState, Slot};
use crate::shutdown_timer::ScheduleError;

/// A pending callback owns only a weak route reference. Distinct identities
/// prevent an already-running cancelled callback from replacing its successor.
pub(super) struct Deadline {
    identity: Arc<()>,
    at: Instant,
    task: AbortHandle,
}

impl Drop for Deadline {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
impl Deadline {
    pub(super) fn identity(&self) -> Arc<()> {
        Arc::clone(&self.identity)
    }
}

impl RouteConnections {
    pub(super) fn arm_idle(self: &Arc<Self>, state: &mut RouteState) -> Result<(), ScheduleError> {
        let Some(left) = state
            .slots
            .iter()
            .filter_map(|slot| slot.connection.idle_time_left())
            .min()
        else {
            state.idle = None;
            return Ok(());
        };

        let delay = prune_delay(left);
        let at = Instant::now().checked_add(delay).ok_or(ScheduleError)?;
        if state.idle.as_ref().is_some_and(|pending| pending.at <= at) {
            return Ok(());
        }

        #[cfg(test)]
        if self
            .fail_next_deadline
            .swap(false, std::sync::atomic::Ordering::AcqRel)
        {
            return Err(ScheduleError);
        }

        let identity = Arc::new(());
        let callback = Arc::clone(&identity);
        let route = Arc::downgrade(self);
        let task = crate::shutdown_timer::run_after(delay, move || {
            if let Some(route) = route.upgrade() {
                route.prune_idle(&callback);
            }
        })
        .ok_or(ScheduleError)?;
        state.idle = Some(Deadline { identity, at, task });
        Ok(())
    }

    pub(super) fn prune_idle(self: &Arc<Self>, identity: &Arc<()>) {
        let mut state = self.lock();
        if !state
            .idle
            .as_ref()
            .is_some_and(|pending| Arc::ptr_eq(identity, &pending.identity))
        {
            return;
        }

        state.idle = None;
        let mut retired = state.prune();
        if self.arm_idle(&mut state).is_err() {
            retired.extend(state.remove_timed());
            state.idle_failed = true;
            debug!(
                outcome = "runtime_unavailable",
                "HTTP/2 proxy idle timer failed"
            );
        }
        drop(state);
        // Native stream leases keep live tunnels and response bodies alive.
        drop(retired);
        self.changed.notify_waiters();
    }
}

impl RouteState {
    pub(super) fn prune(&mut self) -> Vec<Slot> {
        let (kept, retired) = std::mem::take(&mut self.slots)
            .into_iter()
            .partition(|slot| slot.connection.is_reusable());
        self.slots = kept;
        retired
    }

    pub(super) fn remove_timed(&mut self) -> Vec<Slot> {
        let (kept, retired) = std::mem::take(&mut self.slots)
            .into_iter()
            .partition(|slot| slot.connection.idle_time_left().is_none());
        self.slots = kept;
        self.idle = None;
        retired
    }

    pub(super) fn remove_matching(
        &mut self,
        tunnels: &Arc<std::sync::atomic::AtomicUsize>,
    ) -> Vec<Slot> {
        let (kept, retired) = std::mem::take(&mut self.slots)
            .into_iter()
            .partition(|slot| !Arc::ptr_eq(&slot.tunnels, tunnels));
        self.slots = kept;
        retired
    }
}

/// Firefox's connection-manager pruning uses whole seconds, with at least
/// one second between checks (`nsHttpConnection::TimeToLive`, Firefox157).
pub(super) fn prune_delay(left: Duration) -> Duration {
    Duration::from_secs(left.as_secs().max(1))
}
