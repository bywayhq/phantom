//! The timer that closes a client's expired idle HTTP/1.1 connections and
//! ends what its pool entries remember of an origin with no connection, as
//! Firefox's connection manager prunes its connections on one timer.

use std::{
    sync::{Arc, Mutex, MutexGuard, PoisonError, Weak},
    time::Duration,
};

use tokio::{task::AbortHandle, time::Instant};
use tracing::debug;

/// The connections of one pool key, as the prune timer sees them.
pub(super) trait PrunedEntry: Send + Sync {
    /// Closes the key's idle H1 connections that have been idle `limit` or
    /// longer as of `now`, and those the server closed; forgets the origin's
    /// address family when the key has no connection, setup, or slower
    /// attempt left; and returns the time its soonest expiring idle
    /// connection has left.
    fn prune(&self, now: Instant, limit: Duration) -> Option<Duration>;
}

/// One timer per client for the idle limit of
/// [`Http1IdleTimeout::ClosedOnTimer`](phantom_profile::Http1IdleTimeout::ClosedOnTimer),
/// shared by the exact H1 pool and the negotiated pool.
///
/// Line numbers are for Firefox tag `FIREFOX_157_0_RELEASE`:
///
/// - A connection that becomes idle sets the timer for the whole seconds it
///   has left, at least one, unless the timer is already set to fire sooner
///   (`nsHttpConnectionMgr::NewIdleConnectionAdded`,
///   `netwerk/protocol/http/nsHttpConnectionMgr.cpp:4075-4084`;
///   `nsHttpConnection::TimeToLive`,
///   `netwerk/protocol/http/nsHttpConnection.cpp:1009-1025`).
/// - When it fires, every pool key closes its expired idle connections and
///   forgets the address family of an origin left with no connection, and
///   the timer is set again for the soonest expiry left, if any
///   (`nsHttpConnectionMgr.cpp:2572-2625`;
///   `netwerk/protocol/http/ConnectionEntry.cpp:470-503`).
///
/// Firefox also stops its timer when its last idle connection closes while
/// no connection is active (`nsHttpConnectionMgr.cpp:273-289`,
/// `:4086-4090`). Phantom notices a server's close of an idle connection
/// only when the timer fires or a request comes, so its timer still fires
/// then.
///
/// The timer runs on Phantom's deadline service, so it needs no time driver
/// in the caller's runtime; it is set only from within a Tokio runtime.
pub(crate) struct PruneTimer {
    limit: Duration,
    scheduled: bool,
    state: Mutex<TimerState>,
}

#[derive(Default)]
struct TimerState {
    entries: Vec<Weak<dyn PrunedEntry>>,
    wake_at: Option<Instant>,
    task: Option<AbortHandle>,
}

impl PruneTimer {
    /// A timer that closes idle connections once they have been idle
    /// `limit`.
    pub(crate) fn new(limit: Duration) -> Arc<Self> {
        Arc::new(Self {
            limit,
            scheduled: true,
            state: Mutex::default(),
        })
    }

    /// A timer that records when it would fire but fires only when a test
    /// calls [`Self::fire`].
    #[cfg(test)]
    pub(super) fn unscheduled(limit: Duration) -> Arc<Self> {
        Arc::new(Self {
            limit,
            scheduled: false,
            state: Mutex::default(),
        })
    }

    pub(super) const fn limit(&self) -> Duration {
        self.limit
    }

    fn lock(&self) -> MutexGuard<'_, TimerState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds a pool key's connections to those the timer prunes.
    pub(super) fn register(&self, entry: Weak<dyn PrunedEntry>) {
        let mut state = self.lock();
        state.entries.retain(|entry| entry.strong_count() > 0);
        state.entries.push(entry);
    }

    /// Reports a connection that became idle with `left` until it expires.
    pub(super) fn idle_added(self: &Arc<Self>, left: Duration) {
        let now = Instant::now();
        // A limit beyond the clock's range never expires on the timer.
        let Some(at) = now.checked_add(whole_seconds(left)) else {
            return;
        };
        let mut state = self.lock();
        // A wake-up already due has fired or was lost with its runtime.
        if state
            .wake_at
            .is_some_and(|wake_at| wake_at > now && wake_at <= at)
        {
            return;
        }
        self.arm(&mut state, at);
    }

    /// Sets the timer to fire at `at`. It stays unset when no task could be
    /// scheduled, so a later idle connection tries again.
    fn arm(self: &Arc<Self>, state: &mut TimerState, at: Instant) {
        if let Some(task) = state.task.take() {
            task.abort();
        }
        state.wake_at = None;
        if !self.scheduled {
            state.wake_at = Some(at);
            return;
        }
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            debug!("idle connection timer not set outside a Tokio runtime");
            return;
        };
        let Some(deadline) = phantom_net::deadline(at.saturating_duration_since(Instant::now()))
        else {
            debug!("idle connection timer could not be scheduled");
            return;
        };
        let timer = Arc::downgrade(self);
        let task = runtime.spawn(async move {
            deadline.await;
            if let Some(timer) = timer.upgrade() {
                timer.fire();
            }
        });
        state.task = Some(task.abort_handle());
        state.wake_at = Some(at);
    }

    /// Prunes every pool key and sets the timer for the soonest expiry left.
    pub(super) fn fire(self: &Arc<Self>) {
        let entries = {
            let mut state = self.lock();
            state.wake_at = None;
            state.task = None;
            state.entries.retain(|entry| entry.strong_count() > 0);
            state.entries.clone()
        };
        let now = Instant::now();
        let next = entries
            .iter()
            .filter_map(Weak::upgrade)
            .filter_map(|entry| entry.prune(now, self.limit))
            .min();
        let Some(next) = next else {
            return;
        };
        let Some(at) = now.checked_add(whole_seconds(next)) else {
            return;
        };
        let mut state = self.lock();
        if state.wake_at.is_none_or(|wake_at| at < wake_at) {
            self.arm(&mut state, at);
        }
    }

    /// When the timer fires next, if it is set.
    #[cfg(test)]
    pub(super) fn wake_at(&self) -> Option<Instant> {
        self.lock().wake_at
    }
}

impl Drop for PruneTimer {
    fn drop(&mut self) {
        if let Some(task) = self.lock().task.take() {
            task.abort();
        }
    }
}

/// `left` in whole seconds, at least one, as Firefox's `TimeToLive` rounds.
fn whole_seconds(left: Duration) -> Duration {
    Duration::from_secs(left.as_secs().max(1))
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    /// An entry that answers with a fixed time left and counts its prunes.
    struct Entry {
        left: Mutex<Option<Duration>>,
        pruned: Mutex<Vec<Instant>>,
    }

    impl Entry {
        fn new(left: Option<Duration>) -> Arc<Self> {
            Arc::new(Self {
                left: Mutex::new(left),
                pruned: Mutex::new(Vec::new()),
            })
        }

        fn prunes(&self) -> usize {
            self.pruned.lock().map_or(0, |pruned| pruned.len())
        }
    }

    impl PrunedEntry for Entry {
        fn prune(&self, now: Instant, _limit: Duration) -> Option<Duration> {
            if let Ok(mut pruned) = self.pruned.lock() {
                pruned.push(now);
            }
            self.left.lock().ok().and_then(|left| *left)
        }
    }

    fn register(timer: &PruneTimer, entry: &Arc<Entry>) {
        let entry: Arc<dyn PrunedEntry> = entry.clone();
        timer.register(Arc::downgrade(&entry));
    }

    #[tokio::test(start_paused = true)]
    async fn an_idle_connection_sets_the_timer_for_its_whole_seconds() {
        let timer = PruneTimer::unscheduled(Duration::from_secs(115));
        let start = Instant::now();

        timer.idle_added(Duration::from_millis(114_900));
        assert_eq!(timer.wake_at(), Some(start + Duration::from_secs(114)));

        // Less than a second left still waits one second.
        let timer = PruneTimer::unscheduled(Duration::from_secs(115));
        timer.idle_added(Duration::from_millis(300));
        assert_eq!(timer.wake_at(), Some(start + Duration::from_secs(1)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_limit_beyond_the_clock_leaves_the_timer_unset() {
        let timer = PruneTimer::unscheduled(Duration::MAX);
        timer.idle_added(Duration::MAX);
        assert_eq!(timer.wake_at(), None);

        let entry = Entry::new(Some(Duration::MAX));
        register(&timer, &entry);
        timer.fire();
        assert_eq!(entry.prunes(), 1);
        assert_eq!(timer.wake_at(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn only_a_sooner_expiry_moves_the_timer() {
        let timer = PruneTimer::unscheduled(Duration::from_secs(115));
        let start = Instant::now();
        timer.idle_added(Duration::from_secs(115));

        tokio::time::advance(Duration::from_secs(10)).await;
        timer.idle_added(Duration::from_secs(115));
        assert_eq!(timer.wake_at(), Some(start + Duration::from_secs(115)));

        timer.idle_added(Duration::from_secs(30));
        assert_eq!(timer.wake_at(), Some(start + Duration::from_secs(40)));
    }

    #[tokio::test(start_paused = true)]
    async fn firing_prunes_every_entry_and_waits_for_the_soonest_expiry_left() {
        let timer = PruneTimer::unscheduled(Duration::from_secs(115));
        let soon = Entry::new(Some(Duration::from_millis(2_500)));
        let later = Entry::new(Some(Duration::from_secs(60)));
        let empty = Entry::new(None);
        for entry in [&soon, &later, &empty] {
            register(&timer, entry);
        }
        let start = Instant::now();

        timer.fire();

        for entry in [&soon, &later, &empty] {
            assert_eq!(entry.prunes(), 1);
        }
        assert_eq!(timer.wake_at(), Some(start + Duration::from_secs(2)));
    }

    #[tokio::test(start_paused = true)]
    async fn a_timer_with_nothing_left_to_expire_stays_unset() {
        let timer = PruneTimer::unscheduled(Duration::from_secs(115));
        let empty = Entry::new(None);
        register(&timer, &empty);
        timer.idle_added(Duration::from_secs(115));

        timer.fire();

        assert_eq!(empty.prunes(), 1);
        assert_eq!(timer.wake_at(), None);
    }

    #[test]
    fn a_timer_outside_a_runtime_stays_unset() {
        let timer = PruneTimer::new(Duration::from_secs(115));

        timer.idle_added(Duration::from_secs(115));

        assert_eq!(timer.wake_at(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_dropped_entry_is_no_longer_pruned() {
        let timer = PruneTimer::unscheduled(Duration::from_secs(115));
        let kept = Entry::new(None);
        let dropped = Entry::new(Some(Duration::from_secs(1)));
        register(&timer, &kept);
        register(&timer, &dropped);
        drop(dropped);

        timer.fire();

        assert_eq!(kept.prunes(), 1);
        assert_eq!(timer.wake_at(), None);
    }
}
