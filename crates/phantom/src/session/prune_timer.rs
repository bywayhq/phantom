//! The timer that closes a client's expired idle HTTP/1.1 connections and
//! HTTP/2 connections, and ends what its pool entries remember of an origin
//! with no connection, as Firefox's connection manager prunes its
//! connections on one timer.

use std::{
    sync::{Arc, Mutex, MutexGuard, PoisonError, Weak},
    time::Duration,
};

use phantom_net::tcp::AddressFamilyMemory;
use tokio::{task::AbortHandle, time::Instant};
use tracing::debug;

/// What a prune of one pool key found.
pub(super) struct Pruned {
    /// The time the key's soonest expiring idle H1 connection or H2
    /// connection has left.
    pub(super) next: Option<Duration>,
    /// Whether the key has no connection, setup, or slower attempt left.
    pub(super) empty: bool,
}

/// The connections of one pool key, as the prune timer sees them.
pub(super) trait PrunedEntry: Send + Sync {
    /// Closes the key's idle H1 connections that have been idle
    /// `http1_limit` or longer as of `now`, its H2 connections past their
    /// own idle limit, and those the server closed.
    fn prune(&self, now: Instant, http1_limit: Option<Duration>) -> Pruned;

    /// The address family memory the key shares with the other runtimes'
    /// keys of its origin, for a key that remembers one.
    fn address_family(&self) -> Option<&Arc<AddressFamilyMemory>>;
}

/// One timer per client for the idle limits of
/// [`Http1IdleTimeout::ClosedOnTimer`](phantom_profile::Http1IdleTimeout::ClosedOnTimer)
/// and [`Http2IdleTimeout::ClosedOnTimer`](phantom_profile::Http2IdleTimeout::ClosedOnTimer),
/// shared by the exact H1 and H2 pools and the negotiated pool.
///
/// Line numbers are for Firefox tag `FIREFOX_157_0_RELEASE`:
///
/// - A connection that becomes idle sets the timer for the whole seconds it
///   has left, at least one, unless the timer is already set to fire sooner
///   (`nsHttpConnectionMgr::NewIdleConnectionAdded`,
///   `netwerk/protocol/http/nsHttpConnectionMgr.cpp:4075-4084`;
///   `nsHttpConnection::TimeToLive`,
///   `netwerk/protocol/http/nsHttpConnection.cpp:1009-1025`).
/// - When it fires, every pool key closes its expired idle connections, an
///   origin whose keys on every runtime are left with no connection, setup,
///   or slower attempt forgets its address family, and the timer is set
///   again for the soonest expiry left, if any
///   (`nsHttpConnectionMgr.cpp:2572-2625`;
///   `netwerk/protocol/http/ConnectionEntry.cpp:470-503`).
/// - An H2 connection holds its own limit
///   ([`Http2Connection::idle_time_left`](phantom_net::http2::Http2Connection::idle_time_left)).
///   One that joins a pool sets the timer for the time it has left, as an
///   idle H1 connection does (`nsHttpConnectionMgr::ReportSpdyConnection`,
///   `nsHttpConnectionMgr.cpp:1026-1031`), and
///   when the timer fires, a pool key gives up each H2 connection past its
///   limit, which closes once no stream is open (`ConnectionEntry.cpp:486-500`).
///
/// Firefox also stops its timer when its last idle connection closes while
/// no connection is active (`nsHttpConnectionMgr.cpp:273-289`,
/// `:4086-4090`). Phantom notices a server's close of an idle connection
/// only when the timer fires or a request comes, so its timer still fires
/// then.
///
/// The timer waits and prunes on Phantom's deadline service, not on a
/// caller's runtime, so it needs no time driver, keeps running when the
/// runtime that set it is dropped, and prunes the keys of every runtime,
/// including the idle connections of a runtime that is gone.
pub(crate) struct PruneTimer {
    http1_limit: Option<Duration>,
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
    /// A timer that closes idle H1 connections once they have been idle
    /// `http1_limit`, if set, and H2 connections past their own limit.
    pub(crate) fn new(http1_limit: Option<Duration>) -> Arc<Self> {
        Arc::new(Self {
            http1_limit,
            scheduled: true,
            state: Mutex::default(),
        })
    }

    /// A timer with H1 limit `http1_limit` that records when it would fire
    /// but fires only when a test calls [`Self::fire`].
    #[cfg(test)]
    pub(super) fn unscheduled(http1_limit: Duration) -> Arc<Self> {
        Arc::new(Self {
            http1_limit: Some(http1_limit),
            scheduled: false,
            state: Mutex::default(),
        })
    }

    /// The limit of idle H1 connections, if the timer closes them.
    #[cfg(test)]
    pub(super) const fn http1_limit(&self) -> Option<Duration> {
        self.http1_limit
    }

    /// Reports an H1 connection that became idle, when the timer closes
    /// idle H1 connections.
    pub(super) fn http1_idle_added(self: &Arc<Self>) {
        if let Some(limit) = self.http1_limit {
            self.idle_added(limit);
        }
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

    /// Reports a connection that became idle, or an H2 connection that
    /// joined a pool, with `left` until it expires.
    pub(super) fn idle_added(self: &Arc<Self>, left: Duration) {
        let now = Instant::now();
        // A limit beyond the clock's range never expires on the timer.
        let Some(at) = now.checked_add(whole_seconds(left)) else {
            return;
        };
        let mut state = self.lock();
        // A wake-up set for `at` or sooner, even one already due whose prune
        // has not yet run, prunes this connection or sets the timer again
        // for it.
        if state.wake_at.is_some_and(|wake_at| wake_at <= at) {
            return;
        }
        self.arm(&mut state, at);
    }

    /// Sets the timer to fire at `at`. It stays unset when the deadline
    /// service could not schedule it, so a later idle connection tries
    /// again.
    fn arm(self: &Arc<Self>, state: &mut TimerState, at: Instant) {
        if let Some(task) = state.task.take() {
            task.abort();
        }
        state.wake_at = None;
        if !self.scheduled {
            state.wake_at = Some(at);
            return;
        }
        let timer = Arc::downgrade(self);
        let Some(task) =
            phantom_net::run_after(at.saturating_duration_since(Instant::now()), move || {
                if let Some(timer) = timer.upgrade() {
                    timer.fire();
                }
            })
        else {
            debug!("idle connection timer could not be scheduled");
            return;
        };
        state.task = Some(task);
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
        let mut next: Option<Duration> = None;
        // Each memory, and whether every live key that shares it is empty.
        let mut families: Vec<(Arc<AddressFamilyMemory>, bool)> = Vec::new();
        for entry in entries.iter().filter_map(Weak::upgrade) {
            let pruned = entry.prune(now, self.http1_limit);
            next = match (next, pruned.next) {
                (Some(soonest), Some(left)) => Some(soonest.min(left)),
                (soonest, left) => soonest.or(left),
            };
            let Some(family) = entry.address_family() else {
                continue;
            };
            match families
                .iter_mut()
                .find(|(memory, _)| Arc::ptr_eq(memory, family))
            {
                Some((_, empty)) => *empty &= pruned.empty,
                None => families.push((Arc::clone(family), pruned.empty)),
            }
        }
        for (memory, empty) in families {
            if empty {
                memory.forget();
            }
        }
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

    use phantom_net::tcp::AddressFamily;

    use super::*;

    const WAIT: Duration = Duration::from_secs(10);

    /// An entry that answers with a fixed time left and emptiness, and
    /// counts its prunes.
    struct Entry {
        left: Mutex<Option<Duration>>,
        empty: bool,
        family: Arc<AddressFamilyMemory>,
        pruned: Mutex<Vec<Instant>>,
    }

    impl Entry {
        fn new(left: Option<Duration>) -> Arc<Self> {
            Self::sharing(left, true, &Arc::default())
        }

        fn sharing(
            left: Option<Duration>,
            empty: bool,
            family: &Arc<AddressFamilyMemory>,
        ) -> Arc<Self> {
            Arc::new(Self {
                left: Mutex::new(left),
                empty,
                family: Arc::clone(family),
                pruned: Mutex::new(Vec::new()),
            })
        }

        fn prunes(&self) -> usize {
            self.pruned.lock().map_or(0, |pruned| pruned.len())
        }
    }

    impl PrunedEntry for Entry {
        fn prune(&self, now: Instant, _http1_limit: Option<Duration>) -> Pruned {
            if let Ok(mut pruned) = self.pruned.lock() {
                pruned.push(now);
            }
            Pruned {
                next: self.left.lock().ok().and_then(|left| *left),
                empty: self.empty,
            }
        }

        fn address_family(&self) -> Option<&Arc<AddressFamilyMemory>> {
            Some(&self.family)
        }
    }

    /// Waits on the wall clock, as the deadline service keeps it, until
    /// `entry` has been pruned.
    fn wait_for_prune(entry: &Entry) -> bool {
        let deadline = std::time::Instant::now() + WAIT;
        while entry.prunes() == 0 {
            if std::time::Instant::now() > deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        true
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
    async fn a_connection_idle_while_a_prune_is_due_keeps_the_due_wake_up() {
        let timer = PruneTimer::unscheduled(Duration::from_secs(115));
        let entry = Entry::new(Some(Duration::from_secs(115)));
        register(&timer, &entry);
        let start = Instant::now();
        timer.idle_added(Duration::from_secs(115));

        tokio::time::advance(Duration::from_secs(116)).await;
        timer.idle_added(Duration::from_secs(115));
        assert_eq!(timer.wake_at(), Some(start + Duration::from_secs(115)));

        timer.fire();
        assert_eq!(entry.prunes(), 1);
        assert_eq!(
            timer.wake_at(),
            Some(start + Duration::from_secs(116 + 115))
        );
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

    #[tokio::test(start_paused = true)]
    async fn a_family_is_forgotten_only_when_every_runtime_key_of_its_origin_is_empty() {
        let timer = PruneTimer::unscheduled(Duration::from_secs(115));
        let shared = Arc::new(AddressFamilyMemory::new());
        shared.remember(AddressFamily::Ipv4);
        let gone_runtime = Entry::sharing(None, true, &shared);
        let live_runtime = Entry::sharing(Some(Duration::from_secs(60)), false, &shared);
        let other_origin = Arc::new(AddressFamilyMemory::new());
        other_origin.remember(AddressFamily::Ipv6);
        let other = Entry::sharing(None, true, &other_origin);
        for entry in [&gone_runtime, &live_runtime, &other] {
            register(&timer, entry);
        }

        timer.fire();
        assert_eq!(shared.family(), Some(AddressFamily::Ipv4));
        assert_eq!(other_origin.family(), None);

        drop(live_runtime);
        timer.fire();
        assert_eq!(shared.family(), None);
    }

    #[test]
    fn a_timer_set_outside_any_runtime_fires_on_the_deadline_service() {
        let timer = PruneTimer::new(Some(Duration::from_secs(1)));
        let entry = Entry::new(None);
        register(&timer, &entry);

        timer.idle_added(Duration::from_secs(1));

        assert!(timer.wake_at().is_some());
        assert!(wait_for_prune(&entry), "the timer never fired");
    }

    #[test]
    fn the_timer_fires_after_the_runtime_that_set_it_is_dropped() -> std::io::Result<()> {
        let timer = PruneTimer::new(Some(Duration::from_secs(1)));
        let entry = Entry::new(None);
        register(&timer, &entry);
        let first = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        first.block_on(async { timer.idle_added(Duration::from_secs(1)) });
        drop(first);

        assert!(wait_for_prune(&entry), "the timer died with its runtime");
        Ok(())
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
