//! Idle HTTP/1 connections and the idle age of quiet backup openings.

use std::time::Duration;

use phantom_net::http1::Http1Connection;
use tokio::time::Instant;

/// A connection returned to its pool key, and when it was returned.
pub(super) struct IdleConnection {
    pub(super) connection: Http1Connection,
    since: Instant,
}

impl IdleConnection {
    pub(super) fn new(connection: Http1Connection) -> Self {
        Self {
            connection,
            since: Instant::now(),
        }
    }

    /// Chromium closes sockets idle at least this long when a request reaches
    /// its pool (`net/socket/transport_client_socket_pool.cc:263`, `:969-1000`
    /// at tag `154.0.8037.58`).
    pub(super) fn is_reusable(&self, used_idle_timeout: Option<Duration>) -> bool {
        self.connection.is_reusable()
            && used_idle_timeout.is_none_or(|timeout| self.since.elapsed() < timeout)
    }

    fn idle_for(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.since)
    }
}

/// Moves closeable connections out without running their destructors under
/// the pool lock. Connections held by an opening or early data stay owned.
pub(super) fn take_idle_connections(
    idle: &mut Vec<IdleConnection>,
    removed: &mut Vec<IdleConnection>,
) {
    let mut index = 0;
    while index < idle.len() {
        let connection = &idle[index].connection;
        if connection.is_exclusively_owned() && !connection.early_data_pending() {
            removed.push(idle.remove(index));
        } else {
            index += 1;
        }
    }
}

pub(super) fn prune_idle_connections(
    idle: &mut Vec<IdleConnection>,
    now: Instant,
    limit: Option<Duration>,
) -> Option<Duration> {
    idle.retain(|idle| {
        idle.connection.is_reusable() && limit.is_none_or(|limit| idle.idle_for(now) < limit)
    });
    limit.and_then(|limit| {
        idle.iter()
            .map(|idle| limit.saturating_sub(idle.idle_for(now)))
            .min()
    })
}

/// An unfinished backup has no idle age. Expired openings return zero.
pub(super) fn spare_idle_time_left(
    since: Option<Instant>,
    now: Instant,
    limit: Option<Duration>,
) -> Option<Duration> {
    Some(limit?.saturating_sub(now.saturating_duration_since(since?)))
}
