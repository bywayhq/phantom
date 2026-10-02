//! HTTP/1.1 connection policy a client applies to each origin and route.

use std::{num::NonZeroUsize, time::Duration};

/// How many HTTP/1.1 connections a client keeps to one origin and route, and
/// when an idle one stops being reused.
///
/// HTTP/1.1 carries one request at a time on a connection, so a browser runs
/// requests to the same host in parallel by opening several connections to
/// it, up to a fixed per-host limit. Idle connections count toward the limit.
/// A request reuses an idle connection before a new one opens, and waits in
/// order once the limit is reached.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Http1Settings {
    /// Most HTTP/1.1 connections open at once to one origin and route,
    /// counting idle connections and those still being established.
    pub max_connections_per_origin: NonZeroUsize,
    /// When an idle connection stops being reused.
    pub idle_timeout: Http1IdleTimeout,
}

/// When an idle HTTP/1.1 connection, one that has carried a request and now
/// carries none, stops being reused.
///
/// A connection joins the idle list only after it has carried a request, so
/// every variant applies to what Chromium calls a used idle socket.
///
/// Browsers apply their limits differently. Chromium checks its limit only
/// when a request reaches the pool, which [`Self::CheckedOnRequest`] models.
/// Firefox also closes an idle connection on a timer once its limit passes,
/// whether or not a request comes; no variant models that yet, so the enum is
/// non-exhaustive.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum Http1IdleTimeout {
    /// Reuse an idle connection until the server closes it.
    #[default]
    Unlimited,
    /// Close an idle connection instead of reusing it once it has been idle
    /// this long, checked when a request reaches the connections of its
    /// origin and route.
    ///
    /// The request then reuses another idle connection or opens a new one.
    /// Nothing closes an idle connection between requests, and
    /// `CheckedOnRequest(Duration::ZERO)` never reuses one.
    CheckedOnRequest(Duration),
}

impl Http1IdleTimeout {
    /// Returns the limit checked when a request arrives, if any.
    #[must_use]
    pub const fn checked_on_request(self) -> Option<Duration> {
        match self {
            Self::Unlimited => None,
            Self::CheckedOnRequest(timeout) => Some(timeout),
        }
    }
}

#[cfg(test)]
mod tests;
