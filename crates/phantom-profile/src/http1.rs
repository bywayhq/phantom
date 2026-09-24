//! HTTP/1.1 connection policy a client applies to each origin and route.

use std::num::NonZeroUsize;

/// How many HTTP/1.1 connections a client keeps to one origin and route.
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
}

#[cfg(test)]
mod tests;
