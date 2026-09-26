//! Choosing among the HTTP/3 connections to one transport location.
//!
//! Browsers keep one HTTP/3 connection per origin and route. A caller may
//! allow more with `ClientBuilder::max_http3_connections_per_origin`: a new
//! connection opens only when every existing one has as many streams in
//! flight as it can carry, and a new stream goes to the connection with the
//! fewest.

use std::num::NonZeroUsize;

/// What a request should do with a location's HTTP/3 connections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Choice {
    /// Send on the candidate at this position.
    Use(usize),
    /// Open another connection: none exists, or every one is full and the
    /// location is below its connection limit.
    Open,
}

/// One reusable connection a request could use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Candidate {
    /// The server's `initial_max_streams_bidi`, known once the handshake
    /// completed.
    pub(super) peer_limit: Option<u64>,
    /// Streams in flight on the connection.
    pub(super) streams: usize,
}

/// How many streams the HTTP/3 connections to one location may carry.
#[derive(Debug)]
pub(super) struct Http3Spread {
    max_connections: NonZeroUsize,
    local_streams: NonZeroUsize,
}

impl Http3Spread {
    pub(super) const fn new(max_connections: NonZeroUsize, local_streams: NonZeroUsize) -> Self {
        Self {
            max_connections,
            local_streams,
        }
    }

    pub(super) const fn max_connections(&self) -> NonZeroUsize {
        self.max_connections
    }

    /// Chooses the least-loaded connection that has room for another stream.
    ///
    /// A connection's room is the lower of the local active bound and the
    /// server's `initial_max_streams_bidi`, which a server that grants a
    /// stream back as each one closes keeps open at once. A limit of 0 counts
    /// as 1, because the server must grant a stream before any request can
    /// use the connection. A connection whose handshake has not completed
    /// uses the limit another connection to the same location reported, or
    /// the local bound when none has. When no connection has room, another
    /// opens up to the limit; at the limit the least-loaded connection takes
    /// the stream, and QUIC holds it until the server grants stream credit.
    /// Ties go to the earliest candidate, so one connection behaves as a
    /// browser's does.
    pub(super) fn choose(&self, candidates: &[Candidate]) -> Choice {
        let peer_limit = |candidate: &Candidate| {
            candidate
                .peer_limit
                .map(|limit| usize::try_from(limit).unwrap_or(usize::MAX).max(1))
        };
        let reported = candidates.iter().rev().find_map(peer_limit);
        let mut least_loaded: Option<(usize, usize)> = None;
        let mut with_room: Option<(usize, usize)> = None;
        let count = candidates.len();
        for (position, candidate) in candidates.iter().enumerate() {
            let room = peer_limit(candidate)
                .or(reported)
                .map_or(self.local_streams.get(), |peer| {
                    peer.min(self.local_streams.get())
                });
            let load = candidate.streams;
            if least_loaded.is_none_or(|(_, fewest)| load < fewest) {
                least_loaded = Some((position, load));
            }
            if load < room && with_room.is_none_or(|(_, fewest)| load < fewest) {
                with_room = Some((position, load));
            }
        }
        match (with_room, least_loaded) {
            (Some((position, _)), _) => Choice::Use(position),
            (None, Some((position, _))) if count >= self.max_connections.get() => {
                Choice::Use(position)
            }
            _ => Choice::Open,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use super::{Candidate, Choice, Http3Spread};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn bound(value: usize) -> Result<NonZeroUsize, Box<dyn std::error::Error>> {
        NonZeroUsize::new(value).ok_or_else(|| "zero bound".into())
    }

    const fn candidate(peer_limit: Option<u64>, streams: usize) -> Candidate {
        Candidate {
            peer_limit,
            streams,
        }
    }

    #[test]
    fn one_connection_takes_every_stream_by_default() -> TestResult {
        let spread = Http3Spread::new(NonZeroUsize::MIN, bound(100)?);
        assert_eq!(spread.choose(&[]), Choice::Open);
        // Past the server's limit, the single allowed connection still serves.
        assert_eq!(spread.choose(&[candidate(Some(1), 3)]), Choice::Use(0));
        Ok(())
    }

    #[test]
    fn a_saturated_connection_opens_another_up_to_the_limit() -> TestResult {
        let spread = Http3Spread::new(bound(2)?, bound(100)?);
        assert_eq!(spread.choose(&[candidate(Some(1), 0)]), Choice::Use(0));
        assert_eq!(spread.choose(&[candidate(Some(1), 1)]), Choice::Open);
        assert_eq!(
            spread.choose(&[candidate(Some(1), 1), candidate(Some(1), 0)]),
            Choice::Use(1)
        );
        // Both are full and the location is at its limit: the least loaded,
        // then the earliest, takes the stream.
        assert_eq!(
            spread.choose(&[candidate(Some(1), 2), candidate(Some(1), 1)]),
            Choice::Use(1)
        );
        assert_eq!(
            spread.choose(&[candidate(Some(1), 1), candidate(Some(1), 1)]),
            Choice::Use(0)
        );
        Ok(())
    }

    #[test]
    fn the_local_bound_caps_a_larger_server_limit() -> TestResult {
        let spread = Http3Spread::new(bound(2)?, bound(2)?);
        assert_eq!(spread.choose(&[candidate(Some(100), 1)]), Choice::Use(0));
        assert_eq!(spread.choose(&[candidate(Some(100), 2)]), Choice::Open);
        Ok(())
    }

    #[test]
    fn a_connection_before_its_handshake_uses_its_location_s_reported_limit() -> TestResult {
        let spread = Http3Spread::new(bound(3)?, bound(100)?);
        // Nothing reported yet: the local bound applies.
        assert_eq!(spread.choose(&[candidate(None, 50)]), Choice::Use(0));
        assert_eq!(
            spread.choose(&[candidate(Some(2), 2), candidate(None, 1)]),
            Choice::Use(1)
        );
        assert_eq!(
            spread.choose(&[candidate(Some(2), 2), candidate(None, 2)]),
            Choice::Open
        );
        Ok(())
    }

    #[test]
    fn a_zero_server_limit_counts_as_one_stream() -> TestResult {
        let spread = Http3Spread::new(bound(2)?, bound(100)?);
        assert_eq!(spread.choose(&[candidate(Some(0), 0)]), Choice::Use(0));
        assert_eq!(spread.choose(&[candidate(Some(0), 1)]), Choice::Open);
        Ok(())
    }
}
