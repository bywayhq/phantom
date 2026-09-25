//! Choosing among the HTTP/2 connections of one pool key.
//!
//! Browsers keep one HTTP/2 connection per origin and route. A caller may
//! allow more with `ClientBuilder::max_http2_connections_per_origin`: a new
//! connection opens only when every existing one has as many streams in
//! flight as it can carry, and a new stream goes to the connection with the
//! fewest.

use std::{
    num::NonZeroUsize,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use phantom_net::http2::Http2Connection;

/// The streams in flight on one pooled HTTP/2 connection.
#[derive(Clone, Debug, Default)]
pub(super) struct StreamCount(Arc<AtomicUsize>);

impl StreamCount {
    fn get(&self) -> usize {
        self.0.load(Ordering::Acquire)
    }

    /// Counts one more stream until the returned guard drops.
    pub(super) fn open(&self) -> OpenStream {
        self.0.fetch_add(1, Ordering::AcqRel);
        OpenStream(Arc::clone(&self.0))
    }
}

/// One stream counted against its connection until it ends.
#[derive(Debug)]
pub(super) struct OpenStream(Arc<AtomicUsize>);

impl Drop for OpenStream {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// What a request should do with a pool key's HTTP/2 connections.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Choice {
    /// Send on the connection at this index.
    Use(usize),
    /// Open another connection: none exists, or every one is full and the
    /// key is below its connection limit.
    Open,
}

/// How many streams one pool key's HTTP/2 connections may carry.
#[derive(Debug)]
pub(super) struct Http2Spread {
    max_connections: NonZeroUsize,
    local_streams: NonZeroUsize,
    /// The most recent stream limit a peer of this key advertised, used for a
    /// connection whose SETTINGS have not arrived yet.
    learned_peer_limit: Option<usize>,
}

impl Http2Spread {
    pub(super) const fn new(max_connections: NonZeroUsize, local_streams: NonZeroUsize) -> Self {
        Self {
            max_connections,
            local_streams,
            learned_peer_limit: None,
        }
    }

    /// Chooses the least-loaded connection that has room for another stream.
    ///
    /// A connection's room is the lower of the local active bound and the
    /// peer's `SETTINGS_MAX_CONCURRENT_STREAMS`. When no connection has room,
    /// the key opens another up to its limit; at the limit the least-loaded
    /// connection takes the stream and the HTTP/2 layer queues it until the
    /// peer allows it. Ties go to the oldest connection, so a key with one
    /// connection behaves as a browser does.
    pub(super) fn choose<'a>(
        &mut self,
        connections: impl Iterator<Item = (&'a Http2Connection, &'a StreamCount)>,
    ) -> Choice {
        let mut least_loaded: Option<(usize, usize)> = None;
        let mut with_room: Option<(usize, usize)> = None;
        let mut count = 0;
        for (index, (connection, streams)) in connections.enumerate() {
            count += 1;
            if let Some(limit) = connection.peer_max_concurrent_streams() {
                self.learned_peer_limit = Some(limit);
            }
            let room = connection
                .peer_max_concurrent_streams()
                .or(self.learned_peer_limit)
                .map_or(self.local_streams.get(), |peer| {
                    peer.min(self.local_streams.get())
                });
            let load = streams.get();
            if least_loaded.is_none_or(|(_, fewest)| load < fewest) {
                least_loaded = Some((index, load));
            }
            if load < room && with_room.is_none_or(|(_, fewest)| load < fewest) {
                with_room = Some((index, load));
            }
        }
        match (with_room, least_loaded) {
            (Some((index, _)), _) => Choice::Use(index),
            (None, Some((index, _))) if count >= self.max_connections.get() => Choice::Use(index),
            _ => Choice::Open,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use phantom_net::http2::Http2Connection;
    use phantom_profile::chromium;
    use tokio::io::{DuplexStream, duplex};

    use super::{Choice, Http2Spread, StreamCount};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    async fn connection() -> Result<(Http2Connection, DuplexStream), Box<dyn std::error::Error>> {
        let (client, server) = duplex(64 * 1024);
        Ok((
            Http2Connection::connect(client, &chromium::v154_http2()).await?,
            server,
        ))
    }

    fn bound(value: usize) -> Result<NonZeroUsize, Box<dyn std::error::Error>> {
        NonZeroUsize::new(value).ok_or_else(|| "zero bound".into())
    }

    #[tokio::test]
    async fn one_connection_takes_every_stream_by_default() -> TestResult {
        let (first, _peer) = connection().await?;
        let streams = StreamCount::default();
        let mut spread = Http2Spread::new(NonZeroUsize::MIN, bound(2)?);
        assert_eq!(spread.choose(std::iter::empty()), Choice::Open);

        let _held = [streams.open(), streams.open(), streams.open()];
        // Past the local bound, the single allowed connection still serves.
        assert_eq!(
            spread.choose(std::iter::once((&first, &streams))),
            Choice::Use(0)
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_full_connection_opens_another_up_to_the_limit() -> TestResult {
        let (first, _first_peer) = connection().await?;
        let (second, _second_peer) = connection().await?;
        let (first_streams, second_streams) = (StreamCount::default(), StreamCount::default());
        let mut spread = Http2Spread::new(bound(2)?, bound(2)?);

        let first_held = [first_streams.open(), first_streams.open()];
        let one = [(&first, &first_streams)];
        assert_eq!(spread.choose(one.into_iter()), Choice::Open);

        let two = [(&first, &first_streams), (&second, &second_streams)];
        assert_eq!(spread.choose(two.into_iter()), Choice::Use(1));
        let _second_first = second_streams.open();
        assert_eq!(spread.choose(two.into_iter()), Choice::Use(1));
        let _second_full = second_streams.open();
        // Both are full and the key is at its limit: the least loaded, then
        // the oldest, takes the stream.
        assert_eq!(spread.choose(two.into_iter()), Choice::Use(0));
        drop(first_held);
        assert_eq!(spread.choose(two.into_iter()), Choice::Use(0));
        Ok(())
    }
}
