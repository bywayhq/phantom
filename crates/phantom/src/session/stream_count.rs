//! Counting the streams in flight on one pooled multiplexed connection.
//!
//! The HTTP/2 and HTTP/3 pools count a stream from the moment a request
//! leases its connection until the response body ends or is dropped, and
//! compare the count with the peer's stream limit when choosing a
//! connection.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use tokio::sync::Notify;

/// The streams in flight on one pooled HTTP/2 or HTTP/3 connection.
#[derive(Clone, Debug, Default)]
pub(super) struct StreamCount {
    count: Arc<AtomicUsize>,
    /// Woken when a stream ends, so a request waiting for a connection setup
    /// can take the room that stream freed instead.
    ended: Option<Arc<Notify>>,
}

impl StreamCount {
    /// Counts streams and wakes `ended`'s waiters whenever one ends.
    pub(super) fn notifying(ended: Arc<Notify>) -> Self {
        Self {
            count: Arc::default(),
            ended: Some(ended),
        }
    }

    pub(super) fn get(&self) -> usize {
        self.count.load(Ordering::Acquire)
    }

    /// Counts one more stream until the returned guard drops.
    pub(super) fn open(&self) -> OpenStream {
        self.count.fetch_add(1, Ordering::AcqRel);
        OpenStream {
            count: Arc::clone(&self.count),
            ended: self.ended.clone(),
        }
    }
}

/// One stream counted against its connection until it ends.
#[derive(Debug)]
pub(super) struct OpenStream {
    count: Arc<AtomicUsize>,
    ended: Option<Arc<Notify>>,
}

impl Drop for OpenStream {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
        if let Some(ended) = &self.ended {
            ended.notify_waiters();
        }
    }
}
