//! A streaming request body kept while it is sent, so a later attempt of the
//! same request can send it again.
//!
//! Each attempt reads through its own cursor. A cursor first sends the frames
//! kept from earlier attempts and then reads on from the source where the
//! last attempt stopped, so a replay works whether the failed attempt sent
//! none, part, or all of the body, and the first attempt is never delayed.
//! Data beyond the caller's limit is passed on but not kept, and the body can
//! then not be sent again. Chromium keeps a streaming upload the same way,
//! within a window, and replays it before reading on
//! (`ChunkedDataPipeUploadDataStream::EnableCache`,
//! `services/network/chunked_data_pipe_upload_data_stream.cc` lines 61-68
//! and 257-301 at 154.0.8037.58).

use std::{
    collections::VecDeque,
    error::Error as StdError,
    fmt,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
};

use bytes::Bytes;
use http::HeaderMap;
use http_body::{Body, Frame, SizeHint};
use phantom_net::request::{RequestBody, RequestTrailerName};
use tracing::debug;

type BoxError = Box<dyn StdError + Send + Sync>;
type Source = Pin<Box<dyn Body<Data = Bytes, Error = BoxError> + Send>>;

/// The owner of a buffered body, held by the request for its whole send.
///
/// Dropping it stops keeping frames, so the memory goes once the request is
/// done even while an upload that outlived it still reads.
pub(crate) struct ReplayBuffer {
    shared: Arc<Mutex<Shared>>,
    size_hint: SizeHint,
    trailer_names: Vec<RequestTrailerName>,
}

/// Why a buffered body cannot start another attempt.
pub(crate) enum NoReplay {
    /// The source failed; its error went to the attempt that read it.
    Failed,
    /// More data than the limit was read, so not all of it was kept.
    Exhausted,
}

struct Shared {
    source: Source,
    /// Kept data frames; the first is frame number `first_frame`.
    frames: VecDeque<Bytes>,
    first_frame: usize,
    /// Data frames read from the source so far.
    pulled: usize,
    kept_bytes: usize,
    maximum_bytes: usize,
    trailers: Option<HeaderMap>,
    end: End,
    retention: Retention,
    /// The attempt allowed to read; older cursors fail.
    generation: u64,
    /// The number of the next data frame the current attempt sends.
    cursor: usize,
    /// The task that last waited on the source, woken when a later attempt
    /// takes over so its transport sees that at once.
    waiting: Option<Waker>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum End {
    Open,
    Ended,
    Failed,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Retention {
    Keeping,
    Exhausted,
    Released,
}

impl ReplayBuffer {
    pub(crate) fn new<B>(
        body: B,
        trailer_names: Vec<RequestTrailerName>,
        maximum_bytes: usize,
    ) -> Self
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: StdError + Send + Sync + 'static,
    {
        let size_hint = body.size_hint();
        Self {
            shared: Arc::new(Mutex::new(Shared {
                source: Box::pin(BoxedErrors(Box::pin(body))),
                frames: VecDeque::new(),
                first_frame: 0,
                pulled: 0,
                kept_bytes: 0,
                maximum_bytes,
                trailers: None,
                end: End::Open,
                retention: Retention::Keeping,
                generation: 0,
                cursor: 0,
                waiting: None,
            })),
            size_hint,
            trailer_names,
        }
    }

    /// Returns why no further attempt can send the body, if one cannot.
    pub(crate) fn no_replay(&self) -> Option<NoReplay> {
        let shared = lock(&self.shared);
        if shared.end == End::Failed {
            Some(NoReplay::Failed)
        } else if shared.retention == Retention::Exhausted {
            Some(NoReplay::Exhausted)
        } else {
            None
        }
    }

    /// Starts an attempt: every earlier cursor stops, and the new one sends
    /// the body from its first byte.
    pub(crate) fn next_attempt(&self) -> Result<RequestBody, NoReplay> {
        self.start().map(|cursor| self.wrap(cursor))
    }

    fn start(&self) -> Result<BufferedAttempt, NoReplay> {
        if let Some(reason) = self.no_replay() {
            return Err(reason);
        }
        let generation = {
            let mut shared = lock(&self.shared);
            shared.generation += 1;
            shared.cursor = 0;
            if let Some(waiting) = shared.waiting.take() {
                waiting.wake();
            }
            shared.generation
        };
        Ok(BufferedAttempt {
            shared: Arc::clone(&self.shared),
            generation,
            exact_length: self.size_hint.exact(),
            size_hint: self.size_hint,
            next_frame: 0,
            yielded_bytes: 0,
            trailers_sent: false,
        })
    }

    /// Returns a body with this body's framing that is never read, for
    /// building an attempt's fields before any attempt starts.
    pub(crate) fn metadata_body(&self) -> RequestBody {
        self.wrap(Unread(self.size_hint))
    }

    pub(crate) fn has_trailers(&self) -> bool {
        !self.trailer_names.is_empty()
    }

    pub(crate) fn exact_length(&self) -> Option<u64> {
        self.size_hint.exact()
    }

    fn wrap<B>(&self, body: B) -> RequestBody
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: StdError + Send + Sync + 'static,
    {
        if self.trailer_names.is_empty() {
            RequestBody::streaming(body)
        } else {
            RequestBody::streaming_with_trailers(body, self.trailer_names.clone())
        }
    }
}

impl Drop for ReplayBuffer {
    fn drop(&mut self) {
        let mut shared = lock(&self.shared);
        if shared.retention == Retention::Keeping {
            shared.retention = Retention::Released;
            shared.release_read();
        }
    }
}

/// One attempt's reader of a [`ReplayBuffer`].
struct BufferedAttempt {
    shared: Arc<Mutex<Shared>>,
    generation: u64,
    exact_length: Option<u64>,
    size_hint: SizeHint,
    /// The number of the next data frame this attempt sends.
    next_frame: usize,
    yielded_bytes: u64,
    trailers_sent: bool,
}

impl Body for BufferedAttempt {
    type Data = Bytes;
    type Error = BufferedBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BufferedBodyError>>> {
        let this = self.get_mut();
        let owner = Arc::clone(&this.shared);
        let mut shared = lock(&owner);
        // A superseded attempt fails rather than ends, so its transport
        // never completes a request whose body it did not send in full.
        if shared.generation != this.generation {
            return Poll::Ready(Some(Err(BufferedBodyError::Superseded)));
        }
        if this.next_frame < shared.pulled {
            let Some(frame) = this
                .next_frame
                .checked_sub(shared.first_frame)
                .and_then(|index| shared.frames.get(index).cloned())
            else {
                return Poll::Ready(Some(Err(BufferedBodyError::Superseded)));
            };
            this.next_frame += 1;
            shared.cursor = this.next_frame;
            shared.release_read();
            this.yielded_bytes += frame.len() as u64;
            return Poll::Ready(Some(Ok(Frame::data(frame))));
        }
        match shared.end {
            End::Ended => return Poll::Ready(this.kept_trailers(&shared).map(Ok)),
            End::Failed => return Poll::Ready(Some(Err(BufferedBodyError::Superseded))),
            End::Open => {}
        }
        match shared.source.as_mut().poll_frame(context) {
            Poll::Pending => {
                shared.waiting = Some(context.waker().clone());
                Poll::Pending
            }
            Poll::Ready(None) => {
                shared.end = End::Ended;
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(error))) => {
                shared.end = End::Failed;
                Poll::Ready(Some(Err(BufferedBodyError::Source(error))))
            }
            Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    shared.keep(&data);
                    this.next_frame = shared.pulled;
                    shared.cursor = this.next_frame;
                    this.yielded_bytes += data.len() as u64;
                    Poll::Ready(Some(Ok(Frame::data(data))))
                }
                Err(frame) => match frame.into_trailers() {
                    Ok(trailers) => {
                        shared.trailers = Some(trailers.clone());
                        shared.end = End::Ended;
                        this.trailers_sent = true;
                        Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                    }
                    // A frame that is neither data nor trailers carries
                    // nothing to send.
                    Err(_) => {
                        context.waker().wake_by_ref();
                        Poll::Pending
                    }
                },
            },
        }
    }

    // A source whose own end-of-stream signal comes only with its last poll
    // makes the first attempt end HTTP/2 with an empty DATA frame, where a
    // replay ends with its last kept frame; the data sent is the same.
    fn is_end_stream(&self) -> bool {
        let shared = lock(&self.shared);
        if shared.generation != self.generation || self.next_frame < shared.pulled {
            return false;
        }
        match shared.end {
            End::Ended => shared.trailers.is_none() || self.trailers_sent,
            End::Failed => false,
            End::Open => shared.source.is_end_stream(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self.exact_length {
            Some(length) => SizeHint::with_exact(length.saturating_sub(self.yielded_bytes)),
            None => self.size_hint,
        }
    }
}

impl BufferedAttempt {
    /// Returns the source's trailers once, after every data frame.
    fn kept_trailers(&mut self, shared: &Shared) -> Option<Frame<Bytes>> {
        if self.trailers_sent {
            return None;
        }
        self.trailers_sent = true;
        shared.trailers.clone().map(Frame::trailers)
    }
}

impl Shared {
    /// Counts a data frame read from the source and keeps it while the
    /// limit allows.
    fn keep(&mut self, data: &Bytes) {
        self.pulled += 1;
        match self.retention {
            Retention::Keeping
                if self.kept_bytes.saturating_add(data.len()) <= self.maximum_bytes =>
            {
                self.kept_bytes += data.len();
                self.frames.push_back(data.clone());
            }
            Retention::Keeping => {
                self.retention = Retention::Exhausted;
                self.frames.clear();
                self.kept_bytes = 0;
                self.first_frame = self.pulled;
                debug!(
                    maximum_bytes = self.maximum_bytes,
                    "request body exceeded its replay limit; it will not be sent again"
                );
            }
            Retention::Exhausted | Retention::Released => {
                self.frames.clear();
                self.kept_bytes = 0;
                self.first_frame = self.pulled;
            }
        }
    }

    /// Once the owner is gone, frees the kept frames the current attempt has
    /// already sent; no later attempt can need them.
    fn release_read(&mut self) {
        if self.retention != Retention::Released {
            return;
        }
        while self.first_frame < self.cursor {
            let Some(frame) = self.frames.pop_front() else {
                self.first_frame = self.cursor;
                break;
            };
            self.kept_bytes = self.kept_bytes.saturating_sub(frame.len());
            self.first_frame += 1;
        }
    }
}

/// An error of a buffered body's attempt.
#[derive(Debug)]
enum BufferedBodyError {
    /// The caller's body failed.
    Source(BoxError),
    /// A later attempt took the body over, or the source failed in an
    /// earlier read.
    Superseded,
}

impl fmt::Display for BufferedBodyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(_) => formatter.write_str("buffered request body source failed"),
            Self::Superseded => {
                formatter.write_str("a later attempt took over the buffered request body")
            }
        }
    }
}

impl StdError for BufferedBodyError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Self::Source(error) => Some(&**error),
            Self::Superseded => None,
        }
    }
}

/// The caller's body with its error boxed.
struct BoxedErrors<B>(Pin<Box<B>>);

impl<B> Body for BoxedErrors<B>
where
    B: Body<Data = Bytes>,
    B::Error: StdError + Send + Sync + 'static,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        self.0
            .as_mut()
            .poll_frame(context)
            .map(|frame| frame.map(|frame| frame.map_err(Into::into)))
    }

    fn is_end_stream(&self) -> bool {
        self.0.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.0.size_hint()
    }
}

/// A body with a size hint that is never polled.
struct Unread(SizeHint);

impl Body for Unread {
    type Data = Bytes;
    type Error = BufferedBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BufferedBodyError>>> {
        Poll::Ready(Some(Err(BufferedBodyError::Superseded)))
    }

    fn size_hint(&self) -> SizeHint {
        self.0
    }
}

/// Locks the shared state. Only the caller's body can panic under the lock,
/// so a poisoned lock marks the source failed and no attempt reads it again.
fn lock(shared: &Mutex<Shared>) -> MutexGuard<'_, Shared> {
    match shared.lock() {
        Ok(shared) => shared,
        Err(poisoned) => {
            let mut shared = poisoned.into_inner();
            shared.end = End::Failed;
            shared
        }
    }
}

#[cfg(test)]
mod tests;
