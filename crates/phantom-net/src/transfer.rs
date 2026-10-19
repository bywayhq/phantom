//! Optional shared body-byte caps, counters and pacing.

use bytes::Bytes;
use http_body::Frame;
use std::{
    error::Error,
    fmt,
    future::Future,
    num::NonZeroU64,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    pin::Pin,
    sync::{Arc, Mutex, PoisonError},
    task::{Context, Poll},
    time::Duration,
};
use tokio::time::Instant;

/// Optional body-byte caps and rates for a shared [`TransferControl`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransferLimits {
    upload_bytes: Option<u64>,
    download_bytes: Option<u64>,
    upload_rate: Option<NonZeroU64>,
    download_rate: Option<NonZeroU64>,
}

impl TransferLimits {
    /// Creates a policy with no caps or rates.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            upload_bytes: None,
            download_bytes: None,
            upload_rate: None,
            download_rate: None,
        }
    }
    /// Caps uploaded body bytes across all requests and attempts.
    #[must_use]
    pub const fn upload_bytes(mut self, maximum: u64) -> Self {
        self.upload_bytes = Some(maximum);
        self
    }
    /// Caps encoded response-body bytes across all requests and attempts.
    #[must_use]
    pub const fn download_bytes(mut self, maximum: u64) -> Self {
        self.download_bytes = Some(maximum);
        self
    }
    /// Paces upload body data at this many bytes per second.
    #[must_use]
    pub const fn upload_rate(mut self, bytes_per_second: NonZeroU64) -> Self {
        self.upload_rate = Some(bytes_per_second);
        self
    }
    /// Paces encoded response-body data at this many bytes per second.
    #[must_use]
    pub const fn download_rate(mut self, bytes_per_second: NonZeroU64) -> Self {
        self.download_rate = Some(bytes_per_second);
        self
    }
}

/// One transfer direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferDirection {
    /// Request body data passed to protocol writers.
    Upload,
    /// Encoded response body data pulled from protocol readers.
    Download,
}

/// Why a transfer control could not admit more data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum TransferErrorKind {
    /// A shared byte cap or the counter's range was exhausted.
    ByteLimit,
    /// A pacing delay exceeds the clock's range.
    ClockRange,
    /// The caller's Tokio runtime has no usable timer.
    RuntimeUnavailable,
}

/// A transfer cap or pacing failure without request or body contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransferError {
    kind: TransferErrorKind,
    direction: TransferDirection,
}
impl TransferError {
    /// Returns the failure category.
    #[must_use]
    pub const fn kind(self) -> TransferErrorKind {
        self.kind
    }
    /// Returns the affected direction.
    #[must_use]
    pub const fn direction(self) -> TransferDirection {
        self.direction
    }
}
impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} transfer failed: {:?}", self.direction, self.kind)
    }
}
impl Error for TransferError {}

/// Coherent body-byte counters across all requests and attempts.
///
/// Upload counts include repeated bodies and multipart framing. Encoded
/// download counts exclude unread data discarded by a protocol driver.
/// Decoded counts describe data returned by Phantom, also for uncompressed
/// responses. These are not unique application payload or socket-byte counts.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransferSnapshot {
    /// Upload quota reserved, including cancelled paced chunks.
    pub upload_reserved_bytes: u64,
    /// Upload body bytes passed to protocol writers, including resends.
    pub upload_body_bytes: u64,
    /// Encoded download quota reserved, including cancelled paced chunks.
    pub download_reserved_bytes: u64,
    /// Encoded response body bytes passed onward by the control.
    pub download_encoded_bytes: u64,
    /// Decoded response body bytes returned to callers.
    pub download_decoded_bytes: u64,
}

/// Shared optional byte caps, pacing and body-byte counters.
///
/// Clones share both directions. Each paced chunk waits its byte-proportional
/// delay with no initial burst. Cancelling a request preserves its reservation
/// and leaves a gap in the shared schedule. Other streams can still proceed.
/// Caps count reservations, which may exceed delivered bytes after cancellation.
/// Headers, trailers, TLS, proxy overhead and retransmissions are not counted.
/// A protocol may prefetch response data before this control sees it.
#[derive(Clone, Debug)]
pub struct TransferControl(Arc<Control>);
#[derive(Debug)]
struct Control {
    limits: TransferLimits,
    state: Mutex<State>,
}
#[derive(Debug, Default)]
struct State {
    counts: TransferSnapshot,
    upload_next: Option<Instant>,
    download_next: Option<Instant>,
}

impl TransferControl {
    /// Creates independent counters and allowances.
    #[must_use]
    pub fn new(limits: TransferLimits) -> Self {
        Self(Arc::new(Control {
            limits,
            state: Mutex::new(State::default()),
        }))
    }
    /// Returns all counters under one lock.
    #[must_use]
    pub fn snapshot(&self) -> TransferSnapshot {
        self.0
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .counts
    }

    fn reserve(
        &self,
        direction: TransferDirection,
        bytes: usize,
        now: Instant,
    ) -> Result<Option<Instant>, TransferError> {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        let (reserved, maximum, rate, next) = match direction {
            TransferDirection::Upload => (
                state.counts.upload_reserved_bytes,
                self.0.limits.upload_bytes,
                self.0.limits.upload_rate,
                state.upload_next,
            ),
            TransferDirection::Download => (
                state.counts.download_reserved_bytes,
                self.0.limits.download_bytes,
                self.0.limits.download_rate,
                state.download_next,
            ),
        };
        let error = |kind| TransferError { kind, direction };
        let reserved = reserved
            .checked_add(bytes as u64)
            .filter(|value| maximum.is_none_or(|maximum| *value <= maximum))
            .ok_or_else(|| error(TransferErrorKind::ByteLimit))?;
        let deadline = rate
            .filter(|_| bytes != 0)
            .map(|rate| {
                let nanos = (bytes as u128 * 1_000_000_000).div_ceil(u128::from(rate.get()));
                let delay = Duration::from_nanos(
                    u64::try_from(nanos).map_err(|_| error(TransferErrorKind::ClockRange))?,
                );
                next.unwrap_or(now)
                    .max(now)
                    .checked_add(delay)
                    .ok_or_else(|| error(TransferErrorKind::ClockRange))
            })
            .transpose()?;
        match direction {
            TransferDirection::Upload => {
                state.counts.upload_reserved_bytes = reserved;
                state.upload_next = deadline;
            }
            TransferDirection::Download => {
                state.counts.download_reserved_bytes = reserved;
                state.download_next = deadline;
            }
        }
        Ok(deadline)
    }
    fn record(&self, direction: TransferDirection, bytes: usize) {
        let mut state = self.0.state.lock().unwrap_or_else(PoisonError::into_inner);
        let count = match direction {
            TransferDirection::Upload => &mut state.counts.upload_body_bytes,
            TransferDirection::Download => &mut state.counts.download_encoded_bytes,
        };
        *count = count.saturating_add(bytes as u64);
    }
}

/// Internal body adapter shared by the transport and facade crates.
#[doc(hidden)]
pub struct TransferStream {
    control: TransferControl,
    direction: TransferDirection,
    buffered: Bytes,
    admitted: usize,
    // Keep Tokio's timer internals out of nested request-future Send proofs.
    sleep: Option<Pin<Box<dyn Future<Output = ()> + Send + Sync>>>,
    failed: bool,
}
impl TransferStream {
    /// Starts a stream without resetting shared counters or pacing.
    #[must_use]
    pub fn new(control: TransferControl, direction: TransferDirection) -> Self {
        Self {
            control,
            direction,
            buffered: Bytes::new(),
            admitted: 0,
            sleep: None,
            failed: false,
        }
    }
    /// Bytes already pulled from the source but not yet delivered.
    #[must_use]
    pub fn buffered_len(&self) -> usize {
        self.buffered.len()
    }
    /// Records facade output separately from encoded data.
    pub fn record_decoded(&self, bytes: usize) {
        let mut state = self
            .control
            .0
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        state.counts.download_decoded_bytes = state
            .counts
            .download_decoded_bytes
            .saturating_add(bytes as u64);
    }
    /// Records upload data after request framing has accepted it.
    pub fn record_upload(&self, bytes: usize) {
        self.control.record(TransferDirection::Upload, bytes);
    }
    /// Returns a source frame, retaining at most one source data frame.
    pub fn poll_frame<E>(
        &mut self,
        cx: &mut Context<'_>,
        mut source: impl FnMut(&mut Context<'_>) -> Poll<Option<Result<Frame<Bytes>, E>>>,
        error: impl Fn(TransferError) -> E,
    ) -> Poll<Option<Result<Frame<Bytes>, E>>> {
        if self.failed {
            return Poll::Ready(None);
        }
        if self.buffered.is_empty() {
            match source(cx) {
                Poll::Ready(Some(Ok(frame))) => match frame.into_data() {
                    Ok(data) if !data.is_empty() => self.buffered = data,
                    Ok(data) => return Poll::Ready(Some(Ok(Frame::data(data)))),
                    Err(frame) => return Poll::Ready(Some(Ok(frame))),
                },
                other => return other,
            }
        }
        if self.admitted == 0 {
            let rate = match self.direction {
                TransferDirection::Upload => self.control.0.limits.upload_rate,
                TransferDirection::Download => self.control.0.limits.download_rate,
            };
            let length = if rate.is_some() {
                self.buffered.len().min(8192)
            } else {
                self.buffered.len()
            };
            let deadline = match self.control.reserve(self.direction, length, Instant::now()) {
                Ok(deadline) => deadline,
                Err(failure) => return self.fail(error(failure)),
            };
            if let Some(deadline) = deadline {
                match catch_unwind(AssertUnwindSafe(|| tokio::time::sleep_until(deadline))) {
                    Ok(sleep) => self.sleep = Some(Box::pin(sleep)),
                    Err(_) if time_driver_missing() => {
                        return self.fail(error(TransferError {
                            kind: TransferErrorKind::RuntimeUnavailable,
                            direction: self.direction,
                        }));
                    }
                    Err(payload) => resume_unwind(payload),
                }
            }
            self.admitted = length;
        }
        if let Some(sleep) = self.sleep.as_mut() {
            match catch_unwind(AssertUnwindSafe(|| sleep.as_mut().poll(cx))) {
                Ok(Poll::Pending) => return Poll::Pending,
                Ok(Poll::Ready(())) => {}
                Err(_) if time_driver_missing() => {
                    return self.fail(error(TransferError {
                        kind: TransferErrorKind::RuntimeUnavailable,
                        direction: self.direction,
                    }));
                }
                Err(payload) => resume_unwind(payload),
            }
            self.sleep = None;
        }
        let data = self.buffered.split_to(std::mem::take(&mut self.admitted));
        if self.direction == TransferDirection::Download {
            self.control.record(self.direction, data.len());
        }
        Poll::Ready(Some(Ok(Frame::data(data))))
    }
    fn fail<E>(&mut self, error: E) -> Poll<Option<Result<Frame<Bytes>, E>>> {
        self.failed = true;
        self.buffered = Bytes::new();
        self.sleep = None;
        Poll::Ready(Some(Err(error)))
    }
}
impl fmt::Debug for TransferStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransferStream")
            .field("direction", &self.direction)
            .field("buffered_bytes", &self.buffered.len())
            .finish_non_exhaustive()
    }
}

// Tokio has no timer-driver query. As in the facade's deadline timer,
// reproduce a timer failure before attributing a panic to a missing driver.
fn time_driver_missing() -> bool {
    tokio::runtime::Handle::try_current().is_err()
        || catch_unwind(|| drop(tokio::time::sleep_until(Instant::now()))).is_err()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::poll_fn;

    #[test]
    fn concurrent_clones_cannot_overspend_and_independent_controls_stay_separate() {
        let control = TransferControl::new(TransferLimits::new().upload_bytes(32));
        let admitted = std::thread::scope(|scope| {
            let threads: Vec<_> = (0..64)
                .map(|_| {
                    let control = control.clone();
                    scope.spawn(move || {
                        control
                            .reserve(TransferDirection::Upload, 1, Instant::now())
                            .is_ok()
                    })
                })
                .collect();
            threads
                .into_iter()
                .map(|thread| thread.join().is_ok_and(|admitted| admitted))
                .filter(|admitted| *admitted)
                .count()
        });
        assert_eq!(admitted, 32);
        assert_eq!(control.snapshot().upload_reserved_bytes, 32);
        let independent = TransferControl::new(TransferLimits::new().upload_bytes(1));
        assert!(
            independent
                .reserve(TransferDirection::Upload, 1, Instant::now())
                .is_ok()
        );
        assert!(
            control
                .reserve(TransferDirection::Download, 1, Instant::now())
                .is_ok()
        );
    }

    #[test]
    fn shared_pacing_has_no_initial_burst_and_preserves_reserved_gaps() -> Result<(), TransferError>
    {
        let control = TransferControl::new(TransferLimits::new().upload_rate(NonZeroU64::MIN));
        let now = Instant::now();
        assert_eq!(
            control.reserve(TransferDirection::Upload, 2, now)?,
            Some(now + Duration::from_secs(2))
        );
        assert_eq!(
            control.clone().reserve(TransferDirection::Upload, 3, now)?,
            Some(now + Duration::from_secs(5))
        );
        let later = now + Duration::from_secs(10);
        assert_eq!(
            control.reserve(TransferDirection::Upload, 1, later)?,
            Some(later + Duration::from_secs(1))
        );
        Ok(())
    }

    #[tokio::test]
    async fn cancelled_pacing_retains_only_reservation_and_does_not_poll_source_again() {
        let control = TransferControl::new(TransferLimits::new().upload_rate(NonZeroU64::MIN));
        let mut stream = TransferStream::new(control.clone(), TransferDirection::Upload);
        let mut polls = 0;
        let result = poll_fn(|cx| {
            Poll::Ready(stream.poll_frame(
                cx,
                |_| {
                    polls += 1;
                    Poll::Ready(Some(Ok::<_, TransferError>(Frame::data(
                        Bytes::from_static(b"abc"),
                    ))))
                },
                |error| error,
            ))
        })
        .await;
        assert!(result.is_pending());
        assert_eq!(polls, 1);
        assert_eq!(stream.buffered_len(), 3);
        drop(stream);
        assert_eq!(control.snapshot().upload_reserved_bytes, 3);
        assert_eq!(control.snapshot().upload_body_bytes, 0);
    }

    #[tokio::test]
    async fn cap_failure_is_terminal_and_drops_pending_data() {
        let control = TransferControl::new(TransferLimits::new().download_bytes(2));
        let mut stream = TransferStream::new(control.clone(), TransferDirection::Download);
        let result = poll_fn(|cx| {
            stream.poll_frame(
                cx,
                |_| {
                    Poll::Ready(Some(Ok::<_, TransferError>(Frame::data(
                        Bytes::from_static(b"abc"),
                    ))))
                },
                |error| error,
            )
        })
        .await;
        assert!(
            matches!(result, Some(Err(error)) if error.kind() == TransferErrorKind::ByteLimit && error.direction() == TransferDirection::Download)
        );
        assert_eq!(stream.buffered_len(), 0);
        let end = poll_fn(|cx| {
            stream.poll_frame(
                cx,
                |_| panic!("failed stream polled its source"),
                |error| error,
            )
        })
        .await;
        assert!(end.is_none());
        assert_eq!(control.snapshot(), TransferSnapshot::default());
    }

    #[tokio::test]
    async fn rejected_upload_length_consumes_reservation_but_records_no_handoff() {
        use http_body::{Body, SizeHint};
        struct Oversized;
        impl Body for Oversized {
            type Data = Bytes;
            type Error = std::io::Error;
            fn poll_frame(
                self: Pin<&mut Self>,
                _: &mut Context<'_>,
            ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"xx")))))
            }
            fn size_hint(&self) -> SizeHint {
                SizeHint::with_exact(1)
            }
        }
        let control = TransferControl::new(TransferLimits::new());
        let mut body = crate::request::RequestBody::streaming(Oversized)
            .with_transfer_control(control.clone());
        let result = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await;
        assert!(
            matches!(result, Some(Err(error)) if error.kind() == crate::request::RequestBodyErrorKind::LengthMismatch)
        );
        assert_eq!(control.snapshot().upload_reserved_bytes, 2);
        assert_eq!(control.snapshot().upload_body_bytes, 0);
    }

    #[tokio::test]
    async fn paced_chunks_preserve_data_and_trailers_without_early_end()
    -> Result<(), Box<dyn Error>> {
        let control = TransferControl::new(
            TransferLimits::new().download_rate(NonZeroU64::new(1_000_000).ok_or("rate absent")?),
        );
        let mut stream = TransferStream::new(control.clone(), TransferDirection::Download);
        let mut source = Some(Bytes::from(vec![b'x'; 20_000]));
        let mut received = 0;
        while received < 20_000 {
            let frame = poll_fn(|cx| {
                stream.poll_frame(
                    cx,
                    |_| {
                        Poll::Ready(
                            source
                                .take()
                                .map(|data| Ok::<_, TransferError>(Frame::data(data))),
                        )
                    },
                    |error| error,
                )
            })
            .await
            .ok_or("data ended early")??;
            let bytes = frame.into_data().map_err(|_| "unexpected trailers")?;
            assert!(bytes.len() <= 8192);
            assert!(bytes.iter().all(|byte| *byte == b'x'));
            received += bytes.len();
            assert_eq!(stream.buffered_len(), 20_000 - received);
        }
        let frame = poll_fn(|cx| {
            stream.poll_frame(
                cx,
                |_| {
                    Poll::Ready(Some(Ok::<_, TransferError>(Frame::trailers(
                        http::HeaderMap::new(),
                    ))))
                },
                |error| error,
            )
        })
        .await
        .ok_or("trailers absent")??;
        assert!(frame.is_trailers());
        assert_eq!(control.snapshot().download_encoded_bytes, 20_000);
        Ok(())
    }
}
