use std::{
    fmt, io,
    num::NonZeroUsize,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio::sync::watch;

const RECORD_SEPARATOR: u8 = 0x1e;

/// In-memory bounded capture of one QUIC connection's qlog records.
///
/// Snapshots contain only complete JSON-SEQ records. Once the byte bound is
/// reached, records that do not fit are discarded and [`Self::truncated`]
/// becomes true.
#[derive(Clone)]
pub struct QlogCapture {
    inner: Arc<CaptureInner>,
}

impl QlogCapture {
    /// Creates a capture that stores at most `max_bytes` bytes.
    #[must_use]
    pub fn new(max_bytes: NonZeroUsize) -> Self {
        let (completion, _) = watch::channel(false);
        Self {
            inner: Arc::new(CaptureInner {
                max_bytes,
                attached: AtomicBool::new(false),
                complete: AtomicBool::new(false),
                completion,
                state: Mutex::new(CaptureState::default()),
            }),
        }
    }

    /// Returns the maximum number of bytes retained by this capture.
    #[must_use]
    pub fn max_bytes(&self) -> NonZeroUsize {
        self.inner.max_bytes
    }

    /// Returns a point-in-time copy of all complete JSON-SEQ records.
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        lock_state(&self.inner).output.clone()
    }

    /// Returns whether at least one record was discarded because it did not fit.
    #[must_use]
    pub fn truncated(&self) -> bool {
        lock_state(&self.inner).truncated
    }

    /// Returns whether the attached qlog writer has been dropped.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.inner.complete.load(Ordering::Acquire)
    }

    /// Waits until the attached qlog writer has been dropped.
    pub async fn wait_complete(&self) {
        if self.is_complete() {
            return;
        }

        let mut completion = self.inner.completion.subscribe();
        while !self.is_complete() {
            if completion.changed().await.is_err() {
                return;
            }
        }
    }

    pub(super) fn attach(&self) -> Result<quinn::QlogStream, QlogCaptureError> {
        self.inner
            .attached
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| QlogCaptureError::AlreadyAttached)?;

        let mut config = quinn::QlogConfig::default();
        config.writer(Box::new(CaptureWriter {
            inner: Arc::clone(&self.inner),
        }));
        config
            .into_stream()
            .ok_or(QlogCaptureError::InitializationFailed)
    }
}

impl fmt::Debug for QlogCapture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let state = lock_state(&self.inner);
        formatter
            .debug_struct("QlogCapture")
            .field("max_bytes", &self.max_bytes())
            .field("bytes", &state.output.len())
            .field("truncated", &state.truncated)
            .field("complete", &self.is_complete())
            .finish()
    }
}

/// Failure to attach a bounded qlog capture to a QUIC connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum QlogCaptureError {
    /// This capture has already been attached to a connection.
    AlreadyAttached,
    /// Quinn could not initialize the qlog stream.
    InitializationFailed,
}

impl fmt::Display for QlogCaptureError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::AlreadyAttached => "qlog capture is already attached to a connection",
            Self::InitializationFailed => "failed to initialize the qlog stream",
        })
    }
}

impl std::error::Error for QlogCaptureError {}

struct CaptureInner {
    max_bytes: NonZeroUsize,
    attached: AtomicBool,
    complete: AtomicBool,
    completion: watch::Sender<bool>,
    state: Mutex<CaptureState>,
}

#[derive(Default)]
struct CaptureState {
    output: Vec<u8>,
    pending: Vec<u8>,
    saturated: bool,
    truncated: bool,
}

impl CaptureState {
    fn write(&mut self, max_bytes: usize, bytes: &[u8]) {
        for &byte in bytes {
            self.write_byte(max_bytes, byte);
        }
    }

    fn write_byte(&mut self, max_bytes: usize, byte: u8) {
        if self.saturated {
            return;
        }

        if self.pending.is_empty() {
            if byte == RECORD_SEPARATOR {
                self.begin_record(max_bytes);
            } else {
                self.truncated = true;
            }
            return;
        }

        if byte == RECORD_SEPARATOR {
            self.pending.clear();
            self.saturated = true;
            self.truncated = true;
            return;
        }

        if self.output.len() + self.pending.len() == max_bytes {
            self.pending.clear();
            self.saturated = true;
            self.truncated = true;
            return;
        }

        self.pending.push(byte);
        if byte == b'\n' {
            self.output.extend_from_slice(&self.pending);
            self.pending.clear();
        }
    }

    fn begin_record(&mut self, max_bytes: usize) {
        if self.output.len() == max_bytes {
            self.saturated = true;
            self.truncated = true;
        } else {
            self.pending.push(RECORD_SEPARATOR);
        }
    }
}

struct CaptureWriter {
    inner: Arc<CaptureInner>,
}

impl io::Write for CaptureWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = lock_state(&self.inner);
        state.write(self.inner.max_bytes.get(), bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for CaptureWriter {
    fn drop(&mut self) {
        {
            let mut state = lock_state(&self.inner);
            if !state.pending.is_empty() {
                state.pending.clear();
                state.truncated = true;
            }
        }
        self.inner.complete.store(true, Ordering::Release);
        let _ = self.inner.completion.send_replace(true);
    }
}

fn lock_state(inner: &CaptureInner) -> MutexGuard<'_, CaptureState> {
    inner
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use super::*;

    #[test]
    fn stores_only_complete_records_within_the_bound() {
        let capture = QlogCapture::new(
            NonZeroUsize::new(9).unwrap_or_else(|| panic!("test bound is nonzero")),
        );
        let mut writer = CaptureWriter {
            inner: Arc::clone(&capture.inner),
        };

        writer
            .write_all(b"\x1e{\"a\":1}")
            .unwrap_or_else(|error| panic!("record body write failed: {error}"));
        assert!(capture.snapshot().is_empty());
        writer
            .write_all(b"\n")
            .unwrap_or_else(|error| panic!("record terminator write failed: {error}"));
        writer
            .write_all(b"\x1e{\"secret\":true}\n")
            .unwrap_or_else(|error| panic!("oversized record write failed: {error}"));

        assert_eq!(capture.snapshot(), b"\x1e{\"a\":1}\n");
        assert!(capture.truncated());
        assert!(
            !capture
                .snapshot()
                .windows(6)
                .any(|bytes| bytes == b"secret")
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn completion_waits_for_writer_drop() {
        let capture = QlogCapture::new(
            NonZeroUsize::new(1024).unwrap_or_else(|| panic!("test bound is nonzero")),
        );
        let writer = CaptureWriter {
            inner: Arc::clone(&capture.inner),
        };

        assert!(!capture.is_complete());
        drop(writer);
        capture.wait_complete().await;
        assert!(capture.is_complete());
    }

    #[test]
    fn capture_cannot_be_attached_twice() {
        let capture = QlogCapture::new(
            NonZeroUsize::new(4096).unwrap_or_else(|| panic!("test bound is nonzero")),
        );
        let stream = capture
            .attach()
            .unwrap_or_else(|error| panic!("first attachment failed: {error}"));
        let error = match capture.attach() {
            Err(error) => error,
            Ok(_) => panic!("second attachment unexpectedly succeeded"),
        };
        assert_eq!(error, QlogCaptureError::AlreadyAttached);
        drop(stream);
        assert!(capture.is_complete());
    }
}
