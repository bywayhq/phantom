//! TLS 1.3 early data on a resumed TCP connection.
//!
//! The handshake returns once the ClientHello is sent, and the protocol layer
//! writes through the stream as usual: BoringSSL sends those bytes as early
//! data until the server answers. If the server accepts, nothing changes. If it
//! rejects, it processed none of them; the stream finishes the handshake and
//! writes the same bytes again before anything else, so the protocol layer
//! never sees the rejection. Firefox 157 does the same on the same connection:
//! HTTP/1.1 rewinds its request stream (`nsHttpTransaction::Finish0RTT`,
//! `netwerk/protocol/http/nsHttpTransaction.cpp:3414-3424` at tag
//! `FIREFOX_157_0_RELEASE`) and HTTP/2 resends its output queue from the
//! connection preface (`Http2Session::Finish0RTT`,
//! `netwerk/protocol/http/Http2Session.cpp:3384-3393`).
//!
//! A server that selects another ALPN protocol after a rejection would need a
//! different protocol on this connection, so the stream fails instead.

use std::{
    error::Error as StdError,
    fmt, io,
    pin::Pin,
    sync::{Arc, Mutex},
    task::{Context, Poll, ready},
};

use btls::ssl::ErrorCode;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::watch,
};
use tracing::debug;

use super::{TlsStream, session_cache::TlsSessionCapture, trace_alpn};

/// Early data written on a connection whose server has not answered it.
pub(super) struct EarlyData {
    /// Every byte written as early data, in order, to send again after a
    /// rejection.
    sent: Vec<u8>,
    phase: Phase,
    /// The resumed session's ALPN protocol, from which the protocol layer
    /// chose its HTTP version.
    alpn: Option<Box<[u8]>>,
    /// Tickets issued on this connection, held until the handshake completes.
    session_capture: Option<TlsSessionCapture>,
    answer: watch::Sender<Answer>,
    attempts: Arc<Mutex<ReplayAttempts>>,
}

#[derive(Debug, Default)]
struct ReplayAttempts {
    closed: bool,
    registrations: Vec<ReplayRegistration>,
}

#[derive(Debug)]
struct ReplayRegistration {
    budget: Option<crate::HttpAttemptBudget>,
    observation: Option<crate::request_diagnostics::Observation>,
}

impl ReplayAttempts {
    fn admit(&mut self) -> Result<(), crate::HttpAttemptBudgetExhausted> {
        self.closed = true;
        // Admission may conservatively spend some allowances even when another
        // request blocks replay of the connection's shared early-data buffer.
        let registrations = std::mem::take(&mut self.registrations);
        for registration in registrations {
            if let Some(budget) = registration.budget {
                budget.try_admit()?;
            }
            if let Some(observation) = registration.observation {
                observation.admit_replay();
            }
        }
        Ok(())
    }

    fn clear(&mut self) {
        self.closed = true;
        self.registrations.clear();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    /// The server has not answered yet.
    Unanswered,
    /// The server rejected the early data; the handshake is being completed.
    Restarting,
    /// The handshake completed after a rejection; `written` bytes of the early
    /// data have been sent again.
    Resending { written: usize },
}

#[derive(Clone, Debug)]
enum Answer {
    Unanswered,
    /// The handshake completed, and any rejected early data was sent again.
    Settled,
    /// The connection failed: during the handshake when the failure is
    /// known, or afterwards, while sending rejected early data again.
    Failed(Option<EarlyDataFailure>),
}

/// Why a connection that sent early data failed before its handshake
/// completed, so the protocol layer can report what a fresh connection would.
#[derive(Clone, Debug)]
pub(crate) enum EarlyDataFailure {
    /// The handshake failed, after a rejection or without one.
    Handshake {
        error: Arc<io::Error>,
        pin_verification: btls::ssl::SpkiPinVerification,
    },
    /// The server rejected the early data and then selected another ALPN
    /// protocol. The server processed no request on the connection.
    AlpnChanged {
        /// The ALPN protocol the server selected, if any.
        negotiated: Option<Box<[u8]>>,
    },
}

impl EarlyDataFailure {
    /// Returns the TLS error a fresh connection reports for a handshake
    /// failure, or `None` for an ALPN change.
    pub(crate) fn tls_error(&self) -> Option<super::TlsError> {
        match self {
            Self::Handshake {
                error,
                pin_verification,
            } => Some(
                super::TlsError::after_early_data(SharedError(Arc::clone(error)))
                    .with_pin_verification(*pin_verification),
            ),
            Self::AlpnChanged { .. } => None,
        }
    }
}

/// One handshake error shared by the stream's caller and every request that
/// waited on the early data.
///
/// Its message is fixed and its source is the error the handshake reported,
/// the BoringSSL error when there is one, so a printed chain names that error
/// once.
#[derive(Debug)]
struct SharedError(Arc<io::Error>);

impl fmt::Display for SharedError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the connection's TLS handshake failed")
    }
}

impl StdError for SharedError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self.0.get_ref() {
            Some(inner) => Some(inner),
            None => Some(&*self.0),
        }
    }
}

impl EarlyData {
    pub(super) fn new(alpn: Option<Box<[u8]>>, session_capture: Option<TlsSessionCapture>) -> Self {
        Self {
            sent: Vec::new(),
            phase: Phase::Unanswered,
            alpn,
            session_capture,
            answer: watch::Sender::new(Answer::Unanswered),
            attempts: Arc::new(Mutex::new(ReplayAttempts::default())),
        }
    }

    pub(super) fn wait(&self) -> EarlyDataWait {
        EarlyDataWait {
            answer: self.answer.subscribe(),
            attempts: Arc::clone(&self.attempts),
        }
    }
}

impl Drop for EarlyData {
    fn drop(&mut self) {
        // Connection waiters can outlive a cancelled TLS driver. They must
        // not retain request collectors or allowances after replay is gone.
        self.attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
    }
}

/// Tells a protocol layer when the server answers a connection's early data.
///
/// A request that is not replay safe ([`crate::request::is_replay_safe`])
/// waits for [`Self::answered`] before it is written, as Firefox holds such a
/// request until the handshake completes.
#[derive(Clone, Debug)]
pub(crate) struct EarlyDataWait {
    answer: watch::Receiver<Answer>,
    attempts: Arc<Mutex<ReplayAttempts>>,
}

impl EarlyDataWait {
    pub(crate) fn register_attempt(&self, budget: Option<&crate::HttpAttemptBudget>) {
        let observation = crate::request_diagnostics::Observation::current();
        if budget.is_none() && observation.is_none() {
            return;
        }
        let mut attempts = self
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !attempts.closed {
            attempts.registrations.push(ReplayRegistration {
                budget: budget.cloned(),
                observation,
            });
        }
    }

    /// Waits until the handshake completes and any rejected early data has
    /// been sent again.
    ///
    /// # Errors
    ///
    /// Fails when the handshake fails or the connection is dropped first.
    pub(crate) async fn answered(&self) -> io::Result<()> {
        let mut receiver = self.answer.clone();
        let answer = receiver
            .wait_for(|answer| !matches!(answer, Answer::Unanswered))
            .await
            .map(|answer| matches!(*answer, Answer::Settled));
        match answer {
            Ok(true) => Ok(()),
            Ok(false) | Err(_) => Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "the TLS handshake did not complete after early data",
            )),
        }
    }

    /// Returns whether the server has not answered the early data yet and the
    /// connection is still open.
    pub(crate) fn is_pending(&self) -> bool {
        matches!(*self.answer.borrow(), Answer::Unanswered) && self.answer.has_changed().is_ok()
    }

    /// Returns why the connection failed before its handshake completed, if
    /// it did.
    pub(crate) fn failure(&self) -> Option<EarlyDataFailure> {
        match &*self.answer.borrow() {
            Answer::Failed(failure) => failure.clone(),
            Answer::Unanswered | Answer::Settled => None,
        }
    }

    /// Returns whether the server rejected the early data and then selected
    /// another ALPN protocol, which failed the connection. The server
    /// processed none of its requests.
    pub(crate) fn alpn_changed(&self) -> bool {
        matches!(
            *self.answer.borrow(),
            Answer::Failed(Some(EarlyDataFailure::AlpnChanged { .. }))
        )
    }
}

/// The server rejected early data, then selected a different ALPN protocol
/// from the one the resumed session had.
#[derive(Debug)]
struct AlpnChangedAfterRejection {
    early: Option<Box<[u8]>>,
    negotiated: Option<Box<[u8]>>,
}

impl fmt::Display for AlpnChangedAfterRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the server rejected early data sent for {} ALPN and then selected {}",
            trace_alpn(self.early.as_deref()),
            trace_alpn(self.negotiated.as_deref())
        )
    }
}

impl StdError for AlpnChangedAfterRejection {}

impl<S> TlsStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub(super) fn poll_read_early(
        &mut self,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            ready!(self.poll_restart(context))?;
            let before = buffer.filled().len();
            let had_room = buffer.remaining() > 0;
            let result = Pin::new(&mut self.inner).poll_read(context, buffer);
            if self.take_rejection(&result) {
                continue;
            }
            let result = self.observe(result);
            // The peer closed the connection before the handshake completed.
            if matches!(result, Poll::Ready(Ok(())))
                && had_room
                && buffer.filled().len() == before
                && self.early_data.is_some()
            {
                let error = io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the server closed the connection during the TLS handshake",
                );
                self.fail_handshake(error);
            }
            return result;
        }
    }

    pub(super) fn poll_write_early(
        &mut self,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            ready!(self.poll_restart(context))?;
            let result = Pin::new(&mut self.inner).poll_write(context, buffer);
            if self.take_rejection(&result) {
                continue;
            }
            // With partial writes enabled, one successful write is either all
            // early data or all application data, and the handshake is still
            // pending after an early one.
            if let (Poll::Ready(Ok(written)), Some(early)) = (&result, self.early_data.as_mut())
                && early.phase == Phase::Unanswered
                && self.inner.ssl().in_early_data()
            {
                early.sent.extend_from_slice(&buffer[..*written]);
            }
            return self.observe(result);
        }
    }

    /// Finishes the handshake after a rejection and sends the early data
    /// again. Ready at once when the server has not answered.
    pub(super) fn poll_restart(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let Some(early) = self.early_data.as_mut() else {
                return Poll::Ready(Ok(()));
            };
            match early.phase {
                Phase::Unanswered => return Poll::Ready(Ok(())),
                Phase::Restarting => {
                    match ready!(Pin::new(&mut self.inner).poll_do_handshake(context)) {
                        Ok(()) => {}
                        Err(error) => {
                            let error = error.into_io_error().unwrap_or_else(io::Error::other);
                            return Poll::Ready(Err(self.fail_handshake(error)));
                        }
                    }
                    let negotiated = self.inner.ssl().selected_alpn_protocol();
                    if negotiated != early.alpn.as_deref() {
                        let negotiated = negotiated.map(Box::from);
                        let error = AlpnChangedAfterRejection {
                            early: early.alpn.take(),
                            negotiated: negotiated.clone(),
                        };
                        debug!(%error, "TLS connection failed after early data");
                        let error = io::Error::new(io::ErrorKind::InvalidData, error);
                        let failure = EarlyDataFailure::AlpnChanged { negotiated };
                        return Poll::Ready(Err(self.fail_with(error, Some(failure))));
                    }
                    let admitted = early
                        .attempts
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner)
                        .admit();
                    if let Err(error) = admitted {
                        return Poll::Ready(Err(self.fail_handshake(io::Error::other(error))));
                    }
                    early.phase = Phase::Resending { written: 0 };
                }
                Phase::Resending { written } if written == early.sent.len() => self.settle(),
                Phase::Resending { written } => {
                    let unsent = &early.sent[written..];
                    match ready!(Pin::new(&mut self.inner).poll_write(context, unsent)) {
                        Ok(0) => {
                            let error = io::Error::from(io::ErrorKind::WriteZero);
                            return Poll::Ready(Err(self.fail(error)));
                        }
                        Ok(count) => {
                            early.phase = Phase::Resending {
                                written: written + count,
                            };
                        }
                        Err(error) => return Poll::Ready(Err(self.fail(error))),
                    }
                }
            }
        }
    }

    /// Resets the connection when `result` reports that the server rejected
    /// the early data, so the next [`Self::poll_restart`] completes it.
    fn take_rejection<T>(&mut self, result: &Poll<io::Result<T>>) -> bool {
        let Poll::Ready(Err(error)) = result else {
            return false;
        };
        let Some(early) = self.early_data.as_mut() else {
            return false;
        };
        if early.phase != Phase::Unanswered
            || !is_rejection(error)
            || !self.inner.ssl_mut().reset_early_data_reject()
        {
            return false;
        }
        debug!(
            early_data_bytes = early.sent.len(),
            "TLS early data rejected; completing the handshake to send it again"
        );
        early.phase = Phase::Restarting;
        // Requests registered from now on will wait behind the TLS replay and
        // send only after the handshake, rather than joining the early buffer.
        early
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .closed = true;
        true
    }

    /// Settles the early data once a read or write completed the handshake,
    /// and releases waiting requests when it failed.
    fn observe<T>(&mut self, result: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        match result {
            Poll::Ready(Err(error)) if self.inner.ssl().is_init_finished() => {
                Poll::Ready(Err(self.fail(error)))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail_handshake(error))),
            result => {
                if self.inner.ssl().is_init_finished() {
                    self.settle();
                }
                result
            }
        }
    }

    fn settle(&mut self) {
        let Some(early) = self.early_data.take() else {
            return;
        };
        let accepted = self.inner.ssl().early_data_accepted();
        early
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        self.refresh_negotiated();
        if let Some(capture) = &early.session_capture {
            // Portable proof requires native completion; local caching is independent.
            let _ = self.inner.ssl().authenticate_scoped_session_publication();
            capture.commit_authenticated();
        }
        debug!(
            accepted,
            early_data_bytes = early.sent.len(),
            negotiated_alpn = trace_alpn(self.negotiated_alpn.as_deref()),
            "TLS early data answered"
        );
        early.answer.send_replace(Answer::Settled);
    }

    /// Fails the connection after its handshake completed.
    fn fail(&mut self, error: io::Error) -> io::Error {
        self.fail_with(error, None)
    }

    /// Fails the handshake and shares the error with the waiting requests.
    fn fail_handshake(&mut self, error: io::Error) -> io::Error {
        if self.early_data.is_none() {
            return error;
        }
        let kind = error.kind();
        let error = Arc::new(error);
        let failure = EarlyDataFailure::Handshake {
            error: Arc::clone(&error),
            pin_verification: self.inner.ssl().spki_pin_verification(),
        };
        self.fail_with(io::Error::new(kind, SharedError(error)), Some(failure))
    }

    fn fail_with(&mut self, error: io::Error, failure: Option<EarlyDataFailure>) -> io::Error {
        if let Some(early) = self.early_data.take() {
            early
                .attempts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
            early.answer.send_replace(Answer::Failed(failure));
        }
        error
    }
}

fn is_rejection(error: &io::Error) -> bool {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<btls::ssl::Error>())
        .is_some_and(|error| error.code() == ErrorCode::EARLY_DATA_REJECTED)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HttpAttemptBudget;

    #[tokio::test]
    async fn dropping_the_producer_releases_retained_early_data_waiters() -> io::Result<()> {
        let early = EarlyData::new(None, None);
        let waiter = early.wait();
        assert!(waiter.is_pending());
        let budget = HttpAttemptBudget::new(1);
        waiter.register_attempt(Some(&budget));
        drop(early);
        assert!(
            waiter
                .attempts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .registrations
                .is_empty()
        );
        assert_eq!(budget.remaining(), 1);
        assert!(!waiter.is_pending());
        let error = tokio::time::timeout(std::time::Duration::from_secs(1), waiter.answered())
            .await
            .map_err(io::Error::other)?
            .err()
            .ok_or_else(|| io::Error::other("dropped producer reported success"))?;
        assert_eq!(error.kind(), io::ErrorKind::ConnectionAborted);
        Ok(())
    }

    #[test]
    fn mixed_early_requests_need_separate_replay_admissions() {
        let first = HttpAttemptBudget::new(1);
        let second = HttpAttemptBudget::new(0);
        let early = EarlyData::new(None, None);
        let waiter = early.wait();
        waiter.register_attempt(Some(&first));
        waiter.register_attempt(Some(&second));
        let mut attempts = early
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(attempts.admit().is_err());
        assert_eq!(first.remaining(), 0);
        assert_eq!(second.remaining(), 0);
        assert!(attempts.registrations.is_empty());
        assert!(attempts.closed);
    }

    #[test]
    fn replay_admission_is_once_and_does_not_leak_to_later_pooled_requests()
    -> Result<(), crate::HttpAttemptBudgetExhausted> {
        let original = HttpAttemptBudget::new(2);
        let later = HttpAttemptBudget::new(1);
        let early = EarlyData::new(None, None);
        let waiter = early.wait();
        waiter.register_attempt(Some(&original));
        {
            let mut attempts = early
                .attempts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            attempts.admit()?;
            // Further partial-write polls cannot charge this registration again.
            attempts.admit()?;
        }
        waiter.register_attempt(Some(&later));
        assert_eq!(original.remaining(), 1);
        assert_eq!(later.remaining(), 1);
        assert!(
            early
                .attempts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .registrations
                .is_empty()
        );
        Ok(())
    }

    #[test]
    fn accepted_early_data_clears_registrations_without_spending() {
        let budget = HttpAttemptBudget::new(1);
        let early = EarlyData::new(None, None);
        let waiter = early.wait();
        waiter.register_attempt(Some(&budget));
        early
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();
        waiter.register_attempt(Some(&budget));
        assert!(
            early
                .attempts
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .registrations
                .is_empty()
        );
        assert_eq!(budget.remaining(), 1);
    }

    #[tokio::test]
    async fn rejected_early_data_records_each_request_without_an_attempt_budget()
    -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use crate::request_diagnostics::{Observation, RequestDiagnostics};
        let first = RequestDiagnostics::new(std::num::NonZeroUsize::MIN);
        let second = RequestDiagnostics::new(std::num::NonZeroUsize::MIN);
        let early = EarlyData::new(None, None);
        let waiter = early.wait();
        for trace in [&first, &second] {
            trace
                .observe(async {
                    Observation::admit(Some(http::Version::HTTP_2));
                    waiter.register_attempt(None);
                    Ok::<_, ()>(())
                })
                .await
                .map_err(|()| "observer failed")?;
        }
        // The TLS driver has no request task-local scope.
        assert!(Observation::current().is_none());
        early
            .attempts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .admit()?;
        for trace in [&first, &second] {
            let snapshot = trace.snapshot();
            assert_eq!(snapshot.admitted_attempts, 2);
            assert_eq!(snapshot.events.len(), 1);
            assert_eq!(snapshot.dropped_events, 1);
        }
        Ok(())
    }
}
