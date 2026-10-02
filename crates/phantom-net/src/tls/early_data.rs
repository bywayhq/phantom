//! TLS 1.3 early data on a resumed TCP connection.
//!
//! The handshake returns once the ClientHello is sent, and the protocol layer
//! writes through the stream as usual: BoringSSL sends those bytes as early
//! data until the server answers. If the server accepts, nothing changes. If it
//! rejects, it processed none of them; the stream finishes the handshake and
//! writes the same bytes again before anything else, so the protocol layer
//! never sees the rejection. Firefox 156 does the same on the same connection:
//! HTTP/1.1 rewinds its request stream (`nsHttpTransaction::Finish0RTT`,
//! `netwerk/protocol/http/nsHttpTransaction.cpp:3363-3373` at tag
//! `FIREFOX_156_0_RELEASE`) and HTTP/2 resends its output queue from the
//! connection preface (`Http2Session::Finish0RTT`,
//! `netwerk/protocol/http/Http2Session.cpp:3384-3393`).
//!
//! A server that selects another ALPN protocol after a rejection would need a
//! different protocol on this connection, so the stream fails instead.

use std::{
    error::Error as StdError,
    fmt, io,
    pin::Pin,
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Answer {
    Unanswered,
    /// The handshake completed, and any rejected early data was sent again.
    Settled,
    /// The handshake failed.
    Failed,
    /// The server rejected the early data and then selected another ALPN
    /// protocol, so the connection failed without the server processing any
    /// request on it.
    AlpnChanged,
}

impl EarlyData {
    pub(super) fn new(alpn: Option<Box<[u8]>>, session_capture: Option<TlsSessionCapture>) -> Self {
        Self {
            sent: Vec::new(),
            phase: Phase::Unanswered,
            alpn,
            session_capture,
            answer: watch::Sender::new(Answer::Unanswered),
        }
    }

    pub(super) fn wait(&self) -> EarlyDataWait {
        EarlyDataWait(self.answer.subscribe())
    }
}

/// Tells a protocol layer when the server answers a connection's early data.
///
/// A request that is not replay safe ([`crate::request::is_replay_safe`])
/// waits for [`Self::answered`] before it is written, as Firefox holds such a
/// request until the handshake completes.
#[derive(Clone, Debug)]
pub(crate) struct EarlyDataWait(watch::Receiver<Answer>);

impl EarlyDataWait {
    /// Waits until the handshake completes and any rejected early data has
    /// been sent again.
    ///
    /// # Errors
    ///
    /// Fails when the handshake fails or the connection is dropped first.
    pub(crate) async fn answered(&self) -> io::Result<()> {
        let mut receiver = self.0.clone();
        let answer = receiver
            .wait_for(|answer| *answer != Answer::Unanswered)
            .await
            .map(|answer| *answer);
        match answer {
            Ok(Answer::Settled) => Ok(()),
            Ok(Answer::Unanswered | Answer::Failed | Answer::AlpnChanged) | Err(_) => {
                Err(io::Error::new(
                    io::ErrorKind::ConnectionAborted,
                    "the TLS handshake did not complete after early data",
                ))
            }
        }
    }

    /// Returns whether the server rejected the early data and then selected
    /// another ALPN protocol, which failed the connection. The server
    /// processed none of its requests.
    pub(crate) fn alpn_changed(&self) -> bool {
        *self.0.borrow() == Answer::AlpnChanged
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
            let result = Pin::new(&mut self.inner).poll_read(context, buffer);
            if self.take_rejection(&result) {
                continue;
            }
            return self.observe(result);
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
                            return Poll::Ready(Err(self.fail(error)));
                        }
                    }
                    let negotiated = self.inner.ssl().selected_alpn_protocol();
                    if negotiated != early.alpn.as_deref() {
                        let error = AlpnChangedAfterRejection {
                            early: early.alpn.take(),
                            negotiated: negotiated.map(Box::from),
                        };
                        debug!(%error, "TLS connection failed after early data");
                        let error = io::Error::new(io::ErrorKind::InvalidData, error);
                        return Poll::Ready(Err(self.fail_with(error, Answer::AlpnChanged)));
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
        true
    }

    /// Settles the early data once a read or write completed the handshake,
    /// and releases waiting requests when it failed.
    fn observe<T>(&mut self, result: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        match result {
            Poll::Ready(Err(error)) => Poll::Ready(Err(self.fail(error))),
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
        self.refresh_negotiated();
        if let Some(capture) = &early.session_capture {
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

    fn fail(&mut self, error: io::Error) -> io::Error {
        self.fail_with(error, Answer::Failed)
    }

    fn fail_with(&mut self, error: io::Error, answer: Answer) -> io::Error {
        if let Some(early) = self.early_data.take() {
            early.answer.send_replace(answer);
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
