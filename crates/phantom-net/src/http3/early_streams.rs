//! Request-stream opening on an HTTP/3 session that started in early data.
//!
//! When a server rejects early data, Quinn discards every stream opened
//! before the handshake (RFC 9001, section 4.6.2), and the connection starts
//! a new HTTP/3 session. A request that opened its stream on the discarded
//! session after the handshake would instead get a live 1-RTT stream, whose
//! request the server could process while the pool also sends it again on
//! the new session. The early session therefore opens a request stream only
//! while the handshake is still running, when the stream is certainly a
//! 0-RTT stream, or once the server accepted the early data.
//!
//! A request that waits here holds the connection's send lock. A rejection
//! publishes its answer only after it has taken that lock to install the new
//! session, so the gate refuses on the answer the connection driver receives
//! from Quinn. An acceptance is published without the lock, once the
//! handshake metadata passed its checks, so the gate opens only on that
//! published answer.

use std::{
    error::Error,
    fmt,
    future::Future,
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Buf;
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming};
use h3_datagram::quic_traits::DatagramConnectionExt;
use tokio::sync::watch;

use super::early_data::EarlyDataOutcome;

/// `H3_REQUEST_CANCELLED` (RFC 9114, section 8.1).
const H3_REQUEST_CANCELLED: u64 = 0x010c;

type Answered = Pin<Box<dyn Future<Output = ()> + Send + Sync>>;

/// The QUIC connection under one HTTP/3 session, with the early-data gate
/// when the session started before the handshake.
pub(super) struct Transport {
    inner: h3_quinn::Connection,
    gate: Option<OpenGate>,
}

impl Transport {
    /// A session that opens request streams without condition.
    pub(super) fn new(connection: quinn::Connection) -> Self {
        Self {
            inner: h3_quinn::Connection::new(connection),
            gate: None,
        }
    }

    /// A session started in early data. `answer` receives whether Quinn
    /// saw the server accept the early data, and closes unanswered when the
    /// connection ends first; `outcome` receives the published answer.
    pub(super) fn early(
        connection: quinn::Connection,
        answer: watch::Receiver<Option<bool>>,
        outcome: watch::Receiver<Option<EarlyDataOutcome>>,
    ) -> Self {
        Self {
            inner: h3_quinn::Connection::new(connection.clone()),
            gate: Some(OpenGate {
                quinn: connection,
                answer,
                outcome,
            }),
        }
    }
}

impl<B: Buf> quic::Connection<B> for Transport {
    type RecvStream = h3_quinn::RecvStream;
    type OpenStreams = Opener<B>;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        quic::Connection::<B>::poll_accept_recv(&mut self.inner, cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        quic::Connection::<B>::poll_accept_bidi(&mut self.inner, cx)
    }

    fn opener(&self) -> Self::OpenStreams {
        Opener {
            inner: quic::Connection::<B>::opener(&self.inner),
            gate: self.gate.clone(),
            answered: None,
            held: None,
        }
    }
}

/// The session's own streams (control and QPACK) open when it starts, so
/// they need no gate.
impl<B: Buf> quic::OpenStreams<B> for Transport {
    type BidiStream = h3_quinn::BidiStream<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_bidi(&mut self.inner, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<B>::close(&mut self.inner, code, reason);
    }
}

impl<B: Buf> DatagramConnectionExt<B> for Transport {
    type SendDatagramHandler = h3_quinn::datagram::SendDatagramHandler;
    type RecvDatagramHandler = h3_quinn::datagram::RecvDatagramHandler;

    fn send_datagram_handler(&self) -> Self::SendDatagramHandler {
        DatagramConnectionExt::<B>::send_datagram_handler(&self.inner)
    }

    fn recv_datagram_handler(&self) -> Self::RecvDatagramHandler {
        DatagramConnectionExt::<B>::recv_datagram_handler(&self.inner)
    }
}

/// Opens the request streams of one HTTP/3 session.
pub(super) struct Opener<B: Buf> {
    inner: h3_quinn::OpenStreams,
    gate: Option<OpenGate>,
    answered: Option<Answered>,
    /// A stream opened while the handshake completed, so possibly after it.
    held: Option<h3_quinn::BidiStream<B>>,
}

impl<B: Buf> Opener<B> {
    /// Holds `stream` as if its open had raced the handshake's completion.
    #[cfg(test)]
    pub(super) fn hold_for_test(&mut self, stream: h3_quinn::BidiStream<B>) {
        self.held = Some(stream);
    }
}

/// A held stream was never used, so resetting it leaves the server only a
/// reset of an unused stream.
fn reset_unused<B: Buf>(stream: &mut h3_quinn::BidiStream<B>) {
    quic::SendStream::<B>::reset(stream, H3_REQUEST_CANCELLED);
}

impl<B: Buf> Drop for Opener<B> {
    fn drop(&mut self) {
        if let Some(mut stream) = self.held.take() {
            reset_unused(&mut stream);
        }
    }
}

impl<B: Buf> Clone for Opener<B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            gate: self.gate.clone(),
            answered: None,
            held: None,
        }
    }
}

impl<B: Buf> quic::OpenStreams<B> for Opener<B> {
    type BidiStream = h3_quinn::BidiStream<B>;
    type SendStream = h3_quinn::SendStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        let Some(gate) = self.gate.as_ref() else {
            return quic::OpenStreams::<B>::poll_open_bidi(&mut self.inner, cx);
        };
        loop {
            match gate.permit() {
                Permit::Refuse => {
                    self.answered = None;
                    if let Some(mut stream) = self.held.take() {
                        reset_unused(&mut stream);
                    }
                    return Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(
                        DiscardedSession,
                    ))));
                }
                Permit::Wait => {
                    let answered = self.answered.get_or_insert_with(|| gate.next_change());
                    ready!(answered.as_mut().poll(cx));
                    self.answered = None;
                }
                Permit::Open => {
                    if let Some(stream) = self.held.take() {
                        return Poll::Ready(Ok(stream));
                    }
                    let during_handshake = gate.quinn.handshake_data().is_none();
                    let stream = match quic::OpenStreams::<B>::poll_open_bidi(&mut self.inner, cx) {
                        Poll::Ready(stream) => stream?,
                        Poll::Pending => {
                            // Waiting for stream credit: the answer must wake
                            // the request too, since Quinn does not wake
                            // waiting openers when it discards early streams.
                            // The registration checks the answer as it is
                            // now, so one that arrived since the permit was
                            // read wakes the request at once.
                            if !gate.accepted() {
                                let answered =
                                    self.answered.get_or_insert_with(|| gate.next_change());
                                if answered.as_mut().poll(cx).is_ready() {
                                    self.answered = None;
                                    continue;
                                }
                            }
                            return Poll::Pending;
                        }
                    };
                    // The handshake completed between the check and the open,
                    // so the stream may be a 1-RTT one; keep it until the
                    // server's answer says whether the session may use it.
                    if during_handshake && gate.quinn.handshake_data().is_some() {
                        self.held = Some(stream);
                        continue;
                    }
                    return Poll::Ready(Ok(stream));
                }
            }
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::<B>::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        quic::OpenStreams::<B>::close(&mut self.inner, code, reason);
    }
}

#[derive(Clone)]
struct OpenGate {
    quinn: quinn::Connection,
    /// Quinn's answer, as the connection driver received it.
    answer: watch::Receiver<Option<bool>>,
    /// The answer published to requests after the handshake metadata was
    /// checked, or after HTTP/3 started again on a rejection.
    outcome: watch::Receiver<Option<EarlyDataOutcome>>,
}

#[derive(Debug, Eq, PartialEq)]
enum Permit {
    Open,
    Wait,
    Refuse,
}

impl OpenGate {
    fn permit(&self) -> Permit {
        match *self.outcome.borrow() {
            Some(EarlyDataOutcome::Accepted) => return Permit::Open,
            Some(_) => return Permit::Refuse,
            None => {}
        }
        if self.outcome.has_changed().is_err() {
            return Permit::Refuse;
        }
        match *self.answer.borrow() {
            Some(false) => Permit::Refuse,
            // The driver ended without an answer: the connection is gone.
            None if self.answer.has_changed().is_err() => Permit::Refuse,
            // Accepted by the server, but the handshake metadata is not
            // checked yet.
            Some(true) => Permit::Wait,
            // The TLS handshake data appears when the handshake completes,
            // no later than Quinn decides whether the early data was
            // rejected, so a stream opened before it is a 0-RTT stream.
            None if self.quinn.handshake_data().is_none() => Permit::Open,
            None => Permit::Wait,
        }
    }

    /// Returns whether the published answer lets this session open streams
    /// for good.
    fn accepted(&self) -> bool {
        *self.outcome.borrow() == Some(EarlyDataOutcome::Accepted)
    }

    /// Resolves when the permit may have changed: at once when Quinn's
    /// answer is a rejection or its channel closed, when Quinn's answer or
    /// the published answer arrives, or, once Quinn's answer is known, when
    /// the published answer arrives.
    fn next_change(&self) -> Answered {
        let mut answer = self.answer.clone();
        let mut outcome = self.outcome.clone();
        Box::pin(async move {
            let known = match *answer.borrow() {
                Some(false) => return,
                Some(true) => true,
                None if answer.has_changed().is_err() => return,
                None => false,
            };
            if known {
                let _ = outcome.wait_for(Option::is_some).await;
                return;
            }
            let quinn_answered = answer.wait_for(Option::is_some);
            let published = outcome.wait_for(Option::is_some);
            let mut quinn_answered = std::pin::pin!(quinn_answered);
            let mut published = std::pin::pin!(published);
            std::future::poll_fn(|cx| {
                if quinn_answered.as_mut().poll(cx).is_ready()
                    || published.as_mut().poll(cx).is_ready()
                {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            })
            .await;
        })
    }
}

/// The request tried to open a stream on a session its connection discarded
/// after the server rejected its early data. No request bytes were sent.
#[derive(Debug)]
struct DiscardedSession;

impl fmt::Display for DiscardedSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the HTTP/3 session was discarded with its rejected early data")
    }
}

impl Error for DiscardedSession {}
