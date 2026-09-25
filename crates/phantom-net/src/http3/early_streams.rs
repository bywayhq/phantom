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

    /// A session started in early data, whose server's answer arrives on
    /// `outcome`.
    pub(super) fn early(
        connection: quinn::Connection,
        outcome: watch::Receiver<Option<EarlyDataOutcome>>,
    ) -> Self {
        Self {
            inner: h3_quinn::Connection::new(connection.clone()),
            gate: Some(OpenGate {
                quinn: connection,
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
                        // Nothing was written on it, so the server sees only
                        // a reset of an unused stream.
                        quic::SendStream::<B>::reset(&mut stream, H3_REQUEST_CANCELLED);
                    }
                    return Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(
                        DiscardedSession,
                    ))));
                }
                Permit::Wait => {
                    let answered = self.answered.get_or_insert_with(|| gate.answered());
                    ready!(answered.as_mut().poll(cx));
                    self.answered = None;
                }
                Permit::Open => {
                    if let Some(stream) = self.held.take() {
                        return Poll::Ready(Ok(stream));
                    }
                    let during_handshake = gate.quinn.handshake_data().is_none();
                    let stream =
                        ready!(quic::OpenStreams::<B>::poll_open_bidi(&mut self.inner, cx))?;
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
    outcome: watch::Receiver<Option<EarlyDataOutcome>>,
}

enum Permit {
    Open,
    Wait,
    Refuse,
}

impl OpenGate {
    fn permit(&self) -> Permit {
        match *self.outcome.borrow() {
            Some(EarlyDataOutcome::Accepted) => Permit::Open,
            Some(_) => Permit::Refuse,
            // The TLS handshake data appears when the handshake completes,
            // no later than Quinn decides whether the early data was
            // rejected, so a stream opened before it is a 0-RTT stream.
            None if self.quinn.handshake_data().is_none() => Permit::Open,
            None => Permit::Wait,
        }
    }

    fn answered(&self) -> Answered {
        let mut outcome = self.outcome.clone();
        Box::pin(async move {
            let _ = outcome.wait_for(Option::is_some).await;
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
