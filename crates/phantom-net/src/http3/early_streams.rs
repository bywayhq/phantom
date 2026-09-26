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
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};

use bytes::Buf;
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming};
use h3_datagram::quic_traits::DatagramConnectionExt;
use tokio::sync::watch;

use super::early_data::EarlyDataOutcome;

/// `H3_REQUEST_CANCELLED` (RFC 9114, section 8.1).
const H3_REQUEST_CANCELLED: u64 = 0x010c;

/// The unidirectional streams every session opens first: the control stream
/// and the two QPACK streams (RFC 9114, section 6.2).
const CRITICAL_STREAMS: u64 = 3;

type Answered = Pin<Box<dyn Future<Output = ()> + Send + Sync>>;

/// The QUIC connection under one HTTP/3 session, with the early-data gate
/// when the session started before the handshake.
pub(super) struct Transport {
    inner: h3_quinn::Connection,
    gate: Option<OpenGate>,
    /// Present on an early session; see [`EarlySession`].
    early: Option<Arc<EarlySession>>,
    /// A stream the rejected session opened for this one.
    handed_over: Option<HandedOver>,
    /// How many of the session's critical streams have opened.
    critical_opened: u64,
    /// Makes every stream the session opens for itself after its first one
    /// wait until the handshake completes, for tests.
    #[cfg(test)]
    wait_for_handshake: Option<HandshakeWait>,
    /// Makes the session's first stream open only once Quinn answered.
    #[cfg(test)]
    open_after_answer: OpenAfterAnswer,
}

/// Where the test hook that opens the first stream after Quinn's answer is.
#[cfg(test)]
#[derive(Clone, Copy, Default, Eq, PartialEq)]
enum OpenAfterAnswer {
    #[default]
    Off,
    Armed,
    /// The open was decided and waits for the answer.
    Waiting,
}

impl Transport {
    /// A session that opens request streams without condition.
    pub(super) fn new(connection: quinn::Connection) -> Self {
        Self {
            inner: h3_quinn::Connection::new(connection),
            gate: None,
            early: None,
            handed_over: None,
            critical_opened: 0,
            #[cfg(test)]
            wait_for_handshake: None,
            #[cfg(test)]
            open_after_answer: OpenAfterAnswer::Off,
        }
    }

    /// A session started in early data. `accepted` is Quinn's answer to the
    /// early data, which the session reads while it starts. `answer`
    /// receives the same answer from the connection driver once the session
    /// runs, and closes unanswered when the connection ends first; `outcome`
    /// receives the published answer.
    pub(super) fn early(
        connection: quinn::Connection,
        accepted: ZeroRttAnswer,
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
            early: Some(Arc::new(EarlySession::new(accepted))),
            handed_over: None,
            critical_opened: 0,
            #[cfg(test)]
            wait_for_handshake: None,
            #[cfg(test)]
            open_after_answer: OpenAfterAnswer::Off,
        }
    }

    /// Makes the session's first stream open only once Quinn answered,
    /// although the session decided to open it before, as when Quinn
    /// completes the handshake on another thread between the two.
    #[cfg(test)]
    pub(super) fn open_after_answer_for_test(&mut self) {
        self.open_after_answer = OpenAfterAnswer::Armed;
    }

    /// Makes every stream the session opens for itself after its first one
    /// wait until the handshake completes, so the session starts across the
    /// handshake's completion.
    #[cfg(test)]
    pub(super) fn after_open_send_for_test(&mut self, connection: quinn::Connection) {
        self.wait_for_handshake = Some(HandshakeWait {
            connection,
            deadline: None,
            sleep: None,
        });
    }

    /// A session that replaces a rejected one, with the live stream the
    /// rejected session opened, if any, as its first stream.
    pub(super) fn after_rejection(
        connection: quinn::Connection,
        handed_over: Option<HandedOver>,
    ) -> Self {
        Self {
            handed_over,
            ..Self::new(connection)
        }
    }

    /// Returns the state of an early session, whose start the caller ends
    /// once the session has started or failed to.
    pub(super) fn early_session(&self) -> Option<Arc<EarlySession>> {
        self.early.clone()
    }
}

impl Transport {
    /// Whether the session may accept the server's streams: an early session
    /// only once Quinn accepted its early data.
    fn poll_accepts(&self, cx: &mut Context<'_>) -> Poll<()> {
        match &self.early {
            Some(early) => match early.poll_quinn_answer(cx) {
                Poll::Ready(true) => Poll::Ready(()),
                // After a rejection the server's streams belong to the
                // session that replaces this one, and the driver stops
                // polling this one.
                Poll::Ready(false) | Poll::Pending => Poll::Pending,
            },
            None => Poll::Ready(()),
        }
    }
}

impl<B: Buf + Send + 'static> quic::Connection<B> for Transport {
    type RecvStream = h3_quinn::RecvStream;
    type OpenStreams = Opener<B>;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        ready!(self.poll_accepts(cx));
        quic::Connection::<B>::poll_accept_recv(&mut self.inner, cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        ready!(self.poll_accepts(cx));
        quic::Connection::<B>::poll_accept_bidi(&mut self.inner, cx)
    }

    fn opener(&self) -> Self::OpenStreams {
        Opener {
            inner: quic::Connection::<B>::opener(&self.inner),
            gate: self.gate.clone(),
            answered: None,
            held: None,
            #[cfg(test)]
            after_permit: None,
        }
    }
}

/// The session's own streams (control and QPACK) open when it starts, so
/// they need no gate.
impl<B: Buf + Send + 'static> quic::OpenStreams<B> for Transport {
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
        #[cfg(test)]
        if self.critical_opened > 0
            && let Some(wait) = self.wait_for_handshake.as_mut()
        {
            ready!(wait.poll(cx));
        }
        if let Some(stream) = self.handed_over.take()
            && let Ok(stream) = stream.downcast::<h3_quinn::SendStream<B>>()
        {
            self.critical_opened += 1;
            return Poll::Ready(Ok(*stream));
        }
        // Once the handshake completed, a stream opened here is a 1-RTT
        // stream. After a rejection it would take a stream number the
        // session that replaces this one needs, so the start fails and the
        // caller starts again; after an acceptance it is the stream the
        // session asked for.
        let mut raced = false;
        #[cfg(test)]
        let resumed = self.open_after_answer == OpenAfterAnswer::Waiting;
        #[cfg(not(test))]
        let resumed = false;
        if resumed {
            raced = true;
        } else if let (Some(early), Some(gate)) = (&self.early, &self.gate)
            && early.is_starting()
        {
            match ready!(early.poll_open_answer(&gate.quinn, cx)) {
                Some(false) => {
                    return Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(
                        DiscardedSession,
                    ))));
                }
                Some(true) => {}
                None => raced = true,
            }
        }
        #[cfg(test)]
        if raced
            && self.open_after_answer != OpenAfterAnswer::Off
            && let Some(early) = &self.early
        {
            self.open_after_answer = OpenAfterAnswer::Waiting;
            ready!(early.poll_quinn_answer(cx));
            self.open_after_answer = OpenAfterAnswer::Off;
        }
        let mut stream = ready!(quic::OpenStreams::<B>::poll_open_send(&mut self.inner, cx))?;
        // The open was decided before Quinn answered, so the rejection can
        // have landed between the check and the open. Quinn settles its
        // answer when it discards the early streams, so a pending answer
        // means the stream is a 0-RTT one. After a rejection, a 0-RTT stream
        // reports the rejection, and any other stream is a live 1-RTT one
        // on the first number, which the replacement session takes as its
        // control stream.
        if raced
            && let Some(early) = &self.early
            && early.poll_quinn_answer(cx) == Poll::Ready(false)
        {
            let discarded = matches!(
                quic::SendStreamUnframed::<B>::poll_stopped(&mut stream, cx),
                Poll::Ready(Err(_))
            );
            if !discarded {
                early.hand_over(Box::new(stream));
            }
            return Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(
                DiscardedSession,
            ))));
        }
        // The session's critical streams take the first client
        // unidirectional stream numbers, 2, 6 and 10 (RFC 9000, section
        // 2.1). A rejection that lands between the check above and the open
        // lets the open take a live 1-RTT number, and a session started
        // after a rejected one then finds that number taken. Either session
        // fails to start rather than use other stream numbers.
        if self.critical_opened < CRITICAL_STREAMS {
            let expected = self.critical_opened;
            self.critical_opened += 1;
            if quic::SendStream::<B>::send_id(&stream).index() != expected {
                // h3 closes with H3_CLOSED_CRITICAL_STREAM on a failed open,
                // which RFC 9114 section 8.1 reserves for a critical stream
                // the peer closed; this is a local fault, so the connection
                // closes first with H3_INTERNAL_ERROR, and h3's later close
                // has no effect.
                quic::OpenStreams::<B>::close(
                    &mut self.inner,
                    h3::error::Code::H3_INTERNAL_ERROR,
                    b"critical stream number taken",
                );
                return Poll::Ready(Err(StreamErrorIncoming::Unknown(Box::new(
                    UnexpectedStreamNumber,
                ))));
            }
        }
        Poll::Ready(Ok(stream))
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        if let (Some(early), Some(gate)) = (&self.early, &self.gate)
            && gate.quinn.handshake_data().is_some()
            && early.defer_close(code, reason)
        {
            return;
        }
        quic::OpenStreams::<B>::close(&mut self.inner, code, reason);
    }
}

/// Quinn's answer to a connection's early data: `true` when the server
/// accepted it.
pub(super) enum ZeroRttAnswer {
    Waiting(quinn::ZeroRttAccepted),
    Known(bool),
}

impl ZeroRttAnswer {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<bool> {
        match self {
            Self::Known(accepted) => Poll::Ready(*accepted),
            Self::Waiting(answer) => {
                let accepted = ready!(Pin::new(answer).poll(cx));
                *self = Self::Known(accepted);
                Poll::Ready(accepted)
            }
        }
    }
}

/// The state an early session shares with `connect` and the connection
/// driver.
///
/// Quinn discards the early streams and settles its answer in one step, under
/// the connection's lock, but runs on its own task. On a multi-threaded
/// runtime that step can land between any check of the answer and the next
/// use of the connection, so every decision that depends on the answer reads
/// it again after the connection was used:
///
/// - A stream the session opens for itself before Quinn answers is a 0-RTT
///   stream. Once the handshake data is in, an open waits for the answer: an
///   acceptance lets it open as a 1-RTT stream, and a rejection fails it. An
///   open that raced the rejection is checked afterwards; see
///   [`Transport::poll_open_send`].
/// - The session accepts no stream from the server before Quinn's answer, and
///   none after a rejection: the server's streams then belong to the session
///   that replaces it.
/// - Quinn fails every use of a discarded stream, and the session then asks
///   to close the connection. A close it asks for after the handshake
///   completed, and before the connection driver read the answer, is
///   deferred: while the session starts it goes to `connect`, and afterwards
///   to the driver. On a rejection the close is dropped and HTTP/3 starts
///   again; otherwise the connection closes with the code the session chose.
///   A close before the handshake completed cannot come from a rejection and
///   is sent at once.
pub(super) struct EarlySession {
    started: AtomicBool,
    deferred: std::sync::Mutex<DeferredClose>,
    answer: std::sync::Mutex<ZeroRttAnswer>,
    /// A live stream a start that raced the rejection opened; it is the
    /// replacement session's control stream.
    handed_over: std::sync::Mutex<Option<HandedOver>>,
}

/// A stream the rejected session opened after the rejection, for the
/// session that replaces it.
pub(super) type HandedOver = Box<dyn std::any::Any + Send>;

/// A close deferred until Quinn's answer is read.
#[derive(Default)]
struct DeferredClose {
    /// Set once the answer was read; later closes are sent at once.
    answered: bool,
    close: Option<(quinn::VarInt, Vec<u8>)>,
}

/// What an early session's start leaves to its caller.
pub(super) struct Started {
    /// The close the session asked for after its handshake completed.
    pub(super) deferred_close: Option<(quinn::VarInt, Vec<u8>)>,
    /// A live stream for the session that replaces a rejected one.
    pub(super) handed_over: Option<HandedOver>,
}

impl EarlySession {
    fn new(answer: ZeroRttAnswer) -> Self {
        Self {
            started: AtomicBool::new(false),
            deferred: std::sync::Mutex::new(DeferredClose::default()),
            answer: std::sync::Mutex::new(answer),
            handed_over: std::sync::Mutex::new(None),
        }
    }

    fn is_starting(&self) -> bool {
        !self.started.load(Ordering::Acquire)
    }

    /// Polls Quinn's answer.
    pub(super) fn poll_quinn_answer(&self, cx: &mut Context<'_>) -> Poll<bool> {
        self.answer
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .poll(cx)
    }

    /// Resolves to Quinn's answer once it is known, or to `None` at once
    /// while the handshake runs. Once the handshake data is in and the
    /// answer is not, it waits: Quinn answers when the same handshake
    /// completes.
    fn poll_open_answer(
        &self,
        connection: &quinn::Connection,
        cx: &mut Context<'_>,
    ) -> Poll<Option<bool>> {
        if let Poll::Ready(accepted) = self.poll_quinn_answer(cx) {
            return Poll::Ready(Some(accepted));
        }
        if connection.handshake_data().is_none() {
            Poll::Ready(None)
        } else {
            Poll::Pending
        }
    }

    fn hand_over(&self, stream: HandedOver) {
        *self
            .handed_over
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(stream);
    }

    fn defer_close(&self, code: h3::error::Code, reason: &[u8]) -> bool {
        let Ok(code) = quinn::VarInt::from_u64(code.value()) else {
            return false;
        };
        let mut deferred = self
            .deferred
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if deferred.answered {
            return false;
        }
        deferred
            .close
            .get_or_insert_with(|| (code, reason.to_vec()));
        true
    }

    /// Records that the connection driver read Quinn's answer, and returns
    /// the close the session deferred since it started.
    pub(super) fn answered(&self) -> Option<(quinn::VarInt, Vec<u8>)> {
        let mut deferred = self
            .deferred
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        deferred.answered = true;
        deferred.close.take()
    }

    /// Ends the start and returns what it leaves to the caller.
    pub(super) fn finish(&self) -> Started {
        self.started.store(true, Ordering::Release);
        let deferred_close = self
            .deferred
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .close
            .take();
        let handed_over = self
            .handed_over
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        Started {
            deferred_close,
            handed_over,
        }
    }
}

/// The test hook that makes a session's own stream opens wait for the
/// handshake to complete.
#[cfg(test)]
struct HandshakeWait {
    connection: quinn::Connection,
    deadline: Option<tokio::time::Instant>,
    sleep: Option<Pin<Box<tokio::time::Sleep>>>,
}

#[cfg(test)]
impl HandshakeWait {
    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        const LIMIT: std::time::Duration = std::time::Duration::from_secs(5);
        loop {
            if self.connection.handshake_data().is_some() {
                self.sleep = None;
                return Poll::Ready(());
            }
            let now = tokio::time::Instant::now();
            let deadline = *self.deadline.get_or_insert(now + LIMIT);
            assert!(
                now < deadline,
                "the QUIC handshake did not complete within {LIMIT:?} of the session's first stream"
            );
            let sleep = self.sleep.get_or_insert_with(|| {
                Box::pin(tokio::time::sleep(std::time::Duration::from_millis(1)))
            });
            ready!(sleep.as_mut().poll(cx));
            self.sleep = None;
        }
    }
}

impl<B: Buf + Send + 'static> DatagramConnectionExt<B> for Transport {
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
    /// Runs after a permit is granted and before the stream opens.
    #[cfg(test)]
    after_permit: Option<std::sync::Arc<dyn Fn() + Send + Sync>>,
}

impl<B: Buf> Opener<B> {
    /// Holds `stream` as if its open had raced the handshake's completion.
    #[cfg(test)]
    pub(super) fn hold_for_test(&mut self, stream: h3_quinn::BidiStream<B>) {
        self.held = Some(stream);
    }

    /// Runs `hook` after each permit is granted and before the stream opens.
    #[cfg(test)]
    pub(super) fn after_permit_for_test(&mut self, hook: std::sync::Arc<dyn Fn() + Send + Sync>) {
        self.after_permit = Some(hook);
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
            #[cfg(test)]
            after_permit: None,
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
                Permit::Open { during_handshake } => {
                    if let Some(stream) = self.held.take() {
                        return Poll::Ready(Ok(stream));
                    }
                    #[cfg(test)]
                    if let Some(hook) = &self.after_permit {
                        hook();
                    }
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
                    // The permit was granted while the handshake ran, and the
                    // handshake has completed since: the stream may be a
                    // 1-RTT one, so keep it until the server's answer says
                    // whether the session may use it. The state behind the
                    // permit is carried, not read again, so a handshake that
                    // completes after the permit is read is always seen.
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
    /// Open a stream. `during_handshake` is set when the permit rests on
    /// the handshake still running rather than on a published acceptance.
    Open {
        during_handshake: bool,
    },
    Wait,
    Refuse,
}

impl OpenGate {
    fn permit(&self) -> Permit {
        match *self.outcome.borrow() {
            Some(EarlyDataOutcome::Accepted) => {
                return Permit::Open {
                    during_handshake: false,
                };
            }
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
            None if self.quinn.handshake_data().is_none() => Permit::Open {
                during_handshake: true,
            },
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

/// A critical stream of a session did not take the stream number it needs.
#[derive(Debug)]
struct UnexpectedStreamNumber;

impl fmt::Display for UnexpectedStreamNumber {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an HTTP/3 critical stream did not open on its expected stream number")
    }
}

impl Error for UnexpectedStreamNumber {}
