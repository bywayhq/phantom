use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

use bytes::{Buf, Bytes};
use h3::quic::StreamId;
use h3_datagram::datagram_handler::DatagramReader;
use tokio::{runtime::Handle, sync::oneshot, task::JoinHandle};
use tracing::{Instrument, debug, debug_span, dispatcher, instrument::WithSubscriber};

type Reader = DatagramReader<h3_quinn::datagram::RecvDatagramHandler>;

const MAX_DATAGRAMS_PER_TURN: usize = 32;
const MAX_PENDING_VIOLATIONS: usize = 64;
const MIN_PENDING_LIFETIME: Duration = Duration::from_millis(10);
const MAX_PENDING_LIFETIME: Duration = Duration::from_secs(1);
/// Received payloads buffered per datagram flow before new ones are dropped.
pub(super) const MAX_QUEUED_FLOW_DATAGRAMS: usize = 256;
/// Largest UDP payload a Context ID zero datagram may carry (RFC 9298 section 5).
pub(super) const MAX_UDP_PAYLOAD_LEN: usize = 65_527;

#[derive(Clone)]
pub(super) struct DatagramRouter {
    state: Arc<Mutex<RouterState>>,
    _task: Arc<RouterTask>,
}

impl DatagramRouter {
    pub(super) fn spawn(mut reader: Reader, rtt: Duration) -> Self {
        let pending_lifetime = rtt
            .saturating_mul(3)
            .clamp(MIN_PENDING_LIFETIME, MAX_PENDING_LIFETIME);
        let state = Arc::new(Mutex::new(RouterState::new(pending_lifetime)));
        let task_state = Arc::clone(&state);
        let dispatch = dispatcher::get_default(Clone::clone);
        let span = debug_span!("http3.datagram_reader");
        let handle = Handle::current().spawn(
            async move {
                loop {
                    for _ in 0..MAX_DATAGRAMS_PER_TURN {
                        match reader.read_datagram().await {
                            Ok(datagram) => {
                                let stream_id = datagram.stream_id().into_inner();
                                let payload = datagram.payload().clone();
                                lock(&task_state).notify(stream_id, payload);
                            }
                            Err(error) => {
                                debug!(%error, "HTTP/3 datagram reader stopped");
                                lock(&task_state).stop();
                                return;
                            }
                        }
                    }
                    tokio::task::yield_now().await;
                }
            }
            .instrument(span)
            .with_subscriber(dispatch),
        );
        Self {
            state,
            _task: Arc::new(RouterTask { handle }),
        }
    }

    pub(super) fn monitor(&self, stream_id: StreamId) -> DatagramMonitor {
        let (sender, receiver) = oneshot::channel();
        let stream_id = stream_id.into_inner();
        let token = lock(&self.state).register(stream_id, sender);
        DatagramMonitor {
            receiver,
            state: Arc::clone(&self.state),
            stream_id,
            token,
        }
    }

    /// Registers a stream whose HTTP Datagrams carry RFC 9298 UDP payloads.
    ///
    /// Must be called under the request-send lock, like [`Self::monitor`].
    pub(super) fn flow(&self, stream_id: StreamId) -> DatagramFlow {
        let shared = Arc::new(FlowShared::default());
        let stream_id = stream_id.into_inner();
        let token = lock(&self.state).register_flow(stream_id, Arc::clone(&shared));
        DatagramFlow {
            shared,
            state: Arc::clone(&self.state),
            stream_id,
            token,
        }
    }

    pub(super) fn is_failed(&self) -> bool {
        lock(&self.state).failed
    }

    /// Forgets the stream order of a discarded HTTP/3 session.
    ///
    /// A session that replaces one discarded with rejected early data
    /// numbers its request streams again from the first unused one, usually
    /// stream 0. Must be called under the request-send lock, before the new
    /// session registers a stream.
    pub(super) fn restart(&self) {
        let mut state = lock(&self.state);
        state.highest_registered = None;
        state.pending.clear();
    }
}

impl std::fmt::Debug for DatagramRouter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DatagramRouter")
            .finish_non_exhaustive()
    }
}

enum Registration {
    /// A stream without datagram semantics; any datagram is a violation.
    Violation(oneshot::Sender<()>),
    /// A stream whose datagrams are delivered to a bounded queue.
    Flow(Arc<FlowShared>),
}

impl Registration {
    fn end(self, end: FlowEnd) {
        match self {
            Self::Violation(sender) => {
                let _ = sender.send(());
            }
            Self::Flow(flow) => flow.end(end),
        }
    }
}

struct RouterState {
    next_token: u64,
    active: HashMap<u64, (u64, Registration)>,
    // Request streams register in stream-ID order, so every client stream at
    // or below this ID has been opened and is closed unless it is active.
    highest_registered: Option<u64>,
    pending: VecDeque<PendingViolation>,
    stopped: bool,
    failed: bool,
    pending_lifetime: Duration,
}

impl RouterState {
    fn new(pending_lifetime: Duration) -> Self {
        Self {
            next_token: 0,
            active: HashMap::new(),
            highest_registered: None,
            pending: VecDeque::new(),
            stopped: false,
            failed: false,
            pending_lifetime,
        }
    }

    fn register(&mut self, stream_id: u64, sender: oneshot::Sender<()>) -> u64 {
        self.register_at(stream_id, sender, Instant::now())
    }

    fn register_at(&mut self, stream_id: u64, sender: oneshot::Sender<()>, now: Instant) -> u64 {
        self.insert_at(stream_id, Registration::Violation(sender), now)
    }

    fn register_flow(&mut self, stream_id: u64, flow: Arc<FlowShared>) -> u64 {
        self.insert_at(stream_id, Registration::Flow(flow), Instant::now())
    }

    fn insert_at(&mut self, stream_id: u64, registration: Registration, now: Instant) -> u64 {
        self.prune(now);
        self.next_token = self.next_token.wrapping_add(1);
        let token = self.next_token;
        if self.failed {
            registration.end(FlowEnd::RouterFailed);
            return token;
        }
        if self.stopped {
            // A dropped violation sender reports "no violation".
            if let Registration::Flow(flow) = registration {
                flow.end(FlowEnd::ConnectionClosed);
            }
            return token;
        }
        self.highest_registered = self.highest_registered.max(Some(stream_id));
        let early = self
            .pending
            .iter()
            .any(|candidate| candidate.stream_id == stream_id);
        // Pending datagrams for lower IDs belong to streams that were opened
        // but never registered; those streams are already closed.
        self.pending
            .retain(|candidate| candidate.stream_id > stream_id);
        let registration = match registration {
            Registration::Violation(sender) if early => {
                let _ = sender.send(());
                return token;
            }
            Registration::Flow(flow) => {
                if early {
                    // RFC 9297 section 2.1 permits dropping datagrams that
                    // arrive before their stream exists.
                    flow.record_early_drop();
                }
                Registration::Flow(flow)
            }
            registration => registration,
        };
        if let Some((_, previous)) = self.active.insert(stream_id, (token, registration)) {
            previous.end(FlowEnd::ConnectionClosed);
        }
        token
    }

    fn notify(&mut self, stream_id: u64, payload: Bytes) {
        self.notify_at(stream_id, payload, Instant::now());
    }

    fn notify_at(&mut self, stream_id: u64, payload: Bytes, now: Instant) {
        if self.stopped {
            return;
        }
        self.prune(now);
        if self.failed {
            return;
        }
        if let Some((_, Registration::Flow(flow))) = self.active.get(&stream_id) {
            flow.deliver(payload);
            return;
        }
        if let Some((_, registration)) = self.active.remove(&stream_id) {
            registration.end(FlowEnd::ConnectionClosed);
            return;
        }
        // RFC 9297 section 2.1: "If a datagram is received after the
        // corresponding stream's receive side is closed, the received
        // datagrams MUST be silently dropped."
        if self
            .highest_registered
            .is_some_and(|highest| stream_id <= highest)
        {
            return;
        }
        if self
            .pending
            .iter()
            .any(|pending| pending.stream_id == stream_id)
        {
            return;
        }
        if self.pending.len() == MAX_PENDING_VIOLATIONS {
            self.fail("pending_violation_capacity");
            return;
        }
        self.pending.push_back(PendingViolation {
            stream_id,
            observed_at: now,
        });
    }

    fn unregister(&mut self, stream_id: u64, token: u64) {
        if self
            .active
            .get(&stream_id)
            .is_some_and(|(registered, _)| *registered == token)
        {
            self.active.remove(&stream_id);
        }
    }

    fn stop(&mut self) {
        self.stopped = true;
        for (_, registration) in self.active.drain().map(|(_, value)| value) {
            // Violation monitors observe a dropped sender as "no violation".
            if let Registration::Flow(flow) = registration {
                flow.end(FlowEnd::ConnectionClosed);
            }
        }
        self.pending.clear();
    }

    fn fail(&mut self, reason: &'static str) {
        if self.failed {
            return;
        }
        self.failed = true;
        debug!(reason, "HTTP/3 datagram router failed closed");
        self.pending.clear();
        for (_, registration) in self.active.drain().map(|(_, value)| value) {
            registration.end(FlowEnd::RouterFailed);
        }
    }

    fn prune(&mut self, now: Instant) {
        if self.pending.front().is_some_and(|pending| {
            now.saturating_duration_since(pending.observed_at) >= self.pending_lifetime
        }) {
            self.fail("pending_violation_expired");
        }
    }
}

struct PendingViolation {
    stream_id: u64,
    observed_at: Instant,
}

fn lock(state: &Mutex<RouterState>) -> MutexGuard<'_, RouterState> {
    state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct RouterTask {
    handle: JoinHandle<()>,
}

impl Drop for RouterTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub(super) struct DatagramMonitor {
    receiver: oneshot::Receiver<()>,
    state: Arc<Mutex<RouterState>>,
    stream_id: u64,
    token: u64,
}

impl DatagramMonitor {
    pub(super) fn poll_violation(&mut self, context: &mut Context<'_>) -> Poll<Option<()>> {
        match Pin::new(&mut self.receiver).poll(context) {
            Poll::Ready(Ok(())) => Poll::Ready(Some(())),
            Poll::Ready(Err(_)) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl Drop for DatagramMonitor {
    fn drop(&mut self) {
        lock(&self.state).unregister(self.stream_id, self.token);
    }
}

/// Why a datagram flow stopped delivering payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FlowEnd {
    /// The connection's datagram reader stopped or the stream was replaced.
    ConnectionClosed,
    /// The router failed closed after an unattributable datagram.
    RouterFailed,
    /// A Context ID zero payload exceeded 65 527 bytes; RFC 9298 section 5
    /// requires aborting the stream.
    OversizedPayload,
}

/// Payload and drop counts for one datagram flow; never payload contents.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct FlowCounters {
    pub(super) delivered: u64,
    pub(super) dropped_unknown_context: u64,
    pub(super) dropped_overflow: u64,
    pub(super) dropped_early: u64,
    pub(super) dropped_malformed: u64,
}

#[derive(Default)]
pub(super) struct FlowShared {
    state: Mutex<FlowState>,
}

#[derive(Default)]
struct FlowState {
    queue: VecDeque<Bytes>,
    waker: Option<Waker>,
    end: Option<FlowEnd>,
    counters: FlowCounters,
}

impl FlowShared {
    fn lock(&self) -> MutexGuard<'_, FlowState> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Accepts one HTTP Datagram Payload from a QUIC DATAGRAM frame or a
    /// DATAGRAM capsule. Delivery never blocks the connection's reader.
    pub(super) fn deliver(&self, mut payload: Bytes) {
        let mut state = self.lock();
        if state.end.is_some() {
            return;
        }
        let Some((context_id, context_len)) = super::varint::decode(&payload) else {
            state.counters.dropped_malformed += 1;
            return;
        };
        // RFC 9298 section 4: only Context ID zero (UDP payloads) is known;
        // datagrams for unregistered contexts are dropped silently (section 5).
        if context_id != 0 {
            state.counters.dropped_unknown_context += 1;
            return;
        }
        payload.advance(context_len);
        if payload.len() > MAX_UDP_PAYLOAD_LEN {
            state.end = Some(FlowEnd::OversizedPayload);
            state.queue.clear();
            wake(&mut state);
            return;
        }
        if state.queue.len() == MAX_QUEUED_FLOW_DATAGRAMS {
            state.counters.dropped_overflow += 1;
            return;
        }
        state.queue.push_back(payload);
        wake(&mut state);
    }

    pub(super) fn end(&self, end: FlowEnd) {
        let mut state = self.lock();
        if state.end.is_none() {
            state.end = Some(end);
        }
        wake(&mut state);
    }

    fn record_early_drop(&self) {
        self.lock().counters.dropped_early += 1;
    }

    /// Reports whether a Context ID zero payload above 65 527 bytes ended
    /// this flow (RFC 9298 section 5).
    pub(super) fn received_oversized_payload(&self) -> bool {
        self.lock().end == Some(FlowEnd::OversizedPayload)
    }

    pub(super) fn counters(&self) -> FlowCounters {
        self.lock().counters
    }

    /// Returns the next queued UDP payload, or why the flow ended.
    pub(super) fn poll_recv(&self, context: &mut Context<'_>) -> Poll<Result<Bytes, FlowEnd>> {
        let mut state = self.lock();
        if state.end == Some(FlowEnd::OversizedPayload) {
            return Poll::Ready(Err(FlowEnd::OversizedPayload));
        }
        if let Some(payload) = state.queue.pop_front() {
            state.counters.delivered += 1;
            return Poll::Ready(Ok(payload));
        }
        if let Some(end) = state.end {
            return Poll::Ready(Err(end));
        }
        state.waker = Some(context.waker().clone());
        Poll::Pending
    }
}

fn wake(state: &mut FlowState) {
    if let Some(waker) = state.waker.take() {
        waker.wake();
    }
}

/// Receive handle for one stream's RFC 9298 UDP payloads.
///
/// At most [`MAX_QUEUED_FLOW_DATAGRAMS`] payloads are buffered; newer ones are
/// dropped and counted while the queue is full, so the connection's datagram
/// reader never waits for the flow's consumer.
pub(super) struct DatagramFlow {
    shared: Arc<FlowShared>,
    state: Arc<Mutex<RouterState>>,
    stream_id: u64,
    token: u64,
}

impl DatagramFlow {
    pub(super) const fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Returns the next queued UDP payload, or why the flow ended.
    pub(super) fn poll_recv(&self, context: &mut Context<'_>) -> Poll<Result<Bytes, FlowEnd>> {
        self.shared.poll_recv(context)
    }

    /// Delivers an HTTP Datagram Payload received in a DATAGRAM capsule.
    pub(super) fn deliver_capsule(&self, payload: Bytes) {
        self.shared.deliver(payload);
    }

    pub(super) fn counters(&self) -> FlowCounters {
        self.shared.counters()
    }
}

impl std::fmt::Debug for DatagramFlow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DatagramFlow")
            .field("stream_id", &self.stream_id)
            .finish_non_exhaustive()
    }
}

impl Drop for DatagramFlow {
    fn drop(&mut self) {
        lock(&self.state).unregister(self.stream_id, self.token);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::Arc,
        task::{Context, Poll, Waker},
        time::{Duration, Instant},
    };

    use bytes::Bytes;
    use tokio::sync::oneshot;

    use super::{
        FlowEnd, FlowShared, MAX_PENDING_VIOLATIONS, MAX_QUEUED_FLOW_DATAGRAMS, RouterState,
    };

    fn drain(flow: &FlowShared) -> Vec<Bytes> {
        flow.lock().queue.drain(..).collect()
    }

    #[test]
    fn datagram_flow_routes_only_to_its_stream() {
        let mut state = RouterState::new(Duration::from_secs(1));
        let first = Arc::new(FlowShared::default());
        let second = Arc::new(FlowShared::default());
        let (monitor, mut monitor_rx) = oneshot::channel();
        state.register_flow(0, Arc::clone(&first));
        state.register(4, monitor);
        state.register_flow(8, Arc::clone(&second));

        state.notify(8, Bytes::from_static(b"\x00second"));
        state.notify(0, Bytes::from_static(b"\x00first"));
        state.notify(0, Bytes::from_static(b"\x00again"));

        assert_eq!(drain(&first), [&b"first"[..], &b"again"[..]]);
        assert_eq!(drain(&second), [&b"second"[..]]);
        assert!(matches!(
            monitor_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert!(state.active.contains_key(&0));
    }

    #[test]
    fn flow_overflow_drops_new_payloads_without_blocking() {
        let mut state = RouterState::new(Duration::from_secs(1));
        let flow = Arc::new(FlowShared::default());
        state.register_flow(0, Arc::clone(&flow));

        for index in 0..MAX_QUEUED_FLOW_DATAGRAMS + 3 {
            let mut payload = vec![0];
            payload.extend_from_slice(&index.to_be_bytes());
            state.notify(0, Bytes::from(payload));
        }

        let queued = drain(&flow);
        assert_eq!(queued.len(), MAX_QUEUED_FLOW_DATAGRAMS);
        assert_eq!(queued[0].as_ref(), 0_usize.to_be_bytes());
        assert_eq!(flow.lock().counters.dropped_overflow, 3);
        assert!(flow.lock().end.is_none());
    }

    #[test]
    fn unknown_context_and_malformed_payloads_are_dropped() {
        let mut state = RouterState::new(Duration::from_secs(1));
        let flow = Arc::new(FlowShared::default());
        state.register_flow(0, Arc::clone(&flow));

        state.notify(0, Bytes::from_static(b"\x02client-context"));
        state.notify(0, Bytes::from_static(b"@\x00two-byte-zero"));
        state.notify(0, Bytes::new());
        state.notify(0, Bytes::from_static(b"@"));

        assert_eq!(drain(&flow), [&b"two-byte-zero"[..]]);
        let counters = flow.lock().counters;
        assert_eq!(counters.dropped_unknown_context, 1);
        assert_eq!(counters.dropped_malformed, 2);
    }

    #[test]
    fn early_flow_datagram_is_dropped_without_a_violation() {
        let mut state = RouterState::new(Duration::from_secs(1));
        state.notify(0, Bytes::from_static(b"\x00early"));
        let flow = Arc::new(FlowShared::default());

        state.register_flow(0, Arc::clone(&flow));
        state.notify(0, Bytes::from_static(b"\x00later"));

        assert!(!state.failed);
        assert!(state.pending.is_empty());
        assert_eq!(drain(&flow), [&b"later"[..]]);
        assert_eq!(flow.lock().counters.dropped_early, 1);
    }

    #[test]
    fn oversized_udp_payload_ends_the_flow() {
        let mut state = RouterState::new(Duration::from_secs(1));
        let flow = Arc::new(FlowShared::default());
        state.register_flow(0, Arc::clone(&flow));
        state.notify(0, Bytes::from_static(b"\x00queued"));

        state.notify(0, Bytes::from(vec![0; super::MAX_UDP_PAYLOAD_LEN + 2]));

        assert_eq!(flow.lock().end, Some(FlowEnd::OversizedPayload));
        assert!(drain(&flow).is_empty());
    }

    #[test]
    fn stopped_router_ends_flows_after_queued_payloads() {
        let mut state = RouterState::new(Duration::from_secs(1));
        let shared = Arc::new(FlowShared::default());
        state.register_flow(0, Arc::clone(&shared));
        state.notify(0, Bytes::from_static(b"\x00last"));
        state.stop();
        let flow = super::DatagramFlow {
            shared,
            state: Arc::new(std::sync::Mutex::new(RouterState::new(
                Duration::from_secs(1),
            ))),
            stream_id: 0,
            token: 0,
        };
        let mut context = Context::from_waker(Waker::noop());

        assert_eq!(
            flow.poll_recv(&mut context),
            Poll::Ready(Ok(Bytes::from_static(b"last")))
        );
        assert_eq!(
            flow.poll_recv(&mut context),
            Poll::Ready(Err(FlowEnd::ConnectionClosed))
        );
        assert_eq!(flow.counters().delivered, 1);
    }

    #[test]
    fn routes_each_stream_to_its_own_monitor() {
        let mut state = RouterState::new(Duration::from_secs(1));
        let (first, mut first_rx) = oneshot::channel();
        let (second, mut second_rx) = oneshot::channel();
        state.register(0, first);
        state.register(4, second);

        state.notify(4, Bytes::new());

        assert!(matches!(
            first_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(second_rx.try_recv(), Ok(()));
    }

    #[test]
    fn pre_registration_violation_is_delivered_once() {
        let mut state = RouterState::new(Duration::from_secs(1));
        state.notify(8, Bytes::new());
        state.notify(8, Bytes::new());
        let (sender, mut receiver) = oneshot::channel();

        state.register(8, sender);

        assert_eq!(receiver.try_recv(), Ok(()));
        assert!(state.pending.is_empty());
    }

    #[test]
    fn expired_violation_fails_closed_for_later_registration() {
        let lifetime = Duration::from_millis(10);
        let now = Instant::now();
        let mut state = RouterState::new(lifetime);
        state.notify_at(12, Bytes::new(), now);
        let (sender, mut receiver) = oneshot::channel();

        state.register_at(12, sender, now + lifetime);

        assert_eq!(receiver.try_recv(), Ok(()));
        assert!(state.failed);
    }

    #[test]
    fn pending_violation_overflow_fails_closed() {
        let now = Instant::now();
        let mut state = RouterState::new(Duration::from_secs(1));
        state.notify_at(0, Bytes::new(), now);
        state.notify_at(0, Bytes::new(), now);
        for stream_id in 1..=MAX_PENDING_VIOLATIONS as u64 {
            state.notify_at(stream_id, Bytes::new(), now);
        }

        assert!(state.failed);
        assert!(state.pending.is_empty());
    }

    #[test]
    fn datagram_for_a_closed_stream_is_dropped_without_failing() {
        let lifetime = Duration::from_millis(10);
        let now = Instant::now();
        let mut state = RouterState::new(lifetime);
        let (closed, _closed_rx) = oneshot::channel();
        let closed_token = state.register_at(0, closed, now);
        state.unregister(0, closed_token);

        state.notify_at(0, Bytes::new(), now);
        let (later, mut later_rx) = oneshot::channel();
        state.register_at(4, later, now + lifetime);

        assert!(!state.failed);
        assert!(state.pending.is_empty());
        assert!(matches!(
            later_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn pending_datagram_for_a_stream_that_never_registered_is_dropped() {
        let lifetime = Duration::from_millis(10);
        let now = Instant::now();
        let mut state = RouterState::new(lifetime);
        state.notify_at(0, Bytes::new(), now);
        let (later, mut later_rx) = oneshot::channel();

        state.register_at(4, later, now);
        state.notify_at(8, Bytes::new(), now + lifetime / 2);
        let (next, _next_rx) = oneshot::channel();
        state.register_at(12, next, now + lifetime);

        assert!(!state.failed);
        assert!(state.pending.is_empty());
        assert!(matches!(
            later_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn unregister_and_stop_do_not_report_false_violations() {
        let mut state = RouterState::new(Duration::from_secs(1));
        let (first, mut first_rx) = oneshot::channel();
        let (second, mut second_rx) = oneshot::channel();
        let first_token = state.register(0, first);
        state.register(4, second);

        state.unregister(0, first_token);
        state.stop();

        assert!(matches!(
            first_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert!(matches!(
            second_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Closed)
        ));
        assert!(state.active.is_empty());
        assert!(state.pending.is_empty());
    }
}
