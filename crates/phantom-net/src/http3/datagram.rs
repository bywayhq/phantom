use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard},
    task::{Context, Poll},
    time::{Duration, Instant},
};

use h3::quic::StreamId;
use h3_datagram::datagram_handler::DatagramReader;
use tokio::{runtime::Handle, sync::oneshot, task::JoinHandle};
use tracing::{Instrument, debug, debug_span, dispatcher, instrument::WithSubscriber};

type Reader = DatagramReader<h3_quinn::datagram::RecvDatagramHandler>;

const MAX_DATAGRAMS_PER_TURN: usize = 32;
const MAX_PENDING_VIOLATIONS: usize = 64;
const MIN_PENDING_LIFETIME: Duration = Duration::from_millis(10);
const MAX_PENDING_LIFETIME: Duration = Duration::from_secs(1);

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
                                lock(&task_state).notify(datagram.stream_id().into_inner());
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

    pub(super) fn is_failed(&self) -> bool {
        lock(&self.state).failed
    }
}

impl std::fmt::Debug for DatagramRouter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DatagramRouter")
            .finish_non_exhaustive()
    }
}

struct RouterState {
    next_token: u64,
    active: HashMap<u64, (u64, oneshot::Sender<()>)>,
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
        self.prune(now);
        self.next_token = self.next_token.wrapping_add(1);
        let token = self.next_token;
        if self.failed {
            let _ = sender.send(());
            return token;
        }
        if self.stopped {
            return token;
        }
        if let Some(position) = self
            .pending
            .iter()
            .position(|candidate| candidate.stream_id == stream_id)
        {
            self.pending.remove(position);
            let _ = sender.send(());
            return token;
        }
        if let Some((_, previous)) = self.active.insert(stream_id, (token, sender)) {
            let _ = previous.send(());
        }
        token
    }

    fn notify(&mut self, stream_id: u64) {
        self.notify_at(stream_id, Instant::now());
    }

    fn notify_at(&mut self, stream_id: u64, now: Instant) {
        if self.stopped {
            return;
        }
        self.prune(now);
        if self.failed {
            return;
        }
        if let Some((_, sender)) = self.active.remove(&stream_id) {
            let _ = sender.send(());
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
        self.active.clear();
        self.pending.clear();
    }

    fn fail(&mut self, reason: &'static str) {
        if self.failed {
            return;
        }
        self.failed = true;
        debug!(reason, "HTTP/3 datagram router failed closed");
        self.pending.clear();
        for (_, sender) in self.active.drain().map(|(_, value)| value) {
            let _ = sender.send(());
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

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use tokio::sync::oneshot;

    use super::{MAX_PENDING_VIOLATIONS, RouterState};

    #[test]
    fn routes_each_stream_to_its_own_monitor() {
        let mut state = RouterState::new(Duration::from_secs(1));
        let (first, mut first_rx) = oneshot::channel();
        let (second, mut second_rx) = oneshot::channel();
        state.register(0, first);
        state.register(4, second);

        state.notify(4);

        assert!(matches!(
            first_rx.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        ));
        assert_eq!(second_rx.try_recv(), Ok(()));
    }

    #[test]
    fn pre_registration_violation_is_delivered_once() {
        let mut state = RouterState::new(Duration::from_secs(1));
        state.notify(8);
        state.notify(8);
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
        state.notify_at(12, now);
        let (sender, mut receiver) = oneshot::channel();

        state.register_at(12, sender, now + lifetime);

        assert_eq!(receiver.try_recv(), Ok(()));
        assert!(state.failed);
    }

    #[test]
    fn pending_violation_overflow_fails_closed() {
        let now = Instant::now();
        let mut state = RouterState::new(Duration::from_secs(1));
        state.notify_at(0, now);
        state.notify_at(0, now);
        for stream_id in 1..=MAX_PENDING_VIOLATIONS as u64 {
            state.notify_at(stream_id, now);
        }

        assert!(state.failed);
        assert!(state.pending.is_empty());
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
