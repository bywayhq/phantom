//! Runtime-neutral deadlines for HTTP/2 driver shutdown.

use std::{
    cmp::Ordering,
    collections::BinaryHeap,
    sync::{
        OnceLock,
        atomic::{AtomicU64, Ordering as AtomicOrdering},
        mpsc::{self, RecvTimeoutError, Sender},
    },
    thread,
    time::{Duration, Instant},
};

use tokio::sync::oneshot;

static SERVICE: OnceLock<Option<Sender<Deadline>>> = OnceLock::new();
static NEXT_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
pub(super) struct ScheduleError;

pub(super) fn after(delay: Duration) -> Result<oneshot::Receiver<()>, ScheduleError> {
    let service = SERVICE
        .get_or_init(start_service)
        .as_ref()
        .ok_or(ScheduleError)?;
    let (signal, receiver) = oneshot::channel();
    let deadline = Deadline {
        at: Instant::now().checked_add(delay).ok_or(ScheduleError)?,
        sequence: NEXT_SEQUENCE.fetch_add(1, AtomicOrdering::Relaxed),
        signal,
    };
    service.send(deadline).map_err(|_| ScheduleError)?;
    Ok(receiver)
}

fn start_service() -> Option<Sender<Deadline>> {
    let (sender, receiver) = mpsc::channel();
    thread::Builder::new()
        .name("phantom-h2-shutdown-timer".to_owned())
        .spawn(move || run(receiver))
        .ok()
        .map(|_| sender)
}

fn run(receiver: mpsc::Receiver<Deadline>) {
    let mut deadlines = BinaryHeap::new();
    loop {
        while deadlines
            .peek()
            .is_some_and(|deadline: &Deadline| deadline.at <= Instant::now())
        {
            if let Some(deadline) = deadlines.pop() {
                let _ = deadline.signal.send(());
            }
        }

        let received = match deadlines.peek() {
            Some(deadline) => {
                receiver.recv_timeout(deadline.at.saturating_duration_since(Instant::now()))
            }
            None => receiver.recv().map_err(|_| RecvTimeoutError::Disconnected),
        };
        match received {
            Ok(deadline) => deadlines.push(deadline),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return,
        }
    }
}

struct Deadline {
    at: Instant,
    sequence: u64,
    signal: oneshot::Sender<()>,
}

impl PartialEq for Deadline {
    fn eq(&self, other: &Self) -> bool {
        self.at == other.at && self.sequence == other.sequence
    }
}

impl Eq for Deadline {}

impl PartialOrd for Deadline {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Deadline {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .at
            .cmp(&self.at)
            .then_with(|| other.sequence.cmp(&self.sequence))
    }
}
