use serde::Serialize;
use tokio::runtime::Handle;

/// Boundary snapshots only; busy time measures scheduler activity, not CPU.
#[derive(Serialize)]
pub(crate) struct Snapshot {
    alive_tasks: usize,
    global_queue_depth: usize,
    workers: Vec<Worker>,
}

#[derive(Serialize)]
struct Worker {
    index: usize,
    #[cfg(target_has_atomic = "64")]
    busy_ns: u64,
    #[cfg(target_has_atomic = "64")]
    parks: u64,
    #[cfg(target_has_atomic = "64")]
    park_unpark_transitions: u64,
}

impl Snapshot {
    pub(crate) fn capture() -> Self {
        let metrics = Handle::current().metrics();
        Self {
            alive_tasks: metrics.num_alive_tasks(),
            global_queue_depth: metrics.global_queue_depth(),
            workers: (0..metrics.num_workers())
                .map(|index| Worker {
                    index,
                    #[cfg(target_has_atomic = "64")]
                    busy_ns: super::client::nanos(metrics.worker_total_busy_duration(index)),
                    #[cfg(target_has_atomic = "64")]
                    parks: metrics.worker_park_count(index),
                    #[cfg(target_has_atomic = "64")]
                    park_unpark_transitions: metrics.worker_park_unpark_count(index),
                })
                .collect(),
        }
    }
}
