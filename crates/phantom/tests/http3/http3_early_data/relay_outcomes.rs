use std::{error::Error, fmt, io};

use tokio::task::AbortHandle;

use crate::support::tunnel_proxy::finish_with_cleanup;
use super::*;
use relay_observation::RelayObservation;

const OBSERVATION_LIMIT: Duration = Duration::from_secs(2);

pub(crate) struct RelayBackup {
    pub(crate) observation: Arc<RelayObservation>,
    owner: Option<AbortHandle>,
}

impl RelayBackup {
    pub(crate) fn new() -> Self {
        Self {
            observation: Arc::new(RelayObservation::default()),
            owner: None,
        }
    }

    pub(crate) fn register(&mut self, owner: AbortHandle) {
        self.owner = Some(owner);
    }

    fn abort(&self) {
        if let Some(owner) = &self.owner {
            owner.abort();
        }
        if let Some(worker) = &*self
            .observation
            .worker
            .lock()
            .expect("relay worker lock poisoned")
        {
            worker.abort();
        }
    }

    pub(crate) async fn finish(&self) -> TestResult<()> {
        self.abort();
        timeout(Duration::from_secs(5), async {
            while self.owner.as_ref().is_some_and(|owner| !owner.is_finished()) {
                tokio::task::yield_now().await;
            }

            // Parent destruction prevents any further child publication.
            self.abort();
            loop {
                let finished = self
                    .observation
                    .worker
                    .lock()
                    .expect("relay worker lock poisoned")
                    .as_ref()
                    .is_none_or(AbortHandle::is_finished);
                if finished {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await?;

        Ok(())
    }
}

impl Drop for RelayBackup {
    fn drop(&mut self) {
        self.abort();
    }
}

#[derive(Debug)]
struct LocalReadFailure(Arc<()>);

impl fmt::Display for LocalReadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled relay receiver failure")
    }
}

impl Error for LocalReadFailure {}

#[derive(Debug)]
struct RelayDropDeadline(tokio::time::error::Elapsed);

impl fmt::Display for RelayDropDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("abandoned relay kept its actual receiver alive")
    }
}

impl Error for RelayDropDeadline {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

pub(crate) async fn exchange(
    client: &UdpSocket,
    target: &UdpSocket,
    relay: SocketAddr,
) -> TestResult<SocketAddr> {
    client.send_to(b"request", relay).await?;
    let mut bytes = [0; 64];
    let (len, upstream) = timeout(Duration::from_secs(5), target.recv_from(&mut bytes)).await??;
    if &bytes[..len] != b"request" {
        return Err("relay changed the literal request datagram".into());
    }

    target.send_to(b"response", upstream).await?;
    let (len, from) = timeout(Duration::from_secs(5), client.recv_from(&mut bytes)).await??;
    if from != relay || &bytes[..len] != b"response" {
        return Err("relay changed the literal response datagram or source".into());
    }

    Ok(upstream)
}

pub(crate) async fn pending_front(observation: &RelayObservation) -> TestResult<()> {
    timeout(Duration::from_secs(5), async {
        while !observation.front.pending_after_packet.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await?;

    Ok(())
}

enum RelayKind {
    Delayed,
    Gated,
}

enum ObservedContract {
    Abandonment,
    CompletedReadFailure,
}

async fn exercise(kind: RelayKind, contract: ObservedContract) -> TestResult<()> {
    let mut backup = RelayBackup::new();
    let result: TestResult<()> = async {
        let target = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let client = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let (gate, open) = tokio::sync::watch::channel(true);
        let (address, task) = if matches!(kind, RelayKind::Gated) {
            gated_relay_observed(target.local_addr()?, open, Some(Arc::clone(&backup.observation)))
                .await?
        } else {
            delaying_relay_observed(target.local_addr()?, Some(Arc::clone(&backup.observation)))
                .await?
        };
        backup.register(task.abort_handle());

        let upstream = exchange(&client, &target, address).await?;
        pending_front(&backup.observation).await?;
        timeout(Duration::from_secs(5), async {
            while !backup.observation.reply.pending_after_packet.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let worker = backup
            .observation
            .worker
            .lock()
            .expect("relay worker lock poisoned")
            .clone()
            .ok_or("relay did not publish its actual receiver")?;
        if worker.is_finished() || task.is_finished() {
            return Err("relay completed before its pending ownership observation".into());
        }

        if matches!(contract, ObservedContract::CompletedReadFailure) {
            let marker = Arc::new(());
            backup.observation.reply.fail_next_read(io::Error::new(
                io::ErrorKind::PermissionDenied,
                LocalReadFailure(Arc::clone(&marker)),
            ));
            timeout(Duration::from_secs(5), async {
                while !worker.is_finished() {
                    tokio::task::yield_now().await;
                }
            })
            .await?;
            if !backup.observation.reply.invoked.load(Ordering::SeqCst)
                || !backup.observation.reply.destroyed.load(Ordering::SeqCst)
            {
                return Err("actual receiver did not consume the controlled read failure".into());
            }

            let error = timeout(Duration::from_secs(5), stop_relay(task))
                .await?
                .err()
                .ok_or("canonical relay stop discarded its completed local read failure")?;
            let error = error
                .downcast_ref::<io::Error>()
                .ok_or("relay lost its I/O type")?;
            if error.kind() != io::ErrorKind::PermissionDenied {
                return Err("relay changed the original I/O error kind".into());
            }
            let cause = error
                .get_ref()
                .and_then(|error| error.downcast_ref::<LocalReadFailure>())
                .ok_or("relay lost its original local read cause")?;
            if !Arc::ptr_eq(&cause.0, &marker) {
                return Err("relay replaced the original local read cause".into());
            }
        } else {
            drop(task);
            timeout(OBSERVATION_LIMIT, async {
                while !backup.observation.front.destroyed.load(Ordering::SeqCst)
                    || !backup.observation.reply.destroyed.load(Ordering::SeqCst)
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(RelayDropDeadline)?;
            let _front = phantom_testkit::udp::bind_tokio(address)?;
            let _reply = phantom_testkit::udp::bind_tokio(upstream)?;
        }
        if !*gate.borrow() {
            return Err("relay gate changed during ownership observation".into());
        }

        Ok(())
    }
    .await;
    let cleanup = backup.finish().await;
    finish_with_cleanup(result, cleanup)
}

#[tokio::test(flavor = "current_thread")]
async fn abandoning_a_delaying_relay_releases_its_actual_receiver() -> TestResult<()> {
    exercise(RelayKind::Delayed, ObservedContract::Abandonment).await
}

#[tokio::test(flavor = "current_thread")]
async fn abandoning_a_gated_relay_releases_its_actual_receiver() -> TestResult<()> {
    exercise(RelayKind::Gated, ObservedContract::Abandonment).await
}

#[tokio::test(flavor = "current_thread")]
async fn stopping_a_delaying_relay_retains_its_completed_local_read_error() -> TestResult<()> {
    exercise(RelayKind::Delayed, ObservedContract::CompletedReadFailure).await
}

#[tokio::test(flavor = "current_thread")]
async fn stopping_a_gated_relay_retains_its_completed_local_read_error() -> TestResult<()> {
    exercise(RelayKind::Gated, ObservedContract::CompletedReadFailure).await
}
