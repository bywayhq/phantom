use std::{error::Error, fmt, io};

use tokio::task::{AbortHandle, JoinError};

use super::*;
use crate::support::tunnel_proxy::{connection_peer::FixtureFailures, finish_with_cleanup};
use relay_observation::ReceiverObservation;
use relay_outcomes::{RelayBackup, exchange, pending_front};

struct ReceiverBackup {
    outer: RelayBackup,
}

impl ReceiverBackup {
    fn new() -> Self {
        let outer = RelayBackup::new();
        outer
            .observation
            .observe_receivers
            .store(true, Ordering::SeqCst);

        Self { outer }
    }

    fn abort_receivers(&self) -> (Vec<AbortHandle>, TestResult<()>) {
        let (receivers, observed) = self.outer.observation.receivers();
        let mut outcome = observed.map_err(Into::into);
        let mut workers = Vec::new();
        for receiver in receivers {
            let (worker, observed) = receiver.worker();
            outcome = finish_with_cleanup(outcome, observed.map_err(Into::into));
            if let Some(worker) = worker {
                worker.abort();
                workers.push(worker);
            }
        }

        (workers, outcome)
    }

    async fn finish(&self) -> TestResult<()> {
        let outer = self.outer.finish().await;
        // A successful outer backup freezes publication; timeout remains an error.
        let (workers, observed) = self.abort_receivers();
        let completed = timeout(Duration::from_secs(5), async {
            while workers.iter().any(|worker| !worker.is_finished()) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(Into::into);

        finish_with_cleanup(finish_with_cleanup(outer, observed), completed)
    }
}

impl Drop for ReceiverBackup {
    fn drop(&mut self) {
        let (_, outcome) = self.abort_receivers();
        if let Err(error) = outcome {
            eprintln!("relay receiver backup Drop observation failed: {error}");
        }
    }
}

async fn pending_receiver(receiver: &ReceiverObservation) -> TestResult<AbortHandle> {
    timeout(Duration::from_secs(5), async {
        while !receiver.read.pending_after_packet.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    let (worker, observed) = receiver.worker();
    observed?;
    let worker = worker.ok_or("relay did not publish the actual receiver handle")?;
    if worker.is_finished() {
        return Err("relay receiver completed before its Pending observation".into());
    }

    Ok(worker)
}

#[derive(Debug)]
struct CompletedReadFailure(Arc<()>);

impl fmt::Display for CompletedReadFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("controlled completed sibling read failure")
    }
}

impl Error for CompletedReadFailure {}

fn read_failures<'a>(error: &'a (dyn Error + 'static), failures: &mut Vec<&'a io::Error>) {
    if let Some(error) = error.downcast_ref::<io::Error>() {
        failures.push(error);
    } else if let Some(errors) = error.downcast_ref::<FixtureFailures>() {
        read_failures(errors.primary.as_ref(), failures);
        read_failures(errors.cleanup.as_ref(), failures);
    }
}

#[tokio::test(flavor = "current_thread")]
async fn stopping_a_relay_retains_both_completed_receiver_failures() -> TestResult<()> {
    let mut backup = ReceiverBackup::new();
    let result: TestResult<()> = async {
        let target = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let first = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let second = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let (address, task) = delaying_relay_observed(
            target.local_addr()?,
            Some(Arc::clone(&backup.outer.observation)),
        )
        .await?;
        backup.outer.register(task.abort_handle());

        let first_upstream = exchange(&first, &target, address).await?;
        let second_upstream = exchange(&second, &target, address).await?;
        if first_upstream == second_upstream {
            return Err("distinct relay clients shared an upstream socket".into());
        }
        let first_receiver = backup.outer.observation.receiver(first.local_addr()?)?;
        let second_receiver = backup.outer.observation.receiver(second.local_addr()?)?;
        let first_worker = pending_receiver(&first_receiver).await?;
        let second_worker = pending_receiver(&second_receiver).await?;
        pending_front(&backup.outer.observation).await?;
        if first_worker.id() == second_worker.id() {
            return Err("relay published one task for two actual receivers".into());
        }

        let first_marker = Arc::new(());
        let second_marker = Arc::new(());
        // Both installed faults wake their already-pending actual reads.
        first_receiver.read.fail_next_read(io::Error::new(
            io::ErrorKind::PermissionDenied,
            CompletedReadFailure(Arc::clone(&first_marker)),
        ))?;
        second_receiver.read.fail_next_read(io::Error::new(
            io::ErrorKind::PermissionDenied,
            CompletedReadFailure(Arc::clone(&second_marker)),
        ))?;
        timeout(Duration::from_secs(5), async {
            while !first_worker.is_finished() || !second_worker.is_finished() {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        for receiver in [&first_receiver, &second_receiver] {
            if !receiver.read.invoked.load(Ordering::SeqCst)
                || !receiver.read.destroyed.load(Ordering::SeqCst)
            {
                return Err("actual sibling read did not consume its original fault".into());
            }
        }

        let error = timeout(Duration::from_secs(5), stop_relay(task))
            .await?
            .err()
            .ok_or("canonical stop discarded two completed local receiver errors")?;
        let mut failures = Vec::new();
        read_failures(error.as_ref(), &mut failures);
        if failures.len() != 2 {
            return Err("canonical stop did not retain both typed receiver outcomes".into());
        }
        for marker in [&first_marker, &second_marker] {
            if !failures.iter().any(|error| {
                error.kind() == io::ErrorKind::PermissionDenied
                    && error
                        .get_ref()
                        .and_then(|cause| cause.downcast_ref::<CompletedReadFailure>())
                        .is_some_and(|cause| Arc::ptr_eq(&cause.0, marker))
            }) {
                return Err("canonical stop replaced a completed sibling cause".into());
            }
        }

        Ok(())
    }
    .await;
    let cleanup = backup.finish().await;
    finish_with_cleanup(result, cleanup)
}

#[tokio::test(flavor = "current_thread")]
async fn stopping_a_relay_retains_an_externally_cancelled_receiver() -> TestResult<()> {
    let mut backup = ReceiverBackup::new();
    let result: TestResult<()> = async {
        let target = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let client = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
        let (address, task) = delaying_relay_observed(
            target.local_addr()?,
            Some(Arc::clone(&backup.outer.observation)),
        )
        .await?;
        backup.outer.register(task.abort_handle());

        exchange(&client, &target, address).await?;
        let receiver = backup.outer.observation.receiver(client.local_addr()?)?;
        let worker = pending_receiver(&receiver).await?;
        pending_front(&backup.outer.observation).await?;
        let id = worker.id();
        worker.abort();
        timeout(Duration::from_secs(5), async {
            while !worker.is_finished() || !receiver.read.destroyed.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await?;

        let error = timeout(Duration::from_secs(5), stop_relay(task))
            .await?
            .err()
            .ok_or("canonical stop discarded the actual externally cancelled receiver")?;
        let error = error
            .downcast_ref::<JoinError>()
            .ok_or("relay did not retain the actual cancelled JoinError type")?;
        if !error.is_cancelled() || error.id() != id {
            return Err("relay changed the externally cancelled receiver identity".into());
        }

        Ok(())
    }
    .await;
    let cleanup = backup.finish().await;
    finish_with_cleanup(result, cleanup)
}
