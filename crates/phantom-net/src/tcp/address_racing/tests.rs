//! Scripted attempts: each dialed address waits for the test to decide its
//! outcome, and the fallback delay completes only when the test fires it.

use std::{
    collections::HashMap,
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
};

use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use super::race;

type Outcome = io::Result<SocketAddr>;

fn v6(last: u16) -> SocketAddr {
    SocketAddr::new(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last).into(),
        443,
    )
}

fn v4(last: u8) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(192, 0, 2, last).into(), 443)
}

struct CancelGuard {
    address: SocketAddr,
    finished: bool,
    cancelled: mpsc::UnboundedSender<SocketAddr>,
}

impl Drop for CancelGuard {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.cancelled.send(self.address);
        }
    }
}

struct Race {
    started: mpsc::UnboundedReceiver<SocketAddr>,
    cancelled: mpsc::UnboundedReceiver<SocketAddr>,
    outcomes: HashMap<SocketAddr, oneshot::Sender<Outcome>>,
    fallback: Option<oneshot::Sender<()>>,
    task: JoinHandle<Outcome>,
}

impl Race {
    fn start(addresses: &[SocketAddr]) -> Self {
        let (started_tx, started) = mpsc::unbounded_channel();
        let (cancelled_tx, cancelled) = mpsc::unbounded_channel();
        let (fallback_tx, fallback_rx) = oneshot::channel::<()>();
        let mut outcomes = HashMap::new();
        let mut receivers = HashMap::new();
        for address in addresses {
            let (sender, receiver) = oneshot::channel();
            outcomes.insert(*address, sender);
            receivers.insert(*address, receiver);
        }
        let dial = move |address: SocketAddr| {
            let _ = started_tx.send(address);
            let receiver = receivers.remove(&address);
            let cancelled = cancelled_tx.clone();
            async move {
                let mut guard = CancelGuard {
                    address,
                    finished: false,
                    cancelled,
                };
                let outcome = match receiver {
                    Some(receiver) => receiver
                        .await
                        .unwrap_or_else(|_| Err(io::Error::other("outcome dropped"))),
                    None => Err(io::Error::other("address dialed twice")),
                };
                guard.finished = true;
                outcome
            }
        };
        let fallback = async {
            let _ = fallback_rx.await;
        };
        let task = tokio::spawn(race(addresses.to_vec(), fallback, dial));
        Self {
            started,
            cancelled,
            outcomes,
            fallback: Some(fallback_tx),
            task,
        }
    }

    /// Lets the race task run until it waits on the test again.
    async fn settle() {
        for _ in 0..16 {
            tokio::task::yield_now().await;
        }
    }

    async fn started(&mut self) -> Vec<SocketAddr> {
        Self::settle().await;
        let mut started = Vec::new();
        while let Ok(address) = self.started.try_recv() {
            started.push(address);
        }
        started
    }

    async fn cancelled(&mut self) -> Vec<SocketAddr> {
        Self::settle().await;
        let mut cancelled = Vec::new();
        while let Ok(address) = self.cancelled.try_recv() {
            cancelled.push(address);
        }
        cancelled
    }

    fn resolve(&mut self, address: SocketAddr, outcome: Outcome) -> Result<(), String> {
        self.outcomes
            .remove(&address)
            .ok_or_else(|| format!("{address} has no pending outcome"))?
            .send(outcome)
            .map_err(|_| format!("{address} is no longer being attempted"))
    }

    fn succeed(&mut self, address: SocketAddr) -> Result<(), String> {
        self.resolve(address, Ok(address))
    }

    fn fail(&mut self, address: SocketAddr) -> Result<(), String> {
        self.resolve(
            address,
            Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                address.to_string(),
            )),
        )
    }

    fn fire_fallback(&mut self) -> Result<(), String> {
        self.fallback
            .take()
            .ok_or("fallback already fired")?
            .send(())
            .map_err(|()| "race no longer waits for the fallback".to_owned())
    }

    async fn finish(self) -> Result<Outcome, tokio::task::JoinError> {
        self.task.await
    }
}

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test(flavor = "current_thread")]
async fn first_attempt_prefers_ipv6_over_resolver_order() -> TestResult {
    let mut race = Race::start(&[v4(1), v6(1)]);

    assert_eq!(race.started().await, [v6(1)]);
    race.succeed(v6(1))?;
    assert_eq!(race.finish().await??, v6(1));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn fallback_adds_ipv4_attempt_and_winner_cancels_the_other() -> TestResult {
    let mut race = Race::start(&[v6(1), v6(2), v4(1)]);
    assert_eq!(race.started().await, [v6(1)]);

    race.fire_fallback()?;
    assert_eq!(race.started().await, [v4(1)]);
    race.succeed(v4(1))?;

    assert_eq!(race.cancelled().await, [v6(1)]);
    assert_eq!(race.finish().await??, v4(1));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn one_attempt_alternates_families_after_each_failure() -> TestResult {
    let mut race = Race::start(&[v6(1), v6(2), v4(1), v4(2)]);

    assert_eq!(race.started().await, [v6(1)]);
    race.fail(v6(1))?;
    assert_eq!(race.started().await, [v4(1)]);
    race.fail(v4(1))?;
    assert_eq!(race.started().await, [v6(2)]);
    race.fail(v6(2))?;
    assert_eq!(race.started().await, [v4(2)]);
    race.fail(v4(2))?;

    let error = match race.finish().await? {
        Ok(address) => return Err(format!("connected to {address}").into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
    assert_eq!(error.to_string(), v4(2).to_string());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn primary_on_ipv4_at_fallback_becomes_the_ipv4_attempt() -> TestResult {
    let mut race = Race::start(&[v6(1), v6(2), v4(1), v4(2)]);
    assert_eq!(race.started().await, [v6(1)]);
    race.fail(v6(1))?;
    assert_eq!(race.started().await, [v4(1)]);

    race.fire_fallback()?;
    assert_eq!(race.started().await, [v6(2)]);
    assert_eq!(race.cancelled().await, []);

    race.fail(v4(1))?;
    assert_eq!(race.started().await, [v4(2)]);
    race.fail(v6(2))?;
    assert_eq!(race.started().await, []);
    race.succeed(v4(2))?;
    assert_eq!(race.finish().await??, v4(2));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn two_attempts_prefer_their_own_family_and_never_exceed_two() -> TestResult {
    let mut race = Race::start(&[v6(1), v6(2), v6(3), v4(1), v4(2), v4(3)]);
    assert_eq!(race.started().await, [v6(1)]);
    race.fire_fallback()?;
    assert_eq!(race.started().await, [v4(1)]);
    assert_eq!(race.started().await, []);

    race.fail(v6(1))?;
    assert_eq!(race.started().await, [v6(2)]);
    race.fail(v4(1))?;
    assert_eq!(race.started().await, [v4(2)]);
    race.fail(v4(2))?;
    assert_eq!(race.started().await, [v4(3)]);
    race.fail(v4(3))?;
    // The IPv4 attempt falls back to IPv6 once IPv4 is exhausted.
    assert_eq!(race.started().await, [v6(3)]);

    race.succeed(v6(3))?;
    assert_eq!(race.cancelled().await, [v6(2)]);
    assert_eq!(race.finish().await??, v6(3));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn single_family_hosts_still_get_a_second_attempt() -> TestResult {
    let mut race = Race::start(&[v4(1), v4(2)]);
    assert_eq!(race.started().await, [v4(1)]);

    race.fire_fallback()?;
    assert_eq!(race.started().await, [v4(2)]);
    race.succeed(v4(1))?;
    assert_eq!(race.cancelled().await, [v4(2)]);
    assert_eq!(race.finish().await??, v4(1));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn exhausted_single_attempt_fails_without_waiting_for_fallback() -> TestResult {
    let mut race = Race::start(&[v6(1), v6(1)]);
    assert_eq!(race.started().await, [v6(1)]);
    race.fail(v6(1))?;

    let error = match race.finish().await? {
        Ok(address) => return Err(format!("connected to {address}").into()),
        Err(error) => error,
    };
    assert_eq!(error.to_string(), v6(1).to_string());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn no_addresses_is_invalid_input() -> TestResult {
    let race = Race::start(&[]);

    let error = match race.finish().await? {
        Ok(address) => return Err(format!("connected to {address}").into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    Ok(())
}
