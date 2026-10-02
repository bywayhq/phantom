//! Scripted attempts: each dial reports its address to the test, which then
//! decides its outcome, and the delay completes only when the test fires it.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use super::connect;

type Outcome = io::Result<SocketAddr>;
type TestResult = Result<(), Box<dyn std::error::Error>>;

const WAIT: Duration = Duration::from_secs(5);

fn v6(last: u16) -> SocketAddr {
    SocketAddr::new(
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last).into(),
        443,
    )
}

fn v4(last: u8) -> SocketAddr {
    SocketAddr::new(Ipv4Addr::new(192, 0, 2, last).into(), 443)
}

fn refused() -> Outcome {
    Err(io::ErrorKind::ConnectionRefused.into())
}

/// One dial the backup algorithm made: its address and its outcome slot.
struct Dialed {
    address: SocketAddr,
    outcome: oneshot::Sender<Outcome>,
}

struct Connection {
    dials: mpsc::UnboundedReceiver<Dialed>,
    delay: Option<oneshot::Sender<()>>,
    started: Instant,
    task: JoinHandle<io::Result<(SocketAddr, Instant)>>,
}

impl Connection {
    fn start(addresses: &[SocketAddr]) -> Self {
        let (dials_tx, dials) = mpsc::unbounded_channel();
        let (delay_tx, delay_rx) = oneshot::channel::<()>();
        let dial = move |address: SocketAddr| {
            let (outcome, receiver) = oneshot::channel();
            let _ = dials_tx.send(Dialed { address, outcome });
            async move {
                receiver
                    .await
                    .unwrap_or_else(|_| Err(io::Error::other("attempt dropped")))
            }
        };
        let delay = async {
            let _ = delay_rx.await;
        };
        let started = Instant::now();
        let task = tokio::spawn(connect(addresses.to_vec(), delay, dial, started));
        Self {
            dials,
            delay: Some(delay_tx),
            started,
            task,
        }
    }

    async fn next_dial(&mut self) -> Result<Dialed, Box<dyn std::error::Error>> {
        Ok(tokio::time::timeout(WAIT, self.dials.recv())
            .await?
            .ok_or("no further dial")?)
    }

    fn fire_delay(&mut self) {
        if let Some(delay) = self.delay.take() {
            let _ = delay.send(());
        }
    }

    async fn result(self) -> Result<io::Result<(SocketAddr, Instant)>, Box<dyn std::error::Error>> {
        Ok(tokio::time::timeout(WAIT, self.task).await??)
    }
}

fn answer(dialed: Dialed, outcome: Outcome) {
    let _ = dialed.outcome.send(outcome);
}

#[tokio::test(flavor = "current_thread")]
async fn a_primary_that_connects_first_needs_no_backup() -> TestResult {
    let mut connection = Connection::start(&[v6(1), v4(1)]);
    let primary = connection.next_dial().await?;
    assert_eq!(primary.address, v6(1));
    answer(primary, Ok(v6(1)));
    let started = connection.started;

    let (address, attempt_started) = connection.result().await??;

    assert_eq!(address, v6(1));
    assert_eq!(attempt_started, started);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_slow_primary_gets_an_ipv4_backup_that_can_win() -> TestResult {
    let mut connection = Connection::start(&[v6(1), v6(2), v4(1), v4(2)]);
    let primary = connection.next_dial().await?;
    assert_eq!(primary.address, v6(1));

    connection.fire_delay();
    let backup = connection.next_dial().await?;
    assert_eq!(backup.address, v4(1));
    answer(backup, Ok(v4(1)));
    let started = connection.started;

    let (address, attempt_started) = connection.result().await??;

    assert_eq!(address, v4(1));
    assert!(attempt_started > started);
    // The primary attempt was dropped while it still connected.
    assert!(primary.outcome.is_closed());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_refused_connect_moves_to_the_next_address_at_once() -> TestResult {
    let mut connection = Connection::start(&[v6(1), v4(1)]);
    answer(connection.next_dial().await?, refused());

    let next = connection.next_dial().await?;
    assert_eq!(next.address, v4(1));
    answer(next, Ok(v4(1)));

    let (address, _) = connection.result().await??;
    assert_eq!(address, v4(1));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_unreachable_or_timed_out_connect_also_moves_on() -> TestResult {
    for kind in [
        io::ErrorKind::NetworkUnreachable,
        io::ErrorKind::HostUnreachable,
        io::ErrorKind::TimedOut,
    ] {
        let mut connection = Connection::start(&[v6(1), v4(1)]);
        answer(connection.next_dial().await?, Err(kind.into()));
        let next = connection.next_dial().await?;
        assert_eq!(next.address, v4(1), "{kind:?}");
        answer(next, Ok(v4(1)));
        connection.result().await??;
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn another_failure_ends_the_primary_without_a_backup() -> TestResult {
    let mut connection = Connection::start(&[v6(1), v4(1)]);
    answer(
        connection.next_dial().await?,
        Err(io::ErrorKind::ConnectionReset.into()),
    );

    let error = match connection.result().await? {
        Ok(_) => return Err("a reset connect was not the result".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn the_backup_tries_its_next_ipv4_address_and_the_primary_can_still_win() -> TestResult {
    let mut connection = Connection::start(&[v4(1), v4(2)]);
    let primary = connection.next_dial().await?;
    assert_eq!(primary.address, v4(1));

    connection.fire_delay();
    let backup = connection.next_dial().await?;
    assert_eq!(backup.address, v4(1));
    answer(backup, refused());
    let backup_next = connection.next_dial().await?;
    assert_eq!(backup_next.address, v4(2));
    answer(backup_next, refused());

    answer(primary, Ok(v4(1)));
    let (address, _) = connection.result().await??;
    assert_eq!(address, v4(1));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn when_both_attempts_fail_the_last_failure_is_returned() -> TestResult {
    let mut connection = Connection::start(&[v6(1), v4(1)]);
    let primary = connection.next_dial().await?;
    connection.fire_delay();
    let backup = connection.next_dial().await?;
    answer(backup, Err(io::ErrorKind::ConnectionReset.into()));
    // Let the backup's failure land before the primary's.
    tokio::task::yield_now().await;
    answer(primary, refused());
    let primary_next = connection.next_dial().await?;
    assert_eq!(primary_next.address, v4(1));
    answer(primary_next, Err(io::ErrorKind::TimedOut.into()));

    let error = match connection.result().await? {
        Ok(_) => return Err("a failed connection succeeded".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_ipv6_only_host_gets_no_backup() -> TestResult {
    let mut connection = Connection::start(&[v6(1)]);
    let primary = connection.next_dial().await?;
    connection.fire_delay();
    tokio::task::yield_now().await;
    assert!(connection.dials.try_recv().is_err(), "a backup was dialed");
    answer(primary, Ok(v6(1)));

    let (address, _) = connection.result().await??;
    assert_eq!(address, v6(1));
    Ok(())
}
