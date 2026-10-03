//! Scripted attempts: each dial reports its address and timeout to the test,
//! which then decides its outcome, and the delay completes only when the test
//! fires it.

use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};

use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};

use super::{AddressFamily, AddressFamilyMemory, Plan, connect};

type Outcome = io::Result<SocketAddr>;
type TestResult = Result<(), Box<dyn std::error::Error>>;

const WAIT: Duration = Duration::from_secs(5);
const BACKUP_TIMEOUT: Duration = Duration::from_secs(5);

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

const UNKNOWN: Plan = Plan {
    family: None,
    known_family_backup_timeout: Some(BACKUP_TIMEOUT),
};

const fn knowing(family: AddressFamily) -> Plan {
    Plan {
        family: Some(family),
        known_family_backup_timeout: Some(BACKUP_TIMEOUT),
    }
}

/// One dial the backup algorithm made: its address, its timeout, and its
/// outcome slot.
struct Dialed {
    address: SocketAddr,
    timeout: Option<Duration>,
    outcome: oneshot::Sender<Outcome>,
}

/// The slower attempt, connecting in its own task: the address it reached
/// and whether it left the remembered family.
type SlowerTask = JoinHandle<io::Result<(SocketAddr, bool)>>;

/// The connection that won, and the slower attempt when one kept connecting.
struct Won {
    address: SocketAddr,
    started: Instant,
    switched_family: bool,
    slower: Option<SlowerTask>,
}

struct Connection {
    dials: mpsc::UnboundedReceiver<Dialed>,
    delay: Option<oneshot::Sender<()>>,
    started: Instant,
    task: JoinHandle<io::Result<Won>>,
}

impl Connection {
    fn start(addresses: &[SocketAddr]) -> Self {
        Self::start_with(addresses, UNKNOWN)
    }

    fn start_with(addresses: &[SocketAddr], plan: Plan) -> Self {
        let (dials_tx, dials) = mpsc::unbounded_channel();
        let (delay_tx, delay_rx) = oneshot::channel::<()>();
        let dial = move |address: SocketAddr, timeout: Option<Duration>| {
            let (outcome, receiver) = oneshot::channel();
            let _ = dials_tx.send(Dialed {
                address,
                timeout,
                outcome,
            });
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
        let addresses = addresses.to_vec();
        let task = tokio::spawn(async move {
            let won = connect(addresses, plan, delay, dial, started).await?;
            let slower = won.slower.map(|slower| {
                tokio::spawn(async move {
                    let connected = slower.connect().await?;
                    Ok((connected.stream, connected.switched_family))
                })
            });
            Ok(Won {
                address: won.connected.stream,
                started: won.connected.started,
                switched_family: won.connected.switched_family,
                slower,
            })
        });
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

    async fn result(&mut self) -> Result<io::Result<Won>, Box<dyn std::error::Error>> {
        Ok(tokio::time::timeout(WAIT, &mut self.task).await??)
    }
}

async fn slower_result(
    slower: Option<SlowerTask>,
) -> Result<io::Result<(SocketAddr, bool)>, Box<dyn std::error::Error>> {
    let slower = slower.ok_or("no slower attempt")?;
    Ok(tokio::time::timeout(WAIT, slower).await??)
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

    let won = connection.result().await??;

    assert_eq!(won.address, v6(1));
    assert_eq!(won.started, started);
    assert!(won.slower.is_none());
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
    assert_eq!(backup.timeout, None);
    answer(backup, Ok(v4(1)));
    let started = connection.started;

    let won = connection.result().await??;

    assert_eq!(won.address, v4(1));
    assert!(won.started > started);
    assert!(won.slower.is_some());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn the_primary_keeps_connecting_after_the_backup_wins() -> TestResult {
    let mut connection = Connection::start(&[v6(1), v6(2), v4(1)]);
    let primary = connection.next_dial().await?;
    connection.fire_delay();
    answer(connection.next_dial().await?, Ok(v4(1)));
    let won = connection.result().await??;
    assert_eq!(won.address, v4(1));
    assert!(
        !primary.outcome.is_closed(),
        "the primary attempt was closed"
    );

    // The kept attempt still moves to its next address after a refusal.
    answer(primary, refused());
    let next = connection.next_dial().await?;
    assert_eq!(next.address, v6(2));
    answer(next, Ok(v6(2)));

    let (address, switched_family) = slower_result(won.slower).await??;
    assert_eq!(address, v6(2));
    assert!(!switched_family);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn the_backup_keeps_connecting_after_the_primary_wins() -> TestResult {
    let mut connection = Connection::start(&[v6(1), v4(1), v4(2)]);
    let primary = connection.next_dial().await?;
    connection.fire_delay();
    let backup = connection.next_dial().await?;
    assert_eq!(backup.address, v4(1));
    answer(primary, Ok(v6(1)));
    let won = connection.result().await??;
    assert_eq!(won.address, v6(1));

    answer(backup, refused());
    let backup_next = connection.next_dial().await?;
    assert_eq!(backup_next.address, v4(2));
    answer(backup_next, Ok(v4(2)));

    let (address, _) = slower_result(won.slower).await??;
    assert_eq!(address, v4(2));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_slower_attempt_that_runs_out_of_addresses_fails() -> TestResult {
    let mut connection = Connection::start(&[v6(1), v4(1)]);
    let primary = connection.next_dial().await?;
    connection.fire_delay();
    answer(connection.next_dial().await?, Ok(v4(1)));
    let won = connection.result().await??;

    answer(primary, refused());
    let primary_next = connection.next_dial().await?;
    assert_eq!(primary_next.address, v4(1));
    answer(primary_next, Err(io::ErrorKind::ConnectionReset.into()));

    let error = match slower_result(won.slower).await? {
        Ok(_) => return Err("a failed slower attempt connected".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::ConnectionReset);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_refused_connect_moves_to_the_next_address_at_once() -> TestResult {
    let mut connection = Connection::start(&[v6(1), v4(1)]);
    answer(connection.next_dial().await?, refused());

    let next = connection.next_dial().await?;
    assert_eq!(next.address, v4(1));
    answer(next, Ok(v4(1)));

    let won = connection.result().await??;
    assert_eq!(won.address, v4(1));
    assert!(won.slower.is_none());
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
    // Let the backup's last failure land before the primary connects.
    tokio::task::yield_now().await;

    answer(primary, Ok(v4(1)));
    let won = connection.result().await??;
    assert_eq!(won.address, v4(1));
    // The backup had failed, so nothing is still connecting.
    assert!(won.slower.is_none());
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

    let won = connection.result().await??;
    assert_eq!(won.address, v6(1));
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_remembered_family_restricts_both_attempts_and_times_the_backup() -> TestResult {
    let mut connection =
        Connection::start_with(&[v6(1), v4(1), v6(2), v4(2)], knowing(AddressFamily::Ipv4));
    let primary = connection.next_dial().await?;
    assert_eq!(primary.address, v4(1));
    assert_eq!(primary.timeout, None);

    connection.fire_delay();
    let backup = connection.next_dial().await?;
    assert_eq!(backup.address, v4(1));
    assert_eq!(backup.timeout, Some(BACKUP_TIMEOUT));
    answer(backup, Err(io::ErrorKind::TimedOut.into()));
    let backup_next = connection.next_dial().await?;
    assert_eq!(backup_next.address, v4(2));
    assert_eq!(backup_next.timeout, Some(BACKUP_TIMEOUT));
    answer(backup_next, Ok(v4(2)));

    let won = connection.result().await??;
    assert_eq!(won.address, v4(2));
    assert!(!won.switched_family);
    drop(primary);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_attempt_that_exhausts_the_remembered_family_tries_the_other() -> TestResult {
    let mut connection =
        Connection::start_with(&[v6(1), v4(1), v6(2)], knowing(AddressFamily::Ipv4));
    let primary = connection.next_dial().await?;
    assert_eq!(primary.address, v4(1));
    answer(primary, refused());

    let other = connection.next_dial().await?;
    assert_eq!(other.address, v6(1));
    answer(other, refused());
    let other_next = connection.next_dial().await?;
    assert_eq!(other_next.address, v6(2));
    answer(other_next, Ok(v6(2)));

    let won = connection.result().await??;
    assert_eq!(won.address, v6(2));
    assert!(won.switched_family);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn the_other_family_is_tried_without_the_backup_timeout() -> TestResult {
    let mut connection = Connection::start_with(&[v6(1), v4(1)], knowing(AddressFamily::Ipv6));
    let primary = connection.next_dial().await?;
    connection.fire_delay();
    let backup = connection.next_dial().await?;
    assert_eq!(backup.address, v6(1));
    answer(backup, Err(io::ErrorKind::TimedOut.into()));

    let backup_other = connection.next_dial().await?;
    assert_eq!(backup_other.address, v4(1));
    assert_eq!(backup_other.timeout, None);
    answer(backup_other, Ok(v4(1)));

    let won = connection.result().await??;
    assert_eq!(won.address, v4(1));
    assert!(won.switched_family);
    drop(primary);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_remembered_family_without_addresses_starts_on_the_other() -> TestResult {
    let mut connection = Connection::start_with(&[v6(1)], knowing(AddressFamily::Ipv4));
    let primary = connection.next_dial().await?;
    assert_eq!(primary.address, v6(1));
    answer(primary, Ok(v6(1)));

    let won = connection.result().await??;
    assert!(won.switched_family);
    Ok(())
}

#[test]
fn the_first_connection_sets_the_family_and_only_a_switch_replaces_it() {
    let memory = AddressFamilyMemory::new();
    assert_eq!(memory.family(), None);

    memory.record_connection(&v4(1), false);
    assert_eq!(memory.family(), Some(AddressFamily::Ipv4));
    memory.record_connection(&v6(1), false);
    assert_eq!(memory.family(), Some(AddressFamily::Ipv4));

    memory.record_connection(&v6(1), true);
    assert_eq!(memory.family(), Some(AddressFamily::Ipv6));

    let shared = memory.clone();
    shared.forget();
    assert_eq!(memory.family(), None);
}
