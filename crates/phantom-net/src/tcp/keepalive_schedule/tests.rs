use std::{task::Waker, time::Duration};

use phantom_profile::{TcpKeepaliveSchedule, firefox};
use socket2::SockRef;
use tokio::net::{TcpListener, TcpStream};

use super::{KeepalivePhase, TcpKeepaliveControl, probe_interval, switch_delay};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn firefox_schedule() -> TestResult<TcpKeepaliveSchedule> {
    match firefox::v157_tcp().keepalive {
        phantom_profile::TcpKeepalivePolicy::Schedule(schedule) => Ok(schedule),
        other => Err(format!("Firefox recipe has {other:?}").into()),
    }
}

/// The shortest schedule the profile allows: the switch comes four seconds
/// after a dispatch.
fn quick_schedule() -> TcpKeepaliveSchedule {
    TcpKeepaliveSchedule {
        short_lived_idle: Duration::from_secs(1),
        long_lived_idle: Duration::from_secs(5),
        minimum_interval: Duration::from_secs(1),
        short_lived_time: Duration::from_secs(1),
        probe_count: 1,
    }
}

async fn loopback_pair() -> TestResult<(TcpStream, TcpStream)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let client = TcpStream::connect(listener.local_addr()?).await?;
    let (server, _) = listener.accept().await?;
    Ok((client, server))
}

fn apply(control: &TcpKeepaliveControl, socket: &TcpStream) -> std::io::Result<()> {
    control.apply(socket, Waker::noop())
}

#[test]
fn the_interval_is_whole_setup_seconds_and_at_least_the_minimum() -> TestResult {
    let schedule = firefox_schedule()?;

    assert_eq!(
        probe_interval(&schedule, Duration::from_millis(40)),
        Duration::from_secs(1)
    );
    assert_eq!(
        probe_interval(&schedule, Duration::from_millis(2_050)),
        Duration::from_secs(2)
    );
    let slower_minimum = TcpKeepaliveSchedule {
        minimum_interval: Duration::from_secs(3),
        ..schedule
    };
    assert_eq!(
        probe_interval(&slower_minimum, Duration::from_millis(2_050)),
        Duration::from_secs(3)
    );
    Ok(())
}

#[test]
fn firefox_switches_72_seconds_after_a_dispatch_with_a_one_second_interval() -> TestResult {
    let schedule = firefox_schedule()?;

    assert_eq!(
        switch_delay(&schedule, Duration::from_secs(1)),
        Duration::from_secs(72)
    );
    assert_eq!(
        switch_delay(&schedule, Duration::from_secs(2)),
        Duration::from_secs(82)
    );
    Ok(())
}

#[test]
fn the_switch_drops_the_remainder_of_the_short_lived_time() {
    let schedule = TcpKeepaliveSchedule {
        short_lived_time: Duration::from_secs(65),
        short_lived_idle: Duration::from_secs(10),
        ..quick_schedule()
    };

    // 65 - 65 % 10 + 1 probe of 1 s + 2 s.
    assert_eq!(
        switch_delay(&schedule, Duration::from_secs(1)),
        Duration::from_secs(63)
    );
    let largest = TcpKeepaliveSchedule {
        probe_count: 127,
        ..schedule
    };
    assert_eq!(
        switch_delay(&largest, Duration::from_secs(32_767)),
        Duration::from_secs(60 + 127 * 32_767 + 2)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn a_new_connection_gets_short_lived_keepalive_before_its_first_byte() -> TestResult {
    let (client, _server) = loopback_pair().await?;
    let control = TcpKeepaliveControl::opened(firefox_schedule()?, Duration::from_millis(5));

    apply(&control, &client)?;
    // The request that opened the connection does not restart anything.
    control.request_dispatched();
    apply(&control, &client)?;

    assert_eq!(control.applied_phases(), [KeepalivePhase::ShortLived]);
    assert!(SockRef::from(&client).keepalive()?);
    assert_eq!(control.interval(), Duration::from_secs(1));
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert_eq!(
        SockRef::from(&client).tcp_keepalive_time()?,
        Duration::from_secs(10)
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn http2_turns_keepalive_off_for_good() -> TestResult {
    let (client, _server) = loopback_pair().await?;
    let control = TcpKeepaliveControl::opened(firefox_schedule()?, Duration::ZERO);
    apply(&control, &client)?;

    control.http2_negotiated();
    apply(&control, &client)?;
    control.request_dispatched();
    control.upgraded();
    apply(&control, &client)?;

    assert_eq!(
        control.applied_phases(),
        [KeepalivePhase::ShortLived, KeepalivePhase::Disabled]
    );
    assert!(!SockRef::from(&client).keepalive()?);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn an_upgrade_switches_to_long_lived_at_once() -> TestResult {
    let (client, _server) = loopback_pair().await?;
    let control = TcpKeepaliveControl::opened(firefox_schedule()?, Duration::ZERO);
    apply(&control, &client)?;

    control.upgraded();
    apply(&control, &client)?;

    assert_eq!(
        control.applied_phases(),
        [KeepalivePhase::ShortLived, KeepalivePhase::LongLived]
    );
    assert!(SockRef::from(&client).keepalive()?);
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    assert_eq!(
        SockRef::from(&client).tcp_keepalive_time()?,
        Duration::from_secs(600)
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_reused_connection_returns_to_short_lived_keepalive() -> TestResult {
    let (client, _server) = loopback_pair().await?;
    let control = TcpKeepaliveControl::opened(firefox_schedule()?, Duration::ZERO);
    apply(&control, &client)?;
    control.request_dispatched();
    control.upgraded();
    apply(&control, &client)?;

    control.connection_idle();
    control.request_dispatched();
    apply(&control, &client)?;

    assert_eq!(
        control.applied_phases(),
        [
            KeepalivePhase::ShortLived,
            KeepalivePhase::LongLived,
            KeepalivePhase::ShortLived
        ]
    );
    Ok(())
}

/// Applies `control` every 50 ms until it reaches `phase`, and returns how
/// long that took; fails after 30 s.
async fn wait_for_phase(
    control: &TcpKeepaliveControl,
    socket: &TcpStream,
    phase: KeepalivePhase,
) -> TestResult<Duration> {
    let started = std::time::Instant::now();
    while started.elapsed() < Duration::from_secs(30) {
        apply(control, socket)?;
        if control.applied_phases().last() == Some(&phase) {
            return Ok(started.elapsed());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Err(format!("never reached {phase:?}").into())
}

/// Two connections on the four-second schedule: the one with a request
/// outstanding switches when the time comes, and the idle one does not.
#[tokio::test(flavor = "current_thread")]
async fn only_a_connection_with_a_request_outstanding_switches() -> TestResult {
    let (active_socket, _active_server) = loopback_pair().await?;
    let (idle_socket, _idle_server) = loopback_pair().await?;
    let active = TcpKeepaliveControl::opened(quick_schedule(), Duration::ZERO);
    let idle = TcpKeepaliveControl::opened(quick_schedule(), Duration::ZERO);
    apply(&active, &active_socket)?;
    apply(&idle, &idle_socket)?;
    active.request_dispatched();
    idle.request_dispatched();
    idle.connection_idle();

    let waited = wait_for_phase(&active, &active_socket, KeepalivePhase::LongLived).await?;
    apply(&idle, &idle_socket)?;

    assert!(waited >= Duration::from_secs(3), "{waited:?}");
    assert_eq!(idle.applied_phases(), [KeepalivePhase::ShortLived]);
    Ok(())
}

/// A later request moves the switch: with the four-second schedule, a
/// request two seconds in puts it six seconds after the connection opened.
#[tokio::test(flavor = "current_thread")]
async fn a_later_request_moves_the_switch_later() -> TestResult {
    let (socket, _server) = loopback_pair().await?;
    let control = TcpKeepaliveControl::opened(quick_schedule(), Duration::ZERO);
    let opened = std::time::Instant::now();
    apply(&control, &socket)?;
    control.request_dispatched();
    tokio::time::sleep(Duration::from_secs(2)).await;
    control.connection_idle();
    control.request_dispatched();
    let delay = switch_delay(&quick_schedule(), Duration::from_secs(1));

    wait_for_phase(&control, &socket, KeepalivePhase::LongLived).await?;

    let elapsed = opened.elapsed();
    assert!(
        elapsed >= delay + Duration::from_secs(2),
        "switched {elapsed:?} after opening"
    );
    Ok(())
}
