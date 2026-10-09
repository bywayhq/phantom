use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use phantom_profile::{UdpSettings, browser::chrome};

use super::{WSAENOBUFS, bind_socket, observed, retry_past_reserved_ports};
use crate::SourceBinding;

mod paths;
#[cfg(windows)]
mod port_randomization;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const IPV4_LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

/// Whether `settings` set `SO_RANDOMIZE_PORT` on this host: on every Windows
/// when asked, and nowhere else.
fn sets_random_port(settings: Option<UdpSettings>) -> bool {
    cfg!(windows) && settings.is_some_and(|settings| settings.port_randomization)
}

#[tokio::test(flavor = "current_thread")]
async fn udp_socket_sends_from_the_bound_address_not_the_default() -> TestResult {
    // The default is the address a caller would bind without the binding,
    // as a SOCKS5 association passes its control connection's address, so
    // the bound address must differ from it.
    let bound = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2));
    if phantom_testkit::udp::bind((bound, 0).into()).is_err() {
        eprintln!("skipped: 127.0.0.2 is not a local address on this host");
        return Ok(());
    }
    let server = phantom_testkit::udp::bind_tokio((IPV4_LOOPBACK, 0).into())?;
    let binding = SourceBinding::new().with_address(bound);

    let socket = bind_socket(
        server.local_addr()?,
        SocketAddr::new(IPV4_LOOPBACK, 0),
        Some(&binding),
        None,
    )?;
    socket.send_to(b"ping", server.local_addr()?)?;
    let mut buffer = [0_u8; 4];
    let (_, peer) = server.recv_from(&mut buffer).await?;

    assert_eq!(peer, socket.local_addr()?);
    assert_eq!(peer.ip(), bound);
    Ok(())
}

#[test]
fn udp_socket_without_an_address_of_the_family_binds_the_default() -> TestResult {
    let binding = SourceBinding::new();
    let default = SocketAddr::new(IPV4_LOOPBACK, 0);

    let socket = bind_socket(
        SocketAddr::new(IPV4_LOOPBACK, 443),
        default,
        Some(&binding),
        None,
    )?;

    assert_eq!(socket.local_addr()?.ip(), IPV4_LOOPBACK);
    Ok(())
}

#[test]
fn a_socket_takes_port_randomization_only_when_the_settings_ask() -> TestResult {
    let local = SocketAddr::new(IPV4_LOOPBACK, 0);
    let remote = SocketAddr::new(IPV4_LOOPBACK, 443);
    observed::take();

    for settings in [Some(chrome::v154_udp()), Some(UdpSettings::default()), None] {
        bind_socket(remote, local, None, settings)?;
        assert_eq!(
            observed::take(),
            [observed::ObservedSocket {
                random_port: sets_random_port(settings),
            }],
            "{settings:?}"
        );
    }
    Ok(())
}

/// `WSAEADDRINUSE`.
const WSAEADDRINUSE: i32 = 10_048;

/// Runs the reserved-port retry over `outcomes`, one per bind: `None` binds,
/// `Some` fails with that OS error. Returns the OS error of the result, if
/// any, and how many binds were made.
fn retry_over(windows: bool, port: u16, outcomes: &[Option<i32>]) -> (Option<i32>, usize) {
    let mut binds = 0;
    let result = retry_past_reserved_ports(windows, port, || {
        let outcome = outcomes.get(binds).copied().flatten();
        binds += 1;
        outcome.map_or(Ok(()), |code| Err(io::Error::from_raw_os_error(code)))
    });
    (result.err().and_then(|error| error.raw_os_error()), binds)
}

#[test]
fn windows_retries_a_bind_to_port_zero_refused_at_a_reserved_block() {
    assert_eq!(retry_over(true, 0, &[Some(WSAENOBUFS), None]), (None, 2));
}

#[test]
fn windows_returns_the_error_after_three_retries() {
    let outcomes = [Some(WSAENOBUFS); 5];

    assert_eq!(retry_over(true, 0, &outcomes), (Some(WSAENOBUFS), 4));
}

#[test]
fn other_bind_errors_are_not_retried() {
    assert_eq!(
        retry_over(true, 0, &[Some(WSAEADDRINUSE), None]),
        (Some(WSAEADDRINUSE), 1)
    );
}

#[test]
fn a_bind_to_an_explicit_port_is_not_retried() {
    assert_eq!(
        retry_over(true, 443, &[Some(WSAENOBUFS), None]),
        (Some(WSAENOBUFS), 1)
    );
}

#[test]
fn other_platforms_never_retry() {
    assert_eq!(
        retry_over(false, 0, &[Some(WSAENOBUFS), None]),
        (Some(WSAENOBUFS), 1)
    );
}
