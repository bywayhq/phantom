use std::{
    cell::{Cell, RefCell},
    future::ready,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    rc::Rc,
};

use super::super::{PORT_ATTEMPTS, bind_pair, candidate_ports, port_unavailable};
use crate::CaptureResult;

const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[derive(Debug)]
struct Reservation {
    address: SocketAddr,
    live: Rc<Cell<Option<SocketAddr>>>,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        assert_eq!(self.live.replace(None), Some(self.address));
    }
}

#[tokio::test]
async fn dispersed_candidates_escape_a_wide_udp_only_rejection_block() -> CaptureResult<()> {
    let live = Rc::new(Cell::new(None));
    let seen = RefCell::new(Vec::new());
    let (udp, tcp) = bind_pair(
        LOOPBACK,
        candidate_ports(2_000),
        |address| {
            assert_eq!(live.replace(Some(address)), None);
            ready(Ok(Reservation {
                address,
                live: Rc::clone(&live),
            }))
        },
        |address| {
            assert_eq!(live.get(), Some(address));
            seen.borrow_mut().push(address);
            if (22_000..=22_700).contains(&address.port()) {
                Err(io::ErrorKind::AddrInUse.into())
            } else {
                Ok(address)
            }
        },
    )
    .await?;

    let seen = seen.borrow();
    assert_eq!(seen.first().map(SocketAddr::port), Some(22_000));
    assert!(seen.len() > 1);
    assert!(seen.iter().all(|address| {
        address.ip().is_loopback() && (20_000..32_768).contains(&address.port())
    }));
    assert!(!(22_000..=22_700).contains(&udp.port()));
    assert_eq!(udp, tcp.address);
    assert_eq!(live.get(), Some(udp));
    drop(tcp);
    assert_eq!(live.get(), None);
    Ok(())
}

#[tokio::test]
async fn unavailable_tcp_candidate_never_attempts_udp() -> CaptureResult<()> {
    let udp_calls = RefCell::new(Vec::new());
    let (udp, tcp) = bind_pair(
        LOOPBACK,
        [21_000, 29_000],
        |address| {
            ready(if address.port() == 21_000 {
                Err(io::ErrorKind::AddrInUse.into())
            } else {
                Ok(address)
            })
        },
        |address| {
            udp_calls.borrow_mut().push(address.port());
            Ok(address)
        },
    )
    .await?;

    assert_eq!(*udp_calls.borrow(), [29_000]);
    assert_eq!(tcp, udp);
    assert_eq!(udp.port(), 29_000);
    Ok(())
}

#[tokio::test]
async fn unrelated_udp_failure_returns_its_source_and_releases_tcp() -> CaptureResult<()> {
    let live = Rc::new(Cell::new(None));
    let attempts = Cell::new(0);
    let error = bind_pair(
        LOOPBACK,
        [21_000, 29_000],
        |address| {
            attempts.set(attempts.get() + 1);
            assert_eq!(live.replace(Some(address)), None);
            ready(Ok(Reservation {
                address,
                live: Rc::clone(&live),
            }))
        },
        |_| Err::<(), _>(io::Error::other("independent socket failure")),
    )
    .await
    .err()
    .ok_or("unrelated UDP failure did not stop selection")?;

    assert_eq!(attempts.get(), 1);
    assert_eq!(live.get(), None);
    assert_eq!(error.operation, "bind alternative UDP");
    assert_eq!(error.address, SocketAddr::new(LOOPBACK, 21_000));
    assert_eq!(error.source.kind(), io::ErrorKind::Other);
    assert_eq!(error.source.to_string(), "independent socket failure");
    Ok(())
}

#[tokio::test]
async fn repeated_unavailable_candidates_stop_at_the_attempt_bound() -> CaptureResult<()> {
    let attempts = Cell::new(0);
    let error = bind_pair(
        LOOPBACK,
        std::iter::repeat(21_000),
        |_| {
            attempts.set(attempts.get() + 1);
            ready(Err::<(), _>(io::ErrorKind::AddrInUse.into()))
        },
        |_| -> io::Result<()> { panic!("UDP must not bind without TCP ownership") },
    )
    .await
    .err()
    .ok_or("occupied ports did not exhaust selection")?;

    assert_eq!(attempts.get(), PORT_ATTEMPTS);
    assert_eq!(error.operation, "exhaust alternative TCP candidates");
    assert_eq!(error.address, SocketAddr::new(LOOPBACK, 21_000));
    assert_eq!(error.source.kind(), io::ErrorKind::AddrInUse);
    Ok(())
}

#[tokio::test]
async fn unrelated_tcp_failure_stops_before_udp() -> CaptureResult<()> {
    let attempts = Cell::new(0);
    let error = bind_pair(
        LOOPBACK,
        [21_000, 29_000],
        |_| {
            attempts.set(attempts.get() + 1);
            ready(Err::<(), _>(io::ErrorKind::InvalidInput.into()))
        },
        |_| -> io::Result<()> { panic!("UDP must not bind without TCP ownership") },
    )
    .await
    .err()
    .ok_or("unrelated TCP failure did not stop selection")?;

    assert_eq!(attempts.get(), 1);
    assert_eq!(error.operation, "bind alternative TCP");
    assert_eq!(error.address, SocketAddr::new(LOOPBACK, 21_000));
    assert_eq!(error.source.kind(), io::ErrorKind::InvalidInput);
    Ok(())
}

#[test]
fn socket_retries_do_not_hide_other_permission_or_input_failures() {
    assert!(port_unavailable(&io::ErrorKind::AddrInUse.into()));
    assert!(!port_unavailable(&io::ErrorKind::PermissionDenied.into()));
    assert!(!port_unavailable(&io::ErrorKind::InvalidInput.into()));
    assert_eq!(
        port_unavailable(&io::Error::from_raw_os_error(10013)),
        cfg!(windows)
    );
    assert!(!port_unavailable(&io::Error::from_raw_os_error(10014)));
}
