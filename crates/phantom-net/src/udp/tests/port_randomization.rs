//! `SO_RANDOMIZE_PORT` on UDP sockets, read back from Windows.
//!
//! Chromium sets the option on every Windows, so these tests have no minimum
//! build. A Windows without the option, which fails with `WSAENOPROTOOPT`,
//! makes the direct `setsockopt` tests print a skip line instead.

use std::{
    net::{Ipv4Addr, SocketAddr},
    os::windows::io::AsSocket,
};

use phantom_profile::{UdpSettings, chromium};

use super::{IPV4_LOOPBACK, TestResult};
use crate::{SourceBinding, udp::bind_socket, windows_port_randomization};

/// Binds `count` sockets that send to one loopback peer, one after another,
/// and keeps them all open.
fn sockets(
    settings: Option<UdpSettings>,
    source: Option<&SourceBinding>,
    count: usize,
) -> TestResult<Vec<std::net::UdpSocket>> {
    let remote = SocketAddr::new(IPV4_LOOPBACK, 443);
    let local = SocketAddr::new(IPV4_LOOPBACK, 0);
    let mut sockets = Vec::new();
    for _ in 0..count {
        sockets.push(bind_socket(remote, local, source, settings)?);
    }
    Ok(sockets)
}

fn random_port(socket: &std::net::UdpSocket) -> TestResult<bool> {
    Ok(windows_port_randomization::is_enabled(socket.as_socket())?)
}

/// Whether some pair of successive local ports lies far apart. Windows
/// hands out sequential ports one apart when nothing else takes one in
/// between; random ones from the dynamic range almost never stay within 64
/// of each other seven times running.
fn scattered(sockets: &[std::net::UdpSocket]) -> TestResult<bool> {
    let ports = sockets
        .iter()
        .map(|socket| Ok(socket.local_addr()?.port()))
        .collect::<std::io::Result<Vec<u16>>>()?;
    Ok(ports.windows(2).any(|pair| pair[0].abs_diff(pair[1]) > 64))
}

/// Whether `error` says this Windows lacks the option; prints a skip line
/// when it does.
fn lacks_the_option(error: &std::io::Error) -> bool {
    let lacks = error.kind() == std::io::ErrorKind::Unsupported;
    if lacks {
        eprintln!("skipped: this Windows does not support SO_RANDOMIZE_PORT");
    }
    lacks
}

#[test]
fn chromium_sockets_read_back_port_randomization() -> TestResult {
    let sockets = sockets(Some(chromium::v154_udp()), None, 1)?;
    assert!(random_port(&sockets[0])?);
    Ok(())
}

#[test]
fn sockets_without_udp_settings_leave_port_randomization_off() -> TestResult {
    for settings in [None, Some(UdpSettings::default())] {
        let sockets = sockets(settings, None, 1)?;
        assert!(!random_port(&sockets[0])?, "{settings:?}");
    }
    Ok(())
}

/// Windows takes the option only before a UDP socket is bound, and the
/// error comes back with its Winsock code.
#[test]
fn a_bound_udp_socket_rejects_port_randomization() -> TestResult {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    socket.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
    let error = match windows_port_randomization::enable(socket.as_socket()) {
        Ok(()) => return Err("a bound socket took SO_RANDOMIZE_PORT".into()),
        Err(error) => error,
    };
    if lacks_the_option(&error) {
        return Ok(());
    }
    // WSAEINVAL.
    assert_eq!(error.raw_os_error(), Some(10_022));
    assert!(!windows_port_randomization::is_enabled(socket.as_socket())?);
    Ok(())
}

#[test]
fn an_unbound_udp_socket_takes_port_randomization() -> TestResult {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, None)?;
    match windows_port_randomization::enable(socket.as_socket()) {
        Ok(()) => {}
        Err(error) if lacks_the_option(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    assert!(windows_port_randomization::is_enabled(socket.as_socket())?);
    Ok(())
}

/// Without the option, Windows hands out the ports of successive binds in
/// sequence, one apart, which is what `chromium::v154_udp` changes.
///
/// Other test processes bind UDP ports at the same time and can take ports
/// in between, so a pair counts as sequential when the next port is at most
/// 64 above the last; random ports almost never are. A host whose pairs are
/// mostly further apart already randomizes UDP ports, and the test prints a
/// skip line.
#[test]
fn sockets_without_udp_settings_take_sequential_local_ports() -> TestResult {
    let sockets = sockets(None, None, 16)?;
    for socket in &sockets {
        assert!(!random_port(socket)?);
    }
    let ports = sockets
        .iter()
        .map(|socket| Ok(socket.local_addr()?.port()))
        .collect::<std::io::Result<Vec<u16>>>()?;
    let pairs = ports.len() - 1;
    let steps = || ports.windows(2).map(|pair| pair[1].wrapping_sub(pair[0]));
    let sequential = steps().filter(|step| (1..=64).contains(step)).count();
    let one_apart = steps().filter(|step| *step == 1).count();
    if steps().filter(|step| !(1..=64).contains(step)).count() * 2 > pairs {
        eprintln!("skipped: this host already randomizes UDP ports: {ports:?}");
        return Ok(());
    }
    // A wrap from the top of the dynamic range to its bottom, and a jump
    // over a reserved port block, each leave one pair that is not
    // sequential.
    assert!(sequential + 2 >= pairs, "{ports:?}");
    eprintln!("{one_apart} of {pairs} successive ports were one apart");
    Ok(())
}

#[test]
fn chromium_sockets_take_scattered_local_ports() -> TestResult {
    let sockets = sockets(Some(chromium::v154_udp()), None, 8)?;
    for socket in &sockets {
        assert!(random_port(socket)?);
    }
    assert!(scattered(&sockets)?);
    Ok(())
}

#[test]
fn source_bound_chromium_sockets_take_scattered_local_ports() -> TestResult {
    let source = SourceBinding::new().with_address(Ipv4Addr::LOCALHOST.into());
    let sockets = sockets(Some(chromium::v154_udp()), Some(&source), 8)?;
    for socket in &sockets {
        assert!(random_port(socket)?);
    }
    assert!(scattered(&sockets)?);
    Ok(())
}
