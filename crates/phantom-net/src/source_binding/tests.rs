use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use tokio::net::TcpListener;

use super::{SourceBinding, WSAENOBUFS, retry_past_reserved_ports};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const IPV4_LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const IPV6_LOOPBACK: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

#[test]
fn addresses_of_each_family_are_kept_apart() {
    let binding = SourceBinding::new()
        .with_address(IPV4_LOOPBACK)
        .with_address(IPV6_LOOPBACK)
        .with_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));

    assert_eq!(binding.ipv4_address(), Some(Ipv4Addr::new(127, 0, 0, 2)));
    assert_eq!(binding.ipv6_address(), Some(Ipv6Addr::LOCALHOST));
}

#[test]
fn validate_rejects_addresses_that_cannot_be_a_source() {
    for (address, field) in [
        (IpAddr::V4(Ipv4Addr::UNSPECIFIED), "ipv4_address"),
        (IpAddr::V4(Ipv4Addr::BROADCAST), "ipv4_address"),
        (IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), "ipv4_address"),
        (IpAddr::V6(Ipv6Addr::UNSPECIFIED), "ipv6_address"),
        (
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1)),
            "ipv6_address",
        ),
    ] {
        let error = SourceBinding::new().with_address(address).validate();
        assert_eq!(
            error.map_err(|error| error.field()),
            Err(field),
            "{address}"
        );
    }
    assert_eq!(SourceBinding::new().validate(), Ok(()));
    assert_eq!(
        SourceBinding::new()
            .with_address(IPV4_LOOPBACK)
            .with_address(IPV6_LOOPBACK)
            .validate(),
        Ok(())
    );
}

#[test]
fn validate_rejects_malformed_interface_names() {
    for name in ["", "a\0b", "sixteen-bytes-xx"] {
        let error = SourceBinding::new().with_interface(name).validate();
        assert_eq!(
            error.map_err(|error| error.field()),
            Err("interface"),
            "{name:?}"
        );
    }
}

#[test]
fn interface_binding_is_accepted_only_where_the_platform_has_it() {
    let result = SourceBinding::new().with_interface("lo").validate();

    if cfg!(any(target_os = "android", target_os = "linux")) {
        assert_eq!(result, Ok(()));
    } else {
        assert_eq!(result.map_err(|error| error.field()), Err("interface"));
    }
}

#[test]
fn addresses_of_an_unbound_family_are_skipped_in_order() -> TestResult {
    let ipv4_first = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), 443);
    let ipv6 = SocketAddr::new(IPV6_LOOPBACK, 443);
    let ipv4_second = SocketAddr::new(IPV4_LOOPBACK, 443);
    let binding = SourceBinding::new().with_address(IPV4_LOOPBACK);

    let usable = binding.usable_addresses(vec![ipv4_first, ipv6, ipv4_second])?;

    assert_eq!(usable, vec![ipv4_first, ipv4_second]);
    Ok(())
}

#[test]
fn a_binding_without_addresses_keeps_every_family() -> TestResult {
    let addresses = vec![
        SocketAddr::new(IPV6_LOOPBACK, 443),
        SocketAddr::new(IPV4_LOOPBACK, 443),
    ];

    let usable = SourceBinding::new().usable_addresses(addresses.clone())?;

    assert_eq!(usable, addresses);
    Ok(())
}

#[test]
fn no_address_of_a_bound_family_is_address_not_available() {
    let binding = SourceBinding::new().with_address(IPV6_LOOPBACK);

    let error = binding.usable_addresses(vec![SocketAddr::new(IPV4_LOOPBACK, 443)]);

    assert_eq!(
        error.map_err(|error| error.kind()),
        Err(io::ErrorKind::AddrNotAvailable)
    );
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_connection_leaves_from_the_bound_address() -> TestResult {
    let listener = TcpListener::bind((IPV4_LOOPBACK, 0)).await?;
    let binding = SourceBinding::new().with_address(IPV4_LOOPBACK);

    let stream = crate::tcp::connect_resolved(
        vec![listener.local_addr()?],
        None,
        Some(&binding),
        std::time::Instant::now(),
    )
    .await?;
    let (_, peer) = listener.accept().await?;

    assert_eq!(peer.ip(), IPV4_LOOPBACK);
    assert_eq!(stream.local_addr()?, peer);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn tcp_bind_to_a_foreign_address_fails_before_connecting() -> TestResult {
    let listener = TcpListener::bind((IPV4_LOOPBACK, 0)).await?;
    // TEST-NET-1 is assigned to no local interface, so the bind itself fails.
    let binding = SourceBinding::new().with_address(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));

    let result = crate::tcp::connect_resolved(
        vec![listener.local_addr()?],
        None,
        Some(&binding),
        std::time::Instant::now(),
    )
    .await;

    assert_eq!(
        result.map(drop).map_err(|error| error.kind()),
        Err(io::ErrorKind::AddrNotAvailable)
    );
    Ok(())
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

    let socket = binding.bind_udp(server.local_addr()?, SocketAddr::new(IPV4_LOOPBACK, 0))?;
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

    let socket = binding.bind_udp(SocketAddr::new(IPV4_LOOPBACK, 443), default)?;

    assert_eq!(socket.local_addr()?.ip(), IPV4_LOOPBACK);
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

#[cfg(any(target_os = "android", target_os = "linux"))]
#[tokio::test(flavor = "current_thread")]
async fn tcp_connection_binds_to_the_loopback_interface() -> TestResult {
    let listener = TcpListener::bind((IPV4_LOOPBACK, 0)).await?;
    let binding = SourceBinding::new().with_interface("lo");

    let stream = match crate::tcp::connect_resolved(
        vec![listener.local_addr()?],
        None,
        Some(&binding),
        std::time::Instant::now(),
    )
    .await
    {
        Ok(stream) => stream,
        // Linux before 5.7 lets only CAP_NET_RAW bind to an interface.
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            eprintln!("skipped: this kernel refuses SO_BINDTODEVICE without CAP_NET_RAW");
            return Ok(());
        }
        Err(error) => return Err(error.into()),
    };

    let device = socket2::SockRef::from(&stream).device()?;
    assert_eq!(device.as_deref(), Some(&b"lo"[..]));
    Ok(())
}
