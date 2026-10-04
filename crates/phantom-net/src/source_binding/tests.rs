use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use socket2::Domain;
use tokio::net::TcpListener;

use super::{INTERFACE_NAME_LIMIT, InterfaceNameLimit, SourceBinding, unicast_interface_value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const IPV4_LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
const IPV6_LOOPBACK: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

/// The name of the loopback interface, on the platforms that bind an
/// interface by name. On Windows it is the NDIS name, which every host has
/// whatever its display language; its alias is localized.
#[cfg(any(target_os = "android", target_os = "linux"))]
const LOOPBACK_INTERFACE: &str = "lo";
#[cfg(target_vendor = "apple")]
const LOOPBACK_INTERFACE: &str = "lo0";
#[cfg(windows)]
const LOOPBACK_INTERFACE: &str = "loopback_0";

/// A well-formed name that no test host gives an interface.
const UNKNOWN_INTERFACE: &str = "phantom-none0";

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
    let too_long = match INTERFACE_NAME_LIMIT {
        InterfaceNameLimit::Ifnamsiz => "a".repeat(16),
        InterfaceNameLimit::IfMaxStringSize => "a".repeat(257),
    };
    for name in ["", "a\0b", &too_long] {
        let error = SourceBinding::new().with_interface(name).validate();
        assert_eq!(
            error.map_err(|error| error.field()),
            Err("interface"),
            "{name:?}"
        );
    }
}

#[test]
fn ifnamsiz_counts_bytes_up_to_fifteen() {
    let limit = InterfaceNameLimit::Ifnamsiz;

    assert_eq!(limit.check("fifteen-bytes-x"), Ok(()));
    assert!(limit.check("sixteen-bytes-xx").is_err());
    // Eight two-byte characters are 16 bytes.
    assert!(limit.check(&"é".repeat(8)).is_err());
    assert!(limit.check("").is_err());
    assert!(limit.check("a\0b").is_err());
}

#[test]
fn windows_names_count_utf16_code_units_up_to_256() {
    let limit = InterfaceNameLimit::IfMaxStringSize;

    assert_eq!(limit.check(&"a".repeat(256)), Ok(()));
    assert!(limit.check(&"a".repeat(257)).is_err());
    // 200 two-byte characters are 400 bytes but 200 code units, and 129
    // characters outside the Basic Multilingual Plane are 258 code units.
    assert_eq!(limit.check(&"é".repeat(200)), Ok(()));
    assert!(limit.check(&"\u{1F310}".repeat(129)).is_err());
    assert_eq!(limit.check("Wi-Fi 2"), Ok(()));
    assert!(limit.check("").is_err());
    assert!(limit.check("a\0b").is_err());
}

#[test]
fn interface_binding_is_accepted_only_where_the_platform_has_it() {
    let result = SourceBinding::new().with_interface("eth0").validate();

    if cfg!(any(
        target_os = "android",
        target_os = "linux",
        target_vendor = "apple",
        windows
    )) {
        assert_eq!(result, Ok(()));
    } else {
        assert_eq!(result.map_err(|error| error.field()), Err("interface"));
    }
}

#[test]
fn unicast_interface_value_is_network_order_for_ipv4_and_host_order_for_ipv6() {
    assert_eq!(
        unicast_interface_value(0x0102_0304, Domain::IPV4),
        [1, 2, 3, 4]
    );
    assert_eq!(
        unicast_interface_value(0x0102_0304, Domain::IPV6),
        0x0102_0304_u32.to_ne_bytes()
    );
}

#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_vendor = "apple",
    windows
))]
#[test]
fn interface_lookup_finds_loopback_and_reports_an_unknown_name_as_not_found() -> TestResult {
    crate::socket_ffi::interface::index(LOOPBACK_INTERFACE)?;

    let error = crate::socket_ffi::interface::index(UNKNOWN_INTERFACE)
        .err()
        .ok_or("an unknown interface name was found")?;

    assert_eq!(error.kind(), io::ErrorKind::NotFound);
    assert_eq!(
        error.to_string(),
        "no network interface on this host has this name"
    );
    Ok(())
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

#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_vendor = "apple",
    windows
))]
#[tokio::test(flavor = "current_thread")]
async fn tcp_connection_binds_to_the_loopback_interface() -> TestResult {
    let listener = TcpListener::bind((IPV4_LOOPBACK, 0)).await?;
    let binding = SourceBinding::new().with_interface(LOOPBACK_INTERFACE);

    let stream = match crate::tcp::connect_resolved(
        vec![listener.local_addr()?],
        None,
        Some(&binding),
        std::time::Instant::now(),
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) if kernel_refuses_binding(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    };

    assert_bound_to_loopback(&socket2::SockRef::from(&stream), Domain::IPV4)
}

#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_vendor = "apple",
    windows
))]
#[test]
fn udp_socket_binds_to_the_loopback_interface() -> TestResult {
    let binding = SourceBinding::new().with_interface(LOOPBACK_INTERFACE);

    let socket = match crate::udp::bind_socket(
        SocketAddr::new(IPV4_LOOPBACK, 443),
        SocketAddr::new(IPV4_LOOPBACK, 0),
        Some(&binding),
        None,
    ) {
        Ok(socket) => socket,
        Err(error) if kernel_refuses_binding(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    };

    assert_bound_to_loopback(&socket2::SockRef::from(&socket), Domain::IPV4)
}

#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_vendor = "apple",
    windows
))]
#[tokio::test(flavor = "current_thread")]
async fn a_socket_cannot_bind_to_an_interface_no_host_has() -> TestResult {
    let listener = TcpListener::bind((IPV4_LOOPBACK, 0)).await?;
    let binding = SourceBinding::new().with_interface(UNKNOWN_INTERFACE);

    let result = crate::tcp::connect_resolved(
        vec![listener.local_addr()?],
        None,
        Some(&binding),
        std::time::Instant::now(),
    )
    .await;

    let error = result.map(drop).err().ok_or("the connection succeeded")?;
    let message = error.to_string();
    assert!(message.contains(UNKNOWN_INTERFACE), "{message}");
    if !cfg!(any(target_os = "android", target_os = "linux")) {
        assert_eq!(error.kind(), io::ErrorKind::NotFound, "{message}");
    }
    Ok(())
}

/// Binding by index, the Apple path, also runs on Linux and Android, where
/// socket2 sets `SO_BINDTOIFINDEX`.
#[cfg(any(target_os = "android", target_os = "linux", target_vendor = "apple"))]
#[test]
fn binding_by_index_sets_the_interface_index() -> TestResult {
    let socket = socket2::Socket::new(Domain::IPV4, socket2::Type::STREAM, None)?;
    let index = crate::socket_ffi::interface::index(LOOPBACK_INTERFACE)?;

    match super::bind_to_interface_index(&(&socket).into(), LOOPBACK_INTERFACE, Domain::IPV4) {
        Ok(()) => {}
        Err(error) if kernel_refuses_binding(&error) => return Ok(()),
        Err(error) => return Err(error.into()),
    }

    assert_eq!(socket.device_index_v4()?, Some(index));
    Ok(())
}

#[cfg(target_vendor = "apple")]
#[test]
fn an_ipv6_socket_binds_to_the_loopback_interface_by_index() -> TestResult {
    let socket = socket2::Socket::new(Domain::IPV6, socket2::Type::DGRAM, None)?;
    let binding = SourceBinding::new().with_interface(LOOPBACK_INTERFACE);

    binding.bind_interface(&(&socket).into(), Domain::IPV6)?;

    let index = crate::socket_ffi::interface::index(LOOPBACK_INTERFACE)?;
    assert_eq!(socket.device_index_v6()?, Some(index));
    Ok(())
}

#[cfg(windows)]
#[test]
fn an_ipv6_socket_sets_the_unicast_interface_in_host_order() -> TestResult {
    use std::os::windows::io::AsSocket;

    let socket = socket2::Socket::new(Domain::IPV6, socket2::Type::DGRAM, None)?;
    let binding = SourceBinding::new().with_interface(LOOPBACK_INTERFACE);

    binding.bind_interface(&(&socket).into(), Domain::IPV6)?;

    let index = crate::socket_ffi::interface::index(LOOPBACK_INTERFACE)?;
    assert_eq!(
        crate::socket_ffi::interface::unicast_interface(socket.as_socket(), Domain::IPV6)?,
        index.get().to_ne_bytes()
    );
    Ok(())
}

/// Whether `error` is Linux refusing to bind a socket to an interface; prints
/// a skip line when it is. Linux before 5.7 lets only `CAP_NET_RAW` bind to
/// an interface. Always false off Linux and Android.
#[cfg(any(
    target_os = "android",
    target_os = "linux",
    target_vendor = "apple",
    windows
))]
fn kernel_refuses_binding(error: &io::Error) -> bool {
    let refuses = cfg!(any(target_os = "android", target_os = "linux"))
        && error.kind() == io::ErrorKind::PermissionDenied;
    if refuses {
        eprintln!("skipped: this kernel refuses SO_BINDTODEVICE without CAP_NET_RAW");
    }
    refuses
}

#[cfg(any(target_os = "android", target_os = "linux"))]
fn assert_bound_to_loopback(socket: &socket2::SockRef<'_>, _domain: Domain) -> TestResult {
    assert_eq!(
        socket.device()?.as_deref(),
        Some(LOOPBACK_INTERFACE.as_bytes())
    );
    Ok(())
}

#[cfg(target_vendor = "apple")]
fn assert_bound_to_loopback(socket: &socket2::SockRef<'_>, domain: Domain) -> TestResult {
    let index = crate::socket_ffi::interface::index(LOOPBACK_INTERFACE)?;
    let bound = if domain == Domain::IPV6 {
        socket.device_index_v6()?
    } else {
        socket.device_index_v4()?
    };
    assert_eq!(bound, Some(index));
    Ok(())
}

#[cfg(windows)]
fn assert_bound_to_loopback(socket: &socket2::SockRef<'_>, domain: Domain) -> TestResult {
    use std::os::windows::io::AsSocket;

    let index = crate::socket_ffi::interface::index(LOOPBACK_INTERFACE)?;
    // Windows returns IP_UNICAST_IF in host order, though it takes network order.
    assert_eq!(
        crate::socket_ffi::interface::unicast_interface(socket.as_socket(), domain)?,
        index.get().to_ne_bytes()
    );
    Ok(())
}
