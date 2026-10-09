use std::{
    io,
    net::{IpAddr, Ipv6Addr},
};

use super::{retry_reserved_ports, Pair, RESERVED_PORT_RETRIES};

#[tokio::test]
async fn pair_endpoints_bind_only_to_ipv6_loopback() {
    let mut pair = Pair::default();
    let server = pair.server_inner();
    let client = pair.client_endpoint();
    for endpoint in [server, client] {
        let address = endpoint.local_addr().unwrap();
        assert_eq!(address.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_ne!(address.port(), 0);
    }
}

#[test]
fn windows_retries_transient_reserved_port_refusal() {
    let mut attempts = 0;
    let result = retry_reserved_ports(true, || {
        attempts += 1;
        if attempts == 1 {
            Err(io::Error::from_raw_os_error(10_055))
        } else {
            Ok(())
        }
    });
    assert!(result.is_ok());
    assert_eq!(attempts, 2);
}

#[test]
fn windows_returns_last_error_after_three_reserved_port_retries() {
    let mut attempts = 0;
    let result = retry_reserved_ports::<()>(true, || {
        attempts += 1;
        Err(io::Error::from_raw_os_error(10_055))
    });
    assert_eq!(result.unwrap_err().raw_os_error(), Some(10_055));
    assert_eq!(attempts, 1 + RESERVED_PORT_RETRIES);
    assert_eq!(attempts, 4);
}

#[test]
fn other_os_bind_errors_are_returned_without_retry() {
    let mut attempts = 0;
    let result = retry_reserved_ports::<()>(true, || {
        attempts += 1;
        Err(io::Error::from_raw_os_error(10_048))
    });
    assert_eq!(result.unwrap_err().raw_os_error(), Some(10_048));
    assert_eq!(attempts, 1);
}

#[test]
fn non_os_bind_errors_keep_their_kind_and_message() {
    let mut attempts = 0;
    let result = retry_reserved_ports::<()>(true, || {
        attempts += 1;
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "bind sentinel",
        ))
    });
    let error = result.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(error.to_string(), "bind sentinel");
    assert_eq!(attempts, 1);
}

#[test]
fn another_error_after_reserved_port_refusal_is_returned_unchanged() {
    let mut attempts = 0;
    let result = retry_reserved_ports::<()>(true, || {
        attempts += 1;
        let code = if attempts == 1 { 10_055 } else { 10_048 };
        Err(io::Error::from_raw_os_error(code))
    });
    assert_eq!(result.unwrap_err().raw_os_error(), Some(10_048));
    assert_eq!(attempts, 2);
}

#[test]
fn other_platforms_do_not_retry_the_windows_reserved_port_error() {
    let mut attempts = 0;
    let result = retry_reserved_ports::<()>(false, || {
        attempts += 1;
        Err(io::Error::from_raw_os_error(10_055))
    });
    assert_eq!(result.unwrap_err().raw_os_error(), Some(10_055));
    assert_eq!(attempts, 1);
}
