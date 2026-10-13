use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{
    DecodedUdpTarget, REMOTE_VIRTUAL_IP, ReceiveTarget, RelaySend, Socks5Auth, Socks5ErrorKind,
    decode_udp_target, encode_udp_target, negotiate_authentication,
    prepare_socks5_udp_remote_target, read_udp_associate_reply, relay_send_outcome,
    write_udp_associate,
};

type TestResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn udp_target_codec_preserves_fixed_ip_targets_and_rejects_fragments() -> TestResult<()> {
    for target in [
        SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 443)),
        SocketAddr::from((Ipv6Addr::LOCALHOST, 8443)),
    ] {
        let encoded = encode_udp_target(target);
        assert_eq!(
            decode_udp_target(&encoded),
            Some((DecodedUdpTarget::Ip(target), encoded.len()))
        );

        let mut fragmented = encoded;
        fragmented[2] = 1;
        assert_eq!(decode_udp_target(&fragmented), None);
    }
    Ok(())
}

#[test]
fn remote_target_validation_canonicalizes_domains_and_literal_ips() -> TestResult<()> {
    let domain = prepare_socks5_udp_remote_target("origin.example", 443)?;
    assert_eq!(
        domain.target_header,
        b"\0\0\0\x03\x0eorigin.example\x01\xbb"
    );
    assert_eq!(
        SocketAddr::new(IpAddr::V4(REMOTE_VIRTUAL_IP), domain.port),
        SocketAddr::from((REMOTE_VIRTUAL_IP, 443))
    );

    let ipv4 = prepare_socks5_udp_remote_target("192.0.2.9", 8443)?;
    assert_eq!(ipv4.target_header, [0, 0, 0, 1, 192, 0, 2, 9, 0x20, 0xfb]);
    let ipv6 = prepare_socks5_udp_remote_target("2001:db8::9", 443)?;
    assert_eq!(ipv6.target_header[3], 4);
    let expanded_ipv6 =
        prepare_socks5_udp_remote_target("2001:0db8:0000:0000:0000:0000:0000:0009", 443)?;
    assert_eq!(expanded_ipv6.target_header, ipv6.target_header);
    let uppercase = prepare_socks5_udp_remote_target("Origin.Example", 443)?;
    assert_eq!(
        uppercase.target_header,
        b"\0\0\0\x03\x0eorigin.example\x01\xbb"
    );
    let unicode = prepare_socks5_udp_remote_target("bücher.example", 443)?;
    assert_eq!(
        unicode.target_header,
        b"\0\0\0\x03\x15xn--bcher-kva.example\x01\xbb"
    );
    Ok(())
}

#[test]
fn remote_target_validation_rejects_unencodable_values() -> TestResult<()> {
    let too_long = "a".repeat(256);
    for (host, port) in [("", 443), (too_long.as_str(), 443), ("origin.example", 0)] {
        let error = match prepare_socks5_udp_remote_target(host, port) {
            Ok(_) => {
                return Err(format!("invalid remote target {host:?}:{port} succeeded").into());
            }
            Err(error) => error,
        };
        assert_eq!(error.kind(), Socks5ErrorKind::InvalidTarget);
    }
    Ok(())
}

#[test]
fn remote_domain_reply_accepts_exact_domain_and_same_port_ips() -> TestResult<()> {
    let target = prepare_socks5_udp_remote_target("origin.example", 443)?;
    assert!(target.receive_target.accepts(DecodedUdpTarget::Domain {
        domain: b"origin.example",
        port: 443,
    }));
    assert!(target.receive_target.accepts(DecodedUdpTarget::Domain {
        domain: b"ORIGIN.EXAMPLE",
        port: 443,
    }));
    assert!(!target.receive_target.accepts(DecodedUdpTarget::Domain {
        domain: b"other.example",
        port: 443,
    }));
    assert!(!target.receive_target.accepts(DecodedUdpTarget::Domain {
        domain: b"origin.example",
        port: 8443,
    }));

    let first_ip = SocketAddr::from((Ipv4Addr::new(198, 51, 100, 7), 443));
    assert!(
        target
            .receive_target
            .accepts(DecodedUdpTarget::Ip(first_ip))
    );
    assert!(
        target
            .receive_target
            .accepts(DecodedUdpTarget::Ip(first_ip))
    );
    assert!(
        target
            .receive_target
            .accepts(DecodedUdpTarget::Ip(SocketAddr::from((
                Ipv4Addr::new(198, 51, 100, 8),
                443
            ))))
    );
    assert!(
        !target
            .receive_target
            .accepts(DecodedUdpTarget::Ip(SocketAddr::from((
                Ipv4Addr::new(198, 51, 100, 7),
                8443
            ))))
    );
    Ok(())
}

#[test]
fn udp_domain_codec_rejects_fragments_and_truncation() -> TestResult<()> {
    let target = prepare_socks5_udp_remote_target("origin.example", 443)?;
    assert_eq!(
        decode_udp_target(&target.target_header),
        Some((
            DecodedUdpTarget::Domain {
                domain: b"origin.example",
                port: 443,
            },
            target.target_header.len(),
        ))
    );

    let mut fragmented = target.target_header.clone();
    fragmented[2] = 1;
    assert_eq!(decode_udp_target(&fragmented), None);
    assert_eq!(decode_udp_target(&target.target_header[..6]), None);
    assert_eq!(decode_udp_target(&[0, 0, 0, 3, 0, 0, 53]), None);
    Ok(())
}

#[test]
fn local_receive_policy_remains_exact_ip() {
    let target = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 7), 443));
    let policy = ReceiveTarget::ExactIp(target);
    assert!(policy.accepts(DecodedUdpTarget::Ip(target)));
    assert!(!policy.accepts(DecodedUdpTarget::Ip(SocketAddr::from((
        Ipv4Addr::new(192, 0, 2, 8),
        443,
    )))));
    assert!(!policy.accepts(DecodedUdpTarget::Domain {
        domain: b"origin.example",
        port: 443,
    }));
}

#[test]
fn relay_send_errors_drop_the_datagram_without_failing_quic() {
    for kind in [
        std::io::ErrorKind::ConnectionRefused,
        std::io::ErrorKind::HostUnreachable,
        std::io::ErrorKind::NetworkUnreachable,
        std::io::ErrorKind::PermissionDenied,
        std::io::ErrorKind::OutOfMemory,
    ] {
        let outcome = relay_send_outcome(Err(std::io::Error::from(kind)), 8);
        assert!(
            matches!(outcome, Ok(RelaySend::Dropped(ref error)) if error.kind() == kind),
            "{kind:?} reached Quinn: {outcome:?}"
        );
    }
    assert!(matches!(
        relay_send_outcome(Ok(4), 8),
        Ok(RelaySend::Dropped(ref error)) if error.kind() == std::io::ErrorKind::WriteZero
    ));
    assert!(matches!(relay_send_outcome(Ok(8), 8), Ok(RelaySend::Sent)));
}

#[test]
fn blocked_relay_send_is_reported_to_quinn() {
    let outcome = relay_send_outcome(Err(std::io::ErrorKind::WouldBlock.into()), 8);
    assert!(matches!(outcome, Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock));
}

#[tokio::test]
async fn no_authentication_emits_udp_associate_with_unknown_client_address() -> TestResult<()> {
    let (mut client, mut server) = tokio::io::duplex(64);
    let client_address = SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0));
    let peer = SocketAddr::from((Ipv4Addr::new(192, 0, 2, 9), 1080));
    let server_task = tokio::spawn(async move {
        let mut greeting = [0; 3];
        server.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [5, 1, 0]);
        server.write_all(&[5, 0]).await?;

        let mut request = [0; 10];
        server.read_exact(&mut request).await?;
        assert_eq!(request, [5, 3, 0, 1, 0, 0, 0, 0, 0, 0]);
        server
            .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0x9c, 0x40])
            .await?;
        Ok::<_, std::io::Error>(())
    });

    negotiate_authentication(&mut client, Socks5Auth::None).await?;
    write_udp_associate(&mut client, client_address).await?;
    let relay = read_udp_associate_reply(&mut client, peer).await?;

    server_task.await??;
    assert_eq!(relay, SocketAddr::new(peer.ip(), 40_000));
    Ok(())
}

#[tokio::test]
async fn username_password_is_redacted_and_rejection_is_typed() -> TestResult<()> {
    let (mut client, mut server) = tokio::io::duplex(128);
    let server_task = tokio::spawn(async move {
        let mut greeting = [0; 4];
        server.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [5, 2, 0, 2]);
        server.write_all(&[5, 2]).await?;

        let mut request = [0; 13];
        server.read_exact(&mut request).await?;
        assert_eq!(&request, b"\x01\x04user\x06secret");
        server.write_all(&[1, 1]).await?;
        Ok::<_, std::io::Error>(())
    });

    let auth = Socks5Auth::UsernamePassword {
        username: "user",
        password: "secret",
    };
    let error = match negotiate_authentication(&mut client, auth).await {
        Ok(()) => return Err("rejected authentication succeeded".into()),
        Err(error) => error,
    };

    server_task.await??;
    assert_eq!(error.kind(), Socks5ErrorKind::Authentication);
    assert!(!error.to_string().contains("secret"));
    Ok(())
}

#[tokio::test]
async fn malformed_authentication_version_is_negotiation_failure() -> TestResult<()> {
    let (mut client, mut server) = tokio::io::duplex(128);
    let server_task = tokio::spawn(async move {
        let mut greeting = [0; 4];
        server.read_exact(&mut greeting).await?;
        server.write_all(&[5, 2]).await?;

        let mut request = [0; 13];
        server.read_exact(&mut request).await?;
        server.write_all(&[5, 0]).await?;
        Ok::<_, std::io::Error>(())
    });

    let error = match negotiate_authentication(
        &mut client,
        Socks5Auth::UsernamePassword {
            username: "user",
            password: "secret",
        },
    )
    .await
    {
        Ok(()) => return Err("malformed authentication response succeeded".into()),
        Err(error) => error,
    };

    server_task.await??;
    assert_eq!(error.kind(), Socks5ErrorKind::Negotiation);
    Ok(())
}

#[tokio::test]
async fn domain_and_zero_port_relay_replies_are_rejected() -> TestResult<()> {
    for reply in [
        vec![5, 0, 0, 3, 3, b'f', b'o', b'o', 0, 53],
        vec![5, 0, 0, 1, 127, 0, 0, 1, 0, 0],
    ] {
        let (mut client, mut server) = tokio::io::duplex(64);
        let server_task = tokio::spawn(async move { server.write_all(&reply).await });
        let error = match read_udp_associate_reply(
            &mut client,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 1080)),
        )
        .await
        {
            Ok(_) => return Err("invalid relay reply succeeded".into()),
            Err(error) => error,
        };
        server_task.await??;
        assert_eq!(error.kind(), Socks5ErrorKind::Negotiation);
    }
    Ok(())
}
