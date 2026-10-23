use std::{error::Error as _, io};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, duplex},
    time::timeout,
};

use super::super::{Error, Socks5ErrorKind, TargetAddr, connect};
use super::{DEADLINE, TestResult};

#[tokio::test]
async fn connect_consumes_each_bound_address_and_preserves_first_payload_bytes() -> TestResult {
    for reply in [
        vec![5, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        vec![
            5, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ],
        vec![5, 0, 0, 3, 0, 0, 0],
        vec![5, 0, 0, 3, 3, b'p', b'r', b'x', 0, 0],
    ] {
        let (mut client, mut proxy) = duplex(64);
        let peer = tokio::spawn(async move {
            let mut request = [0; 10];
            proxy.read_exact(&mut request).await?;
            assert_eq!(request, [5, 1, 0, 1, 192, 0, 2, 9, 1, 187]);
            proxy.write_all(&reply).await?;
            proxy.write_all(b"response").await
        });
        timeout(
            DEADLINE,
            connect(&mut client, TargetAddr::Ip(([192, 0, 2, 9], 443).into())),
        )
        .await??;
        let mut body = [0; 8];
        timeout(DEADLINE, client.read_exact(&mut body)).await??;
        assert_eq!(&body, b"response");
        timeout(DEADLINE, peer).await???;
    }
    Ok(())
}

#[tokio::test]
async fn connect_rejections_preserve_sources_and_target_fallback() -> TestResult {
    for status in [1, 2, 3, 4, 5, 6, 7, 8, 9, 255] {
        let (mut client, mut proxy) = duplex(64);
        let peer = tokio::spawn(async move {
            let mut request = [0; 10];
            proxy.read_exact(&mut request).await?;
            proxy.write_all(&[5, status, 0, 1]).await
        });
        let result = timeout(
            DEADLINE,
            connect(&mut client, TargetAddr::Ip(([192, 0, 2, 9], 443).into())),
        )
        .await?;
        let error = result.err().ok_or("rejected CONNECT succeeded")?;
        let source = error
            .source()
            .and_then(|source| source.downcast_ref::<Error>());
        assert!(matches!(
            (status, source),
            (1, Some(Error::GeneralSocksServerFailure))
                | (2, Some(Error::ConnectionNotAllowedByRuleset))
                | (3, Some(Error::NetworkUnreachable))
                | (4, Some(Error::HostUnreachable))
                | (5, Some(Error::ConnectionRefused))
                | (6, Some(Error::TtlExpired))
                | (7, Some(Error::CommandNotSupported))
                | (8, Some(Error::AddressTypeNotSupported))
                | (9 | 255, Some(Error::UnknownAuthMethod))
        ));
        assert_eq!(
            error.kind(),
            if status <= 8 {
                Socks5ErrorKind::Rejected
            } else {
                Socks5ErrorKind::Negotiation
            }
        );
        assert_eq!(
            error.is_target_specific_rejection(),
            matches!(status, 3..=6 | 8)
        );
        timeout(DEADLINE, peer).await???;
    }
    Ok(())
}

#[tokio::test]
async fn connect_reply_validation_preserves_precedence_and_nested_io_source() -> TestResult {
    for reply in [vec![4, 5, 1, 9], vec![5, 5, 1, 9], vec![5, 0, 0, 1, 127]] {
        let version = reply[0];
        let reserved = reply[2];
        let (mut client, mut proxy) = duplex(64);
        let peer = tokio::spawn(async move {
            let mut request = [0; 10];
            proxy.read_exact(&mut request).await?;
            proxy.write_all(&reply).await
        });
        let result = timeout(
            DEADLINE,
            connect(&mut client, TargetAddr::Ip(([192, 0, 2, 9], 443).into())),
        )
        .await?;
        let error = result.err().ok_or("malformed CONNECT succeeded")?;
        let source = error
            .source()
            .and_then(|source| source.downcast_ref::<Error>());
        match (version, reserved, source) {
            (4, _, Some(Error::InvalidResponseVersion))
            | (5, 1, Some(Error::InvalidReservedByte)) => {}
            (5, 0, Some(Error::Io(error))) => {
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof)
            }
            _ => return Err("CONNECT error lost validation precedence or I/O source".into()),
        }
        assert_eq!(error.kind(), Socks5ErrorKind::Negotiation);
        assert!(!error.is_target_specific_rejection());
        timeout(DEADLINE, peer).await???;
    }
    Ok(())
}
