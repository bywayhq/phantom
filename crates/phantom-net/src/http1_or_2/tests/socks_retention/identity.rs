use super::*;
use crate::{
    http1_or_2::{Http1Or2TlsError, Http1Or2TlsErrorKind},
    http2::{Http2TlsError, Http2TlsErrorKind},
    route::{Endpoint, OriginRoute, Socks5Target, TcpRoute},
};

#[tokio::test]
async fn exact_h2_rejects_http1_alpn_without_reusing_the_other_socks_negotiation() -> TestResult<()>
{
    timeout(WAIT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let connectors = Connectors::new(&identity, false)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let host = address.ip().to_string();
        let family = AddressFamilyMemory::new();
        let peer = async {
            let mut first = negotiate(&listener, false).await?;
            let mut second = negotiate(&listener, false).await?;
            reply(&mut second).await?;
            let mut stream = tls(second, &acceptor).await?;
            let mut byte = [0];
            match stream.read(&mut byte).await {
                Ok(0) => {}
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::BrokenPipe
                            | io::ErrorKind::UnexpectedEof
                    ) => {}
                other => {
                    return Err(format!("rejected ALPN sent application bytes: {other:?}").into());
                }
            }
            closed(&mut first).await
        };
        let caller = async {
            let error = connectors
                .exact
                .connect_socks_retaining(origin(&host, address.port(), false), &family)
                .await
                .err()
                .ok_or("exact H2 accepted HTTP/1.1")?;
            assert_eq!(error.kind(), Http2TlsErrorKind::UnsupportedAlpn);
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn both_connectors_remember_the_ipv6_target_over_an_ipv4_proxy_and_bound_reply()
-> TestResult<()> {
    for exact in [false, true] {
        timeout(WAIT, async {
            let identity = TestIdentity::generate()?;
            let acceptor = identity.acceptor(TestServerAlpn::H2)?;
            let connectors = Connectors::new(&identity, false)?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let host = address.ip().to_string();
            let family = AddressFamilyMemory::new();
            let peer = async {
                let (mut stream, _) = listener.accept().await?;
                let mut greeting = [0; 3];
                stream.read_exact(&mut greeting).await?;
                assert_eq!(greeting, [5, 1, 0]);
                stream.write_all(&[5, 0]).await?;
                let mut request = [0; 22];
                stream.read_exact(&mut request).await?;
                assert_eq!(&request[..4], &[5, 1, 0, 4]);
                assert_eq!(&request[4..20], &std::net::Ipv6Addr::LOCALHOST.octets());
                assert_eq!(&request[20..], &443u16.to_be_bytes());
                reply(&mut stream).await?;
                let stream = tls(stream, &acceptor).await?;
                serve_h2(stream, "/family").await
            };
            let caller = async {
                let mut route = origin(&host, address.port(), false);
                if let OriginRoute::Tls {
                    tcp: TcpRoute::Socks5 { target, .. },
                    ..
                } = &mut route
                {
                    *target = Socks5Target::LocalDns(Endpoint {
                        host: "::1",
                        port: 443,
                    });
                }
                let (connection, slower) = connectors.connect(exact, route, &family).await?;
                assert!(slower.is_none());
                assert_eq!(family.family(), Some(AddressFamily::Ipv6));
                send(&connection, "/family").await?;
                drop(connection);
                TestResult::Ok(())
            };
            tokio::try_join!(caller, peer)?;
            TestResult::Ok(())
        })
        .await??;
    }
    Ok(())
}

#[tokio::test]
async fn both_connectors_keep_origin_verification_and_cancel_the_other_socks_owner_on_tls_failure()
-> TestResult<()> {
    for exact in [false, true] {
        timeout(WAIT, async {
            let trusted = TestIdentity::generate()?;
            let untrusted = TestIdentity::generate()?;
            let acceptor = untrusted.acceptor(TestServerAlpn::H2)?;
            let connectors = Connectors::new(&trusted, false)?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let host = address.ip().to_string();
            let family = AddressFamilyMemory::new();
            let peer = async {
                let mut first = negotiate(&listener, false).await?;
                let mut second = negotiate(&listener, false).await?;
                reply(&mut second).await?;
                assert!(tls(second, &acceptor).await.is_err());
                closed(&mut first).await
            };
            let caller = async {
                let error = connectors
                    .connect(exact, origin(&host, address.port(), false), &family)
                    .await
                    .err()
                    .ok_or("untrusted origin accepted")?;
                if exact {
                    assert_eq!(
                        error
                            .downcast_ref::<Http2TlsError>()
                            .ok_or("wrong exact error type")?
                            .kind(),
                        Http2TlsErrorKind::Tls
                    );
                } else {
                    assert_eq!(
                        error
                            .downcast_ref::<Http1Or2TlsError>()
                            .ok_or("wrong negotiated error type")?
                            .kind(),
                        Http1Or2TlsErrorKind::Tls
                    );
                }
                TestResult::Ok(())
            };
            tokio::try_join!(caller, peer)?;
            TestResult::Ok(())
        })
        .await??;
    }
    Ok(())
}
