use super::*;
use crate::{proxy::Socks4UserId, route::Socks4Target};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn local_socks4_uses_only_the_first_ipv4_and_keeps_its_user_id() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let host = address.ip().to_string();
        let resolver = HostResolver::new().with_override(
            "local.test",
            [
                Ipv6Addr::LOCALHOST.into(),
                Ipv4Addr::new(127, 0, 0, 2).into(),
                Ipv4Addr::LOCALHOST.into(),
            ],
        );
        let family = AddressFamilyMemory::default();
        let operation = async {
            let route = TcpRoute::Socks4 {
                proxy: Endpoint {
                    host: &host,
                    port: address.port(),
                },
                target: Socks4Target::LocalDns(Endpoint {
                    host: "local.test",
                    port: 443,
                }),
                user_id: Socks4UserId::new("identity")?,
            };
            let (stream, slower) = connect_retaining(
                dialer(Some(&resolver)),
                route,
                &family,
                TcpBackupConnection {
                    delay: Duration::from_secs(1),
                    ..backup()
                },
            )
            .await
            .map_err(|e| e.into_leg())?;
            assert!(slower.is_none());
            assert_eq!(family.family(), Some(AddressFamily::Ipv4));
            drop(stream);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            let mut request = [0; 17];
            stream.read_exact(&mut request).await?;
            assert_eq!(&request, b"\x04\x01\x01\xbb\x7f\x00\x00\x02identity\0");
            stream.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).await?;
            peer::closed(&mut stream).await?;
            peer::no_connection(&listener);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(operation, peer)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn socks4_ipv6_and_invalid_credentials_fail_before_proxy_io() -> TestResult {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let host = address.ip().to_string();
    let family = AddressFamilyMemory::default();
    let route = TcpRoute::Socks4 {
        proxy: Endpoint {
            host: &host,
            port: address.port(),
        },
        target: Socks4Target::RemoteDns(Endpoint {
            host: "::1",
            port: 443,
        }),
        user_id: Socks4UserId::default(),
    };
    assert!(
        matches!(connect_retaining(dialer(None),route,&family,backup()).await,Err(SocksConnectionError::Four(e)) if e.kind()==Socks4ErrorKind::UnsupportedTarget)
    );
    let route = TcpRoute::Socks5 {
        proxy: Endpoint {
            host: &host,
            port: address.port(),
        },
        target: Socks5Target::RemoteDns(Endpoint {
            host: "remote.test",
            port: 443,
        }),
        auth: Socks5Auth::UsernamePassword {
            username: "",
            password: "secret",
        },
    };
    let error = connect_retaining(dialer(None), route, &family, backup()).await;
    assert!(
        matches!(error,Err(SocksConnectionError::Five(e)) if e.kind()==Socks5ErrorKind::InvalidAuthentication)
    );
    peer::no_connection(&listener);
    assert_eq!(family.family(), None);
    Ok(())
}

#[tokio::test]
async fn local_target_rejection_tries_the_next_target_on_a_fresh_proxy_socket() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let host = address.ip().to_string();
        let family = AddressFamilyMemory::default();
        let resolver = HostResolver::new().with_override(
            "local.test",
            [
                Ipv4Addr::new(127, 0, 0, 2).into(),
                Ipv4Addr::LOCALHOST.into(),
            ],
        );
        let operation = async {
            let route = TcpRoute::Socks5 {
                proxy: Endpoint {
                    host: &host,
                    port: address.port(),
                },
                target: Socks5Target::LocalDns(Endpoint {
                    host: "local.test",
                    port: 443,
                }),
                auth: Socks5Auth::None,
            };
            let (stream, slower) = connect_retaining(
                dialer(Some(&resolver)),
                route,
                &family,
                TcpBackupConnection {
                    delay: Duration::from_secs(1),
                    ..backup()
                },
            )
            .await
            .map_err(|e| e.into_leg())?;
            assert!(slower.is_none());
            assert_eq!(family.family(), Some(AddressFamily::Ipv4));
            drop(stream);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            let (mut first, _) = listener.accept().await?;
            assert_eq!(
                peer::five(&mut first, None).await?.host,
                Host::Ip(Ipv4Addr::new(127, 0, 0, 2).into())
            );
            peer::reply(&mut first, 5).await?;
            peer::closed(&mut first).await?;
            let (mut second, _) = listener.accept().await?;
            assert_eq!(
                peer::five(&mut second, None).await?.host,
                Host::Ip(Ipv4Addr::LOCALHOST.into())
            );
            peer::reply(&mut second, 0).await?;
            peer::closed(&mut second).await?;
            peer::no_connection(&listener);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(operation, peer)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn ruleset_rejection_is_terminal_with_its_original_typed_cause() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let host = address.ip().to_string();
        let family = AddressFamilyMemory::default();
        let resolver = HostResolver::new().with_override(
            "local.test",
            [
                Ipv4Addr::LOCALHOST.into(),
                Ipv4Addr::new(127, 0, 0, 2).into(),
            ],
        );
        let operation = async {
            let route = TcpRoute::Socks5 {
                proxy: Endpoint {
                    host: &host,
                    port: address.port(),
                },
                target: Socks5Target::LocalDns(Endpoint {
                    host: "local.test",
                    port: 443,
                }),
                auth: Socks5Auth::None,
            };
            let error = connect_retaining(
                dialer(Some(&resolver)),
                route,
                &family,
                TcpBackupConnection {
                    delay: Duration::from_secs(1),
                    ..backup()
                },
            )
            .await;
            let Err(SocksConnectionError::Five(error)) = error else {
                return Err("ruleset failure lost its SOCKS5 category".into());
            };
            assert_eq!(error.kind(), Socks5ErrorKind::Rejected);
            assert!(!error.is_target_specific_rejection());
            assert_eq!(family.family(), None);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            peer::five(&mut stream, None).await?;
            peer::reply(&mut stream, 2).await?;
            peer::closed(&mut stream).await?;
            peer::no_connection(&listener);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(operation, peer)?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn dropping_a_pending_owner_closes_the_authenticated_tunnel() -> TestResult {
    bounded(async {
        let listener=TcpListener::bind((Ipv4Addr::LOCALHOST,0)).await?;let address=listener.local_addr()?;let host=address.ip().to_string();let family=AddressFamilyMemory::default();let (seen_tx,seen_rx)=oneshot::channel();
        let operation=async {let route=TcpRoute::Socks5{proxy:Endpoint{host:&host,port:address.port()},target:Socks5Target::RemoteDns(Endpoint{host:"remote.test",port:443}),auth:Socks5Auth::None};
            let pending=connect_retaining(dialer(None),route,&family,TcpBackupConnection{delay:Duration::from_secs(1),..backup()});let mut pending=Box::pin(pending);
            tokio::select! {biased;result=&mut pending=>return Err(format!("setup unexpectedly completed: {}",result.is_ok()).into()),seen=seen_rx=>seen?};drop(pending);assert_eq!(family.family(),None);Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())};
        let peer=async {let (mut stream,_)=listener.accept().await?;peer::five(&mut stream,None).await?;seen_tx.send(()).map_err(|_|"setup owner ended")?;peer::closed(&mut stream).await?;peer::no_connection(&listener);Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())};
        tokio::try_join!(operation,peer)?;Ok(())
    }).await
}
