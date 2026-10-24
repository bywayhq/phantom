use super::*;
use crate::{
    host_resolver::{AddressResolver, HostResolver},
    proxy::Socks5Auth,
    route::{Endpoint, Socks5Target},
    tcp::AddressFamily,
};
use peer::{Host, TestResult, WAIT};
use std::{
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::oneshot, time::timeout};
mod peer;
fn backup() -> TcpBackupConnection {
    TcpBackupConnection {
        delay: Duration::from_millis(1),
        known_family_backup_timeout: Some(Duration::from_secs(1)),
        socks_proxy_dns_feedback: phantom_profile::SocksProxyDnsFeedback::AllConnectFailures,
    }
}
fn dialer(resolver: Option<&HostResolver>) -> Dialer<'_> {
    Dialer {
        tcp: Some(phantom_profile::browser::firefox::v157_tcp()),
        resolver,
        ..Dialer::default()
    }
}
async fn bounded(future: impl Future<Output = TestResult>) -> TestResult {
    timeout(WAIT, future).await?
}

#[tokio::test]
async fn completed_negotiation_wins_and_remote_dns_has_no_observed_family() -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy_host = address.ip().to_string();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&calls);
        let resolver = HostResolver::new().with_resolver(AddressResolver::from_fn(move |_| {
            count.fetch_add(1, Ordering::Relaxed);
            async { Err(io::Error::other("remote target must not resolve")) }
        }));
        let family = AddressFamilyMemory::default();
        let (release_tx, release_rx) = oneshot::channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let (quiet_tx, quiet_rx) = oneshot::channel();
        let peer = async {
            let (mut first, _) = listener.accept().await?;
            let request = peer::five(&mut first, Some(("user", "password"))).await?;
            assert_eq!(request.host, Host::Domain("remote.test".into()));
            assert_eq!(request.port, 443);
            let (mut second, _) = listener.accept().await?;
            assert_eq!(
                peer::five(&mut second, Some(("user", "password"))).await?,
                request
            );
            peer::reply(&mut second, 0).await?;
            release_rx.await?;
            peer::reply(&mut first, 0).await?;
            ready_rx.await?;
            let mut byte = [0];
            assert!(
                matches!(first.try_read(&mut byte),Err(e) if e.kind()==io::ErrorKind::WouldBlock)
            );
            quiet_tx
                .send(())
                .map_err(|_| "owner ended before quiet observation")?;
            peer::closed(&mut first).await?;
            peer::closed(&mut second).await?;
            peer::no_connection(&listener);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let operation = async {
            let route = TcpRoute::Socks5 {
                proxy: Endpoint {
                    host: &proxy_host,
                    port: address.port(),
                },
                target: Socks5Target::RemoteDns(Endpoint {
                    host: "remote.test",
                    port: 443,
                }),
                auth: Socks5Auth::UsernamePassword {
                    username: "user",
                    password: "password",
                },
            };
            let (winner, slower) =
                connect_retaining(dialer(Some(&resolver)), route, &family, backup())
                    .await
                    .map_err(|e| e.into_leg())?;
            assert_eq!(family.family(), None);
            let slower = slower.ok_or("missing complete slower negotiation")?;
            assert!(!slower.progress().has_connected());
            release_tx.send(()).map_err(|_| "first peer ended")?;
            let spare = slower.finish().await.ok_or("slower negotiation failed")?;
            assert_eq!(family.family(), None);
            ready_tx.send(()).map_err(|_| "first peer ended")?;
            quiet_rx.await?;
            drop(spare);
            drop(winner);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(peer, operation)?;
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        Ok(())
    })
    .await
}

#[tokio::test]
async fn logical_ipv4_is_remembered_through_an_ipv6_proxy() -> TestResult {
    family_case(Ipv6Addr::LOCALHOST.into(), "127.0.0.1", AddressFamily::Ipv4).await
}
#[tokio::test]
async fn logical_ipv6_is_remembered_through_an_ipv4_proxy() -> TestResult {
    family_case(Ipv4Addr::LOCALHOST.into(), "::1", AddressFamily::Ipv6).await
}
async fn family_case(proxy_ip: IpAddr, target: &str, expected: AddressFamily) -> TestResult {
    bounded(async {
        let listener = TcpListener::bind((proxy_ip, 0)).await?;
        let address = listener.local_addr()?;
        let proxy_host = address.ip().to_string();
        let family = AddressFamilyMemory::default();
        let operation = async {
            let route = TcpRoute::Socks5 {
                proxy: Endpoint {
                    host: &proxy_host,
                    port: address.port(),
                },
                target: Socks5Target::LocalDns(Endpoint {
                    host: target,
                    port: 443,
                }),
                auth: Socks5Auth::None,
            };
            let (stream, slower) = connect_retaining(
                dialer(None),
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
            assert_eq!(family.family(), Some(expected));
            drop(stream);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            let request = peer::five(&mut stream, None).await?;
            assert_eq!(request.host, Host::Ip(target.parse()?));
            peer::reply(&mut stream, 0).await?;
            peer::closed(&mut stream).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(operation, peer)?;
        Ok(())
    })
    .await
}

mod target_failures;

mod feedback;

mod refusal;

mod async_feedback;
