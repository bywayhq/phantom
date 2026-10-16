use super::super::QuietOpening;
use super::*;
use crate::session::prune_timer::PrunedEntry;
use phantom_net::{
    http1::{Http1SocksOpening, Http1TlsConnector},
    proxy::Socks5Auth,
    route::{Endpoint as NetEndpoint, OriginRoute, Socks5Target, TcpRoute},
    tcp::{AddressFamily, SlowerProgress},
};
use phantom_profile::browser::firefox;
use std::{io, net::Ipv4Addr};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Instant, timeout},
};
async fn opening(
    connections: &EntryConnections,
) -> Result<(Http1SocksOpening, TcpStream), Box<dyn std::error::Error>> {
    let connector =
        Http1TlsConnector::new(&firefox::v157_tcp_tls())?.with_tcp_settings(&firefox::v157_tcp());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let origin = OriginRoute::Plaintext {
        tcp: TcpRoute::Socks5 {
            proxy: NetEndpoint {
                host: "127.0.0.1",
                port,
            },
            target: Socks5Target::LocalDns(NetEndpoint {
                host: "127.0.0.1",
                port: 80,
            }),
            auth: Socks5Auth::None,
        },
        family: None,
    };
    let connect = async {
        let (opening, slower) = connector
            .open_socks_retaining(origin, &connections.family)
            .await?;
        drop(slower);
        Ok::<_, Box<dyn std::error::Error>>(opening)
    };
    let peer = async {
        let (mut stream, _) = listener.accept().await?;
        let mut greeting = [0; 3];
        stream.read_exact(&mut greeting).await?;
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await?;
        let mut request = [0; 10];
        stream.read_exact(&mut request).await?;
        assert_eq!(request, [5, 1, 0, 1, 127, 0, 0, 1, 0, 80]);
        stream.write_all(&[5, 0, 0, 1, 127, 0, 0, 2, 0, 81]).await?;
        Ok::<_, Box<dyn std::error::Error>>(stream)
    };
    tokio::try_join!(connect, peer)
}
#[tokio::test]
async fn unpolled_socks_claim_keeps_original_idle_age_then_prunes_the_quiet_tunnel() -> TestResult {
    timeout(Duration::from_secs(5), async {
        let limit = Duration::from_secs(30);
        let connections = timed_connections(NonZeroUsize::MIN, Some(limit));
        let (opening, mut peer) = opening(&connections).await?;
        assert_eq!(connections.family.family(), Some(AddressFamily::Ipv4));
        let progress = SlowerProgress::new();
        progress.mark_connected();
        let since = Instant::now() - Duration::from_secs(10);
        connections.keep_proxy_ready(QuietOpening::Socks(opening), progress, since);
        let Checkout::Proxy(claim) = connections.checkout(false) else {
            return Err("SOCKS opening was not claimed".into());
        };
        drop(claim);
        assert_eq!(connections.lock().leased, 0);
        assert_eq!(connections.lock().spares[0].idle_since, Some(since));
        let mut byte = [0];
        assert!(
            matches!(peer.try_read(&mut byte),Err(error)if error.kind()==io::ErrorKind::WouldBlock)
        );
        assert!(connections.prune(since + limit, Some(limit)).empty);
        assert_eq!(peer.read(&mut byte).await?, 0);
        assert_eq!(connections.open(), 0);
        // The timer owns subsequent family expiry, after its empty snapshot.
        assert_eq!(connections.family.family(), Some(AddressFamily::Ipv4));
        Ok(())
    })
    .await?
}
#[tokio::test]
async fn dropping_socks_pool_owner_closes_its_quiet_tunnel_without_origin_bytes() -> TestResult {
    timeout(Duration::from_secs(5), async {
        let connections = connections(NonZeroUsize::MIN);
        let (opening, mut peer) = opening(&connections).await?;
        let progress = SlowerProgress::new();
        progress.mark_connected();
        connections.keep_proxy_ready(QuietOpening::Socks(opening), progress, Instant::now());
        drop(connections);
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await?, 0);
        Ok(())
    })
    .await?
}
