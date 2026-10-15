//! Exact H2 retains quiet proxy sockets without parallelizing tunnel setup.
use super::super::{Http2ConnectionMode, PoolEntry, ProxyClaim};
use super::{cold_entry, reserve};
use crate::{HttpProxy, Route, authority::Endpoint, session::prune_timer::PrunedEntry};
use phantom_net::{
    http2::{Http2ProxyOpening, Http2TlsConnector},
    route::{Endpoint as NetEndpoint, HttpConnectRoute, ProxyTransport},
    tcp::{SlowerConnection, SlowerProgress},
};
use phantom_profile::browser::firefox;
use std::{future::Future, io, net::Ipv4Addr, sync::Arc, task::Poll, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    time::{Instant, timeout},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_secs(5);

async fn opening(
    entry: &PoolEntry,
) -> TestResult<(Http2TlsConnector, Http2ProxyOpening, TcpStream, Route)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?);
    let proxy = route.as_http_proxy().ok_or("missing proxy")?;
    let connector = Http2TlsConnector::new(&firefox::v157_tcp_tls(), &firefox::v157_http2())?;
    let (opening, slower) = connector
        .open_http_connect_retaining(
            HttpConnectRoute {
                proxy: ProxyTransport::Tcp(NetEndpoint {
                    host: "127.0.0.1",
                    port: address.port(),
                }),
                authority: "127.0.0.1:443",
                headers: proxy.ordered_connect_headers(),
                credentials: None,
            },
            "127.0.0.1",
            &entry.family,
        )
        .await?;
    assert!(slower.is_none());
    let (peer, _) = listener.accept().await?;
    Ok((connector, opening, peer, route))
}

async fn adopt(entry: &Arc<PoolEntry>, opening: Http2ProxyOpening) {
    let progress = SlowerProgress::new();
    progress.mark_connected();
    entry.adopt_proxy(SlowerConnection::new(
        progress,
        async move { Some(opening) },
    ));
    loop {
        let notified = entry.setup_done.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if entry
            .lock()
            .spares
            .iter()
            .any(|spare| spare.ready.is_some())
        {
            break;
        }
        notified.await;
    }
}

async fn head(peer: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= 4096 {
            return Err(io::Error::other("CONNECT head exceeds test bound"));
        }
        head.push(peer.read_u8().await?);
    }
    Ok(head)
}

#[tokio::test]
async fn exact_h2_waits_for_primary_setup_then_claims_its_quiet_backup_after_cancellation()
-> TestResult {
    timeout(WAIT, async {
        let entry = cold_entry().await?;
        let primary = reserve(&entry);
        let (connector, opening, mut peer, route) = opening(&entry).await?;
        adopt(&entry, opening).await;
        let endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
        let mut acquire = Box::pin(entry.acquire(&connector, None, &endpoint, &route, Http2ConnectionMode::TlsOrigin));
        assert!(std::future::poll_fn(|cx| Poll::Ready(acquire.as_mut().poll(cx).is_pending())).await);
        assert!(matches!(peer.try_read(&mut [0]), Err(error) if error.kind() == io::ErrorKind::WouldBlock), "backup sent speculative CONNECT");
        drop(primary);
        tokio::select! {
            result = &mut acquire => { drop(result); return Err("CONNECT finished without response".into()); }
            written = head(&mut peer) => assert_eq!(written?, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"),
        }
        assert!(entry.lock().connecting);
        drop(acquire);
        let mut rest = Vec::new(); peer.read_to_end(&mut rest).await?;
        assert!(rest.is_empty(), "cancelled CONNECT sent origin TLS");
        assert!(!entry.lock().connecting);
        assert!(entry.lock().spares.is_empty());
        Ok(())
    }).await?
}

#[tokio::test]
async fn exact_h2_success_closes_quiet_proxy_backup_without_connect_or_inner_tls() -> TestResult {
    timeout(WAIT, async {
        let entry = cold_entry().await?;
        let primary = reserve(&entry);
        let (_, opening, mut peer, _) = opening(&entry).await?;
        adopt(&entry, opening).await;
        let (client, _h2_peer) = tokio::io::duplex(64 * 1024);
        let winner =
            phantom_net::http2::Http2Connection::connect(client, &firefox::v157_http2()).await?;
        let lease = primary.finish(winner, None);
        let mut written = Vec::new();
        peer.read_to_end(&mut written).await?;
        assert!(written.is_empty());
        assert!(entry.lock().spares.is_empty());
        assert!(!entry.lock().connecting);
        drop(lease);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn exact_h2_unpolled_claim_returns_original_idle_age_for_pruning() -> TestResult {
    timeout(WAIT, async {
        let entry = cold_entry().await?;
        let (_, opening, mut peer, _) = opening(&entry).await?;
        let since = Instant::now() - Duration::from_secs(10);
        let reservation = reserve(&entry);
        drop(ProxyClaim {
            reservation: Some(reservation),
            opening: Some(opening),
            since,
        });
        assert_eq!(entry.lock().spares[0].idle_since, Some(since));
        assert!(!entry.lock().connecting);
        assert!(
            entry
                .prune(
                    since + Duration::from_secs(30),
                    Some(Duration::from_secs(30))
                )
                .empty
        );
        assert_eq!(peer.read(&mut [0]).await?, 0);
        Ok(())
    })
    .await?
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_reuse_stops_waiting_when_only_a_quiet_proxy_backup_remains() -> TestResult {
    timeout(WAIT, async {
        let entry = cold_entry().await?;
        let primary = reserve(&entry);
        let (connector, opening, mut peer, route) = opening(&entry).await?;
        adopt(&entry, opening).await;
        let mut reuse = Box::pin(entry.current_reusable());
        assert!(std::future::poll_fn(|cx| Poll::Ready(reuse.as_mut().poll(cx).is_pending())).await);
        drop(primary);
        assert!(reuse.await.is_none(), "quiet CONNECT backup cannot publish H2 by itself");
        assert_eq!(entry.lock().spares.len(), 1, "reuse lookup consumed the backup");
        let endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
        let mut acquire = Box::pin(entry.acquire(&connector, None, &endpoint, &route, Http2ConnectionMode::TlsOrigin));
        tokio::select! {
            result = &mut acquire => { drop(result); return Err("CONNECT finished without response".into()); }
            written = head(&mut peer) => assert_eq!(written?, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"),
        }
        drop(acquire);
        assert_eq!(peer.read(&mut [0]).await?, 0);
        assert!(!entry.lock().connecting);
        Ok(())
    }).await?
}

#[tokio::test]
async fn checked_on_request_expiry_closes_quiet_backup_before_opening_a_fresh_proxy_socket()
-> TestResult {
    timeout(WAIT, async {
        let limit = Duration::from_secs(10);
        let mut http1 = firefox::v157_http1();
        http1.idle_timeout = phantom_profile::Http1IdleTimeout::CheckedOnRequest(limit);
        let client = crate::Client::builder(
            phantom_profile::ClientProfile::new(firefox::v157_tcp_tls())
                .with_tcp(firefox::v157_tcp())
                .with_http1(http1)
                .with_http2(firefox::v157_http2()),
        ).build()?;
        let endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?);
        let entry = client.state.http2.entry(super::super::PoolKey::new(
            &endpoint, &route, Http2ConnectionMode::TlsOrigin,
        )).await;
        assert_eq!(entry.http1_used_idle_timeout, Some(limit));
        // No timer supplies the requested expiry: acquisition itself must apply it.
        assert_eq!(entry.prune.as_ref().and_then(|timer| timer.http1_limit()), None);
        let connector = Http2TlsConnector::new(&firefox::v157_tcp_tls(), &firefox::v157_http2())?;
        let proxy = route.as_http_proxy().ok_or("missing proxy")?;
        let (opening, slower) = connector.open_http_connect_retaining(HttpConnectRoute {
            proxy: ProxyTransport::Tcp(NetEndpoint { host: "127.0.0.1", port: address.port() }),
            authority: "127.0.0.1:443",
            headers: proxy.ordered_connect_headers(), credentials: None,
        }, "127.0.0.1", &entry.family).await?;
        assert!(slower.is_none());
        let (mut old_peer, _) = listener.accept().await?;
        adopt(&entry, opening).await;
        entry.lock().spares[0].idle_since = Some(Instant::now() - limit);
        let mut acquire = Box::pin(entry.acquire(&connector, None, &endpoint, &route, Http2ConnectionMode::TlsOrigin));
        let mut fresh_peer = tokio::select! {
            result = &mut acquire => { drop(result); return Err("setup finished without proxy response".into()); }
            accepted = listener.accept() => accepted?.0,
        };
        assert_eq!(old_peer.read(&mut [0]).await?, 0, "expired opening was reused");
        tokio::select! {
            result = &mut acquire => { drop(result); return Err("CONNECT finished without response".into()); }
            written = head(&mut fresh_peer) => assert_eq!(written?, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"),
        }
        drop(acquire);
        assert_eq!(fresh_peer.read(&mut [0]).await?, 0);
        assert!(entry.lock().spares.is_empty());
        assert!(!entry.lock().connecting);
        Ok(())
    }).await?
}
