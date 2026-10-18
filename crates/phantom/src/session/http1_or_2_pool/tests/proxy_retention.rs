//! Quiet real proxy sockets exercise claims independently of race timing.
use super::{bound, connections, http2, reserve};
use crate::session::{
    http1_or_2_pool::{Acquired, Checkout, EntryConnections},
    prune_timer::PrunedEntry,
};
use phantom_net::{
    http1_or_2::{Http1Or2ProxyOpening, Http1Or2TlsConnector},
    proxy::HttpConnectHeader,
    route::{Endpoint, HttpConnectRoute, ProxyTransport},
    tcp::{SlowerConnection, SlowerProgress},
};
use phantom_profile::browser::firefox;
use std::{io, net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::{Instant, timeout},
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const WAIT: Duration = Duration::from_secs(5);

#[tokio::test]
async fn refresh_does_not_retain_a_completed_claimed_proxy_spare() -> TestResult {
    timeout(WAIT, async {
        let connections = connections(bound(2)?)?;
        let (opening, mut peer, _) = opening(&connections).await?;
        adopt(&connections, opening).await;
        let Checkout::Proxy(claim) = connections.checkout(false, false) else {
            return Err("quiet opening not claimed".into());
        };
        let registry = Arc::new(crate::session::retired_connections::RetiredConnections::default());
        connections.begin_retirement(&registry);
        let weak = Arc::downgrade(&connections);
        drop(claim);
        drop(connections);
        assert!(
            weak.upgrade().is_none(),
            "completed claim retained the retired owner"
        );
        assert_eq!(peer.read(&mut [0]).await?, 0);
        drop(registry);
        Ok(())
    })
    .await?
}

fn route(port: u16, headers: &[HttpConnectHeader]) -> HttpConnectRoute<'_> {
    HttpConnectRoute {
        speculative_tls: false,
        proxy: ProxyTransport::Tcp(Endpoint {
            host: "127.0.0.1",
            port,
        }),
        authority: "127.0.0.1:443",
        headers,
        credentials: None,
    }
}

async fn opening(
    connections: &EntryConnections,
) -> TestResult<(Http1Or2ProxyOpening, TcpStream, u16)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let connector = Http1Or2TlsConnector::new(&firefox::v157_tcp_tls(), &firefox::v157_http2())?;
    let (opening, slower) = connector
        .open_http_connect_retaining(
            route(port, &[HttpConnectHeader::authority("Host")]),
            "127.0.0.1",
            &connections.family,
        )
        .await?;
    assert!(slower.is_none());
    let (peer, _) = listener.accept().await?;
    Ok((opening, peer, port))
}

async fn adopt(connections: &Arc<EntryConnections>, opening: Http1Or2ProxyOpening) {
    let progress = SlowerProgress::new();
    progress.mark_connected();
    connections.adopt_proxy(SlowerConnection::new(
        progress,
        async move { Some(opening) },
    ));
    loop {
        let notified = connections.setup_done.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if connections
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
async fn unpolled_proxy_claim_retains_original_idle_age_and_prunes_outside_the_lock() -> TestResult
{
    timeout(WAIT, async {
        let connections = connections(bound(2)?)?;
        let (opening, mut peer, _) = opening(&connections).await?;
        adopt(&connections, opening).await;
        let since = Instant::now() - Duration::from_secs(10);
        connections.lock().spares[0].idle_since = Some(since);
        let Checkout::Proxy(claim) = connections.checkout(false, false) else {
            return Err("quiet opening not claimed".into());
        };
        assert_eq!(connections.counts().2, 1);
        assert_eq!(
            connections.lock().open_http1_or_connecting(),
            1,
            "claimed socket counted twice"
        );
        drop(claim);
        assert_eq!(connections.lock().spares[0].idle_since, Some(since));
        assert_eq!(connections.counts().2, 0);
        assert!(
            connections
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

#[tokio::test]
async fn cancelling_a_polled_proxy_claim_closes_connect_and_releases_setup() -> TestResult {
    timeout(WAIT, async {
        let connections = connections(bound(2)?)?;
        let (opening, mut peer, port) = opening(&connections).await?;
        adopt(&connections, opening).await;
        let Checkout::Proxy(claim) = connections.checkout(false, false) else { return Err("quiet opening not claimed".into()); };
        let headers = [HttpConnectHeader::authority("Host")];
        let mut finish = Box::pin(claim.finish(route(port, &headers)));
        tokio::select! {
            result = &mut finish => { drop(result); return Err("CONNECT completed without response".into()); }
            written = head(&mut peer) => assert_eq!(written?, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"),
        }
        drop(finish);
        let mut rest = Vec::new(); peer.read_to_end(&mut rest).await?;
        assert!(rest.is_empty(), "cancelled CONNECT sent origin TLS");
        assert_eq!(connections.counts(), (0, 0, 0));
        assert!(connections.lock().spares.is_empty());
        Ok(())
    }).await?
}

#[tokio::test]
async fn an_h2_winner_cancels_a_claim_but_idle_pruning_does_not_cancel_its_active_connect()
-> TestResult {
    timeout(WAIT, async {
        let connections = connections(bound(2)?)?;
        let winner_reservation = reserve(&connections)?;
        let (opening, mut peer, port) = opening(&connections).await?;
        adopt(&connections, opening).await;
        let since = Instant::now() - Duration::from_secs(10);
        connections.lock().spares[0].idle_since = Some(since);
        let Checkout::Proxy(claim) = connections.checkout(false, false) else { return Err("quiet opening not claimed".into()); };
        let headers = [HttpConnectHeader::authority("Host")];
        let mut finish = Box::pin(claim.finish(route(port, &headers)));
        tokio::select! {
            result = &mut finish => { drop(result); return Err("CONNECT completed without response".into()); }
            written = head(&mut peer) => { written?; }
        }
        let pruned = connections.prune(since + Duration::from_secs(30), Some(Duration::from_secs(30)));
        assert_eq!(pruned.next, None, "active CONNECT kept scheduling idle expiry");
        assert_eq!(connections.lock().spares.len(), 1, "active CONNECT pruned as idle");
        let (winner, _h2_peer) = http2().await?;
        assert!(matches!(winner_reservation.finish(winner), Acquired::Http2));
        assert!(matches!(finish.await?, Acquired::AwaitSetup));
        let mut rest = Vec::new(); peer.read_to_end(&mut rest).await?;
        assert!(rest.is_empty(), "cancelled claim sent origin TLS");
        assert!(connections.lock().spares.is_empty());
        assert_eq!(connections.counts().2, 0);
        Ok(())
    }).await?
}

#[tokio::test]
async fn an_h2_winner_closes_ready_and_pending_quiet_proxy_backups() -> TestResult {
    timeout(WAIT, async {
        let connections = connections(bound(3)?)?;
        let winner_reservation = reserve(&connections)?;
        let (ready, mut ready_peer, _) = opening(&connections).await?;
        adopt(&connections, ready).await;
        let (pending, mut pending_peer, _) = opening(&connections).await?;
        let (release, released) = oneshot::channel::<()>();
        let (started, entered) = oneshot::channel();
        let progress = SlowerProgress::new();
        progress.mark_connected();
        connections.adopt_proxy(SlowerConnection::new(progress, async move {
            started.send(()).ok();
            released.await.ok().map(|()| pending)
        }));
        entered.await?;
        let (winner, _h2_peer) = http2().await?;
        assert!(matches!(winner_reservation.finish(winner), Acquired::Http2));
        let mut bytes = Vec::new();
        ready_peer.read_to_end(&mut bytes).await?;
        assert!(bytes.is_empty());
        pending_peer.read_to_end(&mut bytes).await?;
        assert!(bytes.is_empty(), "quiet backup sent CONNECT or origin TLS");
        assert!(release.send(()).is_err(), "cancelled owner still alive");
        assert!(connections.lock().spares.is_empty());
        Ok(())
    })
    .await?
}
