//! Two actual sockets exercise pool ownership independently of OS race timing.
use super::bound;
use http_body_util::BodyExt;
use phantom_net::{
    http1::{Http1ProxyOpening, Http1TlsConnector},
    proxy::HttpConnectHeader,
    request::{OriginForm, RequestHeader},
    route::{Endpoint as NetEndpoint, HttpConnectRoute, ProxyTransport},
    tcp::{AddressFamily, SlowerConnection, SlowerProgress},
};
use phantom_profile::{ProxyConnectField, browser::firefox};
use std::{io, net::Ipv4Addr, num::NonZeroUsize, sync::Arc, time::Duration};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::{Instant, timeout},
};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
use super::super::{Checkout, EntryConnections, Http1ConnectionMode, Http1Pool, PoolKey};
use crate::{
    HttpProxy, Route,
    authority::Endpoint,
    session::prune_timer::{PruneTimer, PrunedEntry},
};
mod peer;
const WAIT: Duration = Duration::from_secs(5);
#[derive(Clone, Copy)]
enum Auth {
    None,
    Basic,
    Digest,
}

fn routed(base: &Route, value: &str) -> TestResult<Route> {
    let mut template = firefox::v157_proxy_connect();
    template.http1_fields = vec![
        ProxyConnectField::FromRequest {
            name: "X-Claim".into(),
        },
        ProxyConnectField::Authority {
            name: "host".into(),
        },
        ProxyConnectField::ProxyAuthorization {
            name: "Proxy-Authorization".into(),
        },
    ];
    base.with_profile_connect(Some(&template), |_| {
        Some(RequestHeader::new("X-Claim", value))
    })
    .ok_or_else(|| "profile fields were not applied".into())
}

fn borrowed<'a>(route: &'a Route, authority: &'a str) -> TestResult<HttpConnectRoute<'a>> {
    let proxy = route.as_http_proxy().ok_or("missing proxy")?;
    Ok(HttpConnectRoute {
        proxy: ProxyTransport::Tcp(NetEndpoint {
            host: proxy.host(),
            port: proxy.port(),
        }),
        authority,
        headers: proxy.ordered_connect_headers(),
        credentials: proxy.authentication(),
    })
}

async fn quiet_opening(
    connector: &Http1TlsConnector,
    route: &Route,
    family: &phantom_net::tcp::AddressFamilyMemory,
) -> TestResult<Http1ProxyOpening> {
    let (opening, slower) = connector
        .open_http_connect_retaining(borrowed(route, "127.0.0.1:443")?, "127.0.0.1", family)
        .await?;
    assert!(
        slower.is_none(),
        "one loopback address created another race attempt"
    );
    Ok(opening)
}

#[tokio::test]
async fn anonymous_backup_is_adopted_before_the_primary_connect_waits() -> TestResult {
    two_sockets(Auth::None).await
}
#[tokio::test]
async fn basic_backup_claim_uses_current_profile_fields_and_its_own_challenge() -> TestResult {
    two_sockets(Auth::Basic).await
}
#[tokio::test]
async fn digest_backup_claim_does_not_reserve_a_nonce_before_its_challenge() -> TestResult {
    two_sockets(Auth::Digest).await
}

async fn two_sockets(auth: Auth) -> TestResult {
    timeout(WAIT, async {
        let (root, acceptor) = peer::identity()?;
        let connector = Http1TlsConnector::new_with_additional_roots(&firefox::v157_tcp_tls(), [&*root])?.with_tcp_settings(&firefox::v157_tcp());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = HttpProxy::new(&format!("http://{address}"))?;
        let proxy = match auth { Auth::None => proxy, Auth::Basic => proxy.with_basic_auth("user", "secret")?, Auth::Digest => proxy.with_digest_auth("user", "secret")? };
        let base = Route::http_proxy(proxy);
        let first_route = routed(&base, "first")?;
        let second_route = routed(&base, "second")?;
        assert_eq!(first_route, second_route, "per-request fields changed route identity");
        let endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
        let pool = Http1Pool::new(bound(4)?, bound(6)?, bound(6)?);
        let entry = pool.entry(PoolKey::new(&endpoint, &first_route, Http1ConnectionMode::TlsOrigin)).await;
        let Checkout::Reserved(primary_reservation) = entry.connections.checkout(false) else { return Err("primary did not reserve setup".into()); };
        let primary = quiet_opening(&connector, &first_route, &entry.connections.family).await?;
        let (mut primary_peer, _) = listener.accept().await?;
        let backup = quiet_opening(&connector, &first_route, &entry.connections.family).await?;
        let (backup_peer, _) = listener.accept().await?;
        let progress = SlowerProgress::new();
        progress.mark_connected(); // The preceding real TCP connect completed.
        let (release, released) = oneshot::channel();
        let slower = SlowerConnection::new(progress, async move { released.await.ok().map(|()| backup) });
        let route = borrowed(&first_route, "127.0.0.1:443")?;
        let mut primary = Box::pin(entry.finish_proxy_opening(primary, Some(slower), route));
        tokio::select! {
            result = &mut primary => { drop(result); return Err("primary completed before CONNECT response".into()); }
            head = peer::head(&mut primary_peer) => assert_eq!(head?, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nX-Claim: first\r\nhost: 127.0.0.1:443\r\n\r\n"),
        }
        assert_eq!(entry.connections.lock().spares.len(), 1, "spare not adopted before primary CONNECT");
        assert_eq!(entry.connections.open(), 2);
        assert_eq!(entry.connections.family.family(), Some(AddressFamily::Ipv4));
        let mut byte = [0];
        assert!(matches!(backup_peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        release.send(()).map_err(|()| "spare owner ended")?;
        let request = async {
            let lease = entry.acquire(&connector, None, &endpoint, &second_route, Http1ConnectionMode::TlsOrigin, false).await?;
            let response = lease.connection.send_get(OriginForm::parse("/claimed")?, vec![RequestHeader::new("Host", "127.0.0.1")]).await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            drop(lease);
            TestResult::Ok(())
        };
        tokio::try_join!(request, peer::serve(backup_peer, acceptor, auth))?;
        assert!(std::future::poll_fn(|context| std::task::Poll::Ready(listener.poll_accept(context).is_pending())).await, "claim opened a third socket");
        drop(primary);
        drop(primary_reservation);
        let mut after_connect = Vec::new();
        primary_peer.read_to_end(&mut after_connect).await?;
        assert!(after_connect.is_empty(), "cancelled primary sent origin TLS before CONNECT completed");
        assert_eq!(entry.connections.lock().leased, 0);
        assert!(entry.connections.lock().spares.is_empty());
        Ok(())
    }).await?
}

async fn ready(connections: &Arc<EntryConnections>) -> TestResult<(Http1ProxyOpening, TcpStream)> {
    let (root, _) = peer::identity()?;
    let connector =
        Http1TlsConnector::new_with_additional_roots(&firefox::v157_tcp_tls(), [&*root])?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let fields = [HttpConnectHeader::authority("Host")];
    let route = HttpConnectRoute {
        proxy: ProxyTransport::Tcp(NetEndpoint {
            host: "127.0.0.1",
            port: address.port(),
        }),
        authority: "127.0.0.1:443",
        headers: &fields,
        credentials: None,
    };
    let (opening, _) = connector
        .open_http_connect_retaining(route, "127.0.0.1", &connections.family)
        .await?;
    let (peer, _) = listener.accept().await?;
    Ok((opening, peer))
}

fn put(connections: &EntryConnections, opening: Http1ProxyOpening, since: Instant) {
    let progress = SlowerProgress::new();
    progress.mark_connected();
    connections.keep_proxy_ready(opening, progress, since);
}

#[tokio::test]
async fn dropping_an_unpolled_claim_returns_the_quiet_socket_without_restarting_its_idle_age()
-> TestResult {
    timeout(WAIT, async {
        let limit = Duration::from_secs(30);
        let connections = super::timed_connections(NonZeroUsize::MIN, Some(limit));
        let (opening, mut peer) = ready(&connections).await?;
        let since = Instant::now() - Duration::from_secs(10);
        put(&connections, opening, since);
        let Checkout::Proxy(claim) = connections.checkout(false) else { return Err("raw opening not claimed".into()); };
        drop(claim);
        assert_eq!(connections.lock().leased, 0);
        assert_eq!(connections.lock().spares[0].idle_since, Some(since));
        let mut byte = [0];
        assert!(matches!(peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        connections.prune(since + limit, Some(limit));
        assert_eq!(peer.read(&mut byte).await?, 0);
        assert_eq!(connections.open(), 0);
        Ok(())
    }).await?
}

#[tokio::test]
async fn dropping_a_pending_claim_returns_the_later_completed_quiet_opening() -> TestResult {
    timeout(WAIT, async {
        let connections = super::connections(bound(2)?);
        let (opening, mut peer) = ready(&connections).await?;
        let progress = SlowerProgress::new(); progress.mark_connected();
        let (send, receive) = oneshot::channel();
        connections.adopt_proxy(SlowerConnection::new(progress, async move { receive.await.ok().map(|()| opening) }));
        let Checkout::Spare(claim) = connections.checkout(false) else { return Err("pending raw opening not claimed".into()); };
        drop(claim);
        send.send(()).map_err(|()| "spare task ended")?;
        while !connections.lock().spares.iter().any(|spare| spare.ready.is_some()) { tokio::task::yield_now().await; }
        assert_eq!(connections.lock().leased, 0);
        let mut byte = [0];
        assert!(matches!(peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        drop(connections);
        assert_eq!(peer.read(&mut byte).await?, 0);
        Ok(())
    }).await?
}

#[tokio::test]
async fn pruning_a_quiet_proxy_socket_forgets_family_only_after_its_last_owner_leaves() -> TestResult
{
    timeout(WAIT, async {
        let timer = PruneTimer::unscheduled(Duration::ZERO);
        let connections = EntryConnections::new(
            bound(2)?,
            Some(Duration::ZERO),
            Some(Arc::clone(&timer)),
            Arc::default(),
        );
        let (opening, mut peer) = ready(&connections).await?;
        connections.family.remember(AddressFamily::Ipv4);
        put(&connections, opening, Instant::now());
        let Checkout::Reserved(reservation) = connections.checkout(true) else {
            return Err("fresh request reused raw opening".into());
        };
        timer.fire();
        assert_eq!(connections.family.family(), Some(AddressFamily::Ipv4));
        drop(reservation);
        timer.fire();
        assert_eq!(connections.family.family(), None);
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await?, 0);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn cancelling_a_claim_during_connect_or_origin_tls_never_returns_a_partial_tunnel()
-> TestResult {
    for tls_started in [false, true] {
        timeout(WAIT, async {
            let connections = super::connections(bound(2)?);
            let (opening, mut peer) = ready(&connections).await?;
            let address = peer.local_addr()?;
            put(&connections, opening, Instant::now());
            let Checkout::Proxy(claim) = connections.checkout(false) else { return Err("raw opening not claimed".into()); };
            let fields = [HttpConnectHeader::authority("Host")];
            let route = HttpConnectRoute { proxy: ProxyTransport::Tcp(NetEndpoint { host: "127.0.0.1", port: address.port() }), authority: "127.0.0.1:443", headers: &fields, credentials: None };
            let mut finish = Box::pin(claim.finish(route));
            tokio::select! {
                result = &mut finish => { drop(result); return Err("CONNECT completed without a response".into()); }
                head = peer::head(&mut peer) => assert_eq!(head?, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"),
            }
            if tls_started {
                use tokio::io::AsyncWriteExt;
                peer.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                let mut record = [0; 5];
                tokio::select! {
                    result = &mut finish => { drop(result); return Err("TLS completed without a server handshake".into()); }
                    read = peer.read_exact(&mut record) => { read?; assert_eq!(record[0], 22); }
                }
            }
            drop(finish);
            let mut remaining = Vec::new();
            peer.read_to_end(&mut remaining).await?;
            if !tls_started { assert!(remaining.is_empty()); }
            assert_eq!(connections.lock().leased, 0);
            assert!(connections.lock().spares.is_empty());
            assert_eq!(connections.open(), 0);
            Ok::<(), Box<dyn std::error::Error>>(())
        }).await??;
    }
    Ok(())
}

mod https;

mod https_forward;
