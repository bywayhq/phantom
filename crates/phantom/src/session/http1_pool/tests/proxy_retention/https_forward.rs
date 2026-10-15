//! Two actual proxy sockets; adoption precedes primary TLS, with no OS race claim.
use super::*;
use btls::ssl::Ssl;
use http::Method;
use phantom_net::{proxy::HttpsProxyConnector, request::AbsoluteForm};
use std::{
    future::{Future, poll_fn},
    pin::Pin,
    task::Poll,
};
use tokio::io::AsyncWriteExt;
use tokio_btls::SslStream;

fn transport<'a>(
    route: &'a Route,
    proxy: &'a HttpsProxyConnector,
) -> TestResult<ProxyTransport<'a>> {
    let route = route.as_http_proxy().ok_or("missing HTTPS proxy")?;
    Ok(ProxyTransport::Tls {
        endpoint: NetEndpoint {
            host: route.host(),
            port: route.port(),
        },
        server_name: route.host(),
        connector: proxy,
    })
}
async fn opening(
    connector: &Http1TlsConnector,
    proxy: &HttpsProxyConnector,
    route: &Route,
    family: &phantom_net::tcp::AddressFamilyMemory,
) -> TestResult<Http1ProxyOpening> {
    let (opening, slower) = connector
        .open_https_forward_retaining(transport(route, proxy)?, family)
        .await?;
    assert!(slower.is_none());
    Ok(opening)
}

#[tokio::test]
async fn forward_spare_is_adopted_before_primary_tls_and_early_claim_uses_current_request()
-> TestResult {
    timeout(WAIT, async {
        let (root, acceptor) = peer::identity()?;
        let connector = Http1TlsConnector::new_with_additional_roots(&firefox::v157_tcp_tls(), [&*root])?;
        let proxy = HttpsProxyConnector::new_with_additional_roots(&firefox::v157_tcp_tls(), [&*root])?.with_tcp_settings(&firefox::v157_tcp());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let route = Route::http_proxy(HttpProxy::new(&format!("https://{}", listener.local_addr()?))?.with_basic_auth("user", "secret")?);
        let endpoint = Endpoint::new("target.invalid:80".parse()?, 80)?;
        let pool = Http1Pool::new(bound(4)?, bound(6)?, bound(6)?);
        let entry = pool.entry(PoolKey::new(&endpoint, &route, Http1ConnectionMode::Forward)).await;
        entry.https_proxy.set(proxy.clone()).map_err(|_| "context already set")?;
        let permit = entry.admit().await?;
        let Checkout::Reserved(reservation) = entry.connections.checkout(false) else { return Err("primary not reserved".into()); };
        let primary = opening(&connector, &proxy, &route, &entry.connections.family).await?;
        let (mut primary_peer, _) = listener.accept().await?;
        let backup = opening(&connector, &proxy, &route, &entry.connections.family).await?;
        let (backup_peer, _) = listener.accept().await?;
        let progress = SlowerProgress::new();
        progress.mark_connected();
        let (release, released) = oneshot::channel();
        let slower = SlowerConnection::new(progress, async move { released.await.ok().map(|()| backup) });
        let mut primary = Box::pin(entry.finish_forward_opening(primary, Some(slower), transport(&route, &proxy)?));
        let mut record = [0; 5];
        tokio::select! {
            result = &mut primary => { drop(result); return Err("withheld TLS finished".into()); }
            result = primary_peer.read_exact(&mut record) => { result?; }
        }
        assert_eq!(record[0], 22);
        assert_eq!(entry.connections.lock().spares.len(), 1);
        assert_eq!(entry.connections.open(), 2);
        assert_eq!(entry.connections.family.family(), Some(AddressFamily::Ipv4));
        let mut acquire = Box::pin(entry.acquire(&connector, Some(&proxy), &endpoint, &route, Http1ConnectionMode::Forward, false));
        assert!(poll_fn(|cx| Poll::Ready(acquire.as_mut().poll(cx).is_pending())).await);
        assert!(poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_pending())).await, "pending claim caused third dial");
        let mut byte = [0];
        assert!(matches!(backup_peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        release.send(()).map_err(|()| "owner ended")?;
        let request = async {
            let lease = acquire.await?;
            let response = lease.connection.send_forward_request(Method::GET, AbsoluteForm::parse("http://target.invalid/current")?, vec![
                RequestHeader::new("Host", "target.invalid"), RequestHeader::new("X-Claim", "current"), RequestHeader::new("Cookie", "claim=current"), RequestHeader::new("Proxy-Authorization", "Basic dXNlcjpzZWNyZXQ="),
            ], None).await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            drop(lease);
            TestResult::Ok(())
        };
        let server = async {
            let mut tls = SslStream::new(Ssl::new(acceptor.context())?, backup_peer)?;
            Pin::new(&mut tls).accept().await?;
            assert_eq!(peer::head(&mut tls).await?, b"GET http://target.invalid/current HTTP/1.1\r\nHost: target.invalid\r\nX-Claim: current\r\nCookie: claim=current\r\nProxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n");
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await?;
            TestResult::Ok(())
        };
        tokio::try_join!(request, server)?;
        assert!(poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_pending())).await);
        drop(primary);
        drop(reservation);
        drop(permit);
        let mut rest = Vec::new();
        primary_peer.read_to_end(&mut rest).await?;
        assert_eq!(entry.connections.lock().leased, 0);
        assert!(entry.connections.lock().spares.is_empty());
        assert_eq!(entry.admission.available_active(), 6);
        Ok(())
    }).await?
}

async fn pending(
    connections: &Arc<EntryConnections>,
) -> TestResult<(Http1ProxyOpening, TcpStream, HttpsProxyConnector, Route)> {
    let (root, _) = peer::identity()?;
    let connector =
        Http1TlsConnector::new_with_additional_roots(&firefox::v157_tcp_tls(), [&*root])?;
    let proxy = HttpsProxyConnector::new_with_additional_roots(&firefox::v157_tcp_tls(), [&*root])?
        .with_tcp_settings(&firefox::v157_tcp());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let route = Route::http_proxy(HttpProxy::new(&format!(
        "https://{}",
        listener.local_addr()?
    ))?);
    let opening = opening(&connector, &proxy, &route, &connections.family).await?;
    let (peer, _) = listener.accept().await?;
    Ok((opening, peer, proxy, route))
}

#[tokio::test]
async fn unpolled_forward_claim_preserves_idle_age_and_pruning_closes_without_request() -> TestResult
{
    timeout(WAIT, async {
        let limit = Duration::from_secs(30);
        let connections = super::super::timed_connections(NonZeroUsize::MIN, Some(limit));
        let (opening, mut peer, _proxy, _route) = pending(&connections).await?;
        let since = Instant::now() - Duration::from_secs(10);
        put(&connections, opening, since);
        let Checkout::Proxy(claim) = connections.checkout(false) else {
            return Err("not claimed".into());
        };
        drop(claim);
        assert_eq!(connections.lock().spares[0].idle_since, Some(since));
        assert_eq!(connections.lock().leased, 0);
        connections.prune(since + limit, Some(limit));
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await?;
        assert!(bytes.is_empty());
        assert_eq!(connections.open(), 0);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn cancelling_forward_claim_during_outer_tls_releases_socket_and_reservation() -> TestResult {
    timeout(WAIT, async {
        let connections = super::super::connections(bound(2)?);
        let (opening, mut peer, proxy, route) = pending(&connections).await?;
        put(&connections, opening, Instant::now());
        let Checkout::Proxy(claim) = connections.checkout(false) else {
            return Err("not claimed".into());
        };
        let mut finish = Box::pin(claim.finish_forward(transport(&route, &proxy)?));
        let mut record = [0; 5];
        tokio::select! {
            result = &mut finish => { drop(result); return Err("withheld TLS finished".into()); }
            result = peer.read_exact(&mut record) => { result?; }
        }
        assert_eq!(record[0], 22);
        drop(finish);
        let mut rest = Vec::new();
        peer.read_to_end(&mut rest).await?;
        assert_eq!(connections.lock().leased, 0);
        assert!(connections.lock().spares.is_empty());
        assert_eq!(connections.open(), 0);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn failed_pending_forward_owner_returns_admission_and_closes_unclaimed_socket() -> TestResult
{
    timeout(WAIT, async {
        let connections = super::super::connections(bound(2)?);
        let (opening, mut peer, _proxy, _route) = pending(&connections).await?;
        let progress = SlowerProgress::new();
        progress.mark_connected();
        let (release, released) = oneshot::channel();
        connections.adopt_proxy(SlowerConnection::new(progress, async move {
            let _ = released.await;
            drop(opening);
            None
        }));
        let Checkout::Spare(claim) = connections.checkout(false) else {
            return Err("pending owner not claimed".into());
        };
        drop(claim);
        release.send(()).map_err(|()| "owner ended")?;
        while !connections.lock().spares.is_empty() {
            tokio::task::yield_now().await;
        }
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await?;
        assert!(bytes.is_empty());
        assert_eq!(connections.lock().leased, 0);
        assert_eq!(connections.open(), 0);
        Ok(())
    })
    .await?
}

#[test]
fn https_forward_owner_keeps_origin_route_mode_credential_and_runtime_partitions() -> TestResult {
    let pool = Http1Pool::new(bound(8)?, bound(2)?, bound(2)?);
    let endpoint = Endpoint::new("first.invalid:80".parse()?, 80)?;
    let other = Endpoint::new("second.invalid:80".parse()?, 80)?;
    let route = Route::http_proxy(
        HttpProxy::new("https://proxy.invalid:443")?.with_basic_auth("one", "secret")?,
    );
    let changed = Route::http_proxy(
        HttpProxy::new("https://proxy.invalid:443")?.with_basic_auth("two", "secret")?,
    );
    let other_proxy = Route::http_proxy(
        HttpProxy::new("https://other.invalid:443")?.with_basic_auth("one", "secret")?,
    );
    let plaintext_proxy = Route::http_proxy(
        HttpProxy::new("http://proxy.invalid:443")?.with_basic_auth("one", "secret")?,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let entry = runtime.block_on(async {
        let entry = pool
            .entry(PoolKey::new(
                &endpoint,
                &route,
                Http1ConnectionMode::Forward,
            ))
            .await;
        for key in [
            PoolKey::new(&other, &route, Http1ConnectionMode::Forward),
            PoolKey::new(&endpoint, &changed, Http1ConnectionMode::Forward),
            PoolKey::new(&endpoint, &other_proxy, Http1ConnectionMode::Forward),
            PoolKey::new(&endpoint, &plaintext_proxy, Http1ConnectionMode::Forward),
            PoolKey::new(&endpoint, &route, Http1ConnectionMode::TlsOrigin),
        ] {
            let different = pool.entry(key).await;
            assert!(!Arc::ptr_eq(&entry, &different));
            assert!(!Arc::ptr_eq(
                &entry.connections.family,
                &different.connections.family
            ));
        }
        entry
    });
    drop(runtime);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let other_runtime = runtime.block_on(async {
        pool.entry(PoolKey::new(
            &endpoint,
            &route,
            Http1ConnectionMode::Forward,
        ))
        .await
    });
    assert!(!Arc::ptr_eq(&entry, &other_runtime));
    assert!(Arc::ptr_eq(
        &entry.connections.family,
        &other_runtime.connections.family
    ));
    assert!(Arc::ptr_eq(&entry.admission, &other_runtime.admission));
    drop(runtime);
    Ok(())
}
