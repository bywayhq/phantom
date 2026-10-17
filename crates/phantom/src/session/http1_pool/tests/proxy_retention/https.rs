//! Two actual TCP sockets with a gated owner; race timing is not simulated.
use super::*;
use phantom_net::proxy::HttpsProxyConnector;
use std::{future::Future, task::Poll};

mod peer;

fn borrowed<'a>(
    route: &'a Route,
    connector: &'a HttpsProxyConnector,
) -> TestResult<HttpConnectRoute<'a>> {
    let proxy = route.as_http_proxy().ok_or("missing HTTPS proxy")?;
    Ok(HttpConnectRoute {
        speculative_tls: false,
        proxy: ProxyTransport::Tls {
            endpoint: NetEndpoint {
                host: proxy.host(),
                port: proxy.port(),
            },
            server_name: proxy.host(),
            connector,
        },
        authority: "127.0.0.1:443",
        headers: proxy.ordered_connect_headers(),
        credentials: proxy.authentication(),
    })
}

async fn opening(
    connector: &Http1TlsConnector,
    proxy: &HttpsProxyConnector,
    route: &Route,
    family: &phantom_net::tcp::AddressFamilyMemory,
) -> TestResult<Http1ProxyOpening> {
    let (opening, slower) = connector
        .open_http_connect_retaining(borrowed(route, proxy)?, "127.0.0.1", family)
        .await?;
    assert!(slower.is_none());
    Ok(opening)
}

#[tokio::test]
async fn https_spare_is_adopted_before_primary_tls_and_pending_claim_does_not_redial() -> TestResult
{
    claim(Auth::None).await
}
#[tokio::test]
async fn https_claim_uses_current_basic_fields_on_existing_physical_owner() -> TestResult {
    claim(Auth::Basic).await
}
#[tokio::test]
async fn https_claim_uses_current_digest_fields_and_nonce_on_existing_owner() -> TestResult {
    claim(Auth::Digest).await
}

async fn claim(auth: Auth) -> TestResult {
    timeout(WAIT, async {
        let (root, acceptor) = super::peer::identity()?;
        let connector = Http1TlsConnector::new_with_additional_roots(&firefox::v157_tcp_tls(), [&*root])?;
        let proxy_connector = HttpsProxyConnector::new_with_additional_roots(&firefox::v157_tcp_tls(), [&*root])?
            .with_tcp_settings(&firefox::v157_tcp());
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let proxy = HttpProxy::new(&format!("https://{address}"))?;
        let proxy = match auth { Auth::None => proxy, Auth::Basic => proxy.with_basic_auth("user", "secret")?,
            Auth::Digest => proxy.with_digest_auth("user", "secret")? };
        let base = Route::http_proxy(proxy);
        let first = routed(&base, "first")?;
        let second = routed(&base, "second")?;
        assert_eq!(first, second);
        let endpoint = Endpoint::new("127.0.0.1:443".parse()?, 443)?;
        let pool = Http1Pool::new(bound(4)?, bound(6)?, bound(6)?);
        let entry = pool.entry(PoolKey::new(&endpoint, &first, Http1ConnectionMode::TlsOrigin)).await;
        entry.https_proxy.set(proxy_connector.clone()).map_err(|_| "proxy context already set")?;
        let permit = entry.admit().await?;
        let Checkout::Reserved(reservation) = entry.connections.checkout(false) else {
            return Err("primary did not reserve".into());
        };
        let primary = opening(&connector, &proxy_connector, &first, &entry.connections.family).await?;
        let (mut primary_peer, _) = listener.accept().await?;
        let backup = opening(&connector, &proxy_connector, &first, &entry.connections.family).await?;
        let (backup_peer, _) = listener.accept().await?;
        let progress = SlowerProgress::new();
        progress.mark_connected();
        let (release, released) = oneshot::channel();
        let slower = SlowerConnection::new(progress, async move { released.await.ok().map(|()| backup) });
        let mut primary = Box::pin(entry.finish_proxy_opening(primary, Some(slower), borrowed(&first, &proxy_connector)?));
        let mut record = [0; 5];
        tokio::select! {
            result = &mut primary => { drop(result); return Err("withheld primary TLS finished".into()); }
            result = primary_peer.read_exact(&mut record) => { result?; }
        }
        assert_eq!(record[0], 22);
        assert_eq!(entry.connections.lock().spares.len(), 1);
        assert_eq!(entry.connections.open(), 2);
        assert_eq!(entry.connections.family.family(), Some(AddressFamily::Ipv4));
        let mut acquire = Box::pin(entry.acquire(&connector, Some(&proxy_connector), &endpoint,
            &second, Http1ConnectionMode::TlsOrigin, false));
        assert!(std::future::poll_fn(|cx| Poll::Ready(acquire.as_mut().poll(cx).is_pending())).await);
        assert!(std::future::poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_pending())).await,
            "pending owner forced a third dial");
        let mut byte = [0];
        assert!(matches!(backup_peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        release.send(()).map_err(|()| "backup owner ended")?;
        let request = async {
            let lease = acquire.await?;
            let response = lease.connection.send_get(OriginForm::parse("/claimed")?,
                vec![RequestHeader::new("Host", "127.0.0.1")]).await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            drop(lease);
            TestResult::Ok(())
        };
        tokio::try_join!(request, peer::serve(backup_peer, acceptor, auth))?;
        assert!(std::future::poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_pending())).await);
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
    let (root, _) = super::peer::identity()?;
    let connector =
        Http1TlsConnector::new_with_additional_roots(&firefox::v157_tcp_tls(), [&*root])?;
    let proxy = HttpsProxyConnector::new_with_additional_roots(&firefox::v157_tcp_tls(), [&*root])?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let route = Route::http_proxy(HttpProxy::new(&format!(
        "https://{}",
        listener.local_addr()?
    ))?);
    let route = routed(&route, "unused")?;
    let opening = opening(&connector, &proxy, &route, &connections.family).await?;
    let (peer, _) = listener.accept().await?;
    Ok((opening, peer, proxy, route))
}

#[tokio::test]
async fn unpolled_https_claim_returns_original_idle_age_and_prunes_owned_socket() -> TestResult {
    timeout(WAIT, async {
        let limit = Duration::from_secs(30);
        let connections = super::super::timed_connections(NonZeroUsize::MIN, Some(limit));
        let (opening, mut peer, _proxy, _route) = pending(&connections).await?;
        let since = Instant::now() - Duration::from_secs(10);
        put(&connections, opening, since);
        let Checkout::Proxy(claim) = connections.checkout(false) else {
            return Err("opening not claimed".into());
        };
        drop(claim);
        assert_eq!(connections.lock().spares[0].idle_since, Some(since));
        assert_eq!(connections.lock().leased, 0);
        connections.prune(since + limit, Some(limit));
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await?, 0);
        assert_eq!(connections.open(), 0);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn cancelling_https_claim_in_outer_tls_releases_owner_without_returning_partial_state()
-> TestResult {
    timeout(WAIT, async {
        let connections = super::super::connections(bound(2)?);
        let (opening, mut peer, proxy, route) = pending(&connections).await?;
        put(&connections, opening, Instant::now());
        let Checkout::Proxy(claim) = connections.checkout(false) else {
            return Err("opening not claimed".into());
        };
        let mut finish = Box::pin(claim.finish(borrowed(&route, &proxy)?));
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
async fn cancelled_https_waiter_and_failed_outer_owner_leave_no_admission_or_socket() -> TestResult
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
        release.send(()).map_err(|()| "owner already ended")?;
        while !connections.lock().spares.is_empty() {
            tokio::task::yield_now().await;
        }
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await?, 0);
        assert_eq!(connections.lock().leased, 0);
        assert_eq!(connections.open(), 0);
        Ok(())
    })
    .await?
}
