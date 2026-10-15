//! Actual sockets isolate spare ownership from operating-system race timing.
use super::{
    Checkout, EntryConnections, Http1ConnectionMode, Http1Pool, PoolKey, TestResult, bound,
};
use crate::{HttpProxy, Route, authority::Endpoint, session::prune_timer::PruneTimer};
use http::Method;
use http_body_util::BodyExt;
use phantom_net::{
    http1::{Http1Connection, Http1TlsConnector},
    proxy::HttpProxyCredentials,
    request::{AbsoluteForm, RequestHeader},
    route::Endpoint as NetEndpoint,
    tcp::{AddressFamily, SlowerConnection, SlowerProgress},
};
use phantom_profile::browser::firefox;
use std::{future::Future, io, net::Ipv4Addr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

const WAIT: Duration = Duration::from_secs(5);

async fn head(peer: &mut TcpStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut result = Vec::new();
    while !result.ends_with(b"\r\n\r\n") {
        if result.len() >= 4096 {
            return Err("forward request head exceeded fixture bound".into());
        }
        let mut byte = [0];
        peer.read_exact(&mut byte).await?;
        result.push(byte[0]);
    }
    Ok(result)
}

async fn quiet(
    connections: &EntryConnections,
) -> Result<(Http1Connection, TcpStream), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let connector =
        Http1TlsConnector::new(&firefox::v157_tcp_tls())?.with_tcp_settings(&firefox::v157_tcp());
    let (connection, slower) = connector
        .connect_forward_retaining(
            NetEndpoint {
                host: "127.0.0.1",
                port: address.port(),
            },
            &connections.family,
        )
        .await?;
    assert!(slower.is_none());
    let (peer, _) = listener.accept().await?;
    Ok((connection, peer))
}

#[tokio::test]
async fn a_forward_spare_is_quiet_until_claimed_with_current_headers_and_credentials() -> TestResult
{
    timeout(WAIT, async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?.with_basic_auth("user", "secret")?);
        let endpoint = Endpoint::new("target.invalid:80".parse()?, 80)?;
        let connector = Http1TlsConnector::new(&firefox::v157_tcp_tls())?.with_tcp_settings(&firefox::v157_tcp());
        let pool = Http1Pool::new(bound(4)?, bound(2)?, bound(2)?);
        let entry = pool.entry(PoolKey::new(&endpoint, &route, Http1ConnectionMode::Forward)).await;
        let Checkout::Reserved(reservation) = entry.connections.checkout(false) else { return Err("primary did not reserve setup".into()); };
        let (primary, slower) = entry.open(&connector, None, &endpoint, &route, Http1ConnectionMode::Forward).await?;
        assert!(slower.is_none());
        let (mut first_peer, _) = listener.accept().await?;
        let (backup, slower) = connector.connect_forward_retaining(NetEndpoint { host: "127.0.0.1", port: address.port() }, &entry.connections.family).await?;
        assert!(slower.is_none());
        let (mut backup_peer, _) = listener.accept().await?;
        let progress = SlowerProgress::new();
        progress.mark_connected(); // The preceding real backup socket completed.
        let (release, released) = oneshot::channel();
        entry.connections.adopt(SlowerConnection::new(progress, async move { released.await.ok().map(|()| backup) }));
        let primary = reservation.into_lease(primary);
        assert_eq!(entry.connections.open(), 2);
        assert_eq!(entry.connections.family.family(), Some(AddressFamily::Ipv4));
        let mut byte = [0];
        assert!(matches!(first_peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        assert!(matches!(backup_peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        release.send(()).map_err(|()| "backup owner ended")?;
        let request = async {
            let lease = entry.acquire(&connector, None, &endpoint, &route, Http1ConnectionMode::Forward, false).await?;
            let Some(HttpProxyCredentials::Basic(credentials)) = route.as_http_proxy().and_then(HttpProxy::credentials) else { return Err("fixture credentials disappeared".into()); };
            let response = lease.connection.send_forward_request(Method::GET, AbsoluteForm::parse("http://target.invalid/current")?, vec![
                RequestHeader::new("Host", "target.invalid"),
                RequestHeader::new("X-Claim", "current"),
                credentials.proxy_authorization_header(),
            ], None).await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            drop(lease);
            TestResult::Ok(())
        };
        let proxy = async {
            assert_eq!(head(&mut backup_peer).await?, b"GET http://target.invalid/current HTTP/1.1\r\nHost: target.invalid\r\nX-Claim: current\r\nProxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n");
            backup_peer.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await?;
            TestResult::Ok(())
        };
        tokio::try_join!(request, proxy)?;
        assert!(std::future::poll_fn(|cx| std::task::Poll::Ready(listener.poll_accept(cx).is_pending())).await, "claim redialled instead of using the backup");
        assert!(matches!(first_peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        drop(primary);
        assert_eq!(entry.connections.lock().leased, 0);
        assert!(entry.connections.lock().spares.is_empty());
        drop(entry);
        drop(pool);
        assert_eq!(first_peer.read(&mut byte).await?, 0);
        assert_eq!(backup_peer.read(&mut byte).await?, 0);
        Ok(())
    }).await?
}

#[tokio::test]
async fn a_cancelled_forward_claim_keeps_the_later_quiet_spare_and_prunes_its_family() -> TestResult
{
    timeout(WAIT, async {
        let timer = PruneTimer::unscheduled(Duration::ZERO);
        let connections = EntryConnections::new(bound(2)?, Some(Duration::ZERO), Some(Arc::clone(&timer)), Arc::default());
        let (connection, mut peer) = quiet(&connections).await?;
        let progress = SlowerProgress::new(); progress.mark_connected();
        let (release, released) = oneshot::channel();
        connections.adopt(SlowerConnection::new(progress, async move { released.await.ok().map(|()| connection) }));
        let Checkout::Spare(claim) = connections.checkout(false) else { return Err("pending forward spare not claimed".into()); };
        drop(claim);
        release.send(()).map_err(|()| "backup owner ended")?;
        while connections.lock().idle.is_empty() { tokio::task::yield_now().await; }
        assert_eq!(connections.lock().leased, 0);
        assert!(connections.lock().spares.is_empty());
        let mut byte = [0];
        assert!(matches!(peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        // A primary reservation keeps the learned family alive after idle prune.
        let Checkout::Reserved(reservation) = connections.checkout(true) else { return Err("fresh opening reused the spare".into()); };
        timer.fire();
        assert_eq!(connections.family.family(), Some(AddressFamily::Ipv4));
        drop(reservation);
        timer.fire();
        assert_eq!(connections.family.family(), None);
        assert_eq!(connections.open(), 0);
        assert_eq!(peer.read(&mut byte).await?, 0);
        Ok(())
    }).await?
}

#[tokio::test]
async fn a_forward_backup_does_not_create_an_additional_admission_slot() -> TestResult {
    timeout(WAIT, async {
        let pool = Http1Pool::new(bound(2)?, bound(1)?, bound(1)?);
        let endpoint = Endpoint::new("target.invalid:80".parse()?, 80)?;
        let route = Route::http_proxy(HttpProxy::new("http://proxy.invalid:8080")?);
        let entry = pool
            .entry(PoolKey::new(
                &endpoint,
                &route,
                Http1ConnectionMode::Forward,
            ))
            .await;
        let (connection, mut peer) = quiet(&entry.connections).await?;
        let progress = SlowerProgress::new();
        progress.mark_connected();
        let (release, released) = oneshot::channel::<()>();
        entry
            .connections
            .adopt(SlowerConnection::new(progress, async move {
                released.await.ok().map(|()| connection)
            }));
        let permit = entry.admit().await?;
        assert_eq!(entry.admission.available_active(), 0);
        let mut waiting = Box::pin(entry.admit());
        assert!(
            std::future::poll_fn(|cx| std::task::Poll::Ready(
                waiting.as_mut().poll(cx).is_pending()
            ))
            .await
        );
        drop(waiting);
        drop(permit);
        let _permit = entry.admit().await?;
        drop(release);
        drop(entry);
        drop(pool);
        let mut bytes = Vec::new();
        peer.read_to_end(&mut bytes).await?;
        assert!(bytes.is_empty());
        Ok(())
    })
    .await?
}

#[test]
fn forward_connections_keep_origin_route_credentials_mode_and_runtime_partitions() -> TestResult {
    let pool = Http1Pool::new(bound(8)?, bound(2)?, bound(2)?);
    let endpoint = Endpoint::new("first.invalid:80".parse()?, 80)?;
    let other = Endpoint::new("second.invalid:80".parse()?, 80)?;
    let other_port = Endpoint::new("first.invalid:8080".parse()?, 80)?;
    let route = Route::http_proxy(
        HttpProxy::new("http://proxy.invalid:8080")?.with_basic_auth("one", "secret")?,
    );
    let changed = Route::http_proxy(
        HttpProxy::new("http://proxy.invalid:8080")?.with_basic_auth("two", "secret")?,
    );
    let other_proxy = Route::http_proxy(
        HttpProxy::new("http://other-proxy.invalid:8080")?.with_basic_auth("one", "secret")?,
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
            PoolKey::new(&other_port, &route, Http1ConnectionMode::Forward),
            PoolKey::new(&endpoint, &changed, Http1ConnectionMode::Forward),
            PoolKey::new(&endpoint, &other_proxy, Http1ConnectionMode::Forward),
            PoolKey::new(
                &endpoint,
                &Route::Direct,
                Http1ConnectionMode::PlaintextOrigin,
            ),
            PoolKey::new(&endpoint, &route, Http1ConnectionMode::TlsOrigin),
        ] {
            let distinct = pool.entry(key).await;
            assert!(!Arc::ptr_eq(&entry, &distinct));
            assert!(!Arc::ptr_eq(
                &entry.connections.family,
                &distinct.connections.family
            ));
        }
        entry
    });
    drop(runtime);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    // Constructing the key must happen while entered, as actual requests do.
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
