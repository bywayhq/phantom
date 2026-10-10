use std::{io, net::Ipv4Addr, sync::Arc, time::Duration};

use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};

use crate::support::tunnel_proxy::ConnectionPeer;

use super::{
    CountingProxy, H1_ALPN, Origin, ProxyCounts, TestIdentity, TestResult, accept_tls_stream,
    client_builder, proxy_route, read_head, send_one,
};

const DEADLINE: Duration = Duration::from_secs(5);
const CLOSE_WINDOW: Duration = Duration::from_secs(2);

async fn wait_references<T>(value: &Arc<T>, expected: usize) -> TestResult<()> {
    timeout(DEADLINE, async {
        while Arc::strong_count(value) != expected {
            tokio::task::yield_now().await;
        }
    })
    .await?;
    Ok(())
}

struct HeldTunnel {
    proxy: CountingProxy,
    client: Client,
    origin: ConnectionPeer<TestResult<()>>,
    closed: oneshot::Receiver<io::Result<usize>>,
}

async fn held_tunnel() -> TestResult<HeldTunnel> {
    let identity = TestIdentity::generate()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let acceptor = identity.acceptor(H1_ALPN)?;
    let proxy = CountingProxy::start(address).await?;
    let client = client_builder(&identity, false)
        .route(proxy_route(proxy.address, "alice", "secret")?)
        .build()?;
    let (ready, observed) = oneshot::channel();
    let (closure, closed) = oneshot::channel();
    let origin = ConnectionPeer::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut stream = accept_tls_stream(tcp, acceptor).await?;
        assert_eq!(
            read_head(&mut stream).await?,
            format!("GET /held HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()
        );
        // This control origin keeps one response connection open so the real
        // counting proxy's authenticated relay remains live at the drop point.
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await?;
        stream.flush().await?;
        ready
            .send(())
            .map_err(|_| "held origin readiness observer closed")?;

        let result = stream.read(&mut [0_u8; 1]).await;
        // The receiver may leave during finite backup cleanup.
        let _ = closure.send(result);
        Ok(())
    });

    let response = client
        .get(HttpProtocol::Http1, &format!("https://{address}/held"))?
        .send()
        .await?;
    assert_eq!(response.status(), 200);
    assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
    timeout(DEADLINE, observed).await??;
    assert_eq!(
        proxy.counts()?,
        ProxyCounts {
            connections: 2,
            challenges: 1,
            with_credentials: 1
        }
    );
    let heads = proxy.heads()?;
    assert_eq!(
        heads[0],
        format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\n\r\n").as_bytes()
    );
    assert_eq!(heads[1], format!("CONNECT {address} HTTP/1.1\r\nHost: {address}\r\nProxy-Authorization: Basic YWxpY2U6c2VjcmV0\r\n\r\n").as_bytes());

    Ok(HeldTunnel {
        proxy,
        client,
        origin,
        closed,
    })
}

#[tokio::test]
async fn dropping_the_counting_proxy_closes_its_authenticated_live_relay() -> TestResult<()> {
    let HeldTunnel {
        proxy,
        client,
        origin,
        closed,
    } = held_tunnel().await?;
    drop(proxy);
    let observed = timeout(CLOSE_WINDOW, closed).await;

    // Capture the drop observation while the client and runtime are still live.
    // Backup cancellation happens only after the result has been recorded.
    drop(client);
    origin.stop().await?;

    assert!(
        matches!(observed, Ok(Ok(Ok(0))))
            || matches!(observed, Ok(Ok(Err(ref error))) if crate::support::tls::is_peer_gone(error)),
        "dropping the counting proxy retained its authenticated relay: {observed:?}"
    );
    Ok(())
}

#[tokio::test]
async fn dropping_the_origin_closes_an_accepted_incomplete_tls_connection() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let origin = Origin::start(&identity).await?;
    let proxy = CountingProxy::start(origin.address).await?;
    let client = client_builder(&identity, false)
        .route(proxy_route(proxy.address, "alice", "secret")?)
        .build()?;
    send_one(&client, &format!("https://{}/ready", origin.address)).await?;
    assert_eq!(origin.heads()?.len(), 1);
    assert_eq!(
        proxy.counts()?,
        ProxyCounts {
            connections: 2,
            challenges: 1,
            with_credentials: 1
        }
    );
    wait_references(&origin.heads, 2).await?;

    let mut stalled = TcpStream::connect(origin.address).await?;
    stalled.write_all(&[0x16, 0x03, 0x03, 0, 2, 1]).await?;
    // The actual accept loop moves one extra observation Arc into its handler.
    // Wait until the first completed handler is gone and this child is accepted.
    wait_references(&origin.heads, 3).await?;
    drop(origin);
    let observed = timeout(CLOSE_WINDOW, stalled.read_u8()).await;

    drop(stalled);
    drop(client);
    proxy.finish().await?;

    assert!(
        matches!(observed, Ok(Err(ref error)) if crate::support::tls::is_peer_gone(error)),
        "dropping the origin retained its accepted TLS child: {observed:?}"
    );
    Ok(())
}

#[tokio::test]
async fn proxy_completion_retains_a_completed_truncated_connect_failure() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let origin = Origin::start(&identity).await?;
    let proxy = CountingProxy::start(origin.address).await?;
    let client = client_builder(&identity, false)
        .route(proxy_route(proxy.address, "alice", "secret")?)
        .build()?;
    send_one(&client, &format!("https://{}/ready", origin.address)).await?;
    wait_references(&proxy.heads, 2).await?;
    let mut malformed = TcpStream::connect(proxy.address).await?;
    malformed.write_all(b"CONNECT partial").await?;
    wait_references(&proxy.heads, 3).await?;
    malformed.shutdown().await?;
    wait_references(&proxy.heads, 2).await?;

    let completed = proxy.finish().await;
    drop(malformed);
    drop(client);
    origin.finish().await?;

    let error = completed
        .err()
        .ok_or("proxy supervisor discarded its completed truncated CONNECT error")?;
    let cause = error
        .downcast_ref::<io::Error>()
        .ok_or("proxy lost the original typed I/O cause")?;
    assert_eq!(cause.kind(), io::ErrorKind::UnexpectedEof);
    Ok(())
}

#[tokio::test]
async fn origin_completion_retains_a_completed_invalid_tls_failure() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let origin = Origin::start(&identity).await?;
    let proxy = CountingProxy::start(origin.address).await?;
    let client = client_builder(&identity, false)
        .route(proxy_route(proxy.address, "alice", "secret")?)
        .build()?;
    send_one(&client, &format!("https://{}/ready", origin.address)).await?;
    wait_references(&origin.heads, 2).await?;
    let mut malformed = TcpStream::connect(origin.address).await?;
    // A complete record header with a non-TLS content type is rejected by the
    // actual server handshake, rather than held as an incomplete future.
    malformed
        .write_all(b"GET /invalid HTTP/1.0\r\n\r\n")
        .await?;
    let mut alert = Vec::new();
    let close = timeout(DEADLINE, malformed.read_to_end(&mut alert)).await?;
    assert!(
        close.is_ok()
            || matches!(close, Err(ref error) if crate::support::tls::is_peer_gone(error))
    );
    wait_references(&origin.heads, 2).await?;

    let completed = origin.finish().await;
    drop(malformed);
    drop(client);
    proxy.finish().await?;

    let error = completed
        .err()
        .ok_or("origin supervisor discarded its completed TLS error")?;
    assert!(
        error.downcast_ref::<btls::ssl::Error>().is_some(),
        "origin lost its concrete TLS failure: {error}"
    );
    Ok(())
}

#[tokio::test]
async fn an_ordinary_authenticated_exchange_completes_with_literal_observations() -> TestResult<()>
{
    let identity = TestIdentity::generate()?;
    let origin = Origin::start(&identity).await?;
    let proxy = CountingProxy::start(origin.address).await?;
    let client = client_builder(&identity, false)
        .route(proxy_route(proxy.address, "alice", "secret")?)
        .build()?;
    send_one(&client, &format!("https://{}/ordinary", origin.address)).await?;
    assert_eq!(
        proxy.counts()?,
        ProxyCounts {
            connections: 2,
            challenges: 1,
            with_credentials: 1
        }
    );
    assert_eq!(
        origin.heads()?,
        [format!("GET /ordinary HTTP/1.1\r\nHost: {}\r\n\r\n", origin.address).into_bytes()]
    );
    proxy.finish().await?;
    origin.finish().await?;
    drop(client);
    Ok(())
}

#[tokio::test]
async fn a_caller_failure_keeps_the_completed_truncated_connect_failure() -> TestResult<()> {
    super::bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::start(&identity).await?;
        let proxy = CountingProxy::start(origin.address).await?;
        let client = client_builder(&identity, false)
            .route(proxy_route(proxy.address, "alice", "secret")?)
            .build()?;
        send_one(&client, &format!("https://{}/ready", origin.address)).await?;
        assert_eq!(
            proxy.counts()?,
            ProxyCounts {
                connections: 2,
                challenges: 1,
                with_credentials: 1,
            }
        );
        wait_references(&proxy.heads, 2).await?;

        let mut malformed = TcpStream::connect(proxy.address).await?;
        malformed.write_all(b"CONNECT partial").await?;
        wait_references(&proxy.heads, 3).await?;
        malformed.shutdown().await?;
        wait_references(&proxy.heads, 2).await?;

        // Inject the caller outcome only after the actual authenticated exchange
        // and completed malformed child, through the original fixture's finish path.
        let operation: TestResult<()> = Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "injected credential caller failure after an actual exchange",
        )
        .into());
        let result = super::finish_credential_fixture(operation, proxy, origin).await;
        drop(malformed);
        drop(client);

        let error = result
            .err()
            .ok_or("credential fixture lost both failures")?;
        let failures = error
            .downcast_ref::<crate::support::tunnel_proxy::connection_peer::FixtureFailures>()
            .ok_or("credential fixture discarded its completed child failure")?;
        let primary = failures
            .primary
            .downcast_ref::<io::Error>()
            .ok_or("credential caller lost its concrete I/O cause")?;
        let cleanup = failures
            .cleanup
            .downcast_ref::<io::Error>()
            .ok_or("credential peer lost its concrete I/O cause")?;
        assert_eq!(primary.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(cleanup.kind(), io::ErrorKind::UnexpectedEof);
        Ok(())
    })
    .await
}
