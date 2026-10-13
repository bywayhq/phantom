use std::{
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    time::timeout,
};

use crate::support::tunnel_proxy::ConnectionPeer;

use super::{
    Challenge, CountingProxy, Origin, ProxyCounts, TestIdentity, TestResult, client_builder,
    proxy_route, read_head, send_one, serve_connect,
};

const DEADLINE: Duration = Duration::from_secs(5);
const ANONYMOUS: &[u8] = b"CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n";
const CHALLENGE: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
    Proxy-Authenticate: Basic realm=\"counting\"\r\nContent-Length: 0\r\n\r\n";

fn poison(heads: &Arc<Mutex<Vec<Vec<u8>>>>) {
    let heads = Arc::clone(heads);
    let joined = std::thread::spawn(move || {
        let _guard = heads
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        panic!("intentional credential observation lock poisoning");
    })
    .join();
    assert!(joined.is_err());
}

#[tokio::test]
async fn poisoned_counts_report_failure_after_a_real_authenticated_exchange() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let origin = Origin::start(&identity).await?;
    let proxy = CountingProxy::start(origin.address).await?;
    let client = client_builder(&identity, false)
        .route(proxy_route(proxy.address, "alice", "secret")?)
        .build()?;
    send_one(&client, &format!("https://{}/observed", origin.address)).await?;
    assert_eq!(
        proxy.counts()?,
        ProxyCounts {
            connections: 2,
            challenges: 1,
            with_credentials: 1
        }
    );

    poison(&proxy.heads);
    let observed = proxy.counts();
    proxy.finish().await?;
    origin.finish().await?;
    drop(client);

    let error = observed
        .err()
        .ok_or("poisoned counts became a successful empty record")?;
    assert!(error.to_string().contains("poison"));
    Ok(())
}

async fn proxy_writer(
    poisoned: bool,
) -> TestResult<(std::io::Result<Vec<u8>>, std::io::Result<()>, usize)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let heads = Arc::new(Mutex::new(Vec::new()));
    let observed = Arc::clone(&heads);
    let peer = ConnectionPeer::spawn(async move {
        let (stream, _) = listener.accept().await?;
        // Both requests take the real keep-alive challenge path; neither opens an origin.
        serve_connect(stream, address, Challenge::KeepAlive, heads).await
    });
    let mut client = TcpStream::connect(address).await?;
    client.write_all(ANONYMOUS).await?;
    assert_eq!(timeout(DEADLINE, read_head(&mut client)).await??, CHALLENGE);
    assert_eq!(
        observed
            .lock()
            .map_err(|_| "healthy proxy observer was poisoned")?
            .len(),
        1
    );

    if poisoned {
        poison(&observed);
    }
    client.write_all(ANONYMOUS).await?;
    let response = timeout(DEADLINE, read_head(&mut client)).await?;
    client.shutdown().await?;
    drop(client);
    let completed = timeout(DEADLINE, peer).await??;
    let count = observed
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .len();
    Ok((response, completed, count))
}

#[tokio::test]
async fn a_poisoned_proxy_writer_fails_before_an_unrecorded_challenge() -> TestResult<()> {
    let (response, completed, count) = proxy_writer(true).await?;
    assert_eq!(count, 1);
    assert!(
        response.is_err(),
        "proxy sent an unrecorded challenge: {response:?}"
    );
    let error = completed
        .err()
        .ok_or("poisoned proxy writer completed successfully")?;
    assert!(error.to_string().contains("poison"));
    Ok(())
}

#[tokio::test]
async fn a_healthy_proxy_writer_records_both_literal_challenges() -> TestResult<()> {
    let (response, completed, count) = proxy_writer(false).await?;
    assert_eq!(response?, CHALLENGE);
    assert_eq!(count, 2);
    assert!(
        matches!(completed, Err(ref error) if error.kind() == std::io::ErrorKind::UnexpectedEof)
    );
    Ok(())
}

#[tokio::test]
async fn a_poisoned_origin_writer_refuses_its_next_authenticated_request() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let origin = Origin::start(&identity).await?;
    let proxy = CountingProxy::start(origin.address).await?;
    let client = client_builder(&identity, false)
        .route(proxy_route(proxy.address, "alice", "secret")?)
        .build()?;
    let url = format!("https://{}/observed", origin.address);
    send_one(&client, &url).await?;
    assert_eq!(origin.heads()?.len(), 1);

    poison(&origin.heads);
    let result = send_one(&client, &url).await;
    let completion = origin.finish().await;
    proxy.finish().await?;
    drop(client);

    assert!(
        result.is_err(),
        "origin answered a request its observer could not record"
    );
    let error = completion
        .err()
        .ok_or("origin supervisor discarded its observer failure")?;
    assert!(error.to_string().contains("poison"));
    Ok(())
}
