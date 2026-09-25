use std::net::SocketAddr;

use tokio::{io::AsyncWriteExt, net::TcpListener, task::JoinHandle};

use super::{TestResult, read_head};
use crate::proxy::{
    HttpBasicCredentials, HttpConnectError, HttpConnectHeader, MAX_PROXY_CREDENTIAL_ENTRIES,
    ProxyCredentialCache, ProxyScheme, http_connect_tunnel_with_basic_auth,
};

// The challenge closes its connection, so every request of the scripted proxy
// arrives on a connection of its own.
const CHALLENGE: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
    Proxy-Authenticate: Basic realm=\"cache\"\r\n\
    Connection: close\r\n\
    Content-Length: 0\r\n\r\n";
const MALFORMED_CHALLENGE: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\n\
    Proxy-Authenticate: Basic realm=\"unterminated\r\n\
    Content-Length: 0\r\n\r\n";
const ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
const AUTHORIZATION: &[u8] = b"Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n";

fn credentials() -> TestResult<HttpBasicCredentials> {
    Ok(HttpBasicCredentials::new("user", "secret")?)
}

fn connect_headers() -> [HttpConnectHeader; 2] {
    [
        HttpConnectHeader::authority("Host"),
        HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
    ]
}

/// A proxy that answers each accepted connection's CONNECT with the next
/// scripted response and returns every request head, one per connection.
async fn scripted_proxy(
    responses: Vec<&'static [u8]>,
) -> TestResult<(SocketAddr, JoinHandle<std::io::Result<Vec<Vec<u8>>>>)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        let mut heads = Vec::new();
        let mut open = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().await?;
            heads.push(read_head(&mut stream).await?);
            stream.write_all(response).await?;
            stream.flush().await?;
            // Keep each connection open, so a retry that reached this proxy
            // again had to open a new connection.
            open.push(stream);
        }
        Ok(heads)
    });
    Ok((address, task))
}

async fn tunnel(
    cache: &ProxyCredentialCache,
    address: SocketAddr,
    credentials: &HttpBasicCredentials,
) -> Result<(), HttpConnectError> {
    http_connect_tunnel_with_basic_auth(
        crate::direct::Dialer::default(),
        Some(cache),
        "127.0.0.1",
        address.port(),
        "origin.example:443",
        &connect_headers(),
        credentials,
    )
    .await
    .map(drop)
}

fn carries_credentials(head: &[u8]) -> bool {
    head.windows(AUTHORIZATION.len())
        .any(|window| window == AUTHORIZATION)
}

#[tokio::test]
async fn accepted_credentials_are_sent_on_every_later_first_connect() -> TestResult {
    let (address, proxy) =
        scripted_proxy(vec![CHALLENGE, ESTABLISHED, ESTABLISHED, ESTABLISHED]).await?;
    let cache = ProxyCredentialCache::new();
    let credentials = credentials()?;

    for _ in 0..3 {
        tunnel(&cache, address, &credentials).await?;
    }

    let heads = proxy.await??;
    let sent: Vec<bool> = heads.iter().map(|head| carries_credentials(head)).collect();
    // One challenge, one retry, then two tunnels with no challenge: four
    // proxy connections instead of six.
    assert_eq!(sent, [false, true, true, true]);
    assert_eq!(
        heads[1],
        b"CONNECT origin.example:443 HTTP/1.1\r\n\
          Host: origin.example:443\r\n\
          Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n"
    );
    assert_eq!(heads[2], heads[1]);
    assert!(cache.contains(ProxyScheme::Http, "127.0.0.1", address.port(), &credentials));
    Ok(())
}

#[tokio::test]
async fn a_challenge_to_remembered_credentials_forgets_them_and_retries_once() -> TestResult {
    let (address, proxy) = scripted_proxy(vec![CHALLENGE, ESTABLISHED]).await?;
    let cache = ProxyCredentialCache::new();
    let credentials = credentials()?;
    cache.insert(ProxyScheme::Http, "127.0.0.1", address.port(), &credentials);

    tunnel(&cache, address, &credentials).await?;

    let heads = proxy.await??;
    let sent: Vec<bool> = heads.iter().map(|head| carries_credentials(head)).collect();
    assert_eq!(sent, [true, true]);
    // The retry succeeded, so the pair is remembered again.
    assert!(cache.contains(ProxyScheme::Http, "127.0.0.1", address.port(), &credentials));
    Ok(())
}

#[tokio::test]
async fn a_second_challenge_fails_and_leaves_nothing_remembered() -> TestResult {
    let (address, proxy) = scripted_proxy(vec![CHALLENGE, CHALLENGE]).await?;
    let cache = ProxyCredentialCache::new();
    let credentials = credentials()?;
    cache.insert(ProxyScheme::Http, "127.0.0.1", address.port(), &credentials);

    let error = tunnel(&cache, address, &credentials)
        .await
        .err()
        .ok_or("a second challenge was accepted")?;

    assert!(matches!(error, HttpConnectError::AuthenticationRejected));
    assert_eq!(proxy.await??.len(), 2);
    assert!(cache.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_rejected_first_retry_is_not_remembered() -> TestResult {
    let (address, proxy) = scripted_proxy(vec![CHALLENGE, CHALLENGE]).await?;
    let cache = ProxyCredentialCache::new();

    let error = tunnel(&cache, address, &credentials()?)
        .await
        .err()
        .ok_or("a second challenge was accepted")?;

    assert!(matches!(error, HttpConnectError::AuthenticationRejected));
    let heads = proxy.await??;
    assert!(!carries_credentials(&heads[0]));
    assert!(cache.is_empty());
    Ok(())
}

#[tokio::test]
async fn an_unusable_challenge_to_remembered_credentials_forgets_them() -> TestResult {
    let (address, proxy) = scripted_proxy(vec![MALFORMED_CHALLENGE]).await?;
    let cache = ProxyCredentialCache::new();
    let credentials = credentials()?;
    cache.insert(ProxyScheme::Http, "127.0.0.1", address.port(), &credentials);

    let error = tunnel(&cache, address, &credentials)
        .await
        .err()
        .ok_or("a malformed challenge was accepted")?;

    assert!(matches!(
        error,
        HttpConnectError::MalformedAuthenticationChallenge
    ));
    assert_eq!(proxy.await??.len(), 1);
    assert!(cache.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_proxy_that_never_challenges_is_not_remembered() -> TestResult {
    let (address, proxy) = scripted_proxy(vec![ESTABLISHED, ESTABLISHED]).await?;
    let cache = ProxyCredentialCache::new();
    let credentials = credentials()?;

    tunnel(&cache, address, &credentials).await?;
    tunnel(&cache, address, &credentials).await?;

    let heads = proxy.await??;
    assert!(heads.iter().all(|head| !carries_credentials(head)));
    assert!(cache.is_empty());
    Ok(())
}

#[test]
fn entries_are_isolated_by_scheme_host_port_and_credentials() -> TestResult {
    let cache = ProxyCredentialCache::new();
    let credentials = credentials()?;
    let other = HttpBasicCredentials::new("user", "other")?;
    cache.insert(ProxyScheme::Https, "Proxy.Example", 8443, &credentials);

    assert!(cache.contains(ProxyScheme::Https, "proxy.example", 8443, &credentials));
    assert!(!cache.contains(ProxyScheme::Http, "proxy.example", 8443, &credentials));
    assert!(!cache.contains(ProxyScheme::Https, "other.example", 8443, &credentials));
    assert!(!cache.contains(ProxyScheme::Https, "proxy.example", 8444, &credentials));
    assert!(!cache.contains(ProxyScheme::Https, "proxy.example", 8443, &other));

    cache.remove(ProxyScheme::Https, "PROXY.example", 8443, &credentials);
    assert!(cache.is_empty());
    Ok(())
}

#[test]
fn a_full_cache_forgets_the_least_recently_used_pair() -> TestResult {
    let cache = ProxyCredentialCache::new();
    let credentials = credentials()?;
    let ports = (1..).take(MAX_PROXY_CREDENTIAL_ENTRIES);
    for port in ports {
        cache.insert(ProxyScheme::Http, "proxy.example", port, &credentials);
    }
    // Using the oldest pair again makes port 2 the least recently used.
    cache.insert(ProxyScheme::Http, "proxy.example", 1, &credentials);
    cache.insert(ProxyScheme::Http, "proxy.example", 9_999, &credentials);

    assert_eq!(cache.len(), MAX_PROXY_CREDENTIAL_ENTRIES);
    assert!(cache.contains(ProxyScheme::Http, "proxy.example", 1, &credentials));
    assert!(!cache.contains(ProxyScheme::Http, "proxy.example", 2, &credentials));
    assert!(cache.contains(ProxyScheme::Http, "proxy.example", 9_999, &credentials));
    Ok(())
}

#[test]
fn debug_output_counts_entries_without_credentials() -> TestResult {
    let cache = ProxyCredentialCache::new();
    cache.insert(
        ProxyScheme::Http,
        "secret-proxy.example",
        8080,
        &HttpBasicCredentials::new("marker-user", "marker-secret")?,
    );

    let debug = format!("{cache:?}");
    assert_eq!(debug, "ProxyCredentialCache { entries: 1 }");
    Ok(())
}
