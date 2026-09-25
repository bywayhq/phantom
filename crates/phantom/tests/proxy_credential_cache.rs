//! Proxy round trips saved by remembering accepted Basic credentials.

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use http_body_util::BodyExt;
use phantom::{Client, HttpProtocol, HttpProxy, Route};
use tokio::{
    io::{AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

use tls_support::{
    H1_ALPN, TestIdentity, TestResult, accept_tls_stream, client_builder, read_head,
};

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const TUNNELS: usize = 4;

/// Opens `TUNNELS` sequential CONNECT tunnels and counts what the proxy saw.
///
/// The origin closes every connection after one response, so each request
/// needs a new tunnel. Without the credential record, every tunnel costs a
/// `407` and a second proxy connection; with it, only the first does.
#[tokio::test]
async fn sequential_tunnels_pay_for_one_challenge_instead_of_one_per_tunnel() -> TestResult<()> {
    bounded(async {
        let remembered = tunnel_counts(true).await?;
        let forgotten = tunnel_counts(false).await?;

        assert_eq!(
            remembered,
            ProxyCounts {
                connections: TUNNELS + 1,
                challenges: 1,
                with_credentials: TUNNELS,
            }
        );
        assert_eq!(
            forgotten,
            ProxyCounts {
                connections: 2 * TUNNELS,
                challenges: TUNNELS,
                with_credentials: TUNNELS,
            }
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn remembered_credentials_never_reach_another_proxy_or_the_origin() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::start(&identity).await?;
        let first = CountingProxy::start(origin.address).await?;
        let second = CountingProxy::start(origin.address).await?;
        let client = client_builder(&identity, false).build()?;
        let url = format!("https://{}/", origin.address);
        let routes = [
            proxy_route(first.address, "alice", "secret")?,
            proxy_route(first.address, "alice", "secret")?,
            // Same proxy host with another port, and same proxy with other
            // credentials: both start without credentials.
            proxy_route(second.address, "alice", "secret")?,
            proxy_route(first.address, "bob", "other")?,
        ];
        for route in routes {
            let response = client
                .get(HttpProtocol::Http1, &url)?
                .route(route)
                .send()
                .await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
        }

        // The first proxy challenged alice once and bob once; alice's second
        // tunnel went through without a challenge.
        let first_heads = first.heads()?;
        assert_eq!(first.counts().challenges, 2);
        assert_eq!(
            first_heads
                .iter()
                .map(|head| authorization(head))
                .collect::<Vec<_>>(),
            [
                None,
                Some("Basic YWxpY2U6c2VjcmV0".to_owned()),
                Some("Basic YWxpY2U6c2VjcmV0".to_owned()),
                None,
                Some("Basic Ym9iOm90aGVy".to_owned()),
            ]
        );
        assert_eq!(second.counts().challenges, 1);
        assert_eq!(authorization(&second.heads()?[0]), None);
        let origin_heads = origin.heads()?;
        assert_eq!(origin_heads.len(), 4);
        assert!(
            origin_heads
                .iter()
                .all(|head| authorization(head).is_none())
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn each_session_starts_with_an_empty_credential_record() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::start(&identity).await?;
        let proxy = CountingProxy::start(origin.address).await?;
        let client = client_builder(&identity, false)
            .route(proxy_route(proxy.address, "alice", "secret")?)
            .build()?;
        let url = format!("https://{}/", origin.address);

        // The client learns the credentials once.
        send_one(&client, &url).await?;
        send_one(&client, &url).await?;
        assert_eq!(proxy.counts().challenges, 1);

        // Neither kind of session inherits the client's record, and each
        // learns its own.
        let built = client.session_builder().build()?;
        send_one(&built, &url).await?;
        send_one(&built, &url).await?;
        assert_eq!(proxy.counts().challenges, 2);
        let session = client.session();
        send_one(&session, &url).await?;
        assert_eq!(proxy.counts().challenges, 3);

        // The sessions did not change what the client remembers, and a clone
        // shares the client's record.
        send_one(&client.clone(), &url).await?;
        assert_eq!(
            proxy.counts(),
            ProxyCounts {
                connections: 9,
                challenges: 3,
                with_credentials: 6,
            }
        );
        Ok(())
    })
    .await
}

async fn send_one(client: &Client, url: &str) -> TestResult<()> {
    let response = client.get(HttpProtocol::Http1, url)?.send().await?;
    assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
    Ok(())
}

async fn tunnel_counts(preemptive: bool) -> TestResult<ProxyCounts> {
    let identity = TestIdentity::generate()?;
    let origin = Origin::start(&identity).await?;
    let proxy = CountingProxy::start(origin.address).await?;
    let client = client_builder(&identity, false)
        .route(proxy_route(proxy.address, "alice", "secret")?)
        .preemptive_proxy_authentication(preemptive)
        .build()?;
    send_sequentially(&client, origin.address).await?;
    Ok(proxy.counts())
}

async fn send_sequentially(client: &Client, origin: SocketAddr) -> TestResult<()> {
    for index in 0..TUNNELS {
        let response = client
            .get(HttpProtocol::Http1, &format!("https://{origin}/{index}"))?
            .send()
            .await?;
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
    }
    Ok(())
}

fn proxy_route(address: SocketAddr, username: &str, password: &str) -> TestResult<Route> {
    Ok(Route::http_proxy(
        HttpProxy::new(&format!("http://{address}"))?.with_basic_auth(username, password)?,
    ))
}

fn authorization(head: &[u8]) -> Option<String> {
    String::from_utf8_lossy(head).lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("proxy-authorization")
            .then(|| value.trim().to_owned())
    })
}

#[derive(Debug, Eq, PartialEq)]
struct ProxyCounts {
    connections: usize,
    challenges: usize,
    with_credentials: usize,
}

/// A CONNECT proxy that challenges any request without `Proxy-Authorization`
/// and closes that connection, and tunnels any request with it to the origin.
struct CountingProxy {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    heads: Arc<Mutex<Vec<Vec<u8>>>>,
    task: JoinHandle<()>,
}

impl CountingProxy {
    async fn start(origin: SocketAddr) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let connections = Arc::new(AtomicUsize::new(0));
        let heads = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let connections = Arc::clone(&connections);
            let heads = Arc::clone(&heads);
            async move {
                while let Ok((stream, _)) = listener.accept().await {
                    connections.fetch_add(1, Ordering::SeqCst);
                    tokio::spawn(serve_connect(stream, origin, Arc::clone(&heads)));
                }
            }
        });
        Ok(Self {
            address,
            connections,
            heads,
            task,
        })
    }

    fn heads(&self) -> TestResult<Vec<Vec<u8>>> {
        Ok(self
            .heads
            .lock()
            .map_err(|_| "proxy head lock was poisoned")?
            .clone())
    }

    fn counts(&self) -> ProxyCounts {
        let heads = self.heads().unwrap_or_default();
        let with_credentials = heads
            .iter()
            .filter(|head| authorization(head).is_some())
            .count();
        ProxyCounts {
            connections: self.connections.load(Ordering::SeqCst),
            challenges: heads.len() - with_credentials,
            with_credentials,
        }
    }
}

impl Drop for CountingProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_connect(
    mut stream: TcpStream,
    origin: SocketAddr,
    heads: Arc<Mutex<Vec<Vec<u8>>>>,
) -> std::io::Result<()> {
    let head = read_head(&mut stream).await?;
    let authorized = authorization(&head).is_some();
    if let Ok(mut heads) = heads.lock() {
        heads.push(head);
    }
    if !authorized {
        stream
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                  Proxy-Authenticate: Basic realm=\"counting\"\r\n\
                  Content-Length: 0\r\n\r\n",
            )
            .await?;
        return stream.shutdown().await;
    }
    let mut upstream = TcpStream::connect(origin).await?;
    stream
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    copy_bidirectional(&mut stream, &mut upstream)
        .await
        .map(drop)
}

/// A TLS origin that answers each connection once and closes it.
struct Origin {
    address: SocketAddr,
    heads: Arc<Mutex<Vec<Vec<u8>>>>,
    task: JoinHandle<()>,
}

impl Origin {
    async fn start(identity: &TestIdentity) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let heads = Arc::new(Mutex::new(Vec::new()));
        let task = tokio::spawn({
            let heads = Arc::clone(&heads);
            async move {
                while let Ok((tcp, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let heads = Arc::clone(&heads);
                    tokio::spawn(async move {
                        let mut stream = accept_tls_stream(tcp, acceptor).await?;
                        let head = read_head(&mut stream).await?;
                        if let Ok(mut heads) = heads.lock() {
                            heads.push(head);
                        }
                        stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nConnection: close\r\n\
                                  Content-Length: 2\r\n\r\nok",
                            )
                            .await?;
                        stream.shutdown().await?;
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
                    });
                }
            }
        });
        Ok(Self {
            address,
            heads,
            task,
        })
    }

    fn heads(&self) -> TestResult<Vec<Vec<u8>>> {
        Ok(self
            .heads
            .lock()
            .map_err(|_| "origin head lock was poisoned")?
            .clone())
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "proxy credential test timed out")?
}
