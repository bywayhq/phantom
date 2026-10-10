//! Proxy round trips saved by remembering accepted Basic credentials.

use std::{
    error::Error,
    fmt,
    future::Future,
    io,
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
    sync::watch,
    task::JoinSet,
    time::timeout,
};

use crate::support::tls::{
    H1_ALPN, TestIdentity, TestResult, accept_tls_stream, client_builder, read_head,
};
use crate::support::tunnel_proxy::{ConnectionPeer, finish_with_cleanup};

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const TUNNELS: usize = 4;

mod deadline_contract;
mod observer_contract;
mod peer_contract;

/// Opens `TUNNELS` sequential CONNECT tunnels and counts what the proxy saw.
///
/// The origin closes every connection after one response, so each request
/// needs a new tunnel. The proxy closes each challenged connection. Without
/// the credential record, every tunnel costs a `407` and a second proxy
/// connection; with it, only the first does.
#[tokio::test]
async fn sequential_tunnels_pay_for_one_challenge_instead_of_one_per_tunnel() -> TestResult<()> {
    bounded(async {
        let remembered = tunnel_counts(true, Challenge::Close).await?;
        let forgotten = tunnel_counts(false, Challenge::Close).await?;

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

/// The same tunnels through a proxy whose `407` keeps the connection open:
/// each replay goes on the challenged connection, so every tunnel costs one
/// proxy connection whether or not the credentials are remembered.
#[tokio::test]
async fn keep_alive_challenges_cost_no_extra_proxy_connection() -> TestResult<()> {
    bounded(async {
        let remembered = tunnel_counts(true, Challenge::KeepAlive).await?;
        let forgotten = tunnel_counts(false, Challenge::KeepAlive).await?;

        assert_eq!(
            remembered,
            ProxyCounts {
                connections: TUNNELS,
                challenges: 1,
                with_credentials: TUNNELS,
            }
        );
        assert_eq!(
            forgotten,
            ProxyCounts {
                connections: TUNNELS,
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
        let first = match CountingProxy::start(origin.address).await {
            Ok(proxy) => proxy,
            Err(error) => return finish_with_cleanup(Err(error), origin.finish().await),
        };
        let second = match CountingProxy::start(origin.address).await {
            Ok(proxy) => proxy,
            Err(error) => {
                let first_completed = first.finish().await;
                let origin_completed = origin.finish().await;
                return finish_with_cleanup(
                    Err(error),
                    finish_with_cleanup(first_completed, origin_completed),
                );
            }
        };
        let operation = async {
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
            assert_eq!(first.counts()?.challenges, 2);
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
            assert_eq!(second.counts()?.challenges, 1);
            assert_eq!(authorization(&second.heads()?[0]), None);
            let origin_heads = origin.heads()?;
            assert_eq!(origin_heads.len(), 4);
            assert!(
                origin_heads
                    .iter()
                    .all(|head| authorization(head).is_none())
            );
            Ok(client)
        }
        .await;

        let first_completed = first.finish().await;
        let second_completed = second.finish().await;
        let origin_completed = origin.finish().await;
        finish_with_cleanup(
            operation,
            finish_with_cleanup(
                first_completed,
                finish_with_cleanup(second_completed, origin_completed),
            ),
        )?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn each_client_starts_with_an_empty_credential_record() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin = Origin::start(&identity).await?;
        let proxy = match CountingProxy::start(origin.address).await {
            Ok(proxy) => proxy,
            Err(error) => return finish_with_cleanup(Err(error), origin.finish().await),
        };
        let operation = async {
            let build = || -> TestResult<Client> {
                Ok(client_builder(&identity, false)
                    .route(proxy_route(proxy.address, "alice", "secret")?)
                    .build()?)
            };
            let client = build()?;
            let url = format!("https://{}/", origin.address);

            // The client learns the credentials once.
            send_one(&client, &url).await?;
            send_one(&client, &url).await?;
            assert_eq!(proxy.counts()?.challenges, 1);

            // A separately built client does not inherit the record, and learns
            // its own.
            let separate = build()?;
            send_one(&separate, &url).await?;
            send_one(&separate, &url).await?;
            assert_eq!(proxy.counts()?.challenges, 2);

            // The other client did not change what the first remembers, and a
            // clone shares the first client's record.
            send_one(&client.clone(), &url).await?;
            assert_eq!(
                proxy.counts()?,
                ProxyCounts {
                    connections: 7,
                    challenges: 2,
                    with_credentials: 5,
                }
            );
            Ok((client, separate))
        }
        .await;

        finish_credential_fixture(operation, proxy, origin).await?;
        Ok(())
    })
    .await
}

async fn send_one(client: &Client, url: &str) -> TestResult<()> {
    let response = client.get(HttpProtocol::Http1, url)?.send().await?;
    assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
    Ok(())
}

async fn tunnel_counts(preemptive: bool, challenge: Challenge) -> TestResult<ProxyCounts> {
    let identity = TestIdentity::generate()?;
    let origin = Origin::start(&identity).await?;
    let proxy = match CountingProxy::start_with(origin.address, challenge).await {
        Ok(proxy) => proxy,
        Err(error) => return finish_with_cleanup(Err(error), origin.finish().await),
    };
    let operation = async {
        let client = client_builder(&identity, false)
            .route(proxy_route(proxy.address, "alice", "secret")?)
            .preemptive_proxy_authentication(preemptive)
            .build()?;
        send_sequentially(&client, origin.address).await?;
        Ok((client, proxy.counts()?))
    }
    .await;

    let (_client, counts) = finish_credential_fixture(operation, proxy, origin).await?;
    Ok(counts)
}

async fn finish_credential_fixture<T>(
    operation: TestResult<T>,
    proxy: CountingProxy,
    origin: Origin,
) -> TestResult<T> {
    let proxy_completed = proxy.finish().await;
    let origin_completed = origin.finish().await;
    finish_with_cleanup(
        operation,
        finish_with_cleanup(proxy_completed, origin_completed),
    )
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

/// How the counting proxy's `407` treats its connection.
#[derive(Clone, Copy)]
enum Challenge {
    /// `Connection: close`, then the proxy closes the connection.
    Close,
    /// A keep-alive `407`; the next CONNECT may follow on the connection.
    KeepAlive,
}

/// A CONNECT proxy that challenges any request without `Proxy-Authorization`
/// and tunnels any request with it to the origin.
struct CountingProxy {
    address: SocketAddr,
    connections: Arc<AtomicUsize>,
    heads: Arc<Mutex<Vec<Vec<u8>>>>,
    stop: watch::Sender<bool>,
    task: ConnectionPeer<TestResult<()>>,
}

impl CountingProxy {
    async fn start(origin: SocketAddr) -> TestResult<Self> {
        Self::start_with(origin, Challenge::Close).await
    }

    async fn start_with(origin: SocketAddr, challenge: Challenge) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let connections = Arc::new(AtomicUsize::new(0));
        let heads = Arc::new(Mutex::new(Vec::new()));
        let (stop, stopping) = watch::channel(false);
        let task = ConnectionPeer::spawn(serve_counting_proxy(
            listener,
            origin,
            challenge,
            Arc::clone(&connections),
            Arc::clone(&heads),
            stopping,
        ));
        Ok(Self {
            address,
            connections,
            heads,
            stop,
            task,
        })
    }

    fn heads(&self) -> TestResult<Vec<Vec<u8>>> {
        Ok(self
            .heads
            .lock()
            .map_err(|_| io::Error::other(CredentialObserverPoisoned("proxy")))?
            .clone())
    }

    fn counts(&self) -> TestResult<ProxyCounts> {
        let heads = self.heads()?;
        let with_credentials = heads
            .iter()
            .filter(|head| authorization(head).is_some())
            .count();
        Ok(ProxyCounts {
            connections: self.connections.load(Ordering::SeqCst),
            challenges: heads.len() - with_credentials,
            with_credentials,
        })
    }

    async fn finish(self) -> TestResult<()> {
        self.stop.send_replace(true);
        finish_listener(self.task).await
    }
}

async fn serve_connect(
    mut stream: TcpStream,
    origin: SocketAddr,
    challenge: Challenge,
    heads: Arc<Mutex<Vec<Vec<u8>>>>,
) -> std::io::Result<()> {
    loop {
        let head = read_head(&mut stream).await?;
        let authorized = authorization(&head).is_some();
        heads
            .lock()
            .map_err(|_| io::Error::other(CredentialObserverPoisoned("proxy")))?
            .push(head);
        if authorized {
            break;
        }
        match challenge {
            Challenge::Close => {
                stream
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Basic realm=\"counting\"\r\n\
                          Connection: close\r\n\
                          Content-Length: 0\r\n\r\n",
                    )
                    .await?;
                return stream.shutdown().await;
            }
            Challenge::KeepAlive => {
                stream
                    .write_all(
                        b"HTTP/1.1 407 Proxy Authentication Required\r\n\
                          Proxy-Authenticate: Basic realm=\"counting\"\r\n\
                          Content-Length: 0\r\n\r\n",
                    )
                    .await?;
            }
        }
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
    stop: watch::Sender<bool>,
    task: ConnectionPeer<TestResult<()>>,
}

impl Origin {
    async fn start(identity: &TestIdentity) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let heads = Arc::new(Mutex::new(Vec::new()));
        let (stop, stopping) = watch::channel(false);
        let task = ConnectionPeer::spawn(serve_origin_connections(
            listener,
            acceptor,
            Arc::clone(&heads),
            stopping,
        ));
        Ok(Self {
            address,
            heads,
            stop,
            task,
        })
    }

    fn heads(&self) -> TestResult<Vec<Vec<u8>>> {
        Ok(self
            .heads
            .lock()
            .map_err(|_| io::Error::other(CredentialObserverPoisoned("origin")))?
            .clone())
    }

    async fn finish(self) -> TestResult<()> {
        self.stop.send_replace(true);
        finish_listener(self.task).await
    }
}

async fn serve_origin(
    tcp: TcpStream,
    acceptor: btls::ssl::SslAcceptor,
    heads: Arc<Mutex<Vec<Vec<u8>>>>,
) -> TestResult<()> {
    let mut stream = accept_tls_stream(tcp, acceptor).await?;
    let head = read_head(&mut stream).await?;
    heads
        .lock()
        .map_err(|_| io::Error::other(CredentialObserverPoisoned("origin")))?
        .push(head);
    stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\
              Content-Length: 2\r\n\r\nok",
        )
        .await?;
    stream.shutdown().await?;
    Ok(())
}

async fn serve_counting_proxy(
    listener: TcpListener,
    origin: SocketAddr,
    challenge: Challenge,
    connections: Arc<AtomicUsize>,
    heads: Arc<Mutex<Vec<Vec<u8>>>>,
    mut stopping: watch::Receiver<bool>,
) -> TestResult<()> {
    let mut handlers = JoinSet::new();
    let mut completed = Ok(());
    let operation = async {
        loop {
            tokio::select! {
                biased;
                joined = handlers.join_next(), if !handlers.is_empty() => {
                    if let Some(joined) = joined {
                        completed = finish_with_cleanup(
                            std::mem::replace(&mut completed, Ok(())),
                            credential_handler_result(joined),
                        );
                    }
                }
                changed = stopping.changed() => {
                    changed?;
                    if *stopping.borrow_and_update() {
                        return Ok(());
                    }
                }
                accepted = listener.accept() => {
                    let (stream, _) = accepted?;
                    connections.fetch_add(1, Ordering::SeqCst);
                    let heads = Arc::clone(&heads);
                    handlers.spawn(async move {
                        serve_connect(stream, origin, challenge, heads).await?;
                        TestResult::Ok(())
                    });
                }
            }
        }
    }
    .await;
    finish_credential_handlers(operation, handlers, completed).await
}

async fn serve_origin_connections(
    listener: TcpListener,
    acceptor: btls::ssl::SslAcceptor,
    heads: Arc<Mutex<Vec<Vec<u8>>>>,
    mut stopping: watch::Receiver<bool>,
) -> TestResult<()> {
    let mut handlers = JoinSet::new();
    let mut completed = Ok(());
    let operation = async {
        loop {
            tokio::select! {
                biased;
                joined = handlers.join_next(), if !handlers.is_empty() => {
                    if let Some(joined) = joined {
                        completed = finish_with_cleanup(
                            std::mem::replace(&mut completed, Ok(())),
                            credential_handler_result(joined),
                        );
                    }
                }
                changed = stopping.changed() => {
                    changed?;
                    if *stopping.borrow_and_update() {
                        return Ok(());
                    }
                }
                accepted = listener.accept() => {
                    let (tcp, _) = accepted?;
                    handlers.spawn(serve_origin(tcp, acceptor.clone(), Arc::clone(&heads)));
                }
            }
        }
    }
    .await;
    finish_credential_handlers(operation, handlers, completed).await
}

fn credential_handler_result(
    joined: Result<TestResult<()>, tokio::task::JoinError>,
) -> TestResult<()> {
    joined?
}

async fn finish_credential_handlers(
    operation: TestResult<()>,
    mut handlers: JoinSet<TestResult<()>>,
    mut completed: TestResult<()>,
) -> TestResult<()> {
    // Keep completed causes outside the timed future so cancellation cannot discard them.
    let drained = timeout(Duration::from_secs(5), async {
        while let Some(joined) = handlers.join_next().await {
            completed = finish_with_cleanup(
                std::mem::replace(&mut completed, Ok(())),
                credential_handler_result(joined),
            );
        }
    })
    .await;
    if let Err(error) = drained {
        completed = finish_with_cleanup(completed, Err(error.into()));
        handlers.abort_all();
        let cancelled = timeout(Duration::from_secs(5), async {
            while let Some(joined) = handlers.join_next().await {
                let result = match joined {
                    Err(error) if error.is_cancelled() => Ok(()),
                    joined => credential_handler_result(joined),
                };
                completed = finish_with_cleanup(std::mem::replace(&mut completed, Ok(())), result);
            }
        })
        .await;
        if let Err(error) = cancelled {
            completed = finish_with_cleanup(completed, Err(error.into()));
        }
    }
    finish_with_cleanup(operation, completed)
}

async fn finish_listener(mut task: ConnectionPeer<TestResult<()>>) -> TestResult<()> {
    match timeout(Duration::from_secs(12), &mut task).await {
        Ok(joined) => joined?,
        Err(error) => finish_with_cleanup(Err(error.into()), task.stop().await),
    }
}

#[derive(Debug)]
struct CredentialObserverPoisoned(&'static str);

impl fmt::Display for CredentialObserverPoisoned {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} head lock was poisoned", self.0)
    }
}

impl Error for CredentialObserverPoisoned {}

#[derive(Debug)]
struct CredentialDeadline(tokio::time::error::Elapsed);

impl fmt::Display for CredentialDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("proxy credential test timed out")
    }
}

impl Error for CredentialDeadline {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(CredentialDeadline)?
}
