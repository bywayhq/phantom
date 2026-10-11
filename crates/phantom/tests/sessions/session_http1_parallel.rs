//! Parallel HTTP/1.1 connections per origin and route.

use std::{future::Future, net::Ipv4Addr, net::SocketAddr, num::NonZeroUsize, time::Duration};

use btls::ssl::{Ssl, SslAcceptor};
use http_body_util::BodyExt;
use phantom::{
    Client, ClientBuilder, HttpProtocol, HttpProxy, ResponseBody, Route,
    profile::{
        ClientProfile, Http1IdleTimeout, Http1Settings,
        browser::{chrome, firefox},
    },
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    task::AbortHandle,
    time::timeout,
};
use tokio_btls::SslStream;

use crate::support::{
    tls as tls_support,
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};
use tls_support::{H1_ALPN, TestIdentity, client_builder, read_head, tls_settings};

mod owner_contract;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a request must stay queued, or a listener stay quiet, to count as
/// waiting rather than merely slow.
const QUIET_WINDOW: Duration = Duration::from_millis(200);

/// What a loopback HTTP/1.1 server observed, in order.
#[derive(Debug, Eq, PartialEq)]
enum Event {
    /// The listener accepted its nth connection, counting from zero.
    Accepted(usize),
    /// A request head arrived on the numbered connection.
    Request { connection: usize, path: String },
}

/// A loopback HTTP/1.1 server that answers every request with a 4-byte body.
///
/// It serves origin-form and absolute-form requests alike, so it also stands
/// in for a forward proxy.
struct Server {
    address: SocketAddr,
    events: mpsc::UnboundedReceiver<Event>,
    stop: oneshot::Sender<()>,
    task: ConnectionPeer<TestResult>,
}

struct ObservedPeer {
    abort: AbortHandle,
}

impl Drop for ObservedPeer {
    fn drop(&mut self) {
        self.abort.abort();
    }
}

impl Server {
    async fn start() -> TestResult<Self> {
        Self::start_observed(None).await
    }

    async fn start_observed(observation: Option<owner_contract::PeerControl>) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (sender, events) = mpsc::unbounded_channel();
        let (stop, stopped) = oneshot::channel();
        let task = ConnectionPeer::spawn(accept_connections(listener, sender, observation, stopped));
        Ok(Self {
            address,
            events,
            stop,
            task,
        })
    }

    async fn shutdown(self) -> TestResult {
        let Self {
            events: _events,
            stop,
            mut task,
            ..
        } = self;

        // The coordinator may already have failed; its join retains that error.
        let _ = stop.send(());

        timeout(TEST_TIMEOUT, &mut task).await??
    }

    fn uri(&self, path: &str) -> String {
        format!("http://{}/{path}", self.address)
    }

    async fn next(&mut self) -> TestResult<Event> {
        Ok(timeout(TEST_TIMEOUT, self.events.recv())
            .await?
            .ok_or("server stopped")?)
    }

    /// Returns the next event, skipping connection accepts.
    async fn next_request(&mut self) -> TestResult<(usize, String)> {
        loop {
            if let Event::Request { connection, path } = self.next().await? {
                return Ok((connection, path));
            }
        }
    }

    /// Fails if the server observes anything within the quiet window.
    async fn assert_quiet(&mut self) -> TestResult {
        match timeout(QUIET_WINDOW, self.events.recv()).await {
            Err(_) => Ok(()),
            Ok(event) => Err(format!("unexpected server event {event:?}").into()),
        }
    }
}

async fn accept_connections(
    listener: TcpListener,
    sender: mpsc::UnboundedSender<Event>,
    mut observation: Option<owner_contract::PeerControl>,
    mut stopped: oneshot::Receiver<()>,
) -> TestResult {
    let mut peers = Vec::new();
    let mut observed = Vec::new();
    let primary = async {
        let mut accepted = 0;
        loop {
            let (stream, _) = tokio::select! {
                biased;
                _ = &mut stopped => return Ok(()),
                accepted = listener.accept() => accepted?,
            };
            sender.send(Event::Accepted(accepted))?;

            if let Some(control) = observation.take() {
                let (stream, result_owner) = control.attach(stream);
                match result_owner {
                    owner_contract::ResultOwner::Backup(returned) => {
                        let peer = tokio::spawn(serve(stream, accepted, sender.clone()));
                        observed.push(ObservedPeer {
                            abort: peer.abort_handle(),
                        });
                        if let Err(peer) = returned.send(peer) {
                            peers.push(ConnectionPeer::from_task(peer));
                            return Err("accepted peer observation receiver closed".into());
                        }
                    }
                    owner_contract::ResultOwner::Coordinator(completion) => {
                        let peer = ConnectionPeer::spawn(serve(stream, accepted, sender.clone()));
                        let witness = peer.abort_handle();
                        peers.push(peer);
                        if completion.send(witness).is_err() {
                            return Err("accepted peer completion receiver closed".into());
                        }
                    }
                }
            } else {
                peers.push(ConnectionPeer::spawn(serve(stream, accepted, sender.clone())));
            }
            accepted += 1;
        }
    }
    .await;

    drop(listener);
    drop(observed);
    for peer in &peers {
        if !peer.is_finished() {
            peer.abort();
        }
    }

    let mut cleanup = Ok(());
    for peer in peers {
        cleanup = finish_with_cleanup(cleanup, peer.stop().await);
    }
    finish_with_cleanup(primary, cleanup)
}

async fn serve(
    mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    connection: usize,
    events: mpsc::UnboundedSender<Event>,
) -> TestResult {
    loop {
        let head = match read_head(&mut stream).await {
            Ok(head) => head,
            Err(error) if tls_support::is_peer_gone(&error) => return Ok(()),
            Err(error) => return Err(error.into()),
        };

        let path = request_path(&head);
        events.send(Event::Request { connection, path })?;
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
            .await?;
    }
}

async fn serve_tls(tcp: TcpStream, acceptor: SslAcceptor) -> TestResult {
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    std::pin::Pin::new(&mut stream).accept().await?;
    while read_head(&mut stream).await.is_ok() {
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
            .await?;
    }
    Ok(())
}

/// Returns the path of an origin-form or absolute-form request target.
fn request_path(head: &[u8]) -> String {
    let line = String::from_utf8_lossy(head);
    let target = line.split(' ').nth(1).unwrap_or_default();
    let path = target
        .strip_prefix("http://")
        .and_then(|rest| rest.find('/').map(|slash| &rest[slash..]))
        .unwrap_or(target);
    path.trim_start_matches('/').to_owned()
}

fn builder(profile: ClientProfile) -> ClientBuilder {
    Client::builder(profile)
}

fn profile() -> ClientProfile {
    ClientProfile::new(tls_settings())
}

fn bound(value: usize) -> TestResult<NonZeroUsize> {
    Ok(NonZeroUsize::new(value).ok_or("zero bound")?)
}

async fn hold(client: &Client, uri: &str) -> TestResult<http::Response<ResponseBody>> {
    Ok(timeout(TEST_TIMEOUT, client.get(HttpProtocol::Http1, uri)?.send()).await??)
}

async fn finish(response: http::Response<ResponseBody>) -> TestResult {
    let body = timeout(TEST_TIMEOUT, response.into_body().collect())
        .await??
        .to_bytes();
    assert_eq!(body, "done");
    Ok(())
}

async fn bounded<F>(future: F) -> TestResult
where
    F: Future<Output = TestResult>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "parallel HTTP/1 test exceeded deadline")?
}

#[tokio::test]
async fn concurrent_requests_open_connections_up_to_the_bound_then_wait() -> TestResult {
    let mut server = Server::start().await?;
    let primary = bounded(async {
        // The builder bound replaces the recipe's six connections.
        let client = builder(profile().with_http1(chrome::v154_http1()))
            .max_concurrent_http1_requests_per_origin(bound(2)?)
            .build()?;

        let first = hold(&client, &server.uri("first")).await?;
        let second = hold(&client, &server.uri("second")).await?;
        assert_eq!(server.next().await?, Event::Accepted(0));
        assert_eq!(server.next_request().await?, (0, "first".to_owned()));
        assert_eq!(server.next().await?, Event::Accepted(1));
        assert_eq!(server.next_request().await?, (1, "second".to_owned()));

        let request = client.get(HttpProtocol::Http1, &server.uri("third"))?;
        let mut third = tokio::spawn(request.send());
        server.assert_quiet().await?;
        assert!(
            timeout(QUIET_WINDOW, &mut third).await.is_err(),
            "a third request ran while two connections were busy"
        );

        finish(first).await?;
        let third = timeout(TEST_TIMEOUT, third).await???;
        assert_eq!(
            server.next().await?,
            Event::Request {
                connection: 0,
                path: "third".to_owned(),
            }
        );
        finish(second).await?;
        finish(third).await?;
        server.assert_quiet().await?;
        Ok(())
    })
    .await;

    finish_with_cleanup(primary, server.shutdown().await)
}

#[tokio::test]
async fn idle_connection_is_reused_before_another_opens() -> TestResult {
    let mut server = Server::start().await?;
    let primary = bounded(async {
        let client = builder(profile().with_http1(chrome::v154_http1())).build()?;

        let first = hold(&client, &server.uri("first")).await?;
        let second = hold(&client, &server.uri("second")).await?;
        assert_eq!(server.next().await?, Event::Accepted(0));
        assert_eq!(server.next_request().await?, (0, "first".to_owned()));
        assert_eq!(server.next().await?, Event::Accepted(1));
        assert_eq!(server.next_request().await?, (1, "second".to_owned()));

        finish(second).await?;
        let third = hold(&client, &server.uri("third")).await?;
        assert_eq!(
            server.next().await?,
            Event::Request {
                connection: 1,
                path: "third".to_owned(),
            }
        );
        finish(third).await?;
        finish(first).await?;
        server.assert_quiet().await?;
        Ok(())
    })
    .await;

    finish_with_cleanup(primary, server.shutdown().await)
}

/// Chromium's 300-second idle timeout, shortened so the test can wait it out:
/// a connection idle less than the timeout carries the next request, and one
/// idle longer is closed when the next request comes, which opens another.
/// The window is wide enough that a slow host still reuses the connection;
/// the paused-clock pool tests check the exact edge.
#[tokio::test]
async fn connection_idle_past_the_idle_timeout_is_replaced_by_the_next_request() -> TestResult {
    const IDLE_TIMEOUT: Duration = Duration::from_secs(2);
    bounded(async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let uri = |path: &str| format!("http://{address}/{path}");
        let settings = Http1Settings {
            idle_timeout: Http1IdleTimeout::CheckedOnRequest(IDLE_TIMEOUT),
            ..chrome::v154_http1()
        };
        let client = builder(profile().with_http1(settings)).build()?;
        let first_uri = uri("first");
        let second_uri = uri("second");
        let third_uri = uri("third");

        let first = tokio::spawn({
            let client = client.clone();
            async move { finish(hold(&client, &first_uri).await?).await }
        });
        let (mut original, _) = timeout(TEST_TIMEOUT, listener.accept()).await??;
        assert_eq!(request_path(&read_head(&mut original).await?), "first");
        original
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
            .await?;
        first.await??;

        let second = tokio::spawn({
            let client = client.clone();
            async move { finish(hold(&client, &second_uri).await?).await }
        });
        assert_eq!(request_path(&read_head(&mut original).await?), "second");
        original
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
            .await?;
        second.await??;

        tokio::time::sleep(IDLE_TIMEOUT + QUIET_WINDOW).await;
        let third = tokio::spawn({
            let client = client.clone();
            async move { finish(hold(&client, &third_uri).await?).await }
        });
        let (mut replacement, _) = timeout(TEST_TIMEOUT, listener.accept()).await??;
        let mut byte = [0_u8; 1];
        let read = timeout(
            TEST_TIMEOUT,
            tokio::io::AsyncReadExt::read(&mut original, &mut byte),
        )
        .await??;
        assert_eq!(
            read, 0,
            "the expired connection carried bytes instead of closing"
        );
        assert_eq!(request_path(&read_head(&mut replacement).await?), "third");
        replacement
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
            .await?;
        third.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn bound_is_counted_per_route_to_one_origin() -> TestResult {
    let mut first_proxy = Server::start().await?;
    let mut second_proxy = match Server::start().await {
        Ok(proxy) => proxy,
        Err(error) => return finish_with_cleanup(Err(error), first_proxy.shutdown().await),
    };
    let primary = bounded(async {
        let origin = "http://origin.test/";
        let first_route =
            Route::http_proxy(HttpProxy::new(&format!("http://{}", first_proxy.address))?);
        let second_route =
            Route::http_proxy(HttpProxy::new(&format!("http://{}", second_proxy.address))?);
        let client = builder(profile())
            .max_concurrent_http1_requests_per_origin(NonZeroUsize::MIN)
            .route(first_route.clone())
            .build()?;

        let held = hold(&client, &format!("{origin}held")).await?;
        assert_eq!(first_proxy.next().await?, Event::Accepted(0));
        assert_eq!(first_proxy.next_request().await?, (0, "held".to_owned()));

        // The first route's single connection is busy, so its next request waits.
        let request = client
            .get(HttpProtocol::Http1, &format!("{origin}queued"))?
            .route(first_route);
        let mut queued = tokio::spawn(request.send());
        first_proxy.assert_quiet().await?;
        assert!(timeout(QUIET_WINDOW, &mut queued).await.is_err());

        // The second route to the same origin has its own bound.
        let other = timeout(
            TEST_TIMEOUT,
            client
                .get(HttpProtocol::Http1, &format!("{origin}other"))?
                .route(second_route)
                .send(),
        )
        .await??;
        assert_eq!(second_proxy.next().await?, Event::Accepted(0));
        assert_eq!(second_proxy.next_request().await?, (0, "other".to_owned()));
        finish(other).await?;

        finish(held).await?;
        finish(timeout(TEST_TIMEOUT, queued).await???).await?;
        assert_eq!(first_proxy.next_request().await?, (0, "queued".to_owned()));
        Ok(())
    })
    .await;

    let first_cleanup = first_proxy.shutdown().await;
    let second_cleanup = second_proxy.shutdown().await;
    finish_with_cleanup(primary, finish_with_cleanup(first_cleanup, second_cleanup))
}

#[tokio::test]
async fn named_recipe_opens_six_connections_to_one_origin() -> TestResult {
    for recipe in [chrome::v154_http1(), firefox::v157_http1()] {
        assert_eq!(recipe.max_connections_per_origin.get(), 6);
        let mut server = Server::start().await?;
        let primary = bounded(async {
            let client = builder(profile().with_http1(recipe)).build()?;

            let mut held = Vec::new();
            for index in 0..6 {
                held.push(hold(&client, &server.uri(&format!("held-{index}"))).await?);
            }
            let request = client.get(HttpProtocol::Http1, &server.uri("seventh"))?;
            let mut seventh = tokio::spawn(request.send());
            assert!(timeout(QUIET_WINDOW, &mut seventh).await.is_err());

            let mut accepted = 0;
            while let Ok(Some(event)) = timeout(QUIET_WINDOW, server.events.recv()).await {
                if matches!(event, Event::Accepted(_)) {
                    accepted += 1;
                }
            }
            assert_eq!(accepted, 6);

            for response in held {
                finish(response).await?;
            }
            finish(timeout(TEST_TIMEOUT, seventh).await???).await?;
            Ok(())
        })
        .await;

        finish_with_cleanup(primary, server.shutdown().await)?;
    }
    Ok(())
}

#[tokio::test]
async fn profile_without_http1_policy_keeps_one_connection_per_origin() -> TestResult {
    let mut server = Server::start().await?;
    let primary = bounded(async {
        let client = builder(profile()).build()?;

        let first = hold(&client, &server.uri("first")).await?;
        let request = client.get(HttpProtocol::Http1, &server.uri("second"))?;
        let mut second = tokio::spawn(request.send());
        assert!(timeout(QUIET_WINDOW, &mut second).await.is_err());

        finish(first).await?;
        finish(timeout(TEST_TIMEOUT, second).await???).await?;
        assert_eq!(server.next().await?, Event::Accepted(0));
        assert_eq!(server.next_request().await?, (0, "first".to_owned()));
        assert_eq!(server.next_request().await?, (0, "second".to_owned()));
        server.assert_quiet().await?;
        Ok(())
    })
    .await;

    finish_with_cleanup(primary, server.shutdown().await)
}

#[tokio::test]
async fn requests_cancelled_during_connection_setup_leave_the_full_bound() -> TestResult {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let (accepted_tx, mut accepted) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            // The first two connections never answer the ClientHello, so
            // their requests stay in TLS setup until they are cancelled.
            let mut stalled = Vec::new();
            for index in 0..2 {
                let (tcp, _) = listener.accept().await?;
                stalled.push(tcp);
                let _ = accepted_tx.send(index);
            }
            let mut index = 2;
            while let Ok((tcp, _)) = listener.accept().await {
                let _ = accepted_tx.send(index);
                index += 1;
                tokio::spawn(serve_tls(tcp, acceptor.clone()));
            }
            drop(stalled);
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });
        let client = client_builder(&identity, false)
            .max_concurrent_http1_requests_per_origin(bound(2)?)
            .build()?;
        let uri = |path: &str| format!("https://{address}/{path}");

        let mut setups = Vec::new();
        for path in ["cancelled-0", "cancelled-1"] {
            setups.push(tokio::spawn(
                client.get(HttpProtocol::Http1, &uri(path))?.send(),
            ));
        }
        for expected in 0..2 {
            let index = timeout(TEST_TIMEOUT, accepted.recv())
                .await?
                .ok_or("server stopped")?;
            assert_eq!(index, expected);
        }
        for setup in setups {
            setup.abort();
            assert!(setup.await.is_err_and(|error| error.is_cancelled()));
        }

        // Both slots came back: two requests run at once on new connections,
        // and a third still waits at the bound.
        let first = hold(&client, &uri("first")).await?;
        let second = hold(&client, &uri("second")).await?;
        let request = client.get(HttpProtocol::Http1, &uri("third"))?;
        let mut third = tokio::spawn(request.send());
        assert!(timeout(QUIET_WINDOW, &mut third).await.is_err());
        finish(first).await?;
        finish(second).await?;
        finish(timeout(TEST_TIMEOUT, third).await???).await?;

        let mut opened = Vec::new();
        while let Ok(Some(index)) = timeout(QUIET_WINDOW, accepted.recv()).await {
            opened.push(index);
        }
        assert_eq!(opened, [2, 3]);
        server.abort();
        Ok(())
    })
    .await
}

#[test]
fn custom_profile_carries_its_own_http1_bound() -> TestResult {
    let settings = Http1Settings {
        max_connections_per_origin: bound(3)?,
        idle_timeout: Http1IdleTimeout::Unlimited,
    };
    let client = builder(profile().with_http1(settings)).build()?;
    assert!(format!("{client:?}").contains("max_concurrent_http1_requests_per_origin: 3"));
    Ok(())
}

/// On Windows a refused loopback connect takes about two seconds, so a
/// Firefox profile's attempt to `[::1]`, where nothing listens, is still
/// pending when its IPv4 backup connects 250 ms in and carries the first
/// request. The first attempt then moves to `127.0.0.1` as well, and the pool
/// keeps that slower connection idle without a request, as Firefox 157 did
/// in its hook logs: the next two requests share the two connections and no
/// third one opens.
#[cfg(windows)]
#[tokio::test]
async fn a_firefox_profile_keeps_the_slower_backup_connection_for_later_requests() -> TestResult {
    let mut server = Server::start().await?;
    let primary = bounded(async {
        let port = server.address.port();
        // `[::1]` at the same port stays bound without listening, so its
        // connect is refused; a host without IPv6 loopback skips the test.
        let unlistened = tokio::net::TcpSocket::new_v6()?;
        match unlistened.bind(SocketAddr::new(std::net::Ipv6Addr::LOCALHOST.into(), port)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AddrNotAvailable => {
                eprintln!("skipped: this host has no IPv6 loopback address");
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        }
        let client = builder(
            profile()
                .with_http1(firefox::v157_http1())
                .with_tcp(firefox::v157_tcp()),
        )
        .resolve(
            "origin.phantom.test",
            [
                std::net::Ipv6Addr::LOCALHOST.into(),
                Ipv4Addr::LOCALHOST.into(),
            ],
        )
        .build()?;
        let uri = |path: &str| format!("http://origin.phantom.test:{port}/{path}");

        finish(hold(&client, &uri("first")).await?).await?;
        assert_eq!(server.next().await?, Event::Accepted(0));
        assert_eq!(server.next_request().await?, (0, "first".to_owned()));
        // The slower attempt connects with no request once `[::1]` refuses.
        assert_eq!(server.next().await?, Event::Accepted(1));

        let second = hold(&client, &uri("second")).await?;
        let third = hold(&client, &uri("third")).await?;
        let mut used = [
            server.next_request().await?.0,
            server.next_request().await?.0,
        ];
        used.sort_unstable();
        assert_eq!(used, [0, 1]);
        server.assert_quiet().await?;
        finish(second).await?;
        finish(third).await?;
        drop(unlistened);
        Ok(())
    })
    .await;

    finish_with_cleanup(primary, server.shutdown().await)
}
