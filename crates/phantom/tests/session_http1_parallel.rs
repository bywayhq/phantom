//! Parallel HTTP/1.1 connections per origin and route.

#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{future::Future, net::Ipv4Addr, net::SocketAddr, num::NonZeroUsize, time::Duration};

use http_body_util::BodyExt;
use phantom::{
    Client, ClientBuilder, HttpProtocol, HttpProxy, ResponseBody, Route,
    profile::{ClientProfile, Http1Settings, chromium, firefox},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::mpsc,
    task::JoinHandle,
    time::timeout,
};

use btls::ssl::{Ssl, SslAcceptor};
use tokio_btls::SslStream;

use tls_support::{H1_ALPN, TestIdentity, client_builder, read_head, tls_settings};

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
    task: JoinHandle<()>,
}

impl Server {
    async fn start() -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (sender, events) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut accepted = 0;
            while let Ok((stream, _)) = listener.accept().await {
                if sender.send(Event::Accepted(accepted)).is_err() {
                    return;
                }
                tokio::spawn(serve(stream, accepted, sender.clone()));
                accepted += 1;
            }
        });
        Ok(Self {
            address,
            events,
            task,
        })
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

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(mut stream: TcpStream, connection: usize, events: mpsc::UnboundedSender<Event>) {
    while let Ok(head) = read_head(&mut stream).await {
        let path = request_path(&head);
        if events.send(Event::Request { connection, path }).is_err()
            || stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone")
                .await
                .is_err()
        {
            return;
        }
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
    bounded(async {
        let mut server = Server::start().await?;
        // The builder bound replaces the recipe's six connections.
        let client = builder(profile().with_http1(chromium::v154_http1()))
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
    .await
}

#[tokio::test]
async fn idle_connection_is_reused_before_another_opens() -> TestResult {
    bounded(async {
        let mut server = Server::start().await?;
        let client = builder(profile().with_http1(chromium::v154_http1())).build()?;

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
    .await
}

#[tokio::test]
async fn bound_is_counted_per_route_to_one_origin() -> TestResult {
    bounded(async {
        let origin = "http://origin.test/";
        let mut first_proxy = Server::start().await?;
        let mut second_proxy = Server::start().await?;
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
    .await
}

#[tokio::test]
async fn named_recipe_opens_six_connections_to_one_origin() -> TestResult {
    bounded(async {
        for recipe in [chromium::v154_http1(), firefox::v156_http1()] {
            assert_eq!(recipe.max_connections_per_origin.get(), 6);
            let mut server = Server::start().await?;
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
        }
        Ok(())
    })
    .await
}

#[tokio::test]
async fn profile_without_http1_policy_keeps_one_connection_per_origin() -> TestResult {
    bounded(async {
        let mut server = Server::start().await?;
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
    .await
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
    };
    let client = builder(profile().with_http1(settings)).build()?;
    assert!(format!("{client:?}").contains("max_concurrent_http1_requests_per_origin: 3"));
    Ok(())
}
