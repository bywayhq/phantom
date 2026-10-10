//! Authenticated remote-DNS SOCKS5 integration coverage.

use std::{error::Error, fmt, net::Ipv4Addr, pin::Pin, sync::Arc};

use btls::ssl::{Ssl, SslAcceptor};
use http::Response;
use http_body_util::BodyExt;
use phantom::{HttpProtocol, RequestErrorKind, Route, Socks5Proxy};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    task::JoinSet,
    time::{Instant, timeout_at},
};
use tokio_btls::SslStream;

use super::{
    ConnectionPeer, ORIGIN_NAME, TEST_TIMEOUT, bounded, finish_socks_proxy, finish_socks_route,
    finish_with_cleanup,
    socks5_support::{
        ObservedAuthenticatedSocks5Connect, ObservedSocks5Authentication,
        forward_next_authenticated_socks5, forward_one_authenticated_socks5,
        reject_one_socks5_authentication,
    },
    stop_socks_peer,
    tls::{H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls, client_builder, read_head},
};

const USERNAME: &str = "proxy-user";
const PASSWORD: &str = "proxy-password";

#[tokio::test]
async fn http1_authenticates_before_remote_dns_connect() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let origin = ConnectionPeer::spawn(async move {
            let mut stream = accept_tls(origin_listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nauth")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
        });

        let proxy = ConnectionPeer::spawn(forward_one_authenticated_socks5(
            proxy_listener,
            origin_address,
        ));
        let operation: TestResult<()> = async {
            let route = authenticated_route("socks5h", proxy_address)?;
            let client = client_builder(&identity, false).route(route).build()?;

            let response = client
                .get(
                    HttpProtocol::Http1,
                    &format!(
                        "https://{ORIGIN_NAME}:{}/authenticated",
                        origin_address.port()
                    ),
                )?
                .send()
                .await?;
            assert_eq!(response.status(), 200);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "auth");
            drop(client);
            Ok(())
        }
        .await;

        let (origin_observation, proxy_observation) =
            finish_socks_route(operation, origin, proxy).await?;

        assert!(origin_observation.starts_with(b"GET /authenticated HTTP/1.1\r\n"));
        assert_remote_observation(proxy_observation, USERNAME, PASSWORD, origin_address.port());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http2_authenticates_before_remote_dns_connect() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let origin = ConnectionPeer::spawn(async move {
            let stream = accept_tls(origin_listener, acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut respond) = connection
                .accept()
                .await
                .ok_or("connection closed before authenticated request")??;
            let path = request.uri().path().to_owned();
            respond.send_response(Response::builder().status(204).body(())?, true)?;
            std::future::poll_fn(|context| connection.poll_closed(context)).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(path)
        });

        let proxy = ConnectionPeer::spawn(forward_one_authenticated_socks5(
            proxy_listener,
            origin_address,
        ));
        let operation: TestResult<()> = async {
            let route = authenticated_route("socks5h", proxy_address)?;
            let client = client_builder(&identity, true).route(route).build()?;

            let response = client
                .get(
                    HttpProtocol::Http2,
                    &format!(
                        "https://{ORIGIN_NAME}:{}/authenticated",
                        origin_address.port()
                    ),
                )?
                .send()
                .await?;
            assert_eq!(response.status(), 204);
            response.into_body().collect().await?;
            drop(client);
            Ok(())
        }
        .await;

        let (origin_observation, proxy_observation) =
            finish_socks_route(operation, origin, proxy).await?;

        assert_eq!(origin_observation, "/authenticated");
        assert_remote_observation(proxy_observation, USERNAME, PASSWORD, origin_address.port());
        Ok(())
    })
    .await
}

#[tokio::test]
async fn rejected_authentication_sends_no_connect_or_direct_origin_attempt() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_address = origin.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = ConnectionPeer::spawn(reject_one_socks5_authentication(proxy_listener, 1));
        let operation: TestResult<()> = async {
            let route = authenticated_route("socks5h", proxy_address)?;
            let client = client_builder(&identity, false).route(route).build()?;

            let error = match client
                .get(
                    HttpProtocol::Http1,
                    &format!("https://{ORIGIN_NAME}:{}/", origin_address.port()),
                )?
                .send()
                .await
            {
                Ok(_) => return Err("rejected SOCKS5 authentication succeeded".into()),
                Err(error) => error,
            };

            assert_eq!(error.kind(), RequestErrorKind::Proxy);
            assert!(matches!(
                origin.accept(),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
            ));
            Ok(())
        }
        .await;

        assert_eq!(
            finish_socks_proxy(operation, proxy).await?,
            ObservedSocks5Authentication {
                username: USERNAME.to_owned(),
                password: PASSWORD.to_owned(),
            }
        );
        Ok(())
    })
    .await
}

#[tokio::test]
async fn http2_pool_separates_credentials_and_reuses_matches() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let proxy_listener = Arc::new(TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?);
        let proxy_address = proxy_listener.local_addr()?;
        let origin = ConnectionPeer::spawn(serve_two_http2_connections(origin_listener, acceptor));

        let mut proxy_tasks = JoinSet::new();
        for _ in 0..2 {
            let listener = Arc::clone(&proxy_listener);
            proxy_tasks.spawn(async move {
                forward_next_authenticated_socks5(&listener, origin_address).await
            });
        }

        let operation: TestResult<()> = async {
            let first_route = Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?
                .with_username_password("first-user", "first-password")?;
            let second_route = Socks5Proxy::new(&format!("socks5h://{proxy_address}"))?
                .with_username_password("second-user", "second-password")?;
            let session = client_builder(&identity, true).build()?;
            for (path, proxy) in [
                ("/first", first_route.clone()),
                ("/second", second_route),
                ("/first-again", first_route),
            ] {
                let response = session
                    .get(
                        HttpProtocol::Http2,
                        &format!("https://{ORIGIN_NAME}:{}{path}", origin_address.port()),
                    )?
                    .route(Route::socks5(proxy))
                    .send()
                    .await?;
                assert_eq!(response.status(), 204);
                response.into_body().collect().await?;
            }
            drop(session);
            Ok(())
        }
        .await;

        let mut observed = match finish_socks_acquisition(operation, proxy_tasks).await {
            Ok(observed) => observed,
            Err(primary) => {
                return finish_with_cleanup(Err(primary), stop_socks_peer(origin).await);
            }
        };
        let origin_observation = origin.await??;

        observed.sort_by(|left, right| {
            left.authentication
                .username
                .cmp(&right.authentication.username)
        });
        assert_eq!(
            origin_observation,
            [
                vec!["/first".to_owned(), "/first-again".to_owned()],
                vec!["/second".to_owned()],
            ]
        );
        assert_eq!(observed.len(), 2);
        assert_remote_observation(
            observed.remove(0),
            "first-user",
            "first-password",
            origin_address.port(),
        );
        assert_remote_observation(
            observed.remove(0),
            "second-user",
            "second-password",
            origin_address.port(),
        );
        Ok(())
    })
    .await
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn websocket_authenticates_on_the_remote_dns_route() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let origin = ConnectionPeer::spawn(async move {
            let mut stream = accept_tls(origin_listener, acceptor).await?;
            let request = read_head(&mut stream).await?;
            let key = super::header_value(&request, "sec-websocket-key").ok_or("missing key")?;
            let accept = super::websocket_accept(key);
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\n\
                         Upgrade: websocket\r\n\
                         Connection: Upgrade\r\n\
                         Sec-WebSocket-Accept: {accept}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
            stream.flush().await?;
            let mut byte = [0_u8; 1];
            let read = tokio::io::AsyncReadExt::read(&mut stream, &mut byte).await?;
            if read != 0 {
                return Err("WebSocket sent unexpected data before drop".into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
        });

        let proxy = ConnectionPeer::spawn(forward_one_authenticated_socks5(
            proxy_listener,
            origin_address,
        ));
        let operation: TestResult<()> = async {
            let route = authenticated_route("socks5h", proxy_address)?;
            let client = client_builder(&identity, false).route(route).build()?;
            let socket = client
                .websocket(&format!(
                    "wss://{ORIGIN_NAME}:{}/events",
                    origin_address.port()
                ))?
                .connect()
                .await?;
            drop(socket);
            drop(client);
            Ok(())
        }
        .await;

        let (origin_observation, proxy_observation) =
            finish_socks_route(operation, origin, proxy).await?;

        assert!(origin_observation.starts_with(b"GET /events HTTP/1.1\r\n"));
        assert_remote_observation(proxy_observation, USERNAME, PASSWORD, origin_address.port());
        Ok(())
    })
    .await
}

async fn serve_two_http2_connections(
    listener: TcpListener,
    acceptor: SslAcceptor,
) -> TestResult<[Vec<String>; 2]> {
    let mut handlers = JoinSet::new();
    let acquisition = async {
        for _ in 0..2 {
            let stream = accept_socks_http2_connection(&listener, &acceptor).await?;
            handlers.spawn(async move {
                let mut connection = ::http2::server::handshake(stream).await?;
                let mut paths = Vec::new();
                while let Some(request) = connection.accept().await {
                    let (request, mut respond) = request?;
                    paths.push(request.uri().path().to_owned());
                    respond.send_response(Response::builder().status(204).body(())?, true)?;
                }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(paths)
            });
        }
        Ok(())
    }
    .await;

    let mut connections = finish_socks_acquisition(acquisition, handlers).await?;
    connections.sort_by(|left, right| left.first().cmp(&right.first()));
    connections
        .try_into()
        .map_err(|_| "origin did not observe two isolated connections".into())
}

#[tokio::test]
async fn plaintext_http1_authenticates_before_remote_dns_connect() -> TestResult<()> {
    bounded(async {
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let origin = ConnectionPeer::spawn(async move {
            let (mut stream, _) = origin_listener.accept().await?;
            let request = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nauth")
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(request)
        });

        let proxy = ConnectionPeer::spawn(forward_one_authenticated_socks5(
            proxy_listener,
            origin_address,
        ));
        let operation: TestResult<()> = async {
            let identity = TestIdentity::generate_for_dns(ORIGIN_NAME)?;
            let client = client_builder(&identity, false)
                .route(authenticated_route("socks5h", proxy_address)?)
                .build()?;

            let response = client
                .get(
                    HttpProtocol::Http1,
                    &format!(
                        "http://{ORIGIN_NAME}:{}/authenticated",
                        origin_address.port()
                    ),
                )?
                .send()
                .await?;
            assert_eq!(response.status(), 200);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "auth");
            drop(client);
            Ok(())
        }
        .await;

        let (origin_observation, proxy_observation) =
            finish_socks_route(operation, origin, proxy).await?;

        assert!(origin_observation.starts_with(b"GET /authenticated HTTP/1.1\r\n"));
        assert_remote_observation(proxy_observation, USERNAME, PASSWORD, origin_address.port());
        Ok(())
    })
    .await
}

pub(super) async fn accept_socks_http2_connection(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<tokio::net::TcpStream>> {
    let (tcp, _) = listener.accept().await?;
    let ssl = Ssl::new(acceptor.context())?;
    let mut stream = SslStream::new(ssl, tcp)?;
    Pin::new(&mut stream).accept().await?;
    Ok(stream)
}

pub(super) async fn finish_socks_acquisition<T: 'static>(
    acquisition: TestResult<()>,
    handlers: JoinSet<TestResult<T>>,
) -> TestResult<Vec<T>> {
    collect_socks_handlers(acquisition, handlers).await
}

pub(super) async fn finish_socks_handlers<T: 'static>(
    handlers: JoinSet<TestResult<T>>,
) -> TestResult<Vec<T>> {
    collect_socks_handlers(Ok(()), handlers).await
}

async fn collect_socks_handlers<T: 'static>(
    mut operation: TestResult<()>,
    mut handlers: JoinSet<TestResult<T>>,
) -> TestResult<Vec<T>> {
    let mut observed = Vec::new();
    if operation.is_ok() {
        while let Some(completed) = handlers.join_next().await {
            match completed {
                Ok(Ok(value)) => observed.push(value),
                Ok(Err(error)) => operation = Err(error),
                Err(error) => operation = Err(error.into()),
            }
            if operation.is_err() {
                break;
            }
        }
    }

    if operation.is_err() {
        // Observe completed failures before this owner requests cancellation.
        while let Some(completed) = handlers.try_join_next() {
            let result = match completed {
                Ok(result) => result.map(|value| observed.push(value)),
                Err(error) => Err(error.into()),
            };
            operation = finish_with_cleanup(operation, result);
        }

        handlers.abort_all();
        let deadline = Instant::now() + TEST_TIMEOUT;
        loop {
            match timeout_at(deadline, handlers.join_next()).await {
                Ok(None) => break,
                Ok(Some(Err(error))) if error.is_cancelled() => {}
                Ok(Some(completed)) => {
                    let result = match completed {
                        Ok(result) => result.map(|value| observed.push(value)),
                        Err(error) => Err(error.into()),
                    };
                    operation = finish_with_cleanup(operation, result);
                }
                Err(cause) => {
                    operation = finish_with_cleanup(operation, Err(HandlerDeadline(cause).into()));
                    // Keep outcomes already available at the deadline. JoinSet
                    // remains the abort owner for children that have not joined.
                    while let Some(completed) = handlers.try_join_next() {
                        match completed {
                            Err(error) if error.is_cancelled() => {}
                            completed => {
                                let result = match completed {
                                    Ok(result) => result.map(|value| observed.push(value)),
                                    Err(error) => Err(error.into()),
                                };
                                operation = finish_with_cleanup(operation, result);
                            }
                        }
                    }
                    break;
                }
            }
        }
    }

    operation.map(|()| observed)
}

#[derive(Debug)]
struct HandlerDeadline(tokio::time::error::Elapsed);

impl fmt::Display for HandlerDeadline {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "SOCKS5 handler cleanup exceeded its deadline: {}",
            self.0
        )
    }
}

impl Error for HandlerDeadline {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.0)
    }
}

fn authenticated_route(scheme: &str, proxy: std::net::SocketAddr) -> TestResult<Route> {
    Ok(Route::socks5(
        Socks5Proxy::new(&format!("{scheme}://{proxy}"))?
            .with_username_password(USERNAME, PASSWORD)?,
    ))
}

fn assert_remote_observation(
    observed: ObservedAuthenticatedSocks5Connect,
    username: &str,
    password: &str,
    port: u16,
) {
    assert_eq!(
        observed.authentication,
        ObservedSocks5Authentication {
            username: username.to_owned(),
            password: password.to_owned(),
        }
    );
    assert_eq!(observed.connect.host, ORIGIN_NAME);
    assert_eq!(observed.connect.port, port);
}
