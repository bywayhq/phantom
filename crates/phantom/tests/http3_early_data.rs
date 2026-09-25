//! Public HTTP/3 early-data integration tests.
//!
//! A relay holds every server datagram briefly, so a new resumed connection
//! always sends its first request before its handshake can complete.

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;
#[path = "support/tracing.rs"]
mod tracing_support;

use std::{
    collections::HashMap,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::{Buf, Bytes};
use http::{Method, Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    BuildErrorKind, Client, HttpProtocol, RequestErrorKind, RequestTimeouts, TimeoutPhase,
    profile::{ClientProfile, Http3ClientSettings, chromium},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle, time::timeout};
use tracing::instrument::WithSubscriber;

use h3_support::client_settings;
use tls_support::{TestIdentity, TestResult, tls_settings};
use tracing_support::OutcomeSubscriber;

const TEST_TIMEOUT: Duration = Duration::from_secs(20);
const RELAY_DELAY: Duration = Duration::from_millis(150);

#[tokio::test]
async fn rejected_early_data_is_sent_again_after_a_handshake() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let endpoint = quinn::Endpoint::server(
            server_config(&identity, true)?,
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let (relay, relay_task) = delaying_relay(endpoint.local_addr()?).await?;
        let (served_tx, mut served) = mpsc::unbounded_channel();
        let (read_tx, mut read) = mpsc::unbounded_channel::<()>();
        let declining = server_config(&identity, false)?;
        let server = tokio::spawn(async move {
            // The first connection learns a ticket; the second resumes with
            // early data the server accepts.
            for _ in 0..2 {
                let path = serve_then_close(&endpoint, &mut read).await?;
                let _ = served_tx.send(path);
            }
            // The server now declines early data, as after a key rotation.
            endpoint.set_server_config(Some(declining));
            let _ = served_tx.send(String::new());
            // The rejected connection carries no processed request.
            let rejected = endpoint.accept().await.ok_or("endpoint closed")?;
            let rejected = tokio::spawn(async move {
                let connection = rejected.await?;
                let mut connection =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                        .await?;
                let unexpected = connection.accept().await.ok().flatten().is_some();
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(unexpected)
            });
            let path = serve_then_close(&endpoint, &mut read).await?;
            let _ = served_tx.send(path);
            let unexpected = match timeout(Duration::from_secs(1), rejected).await {
                Ok(joined) => joined?.unwrap_or(false),
                Err(_) => false,
            };
            if unexpected {
                return Err("the rejected connection delivered a request".into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let session = early_data_client(&identity)?.session();
        for path in ["/first", "/early"] {
            send(&session, relay, path).await?;
            read_tx.send(())?;
            assert_eq!(served.recv().await.ok_or("server stopped")?, path);
        }
        assert_eq!(served.recv().await.ok_or("server stopped")?, "");

        send(&session, relay, "/rejected").await?;
        read_tx.send(())?;
        assert_eq!(served.recv().await.ok_or("server stopped")?, "/rejected");

        server.await??;
        drop(session);
        relay_task.abort();
        Ok(())
    })
    .await
}

#[test]
fn early_data_requires_http3_session_tickets() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut tcp_tls = tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let without_tickets =
        Client::builder(ClientProfile::new(tcp_tls).with_http3(client_settings()))
            .add_root_certificate_der(identity.root_der.clone())
            .http3_early_data(true)
            .build();
    let error = without_tickets
        .err()
        .ok_or("early data was accepted without session tickets")?;
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    Ok(())
}

async fn send(session: &Client, relay: SocketAddr, path: &str) -> TestResult<()> {
    let response = session
        .get(HttpProtocol::Http3, &format!("https://{relay}{path}"))?
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await?;
    Ok(())
}

/// Serves one request on the next connection, waits until the client read
/// the response, then closes the connection and waits until every server
/// connection has drained.
async fn serve_then_close(
    endpoint: &quinn::Endpoint,
    read: &mut mpsc::UnboundedReceiver<()>,
) -> TestResult<String> {
    let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
    let quic = incoming.await?;
    let mut connection =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(quic.clone())).await?;
    let resolver = connection
        .accept()
        .await?
        .ok_or("connection closed before its request")?;
    let (request, mut stream) = resolver.resolve_request().await?;
    stream
        .send_response(Response::builder().status(StatusCode::OK).body(())?)
        .await?;
    stream.finish().await?;
    read.recv().await.ok_or("client stopped")?;
    quic.close(0u32.into(), b"served");
    drop(connection);
    // Once drained, the client has seen the close and cannot reuse it.
    endpoint.wait_idle().await;
    Ok(request.uri().path().to_owned())
}

fn server_config(identity: &TestIdentity, early_data: bool) -> TestResult<quinn::ServerConfig> {
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    // QUIC permits only 0 or 0xffffffff here (RFC 9001, section 4.6.1).
    tls.max_early_data_size = if early_data { u32::MAX } else { 0 };
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

/// Forwards each client socket's datagrams to `server` at once and the
/// server's replies after [`RELAY_DELAY`], one upstream socket per client.
async fn delaying_relay(server: SocketAddr) -> TestResult<(SocketAddr, JoinHandle<()>)> {
    let front = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
    let address = front.local_addr()?;
    let task = tokio::spawn(async move {
        let mut upstreams: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
        let mut datagram = vec![0; 65_535];
        let mut downstream_tasks = Vec::new();
        while let Ok((len, client)) = front.recv_from(&mut datagram).await {
            let upstream = match upstreams.get(&client) {
                Some(upstream) => Arc::clone(upstream),
                None => {
                    let Ok(upstream) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await else {
                        return;
                    };
                    if upstream.connect(server).await.is_err() {
                        return;
                    }
                    let upstream = Arc::new(upstream);
                    upstreams.insert(client, Arc::clone(&upstream));
                    downstream_tasks.push(tokio::spawn(forward_delayed(
                        Arc::clone(&upstream),
                        Arc::clone(&front),
                        client,
                    )));
                    upstream
                }
            };
            let _ = upstream.send(&datagram[..len]).await;
        }
    });
    Ok((address, task))
}

async fn forward_delayed(upstream: Arc<UdpSocket>, front: Arc<UdpSocket>, client: SocketAddr) {
    let mut datagram = vec![0; 65_535];
    while let Ok(len) = upstream.recv(&mut datagram).await {
        let front = Arc::clone(&front);
        let bytes = datagram[..len].to_vec();
        tokio::spawn(async move {
            tokio::time::sleep(RELAY_DELAY).await;
            let _ = front.send_to(&bytes, client).await;
        });
    }
}

/// An HTTP/3 client with session tickets and early data enabled.
fn early_data_client(identity: &TestIdentity) -> TestResult<Client> {
    let base = client_settings();
    let mut quic_tls = base.tls().clone();
    quic_tls.session_tickets = true;
    let http3 = Http3ClientSettings::new(
        quic_tls,
        base.quic_transport().clone(),
        base.http3().clone(),
        base.request().clone(),
    );
    let mut tcp_tls = tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    let client = Client::builder(ClientProfile::new(tcp_tls).with_http3(http3))
        .add_root_certificate_der(identity.root_der.clone())
        .http3_early_data(true)
        .build()?;
    Ok(client)
}

/// With the Chrome 154 recipes and no caller setting, a resumed connection
/// sends a replay-safe `GET` as early data, while a `POST` that opens a
/// resumed connection waits for the handshake, as the captured browsers do.
///
/// A gate holds every server datagram, so no handshake can complete while it
/// is closed. The `GET` must reach the server through the closed gate, so it
/// left in 0-RTT packets; the `POST` must not. The gate also holds the
/// server's SETTINGS, which the recipe's dynamic QPACK policy waits for: the
/// `GET` is encoded with the SETTINGS remembered with the ticket.
#[tokio::test]
async fn resumed_connection_sends_get_early_and_holds_post() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let endpoint = quinn::Endpoint::server(
            server_config(&identity, true)?,
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let (gate, gate_open) = tokio::sync::watch::channel(true);
        let (relay, relay_task) = gated_relay(endpoint.local_addr()?, gate_open).await?;
        let (arrived_tx, mut arrived) = mpsc::unbounded_channel();
        let (read_tx, mut read) = mpsc::unbounded_channel::<()>();
        let (closed_tx, mut closed) = mpsc::unbounded_channel::<()>();
        let server_gate = gate.subscribe();
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let mut connecting = endpoint.accept().await.ok_or("endpoint closed")?.accept()?;
                // The client's transport parameters, which set how many
                // streams the server may open, arrive with its ClientHello.
                connecting.handshake_data().await?;
                // Serving before the handshake completes (0.5-RTT) lets the
                // server read early data while the gate holds its replies.
                let quic = match connecting.into_0rtt() {
                    Ok((connection, _accepted)) => connection,
                    Err(connecting) => connecting.await?,
                };
                let mut connection = h3::server::Connection::<_, Bytes>::new(
                    h3_quinn::Connection::new(quic.clone()),
                )
                .await?;
                let resolver = connection
                    .accept()
                    .await?
                    .ok_or("connection closed before its request")?;
                let (request, mut stream) = resolver.resolve_request().await?;
                // Whether the client could have completed its handshake.
                let gate_was_open = *server_gate.borrow();
                let _ = arrived_tx.send((request.uri().path().to_owned(), gate_was_open));
                while stream.recv_data().await?.is_some() {}
                stream
                    .send_response(Response::builder().status(StatusCode::OK).body(())?)
                    .await?;
                stream.finish().await?;
                read.recv().await.ok_or("client stopped")?;
                quic.close(0u32.into(), b"served");
                drop(connection);
                // Once drained, the client has seen the close and cannot
                // reuse the connection.
                endpoint.wait_idle().await;
                let _ = closed_tx.send(());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let client = Client::builder(chrome_profile())
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        let subscriber = OutcomeSubscriber::default();

        // A full handshake learns a ticket that permits early data.
        send_with(client.clone(), Method::GET, relay, "/first")
            .with_subscriber(subscriber.dispatch())
            .await?;
        read_tx.send(())?;
        assert_eq!(arrived.recv().await, Some(("/first".to_owned(), true)));
        closed.recv().await.ok_or("server stopped")?;

        for (method, path, early) in [
            (Method::GET, "/early", true),
            (Method::POST, "/post", false),
        ] {
            gate.send_replace(false);
            let request = tokio::spawn(
                send_with(client.clone(), method, relay, path)
                    .with_subscriber(subscriber.dispatch()),
            );
            if early {
                assert_eq!(arrived.recv().await, Some((path.to_owned(), false)));
                gate.send_replace(true);
            } else {
                tokio::time::sleep(RELAY_DELAY * 2).await;
                assert!(
                    arrived.try_recv().is_err(),
                    "{path} arrived before the handshake"
                );
                gate.send_replace(true);
                assert_eq!(arrived.recv().await, Some((path.to_owned(), true)));
            }
            request.await??;
            read_tx.send(())?;
            closed.recv().await.ok_or("server stopped")?;
        }

        // The POST's connection offered early data and waited for it to settle.
        assert_eq!(
            subscriber.early_data_for("http3.response_head"),
            ["none", "sent", "after_handshake"]
        );
        server.await??;
        drop(client);
        relay_task.abort();
        Ok(())
    })
    .await
}

/// `http3_early_data(false)` overrides the recipe: a resumed connection
/// sends no early data.
#[tokio::test]
async fn a_caller_can_turn_off_the_recipe_early_data() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let endpoint = quinn::Endpoint::server(
            server_config(&identity, true)?,
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let (relay, relay_task) = delaying_relay(endpoint.local_addr()?).await?;
        let (served_tx, mut served) = mpsc::unbounded_channel();
        let (read_tx, mut read) = mpsc::unbounded_channel::<()>();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let path = serve_then_close(&endpoint, &mut read).await?;
                let _ = served_tx.send(path);
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let client = Client::builder(chrome_profile())
            .add_root_certificate_der(identity.root_der.clone())
            .http3_early_data(false)
            .build()?;
        let subscriber = OutcomeSubscriber::default();
        for path in ["/first", "/resumed"] {
            send(&client, relay, path)
                .with_subscriber(subscriber.dispatch())
                .await?;
            read_tx.send(())?;
            assert_eq!(served.recv().await.ok_or("server stopped")?, path);
        }
        assert_eq!(
            subscriber.early_data_for("http3.response_head"),
            ["none", "none"]
        );

        server.await??;
        drop(client);
        relay_task.abort();
        Ok(())
    })
    .await
}

/// The named Chrome 154 recipes, with HTTP/3.
fn chrome_profile() -> ClientProfile {
    ClientProfile::new(chromium::v154_tls()).with_http3(Http3ClientSettings::new(
        chromium::v154_http3_tls(),
        chromium::v154_quic(),
        chromium::v154_http3(),
        chromium::v154_http3_request(),
    ))
}

async fn send_with(
    client: Client,
    method: Method,
    relay: SocketAddr,
    path: &'static str,
) -> TestResult<()> {
    let request = client.request(
        HttpProtocol::Http3,
        method.clone(),
        &format!("https://{relay}{path}"),
    )?;
    let request = if method == Method::POST {
        request.body(Bytes::from_static(b"not replay-safe"))
    } else {
        request
    };
    let response = request.send().await?;
    assert_eq!(response.status(), StatusCode::OK);
    response.into_body().collect().await?;
    Ok(())
}

/// Forwards client datagrams to `server` at once, and server datagrams only
/// while `open` holds `true`; datagrams held while it is `false` follow in
/// order once it opens.
async fn gated_relay(
    server: SocketAddr,
    open: tokio::sync::watch::Receiver<bool>,
) -> TestResult<(SocketAddr, JoinHandle<()>)> {
    let front = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
    let address = front.local_addr()?;
    let task = tokio::spawn(async move {
        let mut upstreams: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
        let mut datagram = vec![0; 65_535];
        while let Ok((len, client)) = front.recv_from(&mut datagram).await {
            let upstream = match upstreams.get(&client) {
                Some(upstream) => Arc::clone(upstream),
                None => {
                    let Ok(upstream) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await else {
                        return;
                    };
                    if upstream.connect(server).await.is_err() {
                        return;
                    }
                    let upstream = Arc::new(upstream);
                    upstreams.insert(client, Arc::clone(&upstream));
                    tokio::spawn(forward_gated(
                        Arc::clone(&upstream),
                        Arc::clone(&front),
                        client,
                        open.clone(),
                    ));
                    upstream
                }
            };
            let _ = upstream.send(&datagram[..len]).await;
        }
    });
    Ok((address, task))
}

async fn forward_gated(
    upstream: Arc<UdpSocket>,
    front: Arc<UdpSocket>,
    client: SocketAddr,
    mut open: tokio::sync::watch::Receiver<bool>,
) {
    let mut held = std::collections::VecDeque::new();
    let mut datagram = vec![0; 65_535];
    loop {
        tokio::select! {
            received = upstream.recv(&mut datagram) => {
                let Ok(len) = received else { return };
                held.push_back(datagram[..len].to_vec());
            }
            changed = open.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
        if *open.borrow() {
            while let Some(bytes) = held.pop_front() {
                let _ = front.send_to(&bytes, client).await;
            }
        }
    }
}

/// A `POST` that opens a resumed connection offers early data but waits for
/// the handshake. When the server rejects the early data, the `POST` is sent
/// on a new connection with its whole body.
#[tokio::test]
async fn rejected_early_data_resends_a_post_with_its_body() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let endpoint = quinn::Endpoint::server(
            server_config(&identity, true)?,
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let address = endpoint.local_addr()?;
        let (served_tx, mut served) = mpsc::unbounded_channel();
        let (read_tx, mut read) = mpsc::unbounded_channel::<()>();
        let declining = server_config(&identity, false)?;
        let server = tokio::spawn(async move {
            let first = serve_body_then_close(&endpoint, &mut read).await?;
            let _ = served_tx.send(first);
            // The server now declines early data, as after a key rotation.
            endpoint.set_server_config(Some(declining));
            let rejected = endpoint.accept().await.ok_or("endpoint closed")?;
            let rejected = tokio::spawn(async move {
                let connection = rejected.await?;
                let mut connection =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                        .await?;
                let unexpected = connection.accept().await.ok().flatten().is_some();
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(unexpected)
            });
            let resent = serve_body_then_close(&endpoint, &mut read).await?;
            let _ = served_tx.send(resent);
            let unexpected = match timeout(Duration::from_secs(1), rejected).await {
                Ok(joined) => joined?.unwrap_or(false),
                Err(_) => false,
            };
            if unexpected {
                return Err("the rejected connection delivered a request".into());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let client = Client::builder(chrome_profile())
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        send(&client, address, "/first").await?;
        read_tx.send(())?;
        assert_eq!(
            served.recv().await.ok_or("server stopped")?,
            ("/first".to_owned(), Vec::new())
        );

        let body = b"a body that must arrive whole".to_vec();
        let response = client
            .request(
                HttpProtocol::Http3,
                Method::POST,
                &format!("https://{address}/post"),
            )?
            .body(Bytes::from(body.clone()))
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        response.into_body().collect().await?;
        read_tx.send(())?;
        assert_eq!(
            served.recv().await.ok_or("server stopped")?,
            ("/post".to_owned(), body)
        );

        server.await??;
        Ok(())
    })
    .await
}

/// A resumed connection whose handshake fails after it sent early data fails
/// the request that is waiting on it, without a second connection.
#[tokio::test]
async fn failed_early_data_handshake_is_an_error_without_a_second_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let untrusted = TestIdentity::generate()?;
        let endpoint = quinn::Endpoint::server(
            server_config(&identity, true)?,
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let address = endpoint.local_addr()?;
        let (read_tx, mut read) = mpsc::unbounded_channel::<()>();
        let (learned_tx, learned) = tokio::sync::oneshot::channel();
        let incoming = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&incoming);
        let untrusted_config = server_config(&untrusted, true)?;
        let server = tokio::spawn(async move {
            serve_body_then_close(&endpoint, &mut read).await?;
            // A certificate the client does not trust fails the next
            // handshake after the client has sent its early data.
            endpoint.set_server_config(Some(untrusted_config));
            let _ = learned_tx.send(());
            while let Some(connecting) = endpoint.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let _ = connecting.await;
                });
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let client = Client::builder(chrome_profile())
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        send(&client, address, "/first").await?;
        read_tx.send(())?;
        learned.await?;

        let error = match client
            .request(
                HttpProtocol::Http3,
                Method::POST,
                &format!("https://{address}/post"),
            )?
            .body(Bytes::from_static(b"body"))
            .send()
            .await
        {
            Ok(_) => return Err("a failed handshake produced a response".into()),
            Err(error) => error,
        };
        assert_ne!(error.kind(), RequestErrorKind::Timeout);
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(incoming.load(Ordering::SeqCst), 1);

        server.abort();
        Ok(())
    })
    .await
}

/// The connect timeout bounds a request waiting for its connection's early
/// data to be answered.
#[tokio::test]
async fn connect_timeout_bounds_the_wait_for_early_data() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let endpoint = quinn::Endpoint::server(
            server_config(&identity, true)?,
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let (gate, gate_open) = tokio::sync::watch::channel(true);
        let (relay, relay_task) = gated_relay(endpoint.local_addr()?, gate_open).await?;
        let (read_tx, mut read) = mpsc::unbounded_channel::<()>();
        let (learned_tx, learned) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            serve_body_then_close(&endpoint, &mut read).await?;
            let _ = learned_tx.send(());
            while let Some(connecting) = endpoint.accept().await {
                tokio::spawn(async move {
                    let _ = connecting.await;
                });
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let client = Client::builder(chrome_profile())
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        send(&client, relay, "/first").await?;
        read_tx.send(())?;
        learned.await?;

        // The gate holds the server's replies, so the handshake cannot end.
        gate.send_replace(false);
        let error = match client
            .request(
                HttpProtocol::Http3,
                Method::POST,
                &format!("https://{relay}/post"),
            )?
            .body(Bytes::from_static(b"body"))
            .timeouts(RequestTimeouts::new().connect(Duration::from_millis(400)))
            .send()
            .await
        {
            Ok(_) => return Err("a held handshake produced a response".into()),
            Err(error) => error,
        };
        assert_eq!(error.kind(), RequestErrorKind::Timeout);
        assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Connect));

        gate.send_replace(true);
        server.abort();
        relay_task.abort();
        Ok(())
    })
    .await
}

/// Concurrent requests to a resumed origin share the connection whose early
/// data is still unanswered, as Chrome 154 put its six concurrent fetches on
/// one resumed connection, instead of each opening a connection.
#[tokio::test]
async fn concurrent_requests_share_one_resumed_connection() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let endpoint = quinn::Endpoint::server(
            server_config(&identity, true)?,
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let (relay, relay_task) = delaying_relay(endpoint.local_addr()?).await?;
        let (read_tx, mut read) = mpsc::unbounded_channel::<()>();
        let (learned_tx, learned) = tokio::sync::oneshot::channel();
        let connections = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&connections);
        let server = tokio::spawn(async move {
            serve_body_then_close(&endpoint, &mut read).await?;
            let _ = learned_tx.send(());
            while let Some(connecting) = endpoint.accept().await {
                counted.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(serve_every_request(connecting));
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let client = Client::builder(chrome_profile())
            .add_root_certificate_der(identity.root_der.clone())
            .build()?;
        send(&client, relay, "/first").await?;
        read_tx.send(())?;
        learned.await?;

        let mut requests = Vec::new();
        for method in [
            Method::GET,
            Method::HEAD,
            Method::OPTIONS,
            Method::POST,
            Method::PUT,
            Method::DELETE,
        ] {
            requests.push(tokio::spawn(send_with(
                client.clone(),
                method,
                relay,
                "/concurrent",
            )));
        }
        for request in requests {
            request.await??;
        }
        assert_eq!(connections.load(Ordering::SeqCst), 1);

        server.abort();
        relay_task.abort();
        Ok(())
    })
    .await
}

/// Serves every request on one connection with `200`, concurrently.
async fn serve_every_request(connecting: quinn::Incoming) {
    let Ok(quic) = connecting.await else {
        return;
    };
    let Ok(mut connection) =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(quic)).await
    else {
        return;
    };
    while let Ok(Some(resolver)) = connection.accept().await {
        tokio::spawn(async move {
            let Ok((_, mut stream)) = resolver.resolve_request().await else {
                return;
            };
            while let Ok(Some(_)) = stream.recv_data().await {}
            let Ok(response) = Response::builder().status(StatusCode::OK).body(()) else {
                return;
            };
            if stream.send_response(response).await.is_ok() {
                let _ = stream.finish().await;
            }
        });
    }
}

/// Serves one request on the next connection, returning its path and body,
/// then closes the connection as [`serve_then_close`] does.
async fn serve_body_then_close(
    endpoint: &quinn::Endpoint,
    read: &mut mpsc::UnboundedReceiver<()>,
) -> TestResult<(String, Vec<u8>)> {
    let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
    let quic = incoming.await?;
    let mut connection =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(quic.clone())).await?;
    let resolver = connection
        .accept()
        .await?
        .ok_or("connection closed before its request")?;
    let (request, mut stream) = resolver.resolve_request().await?;
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await? {
        while chunk.has_remaining() {
            let bytes = chunk.chunk();
            body.extend_from_slice(bytes);
            let len = bytes.len();
            chunk.advance(len);
        }
    }
    stream
        .send_response(Response::builder().status(StatusCode::OK).body(())?)
        .await?;
    stream.finish().await?;
    read.recv().await.ok_or("client stopped")?;
    quic.close(0u32.into(), b"served");
    drop(connection);
    endpoint.wait_idle().await;
    Ok((request.uri().path().to_owned(), body))
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "HTTP/3 early-data test exceeded its deadline")?
}
