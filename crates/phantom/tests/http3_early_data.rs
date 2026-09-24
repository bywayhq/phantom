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

use std::{
    collections::HashMap,
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    BuildErrorKind, Client, HttpProtocol,
    profile::{ClientProfile, Http3ClientSettings},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle, time::timeout};

use h3_support::client_settings;
use tls_support::{TestIdentity, TestResult, tls_settings};

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
            .http3_early_data()
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
        .http3_early_data()
        .build()?;
    Ok(client)
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "HTTP/3 early-data test exceeded its deadline")?
}
