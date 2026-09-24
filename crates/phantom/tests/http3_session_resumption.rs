//! Public QUIC session-resumption integration tests.
//!
//! The server counts the tickets clients present through its session store,
//! so each test observes resumption from the peer's side of the wire.

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/socks5_udp.rs"]
mod socks5_udp_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, HttpProtocol, Route, Socks5Proxy,
    profile::{ClientProfile, Http3ClientSettings},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ServerSessionMemoryCache, StoresServerSessions};
use tokio::{net::TcpListener, sync::mpsc, time::timeout};

use h3_support::client_settings;
use socks5_udp_support::forward_one_socks5_udp_associate;
use tls_support::{TestIdentity, TestResult, tls_settings};

const TEST_TIMEOUT: Duration = Duration::from_secs(20);

/// A stateful ticket store that counts presented and accepted tickets.
#[derive(Debug)]
struct CountingStore {
    inner: Arc<ServerSessionMemoryCache>,
    presented: AtomicUsize,
    accepted: AtomicUsize,
}

impl StoresServerSessions for CountingStore {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.inner.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }

    // rustls looks up every TLS 1.3 ticket a client presents with `take`.
    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.presented.fetch_add(1, Ordering::SeqCst);
        let value = self.inner.take(key);
        if value.is_some() {
            self.accepted.fetch_add(1, Ordering::SeqCst);
        }
        value
    }

    fn can_cache(&self) -> bool {
        self.inner.can_cache()
    }
}

/// Tickets presented and accepted when a connection was served.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Presented {
    presented: usize,
    accepted: usize,
}

#[tokio::test]
async fn resumption_stays_on_the_origin_and_route_that_learned_the_ticket() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let store = Arc::new(CountingStore {
            inner: ServerSessionMemoryCache::new(64),
            presented: AtomicUsize::new(0),
            accepted: AtomicUsize::new(0),
        });
        let (origin, endpoint) = server_endpoint(&identity, Arc::clone(&store))?;
        let (served_tx, mut served) = mpsc::unbounded_channel();
        let (read_tx, mut read) = mpsc::unbounded_channel::<()>();
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (quic, connection) = serve_one_connection(&endpoint).await?;
                // Every served connection is closed once the client has read
                // its response, and drained, so the next request needs a new
                // connection.
                read.recv().await.ok_or("client stopped")?;
                quic.close(0u32.into(), b"served");
                drop(connection);
                endpoint.wait_idle().await;
                let _ = served_tx.send(Presented {
                    presented: store.presented.load(Ordering::SeqCst),
                    accepted: store.accepted.load(Ordering::SeqCst),
                });
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = listener.local_addr()?;
        let proxy = tokio::spawn(forward_one_socks5_udp_associate(listener, origin));
        let route = Route::socks5(Socks5Proxy::new(&format!("socks5://{proxy_address}"))?);

        let session = resuming_client(&identity)?.session();
        let uri = format!("https://{origin}/");

        send(session.get(HttpProtocol::Http3, &uri)?).await?;
        read_tx.send(())?;
        let first = served.recv().await.ok_or("server stopped")?;
        assert_eq!(
            first,
            Presented {
                presented: 0,
                accepted: 0
            }
        );

        // The same origin through a proxy is another pool entry: the ticket
        // learned directly is not presented through the proxy.
        send(session.get(HttpProtocol::Http3, &uri)?.route(route)).await?;
        read_tx.send(())?;
        let proxied = served.recv().await.ok_or("server stopped")?;
        assert_eq!(proxied, first);

        // Back on the direct route the retained ticket resumes the session.
        send(session.get(HttpProtocol::Http3, &uri)?).await?;
        read_tx.send(())?;
        let resumed = served.recv().await.ok_or("server stopped")?;
        assert_eq!(
            resumed,
            Presented {
                presented: 1,
                accepted: 1
            }
        );

        server.await??;
        // The association ends when the client drops its pooled connection.
        drop(session);
        let relay = proxy.await??;
        assert!(relay.client_datagrams > 0 && relay.origin_datagrams > 0);
        Ok(())
    })
    .await
}

async fn send(request: phantom::RequestBuilder) -> TestResult<()> {
    let response = request.send().await?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    response.into_body().collect().await?;
    Ok(())
}

/// Serves one request on the next connection and returns that connection.
async fn serve_one_connection(
    endpoint: &quinn::Endpoint,
) -> TestResult<(
    quinn::Connection,
    h3::server::Connection<h3_quinn::Connection, Bytes>,
)> {
    let incoming = endpoint.accept().await.ok_or("HTTP/3 endpoint closed")?;
    let quic = incoming.await?;
    let mut connection =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(quic.clone())).await?;
    let resolver = connection
        .accept()
        .await?
        .ok_or("HTTP/3 connection closed before its request")?;
    let (_, mut stream) = resolver.resolve_request().await?;
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(())?,
        )
        .await?;
    stream.finish().await?;
    Ok((quic, connection))
}

fn server_endpoint(
    identity: &TestIdentity,
    store: Arc<CountingStore>,
) -> TestResult<(SocketAddr, quinn::Endpoint)> {
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.session_storage = store;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let endpoint = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(crypto)),
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    Ok((endpoint.local_addr()?, endpoint))
}

/// An HTTP/3 client whose QUIC TLS profile enables session tickets.
fn resuming_client(identity: &TestIdentity) -> TestResult<Client> {
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
    Ok(
        Client::builder(ClientProfile::new(tcp_tls).with_http3(http3))
            .add_root_certificate_der(identity.root_der.clone())
            .build()?,
    )
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "HTTP/3 resumption test exceeded its deadline")?
}
