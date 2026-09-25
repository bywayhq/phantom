//! Public QUIC session-resumption integration tests.
//!
//! The server counts the tickets clients present through its session store,
//! so each test observes resumption from the peer's side of the wire.

#[allow(dead_code)]
#[path = "support/h3.rs"]
mod h3_support;
#[allow(dead_code)]
#[path = "support/masque.rs"]
mod masque_support;
#[allow(dead_code)]
#[path = "support/socks5_udp.rs"]
mod socks5_udp_support;
#[allow(dead_code)]
#[path = "support/tls.rs"]
mod tls_support;

use std::{
    collections::{BTreeMap, HashMap},
    future::Future,
    net::{Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{Response, StatusCode};
use http_body_util::BodyExt;
use phantom::{
    Client, ConnectUdpProxy, HttpProtocol, Route, Socks5Proxy,
    profile::{ClientProfile, Http3ClientSettings},
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ServerSessionMemoryCache, StoresServerSessions};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::mpsc,
    task::JoinHandle,
    time::timeout,
};

use h3_support::client_settings;
use masque_support::{MasqueProxy, ProxyMode, extended_request_settings};
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

impl CountingStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: ServerSessionMemoryCache::new(64),
            presented: AtomicUsize::new(0),
            accepted: AtomicUsize::new(0),
        })
    }

    fn counts(&self) -> Presented {
        Presented {
            presented: self.presented.load(Ordering::SeqCst),
            accepted: self.accepted.load(Ordering::SeqCst),
        }
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
        let store = CountingStore::new();
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
    let endpoint = quinn::Endpoint::server(
        server_config(identity, store, b"h3")?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    Ok((endpoint.local_addr()?, endpoint))
}

/// A QUIC server configuration offering only `alpn`, so a client that
/// requires `h3` fails its handshake against any other value.
fn server_config(
    identity: &TestIdentity,
    store: Arc<CountingStore>,
    alpn: &[u8],
) -> TestResult<quinn::ServerConfig> {
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], private_key)?;
    tls.alpn_protocols = vec![alpn.to_vec()];
    tls.session_storage = store;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

/// An HTTP/3 client whose QUIC TLS profile enables session tickets.
fn resuming_client(identity: &TestIdentity) -> TestResult<Client> {
    Ok(
        Client::builder(resuming_profile(client_settings().request().clone()))
            .add_root_certificate_der(identity.root_der.clone())
            .build()?,
    )
}

/// A profile whose H3 TLS settings enable session tickets, for the origin
/// and for an outer CONNECT-UDP proxy connection alike.
fn resuming_profile(request: phantom::profile::Http3RequestSettings) -> ClientProfile {
    let base = client_settings();
    let mut quic_tls = base.tls().clone();
    quic_tls.session_tickets = true;
    let http3 = Http3ClientSettings::new(
        quic_tls,
        base.quic_transport().clone(),
        base.http3().clone(),
        request,
    );
    let mut tcp_tls = tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    ClientProfile::new(tcp_tls).with_http3(http3)
}

async fn bounded<F>(future: F) -> TestResult<()>
where
    F: Future<Output = TestResult<()>>,
{
    timeout(TEST_TIMEOUT, future)
        .await
        .map_err(|_| "HTTP/3 resumption test exceeded its deadline")?
}

/// TLS `pre_shared_key`, which carries a presented session ticket.
const PRE_SHARED_KEY: u16 = 41;

/// How the handshake server answers each QUIC connection attempt, in order.
#[derive(Clone, Copy, Debug)]
enum Attempt {
    /// Complete the handshake and answer one request with `204`.
    Serve,
    /// Offer only a non-`h3` ALPN, so the client's handshake fails.
    FailHandshake,
}

/// A server that answers each connection attempt as scripted and closes
/// every served connection once the client has read its response.
struct ScriptedServer {
    address: SocketAddr,
    attempts: Arc<AtomicUsize>,
    read: mpsc::UnboundedSender<()>,
    drained: mpsc::UnboundedReceiver<()>,
    task: JoinHandle<TestResult<()>>,
}

impl ScriptedServer {
    fn spawn(identity: &TestIdentity, script: Vec<Attempt>) -> TestResult<Self> {
        let store = CountingStore::new();
        let (address, endpoint) = server_endpoint(identity, Arc::clone(&store))?;
        let failing = Arc::new(server_config(identity, store, b"not-h3")?);
        let attempts = Arc::new(AtomicUsize::new(0));
        let task_attempts = Arc::clone(&attempts);
        let (read, mut read_rx) = mpsc::unbounded_channel::<()>();
        let (drained_tx, drained) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            for attempt in script {
                let incoming = endpoint.accept().await.ok_or("HTTP/3 endpoint closed")?;
                task_attempts.fetch_add(1, Ordering::SeqCst);
                match attempt {
                    Attempt::FailHandshake => {
                        // Quinn fails the handshake while it processes the
                        // ClientHello, or later if that spans packets.
                        if let Ok(connecting) = incoming.accept_with(Arc::clone(&failing))
                            && connecting.await.is_ok()
                        {
                            return Err("a handshake without h3 ALPN completed".into());
                        }
                    }
                    Attempt::Serve => {
                        let (quic, connection) = serve_one(incoming).await?;
                        read_rx.recv().await.ok_or("client stopped")?;
                        quic.close(0u32.into(), b"served");
                        drop(connection);
                        endpoint.wait_idle().await;
                        let _ = drained_tx.send(());
                    }
                }
            }
            Ok(())
        });
        Ok(Self {
            address,
            attempts,
            read,
            drained,
            task,
        })
    }

    /// Lets the served connection close, and waits until it has drained so
    /// the next request needs a new connection.
    async fn close_served(&mut self) -> TestResult<()> {
        self.read.send(())?;
        self.drained.recv().await.ok_or("server stopped")?;
        Ok(())
    }

    fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
}

#[tokio::test]
async fn a_failed_resumed_handshake_is_repeated_once_without_a_ticket() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut server = ScriptedServer::spawn(
            &identity,
            vec![Attempt::Serve, Attempt::FailHandshake, Attempt::Serve],
        )?;
        let sniffer = HelloSniffer::spawn(server.address).await?;
        let session = resuming_client(&identity)?.session();
        let uri = format!("https://{}/", sniffer.address);

        send(session.get(HttpProtocol::Http3, &uri)?).await?;
        server.close_served().await?;
        // The second request presents the ticket, fails its handshake, and
        // completes on one repeated attempt over the same route.
        send(session.get(HttpProtocol::Http3, &uri)?).await?;
        server.close_served().await?;

        assert_eq!(server.attempts(), 3);
        let hellos = sniffer.hellos();
        let [fresh, resumed, retry] = hellos.as_slice() else {
            return Err(format!("expected three ClientHellos, saw {}", hellos.len()).into());
        };
        assert!(!fresh.contains(&PRE_SHARED_KEY));
        assert_eq!(resumed.last(), Some(&PRE_SHARED_KEY));
        assert!(!retry.contains(&PRE_SHARED_KEY));
        // Apart from the ticket, the repeated attempt makes the same offer.
        let without_ticket: Vec<u16> = resumed
            .iter()
            .copied()
            .filter(|extension| *extension != PRE_SHARED_KEY)
            .collect();
        assert_eq!(sorted(&without_ticket), sorted(retry));
        server.task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_repeated_handshake_that_fails_is_not_repeated_again() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let mut server = ScriptedServer::spawn(
            &identity,
            vec![
                Attempt::Serve,
                Attempt::FailHandshake,
                Attempt::FailHandshake,
            ],
        )?;
        let sniffer = HelloSniffer::spawn(server.address).await?;
        let session = resuming_client(&identity)?.session();
        let uri = format!("https://{}/", sniffer.address);

        send(session.get(HttpProtocol::Http3, &uri)?).await?;
        server.close_served().await?;
        let result = session.get(HttpProtocol::Http3, &uri)?.send().await;
        assert!(
            result.is_err(),
            "a failed repeated handshake produced a response"
        );

        assert_eq!(server.attempts(), 3);
        let hellos = sniffer.hellos();
        let presented: Vec<bool> = hellos
            .iter()
            .map(|hello| hello.contains(&PRE_SHARED_KEY))
            .collect();
        assert_eq!(presented, [false, true, false]);
        server.task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn a_failed_handshake_without_a_ticket_is_not_repeated() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let server = ScriptedServer::spawn(&identity, vec![Attempt::FailHandshake])?;
        let sniffer = HelloSniffer::spawn(server.address).await?;
        let session = resuming_client(&identity)?.session();
        let uri = format!("https://{}/", sniffer.address);

        let result = session.get(HttpProtocol::Http3, &uri)?.send().await;
        assert!(result.is_err(), "a failed handshake produced a response");

        // The request has failed, so any repeated attempt would already have
        // reached the server.
        assert_eq!(server.attempts(), 1);
        let hellos = sniffer.hellos();
        let [hello] = hellos.as_slice() else {
            return Err(format!("expected one ClientHello, saw {}", hellos.len()).into());
        };
        assert!(!hello.contains(&PRE_SHARED_KEY));
        server.task.await??;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn connect_udp_proxy_and_origin_tickets_stay_in_their_own_caches() -> TestResult<()> {
    bounded(async {
        let origin_identity = TestIdentity::generate()?;
        let proxy_identity = TestIdentity::generate()?;
        let origin_store = CountingStore::new();
        let proxy_store = CountingStore::new();
        let (origin, endpoint) = server_endpoint(&origin_identity, Arc::clone(&origin_store))?;
        let proxy = MasqueProxy::spawn_with_session_storage(
            &proxy_identity,
            ProxyMode::Relay,
            Some(proxy_store.clone()),
        )?;
        let (read_tx, mut read) = mpsc::unbounded_channel::<()>();
        let (served_tx, mut served) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let incoming = endpoint.accept().await.ok_or("HTTP/3 endpoint closed")?;
                let (quic, connection) = serve_one(incoming).await?;
                read.recv().await.ok_or("client stopped")?;
                quic.close(0u32.into(), b"served");
                drop(connection);
                endpoint.wait_idle().await;
                let _ = served_tx.send(());
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        });

        let client = Client::builder(resuming_profile(extended_request_settings()))
            .add_root_certificate_der(origin_identity.root_der.clone())
            .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
            .build()?;
        let session = client.session();
        let uri = format!("https://{origin}/");
        let route = Route::connect_udp(ConnectUdpProxy::new(&proxy.template())?);
        // The proxy and the origin share the server name `127.0.0.1`, so a
        // shared cache would present one server's ticket to the other.
        let mut through_proxy = async |session: &phantom::Session| -> TestResult<()> {
            send(session.get(HttpProtocol::Http3, &uri)?.route(route.clone())).await?;
            read_tx.send(())?;
            served.recv().await.ok_or("server stopped")?;
            Ok(())
        };

        through_proxy(&session).await?;
        let none = Presented {
            presented: 0,
            accepted: 0,
        };
        assert_eq!(origin_store.counts(), none);
        assert_eq!(proxy_store.counts(), none);

        // A new inner connection needs a new outer connection. Each presents
        // the ticket its own server issued, and each server accepts it.
        through_proxy(&session).await?;
        let one = Presented {
            presented: 1,
            accepted: 1,
        };
        assert_eq!(origin_store.counts(), one);
        assert_eq!(proxy_store.counts(), one);
        assert_eq!(proxy.connections(), 2);

        // A direct request is another route: nothing learned through the
        // proxy is presented to the origin directly.
        send(session.get(HttpProtocol::Http3, &uri)?.route(Route::Direct)).await?;
        read_tx.send(())?;
        served.recv().await.ok_or("server stopped")?;
        assert_eq!(origin_store.counts(), one);
        assert_eq!(proxy_store.counts(), one);

        server.await??;
        Ok(())
    })
    .await
}

fn sorted(extensions: &[u16]) -> Vec<u16> {
    let mut extensions = extensions.to_vec();
    extensions.sort_unstable();
    extensions
}

/// Completes one handshake and answers one request with `204`.
async fn serve_one(
    incoming: quinn::Incoming,
) -> TestResult<(
    quinn::Connection,
    h3::server::Connection<h3_quinn::Connection, Bytes>,
)> {
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

/// A UDP relay in front of a QUIC server that decrypts each client's
/// Initial packets and records the extension types of every ClientHello, in
/// the order the ClientHellos completed.
///
/// Initial packets are protected with keys every observer can derive from
/// the client's first Destination Connection ID (RFC 9001, section 5.2).
struct HelloSniffer {
    address: SocketAddr,
    hellos: Arc<Mutex<Vec<Vec<u16>>>>,
    task: JoinHandle<()>,
}

impl HelloSniffer {
    async fn spawn(server: SocketAddr) -> TestResult<Self> {
        let front = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
        let address = front.local_addr()?;
        let hellos = Arc::new(Mutex::new(Vec::new()));
        let task_hellos = Arc::clone(&hellos);
        let task = tokio::spawn(async move {
            let mut clients: HashMap<SocketAddr, Arc<UdpSocket>> = HashMap::new();
            let mut streams: HashMap<Vec<u8>, CryptoStream> = HashMap::new();
            let mut buffer = vec![0; 65_535];
            loop {
                let Ok((len, from)) = front.recv_from(&mut buffer).await else {
                    return;
                };
                let datagram = &buffer[..len];
                if let Some((dcid, frames)) = initial_crypto_frames(datagram) {
                    let stream = streams.entry(dcid).or_default();
                    if let Some(extensions) = stream.add(frames) {
                        lock(&task_hellos).push(extensions);
                    }
                }
                let back = match clients.get(&from) {
                    Some(back) => Arc::clone(back),
                    None => {
                        let Ok(back) = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await else {
                            return;
                        };
                        if back.connect(server).await.is_err() {
                            return;
                        }
                        let back = Arc::new(back);
                        tokio::spawn(forward_replies(Arc::clone(&back), Arc::clone(&front), from));
                        clients.insert(from, Arc::clone(&back));
                        back
                    }
                };
                let _ = back.send(datagram).await;
            }
        });
        Ok(Self {
            address,
            hellos,
            task,
        })
    }

    fn hellos(&self) -> Vec<Vec<u16>> {
        lock(&self.hellos).clone()
    }
}

impl Drop for HelloSniffer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn forward_replies(back: Arc<UdpSocket>, front: Arc<UdpSocket>, client: SocketAddr) {
    let mut buffer = vec![0; 65_535];
    loop {
        match back.recv(&mut buffer).await {
            Ok(len) => {
                let _ = front.send_to(&buffer[..len], client).await;
            }
            // Windows reports an earlier ICMP port-unreachable here.
            Err(error) if error.kind() == std::io::ErrorKind::ConnectionReset => {}
            Err(_) => return,
        }
    }
}

/// CRYPTO data of one connection's Initial packets, by offset.
#[derive(Default)]
struct CryptoStream {
    chunks: BTreeMap<u64, Vec<u8>>,
    complete: bool,
}

impl CryptoStream {
    /// Adds CRYPTO frames and returns the ClientHello's extension types the
    /// first time the whole message is present.
    fn add(&mut self, frames: CryptoFrames) -> Option<Vec<u16>> {
        if self.complete {
            return None;
        }
        self.chunks.extend(frames);
        let mut contiguous = Vec::new();
        for (offset, data) in &self.chunks {
            let offset = usize::try_from(*offset).ok()?;
            if offset > contiguous.len() {
                break;
            }
            let skip = contiguous.len() - offset;
            if let Some(rest) = data.get(skip..) {
                contiguous.extend_from_slice(rest);
            }
        }
        let header = contiguous.get(..4)?;
        let length =
            usize::from(header[1]) << 16 | usize::from(header[2]) << 8 | usize::from(header[3]);
        let message = contiguous.get(4..4 + length)?;
        self.complete = true;
        client_hello_extensions(message)
    }
}

/// CRYPTO frame data with its stream offsets, in packet order.
type CryptoFrames = Vec<(u64, Vec<u8>)>;

/// Decrypts the Initial packet that starts `datagram` and returns its
/// Destination Connection ID and CRYPTO frames.
fn initial_crypto_frames(datagram: &[u8]) -> Option<(Vec<u8>, CryptoFrames)> {
    use rustls::quic::{Keys, Version};

    let first = *datagram.first()?;
    // A QUIC v1 long-header Initial packet.
    if first & 0x80 == 0 || first & 0x30 != 0 || datagram.get(1..5)? != [0, 0, 0, 1] {
        return None;
    }
    let mut offset = 5;
    let dcid_len = usize::from(*datagram.get(offset)?);
    let dcid = datagram.get(offset + 1..offset + 1 + dcid_len)?.to_vec();
    offset += 1 + dcid_len;
    offset += 1 + usize::from(*datagram.get(offset)?);
    let token_len = usize::try_from(read_varint(datagram, &mut offset)?).ok()?;
    offset += token_len;
    let length = usize::try_from(read_varint(datagram, &mut offset)?).ok()?;
    let pn_offset = offset;
    let mut packet = datagram.get(..pn_offset.checked_add(length)?)?.to_vec();

    let suite = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256.tls13()?;
    let keys = Keys::initial(Version::V1, suite, suite.quic?, &dcid, rustls::Side::Server);
    let sample_len = keys.remote.header.sample_len();
    let sample = packet
        .get(pn_offset + 4..pn_offset + 4 + sample_len)?
        .to_vec();
    let (head, rest) = packet.split_at_mut(pn_offset);
    keys.remote
        .header
        .decrypt_in_place(&sample, head.first_mut()?, rest.get_mut(..4)?)
        .ok()?;
    let pn_len = usize::from(packet[0] & 0x03) + 1;
    let packet_number = packet
        .get(pn_offset..pn_offset + pn_len)?
        .iter()
        .fold(0_u64, |number, byte| number << 8 | u64::from(*byte));
    let (header, payload) = packet.split_at_mut(pn_offset + pn_len);
    let plain = keys
        .remote
        .packet
        .decrypt_in_place(packet_number, header, payload)
        .ok()?;

    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < plain.len() {
        match read_varint(plain, &mut offset)? {
            // PADDING and PING.
            0x00 | 0x01 => {}
            0x06 => {
                let data_offset = read_varint(plain, &mut offset)?;
                let data_len = usize::try_from(read_varint(plain, &mut offset)?).ok()?;
                let data = plain.get(offset..offset + data_len)?.to_vec();
                offset += data_len;
                frames.push((data_offset, data));
            }
            // A client's first flight carries nothing else before its
            // ClientHello is complete.
            _ => break,
        }
    }
    Some((dcid, frames))
}

fn read_varint(input: &[u8], offset: &mut usize) -> Option<u64> {
    let first = *input.get(*offset)?;
    let len = 1 << (first >> 6);
    let bytes = input.get(*offset..*offset + len)?;
    *offset += len;
    Some(
        bytes[1..]
            .iter()
            .fold(u64::from(first & 0x3f), |value, byte| {
                value << 8 | u64::from(*byte)
            }),
    )
}

/// Returns the extension types of a ClientHello body, in wire order.
fn client_hello_extensions(body: &[u8]) -> Option<Vec<u16>> {
    // legacy_version and random.
    let mut offset = 2 + 32;
    offset += 1 + usize::from(*body.get(offset)?);
    offset += 2 + usize::from(u16::from_be_bytes(
        body.get(offset..offset + 2)?.try_into().ok()?,
    ));
    offset += 1 + usize::from(*body.get(offset)?);
    let extensions_len = usize::from(u16::from_be_bytes(
        body.get(offset..offset + 2)?.try_into().ok()?,
    ));
    offset += 2;
    let end = offset + extensions_len;
    let mut extensions = Vec::new();
    while offset < end {
        extensions.push(u16::from_be_bytes(
            body.get(offset..offset + 2)?.try_into().ok()?,
        ));
        let len = usize::from(u16::from_be_bytes(
            body.get(offset + 2..offset + 4)?.try_into().ok()?,
        ));
        offset += 4 + len;
    }
    Some(extensions)
}

fn lock<T>(value: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    value
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}
