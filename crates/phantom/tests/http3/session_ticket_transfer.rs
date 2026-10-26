//! Public QUIC ticket transfer through independently constructed clients.

use std::{
    net::{Ipv4Addr, SocketAddr},
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use futures_util::FutureExt as _;
use http::{Response, StatusCode, Version};
use http_body_util::BodyExt as _;
use phantom::{
    Client, HttpProtocol, Route, SessionTicketErrorKind, SessionTicketSnapshot,
    profile::{
        CipherSuite, ClientProfile, Http3ClientSettings, Http3QpackEncoding, SessionTickets,
    },
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::ProducesTickets,
};
use tokio::{sync::mpsc, time::timeout};

use crate::support::{
    h3 as h3_support,
    tls::{TestIdentity, TestResult, tls_settings},
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const DEADLINE: Duration = Duration::from_secs(20);

// A stateless server can accept the same authentic ticket from two clients.
// This makes source-cache preservation independently observable after import;
// it does not bypass either client's single-use queue or TLS binder validation.
#[derive(Debug)]
struct TicketOracle {
    inner: Arc<dyn ProducesTickets>,
    counts: Arc<OracleCounts>,
}

#[derive(Debug, Default)]
struct OracleCounts {
    presented: AtomicUsize,
    accepted: AtomicUsize,
}

impl TicketOracle {
    fn new() -> TestResult<Arc<Self>> {
        Ok(Arc::new(Self {
            inner: rustls::crypto::ring::Ticketer::new()?,
            counts: Arc::default(),
        }))
    }

    fn distinct_ticket_key(&self) -> TestResult<Arc<Self>> {
        Ok(Arc::new(Self {
            inner: rustls::crypto::ring::Ticketer::new()?,
            counts: Arc::clone(&self.counts),
        }))
    }

    fn counts(&self) -> Counts {
        Counts {
            presented: self.counts.presented.load(Ordering::SeqCst),
            accepted: self.counts.accepted.load(Ordering::SeqCst),
        }
    }
}

impl ProducesTickets for TicketOracle {
    fn enabled(&self) -> bool {
        self.inner.enabled()
    }

    fn lifetime(&self) -> u32 {
        self.inner.lifetime()
    }

    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.inner.encrypt(plain)
    }

    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        self.counts.presented.fetch_add(1, Ordering::SeqCst);
        let plain = self.inner.decrypt(cipher);
        if plain.is_some() {
            self.counts.accepted.fetch_add(1, Ordering::SeqCst);
        }
        plain
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Counts {
    presented: usize,
    accepted: usize,
}

#[derive(Debug)]
struct Observed {
    connection: usize,
    path: String,
    tickets: Counts,
}

enum ColdRestore {
    Tickets,
    #[cfg(feature = "session-snapshot")]
    Session,
}

#[tokio::test]
async fn public_quic_cold_import_and_warm_replacement_resume_without_consuming_source()
-> TestResult<()> {
    quic_ticket_transfer(ColdRestore::Tickets).await
}

#[cfg(feature = "session-snapshot")]
#[tokio::test]
async fn public_quic_session_checkpoint_restores_single_use_tickets_without_consuming_source()
-> TestResult<()> {
    quic_ticket_transfer(ColdRestore::Session).await
}

async fn quic_ticket_transfer(cold_restore: ColdRestore) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let oracle = TicketOracle::new()?;
    let endpoint = h3_support::quic_server(
        server_config(&identity, Arc::clone(&oracle), 1)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let server_endpoint = endpoint.clone();
    let (observed_tx, mut observed) = mpsc::channel(1);
    let (read_tx, read_rx) = mpsc::channel(1);
    let (closed_tx, mut closed) = mpsc::channel(1);
    let mut peer = ConnectionPeer::spawn(serve(
        server_endpoint,
        Arc::clone(&oracle),
        observed_tx,
        read_rx,
        closed_tx,
    ));
    let outcome = AssertUnwindSafe(timeout(DEADLINE, async {
        let mut key = [0; 32];
        btls::rand::rand_bytes(&mut key)?;
        let source = client(&identity, false)?;
        let warm = client(&identity, false)?;
        let cold = client(&identity, false)?;
        let probe = client(&identity, false)?;

        exchange(&source, address, "/source-seed", 0, 0, &mut observed).await?;
        // Only a published native ticket contributes to the public clear count.
        // The H3 driver publishes held tickets after applying peer SETTINGS.
        let snapshot = export_one_ticket(&source, &probe, &key).await?;
        let restored = SessionTicketSnapshot::from_bytes(snapshot.as_bytes())?;
        assert!(restored.as_bytes() == snapshot.as_bytes());
        close_connection(&read_tx, &mut closed, 0).await?;

        // A different authentic server key gives the warm client a ticket
        // that cannot resume against the source's key restored below.
        endpoint.set_server_config(Some(server_config(
            &identity,
            oracle.distinct_ticket_key()?,
            1,
        )?));
        exchange(&warm, address, "/warm-seed", 1, 0, &mut observed).await?;
        let _warm_snapshot = export_one_ticket(&warm, &probe, &key).await?;
        // Later handshakes cannot refill the receiving clients' ticket queues.
        endpoint.set_server_config(Some(server_config(&identity, Arc::clone(&oracle), 0)?));

        let mismatch = client(&identity, true)?;
        let error = mismatch
            .import_session_tickets(&restored, &key, &[])
            .err()
            .ok_or("accepted a different QUIC TLS cipher policy")?;
        assert_eq!(error.kind(), SessionTicketErrorKind::Policy);
        assert_eq!(mismatch.clear_session_tickets()?, 0);

        // Replace an actual nonempty warm cache while its connection lives.
        warm.import_session_tickets(&restored, &key, &[])?;
        read_tx.send(false).await?;
        exchange(&warm, address, "/warm-after-import", 1, 0, &mut observed).await?;
        close_connection(&read_tx, &mut closed, 1).await?;
        // Only the imported source ticket is valid under the restored key.
        exchange(&warm, address, "/warm-replaced", 2, 1, &mut observed).await?;

        // Clearing an imported slot leaves this resumed connection usable.
        warm.import_session_tickets(&restored, &key, &[])?;
        assert_eq!(warm.clone().clear_session_tickets()?, 1);
        assert_eq!(warm.clear_session_tickets()?, 0);
        read_tx.send(false).await?;
        exchange(&warm, address, "/warm-after-clear", 2, 1, &mut observed).await?;
        warm.import_session_tickets(&restored, &key, &[])?;
        close_connection(&read_tx, &mut closed, 2).await?;

        // No request has created the cold recipient's origin pool/cache yet.
        let cold = match cold_restore {
            ColdRestore::Tickets => {
                cold.import_session_tickets(&restored, &key, &[])?;
                cold
            }
            #[cfg(feature = "session-snapshot")]
            ColdRestore::Session => {
                let checkpoint = source.export_session(&key)?;
                let restored = cold.restore_session(&checkpoint, &key, &[])?;
                assert_eq!(cold.clear_session_tickets()?, 0);
                restored
            }
        };
        exchange(&cold, address, "/cold-import", 3, 2, &mut observed).await?;
        close_connection(&read_tx, &mut closed, 3).await?;
        exchange(&cold, address, "/cold-exhausted", 4, 2, &mut observed).await?;
        close_connection(&read_tx, &mut closed, 4).await?;
        assert_eq!(cold.clear_session_tickets()?, 0);

        exchange(&warm, address, "/warm-import", 5, 3, &mut observed).await?;
        close_connection(&read_tx, &mut closed, 5).await?;
        exchange(&warm, address, "/warm-exhausted", 6, 3, &mut observed).await?;
        close_connection(&read_tx, &mut closed, 6).await?;
        assert_eq!(warm.clear_session_tickets()?, 0);

        // Export and both imports preserved the source's original native slot.
        exchange(&source, address, "/source-preserved", 7, 4, &mut observed).await?;
        close_connection(&read_tx, &mut closed, 7).await?;
        assert_eq!(source.clear_session_tickets()?, 0);
        peer.join().await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }))
    .catch_unwind()
    .await;
    // Run cleanup outside the operation deadline and after assertion unwinds.
    endpoint.close(0u32.into(), b"test cleanup");
    let cleanup = finish_with_cleanup(
        peer.shutdown().await,
        timeout(Duration::from_secs(5), endpoint.wait_idle())
            .await
            .map_err(Into::into),
    );
    match outcome {
        Ok(result) => finish_with_cleanup(result.map_err(Into::into).and_then(|v| v), cleanup),
        Err(panic) => {
            if let Err(error) = cleanup {
                eprintln!("QUIC transfer fixture cleanup failed: {error}");
            }
            std::panic::resume_unwind(panic)
        }
    }
}

async fn export_one_ticket(
    source: &Client,
    probe: &Client,
    key: &[u8; 32],
) -> TestResult<SessionTicketSnapshot> {
    loop {
        let snapshot = source.export_session_tickets(key)?;
        probe.import_session_tickets(&snapshot, key, &[])?;
        match probe.clear_session_tickets()? {
            1 => return Ok(snapshot),
            0 => tokio::task::yield_now().await,
            _ => return Err("one-ticket peer published multiple retained records".into()),
        }
    }
}

async fn exchange(
    client: &Client,
    address: SocketAddr,
    path: &str,
    connection: usize,
    accepted: usize,
    observed: &mut mpsc::Receiver<Observed>,
) -> TestResult<()> {
    let response = client
        .get_with_protocol(HttpProtocol::Http3, &format!("https://{address}{path}"))?
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_3);
    assert_eq!(
        response.into_body().collect().await?.to_bytes(),
        path.as_bytes()
    );
    let observation = observed
        .recv()
        .await
        .ok_or("peer stopped before observation")?;
    assert_eq!(observation.path, path);
    assert_eq!(observation.connection, connection);
    assert_eq!(
        observation.tickets,
        Counts {
            presented: accepted,
            accepted
        }
    );
    Ok(())
}

async fn close_connection(
    read: &mpsc::Sender<bool>,
    closed: &mut mpsc::Receiver<usize>,
    expected: usize,
) -> TestResult<()> {
    read.send(true).await?;
    assert_eq!(
        closed.recv().await.ok_or("peer stopped before drain")?,
        expected
    );
    Ok(())
}

async fn serve(
    endpoint: quinn::Endpoint,
    oracle: Arc<TicketOracle>,
    observed: mpsc::Sender<Observed>,
    mut read: mpsc::Receiver<bool>,
    closed: mpsc::Sender<usize>,
) -> TestResult<()> {
    for index in 0..8 {
        let quic = endpoint.accept().await.ok_or("endpoint closed")?.await?;
        let tickets = oracle.counts();
        let mut connection =
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(quic.clone()))
                .await?;
        loop {
            let resolver = connection.accept().await?.ok_or("missing H3 request")?;
            let (request, mut stream) = resolver.resolve_request().await?;
            if request.method() != http::Method::GET {
                return Err("expected GET".into());
            }
            let path = request.uri().path().to_owned();
            stream
                .send_response(Response::builder().status(StatusCode::OK).body(())?)
                .await?;
            stream
                .send_data(Bytes::copy_from_slice(path.as_bytes()))
                .await?;
            stream.finish().await?;
            observed
                .send(Observed {
                    connection: index,
                    path,
                    tickets,
                })
                .await?;
            if read
                .recv()
                .await
                .ok_or("client stopped before read acknowledgement")?
            {
                break;
            }
        }
        quic.close(0u32.into(), b"request complete");
        drop(connection);
        endpoint.wait_idle().await;
        closed.send(index).await?;
    }
    Ok(())
}

fn server_config(
    identity: &TestIdentity,
    oracle: Arc<TicketOracle>,
    tickets: usize,
) -> TestResult<quinn::ServerConfig> {
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.ticketer = oracle;
    tls.send_tls13_tickets = tickets;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

fn client(identity: &TestIdentity, different_ciphers: bool) -> TestResult<Client> {
    let base = h3_support::client_settings();
    let mut quic_tls = base.tls().clone();
    quic_tls.session_tickets = SessionTickets::enabled(1)?;
    if different_ciphers {
        quic_tls.cipher_suites.push(CipherSuite::Aes256GcmSha384);
    }
    let mut settings = base.http3().clone();
    // A seed request cannot leave before the peer's real SETTINGS are applied.
    settings.qpack_encoding = Http3QpackEncoding::Dynamic;
    let http3 = Http3ClientSettings::new(
        quic_tls,
        base.quic_transport().clone(),
        settings,
        base.request().clone(),
    );
    let mut tcp_tls = tls_settings();
    tcp_tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
    Ok(
        Client::builder(ClientProfile::new(tcp_tls).with_http3(http3))
            .route(Route::Direct)
            .add_root_certificate_der(identity.root_der.clone())
            .build()?,
    )
}
