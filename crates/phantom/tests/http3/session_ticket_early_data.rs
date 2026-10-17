//! Imported QUIC tickets preserve early dispatch and rejection replay.

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
use http::{Method, Response, StatusCode, Version};
use http_body_util::BodyExt as _;
use phantom::{
    Client, HttpProtocol, SessionTicketSnapshot,
    profile::{ClientProfile, Http3ClientSettings, browser::chrome},
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ServerSessionMemoryCache, StoresServerSessions},
};
use tokio::{
    sync::{mpsc, watch},
    time::timeout,
};
use tracing::instrument::WithSubscriber;

use crate::{
    http3_early_data::gated_relay,
    support::{
        h3 as h3_support,
        tls::{TestIdentity, TestResult},
        tracing::OutcomeSubscriber,
        tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
    },
};

const DEADLINE: Duration = Duration::from_secs(20);

#[derive(Debug)]
struct SessionStore {
    inner: Arc<ServerSessionMemoryCache>,
    attempts: AtomicUsize,
    found: AtomicUsize,
}

impl SessionStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: ServerSessionMemoryCache::new(8),
            attempts: AtomicUsize::new(0),
            found: AtomicUsize::new(0),
        })
    }
}

impl StoresServerSessions for SessionStore {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.inner.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }

    fn take(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let session = self.inner.take(key);
        if session.is_some() {
            self.found.fetch_add(1, Ordering::SeqCst);
        }
        session
    }

    fn can_cache(&self) -> bool {
        self.inner.can_cache()
    }
}

#[tokio::test]
async fn cold_imported_quic_ticket_sends_accepted_early_data_before_server_replies()
-> TestResult<()> {
    imported_early_data(true).await
}

#[tokio::test]
async fn cold_imported_quic_ticket_replays_rejected_early_data_once_on_the_same_connection()
-> TestResult<()> {
    imported_early_data(false).await
}

async fn imported_early_data(accept: bool) -> TestResult<()> {
    imported_with_budget(accept, None).await
}

#[tokio::test]
async fn shared_attempt_budget_counts_accepted_and_rejected_quic_early_data() -> TestResult<()> {
    for accepted in [false, true] {
        for maximum in [1, 2] {
            imported_with_budget(accepted, Some(maximum)).await?;
        }
    }
    Ok(())
}

async fn imported_with_budget(accept: bool, maximum: Option<usize>) -> TestResult<()> {
    let denied = !accept && maximum == Some(1);
    let identity = TestIdentity::generate()?;
    let sessions = SessionStore::new();
    let endpoint = h3_support::quic_server(
        server_config(&identity, Arc::clone(&sessions), true, 1)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let (gate, open) = watch::channel(true);
    let (address, mut relay) = gated_relay(endpoint.local_addr()?, open).await?;
    let (arrived_tx, mut arrived) = mpsc::channel(2);
    let (read_tx, read) = mpsc::channel(1);
    let (closed_tx, mut closed) = mpsc::channel(1);
    let mut peer = ConnectionPeer::spawn(serve(
        endpoint.clone(),
        gate.subscribe(),
        arrived_tx,
        read,
        closed_tx,
        denied,
    ));
    let outcome = AssertUnwindSafe(timeout(DEADLINE, async {
        let source = client(&identity)?;
        let recipient = client(&identity)?;
        let probe = client(&identity)?;
        let mut key = [0; 32];
        btls::rand::rand_bytes(&mut key)?;

        let fresh = OutcomeSubscriber::default();
        send(&source, address, "/seed")
            .with_subscriber(fresh.dispatch())
            .await?;
        assert_eq!(arrived.recv().await, Some((0, "/seed".to_owned(), true)));
        assert_eq!(fresh.early_data_for("http3.response_head"), ["none"]);
        assert_eq!(sessions.attempts.load(Ordering::SeqCst), 0);

        // Export readiness observes actual published tickets. Dynamic QPACK
        // also requires that the source has processed the peer's SETTINGS.
        let snapshot = export_one_ticket(&source, &probe, &key).await?;
        read_tx.send(()).await?;
        assert_eq!(closed.recv().await, Some(0));
        endpoint.set_server_config(Some(server_config(
            &identity,
            Arc::clone(&sessions),
            accept,
            0,
        )?));

        // No request has created a pool or cache in this recipient.
        recipient.import_session_tickets(&snapshot, &key, &[])?;
        gate.send_replace(false);
        let trace = OutcomeSubscriber::default();
        let budget = maximum.map(phantom::HttpAttemptBudget::new);
        let request = send_budgeted(&recipient, address, "/imported", budget.clone())
            .with_subscriber(trace.dispatch());
        tokio::pin!(request);

        if accept {
            // The server must decode the complete request before any of its
            // handshake datagrams can reach the new recipient.
            tokio::select! {
                result = &mut request => {
                    result?;
                    return Err("request completed through a closed reply gate".into());
                }
                observation = arrived.recv() => {
                    assert_eq!(observation, Some((1, "/imported".to_owned(), false)));
                }
            }
        } else {
            // The existing dispatch event precedes the handshake answer.
            // Its second event must subsequently show replay after rejection.
            tokio::select! {
                result = &mut request => {
                    result?;
                    return Err("request completed through a closed reply gate".into());
                }
                () = async {
                    while trace.early_data_for("http3.response_head").is_empty() {
                        tokio::task::yield_now().await;
                    }
                } => {}
            }
        }
        assert_eq!(trace.early_data_for("http3.response_head"), ["sent"]);
        gate.send_replace(true);
        let result = request.await;
        if denied {
            let error = result
                .err()
                .ok_or("rejected QUIC early data exceeded allowance")?;
            let error = error
                .downcast_ref::<phantom::RequestError>()
                .ok_or("missing typed request error")?;
            assert_eq!(
                error.kind(),
                phantom::RequestErrorKind::AttemptBudgetExhausted
            );
            assert!(arrived.try_recv().is_err(), "peer received a denied resend");
            assert_eq!(trace.early_data_for("http3.response_head"), ["sent"]);
        } else {
            result?;
        }
        if let Some(budget) = budget {
            let spent = if accept || denied { 1 } else { 2 };
            assert_eq!(
                budget.remaining(),
                maximum.ok_or("missing maximum")? - spent
            );
        }
        if accept {
            assert_eq!(trace.early_data_for("http3.response_head"), ["sent"]);
        } else if !denied {
            assert_eq!(
                arrived.recv().await,
                Some((1, "/imported".to_owned(), true))
            );
            assert_eq!(
                trace.early_data_for("http3.response_head"),
                ["sent", "after_handshake"]
            );
        }
        assert_eq!(sessions.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(sessions.found.load(Ordering::SeqCst), 1);
        read_tx.send(()).await?;
        assert_eq!(closed.recv().await, Some(1));
        assert_eq!(recipient.clear_session_tickets()?, 0);
        // No new ticket was issued on the imported connection. The source's
        // original client cache remains intact even though the stateful
        // server has now consumed its copy.
        assert_eq!(source.clear_session_tickets()?, 1);
        peer.join().await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }))
    .catch_unwind()
    .await;

    gate.send_replace(true);
    endpoint.close(0u32.into(), b"test cleanup");
    let peers = finish_with_cleanup(peer.shutdown().await, relay.stop().await);
    let cleanup = finish_with_cleanup(
        peers,
        timeout(Duration::from_secs(5), endpoint.wait_idle())
            .await
            .map_err(Into::into),
    );
    match outcome {
        Ok(result) => finish_with_cleanup(result.map_err(Into::into).and_then(|v| v), cleanup),
        Err(panic) => {
            if let Err(error) = cleanup {
                eprintln!("imported early-data cleanup failed: {error}");
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
            _ => return Err("one-ticket peer published multiple records".into()),
        }
    }
}

async fn send(client: &Client, address: SocketAddr, path: &str) -> TestResult<()> {
    send_budgeted(client, address, path, None).await
}

async fn send_budgeted(
    client: &Client,
    address: SocketAddr,
    path: &str,
    budget: Option<phantom::HttpAttemptBudget>,
) -> TestResult<()> {
    let mut request = client.get(HttpProtocol::Http3, &format!("https://{address}{path}"))?;
    if let Some(budget) = budget {
        request = request.attempt_budget(budget);
    }
    let response = request.send().await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.version(), Version::HTTP_3);
    assert_eq!(
        response.into_body().collect().await?.to_bytes(),
        path.as_bytes()
    );
    Ok(())
}

async fn serve(
    endpoint: quinn::Endpoint,
    gate: watch::Receiver<bool>,
    arrived: mpsc::Sender<(usize, String, bool)>,
    mut read: mpsc::Receiver<()>,
    closed: mpsc::Sender<usize>,
    denied: bool,
) -> TestResult<()> {
    for index in 0..2 {
        let mut connecting = endpoint.accept().await.ok_or("endpoint closed")?.accept()?;
        connecting.handshake_data().await?;
        let quic = match connecting.into_0rtt() {
            Ok((connection, _accepted)) => connection,
            Err(connecting) => connecting.await?,
        };
        let mut connection =
            h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(quic.clone()))
                .await?;
        if denied && index == 1 {
            read.recv()
                .await
                .ok_or("client stopped before acknowledgement")?;
            match timeout(Duration::from_millis(300), connection.accept()).await {
                Ok(Ok(Some(_))) => return Err("peer received budget-denied QUIC replay".into()),
                Ok(Ok(None)) | Err(_) => {}
                Ok(Err(error)) if error.is_h3_no_error() => {}
                Ok(Err(error)) => return Err(error.into()),
            }
            quic.close(0u32.into(), b"budget checked");
            drop(connection);
            endpoint.wait_idle().await;
            closed.send(index).await?;
            continue;
        }
        let resolver = connection.accept().await?.ok_or("missing H3 request")?;
        let (request, mut stream) = resolver.resolve_request().await?;
        assert_eq!(request.method(), Method::GET);
        assert_eq!(
            request.uri().path(),
            if index == 0 { "/seed" } else { "/imported" }
        );
        while stream.recv_data().await?.is_some() {}
        let gate_was_open = *gate.borrow();
        arrived
            .send((index, request.uri().path().to_owned(), gate_was_open))
            .await?;
        stream
            .send_response(Response::builder().status(StatusCode::OK).body(())?)
            .await?;
        stream
            .send_data(Bytes::copy_from_slice(request.uri().path().as_bytes()))
            .await?;
        stream.finish().await?;
        read.recv()
            .await
            .ok_or("client stopped before acknowledgement")?;
        match timeout(Duration::from_millis(300), connection.accept()).await {
            Ok(Ok(Some(_))) => return Err("duplicate request on imported connection".into()),
            Ok(Ok(None)) | Err(_) => {}
            Ok(Err(error)) if error.is_h3_no_error() => {}
            Ok(Err(error)) => return Err(error.into()),
        }
        quic.close(0u32.into(), b"served");
        drop(connection);
        endpoint.wait_idle().await;
        closed.send(index).await?;
    }
    match timeout(Duration::from_millis(300), endpoint.accept()).await {
        Ok(Some(_)) => Err("unexpected third connection".into()),
        Ok(None) | Err(_) => Ok(()),
    }
}

fn server_config(
    identity: &TestIdentity,
    sessions: Arc<SessionStore>,
    early_data: bool,
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
    tls.session_storage = sessions;
    // Rustls accepts TLS 1.3 early data only with stateful session storage.
    tls.max_early_data_size = if early_data { u32::MAX } else { 0 };
    tls.send_tls13_tickets = tickets;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

fn client(identity: &TestIdentity) -> TestResult<Client> {
    let profile = ClientProfile::new(chrome::v154_tcp_tls()).with_http3(Http3ClientSettings::new(
        chrome::v154_quic_tls(),
        chrome::v154_quic(),
        chrome::v154_http3(),
        chrome::v154_http3_request(),
    ));
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .build()?)
}

mod mapping_confirmation;
