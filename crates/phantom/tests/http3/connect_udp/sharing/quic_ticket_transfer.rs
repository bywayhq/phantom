//! Cold imports retain a shared H3 CONNECT-UDP outer's resumable session.

use super::super::*;

use phantom::SessionTicketSnapshot;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::{ServerSessionMemoryCache, StoresServerSessions},
};

#[derive(Debug)]
struct CountingStore {
    inner: Arc<ServerSessionMemoryCache>,
    presented: AtomicUsize,
    accepted: AtomicUsize,
}

impl CountingStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: ServerSessionMemoryCache::new(16),
            presented: AtomicUsize::new(0),
            accepted: AtomicUsize::new(0),
        })
    }

    fn counts(&self) -> (usize, usize) {
        (
            self.presented.load(Ordering::SeqCst),
            self.accepted.load(Ordering::SeqCst),
        )
    }
}

impl StoresServerSessions for CountingStore {
    fn put(&self, key: Vec<u8>, value: Vec<u8>) -> bool {
        self.inner.put(key, value)
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key)
    }

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

#[tokio::test]
async fn cold_import_resumes_shared_h3_outer_for_two_fresh_inner_origins() -> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let store = CountingStore::new();
    let mut proxy = MasqueProxy::spawn_with_session_storage(
        &proxy_identity,
        ProxyMode::Sharing,
        Some(store.clone()),
    )?;
    let mut origins = Vec::new();
    let result = super::checked(bounded(async {
        // No inner peer issues tickets, so every imported native record came
        // from the genuine H3 outer connection.
        for _ in 0..6 {
            origins.push(origin_without_tickets(&origin_identity)?);
        }
        let source = transfer_client(&origin_identity, &proxy_identity)?;
        let recipient = transfer_client(&origin_identity, &proxy_identity)?;
        let full = transfer_client(&origin_identity, &proxy_identity)?;
        let probe = transfer_client(&origin_identity, &proxy_identity)?;
        // Independently constructed route pools cannot share a live outer
        // across clients. Their configured proxy policy is nevertheless equal.
        let source_route = Route::connect_udp(ConnectUdpProxy::new(&proxy.template())?);
        let receiving_route = Route::connect_udp(ConnectUdpProxy::new(&proxy.template())?);
        let full_route = Route::connect_udp(ConnectUdpProxy::new(&proxy.template())?);
        let mut key = [0; 32];
        btls::rand::rand_bytes(&mut key)?;

        fetch_pair(&source, &source_route, &origins[0..2]).await?;
        assert_shared_round(&proxy, 0);
        assert_eq!(store.counts(), (0, 0));
        let (snapshot, captured) =
            export_outer_tickets(&source, &probe, &key, &receiving_route).await?;
        proxy.close_connections_and_wait().await?;
        proxy.reopen();

        // The independently built recipient has not opened any pool entry.
        recipient.import_session_tickets(
            &snapshot,
            &key,
            std::slice::from_ref(&receiving_route),
        )?;
        fetch_pair(&recipient, &receiving_route, &origins[2..4]).await?;
        assert_shared_round(&proxy, 1);
        assert_eq!(store.counts(), (1, 1));
        // Native export/import preserved the source client cache. Stateful
        // server consumption means that cache cannot also resume this ticket.
        assert!(source.clear_session_tickets()? >= captured);
        assert_eq!(source.clear_session_tickets()?, 0);
        proxy.close_connections_and_wait().await?;
        proxy.reopen();

        // Without importing, an otherwise identical fresh client performs a
        // full outer handshake and presents no stateful session.
        fetch_pair(&full, &full_route, &origins[4..6]).await?;
        assert_shared_round(&proxy, 2);
        assert_eq!(store.counts(), (1, 1));
        for (index, origin) in origins.iter().enumerate() {
            assert_eq!(origin.connections(), 1);
            assert_eq!(
                origin.requests(),
                [if index % 2 == 0 { "/one" } else { "/two" }]
            );
        }
        Ok(())
    }))
    .await;
    let mut result = finish_with_cleanup(result, proxy.finish().await);
    for origin in origins {
        result = finish_with_cleanup(result, origin.finish().await);
    }
    result
}

#[tokio::test]
async fn independent_default_outer_pools_share_live_tickets_and_clear_together() -> TestResult<()> {
    let (origin_identity, proxy_identity) = identities()?;
    let store = CountingStore::new();
    let mut proxy = MasqueProxy::spawn_with_session_storage(
        &proxy_identity,
        ProxyMode::Sharing,
        Some(store.clone()),
    )?;
    let mut origins = Vec::new();
    let result = super::checked(bounded(async {
        for _ in 0..6 {
            origins.push(origin_without_tickets(&origin_identity)?);
        }
        let route = Route::connect_udp(ConnectUdpProxy::new(&proxy.template())?);
        let source = transfer_builder(&origin_identity, &proxy_identity)
            .route(route.clone())
            .build()?;
        let probe = transfer_client(&origin_identity, &proxy_identity)?;
        for origin in &origins[..2] {
            let response = source
                .get_with_protocol(HttpProtocol::Http3, &origin.uri("/one"))?
                .send()
                .await?;
            response.into_body().collect().await?;
        }
        let _ = export_outer_tickets(&source, &probe, &[8; 32], &route).await?;
        assert_eq!(proxy.connections(), 1);
        let shared = source.fork(phantom::SessionSharing::none().tickets(true));
        for origin in &origins[2..4] {
            let response = shared
                .get_with_protocol(HttpProtocol::Http3, &origin.uri("/two"))?
                .send()
                .await?;
            response.into_body().collect().await?;
        }
        assert_eq!(
            proxy.connections(),
            2,
            "fork reused the source outer connection"
        );
        assert_eq!(store.counts(), (1, 1));
        assert!(shared.clear_session_tickets()? > 0);
        assert_eq!(source.clear_session_tickets()?, 0);
        source.refresh_connections().await;
        for origin in &origins[4..] {
            let response = source
                .get_with_protocol(HttpProtocol::Http3, &origin.uri("/three"))?
                .send()
                .await?;
            response.into_body().collect().await?;
        }
        assert_eq!(proxy.connections(), 3);
        assert_eq!(
            store.counts(),
            (1, 1),
            "cleared outer tickets were offered again"
        );
        Ok(())
    }))
    .await;
    let mut result = finish_with_cleanup(result, proxy.finish().await);
    for origin in origins {
        result = finish_with_cleanup(result, origin.finish().await);
    }
    result
}

async fn fetch_pair(client: &Client, route: &Route, pair: &[Origin]) -> TestResult<()> {
    let one = pair[0].uri("/one");
    let two = pair[1].uri("/two");
    tokio::try_join!(
        fetch_route(client, route, &one, "/one"),
        fetch_route(client, route, &two, "/two")
    )?;
    Ok(())
}

async fn fetch_route(client: &Client, route: &Route, uri: &str, body: &str) -> TestResult<()> {
    let response = client
        .get_with_protocol(HttpProtocol::Http3, uri)?
        .route(route.clone())
        .send()
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.into_body().collect().await?.to_bytes(), body);
    Ok(())
}

fn assert_shared_round(proxy: &MasqueProxy, round: usize) {
    assert_eq!(proxy.connections(), round + 1);
    let streams = proxy.stream_ids();
    assert_eq!(streams.len(), 2 * (round + 1));
    let pair = &streams[2 * round..];
    assert_eq!(pair[0].0, pair[1].0);
    assert_ne!(pair[0].1, pair[1].1);
    if round > 0 {
        assert_ne!(streams[2 * (round - 1)].0, pair[0].0);
    }
}

async fn export_outer_tickets(
    source: &Client,
    probe: &Client,
    key: &[u8; 32],
    receiving_route: &Route,
) -> TestResult<(SessionTicketSnapshot, usize)> {
    loop {
        let snapshot = source.export_session_tickets(key)?;
        probe.import_session_tickets(&snapshot, key, std::slice::from_ref(receiving_route))?;
        let retained = probe.clear_session_tickets()?;
        if retained > 0 {
            return Ok((snapshot, retained));
        }
        tokio::task::yield_now().await;
    }
}

fn transfer_client(origin: &TestIdentity, proxy: &TestIdentity) -> TestResult<Client> {
    Ok(transfer_builder(origin, proxy).build()?)
}

fn transfer_builder(origin: &TestIdentity, proxy: &TestIdentity) -> phantom::ClientBuilder {
    let base = masque_client_settings();
    let mut quic_tls = base.tls().clone();
    quic_tls.session_tickets = chrome::v154_quic_tls().session_tickets;
    let http3 = Http3ClientSettings::new(
        quic_tls,
        base.quic_transport().clone(),
        base.http3().clone(),
        base.request().clone(),
    );
    Client::builder(ClientProfile::new(tls_settings()).with_http3(http3))
        .add_root_certificate_der(origin.root_der.clone())
        .add_proxy_root_certificate_der(proxy.root_der.clone())
}

fn origin_without_tickets(identity: &TestIdentity) -> TestResult<Origin> {
    let certificate = CertificateDer::from(identity.leaf_der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        identity.private_key_der().to_vec(),
    ));
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![certificate], key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    tls.send_tls13_tickets = 0;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let endpoint = h3_support::quic_server(config, "127.0.0.1:0".parse()?)?;
    Ok(Origin::serve((endpoint.local_addr()?, endpoint)))
}
