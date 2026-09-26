//! Encrypted Client Hello from an HTTPS DNS record on HTTP/3 connections,
//! through the client facade, against a loopback BoringSSL QUIC origin that
//! decrypts ECH.
//!
//! The origin closes each connection after its response, so every request
//! opens a new one. The first request may start before the record's lookup
//! finishes; later ones find it cached.

use crate::support::ech as ech_support;
use crate::support::tls as tls_support;

use std::{net::Ipv4Addr, num::NonZeroUsize, sync::Arc, time::Duration};

use btls::{
    hpke::HpkeKey,
    ssl::{SslAcceptor, SslContext, SslEchKeys},
};
use bytes::Bytes;
use http_body_util::BodyExt;
use phantom::{
    AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, Client, HttpProtocol, RequestErrorKind,
    ResponseInfo,
    dns::HttpsRecordResolver,
    profile::{ClientProfile, Http3ClientSettings, chromium},
};
use phantom_quic_btls::{QuicServerConfig, ServerHandshakeData};
use phantom_testkit::{
    dns::DnsServer,
    tls::{ClientHelloSummary, EchTestKey, TEST_ECH_KEYS, ech_config, ech_config_list},
};
use tokio::{
    io::AsyncWriteExt,
    net::TcpListener,
    sync::{oneshot, watch},
    task::JoinHandle,
    time::timeout,
};

use ech_support::{
    ORIGIN_NAME, PUBLIC_NAME, STAND_IN_NAME, TEST_TIMEOUT, ech_acceptor, https_rdata_with_alpn,
    origin_identity, record_server, try_handshake,
};
use tls_support::{H1_ALPN, TestIdentity, TestResult, read_head};

const H3_ALPN: &[u8] = b"\x02h3";
/// The QUIC `CRYPTO_ERROR` for the TLS `ech_required` alert (121).
const ECH_REQUIRED: u64 = 0x179;
/// Time for a spawned lookup to finish and cache the record.
const SETTLE: Duration = Duration::from_millis(200);

/// What the origin saw on one QUIC connection.
#[derive(Debug)]
struct Observed {
    outer_server_name: Option<String>,
    ech_accepted: bool,
    server_name: Option<String>,
    closed_with: Option<u64>,
    session_resumed: bool,
}

/// The origin's ECH keys: `config_id` under `key`, with the public name.
fn ech_keys(config_id: u8, key: &EchTestKey) -> TestResult<SslEchKeys> {
    let mut keys = SslEchKeys::builder()?;
    keys.add_key(
        true,
        &ech_config(config_id, key, PUBLIC_NAME),
        HpkeKey::dhkem_p256_sha256(&key.private_key)?,
    )?;
    Ok(keys.build())
}

/// A loopback HTTP/3 origin that records each connection's handshake and
/// answers one request on each completed connection, then closes it.
///
/// With [`Self::spawn_with_tcp`] it also serves HTTP/1.1 over TCP on the same
/// port, from a BoringSSL origin with the same ECH keys, and counts those
/// connections.
struct QuicOrigin {
    port: u16,
    context: SslContext,
    stop: oneshot::Sender<()>,
    task: JoinHandle<TestResult<Vec<Observed>>>,
    /// How many QUIC connections the origin has recorded so far.
    recorded: watch::Receiver<usize>,
    tcp: Option<(Arc<watch::Sender<usize>>, JoinHandle<()>)>,
}

impl QuicOrigin {
    fn spawn(identity: &TestIdentity, config_id: u8, key: &EchTestKey) -> TestResult<Self> {
        let endpoint_context = Self::context(identity, config_id, key)?;
        let endpoint = Self::endpoint(&endpoint_context, 0)?;
        Ok(Self::start(endpoint, endpoint_context, None))
    }

    /// Serves HTTP/3 and, on the same port, HTTP/1.1 over TCP.
    async fn spawn_with_tcp(
        identity: &TestIdentity,
        config_id: u8,
        key: &EchTestKey,
    ) -> TestResult<Self> {
        let context = Self::context(identity, config_id, key)?;
        let acceptor = ech_acceptor(identity, H1_ALPN, config_id, key)?;
        let mut last_error = None;
        // A free UDP port may be taken for TCP; try a few.
        for _ in 0..16 {
            let endpoint = Self::endpoint(&context, 0)?;
            let port = endpoint.local_addr()?.port();
            match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
                Ok(listener) => {
                    let served = Arc::new(watch::Sender::new(0));
                    let tcp = tokio::spawn(serve_tcp(listener, acceptor, Arc::clone(&served)));
                    return Ok(Self::start(endpoint, context, Some((served, tcp))));
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(format!("no port was free for both UDP and TCP: {last_error:?}").into())
    }

    fn context(identity: &TestIdentity, config_id: u8, key: &EchTestKey) -> TestResult<SslContext> {
        let builder = identity.acceptor_builder(H3_ALPN)?;
        builder.set_ech_keys(&ech_keys(config_id, key)?)?;
        Ok(builder.build().into_context())
    }

    fn endpoint(context: &SslContext, port: u16) -> TestResult<quinn::Endpoint> {
        let crypto = QuicServerConfig::new(context.clone());
        Ok(quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(crypto)),
            (Ipv4Addr::LOCALHOST, port).into(),
        )?)
    }

    fn start(
        endpoint: quinn::Endpoint,
        context: SslContext,
        tcp: Option<(Arc<watch::Sender<usize>>, JoinHandle<()>)>,
    ) -> Self {
        let port = endpoint.local_addr().map_or(0, |address| address.port());
        let (stop, mut stopped) = oneshot::channel();
        let (count, recorded) = watch::channel(0);
        let task = tokio::spawn(async move {
            let mut observed = Vec::new();
            let mut serving = Vec::new();
            loop {
                let incoming = tokio::select! {
                    incoming = endpoint.accept() => incoming.ok_or("endpoint closed")?,
                    _ = &mut stopped => break,
                };
                let (seen, connection) = observe(incoming).await?;
                observed.push(seen);
                count.send_replace(observed.len());
                if let Some(connection) = connection {
                    serving.push(tokio::spawn(serve_one(connection)));
                }
            }
            for task in serving {
                task.abort();
            }
            Ok(observed)
        });
        Self {
            port,
            context,
            stop,
            task,
            recorded,
            tcp,
        }
    }

    /// Replaces the ECH keys new QUIC connections are decrypted with.
    fn rotate_keys(&self, config_id: u8, key: &EchTestKey) -> TestResult<()> {
        self.context.set_ech_keys(&ech_keys(config_id, key)?)?;
        Ok(())
    }

    fn url(&self, path: &str) -> String {
        format!("https://{ORIGIN_NAME}:{}{path}", self.port)
    }

    /// Waits until the origin has recorded `quic` QUIC connections and
    /// served `tcp` TCP ones, then returns what each QUIC connection showed
    /// and how many TCP connections were served. A connection that arrives
    /// after those counts are reached is still recorded when it was accepted
    /// first.
    async fn finish(mut self, quic: usize, tcp: usize) -> TestResult<(Vec<Observed>, usize)> {
        timeout(TEST_TIMEOUT, self.recorded.wait_for(|count| *count >= quic))
            .await
            .map_err(|_| format!("the origin saw fewer than {quic} QUIC connections"))??;
        if let Some((served, _)) = &self.tcp {
            timeout(
                TEST_TIMEOUT,
                served.subscribe().wait_for(|count| *count >= tcp),
            )
            .await
            .map_err(|_| format!("the origin served fewer than {tcp} TCP connections"))??;
        }
        let _ = self.stop.send(());
        let observed = self.task.await??;
        let served = match self.tcp {
            Some((served, task)) => {
                task.abort();
                *served.borrow()
            }
            None => 0,
        };
        Ok((observed, served))
    }
}

/// Serves `HTTP/1.1 200` on each TCP connection whose handshake completes
/// with ECH accepted or without ECH, and counts them. A connection rejected
/// under the public name is aborted by the client, which retries.
async fn serve_tcp(
    listener: TcpListener,
    acceptor: SslAcceptor,
    served: Arc<watch::Sender<usize>>,
) {
    while let Ok((tcp, _)) = listener.accept().await {
        let acceptor = acceptor.clone();
        let served = Arc::clone(&served);
        tokio::spawn(async move {
            let Ok((seen, Some(mut tls))) = try_handshake(tcp, &acceptor).await else {
                return;
            };
            if !seen.ech_accepted && seen.outer_server_name.as_deref() == Some(PUBLIC_NAME) {
                return;
            }
            if read_head(&mut tls).await.is_err() {
                return;
            }
            let response = b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok";
            if tls.write_all(response).await.is_ok() {
                served.send_modify(|count| *count += 1);
                let _ = tls.shutdown().await;
            }
        });
    }
}

async fn observe(incoming: quinn::Incoming) -> TestResult<(Observed, Option<quinn::Connection>)> {
    let mut connecting = incoming.accept()?;
    let data = timeout(TEST_TIMEOUT, connecting.handshake_data())
        .await??
        .downcast::<ServerHandshakeData>()
        .map_err(|_| "unexpected server handshake data")?;
    let outer_server_name = ClientHelloSummary::from_handshake_bytes(data.client_hello())?
        .server_name()
        .map(|name| String::from_utf8_lossy(name).into_owned());
    let (closed_with, connection) = match timeout(TEST_TIMEOUT, connecting).await? {
        Ok(connection) => (None, Some(connection)),
        Err(quinn::ConnectionError::ConnectionClosed(close)) => {
            (Some(u64::from(close.error_code)), None)
        }
        Err(error) => return Err(error.into()),
    };
    // Resumption is known only once the handshake has completed.
    let session_resumed = connection
        .as_ref()
        .and_then(quinn::Connection::handshake_data)
        .and_then(|data| data.downcast::<ServerHandshakeData>().ok())
        .is_some_and(|data| data.session_resumed());
    Ok((
        Observed {
            outer_server_name,
            ech_accepted: data.ech_accepted(),
            server_name: data.server_name().map(str::to_owned),
            closed_with,
            session_resumed,
        },
        connection,
    ))
}

async fn serve_one(connection: quinn::Connection) -> TestResult<()> {
    let mut h3 =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection.clone()))
            .await?;
    let resolver = h3.accept().await?.ok_or("client closed before a request")?;
    let (_, mut stream) = resolver.resolve_request().await?;
    stream
        .send_response(http::Response::builder().status(200).body(())?)
        .await?;
    stream.send_data(Bytes::from_static(b"ok")).await?;
    stream.finish().await?;
    // Closing lets the next request find no pooled connection.
    tokio::time::sleep(Duration::from_millis(50)).await;
    connection.close(0_u32.into(), b"done");
    Ok(())
}

/// A DNS server whose record lists `h3` and `h2` and publishes
/// configuration 1 under the first key.
async fn published_record() -> TestResult<DnsServer> {
    let config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
    record_server(vec![https_rdata_with_alpn(
        &[b"h3", b"h2"],
        &ech_config_list(&[config]),
    )])
    .await
}

/// Chrome 154's HTTP/3 recipe, with `ech_from_https_records` as given.
fn profile(ech_from_https_records: bool) -> ClientProfile {
    let mut tls = chromium::v154_http3_tls();
    tls.ech_from_https_records = ech_from_https_records;
    ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_http3(Http3ClientSettings::new(
            tls,
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        ))
}

/// A client whose HTTPS record lookups go to `dns` for the stand-in name,
/// and which reaches `localhost` on the IPv4 loopback the origin listens on.
fn client(identity: &TestIdentity, dns: &DnsServer, profile: ClientProfile) -> TestResult<Client> {
    client_with(identity, dns, profile, AltSvcPolicy::sequential())
}

/// [`client`] with the given Alt-Svc policy.
fn client_with(
    identity: &TestIdentity,
    dns: &DnsServer,
    profile: ClientProfile,
    policy: AltSvcPolicy,
) -> TestResult<Client> {
    let upstream = HttpsRecordResolver::with_nameservers([dns.address()])?;
    let records = HttpsRecordResolver::from_fn(move |_, port| {
        let upstream = upstream.clone();
        async move { upstream.lookup(STAND_IN_NAME, port).await }
    });
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(NonZeroUsize::MIN.saturating_add(7))
        .alt_svc_policy(policy)
        .https_record_discovery(records)
        .resolve(ORIGIN_NAME, [Ipv4Addr::LOCALHOST.into()])
        .build()?)
}

fn assert_accepted(connection: &Observed) {
    assert_eq!(connection.outer_server_name.as_deref(), Some(PUBLIC_NAME));
    assert!(connection.ech_accepted, "{connection:?}");
    assert_eq!(connection.server_name.as_deref(), Some(ORIGIN_NAME));
}

async fn bounded(test: impl Future<Output = TestResult<()>>) -> TestResult<()> {
    timeout(TEST_TIMEOUT, test)
        .await
        .map_err(|_| "ECH test exceeded its deadline")?
}

async fn get(client: &Client, protocol: Option<HttpProtocol>, url: &str) -> TestResult<()> {
    get_as(client, protocol, url, HttpProtocol::Http3).await
}

/// Sends a GET, exact when `protocol` is set, and checks it was answered
/// over `expected`.
async fn get_as(
    client: &Client,
    protocol: Option<HttpProtocol>,
    url: &str,
    expected: HttpProtocol,
) -> TestResult<()> {
    let response = match protocol {
        Some(protocol) => client.get(protocol, url)?.send().await?,
        None => client.get_negotiated(url)?.send().await?,
    };
    let info = response
        .extensions()
        .get::<ResponseInfo>()
        .ok_or("response omitted protocol metadata")?;
    assert_eq!(info.protocol(), expected);
    response.into_body().collect().await?;
    Ok(())
}

#[tokio::test]
async fn exact_http3_offers_the_records_ech() -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        let origin = QuicOrigin::spawn(&identity, 1, &TEST_ECH_KEYS[0])?;
        let client = client(&identity, &dns, profile(true))?;

        for path in ["/first", "/second"] {
            get(&client, Some(HttpProtocol::Http3), &origin.url(path)).await?;
            tokio::time::sleep(SETTLE).await;
        }

        let (observed, _) = origin.finish(2, 0).await?;
        assert_eq!(observed.len(), 2, "{observed:?}");
        assert_accepted(&observed[1]);
        Ok(())
    })
    .await
}

/// Once an exact request has cached the record, a negotiated request takes
/// the HTTP/3 alternative the record advertises and offers its `ech`.
#[tokio::test]
async fn https_record_alternative_offers_the_records_ech() -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        let origin = QuicOrigin::spawn(&identity, 1, &TEST_ECH_KEYS[0])?;
        let client = client(&identity, &dns, profile(true))?;

        get(&client, Some(HttpProtocol::Http3), &origin.url("/first")).await?;
        tokio::time::sleep(SETTLE).await;
        get(&client, None, &origin.url("/second")).await?;

        let (observed, _) = origin.finish(2, 0).await?;
        assert_eq!(observed.len(), 2, "{observed:?}");
        assert_accepted(&observed[1]);
        assert_eq!(dns.queries().len(), 1);
        Ok(())
    })
    .await
}

/// The origin holds configuration 2 under another key. A request whose
/// connection offers the published configuration fails, and the client
/// opens no other QUIC connection for it, as Chrome 154 opened none.
#[tokio::test]
async fn exact_http3_rejection_fails_without_a_quic_retry() -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        let origin = QuicOrigin::spawn(&identity, 2, &TEST_ECH_KEYS[1])?;
        let client = client(&identity, &dns, profile(true))?;

        // The first connection may start before the lookup ends and send
        // GREASE; the second finds the record cached.
        let first = get(&client, Some(HttpProtocol::Http3), &origin.url("/first")).await;
        tokio::time::sleep(SETTLE).await;
        let second = client
            .get(HttpProtocol::Http3, &origin.url("/second"))?
            .send()
            .await
            .err()
            .ok_or("a rejected ECH offer connected")?;
        assert_eq!(second.kind(), RequestErrorKind::Tls);

        let (observed, _) = origin.finish(2, 0).await?;
        let rejected = observed
            .iter()
            .filter(|seen| seen.closed_with == Some(ECH_REQUIRED))
            .collect::<Vec<_>>();
        // Every connection with ECH was rejected once and not repeated.
        let expected = if first.is_ok() { 1 } else { 2 };
        assert_eq!(rejected.len(), expected, "{observed:?}");
        assert_eq!(observed.len(), 2, "{observed:?}");
        for seen in rejected {
            assert_eq!(seen.outer_server_name.as_deref(), Some(PUBLIC_NAME));
            assert!(!seen.ech_accepted);
        }
        Ok(())
    })
    .await
}

/// With the field unset, the client makes no HTTPS query for an exact
/// HTTP/3 request, and the connection sends GREASE with the true name.
#[tokio::test]
async fn exact_http3_without_the_field_keeps_grease() -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        let origin = QuicOrigin::spawn(&identity, 1, &TEST_ECH_KEYS[0])?;
        let client = client(&identity, &dns, profile(false))?;

        get(&client, Some(HttpProtocol::Http3), &origin.url("/first")).await?;

        let (observed, _) = origin.finish(1, 0).await?;
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].outer_server_name.as_deref(), Some(ORIGIN_NAME));
        assert!(!observed[0].ech_accepted);
        assert!(dns.queries().is_empty());
        Ok(())
    })
    .await
}

/// A connection that presented a session ticket and whose ECH is rejected
/// fails without a second attempt: the pool repeats a ticketed connection
/// with a full handshake only after other handshake failures.
#[tokio::test]
async fn a_rejected_ticketed_connection_is_not_repeated_without_the_ticket() -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        let origin = QuicOrigin::spawn(&identity, 1, &TEST_ECH_KEYS[0])?;
        let client = client(&identity, &dns, profile(true))?;

        // The first connection caches the record and a ticket; the second
        // resumes with ECH accepted, so the client holds a fresh ticket.
        for path in ["/first", "/second"] {
            get(&client, Some(HttpProtocol::Http3), &origin.url(path)).await?;
            tokio::time::sleep(SETTLE).await;
        }
        origin.rotate_keys(2, &TEST_ECH_KEYS[1])?;
        let error = client
            .get(HttpProtocol::Http3, &origin.url("/third"))?
            .send()
            .await
            .err()
            .ok_or("a rejected ECH offer connected")?;
        assert_eq!(error.kind(), RequestErrorKind::Tls);

        let (observed, _) = origin.finish(3, 0).await?;
        assert_eq!(observed.len(), 3, "{observed:?}");
        assert_accepted(&observed[1]);
        assert!(observed[1].session_resumed, "{observed:?}");
        assert_eq!(observed[2].closed_with, Some(ECH_REQUIRED));
        assert_eq!(observed[2].outer_server_name.as_deref(), Some(PUBLIC_NAME));
        Ok(())
    })
    .await
}

/// A racing client whose HTTPS-record alternative is rejected sends the
/// request to the origin over TCP, marks the alternative broken, and does
/// not try QUIC again while it stays broken.
#[tokio::test]
async fn racing_client_serves_a_rejected_alternative_from_the_origin() -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        // The origin holds configuration 2; the record publishes 1.
        let origin = QuicOrigin::spawn_with_tcp(&identity, 2, &TEST_ECH_KEYS[1]).await?;
        let race = AltSvcRace::new(
            Duration::from_millis(300),
            AltSvcBrokenBackoff::CHROMIUM_153,
        );
        let client = client_with(&identity, &dns, profile(true), AltSvcPolicy::race(race))?;

        // An exact HTTP/1.1 request caches the record without touching QUIC.
        get_as(
            &client,
            Some(HttpProtocol::Http1),
            &origin.url("/warm"),
            HttpProtocol::Http1,
        )
        .await?;
        tokio::time::sleep(SETTLE).await;
        for path in ["/raced", "/after"] {
            get_as(&client, None, &origin.url(path), HttpProtocol::Http1).await?;
            tokio::time::sleep(SETTLE).await;
        }

        let (observed, tcp_served) = origin.finish(1, 3).await?;
        assert_eq!(observed.len(), 1, "{observed:?}");
        assert_eq!(observed[0].closed_with, Some(ECH_REQUIRED));
        assert_eq!(observed[0].outer_server_name.as_deref(), Some(PUBLIC_NAME));
        assert_eq!(tcp_served, 3);
        Ok(())
    })
    .await
}

/// Under the default sequential policy, a negotiated request whose
/// HTTPS-record alternative is rejected fails, since the alternative's setup
/// failure ends the request; the alternative is marked broken, so the next
/// request is served over TCP without another QUIC connection.
#[tokio::test]
async fn sequential_client_fails_a_rejected_alternative_then_uses_the_origin() -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let dns = published_record().await?;
        // The origin holds configuration 2; the record publishes 1.
        let origin = QuicOrigin::spawn_with_tcp(&identity, 2, &TEST_ECH_KEYS[1]).await?;
        let client = client(&identity, &dns, profile(true))?;

        // An exact HTTP/1.1 request caches the record without touching QUIC.
        get_as(
            &client,
            Some(HttpProtocol::Http1),
            &origin.url("/warm"),
            HttpProtocol::Http1,
        )
        .await?;
        tokio::time::sleep(SETTLE).await;
        let error = client
            .get_negotiated(&origin.url("/rejected"))?
            .send()
            .await
            .err()
            .ok_or("a rejected ECH offer connected")?;
        assert_eq!(error.kind(), RequestErrorKind::Tls);
        get_as(&client, None, &origin.url("/after"), HttpProtocol::Http1).await?;

        let (observed, tcp_served) = origin.finish(1, 2).await?;
        assert_eq!(observed.len(), 1, "{observed:?}");
        assert_eq!(observed[0].closed_with, Some(ECH_REQUIRED));
        assert_eq!(observed[0].outer_server_name.as_deref(), Some(PUBLIC_NAME));
        assert_eq!(tcp_served, 2);
        Ok(())
    })
    .await
}
