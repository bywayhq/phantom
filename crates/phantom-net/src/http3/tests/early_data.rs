use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use bytes::{Buf, Bytes};
use http::{Method, Response, StatusCode};
use phantom_profile::chromium;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};
use tracing::instrument::WithSubscriber;

use super::super::{
    Http3Connection, Http3Connector, Http3ConnectorError, Http3Error, Http3Unprocessed,
};
use super::{TEST_TIMEOUT, TestResult};
use crate::request::OriginForm;
use crate::tls::test_support::{TEST_SERVER_NAME, TestIdentity};
use crate::tracing_test::OutcomeSubscriber;

/// How long the relay holds each server datagram. It exceeds the time the
/// client needs to send its first flight, so that flight always carries the
/// request as early data.
const RELAY_DELAY: Duration = Duration::from_millis(150);

pub(super) type Served = Arc<Mutex<Vec<String>>>;

fn trusting_connector(identity: &TestIdentity) -> TestResult<Http3Connector> {
    trusting_connector_with(identity, &chromium::v154_http3())
}

/// The Chrome 154 recipes with stateless QPACK request encoding, whose
/// requests do not wait for the peer's SETTINGS and so can leave in 0-RTT.
fn stateless_connector(identity: &TestIdentity) -> TestResult<Http3Connector> {
    let mut http3 = chromium::v154_http3();
    http3.qpack_encoding = phantom_profile::Http3QpackEncoding::Stateless;
    trusting_connector_with(identity, &http3)
}

fn trusting_connector_with(
    identity: &TestIdentity,
    http3: &phantom_profile::Http3Settings,
) -> TestResult<Http3Connector> {
    Ok(Http3Connector::new_with_additional_roots(
        &chromium::v154_http3_tls(),
        &chromium::v154_quic(),
        http3,
        &chromium::v154_http3_request(),
        [identity.root_der()],
    )?)
}

/// A QUIC server configuration whose tickets permit early data when
/// `early_data` is set, and which then accepts it.
pub(super) fn server_config(
    identity: &TestIdentity,
    early_data: bool,
) -> TestResult<quinn::ServerConfig> {
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

/// Serves every request on every connection with `200`, recording paths.
pub(super) fn spawn_h3_server(endpoint: quinn::Endpoint, served: Served) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let served = Arc::clone(&served);
            tokio::spawn(async move {
                let Ok(connection) = incoming.await else {
                    return;
                };
                let Ok(mut connection) =
                    h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection))
                        .await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = connection.accept().await {
                    let Ok((request, mut stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    while let Ok(Some(mut data)) = stream.recv_data().await {
                        data.advance(data.remaining());
                    }
                    if let Ok(mut served) = served.lock() {
                        served.push(request.uri().path().to_owned());
                    }
                    let Ok(response) = Response::builder().status(StatusCode::OK).body(()) else {
                        return;
                    };
                    if stream.send_response(response).await.is_err()
                        || stream.finish().await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    })
}

/// Forwards one client's datagrams to `server` at once and the server's
/// replies after [`RELAY_DELAY`].
async fn delaying_relay(server: SocketAddr) -> TestResult<(SocketAddr, JoinHandle<()>)> {
    let front = Arc::new(UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?);
    let back = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    back.connect(server).await?;
    let address = front.local_addr()?;
    let task = tokio::spawn(async move {
        let mut client = None;
        let mut upstream = vec![0; 65_535];
        let mut downstream = vec![0; 65_535];
        loop {
            tokio::select! {
                received = front.recv_from(&mut upstream) => {
                    let Ok((len, from)) = received else { return };
                    client = Some(from);
                    let _ = back.send(&upstream[..len]).await;
                }
                received = back.recv(&mut downstream) => {
                    let Ok(len) = received else { return };
                    let Some(to) = client else { continue };
                    let front = Arc::clone(&front);
                    let datagram = downstream[..len].to_vec();
                    tokio::spawn(async move {
                        tokio::time::sleep(RELAY_DELAY).await;
                        let _ = front.send_to(&datagram, to).await;
                    });
                }
            }
        }
    });
    Ok((address, task))
}

async fn connect(connector: &Http3Connector, address: SocketAddr) -> TestResult<Http3Connection> {
    Ok(timeout(
        TEST_TIMEOUT,
        connector.connect_direct(&address.ip().to_string(), address.port(), TEST_SERVER_NAME),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??)
}

async fn wait_for_ticket(connector: &Http3Connector) -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        while !connector.has_ticket_for(TEST_SERVER_NAME) {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "no session ticket arrived".into())
}

async fn send(
    connector: &Http3Connector,
    connection: &Http3Connection,
    method: Method,
    path: &str,
    body: Option<Bytes>,
) -> TestResult<Response<super::super::Http3Body>> {
    Ok(connector
        .send_request_on(
            connection,
            method,
            TEST_SERVER_NAME,
            OriginForm::parse(path)?,
            Vec::new(),
            body,
        )
        .await?)
}

/// Learns a ticket that permits early data and returns the server address.
pub(super) async fn learn_ticket(
    identity: &TestIdentity,
    isolated: &Http3Connector,
    served: &Served,
) -> TestResult<(SocketAddr, quinn::Endpoint, JoinHandle<()>)> {
    let endpoint = quinn::Endpoint::server(
        server_config(identity, true)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let server = spawn_h3_server(endpoint.clone(), Arc::clone(served));
    let learning = connect(isolated, address).await?;
    wait_for_ticket(isolated).await?;
    drop(learning);
    Ok((address, endpoint, server))
}

#[tokio::test(flavor = "current_thread")]
async fn replay_safe_request_is_sent_as_early_data_only_when_offered() -> TestResult<()> {
    OutcomeSubscriber::install_dynamic_callsite_fallback();
    let identity = TestIdentity::generate()?;
    let served = Served::default();
    // The Chrome 154 recipe offers early data; the plain clone shares its
    // ticket cache but does not.
    let early = stateless_connector(&identity)?.with_isolated_session_cache();
    assert!(!early.requests_wait_for_peer_settings());
    let isolated = early.without_early_data();
    assert!(early.sends_early_data());
    assert!(!isolated.sends_early_data());
    let (address, _endpoint, server) = learn_ticket(&identity, &isolated, &served).await?;

    // Without early data the connection resumes and waits for its handshake.
    let (relay, plain_relay) = delaying_relay(address).await?;
    let plain = connect(&isolated, relay).await?;
    assert!(plain.session_resumed());
    assert!(!plain.sent_early_data());
    assert_eq!(plain.early_data_accepted().await, None);
    wait_for_ticket(&isolated).await?;

    let (relay, early_relay) = delaying_relay(address).await?;
    let subscriber = OutcomeSubscriber::default();
    let (connection, response) = async {
        let connection = connect(&early, relay).await?;
        let response = send(&early, &connection, Method::GET, "/early", None).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((connection, response))
    }
    .with_subscriber(subscriber.dispatch())
    .await?;
    assert!(connection.sent_early_data());
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(connection.early_data_accepted().await, Some(true));
    assert_eq!(
        subscriber.field_values_for("http3.response_head", "early_data"),
        ["sent"]
    );
    assert!(connection.session_resumed());

    drop((plain, connection, response));
    plain_relay.abort();
    early_relay.abort();
    server.abort();
    Ok(())
}

/// Under the recipe's dynamic QPACK policy a request waits for the peer's
/// SETTINGS. A resumed connection starts from the SETTINGS remembered with its
/// ticket, so a replay-safe request's stream opens before the handshake, as
/// Chromium sends it in 0-RTT.
#[tokio::test(flavor = "current_thread")]
async fn dynamic_qpack_sends_a_replay_safe_request_early_from_remembered_settings() -> TestResult<()>
{
    OutcomeSubscriber::install_dynamic_callsite_fallback();
    let identity = TestIdentity::generate()?;
    let served = Served::default();
    let early = trusting_connector(&identity)?.with_isolated_session_cache();
    assert!(early.requests_wait_for_peer_settings());
    let (address, _endpoint, server) = learn_ticket(&identity, &early, &served).await?;

    let (relay, relay_task) = delaying_relay(address).await?;
    let subscriber = OutcomeSubscriber::default();
    let (connection, response) = async {
        let connection = connect(&early, relay).await?;
        let response = send(&early, &connection, Method::GET, "/early", None).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((connection, response))
    }
    .with_subscriber(subscriber.dispatch())
    .await?;
    assert!(connection.sent_early_data());
    assert!(connection.started_from_remembered_settings());
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(connection.early_data_accepted().await, Some(true));
    assert_eq!(
        subscriber.field_values_for("http3.response_head", "early_data"),
        ["sent"]
    );

    drop((connection, response));
    relay_task.abort();
    server.abort();
    Ok(())
}

/// A server that accepts early data and then lowers a limit the remembered
/// SETTINGS promised is closed with `H3_SETTINGS_ERROR` (RFC 9114, section
/// 7.2.4.2).
#[tokio::test(flavor = "current_thread")]
async fn a_server_that_reduces_a_remembered_setting_is_closed_with_settings_error() -> TestResult<()>
{
    const H3_SETTINGS_ERROR: u32 = 0x109;
    let identity = TestIdentity::generate()?;
    let early = trusting_connector(&identity)?.with_isolated_session_cache();
    let endpoint = quinn::Endpoint::server(
        server_config(&identity, true)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let (closed_tx, mut closed) = tokio::sync::mpsc::unbounded_channel();
    let server = tokio::spawn(async move {
        // The resumed connection lowers the field-section limit that the
        // ticket's connection advertised.
        for limit in [16_384, 8_192] {
            let Some(incoming) = endpoint.accept().await else {
                return;
            };
            let closed_tx = closed_tx.clone();
            tokio::spawn(async move {
                let Ok(quic) = incoming.await else {
                    return;
                };
                let Ok(mut connection) = h3::server::builder()
                    .max_field_section_size(limit)
                    .build::<_, Bytes>(h3_quinn::Connection::new(quic.clone()))
                    .await
                else {
                    return;
                };
                while let Ok(Some(_resolver)) = connection.accept().await {}
                let _ = closed_tx.send((limit, quic.closed().await));
            });
        }
    });

    let learning = connect(&early, address).await?;
    wait_for_ticket(&early).await?;
    drop(learning);
    let resumed = connect(&early, address).await?;
    assert!(resumed.sent_early_data());
    assert!(resumed.started_from_remembered_settings());
    // The server accepted the early data, so its SETTINGS were bound by the
    // remembered ones.
    assert_eq!(resumed.early_data_accepted().await, Some(true));
    let reason = timeout(TEST_TIMEOUT, async {
        while let Some((limit, reason)) = closed.recv().await {
            if limit == 8_192 {
                return Some(reason);
            }
        }
        None
    })
    .await
    .map_err(|_| "the resumed connection stayed open")?
    .ok_or("the server stopped")?;
    match reason {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert_eq!(close.error_code, quinn::VarInt::from_u32(H3_SETTINGS_ERROR));
        }
        other => return Err(format!("unexpected close: {other}").into()),
    }
    assert!(!early.can_reuse(&resumed).await);

    drop(resumed);
    server.abort();
    Ok(())
}

/// State stored with a ticket that does not decode as SETTINGS fails the
/// connection with a protocol error at once and closes it, without a panic,
/// a hang, or a second connection attempt.
#[tokio::test(flavor = "current_thread")]
async fn malformed_remembered_settings_fail_the_connection() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let served = Served::default();
    let isolated = trusting_connector(&identity)?.with_isolated_session_cache();
    let (address, _endpoint, server) = learn_ticket(&identity, &isolated, &served).await?;
    // A SETTINGS frame that ends inside a varint.
    let corrupt = isolated.with_test_remembered_settings(&[0x04, 0x02, 0x01]);

    let result = timeout(
        TEST_TIMEOUT,
        corrupt.connect_direct(&address.ip().to_string(), address.port(), TEST_SERVER_NAME),
    )
    .await
    .map_err(|_| "a connection with corrupt remembered SETTINGS hung")?;
    let error = match result {
        Ok(_) => return Err("corrupt remembered SETTINGS produced a connection".into()),
        Err(error) => error,
    };
    let error = http3_error(&error).ok_or("connection failure lost its HTTP/3 error")?;
    assert_eq!(error.kind(), super::super::Http3ErrorKind::Protocol);
    assert_eq!(error.to_string(), "remembered HTTP/3 SETTINGS are invalid");
    assert!(
        served
            .lock()
            .map_err(|_| "served paths poisoned")?
            .is_empty()
    );

    server.abort();
    Ok(())
}

/// Remembered SETTINGS are read back only with a ticket from the same cache,
/// meaning the same origin and route, for the same verified server name.
#[tokio::test(flavor = "current_thread")]
async fn remembered_settings_stay_with_their_ticket_cache_and_server_name() -> TestResult<()> {
    const OTHER_NAME: &str = "other.phantom.test";
    let identity = TestIdentity::generate_for_names(&[TEST_SERVER_NAME, OTHER_NAME])?;
    let served = Served::default();
    let early = trusting_connector(&identity)?.with_isolated_session_cache();
    let (address, _endpoint, server) = learn_ticket(&identity, &early, &served).await?;

    // Another cache, as for another route to the same origin.
    let sibling = trusting_connector(&identity)?.with_isolated_session_cache();
    let other_route = connect(&sibling, address).await?;
    assert!(!other_route.session_resumed());
    assert!(!other_route.started_from_remembered_settings());

    // The same cache, for another server name.
    let other_name = timeout(
        TEST_TIMEOUT,
        early.connect_direct(&address.ip().to_string(), address.port(), OTHER_NAME),
    )
    .await
    .map_err(|_| "HTTP/3 connection timed out")??;
    assert!(!other_name.sent_early_data());
    assert!(!other_name.started_from_remembered_settings());

    let resumed = connect(&early, address).await?;
    assert!(resumed.sent_early_data());
    assert!(resumed.started_from_remembered_settings());

    drop((other_route, other_name, resumed));
    server.abort();
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn a_request_that_is_not_replay_safe_waits_for_the_handshake() -> TestResult<()> {
    OutcomeSubscriber::install_dynamic_callsite_fallback();
    let identity = TestIdentity::generate()?;
    let served = Served::default();
    let isolated = trusting_connector(&identity)?.with_isolated_session_cache();
    let early = isolated.with_early_data();
    let (address, _endpoint, server) = learn_ticket(&identity, &isolated, &served).await?;

    let (relay, relay_task) = delaying_relay(address).await?;
    let subscriber = OutcomeSubscriber::default();
    let responses = async {
        let connection = connect(&early, relay).await?;
        assert!(connection.sent_early_data());
        // A body, and in the second request an unsafe method without one,
        // each make the request unsafe to replay.
        let post = send(
            &early,
            &connection,
            Method::POST,
            "/post",
            Some(Bytes::from_static(b"body")),
        )
        .await?;
        let delete = send(&early, &connection, Method::DELETE, "/delete", None).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>((connection, post, delete))
    }
    .with_subscriber(subscriber.dispatch())
    .await?;
    let (connection, post, delete) = responses;
    assert_eq!(post.status(), StatusCode::OK);
    assert_eq!(delete.status(), StatusCode::OK);
    assert_eq!(
        subscriber.field_values_for("http3.response_head", "early_data"),
        ["after_handshake", "after_handshake"]
    );

    drop((connection, post, delete));
    relay_task.abort();
    server.abort();
    Ok(())
}

/// Paths served by [`spawn_counting_server`], each with its connection's index.
type ServedOn = Arc<Mutex<Vec<(usize, String)>>>;

/// Serves `200` on one connection per entry of `field_section_limits`, each
/// advertising that `SETTINGS_MAX_FIELD_SECTION_SIZE`, and records every
/// served path with the index of its connection.
fn spawn_counting_server(
    endpoint: quinn::Endpoint,
    field_section_limits: Vec<u64>,
) -> (JoinHandle<()>, ServedOn) {
    let served = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&served);
    let task = tokio::spawn(async move {
        for (index, limit) in field_section_limits.into_iter().enumerate() {
            let Some(incoming) = endpoint.accept().await else {
                return;
            };
            let served = Arc::clone(&served);
            tokio::spawn(async move {
                let Ok(quic) = incoming.await else {
                    return;
                };
                let Ok(mut connection) = h3::server::builder()
                    .max_field_section_size(limit)
                    .build::<_, Bytes>(h3_quinn::Connection::new(quic))
                    .await
                else {
                    return;
                };
                while let Ok(Some(resolver)) = connection.accept().await {
                    let Ok((request, mut stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    while let Ok(Some(mut data)) = stream.recv_data().await {
                        data.advance(data.remaining());
                    }
                    if let Ok(mut served) = served.lock() {
                        served.push((index, request.uri().path().to_owned()));
                    }
                    let Ok(response) = Response::builder().status(StatusCode::OK).body(()) else {
                        return;
                    };
                    if stream.send_response(response).await.is_err()
                        || stream.finish().await.is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    (task, recorded)
}

fn unprocessed(error: &(dyn std::error::Error + 'static)) -> Option<Http3Unprocessed> {
    error
        .downcast_ref::<Http3ConnectorError>()
        .and_then(std::error::Error::source)
        .and_then(|source| source.downcast_ref::<Http3Error>())
        .and_then(Http3Error::unprocessed)
}

/// When the server rejects early data, the request that went out early is
/// reported as unprocessed, and the same connection then carries requests
/// on a new HTTP/3 session, as Chromium resends on the connection whose
/// early data was rejected. The server sees no second connection.
#[tokio::test(flavor = "current_thread")]
async fn rejected_early_data_restarts_http3_on_the_same_connection() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let early = trusting_connector(&identity)?.with_isolated_session_cache();
    let endpoint = quinn::Endpoint::server(
        server_config(&identity, true)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let (server, served) = spawn_counting_server(endpoint.clone(), vec![16_384, 16_384]);
    let learning = connect(&early, address).await?;
    wait_for_ticket(&early).await?;
    drop(learning);
    // The server now declines early data, as after a key rotation.
    endpoint.set_server_config(Some(server_config(&identity, false)?));

    let (relay, relay_task) = delaying_relay(address).await?;
    let connection = connect(&early, relay).await?;
    assert!(connection.sent_early_data());
    assert!(connection.started_from_remembered_settings());
    let error = match send(&early, &connection, Method::GET, "/early", None).await {
        Ok(_) => return Err("rejected early data produced a response".into()),
        Err(error) => error,
    };
    assert_eq!(
        unprocessed(error.as_ref()),
        Some(Http3Unprocessed::EarlyDataRejected)
    );
    assert_eq!(connection.early_data_accepted().await, Some(false));
    assert!(!connection.early_data_pending());
    connection.early_data_settled().await?;
    assert!(early.can_reuse(&connection).await);

    let again = send(&early, &connection, Method::GET, "/early", None).await?;
    assert_eq!(again.status(), StatusCode::OK);
    let post = send(
        &early,
        &connection,
        Method::POST,
        "/post",
        Some(Bytes::from_static(b"body")),
    )
    .await?;
    assert_eq!(post.status(), StatusCode::OK);
    let served = served.lock().map_err(|_| "served paths poisoned")?.clone();
    assert_eq!(
        served,
        [(1, "/early".to_owned()), (1, "/post".to_owned())],
        "both requests reached the resumed connection, and nothing else did"
    );

    drop((connection, again, post));
    relay_task.abort();
    server.abort();
    Ok(())
}

/// A request stream is opened on an early session only while the handshake
/// runs or after the server accepted the early data. Between the completed
/// handshake and the published answer, opening waits; after a rejection it
/// fails without allocating a stream, so the session that replaces it
/// numbers its streams from 0.
#[tokio::test(flavor = "current_thread")]
async fn an_early_session_opens_no_stream_between_the_handshake_and_the_answer() -> TestResult<()> {
    use std::future::poll_fn;

    use h3::quic::{OpenStreams as _, SendStream as _};

    use super::super::{early_data::EarlyDataOutcome, early_streams::Transport};

    let identity = TestIdentity::generate()?;
    let served = Served::default();
    let connector = trusting_connector(&identity)?;
    let endpoint = quinn::Endpoint::server(
        server_config(&identity, false)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let server = spawn_h3_server(endpoint, served);
    let connection = connect(&connector, address).await?;
    let quinn = connection.quinn().clone();
    assert!(quinn.handshake_data().is_some());

    let (answer, outcome) = tokio::sync::watch::channel(None);
    let transport = Transport::early(quinn.clone(), outcome.clone());
    let mut rejected = quic_opener(&transport);
    let waiting = timeout(
        Duration::from_millis(100),
        poll_fn(|cx| rejected.poll_open_bidi(cx)),
    )
    .await;
    assert!(waiting.is_err(), "a stream opened before the answer");
    answer.send_replace(Some(EarlyDataOutcome::Rejected));
    let refused = timeout(TEST_TIMEOUT, poll_fn(|cx| rejected.poll_open_bidi(cx))).await?;
    assert!(refused.is_err(), "the discarded session opened a stream");
    let (_send, _recv) = quinn.open_bi().await?;
    assert_eq!(
        u64::from(_send.id()),
        0,
        "the refused open allocated a stream"
    );

    let (answer, outcome) = tokio::sync::watch::channel(None);
    let transport = Transport::early(quinn.clone(), outcome);
    let mut accepted = quic_opener(&transport);
    answer.send_replace(Some(EarlyDataOutcome::Accepted));
    let stream = timeout(TEST_TIMEOUT, poll_fn(|cx| accepted.poll_open_bidi(cx))).await??;
    assert_eq!(stream.send_id().into_inner(), 4);

    drop((stream, connection));
    server.abort();
    Ok(())
}

fn quic_opener(
    transport: &super::super::early_streams::Transport,
) -> super::super::early_streams::Opener<Bytes> {
    h3::quic::Connection::<Bytes>::opener(transport)
}

/// A request that takes the sender after the TLS handshake completed but
/// before the answer to rejected early data is published waits for the
/// answer and is sent once, on the new session.
#[tokio::test(flavor = "current_thread")]
async fn a_request_between_the_handshake_and_a_rejection_is_sent_once() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let hold = Arc::new(tokio::sync::Semaphore::new(0));
    let early = Arc::new(
        trusting_connector(&identity)?
            .with_isolated_session_cache()
            .with_test_restart_hold(Arc::clone(&hold)),
    );
    let endpoint = quinn::Endpoint::server(
        server_config(&identity, true)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let (server, served) = spawn_counting_server(endpoint.clone(), vec![16_384, 16_384]);
    let learning = connect(&early, address).await?;
    wait_for_ticket(&early).await?;
    drop(learning);
    endpoint.set_server_config(Some(server_config(&identity, false)?));

    let connection = connect(&early, address).await?;
    assert!(connection.sent_early_data());
    timeout(TEST_TIMEOUT, async {
        while connection.quinn().handshake_data().is_none() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "the handshake did not complete")?;
    assert!(connection.early_data_pending());

    let request = tokio::spawn({
        let early = Arc::clone(&early);
        let connection = connection.clone();
        async move {
            send(&early, &connection, Method::GET, "/between", None)
                .await
                .map(|response| response.status())
                .map_err(|error| error.to_string())
        }
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !request.is_finished(),
        "the request did not wait for the answer"
    );
    assert!(
        served
            .lock()
            .map_err(|_| "served paths poisoned")?
            .is_empty()
    );

    hold.add_permits(1);
    let status = timeout(TEST_TIMEOUT, request).await???;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(connection.early_data_accepted().await, Some(false));
    let served = served.lock().map_err(|_| "served paths poisoned")?.clone();
    assert_eq!(served, [(1, "/between".to_owned())]);

    drop(connection);
    server.abort();
    Ok(())
}

/// After rejected early data the new HTTP/3 session starts without the
/// SETTINGS remembered with the ticket, so a server that lowers a remembered
/// limit is not closed, where an accepting server is closed with
/// `H3_SETTINGS_ERROR`. Chromium keeps the remembered values after a
/// rejection and closes such a connection with the transport error
/// `INTERNAL_ERROR`.
#[tokio::test(flavor = "current_thread")]
async fn rejected_early_data_discards_the_remembered_settings() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let early = trusting_connector(&identity)?.with_isolated_session_cache();
    let endpoint = quinn::Endpoint::server(
        server_config(&identity, true)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let (server, served) = spawn_counting_server(endpoint.clone(), vec![16_384, 8_192]);
    let learning = connect(&early, address).await?;
    wait_for_ticket(&early).await?;
    drop(learning);
    endpoint.set_server_config(Some(server_config(&identity, false)?));

    let connection = connect(&early, address).await?;
    assert!(connection.started_from_remembered_settings());
    assert_eq!(connection.early_data_accepted().await, Some(false));
    let response = send(&early, &connection, Method::GET, "/lowered", None).await?;
    assert_eq!(response.status(), StatusCode::OK);
    drop(response);
    // The server sends no ALPS, so this waits for its control-stream
    // SETTINGS, which lower the remembered field-section limit.
    timeout(TEST_TIMEOUT, connection.peer_extensions())
        .await
        .map_err(|_| "the server's SETTINGS never arrived")??;
    let response = send(&early, &connection, Method::GET, "/again", None).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(connection.quinn().close_reason().is_none());
    assert!(early.can_reuse(&connection).await);
    let served = served.lock().map_err(|_| "served paths poisoned")?.clone();
    assert_eq!(
        served,
        [(1, "/lowered".to_owned()), (1, "/again".to_owned())]
    );

    drop((connection, response));
    server.abort();
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn early_data_client_hello_adds_only_early_data_and_pre_shared_key() -> TestResult<()> {
    use super::connector::{
        CHROME_154_H3_CLIENT_HELLO_1, CHROME_154_H3_STARTUP, PRE_SHARED_KEY,
        assert_client_hello_matches_capture,
    };
    const EARLY_DATA: u16 = 42;

    let identity = TestIdentity::generate()?;
    let served = Served::default();
    let isolated = trusting_connector(&identity)?.with_isolated_session_cache();
    let early = isolated.with_early_data();
    let (_address, _endpoint, server) = learn_ticket(&identity, &isolated, &served).await?;

    let extensions = assert_client_hello_matches_capture(
        &early,
        CHROME_154_H3_STARTUP,
        CHROME_154_H3_CLIENT_HELLO_1,
        &[EARLY_DATA, PRE_SHARED_KEY],
    )?;
    assert!(extensions.contains(&EARLY_DATA));

    server.abort();
    Ok(())
}

/// Encodes one HTTP/3 frame whose type and length fit one varint byte each,
/// or a two-byte type for `ACCEPT_CH` (0x89).
fn alps_frame(frame_type: u64, payload: &[u8]) -> Vec<u8> {
    let mut frame = match u8::try_from(frame_type) {
        Ok(frame_type) if frame_type < 0x40 => vec![frame_type],
        _ => vec![0x40 | ((frame_type >> 8) as u8), frame_type as u8],
    };
    frame.push(u8::try_from(payload.len()).unwrap_or(u8::MAX));
    frame.extend_from_slice(payload);
    frame
}

/// Extracts the HTTP/3 error behind a connector request failure.
fn http3_error<'a>(error: &'a (dyn std::error::Error + 'static)) -> Option<&'a Http3Error> {
    error
        .downcast_ref::<Http3ConnectorError>()
        .and_then(std::error::Error::source)
        .and_then(|source| source.downcast_ref::<Http3Error>())
}

#[tokio::test(flavor = "current_thread")]
async fn accepted_early_data_applies_peer_alps_once_the_handshake_completes() -> TestResult<()> {
    const ORIGIN: &str = "https://server.phantom.test";
    let identity = TestIdentity::generate()?;
    let served = Served::default();
    let isolated = trusting_connector(&identity)?.with_isolated_session_cache();
    // A SETTINGS frame the server's control stream and the remembered
    // SETTINGS agree with, the largest field-section limit, then an
    // ACCEPT_CH entry for the origin.
    let mut alps = alps_frame(
        0x04,
        &[0x06, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
    );
    let mut entry = vec![u8::try_from(ORIGIN.len())?];
    entry.extend_from_slice(ORIGIN.as_bytes());
    entry.push(14);
    entry.extend_from_slice(b"Sec-CH-UA-Arch");
    alps.extend(alps_frame(0x89, &entry));
    let early = isolated.with_early_data().with_test_early_peer_alps(&alps);
    let (address, _endpoint, server) = learn_ticket(&identity, &isolated, &served).await?;

    let (relay, relay_task) = delaying_relay(address).await?;
    let connection = connect(&early, relay).await?;
    assert!(connection.sent_early_data());
    // The handshake has not completed, so no ALPS is known yet.
    assert_eq!(connection.accept_ch_for_origin(ORIGIN), None);
    let first = send(&early, &connection, Method::GET, "/early", None).await?;
    assert_eq!(first.status(), StatusCode::OK);
    assert_eq!(connection.early_data_accepted().await, Some(true));
    assert_eq!(
        connection.accept_ch_for_origin(ORIGIN),
        Some(&b"Sec-CH-UA-Arch"[..])
    );
    assert!(early.can_reuse(&connection).await);
    let second = send(&early, &connection, Method::GET, "/reused", None).await?;
    assert_eq!(second.status(), StatusCode::OK);

    drop((connection, first, second));
    relay_task.abort();
    server.abort();
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn invalid_peer_alps_on_accepted_early_data_fails_the_request_and_closes() -> TestResult<()> {
    let cases: [(&str, Vec<u8>, &str); 2] = [
        // An ACCEPT_CH entry that ends inside its origin length.
        (
            "/accept-ch",
            alps_frame(0x89, &[0x05]),
            "peer HTTP/3 ALPS metadata is invalid",
        ),
        // A SETTINGS frame that ends inside a varint.
        (
            "/settings",
            alps_frame(0x04, &[0x01, 0x40]),
            "peer HTTP/3 application settings are invalid",
        ),
    ];
    for (path, alps, message) in cases {
        let identity = TestIdentity::generate()?;
        let served = Served::default();
        let isolated = trusting_connector(&identity)?.with_isolated_session_cache();
        let early = isolated.with_early_data().with_test_early_peer_alps(&alps);
        let (address, _endpoint, server) = learn_ticket(&identity, &isolated, &served).await?;

        let (relay, relay_task) = delaying_relay(address).await?;
        let connection = connect(&early, relay).await?;
        assert!(connection.sent_early_data());
        let error = match send(&early, &connection, Method::GET, path, None).await {
            Ok(_) => return Err(format!("{path}: invalid ALPS produced a response").into()),
            Err(error) => error,
        };
        let error = http3_error(error.as_ref()).ok_or("request failure lost its HTTP/3 error")?;
        assert_eq!(
            error.kind(),
            super::super::Http3ErrorKind::Protocol,
            "{path}"
        );
        assert_eq!(error.to_string(), message, "{path}");
        assert_eq!(error.unprocessed(), None, "{path}");
        assert_eq!(
            connection.early_data_accepted().await,
            Some(false),
            "{path}"
        );
        assert!(!early.can_reuse(&connection).await, "{path}");
        assert_eq!(
            connection.accept_ch_for_origin("https://server.phantom.test"),
            None
        );

        drop(connection);
        relay_task.abort();
        server.abort();
    }
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn alps_settings_that_conflict_with_the_control_stream_close_the_connection() -> TestResult<()>
{
    let identity = TestIdentity::generate()?;
    let served = Served::default();
    let isolated = trusting_connector(&identity)?.with_isolated_session_cache();
    // The server's control stream sends SETTINGS_ENABLE_CONNECT_PROTOCOL = 0,
    // which may not follow an ALPS value of 1, as on a full handshake.
    let early = isolated
        .with_early_data()
        .with_test_early_peer_alps(&alps_frame(0x04, &[0x08, 0x01]));
    let (address, _endpoint, server) = learn_ticket(&identity, &isolated, &served).await?;

    let (relay, relay_task) = delaying_relay(address).await?;
    let connection = connect(&early, relay).await?;
    let _ = send(&early, &connection, Method::GET, "/conflict", None).await;
    let closed = timeout(TEST_TIMEOUT, async {
        while early.can_reuse(&connection).await {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await;
    assert!(closed.is_ok(), "the conflicting connection stayed reusable");

    drop(connection);
    relay_task.abort();
    server.abort();
    Ok(())
}
