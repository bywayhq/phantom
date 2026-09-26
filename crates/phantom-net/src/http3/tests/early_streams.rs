//! The early session's stream gate: which requests may open a stream while
//! a connection's early data is unanswered, and how a rejection releases
//! them.

use std::{
    future::poll_fn,
    net::Ipv4Addr,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Wake, Waker},
    time::Duration,
};

use bytes::Bytes;
use h3::quic::{OpenStreams as _, SendStream as _};
use http::{Method, StatusCode};
use tokio::{sync::watch, time::timeout};

use super::super::{
    GateDelay, Http3Unprocessed,
    early_data::EarlyDataOutcome,
    early_streams::{Opener, Transport, ZeroRttAnswer},
};
use super::early_data::{
    Served, StreamTypes, alps_frame, connect, delaying_relay, send, server_config,
    spawn_counting_server, spawn_h3_server, spawn_recording_server, trusting_connector,
    trusting_connector_with, unprocessed, wait_for_ticket,
};
use super::{TEST_TIMEOUT, TestResult};
use crate::tls::test_support::TestIdentity;

type Answer = watch::Sender<Option<bool>>;
type Published = watch::Sender<Option<EarlyDataOutcome>>;

/// A gated transport over `quinn` whose answers the test sends.
fn gated(quinn: &quinn::Connection) -> (Answer, Published, Transport) {
    let (answer, answer_rx) = watch::channel(None);
    let (published, published_rx) = watch::channel(None);
    let transport = Transport::early(
        quinn.clone(),
        ZeroRttAnswer::Known(true),
        answer_rx,
        published_rx,
    );
    (answer, published, transport)
}

fn opener(transport: &Transport) -> Opener<Bytes> {
    h3::quic::Connection::<Bytes>::opener(transport)
}

/// A QUIC server configuration that allows one request stream at a time.
fn one_stream_config(identity: &TestIdentity, early_data: bool) -> TestResult<quinn::ServerConfig> {
    let mut config = server_config(identity, early_data)?;
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1_u32.into());
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// A QUIC server that only holds its connections: an HTTP/3 server would
/// close the connection over a reset or unused request stream.
fn spawn_holding_server(endpoint: quinn::Endpoint) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Some(incoming) = endpoint.accept().await {
            if let Ok(connection) = incoming.await {
                held.push(connection);
            }
        }
    })
}

#[derive(Default)]
struct CountingWaker(AtomicUsize);

impl Wake for CountingWaker {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// On a connection whose handshake completed, opening waits until the
/// answer is published as an acceptance, refuses on Quinn's rejection
/// without allocating a stream, and refuses when either answer channel
/// closes unanswered. Quinn's acceptance alone does not open: the
/// handshake metadata is still unchecked.
#[tokio::test(flavor = "current_thread")]
async fn an_early_session_opens_only_on_a_published_acceptance() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = trusting_connector(&identity)?;
    let endpoint = quinn::Endpoint::server(
        server_config(&identity, false)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let server = spawn_holding_server(endpoint);
    let connection = connect(&connector, address).await?;
    let quinn = connection.quinn().clone();
    assert!(quinn.handshake_data().is_some());
    let wait = Duration::from_millis(100);

    let (answer, _published, transport) = gated(&quinn);
    let mut rejected = opener(&transport);
    let waiting = timeout(wait, poll_fn(|cx| rejected.poll_open_bidi(cx))).await;
    assert!(waiting.is_err(), "a stream opened before any answer");
    answer.send_replace(Some(false));
    let refused = timeout(TEST_TIMEOUT, poll_fn(|cx| rejected.poll_open_bidi(cx))).await?;
    assert!(refused.is_err(), "the discarded session opened a stream");
    let (first, _recv) = quinn.open_bi().await?;
    assert_eq!(
        u64::from(first.id()),
        0,
        "the refused open allocated a stream"
    );

    let (answer, published, transport) = gated(&quinn);
    let mut accepted = opener(&transport);
    answer.send_replace(Some(true));
    let waiting = timeout(wait, poll_fn(|cx| accepted.poll_open_bidi(cx))).await;
    assert!(
        waiting.is_err(),
        "Quinn's acceptance opened before the metadata checks"
    );
    published.send_replace(Some(EarlyDataOutcome::Accepted));
    let stream = timeout(TEST_TIMEOUT, poll_fn(|cx| accepted.poll_open_bidi(cx))).await??;
    assert_eq!(stream.send_id().into_inner(), 4);

    let (answer, published, transport) = gated(&quinn);
    let mut invalid = opener(&transport);
    answer.send_replace(Some(true));
    published.send_replace(Some(EarlyDataOutcome::Invalid(
        super::super::early_data::InvalidHandshake::Alps,
    )));
    let refused = timeout(TEST_TIMEOUT, poll_fn(|cx| invalid.poll_open_bidi(cx))).await?;
    assert!(
        refused.is_err(),
        "invalid handshake metadata opened a stream"
    );

    let (answer, _published, transport) = gated(&quinn);
    let mut closed = opener(&transport);
    drop(answer);
    let refused = timeout(TEST_TIMEOUT, poll_fn(|cx| closed.poll_open_bidi(cx))).await?;
    assert!(refused.is_err(), "a closed answer channel opened a stream");

    let (_answer, published, transport) = gated(&quinn);
    let mut closed = opener(&transport);
    drop(published);
    let refused = timeout(TEST_TIMEOUT, poll_fn(|cx| closed.poll_open_bidi(cx))).await?;
    assert!(
        refused.is_err(),
        "a closed published channel opened a stream"
    );

    drop((stream, connection));
    server.abort();
    Ok(())
}

/// A request that waits for 0-RTT stream credit while the handshake runs
/// has registered on the answer, so a rejection that arrives between two
/// polls wakes it and the next poll refuses.
#[tokio::test(flavor = "current_thread")]
async fn a_rejection_between_two_polls_of_a_request_waiting_for_credit_refuses_it() -> TestResult<()>
{
    let identity = TestIdentity::generate()?;
    let early = trusting_connector(&identity)?.with_isolated_session_cache();
    let endpoint = quinn::Endpoint::server(
        one_stream_config(&identity, true)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let server = spawn_h3_server(endpoint, Served::default());
    let learning = connect(&early, address).await?;
    wait_for_ticket(&early).await?;
    drop(learning);

    // The relay holds the server's replies, so the handshake is still
    // running while the test polls.
    let (relay, relay_task) = delaying_relay(address).await?;
    let connection = connect(&early, relay).await?;
    let quinn = connection.quinn().clone();
    assert!(quinn.handshake_data().is_none());
    let (answer, _published, transport) = gated(&quinn);
    let mut gated_opener = opener(&transport);
    let counter = Arc::new(CountingWaker::default());
    let waker = Waker::from(Arc::clone(&counter));
    let mut cx = Context::from_waker(&waker);

    // The one stream the remembered limit allows.
    let Poll::Ready(first) = gated_opener.poll_open_bidi(&mut cx) else {
        return Err("the first 0-RTT stream did not open".into());
    };
    let _first = first?;
    assert!(gated_opener.poll_open_bidi(&mut cx).is_pending());
    let before = counter.0.load(Ordering::SeqCst);
    answer.send_replace(Some(false));
    assert!(
        counter.0.load(Ordering::SeqCst) > before,
        "the rejection did not wake the request waiting for credit"
    );
    let Poll::Ready(refused) = gated_opener.poll_open_bidi(&mut cx) else {
        return Err("the request stayed pending after the rejection".into());
    };
    assert!(refused.is_err());

    drop(connection);
    relay_task.abort();
    server.abort();
    Ok(())
}

/// A permit granted while the handshake runs stays a handshake-time permit:
/// when the handshake completes between the permit and the open, the stream
/// that opens is held until the answer rather than returned, and a rejection
/// then resets it unused. A hook completes the handshake inside that window.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_handshake_that_completes_after_the_permit_holds_the_stream() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let early = trusting_connector(&identity)?.with_isolated_session_cache();
    let endpoint = quinn::Endpoint::server(
        server_config(&identity, true)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let server = spawn_h3_server(endpoint, Served::default());
    let learning = connect(&early, address).await?;
    wait_for_ticket(&early).await?;
    drop(learning);

    let (relay, relay_task) = delaying_relay(address).await?;
    let connection = connect(&early, relay).await?;
    let quinn = connection.quinn().clone();
    assert!(quinn.handshake_data().is_none());
    let (answer, _published, transport) = gated(&quinn);
    let mut gated_opener = opener(&transport);
    let watched = quinn.clone();
    // Blocks the polling worker, after the permit and before the open, until
    // another worker has completed the handshake.
    gated_opener.after_permit_for_test(Arc::new(move || {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while watched.handshake_data().is_none() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
    }));
    let resets = quinn.stats().frame_tx.reset_stream;

    let opened = timeout(
        Duration::from_millis(300),
        poll_fn(|cx| gated_opener.poll_open_bidi(cx)),
    )
    .await;
    assert!(quinn.handshake_data().is_some());
    assert!(
        opened.is_err(),
        "a stream opened after the handshake was returned unheld"
    );
    answer.send_replace(Some(false));
    let refused = timeout(TEST_TIMEOUT, poll_fn(|cx| gated_opener.poll_open_bidi(cx))).await?;
    assert!(
        refused.is_err(),
        "the held stream was used after a rejection"
    );
    timeout(TEST_TIMEOUT, async {
        while quinn.stats().frame_tx.reset_stream <= resets {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "the held stream was not reset")?;

    drop(connection);
    relay_task.abort();
    server.abort();
    Ok(())
}

/// A stream whose open raced the handshake's completion is held until the
/// answer. A rejection resets it unused, and so does dropping the opener
/// that holds it. Its stream number stays taken: the next stream is the
/// one after it.
#[tokio::test(flavor = "current_thread")]
async fn a_held_stream_is_reset_unused_after_a_rejection() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = trusting_connector(&identity)?;
    let endpoint = quinn::Endpoint::server(
        server_config(&identity, false)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let server = spawn_holding_server(endpoint);
    let connection = connect(&connector, address).await?;
    let quinn = connection.quinn().clone();
    let plain = Transport::new(quinn.clone());
    let wait_for_resets = |count: u64| {
        let quinn = quinn.clone();
        timeout(TEST_TIMEOUT, async move {
            while quinn.stats().frame_tx.reset_stream < count {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
    };
    let before = quinn.stats().frame_tx.reset_stream;

    let (answer, _published, transport) = gated(&quinn);
    let mut held_by = opener(&transport);
    let held = timeout(
        TEST_TIMEOUT,
        poll_fn(|cx| opener(&plain).poll_open_bidi(cx)),
    )
    .await??;
    assert_eq!(held.send_id().into_inner(), 0);
    held_by.hold_for_test(held);
    answer.send_replace(Some(false));
    let refused = timeout(TEST_TIMEOUT, poll_fn(|cx| held_by.poll_open_bidi(cx))).await?;
    assert!(refused.is_err(), "a held stream was used after a rejection");
    wait_for_resets(before + 1)
        .await
        .map_err(|_| "the held stream was not reset")?;

    let (_answer, _published, transport) = gated(&quinn);
    let mut dropped = opener(&transport);
    let held = timeout(
        TEST_TIMEOUT,
        poll_fn(|cx| opener(&plain).poll_open_bidi(cx)),
    )
    .await??;
    assert_eq!(held.send_id().into_inner(), 4);
    dropped.hold_for_test(held);
    drop(dropped);
    wait_for_resets(before + 2)
        .await
        .map_err(|_| "dropping the opener did not reset its stream")?;

    let next = timeout(
        TEST_TIMEOUT,
        poll_fn(|cx| opener(&plain).poll_open_bidi(cx)),
    )
    .await??;
    assert_eq!(next.send_id().into_inner(), 8);

    drop((next, connection));
    server.abort();
    Ok(())
}

/// Runs a request that holds the send lock while it waits for 0-RTT stream
/// credit when the server's rejection arrives. Both requests on the early
/// session fail as unprocessed instead of blocking the restart, which needs
/// that lock, and the connection then carries a request on its new session.
/// How a rejection scenario's connection met the rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Rejection {
    /// The server's answer arrived while requests were on the early session.
    InFlight,
    /// The answer arrived while the early session was still starting, so
    /// HTTP/3 started on the connection before any request.
    AtStart,
}

/// Checks a connection whose early data was rejected while its early
/// session started: the answer is settled at once, and a request goes to the
/// server once, on the session that started after it.
async fn check_rejected_at_start(
    connector: &super::super::Http3Connector,
    connection: &super::super::Http3Connection,
    served: &super::early_data::ServedOn,
    path: &str,
) -> TestResult<Rejection> {
    if connection.early_data_accepted().await != Some(false) {
        return Err("a settled early-data answer was not a rejection".into());
    }
    let response = timeout(
        TEST_TIMEOUT,
        send(connector, connection, Method::GET, path, None),
    )
    .await??;
    if response.status() != StatusCode::OK {
        return Err("the session started after the rejection did not serve".into());
    }
    let served = served.lock().map_err(|_| "served paths poisoned")?.clone();
    if served != [(1, path.to_owned())] {
        return Err(format!("unexpected requests served: {served:?}").into());
    }
    Ok(Rejection::AtStart)
}

async fn credit_wait_rejection(gate_delay: Option<GateDelay>) -> TestResult<Rejection> {
    let identity = TestIdentity::generate()?;
    let mut early = trusting_connector(&identity)?.with_isolated_session_cache();
    if let Some(delay) = gate_delay {
        early = early.with_test_gate_delay(delay);
    }
    let endpoint = quinn::Endpoint::server(
        one_stream_config(&identity, true)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let (server, served) = spawn_counting_server(endpoint.clone(), vec![16_384, 16_384]);
    let learning = connect(&early, address).await?;
    wait_for_ticket(&early).await?;
    drop(learning);
    endpoint.set_server_config(Some(server_config(&identity, false)?));

    let (relay, relay_task) = delaying_relay(address).await?;
    let connection = connect(&early, relay).await?;
    if !connection.sent_early_data() {
        return Err("the connection sent no early data".into());
    }
    if !connection.early_data_pending() {
        let rejection = check_rejected_at_start(&early, &connection, &served, "/again").await;
        relay_task.abort();
        server.abort();
        return rejection;
    }
    let (first, second) = timeout(TEST_TIMEOUT, async {
        tokio::join!(
            send(&early, &connection, Method::GET, "/first", None),
            send(&early, &connection, Method::GET, "/second", None),
        )
    })
    .await
    .map_err(|_| "the rejection was blocked by a request waiting for stream credit")?;
    for result in [first, second] {
        let error = match result {
            Ok(_) => return Err("rejected early data produced a response".into()),
            Err(error) => error,
        };
        if unprocessed(error.as_ref()) != Some(Http3Unprocessed::EarlyDataRejected) {
            return Err(format!("unexpected failure: {error}").into());
        }
    }
    let again = timeout(
        TEST_TIMEOUT,
        send(&early, &connection, Method::GET, "/again", None),
    )
    .await??;
    if again.status() != StatusCode::OK {
        return Err("the new session did not serve the request".into());
    }
    let served = served.lock().map_err(|_| "served paths poisoned")?.clone();
    if served != [(1, "/again".to_owned())] {
        return Err(format!("unexpected requests served: {served:?}").into());
    }

    drop((again, connection));
    relay_task.abort();
    server.abort();
    Ok(Rejection::InFlight)
}

/// Withholding the answer from the gate makes this test time out: a
/// request waiting for credit keeps the send lock and the restart never
/// takes it. That was checked by keeping the gate's answer channel open
/// without sending on it.
#[tokio::test(flavor = "current_thread")]
async fn a_request_waiting_for_stream_credit_does_not_block_a_rejection() -> TestResult<()> {
    credit_wait_rejection(None).await.map(|_| ())
}

/// Runs a request that takes the sender after the TLS handshake completed
/// but before the answer to rejected early data is published. It waits for
/// the answer and is sent once, on the new session. `release` is how long
/// the publication is held.
async fn handshake_window_rejection(
    gate_delay: Option<GateDelay>,
    release: Duration,
) -> TestResult<Rejection> {
    let identity = TestIdentity::generate()?;
    let hold = Arc::new(tokio::sync::Semaphore::new(0));
    let mut early = trusting_connector(&identity)?
        .with_isolated_session_cache()
        .with_test_answer_hold(Arc::clone(&hold));
    if let Some(delay) = gate_delay {
        early = early.with_test_gate_delay(delay);
    }
    let early = Arc::new(early);
    let endpoint = quinn::Endpoint::server(
        server_config(&identity, true)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let (server, served) = spawn_counting_server(endpoint.clone(), vec![16_384, 16_384]);
    // The learning connection publishes no early-data answer.
    let learning = connect(&early, address).await?;
    wait_for_ticket(&early).await?;
    drop(learning);
    endpoint.set_server_config(Some(server_config(&identity, false)?));

    let connection = connect(&early, address).await?;
    if !connection.sent_early_data() {
        return Err("the connection sent no early data".into());
    }
    if !connection.early_data_pending() {
        let rejection = check_rejected_at_start(&early, &connection, &served, "/between").await;
        server.abort();
        return rejection;
    }
    timeout(TEST_TIMEOUT, async {
        while connection.quinn().handshake_data().is_none() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .map_err(|_| "the handshake did not complete")?;
    if !connection.early_data_pending() {
        return Err("the answer was published while held".into());
    }

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
    tokio::time::sleep(release).await;
    if request.is_finished() {
        let result = request.await?;
        return Err(format!("the request did not wait for the answer: {result:?}").into());
    }
    if !served
        .lock()
        .map_err(|_| "served paths poisoned")?
        .is_empty()
    {
        return Err("the request reached the server before the answer".into());
    }
    hold.add_permits(1);
    let status = timeout(TEST_TIMEOUT, request).await???;
    if status != StatusCode::OK {
        return Err(format!("unexpected status {status}").into());
    }
    let served = served.lock().map_err(|_| "served paths poisoned")?.clone();
    if served != [(1, "/between".to_owned())] {
        return Err(format!("unexpected requests served: {served:?}").into());
    }

    drop(connection);
    server.abort();
    Ok(Rejection::InFlight)
}

#[tokio::test(flavor = "current_thread")]
async fn a_request_between_the_handshake_and_a_rejection_is_sent_once() -> TestResult<()> {
    handshake_window_rejection(None, Duration::from_millis(100))
        .await
        .map(|_| ())
}

/// A request that holds the send lock while it waits for stream credit on a
/// connection whose early data the server accepted does not open its stream
/// on Quinn's acceptance alone. The handshake metadata then fails its
/// checks, so the request fails and never reaches the server.
#[tokio::test(flavor = "current_thread")]
async fn a_parked_request_does_not_open_before_invalid_metadata_is_found() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let hold = Arc::new(tokio::sync::Semaphore::new(0));
    let isolated = trusting_connector(&identity)?.with_isolated_session_cache();
    let early = Arc::new(
        isolated
            .with_early_data()
            .with_test_early_peer_alps(&alps_frame(0x89, &[0x05]))
            .with_test_answer_hold(Arc::clone(&hold)),
    );
    let endpoint = quinn::Endpoint::server(
        one_stream_config(&identity, true)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let served = Served::default();
    let server = spawn_h3_server(endpoint, Arc::clone(&served));
    let learning = connect(&isolated, address).await?;
    wait_for_ticket(&isolated).await?;
    drop(learning);

    let (relay, relay_task) = delaying_relay(address).await?;
    let connection = connect(&early, relay).await?;
    assert!(connection.sent_early_data());
    let first = tokio::spawn({
        let connection = connection.clone();
        let early = Arc::clone(&early);
        async move {
            send(&early, &connection, Method::GET, "/first", None)
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
    });
    let second = tokio::spawn({
        let connection = connection.clone();
        let early = Arc::clone(&early);
        async move {
            send(&early, &connection, Method::GET, "/second", None)
                .await
                .map(|_| ())
                .map_err(|error| error.to_string())
        }
    });
    // Long enough for the handshake to complete and for the server's
    // response to the first request to return stream credit.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(connection.quinn().handshake_data().is_some());
    assert!(!second.is_finished(), "the parked request did not wait");
    assert_eq!(
        *served.lock().map_err(|_| "served paths poisoned")?,
        ["/first".to_owned()],
        "the parked request opened on Quinn's acceptance alone"
    );
    hold.add_permits(1);
    let (first, second) = (
        timeout(TEST_TIMEOUT, first).await??,
        timeout(TEST_TIMEOUT, second).await??,
    );
    assert!(first.is_err(), "invalid ALPS produced a response");
    assert!(second.is_err(), "invalid ALPS produced a response");
    assert_eq!(connection.early_data_accepted().await, Some(false));
    assert_eq!(
        *served.lock().map_err(|_| "served paths poisoned")?,
        ["/first".to_owned()]
    );

    drop(connection);
    relay_task.abort();
    server.abort();
    Ok(())
}

/// Returns delays of 0 to 3 ms from a small generator, so each connection
/// passes Quinn's answer to the stream gate at a different point.
fn random_gate_delay(seed: u64) -> GateDelay {
    let state = Arc::new(AtomicU64::new(seed | 1));
    GateDelay(Arc::new(move || {
        let mut value = state.load(Ordering::Relaxed);
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        state.store(value, Ordering::Relaxed);
        Duration::from_micros(value % 3_000)
    }))
}

fn stress_iterations() -> usize {
    std::env::var("PHANTOM_H3_STRESS_ITERATIONS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10)
}

/// Repeats both rejection scenarios on a four-worker runtime, with a random
/// delay between the driver receiving Quinn's answer and the stream gate
/// seeing it. `PHANTOM_H3_STRESS_ITERATIONS` sets the repetitions (10 by
/// default) and `PHANTOM_H3_STRESS_SEED` the delay seed, which every failure
/// and the final counts report. The seed reproduces only the injected
/// delays, not the scheduling of the runtime or the network. A connection
/// whose rejection arrived while its early session was still starting is
/// checked and counted as its own outcome.
///
/// The delays fall between whole polls, so the test does not reach windows
/// inside one poll, such as the handshake completing between the permit and
/// the open; the hook-driven unit tests above cover those.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejection_scenarios_hold_under_a_multi_threaded_runtime() -> TestResult<()> {
    let iterations = stress_iterations();
    let seed = match std::env::var("PHANTOM_H3_STRESS_SEED") {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| format!("PHANTOM_H3_STRESS_SEED is not a u64: {value:?}"))?,
        Err(_) => std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos() as u64)
            .unwrap_or(0x9e37_79b9_7f4a_7c15),
    };
    let mut credit_wait = [0_usize; 2];
    let mut handshake_window = [0_usize; 2];
    let index = |rejection| match rejection {
        Rejection::InFlight => 0,
        Rejection::AtStart => 1,
    };
    for iteration in 0..iterations {
        let mixed = seed ^ (iteration as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15);
        let delay = random_gate_delay(mixed);
        let rejection = credit_wait_rejection(Some(delay.clone()))
            .await
            .map_err(|error| format!("credit wait, seed {seed}, iteration {iteration}: {error}"))?;
        credit_wait[index(rejection)] += 1;
        let release = Duration::from_micros(mixed.rotate_left(17) % 5_000);
        let rejection = handshake_window_rejection(Some(delay), release)
            .await
            .map_err(|error| {
                format!("handshake window, seed {seed}, iteration {iteration}: {error}")
            })?;
        handshake_window[index(rejection)] += 1;
    }
    println!(
        "seed {seed}: {iterations} iterations; credit wait passed {} in flight and {} at \
         start; handshake window passed {} in flight and {} at start",
        credit_wait[0], credit_wait[1], handshake_window[0], handshake_window[1]
    );
    Ok(())
}

/// The Chrome HTTP/3 profile with both QPACK stream types written when the
/// session starts, so a server reads the type of every critical stream. The
/// QPACK stream order stays Chrome's: decoder, then encoder.
fn typed_critical_streams() -> phantom_profile::Http3Settings {
    let mut settings = phantom_profile::chromium::v154_http3();
    settings.qpack_decoder_stream = phantom_profile::Http3QpackDecoderStream::Eager;
    settings.qpack_encoder_stream = phantom_profile::Http3QpackEncoderStream::Eager;
    settings
}

/// Waits until the server read the types of client streams 2, 6 and 10 on
/// its connection `index`, and checks they are the control stream and the
/// QPACK decoder and encoder streams, in the Chrome profile's order.
async fn check_critical_stream_types(types: &StreamTypes, index: usize) -> TestResult<()> {
    const EXPECTED: [(u64, u64); 3] = [(2, 0x00), (6, 0x03), (10, 0x02)];
    timeout(TEST_TIMEOUT, async {
        loop {
            let mut seen = types
                .lock()
                .map_err(|_| "stream types poisoned")?
                .iter()
                .filter(|(connection, id, _)| *connection == index && *id < 14)
                .map(|(_, id, stream_type)| (*id, *stream_type))
                .collect::<Vec<_>>();
            seen.sort_unstable();
            if seen.len() >= EXPECTED.len() {
                if seen != EXPECTED {
                    return Err(format!("unexpected critical stream types: {seen:x?}").into());
                }
                return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .map_err(|_| "the server did not read three critical stream types")?
}

/// A server that rejects early data while the early HTTP/3 session is still
/// writing its first stream bytes leaves the connection open: HTTP/3 starts
/// on it as on a connection without early data, and it carries a request.
/// A hook makes the session's second and third streams wait until the
/// handshake completed; the first was opened in 0-RTT.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejection_while_the_early_session_starts_keeps_the_connection() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let early = trusting_connector_with(&identity, &typed_critical_streams())?
        .with_isolated_session_cache()
        .with_test_start_after_handshake();
    let endpoint = quinn::Endpoint::server(
        server_config(&identity, true)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let (server, served, types) = spawn_recording_server(endpoint.clone(), vec![16_384, 16_384]);
    let learning = connect(&early, address).await?;
    wait_for_ticket(&early).await?;
    drop(learning);
    endpoint.set_server_config(Some(server_config(&identity, false)?));

    let connection = connect(&early, address).await?;
    // The connection offered early data, and the server rejected it.
    assert!(connection.sent_early_data());
    assert!(!connection.early_data_pending());
    assert_eq!(connection.early_data_accepted().await, Some(false));
    assert!(!connection.started_from_remembered_settings());
    // The session that started after the rejection took client streams 2,
    // 6, and 10 for its control and QPACK streams, as a fresh connection's
    // does, so the next unidirectional stream is 14.
    let next = connection.quinn().open_uni().await?;
    assert_eq!(u64::from(next.id()), 14);
    drop(next);
    let response = send(&early, &connection, Method::GET, "/started", None).await?;
    assert_eq!(response.status(), StatusCode::OK);
    let served = served.lock().map_err(|_| "served paths poisoned")?.clone();
    assert_eq!(served, [(1, "/started".to_owned())]);
    check_critical_stream_types(&types, 1).await?;

    drop((response, connection));
    server.abort();
    Ok(())
}

/// A server that accepts early data while the early HTTP/3 session is still
/// opening its own streams keeps the connection and the session: the
/// streams the session opens after the handshake are the control and QPACK
/// streams it asked for, on client streams 2, 6 and 10, and requests
/// succeed. A hook makes the session's second and third streams wait until
/// the handshake completed; the first was opened in 0-RTT.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_acceptance_while_the_early_session_starts_keeps_the_connection() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let early = trusting_connector_with(&identity, &typed_critical_streams())?
        .with_isolated_session_cache()
        .with_test_start_after_handshake();
    let endpoint = quinn::Endpoint::server(
        server_config(&identity, true)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let address = endpoint.local_addr()?;
    let (server, served, types) = spawn_recording_server(endpoint.clone(), vec![16_384, 16_384]);
    let learning = connect(&early, address).await?;
    wait_for_ticket(&early).await?;
    drop(learning);

    let connection = connect(&early, address).await?;
    assert!(connection.sent_early_data());
    assert_eq!(connection.early_data_accepted().await, Some(true));
    for path in ["/accepted", "/again"] {
        let response = send(&early, &connection, Method::GET, path, None).await?;
        assert_eq!(response.status(), StatusCode::OK);
    }
    let served = served.lock().map_err(|_| "served paths poisoned")?.clone();
    assert_eq!(
        served,
        [(1, "/accepted".to_owned()), (1, "/again".to_owned())]
    );
    check_critical_stream_types(&types, 1).await?;
    let next = connection.quinn().open_uni().await?;
    assert_eq!(u64::from(next.id()), 14);

    drop((next, connection));
    server.abort();
    Ok(())
}
