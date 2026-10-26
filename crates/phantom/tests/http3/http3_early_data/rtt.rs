//! Real early responses publish only completed verified racing history.

use super::*;
use crate::support::http3_upgrade::{
    AlternativeBehavior, Http3UpgradeFixture, PlannedResponse, UpgradeScript,
};
use phantom::{
    AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, AltSvcRttDelay, AltSvcSnapshot,
    AltSvcSnapshotEntry, ResponseInfo,
};
use std::{fmt, sync::Mutex, time::SystemTime};
use tracing::instrument::WithSubscriber;
use tracing::{
    Dispatch, Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

#[derive(Clone, Default)]
struct DelayObservation(Arc<Mutex<Vec<String>>>);

impl DelayObservation {
    fn dispatch(&self) -> Dispatch {
        // Register the existing test fallback for callsites used by other peers.
        let _ = crate::support::tracing::OutcomeSubscriber::default().dispatch();
        let dispatch = Dispatch::new(self.clone());
        tracing::callsite::rebuild_interest_cache();
        dispatch
    }

    fn values(&self) -> TestResult<Vec<String>> {
        Ok(self
            .0
            .lock()
            .map_err(|_| "delay observation poisoned")?
            .clone())
    }
}

impl Subscriber for DelayObservation {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::always()
    }
    fn enabled(&self, _: &Metadata<'_>) -> bool {
        true
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut visitor = DelayVisitor(None);
        event.record(&mut visitor);
        if let Some(value) = visitor.0 {
            match self.0.lock() {
                Ok(mut values) => values.push(value),
                Err(poisoned) => poisoned.into_inner().push(value),
            }
        }
    }
}

struct DelayVisitor(Option<String>);
impl Visit for DelayVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "alt_svc_origin_delay" {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

fn racing_policy() -> AltSvcPolicy {
    AltSvcPolicy::race(
        AltSvcRace::new(Duration::ZERO, AltSvcBrokenBackoff::CHROMIUM_153)
            .with_rtt_delay(
                AltSvcRttDelay::new(NonZeroUsize::MIN.saturating_add(7), Duration::from_secs(60))
                    .with_additional_delay(Duration::from_millis(100)),
            )
            .with_alternative_setup_limit(Duration::from_millis(500)),
    )
}

// A distinct origin and target each time avoids ready H2/H3 bypass. This
// measures the client-wide completed-success gate and missing-target default,
// not the actual target's SRTT or an artificial handshake duration.
async fn probe(client: &Client, identity: &TestIdentity, expected: &str) -> TestResult<()> {
    let fixture = Http3UpgradeFixture::spawn(
        identity,
        "127.0.0.1",
        UpgradeScript::new(
            [PlannedResponse::new(StatusCode::OK).body("probe")],
            AlternativeBehavior::responses([]),
        ),
    )
    .await?;
    let socket = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
    let port = socket.local_addr()?.port();
    let (stop, mut stopped) = tokio::sync::oneshot::channel();
    let blackhole = ConnectionPeer::spawn(async move {
        let mut bytes = vec![0; 65_535];
        loop {
            tokio::select! {
                biased;
                _ = &mut stopped => return Ok::<(), Box<dyn std::error::Error + Send + Sync>>(()),
                received = socket.recv_from(&mut bytes) => { received?; }
            }
        }
    });
    let operation: TestResult<()> = async {
        let origin = format!("https://127.0.0.1:{}", fixture.origin_address().port());
        client.import_alt_svc(&AltSvcSnapshot::new(vec![AltSvcSnapshotEntry::new(
            origin,
            "127.0.0.1",
            port,
            SystemTime::now() + Duration::from_secs(3600),
        )]))?;
        let observation = DelayObservation::default();
        let response = client
            .get(&fixture.origin_url("/probe"))?
            .send()
            .with_subscriber(observation.dispatch())
            .await?;
        assert_eq!(
            response
                .extensions()
                .get::<ResponseInfo>()
                .map(ResponseInfo::protocol),
            Some(HttpProtocol::Http2)
        );
        assert_eq!(response.into_body().collect().await?.to_bytes(), "probe");
        assert_eq!(observation.values()?, [expected]);
        let observed = fixture.snapshot()?;
        assert_eq!(observed.origin_connections, 1);
        assert_eq!(observed.origin_request_count, 1);
        assert_eq!(
            observed.origin_requests[0].path_and_query.as_deref(),
            Some("/probe")
        );
        assert!(observed.alternative_requests.is_empty());
        Ok(())
    }
    .await;
    let _ = stop.send(());
    let stopped: TestResult<()> = async {
        timeout(TEST_TIMEOUT, blackhole).await???;
        Ok(())
    }
    .await;
    finish_with_cleanup(
        operation,
        finish_with_cleanup(stopped, fixture.finish().await.map(|_| ())),
    )
}

async fn early_publication(clear_while_pending: bool) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let endpoint = h3_support::quic_server(
        server_config(&identity, true)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let (gate, open) = tokio::sync::watch::channel(true);
    let (relay, relay_task) = gated_relay(endpoint.local_addr()?, open).await?;
    let mut server_peer = None;
    let mut request_peer = None;
    let outcome: TestResult<()> = async {
        let (arrived_tx, mut arrived) = mpsc::unbounded_channel();
        let (read_tx, mut read) = mpsc::unbounded_channel();
        let (closed_tx, mut closed) = mpsc::unbounded_channel();
        let server_gate = gate.subscribe();
        server_peer = Some(ConnectionPeer::spawn(async move {
            let mut connections = Vec::new();
            for expected in ["/ticket", "/early"] {
                let mut connecting = endpoint.accept().await.ok_or("endpoint closed")?.accept()?;
                connecting.handshake_data().await?;
                let (quic, completed) = connecting
                    .into_0rtt()
                    .map_err(|_| "server could not serve before Finished")?;
                let mut connection = h3::server::Connection::<_, Bytes>::new(
                    h3_quinn::Connection::new(quic.clone()),
                )
                .await?;
                let resolver = connection.accept().await?.ok_or("closed before request")?;
                let (request, mut stream) = resolver.resolve_request().await?;
                assert_eq!(request.uri().path(), expected);
                assert_eq!(request.method(), Method::GET);
                let mut body = Vec::new();
                while let Some(mut chunk) = stream.recv_data().await? {
                    while chunk.has_remaining() {
                        body.extend_from_slice(chunk.chunk());
                        let len = chunk.chunk().len();
                        chunk.advance(len);
                    }
                }
                assert!(body.is_empty());
                arrived_tx.send((request.uri().path().to_owned(), *server_gate.borrow()))?;
                stream
                    .send_response(Response::builder().status(StatusCode::OK).body(())?)
                    .await?;
                stream
                    .send_data(Bytes::from_static(b"early-response"))
                    .await?;
                stream.finish().await?;
                read.recv().await.ok_or("caller stopped")?;
                // The server completion notification's bool has no server
                // meaning; completion and the live connection prove Finished.
                let _server_notification = completed.await;
                assert!(quic.close_reason().is_none());
                expect_no_second_request(&mut connection).await?;
                quic.close(0u32.into(), b"served");
                drop(connection);
                endpoint.wait_idle().await;
                // Address-based IDs remain distinct while both handles are alive.
                connections.push(quic);
                closed_tx.send(())?;
            }
            assert_ne!(
                connections[0].stable_id(),
                connections[1].stable_id(),
                "pool reuse hid resumption"
            );
            expect_no_connection(&endpoint).await
        }));
        let client = Client::builder(chrome_profile().with_http2(chrome::v154_http2()))
            .add_root_certificate_der(identity.root_der.clone())
            .alt_svc(NonZeroUsize::MIN.saturating_add(7))
            .alt_svc_policy(racing_policy())
            .build()?;
        let subscriber = OutcomeSubscriber::default();
        let response = client
            .get_with_protocol(HttpProtocol::Http3, &format!("https://{relay}/ticket"))?
            .send()
            .with_subscriber(subscriber.dispatch())
            .await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await?.to_bytes(),
            "early-response"
        );
        assert_eq!(arrived.recv().await, Some(("/ticket".to_owned(), true)));
        read_tx.send(())?;
        closed.recv().await.ok_or("server stopped")?;
        assert_eq!(subscriber.early_data_for("http3.response_head"), ["none"]);
        // Genuine ticket remains; only racing samples/generation are cleared.
        client.clear_alt_svc_racing_history();
        gate.send_replace(false);
        request_peer = Some(ConnectionPeer::spawn({
            let client = client.clone();
            let url = format!("https://{relay}/early");
            async move {
                let response = client
                    .get_with_protocol(HttpProtocol::Http3, &url)?
                    .send()
                    .await?;
                assert_eq!(response.status(), StatusCode::OK);
                assert_eq!(
                    response.into_body().collect().await?.to_bytes(),
                    "early-response"
                );
                Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
            }
            .with_subscriber(subscriber.dispatch())
        }));
        assert_eq!(arrived.recv().await, Some(("/early".to_owned(), false)));
        assert_eq!(
            subscriber.early_data_for("http3.response_head"),
            ["none", "sent"]
        );
        assert!(
            !request_peer
                .as_ref()
                .ok_or("request missing")?
                .is_finished()
        );
        probe(&client, &identity, "0ns").await?;
        if clear_while_pending {
            client.clear_alt_svc_racing_history();
        }
        gate.send_replace(true);
        request_peer.take().ok_or("request missing")?.await??;
        read_tx.send(())?;
        closed.recv().await.ok_or("server stopped")?;
        probe(
            &client,
            &identity,
            if clear_while_pending { "0ns" } else { "400ms" },
        )
        .await?;
        assert_eq!(
            subscriber.early_data_for("http3.response_head"),
            ["none", "sent"]
        );
        server_peer.take().ok_or("server missing")?.await??;
        Ok(())
    }
    .await;
    gate.send_replace(true);
    let cleanup = finish_with_cleanup(
        stop_fixture_peer(request_peer).await,
        stop_fixture_peer(server_peer).await,
    );
    finish_with_cleanup(
        outcome,
        finish_with_cleanup(cleanup, stop_relay(relay_task).await),
    )
}

#[tokio::test]
async fn resumed_response_publishes_after_finished_and_not_while_pending() -> TestResult<()> {
    bounded(early_publication(false)).await
}

#[tokio::test]
async fn clearing_during_early_handshake_prevents_response_from_reseeding() -> TestResult<()> {
    bounded(early_publication(true)).await
}
