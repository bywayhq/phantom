//! Real early WebSocket setup publishes completed verified racing history.

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
            .get_negotiated(&fixture.origin_url("/probe"))?
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

async fn extended_connect_publication(answer: Answer) -> TestResult<()> {
    let mut origins = Vec::new();
    let mut relay_owner = None;
    let caller = bounded(async {
        let identity = TestIdentity::generate()?;
        let endpoint = h3_support::quic_server(
            early_data_server(&identity)?,
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        origins.push(Origin::serve(
            (endpoint.local_addr()?, endpoint),
            Behavior::answering(answer),
            0,
        ));
        let origin = origins.last_mut().ok_or("origin missing")?;
        relay_owner = Some(ZeroRttRelay::spawn(origin.address).await?);
        let relay = relay_owner.as_ref().ok_or("relay missing")?;
        let zero_rtt = Arc::clone(&relay.log);
        let relay = relay.address;
        let base = client_settings();
        let mut tls = base.tls().clone();
        tls.session_tickets = phantom_profile::SessionTickets::enabled(2)?;
        let http3 = Http3ClientSettings::new(
            tls,
            base.quic_transport().clone(),
            base.http3().clone(),
            extended_request_settings(),
        );
        let client = Client::builder(
            ClientProfile::new(chrome::v154_tcp_tls())
                .with_http2(chrome::v154_http2())
                .with_http3(http3),
        )
        .add_root_certificate_der(identity.root_der.clone())
        .http3_early_data(true)
        .alt_svc(NonZeroUsize::MIN.saturating_add(7))
        .alt_svc_policy(racing_policy())
        .build()?;
        assert_eq!(
            get_body(&client, &format!("https://{relay}/ticket")).await?,
            "ordinary"
        );
        origin.close_connections().await;
        // Only racing history is cleared; the ticket still offers real 0-RTT.
        client.clear_alt_svc_racing_history();
        let opening = client
            .websocket_with_protocol(HttpProtocol::Http3, &format!("wss://{relay}/resumed"))?
            .connect()
            .await;
        match answer {
            Answer::Echo => {
                let mut socket = opening?;
                assert_eq!(socket.handshake_response().version(), Version::HTTP_3);
                assert_echoes(&mut socket).await?;
                socket.close(None).await?;
            }
            Answer::Reject => {
                let error = match opening {
                    Ok(_) => return Err("403 opened a WebSocket".into()),
                    Err(error) => error,
                };
                assert_eq!(error.kind(), WebSocketErrorKind::HandshakeRejected);
                let response = error.into_response().ok_or("rejection lost response")?;
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                assert_eq!(response.version(), Version::HTTP_3);
                assert_eq!(
                    response.into_body().collect().await?.to_bytes(),
                    "forbidden"
                );
            }
            _ => return Err("unsupported publication control".into()),
        }
        assert_eq!(origin.connections(), 2);
        assert_eq!(origin.methods(), ["GET", "CONNECT"]);
        assert_eq!(
            zero_rtt
                .lock()
                .map_err(|_| "zero-RTT log poisoned")?
                .clone(),
            [false, true]
        );
        // Drain the actual resumed connection before the fresh probe can run.
        origin.close_connections().await;
        probe(&client, &identity, "400ms").await?;
        client.clear_alt_svc_racing_history();
        probe(&client, &identity, "0ns").await?;
        Ok(())
    })
    .await;
    let caller = match relay_owner.as_mut() {
        Some(relay) => relay.finish(caller).await,
        None => caller,
    };
    finish_origins(&mut origins, caller).await
}

#[tokio::test]
async fn settled_early_websocket_connect_publishes_verified_success() -> TestResult<()> {
    extended_connect_publication(Answer::Echo).await
}

#[tokio::test]
async fn settled_early_connect_rejection_still_publishes_verified_transport_success()
-> TestResult<()> {
    extended_connect_publication(Answer::Reject).await
}
