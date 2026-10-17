//! Actual peer publication and race-policy decisions; arithmetic uses model tests.

use tracing::instrument::WithSubscriber;
use tracing::{
    Dispatch, Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

use super::*;
use crate::support::tunnel_proxy::connection_peer::{ConnectionPeer, finish_with_cleanup};
use phantom::{AltSvcRttDelay, ServerAuthentication};

#[derive(Clone, Default)]
struct DelayObservation(Arc<Mutex<Vec<String>>>, Arc<AtomicUsize>);

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
        let mut visitor = DelayVisitor {
            delay: None,
            broken: false,
        };
        event.record(&mut visitor);
        if visitor.broken {
            self.1.fetch_add(1, Ordering::SeqCst);
        }
        if let Some(value) = visitor.delay {
            match self.0.lock() {
                Ok(mut values) => values.push(value),
                Err(poisoned) => poisoned.into_inner().push(value),
            }
        }
    }
}

struct DelayVisitor {
    delay: Option<String>,
    broken: bool,
}
impl Visit for DelayVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "outcome" && value == "broken" {
            self.broken = true;
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "alt_svc_origin_delay" {
            self.delay = Some(format!("{value:?}"));
        }
    }
}

fn policy() -> AltSvcPolicy {
    let settings =
        AltSvcRttDelay::new(NonZeroUsize::MIN.saturating_add(7), Duration::from_secs(60))
            .with_additional_delay(Duration::from_millis(100));
    AltSvcPolicy::race(
        AltSvcRace::new(Duration::ZERO, AltSvcBrokenBackoff::CHROMIUM_153)
            .with_rtt_delay(settings)
            .with_alternative_setup_limit(Duration::from_millis(500)),
    )
}

async fn fixture(
    identity: &TestIdentity,
    next_alternative: u16,
) -> TestResult<Http3UpgradeFixture> {
    Http3UpgradeFixture::spawn(
        identity,
        ORIGIN_NAME,
        UpgradeScript::new(
            [
                PlannedResponse::new(StatusCode::OK)
                    .header(
                        "alt-svc",
                        format!("h3=\"{ALTERNATIVE_HOST}:{next_alternative}\"; ma=3600").parse()?,
                    )
                    .body("origin"),
                PlannedResponse::new(StatusCode::OK).body("pooled"),
            ],
            AlternativeBehavior::responses([]),
        )
        .origin_http3([
            PlannedResponse::new(StatusCode::OK).body("warm"),
            PlannedResponse::new(StatusCode::OK).body("warm"),
        ]),
    )
    .await
}

#[derive(Clone, Copy)]
enum Seed {
    Fresh,
    Verified,
    Cleared,
    Independent,
    Failed,
}

async fn decision(seed: Seed, authentication: ServerAuthentication) -> TestResult<()> {
    let identity = identity()?;
    let socket = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
    let port = socket.local_addr()?.port();
    let next_socket = phantom_testkit::udp::bind_tokio((Ipv4Addr::LOCALHOST, 0).into())?;
    let fixture = fixture(&identity, next_socket.local_addr()?.port()).await?;
    let (stop, mut stopped) = oneshot::channel();
    let packets = Arc::new(AtomicUsize::new(0));
    let observed_packets = Arc::clone(&packets);
    let blackhole = ConnectionPeer::spawn(async move {
        let mut bytes = vec![0; 65_535];
        let mut next_bytes = vec![0; 65_535];
        loop {
            tokio::select! {
                biased;
                _ = &mut stopped => return Ok::<(), Box<dyn Error + Send + Sync>>(()),
                packet = socket.recv_from(&mut bytes) => {
                    packet?;
                    observed_packets.fetch_add(1, Ordering::SeqCst);
                }
                packet = next_socket.recv_from(&mut next_bytes) => {
                    packet?;
                }
            }
        }
    });
    let operation: TestResult<()> = async {
        let builder = if authentication.verifies() {
            client_builder(&identity)?
        } else {
            Client::builder(profile()).alt_svc(NonZeroUsize::MIN.saturating_add(7))
        };
        let mut client = builder
            .resolve(ORIGIN_NAME, [IpAddr::V4(Ipv4Addr::LOCALHOST)])
            .alt_svc_policy(policy())
            .server_authentication(authentication)
            .build()?;
        if matches!(seed, Seed::Failed) {
            failed_handshake(&client).await?;
        } else if !matches!(seed, Seed::Fresh) {
            assert_eq!(send_exact(&client, &fixture, "/warm").await?, "warm");
        }
        if matches!(seed, Seed::Cleared) {
            client.clear_alt_svc_racing_history();
            // Reuse of the old actual connection must not reseed the new generation.
            assert_eq!(send_exact(&client, &fixture, "/warm-again").await?, "warm");
        }
        if matches!(seed, Seed::Independent) {
            client = client_builder(&identity)?
                .resolve(ORIGIN_NAME, [IpAddr::V4(Ipv4Addr::LOCALHOST)])
                .alt_svc_policy(policy())
                .build()?;
        }
        import_alternative(&client, &fixture, port)?;
        let observation = DelayObservation::default();
        let response = client
            .clone()
            .get_negotiated(&fixture.origin_url("/race"))?
            .send()
            .with_subscriber(observation.dispatch())
            .await?;
        assert_eq!(protocol(&response)?, HttpProtocol::Http2);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "origin");
        let expected = if matches!(seed, Seed::Verified) && authentication.verifies() {
            "400ms"
        } else {
            "0ns"
        };
        assert_eq!(observation.values()?, [expected]);
        while packets.load(Ordering::SeqCst) == 0 {
            if blackhole.is_finished() {
                return Err("blackhole receiver ended before observing the alternative".into());
            }
            tokio::task::yield_now().await;
        }
        // Expiry must not hide the pooled-origin decision. The first response
        // advertises a fresh location, preserving this client's RTT history.
        timeout(TEST_TIMEOUT, async {
            while observation.1.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await?;
        let pooled = client
            .get_negotiated(&fixture.origin_url("/pooled"))?
            .send()
            .with_subscriber(observation.dispatch())
            .await?;
        assert_eq!(protocol(&pooled)?, HttpProtocol::Http2);
        assert_eq!(pooled.into_body().collect().await?.to_bytes(), "pooled");
        assert_eq!(observation.values()?, [expected, "0ns"]);
        let seen = fixture.snapshot()?;
        assert_eq!(seen.origin_connections, 1);
        assert_eq!(seen.origin_request_count, 2);
        assert_eq!(
            seen.origin_http3_connections,
            usize::from(!matches!(seed, Seed::Fresh | Seed::Failed))
        );
        assert_eq!(
            seen.origin_http3_requests.len(),
            if matches!(seed, Seed::Cleared) {
                2
            } else {
                seen.origin_http3_connections
            }
        );
        assert!(seen.alternative_requests.is_empty());
        drop(client);
        Ok(())
    }
    .await;
    let _ = stop.send(());
    let blackhole_cleanup = async {
        timeout(TEST_TIMEOUT, blackhole).await???;
        Ok(())
    }
    .await;
    let fixture_cleanup = fixture.finish().await.map(|_| ());
    finish_with_cleanup(
        operation,
        finish_with_cleanup(blackhole_cleanup, fixture_cleanup),
    )
}

async fn failed_handshake(client: &Client) -> TestResult<()> {
    let unrelated_identity = identity()?;
    let (address, endpoint) = h3_support::server_endpoint(&unrelated_identity)?;
    let owner = endpoint.clone();
    let mut peer = ConnectionPeer::spawn(async move {
        let incoming = owner
            .accept()
            .await
            .ok_or("untrusted peer closed before handshake")?;
        let result: TestResult<()> = match incoming.await {
            Err(_) => Ok(()),
            Ok(_) => Err("untrusted native handshake unexpectedly succeeded".into()),
        };
        result
    });
    let result: TestResult<()> = async {
        let error = client
            .get(
                HttpProtocol::Http3,
                &format!("https://{ORIGIN_NAME}:{}", address.port()),
            )?
            .send()
            .await
            .err()
            .ok_or("untrusted server returned a response")?;
        assert_eq!(error.kind(), RequestErrorKind::Tls);
        timeout(TEST_TIMEOUT, &mut peer).await???;
        Ok(())
    }
    .await;
    endpoint.close(0_u32.into(), b"failed authentication control complete");
    let peer_cleanup = peer.shutdown().await;
    let endpoint_cleanup = timeout(TEST_TIMEOUT, endpoint.wait_idle())
        .await
        .map_err(Into::into);
    finish_with_cleanup(result, finish_with_cleanup(peer_cleanup, endpoint_cleanup))
}

#[tokio::test]
async fn verified_ticket_disabled_h3_supplies_client_local_success() -> TestResult<()> {
    bounded(decision(Seed::Verified, ServerAuthentication::WebPki)).await
}

#[tokio::test]
async fn a_fresh_client_starts_origin_without_success_history() -> TestResult<()> {
    bounded(decision(Seed::Fresh, ServerAuthentication::WebPki)).await
}

#[tokio::test]
async fn clearing_history_prevents_a_reused_connection_from_reseeding() -> TestResult<()> {
    bounded(decision(Seed::Cleared, ServerAuthentication::WebPki)).await
}

#[tokio::test]
async fn another_client_cannot_consume_verified_history() -> TestResult<()> {
    bounded(decision(Seed::Independent, ServerAuthentication::WebPki)).await
}

#[tokio::test]
async fn a_failed_verification_never_supplies_success_history() -> TestResult<()> {
    bounded(decision(Seed::Failed, ServerAuthentication::WebPki)).await
}

#[cfg(feature = "danger-disable-verification")]
#[tokio::test]
async fn an_unverified_completed_connection_never_supplies_success_history() -> TestResult<()> {
    bounded(decision(
        Seed::Verified,
        ServerAuthentication::DangerDisabled,
    ))
    .await
}
