//! Advertisement validation performs authenticated setup before any HTTP stream.

use std::{any::Any, panic::AssertUnwindSafe, time::SystemTime};

use futures_util::FutureExt;
use phantom::{
    AltSvcSnapshot, AltSvcSnapshotEntry, HttpAttemptBudget, profile::Http3AltSvcValidation,
};
use tokio::sync::watch;
use tracing::{
    Dispatch, Event, Metadata, Subscriber,
    field::{Field, Visit},
    span::{Attributes, Id, Record},
    subscriber::Interest,
};

use super::*;
use crate::support::tunnel_proxy::finish_with_cleanup;

#[tokio::test]
async fn firefox_advertisement_authenticates_without_spending_an_http_attempt_or_sending_a_request()
-> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (release, gate) = watch::channel(false);
    let fixture = Http3UpgradeFixture::spawn(
        &identity,
        ORIGIN_NAME,
        script([
            PlannedResponse::new(StatusCode::OK).advertise_alternative(),
            PlannedResponse::new(StatusCode::OK),
        ])
        .hold_alternative_handshake(gate),
    )
    .await?;
    let client = firefox_client(&identity)?;
    let events = ValidationObservation::new();
    let dispatch = Dispatch::new(events.clone());
    let _scope = tracing::dispatcher::set_default(&dispatch);
    tracing::callsite::rebuild_interest_cache();
    let outcome = AssertUnwindSafe(bounded(async {
        let allowance = HttpAttemptBudget::new(3);
        let mut peer = fixture.alternative_progress();
        drain(
            client
                .get_negotiated(&fixture.origin_url("/learn"))?
                .attempt_budget(allowance.clone())
                .send()
                .await?,
        )
        .await?;
        peer.wait_for(|seen| seen.incoming == 1).await?;
        assert_eq!(allowance.remaining(), 2);
        assert_eq!(peer.borrow().handshakes, 0);
        assert_eq!(peer.borrow().streams, 0);
        assert_eq!(peer.borrow().requests, 0);

        // An advertised but unchecked mapping cannot dispatch HTTP/3.
        let pending = client
            .get_negotiated(&fixture.origin_url("/while-pending"))?
            .attempt_budget(allowance.clone())
            .send()
            .await?;
        assert_eq!(protocol(&pending)?, HttpProtocol::Http2);
        drain(pending).await?;
        assert_eq!(allowance.remaining(), 1);
        assert_eq!(peer.borrow().streams, 0);
        assert_eq!(peer.borrow().requests, 0);

        release.send_replace(true);
        events.validated().await?;
        peer.wait_for(|seen| seen.h3_sessions == 1).await?;
        assert_eq!(peer.borrow().handshakes, 1);
        assert_eq!(peer.borrow().streams, 0);
        assert_eq!(peer.borrow().requests, 0);
        assert_eq!(allowance.remaining(), 1);

        let response = client
            .get_negotiated(&fixture.origin_url("/validated"))?
            .attempt_budget(allowance.clone())
            .send()
            .await?;
        assert_eq!(protocol(&response)?, HttpProtocol::Http3);
        drain(response).await?;
        assert_eq!(allowance.remaining(), 0);
        let seen = fixture.snapshot()?;
        assert_eq!(seen.origin_request_count, 2);
        assert_eq!(seen.alternative_connections, 1);
        assert_eq!(seen.alternative_requests.len(), 1);
        assert_eq!(peer.borrow().streams, 1);
        assert_eq!(
            seen.alternative_requests[0].path_and_query.as_deref(),
            Some("/validated")
        );
        assert_eq!(
            header_values(&seen.alternative_requests[0], "alt-used"),
            [fixture.alternative_address().to_string().as_bytes()]
        );
        Ok(())
    }))
    .catch_unwind()
    .await;
    finish_control(client, fixture, outcome).await
}

#[tokio::test]
async fn importing_a_firefox_snapshot_waits_for_a_real_advertisement_to_start_validation()
-> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let fixture = Http3UpgradeFixture::spawn(
        &identity,
        ORIGIN_NAME,
        script([
            PlannedResponse::new(StatusCode::OK),
            PlannedResponse::new(StatusCode::OK).advertise_alternative(),
        ]),
    )
    .await?;
    let client = firefox_client(&identity)?;
    let events = ValidationObservation::new();
    let dispatch = Dispatch::new(events.clone());
    let _scope = tracing::dispatcher::set_default(&dispatch);
    tracing::callsite::rebuild_interest_cache();
    let outcome = AssertUnwindSafe(bounded(async {
        client.import_alt_svc(&AltSvcSnapshot::new(vec![AltSvcSnapshotEntry::new(
            format!("https://{}", fixture.origin_address()),
            ORIGIN_NAME,
            fixture.alternative_address().port(),
            SystemTime::now() + Duration::from_secs(60),
        )]))?;
        // A completed origin exchange is a finite observation after import.
        let response = client
            .get_negotiated(&fixture.origin_url("/imported"))?
            .send()
            .await?;
        assert_eq!(protocol(&response)?, HttpProtocol::Http2);
        drain(response).await?;
        assert_eq!(fixture.alternative_progress().borrow().incoming, 0);
        assert_eq!(events.state.borrow().validated, 0);
        drain(
            client
                .get(HttpProtocol::Http2, &fixture.origin_url("/advertise"))?
                .send()
                .await?,
        )
        .await?;
        events.validated().await?;
        let response = client
            .get_negotiated(&fixture.origin_url("/validated"))?
            .send()
            .await?;
        assert_eq!(protocol(&response)?, HttpProtocol::Http3);
        drain(response).await?;
        let seen = fixture.snapshot()?;
        assert_eq!(seen.origin_request_count, 2);
        assert_eq!(seen.alternative_connections, 1);
        assert_eq!(seen.alternative_requests.len(), 1);
        Ok(())
    }))
    .catch_unwind()
    .await;
    finish_control(client, fixture, outcome).await
}

#[tokio::test]
async fn clearing_a_pending_firefox_advertisement_cancels_validation_without_sending_http()
-> TestResult<()> {
    cancelled_validation(Cancel::Clear).await
}

#[tokio::test]
async fn refreshing_connections_cancels_pending_firefox_validation() -> TestResult<()> {
    cancelled_validation(Cancel::Refresh).await
}

#[tokio::test]
async fn shutdown_joins_pending_firefox_validation_without_sending_http() -> TestResult<()> {
    cancelled_validation(Cancel::Shutdown).await
}

#[cfg(feature = "https-records")]
#[tokio::test]
async fn an_ech_authenticated_origin_does_not_start_advertisement_validation() -> TestResult<()> {
    use crate::support::ech;
    use phantom_testkit::tls::{TEST_ECH_KEYS, ech_config, ech_config_list};

    let identity = ech::origin_identity()?;
    let acceptor = ech::ech_acceptor(&identity, tls_support::H2_ALPN, 1, &TEST_ECH_KEYS[0])?;
    let fixture = Http3UpgradeFixture::spawn_with_origin_acceptor(
        &identity,
        ech::ORIGIN_NAME,
        script([
            PlannedResponse::new(StatusCode::OK).advertise_alternative(),
            PlannedResponse::new(StatusCode::OK).advertise_alternative(),
        ]),
        acceptor,
    )
    .await?;
    let configs = ech_config_list(&[ech_config(1, &TEST_ECH_KEYS[0], ech::PUBLIC_NAME)]);
    let mut dns = ech::record_server(vec![ech::https_rdata(&configs)]).await?;
    let firefox = firefox::v157_windows();
    let profile = ClientProfile::new(ech::ech_tls_settings())
        .with_http2(firefox::v157_http2())
        .with_http3(firefox.http3().ok_or("Firefox HTTP/3 missing")?.clone());
    let client = ech::discovering_client(&identity, &dns, profile, None)?;
    let events = ValidationObservation::new();
    let dispatch = Dispatch::new(events.clone());
    let _scope = tracing::dispatcher::set_default(&dispatch);
    tracing::callsite::rebuild_interest_cache();
    let outcome = AssertUnwindSafe(bounded(async {
        for path in ["/ech-advertisement", "/same-ech-connection"] {
            let response = client
                .get_negotiated(&fixture.origin_url(path))?
                .send()
                .await?;
            assert_eq!(protocol(&response)?, HttpProtocol::Http2);
            drain(response).await?;
        }
        // Actual decryption on the origin proves a selected configuration,
        // rather than merely an ECH-enabled profile or a GREASE offer.
        assert!(!dns.queries().is_empty());
        assert_eq!(fixture.snapshot()?.origin_ech_connections, 1);
        client.shutdown().await;
        assert_eq!(events.state.borrow().validated, 0);
        assert_eq!(events.state.borrow().cancelled, 0);
        assert_eq!(fixture.alternative_progress().borrow().incoming, 0);
        assert!(
            client
                .export_alt_svc()
                .ok_or("Alt-Svc disabled")?
                .is_empty()
        );
        Ok(())
    }))
    .catch_unwind()
    .await;
    let result = finish_control(client, fixture, outcome).await;
    finish_with_cleanup(result, dns.finish().await.map_err(Into::into))
}

#[derive(Clone, Copy)]
enum Cancel {
    Clear,
    Refresh,
    Shutdown,
}

async fn cancelled_validation(action: Cancel) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let (_release, gate) = watch::channel(false);
    let fixture = Http3UpgradeFixture::spawn(
        &identity,
        ORIGIN_NAME,
        script([
            PlannedResponse::new(StatusCode::OK).advertise_alternative(),
            PlannedResponse::new(StatusCode::OK),
        ])
        .hold_alternative_handshake(gate),
    )
    .await?;
    let client = firefox_client(&identity)?;
    let events = ValidationObservation::new();
    let dispatch = Dispatch::new(events.clone());
    let _scope = tracing::dispatcher::set_default(&dispatch);
    tracing::callsite::rebuild_interest_cache();
    let outcome = AssertUnwindSafe(bounded(async {
        let mut peer = fixture.alternative_progress();
        drain(
            client
                .get_negotiated(&fixture.origin_url("/learn"))?
                .send()
                .await?,
        )
        .await?;
        peer.wait_for(|seen| seen.incoming == 1).await?;
        assert_eq!(peer.borrow().handshakes, 0);
        match action {
            Cancel::Clear => client.clear_alt_svc(),
            Cancel::Refresh => client.refresh_connections().await,
            Cancel::Shutdown => client.shutdown().await,
        }
        if !matches!(action, Cancel::Shutdown) {
            let response = client
                .get_negotiated(&fixture.origin_url("/after-cancel"))?
                .send()
                .await?;
            assert_eq!(protocol(&response)?, HttpProtocol::Http2);
            drain(response).await?;
        }
        // Shutdown observes any cancellation requested by clear/refresh too.
        client.shutdown().await;
        assert!(client.is_closed());
        assert_eq!(events.state.borrow().cancelled, 1);
        assert_eq!(events.state.borrow().validated, 0);
        // Retire the held incoming with its fixture owner. Starting a server
        // handshake after client cancellation would test peer teardown instead.
        assert_eq!(peer.borrow().handshakes, 0);
        assert_eq!(peer.borrow().streams, 0);
        assert_eq!(peer.borrow().requests, 0);
        if matches!(action, Cancel::Clear) {
            assert!(
                client
                    .export_alt_svc()
                    .ok_or("Alt-Svc disabled")?
                    .is_empty()
            );
        }
        Ok(())
    }))
    .catch_unwind()
    .await;
    finish_control(client, fixture, outcome).await
}

fn script(origin: impl IntoIterator<Item = PlannedResponse>) -> UpgradeScript {
    UpgradeScript::new(
        origin,
        AlternativeBehavior::responses([PlannedResponse::new(StatusCode::OK)]),
    )
}

fn firefox_client(identity: &TestIdentity) -> TestResult<Client> {
    let profile = firefox::v157_windows();
    assert_eq!(
        profile
            .http3()
            .ok_or("Firefox HTTP/3 missing")?
            .http3()
            .alt_svc_validation,
        Http3AltSvcValidation::OnAdvertisement
    );
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(NonZeroUsize::MIN)
        .max_concurrent_http3_requests_per_origin(NonZeroUsize::MIN)
        .max_pending_http3_requests_per_origin(NonZeroUsize::MIN)
        .build()?)
}

async fn finish_control(
    client: Client,
    fixture: Http3UpgradeFixture,
    outcome: Result<TestResult<()>, Box<dyn Any + Send>>,
) -> TestResult<()> {
    let outcome = outcome.unwrap_or_else(|panic| {
        let text = panic
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| panic.downcast_ref::<&str>().copied())
            .unwrap_or("validation control panicked");
        Err(std::io::Error::other(text.to_owned()).into())
    });
    drop(client);
    finish_with_cleanup(outcome, fixture.finish().await.map(|_| ()))
}

#[derive(Clone, Copy, Default)]
struct ValidationProgress {
    validated: usize,
    cancelled: usize,
}

#[derive(Clone)]
struct ValidationObservation {
    state: watch::Sender<ValidationProgress>,
}

impl ValidationObservation {
    fn new() -> Self {
        Self {
            state: watch::channel(ValidationProgress::default()).0,
        }
    }

    async fn validated(&self) -> TestResult<()> {
        let mut events = self.state.subscribe();
        events.wait_for(|seen| seen.validated == 1).await?;
        Ok(())
    }
}

impl Subscriber for ValidationObservation {
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
        let mut fields = ValidationFields::default();
        event.record(&mut fields);
        if fields.message == "Alt-Svc validation finished" && fields.validated {
            self.state.send_modify(|seen| seen.validated += 1);
        } else if fields.message == "Alt-Svc validation task ended" && fields.cancelled {
            self.state.send_modify(|seen| seen.cancelled += 1);
        }
    }
}

#[derive(Default)]
struct ValidationFields {
    message: String,
    validated: bool,
    cancelled: bool,
}

impl Visit for ValidationFields {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "outcome" {
            self.validated = value == "validated";
        }
        if field.name() == "message" {
            self.message = value.to_owned();
        }
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        if field.name() == "cancelled" {
            self.cancelled = value;
        }
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
}
