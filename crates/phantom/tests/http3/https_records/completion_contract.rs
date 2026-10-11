use std::{error::Error, fmt, time::Duration};

use http_body_util::BodyExt;
use phantom::{
    HttpProtocol,
    dns::{HttpsLookupErrorKind, HttpsRecordResolver},
};
use phantom_testkit::dns::DnsServer;
use tokio::{
    sync::watch,
    time::{Instant, timeout_at},
};

use super::{
    H3_RECORD, LookupOutcome, ObservedLookup, bounded, client_builder, identity, observe_resolver,
    protocol, records, resolver, spawn_fixture,
};
use crate::support::{tls::TestResult, tunnel_proxy::finish_with_cleanup};

const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
struct HeldLookupFailure(HttpsLookupErrorKind);

impl fmt::Display for HeldLookupFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "held lookup failed during cleanup: {:?}", self.0)
    }
}

impl Error for HeldLookupFailure {}

struct LookupRelease(watch::Sender<bool>);

impl LookupRelease {
    fn release(&self) {
        self.0.send_replace(true);
    }
}

impl Drop for LookupRelease {
    fn drop(&mut self) {
        self.release();
    }
}

struct HeldLookup {
    lookup: ObservedLookup,
    upstream: watch::Receiver<Option<LookupOutcome>>,
    release: LookupRelease,
    release_result: watch::Receiver<Option<Result<(), watch::error::RecvError>>>,
    request_started: bool,
}

impl HeldLookup {
    async fn upstream_result(&mut self) -> TestResult<LookupOutcome> {
        let observed = self.upstream.wait_for(Option::is_some).await?;
        observed
            .as_ref()
            .copied()
            .ok_or_else(|| "held lookup omitted its upstream result".into())
    }

    async fn finish(&mut self) -> TestResult<()> {
        self.release.release();

        if !self.request_started {
            return Ok(());
        }

        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let lookup_cleanup: TestResult<()> = async {
            let outcome = timeout_at(deadline, self.lookup.completed()).await??;
            outcome.map_err(|kind| HeldLookupFailure(kind).into())
        }
        .await;

        let release_cleanup: TestResult<()> = async {
            let released =
                timeout_at(deadline, self.release_result.wait_for(Option::is_some)).await??;
            released
                .as_ref()
                .ok_or("held lookup omitted its release result")?
                .clone()?;
            Ok(())
        }
        .await;

        finish_with_cleanup(lookup_cleanup, release_cleanup)
    }
}

fn held_resolver(dns: &DnsServer) -> TestResult<HeldLookup> {
    let upstream = resolver(dns)?;
    let (release, gate) = watch::channel(false);
    let release = LookupRelease(release);
    let (observed, receiver) = watch::channel(None);
    let (release_result, release_receiver) = watch::channel(None);
    let resolver = HttpsRecordResolver::from_fn(move |host, port| {
        let upstream = upstream.clone();
        let observed = observed.clone();
        let mut gate = gate.clone();
        let release_result = release_result.clone();
        async move {
            let result = upstream.lookup(&host, port).await;
            observed.send_replace(Some(
                result.as_ref().map(|_| ()).map_err(|error| error.kind()),
            ));

            let released = gate.wait_for(|released| *released).await.map(|_| ());
            release_result.send_replace(Some(released));
            result
        }
    });

    Ok(HeldLookup {
        lookup: observe_resolver(resolver),
        upstream: receiver,
        release,
        release_result: release_receiver,
        request_started: false,
    })
}

struct ObservedRequests {
    first: HttpProtocol,
    first_body: bytes::Bytes,
    second: HttpProtocol,
    second_body: bytes::Bytes,
    pending_after_first: bool,
    pending_after_second: bool,
    calls_while_held: usize,
    completed: LookupOutcome,
    later: HttpProtocol,
    later_body: bytes::Bytes,
}

#[tokio::test(flavor = "current_thread")]
async fn an_actual_result_stays_pending_until_released_then_selects_http3() -> TestResult<()> {
    let identity = identity()?;
    let dns = DnsServer::spawn(records(H3_RECORD)).await?;
    let mut held = held_resolver(&dns)?;
    let mut fixture = None;
    let mut client = None;
    let mut observations = None;

    let primary = bounded(async {
        fixture = Some(spawn_fixture(&identity, 2, 1).await?);
        let fixture = fixture.as_ref().ok_or("fixture was not acquired")?;
        client = Some(
            client_builder(&identity)
                .https_record_discovery(held.lookup.resolver.clone())
                .build()?,
        );
        let client = client.as_ref().ok_or("client was not acquired")?;

        let first = client.get_negotiated(&fixture.origin_url("/first"))?;
        held.request_started = true;
        let first = first.send().await?;
        let first_protocol = protocol(&first)?;
        let first_body = first.into_body().collect().await?.to_bytes();

        held.upstream_result()
            .await?
            .map_err(|kind| format!("held real DNS lookup failed: {kind:?}"))?;

        let pending_after_first = held.lookup.completion.borrow().is_none();

        let second = client
            .get_negotiated(&fixture.origin_url("/held"))?
            .send()
            .await?;
        let second_protocol = protocol(&second)?;
        let second_body = second.into_body().collect().await?.to_bytes();

        let pending_after_second = held.lookup.completion.borrow().is_none();
        let calls_while_held = held.lookup.calls();

        held.release.release();
        let completed = held.lookup.completed().await?;
        let later = client
            .get_negotiated(&fixture.origin_url("/released"))?
            .send()
            .await?;
        let later_protocol = protocol(&later)?;
        let later_body = later.into_body().collect().await?.to_bytes();

        observations = Some(ObservedRequests {
            first: first_protocol,
            first_body,
            second: second_protocol,
            second_body,
            pending_after_first,
            pending_after_second,
            calls_while_held,
            completed,
            later: later_protocol,
            later_body,
        });
        Ok(())
    })
    .await;

    held.release.release();
    drop(client);

    let lookup_cleanup = held.finish().await;
    let fixture_cleanup = match fixture {
        Some(fixture) => fixture.finish().await.map(|_| ()),
        None => Ok(()),
    };
    finish_with_cleanup(
        finish_with_cleanup(primary, lookup_cleanup),
        fixture_cleanup,
    )?;
    let observed = observations.ok_or("request sequence omitted its observations")?;

    assert_eq!(observed.first, HttpProtocol::Http2);
    assert_eq!(observed.first_body, "origin");
    assert!(observed.pending_after_first);
    assert_eq!(observed.second, HttpProtocol::Http2);
    assert_eq!(observed.second_body, "origin");
    assert!(observed.pending_after_second);
    assert_eq!(observed.calls_while_held, 1);

    assert_eq!(observed.completed, Ok(()));
    assert_eq!(observed.later, HttpProtocol::Http3);
    assert_eq!(observed.later_body, "http3");
    assert_eq!(held.lookup.calls(), 1);
    assert_eq!(dns.queries().len(), 1);
    Ok(())
}
