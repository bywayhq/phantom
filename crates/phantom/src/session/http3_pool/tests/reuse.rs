//! Cross-origin reservations share a real authenticated QUIC connection.

use std::{
    future::{Future, pending},
    net::Ipv4Addr,
    num::NonZeroUsize,
    panic::AssertUnwindSafe,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use futures_util::FutureExt;
use phantom_net::{
    host_resolver::{AddressResolver, HostResolver},
    http3::Http3Connector,
    request::OriginForm,
};
use phantom_profile::browser::firefox;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::{
    sync::{Notify, watch},
    time::timeout,
};
use tracing::Span;

use super::{Http3Pool, PoolKey, poll_once};
use crate::{
    RequestTimeouts, RetryPolicy, Route,
    authority::Endpoint,
    retry::ConnectionSetupRetryState,
    session::{
        client_hints::Dispatched,
        http3_pool::{Http3Lease, Http3SetupControl, Http3TransportTarget, validate_request},
    },
    timeout::TimeoutBudget,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const DONOR: &str = "donor.test";
const SECOND: &str = "second.test";
const THIRD: &str = "third.test";
const DEADLINE: Duration = Duration::from_secs(10);
const CLEANUP: Duration = Duration::from_secs(5);

#[tokio::test]
async fn refresh_during_origin_resolution_rejects_the_captured_donor() -> TestResult {
    let gate = Arc::new(DnsGate::default());
    let fixture = Fixture::new(1, 3, Some(Arc::clone(&gate)))?;
    fixture
        .run(async {
            drop(fixture.seed().await?);
            let candidates = fixture.candidates(&fixture.second).await?;
            let mut acquiring = Box::pin(fixture.pool.acquire_reused(
                candidates,
                &fixture.connector,
                budget()?,
            ));
            assert!(poll_once(acquiring.as_mut()).is_none());
            assert_eq!(gate.entered.load(Ordering::SeqCst), 1);

            fixture.pool.refresh_connections().await;
            gate.release.notify_one();
            assert!(
                acquiring.await?.is_none(),
                "a pre-refresh DNS snapshot was admitted"
            );
            assert!(fixture.candidates(&fixture.second).await.is_err());
            Ok(())
        })
        .await
}

#[tokio::test]
async fn refresh_while_origin_admission_waits_rejects_the_old_physical_slot() -> TestResult {
    let fixture = Fixture::new(1, 3, None)?;
    fixture
        .run(async {
            drop(fixture.seed().await?);
            let blocked = fixture
                .pool
                .admit(&fixture.second, &Route::Direct, budget()?)
                .await?;
            let owner = fixture.donor_owner().await?;
            let candidates = fixture.candidates(&fixture.second).await?;
            let mut acquiring = Box::pin(fixture.pool.acquire_reused(
                candidates,
                &fixture.connector,
                budget()?,
            ));
            assert!(poll_once(acquiring.as_mut()).is_none());

            fixture.pool.refresh_connections().await;
            drop(blocked);
            assert!(
                acquiring.await?.is_none(),
                "admission revived a retired generation"
            );
            assert_eq!(
                owner
                    .lock_slots()
                    .connections
                    .front()
                    .ok_or("donor slot missing")?
                    .streams
                    .get(),
                0
            );
            assert_eq!(fixture.logical_available(&fixture.second).await, 1);
            Ok(())
        })
        .await
}

#[tokio::test]
async fn cancelling_waiting_and_reserved_reuse_releases_origin_and_physical_capacity() -> TestResult
{
    let fixture = Fixture::new(1, 3, None)?;
    fixture
        .run(async {
            drop(fixture.seed().await?);
            let owner = fixture.donor_owner().await?;
            let blocked = fixture
                .pool
                .admit(&fixture.second, &Route::Direct, budget()?)
                .await?;
            let candidates = fixture.candidates(&fixture.second).await?;
            let mut acquiring = Box::pin(fixture.pool.acquire_reused(
                candidates,
                &fixture.connector,
                budget()?,
            ));
            assert!(poll_once(acquiring.as_mut()).is_none());
            drop(acquiring);
            // The cancelled wait must also release the bounded pending slot.
            let candidates = fixture.candidates(&fixture.second).await?;
            let mut replacement = Box::pin(fixture.pool.acquire_reused(
                candidates,
                &fixture.connector,
                budget()?,
            ));
            assert!(poll_once(replacement.as_mut()).is_none());
            drop(replacement);
            drop(blocked);
            assert_eq!(fixture.logical_available(&fixture.second).await, 1);

            let lease = fixture
                .reuse(&fixture.second)
                .await?
                .ok_or("cancelled waiter retained admission")?;
            assert_eq!(fixture.logical_available(&fixture.second).await, 0);
            assert_eq!(
                owner
                    .lock_slots()
                    .connections
                    .front()
                    .ok_or("donor slot missing")?
                    .streams
                    .get(),
                1
            );
            let mut waiting = Box::pin(async move {
                let _lease = lease;
                pending::<()>().await;
            });
            assert!(poll_once(waiting.as_mut()).is_none());
            drop(waiting);
            assert_eq!(fixture.logical_available(&fixture.second).await, 1);
            assert_eq!(
                owner
                    .lock_slots()
                    .connections
                    .front()
                    .ok_or("donor slot missing")?
                    .streams
                    .get(),
                0
            );
            drop(
                fixture
                    .reuse(&fixture.second)
                    .await?
                    .ok_or("cancelled lease retained a stream")?,
            );
            Ok(())
        })
        .await
}

#[tokio::test]
async fn independent_origins_respect_the_shared_physical_local_stream_bound() -> TestResult {
    shared_capacity(1, 3).await
}

#[tokio::test]
async fn independent_origins_respect_the_shared_physical_peer_stream_bound() -> TestResult {
    shared_capacity(3, 1).await
}

async fn shared_capacity(local: usize, peer: u32) -> TestResult {
    let fixture = Fixture::new(local, peer, None)?;
    fixture
        .run(async {
            drop(fixture.seed().await?);
            let second = fixture
                .reuse(&fixture.second)
                .await?
                .ok_or("B was not admitted")?;
            assert_eq!(
                second.connection().peer_initial_max_streams_bidi(),
                Some(u64::from(peer))
            );
            assert_eq!(fixture.logical_available(&fixture.second).await, local - 1);
            assert!(
                fixture.reuse(&fixture.third).await?.is_none(),
                "C exceeded the donor's physical stream bound"
            );
            assert_eq!(fixture.logical_available(&fixture.third).await, local);
            let token = Arc::clone(&second.lease.token);
            let owner = Arc::clone(&second.lease.owner);
            drop(second);
            let third = fixture
                .reuse(&fixture.third)
                .await?
                .ok_or("B did not release physical capacity")?;
            assert!(Arc::ptr_eq(&token, &third.lease.token));
            assert!(Arc::ptr_eq(&owner, &third.lease.owner));
            assert!(!Arc::ptr_eq(&third.entry, &third.lease.owner));
            assert_eq!(fixture.logical_available(&fixture.second).await, local);
            assert_eq!(fixture.logical_available(&fixture.third).await, local - 1);
            drop(third);
            assert_eq!(fixture.logical_available(&fixture.third).await, local);
            Ok(())
        })
        .await
}

#[tokio::test]
async fn close_idle_and_refresh_preserve_a_coalesced_response_until_its_body_ends() -> TestResult {
    let fixture = Fixture::new(1, 3, None)?;
    fixture
        .run(async {
            drop(fixture.seed().await?);
            let lease = fixture
                .reuse(&fixture.second)
                .await?
                .ok_or("B was not admitted")?;
            let owner = Arc::downgrade(&lease.lease.owner);
            let count = lease.lease.streams.clone();
            fixture.pool.close_idle_connections().await;
            assert_eq!(
                owner
                    .upgrade()
                    .ok_or("physical owner retired while held")?
                    .lock_slots()
                    .connections
                    .len(),
                1,
                "close-idle retired a held lease"
            );
            let target = OriginForm::parse("/held")?;
            let authority = fixture.second.authority().as_str();
            let fields = validate_request(
                &fixture.connector,
                None,
                &Route::Direct,
                Http3TransportTarget::for_origin(&fixture.second),
                &http::Method::GET,
                authority,
                &target,
                Vec::new(),
                &[],
                None,
                None,
            )?;
            let mut retries = ConnectionSetupRetryState::new(RetryPolicy::none(), Span::none());
            let sent = fixture
                .pool
                .send_request_on_lease(
                    lease,
                    &fixture.connector,
                    http::Method::GET,
                    authority,
                    target,
                    fields,
                    Vec::new(),
                    None,
                    None,
                    budget()?,
                    &mut retries,
                )
                .await?;
            let Dispatched::Sent((response, _)) = sent else {
                return Err("unexpected client-hint restart".into());
            };
            assert_eq!(response.status(), http::StatusCode::OK);
            assert_eq!(count.get(), 1);
            assert_eq!(fixture.logical_available(&fixture.second).await, 0);
            fixture.pool.close_idle_connections().await;
            assert_eq!(
                owner
                    .upgrade()
                    .ok_or("physical owner retired while held")?
                    .lock_slots()
                    .connections
                    .len(),
                1,
                "close-idle retired a held response"
            );
            fixture.pool.refresh_connections().await;
            assert!(
                owner.upgrade().is_some(),
                "held response lost its physical owner"
            );
            assert!(fixture.candidates(&fixture.third).await.is_err());
            fixture.release_body.notify_one();
            assert_eq!(response.into_body().collect_with_limit(2).await?, b"ok"[..]);
            assert!(
                owner.upgrade().is_none(),
                "completed response retained its physical owner"
            );
            assert_eq!(count.get(), 0);
            assert_eq!(fixture.logical_available(&fixture.second).await, 1);
            Ok(())
        })
        .await
}

fn budget() -> Result<TimeoutBudget, crate::RequestError> {
    TimeoutBudget::new(RequestTimeouts::new().total(DEADLINE))
}

#[derive(Default)]
struct DnsGate {
    entered: AtomicUsize,
    release: Notify,
}

struct Fixture {
    pool: Http3Pool,
    connector: Http3Connector,
    endpoint: quinn::Endpoint,
    donor: Endpoint,
    second: Endpoint,
    third: Endpoint,
    release_body: Notify,
}

impl Fixture {
    fn new(active: usize, peer_limit: u32, dns_gate: Option<Arc<DnsGate>>) -> TestResult<Self> {
        let key = rcgen::KeyPair::generate()?;
        let cert = rcgen::CertificateParams::new(vec![DONOR.into(), SECOND.into(), THIRD.into()])?
            .self_signed(&key)?;
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_bidi_streams(peer_limit.into());
        config.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(config),
            phantom_testkit::udp::bind((Ipv4Addr::LOCALHOST, 0).into())?,
            Arc::new(quinn::TokioRuntime),
        )?;
        let port = endpoint.local_addr()?.port();
        let mut resolver = HostResolver::new()
            .with_override(DONOR, [Ipv4Addr::LOCALHOST.into()])
            .with_override(THIRD, [Ipv4Addr::LOCALHOST.into()]);
        if let Some(gate) = dns_gate {
            resolver = resolver.with_resolver(AddressResolver::from_fn(move |host| {
                let gate = Arc::clone(&gate);
                async move {
                    if host != SECOND {
                        return Err(std::io::Error::other("unexpected test lookup"));
                    }
                    gate.entered.fetch_add(1, Ordering::SeqCst);
                    gate.release.notified().await;
                    Ok(vec![Ipv4Addr::LOCALHOST.into()])
                }
            }));
        } else {
            resolver = resolver.with_override(SECOND, [Ipv4Addr::LOCALHOST.into()]);
        }
        let connector = Http3Connector::new_with_additional_roots(
            &firefox::v157_quic_tls(),
            &firefox::v157_quic(),
            &firefox::v157_http3(),
            &firefox::v157_http3_request(),
            [cert.der().as_ref()],
        )?
        .with_host_resolver(resolver);
        Ok(Self {
            pool: Http3Pool::new(
                NonZeroUsize::new(4).ok_or("invalid pool capacity")?,
                NonZeroUsize::new(active).ok_or("invalid active bound")?,
                NonZeroUsize::MIN,
            ),
            connector,
            endpoint,
            donor: Endpoint::new(format!("{DONOR}:{port}").parse()?, port)?,
            second: Endpoint::new(format!("{SECOND}:{port}").parse()?, port)?,
            third: Endpoint::new(format!("{THIRD}:{port}").parse()?, port)?,
            release_body: Notify::new(),
        })
    }

    async fn seed(&self) -> TestResult<Http3Lease> {
        let mut retries = ConnectionSetupRetryState::new(RetryPolicy::none(), Span::none());
        let lease = self
            .pool
            .admit(&self.donor, &Route::Direct, budget()?)
            .await?
            .connect(
                &self.connector,
                None,
                &self.donor,
                &Route::Direct,
                Http3TransportTarget::for_origin(&self.donor),
                budget()?,
                &mut retries,
                Http3SetupControl::default(),
            )
            .await?;
        assert!(self.connector.can_reuse_now(lease.connection()));
        Ok(lease)
    }

    async fn candidates(
        &self,
        origin: &Endpoint,
    ) -> TestResult<super::super::Http3ReuseCandidates> {
        self.pool
            .reuse_candidates(&self.connector, origin, &Route::Direct)
            .await
            .ok_or_else(|| "no reusable donor".into())
    }

    async fn reuse(&self, origin: &Endpoint) -> TestResult<Option<Http3Lease>> {
        Ok(self
            .pool
            .acquire_reused(self.candidates(origin).await?, &self.connector, budget()?)
            .await?)
    }

    async fn logical_available(&self, origin: &Endpoint) -> usize {
        self.pool
            .entry(PoolKey::new(origin, &Route::Direct))
            .await
            .admission
            .available_active()
    }

    async fn donor_owner(&self) -> TestResult<Arc<super::super::PoolEntry>> {
        let owner = self
            .pool
            .entry(PoolKey::new(&self.donor, &Route::Direct))
            .await;
        if owner.lock_slots().connections.len() != 1 {
            return Err("expected one authenticated donor".into());
        }
        Ok(owner)
    }

    async fn serve(&self, mut stopped: watch::Receiver<bool>) -> TestResult {
        let incoming = tokio::select! {
            _ = stopped.wait_for(|value| *value) => return Ok(()),
            incoming = self.endpoint.accept() => incoming.ok_or("endpoint closed before handshake")?,
        };
        let connection = tokio::select! {
            _ = stopped.wait_for(|value| *value) => return Ok(()),
            connected = incoming => connected?,
        };
        let mut h3: h3::server::Connection<_, Bytes> =
            h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
        let accepted = tokio::select! {
            _ = stopped.wait_for(|value| *value) => return Ok(()),
            accepted = h3.accept() => match accepted {
                // Refresh can release the last donor without sending a request.
                Ok(None) => return Ok(()),
                Err(h3::error::ConnectionError::Remote(
                    h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code }, ..
                )) if error_code == h3::error::Code::H3_NO_ERROR.value() => return Ok(()),
                accepted => accepted?.ok_or("peer closed before test request")?,
            },
        };
        let (request, mut stream) = accepted.resolve_request().await?;
        assert_eq!(
            request.uri().authority().map(|value| value.as_str()),
            Some(self.second.authority().as_str())
        );
        assert_eq!(request.uri().path(), "/held");
        assert!(stream.recv_data().await?.is_none());
        stream
            .send_response(http::Response::builder().status(200).body(())?)
            .await?;
        tokio::select! {
            _ = stopped.wait_for(|value| *value) => return Ok(()),
            () = self.release_body.notified() => {}
        }
        stream.send_data(Bytes::from_static(b"ok")).await?;
        stream.finish().await?;
        stopped.wait_for(|value| *value).await?;
        Ok(())
    }

    async fn run(&self, caller: impl Future<Output = TestResult>) -> TestResult {
        let (stop, stopped) = watch::channel(false);
        let caller = async {
            let result = caller.await;
            let _ = stop.send(true);
            result
        };
        // The peer and caller remain children of this future, even on panic.
        let outcome = AssertUnwindSafe(timeout(DEADLINE, async {
            tokio::try_join!(caller, self.serve(stopped)).map(|_| ())
        }))
        .catch_unwind()
        .await;
        self.endpoint
            .close(0_u32.into(), b"pool reuse test complete");
        let cleanup = timeout(CLEANUP, self.endpoint.wait_idle()).await;
        let primary: TestResult = match outcome {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(error.into()),
            Err(payload) => {
                let message = payload
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| payload.downcast_ref::<&str>().copied())
                    .unwrap_or("pool reuse assertion panicked");
                Err(std::io::Error::other(message.to_owned()).into())
            }
        };
        match (primary, cleanup) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(error), Ok(())) => Err(error),
            (Ok(()), Err(error)) => Err(error.into()),
            (Err(primary), Err(cleanup)) => {
                Err(std::io::Error::other(format!("{primary}; endpoint cleanup: {cleanup}")).into())
            }
        }
    }
}
