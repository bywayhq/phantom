use std::{num::NonZeroUsize, sync::Arc};

use super::{Http3Pool, Http3TransportTarget, PoolKey, TransportLocation};
use crate::{Route, Socks5Proxy, authority::Endpoint};

mod reuse;
mod warmup;

#[tokio::test]
async fn per_origin_admission_survives_lru_eviction() -> Result<(), Box<dyn std::error::Error>> {
    let one = NonZeroUsize::MIN;
    let pool = Http3Pool::new(one, one, one);
    let first = Endpoint::new("first.test:443".parse()?, 443)?;
    let second = Endpoint::new("second.test:443".parse()?, 443)?;

    let first_entry = pool.entry(PoolKey::new(&first, &Route::Direct)).await;
    let permit = first_entry.admit().await?;
    pool.entry(PoolKey::new(&second, &Route::Direct)).await;
    drop(first_entry);
    let replacement = pool.entry(PoolKey::new(&first, &Route::Direct)).await;

    assert!(Arc::ptr_eq(permit.admission(), &replacement.admission));
    assert_eq!(replacement.admission.available_active(), 0);
    drop(permit);
    assert_eq!(replacement.admission.available_active(), 1);
    Ok(())
}

#[tokio::test]
async fn connect_turn_serializes_one_transport_location_only()
-> Result<(), Box<dyn std::error::Error>> {
    let one = NonZeroUsize::MIN;
    let pool = Http3Pool::new(one, one, one);
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    let entry = pool.entry(PoolKey::new(&endpoint, &Route::Direct)).await;
    let alternative = TransportLocation::new(Http3TransportTarget::new("alt.test", 8443));
    let origin = TransportLocation::new(Http3TransportTarget::for_origin(&endpoint));

    let setup = entry.connect_turn(alternative.clone()).await;
    // Exact H3 to the origin location does not wait for the alternative.
    let exact = std::pin::pin!(entry.connect_turn(origin));
    let exact = poll_once(exact).ok_or("exact H3 waited for another location")?;
    // A second setup to the same location waits until the turn ends.
    let mut same = std::pin::pin!(entry.connect_turn(alternative));
    assert!(poll_once(same.as_mut()).is_none());
    drop(setup);
    let same = poll_once(same).ok_or("the released turn was not handed over")?;

    drop((exact, same));
    assert!(super::lock_turns(&entry.turns).is_empty());
    Ok(())
}

#[test]
fn an_attempt_limit_without_a_time_driver_fails_instead_of_panicking()
-> Result<(), Box<dyn std::error::Error>> {
    use phantom_net::http3::Http3Connector;
    use phantom_profile::browser::chrome;

    use super::Http3SetupControl;
    use crate::RequestErrorKind;

    // I/O but no time driver: `tokio::time::timeout` would panic here.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    runtime.block_on(async {
        let connector = Http3Connector::new_with_additional_roots(
            &chrome::v154_quic_tls(),
            &chrome::v154_quic(),
            &chrome::v154_http3(),
            &chrome::v154_http3_request(),
            std::iter::empty(),
        )?;
        let one = NonZeroUsize::MIN;
        let pool = Http3Pool::new(one, one, one);
        let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
        let entry = pool.entry(PoolKey::new(&endpoint, &Route::Direct)).await;
        let control = Http3SetupControl {
            attempt_limit: Some(std::time::Duration::from_secs(1)),
            ..Http3SetupControl::default()
        };
        let result = entry
            .acquire(
                &connector,
                None,
                &endpoint,
                &Route::Direct,
                Http3TransportTarget::for_origin(&endpoint),
                control,
            )
            .await;
        match result {
            Ok(_) => Err("a limited attempt ran without a time driver".into()),
            Err(error) => {
                assert_eq!(error.kind(), RequestErrorKind::RuntimeUnavailable);
                Ok(())
            }
        }
    })
}

/// A request awaits `acquire` whether it reuses a connection or opens one,
/// so only `open`, which a new connection boxes, may hold the connectors'
/// futures.
#[cfg(debug_assertions)]
#[test]
fn acquire_leaves_connection_setup_off_the_request_future() {
    // A reuse holds only the arguments, the connect turn, and the boxed
    // setup.
    let size = phantom_testkit::future_size::future_size(&super::PoolEntry::acquire);
    assert!(size <= 1024, "PoolEntry::acquire is {size} bytes");
}

/// `connect_with` holds the connectors' futures for a new connection,
/// boxed apart from `open`; see `phantom_testkit::future_size`.
///
/// With all features, `connect_with` is 8,728 bytes and `open` 1,120 on
/// Windows (x86-64, Rust 1.99.0), the only platform measured.
#[cfg(debug_assertions)]
#[test]
fn opening_a_connection_stays_within_the_setup_budget() {
    use phantom_testkit::future_size::{SETUP_FUTURE_BUDGET, assert_within, future_size};

    assert_within(
        SETUP_FUTURE_BUDGET,
        &[
            ("PoolEntry::open", future_size(&super::PoolEntry::open)),
            (
                "PoolEntry::connect_with",
                future_size(&super::PoolEntry::connect_with),
            ),
        ],
    );
}

fn poll_once<F: std::future::Future>(future: std::pin::Pin<&mut F>) -> Option<F::Output> {
    match future.poll(&mut std::task::Context::from_waker(std::task::Waker::noop())) {
        std::task::Poll::Ready(output) => Some(output),
        std::task::Poll::Pending => None,
    }
}

/// Only a replay-safe request on a connection whose early data is
/// unanswered, where the QPACK policy does not wait for the peer's
/// SETTINGS or remembered SETTINGS stand in for them, goes out before the
/// handshake with the pre-handshake client hints; every other request
/// waits and uses the handshake's hints.
#[test]
fn only_an_unheld_replay_safe_request_goes_out_before_the_handshake() {
    use super::sends_before_handshake;

    assert!(sends_before_handshake(true, true, false));
    for (replay_safe, pending, waits) in [
        (true, true, true),
        (false, true, false),
        (true, false, false),
        (false, false, true),
    ] {
        assert!(!sends_before_handshake(replay_safe, pending, waits));
    }
}

#[test]
fn only_bodiless_safe_requests_without_trailers_are_replay_safe() {
    use http::Method;
    use phantom_net::request::RequestBody;
    use phantom_net::request::RequestHeader;

    use super::is_replay_safe;

    for method in [Method::GET, Method::HEAD, Method::OPTIONS, Method::TRACE] {
        assert!(is_replay_safe(&method, None, &[]), "{method}");
    }
    for method in [Method::POST, Method::PUT, Method::DELETE, Method::CONNECT] {
        assert!(!is_replay_safe(&method, None, &[]), "{method}");
    }
    let body = RequestBody::from_bytes(bytes::Bytes::from_static(b"body"));
    assert!(!is_replay_safe(&Method::GET, Some(&body), &[]));
    let trailer = RequestHeader::new("x-trailer", "1");
    assert!(!is_replay_safe(&Method::GET, None, &[trailer]));
}

#[test]
fn transport_location_is_separate_from_origin_pool_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    let key = PoolKey::new(&endpoint, &Route::Direct);
    let alternative = TransportLocation::new(Http3TransportTarget::new("Alt.Test", 8443));
    let matching = TransportLocation::new(Http3TransportTarget::new("alt.test", 8443));
    let origin = TransportLocation::new(Http3TransportTarget::for_origin(&endpoint));

    assert_eq!(key, PoolKey::new(&endpoint, &Route::Direct));
    assert_eq!(alternative, matching);
    assert_ne!(alternative, origin);
    Ok(())
}

#[cfg(feature = "https-records")]
#[test]
fn destination_policy_applies_only_to_learned_direct_alt_svc()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::session::alt_svc::{AltSvcStore, AlternativeTarget};
    use crate::{AltSvcHttpsPolicy, AltSvcSnapshot, AltSvcSnapshotEntry};
    use std::time::{Duration, SystemTime};

    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    let store = AltSvcStore::new(NonZeroUsize::MIN);
    store.import(&AltSvcSnapshot::new(vec![AltSvcSnapshotEntry::new(
        "https://origin.test",
        "alt.test",
        8443,
        SystemTime::now()
            .checked_add(Duration::from_secs(30))
            .ok_or("expiry overflow")?,
    )]))?;
    let selected = store.get_up_to(&endpoint, &Route::Direct, 1);
    let alternative = AlternativeTarget::new(selected.first().ok_or("alternative absent")?);
    let learned = Http3TransportTarget::for_alternative(&alternative);
    let origin_https = AlternativeTarget::https_record(&endpoint, false, false);
    let timeout = Duration::from_secs(1);
    let policy = AltSvcHttpsPolicy::Destination {
        lookup_timeout: timeout,
    };

    assert_eq!(
        learned.destination_lookup_timeout(&Route::Direct, policy),
        Some(timeout)
    );
    assert_eq!(
        learned.destination_lookup_timeout(&Route::Direct, AltSvcHttpsPolicy::default()),
        None
    );
    let proxy = Route::socks5(Socks5Proxy::new("socks5h://proxy.test:1080")?);
    assert_eq!(learned.destination_lookup_timeout(&proxy, policy), None);
    for target in [
        Http3TransportTarget::for_origin(&endpoint),
        Http3TransportTarget::for_alternative(&origin_https),
        Http3TransportTarget::new("alt.test", 8443),
    ] {
        assert_eq!(
            target.destination_lookup_timeout(&Route::Direct, policy),
            None
        );
    }
    Ok(())
}

#[test]
fn an_alternative_learned_on_one_route_uses_that_route_s_entry()
-> Result<(), Box<dyn std::error::Error>> {
    let endpoint = Endpoint::new("origin.test:443".parse()?, 443)?;
    let proxied = Route::socks5(Socks5Proxy::new("socks5h://proxy.test:1080")?);
    let other = Route::socks5(Socks5Proxy::new("socks5h://other.test:1080")?);

    // The same alternative location on another route is another entry, so
    // a proxied alternative never reuses a direct connection or another
    // proxy's.
    assert_ne!(
        PoolKey::new(&endpoint, &proxied),
        PoolKey::new(&endpoint, &Route::Direct)
    );
    assert_ne!(
        PoolKey::new(&endpoint, &proxied),
        PoolKey::new(&endpoint, &other)
    );
    assert_eq!(
        PoolKey::new(&endpoint, &proxied),
        PoolKey::new(&endpoint, &proxied)
    );
    Ok(())
}

#[tokio::test]
async fn only_an_origin_handshake_failure_qualifies_for_inner_ticket_retry()
-> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::{error::Error as StdError, net::Ipv4Addr, panic::AssertUnwindSafe};

    use futures_util::FutureExt;
    use phantom_net::{
        http3::{ConnectUdpError, ConnectUdpErrorKind, Http3Connector, Http3ConnectorErrorKind},
        proxy::ConnectUdpProxyPool,
        request::OriginForm,
        route::{ConnectUdpRoute, ConnectUdpTransport, DatagramRoute, Endpoint as DialEndpoint},
    };
    use phantom_profile::{Http3PseudoHeader, browser::chrome};

    type TestResult = Result<(), Box<dyn StdError + Send + Sync>>;
    const DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

    #[derive(Debug)]
    struct NoCertificate;

    impl rustls::server::ResolvesServerCert for NoCertificate {
        fn resolve(
            &self,
            _: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            None
        }
    }

    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(NoCertificate));
    tls.alpn_protocols = vec![b"not-h3".to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)?;
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(quinn::ServerConfig::with_crypto(Arc::new(crypto))),
        phantom_testkit::udp::bind((Ipv4Addr::LOCALHOST, 0).into())?,
        Arc::new(quinn::TokioRuntime),
    )?;
    let address = endpoint.local_addr()?;
    let authority = address.to_string();
    let mut request = chrome::v154_http3_request();
    request.extended_connect_pseudo_header_order = Some(vec![
        Http3PseudoHeader::Method,
        Http3PseudoHeader::Protocol,
        Http3PseudoHeader::Scheme,
        Http3PseudoHeader::Authority,
        Http3PseudoHeader::Path,
    ]);
    let connector = Http3Connector::new_with_additional_roots(
        &chrome::v154_quic_tls(),
        &chrome::v154_quic(),
        &chrome::v154_http3(),
        &request,
        std::iter::empty(),
    )?;
    let pool = ConnectUdpProxyPool::new();

    let body = async {
        let peer = async {
            for _ in 0..2 {
                let incoming = endpoint.accept().await.ok_or("test endpoint closed")?;
                assert!(incoming.await.is_err(), "incompatible ALPN was accepted");
            }
            Ok::<(), Box<dyn StdError + Send + Sync>>(())
        };
        let client = async {
            let direct = connector
                .connect(
                    DatagramRoute::Direct(DialEndpoint {
                        host: "127.0.0.1",
                        port: address.port(),
                    }),
                    "127.0.0.1",
                )
                .await
                .err()
                .ok_or("direct handshake unexpectedly succeeded")?;
            assert_eq!(direct.kind(), Http3ConnectorErrorKind::Handshake);
            assert!(super::SetupFailure::Origin(direct).is_origin_handshake());

            let proxy = connector
                .connect(
                    DatagramRoute::ConnectUdp(ConnectUdpRoute {
                        proxy: DialEndpoint {
                            host: "127.0.0.1",
                            port: address.port(),
                        },
                        transport: ConnectUdpTransport::Http3(&connector),
                        authority: &authority,
                        path: OriginForm::parse("/udp/127.0.0.1/443/")?,
                        headers: Vec::new(),
                        credentials: None,
                        pool: Some(&pool),
                        prepared_outer: None,
                    }),
                    "origin.test",
                )
                .await
                .err()
                .ok_or("outer proxy handshake unexpectedly succeeded")?;
            assert_eq!(proxy.kind(), Http3ConnectorErrorKind::Proxy);
            assert_eq!(
                proxy
                    .source()
                    .and_then(|source| source.downcast_ref::<ConnectUdpError>())
                    .ok_or("proxy failure lost CONNECT-UDP cause")?
                    .kind(),
                ConnectUdpErrorKind::Handshake,
            );
            assert!(!super::SetupFailure::ConnectUdp(proxy).is_origin_handshake());
            Ok::<(), Box<dyn StdError + Send + Sync>>(())
        };
        tokio::try_join!(client, peer)?;
        Ok::<(), Box<dyn StdError + Send + Sync>>(())
    };
    let primary = AssertUnwindSafe(tokio::time::timeout(DEADLINE, body))
        .catch_unwind()
        .await;
    // Both peer futures are directly owned. Cleanup runs after every
    // assertion, error and deadline, rather than only after success.
    endpoint.close(0_u32.into(), b"test complete");
    let cleanup: TestResult = tokio::time::timeout(DEADLINE, endpoint.wait_idle())
        .await
        .map_err(Into::into);
    let primary: TestResult = match primary {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(error.into()),
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("handshake classification assertion panicked");
            Err(std::io::Error::other(message.to_owned()).into())
        }
    };
    match (primary, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => {
            Err(std::io::Error::other(format!("{primary}; endpoint cleanup: {cleanup}")).into())
        }
    }
}
