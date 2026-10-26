//! Request-time alternatives retain Firefox's first-421 recovery behavior.

use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    num::NonZeroUsize,
    panic::AssertUnwindSafe,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

use futures_util::FutureExt;
use http::{HeaderValue, StatusCode};
use phantom::{
    AddressResolver, AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, AltSvcSnapshot,
    AltSvcSnapshotEntry, Client, HttpAttemptBudget, HttpProtocol, RequestHeader, ResponseInfo,
    profile::{
        Http3AltSvcValidation, Http3ClientSettings, Http3MisdirectedRequest, browser::firefox,
    },
};
use tokio::{sync::oneshot, time::timeout};

use crate::support::{
    http3_upgrade::{
        AlternativeBehavior, Http3UpgradeFixture, ObservedRequest, PlannedResponse, UpgradeScript,
    },
    tls::{TestIdentity, TestResult},
    tunnel_proxy::finish_with_cleanup,
};

const DEADLINE: Duration = Duration::from_secs(10);
const ORIGIN: &str = "localhost";

#[tokio::test]
async fn request_time_selected_421_restarts_with_frozen_fields_and_evicts_the_advertisement()
-> TestResult<()> {
    restart(AltSvcPolicy::sequential()).await
}

#[tokio::test]
async fn request_time_race_winning_421_restarts_on_origin_without_reracing() -> TestResult<()> {
    let backoff = AltSvcBrokenBackoff::new(Duration::from_secs(60), Duration::from_secs(600))?;
    // The shared peer has no handshake gate. This existing race-policy seam
    // holds only the first origin candidate beyond the request deadline; the
    // 421 continuation must connect directly, without applying this delay again.
    let race =
        AltSvcRace::new(Duration::from_secs(30), backoff).with_max_alternatives(NonZeroUsize::MIN);
    restart(AltSvcPolicy::race(race)).await
}

async fn restart(policy: AltSvcPolicy) -> TestResult<()> {
    let identity = TestIdentity::generate_for_ip_and_dns(IpAddr::V4(Ipv4Addr::LOCALHOST), ORIGIN)?;
    let fixture = Http3UpgradeFixture::spawn(
        &identity,
        ORIGIN,
        UpgradeScript::new(
            [PlannedResponse::new(StatusCode::OK).body("origin")],
            AlternativeBehavior::responses([PlannedResponse::new(StatusCode::MISDIRECTED_REQUEST)
                .header("alt-svc", HeaderValue::from_static(r#"h3=":1"; ma=60"#))]),
        ),
    )
    .await?;
    let spare = match Http3UpgradeFixture::spawn(
        &identity,
        ORIGIN,
        UpgradeScript::new([], AlternativeBehavior::responses([])),
    )
    .await
    {
        Ok(spare) => spare,
        Err(error) => {
            return finish_with_cleanup(Err(error), fixture.finish().await.map(|_| ()));
        }
    };

    let authority = format!("{ORIGIN}:{}", fixture.origin_address().port());
    let operation = async {
        let (lookup_seen, lookup_started) = oneshot::channel();
        let (resume_lookup, lookup_released) = oneshot::channel();
        let gate = Arc::new(Mutex::new(Some((lookup_seen, lookup_released))));
        let resolver = AddressResolver::from_fn(move |host| {
            let gate = gate
                .lock()
                .map_err(|_| io::Error::other("origin DNS barrier was poisoned"))
                .and_then(|mut gate| {
                    gate.take()
                        .ok_or_else(|| io::Error::other("extra origin DNS lookup"))
                });
            async move {
                if host != ORIGIN {
                    return Err(io::Error::other("unexpected DNS name"));
                }
                let (seen, released) = gate?;
                seen.send(())
                    .map_err(|_| io::Error::other("origin lookup observer stopped"))?;
                released
                    .await
                    .map_err(|_| io::Error::other("origin lookup was not released"))?;
                Ok(vec![Ipv4Addr::LOCALHOST.into()])
            }
        });
        let mut settings = firefox::v157_http3();
        // These imported alternatives exercise request-time selection and racing.
        // Default Firefox advertisement validation is covered by the upgrade and
        // coalesced replay controls, which await actual authenticated publication.
        settings.alt_svc_validation = Http3AltSvcValidation::OnRequest;
        let profile = firefox::v157_windows().with_http3(Http3ClientSettings::new(
            firefox::v157_quic_tls(),
            firefox::v157_quic(),
            settings,
            firefox::v157_http3_request(),
        ));
        assert_eq!(
            profile
                .http3()
                .ok_or("Firefox has no H3 settings")?
                .http3()
                .misdirected_request,
            Http3MisdirectedRequest::RetryFirst,
        );
        let builder = Client::builder(profile)
            .add_root_certificate_der(identity.root_der.clone())
            .dns_resolver(resolver)
            .no_dns_cache()
            .alt_svc(NonZeroUsize::new(8).ok_or("invalid Alt-Svc capacity")?)
            .alt_svc_policy(policy);
        #[cfg(feature = "cookies")]
        let builder = builder.cookies();
        let client = builder.build()?;
        let origin = format!("https://{ORIGIN}:{}", fixture.origin_address().port());
        let url = fixture.origin_url("/misdirected");
        let expires = SystemTime::now() + Duration::from_secs(3600);
        client.import_alt_svc(&AltSvcSnapshot::new(
            [
                fixture.alternative_address().port(),
                spare.alternative_address().port(),
            ]
            .into_iter()
            .map(|port| AltSvcSnapshotEntry::new(origin.clone(), "127.0.0.1", port, expires))
            .collect(),
        ))?;
        assert_eq!(
            client
                .export_alt_svc()
                .ok_or("Alt-Svc disabled")?
                .entries()
                .len(),
            2
        );
        #[cfg(feature = "cookies")]
        client
            .cookie_jar()
            .ok_or("cookie jar disabled")?
            .set_cookie(&url, "sid=original; Path=/")?;
        let allowance = HttpAttemptBudget::new(2);
        let send = async {
            let response = client
                .get(&url)?
                .headers(caller_fields())
                .attempt_budget(allowance.clone())
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(
                response
                    .extensions()
                    .get::<ResponseInfo>()
                    .ok_or("missing response protocol")?
                    .protocol(),
                HttpProtocol::Http2
            );
            assert_eq!(response.into_body().collect_with_limit(6).await?, "origin");
            TestResult::Ok(())
        };
        let change_cookie = async {
            lookup_started.await?;
            let observed = fixture.snapshot()?;
            assert_eq!(observed.alternative_requests.len(), 1);
            assert_eq!(observed.origin_request_count, 0);
            // The first H3 request is already on the wire. Freeze the checked
            // origin fields even when the jar changes before fallback I/O.
            #[cfg(feature = "cookies")]
            client
                .cookie_jar()
                .ok_or("cookie jar disabled")?
                .set_cookie(&url, "sid=changed; Path=/")?;
            resume_lookup
                .send(())
                .map_err(|_| "origin lookup stopped")?;
            TestResult::Ok(())
        };
        tokio::try_join!(send, change_cookie)?;
        assert_eq!(
            allowance.remaining(),
            0,
            "each wire attempt must spend once"
        );
        assert!(
            client
                .export_alt_svc()
                .ok_or("Alt-Svc disabled")?
                .entries()
                .is_empty(),
            "421 retained a location from the old advertisement or learned its replacement"
        );
        #[cfg(feature = "cookies")]
        assert_eq!(
            client
                .cookie_jar()
                .ok_or("cookie jar disabled")?
                .request_value(&url)?
                .as_deref(),
            Some("sid=changed")
        );
        TestResult::Ok(())
    };
    let result = match AssertUnwindSafe(timeout(DEADLINE, operation))
        .catch_unwind()
        .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(error.into()),
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("misdirected-request assertion panicked");
            Err(io::Error::other(message.to_owned()).into())
        }
    };
    // Both owners are joined even when the request, an assertion, or the
    // other peer's cleanup fails. Each uses the fixture's existing stop bound.
    let observed = fixture.finish().await;
    let unused = spare.finish().await;
    let cleanup = match (observed, unused) {
        (Ok(observed), Ok(unused)) => Ok((observed, unused)),
        (Err(primary), cleanup) => finish_with_cleanup(Err(primary), cleanup.map(|_| ())),
        (Ok(_), Err(error)) => Err(error),
    };
    let (observed, unused) = match result {
        Ok(()) => cleanup?,
        Err(primary) => return finish_with_cleanup(Err(primary), cleanup.map(|_| ())),
    };
    assert_eq!(observed.alternative_connections, 1);
    assert_eq!(observed.alternative_requests.len(), 1);
    assert_eq!(observed.origin_connections, 1);
    assert_eq!(observed.origin_request_count, 1);
    assert_eq!(observed.origin_requests.len(), 1);
    assert_eq!(
        unused.alternative_connections, 0,
        "421 tried the next alternative"
    );
    assert!(unused.alternative_requests.is_empty());
    assert_eq!(unused.origin_connections, 0);
    let first = &observed.alternative_requests[0];
    let fallback = &observed.origin_requests[0];
    for request in [first, fallback] {
        assert_eq!(request.method, http::Method::GET);
        assert_eq!(request.authority.as_deref(), Some(authority.as_str()));
        assert_eq!(request.path_and_query.as_deref(), Some("/misdirected"));
        assert_eq!(request.server_name.as_deref(), Some(ORIGIN));
    }
    assert_eq!(safe_fields(first), safe_fields(fallback));
    assert_eq!(
        safe_fields(fallback),
        vec![
            ("x-first".into(), b"one".to_vec()),
            ("authorization".into(), b"Basic dGVzdDpzZWNyZXQ=".to_vec()),
            ("x-last".into(), b"two".to_vec()),
            ("cookie".into(), b"sid=original".to_vec()),
        ]
    );
    assert!(
        !fallback
            .fields
            .iter()
            .any(|field| field.name.eq_ignore_ascii_case("alt-used"))
    );
    Ok(())
}

fn caller_fields() -> Vec<RequestHeader> {
    let fields = vec![
        RequestHeader::new("x-first", "one"),
        RequestHeader::new("authorization", "Basic dGVzdDpzZWNyZXQ="),
        RequestHeader::new("x-last", "two"),
    ];
    #[cfg(not(feature = "cookies"))]
    let fields = {
        let mut fields = fields;
        fields.push(RequestHeader::new("cookie", "sid=original"));
        fields
    };
    fields
}

fn safe_fields(request: &ObservedRequest) -> Vec<(String, Vec<u8>)> {
    request
        .fields
        .iter()
        .filter(|field| {
            matches!(
                field.name.to_ascii_lowercase().as_str(),
                "x-first" | "authorization" | "x-last" | "cookie"
            )
        })
        .map(|field| (field.name.to_ascii_lowercase(), field.value.clone()))
        .collect()
}
