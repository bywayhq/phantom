use std::{num::NonZeroUsize, sync::Arc, time::Duration};

use phantom_profile::{ClientProfile, Http3ClientSettings, TlsSettings, browser::chrome};

use crate::{
    AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, BuildErrorKind, Client, RequestBuilder,
    RequestTimeouts, ResponseBody, RetryPolicy,
};

fn assert_send_sync_clone<T: Send + Sync + Clone>() {}
fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn client_handles_are_send_sync_and_clone() {
    assert_send_sync_clone::<Client>();
    fn assert_send<T: Send>() {}
    assert_send::<crate::ClientBuilder>();
    fn assert_send_static<T: Send + 'static>() {}
    assert_send_static::<RequestBuilder>();
    assert_send_sync::<ResponseBody>();
    #[cfg(feature = "cookies")]
    assert_send_sync::<super::CookieJar>();
}

/// A profile with negotiated HTTP/1.1+HTTP/2 and HTTP/3, whose HTTP/3 TLS
/// settings are `http3_tls`.
fn profile(http3_tls: TlsSettings) -> ClientProfile {
    ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            http3_tls,
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
}

fn nonzero(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap_or(NonZeroUsize::MIN)
}

#[test]
fn profile_used_idle_timeout_reaches_both_http1_pools() -> Result<(), Box<dyn std::error::Error>> {
    let chromium_client =
        Client::builder(profile(chrome::v154_quic_tls()).with_http1(chrome::v154_http1()))
            .build()?;
    let firefox = Client::builder(
        profile(chrome::v154_quic_tls())
            .with_http1(phantom_profile::browser::firefox::v157_http1()),
    )
    .build()?;

    let timeout = Some(Duration::from_secs(300));
    assert_eq!(chromium_client.state.http1.used_idle_timeout(), timeout);
    assert_eq!(
        chromium_client.state.http1_or_2.http1_used_idle_timeout(),
        timeout
    );
    assert!(chromium_client.state.http1.prune_timer().is_none());
    assert!(chromium_client.state.http1_or_2.prune_timer().is_none());

    let timeout = Some(Duration::from_secs(115));
    assert_eq!(firefox.state.http1.used_idle_timeout(), timeout);
    assert_eq!(firefox.state.http1_or_2.http1_used_idle_timeout(), timeout);
    // One timer closes the idle connections of both pools.
    let exact = firefox.state.http1.prune_timer().ok_or("no exact timer")?;
    let negotiated = firefox
        .state
        .http1_or_2
        .prune_timer()
        .ok_or("no negotiated timer")?;
    assert!(Arc::ptr_eq(exact, negotiated));
    assert_eq!(exact.http1_limit(), Some(Duration::from_secs(115)));
    Ok(())
}

#[test]
fn an_http2_idle_limit_shares_the_prune_timer_of_every_pool()
-> Result<(), Box<dyn std::error::Error>> {
    let chromium_client = Client::builder(profile(chrome::v154_quic_tls())).build()?;
    assert!(chromium_client.state.http2.prune_timer().is_none());

    let firefox_http2 = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(phantom_profile::browser::firefox::v157_http2());
    let http2_only = Client::builder(firefox_http2.clone()).build()?;
    let timer = http2_only
        .state
        .http2
        .prune_timer()
        .ok_or("no HTTP/2 timer")?;
    // HTTP/1.1 connections keep no idle limit of their own.
    assert_eq!(timer.http1_limit(), None);
    let negotiated = http2_only
        .state
        .http1_or_2
        .prune_timer()
        .ok_or("no negotiated timer")?;
    assert!(Arc::ptr_eq(timer, negotiated));

    let firefox =
        Client::builder(firefox_http2.with_http1(phantom_profile::browser::firefox::v157_http1()))
            .build()?;
    let exact = firefox.state.http2.prune_timer().ok_or("no HTTP/2 timer")?;
    let http1 = firefox.state.http1.prune_timer().ok_or("no HTTP/1 timer")?;
    assert!(Arc::ptr_eq(exact, http1));
    assert_eq!(exact.http1_limit(), Some(Duration::from_secs(115)));
    Ok(())
}

#[test]
fn client_applies_its_options() -> Result<(), Box<dyn std::error::Error>> {
    let timeouts = RequestTimeouts::new().total(Duration::from_secs(5));
    let retry = RetryPolicy::connection_failures(nonzero(2), Duration::from_millis(1));
    let client = Client::builder(profile(chrome::v154_quic_tls()))
        .request_timeouts(timeouts)
        .retry_policy(retry)
        .max_http2_connections_per_origin(nonzero(3))
        .max_http3_connections_per_origin(nonzero(4))
        .build()?;
    let defaults = Client::builder(profile(chrome::v154_quic_tls())).build()?;

    assert_eq!(client.request_timeouts(), timeouts);
    assert_eq!(client.retry_policy(), retry);
    assert_eq!(client.state.http2.max_connections(), nonzero(3));
    assert_eq!(client.state.http3.max_connections(), nonzero(4));
    assert_eq!(defaults.state.http3.max_connections(), NonZeroUsize::MIN);
    assert_eq!(defaults.request_timeouts(), RequestTimeouts::new());
    Ok(())
}

#[test]
fn client_early_data_choice_overrides_the_profile() -> Result<(), Box<dyn std::error::Error>> {
    let sends_early_data = |client: &Client| {
        client
            .inner
            .http3
            .as_ref()
            .is_some_and(|connector| connector.sends_early_data())
    };
    // The Chrome 154 QUIC recipe offers early data.
    let builder = || Client::builder(profile(chrome::v154_quic_tls()));
    assert!(sends_early_data(&builder().build()?));
    assert!(!sends_early_data(
        &builder().http3_early_data(false).build()?
    ));
    assert!(sends_early_data(&builder().http3_early_data(true).build()?));

    let mut quic = chrome::v154_quic();
    quic.early_data = false;
    let without_recipe_early_data = || {
        Client::builder(
            ClientProfile::new(chrome::v154_tcp_tls())
                .with_http2(chrome::v154_http2())
                .with_http3(Http3ClientSettings::new(
                    chrome::v154_quic_tls(),
                    quic.clone(),
                    chrome::v154_http3(),
                    chrome::v154_http3_request(),
                )),
        )
    };
    assert!(!sends_early_data(&without_recipe_early_data().build()?));
    assert!(sends_early_data(
        &without_recipe_early_data().http3_early_data(true).build()?
    ));
    Ok(())
}

#[test]
fn client_build_rejects_invalid_options() -> Result<(), Box<dyn std::error::Error>> {
    // The ceiling itself is accepted.
    Client::builder(profile(chrome::v154_quic_tls()))
        .max_http3_connections_per_origin(nonzero(super::HTTP3_CONNECTIONS_PER_ORIGIN_CEILING))
        .build()?;

    let mut without_tickets = chrome::v154_quic_tls();
    without_tickets.session_tickets = phantom_profile::SessionTickets::disabled();
    let builder = || Client::builder(profile(without_tickets.clone()));
    let rejected = [
        (
            "an unrepresentable timeout",
            builder().request_timeouts(RequestTimeouts::new().total(Duration::MAX)),
        ),
        (
            "an unrepresentable retry delay",
            builder().retry_policy(RetryPolicy::connection_failures(
                NonZeroUsize::MIN,
                Duration::MAX,
            )),
        ),
        (
            "early data without session tickets",
            builder().http3_early_data(true),
        ),
        (
            "an Alt-Svc race without a store",
            builder().alt_svc_policy(AltSvcPolicy::race(AltSvcRace::new(
                Duration::from_millis(300),
                AltSvcBrokenBackoff::CHROMIUM_153,
            ))),
        ),
        (
            "an unrepresentable negotiated setup wait limit",
            builder().negotiated_setup_wait_limit(Duration::MAX),
        ),
        (
            "more HTTP/3 connections per origin than the ceiling",
            builder().max_http3_connections_per_origin(nonzero(9)),
        ),
    ];
    #[cfg(feature = "https-records")]
    let rejected = rejected.into_iter().chain([(
        "HTTPS record discovery without an Alt-Svc store",
        builder().https_record_discovery(crate::dns::HttpsRecordResolver::from_fn(|_, _| async {
            Ok(crate::dns::HttpsRecordLookup::new(Vec::new(), None))
        })),
    )]);
    for (case, builder) in rejected {
        let error = builder
            .build()
            .err()
            .ok_or_else(|| format!("a client with {case} was built"))?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy, "{case}");
    }
    Ok(())
}

#[test]
fn client_build_rejects_admission_bounds_above_the_semaphore_limit()
-> Result<(), Box<dyn std::error::Error>> {
    type BoundSetter = fn(crate::ClientBuilder, NonZeroUsize) -> crate::ClientBuilder;
    let setters: [BoundSetter; 6] = [
        crate::ClientBuilder::max_concurrent_http1_requests_per_origin,
        crate::ClientBuilder::max_pending_http1_requests_per_origin,
        crate::ClientBuilder::max_concurrent_http2_requests_per_origin,
        crate::ClientBuilder::max_pending_http2_requests_per_origin,
        crate::ClientBuilder::max_concurrent_http3_requests_per_origin,
        crate::ClientBuilder::max_pending_http3_requests_per_origin,
    ];
    let ceiling = nonzero(tokio::sync::Semaphore::MAX_PERMITS);
    let above = nonzero(tokio::sync::Semaphore::MAX_PERMITS + 1);
    for setter in setters {
        let error = setter(Client::builder(profile(chrome::v154_quic_tls())), above)
            .build()
            .err()
            .ok_or("an oversized admission bound was accepted")?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);

        setter(Client::builder(profile(chrome::v154_quic_tls())), ceiling).build()?;
    }
    Ok(())
}

#[test]
fn profile_http1_admission_bound_is_checked_after_a_client_override()
-> Result<(), Box<dyn std::error::Error>> {
    let mut http1 = chrome::v154_http1();
    http1.max_connections_per_origin = nonzero(tokio::sync::Semaphore::MAX_PERMITS + 1);
    let oversized_profile = profile(chrome::v154_quic_tls()).with_http1(http1);

    let error = Client::builder(oversized_profile.clone())
        .build()
        .err()
        .ok_or("an oversized profile admission bound was accepted")?;
    assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);

    let client = Client::builder(oversized_profile)
        .max_concurrent_http1_requests_per_origin(NonZeroUsize::MIN)
        .build()?;
    assert_eq!(client.state.http1.max_active(), NonZeroUsize::MIN);

    let mut http1 = chrome::v154_http1();
    http1.max_connections_per_origin = nonzero(tokio::sync::Semaphore::MAX_PERMITS);
    Client::builder(profile(chrome::v154_quic_tls()).with_http1(http1)).build()?;
    Ok(())
}
