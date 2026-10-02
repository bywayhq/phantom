use std::{num::NonZeroUsize, time::Duration};

use phantom_profile::{ClientProfile, Http3ClientSettings, TlsSettings, chromium};

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
    ClientProfile::new(chromium::v154_tls())
        .with_http2(chromium::v154_http2())
        .with_http3(Http3ClientSettings::new(
            http3_tls,
            chromium::v154_quic(),
            chromium::v154_http3(),
            chromium::v154_http3_request(),
        ))
}

fn nonzero(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap_or(NonZeroUsize::MIN)
}

#[test]
fn client_applies_its_options() -> Result<(), Box<dyn std::error::Error>> {
    let timeouts = RequestTimeouts::new().total(Duration::from_secs(5));
    let retry = RetryPolicy::connection_failures(nonzero(2), Duration::from_millis(1));
    let client = Client::builder(profile(chromium::v154_http3_tls()))
        .request_timeouts(timeouts)
        .retry_policy(retry)
        .max_http2_connections_per_origin(nonzero(3))
        .max_http3_connections_per_origin(nonzero(4))
        .build()?;
    let defaults = Client::builder(profile(chromium::v154_http3_tls())).build()?;

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
    let builder = || Client::builder(profile(chromium::v154_http3_tls()));
    assert!(sends_early_data(&builder().build()?));
    assert!(!sends_early_data(
        &builder().http3_early_data(false).build()?
    ));
    assert!(sends_early_data(&builder().http3_early_data(true).build()?));

    let mut quic = chromium::v154_quic();
    quic.early_data = false;
    let without_recipe_early_data = || {
        Client::builder(
            ClientProfile::new(chromium::v154_tls())
                .with_http2(chromium::v154_http2())
                .with_http3(Http3ClientSettings::new(
                    chromium::v154_http3_tls(),
                    quic.clone(),
                    chromium::v154_http3(),
                    chromium::v154_http3_request(),
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
    Client::builder(profile(chromium::v154_http3_tls()))
        .max_http3_connections_per_origin(nonzero(super::HTTP3_CONNECTIONS_PER_ORIGIN_CEILING))
        .build()?;

    let mut without_tickets = chromium::v154_http3_tls();
    without_tickets.session_tickets = false;
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
