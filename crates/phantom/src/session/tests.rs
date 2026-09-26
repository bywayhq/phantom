use std::{num::NonZeroUsize, time::Duration};

use phantom_profile::{ClientProfile, Http3ClientSettings, TlsSettings, chromium};

use super::{ClientOptions, SessionBuilder};
use crate::{
    AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, BuildErrorKind, Client, RedirectPolicy,
    RequestBuilder, RequestTimeouts, ResponseBody, RetryPolicy,
};

fn assert_send_sync_clone<T: Send + Sync + Clone>() {}
fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn client_handles_are_send_sync_and_clone() {
    assert_send_sync_clone::<Client>();
    fn assert_send<T: Send>() {}
    assert_send::<SessionBuilder>();
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

/// Every per-client option can be set on a session.
///
/// The pattern names every [`ClientOptions`] field, so a new option does not
/// compile here until its setter is called on a [`SessionBuilder`] below.
/// The setters come from `client_option_setters!`, which also defines them on
/// [`ClientBuilder`](crate::ClientBuilder).
#[test]
fn session_builder_sets_every_client_option() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder(profile(chromium::v154_http3_tls())).build()?;
    let builder = client
        .session_builder()
        .redirect_policy(RedirectPolicy::limited(nonzero(3)))
        .retry_policy(RetryPolicy::connection_failures(
            nonzero(2),
            Duration::from_millis(1),
        ))
        .request_timeouts(RequestTimeouts::new().total(Duration::from_secs(1)))
        .max_retained_http1_connections(nonzero(2))
        .max_concurrent_http1_requests_per_origin(nonzero(3))
        .max_pending_http1_requests_per_origin(nonzero(4))
        .max_retained_http2_connections(nonzero(5))
        .max_concurrent_http2_requests_per_origin(nonzero(6))
        .max_pending_http2_requests_per_origin(nonzero(7))
        .max_http2_connections_per_origin(nonzero(8))
        .negotiated_setup_wait_limit(Duration::from_millis(300))
        .max_retained_http3_connections(nonzero(9))
        .max_concurrent_http3_requests_per_origin(nonzero(10))
        .max_pending_http3_requests_per_origin(nonzero(11))
        .max_client_hint_origins(nonzero(12))
        .alt_svc(nonzero(13))
        .alt_svc_policy(AltSvcPolicy::race(AltSvcRace::new(
            Duration::from_millis(300),
            AltSvcBrokenBackoff::CHROMIUM_153,
        )))
        .http3_early_data(false);
    #[cfg(feature = "https-records")]
    let builder =
        builder.https_record_discovery(crate::dns::HttpsRecordResolver::from_fn(|_, _| async {
            Ok(crate::dns::HttpsRecordLookup::new(Vec::new(), None))
        }));
    #[cfg(feature = "cookies")]
    let builder = builder.cookies();
    let debug = format!("{builder:?}");
    assert!(debug.contains("http3_early_data: Some(false)"), "{debug}");

    let defaults = ClientOptions::default();
    let ClientOptions {
        redirect_policy,
        retry_policy,
        request_timeouts,
        max_retained_http1_connections,
        max_concurrent_http1_requests_per_origin,
        max_pending_http1_requests_per_origin,
        max_retained_http2_connections,
        max_concurrent_http2_requests_per_origin,
        max_pending_http2_requests_per_origin,
        max_http2_connections_per_origin,
        negotiated_setup_wait_limit,
        max_retained_http3_connections,
        max_concurrent_http3_requests_per_origin,
        max_pending_http3_requests_per_origin,
        max_client_hint_origins,
        max_alt_svc_origins,
        alt_svc_policy,
        http3_early_data,
        #[cfg(feature = "https-records")]
        https_record_resolver,
        #[cfg(feature = "cookies")]
        cookie_jar,
    } = builder.options;
    assert_ne!(redirect_policy, defaults.redirect_policy);
    assert_ne!(retry_policy, defaults.retry_policy);
    assert_ne!(request_timeouts, defaults.request_timeouts);
    assert_ne!(
        max_retained_http1_connections,
        defaults.max_retained_http1_connections
    );
    assert_ne!(
        max_concurrent_http1_requests_per_origin,
        defaults.max_concurrent_http1_requests_per_origin
    );
    assert_ne!(
        max_pending_http1_requests_per_origin,
        defaults.max_pending_http1_requests_per_origin
    );
    assert_ne!(
        max_retained_http2_connections,
        defaults.max_retained_http2_connections
    );
    assert_ne!(
        max_concurrent_http2_requests_per_origin,
        defaults.max_concurrent_http2_requests_per_origin
    );
    assert_ne!(
        max_pending_http2_requests_per_origin,
        defaults.max_pending_http2_requests_per_origin
    );
    assert_ne!(
        max_http2_connections_per_origin,
        defaults.max_http2_connections_per_origin
    );
    assert_ne!(
        negotiated_setup_wait_limit,
        defaults.negotiated_setup_wait_limit
    );
    assert_ne!(
        max_retained_http3_connections,
        defaults.max_retained_http3_connections
    );
    assert_ne!(
        max_concurrent_http3_requests_per_origin,
        defaults.max_concurrent_http3_requests_per_origin
    );
    assert_ne!(
        max_pending_http3_requests_per_origin,
        defaults.max_pending_http3_requests_per_origin
    );
    assert_ne!(max_client_hint_origins, defaults.max_client_hint_origins);
    assert_ne!(max_alt_svc_origins, defaults.max_alt_svc_origins);
    assert_ne!(alt_svc_policy, defaults.alt_svc_policy);
    assert_ne!(http3_early_data, defaults.http3_early_data);
    #[cfg(feature = "https-records")]
    assert!(https_record_resolver.is_some() && defaults.https_record_resolver.is_none());
    #[cfg(feature = "cookies")]
    assert!(cookie_jar.is_some() && defaults.cookie_jar.is_none());
    Ok(())
}

#[test]
fn session_applies_its_options() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::builder(profile(chromium::v154_http3_tls())).build()?;
    let timeouts = RequestTimeouts::new().total(Duration::from_secs(5));
    let retry = RetryPolicy::connection_failures(nonzero(2), Duration::from_millis(1));
    let session = client
        .session_builder()
        .request_timeouts(timeouts)
        .retry_policy(retry)
        .max_http2_connections_per_origin(nonzero(3))
        .build()?;

    assert_eq!(session.request_timeouts(), timeouts);
    assert_eq!(session.retry_policy(), retry);
    assert_eq!(session.state.http2.max_connections(), nonzero(3));
    assert_eq!(client.request_timeouts(), RequestTimeouts::new());
    Ok(())
}

#[test]
fn session_early_data_choice_replaces_the_clients() -> Result<(), Box<dyn std::error::Error>> {
    let sends_early_data = |client: &Client| {
        client
            .inner
            .http3
            .as_ref()
            .is_some_and(|connector| connector.sends_early_data())
    };
    // The Chrome 154 QUIC recipe offers early data.
    let client = Client::builder(profile(chromium::v154_http3_tls())).build()?;
    assert!(sends_early_data(&client));

    let without = client.session_builder().http3_early_data(false).build()?;
    assert!(!sends_early_data(&without));
    assert!(sends_early_data(&client));
    assert!(sends_early_data(&client.session_builder().build()?));

    let client = Client::builder(profile(chromium::v154_http3_tls()))
        .http3_early_data(false)
        .build()?;
    assert!(!sends_early_data(&client.session_builder().build()?));
    let with = client.session_builder().http3_early_data(true).build()?;
    assert!(sends_early_data(&with));
    Ok(())
}

#[test]
fn session_build_rejects_what_client_build_rejects() -> Result<(), Box<dyn std::error::Error>> {
    let mut without_tickets = chromium::v154_http3_tls();
    without_tickets.session_tickets = false;
    let client = Client::builder(profile(without_tickets)).build()?;
    let rejected = [
        (
            "an unrepresentable timeout",
            client
                .session_builder()
                .request_timeouts(RequestTimeouts::new().total(Duration::MAX)),
        ),
        (
            "an unrepresentable retry delay",
            client
                .session_builder()
                .retry_policy(RetryPolicy::connection_failures(
                    NonZeroUsize::MIN,
                    Duration::MAX,
                )),
        ),
        (
            "early data without session tickets",
            client.session_builder().http3_early_data(true),
        ),
        (
            "an Alt-Svc race without a store",
            client
                .session_builder()
                .alt_svc_policy(AltSvcPolicy::race(AltSvcRace::new(
                    Duration::from_millis(300),
                    AltSvcBrokenBackoff::CHROMIUM_153,
                ))),
        ),
    ];
    for (case, builder) in rejected {
        let error = builder
            .build()
            .err()
            .ok_or_else(|| format!("a session with {case} was built"))?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy, "{case}");
    }
    Ok(())
}
