use std::{num::NonZeroUsize, time::Duration};

use phantom_profile::{ClientProfile, Http3ClientSettings, browser::chrome};

use crate::{
    AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, Client, RedirectPolicy, RequestTimeouts,
    RetryPolicy, session::ClientOptions,
};

/// A profile with negotiated HTTP/1.1+HTTP/2 and HTTP/3.
fn profile() -> ClientProfile {
    ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            chrome::v154_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            chrome::v154_http3_request(),
        ))
}

fn nonzero(value: usize) -> NonZeroUsize {
    NonZeroUsize::new(value).unwrap_or(NonZeroUsize::MIN)
}

/// Every per-client option has a [`ClientBuilder`](crate::ClientBuilder)
/// setter that writes it.
///
/// The pattern names every [`ClientOptions`] field, so a new option does not
/// compile here until its setter is called below.
#[test]
fn client_builder_sets_every_client_option() {
    let builder = Client::builder(profile())
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
        .max_http3_connections_per_origin(nonzero(2))
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
        max_http3_connections_per_origin,
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
    assert_ne!(
        max_http3_connections_per_origin,
        defaults.max_http3_connections_per_origin
    );
    assert_ne!(max_client_hint_origins, defaults.max_client_hint_origins);
    assert_ne!(max_alt_svc_origins, defaults.max_alt_svc_origins);
    assert_ne!(alt_svc_policy, defaults.alt_svc_policy);
    assert_ne!(http3_early_data, defaults.http3_early_data);
    #[cfg(feature = "https-records")]
    assert!(https_record_resolver.is_some() && defaults.https_record_resolver.is_none());
    #[cfg(feature = "cookies")]
    assert!(cookie_jar.is_some() && defaults.cookie_jar.is_none());
}
