use crate::{chromium, firefox};

#[test]
fn chromium_154_opens_six_http1_connections_per_origin() {
    // `g_max_sockets_per_group` for the normal pool,
    // `net/socket/client_socket_pool_manager.cc:54-58` at `154.0.8037.58`.
    assert_eq!(chromium::v154_http1().max_connections_per_origin.get(), 6);
}

#[test]
fn firefox_157_opens_six_http1_connections_per_origin() {
    // `network.http.max-persistent-connections-per-server`,
    // `modules/libpref/init/all.js:1153` at `FIREFOX_157_0_RELEASE`.
    assert_eq!(firefox::v157_http1().max_connections_per_origin.get(), 6);
}

#[test]
fn chromium_154_stops_reusing_a_connection_idle_300_seconds() {
    // `g_used_idle_socket_timeout_s`, `net/socket/client_socket_pool.cc:42`
    // at `154.0.8037.58`.
    assert_eq!(
        chromium::v154_http1().idle_timeout,
        crate::Http1IdleTimeout::CheckedOnRequest(std::time::Duration::from_secs(300))
    );
}

#[test]
fn firefox_157_keeps_an_idle_connection_until_the_server_closes_it() {
    // Firefox's 115-second `network.http.keep-alive.timeout` is not modeled.
    assert_eq!(
        firefox::v157_http1().idle_timeout,
        crate::Http1IdleTimeout::Unlimited
    );
}

#[test]
fn only_the_timer_variant_closes_connections_between_requests() {
    let limit = std::time::Duration::from_secs(5);
    assert_eq!(crate::Http1IdleTimeout::Unlimited.closed_on_timer(), None);
    assert_eq!(
        crate::Http1IdleTimeout::CheckedOnRequest(limit).closed_on_timer(),
        None
    );
    assert_eq!(
        crate::Http1IdleTimeout::ClosedOnTimer(limit).closed_on_timer(),
        Some(limit)
    );
}

#[test]
fn a_timer_idle_limit_is_valid_up_to_firefox_range() {
    let settings = |limit| crate::Http1Settings {
        idle_timeout: crate::Http1IdleTimeout::ClosedOnTimer(limit),
        ..firefox::v157_http1()
    };
    let most = std::time::Duration::from_secs(super::MAX_HTTP1_TIMER_IDLE_SECONDS);
    assert_eq!(settings(most).validate(), Ok(()));
    assert_eq!(settings(std::time::Duration::ZERO).validate(), Ok(()));
    let over = most + std::time::Duration::from_nanos(1);
    for limit in [over, std::time::Duration::MAX] {
        let error = settings(limit).validate().err();
        assert_eq!(error.map(|error| error.field()), Some("idle_timeout"));
    }
}

#[test]
fn the_browser_http1_settings_are_valid() {
    assert_eq!(chromium::v154_http1().validate(), Ok(()));
    assert_eq!(firefox::v157_http1().validate(), Ok(()));
}
