//! Stack budget for the futures that open connections.

use phantom_testkit::future_size::{SETUP_FUTURE_BUDGET, assert_within, future_size};

use crate::{
    http1::Http1TlsConnector, http1_or_2::Http1Or2TlsConnector, http2::Http2TlsConnector,
    http3::Http3Connector, proxy::HttpsProxyConnector,
};

/// Opening a connection awaits DNS, TCP or QUIC, proxy, TLS, and protocol
/// setup futures inline, and a debug build's poll frames grow with them;
/// see `phantom_testkit::future_size`.
///
/// Each route-taking operation includes all of its route variants. When
/// this fails, for
/// example after a toolchain upgrade, run it with `--nocapture` to see every
/// size, then pin a by-value wrapper's operation or box the largest cold
/// branch with `Box::pin`. Raise `SETUP_FUTURE_BUDGET` only with the
/// measurements that justify it.
#[test]
fn connection_setup_futures_stay_within_the_stack_budget() {
    type H1 = Http1TlsConnector;
    type H2 = Http2TlsConnector;
    type H12 = Http1Or2TlsConnector;
    type H3 = Http3Connector;

    let futures = vec![
        ("Http1TlsConnector::connect", future_size(&H1::connect)),
        ("Http1TlsConnector::send", future_size(&H1::send)),
        ("Http1TlsConnector::upgrade", future_size(&H1::upgrade)),
        ("Http2TlsConnector::connect", future_size(&H2::connect)),
        ("Http2TlsConnector::send", future_size(&H2::send)),
        (
            "Http2TlsConnector::extended_connect",
            future_size(&H2::extended_connect),
        ),
        ("Http1Or2TlsConnector::connect", future_size(&H12::connect)),
        ("Http3Connector::connect", future_size(&H3::connect)),
        ("Http3Connector::send", future_size(&H3::send)),
        (
            "http3::send_with_config",
            future_size(&crate::http3::send_with_config),
        ),
        (
            "HttpsProxyConnector::connect_forward_http2_with_credentials",
            future_size(&HttpsProxyConnector::connect_forward_http2_with_credentials),
        ),
        (
            "HttpsProxyConnector::connect_tunnel",
            future_size(&HttpsProxyConnector::connect_tunnel),
        ),
        (
            "HttpsProxyConnector::connect_tunnel_with_basic_auth",
            future_size(&HttpsProxyConnector::connect_tunnel_with_basic_auth),
        ),
        (
            "HttpsProxyConnector::connect_udp_tunnel",
            future_size(&HttpsProxyConnector::connect_udp_tunnel),
        ),
        (
            "proxy::http_connect_tunnel_with_basic_auth",
            future_size(&crate::proxy::http_connect_tunnel_with_basic_auth),
        ),
        (
            "proxy::socks5_tunnel_remote_dns",
            future_size(&crate::proxy::socks5_tunnel_remote_dns),
        ),
        (
            "proxy::socks5_tunnel_local_dns",
            future_size(&crate::proxy::socks5_tunnel_local_dns),
        ),
        (
            "proxy::associate_socks5_udp_remote_with_auth",
            future_size(&crate::proxy::associate_socks5_udp_remote_with_auth),
        ),
        (
            "proxy::associate_socks5_udp_local_with_auth",
            future_size(&crate::proxy::associate_socks5_udp_local_with_auth),
        ),
    ];
    assert_within(SETUP_FUTURE_BUDGET, &futures);
}
