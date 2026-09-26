//! Stack budget for the futures that open connections.

use phantom_testkit::future_size::{SETUP_FUTURE_BUDGET, assert_within, future_size};
use tokio::net::TcpStream;

use crate::{
    http1::Http1TlsConnector, http1_or_2::Http1Or2TlsConnector, http2::Http2TlsConnector,
    http3::Http3Connector, proxy::HttpsProxyConnector,
};

/// Opening a connection awaits DNS, TCP or QUIC, proxy, TLS, and protocol
/// setup futures inline, and a debug build's poll frames grow with them;
/// see `phantom_testkit::future_size`.
///
/// With all features, the largest, `Http3Connector::connect_connect_udp`, is
/// 8,992 bytes on Windows (x86-64, Rust 1.98.1), the only platform
/// measured. When this fails, for
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

    #[cfg_attr(not(feature = "https-records"), allow(unused_mut))]
    let mut futures = vec![
        (
            "Http1TlsConnector::connect",
            future_size(&H1::connect::<TcpStream>),
        ),
        (
            "Http1TlsConnector::connect_direct",
            future_size(&H1::connect_direct),
        ),
        (
            "Http1TlsConnector::connect_plaintext_direct",
            future_size(&H1::connect_plaintext_direct),
        ),
        (
            "Http1TlsConnector::connect_forward_proxy",
            future_size(&H1::connect_forward_proxy),
        ),
        (
            "Http1TlsConnector::connect_https_forward_proxy",
            future_size(&H1::connect_https_forward_proxy),
        ),
        (
            "Http1TlsConnector::connect_http_connect",
            future_size(&H1::connect_http_connect),
        ),
        (
            "Http1TlsConnector::connect_http_connect_with_basic_auth",
            future_size(&H1::connect_http_connect_with_basic_auth),
        ),
        (
            "Http1TlsConnector::connect_https_connect",
            future_size(&H1::connect_https_connect),
        ),
        (
            "Http1TlsConnector::connect_https_connect_with_basic_auth",
            future_size(&H1::connect_https_connect_with_basic_auth),
        ),
        (
            "Http1TlsConnector::connect_socks5_remote_with_auth",
            future_size(&H1::connect_socks5_remote_with_auth),
        ),
        (
            "Http1TlsConnector::connect_socks5_local_with_auth",
            future_size(&H1::connect_socks5_local_with_auth),
        ),
        (
            "Http1TlsConnector::connect_plaintext_socks5_remote_with_auth",
            future_size(&H1::connect_plaintext_socks5_remote_with_auth),
        ),
        (
            "Http1TlsConnector::connect_plaintext_socks5_local_with_auth",
            future_size(&H1::connect_plaintext_socks5_local_with_auth),
        ),
        (
            "Http1TlsConnector::upgrade_get_https_connect_with_basic_auth",
            future_size(&H1::upgrade_get_https_connect_with_basic_auth),
        ),
        (
            "Http1TlsConnector::send_request_https_connect_with_basic_auth",
            future_size(&H1::send_request_https_connect_with_basic_auth),
        ),
        (
            "Http2TlsConnector::connect",
            future_size(&H2::connect::<TcpStream>),
        ),
        (
            "Http2TlsConnector::connect_direct",
            future_size(&H2::connect_direct),
        ),
        (
            "Http2TlsConnector::connect_http_connect",
            future_size(&H2::connect_http_connect),
        ),
        (
            "Http2TlsConnector::connect_http_connect_with_basic_auth",
            future_size(&H2::connect_http_connect_with_basic_auth),
        ),
        (
            "Http2TlsConnector::connect_https_connect",
            future_size(&H2::connect_https_connect),
        ),
        (
            "Http2TlsConnector::connect_https_connect_with_basic_auth",
            future_size(&H2::connect_https_connect_with_basic_auth),
        ),
        (
            "Http2TlsConnector::connect_socks5_remote_with_auth",
            future_size(&H2::connect_socks5_remote_with_auth),
        ),
        (
            "Http2TlsConnector::connect_socks5_local_with_auth",
            future_size(&H2::connect_socks5_local_with_auth),
        ),
        (
            "Http2TlsConnector::send_extended_connect_direct",
            future_size(&H2::send_extended_connect_direct),
        ),
        (
            "Http2TlsConnector::send_extended_connect_https_connect_with_basic_auth",
            future_size(&H2::send_extended_connect_https_connect_with_basic_auth),
        ),
        (
            "Http2TlsConnector::send_request_https_connect_with_basic_auth",
            future_size(&H2::send_request_https_connect_with_basic_auth),
        ),
        (
            "Http1Or2TlsConnector::connect",
            future_size(&H12::connect::<TcpStream>),
        ),
        (
            "Http1Or2TlsConnector::connect_direct",
            future_size(&H12::connect_direct),
        ),
        (
            "Http1Or2TlsConnector::connect_http_connect",
            future_size(&H12::connect_http_connect),
        ),
        (
            "Http1Or2TlsConnector::connect_http_connect_with_basic_auth",
            future_size(&H12::connect_http_connect_with_basic_auth),
        ),
        (
            "Http1Or2TlsConnector::connect_https_connect",
            future_size(&H12::connect_https_connect),
        ),
        (
            "Http1Or2TlsConnector::connect_https_connect_with_basic_auth",
            future_size(&H12::connect_https_connect_with_basic_auth),
        ),
        (
            "Http1Or2TlsConnector::connect_socks5_remote_with_auth",
            future_size(&H12::connect_socks5_remote_with_auth),
        ),
        (
            "Http1Or2TlsConnector::connect_socks5_local_with_auth",
            future_size(&H12::connect_socks5_local_with_auth),
        ),
        (
            "Http3Connector::connect_direct",
            future_size(&H3::connect_direct),
        ),
        (
            "Http3Connector::connect_socks5_remote_with_auth",
            future_size(&H3::connect_socks5_remote_with_auth),
        ),
        (
            "Http3Connector::connect_socks5_local_with_auth",
            future_size(&H3::connect_socks5_local_with_auth),
        ),
        (
            "Http3Connector::connect_connect_udp",
            future_size(&H3::connect_connect_udp),
        ),
        (
            "Http3Connector::connect_connect_udp_with_basic_auth",
            future_size(&H3::connect_connect_udp_with_basic_auth),
        ),
        (
            "Http3Connector::connect_connect_udp_over_tcp",
            future_size(&H3::connect_connect_udp_over_tcp),
        ),
        (
            "Http3Connector::send_request_direct",
            future_size(&H3::send_request_direct),
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
            "proxy::connect_http_tunnel_direct_with_basic_auth",
            future_size(&crate::proxy::connect_http_tunnel_direct_with_basic_auth),
        ),
        (
            "proxy::connect_socks5_tunnel_direct_with_auth",
            future_size(&crate::proxy::connect_socks5_tunnel_direct_with_auth),
        ),
        (
            "proxy::connect_socks5_tunnel_local_with_auth",
            future_size(&crate::proxy::connect_socks5_tunnel_local_with_auth),
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
    #[cfg(feature = "https-records")]
    futures.extend(ech::futures());
    assert_within(SETUP_FUTURE_BUDGET, &futures);
}

/// The ECH entry points take the HTTPS record lookup as an `impl Future`,
/// so each is measured through a wrapper with a ready lookup. The caller's
/// lookup future adds its own size on top.
#[cfg(feature = "https-records")]
mod ech {
    use std::future::{Future, Ready, ready};

    use phantom_testkit::future_size::future_size;

    use super::{Http1Or2TlsConnector, Http1TlsConnector, Http2TlsConnector, Http3Connector};
    use crate::{
        dns::EchConfigList,
        http2::{OriginForm, RequestHeader},
    };

    fn no_ech() -> Ready<Option<EchConfigList>> {
        ready(None)
    }

    fn http1<'a>(connector: &'a Http1TlsConnector, host: &'a str) -> impl Future + 'a {
        connector.connect_direct_with_ech(host, 443, host, no_ech())
    }

    fn http2<'a>(connector: &'a Http2TlsConnector, host: &'a str) -> impl Future + 'a {
        connector.connect_direct_with_ech(host, 443, host, no_ech())
    }

    fn http2_extended<'a>(
        connector: &'a Http2TlsConnector,
        host: &'a str,
        target: OriginForm,
        headers: Vec<RequestHeader>,
    ) -> impl Future + 'a {
        connector.send_extended_connect_direct_with_ech(
            host,
            443,
            host,
            host,
            target,
            headers,
            no_ech(),
        )
    }

    fn http1_or_2<'a>(connector: &'a Http1Or2TlsConnector, host: &'a str) -> impl Future + 'a {
        connector.connect_direct_with_ech(host, 443, host, no_ech())
    }

    fn http3<'a>(connector: &'a Http3Connector, host: &'a str) -> impl Future + 'a {
        connector.connect_direct_with_ech(host, 443, host, no_ech())
    }

    pub(super) fn futures() -> [(&'static str, usize); 5] {
        [
            (
                "Http1TlsConnector::connect_direct_with_ech",
                future_size(&http1),
            ),
            (
                "Http2TlsConnector::connect_direct_with_ech",
                future_size(&http2),
            ),
            (
                "Http2TlsConnector::send_extended_connect_direct_with_ech",
                future_size(&http2_extended),
            ),
            (
                "Http1Or2TlsConnector::connect_direct_with_ech",
                future_size(&http1_or_2),
            ),
            (
                "Http3Connector::connect_direct_with_ech",
                future_size(&http3),
            ),
        ]
    }
}
