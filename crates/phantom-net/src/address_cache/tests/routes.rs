//! Which names each connector resolves through its host resolver and cache.
//!
//! Every name resolves to a loopback peer that accepts and immediately
//! closes, so the step after the TCP connect fails; QUIC attempts are cut
//! short by a timeout. A fresh cache per path records the names it was asked
//! to resolve.

use std::time::Duration;

use phantom_profile::{Http3PseudoHeader, chromium};
use tokio::{net::TcpListener, task::JoinHandle};

use super::{Recorder, TestResult, V4, long_lived};
use crate::{
    address_cache::AddressCache,
    host_resolver::HostResolver,
    http1::Http1TlsConnector,
    http1_or_2::Http1Or2TlsConnector,
    http2::Http2TlsConnector,
    http3::{Http3Connector, OriginForm},
    proxy::{HttpConnectHeader, HttpsProxyConnector, HttpsProxyProtocol, Socks5Auth},
};

const ORIGIN: &str = "origin.phantom.test";
const PROXY: &str = "proxy.phantom.test";
const AUTHORITY: &str = "origin.phantom.test:443";
const QUIC_WAIT: Duration = Duration::from_millis(300);

struct ClosingPeer {
    port: u16,
    task: JoinHandle<()>,
}

impl ClosingPeer {
    async fn bind() -> TestResult<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });
        Ok(Self { port, task })
    }
}

impl Drop for ClosingPeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn recording_cache() -> (Recorder, HostResolver) {
    let recorder = Recorder::open();
    let cache = recorder.cache(long_lived(), super::answer(&[V4]));
    (recorder, HostResolver::new().with_address_cache(cache))
}

fn names(recorder: &Recorder) -> Vec<String> {
    recorder.names().iter().map(ToString::to_string).collect()
}

fn http3() -> TestResult<Http3Connector> {
    Ok(Http3Connector::new(
        &chromium::v154_http3_tls(),
        &chromium::v154_quic(),
        &chromium::v154_http3(),
        &chromium::v154_http3_request(),
    )?)
}

#[tokio::test(flavor = "current_thread")]
async fn http1_resolves_origins_proxies_and_local_socks5_targets_only() -> TestResult {
    let peer = ClosingPeer::bind().await?;
    let connect_headers = [HttpConnectHeader::authority("Host")];
    let connector = || -> TestResult<(Recorder, Http1TlsConnector)> {
        let (recorder, cache) = recording_cache();
        let connector =
            Http1TlsConnector::new(&chromium::v154_tls())?.with_host_resolver(cache.clone());
        assert_eq!(
            connector
                .host_resolver()
                .and_then(HostResolver::cache)
                .map(AddressCache::len),
            Some(0)
        );
        Ok((recorder, connector))
    };

    let (recorder, http1) = connector()?;
    let _ = http1
        .connect_via(
            crate::route::TcpRoute::Direct(crate::route::Endpoint {
                host: ORIGIN,
                port: peer.port,
            }),
            ORIGIN,
        )
        .await;
    assert_eq!(names(&recorder), [ORIGIN], "direct TLS");

    let (recorder, http1) = connector()?;
    let _ = http1.connect_plaintext_direct(ORIGIN, peer.port).await;
    assert_eq!(names(&recorder), [ORIGIN], "direct plaintext");

    let (recorder, http1) = connector()?;
    let _ = http1.connect_forward_proxy(PROXY, peer.port).await;
    assert_eq!(names(&recorder), [PROXY], "forward proxy");

    let (recorder, http1) = connector()?;
    let _ = http1
        .connect_via(
            crate::route::TcpRoute::HttpConnect(crate::route::HttpConnectRoute {
                proxy: crate::route::ProxyTransport::Tcp(crate::route::Endpoint {
                    host: PROXY,
                    port: peer.port,
                }),
                authority: AUTHORITY,
                headers: &connect_headers,
                credentials: None,
            }),
            ORIGIN,
        )
        .await;
    assert_eq!(names(&recorder), [PROXY], "HTTP CONNECT");

    let (recorder, http1) = connector()?;
    let _ = http1
        .connect_via(
            crate::route::TcpRoute::Socks5 {
                proxy: crate::route::Endpoint {
                    host: PROXY,
                    port: peer.port,
                },
                target: crate::route::Socks5Target::RemoteDns(crate::route::Endpoint {
                    host: ORIGIN,
                    port: 443,
                }),
                auth: crate::proxy::Socks5Auth::None,
            },
            ORIGIN,
        )
        .await;
    assert_eq!(names(&recorder), [PROXY], "SOCKS5 remote DNS");

    let (recorder, http1) = connector()?;
    let _ = http1
        .connect_via(
            crate::route::TcpRoute::Socks5 {
                proxy: crate::route::Endpoint {
                    host: PROXY,
                    port: peer.port,
                },
                target: crate::route::Socks5Target::LocalDns(crate::route::Endpoint {
                    host: ORIGIN,
                    port: 443,
                }),
                auth: crate::proxy::Socks5Auth::None,
            },
            ORIGIN,
        )
        .await;
    assert_eq!(names(&recorder), [ORIGIN, PROXY], "SOCKS5 local DNS");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn http2_and_negotiated_connectors_resolve_through_the_cache() -> TestResult {
    let peer = ClosingPeer::bind().await?;
    let (recorder, cache) = recording_cache();
    let http2 = Http2TlsConnector::new(&chromium::v154_tls(), &chromium::v154_http2())?
        .with_host_resolver(cache);

    let _ = http2
        .connect_via(
            crate::route::TcpRoute::Direct(crate::route::Endpoint {
                host: ORIGIN,
                port: peer.port,
            }),
            ORIGIN,
        )
        .await;
    let _ = http2
        .connect_via(
            crate::route::TcpRoute::Socks5 {
                proxy: crate::route::Endpoint {
                    host: PROXY,
                    port: peer.port,
                },
                target: crate::route::Socks5Target::RemoteDns(crate::route::Endpoint {
                    host: ORIGIN,
                    port: 443,
                }),
                auth: Socks5Auth::None,
            },
            ORIGIN,
        )
        .await;
    let negotiated = Http1Or2TlsConnector::from_http2(&http2)?;
    let _ = negotiated
        .connect_via(
            crate::route::TcpRoute::Direct(crate::route::Endpoint {
                host: ORIGIN,
                port: peer.port,
            }),
            ORIGIN,
        )
        .await;

    assert_eq!(names(&recorder), [ORIGIN, PROXY], "each name resolved once");
    assert!(negotiated.host_resolver().is_some());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn https_proxy_host_resolves_through_the_proxy_connector() -> TestResult {
    let peer = ClosingPeer::bind().await?;
    let (origin_recorder, origin_cache) = recording_cache();
    let (proxy_recorder, proxy_cache) = recording_cache();
    let origin = Http1TlsConnector::new(&chromium::v154_tls())?.with_host_resolver(origin_cache);
    let proxy = HttpsProxyConnector::new(&chromium::v154_tls())?.with_host_resolver(proxy_cache);
    let connect_headers = [HttpConnectHeader::authority("Host")];

    let _ = origin
        .connect_via(
            crate::route::TcpRoute::HttpConnect(crate::route::HttpConnectRoute {
                proxy: crate::route::ProxyTransport::Tls {
                    endpoint: crate::route::Endpoint {
                        host: PROXY,
                        port: peer.port,
                    },
                    server_name: PROXY,
                    connector: &proxy,
                },
                authority: AUTHORITY,
                headers: &connect_headers,
                credentials: None,
            }),
            ORIGIN,
        )
        .await;

    assert_eq!(names(&proxy_recorder), [PROXY]);
    assert!(names(&origin_recorder).is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn http3_resolves_origins_proxies_and_local_socks5_targets_only() -> TestResult {
    let peer = ClosingPeer::bind().await?;
    let connector = || -> TestResult<(Recorder, Http3Connector)> {
        let (recorder, cache) = recording_cache();
        Ok((recorder, http3()?.with_host_resolver(cache)))
    };

    let (recorder, h3) = connector()?;
    let _ = tokio::time::timeout(
        QUIC_WAIT,
        h3.connect(
            crate::route::DatagramRoute::Direct(crate::route::Endpoint {
                host: ORIGIN,
                port: peer.port,
            }),
            ORIGIN,
        ),
    )
    .await;
    assert_eq!(names(&recorder), [ORIGIN], "direct QUIC");

    let (recorder, h3) = connector()?;
    let _ = tokio::time::timeout(
        QUIC_WAIT,
        h3.connect(
            crate::route::DatagramRoute::Socks5 {
                proxy: crate::route::Endpoint {
                    host: PROXY,
                    port: peer.port,
                },
                target: crate::route::Socks5Target::RemoteDns(crate::route::Endpoint {
                    host: ORIGIN,
                    port: 443,
                }),
                auth: crate::proxy::Socks5Auth::None,
            },
            ORIGIN,
        ),
    )
    .await;
    assert_eq!(names(&recorder), [PROXY], "SOCKS5 UDP remote DNS");

    let (recorder, h3) = connector()?;
    let _ = tokio::time::timeout(
        QUIC_WAIT,
        h3.connect(
            crate::route::DatagramRoute::Socks5 {
                proxy: crate::route::Endpoint {
                    host: PROXY,
                    port: peer.port,
                },
                target: crate::route::Socks5Target::LocalDns(crate::route::Endpoint {
                    host: ORIGIN,
                    port: 443,
                }),
                auth: crate::proxy::Socks5Auth::None,
            },
            ORIGIN,
        ),
    )
    .await;
    assert_eq!(names(&recorder), [ORIGIN, PROXY], "SOCKS5 UDP local DNS");
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn connect_udp_over_tcp_resolves_only_the_proxy() -> TestResult {
    let peer = ClosingPeer::bind().await?;
    let (target_recorder, target_cache) = recording_cache();
    let (proxy_recorder, proxy_cache) = recording_cache();
    let h3 = http3()?.with_host_resolver(target_cache);
    let proxy = HttpsProxyConnector::new(&chromium::v154_tls())?.with_host_resolver(proxy_cache);
    let authority = format!("{PROXY}:{}", peer.port);

    let _ = tokio::time::timeout(
        QUIC_WAIT,
        h3.connect(
            crate::route::DatagramRoute::ConnectUdp(crate::route::ConnectUdpRoute {
                proxy: crate::route::Endpoint {
                    host: PROXY,
                    port: peer.port,
                },
                transport: crate::route::ConnectUdpTransport::Tls {
                    connector: &proxy,
                    protocol: HttpsProxyProtocol::Http1,
                },
                authority: &authority,
                path: OriginForm::parse("/.well-known/masque/udp/origin.phantom.test/443/")?,
                headers: Vec::new(),
                credentials: None,
            }),
            ORIGIN,
        ),
    )
    .await;

    assert_eq!(names(&proxy_recorder), [PROXY]);
    assert!(names(&target_recorder).is_empty());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn connect_udp_over_http3_resolves_only_the_proxy() -> TestResult {
    let (recorder, cache) = recording_cache();
    let h3 = http3()?.with_host_resolver(cache);
    let mut request = chromium::v154_http3_request();
    request.extended_connect_pseudo_header_order = Some(vec![
        Http3PseudoHeader::Method,
        Http3PseudoHeader::Protocol,
        Http3PseudoHeader::Scheme,
        Http3PseudoHeader::Authority,
        Http3PseudoHeader::Path,
    ]);
    let proxy = Http3Connector::new(
        &chromium::v154_http3_tls(),
        &chromium::v154_quic(),
        &chromium::v154_http3(),
        &request,
    )?;
    // Nothing listens on this UDP port, so the outer QUIC connection never
    // completes; the name lookup precedes it.
    let port = phantom_testkit::udp::bind("127.0.0.1:0".parse()?)?
        .local_addr()?
        .port();
    let authority = format!("{PROXY}:{port}");

    let _ = tokio::time::timeout(
        QUIC_WAIT,
        h3.connect(
            crate::route::DatagramRoute::ConnectUdp(crate::route::ConnectUdpRoute {
                proxy: crate::route::Endpoint {
                    host: PROXY,
                    port: port,
                },
                transport: crate::route::ConnectUdpTransport::Http3(&proxy),
                authority: &authority,
                path: OriginForm::parse("/.well-known/masque/udp/origin.phantom.test/443/")?,
                headers: Vec::new(),
                credentials: None,
            }),
            ORIGIN,
        ),
    )
    .await;

    assert_eq!(names(&recorder), [PROXY]);
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn clones_for_isolated_tls_sessions_keep_the_cache() -> TestResult {
    let (_, cache) = recording_cache();
    let http1 = Http1TlsConnector::new(&chromium::v154_tls())?.with_host_resolver(cache.clone());
    let http3 = http3()?.with_host_resolver(cache);

    assert!(
        http1
            .with_isolated_session_cache()
            .host_resolver()
            .is_some()
    );
    assert!(
        http3
            .with_isolated_session_cache()
            .host_resolver()
            .is_some()
    );
    assert!(http3.with_early_data().host_resolver().is_some());
    Ok(())
}
