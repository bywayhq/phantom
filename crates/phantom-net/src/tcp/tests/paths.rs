//! Every connector's TCP connect path applies its profile socket options.
//!
//! Each peer accepts and immediately closes, so the protocol step after the
//! TCP connect fails; the sockets are read back when they connect.

use phantom_profile::{TcpSettings, chromium};
use tokio::{net::TcpListener, task::JoinHandle};

use super::{TestResult, chromium_like, sets_random_port};
use crate::{
    http1::Http1TlsConnector,
    http1_or_2::Http1Or2TlsConnector,
    http2::Http2TlsConnector,
    http3::Http3Connector,
    proxy::{HttpBasicCredentials, HttpConnectHeader, HttpsProxyConnector, Socks5Auth},
    tcp::observed::{self, ObservedSocket},
};

const SERVER_NAME: &str = "server.phantom.test";
const AUTHORITY: &str = "server.phantom.test:443";

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

fn assert_profiled(path: &str, sockets: &[ObservedSocket]) {
    assert!(!sockets.is_empty(), "{path} opened no TCP connection");
    for socket in sockets {
        assert_eq!(
            *socket,
            ObservedSocket {
                nodelay: true,
                keepalive: true,
                random_port: sets_random_port(&chromium_like()),
            },
            "{path}"
        );
    }
}

fn http1(settings: &TcpSettings) -> TestResult<Http1TlsConnector> {
    Ok(Http1TlsConnector::new(&chromium::v154_tls())?.with_tcp_settings(settings))
}

fn http2(settings: &TcpSettings) -> TestResult<Http2TlsConnector> {
    Ok(
        Http2TlsConnector::new(&chromium::v154_tls(), &chromium::v154_http2())?
            .with_tcp_settings(settings),
    )
}

fn https_proxy(settings: &TcpSettings) -> TestResult<HttpsProxyConnector> {
    Ok(HttpsProxyConnector::new(&chromium::v154_tls())?.with_tcp_settings(settings))
}

fn http3(settings: &TcpSettings) -> TestResult<Http3Connector> {
    Ok(Http3Connector::new(
        &chromium::v154_http3_tls(),
        &chromium::v154_quic(),
        &chromium::v154_http3(),
        &chromium::v154_http3_request(),
    )?
    .with_tcp_settings(settings))
}

#[tokio::test(flavor = "current_thread")]
async fn connectors_without_tcp_settings_keep_os_defaults() -> TestResult {
    let peer = ClosingPeer::bind().await?;
    observed::take();

    let connector = Http1TlsConnector::new(&chromium::v154_tls())?;
    let _ = connector
        .connect(crate::route::Http1Route::Origin(
            crate::route::OriginRoute::Tls {
                tcp: crate::route::TcpRoute::Direct(crate::route::Endpoint {
                    host: "127.0.0.1",
                    port: peer.port,
                }),
                server_name: SERVER_NAME,
                setup: crate::route::DirectTlsSetup::Default,
            },
        ))
        .await;

    let sockets = observed::take();
    assert_eq!(
        sockets,
        [ObservedSocket {
            nodelay: false,
            keepalive: false,
            random_port: false,
        }]
    );
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn http1_connect_paths_apply_tcp_settings() -> TestResult {
    let peer = ClosingPeer::bind().await?;
    let settings = chromium_like();
    let connector = http1(&settings)?;
    let connect_headers = [HttpConnectHeader::authority("Host")];
    let basic_headers = [
        HttpConnectHeader::authority("Host"),
        HttpConnectHeader::proxy_authorization("Proxy-Authorization"),
    ];
    let credentials = HttpBasicCredentials::new("user", "secret")?;
    observed::take();

    let _ = connector
        .connect(crate::route::Http1Route::Origin(
            crate::route::OriginRoute::Tls {
                tcp: crate::route::TcpRoute::Direct(crate::route::Endpoint {
                    host: "127.0.0.1",
                    port: peer.port,
                }),
                server_name: SERVER_NAME,
                setup: crate::route::DirectTlsSetup::Default,
            },
        ))
        .await;
    assert_profiled("direct TLS", &observed::take());

    let _ = connector
        .connect(crate::route::Http1Route::Origin(
            crate::route::OriginRoute::Plaintext {
                tcp: crate::route::TcpRoute::Direct(crate::route::Endpoint {
                    host: "127.0.0.1",
                    port: peer.port,
                }),
                family: None,
            },
        ))
        .await;
    assert_profiled("direct plaintext", &observed::take());

    let _ = connector
        .connect(crate::route::Http1Route::Forward(
            crate::route::ProxyTransport::Tcp(crate::route::Endpoint {
                host: "127.0.0.1",
                port: peer.port,
            }),
        ))
        .await;
    assert_profiled("forward proxy", &observed::take());

    let _ = connector
        .connect(crate::route::Http1Route::Origin(
            crate::route::OriginRoute::Tls {
                tcp: crate::route::TcpRoute::HttpConnect(crate::route::HttpConnectRoute {
                    proxy: crate::route::ProxyTransport::Tcp(crate::route::Endpoint {
                        host: "127.0.0.1",
                        port: peer.port,
                    }),
                    authority: AUTHORITY,
                    headers: &connect_headers,
                    credentials: None,
                }),
                server_name: SERVER_NAME,
                setup: crate::route::DirectTlsSetup::Default,
            },
        ))
        .await;
    assert_profiled("HTTP CONNECT", &observed::take());

    let _ = connector
        .connect(crate::route::Http1Route::Origin(
            crate::route::OriginRoute::Tls {
                tcp: crate::route::TcpRoute::HttpConnect(crate::route::HttpConnectRoute {
                    proxy: crate::route::ProxyTransport::Tcp(crate::route::Endpoint {
                        host: "127.0.0.1",
                        port: peer.port,
                    }),
                    authority: AUTHORITY,
                    headers: &basic_headers,
                    credentials: Some(&credentials),
                }),
                server_name: SERVER_NAME,
                setup: crate::route::DirectTlsSetup::Default,
            },
        ))
        .await;
    assert_profiled("HTTP CONNECT with Basic", &observed::take());

    let _ = connector
        .connect(crate::route::Http1Route::Origin(
            crate::route::OriginRoute::Tls {
                tcp: crate::route::TcpRoute::Socks5 {
                    proxy: crate::route::Endpoint {
                        host: "127.0.0.1",
                        port: peer.port,
                    },
                    target: crate::route::Socks5Target::RemoteDns(crate::route::Endpoint {
                        host: SERVER_NAME,
                        port: 443,
                    }),
                    auth: crate::proxy::Socks5Auth::None,
                },
                server_name: SERVER_NAME,
                setup: crate::route::DirectTlsSetup::Default,
            },
        ))
        .await;
    assert_profiled("SOCKS5 remote DNS", &observed::take());

    let _ = connector
        .connect(crate::route::Http1Route::Origin(
            crate::route::OriginRoute::Tls {
                tcp: crate::route::TcpRoute::Socks5 {
                    proxy: crate::route::Endpoint {
                        host: "127.0.0.1",
                        port: peer.port,
                    },
                    target: crate::route::Socks5Target::LocalDns(crate::route::Endpoint {
                        host: "127.0.0.1",
                        port: 443,
                    }),
                    auth: crate::proxy::Socks5Auth::None,
                },
                server_name: SERVER_NAME,
                setup: crate::route::DirectTlsSetup::Default,
            },
        ))
        .await;
    assert_profiled("SOCKS5 local DNS", &observed::take());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn https_proxy_connections_apply_the_proxy_connectors_tcp_settings() -> TestResult {
    let peer = ClosingPeer::bind().await?;
    let settings = chromium_like();
    let origin = Http1TlsConnector::new(&chromium::v154_tls())?;
    let proxy = https_proxy(&settings)?;
    let connect_headers = [HttpConnectHeader::authority("Host")];
    observed::take();

    let _ = origin
        .connect(crate::route::Http1Route::Forward(
            crate::route::ProxyTransport::Tls {
                connector: &proxy,
                endpoint: crate::route::Endpoint {
                    host: "127.0.0.1",
                    port: peer.port,
                },
                server_name: SERVER_NAME,
            },
        ))
        .await;
    assert_profiled("HTTPS forward proxy", &observed::take());

    let _ = origin
        .connect(crate::route::Http1Route::Origin(
            crate::route::OriginRoute::Tls {
                tcp: crate::route::TcpRoute::HttpConnect(crate::route::HttpConnectRoute {
                    proxy: crate::route::ProxyTransport::Tls {
                        endpoint: crate::route::Endpoint {
                            host: "127.0.0.1",
                            port: peer.port,
                        },
                        server_name: SERVER_NAME,
                        connector: &proxy,
                    },
                    authority: AUTHORITY,
                    headers: &connect_headers,
                    credentials: None,
                }),
                server_name: SERVER_NAME,
                setup: crate::route::DirectTlsSetup::Default,
            },
        ))
        .await;
    assert_profiled("HTTPS CONNECT", &observed::take());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn http2_connect_paths_apply_tcp_settings() -> TestResult {
    let peer = ClosingPeer::bind().await?;
    let settings = chromium_like();
    let connector = http2(&settings)?;
    let connect_headers = [HttpConnectHeader::authority("Host")];
    observed::take();

    let _ = connector
        .connect(crate::route::Http2Route::Origin(
            crate::route::OriginRoute::Tls {
                tcp: crate::route::TcpRoute::Direct(crate::route::Endpoint {
                    host: "127.0.0.1",
                    port: peer.port,
                }),
                server_name: SERVER_NAME,
                setup: crate::route::DirectTlsSetup::Default,
            },
        ))
        .await;
    assert_profiled("HTTP/2 direct", &observed::take());

    let _ = connector
        .connect(crate::route::Http2Route::Origin(
            crate::route::OriginRoute::Tls {
                tcp: crate::route::TcpRoute::HttpConnect(crate::route::HttpConnectRoute {
                    proxy: crate::route::ProxyTransport::Tcp(crate::route::Endpoint {
                        host: "127.0.0.1",
                        port: peer.port,
                    }),
                    authority: AUTHORITY,
                    headers: &connect_headers,
                    credentials: None,
                }),
                server_name: SERVER_NAME,
                setup: crate::route::DirectTlsSetup::Default,
            },
        ))
        .await;
    assert_profiled("HTTP/2 over HTTP CONNECT", &observed::take());

    let _ = connector
        .connect(crate::route::Http2Route::Origin(
            crate::route::OriginRoute::Tls {
                tcp: crate::route::TcpRoute::Socks5 {
                    proxy: crate::route::Endpoint {
                        host: "127.0.0.1",
                        port: peer.port,
                    },
                    target: crate::route::Socks5Target::RemoteDns(crate::route::Endpoint {
                        host: SERVER_NAME,
                        port: 443,
                    }),
                    auth: Socks5Auth::None,
                },
                server_name: SERVER_NAME,
                setup: crate::route::DirectTlsSetup::Default,
            },
        ))
        .await;
    assert_profiled("HTTP/2 over SOCKS5", &observed::take());

    let negotiated = Http1Or2TlsConnector::from_http2(&connector)?;
    assert_eq!(negotiated.tcp_settings(), Some(&settings));
    let _ = negotiated
        .connect(crate::route::OriginRoute::Tls {
            tcp: crate::route::TcpRoute::Direct(crate::route::Endpoint {
                host: "127.0.0.1",
                port: peer.port,
            }),
            server_name: SERVER_NAME,
            setup: crate::route::DirectTlsSetup::Default,
        })
        .await;
    assert_profiled("HTTP/1.1-or-HTTP/2 direct", &observed::take());
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn socks5_udp_control_connection_applies_tcp_settings() -> TestResult {
    let peer = ClosingPeer::bind().await?;
    let connector = http3(&chromium_like())?;
    observed::take();

    let _ = connector
        .connect(
            crate::route::DatagramRoute::Socks5 {
                proxy: crate::route::Endpoint {
                    host: "127.0.0.1",
                    port: peer.port,
                },
                target: crate::route::Socks5Target::RemoteDns(crate::route::Endpoint {
                    host: SERVER_NAME,
                    port: 443,
                }),
                auth: crate::proxy::Socks5Auth::None,
            },
            SERVER_NAME,
        )
        .await;
    assert_profiled("SOCKS5 UDP control", &observed::take());
    Ok(())
}
