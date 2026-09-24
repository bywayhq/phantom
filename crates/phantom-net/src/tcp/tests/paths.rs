//! Every connector's TCP connect path applies its profile socket options.
//!
//! Each peer accepts and immediately closes, so the protocol step after the
//! TCP connect fails; the sockets are read back when they connect.

use phantom_profile::{TcpSettings, chromium};
use tokio::{net::TcpListener, task::JoinHandle};

use super::{TestResult, chromium_like};
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
        .connect_direct("127.0.0.1", peer.port, SERVER_NAME)
        .await;

    let sockets = observed::take();
    assert_eq!(
        sockets,
        [ObservedSocket {
            nodelay: false,
            keepalive: false,
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
        .connect_direct("127.0.0.1", peer.port, SERVER_NAME)
        .await;
    assert_profiled("direct TLS", &observed::take());

    let _ = connector
        .connect_plaintext_direct("127.0.0.1", peer.port)
        .await;
    assert_profiled("direct plaintext", &observed::take());

    let _ = connector
        .connect_forward_proxy("127.0.0.1", peer.port)
        .await;
    assert_profiled("forward proxy", &observed::take());

    let _ = connector
        .connect_http_connect(
            "127.0.0.1",
            peer.port,
            AUTHORITY,
            &connect_headers,
            SERVER_NAME,
        )
        .await;
    assert_profiled("HTTP CONNECT", &observed::take());

    let _ = connector
        .connect_http_connect_with_basic_auth(
            "127.0.0.1",
            peer.port,
            AUTHORITY,
            &basic_headers,
            &credentials,
            SERVER_NAME,
        )
        .await;
    assert_profiled("HTTP CONNECT with Basic", &observed::take());

    let _ = connector
        .connect_socks5_remote("127.0.0.1", peer.port, SERVER_NAME, 443, SERVER_NAME)
        .await;
    assert_profiled("SOCKS5 remote DNS", &observed::take());

    let _ = connector
        .connect_socks5_local("127.0.0.1", peer.port, "127.0.0.1", 443, SERVER_NAME)
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
        .connect_https_forward_proxy(&proxy, "127.0.0.1", peer.port, SERVER_NAME)
        .await;
    assert_profiled("HTTPS forward proxy", &observed::take());

    let _ = origin
        .connect_https_connect(
            &proxy,
            "127.0.0.1",
            peer.port,
            SERVER_NAME,
            AUTHORITY,
            &connect_headers,
            SERVER_NAME,
        )
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
        .connect_direct("127.0.0.1", peer.port, SERVER_NAME)
        .await;
    assert_profiled("HTTP/2 direct", &observed::take());

    let _ = connector
        .connect_http_connect(
            "127.0.0.1",
            peer.port,
            AUTHORITY,
            &connect_headers,
            SERVER_NAME,
        )
        .await;
    assert_profiled("HTTP/2 over HTTP CONNECT", &observed::take());

    let _ = connector
        .connect_socks5_remote_with_auth(
            "127.0.0.1",
            peer.port,
            Socks5Auth::None,
            SERVER_NAME,
            443,
            SERVER_NAME,
        )
        .await;
    assert_profiled("HTTP/2 over SOCKS5", &observed::take());

    let negotiated = Http1Or2TlsConnector::from_http2(&connector)?;
    assert_eq!(negotiated.tcp_settings(), Some(&settings));
    let _ = negotiated
        .connect_direct("127.0.0.1", peer.port, SERVER_NAME)
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
        .connect_socks5_remote("127.0.0.1", peer.port, SERVER_NAME, 443, SERVER_NAME)
        .await;
    assert_profiled("SOCKS5 UDP control", &observed::take());
    Ok(())
}
