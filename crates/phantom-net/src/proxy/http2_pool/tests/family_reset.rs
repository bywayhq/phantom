//! Ordinary H2-proxy restarts forget the original entry's address family.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use bytes::Bytes;
use http::{Method, Response};
use phantom_profile::browser::firefox;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::oneshot,
    time::timeout,
};

use super::Http2ProxyPool;
use crate::{
    host_resolver::{AddressResolver, HostResolver},
    proxy::{HttpConnectError, HttpConnectHeader, HttpsProxyConnector, HttpsProxyProtocol},
    tcp::AddressFamily,
    tls::test_support::{TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn},
};

#[tokio::test]
async fn ordinary_h2_redial_uses_resolver_order() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let ipv4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = ipv4.local_addr()?.port();
        let ipv6 = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await?;
        let lookups = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&lookups);
        let resolver = HostResolver::new().with_resolver(AddressResolver::from_fn(move |host| {
            let index = count.fetch_add(1, Ordering::SeqCst);
            async move {
                if host != "proxy.test" {
                    return Err(io::Error::other("locally resolved an inner origin"));
                }
                Ok(if index == 0 {
                    vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
                } else {
                    vec![IpAddr::V6(Ipv6Addr::LOCALHOST), IpAddr::V4(Ipv4Addr::LOCALHOST)]
                })
            }
        }));
        let pool = Http2ProxyPool::new();
        let connector = HttpsProxyConnector::new_with_additional_roots(
            &firefox::v157_tcp_tls(), [identity.root_der()],
        )?
        .with_http2_settings(&firefox::v157_http2())
        .with_tcp_settings(&firefox::v157_tcp())
        .with_host_resolver(resolver)
        .with_http2_proxy_pool(pool.clone())
        .with_protocol(HttpsProxyProtocol::Http2);
        let (first_done, first_finished) = oneshot::channel();
        let (done, finished) = oneshot::channel();

        let client = async {
            let mut first = connector.connect_tunnel(
                "proxy.test", port, TEST_SERVER_NAME, "origin.invalid:443",
                &[HttpConnectHeader::authority("Host")],
            ).await?;
            let mut body = [0; 2];
            first.read_exact(&mut body).await?;
            assert_eq!(&body, b"ok");
            first_done.send(()).map_err(|_| "first proxy stopped early")?;
            pool.refresh_connections();

            let mut second = connector.connect_tunnel(
                "proxy.test", port, TEST_SERVER_NAME, "origin.invalid:443",
                &[HttpConnectHeader::authority("Host")],
            ).await?;
            second.read_exact(&mut body).await?;
            assert_eq!(&body, b"ok");
            done.send(()).map_err(|_| "second proxy stopped early")?;
            drop((first, second));
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            let (first, _) = ipv4.accept().await?;
            let first_listener = identity.acceptor(TestServerAlpn::H2)?;
            let first = accept_tls_stream(first, first_listener).await?;
            let mut first = ::http2::server::handshake(first).await?;
            let (request, mut reply) = first.accept().await.ok_or("no first CONNECT")??;
            assert_eq!(request.method(), Method::CONNECT);
            let mut body = reply.send_response(Response::new(()), false)?;
            body.send_data(Bytes::from_static(b"ok"), false)?;
            tokio::select! {
                result = first_finished => result.map_err(|_| "first client failed")?,
                extra = first.accept() => return Err(format!("unexpected first proxy event: {}", extra.is_some()).into()),
            }
            let (second, _) = tokio::select! {
                result = ipv6.accept() => result?,
                result = ipv4.accept() => {
                    let _unexpected = result?;
                    return Err("second ordinary H2 proxy connection retained IPv4".into());
                }
                extra = first.accept() => return Err(format!("active first tunnel ended during refresh: {}", extra.is_some()).into()),
            };
            let second = accept_tls_stream(second, identity.acceptor(TestServerAlpn::H2)?).await?;
            let mut second = ::http2::server::handshake(second).await?;
            let (request, mut reply) = second.accept().await.ok_or("no second CONNECT")??;
            assert_eq!(request.method(), Method::CONNECT);
            let mut body = reply.send_response(Response::new(()), false)?;
            body.send_data(Bytes::from_static(b"ok"), false)?;
            tokio::select! {
                biased;
                result = finished => result.map_err(|_| "second client failed")?,
                extra = second.accept() => return Err(format!("unexpected second proxy event: {}", extra.is_some()).into()),
            }
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(client, peer)?;
        assert_eq!(lookups.load(Ordering::SeqCst), 2);
        Ok(())
    })
    .await
    .map_err(|_| "ordinary H2 proxy family reset exceeded its deadline")?
}

#[tokio::test]
async fn failed_proxy_tls_keeps_the_connected_family() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let pool = Http2ProxyPool::new();
        let connector = HttpsProxyConnector::new_with_additional_roots(
            &firefox::v157_tcp_tls(),
            [identity.root_der()],
        )?
        .with_http2_settings(&firefox::v157_http2())
        .with_tcp_settings(&firefox::v157_tcp())
        .with_http2_proxy_pool(pool.clone())
        .with_protocol(HttpsProxyProtocol::Http2);
        let route = pool.route(super::super::RouteKey::new(
            connector.connect_udp_settings(),
            "127.0.0.1",
            port,
            TEST_SERVER_NAME,
            None,
        ));
        let client = async {
            let result = connector
                .connect_tunnel(
                    "127.0.0.1",
                    port,
                    TEST_SERVER_NAME,
                    "origin.invalid:443",
                    &[HttpConnectHeader::authority("Host")],
                )
                .await;
            assert!(matches!(result, Err(HttpConnectError::ProxyTls(_))));
            assert_eq!(route.family.family(), Some(AddressFamily::Ipv4));
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        let peer = async {
            let (mut stream, _) = listener.accept().await?;
            stream.write_all(b"not a TLS record").await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        };
        tokio::try_join!(client, peer)?;
        Ok(())
    })
    .await
    .map_err(|_| "failed proxy TLS family control exceeded its deadline")?
}

async fn accept_tls_stream(
    stream: tokio::net::TcpStream,
    acceptor: btls::ssl::SslAcceptor,
) -> TestResult<tokio_btls::SslStream<tokio::net::TcpStream>> {
    let ssl = btls::ssl::Ssl::new(acceptor.context())?;
    let mut stream = tokio_btls::SslStream::new(ssl, stream)?;
    std::pin::Pin::new(&mut stream).accept().await?;
    Ok(stream)
}
