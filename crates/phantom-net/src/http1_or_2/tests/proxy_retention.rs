use super::*;
use crate::{
    http1_or_2::{Http1Or2Connection, Http1Or2TlsConnector, Http1Or2TlsError},
    proxy::HttpConnectHeader,
    request::RequestHeader,
    route::{Endpoint, HttpConnectRoute, ProxyTransport},
    tcp::AddressFamilyMemory,
    tls::test_support::{
        TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn, loopback_listener,
    },
};
use btls::ssl::Ssl;
use std::io;
use std::pin::Pin;
use tokio::sync::oneshot;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use tokio_btls::SslStream as BoringStream;

fn route<'a>(port: u16, fields: &'a [HttpConnectHeader]) -> HttpConnectRoute<'a> {
    HttpConnectRoute {
        speculative_tls: false,
        proxy: ProxyTransport::Tcp(Endpoint {
            host: "127.0.0.1",
            port,
        }),
        authority: "127.0.0.1:443",
        headers: fields,
        credentials: None,
    }
}

async fn head(stream: &mut (impl AsyncReadExt + Unpin)) -> TestResult<Vec<u8>> {
    let mut head = Vec::new();
    while head.len() < 4096 {
        head.push(stream.read_u8().await?);
        if head.ends_with(b"\r\n\r\n") {
            return Ok(head);
        }
    }
    Err("CONNECT head exceeded fixture bound".into())
}
#[tokio::test]
async fn quiet_connect_opening_uses_current_fields_and_actual_origin_alpn() -> TestResult<()> {
    for strategy in [
        crate::http1::Http1WriteStrategy::Automatic,
        crate::http1::Http1WriteStrategy::Queued,
    ] {
        for (alpn, h2) in [(TestServerAlpn::Http1, false), (TestServerAlpn::H2, true)] {
            for https in [false, true] {
                timeout(TEST_TIMEOUT, async {
            let identity = TestIdentity::generate_for_names(&["127.0.0.1"])?;
            let connector = Http1Or2TlsConnector::new_with_additional_roots(
                &v154_tcp_tls(), &v154_http2(), [identity.root_der()],
            )?.with_http1_write_strategy(strategy);
            let acceptor = identity.acceptor(alpn)?;
            let outer_acceptor = identity.acceptor(TestServerAlpn::Http1)?;
            let proxy = crate::proxy::HttpsProxyConnector::new_with_additional_roots(
                &v154_tcp_tls(), [identity.root_der()],
            )?;
            let (address, listener) = loopback_listener().await?;
            let initial = [HttpConnectHeader::authority("host")];
            let current = [HttpConnectHeader::field(RequestHeader::new("X-Claim", "current")),
                HttpConnectHeader::authority("host")];
            let (quiet, checked) = oneshot::channel();
            let (finished, done) = oneshot::channel();
            let family = AddressFamilyMemory::new();
            let transport = if https {
                ProxyTransport::Tls {
                    endpoint: Endpoint { host: "127.0.0.1", port: address.port() },
                    server_name: "127.0.0.1", connector: &proxy,
                }
            } else { ProxyTransport::Tcp(Endpoint { host: "127.0.0.1", port: address.port() }) };
            let client = async {
                let (opening, slower) = connector.open_http_connect_retaining(
                    HttpConnectRoute { speculative_tls: false, proxy: transport, ..route(address.port(), &initial) }, "127.0.0.1", &family,
                ).await?;
                assert!(slower.is_none());
                checked.await?;
                let result = opening.finish(HttpConnectRoute { speculative_tls: false, proxy: transport, ..route(address.port(), &current) }).await;
                let _ = finished.send(());
                result.map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            };
            let peer = async {
                let (stream, _) = listener.accept().await?;
                let mut byte = [0];
                assert!(matches!(stream.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
                quiet.send(()).map_err(|_| "claimant stopped before quiet check")?;
                let mut stream = if https {
                    let mut outer = BoringStream::new(Ssl::new(outer_acceptor.context())?, stream)?;
                    Pin::new(&mut outer).accept().await?;
                    crate::route::ConnectedStream::new(outer)
                } else { crate::route::ConnectedStream::new(stream) };
                let observed = head(&mut stream).await?;
                stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                let mut stream = BoringStream::new(Ssl::new(acceptor.context())?, stream)?;
                Pin::new(&mut stream).accept().await?;
                if h2 {
                    let mut connection = ::http2::server::handshake(stream).await?;
                    tokio::select! {
                        _ = done => {},
                        _ = connection.accept() => return Err("unexpected origin request before finish".into()),
                    }
                } else { done.await?; }
                Ok::<_, Box<dyn std::error::Error + Send + Sync>>(observed)
            };
            let (client, peer) = tokio::join!(client, peer);
            let (connection, observed) = match (client, peer) {
                (Ok(connection), Ok(observed)) => (connection, observed),
                (Err(client), Err(peer)) => return Err(format!("client: {client}; peer: {peer}").into()),
                (Err(error), _) | (_, Err(error)) => return Err(error),
            };
            assert_eq!(matches!(connection, Http1Or2Connection::Http2(_)), h2);
            let expected = concat!(
                "CONNECT 127.0.0.1:443 HTTP/1.1\r\n",
                "X-Claim: current\r\n",
                "host: 127.0.0.1:443\r\n\r\n",
            );
            assert_eq!(observed, expected.as_bytes());
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
        }).await??;
            }
        }
    }
    Ok(())
}

#[test]
fn invalid_connect_fields_are_rejected_before_runtime_or_proxy_io() -> TestResult<()> {
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    let connector = Http1Or2TlsConnector::new(&v154_tcp_tls(), &v154_http2())?;
    let family = AddressFamilyMemory::new();
    let mut opening =
        pin!(connector.open_http_connect_retaining(route(0, &[]), "127.0.0.1", &family));
    assert!(matches!(
        opening
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(Http1Or2TlsError::Proxy(
            crate::proxy::HttpConnectError::MissingAuthorityHeader
        )))
    ));
    Ok(())
}

#[test]
fn h2_proxy_transport_is_rejected_before_runtime_or_proxy_io() -> TestResult<()> {
    use std::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };
    let identity = TestIdentity::generate()?;
    let connector = Http1Or2TlsConnector::new_with_additional_roots(
        &v154_tcp_tls(),
        &v154_http2(),
        [identity.root_der()],
    )?;
    let proxy = crate::proxy::HttpsProxyConnector::new(&v154_tcp_tls())?
        .with_protocol(crate::proxy::HttpsProxyProtocol::Http2)
        .with_http2_settings(&v154_http2());
    let fields = [HttpConnectHeader::authority("host")];
    let route = HttpConnectRoute {
        speculative_tls: false,
        proxy: ProxyTransport::Tls {
            endpoint: Endpoint {
                host: "127.0.0.1",
                port: 0,
            },
            server_name: "127.0.0.1",
            connector: &proxy,
        },
        ..route(0, &fields)
    };
    let family = AddressFamilyMemory::new();
    let mut opening = pin!(connector.open_http_connect_retaining(route, "127.0.0.1", &family));
    assert!(
        matches!(opening.as_mut().poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(Err(Http1Or2TlsError::Connect(error))) if error.kind() == io::ErrorKind::InvalidInput)
    );
    Ok(())
}
