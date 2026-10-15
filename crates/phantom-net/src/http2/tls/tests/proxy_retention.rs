use super::*;
use crate::tcp::AddressFamilyMemory;
use std::io;
use tokio::sync::oneshot;

fn route<'a>(port: u16, fields: &'a [HttpConnectHeader]) -> HttpConnectRoute<'a> {
    HttpConnectRoute {
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
async fn quiet_connect_opening_settles_exact_h2_and_rejects_other_origin_alpn() -> TestResult<()> {
    for alpn in [
        TestServerAlpn::None,
        TestServerAlpn::Http1,
        TestServerAlpn::H2,
    ] {
        for https in [false, true] {
            timeout(TEST_TIMEOUT, async {
            let identity = TestIdentity::generate_for_names(&["127.0.0.1"])?;
            let connector = test_connector(&identity)?;
            let acceptor = identity.acceptor(alpn)?;
            let outer_acceptor = identity.acceptor(TestServerAlpn::Http1)?;
            let proxy = crate::proxy::HttpsProxyConnector::new_with_additional_roots(
                &tls_settings(), [identity.root_der()],
            )?;
            let (address, listener) = loopback_listener().await?;
            let fields = [HttpConnectHeader::authority("host")];
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
                    HttpConnectRoute { proxy: transport, ..route(address.port(), &fields) }, "127.0.0.1", &family,
                ).await?;
                assert!(slower.is_none());
                checked.await?;
                let result = opening.finish(HttpConnectRoute { proxy: transport, ..route(address.port(), &fields) }).await;
                let _ = finished.send(());
                Ok::<_, Box<dyn Error + Send + Sync>>(result)
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
                if matches!(alpn, TestServerAlpn::H2) {
                    let mut connection = ::http2::server::handshake(stream).await?;
                    tokio::select! {
                        _ = done => {},
                        _ = connection.accept() => return Err("unexpected origin request before finish".into()),
                    }
                } else { done.await?; }
                Ok::<_, Box<dyn Error + Send + Sync>>(observed)
            };
            let (client, peer) = tokio::join!(client, peer);
            let (result, observed) = match (client, peer) {
                (Ok(result), Ok(observed)) => (result, observed),
                (Err(client), Err(peer)) => return Err(format!("client: {client}; peer: {peer}").into()),
                (Err(error), _) | (_, Err(error)) => return Err(error),
            };
            assert!(matches!((alpn, result),
                (TestServerAlpn::H2, Ok(_)) |
                (TestServerAlpn::None, Err(Http2TlsError::MissingNegotiatedAlpn)) |
                (TestServerAlpn::Http1, Err(Http2TlsError::UnsupportedAlpn { .. }))));
            let expected = concat!(
                "CONNECT 127.0.0.1:443 HTTP/1.1\r\n",
                "host: 127.0.0.1:443\r\n\r\n",
            );
            assert_eq!(observed, expected.as_bytes());
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }).await??;
        }
    }
    Ok(())
}

#[test]
fn invalid_connect_fields_are_rejected_before_runtime_or_proxy_io() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let family = AddressFamilyMemory::new();
    let mut opening =
        pin!(connector.open_http_connect_retaining(route(0, &[]), "127.0.0.1", &family));
    assert!(matches!(
        opening
            .as_mut()
            .poll(&mut std::task::Context::from_waker(std::task::Waker::noop())),
        std::task::Poll::Ready(Err(Http2TlsError::Proxy(
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
    let connector = test_connector(&identity)?;
    let proxy = crate::proxy::HttpsProxyConnector::new(&tls_settings())?
        .with_protocol(crate::proxy::HttpsProxyProtocol::Http2)
        .with_http2_settings(&v154_http2());
    let fields = [HttpConnectHeader::authority("host")];
    let route = HttpConnectRoute {
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
        Poll::Ready(Err(Http2TlsError::Connect(error))) if error.kind() == io::ErrorKind::InvalidInput)
    );
    Ok(())
}
