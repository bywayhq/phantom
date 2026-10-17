use super::*;
use crate::{http1_or_2::Http1Or2TlsConnector, tcp::AddressFamilyMemory};
use tokio::sync::oneshot;

async fn connect_head(stream: &mut (impl AsyncRead + Unpin)) -> TestResult<Vec<u8>> {
    let mut bytes = Vec::new();
    while bytes.len() < 4096 {
        bytes.push(stream.read_u8().await?);
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
    Err("proxy head exceeded fixture bound".into())
}

#[tokio::test]
async fn proxy_finish_installs_extended_connect_settings_with_original_tls_and_fields()
-> TestResult<()> {
    for negotiated in [false, true] {
        for https in [false, true] {
            bounded_tls_test(async {
                let origin = TestIdentity::generate_for_names(&["127.0.0.1"])?;
                let proxy = TestIdentity::generate_for_names(&["127.0.0.1"])?;
                let connector = test_connector(&origin)?;
                let negotiated_connector = Http1Or2TlsConnector::new_with_additional_roots(
                    &tls_settings(), &v154_http2(), [origin.root_der()],
                )?;
                let outer = crate::proxy::HttpsProxyConnector::new_with_additional_roots(
                    &tls_settings(), [proxy.root_der()],
                )?;
                let (address, listener) = loopback_listener().await?;
                let fields = [HttpConnectHeader::authority("Host"), HttpConnectHeader::field(RequestHeader::new("X-Claim", "current"))];
                let transport = if https { ProxyTransport::Tls { endpoint: Endpoint { host: "127.0.0.1", port: address.port() }, server_name: "127.0.0.1", connector: &outer } }
                    else { ProxyTransport::Tcp(Endpoint { host: "127.0.0.1", port: address.port() }) };
                let route = HttpConnectRoute { speculative_tls: false, proxy: transport, authority: "127.0.0.1:443", headers: &fields, credentials: None };
                let family = AddressFamilyMemory::new();
                let (opened, ready) = oneshot::channel();
                let (enabled, capability) = oneshot::channel();
                let caller = async {
                    let opening = if negotiated {
                        let (opening, slower) = negotiated_connector.open_http_connect_retaining(route, "127.0.0.1", &family).await?;
                        assert!(slower.is_none());
                        opening.finish_extended_connect(route, "127.0.0.1", OriginForm::parse("/events")?, vec![RequestHeader::new("x-claim", "current")]).await?
                    } else {
                        let (opening, slower) = connector.open_http_connect_retaining(route, "127.0.0.1", &family).await?;
                        assert!(slower.is_none());
                        opening.finish_extended_connect(route, "127.0.0.1", OriginForm::parse("/events")?, vec![RequestHeader::new("x-claim", "current")]).await?
                    };
                    opened.send(()).map_err(|_| "peer ended before opening publication")?;
                    capability.await?;
                    // This operation rejects ordinary H2 connections, even when
                    // their peer enables CONNECT. It proves the typed finisher
                    // installed extended settings rather than ordinary settings.
                    let request = crate::http2::prepare_extended_connect("127.0.0.1", OriginForm::parse("/events")?, vec![RequestHeader::new("x-claim", "current")])?;
                    let result = opening.connection().send_connect_udp(request).await?;
                    assert!(matches!(result, crate::http2::Http2ExtendedConnectOutcome::Accepted { .. }));
                    drop(result);
                    TestResult::Ok(())
                };
                let peer = async {
                    let (tcp, _) = listener.accept().await?;
                    let mut stream = if https {
                        let acceptor = proxy.acceptor(TestServerAlpn::Http1)?;
                        let mut stream = BoringStream::new(Ssl::new(acceptor.context())?, tcp)?;
                        Pin::new(&mut stream).accept().await?;
                        crate::route::ConnectedStream::new(stream)
                    } else { crate::route::ConnectedStream::new(tcp) };
                    assert_eq!(connect_head(&mut stream).await?, b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\nX-Claim: current\r\n\r\n");
                    stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
                    let acceptor = origin.acceptor(TestServerAlpn::H2)?;
                    let mut stream = BoringStream::new(Ssl::new(acceptor.context())?, stream)?;
                    Pin::new(&mut stream).accept().await?;
                    assert_eq!(stream.ssl().selected_alpn_protocol(), Some(b"h2".as_slice()));
                    let mut builder = ::http2::server::Builder::new();
                    builder.enable_connect_protocol();
                    let mut connection = builder.handshake::<_, Bytes>(stream).await?;
                    ready.await?;
                    // Polling accept drives the real settings handshake; no
                    // application request may precede the caller's send.
                    {
                        let mut accept = pin!(connection.accept());
                        assert!(poll_fn(|cx| std::task::Poll::Ready(accept.as_mut().poll(cx))).await.is_pending());
                    }
                    enabled.send(()).map_err(|_| "caller ended before capability")?;
                    let (request, mut respond) = connection.accept().await.ok_or("missing extended CONNECT")??;
                    assert_eq!(request.method(), http::Method::CONNECT);
                    assert_eq!(request.uri().path(), "/events");
                    assert_eq!(request.extensions().get::<::http2::ext::Protocol>().map(|p| p.as_str()), Some("websocket"));
                    assert_eq!(request.headers().get("x-claim").ok_or("missing claimant field")?, "current");
                    let _send = respond.send_response(Response::new(()), false)?;
                    match connection.accept().await {
                        None => {},
                        Some(Err(error)) if error.get_io().is_some_and(|e| matches!(e.kind(), std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe)) => {},
                        Some(Err(error)) => return Err(error.into()),
                        Some(Ok(_)) => return Err("duplicate application HEADERS".into()),
                    }
                    TestResult::Ok(())
                };
                tokio::try_join!(caller, peer)?;
                Ok(())
            }).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn proxy_extended_connect_rejects_changed_route_and_invalid_fields_before_tunnel_io()
-> TestResult<()> {
    for negotiated in [false, true] {
        for changed in [false, true] {
            bounded_tls_test(async {
                let identity = TestIdentity::generate_for_names(&["127.0.0.1"])?;
                let connector = test_connector(&identity)?;
                let negotiated_connector = Http1Or2TlsConnector::new_with_additional_roots(&tls_settings(), &v154_http2(), [identity.root_der()])?;
                let (address, listener) = loopback_listener().await?;
                let fields = [HttpConnectHeader::authority("Host")];
                let route = HttpConnectRoute { speculative_tls: false, proxy: ProxyTransport::Tcp(Endpoint { host: "127.0.0.1", port: address.port() }), authority: "127.0.0.1:443", headers: &fields, credentials: None };
                let family = AddressFamilyMemory::new();
                let caller = async {
                    let current = HttpConnectRoute { authority: if changed { "other.test:443" } else { route.authority }, ..route };
                    let headers = if changed { vec![] } else { vec![RequestHeader::new("connection", "upgrade")] };
                    let result = if negotiated {
                        let (opening, _) = negotiated_connector.open_http_connect_retaining(route, "127.0.0.1", &family).await?;
                        opening.finish_extended_connect(current, "127.0.0.1", OriginForm::parse("/")?, headers).await
                    } else {
                        let (opening, _) = connector.open_http_connect_retaining(route, "127.0.0.1", &family).await?;
                        opening.finish_extended_connect(current, "127.0.0.1", OriginForm::parse("/")?, headers).await
                    };
                    if changed { assert!(matches!(result, Err(Http2TlsError::Connect(ref error)) if error.kind() == std::io::ErrorKind::InvalidInput)); }
                    else { assert!(matches!(result, Err(Http2TlsError::Http2(Http2Error::ForbiddenHeader { .. })))); }
                    TestResult::Ok(())
                };
                let peer = async {
                    let (mut stream, _) = listener.accept().await?;
                    let mut byte = [0];
                    match stream.read(&mut byte).await {
                        Ok(0) => {},
                        Err(error) if matches!(error.kind(), std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::BrokenPipe) => {},
                        other => return Err(format!("invalid claimant wrote tunnel bytes: {other:?}").into()),
                    }
                    TestResult::Ok(())
                };
                tokio::try_join!(caller, peer)?;
                Ok(())
            }).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn proxy_extended_connect_resumes_the_original_origin_ticket_context() -> TestResult<()> {
    for negotiated in [false, true] {
        bounded_tls_test(async {
            let identity = TestIdentity::generate_for_names(&["127.0.0.1"])?;
            let acceptor = identity.acceptor(TestServerAlpn::H2)?;
            let exact = test_connector(&identity)?.with_isolated_session_cache();
            let combined = Http1Or2TlsConnector::new_with_additional_roots(
                &tls_settings(),
                &v154_http2(),
                [identity.root_der()],
            )?
            .with_isolated_session_cache();
            let original = if negotiated {
                combined.http2_connector()
            } else {
                exact.clone()
            };
            let (address, listener) = loopback_listener().await?;
            let fields = [HttpConnectHeader::authority("Host")];
            let route = HttpConnectRoute {
                speculative_tls: false,
                proxy: ProxyTransport::Tcp(Endpoint {
                    host: "127.0.0.1",
                    port: address.port(),
                }),
                authority: "127.0.0.1:443",
                headers: &fields,
                credentials: None,
            };
            let family = AddressFamilyMemory::new();
            let (peer_ready, peer_handshake) = oneshot::channel();
            let caller = async {
                let mut seed = original
                    .tls
                    .connect("127.0.0.1", TcpStream::connect(address).await?)
                    .await?;
                assert_eq!(seed.read_u8().await?, 1);
                seed.write_all(&[2]).await?;
                drop(seed);
                let opening = if negotiated {
                    let (opening, _) = combined
                        .open_http_connect_retaining(route, "127.0.0.1", &family)
                        .await?;
                    opening
                        .finish_extended_connect(
                            route,
                            "127.0.0.1",
                            OriginForm::parse("/")?,
                            vec![],
                        )
                        .await?
                } else {
                    let (opening, _) = exact
                        .open_http_connect_retaining(route, "127.0.0.1", &family)
                        .await?;
                    opening
                        .finish_extended_connect(
                            route,
                            "127.0.0.1",
                            OriginForm::parse("/")?,
                            vec![],
                        )
                        .await?
                };
                peer_handshake.await?;
                drop(opening);
                TestResult::Ok(())
            };
            let peer = async {
                let (tcp, _) = listener.accept().await?;
                let mut seed = BoringStream::new(Ssl::new(acceptor.context())?, tcp)?;
                Pin::new(&mut seed).accept().await?;
                assert!(!seed.ssl().session_reused());
                seed.write_all(&[1]).await?;
                assert_eq!(seed.read_u8().await?, 2);
                drop(seed);
                let (mut stream, _) = listener.accept().await?;
                assert_eq!(
                    connect_head(&mut stream).await?,
                    b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n"
                );
                stream
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                let mut tls = BoringStream::new(Ssl::new(acceptor.context())?, stream)?;
                Pin::new(&mut tls).accept().await?;
                assert!(
                    tls.ssl().session_reused(),
                    "typed opening replaced the original ticket context"
                );
                let mut builder = ::http2::server::Builder::new();
                builder.enable_connect_protocol();
                let mut connection = builder.handshake::<_, Bytes>(tls).await?;
                peer_ready
                    .send(())
                    .map_err(|_| "caller ended before peer handshake")?;
                match connection.accept().await {
                    None => {}
                    Some(Err(error))
                        if error.get_io().is_some_and(|error| {
                            matches!(
                                error.kind(),
                                std::io::ErrorKind::ConnectionAborted
                                    | std::io::ErrorKind::ConnectionReset
                                    | std::io::ErrorKind::BrokenPipe
                            )
                        }) => {}
                    Some(Err(error)) => return Err(error.into()),
                    Some(Ok(_)) => {
                        return Err("typed opening emitted speculative application HEADERS".into());
                    }
                }
                TestResult::Ok(())
            };
            tokio::try_join!(caller, peer)?;
            Ok(())
        })
        .await?;
    }
    Ok(())
}
