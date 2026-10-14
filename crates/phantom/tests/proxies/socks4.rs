//! SOCKS4 and SOCKS4a public routes, observed by independent loopback peers.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};

use http::Response;
use http_body_util::BodyExt;
use phantom::{
    AddressResolver, Client, HttpProtocol, RequestErrorKind, RequestTimeouts, Route, Socks4DnsMode,
    Socks4Proxy, TimeoutPhase, profile::browser::chrome,
};
use phantom_net::proxy::{Socks4Error, Socks4ErrorKind};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
};

use super::socks5::finish_socks_route;
use crate::support::{
    tls::{
        H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls, client_builder, is_peer_gone,
        read_head,
    },
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

const HOST: &str = "origin.socks4.test";

#[tokio::test]
async fn http1_http2_and_alpn_use_explicit_local_and_remote_dns_tunnels() -> TestResult<()> {
    for dns in [Socks4DnsMode::Local, Socks4DnsMode::Remote] {
        for protocol in [HttpProtocol::Http1, HttpProtocol::Http2] {
            for negotiated in [false, true] {
                request_through_proxy(RequestCase {
                    dns,
                    protocol,
                    negotiated,
                    proxy_ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                })
                .await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn an_ipv6_proxy_endpoint_can_tunnel_to_an_ipv4_origin() -> TestResult<()> {
    request_through_proxy(RequestCase {
        dns: Socks4DnsMode::Remote,
        protocol: HttpProtocol::Http1,
        negotiated: false,
        proxy_ip: IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
    })
    .await
}

#[tokio::test]
async fn plaintext_http1_tunnels_an_origin_form_request_with_a_canonical_domain() -> TestResult<()>
{
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = listener.local_addr()?;
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = proxy_listener.local_addr()?;
    let origin = ConnectionPeer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        let request = read_head(&mut stream).await?;
        assert!(request.starts_with(b"GET /plain HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await?;
        stream.shutdown().await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let proxy = ConnectionPeer::spawn(forward_one(proxy_listener, origin_address));
    let operation = match tokio::time::timeout(Duration::from_secs(5), async {
        let client = Client::builder(chrome::v154_windows())
            .route(Route::socks4(Socks4Proxy::new(&format!(
                "socks4a://{proxy_address}"
            ))?))
            .dns_resolver(AddressResolver::from_fn(|host| async move {
                Err(io::Error::other(format!("unexpected local lookup: {host}")))
            }))
            .build()?;
        let response = client
            .get(
                HttpProtocol::Http1,
                &format!("http://BÜCHER.example:{}/plain", origin_address.port()),
            )?
            .send()
            .await?;
        assert_eq!(response.status(), 200);
        assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
        drop(client);
        Ok(())
    })
    .await
    {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    let (_, observed) = finish_socks_route(operation, origin, proxy).await?;
    assert_eq!(observed.domain.as_deref(), Some("xn--bcher-kva.example"));
    assert_eq!(observed.user_id, "");
    Ok(())
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn plaintext_websocket_uses_remote_dns_and_user_identification() -> TestResult<()> {
    use crate::support::websocket_origin;

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = listener.local_addr()?;
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = proxy_listener.local_addr()?;
    let client = Client::builder(chrome::v154_windows())
        .route(Route::socks4(
            Socks4Proxy::new(&format!("socks4a://{proxy_address}"))?.with_user_id("socket-user")?,
        ))
        .dns_resolver(AddressResolver::from_fn(|_| async {
            Err(io::Error::other("unexpected WebSocket origin lookup"))
        }))
        .build()?;
    let origin = ConnectionPeer::spawn(websocket_origin::serve_plaintext_h1_echo(listener));
    let proxy = ConnectionPeer::spawn(forward_one(proxy_listener, origin_address));
    let operation = exchange_websocket(
        client,
        HttpProtocol::Http1,
        format!("ws://BÜCHER.example:{}/socket", origin_address.port()),
    )
    .await;
    let ((head, message), observed) = finish_socks_route(operation, origin, proxy).await?;
    assert!(head.starts_with(b"GET /socket HTTP/1.1\r\n"));
    let authority = format!("xn--bcher-kva.example:{}", origin_address.port());
    assert_eq!(
        crate::support::websocket::header_value(&head, "host"),
        Some(authority.as_str())
    );
    assert_eq!(message.payload, b"hello");
    assert_eq!(observed.domain.as_deref(), Some("xn--bcher-kva.example"));
    assert_eq!(observed.user_id, "socket-user");
    Ok(())
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn http2_websocket_uses_an_extended_connect_through_remote_dns() -> TestResult<()> {
    use crate::support::websocket_origin;

    let identity = TestIdentity::generate_for_dns(HOST)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = listener.local_addr()?;
    let acceptor = identity.acceptor(H2_ALPN)?;
    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = proxy_listener.local_addr()?;
    let client = client_builder(&identity, true)
        .route(Route::socks4(
            Socks4Proxy::new(&format!("socks4a://{proxy_address}"))?.with_user_id("socket-user")?,
        ))
        .dns_resolver(AddressResolver::from_fn(|_| async {
            Err(io::Error::other("unexpected WebSocket origin lookup"))
        }))
        .build()?;
    let origin = ConnectionPeer::spawn(websocket_origin::serve_h2_echo(listener, acceptor));
    let proxy = ConnectionPeer::spawn(forward_one(proxy_listener, origin_address));
    let operation = exchange_websocket(
        client,
        HttpProtocol::Http2,
        format!("wss://{HOST}:{}/socket", origin_address.port()),
    )
    .await;
    let (request, observed) = finish_socks_route(operation, origin, proxy).await?;
    assert_eq!(request.protocol.as_deref(), Some("websocket"));
    assert_eq!(request.path.as_deref(), Some("/socket"));
    let authority = format!("{HOST}:{}", origin_address.port());
    assert_eq!(request.authority.as_deref(), Some(authority.as_str()));
    assert_eq!(request.scheme.as_deref(), Some("https"));
    assert_eq!(request.message.payload, b"hello");
    assert_eq!(observed.domain.as_deref(), Some(HOST));
    assert_eq!(observed.user_id, "socket-user");
    Ok(())
}

#[cfg(feature = "websocket")]
async fn exchange_websocket(client: Client, protocol: HttpProtocol, url: String) -> TestResult<()> {
    use phantom::{WebSocketCloseFrame, WebSocketMessage};

    match tokio::time::timeout(Duration::from_secs(5), async {
        let mut socket = client
            .websocket_with_protocol(protocol, &url)?
            .connect()
            .await?;
        socket.send(WebSocketMessage::Text("hello".into())).await?;
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Text("echo:hello".into())
        );
        let close = WebSocketCloseFrame::new(1000, "done")?;
        socket.close(Some(close.clone())).await?;
        assert_eq!(
            socket.receive().await?,
            WebSocketMessage::Close(Some(close))
        );
        drop(socket);
        drop(client);
        Ok(())
    })
    .await
    {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    }
}

struct RequestCase {
    dns: Socks4DnsMode,
    protocol: HttpProtocol,
    negotiated: bool,
    proxy_ip: IpAddr,
}

async fn request_through_proxy(case: RequestCase) -> TestResult<()> {
    let RequestCase {
        dns,
        protocol,
        negotiated,
        proxy_ip,
    } = case;
    let remote = dns == Socks4DnsMode::Remote;
    let identity = TestIdentity::generate_for_dns(HOST)?;
    let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = origin_listener.local_addr()?;
    let acceptor = identity.acceptor(if protocol == HttpProtocol::Http2 {
        H2_ALPN
    } else {
        H1_ALPN
    })?;
    let proxy_listener = TcpListener::bind((proxy_ip, 0)).await?;
    let proxy_address = proxy_listener.local_addr()?;
    let origin = ConnectionPeer::spawn(async move {
        let mut stream = accept_tls(origin_listener, acceptor).await?;
        if protocol == HttpProtocol::Http2 {
            let mut connection = ::http2::server::handshake(stream).await?;
            let (request, mut response) = connection
                .accept()
                .await
                .ok_or("missing HTTP/2 request")??;
            assert_eq!(request.uri().path(), "/tunnel");
            response.send_response(Response::builder().status(204).body(())?, true)?;
            std::future::poll_fn(|context| connection.poll_closed(context)).await?;
        } else {
            let request = read_head(&mut stream).await?;
            assert!(request.starts_with(b"GET /tunnel HTTP/1.1\r\n"));
            stream.write_all(b"HTTP/1.1 204 No Content\r\n\r\n").await?;
            stream.shutdown().await?;
        }
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let proxy = ConnectionPeer::spawn(forward_one(proxy_listener, origin_address));
    let resolver = AddressResolver::from_fn(move |host| async move {
        assert_eq!(host, HOST);
        assert!(!remote, "remote target was resolved locally");
        Ok(vec![
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
        ])
    });
    let operation = match tokio::time::timeout(Duration::from_secs(5), async {
        let scheme = if remote { "socks4a" } else { "socks4" };
        let route = Route::socks4(
            Socks4Proxy::new(&format!("{scheme}://{proxy_address}"))?.with_user_id("test-user")?,
        );
        let client = client_builder(&identity, protocol == HttpProtocol::Http2 || negotiated)
            .dns_resolver(resolver)
            .route(route)
            .build()?;
        let url = format!("https://{HOST}:{}/tunnel", origin_address.port());
        let request = if negotiated {
            client.get_negotiated(&url)?
        } else {
            client.get(protocol, &url)?
        };
        let response = request.send().await?;
        assert_eq!(response.status(), 204);
        response.into_body().collect().await?;
        drop(client);
        Ok(())
    })
    .await
    {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    let (_, observed) = finish_socks_route(operation, origin, proxy).await?;
    assert_eq!(observed.user_id, "test-user");
    assert_eq!(observed.port, origin_address.port());
    if remote {
        assert_eq!(observed.address, [0, 0, 0, 1]);
        assert_eq!(observed.domain.as_deref(), Some(HOST));
    } else {
        assert_eq!(observed.address, [127, 0, 0, 1]);
        assert_eq!(observed.domain, None);
    }
    Ok(())
}

#[tokio::test]
async fn http3_ipv6_and_failed_local_dns_never_contact_the_proxy() -> TestResult<()> {
    let proxy = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    proxy.set_nonblocking(true)?;
    let address = proxy.local_addr()?;
    let route = Route::socks4(Socks4Proxy::new(&format!("socks4://{address}"))?);
    let client = Client::builder(chrome::v154_windows())
        .route(route)
        .dns_resolver(AddressResolver::from_fn(|_| async {
            Err(io::Error::new(io::ErrorKind::NotFound, "owned DNS failure"))
        }))
        .build()?;
    let error = client
        .get(HttpProtocol::Http3, "https://origin.socks4.test/")?
        .send()
        .await
        .err()
        .ok_or("operation unexpectedly succeeded")?;
    assert_eq!(error.kind(), RequestErrorKind::UnsupportedRoute);
    let error = client
        .get(HttpProtocol::Http1, "http://[::1]/")?
        .send()
        .await
        .err()
        .ok_or("operation unexpectedly succeeded")?;
    assert_eq!(
        socks_error(&error)?.kind(),
        Socks4ErrorKind::UnsupportedTarget
    );
    let error = client
        .get(HttpProtocol::Http1, "http://origin.socks4.test/")?
        .send()
        .await
        .err()
        .ok_or("operation unexpectedly succeeded")?;
    assert_eq!(error.kind(), RequestErrorKind::Resolve);
    assert!(matches!(proxy.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[tokio::test]
async fn rejection_preserves_status_and_never_dials_the_origin_directly() -> TestResult<()> {
    let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    origin.set_nonblocking(true)?;
    let target = origin.local_addr()?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let peer = ConnectionPeer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        read_connect(&mut stream).await?;
        stream.write_all(&[0, 91, 0, 0, 0, 0, 0, 0]).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let client = Client::builder(chrome::v154_windows())
        .route(Route::socks4(Socks4Proxy::new(&format!(
            "socks4://{address}"
        ))?))
        .build()?;
    let result: TestResult<()> = async {
        let error = client
            .get(HttpProtocol::Http1, &format!("http://{target}/"))?
            .send()
            .await
            .err()
            .ok_or("operation unexpectedly succeeded")?;
        assert_eq!(error.kind(), RequestErrorKind::Proxy);
        assert_eq!(socks_error(&error)?.reply_status(), Some(91));
        assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        Ok(())
    }
    .await;
    finish_peer(result, peer).await
}

#[tokio::test]
async fn connect_deadline_closes_a_stalled_proxy_without_origin_bytes() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let peer = ConnectionPeer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        read_connect(&mut stream).await?;
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await?, 0);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let client = Client::builder(chrome::v154_windows())
        .route(Route::socks4(Socks4Proxy::new(&format!(
            "socks4a://{address}"
        ))?))
        .request_timeouts(RequestTimeouts::new().connect(Duration::from_millis(200)))
        .build()?;
    let result: TestResult<()> = async {
        let error = client
            .get(HttpProtocol::Http1, "http://origin.socks4.test/")?
            .send()
            .await
            .err()
            .ok_or("operation unexpectedly succeeded")?;
        assert_eq!(error.timeout_phase(), Some(TimeoutPhase::Connect));
        Ok(())
    }
    .await;
    finish_peer(result, peer).await
}

#[tokio::test]
async fn cancellation_after_negotiation_starts_closes_the_proxy() -> TestResult<()> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let (observed, received) = tokio::sync::oneshot::channel();
    let peer = ConnectionPeer::spawn(async move {
        let (mut stream, _) = listener.accept().await?;
        read_connect(&mut stream).await?;
        observed
            .send(())
            .map_err(|_| "request dropped before negotiation")?;
        let mut byte = [0];
        assert_eq!(stream.read(&mut byte).await?, 0);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    });
    let client = Client::builder(chrome::v154_windows())
        .route(Route::socks4(Socks4Proxy::new(&format!(
            "socks4a://{address}"
        ))?))
        .build()?;
    let operation: TestResult<()> = match tokio::time::timeout(Duration::from_secs(5), async {
        let request = client.get(HttpProtocol::Http1, "http://origin.socks4.test/")?.send();
        tokio::pin!(request);
        tokio::select! {
            result = &mut request => return Err(format!("request completed before cancellation: {result:?}").into()),
            result = received => result?,
        }
        Ok(())
    }).await {
        Ok(result) => result,
        Err(error) => Err(error.into()),
    };
    finish_peer(operation, peer).await
}

#[tokio::test]
async fn ipv6_only_and_empty_dns_answers_fail_before_proxy_contact() -> TestResult<()> {
    let proxy = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    proxy.set_nonblocking(true)?;
    let address = proxy.local_addr()?;
    for addresses in [vec![], vec![IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)]] {
        let expected = if addresses.is_empty() {
            Socks4ErrorKind::Resolve
        } else {
            Socks4ErrorKind::UnsupportedTarget
        };
        let resolver = AddressResolver::from_fn(move |_| {
            let addresses = addresses.clone();
            async move { Ok(addresses) }
        });
        let client = Client::builder(chrome::v154_windows())
            .dns_resolver(resolver)
            .route(Route::socks4(Socks4Proxy::new(&format!(
                "socks4://{address}"
            ))?))
            .build()?;
        let error = client
            .get(HttpProtocol::Http1, "http://origin.socks4.test/")?
            .send()
            .await
            .err()
            .ok_or("operation unexpectedly succeeded")?;
        assert_eq!(socks_error(&error)?.kind(), expected);
    }
    assert!(matches!(proxy.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

#[tokio::test]
async fn refused_proxy_keeps_connection_cause_and_never_uses_direct_route() -> TestResult<()> {
    let origin = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    origin.set_nonblocking(true)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    drop(listener);
    let client = Client::builder(chrome::v154_windows())
        .route(Route::socks4(Socks4Proxy::new(&format!(
            "socks4://{address}"
        ))?))
        .build()?;
    let error = tokio::time::timeout(
        Duration::from_secs(5),
        client
            .get(
                HttpProtocol::Http1,
                &format!("http://{}/", origin.local_addr()?),
            )?
            .send(),
    )
    .await?
    .err()
    .ok_or("operation unexpectedly succeeded")?;
    assert_eq!(error.kind(), RequestErrorKind::Proxy);
    let source = socks_error(&error)?;
    assert_eq!(source.kind(), Socks4ErrorKind::Connect);
    assert!(
        std::error::Error::source(source)
            .and_then(|error| error.downcast_ref::<io::Error>())
            .is_some()
    );
    assert!(matches!(origin.accept(), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    Ok(())
}

fn socks_error<'a>(error: &'a (dyn std::error::Error + 'static)) -> TestResult<&'a Socks4Error> {
    let mut current = Some(error);
    while let Some(source) = current {
        if let Some(source) = source.downcast_ref::<Socks4Error>() {
            return Ok(source);
        }
        current = source.source();
    }
    Err("missing SOCKS4 error source".into())
}

async fn finish_peer(
    operation: TestResult<()>,
    mut peer: ConnectionPeer<TestResult<()>>,
) -> TestResult<()> {
    if operation.is_err() {
        return finish_with_cleanup(operation, peer.stop().await);
    }

    match tokio::time::timeout(Duration::from_secs(5), &mut peer).await {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(error.into()),
        Err(error) => finish_with_cleanup(Err(error.into()), peer.stop().await),
    }
}

struct ObservedConnect {
    address: [u8; 4],
    port: u16,
    user_id: String,
    domain: Option<String>,
}

async fn read_connect(stream: &mut TcpStream) -> TestResult<ObservedConnect> {
    let mut header = [0; 8];
    stream.read_exact(&mut header).await?;
    assert_eq!(&header[..2], &[4, 1]);
    let user_id = read_terminated(stream, 255).await?;
    let address = [header[4], header[5], header[6], header[7]];
    let domain = if address[..3] == [0, 0, 0] && address[3] != 0 {
        Some(read_terminated(stream, 253).await?)
    } else {
        None
    };
    Ok(ObservedConnect {
        address,
        port: u16::from_be_bytes([header[2], header[3]]),
        user_id,
        domain,
    })
}

async fn read_terminated(stream: &mut TcpStream, limit: usize) -> TestResult<String> {
    let mut bytes = Vec::new();
    for _ in 0..=limit {
        let byte = stream.read_u8().await?;
        if byte == 0 {
            return Ok(String::from_utf8(bytes)?);
        }
        bytes.push(byte);
    }
    Err("unterminated SOCKS4 field".into())
}

async fn forward_one(listener: TcpListener, origin: SocketAddr) -> TestResult<ObservedConnect> {
    let (mut downstream, _) = listener.accept().await?;
    let observed = read_connect(&mut downstream).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    downstream.write_all(&[0, 90, 0, 0, 0, 0, 0, 0]).await?;
    match copy_bidirectional(&mut downstream, &mut upstream).await {
        Ok(_) => {}
        Err(error) if is_peer_gone(&error) => {}
        Err(error) => return Err(error.into()),
    }
    Ok(observed)
}
