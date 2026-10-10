//! A client certificate chosen by host and port with
//! `ClientBuilder::client_certificate_for`.
//!
//! Each origin requires a certificate from one authority. The client's other
//! certificates come from other authorities, so a request succeeds only when
//! the origin's own certificate reaches it.

use std::{
    future::poll_fn,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    num::NonZeroUsize,
    time::Duration,
};

use btls::{
    ssl::{SslAcceptor, SslVerifyMode},
    x509::X509,
};
use http::{Response, StatusCode};
use phantom::{
    AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, BuildErrorKind, Client, ClientBuilder,
    ConnectUdpProxy, HttpProtocol, HttpProxy, RedirectPolicy, RequestError, ResponseInfo, Route,
    Socks5Proxy,
    profile::{ClientProfile, SignatureScheme, TlsVersion, browser::chrome},
};
use rcgen::{KeyPair, PKCS_ECDSA_P384_SHA384};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_btls::SslStream;

use super::{TEST_TIMEOUT, acceptor, get, serve_one, serve_one_http3, tls};
use crate::support::{
    client_certificate::{ClientIdentity, quic_endpoint_requiring},
    h3::client_settings as http3_settings,
    masque::{MasqueProxy, ProxyMode, masque_client_settings},
    socks5::forward_one_socks5,
    tls::{
        H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls, accept_tls_stream, client_builder,
        is_peer_gone, read_head, tls_settings,
    },
    tunnel_proxy::{
        ConnectionPeer, finish_with_cleanup, https1_connect_recording_client_certificate,
    },
};

/// A name the client resolves to the loopback address.
const ORIGIN: &str = "origin.test";

async fn bind() -> TestResult<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    Ok((listener, address))
}

/// An HTTP/1.1 client over TLS 1.3 that trusts `server`.
fn http1_builder(server: &TestIdentity) -> ClientBuilder {
    Client::builder(ClientProfile::new(tls(TlsVersion::Tls13)))
        .add_root_certificate_der(server.root_der.clone())
}

/// A TLS acceptor offering `alpn` that requires a certificate issued by one
/// of `authorities`, and can resume the sessions it issues.
fn requiring(
    server: &TestIdentity,
    alpn: &'static [u8],
    authorities: &[&[u8]],
) -> TestResult<SslAcceptor> {
    let mut builder = server.acceptor_builder(alpn)?;
    for authority in authorities {
        builder
            .cert_store_mut()
            .add_cert(X509::from_der(authority)?)?;
    }
    builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    // A server that requires a client certificate resumes sessions only
    // under a session ID context.
    builder.set_session_id_context(b"per-origin")?;
    Ok(builder.build())
}

fn presented(stream: &SslStream<TcpStream>) -> TestResult<Option<Vec<u8>>> {
    Ok(stream
        .ssl()
        .peer_certificate()
        .map(|certificate| certificate.to_der())
        .transpose()?)
}

/// Serves one HTTP/2 request over TLS and returns the client certificate the
/// handshake received.
async fn serve_one_http2(
    listener: TcpListener,
    acceptor: SslAcceptor,
) -> TestResult<Option<Vec<u8>>> {
    let stream = accept_tls(listener, acceptor).await?;
    let presented = presented(&stream)?;
    let mut connection = ::http2::server::handshake(stream).await?;
    let (_, mut respond) = connection
        .accept()
        .await
        .ok_or("connection closed before a request")??;
    respond.send_response(
        Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(())?,
        true,
    )?;
    connection.graceful_shutdown();
    match poll_fn(|context| connection.poll_closed(context)).await {
        Err(error) if !error.get_io().is_some_and(is_peer_gone) => return Err(error.into()),
        _ => {}
    }
    Ok(presented)
}

/// Serves one HTTP/1.1 request on its own connection, which it then closes,
/// and returns the client certificate and whether the session was resumed.
async fn serve_one_and_close(
    listener: &TcpListener,
    acceptor: &SslAcceptor,
) -> TestResult<(Option<Vec<u8>>, bool)> {
    let (tcp, _) = listener.accept().await?;
    let mut stream = accept_tls_stream(tcp, acceptor.clone()).await?;
    let result = (presented(&stream)?, stream.ssl().session_reused());
    read_head(&mut stream).await?;
    stream
        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
        .await?;
    stream.shutdown().await?;
    Ok(result)
}

#[tokio::test]
async fn each_origin_receives_its_own_certificate_over_http1() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let first = ClientIdentity::p256()?;
    let second = ClientIdentity::p256()?;
    let (first_listener, first_address) = bind().await?;
    let (second_listener, second_address) = bind().await?;
    let client = http1_builder(&server)
        .client_certificate_for(&format!("https://{first_address}"), first.certificate()?)
        .client_certificate_for(&format!("https://{second_address}"), second.certificate()?)
        .build()?;

    let first_acceptor = acceptor(&server, Some(&first.authority_der))?;
    let second_acceptor = acceptor(&server, Some(&second.authority_der))?;
    let (first_presented, second_presented, first_status, second_status) =
        timeout(TEST_TIMEOUT, async {
            tokio::join!(
                serve_one(first_listener, first_acceptor),
                serve_one(second_listener, second_acceptor),
                get(&client, format!("https://{first_address}/")),
                get(&client, format!("https://{second_address}/")),
            )
        })
        .await?;

    assert_eq!(first_status?, StatusCode::NO_CONTENT);
    assert_eq!(second_status?, StatusCode::NO_CONTENT);
    assert_eq!(first_presented?, Some(first.leaf_der));
    assert_eq!(second_presented?, Some(second.leaf_der));
    Ok(())
}

#[tokio::test]
async fn an_unmapped_origin_receives_the_client_wide_certificate() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let mapped = ClientIdentity::p256()?;
    let default = ClientIdentity::p256()?;
    let (mapped_listener, mapped_address) = bind().await?;
    let (other_listener, other_address) = bind().await?;
    let client = http1_builder(&server)
        .client_certificate(default.certificate()?)
        .client_certificate_for(&format!("https://{mapped_address}"), mapped.certificate()?)
        .build()?;

    let mapped_acceptor = acceptor(&server, Some(&mapped.authority_der))?;
    let default_acceptor = acceptor(&server, Some(&default.authority_der))?;
    let (mapped_presented, other_presented, mapped_status, other_status) =
        timeout(TEST_TIMEOUT, async {
            tokio::join!(
                serve_one(mapped_listener, mapped_acceptor),
                serve_one(other_listener, default_acceptor),
                get(&client, format!("https://{mapped_address}/")),
                get(&client, format!("https://{other_address}/")),
            )
        })
        .await?;

    assert_eq!(mapped_status?, StatusCode::NO_CONTENT);
    assert_eq!(other_status?, StatusCode::NO_CONTENT);
    assert_eq!(mapped_presented?, Some(mapped.leaf_der));
    assert_eq!(other_presented?, Some(default.leaf_der));
    Ok(())
}

#[tokio::test]
async fn mapping_applies_over_http2_and_negotiated_requests() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let mapped = ClientIdentity::p256()?;
    let default = ClientIdentity::p256()?;
    for negotiated in [false, true] {
        let (listener, address) = bind().await?;
        let client = client_builder(&server, true)
            .client_certificate(default.certificate()?)
            .client_certificate_for(&format!("https://{address}"), mapped.certificate()?)
            .build()?;
        let uri = format!("https://{address}/");
        let request = async {
            let builder = if negotiated {
                client.get_negotiated(&uri)?
            } else {
                client.get(HttpProtocol::Http2, &uri)?
            };
            Ok::<_, RequestError>(builder.send().await?.status())
        };

        let mapped_acceptor = requiring(&server, H2_ALPN, &[&mapped.authority_der])?;
        let (presented, status) = timeout(TEST_TIMEOUT, async {
            tokio::join!(serve_one_http2(listener, mapped_acceptor), request,)
        })
        .await?;

        assert_eq!(status?, StatusCode::NO_CONTENT, "negotiated: {negotiated}");
        assert_eq!(
            presented?,
            Some(mapped.leaf_der.clone()),
            "negotiated: {negotiated}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn mapping_applies_over_http3() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let mapped = ClientIdentity::p256()?;
    let default = ClientIdentity::p256()?;
    let (address, endpoint) = quic_endpoint_requiring(&server, &mapped.authority_der)?;
    let client = Client::builder(ClientProfile::new(tls_settings()).with_http3(http3_settings()))
        .add_root_certificate_der(server.root_der.clone())
        .client_certificate(default.certificate()?)
        .client_certificate_for(&format!("https://{address}"), mapped.certificate()?)
        .build()?;
    let (done, done_received) = oneshot::channel();

    let (presented, status) = timeout(TEST_TIMEOUT, async {
        tokio::join!(serve_one_http3(&endpoint, done_received), async {
            let status = client
                .get(HttpProtocol::Http3, &format!("https://{address}/"))?
                .send()
                .await?
                .status();
            let _ = done.send(());
            Ok::<_, RequestError>(status)
        })
    })
    .await?;

    assert_eq!(status?, StatusCode::NO_CONTENT);
    assert_eq!(presented?, Some(mapped.leaf_der));
    Ok(())
}

/// A client for `origin.test` that maps `origin_port` to `origin_identity`
/// and, as a decoy, the alternative's own port to another certificate.
fn alternative_client(
    server: &TestIdentity,
    origin_port: u16,
    origin_identity: &ClientIdentity,
    alternative_port: u16,
) -> TestResult<ClientBuilder> {
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chrome::v154_http2())
        .with_http3(http3_settings());
    Ok(Client::builder(profile)
        .add_root_certificate_der(server.root_der.clone())
        .resolve(ORIGIN, [IpAddr::V4(Ipv4Addr::LOCALHOST)])
        .alt_svc(NonZeroUsize::MIN)
        .client_certificate_for(
            &format!("https://{ORIGIN}:{origin_port}"),
            origin_identity.certificate()?,
        )
        .client_certificate_for(
            &format!("https://{ORIGIN}:{alternative_port}"),
            ClientIdentity::p256()?.certificate()?,
        ))
}

#[tokio::test]
async fn a_pinned_alternative_receives_the_origin_s_certificate() -> TestResult<()> {
    let server = TestIdentity::generate_for_dns(ORIGIN)?;
    let mapped = ClientIdentity::p256()?;
    let (address, endpoint) = quic_endpoint_requiring(&server, &mapped.authority_der)?;
    let client = alternative_client(&server, 443, &mapped, address.port())?.build()?;
    let (done, done_received) = oneshot::channel();

    let (presented, status) = timeout(TEST_TIMEOUT, async {
        tokio::join!(serve_one_http3(&endpoint, done_received), async {
            let status = client
                .get(HttpProtocol::Http3, &format!("https://{ORIGIN}/"))?
                .alt_svc_alternative(ORIGIN, address.port())
                .send()
                .await?
                .status();
            let _ = done.send(());
            Ok::<_, RequestError>(status)
        })
    })
    .await?;

    assert_eq!(status?, StatusCode::NO_CONTENT);
    assert_eq!(presented?, Some(mapped.leaf_der));
    Ok(())
}

#[tokio::test]
async fn a_learned_alternative_receives_the_origin_s_certificate() -> TestResult<()> {
    let race = AltSvcPolicy::race(AltSvcRace::new(
        // Long enough that only the alternative connects.
        Duration::from_secs(30),
        AltSvcBrokenBackoff::CHROMIUM_153,
    ));
    for policy in [AltSvcPolicy::sequential(), race] {
        let server = TestIdentity::generate_for_dns(ORIGIN)?;
        let mapped = ClientIdentity::p256()?;
        let (origin_listener, origin_address) = bind().await?;
        let (alternative, endpoint) = quic_endpoint_requiring(&server, &mapped.authority_der)?;
        let client =
            alternative_client(&server, origin_address.port(), &mapped, alternative.port())?
                .alt_svc_policy(policy)
                .build()?;
        let uri = format!("https://{ORIGIN}:{}/", origin_address.port());
        let advertisement = format!(
            "HTTP/1.1 204 No Content\r\nAlt-Svc: h3=\":{}\"; ma=60\r\n\r\n",
            alternative.port()
        );
        let origin = async {
            let mut stream = accept_tls(
                origin_listener,
                acceptor(&server, Some(&mapped.authority_der))?,
            )
            .await?;
            let presented = presented(&stream)?;
            read_head(&mut stream).await?;
            stream.write_all(advertisement.as_bytes()).await?;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>(presented)
        };

        let (origin_presented, learned) = timeout(TEST_TIMEOUT, async {
            tokio::join!(origin, async {
                Ok::<_, RequestError>(client.get_negotiated(&uri)?.send().await?.status())
            })
        })
        .await?;
        assert_eq!(learned?, StatusCode::NO_CONTENT, "{policy:?}");
        assert_eq!(
            origin_presented?,
            Some(mapped.leaf_der.clone()),
            "{policy:?}"
        );

        let (done, done_received) = oneshot::channel();
        let (presented, response) = timeout(TEST_TIMEOUT, async {
            tokio::join!(serve_one_http3(&endpoint, done_received), async {
                let response = client.get_negotiated(&uri)?.send().await?;
                let _ = done.send(());
                Ok::<_, RequestError>(response)
            })
        })
        .await?;
        let response = response?;
        assert_eq!(response.status(), StatusCode::NO_CONTENT, "{policy:?}");
        let info = response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("response omitted ResponseInfo")?;
        assert_eq!(info.protocol(), HttpProtocol::Http3, "{policy:?}");
        assert_eq!(presented?, Some(mapped.leaf_der.clone()), "{policy:?}");
    }
    Ok(())
}

#[tokio::test]
async fn a_session_ticket_is_never_offered_to_another_host_and_port() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let mapped = ClientIdentity::p256()?;
    let default = ClientIdentity::p256()?;
    let (first_listener, first_address) = bind().await?;
    let (second_listener, second_address) = bind().await?;
    // One acceptor, so either listener could resume the other's session.
    let acceptor = requiring(
        &server,
        H1_ALPN,
        &[&mapped.authority_der, &default.authority_der],
    )?;
    let client = http1_builder(&server)
        .client_certificate(default.certificate()?)
        .client_certificate_for(&format!("https://{first_address}"), mapped.certificate()?)
        .build()?;

    let served = async {
        let first = serve_one_and_close(&first_listener, &acceptor).await?;
        let resumed = serve_one_and_close(&first_listener, &acceptor).await?;
        let other = serve_one_and_close(&second_listener, &acceptor).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>([first, resumed, other])
    };
    let requests = async {
        for address in [first_address, first_address, second_address] {
            assert_eq!(
                get(&client, format!("https://{address}/")).await?,
                StatusCode::NO_CONTENT
            );
        }
        Ok::<_, RequestError>(())
    };
    let (served, requested) =
        timeout(TEST_TIMEOUT, async { tokio::join!(served, requests) }).await?;
    requested?;
    let [first, resumed, other] = served?;

    assert_eq!(first, (Some(mapped.leaf_der.clone()), false));
    // The positive control: the first origin's ticket works there.
    assert!(resumed.1, "the origin's own ticket was not offered");
    assert_eq!(other, (Some(default.leaf_der), false));
    Ok(())
}

/// Sends `hello`, expects `echo:hello`, and completes the Close handshake.
#[cfg(feature = "websocket")]
async fn exchange_echo(mut socket: phantom::WebSocket) -> TestResult<()> {
    use phantom::{WebSocketCloseFrame, WebSocketMessage};

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
    Ok(())
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn a_wss_opening_over_http1_presents_the_origin_s_certificate() -> TestResult<()> {
    use crate::support::websocket_origin::serve_h1_echo;

    let server = TestIdentity::generate()?;
    let mapped = ClientIdentity::p256()?;
    let default = ClientIdentity::p256()?;
    let (listener, address) = bind().await?;
    let origin = ConnectionPeer::spawn(serve_h1_echo(
        listener,
        acceptor(&server, Some(&mapped.authority_der))?,
    ));
    let client = client_builder(&server, false)
        .client_certificate(default.certificate()?)
        .client_certificate_for(&format!("wss://{address}"), mapped.certificate()?)
        .build()?;

    timeout(TEST_TIMEOUT, async {
        let socket = client
            .websocket(&format!("wss://{address}/"))?
            .connect()
            .await?;
        exchange_echo(socket).await?;
        origin.await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await?
}

#[cfg(feature = "websocket")]
#[tokio::test]
async fn a_wss_opening_over_http2_presents_the_origin_s_certificate() -> TestResult<()> {
    use phantom::profile::Http2PseudoHeader;

    use crate::support::websocket_origin::serve_h2_echo;

    let server = TestIdentity::generate()?;
    let mapped = ClientIdentity::p256()?;
    let default = ClientIdentity::p256()?;
    let (listener, address) = bind().await?;
    let origin = ConnectionPeer::spawn(serve_h2_echo(
        listener,
        requiring(&server, H2_ALPN, &[&mapped.authority_der])?,
    ));
    let mut http2 = chrome::v154_http2();
    http2.extended_connect_pseudo_header_order = Some(vec![
        Http2PseudoHeader::Method,
        Http2PseudoHeader::Protocol,
        Http2PseudoHeader::Authority,
        Http2PseudoHeader::Scheme,
        Http2PseudoHeader::Path,
    ]);
    let client = Client::builder(ClientProfile::new(tls_settings()).with_http2(http2))
        .add_root_certificate_der(server.root_der.clone())
        .client_certificate(default.certificate()?)
        .client_certificate_for(&format!("wss://{address}"), mapped.certificate()?)
        .build()?;

    timeout(TEST_TIMEOUT, async {
        let socket = client
            .websocket_with_protocol(HttpProtocol::Http2, &format!("wss://{address}/"))?
            .connect()
            .await?;
        exchange_echo(socket).await?;
        origin.await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    })
    .await?
}

#[tokio::test]
async fn an_http_proxy_tunnel_carries_the_mapped_certificate_to_the_origin_only() -> TestResult<()>
{
    let origin = TestIdentity::generate()?;
    let proxy = TestIdentity::generate()?;
    let mapped = ClientIdentity::p256()?;
    let (origin_listener, origin_address) = bind().await?;
    let (proxy_listener, proxy_address) = bind().await?;
    // The proxy sends a CertificateRequest and accepts whatever comes back.
    let mut proxy_acceptor = proxy.acceptor_builder(H1_ALPN)?;
    proxy_acceptor.set_verify_callback(SslVerifyMode::PEER, |_, _| true);
    let proxy_task = ConnectionPeer::spawn(https1_connect_recording_client_certificate(
        proxy_listener,
        proxy_acceptor.build(),
        origin_address,
    ));
    let client = http1_builder(&origin)
        .add_proxy_root_certificate_der(proxy.root_der.clone())
        .route(Route::http_proxy(HttpProxy::new(&format!(
            "https://{proxy_address}"
        ))?))
        .client_certificate_for(&format!("https://{origin_address}"), mapped.certificate()?)
        .client_certificate_for(&format!("https://{proxy_address}"), mapped.certificate()?)
        .build()?;

    let mapped_acceptor = acceptor(&origin, Some(&mapped.authority_der))?;
    let (presented_to_origin, status) = timeout(TEST_TIMEOUT, async {
        tokio::join!(
            serve_one(origin_listener, mapped_acceptor),
            get(&client, format!("https://{origin_address}/"))
        )
    })
    .await?;

    assert_eq!(status?, StatusCode::NO_CONTENT);
    assert_eq!(presented_to_origin?, Some(mapped.leaf_der));
    assert_eq!(
        timeout(TEST_TIMEOUT, proxy_task).await???.cancel().await?,
        None
    );
    Ok(())
}

#[tokio::test]
async fn a_socks5_tunnel_carries_the_mapped_certificate_to_the_origin() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let mapped = ClientIdentity::p256()?;
    let default = ClientIdentity::p256()?;
    let (origin_listener, origin_address) = bind().await?;
    let (proxy_listener, proxy_address) = bind().await?;
    let proxy = ConnectionPeer::spawn(forward_one_socks5(proxy_listener, origin_address));
    let client = http1_builder(&server)
        .route(Route::socks5(Socks5Proxy::new(&format!(
            "socks5://{proxy_address}"
        ))?))
        .client_certificate(default.certificate()?)
        .client_certificate_for(&format!("https://{origin_address}"), mapped.certificate()?)
        .build()?;

    let mapped_acceptor = acceptor(&server, Some(&mapped.authority_der))?;
    let (presented, status) = timeout(TEST_TIMEOUT, async {
        tokio::join!(
            serve_one(origin_listener, mapped_acceptor),
            get(&client, format!("https://{origin_address}/"))
        )
    })
    .await?;
    let primary: TestResult<_> = async { Ok((status?, presented?)) }.await;
    let (status, presented) = finish_with_cleanup(primary, proxy.stop().await)?;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(presented, Some(mapped.leaf_der));
    Ok(())
}

#[tokio::test]
async fn a_connect_udp_tunnel_carries_the_mapped_certificate_to_the_origin_only() -> TestResult<()>
{
    let origin = TestIdentity::generate()?;
    let proxy_identity = TestIdentity::generate()?;
    let mapped = ClientIdentity::p256()?;
    let (address, endpoint) = quic_endpoint_requiring(&origin, &mapped.authority_der)?;
    let proxy = MasqueProxy::spawn_requesting_client_certificates(
        &proxy_identity,
        ProxyMode::Relay,
        &mapped.authority_der,
    )?;
    let profile = ClientProfile::new(tls_settings())
        .with_http2(chrome::v154_http2())
        .with_http3(masque_client_settings());
    let client = Client::builder(profile)
        .add_root_certificate_der(origin.root_der.clone())
        .add_proxy_root_certificate_der(proxy_identity.root_der.clone())
        .route(Route::connect_udp(ConnectUdpProxy::new(&proxy.template())?))
        .client_certificate_for(&format!("https://{address}"), mapped.certificate()?)
        .client_certificate_for(&format!("https://{}", proxy.address), mapped.certificate()?)
        .build()?;
    let (done, done_received) = oneshot::channel();

    let (presented, status) = timeout(TEST_TIMEOUT, async {
        tokio::join!(serve_one_http3(&endpoint, done_received), async {
            let status = client
                .get(HttpProtocol::Http3, &format!("https://{address}/"))?
                .send()
                .await?
                .status();
            let _ = done.send(());
            Ok::<_, RequestError>(status)
        })
    })
    .await?;

    assert_eq!(status?, StatusCode::NO_CONTENT);
    assert_eq!(presented?, Some(mapped.leaf_der));
    assert_eq!(proxy.connections(), 1);
    assert_eq!(proxy.client_certificates(), 0);
    Ok(())
}

#[tokio::test]
async fn each_redirect_hop_presents_its_own_origin_s_certificate() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let first = ClientIdentity::p256()?;
    let second = ClientIdentity::p256()?;
    let (first_listener, first_address) = bind().await?;
    let (second_listener, second_address) = bind().await?;
    let client = http1_builder(&server)
        .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
        .client_certificate_for(&format!("https://{first_address}"), first.certificate()?)
        .client_certificate_for(&format!("https://{second_address}"), second.certificate()?)
        .build()?;
    let redirect = format!(
        "HTTP/1.1 302 Found\r\nLocation: https://{second_address}/next\r\nContent-Length: 0\r\n\r\n"
    );
    let redirecting = async {
        let mut stream = accept_tls(
            first_listener,
            acceptor(&server, Some(&first.authority_der))?,
        )
        .await?;
        let presented = presented(&stream)?;
        read_head(&mut stream).await?;
        stream.write_all(redirect.as_bytes()).await?;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(presented)
    };

    let second_acceptor = acceptor(&server, Some(&second.authority_der))?;
    let (first_presented, second_presented, status) = timeout(TEST_TIMEOUT, async {
        tokio::join!(
            redirecting,
            serve_one(second_listener, second_acceptor),
            get(&client, format!("https://{first_address}/"))
        )
    })
    .await?;

    assert_eq!(status?, StatusCode::NO_CONTENT);
    assert_eq!(first_presented?, Some(first.leaf_der));
    assert_eq!(second_presented?, Some(second.leaf_der));
    Ok(())
}

#[tokio::test]
async fn a_later_mapping_for_the_same_origin_replaces_the_earlier_one() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let replaced = ClientIdentity::p256()?;
    let mapped = ClientIdentity::p256()?;
    let (listener, address) = bind().await?;
    let client = http1_builder(&server)
        .client_certificate_for(&format!("https://{address}"), replaced.certificate()?)
        .client_certificate_for(&format!("wss://{address}/"), mapped.certificate()?)
        .build()?;

    let mapped_acceptor = acceptor(&server, Some(&mapped.authority_der))?;
    let (presented, status) = timeout(TEST_TIMEOUT, async {
        tokio::join!(
            serve_one(listener, mapped_acceptor),
            get(&client, format!("https://{address}/"))
        )
    })
    .await?;

    assert_eq!(status?, StatusCode::NO_CONTENT);
    assert_eq!(presented?, Some(mapped.leaf_der));
    Ok(())
}

#[tokio::test]
async fn a_mapping_matches_however_the_host_is_written() -> TestResult<()> {
    let server = TestIdentity::generate_for_dns(ORIGIN)?;
    let mapped = ClientIdentity::p256()?;
    let (listener, address) = bind().await?;
    let client = http1_builder(&server)
        .resolve(ORIGIN, [IpAddr::V4(Ipv4Addr::LOCALHOST)])
        .client_certificate_for(
            &format!("https://ORIGIN.Test:{}/", address.port()),
            mapped.certificate()?,
        )
        .build()?;

    let mapped_acceptor = acceptor(&server, Some(&mapped.authority_der))?;
    let (presented, status) = timeout(TEST_TIMEOUT, async {
        tokio::join!(
            serve_one(listener, mapped_acceptor),
            get(&client, format!("https://origin.TEST:{}/", address.port()))
        )
    })
    .await?;

    assert_eq!(status?, StatusCode::NO_CONTENT);
    assert_eq!(presented?, Some(mapped.leaf_der));
    Ok(())
}

#[test]
fn a_malformed_origin_is_an_invalid_policy() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let identity = ClientIdentity::p256()?;
    for origin in [
        "example.com",
        "http://a.test",
        "ws://a.test",
        "https://a.test/path",
        "https://a.test/?q",
        "https://a.test#f",
        "https://user@a.test",
        "https://a.test:99999",
        "https://exa mple.test",
    ] {
        let error = http1_builder(&server)
            .client_certificate_for(origin, identity.certificate()?)
            .build()
            .err()
            .ok_or_else(|| format!("{origin:?} was accepted"))?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy, "{origin:?}");
    }
    Ok(())
}

#[test]
fn a_mapped_certificate_the_profile_cannot_sign_with_is_an_invalid_policy() -> TestResult<()> {
    let server = TestIdentity::generate()?;
    let mut rsa_only = tls(TlsVersion::Tls13);
    rsa_only.signature_schemes = vec![SignatureScheme::RsaPssRsaeSha256];
    let p384 = ClientIdentity::issue(KeyPair::generate_for(&PKCS_ECDSA_P384_SHA384)?)?;
    for (tls, certificate) in [
        (rsa_only, ClientIdentity::p256()?.certificate()?),
        (tls(TlsVersion::Tls13), p384.certificate()?),
    ] {
        let error = Client::builder(ClientProfile::new(tls))
            .add_root_certificate_der(server.root_der.clone())
            .client_certificate_for("https://a.test", certificate)
            .build()
            .err()
            .ok_or("a profile without a usable signature scheme was accepted")?;
        assert_eq!(error.kind(), BuildErrorKind::InvalidPolicy);
    }
    Ok(())
}
