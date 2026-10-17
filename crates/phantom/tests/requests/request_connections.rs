//! Connection metadata from actual handshakes and pooled dispatches.

use std::{net::Ipv4Addr, num::NonZeroUsize, sync::Arc, time::Duration};

use phantom::{
    ConnectionEndpointScope, HttpProtocol, RequestConnection, RequestTimingPhase,
    TlsConnectionInfo, TlsConnectionState,
};
use tokio::{io::AsyncWriteExt, net::TcpListener, time::timeout};

use crate::support::{
    h2, h3 as h3_support,
    tls::{H1_ALPN, H2_ALPN, TestIdentity, TestResult, accept_tls, read_head, tls_settings},
    tunnel_proxy::{ConnectionPeer, finish_with_cleanup},
};

fn established(state: &TlsConnectionState) -> TestResult<&Arc<TlsConnectionInfo>> {
    match state {
        TlsConnectionState::Established(info) => Ok(info),
        _ => Err(format!("expected completed TLS, got {state:?}").into()),
    }
}

fn connection(trace: &phantom::RequestDiagnostics) -> TestResult<Arc<RequestConnection>> {
    let snapshot = trace.snapshot();
    let event = snapshot
        .events
        .iter()
        .find(|event| event.phase == RequestTimingPhase::ConnectionUse)
        .ok_or("missing connection use")?;
    assert_eq!(event.admission, Some(1));
    Ok(Arc::clone(
        event
            .connection
            .as_ref()
            .ok_or("missing connection facts")?,
    ))
}

fn build_client(
    builder: phantom::ClientBuilder,
    identity: &TestIdentity,
    verify: bool,
) -> TestResult<phantom::Client> {
    if verify {
        return Ok(builder
            .add_root_certificate_der(identity.root_der.clone())
            .build()?);
    }
    #[cfg(feature = "danger-disable-verification")]
    return Ok(builder
        .server_authentication(phantom::ServerAuthentication::DangerDisabled)
        .build()?);
    #[cfg(not(feature = "danger-disable-verification"))]
    Err("disabled-verification test requires its feature".into())
}

async fn tcp_reuse(protocol: HttpProtocol, observe_first: bool, verify: bool) -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let h2 = protocol == HttpProtocol::Http2;
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(if h2 { H2_ALPN } else { H1_ALPN })?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let url = format!("https://{address}/");
        let peer = ConnectionPeer::spawn(async move {
            let mut socket = accept_tls(listener, acceptor).await?;
            if h2 {
                h2::accept_client_preface(&mut socket).await?;
            }
            for index in 0..3 {
                if h2 {
                    let stream = 1 + index * 2;
                    h2::read_request_headers(&mut socket, stream).await?;
                    h2::write_frame(&mut socket, 1, 5, stream, &[0x88]).await?;
                } else {
                    read_head(&mut socket).await?;
                    socket
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await?;
                }
                socket.flush().await?;
            }
            Ok(())
        });
        let caller = async {
            let mut tls = tls_settings();
            if !h2 {
                tls.alpn_protocols = vec![Box::from(&b"http/1.1"[..])];
            }
            let mut profile = phantom::profile::ClientProfile::new(tls);
            if h2 {
                profile = profile.with_http2(phantom::profile::browser::chrome::v154_http2());
            }
            let client = build_client(phantom::Client::builder(profile), &identity, verify)?;
            let mut previous = None;
            for index in 0..3 {
                let mut request = client.get(protocol, &url)?;
                let diagnostics = (observe_first || index != 0)
                    .then(|| request.diagnostics(NonZeroUsize::MIN.saturating_add(63)));
                let response = request.send().await?;
                assert_eq!(response.status(), 200);
                assert!(response.into_body().collect_with_limit(0).await?.is_empty());
                if let Some(trace) = diagnostics {
                    let used = connection(&trace)?;
                    assert_eq!(used.reused, index != 0);
                    assert_eq!(used.endpoint_scope, ConnectionEndpointScope::TcpSocket);
                    assert_eq!(used.peer_address, Some(address));
                    assert_eq!(
                        used.local_address.ok_or("missing socket address")?.ip(),
                        Ipv4Addr::LOCALHOST
                    );
                    assert!(matches!(used.proxy_tls, TlsConnectionState::NotUsed));
                    let tls = established(&used.origin_tls)?;
                    assert_eq!(tls.peer_verified, verify);
                    assert!(!tls.session_resumed);
                    assert_eq!(tls.version, Some(phantom::profile::TlsVersion::Tls12));
                    assert_eq!(
                        tls.alpn.as_deref(),
                        Some(if h2 { &b"h2"[..] } else { &b"http/1.1"[..] })
                    );
                    let chain = tls
                        .peer_certificates
                        .as_ref()
                        .ok_or("missing certificates")?;
                    assert!(!chain.is_empty());
                    btls::x509::X509::from_der(&chain[0])?;
                    if let Some(previous) = previous {
                        assert!(Arc::ptr_eq(&previous, tls));
                    }
                    previous = Some(Arc::clone(tls));
                }
            }
            Ok(())
        };
        finish_with_cleanup(caller.await, peer.stop().await)
    })
    .await?
}

#[tokio::test]
async fn tcp_metadata_distinguishes_fresh_and_reused_http_connections() -> TestResult<()> {
    for protocol in [HttpProtocol::Http1, HttpProtocol::Http2] {
        tcp_reuse(protocol, true, true).await?;
    }
    Ok(())
}

#[tokio::test]
async fn pooled_tcp_metadata_survives_an_unobserved_handshake() -> TestResult<()> {
    for protocol in [HttpProtocol::Http1, HttpProtocol::Http2] {
        tcp_reuse(protocol, false, true).await?;
    }
    Ok(())
}

#[tokio::test]
async fn quic_metadata_survives_pooling_and_an_unobserved_handshake() -> TestResult<()> {
    quic_reuse(true).await
}

#[cfg(feature = "danger-disable-verification")]
#[tokio::test]
async fn certificates_do_not_imply_peer_verification() -> TestResult<()> {
    for protocol in [HttpProtocol::Http1, HttpProtocol::Http2] {
        tcp_reuse(protocol, true, false).await?;
    }
    quic_reuse(false).await
}

async fn quic_reuse(verify: bool) -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let identity = TestIdentity::generate()?;
        let (address, endpoint) = h3_support::server_endpoint(&identity)?;
        let peer = ConnectionPeer::spawn(async move {
            let incoming = endpoint.accept().await.ok_or("endpoint closed")?;
            let connection = incoming.await?;
            let mut connection: h3::server::Connection<_, bytes::Bytes> =
                h3::server::Connection::new(h3_quinn::Connection::new(connection)).await?;
            for _ in 0..3 {
                let resolver = connection.accept().await?.ok_or("connection closed")?;
                let (_, mut stream) = resolver.resolve_request().await?;
                stream.send_response(http::Response::new(())).await?;
                stream.finish().await?;
            }
            endpoint.wait_idle().await;
            Ok(())
        });
        let caller = async {
            let builder = phantom::Client::builder(
                phantom::profile::ClientProfile::new(h3_support::client_tls_settings())
                    .with_http3(h3_support::client_settings()),
            );
            let client = build_client(builder, &identity, verify)?;
            let mut previous = None;
            for index in 0..3 {
                let mut request =
                    client.get(HttpProtocol::Http3, &format!("https://{address}/"))?;
                let trace =
                    (index != 0).then(|| request.diagnostics(NonZeroUsize::MIN.saturating_add(63)));
                let response = request.send().await?;
                assert_eq!(response.status(), 200);
                response.into_body().collect_with_limit(0).await?;
                if let Some(trace) = trace {
                    let used = connection(&trace)?;
                    assert!(used.reused);
                    assert_eq!(used.endpoint_scope, ConnectionEndpointScope::QuicEndpoint);
                    assert_eq!(used.peer_address, Some(address));
                    assert!(used.local_address.is_some());
                    assert!(matches!(used.proxy_tls, TlsConnectionState::NotUsed));
                    let tls = established(&used.origin_tls)?;
                    assert_eq!(tls.peer_verified, verify);
                    assert!(!tls.session_resumed);
                    assert_eq!(tls.version, Some(phantom::profile::TlsVersion::Tls13));
                    assert_eq!(
                        tls.cipher_suite,
                        Some(phantom::profile::CipherSuite::Aes128GcmSha256)
                    );
                    assert_eq!(tls.alpn.as_deref(), Some(&b"h3"[..]));
                    let chain = tls
                        .peer_certificates
                        .as_ref()
                        .ok_or("missing QUIC certificates")?;
                    assert!(!chain.is_empty());
                    btls::x509::X509::from_der(&chain[0])?;
                    if let Some(previous) = previous {
                        assert!(Arc::ptr_eq(&previous, tls));
                    }
                    previous = Some(Arc::clone(tls));
                }
            }
            drop(client);
            Ok(())
        };
        finish_with_cleanup(caller.await, peer.stop().await)
    })
    .await?
}
