//! Actual outer TLS; forwarding never creates a CONNECT or origin TLS layer.
use super::{read_plaintext_head, test_connector, test_proxy_connector};
use crate::{
    http1::Http1TlsError,
    proxy::{
        HttpConnectHeader, HttpsProxyConnector, HttpsProxyProtocol, ProxyCredentialCache,
        http1_opening::ProxyBinding,
    },
    request::{AbsoluteForm, RequestHeader},
    route::{Endpoint, HttpConnectRoute, ProxyTransport},
    tcp::{AddressFamily, AddressFamilyMemory, SlowerAttempt},
    tls::test_support::{
        TEST_SERVER_NAME, TEST_TIMEOUT, TestIdentity, TestResult, TestServerAlpn, loopback_listener,
    },
};
use btls::ssl::{Ssl, SslAcceptor};
use http::Method;
use http_body_util::BodyExt;
use std::{future::poll_fn, io, pin::Pin, task::Poll, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf},
    net::TcpStream,
    time::timeout,
};
use tokio_btls::SslStream;

fn transport(port: u16, connector: &HttpsProxyConnector) -> ProxyTransport<'_> {
    ProxyTransport::Tls {
        endpoint: Endpoint {
            host: "127.0.0.1",
            port,
        },
        server_name: TEST_SERVER_NAME,
        connector,
    }
}
async fn accept<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    acceptor: &SslAcceptor,
) -> TestResult<SslStream<S>> {
    let mut tls = SslStream::new(Ssl::new(acceptor.context())?, stream)?;
    Pin::new(&mut tls).accept().await?;
    Ok(tls)
}
async fn closed(stream: &mut (impl AsyncRead + Unpin)) -> TestResult<()> {
    let mut byte = [0];
    match stream.read(&mut byte).await {
        Ok(0) => Ok(()),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::ConnectionReset
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            ) =>
        {
            Ok(())
        }
        result => Err(format!("owned proxy did not close: {result:?}").into()),
    }
}

#[tokio::test]
async fn forward_physical_selection_records_proxy_family_before_tls_and_cancels_handshake()
-> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let proxy = test_proxy_connector(&identity)?.with_tcp_settings(&phantom_profile::browser::firefox::v157_tcp());
        let (address, listener) = loopback_listener().await?;
        let transport = transport(address.port(), &proxy);
        let family = AddressFamilyMemory::default();
        let (opening, slower) = connector.open_https_forward_retaining(transport, &family).await?;
        assert!(slower.is_none());
        assert_eq!(family.family(), Some(AddressFamily::Ipv4));
        let (mut peer, _) = listener.accept().await?;
        let mut byte = [0];
        assert!(matches!(peer.try_read(&mut byte), Err(error) if error.kind() == io::ErrorKind::WouldBlock));
        let mut finish = Box::pin(opening.finish_forward(transport));
        let mut record = [0; 5];
        tokio::select! {
            result = &mut finish => { drop(result); return Err("withheld outer TLS finished".into()); }
            result = peer.read_exact(&mut record) => { result?; }
        }
        assert_eq!(record[0], 22);
        drop(finish);
        let mut rest = Vec::new();
        peer.read_to_end(&mut rest).await?;
        assert!(!rest.windows(b"CONNECT ".len()).any(|bytes| bytes == b"CONNECT "));
        assert!(!rest.windows(b"Proxy-Authorization".len()).any(|bytes| bytes == b"Proxy-Authorization"));
        Ok(())
    }).await?
}

#[tokio::test]
async fn forward_slower_owner_finishes_outer_tls_then_claim_sends_current_request_only()
-> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let connector = test_connector(&identity)?;
        let proxy = test_proxy_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        let transport = transport(address.port(), &proxy);
        let attempt = SlowerAttempt::scripted(async move { TcpStream::connect(address).await }, Duration::ZERO, None);
        let slower = connector.slower_proxy_opening(attempt, ProxyBinding::forward(transport).map_err(Http1TlsError::from)?);
        let progress = slower.progress();
        let (quiet, checked) = tokio::sync::oneshot::channel();
        let client = async {
            let opening = slower.finish().await.ok_or("outer TLS spare failed")?;
            assert!(progress.has_connected());
            checked.await?;
            let connection = opening.finish_forward(transport).await?;
            let response = connection.send_forward_request(Method::GET, AbsoluteForm::parse("http://target.invalid/current")?, vec![
                RequestHeader::new("Host", "target.invalid"),
                RequestHeader::new("X-Claim", "current"),
                RequestHeader::new("Cookie", "claim=current"),
                RequestHeader::new("Proxy-Authorization", "Basic dXNlcjpzZWNyZXQ="),
            ], None).await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            TestResult::Ok(())
        };
        let server = async {
            let (tcp, _) = listener.accept().await?;
            let mut tls = accept(tcp, &acceptor).await?;
            let mut byte = [0];
            let mut read = ReadBuf::new(&mut byte);
            assert!(poll_fn(|cx| Poll::Ready(Pin::new(&mut tls).poll_read(cx, &mut read).is_pending())).await);
            quiet.send(()).map_err(|()| "claim ended before quiet proof")?;
            assert_eq!(read_plaintext_head(&mut tls).await?, b"GET http://target.invalid/current HTTP/1.1\r\nHost: target.invalid\r\nX-Claim: current\r\nCookie: claim=current\r\nProxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n");
            tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok").await?;
            TestResult::Ok(())
        };
        tokio::try_join!(client, server)?;
        assert!(poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_pending())).await, "claim redialled");
        Ok(())
    }).await?
}

#[tokio::test]
async fn forward_binding_rejects_changed_cache_credentials_sni_endpoint_and_protocol_before_tls()
-> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let proxy = test_proxy_connector(&identity)?.with_isolated_session_cache().with_proxy_credential_cache(ProxyCredentialCache::new());
        for part in 0..5 {
            let (address, listener) = loopback_listener().await?;
            let (opening, _) = connector.open_https_forward_retaining(transport(address.port(), &proxy), &AddressFamilyMemory::default()).await?;
            let (mut peer, _) = listener.accept().await?;
            let changed = match part {
                0 => proxy.with_isolated_session_cache(),
                1 => proxy.clone().with_proxy_credential_cache(ProxyCredentialCache::new()),
                2 => proxy.clone().with_protocol(HttpsProxyProtocol::Http2),
                _ => proxy.clone(),
            };
            let changed_transport = ProxyTransport::Tls {
                endpoint: Endpoint { host: if part == 3 { "other.invalid" } else { "127.0.0.1" }, port: address.port() },
                server_name: if part == 4 { "other.invalid" } else { TEST_SERVER_NAME }, connector: &changed,
            };
            assert!(matches!(opening.finish_forward(changed_transport).await, Err(Http1TlsError::Connect(error)) if error.kind() == io::ErrorKind::InvalidInput));
            let mut bytes = Vec::new();
            peer.read_to_end(&mut bytes).await?;
            assert!(bytes.is_empty(), "mismatched binding sent outer TLS");
        }
        Ok(())
    }).await?
}

#[tokio::test]
async fn forward_and_connect_purposes_cannot_be_interchanged_before_outer_tls() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let connector = test_connector(&identity)?;
        let proxy = test_proxy_connector(&identity)?;
        for forward in [true, false] {
            let (address, listener) = loopback_listener().await?;
            let transport = transport(address.port(), &proxy);
            let headers = [HttpConnectHeader::authority("Host")];
            let route = HttpConnectRoute { speculative_tls: false, proxy: transport, authority: "target.invalid:443", headers: &headers, credentials: None };
            let family = AddressFamilyMemory::default();
            let (opening, _) = if forward { connector.open_https_forward_retaining(transport, &family).await? }
                else { connector.open_http_connect_retaining(route, "target.invalid", &family).await? };
            let (mut peer, _) = listener.accept().await?;
            let result = if forward { opening.finish(route).await } else { opening.finish_forward(transport).await };
            assert!(matches!(result, Err(Http1TlsError::Connect(error)) if error.kind() == io::ErrorKind::InvalidInput));
            let mut bytes = Vec::new();
            peer.read_to_end(&mut bytes).await?;
            assert!(bytes.is_empty());
        }
        Ok(())
    }).await?
}

#[tokio::test]
async fn forward_outer_tls_verification_failure_closes_supplied_socket_without_redial()
-> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let wrong_identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let connector = test_connector(&identity)?;
        let proxy = test_proxy_connector(&wrong_identity)?;
        let (address, listener) = loopback_listener().await?;
        let transport = transport(address.port(), &proxy);
        let (opening, _) = connector
            .open_https_forward_retaining(transport, &AddressFamilyMemory::default())
            .await?;
        let client = async {
            assert!(matches!(
                opening.finish_forward(transport).await,
                Err(Http1TlsError::Proxy(
                    crate::proxy::HttpConnectError::ProxyTls(_)
                ))
            ));
            TestResult::Ok(())
        };
        let server = async {
            let (tcp, _) = listener.accept().await?;
            assert!(accept(tcp, &acceptor).await.is_err());
            TestResult::Ok(())
        };
        tokio::try_join!(client, server)?;
        assert!(poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_pending())).await);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn unused_forward_spare_closes_verified_outer_tls_without_application_bytes() -> TestResult<()>
{
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(TestServerAlpn::Http1)?;
        let connector = test_connector(&identity)?;
        let proxy = test_proxy_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        let attempt = SlowerAttempt::scripted(
            async move { TcpStream::connect(address).await },
            Duration::ZERO,
            None,
        );
        let slower = connector.slower_proxy_opening(
            attempt,
            ProxyBinding::forward(transport(address.port(), &proxy))
                .map_err(Http1TlsError::from)?,
        );
        let client = async {
            let opening = slower.finish().await.ok_or("outer TLS spare failed")?;
            drop(opening);
            TestResult::Ok(())
        };
        let server = async {
            let (tcp, _) = listener.accept().await?;
            let mut tls = accept(tcp, &acceptor).await?;
            closed(&mut tls).await
        };
        tokio::try_join!(client, server)?;
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn forwarding_retention_rejects_outer_h2_before_proxy_resolution() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let connector = test_connector(&identity)?;
    let proxy = test_proxy_connector(&identity)?.with_protocol(HttpsProxyProtocol::Http2);
    let result = connector
        .open_https_forward_retaining(
            ProxyTransport::Tls {
                endpoint: Endpoint {
                    host: "must-not-resolve.invalid",
                    port: 443,
                },
                server_name: "must-not-resolve.invalid",
                connector: &proxy,
            },
            &AddressFamilyMemory::default(),
        )
        .await;
    assert!(matches!(
        result,
        Err(Http1TlsError::Proxy(
            crate::proxy::HttpConnectError::ForwardingRequiresHttp1
        ))
    ));
    Ok(())
}
