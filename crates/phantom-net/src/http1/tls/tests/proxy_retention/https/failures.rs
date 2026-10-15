use super::*;
use crate::proxy::HttpConnectError;

#[tokio::test]
async fn untrusted_proxy_tls_fails_without_connect_or_origin_tls() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let trusted = TestIdentity::generate()?;
        let wrong = TestIdentity::generate()?;
        let acceptor = wrong.acceptor(TestServerAlpn::Http1)?;
        let connector = super::super::super::test_connector(&trusted)?;
        let proxy = super::super::super::test_proxy_connector(&trusted)?;
        let (address, listener) = loopback_listener().await?;
        let fields = fields("unused", false);
        let route = route(address.port(), &proxy, &fields, None);
        let (opening, _) = connector
            .open_http_connect_retaining(route, TEST_SERVER_NAME, &AddressFamilyMemory::default())
            .await?;
        let client = async {
            assert!(matches!(
                opening.finish(route).await,
                Err(Http1TlsError::Proxy(HttpConnectError::ProxyTls(_)))
            ));
            TestResult::Ok(())
        };
        let server = async {
            let (stream, _) = listener.accept().await?;
            assert!(accept(stream, &acceptor).await.is_err());
            TestResult::Ok(())
        };
        tokio::try_join!(client, server)?;
        assert!(poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_pending())).await);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn an_h2_alpn_on_an_h1_proxy_is_typed_failure_without_connect_or_fallback() -> TestResult<()>
{
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(TestServerAlpn::H2)?;
        let connector = super::super::super::test_connector(&identity)?;
        let proxy = super::super::super::test_proxy_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        let fields = fields("unused", false);
        let route = route(address.port(), &proxy, &fields, None);
        let (opening, _) = connector.open_http_connect_retaining(route, TEST_SERVER_NAME,
            &AddressFamilyMemory::default()).await?;
        let client = async {
            assert!(matches!(opening.finish(route).await,
                Err(Http1TlsError::Proxy(HttpConnectError::UnsupportedAlpn { selected })) if &*selected == b"h2"));
            TestResult::Ok(())
        };
        let server = async {
            let (stream, _) = listener.accept().await?;
            let mut stream = accept(stream, &acceptor).await?;
            closed(&mut stream).await
        };
        tokio::try_join!(client, server)?;
        assert!(poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_pending())).await);
        Ok(())
    }).await?
}

#[tokio::test]
async fn trusted_proxy_does_not_make_an_untrusted_origin_acceptable() -> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let identity = TestIdentity::generate()?;
        let wrong_origin = TestIdentity::generate()?;
        let outer = identity.acceptor(TestServerAlpn::Http1)?;
        let inner = wrong_origin.acceptor(TestServerAlpn::Http1)?;
        let connector = super::super::super::test_connector(&identity)?;
        let proxy = super::super::super::test_proxy_connector(&identity)?;
        let (address, listener) = loopback_listener().await?;
        let fields = fields("claim", false);
        let route = route(address.port(), &proxy, &fields, None);
        let (opening, _) = connector.open_http_connect_retaining(route, TEST_SERVER_NAME,
            &AddressFamilyMemory::default()).await?;
        let client = async {
            assert!(matches!(opening.finish(route).await, Err(Http1TlsError::Tls(_))));
            TestResult::Ok(())
        };
        let server = async {
            let (stream, _) = listener.accept().await?;
            let mut stream = accept(stream, &outer).await?;
            assert_eq!(read_plaintext_head(&mut stream).await?, b"CONNECT server.phantom.test:443 HTTP/1.1\r\nX-Claim: claim\r\nhost: server.phantom.test:443\r\n\r\n");
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;
            assert!(accept(stream, &inner).await.is_err());
            TestResult::Ok(())
        };
        tokio::try_join!(client, server)?;
        Ok(())
    }).await?
}

#[tokio::test]
async fn invalid_https_connect_fields_do_not_consume_dns_or_open_proxy_tls() -> TestResult<()> {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    let identity = TestIdentity::generate()?;
    let connector = super::super::super::test_connector(&identity)?;
    let calls = Arc::new(AtomicUsize::new(0));
    let count = Arc::clone(&calls);
    let resolver = crate::host_resolver::HostResolver::default().with_resolver(
        crate::host_resolver::AddressResolver::from_fn(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            async { Ok(vec![std::net::Ipv4Addr::LOCALHOST.into()]) }
        }),
    );
    let proxy = super::super::super::test_proxy_connector(&identity)?.with_host_resolver(resolver);
    let invalid = [crate::proxy::HttpConnectHeader::field(RequestHeader::new(
        "X-Claim",
        "bad\r\nfield",
    ))];
    let route = HttpConnectRoute {
        proxy: ProxyTransport::Tls {
            endpoint: Endpoint {
                host: "must-not-resolve.invalid",
                port: 443,
            },
            server_name: TEST_SERVER_NAME,
            connector: &proxy,
        },
        authority: "server.phantom.test:443",
        headers: &invalid,
        credentials: None,
    };
    assert!(matches!(
        connector
            .open_http_connect_retaining(route, TEST_SERVER_NAME, &AddressFamilyMemory::default())
            .await,
        Err(Http1TlsError::Proxy(_))
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn disabled_tls_caches_match_only_the_original_configuration() -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let mut settings = super::super::super::tls_settings();
    settings.session_tickets = phantom_profile::SessionTickets::disabled();
    let proxy = HttpsProxyConnector::new_with_additional_roots(&settings, [identity.root_der()])?;
    assert!(proxy.session_ticket_cache().is_none());
    assert!(proxy.same_http1_opening_context(&proxy.clone()));
    assert!(
        !proxy.same_http1_opening_context(&HttpsProxyConnector::new_with_additional_roots(
            &settings,
            [identity.root_der()]
        )?)
    );
    Ok(())
}

#[tokio::test]
async fn failed_slower_outer_tls_returns_no_opening_and_closes_its_owned_socket() -> TestResult<()>
{
    timeout(TEST_TIMEOUT, async {
        let trusted = TestIdentity::generate()?;
        let wrong = TestIdentity::generate()?;
        let acceptor = wrong.acceptor(TestServerAlpn::Http1)?;
        let connector = super::super::super::test_connector(&trusted)?;
        let proxy = super::super::super::test_proxy_connector(&trusted)?;
        let (address, listener) = loopback_listener().await?;
        let fields = fields("unused", false);
        let binding = ProxyBinding::new(
            route(address.port(), &proxy, &fields, None),
            TEST_SERVER_NAME,
        )?;
        let attempt = SlowerAttempt::scripted(
            async move { TcpStream::connect(address).await },
            std::time::Duration::ZERO,
            None,
        );
        let slower = connector.slower_proxy_opening(attempt, binding);
        let client = async {
            assert!(slower.finish().await.is_none());
            TestResult::Ok(())
        };
        let server = async {
            let (stream, _) = listener.accept().await?;
            assert!(accept(stream, &acceptor).await.is_err());
            TestResult::Ok(())
        };
        tokio::try_join!(client, server)?;
        assert!(poll_fn(|cx| Poll::Ready(listener.poll_accept(cx).is_pending())).await);
        Ok(())
    })
    .await?
}
