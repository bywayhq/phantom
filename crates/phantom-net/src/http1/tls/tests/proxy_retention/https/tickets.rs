//! Actual issued TLS 1.3 tickets distinguish the two retained cache owners.
use super::*;
use crate::{
    http1::Http1TlsConnector,
    route::{DirectTlsSetup, Http1Route, Http1Target, OriginRoute, TcpRoute},
};

#[tokio::test]
async fn unused_https_spare_resumes_original_proxy_cache_and_preserves_origin_ticket()
-> TestResult<()> {
    timeout(TEST_TIMEOUT, async {
        let proxy_identity = TestIdentity::generate()?;
        let origin_identity = TestIdentity::generate()?;
        let proxy_acceptor = proxy_identity.acceptor(TestServerAlpn::Http1)?;
        let origin_acceptor = origin_identity.acceptor(TestServerAlpn::Http1)?;
        let mut settings = phantom_profile::browser::chrome::v154_tcp_tls();
        settings.versions =
            phantom_profile::TlsVersionRange::only(phantom_profile::TlsVersion::Tls13);
        settings.session_tickets = phantom_profile::SessionTickets::enabled(1)?;
        settings.tcp_early_data = false;
        let connector =
            Http1TlsConnector::new_with_additional_roots(&settings, [origin_identity.root_der()])?
                .with_isolated_session_cache();
        let proxy =
            HttpsProxyConnector::new_with_additional_roots(&settings, [proxy_identity.root_der()])?
                .with_isolated_session_cache();
        let (proxy_address, proxy_listener) = loopback_listener().await?;
        let (origin_address, origin_listener) = loopback_listener().await?;
        let (quiet, checked) = tokio::sync::oneshot::channel();
        let client = async {
            let request = || async {
                let response = connector
                    .send(
                        Http1Route::Origin(OriginRoute::Tls {
                            tcp: TcpRoute::Direct(Endpoint {
                                host: "127.0.0.1",
                                port: origin_address.port(),
                            }),
                            server_name: TEST_SERVER_NAME,
                            setup: DirectTlsSetup::Default,
                        }),
                        http::Method::GET,
                        Http1Target::Origin(OriginForm::parse("/ticket")?),
                        vec![RequestHeader::new("Host", TEST_SERVER_NAME)],
                        None,
                    )
                    .await?;
                assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
                TestResult::Ok(())
            };
            request().await?;
            let (raw, slower) = proxy
                .open_http1_proxy_retaining(
                    "127.0.0.1",
                    proxy_address.port(),
                    &AddressFamilyMemory::default(),
                )
                .await?;
            assert!(slower.is_none());
            let mut warm = proxy.finish_http1_proxy_tls(raw, TEST_SERVER_NAME).await?;
            let mut byte = [0];
            warm.read_exact(&mut byte).await?; // Process actual post-handshake ticket.
            assert_eq!(&byte, b"x");
            drop(warm);
            let fields = fields("unused", false);
            let binding = ProxyBinding::new(
                route(proxy_address.port(), &proxy, &fields, None),
                TEST_SERVER_NAME,
            )
            .map_err(Http1TlsError::from)?;
            let attempt = SlowerAttempt::scripted(
                async move { TcpStream::connect(proxy_address).await },
                std::time::Duration::ZERO,
                None,
            );
            let opening = connector
                .slower_proxy_opening(attempt, binding)
                .finish()
                .await
                .ok_or("actual resumed proxy spare failed")?;
            checked.await?;
            drop(opening);
            request().await?;
            TestResult::Ok(())
        };
        let proxy_server = async {
            let (stream, _) = proxy_listener.accept().await?;
            let mut warm = accept(stream, &proxy_acceptor).await?;
            assert_eq!(warm.ssl().version2(), Some(btls::ssl::SslVersion::TLS1_3));
            assert!(!warm.ssl().session_reused());
            warm.write_all(b"x").await?;
            warm.flush().await?;
            closed(&mut warm).await?;
            let (stream, _) = proxy_listener.accept().await?;
            let mut spare = accept(stream, &proxy_acceptor).await?;
            assert!(
                spare.ssl().session_reused(),
                "spare did not use original proxy ticket"
            );
            let mut byte = [0];
            let mut read = ReadBuf::new(&mut byte);
            assert!(
                poll_fn(|cx| Poll::Ready(
                    Pin::new(&mut spare).poll_read(cx, &mut read).is_pending()
                ))
                .await
            );
            quiet
                .send(())
                .map_err(|()| "spare owner ended before quiet proof")?;
            closed(&mut spare).await
        };
        let origin_server = async {
            for resumed in [false, true] {
                let (stream, _) = origin_listener.accept().await?;
                let mut stream = accept(stream, &origin_acceptor).await?;
                assert_eq!(stream.ssl().version2(), Some(btls::ssl::SslVersion::TLS1_3));
                assert_eq!(
                    stream.ssl().session_reused(),
                    resumed,
                    "unused proxy spare consumed or replaced the origin ticket"
                );
                assert_eq!(
                    read_plaintext_head(&mut stream).await?,
                    b"GET /ticket HTTP/1.1\r\nHost: server.phantom.test\r\n\r\n"
                );
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await?;
                stream.flush().await?;
            }
            TestResult::Ok(())
        };
        tokio::try_join!(client, proxy_server, origin_server)?;
        Ok(())
    })
    .await?
}
