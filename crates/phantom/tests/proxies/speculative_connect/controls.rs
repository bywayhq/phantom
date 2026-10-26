use super::*;
use tokio::io::AsyncReadExt;

#[tokio::test]
async fn speculative_unsupported_combinations_fail_before_proxy_io() -> TestResult<()> {
    for http2_proxy in [false, true] {
        for mode in 0..3 {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let proxy = if http2_proxy {
                HttpProxy::new(&format!("https://{address}"))?.with_http2_transport()?
            } else {
                HttpProxy::new(&format!("http://{address}"))?.with_digest_auth("user", "secret")?
            }
            .with_speculative_tls(true);
            let client = Client::builder(chrome::v154_windows())
                .route(Route::http_proxy(proxy))
                .build()?;
            let request = match mode {
                0 => client
                    .get_with_protocol(HttpProtocol::Http1, "https://127.0.0.1/speculative")?,
                1 => client
                    .get_with_protocol(HttpProtocol::Http2, "https://127.0.0.1/speculative")?,
                _ => client.get("https://127.0.0.1/speculative")?,
            };
            let error = timeout(Duration::from_secs(3), request.send())
                .await?
                .err()
                .ok_or("unsupported route succeeded")?;
            assert_eq!(error.kind(), RequestErrorKind::Proxy, "{error}");
            assert!(
                timeout(Duration::from_millis(20), listener.accept())
                    .await
                    .is_err()
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn speculative_connect_still_rejects_an_untrusted_origin() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        let identity = TestIdentity::generate()?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?
            .with_speculative_tls(true);
        let client = Client::builder(chrome::v154_windows())
            .route(Route::http_proxy(proxy))
            .build()?;
        let caller = async {
            let error = client
                .get_with_protocol(HttpProtocol::Http1, "https://127.0.0.1/speculative")?
                .send()
                .await
                .err()
                .ok_or("untrusted origin succeeded")?;
            assert_eq!(error.kind(), RequestErrorKind::Tls);
            TestResult::Ok(())
        };
        let peer = async {
            let (socket, _) = listener.accept().await?;
            let mut socket = BufReader::new(socket);
            read_head(&mut socket).await?;
            assert_eq!(socket.fill_buf().await?.first(), Some(&22));
            socket
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            let ssl = Ssl::new(acceptor.context())?;
            let mut tls = SslStream::new(ssl, socket)?;
            assert!(Pin::new(&mut tls).accept().await.is_err());
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        TestResult::Ok(())
    })
    .await?
}

#[tokio::test]
async fn cancelling_speculative_connect_closes_the_pending_proxy_socket() -> TestResult<()> {
    timeout(Duration::from_secs(10), async {
        for mode in 0..3 {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let proxy = HttpProxy::new(&format!("http://{}", listener.local_addr()?))?.with_speculative_tls(true);
            let client = Client::builder(firefox::v157_windows()).route(Route::http_proxy(proxy)).build()?;
            let request = match mode {
                0 => client.get_with_protocol(HttpProtocol::Http1, "https://127.0.0.1/speculative")?,
                1 => client.get_with_protocol(HttpProtocol::Http2, "https://127.0.0.1/speculative")?,
                _ => client.get("https://127.0.0.1/speculative")?,
            };
            let mut pending = Box::pin(request.send());
            let peer = async {
                let (socket, _) = listener.accept().await?;
                let mut socket = BufReader::new(socket);
                read_head(&mut socket).await?;
                assert_eq!(socket.fill_buf().await?.first(), Some(&22));
                TestResult::Ok(socket)
            };
            let mut peer = tokio::select! {
                result = &mut pending => { drop(result); return Err("proxy accepted without a response".into()); }
                peer = peer => peer?,
            };
            drop(pending);
            let mut bytes = Vec::new();
            peer.read_to_end(&mut bytes).await?;
            assert!(!bytes.windows(8).any(|part| part == b"CONNECT "));
        }
        TestResult::Ok(())
    }).await?
}
