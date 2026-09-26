use super::*;

#[tokio::test]
async fn authenticated_connect_tunnel_is_reused_by_http1_session() -> TestResult<()> {
    bounded(async {
        let identity = TestIdentity::generate()?;
        let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let origin_address = origin_listener.local_addr()?;
        let origin_acceptor = identity.acceptor(H1_ALPN)?;
        let origin = tokio::spawn(async move {
            let mut stream = tls_support::accept_tls(origin_listener, origin_acceptor).await?;
            let first = read_head(&mut stream).await?;
            stream
                .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
                .await?;
            stream.flush().await?;
            let second = read_head(&mut stream).await?;
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await?;
            stream.shutdown().await?;
            Ok::<_, Box<dyn Error + Send + Sync>>([first, second])
        });

        let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_address = proxy_listener.local_addr()?;
        let proxy = tokio::spawn(challenge_then_forward(proxy_listener, origin_address));
        let route = Route::http_connect(
            HttpProxy::new(&format!("http://{proxy_address}"))?
                .with_basic_auth("alice", "secret")?,
        );
        let session = client_builder(&identity, false)
            .route(route)
            .build()?
            .session();

        for path in ["first", "second"] {
            let response = session
                .get(
                    HttpProtocol::Http1,
                    &format!("https://{origin_address}/{path}"),
                )?
                .send()
                .await?;
            assert_eq!(response.status(), 204);
            response.into_body().collect().await?;
        }
        drop(session);

        let (anonymous, authorized, third_attempted) = proxy.await??;
        assert!(!contains_ascii_case_insensitive(
            &anonymous,
            b"proxy-authorization"
        ));
        assert!(contains_ascii_case_insensitive(
            &authorized,
            b"proxy-authorization: basic ywxpy2u6c2vjcmv0"
        ));
        assert!(!third_attempted);
        let requests = origin.await??;
        assert!(requests[0].starts_with(b"GET /first HTTP/1.1\r\n"));
        assert!(requests[1].starts_with(b"GET /second HTTP/1.1\r\n"));
        Ok(())
    })
    .await
}

async fn challenge_then_forward(
    listener: TcpListener,
    origin: std::net::SocketAddr,
) -> TestResult<(Vec<u8>, Vec<u8>, bool)> {
    let (mut first, _) = listener.accept().await?;
    let anonymous = read_head(&mut first).await?;
    first
        .write_all(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n\
              Proxy-Authenticate: Basic realm=session\r\n\
              Content-Length: 0\r\n\r\n",
        )
        .await?;
    first.shutdown().await?;

    let (mut second, _) = listener.accept().await?;
    let authorized = read_head(&mut second).await?;
    let mut upstream = TcpStream::connect(origin).await?;
    second
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;
    second.flush().await?;
    copy_bidirectional(&mut second, &mut upstream).await?;
    let third_attempted = timeout(Duration::from_millis(100), listener.accept())
        .await
        .is_ok();
    Ok((anonymous, authorized, third_attempted))
}

fn contains_ascii_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}
