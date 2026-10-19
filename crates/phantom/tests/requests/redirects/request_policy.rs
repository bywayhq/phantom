use super::*;

#[tokio::test]
async fn request_redirect_policy_applies_to_exact_and_negotiated_http2() -> TestResult<()> {
    let mut server = None;
    let primary = bounded(async {
        for negotiated in [false, true] {
            let identity = TestIdentity::generate()?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let acceptor = identity.acceptor(H2_ALPN)?;
            server = Some(ConnectionPeer::spawn(async move {
                let stream = accept_tls(&listener, &acceptor).await?;
                serve_redirect_probe(stream, StatusCode::FOUND, b"request-policy").await
            }));
            let client = client_builder(&identity, true).build()?;
            let uri = format!("https://{address}/.well-known/phantom/redirect/302/start");
            let request = if negotiated {
                client.request_negotiated(Method::POST, &uri)?
            } else {
                client.request(HttpProtocol::Http2, Method::POST, &uri)?
            };
            let response = request
                .redirect_policy(RedirectPolicy::custom(NonZeroUsize::MIN, |attempt| {
                    assert_eq!(attempt.status(), StatusCode::FOUND);
                    assert_eq!(attempt.method(), Method::POST);
                    assert_eq!(attempt.next_method(), Method::GET);
                    phantom::RedirectDecision::Follow
                }))
                .body(Bytes::from_static(b"request-policy"))
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_response_info(
                &response,
                &format!("https://{address}/.well-known/phantom/redirect/302/final"),
            )?;
            response.into_body().collect().await?;
            drop(client);
            server
                .as_mut()
                .ok_or("redirect peer was not started")?
                .join()
                .await??;
        }
        Ok(())
    })
    .await;
    let cleanup = match server.as_mut() {
        Some(peer) => peer.shutdown().await,
        None => Ok(()),
    };
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn request_redirect_policy_overrides_do_not_change_later_requests() -> TestResult<()> {
    let mut server = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (heads_tx, mut heads) = tokio::sync::mpsc::unbounded_channel();
        server = Some(HopServer::spawn(listener, heads_tx, |path| match path {
            "/start" => Some("/final".into()),
            "/chain" => Some("/start".into()),
            _ => None,
        }));
        let client = client_builder(&identity, false)
            .redirect_policy(RedirectPolicy::limited(
                NonZeroUsize::new(2).ok_or("two is nonzero")?,
            ))
            .build()?;
        let start = format!("http://{address}/start");
        let stopped = client
            .get(HttpProtocol::Http1, &start)?
            .redirect_policy(RedirectPolicy::none())
            .send()
            .await?;
        assert_eq!(stopped.status(), StatusCode::FOUND);
        assert_eq!(
            stopped
                .extensions()
                .get::<ResponseInfo>()
                .ok_or("response metadata absent")?
                .redirects_followed(),
            0,
        );
        stopped.into_body().collect().await?;

        let inherited = client.get(HttpProtocol::Http1, &start)?.send().await?;
        assert_eq!(inherited.status(), StatusCode::OK);
        inherited.into_body().collect().await?;

        let error = client
            .get(HttpProtocol::Http1, &format!("http://{address}/chain"))?
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .send()
            .await
            .err()
            .ok_or("request override exceeded its one-hop limit")?;
        assert_eq!(error.kind(), RequestErrorKind::Redirect);

        let inherited = client
            .clone()
            .get(HttpProtocol::Http1, &start)?
            .send()
            .await?;
        assert_eq!(inherited.status(), StatusCode::OK);
        inherited.into_body().collect().await?;
        for path in [
            "/start", "/start", "/final", "/chain", "/start", "/start", "/final",
        ] {
            let head = heads.recv().await.ok_or("request was not observed")?;
            assert!(head.starts_with(format!("GET {path} HTTP/1.1\r\n").as_bytes()));
        }
        assert!(heads.try_recv().is_err());
        drop(client);
        Ok(())
    })
    .await;
    let cleanup = match server.as_mut() {
        Some(peer) => peer.shutdown().await,
        None => Ok(()),
    };
    finish_with_cleanup(primary, cleanup)
}

#[tokio::test]
async fn request_redirect_policy_can_enable_following_for_a_default_client() -> TestResult<()> {
    let mut server = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (heads_tx, mut heads) = tokio::sync::mpsc::unbounded_channel();
        server = Some(HopServer::spawn(listener, heads_tx, |path| {
            (path == "/start").then(|| "/final".into())
        }));
        let client = client_builder(&identity, false).build()?;
        let uri = format!("http://{address}/start");
        let followed = client
            .get(HttpProtocol::Http1, &uri)?
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .send()
            .await?;
        assert_eq!(followed.status(), StatusCode::OK);
        assert_response_info(&followed, &format!("http://{address}/final"))?;
        followed.into_body().collect().await?;

        let stopped = client.get(HttpProtocol::Http1, &uri)?.send().await?;
        assert_eq!(stopped.status(), StatusCode::FOUND);
        stopped.into_body().collect().await?;

        let budget = phantom::HttpAttemptBudget::new(1);
        let error = client
            .get(HttpProtocol::Http1, &uri)?
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .attempt_budget(budget.clone())
            .send()
            .await
            .err()
            .ok_or("redirect override exceeded the shared attempt budget")?;
        assert_eq!(error.kind(), RequestErrorKind::AttemptBudgetExhausted);
        assert_eq!(budget.remaining(), 0);
        for path in ["/start", "/final", "/start", "/start"] {
            let head = heads.recv().await.ok_or("request was not observed")?;
            assert!(head.starts_with(format!("GET {path} HTTP/1.1\r\n").as_bytes()));
        }
        assert!(heads.try_recv().is_err());
        drop(client);
        Ok(())
    })
    .await;
    let cleanup = match server.as_mut() {
        Some(peer) => peer.shutdown().await,
        None => Ok(()),
    };
    finish_with_cleanup(primary, cleanup)
}
