use super::*;
use phantom::RedirectHistory;

#[tokio::test]
async fn redirect_history_is_opt_in_bounded_and_preserved_by_body_helpers() -> TestResult<()> {
    let mut server = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (heads_tx, mut heads) = tokio::sync::mpsc::unbounded_channel();
        server = Some(HopServer::spawn(listener, heads_tx, |path| match path {
            "/start?token=private" => Some("/middle".into()),
            "/middle" => Some("/final".into()),
            _ => None,
        }));
        let client = client_builder(&identity, false)
            .redirect_policy(RedirectPolicy::limited(
                NonZeroUsize::new(2).ok_or("two is nonzero")?,
            ))
            .build()?;
        let start = format!("http://{address}/start?token=private");
        let response = client
            .get(HttpProtocol::Http1, &start)?
            .redirect_history(NonZeroUsize::MIN)
            .send()
            .await?;
        let response = phantom::response_bytes(response, 1024).await?;
        let history = response
            .extensions()
            .get::<RedirectHistory>()
            .ok_or("history absent")?;
        assert_eq!(history.entries().len(), 1);
        assert_eq!(history.omitted_hops(), 1);
        let hop = &history.entries()[0];
        assert_eq!(hop.from_uri().to_string(), start);
        assert_eq!(hop.to_uri().to_string(), format!("http://{address}/middle"));
        assert_eq!(hop.method(), Method::GET);
        assert_eq!(hop.next_method(), Method::GET);
        assert_eq!(hop.status(), StatusCode::FOUND);
        let debug = format!("{history:?} {hop:?}");
        assert!(!debug.contains("private"));
        assert!(!debug.contains("middle"));
        assert_eq!(
            response
                .extensions()
                .get::<ResponseInfo>()
                .ok_or("metadata absent")?
                .redirects_followed(),
            2
        );
        let final_uri = format!("http://{address}/final");
        let disabled = client.get(HttpProtocol::Http1, &final_uri)?.send().await?;
        assert!(disabled.extensions().get::<RedirectHistory>().is_none());
        disabled.into_body().collect().await?;
        let empty = client
            .get(HttpProtocol::Http1, &final_uri)?
            .redirect_history(NonZeroUsize::MIN)
            .send()
            .await?;
        let history = empty
            .extensions()
            .get::<RedirectHistory>()
            .ok_or("empty history absent")?;
        assert!(history.entries().is_empty());
        assert_eq!(history.omitted_hops(), 0);
        empty.into_body().collect().await?;
        let stopped = client
            .get(HttpProtocol::Http1, &start)?
            .redirect_policy(RedirectPolicy::none())
            .redirect_history(NonZeroUsize::MIN)
            .send()
            .await?;
        assert_eq!(stopped.status(), StatusCode::FOUND);
        let history = stopped
            .extensions()
            .get::<RedirectHistory>()
            .ok_or("stopped history absent")?;
        assert!(history.entries().is_empty());
        assert_eq!(history.omitted_hops(), 0);
        stopped.into_body().collect().await?;
        for path in [
            "/start?token=private",
            "/middle",
            "/final",
            "/final",
            "/final",
            "/start?token=private",
        ] {
            let head = heads.recv().await.ok_or("request absent")?;
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
async fn redirect_history_records_method_changes_for_exact_and_negotiated_http2() -> TestResult<()>
{
    let mut server = None;
    let primary = bounded(async {
        for negotiated in [false, true] {
            for status in [StatusCode::FOUND, StatusCode::TEMPORARY_REDIRECT] {
                let identity = TestIdentity::generate()?;
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
                let address = listener.local_addr()?;
                let acceptor = identity.acceptor(H2_ALPN)?;
                server = Some(ConnectionPeer::spawn(async move {
                    let stream = accept_tls(&listener, &acceptor).await?;
                    serve_redirect_probe(stream, status, b"history").await
                }));
                let client = client_builder(&identity, true).build()?;
                let uri = format!(
                    "https://{address}/.well-known/phantom/redirect/{}/start",
                    status.as_u16()
                );
                let request = if negotiated {
                    client.request_negotiated(Method::POST, &uri)?
                } else {
                    client.request(HttpProtocol::Http2, Method::POST, &uri)?
                };
                let response = request
                    .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
                    .redirect_history(NonZeroUsize::MIN)
                    .body(Bytes::from_static(b"history"))
                    .send()
                    .await?;
                let history = response
                    .extensions()
                    .get::<RedirectHistory>()
                    .ok_or("history absent")?;
                assert_eq!(history.omitted_hops(), 0);
                assert_eq!(history.entries().len(), 1);
                let hop = &history.entries()[0];
                assert_eq!(hop.from_uri().to_string(), uri);
                assert_eq!(
                    hop.to_uri().to_string(),
                    format!(
                        "https://{address}/.well-known/phantom/redirect/{}/final",
                        status.as_u16()
                    )
                );
                assert_eq!(hop.status(), status);
                assert_eq!(hop.method(), Method::POST);
                assert_eq!(
                    hop.next_method(),
                    if status == StatusCode::FOUND {
                        Method::GET
                    } else {
                        Method::POST
                    }
                );
                response.into_body().collect().await?;
                drop(client);
                server.as_mut().ok_or("peer absent")?.join().await??;
            }
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
