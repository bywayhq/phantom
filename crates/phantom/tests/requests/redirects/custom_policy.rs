use super::*;
use phantom::{HttpAttemptBudget, RedirectDecision, RedirectHistory};

#[tokio::test]
async fn stopping_callback_returns_the_redirect_without_spending_another_attempt() -> TestResult<()>
{
    let mut server = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (heads_tx, mut heads) = tokio::sync::mpsc::unbounded_channel();
        server = Some(HopServer::spawn(listener, heads_tx, |path| {
            (path == "/start").then(|| "/final".into())
        }));
        let client = client_builder(&identity, false)
            .redirect_policy(RedirectPolicy::custom(NonZeroUsize::MIN, |_| {
                RedirectDecision::Stop
            }))
            .build()?;
        let budget = HttpAttemptBudget::new(1);
        let response = client
            .get_with_protocol(HttpProtocol::Http1, &format!("http://{address}/start"))?
            .attempt_budget(budget.clone())
            .redirect_history(NonZeroUsize::MIN)
            .send()
            .await?;
        assert_eq!(response.status(), StatusCode::FOUND);
        assert_eq!(budget.remaining(), 0);
        assert!(
            response
                .extensions()
                .get::<RedirectHistory>()
                .ok_or("redirect history absent")?
                .entries()
                .is_empty()
        );
        response.into_body().collect().await?;
        assert!(
            heads
                .recv()
                .await
                .ok_or("initial request absent")?
                .starts_with(b"GET /start HTTP/1.1\r\n")
        );
        assert!(heads.try_recv().is_err());

        let followed = client
            .clone()
            .get_with_protocol(HttpProtocol::Http1, &format!("http://{address}/start"))?
            .redirect_policy(RedirectPolicy::limited(NonZeroUsize::MIN))
            .send()
            .await?;
        assert_eq!(followed.status(), StatusCode::OK);
        followed.into_body().collect().await?;
        for path in ["/start", "/final"] {
            assert!(
                heads
                    .recv()
                    .await
                    .ok_or("followed request absent")?
                    .starts_with(format!("GET {path} HTTP/1.1\r\n").as_bytes())
            );
        }
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
async fn rejecting_callback_checks_later_hops_before_another_send() -> TestResult<()> {
    let mut server = None;
    let primary = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (heads_tx, mut heads) = tokio::sync::mpsc::unbounded_channel();
        server = Some(HopServer::spawn(listener, heads_tx, |path| match path {
            "/start" => Some("/middle".into()),
            "/middle" => Some("/blocked".into()),
            _ => None,
        }));
        let client = client_builder(&identity, false)
            .redirect_policy(RedirectPolicy::custom(
                NonZeroUsize::new(2).ok_or("nonzero")?,
                |attempt| {
                    if attempt.to_url().path() == "/blocked" {
                        assert_eq!(attempt.hop(), 2);
                        RedirectDecision::Reject
                    } else {
                        RedirectDecision::Follow
                    }
                },
            ))
            .build()?;
        let budget = HttpAttemptBudget::new(3);
        let error = client
            .get_with_protocol(HttpProtocol::Http1, &format!("http://{address}/start"))?
            .attempt_budget(budget.clone())
            .send()
            .await
            .err()
            .ok_or("blocked redirect was followed")?;
        assert_eq!(error.kind(), RequestErrorKind::Redirect);
        assert_eq!(budget.remaining(), 1);
        for path in ["/start", "/middle"] {
            assert!(
                heads
                    .recv()
                    .await
                    .ok_or("request absent")?
                    .starts_with(format!("GET {path} HTTP/1.1\r\n").as_bytes())
            );
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
