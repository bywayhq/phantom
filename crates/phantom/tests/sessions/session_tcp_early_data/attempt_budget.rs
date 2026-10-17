use super::*;
use crate::early_data_server::accept_with_early_data;

#[tokio::test]
async fn tcp_early_data_replay_spends_another_attempt_before_rewriting_bytes() -> TestResult<()> {
    for protocol in [Some(HttpProtocol::Http1), Some(HttpProtocol::Http2), None] {
        for accepted in [false, true] {
            for allowance in [1, 2] {
                replay_case(protocol, accepted, allowance).await?;
            }
        }
    }
    Ok(())
}

async fn replay_case(
    protocol: Option<HttpProtocol>,
    accepted: bool,
    allowance: usize,
) -> TestResult<()> {
    let mut server = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let offers = Offers::default();
        let alpn = if protocol == Some(HttpProtocol::Http1) {
            H1_ALPN
        } else {
            H2_ALPN
        };
        let acceptor = acceptor_for(&identity, &offers, alpn)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let (first_closed, wait_for_first_close) = oneshot::channel();
        let denied = !accepted && allowance == 1;
        server = Some(ConnectionPeer::spawn(async move {
            let first = accept(&listener, &acceptor, Duration::ZERO).await?;
            if alpn == H1_ALPN {
                serve_http1(first).await?;
            } else {
                serve_http2(first, "/seed").await?;
            }
            first_closed
                .send(())
                .map_err(|_| "client stopped before first close")?;
            let mut second =
                accept_with_early_data(&listener, &acceptor, SERVER_DELAY, accepted).await?;
            assert!(second.stream.ssl().session_reused());
            if denied {
                expect_no_request(&mut second).await?;
            } else if alpn == H1_ALPN {
                serve_http1(second).await?;
            } else {
                serve_http2(second, "/limited").await?;
            }
            Ok::<_, Box<dyn Error + Send + Sync>>(())
        }));
        let session = client(&identity)?;
        let seed = format!("https://{address}/seed");
        let request = match protocol {
            Some(protocol) => session.get(protocol, &seed)?,
            None => session.get_negotiated(&seed)?,
        };
        request.send().await?.into_body().collect().await?;
        wait_for_first_close.await?;
        let budget = phantom::HttpAttemptBudget::new(allowance);
        let url = format!("https://{address}/limited");
        let request = match protocol {
            Some(protocol) => session.get(protocol, &url)?,
            None => session.get_negotiated(&url)?,
        };
        let result = request.attempt_budget(budget.clone()).send().await;
        if denied {
            let error = result.err().ok_or("TLS replay exceeded shared allowance")?;
            assert_eq!(error.kind(), RequestErrorKind::AttemptBudgetExhausted);
            assert!(source_chain(&error).contains("shared HTTP attempt budget exhausted"));
        } else {
            result?.into_body().collect().await?;
        }
        assert_eq!(
            budget.remaining(),
            allowance - if accepted { 1 } else { allowance }
        );
        drop(session);
        join(&mut server).await?;
        assert_eq!(offers.take(), [FRESH, EARLY]);
        Ok(())
    })
    .await;
    finish(result, server).await
}
