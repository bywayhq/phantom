use super::*;

#[tokio::test]
async fn shared_attempt_budget_stops_critical_client_hint_resends() -> TestResult<()> {
    let mut server = None;
    let mut retained_client = None;
    let result = bounded(async {
        let identity = TestIdentity::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let (client_done, wait_for_client) = oneshot::channel();
        server = Some(ConnectionPeer::spawn(async move {
            let stream = accept_tls(&listener, &acceptor).await?;
            let mut connection = ::http2::server::handshake(stream).await?;
            let (first, mut response) = accept_http2(&mut connection).await?;
            assert_hints(first.headers(), false)?;
            response.send_response(
                Response::builder()
                    .status(StatusCode::OK)
                    .header("accept-ch", "Sec-CH-UA-Arch")
                    .header("critical-ch", "Sec-CH-UA-Arch")
                    .body(())?,
                true,
            )?;
            drop((first, response));
            drive_http2_until_client_done(&mut connection, wait_for_client).await
        }));
        let session = client(&identity)?;
        retained_client = Some(session.clone());
        let budget = phantom::HttpAttemptBudget::new(1);
        let error = session
            .get(HttpProtocol::Http2, &format!("https://{address}/"))?
            .attempt_budget(budget.clone())
            .send()
            .await
            .err()
            .ok_or("client-hint resend exceeded shared allowance")?;
        assert_eq!(error.kind(), RequestErrorKind::AttemptBudgetExhausted);
        assert_eq!(budget.remaining(), 0);
        client_done
            .send(())
            .map_err(|_| "client-hint peer stopped early")?;
        join_hint_peer(&mut server).await?;
        Ok(())
    })
    .await;
    let result = finish_with_cleanup(result, stop_hint_peer(server).await);
    drop(retained_client);
    result
}
