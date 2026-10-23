//! An accepted imported early winner restarts a misdirected request on its origin.

use std::{io, num::NonZeroUsize, time::SystemTime};

use phantom::{
    AltSvcBrokenBackoff, AltSvcPolicy, AltSvcRace, AltSvcSnapshot, AltSvcSnapshotEntry,
    ClientBuilder, HttpAttemptBudget, ResponseInfo,
    profile::{Http3MisdirectedRequest, SessionTickets},
};

use crate::support::http3_upgrade::{
    AlternativeBehavior, Http3UpgradeFixture, PlannedResponse, UpgradeScript,
};

use super::*;

#[tokio::test]
async fn imported_accepted_early_winner_421_recovers_without_reconfirming_or_reracing()
-> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let origin = Http3UpgradeFixture::spawn(
        &identity,
        "127.0.0.1",
        UpgradeScript::new(
            [
                PlannedResponse::new(StatusCode::OK).body("origin"),
                PlannedResponse::new(StatusCode::OK).body("origin"),
            ],
            AlternativeBehavior::responses([]),
        ),
    )
    .await?;
    let sessions = SessionStore::new();
    let (gate, open) = watch::channel(true);
    let mut endpoint = None;
    let mut relay = None;
    let mut peer = None;
    let outcome = AssertUnwindSafe(timeout(DEADLINE, async {
        let server = h3_support::quic_server(
            server_config(&identity, Arc::clone(&sessions), true, 1)?,
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        endpoint = Some(server.clone());
        let (address, owned_relay) = gated_relay(server.local_addr()?, open).await?;
        relay = Some(owned_relay);
        let (arrived_tx, mut arrived) = mpsc::channel(2);
        let (read_tx, read) = mpsc::channel(1);
        let (closed_tx, mut closed) = mpsc::channel(1);
        peer = Some(ConnectionPeer::spawn(serve(
            server.clone(),
            gate.subscribe(),
            arrived_tx,
            read,
            closed_tx,
            ImportedReply::AcceptedMisdirected,
        )));
        let source = misdirected_client(&identity)?.build()?;
        let recipient = misdirected_client(&identity)?.build()?;
        let probe = misdirected_client(&identity)?.build()?;
        let mut key = [0; 32];
        btls::rand::rand_bytes(&mut key)?;
        // Seed the same logical origin and actual alternative location that
        // the cold recipient will use; a different origin would scope its ticket away.
        let fresh = OutcomeSubscriber::default();
        let seed = source
            .get(HttpProtocol::Http3, &origin.origin_url("/seed"))?
            .alt_svc_alternative("127.0.0.1", address.port())
            .send()
            .with_subscriber(fresh.dispatch())
            .await?;
        assert_eq!(seed.status(), StatusCode::OK);
        assert_eq!(seed.version(), Version::HTTP_3);
        assert_eq!(seed.into_body().collect().await?.to_bytes(), "/seed");
        assert_eq!(arrived.recv().await, Some((0, "/seed".to_owned(), true)));
        assert_eq!(fresh.early_data_for("http3.response_head"), ["none"]);
        assert_eq!(sessions.attempts.load(Ordering::SeqCst), 0);
        let snapshot = export_one_ticket(&source, &probe, &key).await?;
        read_tx.send(()).await?;
        assert_eq!(closed.recv().await, Some(0));
        server.set_server_config(Some(server_config(
            &identity,
            Arc::clone(&sessions),
            true,
            0,
        )?));
        recipient.import_session_tickets(&snapshot, &key, &[])?;
        let logical_origin = format!("https://{}", origin.origin_address());
        recipient.import_alt_svc(&AltSvcSnapshot::new(vec![AltSvcSnapshotEntry::new(
            logical_origin,
            "127.0.0.1",
            address.port(),
            SystemTime::now() + Duration::from_secs(3600),
        )]))?;
        assert_eq!(
            recipient.export_alt_svc().ok_or("Alt-Svc disabled")?.len(),
            1
        );
        gate.send_replace(false);
        let trace = OutcomeSubscriber::default();
        let allowance = HttpAttemptBudget::new(2);
        let request = async {
            let response = recipient
                .get_negotiated(&origin.origin_url("/imported"))?
                .attempt_budget(allowance.clone())
                .send()
                .await?;
            assert_origin_response(response).await
        }
        .with_subscriber(trace.dispatch());
        tokio::pin!(request);
        tokio::select! {
            result = &mut request => {
                result?;
                return Err("request completed through the closed handshake reply gate".into());
            }
            observation = arrived.recv() => {
                assert_eq!(observation, Some((1, "/imported".to_owned(), false)));
            }
        }
        // Complete HTTP was decoded while no server handshake replies could
        // reach the recipient. The server then awaits completion before 421.
        assert_eq!(trace.early_data_for("http3.response_head"), ["sent"]);
        assert_eq!(sessions.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(sessions.found.load(Ordering::SeqCst), 1);
        assert_eq!(origin.snapshot()?.origin_connections, 0);
        gate.send_replace(true);
        request.await?;
        assert_eq!(allowance.remaining(), 0);
        assert_eq!(trace.early_data_for("http3.response_head"), ["sent"]);
        assert!(
            recipient
                .export_alt_svc()
                .ok_or("Alt-Svc disabled")?
                .is_empty(),
            "accepted early-win settlement restored the removed advertisement"
        );
        assert_origin_response(
            recipient
                .get_negotiated(&origin.origin_url("/after"))?
                .attempt_budget(HttpAttemptBudget::new(1))
                .send()
                .await?,
        )
        .await?;
        assert!(
            recipient
                .export_alt_svc()
                .ok_or("Alt-Svc disabled")?
                .is_empty()
        );
        assert!(
            arrived.try_recv().is_err(),
            "origin continuation sent another H3 request"
        );
        read_tx.send(()).await?;
        assert_eq!(closed.recv().await, Some(1));
        peer.as_mut().ok_or("missing QUIC peer")?.join().await??;
        assert_eq!(recipient.clear_session_tickets()?, 0);
        assert_eq!(source.clear_session_tickets()?, 1);
        TestResult::Ok(())
    }))
    .catch_unwind()
    .await;

    gate.send_replace(true);
    if let Some(endpoint) = &endpoint {
        endpoint.close(0u32.into(), b"test cleanup");
    }
    let peer_cleanup = match &mut peer {
        Some(peer) => peer.shutdown().await,
        None => Ok(()),
    };
    let relay_cleanup = match &mut relay {
        Some(relay) => relay.stop().await,
        None => Ok(()),
    };
    let cleanup = finish_with_cleanup(peer_cleanup, relay_cleanup);
    let idle = match &endpoint {
        Some(endpoint) => timeout(Duration::from_secs(5), endpoint.wait_idle())
            .await
            .map_err(Into::into),
        None => Ok(()),
    };
    let cleanup = finish_with_cleanup(cleanup, idle);
    let observed = origin.finish().await;
    let result = match outcome {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => Err(error.into()),
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("early misdirected-request assertion panicked");
            Err(io::Error::other(message.to_owned()).into())
        }
    };
    let result = finish_with_cleanup(result, cleanup);
    let observed = match result {
        Ok(()) => observed?,
        Err(primary) => return finish_with_cleanup(Err(primary), observed.map(|_| ())),
    };
    assert_eq!(observed.origin_connections, 1);
    assert_eq!(observed.origin_request_count, 2);
    assert_eq!(
        observed
            .origin_requests
            .iter()
            .map(|request| request.path_and_query.as_deref())
            .collect::<Vec<_>>(),
        [Some("/imported"), Some("/after")]
    );
    assert_eq!(observed.alternative_connections, 0);
    assert!(observed.alternative_requests.is_empty());
    Ok(())
}

fn misdirected_client(identity: &TestIdentity) -> TestResult<ClientBuilder> {
    let mut http3 = chrome::v154_http3();
    http3.misdirected_request = Http3MisdirectedRequest::RetryFirst;
    let quic = chrome::v154_quic();
    assert!(quic.early_data);
    // Count only the imported QUIC ticket, not new tickets from the H2 fallback.
    let mut tcp_tls = chrome::v154_tcp_tls();
    tcp_tls.session_tickets = SessionTickets::disabled();
    let profile = ClientProfile::new(tcp_tls)
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            chrome::v154_quic_tls(),
            quic,
            http3,
            chrome::v154_http3_request(),
        ));
    let backoff = AltSvcBrokenBackoff::new(Duration::from_secs(60), Duration::from_secs(600))?;
    // As in the existing early-race control, defer the initial TCP candidate;
    // a 421 continuation must not wait for this race delay a second time.
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(NonZeroUsize::MIN)
        .alt_svc_policy(AltSvcPolicy::race(AltSvcRace::new(
            Duration::from_secs(30),
            backoff,
        ))))
}

async fn assert_origin_response(response: http::Response<phantom::ResponseBody>) -> TestResult<()> {
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .extensions()
            .get::<ResponseInfo>()
            .ok_or("missing response protocol")?
            .protocol(),
        HttpProtocol::Http2
    );
    assert_eq!(response.into_body().collect_with_limit(6).await?, "origin");
    Ok(())
}
