//! Checked early-data settlement can validate a mapping before any response.

use std::{collections::BTreeSet, num::NonZeroUsize, time::SystemTime};

use phantom::{AltSvcSnapshot, AltSvcSnapshotEntry, profile::Http3AltUsed};
use tokio::task::JoinSet;

use super::*;

#[derive(Debug)]
struct Observed {
    path: String,
    method: Method,
    alt_used: Option<String>,
    reply_gate_open: bool,
}

type Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

#[tokio::test]
async fn accepted_early_handshake_confirms_a_reused_mapping_before_any_response() -> TestResult<()>
{
    checked_mapping(true).await
}

#[tokio::test]
async fn rejected_early_handshake_confirms_a_reused_mapping_before_any_response() -> TestResult<()>
{
    checked_mapping(false).await
}

async fn checked_mapping(accept: bool) -> TestResult<()> {
    let identity = TestIdentity::generate()?;
    let sessions = SessionStore::new();
    let endpoint = h3_support::quic_server(
        server_config(&identity, Arc::clone(&sessions), true, 1)?,
        (Ipv4Addr::LOCALHOST, 0).into(),
    )?;
    let (gate, open) = watch::channel(true);
    let (address, mut relay) = gated_relay(endpoint.local_addr()?, open).await?;
    let (arrived_tx, mut arrived) = mpsc::channel(5);
    let (read_tx, read) = mpsc::channel(1);
    let (closed_tx, mut closed) = mpsc::channel(1);
    let (release, responses) = watch::channel(false);
    let mut peer = ConnectionPeer::spawn(serve_mapping(
        endpoint.clone(),
        gate.subscribe(),
        arrived_tx,
        read,
        closed_tx,
        responses,
    ));
    let mut requests = JoinSet::new();
    let outcome = AssertUnwindSafe(timeout(DEADLINE, async {
        let source = mapping_client(&identity)?;
        let recipient = mapping_client(&identity)?;
        let probe = mapping_client(&identity)?;
        let mut key = [0; 32];
        btls::rand::rand_bytes(&mut key)?;
        send(&source, address, "/seed").await?;
        assert_eq!(sessions.attempts.load(Ordering::SeqCst), 0);
        let snapshot = export_one_ticket(&source, &probe, &key).await?;
        read_tx.send(()).await?;
        assert_eq!(closed.recv().await, Some(0));
        endpoint.set_server_config(Some(server_config(
            &identity,
            Arc::clone(&sessions),
            accept,
            0,
        )?));
        recipient.import_session_tickets(&snapshot, &key, &[])?;
        recipient.import_alt_svc(&AltSvcSnapshot::new(vec![AltSvcSnapshotEntry::new(
            format!("https://{address}"),
            address.ip().to_string(),
            address.port(),
            SystemTime::now() + Duration::from_secs(60),
        )]))?;
        gate.send_replace(false);
        let first = OutcomeSubscriber::default();
        spawn_request(
            &mut requests,
            &recipient,
            address,
            Method::GET,
            "/early-one",
            &first,
        );
        wait_for_early_dispatch(&first, &mut requests).await?;
        let second = OutcomeSubscriber::default();
        spawn_request(
            &mut requests,
            &recipient,
            address,
            Method::GET,
            "/early-two",
            &second,
        );
        wait_for_early_dispatch(&second, &mut requests).await?;
        assert_eq!(first.early_data_for("http3.response_head"), ["sent"]);
        assert_eq!(second.early_data_for("http3.response_head"), ["sent"]);

        let mut observations = Vec::new();
        if accept {
            // Both complete early requests reach the actual peer while every
            // server handshake datagram is still behind the closed gate.
            for _ in 0..2 {
                observations.push(observe(&mut arrived, &mut requests).await?);
            }
            assert_initial(&observations, false);
        }
        gate.send_replace(true);
        if !accept {
            for _ in 0..2 {
                observations.push(observe(&mut arrived, &mut requests).await?);
            }
            assert_initial(&observations, true);
            assert_eq!(
                first.early_data_for("http3.response_head"),
                ["sent", "after_handshake"]
            );
            assert_eq!(
                second.early_data_for("http3.response_head"),
                ["sent", "after_handshake"]
            );
        }

        // POST cannot be dispatched before the checked Accepted/Rejected
        // outcome. Its observed stream is a handshake barrier, not a response.
        let barrier = OutcomeSubscriber::default();
        spawn_request(
            &mut requests,
            &recipient,
            address,
            Method::POST,
            "/checked",
            &barrier,
        );
        let checked = observe(&mut arrived, &mut requests).await?;
        assert_eq!(checked.path, "/checked");
        assert_eq!(checked.method, Method::POST);
        assert_eq!(
            barrier.early_data_for("http3.response_head"),
            ["after_handshake"]
        );
        observations.push(checked);
        // The next admission sees an already-settled connection and registers
        // its current mapping synchronously, independently of whether the
        // original pending writer has already published its confirmation.
        spawn_request(
            &mut requests,
            &recipient,
            address,
            Method::POST,
            "/registered",
            &barrier,
        );
        let registered = observe(&mut arrived, &mut requests).await?;
        assert_eq!(registered.path, "/registered");
        assert_eq!(registered.method, Method::POST);
        observations.push(registered);

        let later_trace = OutcomeSubscriber::default();
        spawn_request(
            &mut requests,
            &recipient,
            address,
            Method::GET,
            "/later",
            &later_trace,
        );
        let later = observe(&mut arrived, &mut requests).await?;
        assert_eq!(later.path, "/later");
        assert_eq!(later.method, Method::GET);
        let expected_alt_used = address.to_string();
        assert_eq!(later.alt_used.as_deref(), Some(expected_alt_used.as_str()));
        assert_eq!(
            later_trace.early_data_for("http3.response_head"),
            ["after_handshake"]
        );
        observations.push(later);
        assert_eq!(sessions.attempts.load(Ordering::SeqCst), 1);
        assert_eq!(sessions.found.load(Ordering::SeqCst), 1);
        assert_eq!(observations.len(), 5);
        assert!(!*release.borrow());
        assert_eq!(requests.len(), 5);
        release.send_replace(true);
        for _ in 0..5 {
            let task = requests.join_next().await.ok_or("request task missing")?;
            task??;
        }
        assert!(requests.is_empty());
        if accept {
            assert_eq!(first.early_data_for("http3.response_head"), ["sent"]);
            assert_eq!(second.early_data_for("http3.response_head"), ["sent"]);
        } else {
            assert_eq!(
                first.early_data_for("http3.response_head"),
                ["sent", "after_handshake"]
            );
            assert_eq!(
                second.early_data_for("http3.response_head"),
                ["sent", "after_handshake"]
            );
        }
        assert_eq!(recipient.clear_session_tickets()?, 0);
        assert_eq!(source.clear_session_tickets()?, 1);
        read_tx.send(()).await?;
        assert_eq!(closed.recv().await, Some(1));
        peer.join().await??;
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(())
    }))
    .catch_unwind()
    .await;

    gate.send_replace(true);
    release.send_replace(true);
    requests.shutdown().await;
    endpoint.close(0u32.into(), b"test cleanup");
    let peers = finish_with_cleanup(peer.shutdown().await, relay.stop().await);
    let cleanup = finish_with_cleanup(
        peers,
        timeout(Duration::from_secs(5), endpoint.wait_idle())
            .await
            .map_err(Into::into),
    );
    match outcome {
        Ok(result) => finish_with_cleanup(result.map_err(Into::into).and_then(|v| v), cleanup),
        Err(panic) => {
            if let Err(error) = cleanup {
                eprintln!("early mapping cleanup failed: {error}");
            }
            std::panic::resume_unwind(panic)
        }
    }
}

fn mapping_client(identity: &TestIdentity) -> TestResult<Client> {
    let mut request = chrome::v154_http3_request();
    request.alt_used = Http3AltUsed::ValidatedMapping;
    let profile = ClientProfile::new(chrome::v154_tcp_tls())
        .with_http2(chrome::v154_http2())
        .with_http3(Http3ClientSettings::new(
            chrome::v154_quic_tls(),
            chrome::v154_quic(),
            chrome::v154_http3(),
            request,
        ));
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(NonZeroUsize::MIN)
        .build()?)
}

fn spawn_request(
    requests: &mut JoinSet<TestResult<()>>,
    client: &Client,
    address: SocketAddr,
    method: Method,
    path: &'static str,
    trace: &OutcomeSubscriber,
) {
    let client = client.clone();
    let dispatch = trace.dispatch();
    requests.spawn(
        async move {
            let response = client
                .request_negotiated(method, &format!("https://{address}{path}"))?
                .send()
                .await?;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.version(), Version::HTTP_3);
            assert_eq!(
                response.into_body().collect().await?.to_bytes(),
                path.as_bytes()
            );
            Ok(())
        }
        .with_subscriber(dispatch),
    );
}

async fn wait_for_early_dispatch(
    trace: &OutcomeSubscriber,
    requests: &mut JoinSet<TestResult<()>>,
) -> TestResult<()> {
    tokio::select! {
        result = requests.join_next() => {
            let task = result.ok_or("request task missing")?;
            task??;
            Err("request completed before a held response".into())
        }
        () = async {
            while trace.early_data_for("http3.response_head").is_empty() { tokio::task::yield_now().await; }
        } => Ok(()),
    }
}

async fn observe(
    arrived: &mut mpsc::Receiver<Observed>,
    requests: &mut JoinSet<TestResult<()>>,
) -> TestResult<Observed> {
    tokio::select! {
        result = requests.join_next() => {
            let task = result.ok_or("request task missing")?;
            task??;
            Err("request completed before a held response".into())
        }
        observed = arrived.recv() => observed.ok_or_else(|| "mapping peer stopped".into()),
    }
}

fn assert_initial(observations: &[Observed], gate_open: bool) {
    let paths: BTreeSet<_> = observations
        .iter()
        .map(|observed| observed.path.as_str())
        .collect();
    assert_eq!(paths, BTreeSet::from(["/early-one", "/early-two"]));
    for observed in observations {
        assert_eq!(observed.method, Method::GET);
        assert_eq!(observed.alt_used, None);
        assert_eq!(observed.reply_gate_open, gate_open);
    }
}

async fn serve_mapping(
    endpoint: quinn::Endpoint,
    gate: watch::Receiver<bool>,
    arrived: mpsc::Sender<Observed>,
    mut read: mpsc::Receiver<()>,
    closed: mpsc::Sender<usize>,
    mut responses: watch::Receiver<bool>,
) -> TestResult<()> {
    // Seed a genuine ticket, including the peer SETTINGS remembered with it.
    let seed = endpoint.accept().await.ok_or("endpoint closed")?.await?;
    let mut connection =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(seed.clone())).await?;
    let resolver = connection.accept().await?.ok_or("missing seed request")?;
    let (request, mut stream) = resolver.resolve_request().await?;
    assert_eq!(request.uri().path(), "/seed");
    while stream.recv_data().await?.is_some() {}
    answer(&mut stream, "/seed").await?;
    read.recv().await.ok_or("seed client stopped")?;
    seed.close(0u32.into(), b"seeded");
    drop(connection);
    endpoint.wait_idle().await;
    closed.send(0).await?;

    let mut connecting = endpoint.accept().await.ok_or("endpoint closed")?.accept()?;
    connecting.handshake_data().await?;
    let quic = match connecting.into_0rtt() {
        Ok((connection, _)) => connection,
        Err(connecting) => connecting.await?,
    };
    let mut connection =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(quic.clone())).await?;
    let mut held = Vec::with_capacity(5);
    for _ in 0..5 {
        let resolver = connection
            .accept()
            .await?
            .ok_or("mapping connection closed")?;
        let (request, mut stream) = resolver.resolve_request().await?;
        while stream.recv_data().await?.is_some() {}
        let alt_used = request
            .headers()
            .get_all("alt-used")
            .iter()
            .map(|value| value.to_str().map(str::to_owned))
            .collect::<Result<Vec<_>, _>>()?;
        assert!(alt_used.len() <= 1);
        let path = request.uri().path().to_owned();
        let reply_gate_open = *gate.borrow();
        arrived
            .send(Observed {
                path: path.clone(),
                method: request.method().clone(),
                alt_used: alt_used.into_iter().next(),
                reply_gate_open,
            })
            .await?;
        held.push((path, stream));
    }
    responses.wait_for(|release| *release).await?;
    for (path, mut stream) in held {
        answer(&mut stream, &path).await?;
    }
    read.recv().await.ok_or("recipient stopped")?;
    match timeout(Duration::from_millis(300), connection.accept()).await {
        Ok(Ok(Some(_))) => return Err("unexpected sixth imported request".into()),
        Ok(Ok(None)) | Err(_) => {}
        Ok(Err(error)) if error.is_h3_no_error() => {}
        Ok(Err(error)) => return Err(error.into()),
    }
    quic.close(0u32.into(), b"served");
    drop(connection);
    endpoint.wait_idle().await;
    closed.send(1).await?;
    match timeout(Duration::from_millis(300), endpoint.accept()).await {
        Ok(Some(_)) => Err("unexpected third connection".into()),
        Ok(None) | Err(_) => Ok(()),
    }
}

async fn answer(stream: &mut Stream, path: &str) -> TestResult<()> {
    stream
        .send_response(Response::builder().status(StatusCode::OK).body(())?)
        .await?;
    stream
        .send_data(Bytes::copy_from_slice(path.as_bytes()))
        .await?;
    stream.finish().await?;
    Ok(())
}
