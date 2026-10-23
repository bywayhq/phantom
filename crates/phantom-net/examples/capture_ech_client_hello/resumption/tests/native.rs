use btls::ssl::{ScopedSslSession, SslConnector, SslSessionScope, SslVerifyMode};

use super::*;

type Tickets = Arc<Mutex<Vec<Result<ScopedSslSession, btls::error::ErrorStack>>>>;

async fn sequence(mode: Mode) -> CaptureResult<()> {
    let (identity, trust_root) = crate::tests::test_identity()?;
    let run = Run::new(mode)?;
    let config = ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME);
    let list = ech_config_list(std::slice::from_ref(&config));
    let mut keys = SslEchKeys::builder()?;
    keys.add_key(
        true,
        &config,
        HpkeKey::dhkem_p256_sha256(&TEST_ECH_KEYS[0].private_key)?,
    )?;
    let mut acceptor = identity.acceptor_builder(Some(&keys.build()))?;
    acceptor.set_min_proto_version(Some(SslVersion::TLS1_3))?;
    run.observe(&mut acceptor);
    let acceptor = acceptor.build();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let captured = Arc::new(Captured {
        resumption: Some(Arc::clone(&run)),
        ..Captured::default()
    });
    let server = async {
        for _ in 0..2 {
            let (tcp, _) = listener.accept().await?;
            let slot = captured.reserve_tcp();
            record_tcp(tcp, acceptor.clone(), Arc::clone(&captured), slot).await?;
        }
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };
    let client = async {
        let mut builder = SslConnector::bare_builder(SslMethod::tls())?;
        builder.set_verify(SslVerifyMode::PEER);
        builder
            .cert_store_mut()
            .add_cert(X509::from_der(&trust_root)?)?;
        builder.set_min_proto_version(Some(SslVersion::TLS1_3))?;
        builder.set_alpn_protos(HTTP1_ALPN_WIRE)?;
        builder.enable_scoped_client_sessions_with_early_data();
        let connector = builder.build();
        let scope = SslSessionScope::default();
        let tickets: Tickets = Arc::default();
        for (index, path) in [SEED, RESUME].into_iter().enumerate() {
            let session = tickets
                .lock()
                .map_err(|_| "test ticket lock poisoned")?
                .pop()
                .transpose()?;
            if index == 1 && session.is_none() {
                return Err("seed did not deliver a ticket".into());
            }
            let published = Arc::clone(&tickets);
            let mut ssl = connector
                .configure()?
                .into_ssl_with_scoped_session(HOSTNAME, &scope, session.as_ref(), move |ticket| {
                    published
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push(ticket);
                })?
                .ok_or("scoped client session rejected")?;
            ssl.set_ech_config_list(&list)?;
            ssl.set_early_data_enabled(true);
            let mut tls = SslStream::new(ssl, TcpStream::connect(address).await?)?;
            Pin::new(&mut tls).connect().await?;
            if index == 0 {
                assert!(tls.ssl().is_init_finished());
                assert!(tls.ssl().ech_accepted());
                assert!(tls.ssl().authenticate_scoped_session_publication());
            } else {
                assert!(tls.ssl().in_early_data());
                assert!(!tls.ssl().is_init_finished());
            }
            let request = format!("GET {path} HTTP/1.1\r\nhost: {HOSTNAME}\r\n\r\n");
            tls.write_all(request.as_bytes()).await?;
            tls.flush().await?;
            if index == 1 {
                let completion = Pin::new(&mut tls).do_handshake().await;
                if mode == Mode::EarlyReject {
                    let rejected = completion
                        .err()
                        .ok_or("native client accepted rejected early data")?;
                    assert_eq!(rejected.code(), ErrorCode::EARLY_DATA_REJECTED);
                    assert!(tls.ssl_mut().reset_early_data_reject());
                    Pin::new(&mut tls).do_handshake().await?;
                    tls.write_all(request.as_bytes()).await?;
                    tls.flush().await?;
                } else {
                    completion?;
                    // No more application bytes follow the early GET. The
                    // server must consume Finished and respond without one.
                }
                assert!(tls.ssl().is_init_finished());
                assert!(tls.ssl().session_reused());
                assert!(tls.ssl().ech_accepted());
                assert_eq!(tls.ssl().early_data_accepted(), mode == Mode::EarlyAccept);
            }
            let mut response = Vec::new();
            tls.read_to_end(&mut response).await?;
            assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
            if index == 0 {
                assert!(response.ends_with(SEED_PAGE));
            } else {
                assert!(response.ends_with(b"\r\n\r\nok"));
            }
            tls.shutdown().await?;
        }
        Ok::<(), Box<dyn Error + Send + Sync>>(())
    };
    // Direct joined futures own both sides; error/timeout drops both endpoints.
    timeout(Duration::from_secs(3), async {
        tokio::try_join!(server, client)
    })
    .await??;
    let state = run.lock();
    let seed = state
        .connections
        .get(&state.seed.ok_or("actual seed not recorded")?)
        .ok_or("seed missing")?;
    let resumed = state
        .connections
        .values()
        .find(|value| value.requests.iter().any(|request| request.path == RESUME))
        .ok_or("resumed request missing")?;
    assert!(seed.handshake_complete);
    assert!(!seed.resumed);
    assert!(
        seed.tickets
            .iter()
            .any(|ticket| ticket.max_early_data.is_some_and(|size| size > 0))
    );
    assert!(resumed.handshake_complete);
    assert!(resumed.resumed);
    assert!(resumed.offers.iter().any(|offer| {
        offer.early_data
            && offer
                .tickets
                .iter()
                .any(|hash| seed.tickets.iter().any(|ticket| &ticket.sha256 == hash))
    }));
    assert_eq!(resumed.early_accepted, mode == Mode::EarlyAccept);
    assert_eq!(resumed.early_bytes > 0, mode == Mode::EarlyAccept);
    let request = format!("GET {RESUME} HTTP/1.1\r\nhost: {HOSTNAME}\r\n\r\n");
    if mode == Mode::EarlyAccept {
        assert_eq!(resumed.early_bytes, request.len());
        assert_eq!(
            resumed.early_sha256.as_deref(),
            Some(digest(request.as_bytes()).as_str())
        );
    } else {
        assert_eq!(resumed.early_sha256, None);
    }
    assert_eq!(resumed.requests.len(), 1);
    assert_eq!(resumed.requests[0].head_sha256, digest(request.as_bytes()));
    assert_eq!(resumed.requests[0].early_bytes, resumed.early_bytes);
    assert_eq!(
        resumed
            .requests
            .iter()
            .filter(|request| request.served)
            .count(),
        1
    );
    Ok(())
}

#[tokio::test]
async fn actual_ech_resumption_records_plaintext_before_finished_and_one_served_get()
-> CaptureResult<()> {
    sequence(Mode::EarlyAccept).await
}

#[tokio::test]
async fn actual_rejected_early_data_records_only_the_post_finished_replay_as_served()
-> CaptureResult<()> {
    sequence(Mode::EarlyReject).await
}
