use super::*;

#[derive(Debug, PartialEq, Eq)]
enum RelayExit {
    Cancelled,
    Completed,
}

struct ExitWitness {
    sender: Option<oneshot::Sender<RelayExit>>,
    completed: bool,
}

impl Drop for ExitWitness {
    fn drop(&mut self) {
        if let Some(sender) = self.sender.take() {
            let exit = if self.completed {
                RelayExit::Completed
            } else {
                RelayExit::Cancelled
            };
            // A missing observer is not evidence of a successful close.
            let _ = sender.send(exit);
        }
    }
}

struct ReleaseOnDrop(Option<oneshot::Sender<()>>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        if let Some(release) = self.0.take() {
            // The control must release its baseline relay on exceptional exit too.
            let _ = release.send(());
        }
    }
}

#[tokio::test]
async fn dropping_the_verified_tunnel_relay_cancels_it_with_both_peers_live() -> TestResult<()> {
    let origin_identity = TestIdentity::generate()?;
    let proxy_identity = TestIdentity::generate()?;
    let origin_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let origin_address = origin_listener.local_addr()?;
    let origin_acceptor = origin_identity.acceptor(H2_ALPN)?;
    let (done, done_rx) = oneshot::channel::<()>();
    let origin = ConnectionPeer::spawn(async move {
        let stream = accept_tls(origin_listener, origin_acceptor).await?;
        let mut connection = ::http2::server::handshake(stream).await?;
        let (request, mut respond) = connection
            .accept()
            .await
            .ok_or("missing tunneled request")??;
        assert_eq!(request.method(), http::Method::GET);
        assert_eq!(request.uri().path(), "/h2");
        let mut body = respond.send_response(Response::new(()), false)?;
        body.send_data(Bytes::from_static(b"verified"), true)?;
        tokio::select! {
            result = done_rx => { result?; TestResult::Ok(()) },
            result = connection.accept() => match result {
                None => Ok(()),
                Some(Err(error)) if error.get_io().is_some_and(is_peer_gone) => Ok(()),
                Some(Err(error)) => Err(error.into()),
                Some(Ok(_)) => Err("unexpected additional origin request".into()),
            }
        }
    });

    let proxy_listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let proxy_address = proxy_listener.local_addr()?;
    let proxy_acceptor = proxy_identity.acceptor(H1_ALPN)?;
    let (release, released) = oneshot::channel();
    let mut release = ReleaseOnDrop(Some(release));
    let (exit_sender, mut exit) = oneshot::channel();
    let (outcome_sender, mut outcome) = oneshot::channel();
    let witness = ExitWitness {
        sender: Some(exit_sender),
        completed: false,
    };
    let proxy = ConnectionPeer::spawn(async move {
        let mut stream = accept_tls(proxy_listener, proxy_acceptor).await?;
        let connect = read_head(&mut stream).await?;
        let mut target = TcpStream::connect(origin_address).await?;
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let relay = spawn_relay(async move {
            let mut witness = witness;
            let result = tokio::select! {
                result = copy_bidirectional(&mut stream, &mut target) => result,
                result = released => result.map(|()| (0, 0)).map_err(io::Error::other),
            };
            witness.completed = true;
            // The actual relay error remains independently observable before its owner is lost.
            let copied = result
                .as_ref()
                .copied()
                .map_err(|error| io::Error::new(error.kind(), error.to_string()));
            outcome_sender
                .send(copied)
                .map_err(|_| io::Error::other("relay outcome observer disappeared"))?;
            result
        });
        TestResult::Ok((connect, relay))
    });
    let snapshot =
        EnvironmentProxies::from_values([("https_proxy", format!("https://{proxy_address}"))])?;
    let client = client_builder(&origin_identity, true)
        .add_proxy_root_certificate_der(proxy_identity.root_der)
        .environment_proxies(snapshot)
        .build()?;
    let response = client
        .get(HttpProtocol::Http2, &format!("https://{origin_address}/h2"))?
        .send()
        .await?;
    assert_eq!(response.version(), http::Version::HTTP_2);
    assert_eq!(response.status(), 200);
    assert_eq!(response.into_body().collect().await?.to_bytes(), "verified");
    let (connect, relay) = timeout(DEADLINE, proxy).await???;
    assert!(connect.starts_with(format!("CONNECT {origin_address} HTTP/1.1\r\n").as_bytes()));

    drop(relay);
    let observed = match timeout(QUIET, &mut exit).await {
        Ok(result) => Some(result?),
        Err(_) => None,
    };
    if observed.is_none() {
        release
            .0
            .take()
            .ok_or("missing baseline release")?
            .send(())
            .map_err(|_| "relay ended before fallback release")?;
        assert_eq!(timeout(DEADLINE, &mut outcome).await???, (0, 0));
        assert_eq!(timeout(DEADLINE, &mut exit).await??, RelayExit::Completed);
    } else if observed == Some(RelayExit::Completed) {
        timeout(DEADLINE, &mut outcome).await???;
    }

    let origin_cleanup = origin.stop().await;
    // The client and completion sender stay live through the owner-lifetime observation.
    drop(client);
    drop(done);
    origin_cleanup?;
    assert_eq!(
        observed,
        Some(RelayExit::Cancelled),
        "verified relay outlived its owner during finite observation"
    );
    Ok(())
}
