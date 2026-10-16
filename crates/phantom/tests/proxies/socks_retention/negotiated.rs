//! Ordinary negotiated and exact H2 requests use complete SOCKS negotiations.
use super::*;
use crate::support::tls::H2_ALPN;
use http::{Method, Version};
use phantom::{RequestBuilder, RequestErrorKind};

fn client(
    identity: &TestIdentity,
    address: std::net::SocketAddr,
    calls: Arc<AtomicUsize>,
) -> TestResult<Client> {
    let mut tcp = firefox::v157_tcp();
    tcp.address_selection = TcpAddressSelection::Backup(TcpBackupConnection {
        delay: Duration::from_millis(1),
        known_family_backup_timeout: Some(Duration::from_secs(1)),
    });
    let profile = ClientProfile::new(tls_settings())
        .with_tcp(tcp)
        .with_http1(firefox::v157_http1())
        .with_http2(firefox::v157_http2());
    Ok(Client::builder(profile)
        .add_root_certificate_der(identity.root_der.clone())
        .route(Route::socks5(
            Socks5Proxy::new(&format!("socks5h://{address}"))?
                .with_username_password("user", "secret")?,
        ))
        .dns_resolver(AddressResolver::from_fn(move |_| {
            calls.fetch_add(1, Ordering::Relaxed);
            async {
                Err(io::Error::other(
                    "remote target must not be resolved locally",
                ))
            }
        }))
        .build()?)
}

fn request(
    client: &Client,
    exact: bool,
    path: &str,
) -> Result<RequestBuilder, phantom::RequestError> {
    let uri = format!("https://{HOST}/{path}");
    let request = if exact {
        client.request(HttpProtocol::Http2, Method::POST, &uri)?
    } else {
        client.request_negotiated(Method::POST, &uri)?
    };
    Ok(request
        .header(RequestHeader::new("x-current", path))
        .body("current-body"))
}

#[tokio::test]
async fn negotiated_h2_cancels_pending_socks_and_reuses_only_the_authenticated_winner()
-> TestResult<()> {
    h2_requests(false).await
}

#[tokio::test]
async fn exact_h2_cancels_pending_socks_and_reuses_only_the_authenticated_winner() -> TestResult<()>
{
    h2_requests(true).await
}

async fn h2_requests(exact: bool) -> TestResult<()> {
    timeout(WAIT, async {
        let identity = TestIdentity::generate_for_dns(HOST)?;
        let acceptor = identity.acceptor(H2_ALPN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let client = client(&identity, address, Arc::clone(&calls))?;
        let peer = async {
            let mut first = negotiate(&listener, Protocol::Five, 443).await?;
            let mut second = negotiate(&listener, Protocol::Five, 443).await?;
            reply(&mut second, Protocol::Five).await?;
            let stream = accept_tls_stream(second, acceptor).await?;
            let mut byte = [0];
            match first.read(&mut byte).await {
                Ok(0) => {},
                Err(error) if matches!(error.kind(), io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted | io::ErrorKind::BrokenPipe) => {},
                other => return Err(format!("pending SOCKS was not canceled: {other:?}").into()),
            }
            let mut connection = ::http2::server::handshake(stream).await?;
            for (path, stream_id) in [("first", 3), ("current", 5)] {
                let (request, mut respond) = connection.accept().await.ok_or("missing pooled H2 request")??;
                assert_eq!(request.method(), Method::POST);
                assert_eq!(request.uri().path(), format!("/{path}"));
                assert_eq!(request.uri().authority().map(|a| a.as_str()), Some(HOST));
                assert_eq!(request.headers()["x-current"], path);
                assert!(!request.headers().contains_key("proxy-authorization"));
                assert_eq!(respond.stream_id().as_u32(), stream_id);
                let mut body = request.into_body();
                let body = async {
                    let mut bytes = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk?;
                        body.flow_control().release_capacity(chunk.len())?;
                        bytes.extend_from_slice(&chunk);
                    }
                    assert_eq!(bytes, b"current-body");
                    TestResult::Ok(())
                };
                tokio::select! {
                    result = body => result?,
                    extra = connection.accept() => return Err(format!("unexpected concurrent request before body completion: {extra:?}").into()),
                }
                respond.send_response(http::Response::builder().status(204).body(())?, true)?;
            }
            assert!(connection.accept().await.is_none(), "unexpected replay");
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(listener.poll_accept(&mut context).is_pending(), "reused request redialed or repeated authentication");
            TestResult::Ok(())
        };
        let caller = async {
            for path in ["first", "current"] {
                let response = request(&client, exact, path)?.send().await?;
                assert_eq!(response.version(), Version::HTTP_2);
                assert_eq!(response.status(), 204);
                assert!(response.into_body().collect().await?.to_bytes().is_empty());
            }
            drop(client);
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        Ok(())
    }).await?
}

#[tokio::test]
async fn negotiated_h1_claims_the_authenticated_tls_spare_without_redial_or_old_headers()
-> TestResult<()> {
    timeout(WAIT, async {
        let identity = TestIdentity::generate_for_dns(HOST)?;
        let acceptor = identity.acceptor(H1_ALPN)?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let calls = Arc::new(AtomicUsize::new(0));
        let client = client(&identity, address, Arc::clone(&calls))?;
        let (release, released) = oneshot::channel();
        let (ready, was_ready) = oneshot::channel();
        let (claim, claimed) = oneshot::channel();
        let (quiet, was_quiet) = oneshot::channel();
        let caller = async {
            let response = client
                .get_negotiated(&format!("https://{HOST}/prime"))?
                .header(RequestHeader::new("x-claim", "prime"))
                .send()
                .await?;
            assert_eq!(response.version(), Version::HTTP_11);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            release.send(()).map_err(|_| "spare peer ended")?;
            was_ready.await?;
            claim.send(()).map_err(|_| "spare peer ended")?;
            was_quiet.await?;
            let response = client
                .get_negotiated(&format!("https://{HOST}/current"))?
                .header(RequestHeader::new("x-claim", "current"))
                .send()
                .await?;
            assert_eq!(response.version(), Version::HTTP_11);
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            drop(client);
            TestResult::Ok(())
        };
        let peer = async {
            let mut first = negotiate(&listener, Protocol::Five, 443).await?;
            let mut second = negotiate(&listener, Protocol::Five, 443).await?;
            reply(&mut second, Protocol::Five).await?;
            let mut second = accept_tls_stream(second, acceptor.clone()).await?;
            respond(&mut second, "prime", "x-claim").await?;
            released.await?;
            reply(&mut first, Protocol::Five).await?;
            let first = accept_tls_stream(first, acceptor).await?;
            super::claim(first, ready, claimed, quiet, "x-claim").await?;
            let mut context = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(listener.poll_accept(&mut context).is_pending());
            TestResult::Ok(())
        };
        tokio::try_join!(caller, peer)?;
        assert_eq!(calls.load(Ordering::Relaxed), 0);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn both_public_h2_paths_report_proxy_auth_failure_without_sending_origin_bytes()
-> TestResult<()> {
    for exact in [false, true] {
        timeout(WAIT, async {
            let identity = TestIdentity::generate_for_dns(HOST)?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let calls = Arc::new(AtomicUsize::new(0));
            let client = client(&identity, address, Arc::clone(&calls))?;
            let caller = async {
                let error = match request(&client, exact, "private")?.send().await {
                    Ok(_) => return Err("proxy authentication failure accepted".into()),
                    Err(error) => error,
                };
                assert_eq!(error.kind(), RequestErrorKind::Proxy);
                assert!(!error.to_string().contains("secret"));
                drop(client);
                TestResult::Ok(())
            };
            let peer = async {
                let (mut stream, _) = listener.accept().await?;
                let mut greeting = [0; 4];
                stream.read_exact(&mut greeting).await?;
                assert_eq!(greeting, [5, 2, 0, 2]);
                stream.write_all(&[5, 2]).await?;
                let mut auth = [0; 13];
                stream.read_exact(&mut auth).await?;
                assert_eq!(&auth, b"\x01\x04user\x06secret");
                stream.write_all(&[1, 1]).await?;
                let mut byte = [0];
                match stream.read(&mut byte).await {
                    Ok(0) => {}
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                                | io::ErrorKind::BrokenPipe
                        ) => {}
                    other => {
                        return Err(format!(
                            "failed SOCKS authentication received origin bytes: {other:?}"
                        )
                        .into());
                    }
                }
                TestResult::Ok(())
            };
            tokio::try_join!(caller, peer)?;
            assert_eq!(calls.load(Ordering::Relaxed), 0);
            TestResult::Ok(())
        })
        .await??;
    }
    Ok(())
}
