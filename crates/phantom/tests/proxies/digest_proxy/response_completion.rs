//! Forwarded body completion, cancellation and HTTP/2 trailer boundaries.

use super::*;

#[tokio::test]
async fn dropping_a_partially_read_digest_response_does_not_accept_its_nextnonce() -> TestResult {
    tokio::time::timeout(Duration::from_secs(15), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let peer = ConnectionPeer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            assert!(authorization(&read_head(&mut stream).await?)?.is_none());
            stream.write_all(challenge("SHA-256", "first", false).as_bytes()).await?;
            let value = authorization(&read_head(&mut stream).await?)?.ok_or("authorization missing")?;
            let proof = oracle::verify(&value, "GET", URL, "SHA-256", "first")?;
            // Keep the body incomplete after a valid response-head proof.
            stream.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nProxy-Authentication-Info: {}, nextnonce=third\r\n\r\nok", proof.information).as_bytes()).await?;
            let next = tokio::select! {
                head = read_head(&mut stream) => match head {
                    Ok(head) => head,
                    Err(error) if crate::support::tls::is_peer_gone(&error) || error.kind() == std::io::ErrorKind::UnexpectedEof => {
                        stream = listener.accept().await?.0;
                        read_head(&mut stream).await?
                    }
                    Err(error) => return Err(error.into()),
                },
                accepted = listener.accept() => {
                    stream = accepted?.0;
                    read_head(&mut stream).await?
                }
            };
            assert!(authorization(&next)?.is_none(), "partial body accepted a nonce");
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await?;
            Ok(())
        });
        let operation = async {
            let identity = TestIdentity::generate()?;
            let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?.with_digest_auth("user", "password")?);
            let client = client_builder(&identity, false).route(route).build()?;
            let response = client.get(HttpProtocol::Http1, URL)?.send().await?;
            let mut body = response.into_body();
            let first = body.frame().await.ok_or("partial data frame missing")??;
            assert_eq!(first.data_ref().ok_or("data frame missing")?, "ok");
            drop(body);
            let response = client.get(HttpProtocol::Http1, URL)?.send().await?;
            assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
            Ok(client)
        }.await;
        finish_peer(operation, peer).await?;
        Ok(())
    }).await.map_err(|_| "Digest partial body deadline")?
}

#[derive(Clone, Copy, Debug)]
enum TrailerProof {
    Valid,
    Incorrect,
    Missing,
}

#[tokio::test]
async fn http2_digest_trailers_are_verified_before_the_nonce_becomes_preemptive() -> TestResult {
    tokio::time::timeout(Duration::from_secs(25), async {
        for location in [TrailerProof::Valid, TrailerProof::Incorrect, TrailerProof::Missing] {
            let identity = TestIdentity::generate()?;
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let acceptor = identity.acceptor(H2_ALPN)?;
            let (done_tx, mut done_rx) = tokio::sync::oneshot::channel();
            let peer = ConnectionPeer::spawn(async move {
                let (tcp, _) = listener.accept().await?;
                let stream = accept_tls_stream(tcp, acceptor).await?;
                let mut connection = http2::server::handshake(stream).await?;
                for index in 0..3 {
                    let (request, mut respond) = connection.accept().await.ok_or("forwarded request missing")??;
                    assert_eq!(request.method(), http::Method::GET);
                    assert_eq!(request.uri().path_and_query().map(|value| value.as_str()), Some(PATH));
                    let value = request.headers().get("proxy-authorization");
                    if index == 0 {
                        assert!(value.is_none());
                        respond.send_response(http::Response::builder().status(407).header("proxy-authenticate", oracle::challenge("SHA-256", "first", false)).body(())?, true)?;
                    } else if index == 1 {
                        let proof = oracle::verify(value.ok_or("missing Digest")?.to_str()?, "GET", PATH, "SHA-256", "first")?;
                        let mut send = respond.send_response(http::Response::builder().header("trailer", "Proxy-Authentication-Info").body(())?, false)?;
                        send.send_data(bytes::Bytes::from_static(b"ok"), false)?;
                        let mut trailers = http::HeaderMap::new();
                        match location {
                            TrailerProof::Valid => { trailers.insert("proxy-authentication-info", format!("{}, nextnonce=third", proof.information).parse()?); }
                            TrailerProof::Incorrect => { trailers.insert("proxy-authentication-info", format!("{}, nextnonce=third", proof.information.replacen("rspauth=\"", "rspauth=\"0", 1)).parse()?); }
                            TrailerProof::Missing => { trailers.insert("x-end", "complete".parse()?); }
                        }
                        send.send_trailers(trailers)?;
                    } else {
                        if matches!(location, TrailerProof::Valid) {
                            let proof = oracle::verify(value.ok_or("verified nextnonce not remembered")?.to_str()?, "GET", PATH, "SHA-256", "third")?;
                            assert_eq!(proof.count, "00000001");
                        } else { assert!(value.is_none(), "invalid trailer accepted nonce: {location:?}"); }
                        let mut send = respond.send_response(http::Response::builder().body(())?, false)?;
                        send.send_data(bytes::Bytes::from_static(b"ok"), true)?;
                    }
                }
                tokio::select! {
                    _ = &mut done_rx => {},
                    request = connection.accept() => { if let Some(request) = request { request?; return Err("unexpected forwarded request".into()); } }
                }
                Ok(())
            });
            let operation = async {
                let route = Route::http_proxy(HttpProxy::new(&format!("https://{address}"))?.with_http2_transport()?.with_digest_auth("user", "password")?);
                let client = client_builder(&identity, true).add_proxy_root_certificate_der(identity.root_der.clone()).route(route).build()?;
                let response = client.get(HttpProtocol::Http2, URL)?.send().await?;
                let result = response.into_body().collect().await;
                if matches!(location, TrailerProof::Valid) { assert_eq!(result?.to_bytes(), "ok"); }
                else { assert!(result.is_err(), "invalid H2 trailer accepted: {location:?}"); }
                let response = client.get(HttpProtocol::Http2, URL)?.send().await?;
                assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
                done_tx.send(()).map_err(|()| "peer exited early")?;
                Ok(client)
            }.await;
            finish_peer(operation, peer).await?;
        }
        Ok(())
    }).await.map_err(|_| "Digest HTTP/2 trailer deadline")?
}

#[tokio::test]
async fn empty_digest_response_with_missing_required_proof_records_body_failure() -> TestResult {
    tokio::time::timeout(Duration::from_secs(10), async {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = listener.local_addr()?;
        let peer = ConnectionPeer::spawn(async move {
            let (mut stream, _) = listener.accept().await?;
            read_head(&mut stream).await?;
            stream.write_all(challenge("SHA-256", "first", false).as_bytes()).await?;
            let value = authorization(&read_head(&mut stream).await?)?.ok_or("missing authorization")?;
            oracle::verify(&value, "GET", URL, "SHA-256", "first")?;
            stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTrailer: Proxy-Authentication-Info\r\n\r\n").await?;
            Ok(())
        });
        let operation = async {
            let identity = TestIdentity::generate()?;
            let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?.with_digest_auth("user", "password")?);
            let client = client_builder(&identity, false).route(route).build()?;
            let mut request = client.get(HttpProtocol::Http1, URL)?;
            let diagnostics = request.diagnostics(std::num::NonZeroUsize::MIN.saturating_add(127));
            let error = request.send().await.err().ok_or("missing Digest proof accepted")?;
            assert_eq!(error.kind(), phantom::RequestErrorKind::Proxy);
            let snapshot = diagnostics.snapshot();
            assert_eq!(snapshot.outcome, phantom::RequestTimelineOutcome::Failed);
            assert!(snapshot.events.iter().any(|event| event.phase == phantom::RequestTimingPhase::ResponseBody
                && event.outcome == phantom::RequestTimingOutcome::Failed));
            Ok(client)
        }.await;
        finish_peer(operation, peer).await?;
        Ok(())
    }).await.map_err(|_| "Digest empty-body deadline")?
}
