use super::*;

#[derive(Clone, Copy, Debug)]
enum ProofLocation {
    Trailer,
    WrongTrailer,
    MissingTrailer,
    DuplicateHeadAndTrailer,
}

#[tokio::test]
async fn digest_forwarding_checks_real_chunked_proxy_proofs_before_nonce_acceptance() -> TestResult
{
    tokio::time::timeout(Duration::from_secs(20), async {
        for location in [ProofLocation::Trailer, ProofLocation::WrongTrailer, ProofLocation::MissingTrailer, ProofLocation::DuplicateHeadAndTrailer] {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
            let address = listener.local_addr()?;
            let peer = ConnectionPeer::spawn(async move {
                let (mut stream, _) = listener.accept().await?;
                assert!(authorization(&read_head(&mut stream).await?)?.is_none());
                stream.write_all(challenge("SHA-256", "first", false).as_bytes()).await?;
                let value = authorization(&read_head(&mut stream).await?)?.ok_or("authorization missing")?;
                let proof = oracle::verify(&value, "GET", URL, "SHA-256", "first")?;
                let head_proof = if matches!(location, ProofLocation::DuplicateHeadAndTrailer) { format!("Proxy-Authentication-Info: {}, nextnonce=third\r\n", proof.information) } else { String::new() };
                let trailer = match location {
                    ProofLocation::Trailer | ProofLocation::DuplicateHeadAndTrailer => format!("Proxy-Authentication-Info: {}, nextnonce=third\r\n", proof.information),
                    ProofLocation::WrongTrailer => format!("Proxy-Authentication-Info: {}, nextnonce=third\r\n", proof.information.replacen("rspauth=\"", "rspauth=\"0", 1)),
                    ProofLocation::MissingTrailer => String::new(),
                };
                stream.write_all(format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: Proxy-Authentication-Info\r\n{head_proof}\r\n2\r\nok\r\n0\r\n{trailer}\r\n").as_bytes()).await?;
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
                let value = authorization(&next)?;
                if matches!(location, ProofLocation::Trailer) {
                    let proof = oracle::verify(&value.ok_or("verified nextnonce not remembered")?, "GET", URL, "SHA-256", "third")?;
                    assert_eq!(proof.count, "00000001");
                } else {
                    assert!(value.is_none(), "failed response cached nonce: {location:?}");
                }
                stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok").await?;
                Ok(())
            });
            let operation = async {
                let identity = TestIdentity::generate()?;
                let route = Route::http_proxy(HttpProxy::new(&format!("http://{address}"))?.with_digest_auth("user", "password")?);
                let client = client_builder(&identity, false).route(route).build()?;
                let response = client.get(HttpProtocol::Http1, URL)?.send().await?;
                let result = response.into_body().collect().await;
                if matches!(location, ProofLocation::Trailer) { assert_eq!(result?.to_bytes(), "ok"); }
                else { assert!(result.is_err(), "invalid trailer accepted: {location:?}"); }
                let response = client.get(HttpProtocol::Http1, URL)?.send().await?;
                assert_eq!(response.into_body().collect().await?.to_bytes(), "ok");
                Ok(client)
            }.await;
            finish_peer(operation, peer).await?;
        }
        Ok(())
    }).await.map_err(|_| "Digest trailer peer deadline")?
}
