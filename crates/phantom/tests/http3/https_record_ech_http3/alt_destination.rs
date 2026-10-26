//! A learned alternative has its own DNS metadata and keeps origin authentication.

use std::sync::Mutex;

use phantom::AltSvcHttpsPolicy;
use phantom_net::dns::{HttpsRecord, HttpsRecordAnswer, HttpsRecordLookup};

use super::*;

const DESTINATION: &str = "alternative.test";

type HandshakeObservations = Vec<(Observed, Option<String>)>;

struct DestinationOrigin {
    port: u16,
    tcp_reservation: TcpListener,
    stop: oneshot::Sender<()>,
    task: ConnectionPeer<TestResult<HandshakeObservations>>,
}

impl DestinationOrigin {
    async fn spawn(identity: &TestIdentity) -> TestResult<Self> {
        let context = QuicOrigin::context(identity, 1, &TEST_ECH_KEYS[0])?;
        let (endpoint, tcp_reservation) = Self::bind(&context).await?;
        let port = endpoint.local_addr()?.port();
        let (stop, mut stopped) = oneshot::channel();
        let task = ConnectionPeer::spawn(async move {
            let mut observed = Vec::new();
            let result: TestResult<()> = async {
                loop {
                    let incoming = tokio::select! {
                        biased;
                        _ = &mut stopped => break,
                        incoming = endpoint.accept() => incoming.ok_or("QUIC endpoint closed")?,
                    };
                    let outcome = tokio::select! {
                        biased;
                        _ = &mut stopped => break,
                        result = async {
                            let (seen, connection) = observe(incoming, None).await?;
                            let authority = match connection {
                                Some(connection) => Some(answer(connection).await?),
                                None => None,
                            };
                            Ok::<_, Box<dyn Error + Send + Sync>>((seen, authority))
                        } => result?,
                    };
                    observed.push(outcome);
                }
                Ok(())
            }
            .await;
            endpoint.close(0_u32.into(), b"test finished");
            let cleanup = timeout(TEST_TIMEOUT, endpoint.wait_idle())
                .await
                .map_err(Into::into);
            finish_with_cleanup(result, cleanup)?;
            Ok(observed)
        });
        Ok(Self {
            port,
            tcp_reservation,
            stop,
            task,
        })
    }

    async fn bind(context: &SslContext) -> TestResult<(quinn::Endpoint, TcpListener)> {
        let mut last_error = None;
        for port in shared_port::candidates() {
            let endpoint = match QuicOrigin::endpoint(context, port) {
                Ok(endpoint) => endpoint,
                Err(error) if shared_port::is_unavailable_boxed(error.as_ref()) => {
                    last_error = Some(error.to_string());
                    continue;
                }
                Err(error) => return Err(error),
            };
            match TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await {
                Ok(listener) => return Ok((endpoint, listener)),
                Err(error) if shared_port::is_unavailable(&error) => {
                    last_error = Some(error.to_string());
                }
                Err(error) => return Err(error.into()),
            }
        }
        Err(format!(
            "no loopback port was free for both UDP and TCP; last error: {}",
            last_error.as_deref().unwrap_or("none")
        )
        .into())
    }

    async fn finish(self) -> TestResult<HandshakeObservations> {
        let _reservation = self.tcp_reservation;
        let _ = self.stop.send(());
        timeout(TEST_TIMEOUT, self.task).await??
    }
}

async fn answer(connection: quinn::Connection) -> TestResult<String> {
    let mut h3 =
        h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(connection.clone()))
            .await?;
    let resolver = h3
        .accept()
        .await?
        .ok_or("client closed before alternative request")?;
    let (request, mut stream) = resolver.resolve_request().await?;
    let authority = request
        .uri()
        .authority()
        .ok_or("HTTP/3 authority absent")?
        .to_string();
    stream
        .send_response(http::Response::builder().status(200).body(())?)
        .await?;
    stream.send_data(Bytes::from_static(b"ok")).await?;
    stream.finish().await?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    connection.close(0_u32.into(), b"next handshake");
    Ok(authority)
}

struct Advertisement {
    port: u16,
    stop: oneshot::Sender<()>,
    task: ConnectionPeer<TestResult<Vec<u8>>>,
}

impl Advertisement {
    async fn spawn(identity: &TestIdentity, destination: u16) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let acceptor = identity.acceptor(H1_ALPN)?;
        let (stop, mut stopped) = oneshot::channel();
        let task = ConnectionPeer::spawn(async move {
            tokio::select! {
                biased;
                _ = &mut stopped => Err("advertisement stopped before response".into()),
                result = async {
                    let (tcp, _) = listener.accept().await?;
                    let (_, tls) = try_handshake(tcp, &acceptor).await?;
                    let mut tls = tls.ok_or("advertisement TLS handshake failed")?;
                    let head = read_head(&mut tls).await?;
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nAlt-Svc: h3=\"{DESTINATION}:{destination}\"; ma=300\r\n\r\nok"
                    );
                    tls.write_all(response.as_bytes()).await?;
                    tls.shutdown().await?;
                    Ok(head)
                } => result,
            }
        });
        Ok(Self { port, stop, task })
    }

    async fn finish(self) -> TestResult<Vec<u8>> {
        let _stop = self.stop;
        timeout(TEST_TIMEOUT, self.task).await??
    }
}

#[derive(Clone, Copy)]
enum Reply {
    Ech,
    Empty,
    Incompatible,
    Delayed,
    Failed,
}

async fn exchange(reply: Reply, requests: usize, destination_policy: bool) -> TestResult<()> {
    let identity = origin_identity()?;
    let origin = DestinationOrigin::spawn(&identity).await?;
    let destination_port = origin.port;
    let advertisement = Advertisement::spawn(&identity, origin.port).await?;
    assert_ne!(advertisement.port, destination_port);
    let authority = format!("{ORIGIN_NAME}:{}", advertisement.port);
    let url = format!("https://{authority}/resource");
    let queries = Arc::new(Mutex::new(Vec::new()));
    let recorded_queries = queries.clone();
    let ech = ech_config_list(&[ech_config(1, &TEST_ECH_KEYS[0], PUBLIC_NAME)]);
    let record = HttpsRecord::from_rdata(&https_rdata_with_alpn(
        if matches!(reply, Reply::Incompatible) {
            &[b"h2"]
        } else {
            &[b"h3"]
        },
        &ech,
    ))?;
    let resolver = HttpsRecordResolver::from_fn(move |host, port| {
        let record = record.clone();
        let queries = recorded_queries.clone();
        async move {
            queries
                .lock()
                .map_err(|_| {
                    phantom_net::dns::HttpsLookupError::other(std::io::Error::other(
                        "query observer poisoned",
                    ))
                })?
                .push((host.to_string(), port));
            if host == DESTINATION {
                if matches!(reply, Reply::Failed) {
                    return Err(phantom_net::dns::HttpsLookupError::other(
                        std::io::Error::other("controlled destination failure"),
                    ));
                }
                if matches!(reply, Reply::Delayed) {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                if !matches!(reply, Reply::Empty) {
                    return Ok(HttpsRecordLookup::new(
                        vec![HttpsRecordAnswer::new(DESTINATION, 300, record)],
                        None,
                    ));
                }
            }
            Ok(HttpsRecordLookup::new(Vec::new(), Some(300)))
        }
    });
    let builder = Client::builder(profile(true))
        .add_root_certificate_der(identity.root_der.clone())
        .alt_svc(NonZeroUsize::MIN.saturating_add(7))
        .alt_svc_policy(AltSvcPolicy::sequential())
        .https_record_discovery(resolver)
        .http3_early_data(false)
        .resolve(ORIGIN_NAME, [Ipv4Addr::LOCALHOST.into()])
        .resolve(DESTINATION, [Ipv4Addr::LOCALHOST.into()]);
    let builder = if destination_policy {
        builder.alt_svc_https_policy(AltSvcHttpsPolicy::Destination {
            lookup_timeout: if matches!(reply, Reply::Delayed) {
                Duration::from_millis(100)
            } else {
                Duration::from_secs(1)
            },
        })
    } else {
        builder
    };
    let client = builder.build()?;
    let operation = async {
        get_as(&client, None, &url, HttpProtocol::Http1).await?;
        for _ in 0..requests {
            if matches!(reply, Reply::Incompatible | Reply::Delayed | Reply::Failed) {
                let error = client
                    .get(&url)?
                    .send()
                    .await
                    .err()
                    .ok_or("failed destination lookup silently sent a request")?;
                assert_eq!(error.kind(), RequestErrorKind::Resolve);
                assert_eq!(error.protocol(), Some(HttpProtocol::Http3));
                if matches!(reply, Reply::Failed) {
                    let source =
                        std::iter::successors(Some(&error as &(dyn Error + 'static)), |source| {
                            (*source).source()
                        })
                        .find_map(|source| {
                            source.downcast_ref::<phantom_net::dns::HttpsLookupError>()
                        })
                        .ok_or("typed destination lookup failure was erased")?;
                    let cause = source
                        .source()
                        .and_then(|cause| cause.downcast_ref::<std::io::Error>())
                        .ok_or("controlled resolver cause was erased")?;
                    assert_eq!(cause.to_string(), "controlled destination failure");
                }
            } else {
                get_as(&client, None, &url, HttpProtocol::Http3).await?;
                tokio::time::sleep(SETTLE).await;
            }
        }
        Ok(())
    }
    .await;
    let tcp = advertisement.finish().await;
    let quic = origin.finish().await;
    let cleanup = finish_with_cleanup(
        quic,
        tcp.map(|head| {
            assert!(String::from_utf8_lossy(&head).lines().any(|line| {
                line.split_once(':').is_some_and(|(name, value)| {
                    name.eq_ignore_ascii_case("host") && value.trim() == authority
                })
            }));
        }),
    );
    let observed = match operation {
        Ok(()) => cleanup?,
        Err(error) => return finish_with_cleanup(Err(error), cleanup.map(|_| ())),
    };
    if matches!(reply, Reply::Incompatible | Reply::Delayed | Reply::Failed) {
        assert!(
            observed.is_empty(),
            "QUIC started before required DNS metadata: {observed:?}"
        );
    } else {
        assert_eq!(observed.len(), requests);
        for (seen, observed_authority) in &observed {
            assert_eq!(seen.server_name.as_deref(), Some(ORIGIN_NAME));
            assert_eq!(observed_authority.as_deref(), Some(authority.as_str()));
            if destination_policy && matches!(reply, Reply::Ech) {
                assert_accepted(seen);
            } else {
                assert!(!seen.ech_accepted);
            }
        }
        if requests == 2 {
            assert!(!observed[0].0.session_resumed);
            assert!(observed[1].0.session_resumed);
        }
    }
    let queries = queries.lock().map_err(|_| "query observer poisoned")?;
    let destinations = queries
        .iter()
        .filter(|(host, _)| host == DESTINATION)
        .cloned()
        .collect::<Vec<_>>();
    let expected = if destination_policy {
        vec![(DESTINATION.to_owned(), destination_port)]
    } else {
        Vec::new()
    };
    assert_eq!(destinations, expected);
    Ok(())
}

#[tokio::test]
async fn destination_keeps_its_tcp_port_reserved() -> TestResult<()> {
    bounded(async {
        let identity = origin_identity()?;
        let origin = DestinationOrigin::spawn(&identity).await?;
        let port = origin.port;
        let duplicate = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).await;
        let advertisement = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await;
        let cleanup = origin.finish().await;
        let advertisement = advertisement?;
        let error = duplicate
            .err()
            .ok_or("destination TCP port was not reserved")?;
        assert!(shared_port::is_unavailable(&error), "{error}");
        assert_ne!(advertisement.local_addr()?.port(), port);
        cleanup?;
        Ok(())
    })
    .await
}

#[tokio::test]
async fn learned_destination_ech_keeps_origin_authority_and_resumes() -> TestResult<()> {
    bounded(exchange(Reply::Ech, 2, true)).await
}

#[tokio::test]
async fn authoritative_empty_destination_keeps_origin_authentication() -> TestResult<()> {
    bounded(exchange(Reply::Empty, 1, true)).await
}

#[tokio::test]
async fn incompatible_destination_records_prevent_quic() -> TestResult<()> {
    bounded(exchange(Reply::Incompatible, 1, true)).await
}

#[tokio::test]
async fn required_destination_deadline_prevents_quic() -> TestResult<()> {
    bounded(exchange(Reply::Delayed, 1, true)).await
}

#[tokio::test]
async fn failed_destination_lookup_prevents_quic() -> TestResult<()> {
    bounded(exchange(Reply::Failed, 1, true)).await
}

#[tokio::test]
async fn default_policy_does_not_query_the_learned_destination() -> TestResult<()> {
    bounded(exchange(Reply::Ech, 1, false)).await
}
