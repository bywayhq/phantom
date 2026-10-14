use super::{
    gate::Gate,
    peer::{Advertisement, NativePeer},
    *,
};

struct Fixture {
    client: Client,
    peer: NativePeer,
    gate: Gate,
    authority: String,
    url: String,
    queries: Arc<std::sync::Mutex<Vec<(String, u16)>>>,
}

impl Fixture {
    async fn begin(attempt: Attempt) -> TestResult<Self> {
        let identity = origin_identity()?;
        let (open, opened) = watch::channel(true);
        let peer = NativePeer::spawn(&identity, attempt, opened)?;
        let gate = match Gate::spawn(peer.address, open).await {
            Ok(gate) => gate,
            Err(error) => return finish_with_cleanup(Err(error), peer.finish().await),
        };
        let advertisement = match Advertisement::spawn(&identity, gate.address.port()).await {
            Ok(advertisement) => advertisement,
            Err(error) => {
                let cleanup = finish_with_cleanup(peer.finish().await, gate.finish().await);
                return finish_with_cleanup(Err(error), cleanup);
            }
        };
        let authority = format!("{ORIGIN_NAME}:{}", advertisement.port);
        let url = format!("https://{authority}");
        let queries = Arc::new(std::sync::Mutex::new(Vec::new()));
        let setup: TestResult<Client> = async {
            let client = destination_client(&identity, queries.clone())?;
            get_as(
                &client,
                None,
                &format!("{url}/advertisement"),
                HttpProtocol::Http1,
            )
            .await?;
            Ok(client)
        }
        .await;
        let advertisement = match &setup {
            Ok(_) => advertisement.finish().await,
            Err(_) => advertisement.stop().await,
        };
        let client = match finish_with_cleanup(setup, advertisement) {
            Ok(client) => client,
            Err(error) => {
                let cleanup = finish_with_cleanup(peer.finish().await, gate.finish().await);
                return finish_with_cleanup(Err(error), cleanup);
            }
        };
        Ok(Self {
            client,
            peer,
            gate,
            authority,
            url,
            queries,
        })
    }

    async fn warm(&mut self) -> TestResult<()> {
        let subscriber = OutcomeSubscriber::default();
        send(
            self.client.clone(),
            format!("{}/warm", self.url),
            Attempt::Accept,
        )
        .with_subscriber(subscriber.dispatch())
        .await?;
        assert_eq!(subscriber.early_data_for("http3.response_head"), ["none"]);
        self.peer.read.send(())?;
        let Event::Pending(pending) = next(&mut self.peer.events).await? else {
            return Err("warm pending observation missing".into());
        };
        assert_eq!(pending.connection, 1);
        assert_eq!(pending.outer_name.as_deref(), Some(PUBLIC_NAME));
        assert!(!pending.offered_early);
        let Event::Request(request) = next(&mut self.peer.events).await? else {
            return Err("warm request observation missing".into());
        };
        self.assert_request(&request, Attempt::Accept, "/warm", true);
        assert_eq!(request.connection, 1);
        assert_eq!(request.stable_id, pending.stable_id);
        let Event::Complete {
            connection,
            stable_id,
            server_notification,
            native,
        } = next(&mut self.peer.events).await?
        else {
            return Err("warm completion missing".into());
        };
        assert_eq!(connection, 1);
        eprintln!("warm server notification (not an acceptance result): {server_notification}");
        assert_eq!(stable_id, pending.stable_id);
        assert!(!native.session_resumed());
        assert!(native.ech_accepted());
        assert_eq!(native.early_data_accepted(), Some(false));
        assert!(matches!(next(&mut self.peer.events).await?, Event::Drained));
        self.gate.open.send_replace(false);
        Ok(())
    }

    fn assert_request(&self, request: &RequestSeen, attempt: Attempt, path: &str, gate_open: bool) {
        assert_eq!(request.authority, self.authority);
        assert_eq!(request.path, path);
        assert_eq!(request.marker, "unchanged");
        assert_eq!(request.gate_open, gate_open);
        assert_eq!(
            request.method,
            if attempt == Attempt::Post {
                http::Method::POST
            } else {
                http::Method::GET
            }
        );
        assert_eq!(
            request.body,
            if matches!(attempt, Attempt::Post | Attempt::GetBody) {
                b"request-body".as_slice()
            } else {
                b""
            }
        );
        assert_eq!(
            request.trailer.as_deref(),
            (attempt == Attempt::GetTrailers).then_some("end")
        );
    }

    async fn finish(self) -> TestResult<()> {
        let Self {
            client,
            peer,
            gate,
            queries,
            ..
        } = self;
        let query_check: TestResult<()> = queries
            .lock()
            .map_err(|_| "query observer poisoned".into())
            .and_then(|queries| {
                let destination_queries = queries
                    .iter()
                    .filter(|(host, _)| host == DESTINATION)
                    .cloned()
                    .collect::<Vec<_>>();
                if destination_queries == [(DESTINATION.to_owned(), gate.address.port())] {
                    Ok(())
                } else {
                    Err(format!("destination queries changed: {destination_queries:?}").into())
                }
            });
        let server = peer.address;
        let sockets = Arc::clone(&gate.sockets);
        gate.open.send_replace(true);
        drop(client);
        let cleanup = finish_with_cleanup(peer.finish().await, gate.finish().await);
        finish_with_cleanup(query_check, cleanup)?;
        // Joined owners have released both listening and upstream sockets.
        let sockets = sockets.lock().map_err(|_| "socket observer poisoned")?;
        for address in sockets.iter().copied().chain([server]) {
            let rebound = phantom_testkit::udp::bind_tokio(address)?;
            assert_eq!(rebound.local_addr()?, address);
        }
        Ok(())
    }
}

async fn exercise(attempt: Attempt) -> TestResult<()> {
    let mut fixture = Fixture::begin(attempt).await?;
    let mut request_peer = None;
    let operation: TestResult<()> = async {
        fixture.warm().await?;
        let subscriber = OutcomeSubscriber::default();
        request_peer = Some(ConnectionPeer::spawn(
            send(
                fixture.client.clone(),
                format!("{}/attempt", fixture.url),
                attempt,
            )
            .with_subscriber(subscriber.dispatch()),
        ));
        let Event::Pending(pending) = next(&mut fixture.peer.events).await? else {
            return Err("resumed pending observation missing".into());
        };
        assert_eq!(pending.connection, 2);
        assert_ne!(pending.stable_id, 0);
        assert!(
            pending.offered_early,
            "real ticket did not offer early_data: {pending:?}"
        );
        assert_eq!(pending.outer_name.as_deref(), Some(PUBLIC_NAME));
        assert_eq!(pending.native.early_data_accepted(), None);
        fixture.gate.held_reply().await?;
        if attempt == Attempt::Cancel {
            early_dispatch(&subscriber).await;
            assert_eq!(subscriber.early_data_for("http3.response_head"), ["sent"]);
            request_peer
                .take()
                .ok_or("request owner absent")?
                .stop()
                .await?;
            return Ok(());
        }
        if attempt == Attempt::RejectEch {
            early_dispatch(&subscriber).await;
            assert_eq!(subscriber.early_data_for("http3.response_head"), ["sent"]);
            assert!(!pending.native.ech_accepted());
            fixture.gate.open.send_replace(true);
            let error = request_peer
                .take()
                .ok_or("request owner absent")?
                .await?
                .err()
                .ok_or("ECH rejection sent application data")?;
            let request = error
                .downcast_ref::<phantom::RequestError>()
                .ok_or("ECH rejection lost request error")?;
            assert_eq!(request.kind(), RequestErrorKind::Tls);
            assert_eq!(subscriber.early_data_for("http3.response_head"), ["sent"]);
            assert!(matches!(
                next(&mut fixture.peer.events).await?,
                Event::EchFailed(ECH_REQUIRED)
            ));
            assert!(matches!(
                next(&mut fixture.peer.events).await?,
                Event::Finished
            ));
            return Ok(());
        }
        assert!(pending.native.ech_accepted());
        assert_eq!(pending.native.server_name(), Some(ORIGIN_NAME));
        let early = attempt == Attempt::Accept;
        let request = if early {
            let Event::Request(request) = next(&mut fixture.peer.events).await? else {
                return Err("early GET never reached native peer".into());
            };
            assert!(
                !pending.native.session_resumed(),
                "pending metadata claimed completed resumption"
            );
            assert_eq!(subscriber.early_data_for("http3.response_head"), ["sent"]);
            Some(request)
        } else {
            if attempt == Attempt::RejectEarly {
                early_dispatch(&subscriber).await;
                assert_eq!(subscriber.early_data_for("http3.response_head"), ["sent"]);
            }
            // Explicitly poll peer observation while the real server flight is held.
            // This is the existing finite quiet window, not future absence proof.
            match timeout(QUIET_WINDOW, fixture.peer.events.recv()).await {
                Err(_) => {}
                Ok(event) => {
                    return Err(format!(
                        "request/handshake progressed through closed gate: {event:?}"
                    )
                    .into());
                }
            }
            assert!(
                !request_peer
                    .as_ref()
                    .ok_or("request owner absent")?
                    .is_finished()
            );
            if attempt != Attempt::RejectEarly {
                assert!(subscriber.early_data_for("http3.response_head").is_empty());
            }
            None
        };
        if let Some(request) = &request {
            fixture.assert_request(request, attempt, "/attempt", false);
            assert_eq!(request.connection, 2);
            assert_eq!(request.stable_id, pending.stable_id);
        }
        fixture.gate.open.send_replace(true);
        request_peer.take().ok_or("request owner absent")?.await??;
        fixture.peer.read.send(())?;
        if !early {
            let Event::Request(request) = next(&mut fixture.peer.events).await? else {
                return Err("post-handshake request missing".into());
            };
            fixture.assert_request(&request, attempt, "/attempt", true);
            assert_eq!(request.connection, pending.connection);
            assert_eq!(request.stable_id, pending.stable_id);
        }
        let Event::Complete {
            connection,
            stable_id,
            server_notification,
            native,
        } = next(&mut fixture.peer.events).await?
        else {
            return Err("native Finished completion missing".into());
        };
        assert_eq!(connection, pending.connection);
        eprintln!("resumed server notification (not an acceptance result): {server_notification}");
        assert_eq!(stable_id, pending.stable_id);
        assert!(native.session_resumed());
        assert!(native.ech_accepted());
        assert_eq!(native.server_name(), Some(ORIGIN_NAME));
        assert_eq!(
            native.early_data_accepted(),
            Some(attempt != Attempt::RejectEarly)
        );
        assert_eq!(
            pending.native.early_data_accepted(),
            None,
            "pending snapshot changed"
        );
        assert_eq!(
            subscriber.early_data_for("http3.response_head"),
            match attempt {
                Attempt::Accept => vec!["sent"],
                Attempt::RejectEarly => vec!["sent", "after_handshake"],
                _ => vec!["after_handshake"],
            }
        );
        assert!(matches!(
            next(&mut fixture.peer.events).await?,
            Event::Drained
        ));
        assert!(matches!(
            next(&mut fixture.peer.events).await?,
            Event::Finished
        ));
        Ok(())
    }
    .await;
    let request_cleanup = match request_peer {
        Some(mut request) => request.shutdown().await,
        None => Ok(()),
    };
    let cleanup = finish_with_cleanup(request_cleanup, fixture.finish().await);
    finish_with_cleanup(operation, cleanup)
}

#[tokio::test]
async fn accepted_ech_get_reaches_alternate_before_any_server_reply() -> TestResult<()> {
    bounded(exercise(Attempt::Accept)).await
}

#[tokio::test]
async fn rejected_early_get_replays_once_on_the_same_ech_connection() -> TestResult<()> {
    bounded(exercise(Attempt::RejectEarly)).await
}

#[tokio::test]
async fn post_body_waits_for_the_resumed_ech_handshake() -> TestResult<()> {
    bounded(exercise(Attempt::Post)).await
}

#[tokio::test]
async fn get_body_waits_for_the_resumed_ech_handshake() -> TestResult<()> {
    bounded(exercise(Attempt::GetBody)).await
}

#[tokio::test]
async fn get_trailers_wait_for_the_resumed_ech_handshake() -> TestResult<()> {
    bounded(exercise(Attempt::GetTrailers)).await
}

#[tokio::test]
async fn rejected_ech_never_replays_the_early_application_request() -> TestResult<()> {
    bounded(exercise(Attempt::RejectEch)).await
}

#[tokio::test]
async fn cancelling_a_held_ech_attempt_joins_peers_and_releases_udp_sockets() -> TestResult<()> {
    bounded(exercise(Attempt::Cancel)).await
}
