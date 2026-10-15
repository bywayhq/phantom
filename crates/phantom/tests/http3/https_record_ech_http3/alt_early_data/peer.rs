use h3::proto::{
    coding::Encode,
    frame::{Frame, SettingId, Settings},
};

use super::*;

/// One source of values for the serialized TLS context and HTTP/3 builder.
#[derive(Clone, Copy)]
struct ServerSettings {
    max_fields: u64,
}

impl ServerSettings {
    fn encoded(self) -> TestResult<Vec<u8>> {
        let mut settings = Settings::default();
        for (id, value) in [
            (SettingId::MAX_HEADER_LIST_SIZE, self.max_fields),
            (SettingId::ENABLE_CONNECT_PROTOCOL, 0),
            (SettingId::ENABLE_WEBTRANSPORT, 0),
            (SettingId::H3_DATAGRAM, 0),
            (SettingId::WEBTRANSPORT_MAX_SESSIONS, 0),
        ] {
            settings.insert(id, value)?;
        }
        let mut bytes = Vec::new();
        Frame::<Bytes>::Settings(settings).encode(&mut bytes);
        Ok(bytes)
    }

    fn builder(self) -> h3::server::Builder {
        let mut builder = h3::server::builder();
        builder
            .send_grease(false)
            .max_field_section_size(self.max_fields)
            .enable_extended_connect(false)
            .enable_webtransport(false)
            .enable_datagram(false)
            .max_webtransport_sessions(0);
        builder
    }
}

pub(super) struct NativePeer {
    pub address: SocketAddr,
    pub events: mpsc::UnboundedReceiver<Event>,
    pub read: mpsc::UnboundedSender<()>,
    stop: oneshot::Sender<()>,
    task: ConnectionPeer<TestResult<()>>,
}

impl NativePeer {
    pub(super) fn spawn(
        identity: &TestIdentity,
        attempt: Attempt,
        gate: watch::Receiver<bool>,
    ) -> TestResult<Self> {
        let context = QuicOrigin::context(identity, 1, &TEST_ECH_KEYS[0])?;
        let original = ServerSettings { max_fields: 4096 };
        let native =
            QuicServerConfig::new(context.clone()).with_early_data(&original.encoded()?)?;
        let endpoint = crate::support::h3::quic_server(
            quinn::ServerConfig::with_crypto(Arc::new(native)),
            (Ipv4Addr::LOCALHOST, 0).into(),
        )?;
        let address = endpoint.local_addr()?;
        let (events_tx, events) = mpsc::unbounded_channel();
        let (read, mut read_rx) = mpsc::unbounded_channel();
        let (stop, mut stopping) = oneshot::channel();
        let worker_endpoint = endpoint.clone();
        let task = ConnectionPeer::spawn(async move {
            let endpoint = worker_endpoint;
            let flow: TestResult<()> = async {
                serve(
                    &endpoint,
                    original,
                    &gate,
                    &events_tx,
                    &mut read_rx,
                    1,
                    false,
                )
                .await?;
                let next = if attempt == Attempt::RejectEarly {
                    ServerSettings { max_fields: 8192 }
                } else {
                    original
                };
                if attempt == Attempt::RejectEch {
                    context.set_ech_keys(&ech_keys(2, &TEST_ECH_KEYS[1])?)?;
                }
                let native = QuicServerConfig::new(context).with_early_data(&next.encoded()?)?;
                endpoint
                    .set_server_config(Some(quinn::ServerConfig::with_crypto(Arc::new(native))));
                serve(
                    &endpoint,
                    next,
                    &gate,
                    &events_tx,
                    &mut read_rx,
                    2,
                    attempt == Attempt::RejectEch,
                )
                .await?;
                let quiet: TestResult<()> = match timeout(QUIET_WINDOW, endpoint.accept()).await {
                    Ok(Some(_)) => {
                        Err("an extra native QUIC connection followed the attempt".into())
                    }
                    Ok(None) => Err("native endpoint unexpectedly stopped".into()),
                    Err(_) => Ok(()),
                };
                quiet?;
                events_tx.send(Event::Finished)?;
                Ok(())
            }
            .await;
            flow
        });
        // The coordinator owns shutdown even when a request is cancelled.
        let task = ConnectionPeer::spawn(async move {
            let mut worker = task;
            let result = tokio::select! {
                biased;
                _ = &mut stopping => worker.shutdown().await,
                result = &mut worker => result.map_err(Into::into).and_then(|result| result),
            };
            endpoint.close(0_u32.into(), b"native fixture shutdown");
            let cleanup = timeout(TEST_TIMEOUT, endpoint.wait_idle())
                .await
                .map_err(Into::into);
            finish_with_cleanup(result, cleanup)
        });
        Ok(Self {
            address,
            events,
            read,
            stop,
            task,
        })
    }

    pub(super) async fn finish(self) -> TestResult<()> {
        // A completed result is still observed even if its stop receiver dropped.
        let _ = self.stop.send(());
        timeout(TEST_TIMEOUT, self.task).await??
    }
}

async fn serve(
    endpoint: &quinn::Endpoint,
    settings: ServerSettings,
    gate: &watch::Receiver<bool>,
    events: &mpsc::UnboundedSender<Event>,
    read: &mut mpsc::UnboundedReceiver<()>,
    connection: usize,
    reject_ech: bool,
) -> TestResult<()> {
    let mut connecting = endpoint
        .accept()
        .await
        .ok_or("native endpoint closed")?
        .accept()?;
    let native = connecting
        .handshake_data()
        .await?
        .downcast::<ServerHandshakeData>()
        .map_err(|_| "native handshake type changed")?;
    let hello = ClientHelloSummary::from_handshake_bytes(native.client_hello())?;
    let outer_name = hello
        .server_name()
        .map(|name| String::from_utf8_lossy(name).into_owned());
    let offered_early = hello.extension_types().contains(&42);
    let (quic, completed) = connecting
        .into_0rtt()
        .map_err(|_| "native server refused 0.5-RTT")?;
    events.send(Event::Pending(PendingSeen {
        connection,
        stable_id: quic.stable_id(),
        outer_name,
        offered_early,
        native: *native,
    }))?;
    if reject_ech {
        let closed = quic.closed().await;
        let quinn::ConnectionError::ConnectionClosed(close) = closed else {
            return Err(closed.into());
        };
        events.send(Event::EchFailed(u64::from(close.error_code)))?;
        endpoint.wait_idle().await;
        return Ok(());
    }
    let mut h3 = settings
        .builder()
        .build(h3_quinn::Connection::new(quic.clone()))
        .await?;
    let resolver = h3
        .accept()
        .await?
        .ok_or("client closed before native request")?;
    let (request, mut stream) = resolver.resolve_request().await?;
    let gate_open = *gate.borrow();
    let mut body = Vec::new();
    while let Some(mut data) = stream.recv_data().await? {
        while data.has_remaining() {
            let chunk = data.chunk();
            body.extend_from_slice(chunk);
            let len = chunk.len();
            data.advance(len);
        }
    }
    let trailers = stream.recv_trailers().await?;
    events.send(Event::Request(RequestSeen {
        connection,
        stable_id: quic.stable_id(),
        method: request.method().clone(),
        authority: request
            .uri()
            .authority()
            .ok_or("native authority absent")?
            .to_string(),
        path: request.uri().path().to_owned(),
        marker: request
            .headers()
            .get("x-early-marker")
            .ok_or("request marker absent")?
            .to_str()?
            .to_owned(),
        body,
        trailer: trailers
            .as_ref()
            .and_then(|headers| headers.get("x-early-trailer"))
            .map(|value| value.to_str().map(str::to_owned))
            .transpose()?,
        gate_open,
    }))?;
    stream
        .send_response(http::Response::builder().status(200).body(())?)
        .await?;
    stream.send_data(Bytes::from_static(b"ok")).await?;
    stream.finish().await?;
    // Quinn's server notification carries no early-data acceptance contract.
    // Native metadata below distinguishes a completed handshake from failure.
    let server_notification = completed.await;
    eprintln!(
        "native server completion: connection={connection}, notification={server_notification}, close_reason={:?}",
        quic.close_reason()
    );
    if let Some(error) = quic.close_reason() {
        return Err(error.into());
    }
    let native = quic
        .handshake_data()
        .ok_or("completed native metadata absent")?
        .downcast::<ServerHandshakeData>()
        .map_err(|_| "completed native metadata type changed")?;
    if native.early_data_accepted().is_none() {
        return Err("server notification preceded completed native metadata".into());
    }
    events.send(Event::Complete {
        connection,
        stable_id: quic.stable_id(),
        server_notification,
        native: *native,
    })?;
    read.recv()
        .await
        .ok_or("client dropped response acknowledgement")?;
    match timeout(QUIET_WINDOW, h3.accept()).await {
        Ok(Ok(Some(_))) => {
            return Err("a second request was processed on one native connection".into());
        }
        Ok(Ok(None)) | Err(_) => {}
        Ok(Err(error)) if error.is_h3_no_error() => {}
        Ok(Err(error)) => return Err(error.into()),
    }
    if connection == 1 {
        h3.shutdown(0).await?;
        // Keep the warm flight open until its client processed GOAWAY.
        read.recv()
            .await
            .ok_or("client dropped retirement acknowledgement")?;
    }
    quic.close(0_u32.into(), b"new connection required");
    drop(h3);
    endpoint.wait_idle().await;
    events.send(Event::Drained)?;
    Ok(())
}

pub(super) struct Advertisement {
    pub port: u16,
    task: ConnectionPeer<TestResult<()>>,
}

impl Advertisement {
    pub(super) async fn spawn(identity: &TestIdentity, alternative: u16) -> TestResult<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = listener.local_addr()?.port();
        let acceptor = identity.acceptor(H1_ALPN)?;
        let task = ConnectionPeer::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let (_, tls) = try_handshake(tcp, &acceptor).await?;
            let mut tls = tls.ok_or("advertisement handshake failed")?;
            let head = read_head(&mut tls).await?;
            assert!(String::from_utf8_lossy(&head).contains(&format!("{ORIGIN_NAME}:{port}")));
            tls.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\nAlt-Svc: h3=\"{DESTINATION}:{alternative}\"; ma=300\r\n\r\nok").as_bytes()).await?;
            tls.shutdown().await?;
            Ok(())
        });
        Ok(Self { port, task })
    }

    pub(super) async fn finish(self) -> TestResult<()> {
        timeout(TEST_TIMEOUT, self.task).await??
    }
    pub(super) async fn stop(self) -> TestResult<()> {
        self.task.stop().await
    }
}
