//! Concurrent test relays: each accepted stream owns one UDP target.

use std::collections::HashMap;

use super::*;

type H3Stream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type Flows = Arc<Mutex<HashMap<u64, mpsc::Sender<Bytes>>>>;
const AUTHORIZATION: &[u8] = b"Basic dXNlcjpwYXNz";

fn authorized(fields: &[(String, Vec<u8>)]) -> bool {
    fields.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("proxy-authorization") && value == AUTHORIZATION
    })
}

struct RegisteredFlow {
    id: u64,
    flows: Flows,
}
impl Drop for RegisteredFlow {
    fn drop(&mut self) {
        lock(&self.flows).remove(&self.id);
    }
}

pub(super) async fn serve_h3(
    quinn: &quinn::Connection,
    mode: ProxyMode,
    log: Arc<Mutex<ProxyLog>>,
    mut close: watch::Receiver<CloseState>,
    initial: CloseState,
) -> TestResult<()> {
    let mut builder = h3::server::builder();
    builder.enable_extended_connect(true).enable_datagram(true);
    let mut connection = builder
        .build(h3_quinn::Connection::new(quinn.clone()))
        .await?;
    let flows: Flows = Arc::new(Mutex::new(HashMap::new()));
    let mut tasks = JoinSet::new();
    let outcome = loop {
        tokio::select! {
            biased;
            () = connection_closed(&mut close, initial) => {
                quinn.close(0_u32.into(), b"test proxy closed the connection");
                break Ok(());
            },
            accepted = connection.accept() => match accepted {
                Ok(Some(resolver)) => {
                    if tasks.len() >= MAX_STREAM_REQUESTS { break Err("MASQUE active stream limit exceeded".into()); }
                    let resolved = tokio::select! {
                        biased;
                        () = connection_closed(&mut close, initial) => {
                            quinn.close(0_u32.into(), b"test proxy closed the connection");
                            break Ok(());
                        },
                        resolved = resolver.resolve_request() => resolved,
                    };
                    let (request, stream) = match resolved {
                        Ok(resolved) => resolved,
                        Err(error) => break Err(error.into()),
                    };
                    let observed = ObservedConnectUdp {
                        method: request.method().to_string(),
                        protocol: request.extensions().get::<h3::ext::Protocol>().map(|p| p.as_str().to_owned()),
                        scheme: request.uri().scheme_str().map(str::to_owned),
                        authority: request.uri().authority().map(ToString::to_string),
                        path: request.uri().path_and_query().map_or_else(String::new, |p| p.as_str().to_owned()),
                        fields: request.headers().iter().map(|(n,v)| (n.as_str().to_owned(), v.as_bytes().to_vec())).collect(),
                        sensitive: request.headers().iter().filter(|(_,v)| v.is_sensitive()).map(|(n,_)| n.as_str().to_owned()).collect(),
                    };
                    {
                        let mut log = lock(&log);
                        if log.requests.len() >= MAX_STREAM_REQUESTS { break Err("MASQUE request record limit exceeded".into()); }
                        log.stream_ids.push((quinn.stable_id(), stream.id().into_inner()));
                        log.requests.push(observed.clone());
                    }
                    tasks.spawn(h3_tunnel(quinn.clone(), stream, observed, mode, Arc::clone(&flows), Arc::clone(&log)));
                }
                Ok(None) => break Ok(()),
                Err(error) if h3_connection_closed(&error) => break Ok(()),
                Err(error) => break Err(error.into()),
            },
            received = quinn.read_datagram() => match received {
                Ok(mut payload) => {
                    let Some(id) = decode_varint(&mut payload) else { continue };
                    let Some(context) = decode_varint(&mut payload) else { continue };
                    if context == 0 && payload.len() <= MAX_UDP_PAYLOAD
                        && let Some(flow) = lock(&flows).get(&id)
                    {
                        let _ = flow.try_send(payload);
                    }
                }
                Err(quinn::ConnectionError::ApplicationClosed(close)) if close.error_code == 0_u32.into() => break Ok(()),
                Err(error) => break Err(error.into()),
            },
            joined = tasks.join_next(), if !tasks.is_empty() => match joined {
                Some(Ok(Ok(()))) => {},
                Some(Ok(Err(error))) => break Err(error),
                Some(Err(error)) => break Err(error.into()),
                None => break Err("MASQUE stream task disappeared".into()),
            },
        }
    };
    tasks.abort_all();
    let mut cleanup = Ok(());
    while let Some(joined) = tasks.join_next().await {
        let result = match joined {
            Ok(result) => result,
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error.into()),
        };
        cleanup = finish_with_cleanup(cleanup, result);
    }
    finish_with_cleanup(outcome, cleanup)
}

fn h3_connection_closed(error: &h3::error::ConnectionError) -> bool {
    error.is_h3_no_error()
        || matches!(
            error,
            h3::error::ConnectionError::Remote(
                h3::quic::ConnectionErrorIncoming::ApplicationClose { error_code: 0, .. }
            )
        )
}

fn h3_stream_closed(code: h3::error::Code) -> bool {
    code == h3::error::Code::H3_NO_ERROR || code == h3::error::Code::H3_REQUEST_CANCELLED
}

async fn h3_tunnel(
    quinn: quinn::Connection,
    mut stream: H3Stream,
    request: ObservedConnectUdp,
    mode: ProxyMode,
    flows: Flows,
    log: Arc<Mutex<ProxyLog>>,
) -> TestResult<()> {
    let authenticated = authorized(&request.fields);
    if matches!(
        mode,
        ProxyMode::SharingChallenge | ProxyMode::SharingChallengeResetOnce
    ) && !authenticated
    {
        stream
            .send_response(
                Response::builder()
                    .status(407)
                    .header("proxy-authenticate", CHALLENGE)
                    .body(())?,
            )
            .await?;
        stream.finish().await?;
        return Ok(());
    }
    let reset_authenticated = if mode == ProxyMode::SharingChallengeResetOnce && authenticated {
        let mut log = lock(&log);
        let reset = !log.authenticated_reset_sent;
        log.authenticated_reset_sent = true;
        reset
    } else {
        false
    };
    if reset_authenticated
        || (mode == ProxyMode::SharingResetFirst && stream.id().into_inner() == 0)
    {
        stream.stop_stream(h3::error::Code::H3_REQUEST_CANCELLED);
        return Ok(());
    }
    let target = parse_target(&request.path).ok_or("CONNECT-UDP path has no loopback target")?;
    let held = lock(&log).held_setup.take();
    if let Some(held) = held {
        held.observed
            .send((quinn.stable_id(), stream.id().into_inner()))
            .map_err(|_| "held MASQUE setup observer disappeared")?;
        held.release.await?;
    }
    let udp = phantom_testkit::udp::bind_tokio("127.0.0.1:0".parse()?)?;
    udp.connect(target).await?;
    let id = stream.id().into_inner() / 4;
    let (sender, mut incoming) = mpsc::channel(64);
    lock(&flows).insert(id, sender);
    let _registration = RegisteredFlow { id, flows };
    stream
        .send_response(
            Response::builder()
                .status(200)
                .header("capsule-protocol", "?1")
                .body(())?,
        )
        .await?;
    let mut prefix = Vec::new();
    encode_varint(id, &mut prefix);
    prefix.push(0);
    let mut buffer = vec![0; MAX_UDP_PAYLOAD];
    loop {
        tokio::select! {
            payload = incoming.recv() => {
                let Some(payload) = payload else { return Ok(()) };
                udp.send(&payload).await?;
            },
            received = udp.recv(&mut buffer) => match received {
                Ok(count) => {
                    lock(&log).origin_datagrams += 1;
                    match quinn.send_datagram(datagram(&prefix, &buffer[..count])) {
                        Ok(()) | Err(quinn::SendDatagramError::TooLarge) => {},
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => {},
                Err(error) => return Err(error.into()),
            },
            data = stream.recv_data() => match data {
                Ok(Some(_)) => return Err("unexpected capsule data in H3 datagram peer".into()),
                Ok(None) => return Ok(()),
                Err(h3::error::StreamError::RemoteTerminate { code, .. }) if h3_stream_closed(code) => return Ok(()),
                Err(h3::error::StreamError::ConnectionError(error)) if h3_connection_closed(&error) => return Ok(()),
                Err(error) => return Err(error.into()),
            },
        }
    }
}

pub(super) async fn serve_h2<S>(
    stream: S,
    mode: StreamMode,
    log: Arc<Mutex<StreamLog>>,
    mut stopped: watch::Receiver<bool>,
) -> TestResult<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = ::http2::server::Builder::new();
    builder.enable_connect_protocol();
    let mut connection = builder.handshake::<_, Bytes>(stream).await?;
    let connection_id = {
        let mut log = lock(&log);
        log.sharing_connections += 1;
        log.sharing_connections
    };
    let (stop_tunnels, tunnel_stopped) = watch::channel(false);
    let mut tasks = JoinSet::new();
    let mut intentional_stop = false;
    let outcome: TestResult<()> = async {
        loop {
            tokio::select! {
                biased;
                stopped = stream_outcomes::stopped(&mut stopped) => {
                    intentional_stop = stopped.is_ok();
                    break stopped;
                },
                accepted = connection.accept() => match accepted {
                    Some(Ok((request, mut respond))) => {
                        if tasks.len() >= MAX_STREAM_REQUESTS { break Err("MASQUE active stream limit exceeded".into()); }
                        let observed = ObservedStreamRequest {
                            method: request.method().to_string(),
                            protocol: request.extensions().get::<::http2::ext::Protocol>().map(|p| p.as_str().to_owned()),
                            scheme: request.uri().scheme_str().map(str::to_owned),
                            authority: request.uri().authority().map(ToString::to_string),
                            path: request.uri().path_and_query().map_or_else(String::new, |p| p.as_str().to_owned()),
                            fields: request.extensions().get::<::http2::ext::OrderedHeaders>().map(|fields| fields.as_slice().iter().map(|(n,v)| (n.as_str().to_owned(),v.as_bytes().to_vec())).collect()).unwrap_or_default(),
                            head: None,
                        };
                        {
                            let mut log = lock(&log);
                            if log.stream_ids.len() >= MAX_STREAM_REQUESTS { break Err("MASQUE stream record limit exceeded".into()); }
                            log.stream_ids.push((connection_id, request.body().stream_id().as_u32().into()));
                        }
                        let authenticated = authorized(&observed.fields);
                        let target = parse_target(&observed.path);
                        record_stream_request(&log, observed)?;
                        if matches!(mode, StreamMode::SharingChallenge | StreamMode::SharingChallengeResetOnce) && !authenticated {
                            respond.send_response(Response::builder().status(407).header("proxy-authenticate", CHALLENGE).body(())?, true)?;
                            continue;
                        }
                        if mode == StreamMode::SharingChallengeResetOnce && authenticated {
                            let mut log = lock(&log);
                            if !log.authenticated_reset_sent {
                                log.authenticated_reset_sent = true;
                                respond.send_reset(::http2::Reason::CANCEL);
                                continue;
                            }
                        }
                        let target = target.ok_or("CONNECT-UDP path has no loopback target")?;
                        let send = respond.send_response(Response::builder().status(200).header("capsule-protocol", "?1").body(())?, false)?;
                        let mut send = send;
                        if mode == StreamMode::SharingResetFirst && request.body().stream_id().as_u32() == 1 {
                            send.send_reset(::http2::Reason::CANCEL);
                            continue;
                        }
                        tasks.spawn(h2_tunnel(request.into_body(), send, target, Arc::clone(&log), tunnel_stopped.clone()));
                    }
                    Some(Err(error)) if stream_outcomes::h2_peer_closed(&error) => break Ok(()),
                    Some(Err(error)) => break Err(error.into()),
                    None => break Ok(()),
                },
                joined = tasks.join_next(), if !tasks.is_empty() => match joined {
                    Some(Ok(Ok(()))) => {},
                    Some(Ok(Err(error))) => break Err(error),
                    Some(Err(error)) => break Err(error.into()),
                    None => break Err("MASQUE stream task disappeared".into()),
                },
            }
        }
    }
    .await;
    // Let each relay stop and join its own pumps before the connection exits.
    stop_tunnels.send_replace(true);
    let mut cleanup = Ok(());
    while let Some(joined) = tasks.join_next().await {
        let result = match joined {
            Ok(result) => result,
            Err(error) => Err(error.into()),
        };
        cleanup = finish_with_cleanup(cleanup, result);
    }
    if intentional_stop {
        // Graceful shutdown sends GOAWAY before its round-trip PING fence.
        // Keep driving it so the close acknowledgement covers peer retirement,
        // not only dropping this server's transport and relay tasks.
        connection.graceful_shutdown();
        let closed = match poll_fn(|cx| connection.poll_closed(cx)).await {
            Ok(()) => Ok(()),
            Err(error) if stream_outcomes::h2_peer_closed(&error) => Ok(()),
            Err(error) => Err(error.into()),
        };
        cleanup = finish_with_cleanup(cleanup, closed);
    }
    finish_with_cleanup(outcome, cleanup)
}

async fn h2_tunnel(
    mut body: ::http2::RecvStream,
    mut send: ::http2::SendStream<Bytes>,
    target: SocketAddr,
    log: Arc<Mutex<StreamLog>>,
    stopped: watch::Receiver<bool>,
) -> TestResult<()> {
    let mut pumps = JoinSet::new();
    let (inbound_tx, inbound) = mpsc::channel(64);
    let (outbound, mut outbound_rx) = mpsc::channel::<Bytes>(64);
    pumps.spawn(async move {
        loop {
            let chunk = match body.data().await {
                Some(Ok(chunk)) => chunk,
                None => return Ok(stream_outcomes::PumpEnd::PeerClosed),
                Some(Err(error)) if stream_outcomes::h2_peer_closed(&error) => {
                    return Ok(stream_outcomes::PumpEnd::PeerClosed);
                }
                Some(Err(error)) => return Err(error.into()),
            };
            body.flow_control().release_capacity(chunk.len())?;
            if inbound_tx.send(chunk).await.is_err() {
                return Ok(stream_outcomes::PumpEnd::InputEnded);
            }
        }
    });
    pumps.spawn(async move {
        while let Some(mut chunk) = outbound_rx.recv().await {
            while !chunk.is_empty() {
                send.reserve_capacity(chunk.len());
                let capacity = match poll_fn(|cx| send.poll_capacity(cx)).await {
                    Some(Ok(capacity)) => capacity,
                    Some(Err(error)) if stream_outcomes::h2_peer_closed(&error) => {
                        return Ok(stream_outcomes::PumpEnd::PeerClosed);
                    }
                    Some(Err(error)) => return Err(error.into()),
                    None => return Ok(stream_outcomes::PumpEnd::PeerClosed),
                };
                if capacity == 0 {
                    continue;
                }
                let part = chunk.split_to(capacity.min(chunk.len()));
                if let Err(error) = send.send_data(part, false) {
                    if stream_outcomes::h2_peer_closed(&error) {
                        return Ok(stream_outcomes::PumpEnd::PeerClosed);
                    }
                    return Err(error.into());
                }
            }
        }
        Ok(stream_outcomes::PumpEnd::OutputEnded)
    });
    stream_outcomes::relay(
        pumps,
        relay_capsules(inbound, outbound, target, log),
        stopped,
    )
    .await
}

#[cfg(test)]
mod tests {
    #[test]
    fn stream_termination_accepts_only_normal_close_and_cancellation() {
        use h3::error::Code;
        assert!(super::h3_stream_closed(Code::H3_NO_ERROR));
        assert!(super::h3_stream_closed(Code::H3_REQUEST_CANCELLED));
        assert!(!super::h3_stream_closed(Code::H3_GENERAL_PROTOCOL_ERROR));
        assert!(!super::h3_stream_closed(Code::H3_MESSAGE_ERROR));
    }
}
